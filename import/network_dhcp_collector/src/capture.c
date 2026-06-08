/*
 * capture.c — raw‑socket packet capture with BPF filter (DHCPv4/v6)
 * Works on Linux (AF_PACKET). No decoding here: we just forward L2 frames to a
 * callback supplied by main.c so that unit tests can stub it.
 */

 #include "capture.h"

 #include <linux/if_packet.h>
 #include <linux/if_ether.h>
 #include <linux/filter.h>
 #include <net/if.h>
 #include <signal.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/ioctl.h>
 #include <sys/socket.h>
 #include <sys/uio.h>
 #include <time.h>
 #include <unistd.h>
 
 #define MAX_BUF    2048
 #define BATCH_SIZE 32
 
 static int           raw_sock = -1;
 static struct packet_mreq promisc_req;
 static packet_cb     user_cb;
 static void          *user_ctx;
 
 /*──────────────────────────────────────────────────────────────────────────*/
 static void handle_signal(int sig)
 {
     if (raw_sock >= 0) {
         if (promisc_req.mr_ifindex)
             setsockopt(raw_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
                        &promisc_req, sizeof promisc_req);
         close(raw_sock);
     }
     fprintf(stderr, "\n(signal %d) capture stopped.\n", sig);
     _Exit(EXIT_SUCCESS);
 }
 
 /*──────────────────────────────────────────────────────────────────────────*/
 static int attach_dhcp_filter(int sock)
 {
     /* Accept if (IPv4 UDP dst 67/68) OR (IPv6 UDP dst 546/547) */
     static const struct sock_filter code[] = {
         /* ── IPv4 ───────────────────────────────────────────── */
         BPF_STMT(BPF_LD  | BPF_H | BPF_ABS, 12),                  /* ethertype       */
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, ETH_P_IP, 0, 6),      /* not IPv4? skip  */
         BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, 23),                 /* ip->protocol    */
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, IPPROTO_UDP, 0, 4),
         BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),                 /* X = ip.hdr_len  */
         BPF_STMT(BPF_LD  | BPF_H | BPF_IND, 16),                 /* UDP dst port    */
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, 67, 0, 1),
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, 68, 0, 1),
         BPF_STMT(BPF_RET | BPF_K, (uint32_t)-1),                 /* accept          */
 
         /* ── IPv6 ───────────────────────────────────────────── */
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, ETH_P_IPV6, 0, 8),    /* not IPv6? skip  */
         BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, 20),                 /* nexthdr         */
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, IPPROTO_UDP, 0, 6),
         BPF_STMT(BPF_LDX | BPF_IMM, 54),                         /* fixed offset    */
         BPF_STMT(BPF_LD  | BPF_H | BPF_IND, 2),                  /* UDP dst port    */
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, 546, 0, 1),
         BPF_JUMP(BPF_JMP | BPF_JEQ| BPF_K, 547, 0, 1),
         BPF_STMT(BPF_RET | BPF_K, (uint32_t)-1),                 /* accept          */
 
         /* ── default ────────────────────────────────────────── */
         BPF_STMT(BPF_RET | BPF_K, 0),                            /* reject          */
     };
 
     const struct sock_fprog prog = {
         .len    = (unsigned short)(sizeof code / sizeof code[0]),
         .filter = (struct sock_filter *)code,
     };
     return setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog);
 }
 
 /*──────────────────────────────────────────────────────────────────────────*/
 int cap_run(const char *iface, packet_cb cb, void *userdata)
 {
     if (!iface || !cb) {
         fprintf(stderr, "cap_run: bad args\n");
         return -1;
     }
 
     /* store for ISR */
     user_cb  = cb;
     user_ctx = userdata;
 
     struct sigaction sa = { .sa_handler = handle_signal };
     sigaction(SIGINT,  &sa, NULL);
     sigaction(SIGTERM, &sa, NULL);
 
     /* open raw socket */
     raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
     if (raw_sock < 0) {
         perror("socket");
         return -1;
     }
 
     /* map ifname to index */
     struct ifreq ifr = {0};
     strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
     if (ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
         perror("SIOCGIFINDEX");
         return -1;
     }
 
     /* bind */
     struct sockaddr_ll sll = {
         .sll_family   = AF_PACKET,
         .sll_ifindex  = ifr.ifr_ifindex,
         .sll_protocol = htons(ETH_P_ALL),
     };
     if (bind(raw_sock, (struct sockaddr *)&sll, sizeof sll) < 0) {
         perror("bind");
         return -1;
     }
 
     /* promisc */
     promisc_req = (struct packet_mreq){ .mr_ifindex = ifr.ifr_ifindex,
                                         .mr_type    = PACKET_MR_PROMISC };
     setsockopt(raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                &promisc_req, sizeof promisc_req);
 
     /* BPF filter */
     if (attach_dhcp_filter(raw_sock) < 0) {
         perror("filter");
         return -1;
     }
 
     /* prepare iovecs */
     uint8_t        bufs[BATCH_SIZE][MAX_BUF] __attribute__((aligned(8)));
     struct iovec   iov[BATCH_SIZE];
     struct mmsghdr msgs[BATCH_SIZE];
 
     for (int i = 0; i < BATCH_SIZE; ++i) {
         iov[i] = (struct iovec){ .iov_base = bufs[i], .iov_len = sizeof bufs[i] };
         msgs[i] = (struct mmsghdr){ .msg_hdr = { .msg_iov = &iov[i], .msg_iovlen = 1 } };
     }
 
     struct timespec tv = { .tv_sec = 1, .tv_nsec = 0 };
 
     /* main loop */
     for (;;) {
         int n = recvmmsg(raw_sock, msgs, BATCH_SIZE, MSG_WAITFORONE, &tv);
         if (n < 0) {
             if (errno == EINTR)
                 continue;
             perror("recvmmsg");
             break;
         }
         if (n == 0)
             continue; /* timeout */
 
         for (int i = 0; i < n; ++i) {
             user_cb((const uint8_t *)iov[i].iov_base, msgs[i].msg_len, user_ctx);
             msgs[i].msg_len = 0; /* reset */
         }
     }
 
     return 0; /* unreachable due to signals, but keeps compiler happy */
 }
 