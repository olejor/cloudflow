/*
 * dhcp_sniffer_verbose_refactored.c
 *
 * Compile:
 *   gcc -o dhcp_sniffer_verbose_refactored dhcp_sniffer_verbose_refactored.c
 *
 * Usage (must be root):
 *   sudo ./dhcp_sniffer_verbose_refactored <interface>
 *
 * Extracts and prints detailed DHCPv4/v6 information,
 * including fixed‐header fields and all options (as o<opt>=<value>).
 */

 #define _GNU_SOURCE
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
 #include <time.h>
 
 #include <sys/socket.h>
 #include <sys/ioctl.h>
 #include <sys/uio.h>
 
 #include <net/if.h>
 #include <arpa/inet.h>
 
 #include <linux/if_packet.h>
 #include <linux/if_ether.h>
 #include <linux/ip.h>
 #include <linux/ipv6.h>
 #include <netinet/udp.h>
 #include <linux/filter.h>
 
 #define BATCH_SIZE  32
 #define MAX_BUF     2048
 
 /* Helpers: hex dump */
 static void dump_hex(const unsigned char *buf, size_t len) {
     for (size_t i = 0; i < len; i++) {
         printf("%02x", buf[i]);
         if ((i + 1) % 16 == 0) printf("\n"); else printf(" ");
     }
     if (len % 16) printf("\n");
     printf("\n");
 }
 
 /* Packet processing declarations */
 void process_packet(const unsigned char *pkt, size_t len);
 void process_dhcpv4(const unsigned char *pl, size_t pl_len, size_t pkt_len);
 void process_dhcpv6(const unsigned char *pl, size_t pl_len, size_t pkt_len);
 
 /* BPF filter: keep only DHCPv4 (67/68) & DHCPv6 (546/547) */
 static int set_bpf_filter(int sock) {
     static const struct sock_filter filter[] = {
         /* IPv4 & UDP dst 67/68, no fragments */
         BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 12),
         BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x0800, 0, 7),
         BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 14),
         BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x1fff, 5, 0),
         BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, 14),
         BPF_STMT(BPF_LD|BPF_H|BPF_IND, 2),
         BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 67, 0, 1),
         BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 68, 0, 1),
         BPF_STMT(BPF_RET|BPF_K, 0x40000),
         /* IPv6 & UDP dst 546/547 */
         BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x86DD, 0, 5),
         BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 20),
         BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 0, 2),
         BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, 54),
         BPF_STMT(BPF_LD|BPF_H|BPF_IND, 2),
         BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 546, 0, 1),
         BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 547, 0, 1),
         BPF_STMT(BPF_RET|BPF_K, 0x40000),
         /* drop others */
         BPF_STMT(BPF_RET|BPF_K, 0),
     };
     struct sock_fprog prog = {
         .len    = sizeof(filter)/sizeof(filter[0]),
         .filter = (struct sock_filter*)filter,
     };
     if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
         perror("SO_ATTACH_FILTER");
         return -1;
     }
     return 0;
 }
 
 int main(int argc, char **argv) {
     if (argc!=2) {
         fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
         return EXIT_FAILURE;
     }
     const char *ifname = argv[1];
 
     int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
     if (sock<0) { perror("socket"); return EXIT_FAILURE; }
 
     struct ifreq ifr = {};
     strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
     if (ioctl(sock, SIOCGIFINDEX, &ifr)<0) { perror("ioctl"); close(sock); return EXIT_FAILURE; }
     struct sockaddr_ll sll = { AF_PACKET, ifr.ifr_ifindex, htons(ETH_P_ALL) };
     if (bind(sock,(struct sockaddr*)&sll,sizeof(sll))<0) { perror("bind"); close(sock); return EXIT_FAILURE; }
 
     struct packet_mreq mreq = { .mr_ifindex=ifr.ifr_ifindex, .mr_type=PACKET_MR_PROMISC };
     setsockopt(sock,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mreq,sizeof(mreq));
 
     if (set_bpf_filter(sock)<0) { close(sock); return EXIT_FAILURE; }
     printf("Capturing DHCPv4/v6 on %s...\n", ifname);
 
     unsigned char    bufs[BATCH_SIZE][MAX_BUF];
     struct iovec     iov[BATCH_SIZE];
     struct mmsghdr   msgs[BATCH_SIZE];
     struct timespec  timeout = {1,0};
     for(int i=0;i<BATCH_SIZE;i++){
         iov[i].iov_base = bufs[i];
         iov[i].iov_len  = sizeof bufs[i];
         memset(&msgs[i],0,sizeof msgs[i]);
         msgs[i].msg_hdr.msg_iov    = &iov[i];
         msgs[i].msg_hdr.msg_iovlen = 1;
     }
 
     while(1) {
         int n = recvmmsg(sock,msgs,BATCH_SIZE,MSG_WAITFORONE,&timeout);
         if (n<0) { if(errno==EINTR) continue; perror("recvmmsg"); break; }
         for(int i=0;i<n;i++){
             process_packet(bufs[i], msgs[i].msg_len);
             msgs[i].msg_len = 0;
         }
     }
     close(sock);
     return EXIT_SUCCESS;
 }
 
 void process_packet(const unsigned char *pkt, size_t len) {
     if(len<sizeof(struct ethhdr)) return;
     const struct ethhdr *eth = (void*)pkt;
     uint16_t ethertype = ntohs(eth->h_proto);
     const unsigned char *pl = pkt+sizeof(*eth);
     size_t pl_len = len-sizeof(*eth);
     if(ethertype==ETH_P_IP && pl_len>=sizeof(struct iphdr))
         process_dhcpv4(pl,pl_len,len);
     else if(ethertype==ETH_P_IPV6 && pl_len>=sizeof(struct ipv6hdr))
         process_dhcpv6(pl,pl_len,len);
 }
 
 void process_dhcpv4(const unsigned char *pl, size_t pl_len, size_t pkt_len) {
     const struct iphdr *ip = (void*)pl;
     if(ip->protocol!=IPPROTO_UDP) return;
     size_t ihl=ip->ihl*4;
     if(pl_len<ihl+sizeof(struct udphdr)) return;
     const struct udphdr *udp=(void*)(pl+ihl);
     uint16_t sport=ntohs(udp->source), dport=ntohs(udp->dest);
     if(!(sport==67||sport==68||dport==67||dport==68)) return;
 
     char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
     inet_ntop(AF_INET,&ip->saddr,src,sizeof src);
     inet_ntop(AF_INET,&ip->daddr,dst,sizeof dst);
     printf("\n=== DHCPv4 %s → %s (len=%zu) ===\n",src,dst,pkt_len);
 
     const unsigned char *dhcp = pl+ihl+sizeof(*udp);
     int dhcp_len = pl_len-ihl-sizeof(*udp);
     if(dhcp_len<240){ printf("<truncated DHCP header>\n"); return; }
 
     uint8_t op=dhcp[0], htype=dhcp[1], hlen=dhcp[2], hops=dhcp[3];
     uint32_t xid=ntohl(*(uint32_t*)(dhcp+4));
     uint16_t secs=ntohs(*(uint16_t*)(dhcp+8));
     uint16_t flags=ntohs(*(uint16_t*)(dhcp+10));
     struct in_addr ci,yi,si,gi;
     memcpy(&ci.s_addr,dhcp+12,4);
     memcpy(&yi.s_addr,dhcp+16,4);
     memcpy(&si.s_addr,dhcp+20,4);
     memcpy(&gi.s_addr,dhcp+24,4);
     printf("op=%u htype=%u hlen=%u hops=%u xid=0x%08x secs=%u flags=0x%04x\n",
            op,htype,hlen,hops,xid,secs,flags);
     printf("ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s\n",
            inet_ntop(AF_INET,&ci,src,sizeof src),
            inet_ntop(AF_INET,&yi,src,sizeof src),
            inet_ntop(AF_INET,&si,src,sizeof src),
            inet_ntop(AF_INET,&gi,src,sizeof src));
     printf("chaddr="); for(int i=0;i<hlen&&i<16;i++) printf("%02x",dhcp[28+i]); printf("\n");
     if(dhcp[44]) printf("sname=%.64s\n",dhcp+44); if(dhcp[108]) printf("file=%.128s\n",dhcp+108);
 
     /* options as o<tag>=hex */
     unsigned char *opt=(unsigned char*)(dhcp+240);
     int left=dhcp_len-240;
     while(left>1) {
         uint8_t tag=*opt++;
         left--;
         if(tag==0) continue;
         if(tag==255) { printf("o255=end\n"); break; }
         if(left<1) break;
         uint8_t l=*opt++;
         left--;
         if(l>left) break;
         printf("o%u=", tag);
         for(int j=0;j<l;j++) printf("%02x", opt[j]);
         printf("\n");
         opt+=l; left-=l;
     }
 
     dump_hex(pl-sizeof(struct ethhdr), pkt_len);
 }
 
 void process_dhcpv6(const unsigned char *pl, size_t pl_len, size_t pkt_len) {
     const struct ipv6hdr *ip6=(void*)pl;
     if(ip6->nexthdr!=IPPROTO_UDP) return;
     if(pl_len<sizeof(*ip6)+sizeof(struct udphdr)) return;
     const struct udphdr *udp6=(void*)(pl+sizeof(*ip6));
     uint16_t sport=ntohs(udp6->source), dport=ntohs(udp6->dest);
     if(!(sport==546||sport==547||dport==546||dport==547)) return;
 
     char src6[INET6_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];
     inet_ntop(AF_INET6,&ip6->saddr,src6,sizeof src6);
     inet_ntop(AF_INET6,&ip6->daddr,dst6,sizeof dst6);
     printf("\n=== DHCPv6 %s -> %s (len=%zu) ===\n",src6,dst6,pkt_len);
 
     const unsigned char *dhcp6=pl+sizeof(*ip6)+sizeof(*udp6);
     size_t dhcp6_len=pl_len-sizeof(*ip6)-sizeof(*udp6);
     if(dhcp6_len<4) return;
     /* msgtype at byte 0, then txn-id 3 bytes */
     uint8_t mtype=dhcp6[0]; printf("o53=%02x   \n", mtype);
     unsigned char *opt6=(unsigned char*)(dhcp6+4);
     size_t left=dhcp6_len-4;
     while(left>4) {
         uint16_t tag=ntohs(*(uint16_t*)opt6);
         uint16_t l=ntohs(*(uint16_t*)(opt6+2));
         opt6+=4; left-=4;
         if(l>left) break;
         printf("o%u=", tag);
         for(int j=0;j<l;j++) printf("%02x", opt6[j]);
         printf("\n");
         opt6+=l; left-=l;
     }
     dump_hex(pl-sizeof(struct ethhdr), pkt_len);
 }
 
