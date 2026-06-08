/*
 * dhcp_sniffer_improved.c – minimal‑dependency DHCPv4/v6 sniffer
 *
 * Build:
 *     gcc -Wall -Wextra -O2 -o dhcp_sniffer dhcp_sniffer_improved.c
 *
 * Run (requires CAP_NET_RAW or root):
 *     sudo ./dhcp_sniffer <interface>
 *
 * Compared to the original version this variant focuses on
 *  • safer pointer handling (memcpy -> avoid unaligned access)
 *  • correct use of inet_ntop buffers
 *  • graceful shutdown that removes the promiscuous membership
 *  • optional VLAN‑tag awareness (single 802.1Q tag)
 *  • slightly richer output and clearer formatting
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define BATCH_SIZE  32
#define MAX_BUF     2048

static int raw_sock = -1;               /* global for signal handler */
static struct packet_mreq promisc_req;  /* ditto */

/* ———————————————————————————————————————————————————————— */
static void cleanup(int signum)
{
    if (raw_sock >= 0) {
        if (promisc_req.mr_ifindex && promisc_req.mr_type == PACKET_MR_PROMISC)
            setsockopt(raw_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
                       &promisc_req, sizeof(promisc_req));
        close(raw_sock);
    }
    fprintf(stderr, "\nCaught signal %d – exiting.\n", signum);
    _Exit(EXIT_SUCCESS);
}

static void install_signal_handlers(void)
{
    struct sigaction sa = { .sa_handler = cleanup };
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

/* ———————————————————————————————————————————————————————— */
static void dump_hex(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        printf("%02x%c", buf[i], ((i + 1) % 16) ? ' ' : '\n');
    }
    if (len % 16)
        putchar('\n');
}

static void process_dhcpv4(const unsigned char *pkt, size_t len);
static void process_dhcpv6(const unsigned char *pkt, size_t len);

/* ——— tiny helpers ——— */
#define MIN(a,b) ((a) < (b) ? (a) : (b))

static const char *safe_ntop4(const void *addr)
{
    static char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, buf, sizeof(buf));
    return buf;
}

static const char *safe_ntop6(const void *addr)
{
    static char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return buf;
}

/* ———————————————————————————————————————————————————————— */
static int attach_bpf(int sock)
{
    /* The filter is equivalent to:
     *   (udp dst port 67 or 68) or (udp dst port 546 or 547)
     *   – with optional single VLAN tag skipped.
     */
    static const struct sock_filter filter[] = {
        /* step past ethernet (14) or vlan (18) header */
        BPF_STMT(BPF_LD  | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_8021Q, 0, 3),
        BPF_STMT(BPF_LD  | BPF_H | BPF_ABS, 16), /* VLAN ethertype */
        BPF_JUMP(BPF_JMP | BPF_JA  | BPF_K, 1, 0, 0), /* skip next */
        BPF_STMT(BPF_LD  | BPF_H | BPF_ABS, 12),

        /* IPv4? */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 8),
        BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, 23),          /* proto */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 6),
        BPF_STMT(BPF_LD  | BPF_H | BPF_ABS, 20),          /* frag */
        BPF_JUMP(BPF_JMP | BPF_JSET| BPF_K, 0x1fff, 4, 0),/* frag? */
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),          /* ip.hdr */
        BPF_STMT(BPF_LD  | BPF_H | BPF_IND, 16),          /* dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 67, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 68, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, (uint32_t)-1),

        /* IPv6? */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 0, 9),
        BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, 20),          /* nxt hdr */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 7),
        BPF_STMT(BPF_LDX | BPF_IMM, 54),                  /* fixed */
        BPF_STMT(BPF_LD  | BPF_H | BPF_IND, 2),           /* dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 546, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 547, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, (uint32_t)-1),

        /* default – drop */
        BPF_STMT(BPF_RET | BPF_K, 0)
    };

    const struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = (struct sock_filter *)filter,
    };

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("SO_ATTACH_FILTER");
        return -1;
    }
    return 0;
}

/* ———————————————————————————————————————————————————————— */
static void process_packet(const unsigned char *buf, size_t len)
{
    if (len < sizeof(struct ethhdr))
        return;

    const struct ethhdr *eth = (const struct ethhdr *)buf;
    uint16_t ethertype = ntohs(eth->h_proto);
    size_t   offset    = sizeof(struct ethhdr);

    /* Skip at most one VLAN tag */
    if (ethertype == ETH_P_8021Q && len >= offset + 4) {
        ethertype = ntohs(*(uint16_t *)(buf + offset + 2));
        offset   += 4;
    }

    const unsigned char *pl = buf + offset;
    size_t pl_len = len - offset;

    if (ethertype == ETH_P_IP)
        process_dhcpv4(pl, pl_len);
    else if (ethertype == ETH_P_IPV6)
        process_dhcpv6(pl, pl_len);
}

/* ————————————————— DHCPv4 ———————————————————————— */
static void process_dhcpv4(const unsigned char *pkt, size_t len)
{
    struct iphdr ip;
    if (len < sizeof ip)
        return;
    memcpy(&ip, pkt, sizeof ip);

    if (ip.protocol != IPPROTO_UDP)
        return;

    size_t ihl = ip.ihl * 4u;
    if (len < ihl + sizeof(struct udphdr))
        return;

    struct udphdr udp;
    memcpy(&udp, pkt + ihl, sizeof udp);

    uint16_t sport = ntohs(udp.source);
    uint16_t dport = ntohs(udp.dest);
    if (!((sport == 67 || sport == 68 || dport == 67 || dport == 68)))
        return;

    printf("\n—— DHCPv4 %s → %s ——\n",
           safe_ntop4(&ip.saddr), safe_ntop4(&ip.daddr));

    const unsigned char *dhcp = pkt + ihl + sizeof udp;
    ssize_t dhcp_len = (ssize_t)len - (ssize_t)ihl - (ssize_t)sizeof udp;
    if (dhcp_len < 240) {
        puts("<truncated DHCP header>");
        return;
    }

    uint32_t xid;
    memcpy(&xid, dhcp + 4, sizeof xid);
    xid = ntohl(xid);

    uint16_t secs, flags;
    memcpy(&secs,  dhcp + 8,  sizeof secs);
    memcpy(&flags, dhcp + 10, sizeof flags);
    secs  = ntohs(secs);
    flags = ntohs(flags);

    printf("xid=0x%08x secs=%u flags=0x%04x\n", xid, secs, flags);

    struct in_addr ci, yi, si, gi;
    memcpy(&ci, dhcp + 12, 4);
    memcpy(&yi, dhcp + 16, 4);
    memcpy(&si, dhcp + 20, 4);
    memcpy(&gi, dhcp + 24, 4);

    printf("ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s\n",
           safe_ntop4(&ci), safe_ntop4(&yi), safe_ntop4(&si), safe_ntop4(&gi));

    uint8_t hlen = dhcp[2];
    printf("chaddr=");
    for (uint8_t i = 0; i < MIN(hlen, 16); ++i)
        printf("%02x", dhcp[28 + i]);
    putchar('\n');

    /* options */
    const unsigned char *opt = dhcp + 240;
    ssize_t left = dhcp_len - 240;
    while (left > 1) {
        uint8_t tag = *opt++;
        --left;
        if (tag == 0)
            continue;   /* pad */
        if (tag == 255) {
            puts("eof");
            break;
        }
        if (left < 1)
            break;
        uint8_t l = *opt++;
        --left;
        if (l > left)
            break;
        printf("o%u=", tag);
        for (uint8_t j = 0; j < l; ++j)
            printf("%02x", opt[j]);
        putchar('\n');
        opt  += l;
        left -= l;
    }
}

/* ————————————————— DHCPv6 ———————————————————————— */
static void process_dhcpv6(const unsigned char *pkt, size_t len)
{
    struct ipv6hdr ip6;
    if (len < sizeof ip6)
        return;
    memcpy(&ip6, pkt, sizeof ip6);

    if (ip6.nexthdr != IPPROTO_UDP)
        return;

    if (len < sizeof ip6 + sizeof(struct udphdr))
        return;

    struct udphdr udp6;
    memcpy(&udp6, pkt + sizeof ip6, sizeof udp6);

    uint16_t sport = ntohs(udp6.source);
    uint16_t dport = ntohs(udp6.dest);
    if (!((sport == 546 || sport == 547 || dport == 546 || dport == 547)))
        return;

    printf("\n—— DHCPv6 %s → %s ——\n",
           safe_ntop6(&ip6.saddr), safe_ntop6(&ip6.daddr));

    const unsigned char *dhcp6 = pkt + sizeof ip6 + sizeof udp6;
    ssize_t dhcp6_len = (ssize_t)len - (ssize_t)sizeof ip6 - (ssize_t)sizeof udp6;

    if (dhcp6_len < 4)
        return;

    uint8_t mtype = dhcp6[0];
    uint32_t tid = (dhcp6[1] << 16) | (dhcp6[2] << 8) | dhcp6[3];
    printf("msg‑type=%u, xid=0x%06x\n", mtype, tid);

    const unsigned char *opt = dhcp6 + 4;
    ssize_t left = dhcp6_len - 4;
    while (left >= 4) {
        uint16_t tag   = ntohs(*(const uint16_t *)opt);
        uint16_t l     = ntohs(*(const uint16_t *)(opt + 2));
        opt  += 4;
        left -= 4;
        if (l > left)
            break;
        printf("o%u=", tag);
        for (uint16_t j = 0; j < l; ++j)
            printf("%02x", opt[j]);
        putchar('\n');
        opt  += l;
        left -= l;
    }
}

/* ———————————————————————————————————————————————————————— */
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    install_signal_handlers();

    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        cleanup(EXIT_FAILURE);
    }

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_ifindex  = ifr.ifr_ifindex,
        .sll_protocol = htons(ETH_P_ALL),
    };
    if (bind(raw_sock, (struct sockaddr *)&sll, sizeof sll) < 0) {
        perror("bind");
        cleanup(EXIT_FAILURE);
    }

    promisc_req = (struct packet_mreq){
        .mr_ifindex = ifr.ifr_ifindex,
        .mr_type    = PACKET_MR_PROMISC,
    };
    if (setsockopt(raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   &promisc_req, sizeof promisc_req) < 0) {
        perror("PACKET_ADD_MEMBERSHIP");
        cleanup(EXIT_FAILURE);
    }

    if (attach_bpf(raw_sock) < 0)
        cleanup(EXIT_FAILURE);

    puts("Capturing DHCPv4 / DHCPv6 … (Ctrl‑C to stop)");

    /* --- recvmmsg loop --- */
    unsigned char  bufs[BATCH_SIZE][MAX_BUF] __attribute__((aligned(8)));
    struct iovec   iov[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; ++i) {
        iov[i] = (struct iovec){ .iov_base = bufs[i], .iov_len = sizeof bufs[i] };
        msgs[i] = (struct mmsghdr){ .msg_hdr = { .msg_iov = &iov[i], .msg_iovlen = 1 } };
    }

    struct timespec tv = { .tv_sec = 1, .tv_nsec = 0 };

    for (;;) {
        int n = recvmmsg(raw_sock, msgs, BATCH_SIZE, MSG_WAITFORONE, &tv);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("recvmmsg");
            break;
        }
        if (n == 0)
            continue;   /* timeout */
        for (int i = 0; i < n; ++i) {
            process_packet(iov[i].iov_base, msgs[i].msg_len);
            msgs[i].msg_len = 0;   /* reset for next round */
        }
    }

    cleanup(EXIT_FAILURE);
}

