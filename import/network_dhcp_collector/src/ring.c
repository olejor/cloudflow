/*  dhcp_mmap_sniffer.c  —  minimal DHCPv4/v6 sniffer using PACKET_MMAP   */
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
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

/* ring parameters (multiple-of-page sizes are fastest) */
#define FRAME_SZ 2048      /* ≥ MTU + ETH_HLEN            */
#define BLOCK_SZ (1 << 22) /* 4 MiB per block             */
#define BLOCK_NR 16        /* 64 MiB total ring           */

static int sock_fd = -1;
static void *ring = MAP_FAILED;
static struct tpacket_req3 req; /* keep for munmap()           */

static void die(const char *s)
{
    perror(s);
    exit(EXIT_FAILURE);
}

/* ctrl-C cleanup */
static void cleanup(int sig)
{
    if (ring != MAP_FAILED)
        munmap(ring, req.tp_block_size * req.tp_block_nr);
    if (sock_fd >= 0)
        close(sock_fd);
    _Exit(EXIT_SUCCESS);
}

/* very small helpers ------------------------------------------------------- */
static const char *ntop4(const void *a)
{
    static char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, a, buf, sizeof buf) ?: "?";
}
static const char *ntop6(const void *a)
{
    static char buf[INET6_ADDRSTRLEN];
    return inet_ntop(AF_INET6, a, buf, sizeof buf) ?: "?";
}

/* cBPF filter: (udp dst 67/68) || (udp dst 546/547) ----------------------- */
static int attach_dhcp_filter(int fd)
{
    static const struct sock_filter code[] = {
        /* assume no VLAN for brevity. add vlan-pop if needed              */
        /* ---- IPv4 ----------------------------------------------------- */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12), /* ethertype */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 6),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23), /* proto     */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 4),
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14), /* iphlen    */
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),  /* dst port  */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 67, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 68, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, (uint32_t)-1),
        /* ---- IPv6 ----------------------------------------------------- */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 0, 7),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 20), /* nexthdr   */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 5),
        BPF_STMT(BPF_LDX | BPF_IMM, 54),       /* offset    */
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2), /* dst port  */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 546, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 547, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, (uint32_t)-1),
        /* default drop -------------------------------------------------- */
        BPF_STMT(BPF_RET | BPF_K, 0)};
    const struct sock_fprog p = {
        .len = sizeof(code) / sizeof(code[0]),
        .filter = (struct sock_filter *)code};
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof(p));
}

/* packet printer ---------------------------------------------------------- */
static void handle_frame(const uint8_t *f, size_t len)
{
    if (len < sizeof(struct ethhdr))
        return;
    const struct ethhdr *eth = (void *)f;
    uint16_t type = ntohs(eth->h_proto);

    /* single VLAN tag skip (optional) */
    size_t off = sizeof(*eth);
    if (type == ETH_P_8021Q && len >= off + 4)
    {
        type = ntohs(*(uint16_t *)(f + off + 2));
        off += 4;
    }

    if (type == ETH_P_IP)
    {
        const struct iphdr *ip = (void *)(f + off);
        if (len < off + sizeof *ip || ip->protocol != IPPROTO_UDP)
            return;
        size_t ihl = ip->ihl * 4u;
        const struct udphdr *u = (void *)(f + off + ihl);
        if (len < off + ihl + sizeof *u)
            return;
        printf("DHCPv4 %s → %s\n",
               ntop4(&ip->saddr), ntop4(&ip->daddr));
    }
    else if (type == ETH_P_IPV6)
    {
        const struct ipv6hdr *ip6 = (void *)(f + off);
        if (len < off + sizeof *ip6 || ip6->nexthdr != IPPROTO_UDP)
            return;
        const struct udphdr *u = (void *)(f + off + sizeof *ip6);
        if (len < off + sizeof *ip6 + sizeof *u)
            return;
        printf("DHCPv6 %s → %s\n",
               ntop6(&ip6->saddr), ntop6(&ip6->daddr));
    }
}

/* main capture loop -------------------------------------------------------- */
static void run_ring(void)
{
    struct pollfd pfd = {.fd = sock_fd, .events = POLLIN};
    uint32_t idx = 0;

    for (;;)
    {
        if (poll(&pfd, 1, 1000) < 0)
        {
            if (errno == EINTR)
                continue;
            die("poll");
        }

        while (1)
        {
            struct tpacket3_hdr *h =
                (void *)((uint8_t *)ring + idx * req.tp_frame_size);

            if (!(h->tp_status & TP_STATUS_USER))
                break;

            const uint8_t *frame = (uint8_t *)h + h->tp_mac;
            handle_frame(frame, h->tp_snaplen);

            h->tp_status = TP_STATUS_KERNEL; /* give back */
            idx = (idx + 1) % req.tp_frame_nr;
        }
    }
}

/* ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <iface>\n", argv[0]);
        return 1;
    }

    /* ^C handler */
    struct sigaction sa = {.sa_handler = cleanup};
    sigaction(SIGINT, &sa, NULL);

    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0)
        die("socket");

    /* bind to interface */
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0)
        die("SIOCGIFINDEX");
    struct sockaddr_ll sll = {.sll_family = AF_PACKET,
                              .sll_ifindex = ifr.ifr_ifindex,
                              .sll_protocol = htons(ETH_P_ALL)};
    if (bind(sock_fd, (void *)&sll, sizeof sll) < 0)
        die("bind");

    /* packet version V3 + ring allocation */
    int ver = TPACKET_V3;
    if (setsockopt(sock_fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0)
        die("PACKET_VERSION");

    req.tp_block_size = BLOCK_SZ;
    req.tp_frame_size = FRAME_SZ;
    req.tp_block_nr = BLOCK_NR;
    req.tp_frame_nr = (BLOCK_SZ / FRAME_SZ) * BLOCK_NR;
    req.tp_retire_blk_tov = 60; /* ms timeout */
    if (setsockopt(sock_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) < 0)
        die("PACKET_RX_RING");

    ring = mmap(NULL, req.tp_block_size * req.tp_block_nr,
                PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sock_fd, 0);
    if (ring == MAP_FAILED)
        die("mmap");

    /* BPF filter */
    if (attach_dhcp_filter(sock_fd) < 0)
        die("SO_ATTACH_FILTER");

    printf("DHCP sniffer on %s (Ctrl-C to quit)\n", argv[1]);
    run_ring();
    return 0;
}
