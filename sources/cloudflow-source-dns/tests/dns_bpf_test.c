/* Behavioral correctness test for the DNS udp/53 + tcp/53 VLAN-aware cBPF
 * filter (WP-DNS06).
 *
 * A kernel-attached socket filter silently drops what it rejects, so it cannot
 * be exercised live in CI. Instead this test PROVES correctness in userspace:
 * it assembles build_dns_bpf_filter(), then runs a tiny cBPF interpreter --
 * implementing exactly the opcodes this filter uses -- over hand-built
 * Ethernet frames and asserts the accept/drop verdict for each. The verdict
 * table is printed so a reviewer can eyeball every case.
 *
 * Frames use documentation address space (RFC 5737 198.51.100.0/24 and RFC
 * 3849 2001:db8::/32), the same convention as the DHCP/decap fixture tests. */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdio.h>
#include <string.h>

#include <linux/filter.h>
#include <linux/if_ether.h> /* ETH_P_IP, ETH_P_IPV6, ETH_P_8021Q, ETH_P_ARP */

#include "dns_bpf.h"

/* --------------------------------------------------------------------------
 * Tiny cBPF interpreter: only the opcodes build_dns_bpf_filter() emits.
 * Returns the RET k value (0 == drop, non-zero == accept). An out-of-bounds
 * packet load returns 0 (drop), matching the kernel's classic-BPF semantics.
 * jt/jf/JA offsets are relative to the NEXT instruction; the for-loop's pc++
 * supplies that +1. */
static unsigned int bpf_run(const struct sock_filter *prog, int plen,
                            const unsigned char *pkt, unsigned int len)
{
    unsigned int A = 0, X = 0;
    int pc;

    for (pc = 0; pc >= 0 && pc < plen; pc++) {
        const struct sock_filter *ins = &prog[pc];
        unsigned int k = ins->k;

        switch (ins->code) {
        case BPF_LD | BPF_B | BPF_ABS:
            if (k + 1u > len)
                return 0;
            A = pkt[k];
            break;
        case BPF_LD | BPF_H | BPF_ABS:
            if (k + 2u > len)
                return 0;
            A = ((unsigned int)pkt[k] << 8) | pkt[k + 1];
            break;
        case BPF_LD | BPF_W | BPF_ABS:
            if (k + 4u > len)
                return 0;
            A = ((unsigned int)pkt[k] << 24) | ((unsigned int)pkt[k + 1] << 16) |
                ((unsigned int)pkt[k + 2] << 8) | pkt[k + 3];
            break;
        case BPF_LD | BPF_B | BPF_IND:
            if (X + k + 1u > len)
                return 0;
            A = pkt[X + k];
            break;
        case BPF_LD | BPF_H | BPF_IND:
            if (X + k + 2u > len)
                return 0;
            A = ((unsigned int)pkt[X + k] << 8) | pkt[X + k + 1];
            break;
        case BPF_LD | BPF_W | BPF_IND:
            if (X + k + 4u > len)
                return 0;
            A = ((unsigned int)pkt[X + k] << 24) | ((unsigned int)pkt[X + k + 1] << 16) |
                ((unsigned int)pkt[X + k + 2] << 8) | pkt[X + k + 3];
            break;
        case BPF_LD | BPF_IMM:
            A = k;
            break;
        case BPF_LDX | BPF_IMM:
            X = k;
            break;
        case BPF_LDX | BPF_B | BPF_MSH:
            if (k + 1u > len)
                return 0;
            X = 4u * (pkt[k] & 0x0fu);
            break;
        case BPF_JMP | BPF_JA:
            pc += (int)k;
            break;
        case BPF_JMP | BPF_JEQ | BPF_K:
            pc += (A == k) ? ins->jt : ins->jf;
            break;
        case BPF_JMP | BPF_JSET | BPF_K:
            pc += (A & k) ? ins->jt : ins->jf;
            break;
        case BPF_RET | BPF_K:
            return k;
        default:
            /* An opcode the DNS filter should never emit: fail loudly. */
            CU_FAIL("cBPF interpreter hit an unsupported opcode");
            return 0;
        }
    }

    /* Ran off the end without a RET: treat as drop. */
    return 0;
}

/* --------------------------------------------------------------------------
 * Frame builder: a growable byte buffer with big-endian append helpers.
 */
typedef struct {
    unsigned char buf[256];
    unsigned int len;
} frame_t;

static void f_reset(frame_t *f)
{
    memset(f->buf, 0, sizeof(f->buf));
    f->len = 0;
}

static void f_u8(frame_t *f, unsigned int v)
{
    f->buf[f->len++] = (unsigned char)(v & 0xffu);
}

static void f_u16(frame_t *f, unsigned int v)
{
    f_u8(f, v >> 8);
    f_u8(f, v);
}

/* Ethernet header; if vlan != 0, insert a single 802.1Q tag (TCI = VLAN 100)
 * so the real EtherType lands at offset 16 and the IP header at offset 18. */
static void put_eth(frame_t *f, unsigned int ethertype, int vlan)
{
    int i;

    for (i = 0; i < 6; i++)
        f_u8(f, 0xaa); /* dst MAC */
    for (i = 0; i < 6; i++)
        f_u8(f, 0xbb); /* src MAC */
    if (vlan) {
        f_u16(f, ETH_P_8021Q);
        f_u16(f, 0x0064); /* PCP/DEI 0, VLAN id 100 */
    }
    f_u16(f, ethertype);
}

/* IPv4 header (20 bytes, IHL=5). `frag` goes into the flags+fragment-offset
 * field (bytes 6-7): 0 for a normal datagram, non-zero low 13 bits for a
 * non-first fragment. */
static void put_ipv4(frame_t *f, unsigned int proto, unsigned int frag)
{
    f_u8(f, 0x45);      /* version 4, IHL 5 */
    f_u8(f, 0x00);      /* DSCP/ECN */
    f_u16(f, 0x0000);   /* total length (filter does not check) */
    f_u16(f, 0x1234);   /* identification */
    f_u16(f, frag);     /* flags + fragment offset */
    f_u8(f, 64);        /* TTL */
    f_u8(f, proto);     /* protocol */
    f_u16(f, 0x0000);   /* header checksum (filter does not check) */
    /* src 198.51.100.10, dst 198.51.100.20 (RFC 5737) */
    f_u8(f, 198); f_u8(f, 51); f_u8(f, 100); f_u8(f, 10);
    f_u8(f, 198); f_u8(f, 51); f_u8(f, 100); f_u8(f, 20);
}

/* IPv6 header (40 bytes). */
static void put_ipv6(frame_t *f, unsigned int next_header)
{
    int i;

    f_u8(f, 0x60);        /* version 6 */
    f_u8(f, 0x00);
    f_u16(f, 0x0000);     /* traffic class / flow label */
    f_u16(f, 0x0000);     /* payload length (filter does not check) */
    f_u8(f, next_header); /* next header */
    f_u8(f, 64);          /* hop limit */
    /* src 2001:db8::1 (RFC 3849) */
    f_u8(f, 0x20); f_u8(f, 0x01); f_u8(f, 0x0d); f_u8(f, 0xb8);
    for (i = 0; i < 11; i++)
        f_u8(f, 0x00);
    f_u8(f, 0x01);
    /* dst 2001:db8::2 */
    f_u8(f, 0x20); f_u8(f, 0x01); f_u8(f, 0x0d); f_u8(f, 0xb8);
    for (i = 0; i < 11; i++)
        f_u8(f, 0x00);
    f_u8(f, 0x02);
}

static void put_udp(frame_t *f, unsigned int sport, unsigned int dport)
{
    f_u16(f, sport);
    f_u16(f, dport);
    f_u16(f, 8);      /* length */
    f_u16(f, 0);      /* checksum */
}

static void put_tcp(frame_t *f, unsigned int sport, unsigned int dport)
{
    f_u16(f, sport);
    f_u16(f, dport);
    f_u16(f, 0x0000); f_u16(f, 0x0001); /* sequence number */
    f_u16(f, 0x0000); f_u16(f, 0x0000); /* acknowledgement number */
    f_u8(f, 0x50);    /* data offset 5 (20-byte header), reserved */
    f_u8(f, 0x02);    /* flags: SYN */
    f_u16(f, 0xffff); /* window */
    f_u16(f, 0x0000); /* checksum */
    f_u16(f, 0x0000); /* urgent pointer */
}

/* --------------------------------------------------------------------------
 * The verdict table.
 */
#define EPHEMERAL 40000u

typedef enum { L4_UDP, L4_TCP, L4_ICMP, L4_NONE } l4_t;
typedef enum { IPV4, IPV6, NONIP } ipver_t;

typedef struct {
    const char *name;
    ipver_t ipver;
    int vlan;
    l4_t l4;
    unsigned int sport;
    unsigned int dport;
    unsigned int frag;     /* IPv4 fragment field */
    unsigned int ethertype_override; /* for NONIP */
    int expect_accept;
} case_t;

static void build_frame(const case_t *c, frame_t *f)
{
    unsigned int proto;

    f_reset(f);

    if (c->ipver == NONIP) {
        put_eth(f, c->ethertype_override, c->vlan);
        /* a little payload so length-based loads are well-defined */
        f_u16(f, 0x0001);
        f_u16(f, 0x0800);
        return;
    }

    if (c->ipver == IPV4) {
        put_eth(f, ETH_P_IP, c->vlan);
        switch (c->l4) {
        case L4_UDP:  proto = 17; break;
        case L4_TCP:  proto = 6;  break;
        case L4_ICMP: proto = 1;  break;
        default:      proto = 0;  break;
        }
        put_ipv4(f, proto, c->frag);
    } else {
        put_eth(f, ETH_P_IPV6, c->vlan);
        switch (c->l4) {
        case L4_UDP:  proto = 17; break;
        case L4_TCP:  proto = 6;  break;
        case L4_ICMP: proto = 58; break; /* ICMPv6 */
        default:      proto = 0;  break;
        }
        put_ipv6(f, proto);
    }

    switch (c->l4) {
    case L4_UDP: put_udp(f, c->sport, c->dport); break;
    case L4_TCP: put_tcp(f, c->sport, c->dport); break;
    case L4_ICMP:
        /* minimal ICMP header bytes; no ports */
        f_u8(f, 8); f_u8(f, 0); f_u16(f, 0);
        break;
    default:
        break;
    }
}

static const case_t cases[] = {
    /* ---- ACCEPT: untagged ---- */
    { "IPv4/UDP dst 53",         IPV4, 0, L4_UDP, EPHEMERAL, 53,        0, 0, 1 },
    { "IPv4/UDP src 53",         IPV4, 0, L4_UDP, 53,        EPHEMERAL, 0, 0, 1 },
    { "IPv4/TCP dst 53",         IPV4, 0, L4_TCP, EPHEMERAL, 53,        0, 0, 1 },
    { "IPv4/TCP src 53",         IPV4, 0, L4_TCP, 53,        EPHEMERAL, 0, 0, 1 },
    { "IPv6/UDP dst 53",         IPV6, 0, L4_UDP, EPHEMERAL, 53,        0, 0, 1 },
    { "IPv6/TCP dst 53",         IPV6, 0, L4_TCP, EPHEMERAL, 53,        0, 0, 1 },
    /* ---- ACCEPT: single 802.1Q VLAN tag ---- */
    { "VLAN IPv4/UDP dst 53",    IPV4, 1, L4_UDP, EPHEMERAL, 53,        0, 0, 1 },
    { "VLAN IPv4/UDP src 53",    IPV4, 1, L4_UDP, 53,        EPHEMERAL, 0, 0, 1 },
    { "VLAN IPv4/TCP dst 53",    IPV4, 1, L4_TCP, EPHEMERAL, 53,        0, 0, 1 },
    { "VLAN IPv4/TCP src 53",    IPV4, 1, L4_TCP, 53,        EPHEMERAL, 0, 0, 1 },
    { "VLAN IPv6/UDP dst 53",    IPV6, 1, L4_UDP, EPHEMERAL, 53,        0, 0, 1 },
    { "VLAN IPv6/TCP dst 53",    IPV6, 1, L4_TCP, EPHEMERAL, 53,        0, 0, 1 },
    /* ---- DROP ---- */
    { "IPv4/UDP port 54",        IPV4, 0, L4_UDP, EPHEMERAL, 54,        0, 0, 0 },
    { "IPv4/TCP port 80",        IPV4, 0, L4_TCP, EPHEMERAL, 80,        0, 0, 0 },
    { "IPv4/ICMP",               IPV4, 0, L4_ICMP, 0,        0,         0, 0, 0 },
    { "IPv6/UDP port 54",        IPV6, 0, L4_UDP, EPHEMERAL, 54,        0, 0, 0 },
    { "ARP (non-IP ethertype)",  NONIP, 0, L4_NONE, 0,       0,         0, ETH_P_ARP, 0 },
    { "IPv4/UDP:53 non-first frag", IPV4, 0, L4_UDP, EPHEMERAL, 53,     0x0001, 0, 0 },
};

#define N_CASES ((int)(sizeof(cases) / sizeof(cases[0])))

static struct sock_filter g_prog[DNS_BPF_MAX_INSNS];
static int g_prog_n;

/* Assemble once and sanity-check the instruction count. */
static void test_dns_bpf_assembles(void)
{
    g_prog_n = build_dns_bpf_filter(g_prog, DNS_BPF_MAX_INSNS);

    CU_ASSERT_TRUE_FATAL(g_prog_n > 0);
    /* Comfortably within cf_bpf's CF_BPF_ASM_MAX_INSNS (96) and our buffer. */
    CU_ASSERT_TRUE(g_prog_n <= DNS_BPF_MAX_INSNS);
    CU_ASSERT_TRUE(g_prog_n <= 96);

    /* The convenience wrapper yields the same program + a matching length. */
    {
        struct sock_filter prog2[DNS_BPF_MAX_INSNS];
        const struct sock_filter *bpf = NULL;
        unsigned short bpf_len = 0;
        int n2 = build_dns_bpf_filter_config(prog2, DNS_BPF_MAX_INSNS, &bpf, &bpf_len);

        CU_ASSERT_EQUAL(n2, g_prog_n);
        CU_ASSERT_PTR_EQUAL(bpf, prog2);
        CU_ASSERT_EQUAL((int)bpf_len, n2);
    }

    fprintf(stderr, "\nDNS cBPF filter assembled: %d instructions\n", g_prog_n);
}

/* Run every crafted frame through the interpreter and assert its verdict,
 * printing the full accept/drop table. */
static void test_dns_bpf_verdicts(void)
{
    int i;

    CU_ASSERT_TRUE_FATAL(g_prog_n > 0);

    fprintf(stderr, "\n%-32s %-8s %-8s\n", "case", "expect", "got");
    fprintf(stderr, "%-32s %-8s %-8s\n", "--------------------------------",
            "------", "------");

    for (i = 0; i < N_CASES; i++) {
        frame_t f;
        unsigned int verdict;
        int accepted;

        build_frame(&cases[i], &f);
        verdict = bpf_run(g_prog, g_prog_n, f.buf, f.len);
        accepted = (verdict != 0);

        fprintf(stderr, "%-32s %-8s %-8s %s\n", cases[i].name,
                cases[i].expect_accept ? "ACCEPT" : "DROP",
                accepted ? "ACCEPT" : "DROP",
                accepted == cases[i].expect_accept ? "" : "  <== MISMATCH");

        CU_ASSERT_EQUAL(accepted, cases[i].expect_accept);
    }
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cloudflow-source-dns dns_bpf", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "DNS cBPF filter assembles within limits", test_dns_bpf_assembles) ||
        !CU_add_test(suite, "DNS cBPF filter accept/drop verdicts", test_dns_bpf_verdicts)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
