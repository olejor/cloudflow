#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/filter.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include "config.h"
#include "sync.h"
#include "rx-ring.h"
#include "redis.h"
#include "queue.h"
#include "utils.h"
#include "filter.h"
#include "stats.h"


#define PFX "[rx-ring] "

struct ring {
	atomic_int fd;
	struct tpacket_req3 req;
	void *mem;
	size_t mem_size;
	struct iovec rd[RX_RING_BLOCK_NR];
} packet_rx_ring = {
	.req = {
		.tp_block_size = RX_RING_BLOCK_SIZE,
		.tp_block_nr = RX_RING_BLOCK_NR,
		.tp_frame_size = RX_RING_FRAME_SIZE,
		.tp_frame_nr = RX_RING_FRAME_NR,
	},
	.mem_size = RX_RING_BLOCK_SIZE * RX_RING_BLOCK_NR,
};

static pthread_t thread_id;

extern struct config config;
extern struct stats stats;


static int bind_fd_to_iface(int fd, const char *iface)
{
	int ret;
	struct ifreq ifr;
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = 0,
	};

	if (!iface) {
		printf(PFX "bound to all interfaces\n");
		return 0;
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);

	ret = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (ret < 0) {
		fprintf(stderr, PFX "ioctl() failed: %m\n");
		return 1;
	}

	sa.sll_ifindex = ifr.ifr_ifindex;

	ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, PFX "bind() failed: %m\n");
		return 1;
	}

	printf(PFX "bound to %s\n", iface);

	return 0;
}

static int set_bpf_filter(int fd)
{
	int ret;
	struct sock_filter bpf_filter[] = {
		/*
		 * accept IPv4 and IPv6 unfragmented UDP packets with dst port 514
		 *
		 * based on:
		 * tcpdump -dd '((ip and udp dst port 514 and (ip[6] & 0x1fff = 0)) or (ip6 and udp dst port 514))'
		 */
		{ 0x28,  0,  0, 0x0000000c }, /* load EtherType field from Ethernet header */
		{ 0x15,  0,  7, 0x00000800 }, /* if IPv4 continue else skip 7 instructions */
		{ 0x30,  0,  0, 0x00000017 }, /* load IPv4 protocol field */
		{ 0x15,  0, 11, 0x00000011 }, /* if UDP continue else skip 11 instructions */
		{ 0x28,  0,  0, 0x00000014 }, /* load IPv4 fragment offset field */
		{ 0x45,  9,  0, 0x00001fff }, /* if non zero skip 9 instructions else continue */
		{ 0xb1,  0,  0, 0x0000000e }, /* adjust the offset to start of the UDP header */
		{ 0x48,  0,  0, 0x00000010 }, /* load UDP dst port */
		{ 0x15,  5,  6, 0x00000202 }, /* if UDP dst port is 514 skip 5 instructions else skip 6 instructions */
		{ 0x15,  0,  5, 0x000086dd }, /* if IPv6 continue else skip 5 instructions */
		{ 0x30,  0,  0, 0x00000014 }, /* load IPv6 protocol field */
		{ 0x15,  0,  3, 0x00000011 }, /* if UDP continue else skip 3 instructions */
		{ 0x28,  0,  0, 0x00000038 }, /* load UDP dst port */
		{ 0x15,  0,  1, 0x00000202 }, /* if UDP dst port is 514 continue else skip 1 instruction */
		{ 0x06,  0,  0, 0x00040000 }, /* accept the packet */
		{ 0x06,  0,  0, 0x00000000 }, /* drop the packet */
	};
	struct sock_fprog bpf_prog = {
	    .filter = bpf_filter,
	    .len = ARRAY_SIZE(bpf_filter),
	};

	ret = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog));
	if (ret < 0) {
		fprintf(stderr, PFX "setsockopt() SO_ATTACH_FILTER failed: %m\n");
		return 1;
	}

	printf(PFX "BPF UDP filter attached\n");

	return 0;
}

static int set_packet_version(int fd)
{
	int ret;
	int pv = TPACKET_V3;

	ret = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &pv, sizeof(pv));
	if (ret < 0) {
		fprintf(stderr, PFX "setsockopt() PACKET_VERSION failed: %m\n");
		return 1;
	}

	return 0;
}

static int set_packet_rx_ring(int fd, struct tpacket_req3 *req)
{
	int ret;

	ret = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *)req, sizeof(*req));
	if (ret < 0) {
		fprintf(stderr, PFX "setsockopt() PACKET_RX_RING failed: %m\n");
		return 1;
	}

	return 0;
}

static int mmap_rx_ring(int fd, struct ring *rx_ring)
{
	void *mem;

	mem = mmap(0, rx_ring->mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		fprintf(stderr, PFX "mmap() of %ld bytes failed: %m\n", rx_ring->mem_size);
		return 1;
	}

	printf(PFX "mmap %ld kB @ %p\n", rx_ring->mem_size / 1024, mem);

	rx_ring->mem = mem;

	for (int i = 0; i < ARRAY_SIZE(rx_ring->rd); i++) {
		rx_ring->rd[i].iov_base = mem + (i * RX_RING_BLOCK_SIZE);
		rx_ring->rd[i].iov_len = RX_RING_BLOCK_SIZE;

		printf(PFX "iov[%d] %ld kB @ %p\n", i, rx_ring->rd[i].iov_len / 1024, rx_ring->rd[i].iov_base);
	}


	return 0;
}

static int rx_ring_open(const char *iface, struct ring *rx_ring)
{
	int ret;
	int fd;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		fprintf(stderr, PFX "socket() failed: %m\n");
		return 1;
	}

	rx_ring->fd = fd;

	ret = bind_fd_to_iface(fd, iface);
	if (ret)
		goto err;

	ret = set_bpf_filter(fd);
	if (ret)
		goto err;

	ret = set_packet_version(fd);
	if (ret < 0)
		goto err;

	ret = set_packet_rx_ring(fd, &rx_ring->req);
	if (ret < 0)
		goto err;

	ret = mmap_rx_ring(fd, rx_ring);
	if (ret < 0)
		goto err;

	return 0;

err:
	close(fd);
	return 1;
}

static int rx_ring_close(struct ring *rx_ring)
{
	int ret;

	ret = munmap(rx_ring->mem, rx_ring->mem_size);
	if (ret) {
		fprintf(stderr, PFX "munmap() failed: %m\n");
		return 1;
	}

	ret = close(rx_ring->fd);
	if (ret) {
		fprintf(stderr, PFX "close() failed: %m\n");
		return 1;
	}

	memset(rx_ring, 0x00, sizeof(*rx_ring));

	return 0;
}

static inline int block_is_ready(const struct tpacket_block_desc *block)
{
	return block->hdr.bh1.block_status & TP_STATUS_USER;
}

static inline void block_mark_done(struct tpacket_block_desc *block)
{
	block->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

static inline double tp3_ts_to_double(const struct tpacket3_hdr *packet)
{
	return packet->tp_sec + (double)packet->tp_nsec / (1000 * 1000 * 1000);
}

static void handle_packet(const struct tpacket3_hdr *packet)
{
	const struct ethhdr *eth = (const struct ethhdr *)((const char *)packet + packet->tp_mac);
	uint16_t protocol = ntohs(eth->h_proto);
	const struct iphdr *ip;
	const struct ipv6hdr *ipv6;
	const struct udphdr *udp;
	const struct in_addr *source_ipv4addr;
	const struct in6_addr *source_ipv6addr;
	const char *payload;
	size_t payload_len;
	uint8_t filter_match;

	/*
	 * We expect only packets filtered with BPF here.
	 */
	if (protocol == ETH_P_IP) {
		ip = (const struct iphdr *)((const char *)eth + ETH_HLEN);
		ASSERT(ip->protocol == IPPROTO_UDP);
		udp = (const struct udphdr *)((const char *)ip + ip->ihl * 4);
		source_ipv4addr = (const struct in_addr *)&ip->saddr;
		source_ipv6addr = NULL;
	} else if (protocol == ETH_P_IPV6) {
		ipv6 = (const struct ipv6hdr *)((const char *)eth + ETH_HLEN);
		ASSERT(ipv6->nexthdr == IPPROTO_UDP);
		udp = (const struct udphdr *)((const char *)ipv6 + sizeof(struct ipv6hdr));
		source_ipv4addr = NULL;
		source_ipv6addr = &ipv6->saddr;
	} else {
		ASSERT(0);
		return;
	}

	payload_len = ntohs(udp->len) - sizeof(struct udphdr);
	if (payload_len == 0)
		return;

	if (payload_len > QUEUE_MESSAGE_SIZE)
		payload_len = QUEUE_MESSAGE_SIZE - 1;

	ATOMIC_ADD(stats.rx_ring.bytes, payload_len);

	payload = (const char *)udp + sizeof(struct udphdr);
	filter_match = filter_match_rules(payload, payload_len, source_ipv4addr, source_ipv6addr);
	if (filter_match) {
		int ret;
		struct queue_element_header hdr = {
			.redis = {
				.stream = filter_match,
			},
		};

		hdr.timestamp = tp3_ts_to_double(packet);

		if (protocol == ETH_P_IP) {
			hdr.host.addr.ip4_addr.s_addr = ip->saddr;
		} else {
			hdr.host.ip6 = 1;
			hdr.host.addr.ip6_addr = ipv6->saddr;
		}

		ret = redis_queue_push(&hdr, payload, payload_len);
		if (ret)
			ATOMIC_INC(stats.rx_ring.overflow);
	}
}

static void block_walk(const struct tpacket_block_desc *block)
{
	const struct tpacket3_hdr *packet;

	packet = (const struct tpacket3_hdr *)((const char *)block + block->hdr.bh1.offset_to_first_pkt);

	for (int i = 0; i < (int)block->hdr.bh1.num_pkts; i++) {
		handle_packet(packet);

		packet = (const struct tpacket3_hdr *)((const char *)packet + packet->tp_next_offset);
	}
}

void read_rx_ring_packet_stats(void)
{
	int ret;
	struct tpacket_stats_v3 stats_v3;
	socklen_t len = sizeof(stats_v3);

	ret = getsockopt(packet_rx_ring.fd, SOL_PACKET, PACKET_STATISTICS, &stats_v3, &len);
	if (ret < 0) {
		fprintf(stderr, PFX "getsockopt() failed: %m\n");
		return;
	}

	/* called from stats context so no need for atomics */
	stats.rx_ring.tp_packets = stats_v3.tp_packets;
	stats.rx_ring.tp_drops = stats_v3.tp_drops;
	stats.rx_ring.tp_freeze_q_cnt = stats_v3.tp_freeze_q_cnt;
}

static int rx_ring_watch(struct ring *rx_ring)
{
	int ret;
	int epollfd;
	struct epoll_event ev;
	struct epoll_event events[1];

	ret = rx_ring_open(config.interface, rx_ring);
	if (ret)
		return 1;

	epollfd = epoll_create1(0);
	if (epollfd < 0) {
		fprintf(stderr, PFX "epoll_create1() failed: %m\n");
		rx_ring_close(rx_ring);
		return 1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = rx_ring->fd;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, rx_ring->fd, &ev);
	if (ret) {
		fprintf(stderr, PFX "epoll_ctl() failed: %m\n");
		close(epollfd);
		rx_ring_close(rx_ring);
		return 1;
	}

	while (!stop_notified()) {
		int nfds;
		int timeout_ms = 1000;

		nfds = epoll_wait(epollfd, events, ARRAY_SIZE(events), timeout_ms);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;

			fprintf(stderr, PFX "epoll_wait() failed: %m\n");
			ret = 1;
			break;
		}

		if (nfds == 0)
			continue;

		if (events[0].data.fd != rx_ring->fd)
			continue;

		for (int i = 0; i < RX_RING_BLOCK_NR; i++) {
			struct tpacket_block_desc *block = rx_ring->rd[i].iov_base;

			if (!block_is_ready(block))
				continue;

			block_walk(block);

			block_mark_done(block);
		}
	}

	close(epollfd);

	rx_ring_close(rx_ring);

	return ret;
}

static void *rx_ring_thread(void *arg)
{
	int ret;
	struct sched_param sc = {
		.sched_priority = 32,
	};

	(void)arg;

	pthread_setname_np(pthread_self(), "rx-ring");

	/*
	 * run rx-ring thread at higher priority so that it has enough CPU time
	 * to read rx ring on time and not drop frames at high bitrate
	 */
	ret = sched_setscheduler(0, SCHED_FIFO, &sc);
	if (ret) {
		fprintf(stderr, PFX "failed to set SCHED_FIFO %d priority\n", sc.sched_priority);
		goto err;
	}

	printf(PFX "thread started\n");

	ret = rx_ring_watch(&packet_rx_ring);

	printf(PFX "thread stopped\n");

err:
	stop_notify(ret);

	return NULL;
}

int rx_ring_start(void)
{
	int ret;

	ret = pthread_create(&thread_id, NULL, rx_ring_thread, NULL);
	if (ret)
		fprintf(stderr, PFX "ptrhead_create() failed: %s\n", strerror(ret));

	return ret;
}

int rx_ring_stop(void)
{
	return pthread_join(thread_id, NULL);
}
