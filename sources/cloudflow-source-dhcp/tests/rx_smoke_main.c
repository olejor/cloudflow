/* rx-smoke: manual live-capture harness for the WP-08 acceptance criterion
 * "run with CAP_NET_RAW on a veth pair, inject DHCP + non-DHCP traffic with
 * scapy, verify only DHCP arrives and kernel stats report the filtering."
 * Not a CUnit test (needs a real interface + CAP_NET_RAW/root, unavailable
 * in an ordinary build/CI environment) -- see README.md's "Manual veth
 * capture test" section for the exact procedure this binary is part of.
 *
 * Usage: rx-smoke <interface> <seconds>
 *
 * Runs rx_reader against <interface> for <seconds>, then prints every
 * queued cf_packet_item_t (so the caller can confirm only DHCP frames were
 * queued) and the final stats snapshot (packets_received_total,
 * packets_dropped_total, rx_queue_drop_total, packets_truncated_total,
 * rx_queue_depth), then exits 0. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_log.h"
#include "cf_queue.h"
#include "cf_stats.h"
#include "cf_time.h"
#include "cloudflow.h"
#include "rx_reader.h"
#include "source_stats.h"

#define SMOKE_QUEUE_CAPACITY 256

int main(int argc, char **argv)
{
    cf_queue_t q;
    cf_source_stats_t stats;
    rx_reader_config_t cfg;
    int seconds;
    cf_packet_item_t item;
    int queued = 0;
    char buf[32];

    if (argc != 3) {
        fprintf(stderr, "usage: %s <interface> <seconds>\n", argv[0]);
        return 2;
    }

    cf_log_init("rx-smoke");

    seconds = atoi(argv[2]);
    if (seconds <= 0)
        seconds = 5;

    if (cf_queue_init(&q, SMOKE_QUEUE_CAPACITY, sizeof(cf_packet_item_t)) != 0) {
        fprintf(stderr, "cf_queue_init failed\n");
        return 1;
    }

    memset(&stats, 0, sizeof(stats));

    cfg.interface_name = argv[1];
    cfg.block_size = 0;  /* defaults */
    cfg.block_count = 0;
    cfg.frame_size = 0;
    cfg.out = &q;
    cfg.stats = &stats;
    cfg.on_full = CF_ONFULL_DROP_NEWEST;

    if (rx_reader_start(&cfg) != 0) {
        fprintf(stderr, "rx_reader_start failed (need CAP_NET_RAW / root?)\n");
        cf_queue_destroy(&q);
        return 1;
    }

    printf("rx-smoke: capturing on %s for %d s...\n", argv[1], seconds);
    cf_sleep_ns((int64_t)seconds * 1000000000LL);

    rx_reader_stop();

    while (cf_queue_pop(&q, &item) == 0) {
        queued++;
        printf("packet[%d]: observed_time_unix_nano=%s packet_len=%u captured_len=%u flags=0x%x"
               " first_bytes=%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x eth=%02x%02x\n",
               queued, cf_log_i64(buf, sizeof(buf), item.observed_time_unix_nano), item.packet_len,
               item.captured_len, item.flags, item.data[0], item.data[1], item.data[2], item.data[3],
               item.data[4], item.data[5], item.data[6], item.data[7], item.data[8], item.data[9],
               item.data[10], item.data[11], item.data[12], item.data[13]);
    }

    printf("rx-smoke: queued_packets=%d\n", queued);
    printf("rx-smoke: stats packets_received_total=%lu packets_dropped_total=%lu "
           "rx_queue_drop_total=%lu packets_truncated_total=%lu rx_queue_depth=%lu\n",
           CF_ATOMIC_READ(stats.packets_received_total), CF_ATOMIC_READ(stats.packets_dropped_total),
           CF_ATOMIC_READ(stats.rx_queue_drop_total), CF_ATOMIC_READ(stats.packets_truncated_total),
           CF_ATOMIC_READ(stats.rx_queue_depth));

    cf_queue_destroy(&q);

    return 0;
}
