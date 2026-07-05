#define _GNU_SOURCE

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cf_log.h"
#include "cf_queue.h"
#include "cf_sync.h"
#include "cf_time.h"
#include "cf_redis_producer.h"

#include "cf_bpf.h"
#include "cf_pcap_replay.h"
#include "cf_rx_reader.h"
#include "config.h"
#include "dns_bpf.h"
#include "dns_stage.h"
#include "dns_source_stats.h"
#include "leg_classify.h"
#include "stats.h"

/* WP-DNS07: the cloudflow-source-dns application. Wires the three-thread DNS
 * pipeline (rx-reader | parse+correlate event stage | redis-producer)
 * together, loads config, installs signal handlers, runs the periodic stats
 * loop on the main thread, and shuts down in reverse pipeline order (reader
 * first so the queues drain), per docs/dns-source.md. Lifecycle mirrors the
 * DHCP source's main.c (sources/cloudflow-source-dhcp/src/main.c), swapping the
 * DHCP formatter for the DNS event stage and the DHCP BPF for the DNS BPF. */

#ifndef CF_SOURCE_DNS_VERSION
#define CF_SOURCE_DNS_VERSION "0.2.0"
#endif

#define CF_STATS_LOOP_TICK_MS 200 /* how often the main loop wakes to re-check stop/interval */

/* --replay drain: after pcap_replay_file() returns, wait until both queues are
 * empty before stopping, bounded by this deadline so a stuck pipeline cannot
 * hang the process forever. */
#define CF_REPLAY_DRAIN_DEADLINE_NS (30LL * 1000 * 1000 * 1000) /* 30s */
#define CF_REPLAY_DRAIN_POLL_NS (5LL * 1000 * 1000)             /* 5ms */

static void print_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s -c <config.yaml> [--replay <pcap>]\n"
            "       %s --version\n"
            "\n"
            "Options:\n"
            "  -c, --config <path>   YAML config (required, even with --replay)\n"
            "  --replay <pcap>       Replay a classic pcap through the pipeline, then\n"
            "                        drain the queues and exit (integration mode)\n"
            "  --version             Print version and exit\n"
            "  -h, --help            Print this help and exit\n"
            "\n"
            "Environment overrides: CF_REDIS_ENDPOINTS CF_INTERFACE CF_SOURCE_HOST\n",
            argv0, argv0);
}

/* Builds a cf_dns_addr_set_t from a config string list (DNS-D7). Every entry
 * that inet_pton rejects is logged and skipped. Returns a heap set (possibly
 * empty) on success, or NULL only on allocation failure. NOTE: the DNS-D7
 * "auto-derive local addresses from the capture interface" helper does not
 * exist yet in the capture library, so the local set is the configured list
 * only; this is documented in the README. */
static cf_dns_addr_set_t *build_addr_set(char *const *addrs, size_t count, const char *label)
{
    cf_dns_addr_set_t *set = cf_dns_addr_set_new();
    size_t i;

    if (!set) {
        cf_log(CF_LOG_ERROR, "out of memory building address set", "set", label, NULL);
        return NULL;
    }

    for (i = 0; i < count; i++) {
        if (!cf_dns_addr_set_add_str(set, addrs[i]))
            cf_log(CF_LOG_WARN, "config: ignoring malformed address", "set", label, "value",
                   addrs[i], NULL);
    }
    return set;
}

/* Builds the WP-DNS11a service-role map from the parsed dns.service_roles
 * groups: each address in a group is mapped to that group's label. An address
 * that inet_pton rejects is logged and skipped (never fatal). Returns a heap map
 * (possibly empty) on success, or NULL only on allocation failure. */
static cf_dns_role_map_t *build_role_map(const cf_dns_service_role_t *roles, size_t count)
{
    cf_dns_role_map_t *map = cf_dns_role_map_new();
    size_t i, j;

    if (!map) {
        cf_log(CF_LOG_ERROR, "out of memory building service-role map", NULL);
        return NULL;
    }

    for (i = 0; i < count; i++) {
        for (j = 0; j < roles[i].address_count; j++) {
            if (!cf_dns_role_map_add_str(map, roles[i].addresses[j], roles[i].label))
                cf_log(CF_LOG_WARN, "config: ignoring malformed service_role address",
                       "label", roles[i].label, "value", roles[i].addresses[j], NULL);
        }
    }
    return map;
}

int main(int argc, char *argv[])
{
    const char *config_path = NULL;
    const char *replay_path = NULL;
    cf_dns_config_t *cfg = NULL;
    cf_dns_source_stats_t stats;
    cf_redis_stats_t redis_stats;
    cf_queue_t q_pkt; /* rx-reader -> event stage */
    cf_queue_t q_evt; /* event stage -> redis-producer */
    int q_pkt_init = 0, q_evt_init = 0;
    int redis_started = 0, stage_started = 0, rx_started = 0;
    const char **endpoints = NULL;
    cf_dns_addr_set_t *local_addrs = NULL;
    cf_dns_addr_set_t *backend_addrs = NULL;
    cf_dns_role_map_t *role_map = NULL;
    char hostname[256];
    int exit_code = 0;

    static struct option long_options[] = {
        {"config", required_argument, NULL, 'c'},
        {"replay", required_argument, NULL, 'r'},
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int c;

    while ((c = getopt_long(argc, argv, "c:h", long_options, NULL)) != -1) {
        switch (c) {
        case 'c':
            config_path = optarg;
            break;
        case 'r':
            replay_path = optarg;
            break;
        case 'V':
            printf("cloudflow-source-dns %s\n", CF_SOURCE_DNS_VERSION);
            return 0;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!config_path) {
        /* -c is required in both live and --replay mode: the config supplies
         * redis endpoints/streams, queue sizing, and the correlation/classifier
         * knobs the pipeline needs even when the input is a pcap. (--replay only
         * swaps the input stage.) */
        fprintf(stderr, "error: -c <config> is required\n");
        print_usage(argv[0]);
        return 2;
    }

    cf_log_init("cloudflow-source-dns");

    cfg = cf_config_load(config_path);
    if (!cfg) {
        /* cf_config_load already logged a structured error. */
        return 1;
    }

    cf_stop_install_signal_handlers();

    memset(&stats, 0, sizeof(stats));
    memset(&redis_stats, 0, sizeof(redis_stats));

    /* Bounded SPSC queues, capacities from config. */
    if (cf_queue_init(&q_pkt, cfg->rx_to_stage_capacity, sizeof(cf_packet_item_t)) != 0) {
        cf_log(CF_LOG_ERROR, "failed to init rx->stage queue", NULL);
        exit_code = 1;
        goto cleanup;
    }
    q_pkt_init = 1;

    if (cf_queue_init(&q_evt, cfg->stage_to_redis_capacity, sizeof(cf_event_item_t)) != 0) {
        cf_log(CF_LOG_ERROR, "failed to init stage->redis queue", NULL);
        exit_code = 1;
        goto cleanup;
    }
    q_evt_init = 1;

    /* Build the leg-classifier address sets (DNS-D7) from config. */
    local_addrs = build_addr_set(cfg->dns_local_service_addresses,
                                 cfg->dns_local_service_address_count, "local_service_addresses");
    backend_addrs = build_addr_set(cfg->dns_backend_addresses, cfg->dns_backend_address_count,
                                   "backend_addresses");
    if (!local_addrs || !backend_addrs) {
        exit_code = 1;
        goto cleanup;
    }

    /* Build the WP-DNS11a service-role map (server-side address -> operator
     * label) from config. */
    role_map = build_role_map(cfg->dns_service_roles, cfg->dns_service_role_count);
    if (!role_map) {
        exit_code = 1;
        goto cleanup;
    }

    /* Build the const endpoints array the producer expects. */
    endpoints = calloc(cfg->redis_endpoint_count, sizeof(*endpoints));
    if (!endpoints) {
        cf_log(CF_LOG_ERROR, "out of memory", NULL);
        exit_code = 1;
        goto cleanup;
    }
    for (size_t i = 0; i < cfg->redis_endpoint_count; i++)
        endpoints[i] = cfg->redis_endpoints[i];

    /* redis-producer (downstream stage started first: it must be ready to drain
     * q_evt as soon as the event stage produces). Writes cloudflow:v1:wire:dns
     * -- the stream name comes from cf_stream_name(CF_STREAM_DNS) inside the
     * producer library; there is no per-instance override (DNS-D3). */
    {
        cf_redis_producer_config_t rcfg;

        memset(&rcfg, 0, sizeof(rcfg));
        rcfg.endpoints = endpoints;
        rcfg.endpoint_count = cfg->redis_endpoint_count;
        rcfg.maxlen_approx = cfg->redis_maxlen_approx;
        rcfg.pipeline_max = cfg->redis_xadd_batch_size;
        rcfg.flush_interval_ms = cfg->redis_xadd_flush_interval_ms;
        rcfg.in = &q_evt;
        rcfg.stats = &redis_stats;

        if (cf_redis_producer_start(&rcfg) != 0) {
            cf_log(CF_LOG_ERROR, "cf_redis_producer_start failed", NULL);
            exit_code = 1;
            goto cleanup;
        }
        redis_started = 1;
    }

    /* Resolve source_host: config value, else gethostname(). */
    const char *source_host = cfg->source_host;
    if (!source_host || source_host[0] == '\0') {
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            hostname[sizeof(hostname) - 1] = '\0';
            source_host = hostname;
        } else {
            source_host = "unknown";
        }
    }

    /* DNS event stage (parse + classify + correlate + sample + encode). */
    {
        dns_stage_config_t scfg;

        memset(&scfg, 0, sizeof(scfg));
        scfg.source_host = source_host;
        scfg.source_instance = cfg->service_name;
        scfg.capture_interface = cfg->capture_interface;
        scfg.observation_method = replay_path ? "pcap-replay" : "rxring";
        scfg.in = &q_pkt;
        scfg.out = &q_evt;
        scfg.stats = &stats;
        scfg.on_full = cfg->queues_on_full;
        scfg.correlator.capacity = cfg->dns_pending_table_capacity;
        scfg.correlator.query_timeout_nanos =
            (int64_t)cfg->dns_query_timeout_ms * 1000000LL;
        scfg.correlator.on_table_full = cfg->dns_on_table_full;
        scfg.local_addrs = local_addrs;
        scfg.backend_addrs = backend_addrs;
        scfg.role_map = role_map;
        scfg.emit_policy.mode = cfg->dns_emit_mode;
        scfg.emit_policy.sample_denominator = cfg->dns_sample_denominator;

        if (dns_stage_start(&scfg) != 0) {
            cf_log(CF_LOG_ERROR, "dns_stage_start failed", NULL);
            exit_code = 1;
            goto cleanup;
        }
        stage_started = 1;
    }

    cf_log(CF_LOG_INFO, "cloudflow-source-dns starting",
           "mode", replay_path ? "replay" : "capture", "interface", cfg->capture_interface,
           "source_host", source_host, NULL);

    if (replay_path) {
        /* --- replay path: synchronous input, then bounded drain. --- */
        long n;
        int64_t deadline;

        n = pcap_replay_file(replay_path, &q_pkt, &stats.rx, cfg->queues_on_full);
        if (n < 0) {
            cf_log(CF_LOG_ERROR, "pcap replay failed", "path", replay_path, NULL);
            exit_code = 1;
            goto cleanup;
        }

        {
            char nb[24];
            cf_log(CF_LOG_INFO, "pcap replay complete", "frames",
                   cf_log_u64(nb, sizeof(nb), (uint64_t)n), NULL);
        }

        /* Wait until both queues drain (the event stage and producer catch up),
         * bounded by CF_REPLAY_DRAIN_DEADLINE_NS. */
        deadline = cf_now_mono_nano() + CF_REPLAY_DRAIN_DEADLINE_NS;
        while (cf_now_mono_nano() < deadline) {
            if (cf_queue_length(&q_pkt) == 0 && cf_queue_length(&q_evt) == 0) {
                /* One extra grace pass: the item may be mid-flight inside the
                 * producer's in-flight pipeline (popped from q_evt but not yet
                 * XADD-flushed). Give the flush interval time to elapse. */
                cf_sleep_ns((int64_t)(cfg->redis_xadd_flush_interval_ms + 20) * 1000000LL);
                break;
            }
            if (cf_stop_notified())
                break;
            cf_sleep_ns(CF_REPLAY_DRAIN_POLL_NS);
        }

        cf_dns_stats_report(&stats, &redis_stats, &q_pkt, &q_evt, cfg->stats_reset_on_report);
        /* Fall through to reverse-order shutdown; exit 0 on the happy path. */
    } else {
        /* --- live capture path. --- */
        cf_rx_reader_config_t rcfg;
        struct sock_filter dns_bpf[DNS_BPF_MAX_INSNS];
        int dns_bpf_len;
        int64_t next_report_ns;

        /* Assemble the DNS-specific VLAN-aware cBPF filter (dns_bpf.c, built on
         * the shared cf_bpf primitives) and hand it to the generic capture loop,
         * which attaches it via SO_ATTACH_FILTER. */
        dns_bpf_len = build_dns_bpf_filter(dns_bpf, DNS_BPF_MAX_INSNS);
        if (dns_bpf_len < 0) {
            cf_log(CF_LOG_ERROR, "failed to assemble DNS BPF filter", NULL);
            exit_code = 1;
            goto cleanup;
        }

        memset(&rcfg, 0, sizeof(rcfg));
        rcfg.interface_name = cfg->capture_interface;
        rcfg.out = &q_pkt;
        rcfg.stats = &stats.rx;
        rcfg.on_full = cfg->queues_on_full;
        rcfg.copy_snaplen = cfg->capture_snaplen;
        rcfg.bpf = dns_bpf;
        rcfg.bpf_len = (unsigned short)dns_bpf_len;

        if (cf_rx_reader_start(&rcfg) != 0) {
            cf_log(CF_LOG_ERROR, "cf_rx_reader_start failed", NULL);
            exit_code = 1;
            goto cleanup;
        }
        rx_started = 1;

        /* Stats loop on the main thread: emit one line every stats.interval_s
         * until stop is notified. */
        next_report_ns = cf_now_mono_nano() + (int64_t)cfg->stats_interval_s * 1000000000LL;
        while (!cf_stop_notified()) {
            cf_sleep_ns((int64_t)CF_STATS_LOOP_TICK_MS * 1000000LL);
            if (cf_now_mono_nano() >= next_report_ns) {
                cf_dns_stats_report(&stats, &redis_stats, &q_pkt, &q_evt,
                                    cfg->stats_reset_on_report);
                next_report_ns += (int64_t)cfg->stats_interval_s * 1000000000LL;
            }
        }

        cf_log(CF_LOG_INFO, "stop requested, shutting down", NULL);
    }

cleanup:
    /* Reverse pipeline order: stop the input stage first so the event stage and
     * producer drain what is still queued (both stop() calls drain), then the
     * event stage (which drains pending queries as unanswered), then the
     * producer. */
    if (rx_started)
        cf_rx_reader_stop();
    if (stage_started)
        dns_stage_stop();
    if (redis_started)
        cf_redis_producer_stop();

    /* Final stats line so the last counters (post-drain) are visible. */
    if (redis_started || stage_started || rx_started)
        cf_dns_stats_report(&stats, &redis_stats, q_pkt_init ? &q_pkt : NULL,
                            q_evt_init ? &q_evt : NULL, cfg ? cfg->stats_reset_on_report : 0);

    if (q_evt_init)
        cf_queue_destroy(&q_evt);
    if (q_pkt_init)
        cf_queue_destroy(&q_pkt);

    cf_dns_addr_set_free(local_addrs);
    cf_dns_addr_set_free(backend_addrs);
    cf_dns_role_map_free(role_map);
    free(endpoints);
    cf_config_free(cfg);

    /* Exit code: nonzero on a startup/replay error; otherwise the stop reason.
     * A normal signal-driven shutdown is success (exit 0), matching the DHCP
     * source's "kill -TERM during replay exits 0" acceptance criterion. */
    return exit_code;
}
