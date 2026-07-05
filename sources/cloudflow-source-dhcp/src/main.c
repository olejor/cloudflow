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
#include "dhcp_bpf.h"
#include "formatter.h"
#include "source_stats.h"
#include "stats.h"

/* WP-11: the cloudflow-source-dhcp application. Wires the three-thread
 * pipeline (rx-reader | event-formatter | redis-producer) together, loads
 * config, installs signal handlers, runs the periodic stats loop on the main
 * thread, and shuts down in reverse pipeline order (reader first so the
 * queues drain), per docs/dhcp-source.md's WP-11 section. Lifecycle
 * modeled on a prior syslog-collector prototype. */

#ifndef CF_SOURCE_DHCP_VERSION
#define CF_SOURCE_DHCP_VERSION "0.1.0"
#endif

#define CF_STATS_LOOP_TICK_MS 200 /* how often the main loop wakes to re-check stop/interval */

/* --replay drain: after pcap_replay_file() returns, wait until both queues
 * are empty before stopping, bounded by this deadline so a stuck pipeline
 * cannot hang the process forever. M1's acceptance path. */
#define CF_REPLAY_DRAIN_DEADLINE_NS (30LL * 1000 * 1000 * 1000) /* 30s */
#define CF_REPLAY_DRAIN_POLL_NS (5LL * 1000 * 1000)             /* 5ms */

static void print_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s -c <config.yaml> [--replay <pcap>]\n"
            "       %s --version\n"
            "\n"
            "Options:\n"
            "  -c, --config <path>   YAML config (required unless --replay given alone)\n"
            "  --replay <pcap>       Replay a classic pcap through the pipeline, then\n"
            "                        drain the queues and exit (integration/M1 mode)\n"
            "  --version             Print version and exit\n"
            "  -h, --help            Print this help and exit\n"
            "\n"
            "Environment overrides: CF_REDIS_ENDPOINTS CF_INTERFACE CF_SOURCE_HOST\n",
            argv0, argv0);
}

int main(int argc, char *argv[])
{
    const char *config_path = NULL;
    const char *replay_path = NULL;
    cf_source_config_t *cfg = NULL;
    cf_source_stats_t stats;
    cf_redis_stats_t redis_stats;
    cf_queue_t q_pkt;   /* rx-reader -> formatter */
    cf_queue_t q_evt;   /* formatter -> redis-producer */
    int q_pkt_init = 0, q_evt_init = 0;
    int redis_started = 0, formatter_started = 0, rx_started = 0;
    const char **endpoints = NULL;
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
            printf("cloudflow-source-dhcp %s\n", CF_SOURCE_DHCP_VERSION);
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
         * redis endpoints/streams and queue sizing the pipeline needs even
         * when the input is a pcap. (--replay only swaps the input stage.) */
        fprintf(stderr, "error: -c <config> is required\n");
        print_usage(argv[0]);
        return 2;
    }

    cf_log_init("cloudflow-source-dhcp");

    cfg = cf_config_load(config_path);
    if (!cfg) {
        /* cf_config_load already logged a structured error. */
        return 1;
    }

    cf_stop_install_signal_handlers();

    memset(&stats, 0, sizeof(stats));
    memset(&redis_stats, 0, sizeof(redis_stats));

    /* Bounded SPSC queues, capacities from config. */
    if (cf_queue_init(&q_pkt, cfg->rx_to_formatter_capacity, sizeof(cf_packet_item_t)) != 0) {
        cf_log(CF_LOG_ERROR, "failed to init rx->formatter queue", NULL);
        exit_code = 1;
        goto cleanup;
    }
    q_pkt_init = 1;

    if (cf_queue_init(&q_evt, cfg->formatter_to_redis_capacity, sizeof(cf_event_item_t)) != 0) {
        cf_log(CF_LOG_ERROR, "failed to init formatter->redis queue", NULL);
        exit_code = 1;
        goto cleanup;
    }
    q_evt_init = 1;

    /* Build the const endpoints array the producer expects. */
    endpoints = calloc(cfg->redis_endpoint_count, sizeof(*endpoints));
    if (!endpoints) {
        cf_log(CF_LOG_ERROR, "out of memory", NULL);
        exit_code = 1;
        goto cleanup;
    }
    for (size_t i = 0; i < cfg->redis_endpoint_count; i++)
        endpoints[i] = cfg->redis_endpoints[i];

    /* redis-producer (downstream stage started first: it must be ready to
     * drain q_evt as soon as the formatter produces). */
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

    /* event-formatter. */
    {
        formatter_config_t fcfg;

        memset(&fcfg, 0, sizeof(fcfg));
        fcfg.source_host = source_host;
        fcfg.source_instance = cfg->service_name;
        fcfg.capture_interface = cfg->capture_interface;
        fcfg.observation_method = replay_path ? "pcap-replay" : "rxring";
        fcfg.in = &q_pkt;
        fcfg.out = &q_evt;
        fcfg.stats = &stats;
        fcfg.on_full = cfg->queues_on_full;

        if (formatter_start(&fcfg) != 0) {
            cf_log(CF_LOG_ERROR, "formatter_start failed", NULL);
            exit_code = 1;
            goto cleanup;
        }
        formatter_started = 1;
    }

    cf_log(CF_LOG_INFO, "cloudflow-source-dhcp starting",
           "mode", replay_path ? "replay" : "capture", "interface", cfg->capture_interface,
           "source_host", source_host, NULL);

    if (replay_path) {
        /* --- M1 replay path: synchronous input, then bounded drain. --- */
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

        /* Wait until both queues drain (formatter and producer catch up),
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

        cf_stats_report(&stats, &redis_stats, &q_pkt, &q_evt, cfg->stats_reset_on_report);
        /* Fall through to reverse-order shutdown; exit 0 on the happy path. */
    } else {
        /* --- live capture path. --- */
        cf_rx_reader_config_t rcfg;
        struct sock_filter dhcp_bpf[CF_BPF_ASM_MAX_INSNS];
        int dhcp_bpf_len;
        int64_t next_report_ns;

        /* Assemble the DHCP-specific cBPF filter (dhcp_bpf.c, built on the
         * shared cf_bpf primitives) and hand it to the generic capture loop,
         * which attaches it via SO_ATTACH_FILTER. */
        dhcp_bpf_len = build_dhcp_bpf_filter(dhcp_bpf, CF_BPF_ASM_MAX_INSNS);
        if (dhcp_bpf_len < 0) {
            cf_log(CF_LOG_ERROR, "failed to assemble DHCP BPF filter", NULL);
            exit_code = 1;
            goto cleanup;
        }

        memset(&rcfg, 0, sizeof(rcfg));
        rcfg.interface_name = cfg->capture_interface;
        rcfg.out = &q_pkt;
        rcfg.stats = &stats.rx;
        rcfg.on_full = cfg->queues_on_full;
        rcfg.copy_snaplen = cfg->capture_snaplen;
        rcfg.bpf = dhcp_bpf;
        rcfg.bpf_len = (unsigned short)dhcp_bpf_len;

        if (cf_rx_reader_start(&rcfg) != 0) {
            cf_log(CF_LOG_ERROR, "cf_rx_reader_start failed", NULL);
            exit_code = 1;
            goto cleanup;
        }
        rx_started = 1;

        /* Stats loop on the main thread: emit one line every
         * stats.interval_s until stop is notified. */
        next_report_ns = cf_now_mono_nano() + (int64_t)cfg->stats_interval_s * 1000000000LL;
        while (!cf_stop_notified()) {
            cf_sleep_ns((int64_t)CF_STATS_LOOP_TICK_MS * 1000000LL);
            if (cf_now_mono_nano() >= next_report_ns) {
                cf_stats_report(&stats, &redis_stats, &q_pkt, &q_evt,
                                cfg->stats_reset_on_report);
                next_report_ns += (int64_t)cfg->stats_interval_s * 1000000000LL;
            }
        }

        cf_log(CF_LOG_INFO, "stop requested, shutting down", NULL);
    }

cleanup:
    /* Reverse pipeline order: stop the input stage first so the formatter and
     * producer drain what is still queued (both stop() calls drain), then the
     * formatter, then the producer. */
    if (rx_started)
        cf_rx_reader_stop();
    if (formatter_started)
        formatter_stop();
    if (redis_started)
        cf_redis_producer_stop();

    /* Final stats line so the last counters (post-drain) are visible. */
    if (redis_started || formatter_started || rx_started)
        cf_stats_report(&stats, &redis_stats,
                        q_pkt_init ? &q_pkt : NULL, q_evt_init ? &q_evt : NULL,
                        cfg ? cfg->stats_reset_on_report : 0);

    if (q_evt_init)
        cf_queue_destroy(&q_evt);
    if (q_pkt_init)
        cf_queue_destroy(&q_pkt);

    free(endpoints);
    cf_config_free(cfg);

    /* Exit code: nonzero on a startup/replay error; otherwise the stop
     * reason. cf_stop_notified() is non-zero after a signal; treat a normal
     * signal-driven shutdown as success (exit 0), matching the WP-11
     * acceptance criterion "kill -TERM during replay exits 0". */
    return exit_code;
}
