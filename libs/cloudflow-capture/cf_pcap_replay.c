#include "cf_pcap_replay.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cf_log.h"
#include "cf_stats.h"
#include "cloudflow.h"
#include "cf_rx_stats.h" /* CF_PACKET_FLAG_TRUNCATED */

/* ------------------------------------------------------------------------
 * Classic pcap file structures: magic detection/byte-swap, pcapng
 * rejection, the nanosecond-magic variants, and truncation/flag handling
 * to match cf_packet_item_t and cf_rx_reader.c's behavior. */

struct pcap_file_hdr {
    uint32_t magic;
    uint16_t ver_major;
    uint16_t ver_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_rec_hdr {
    uint32_t ts_sec;
    uint32_t ts_frac; /* microseconds, or nanoseconds for the nsec magic */
    uint32_t incl_len;
    uint32_t orig_len;
};

#define PCAP_MAGIC_USEC_LE 0xa1b2c3d4u
#define PCAP_MAGIC_USEC_BE 0xd4c3b2a1u
#define PCAP_MAGIC_NSEC_LE 0xa1b23c4du /* libpcap's own nanosecond-resolution magic */
#define PCAP_MAGIC_NSEC_BE 0x4d3cb2a1u
#define PCAP_MAGIC_NSEC_ALT 0xa3b4c3d4u /* nanosecond variant */
#define PCAPNG_MAGIC 0x0a0d0d0au

#define DLT_EN10MB 1u

/* Frames larger than this are treated as a corrupt/malicious file rather
 * than trusted at face value: a legitimate classic-pcap capture's snaplen
 * essentially never exceeds a few hundred KiB, and the alternative is
 * trusting a 32-bit incl_len straight from the file to size a read. */
#define PCAP_REPLAY_MAX_INCL_LEN (16u * 1024u * 1024u)

static uint32_t bswap32(uint32_t x)
{
    return (x >> 24) | ((x >> 8) & 0xff00u) | ((x << 8) & 0xff0000u) | (x << 24);
}

long pcap_replay_file(const char *path, cf_queue_t *out, cf_rx_stats_t *stats,
                       cf_queue_full_policy_t on_full)
{
    FILE *fp;
    struct pcap_file_hdr fh;
    int swap;
    int nsec;
    uint32_t linktype;
    struct pcap_rec_hdr rh;
    long frame_count = 0;

    if (!path || !out) {
        cf_log(CF_LOG_ERROR, "pcap_replay_file: invalid arguments", NULL);
        return -1;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        cf_log(CF_LOG_ERROR, "pcap_replay_file: fopen failed", "path", path,
               "error", strerror(errno), NULL);
        return -1;
    }

    if (fread(&fh, 1, sizeof(fh), fp) != sizeof(fh)) {
        cf_log(CF_LOG_ERROR, "pcap_replay_file: short read on file header", "path", path, NULL);
        fclose(fp);
        return -1;
    }

    if (fh.magic == PCAPNG_MAGIC) {
        cf_log(CF_LOG_ERROR, "pcap_replay_file: pcapng is not supported, only classic pcap",
               "path", path, NULL);
        fclose(fp);
        return -1;
    }

    switch (fh.magic) {
    case PCAP_MAGIC_USEC_LE:
        swap = 0;
        nsec = 0;
        break;
    case PCAP_MAGIC_USEC_BE:
        swap = 1;
        nsec = 0;
        break;
    case PCAP_MAGIC_NSEC_LE:
        swap = 0;
        nsec = 1;
        break;
    case PCAP_MAGIC_NSEC_BE:
        swap = 1;
        nsec = 1;
        break;
    case PCAP_MAGIC_NSEC_ALT:
        swap = 0;
        nsec = 1;
        break;
    default:
        cf_log(CF_LOG_ERROR, "pcap_replay_file: unsupported pcap magic", "path", path, NULL);
        fclose(fp);
        return -1;
    }

    linktype = swap ? bswap32(fh.network) : fh.network;
    if (linktype != DLT_EN10MB) {
        cf_log(CF_LOG_ERROR, "pcap_replay_file: only DLT_EN10MB (Ethernet) pcaps are supported",
               "path", path, NULL);
        fclose(fp);
        return -1;
    }

    while (fread(&rh, 1, sizeof(rh), fp) == sizeof(rh)) {
        cf_packet_item_t item;
        uint32_t ts_sec = swap ? bswap32(rh.ts_sec) : rh.ts_sec;
        uint32_t ts_frac = swap ? bswap32(rh.ts_frac) : rh.ts_frac;
        uint32_t incl_len = swap ? bswap32(rh.incl_len) : rh.incl_len;
        uint32_t orig_len = swap ? bswap32(rh.orig_len) : rh.orig_len;
        uint32_t copy_len;

        if (incl_len > PCAP_REPLAY_MAX_INCL_LEN) {
            cf_log(CF_LOG_ERROR, "pcap_replay_file: implausible record length, stopping",
                   "path", path, NULL);
            fclose(fp);
            return -1;
        }

        memset(&item, 0, sizeof(item));
        item.observed_time_unix_nano =
            (int64_t)ts_sec * 1000000000LL + (int64_t)ts_frac * (nsec ? 1LL : 1000LL);
        item.packet_len = orig_len;

        copy_len = incl_len;
        if (copy_len > CLOUDFLOW_PACKET_MAX_SIZE) {
            copy_len = CLOUDFLOW_PACKET_MAX_SIZE;
            item.flags |= CF_PACKET_FLAG_TRUNCATED;
        }
        item.captured_len = copy_len;

        if (fread(item.data, 1, copy_len, fp) != copy_len) {
            cf_log(CF_LOG_ERROR, "pcap_replay_file: short read on record data", "path", path, NULL);
            fclose(fp);
            return -1;
        }

        /* If the ring truncated the copy, the file still has the rest of
         * this record's bytes to skip before the next record header. */
        if (incl_len > copy_len && fseek(fp, (long)(incl_len - copy_len), SEEK_CUR) != 0) {
            cf_log(CF_LOG_ERROR, "pcap_replay_file: seek past truncated record failed",
                   "path", path, NULL);
            fclose(fp);
            return -1;
        }

        frame_count++;

        if (stats) {
            CF_ATOMIC_INC(stats->packets_received_total);
            CF_ATOMIC_ADD(stats->rx_bytes_copied_total, (unsigned long)copy_len);
            if (item.flags & CF_PACKET_FLAG_TRUNCATED)
                CF_ATOMIC_INC(stats->packets_truncated_total);
        }

        (void)cf_queue_push_policy(out, &item, sizeof(item), on_full,
                                    stats ? &stats->rx_queue_drop_total : NULL);
    }

    fclose(fp);

    return frame_count;
}
