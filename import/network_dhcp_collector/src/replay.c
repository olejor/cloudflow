/*
 * pcap_replay.c — offline reader that feeds Ethernet frames from a .pcap file
 *                  into the same packet_cb used by live capture.
 *
 * Public API:
 *     int cap_run_pcap(const char *path, packet_cb cb, void *userdata);
 *
 * Usage example in main.c:
 *     if (pcap_path)
 *         cap_run_pcap(pcap_path, packet_handler, NULL);
 */

#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>

/* ——— PCAP file structures ——— */
struct pcap_hdr {
    uint32_t magic;
    uint16_t ver_major;
    uint16_t ver_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_rec_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

#define PCAP_MAGIC_BE 0xd4c3b2a1u
#define PCAP_MAGIC_LE 0xa1b2c3d4u

/* endian‑flip helpers */
static uint16_t bswap16(uint16_t x) { return (x>>8) | (x<<8); }
static uint32_t bswap32(uint32_t x) {
    return (x>>24) | ((x>>8)&0xff00) | ((x<<8)&0xff0000) | (x<<24);
}

/* ———————————————————————————————————————————————— */
int cap_run_pcap(const char *path, packet_cb cb, void *ud)
{
    if (!path || !cb) {
        errno = EINVAL; return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    struct pcap_hdr gh;
    if (fread(&gh, 1, sizeof gh, fp) != sizeof gh) {
        fclose(fp); errno = EIO; return -1;
    }

    int swap = 0;
    if (gh.magic == PCAP_MAGIC_LE) {
        swap = 0;
    } else if (gh.magic == PCAP_MAGIC_BE) {
        swap = 1;
    } else {
        fprintf(stderr, "Unsupported pcap magic 0x%08x\n", gh.magic);
        fclose(fp); errno = EINVAL; return -1;
    }

    uint32_t linktype = swap ? bswap32(gh.network) : gh.network;
    if (linktype != 1 /* DLT_EN10MB */) {
        fprintf(stderr, "Only Ethernet PCAPs (linktype 1) supported, got %u\n", linktype);
        fclose(fp); errno = EPROTOTYPE; return -1;
    }

    uint32_t snaplen = swap ? bswap32(gh.snaplen) : gh.snaplen;
    uint8_t *buf = malloc(snaplen);
    if (!buf) { fclose(fp); return -1; }

    struct pcap_rec_hdr rh;
    while (fread(&rh, 1, sizeof rh, fp) == sizeof rh) {
        uint32_t incl = swap ? bswap32(rh.incl_len) : rh.incl_len;
        if (incl > snaplen) {
            fseek(fp, incl, SEEK_CUR); /* skip */
            continue;
        }
        if (fread(buf, 1, incl, fp) != incl)
            break;
        cb(buf, incl, ud);
    }

    free(buf);
    fclose(fp);
    return 0;
}
