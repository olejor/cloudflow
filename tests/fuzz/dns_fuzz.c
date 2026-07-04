/* tests/fuzz/dns_fuzz.c
 *
 * AFL-style fuzz harness for cf_dns_parse() (libs/cloudflow-packet,
 * WP-DNS03). Reads one bare DNS message -- either from the file named in
 * argv[1] (the usual `afl-fuzz -- ./dns_fuzz @@` invocation) or from stdin
 * if no argument is given -- and calls cf_dns_parse() on it. The input is a
 * BARE DNS message: no UDP/TCP framing, no TCP 2-byte length prefix (the
 * caller strips that before cf_dns_parse ever sees the bytes; see
 * docs/dns-source.md, DNS-D1). The only property under test is "never
 * crashes / never leaks, on any input, of any length"; correctness of the
 * parsed fields is tests/unit's job. Every successfully parsed message is
 * packed and freed too, so a heap corruption bug that only manifests during
 * packing (e.g. from a malformed name/length silently producing an
 * inconsistent tree) is also caught, and running this harness under ASan
 * (see dns_fuzz_quick_check.sh) also exercises use-after-free/leak paths --
 * including the parser-warning list, which cf_dns_parse appends to and the
 * caller owns, so this harness takes and frees it to stay leak-clean.
 *
 * Same conventions as tests/fuzz/dhcpv4_fuzz.c / dhcpv6_fuzz.c / README.md
 * and import/network_syslog_collector/tests/Fuzzing.md (read-only
 * reference). Not wired into `make test` or the top-level SUBDIRS -- per the
 * WP-DNS09 spec, this only needs to exist and build; running it (under AFL
 * or the quick local sweep script) is a manual/local step, documented as
 * performed in the PR/task report.
 */

#include <stdio.h>
#include <stdlib.h>

#include "cf_dns.h"
#include "cf_parse_util.h"

/* Comfortably larger than any real DNS message (udp/53 or a single-segment
 * tcp/53 message); AFL truncates/generates inputs of arbitrary size, so this
 * is just an upper bound on how much of a huge input file we bother
 * reading. */
#define MAX_PAYLOAD_LEN 65536

static size_t read_payload(FILE *f, uint8_t *buf, size_t buf_cap)
{
    return fread(buf, 1, buf_cap, f);
}

int main(int argc, char **argv)
{
    static uint8_t payload[MAX_PAYLOAD_LEN];
    size_t payload_len;
    FILE *f;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t warnings;

    if (argc >= 2) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror("fopen");
            return 1;
        }
    } else {
        f = stdin;
    }

    payload_len = read_payload(f, payload, sizeof(payload));

    if (f != stdin)
        fclose(f);

    cf_warn_list_init(&warnings);

    if (cf_dns_parse(payload, payload_len, &msg, &warnings) == 1) {
        size_t packed_len = cloudflow__v1__dns_message__get_packed_size(msg);
        uint8_t *packed = malloc(packed_len);

        if (packed) {
            cloudflow__v1__dns_message__pack(msg, packed);
            free(packed);
        }
        cloudflow__v1__dns_message__free_unpacked(msg, NULL);
    }

    /* cf_dns_parse appends warnings to a caller-owned list; drain and free
     * them (each warning + the array itself) so the harness is leak-clean
     * under ASan regardless of whether the parse succeeded. */
    {
        size_t n_warn = 0;
        Cloudflow__V1__ParserWarning **warn_items = NULL;

        cf_warn_list_take(&warnings, &n_warn, &warn_items);
        for (size_t i = 0; i < n_warn; i++)
            cloudflow__v1__parser_warning__free_unpacked(warn_items[i], NULL);
        free(warn_items);
    }

    return 0;
}
