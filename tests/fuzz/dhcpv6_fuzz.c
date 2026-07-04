/* tests/fuzz/dhcpv6_fuzz.c
 *
 * AFL-style fuzz harness for cf_dhcpv6_parse() (libs/cloudflow-packet,
 * WP-07). Reads one DHCPv6 payload -- either from the file named in
 * argv[1] (the usual `afl-fuzz -- ./dhcpv6_fuzz @@` invocation) or from
 * stdin if no argument is given -- and calls cf_dhcpv6_parse() on it. The
 * only property under test is "never crashes, on any input, of any
 * length"; correctness of the parsed fields is
 * tests/unit/cf_dhcpv6_test.c's job. Every successfully parsed event is
 * packed and freed too, so a heap corruption bug that only manifests
 * during packing (e.g. from a malformed length silently producing an
 * inconsistent tree) is also caught, and running this harness under ASan
 * (see dhcpv6_fuzz_quick_check.sh) also exercises use-after-free/leak
 * paths.
 *
 * Same conventions as tests/fuzz/dhcpv4_fuzz.c / README.md and
 * a prior syslog-collector prototype's fuzzing harness (read-only reference).
 * Not wired into `make test` or the top-level SUBDIRS -- per the WP-07
 * spec, this only needs to exist and build; running it (under AFL or the
 * quick local sweep script) is a manual/local step, documented as
 * performed in the PR/task report.
 */

#include <stdio.h>
#include <stdlib.h>

#include "cf_dhcpv6.h"

/* Comfortably larger than any real DHCPv6 payload; AFL truncates/generates
 * inputs of arbitrary size, so this is just an upper bound on how much of a
 * huge input file we bother reading. */
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
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev;

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

    ev = cf_dhcpv6_parse(payload, payload_len, &event_type);
    if (ev) {
        size_t packed_len = cloudflow__v1__dhcp_v6_packet_event__get_packed_size(ev);
        uint8_t *packed = malloc(packed_len);

        if (packed) {
            cloudflow__v1__dhcp_v6_packet_event__pack(ev, packed);
            free(packed);
        }
        cf_dhcpv6_event_free(ev);
    }

    return 0;
}
