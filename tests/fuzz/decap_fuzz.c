/* tests/fuzz/decap_fuzz.c
 *
 * AFL-style fuzz harness for cf_decap_udp() (libs/cloudflow-packet). Reads
 * one frame -- either from the file named in argv[1] (the usual afl-fuzz
 * `-- ./decap_fuzz @@` invocation) or from stdin if no argument is given --
 * and calls cf_decap_udp() on it. The only property under test is "never
 * crashes, on any input, of any length"; the return code and populated
 * fields are not asserted here (that's what tests/unit/cf_decap_test.c is
 * for). See tests/fuzz/README.md for how to run this under AFL, and
 * a prior syslog-collector prototype's fuzzing harness and filter
 * fuzz test for the pattern
 * this is adapted from (read-only references, not modified).
 *
 * Not wired into `make test` or the top-level SUBDIRS -- per the WP-05
 * spec, this only needs to exist and build.
 */

#include <stdio.h>

#include "cf_decap.h"

/* Comfortably larger than any real frame (jumbo Ethernet included); AFL
 * truncates/generates inputs of arbitrary size, so this is just an upper
 * bound on how much of a huge input file we bother reading. */
#define MAX_FRAME_LEN 65536

static size_t read_frame(FILE *f, uint8_t *buf, size_t buf_cap)
{
    return fread(buf, 1, buf_cap, f);
}

int main(int argc, char **argv)
{
    static uint8_t frame[MAX_FRAME_LEN];
    size_t frame_len;
    cf_decap_udp_t out;
    FILE *f;

    if (argc >= 2) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror("fopen");
            return 1;
        }
    } else {
        f = stdin;
    }

    frame_len = read_frame(f, frame, sizeof(frame));

    if (f != stdin)
        fclose(f);

    (void)cf_decap_udp(frame, frame_len, &out);

    return 0;
}
