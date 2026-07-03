# Fuzzing cf_decap_udp()

`decap_fuzz.c` is an AFL-style harness: it reads one frame (from the file
named in `argv[1]`, or stdin if no argument is given) and calls
`cf_decap_udp()` on it. Not wired into `make test` or the top-level
`SUBDIRS` -- it only needs to build; running it under AFL is a manual local
step. Same conventions as
`import/network_syslog_collector/tests/Fuzzing.md`.

Build the harness (plain gcc, not the hardened toolchain):

```sh
make -C libs/cloudflow-packet all   # build/libcloudflow-packet.a
make -C tests/fuzz all              # tests/fuzz/decap_fuzz
```

Run it once against a single file to sanity-check it (exit code 0, no
crash):

```sh
./tests/fuzz/decap_fuzz some_frame.bin
```

To fuzz with AFL, rebuild with the instrumenting compiler and run
`afl-fuzz` against a small seed corpus (e.g. the raw bytes of the frames
built in `tests/unit/cf_decap_test.c`):

```sh
make -C tests/fuzz clean
make -C tests/fuzz CC=afl-gcc all

mkdir -p tests/fuzz/testcases tests/fuzz/findings
# seed with a couple of plausible frames, e.g. an untagged IPv4/UDP frame
# and a QinQ IPv6/UDP frame dumped to disk from the unit test builders.

timeout 10m afl-fuzz -i tests/fuzz/testcases -o tests/fuzz/findings \
    -- ./tests/fuzz/decap_fuzz @@
```
