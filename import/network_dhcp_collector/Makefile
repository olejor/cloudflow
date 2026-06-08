CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2 -g
LDLIBS  :=

src   := src/main.c src/capture.c src/decode_v4.c src/decode_v6.c src/util.c
inc   := -Iinclude

dhcp_sniffer: $(src)
	$(CC) $(CFLAGS) $(inc) $^ -o $@ $(LDLIBS)

tests/%_test: tests/%_test.c src/decode_%_test.c src/util.c
	$(CC) $(CFLAGS) $(inc) $^ -o $@ $(LDLIBS)

.PHONY: test
test: tests/decode_v4_test tests/decode_v6_test
	@$(foreach t,$^,$t && echo "✔ $t passed";)
