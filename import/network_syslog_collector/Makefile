GIT_VERSION := $(shell git describe --dirty=+ 2>/dev/null || echo "unknown")
LAST_CHANGE := $(shell git log -n 1 --date=short | grep Date | tr -s " " | cut -d " " -f2)
CC ?= gcc

CFLAGS=-DVERSION='"$(GIT_VERSION)"' -DLAST_CHANGE='"$(LAST_CHANGE)"' \
       -Isrc -I/usr/local/include \
       -pthread \
       -MMD \
       -O2 -g -std=gnu11 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -march=native -Wall -Wextra -Werror


LDFLAGS=-L/usr/local/lib -Wl,-Bstatic -lhiredis -lhiredis_cluster -lyyjson -Wl,-Bdynamic -lpthread -z relro -z now -z noexecstack
LTO_FLAGS=-flto
SRC_DIR=src
BUILD_DIR=build
PROGRAM=logchewie
SOURCES=$(wildcard $(SRC_DIR)/*.c)
OBJECTS=$(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS=$(OBJECTS:.o=.d)
TARGET=$(BUILD_DIR)/$(PROGRAM)

# test targets
TESTS_DIR = tests
LOG_GENERATOR = log_generator
FILTER_UNIT_TEST = filter_unit_test
FILTER_FUZZ_TEST = filter_fuzz_test
QUEUE_UNIT_TEST = queue_unit_test


ifeq ($(shell id -u), 0)
  SUDO =
else
  SUDO = sudo
endif


all: $(TARGET)


$(BUILD_DIR):
	@mkdir -p $@

$(TARGET): $(OBJECTS)
	$(CC) $(LTO_FLAGS) $^ -o $@ $(LDFLAGS)
	$(SUDO) setcap cap_net_raw,cap_sys_nice=eip $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LTO_FLAGS) -c $< -o $@

-include $(DEPS)

log_generator: $(TESTS_DIR)/log_generator.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LTO_FLAGS) $^ -o $(BUILD_DIR)/$(LOG_GENERATOR)

filter_unit_test: $(TESTS_DIR)/filter_unit_test.c $(SRC_DIR)/filter.c $(SRC_DIR)/utils.c $(SRC_DIR)/stats.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DUNIT_TESTS -Itests $(LTO_FLAGS) $^ -o $(BUILD_DIR)/$(FILTER_UNIT_TEST) $(LDFLAGS) -lcunit

filter_fuzz_test: $(TESTS_DIR)/filter_fuzz_test.c $(SRC_DIR)/filter.c $(SRC_DIR)/utils.c $(SRC_DIR)/stats.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LTO_FLAGS) $^ -o $(BUILD_DIR)/$(FILTER_FUZZ_TEST) $(LDFLAGS)

queue_unit_test: $(TESTS_DIR)/queue_unit_test.c $(SRC_DIR)/queue.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LTO_FLAGS) $^ -o $(BUILD_DIR)/$(QUEUE_UNIT_TEST) $(LDFLAGS) -lcunit


cluster-start:
	$(SUDO) sysctl -w vm.overcommit_memory=1
	docker compose -f docker/compose.yml up --detach


cluster-stop:
	docker compose -f docker/compose.yml down --volumes


cluster-info:
	docker compose -f docker/compose.yml ps


cluster-stats:
	docker compose -f docker/compose.yml stats


help:
	@echo 'Build targets:'
	@echo '  all               - default target, builds logchewie'
	@echo '  logchewie         - build logchewie'
	@echo '  log_generator     - build log generator'
	@echo '  filter_unit_test  - build filter unit test'
	@echo '  filter_fuzz_test  - build filter fuzz test'
	@echo '  queue_unit_test   - queue unit test'
	@echo ''
	@echo 'Cluster targets:'
	@echo '  cluster-start     - start redis cluster and detach'
	@echo '  cluster-stop      - stop redis cluster'
	@echo '  cluster-info      - show runtime info on redis cluster'
	@echo '  cluster-stats     - show runtime stats for redis cluster'
	@echo ''
	@echo 'Other targets:'
	@echo '  clean             - remove build directory'

clean:
	rm -rf $(BUILD_DIR)


.PHONY: all cluster-start cluster-stop cluster-info cluster-stats help clean
