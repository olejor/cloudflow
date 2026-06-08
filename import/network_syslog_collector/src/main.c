#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "config.h"
#include "sync.h"
#include "redis.h"
#include "rx-ring.h"
#include "filter.h"
#include "stats.h"

struct config config = {
	.redis_servers = REDIS_SERVERS_DEFAULT,
	.redis_threads = REDIS_THREADS_DEFAULT,
};


int main(int argc, char *argv[])
{
	int ret;

	process_env(&config);
	process_args(argc, argv, &config);

	signal(SIGINT, stop_signal);

	ret = filter_init();
	if (ret)
		return 1;

	ret = redis_start();
	if (ret) {
		filter_cleanup();
		return 1;
	}

	ret = rx_ring_start();
	if (ret) {
		redis_stop();
		filter_cleanup();
		return 1;
	}

	stats_loop();

	rx_ring_stop();
	redis_stop();
	filter_cleanup();

	return stop_code_get();
}
