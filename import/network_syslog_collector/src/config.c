#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "config.h"

#ifndef LAST_CHANGE
#define LAST_CHANGE "?"
#endif

#ifndef VERSION
#define VERSION "?"
#endif

static void sanitize_int(const char *name, int min, int max, int val)
{
	if (val >= min && val <= max)
		return;

	fprintf(stderr, "%s value %d out of range: %d..%d\n", name, val, min, max);
	exit(EXIT_FAILURE);
}

void process_env(struct config *config) {
	const char *env;

	env = getenv("INTERFACE");
	if (env)
		config->interface = env;

	env = getenv("REDIS_SERVERS");
	if (env)
		config->redis_servers = env;

	env = getenv("REDIS_THREADS");
	if (env)
		config->redis_threads = atoi(env);

	sanitize_int("REDIS_THREADS", REDIS_THREADS_MIN, REDIS_THREADS_MAX, config->redis_threads);

	env = getenv("VERBOSE");
	if (env)
		config->verbose = 1;

	env = getenv("STATS");
	if (env)
		config->stats = 1;
}

void process_args(int argc, char *argv[], struct config *config) {
	int c;
	int option_index = 0;

	static struct option long_options[] = {
		{ "help",           no_argument,       NULL, 'h'},
		{ "interface",      required_argument, NULL, 'i'},
		{ "redis_servers",  required_argument, NULL, 's'},
		{ "redis_threads",  required_argument, NULL, 't'},
		{ "verbose",        no_argument,       NULL, 'v'},
		{ "stats",          no_argument,       NULL, 'a'},
		{ NULL,             0,                 NULL, 0  }
	};

	while ((c = getopt_long(argc, argv, "hi:s:o:t:va", long_options, &option_index)) != -1) {
		switch (c) {
		case 'i':
			config->interface = optarg;
			break;
		case 's':
			config->redis_servers = optarg;
			break;
		case 't':
			config->redis_threads = atoi(optarg);
			break;
		case 'v':
			config->verbose = 1;
			break;
		case 'a':
			config->stats = 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [options]\n", argv[0]);
			fprintf(stderr, "Options:\n");
			fprintf(stderr, "  -h, --help\n");
			fprintf(stderr, "  -i, --interface                      Listen on this interface only\n");
			fprintf(stderr, "  -s, --redis_servers <servers>        Redis servers\n");
			fprintf(stderr, "  -t, --redis_threads <nr>             Number of redis threads\n");
			fprintf(stderr, "  -v, --verbose                        Verbose output\n");
			fprintf(stderr, "  -a, --stats                          Print stats every second\n");
			fprintf(stderr, "\n");
			fprintf(stderr, "Environment variables:\n");
			fprintf(stderr, "  INTERFACE REDIS_SERVERS REDIS_THREADS VERBOSE STATS\n");
			fprintf(stderr, "\n");
			fprintf(stderr, "%s built %s rev %s\n", argv[0], LAST_CHANGE, VERSION);
			exit(EXIT_FAILURE);
		}
	}

	sanitize_int("--redis_threads", REDIS_THREADS_MIN, REDIS_THREADS_MAX, config->redis_threads);
}
