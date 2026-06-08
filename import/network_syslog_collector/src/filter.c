#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <assert.h>

#include "utils.h"
#include "stats.h"
#include "filter.h"

#define PFX "[filter] "

#define BENCHMARK 0
#define DEBUG_FILTER 0


#ifdef UNIT_TESTS
#include "filter_unit_test.h"
#else
/*
 * The structure describes filtering rule.
 */
static struct filter_rule filter_rules[] = {
	/* Match messages with priority == 185. */
	{
		.stream_id = SYSLOG_EDR,
		.priority = 185,
		.facility = 0xff,
		.severity = 0xff,
	},
	/* Match message with (facility == LOG_DAEMON && severiy <= LOG_DAEMON) */
	/* with payload matching "^.*DHCPACK" pattern. */
	{
		.stream_id = SYSLOG_DHCP_ACK,
		.priority = 0xff,
		.facility = 3,
		.sev_comparison = MATCH_LESS_EQ,
		.severity = 6,
		.pattern = "^.*DHCPACK"
	},
	/* Match messages with severity == LOG_EMERG. */
	{
		.stream_id = SYSLOG_SEV_EMERG,
		.priority = 0xff,
		.facility = 0xff,
		.sev_comparison = MATCH_EQ,
		.severity = 0,
	},
	/* Match messages with severity == LOG_ALERT. */
	{
		.stream_id = SYSLOG_SEV_ALERT,
		.priority = 0xff,
		.facility = 0xff,
		.sev_comparison = MATCH_EQ,
		.severity = 1,
	},
#if 0
	/* Match all trafic comming from 127.0.0.1 IP address (for testing purposes only). */
	{
		.stream_id = SYSLOG_TEST,
		.priority = 0xff,
		.facility = 0xff,
		.severity = 0xff,
		.source_ip = "127.0.0.1",
	},
	/* match all trafic comming from ::1 IP address (for testing purposes only) */
	{
		.stream_id = SYSLOG_TEST,
		.priority = 0xff,
		.facility = 0xff,
		.severity = 0xff,
		.source_ip = "::1",
	},
	/* Match all traffic (for testing purposes only) */
	{
		.stream_id = SYSLOG_TEST,
		.priority = 0xff,
		.facility = 0xff,
		.severity = 0xff,
	},
#endif
};
#endif /* UNIT_TESTS */

#define MAX_LOG_SIZE 2048

#if BENCHMARK
double total_time = 0;
int count = 0;
#endif /* BENCHMARK */


extern struct stats stats;

/*
 * The stats structure doesn't know the filter_rules array so make sure
 * there is enough space in stats.filter.rules for filter_rules[] stats.
 */
static_assert(ARRAY_SIZE(filter_rules) <= ARRAY_SIZE(stats.filter.rules), "increase number of slots in stats.filter.rules[]");


/*
 * Find the terminating '>' character in a priority string i.e. "<123> ...".
 * This function is always called with the 2 first characters of a message
 * skipped and it has to handle '>' at three positions: ">", "2>" and "23>".
 */
static const char *unrolled_strnchr(const char *str, size_t len)
{
	if (len >= 3) {
		if (str[0] == '>')
			return &str[0];
		if (str[1] == '>')
			return &str[1];
		if (str[2] == '>')
			return &str[2];
	} else if (len == 2) {
		if (str[0] == '>')
			return &str[0];
		if (str[1] == '>')
			return &str[1];
	} else {
		if (str[0] == '>')
			return &str[0];
	}

	return NULL;
}

/*
 * Unrolled version of atoi() that handles strings from "1" to "123" and
 * nothing more.
 */
static uint8_t unrolled_atoi(const char *str, size_t len)
{
	if (len == 1)
		return (str[0] - '0');
	if (len == 2)
		return (str[0] - '0') * 10 + (str[1] - '0');
	if (len == 3)
		return (str[0] - '0') * 100 + (str[1] - '0') * 10 + (str[2] - '0');

	return 0xff;
}

static uint8_t get_priority(const char *message, size_t len)
{
	char buffer[4]; /* assuming prio is 3 digits max */
	const char *header_end;
	size_t header_len;

	/*
	 * at this point the minimal length message would be "0>" so we can
	 * jump one character (the digit) and look for '>'
	 */
	header_end = unrolled_strnchr(message + 1, len - 1);
	if (!header_end)
		return 0xff; /* '>' not found */

	header_len = header_end - message;
	if (header_len == 0 || header_len > 3)
		return 0xff; /* invalid header length */

	memcpy(buffer, message, header_len);
	buffer[header_len] = '\0';

	return unrolled_atoi(buffer, header_len);
}

int filter_init(void)
{
	int ret;

	for (int i = 0; i < ARRAY_SIZE(filter_rules); i++) {
		ATOMIC_INC(stats.filter.rules[i].used);

		if (!filter_rules[i].source_ip)
			continue;

		/* build binary IPv4 source address for faster comparison in filter */
		ret = inet_pton(AF_INET, filter_rules[i].source_ip, &filter_rules[i].source_ipv4addr);
		if (ret == 1)
			continue;

		/* no valid IPv4, try with IPv6 */

		/* build binary IPv6 source address for faster comparison in filter */
		ret = inet_pton(AF_INET6, filter_rules[i].source_ip, &filter_rules[i].source_ipv6addr);
		if (ret == 1)
			continue;

		printf(PFX "invalid IP address in filter nr %d: %s\n", i, filter_rules[i].source_ip);
		return 1;
	}

	for (int i = 0; i < ARRAY_SIZE(filter_rules); i++) {
		if (!filter_rules[i].pattern)
			continue;

		/* pattern is known and constant so we can compile regex once at init and use it later */
		if (regcomp(&filter_rules[i].regex, filter_rules[i].pattern, REG_EXTENDED)) {
			fprintf(stderr, PFX "regcomp for filter \"%s\" failed\n", filter_rules[i].pattern);
			return 1;
		}
	}

	return 0;
}

void filter_cleanup(void)
{
	for (int i = 0; i < ARRAY_SIZE(filter_rules); i++) {
		if (filter_rules[i].pattern)
			regfree(&filter_rules[i].regex);
	}
}

/*
 * Function checks if message matches the single rule.
 *
 * Function returns stream id.
 * If message doesn't match returns 0.
 */
static uint8_t filter_match_rule(const struct filter_rule *rule, const char *message, const size_t len, const uint8_t priority, const struct in_addr *source_ipv4addr, const struct in6_addr *source_ipv6addr)
{
#if BENCHMARK
	struct timespec start;
	ts_from_now(&start);
#endif /* BENCHMARK */

	if (rule->priority != 0xFF && rule->priority != priority) {
#if DEBUG_FILTER
		printf(PFX "[%s:%d]\n", __FUNCTION__, __LINE__);
#endif
		return 0;
	}

	if (rule->facility != 0xFF && rule->facility != (priority >> 3)) {
#if DEBUG_FILTER
		printf(PFX "[%s:%d]\n", __FUNCTION__, __LINE__);
#endif
		return 0;
	}

	if (rule->sev_comparison != MATCH_ANY) {
		if (rule->severity != 0xFF && (rule->sev_comparison == MATCH_EQ && rule->severity != (priority & 0x07))) {
#if DEBUG_FILTER
			printf(PFX "[%s:%d]\n", __FUNCTION__, __LINE__);
#endif
			return 0;
		} else if (rule->severity != 0xFF && (rule->sev_comparison == MATCH_LESS_EQ && rule->severity > (priority & 0x07))) {
#if DEBUG_FILTER
			printf(PFX "[%s:%d]\n", __FUNCTION__, __LINE__);
#endif
			return 0;
		}
	}

	if (rule->pattern) {
		char buffer[MAX_LOG_SIZE];

		// syslog messageg retreived from rxbuffer do not have '\0' at the end
		// copy the message to temporary buffer and null terminate
		// regex requires null terminated strings
		memcpy(buffer, message, len);
		buffer[len] = '\0';

		int retregex = regexec(&rule->regex, buffer, 0, NULL, 0);
		if (retregex == REG_NOMATCH) {
			return 0;
		}
	}

	if (rule->source_ip) {
		if (source_ipv4addr && rule->source_ipv4addr.s_addr != source_ipv4addr->s_addr)
			return 0;

		if (source_ipv6addr && memcmp(&rule->source_ipv6addr, source_ipv6addr, sizeof(struct in6_addr)) != 0)
			return 0;
	}

#if DEBUG_FILTER
	printf(PFX "Matching [%s] stream\nmessage: %s\n", GET_STREAM(rule->stream_id), message);
#endif

#if BENCHMARK
	total_time += ts_diff_ns(&start);
	count++;

	double average_time = total_time / count;
	printf("[%s] average execution time after %d executions: %f nanoseconds\n", __FUNCTION__, count, average_time);
#endif /* BENCHMARK */

	return rule->stream_id;
}

uint8_t filter_match_rules(const char *message, const size_t len, const struct in_addr *source_ipv4addr, const struct in6_addr *source_ipv6addr)
{
	uint8_t priority;

	ATOMIC_INC(stats.filter.messages);

	/* valid message starts with at least 3 bytes with priority "<0>" */
	if (len < 3)
		return 0;

	/* the message must start with '<' */
	if (message[0] != '<')
		return 0;

	/* jump first byte and look for priority */
	priority = get_priority(message + 1, len - 1);
	if (priority == 0xff)
		return 0;

	for (int i = 0; i < ARRAY_SIZE(filter_rules); i++) {
		uint8_t ret;

		ret = filter_match_rule(&filter_rules[i], message + 1, len - 1, priority, source_ipv4addr, source_ipv6addr);
		if (ret) {
			ATOMIC_INC(stats.filter.matched);
			ATOMIC_INC(stats.filter.rules[i].matched);
			return ret;
		}
	}

	return 0;
}
