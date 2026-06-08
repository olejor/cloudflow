#ifndef __FILTER_H__
#define __FILTER_H__

#include <stdint.h>
#include <regex.h>
#include <arpa/inet.h>

/*
 * Severity comparison can be either equal to defined value or
 * less-equal to defined value.
 * If severity value doesn't matter use ANY comparison type to skip
 * severity processing.
 */
typedef enum {
	MATCH_ANY,
	MATCH_EQ,
	MATCH_LESS_EQ
} comparison_type_e;

/**
 * The list of Redis stream IDs.
 */
typedef enum {
	SYSLOG_NULL, // start indexing from 1, as filter_match_rule returns 0 if stream doesn't match
	SYSLOG_EDR,
	SYSLOG_DHCP_ACK,
	SYSLOG_SEV_EMERG,
	SYSLOG_SEV_ALERT,
	SYSLOG_TEST
} stream_id_e;

/**
 * The structure describes Redis stream.
 * For each Redis stream we assign it an ID.
 * That allows to process filtering based on IDs,
 * withput strcmp and strcpy.
 */
typedef struct
{
	stream_id_e id;
	const char *stream_name;
} stream_t;

/**
 * The structure describes filtering rule.
 */
struct filter_rule {
	stream_id_e stream_id;
	uint8_t priority;
	uint8_t facility;
	comparison_type_e sev_comparison;
	uint8_t severity;
	const char *pattern;
	regex_t regex;
	const char *source_ip;
	struct in_addr source_ipv4addr;
	struct in6_addr source_ipv6addr;
};

/**
 * This array describes all Redis streams which
 * can be applied for filtering rules.
 */
static const stream_t streams_filter[] = {
	{ SYSLOG_NULL,      NULL }, // start indexing from 1, as filter_match_rule returns 0 if stream doesn't match
	{ SYSLOG_EDR,       "syslog:edr" },
	{ SYSLOG_DHCP_ACK,  "syslog:dhcp:ack" },
	{ SYSLOG_SEV_EMERG, "syslog:sev:emerg" },
	{ SYSLOG_SEV_ALERT, "syslog:sev:alert" },
	{ SYSLOG_TEST,      "syslog:test" }
};

#define GET_STREAM(id) (streams_filter[id].stream_name)

/**
 * Function initializes messages filter.
 * Returns 0 if successfully initialized, 1 otherwise.
 */
int filter_init(void);

/**
 * Function frees precompiled regexexs.
 */
void filter_cleanup(void);

/**
 * Function checks if message matches the set of global rules.
 * If message matches the firts rule in the list filter stops
 * message processing and message is accepted to forward.
 *
 * Function returns Redis stream id.
 * If message doesn't match returns 0.
 */
uint8_t filter_match_rules(const char *message, const size_t len, const struct in_addr *source_ipv4addr, const struct in6_addr *source_ipv6addr);

#endif
