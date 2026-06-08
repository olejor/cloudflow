#ifndef __FILTER_UNIT_TEST_H__
#define __FILTER_UNIT_TEST_H__

#include <regex.h>
#include "filter.h"

/*
 * The structure describes filtering rule.
 */
static struct filter_rule filter_rules[] = {
/* set of standard production filter rules */
	{
		.stream_id = SYSLOG_EDR,
		.priority = 185,
		.facility = 0xff,
		.severity = 0xff,
	}, {
		.stream_id = SYSLOG_DHCP_ACK,
		.priority = 0xff,
		.facility = 3,
		.sev_comparison = MATCH_EQ,
		.severity = 6,
		.pattern = "^.*DHCPACK"
	}, {
		.stream_id = SYSLOG_SEV_EMERG,
		.priority = 0xff,
		.facility = 0xff,
		.sev_comparison = MATCH_EQ,
		.severity = 0,
	}, {
		.stream_id = SYSLOG_SEV_ALERT,
		.priority = 0xff,
		.facility = 0xff,
		.sev_comparison = MATCH_EQ,
		.severity = 1,
	},
/* set of unit tests filter rules */
	{
		.stream_id = SYSLOG_TEST,
		.priority = 0xff,
		.facility = 0xff,
		.sev_comparison = MATCH_EQ,
		.severity = 0xff,
		.pattern = "Test"
	}, {
		.stream_id = SYSLOG_TEST,
		.priority = 0xff,
		.facility = 0xff,
		.severity = 0xff,
		.pattern = "hello",
	}, {
		.stream_id = SYSLOG_TEST,
		.priority = 0xff,
		.facility = 0xff,
		.severity = 0xff,
		.pattern = "a[0-9]b",
	}
};

/* help macro for unit test */
#define SET_FILTER_RULE(index, field, value) (filter_rules[(index)].field = (value))

#endif
