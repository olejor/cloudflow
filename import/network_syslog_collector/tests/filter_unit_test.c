#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <CUnit/Basic.h>

#include "filter.h"
#include "filter_unit_test.h"

#define MAX_LOG_SIZE 2048

typedef struct {
	uint8_t value;
	const char *name;
} prio_components_t;

const prio_components_t facilities[] = {
	{ LOG_KERN, "LOG_KERN" },
	{ LOG_USER, "LOG_USER" },
	{ LOG_MAIL, "LOG_MAIL" },
	{ LOG_DAEMON, "LOG_DAEMON" },
	{ LOG_AUTH, "LOG_AUTH" },
	{ LOG_SYSLOG, "LOG_SYSLOG" },
	{ LOG_LPR, "LOG_LPR" },
	{ LOG_NEWS, "LOG_NEWS" },
	{ LOG_UUCP, "LOG_UUCP" },
	{ LOG_CRON, "LOG_CRON" },
	{ LOG_AUTHPRIV, "LOG_AUTHPRIV" },
	{ LOG_FTP, "LOG_FTP" },
	{ LOG_LOCAL0, "LOG_LOCAL0" },
	{ LOG_LOCAL1, "LOG_LOCAL1" },
	{ LOG_LOCAL2, "LOG_LOCAL2" },
	{ LOG_LOCAL3, "LOG_LOCAL3" },
	{ LOG_LOCAL4, "LOG_LOCAL4" },
	{ LOG_LOCAL5, "LOG_LOCAL5" },
	{ LOG_LOCAL6, "LOG_LOCAL6" },
	{ LOG_LOCAL7, "LOG_LOCAL7" }
};

const prio_components_t severities[] = {
	{ LOG_EMERG, "LOG_EMERG" },
	{ LOG_ALERT, "LOG_ALERT" },
	{ LOG_CRIT, "LOG_CRIT" },
	{ LOG_ERR, "LOG_ERR" },
	{ LOG_WARNING, "LOG_WARNING" },
	{ LOG_NOTICE, "LOG_NOTICE" },
	{ LOG_INFO, "LOG_INFO" },
	{ LOG_DEBUG, "LOG_DEBUG" }
};

// replaces \0 at the end of the string with '.'
static void remove_null_terminator(char * str)
{
	int len = strlen(str);
	if (len > 0 && str[len -1] == '\0') {
		str[len - 1] = '.';
	}
}

void test_facsev_matrix_success()
{
	int num_facilities = sizeof(facilities) / sizeof(facilities[0]);
	int num_severities = sizeof(severities) / sizeof(severities[0]);

	printf("\n\n");
	for (int i = 0; i < num_facilities; i++) {
		for (int j = 0; j < num_severities; j++) {

			char test_log[MAX_LOG_SIZE];

			snprintf(test_log, MAX_LOG_SIZE, "<%d> Test log with facility [%s], severity [%s]",
				LOG_MAKEPRI(facilities[i].value, severities[j].value),
				facilities[i].name, severities[j].name);

			printf("Checking log with (%s) facility, (%s), severity <%d> and \"Test\" pattern ...\n",
				facilities[i].name, severities[j].name,
				LOG_MAKEPRI(facilities[i].value, severities[j].value));

			int log_len = strlen(test_log);
			remove_null_terminator(test_log);

			SET_FILTER_RULE(4, facility, LOG_FAC(facilities[i].value));
			SET_FILTER_RULE(4, severity, LOG_FAC(severities[j].value));
			CU_ASSERT_NOT_EQUAL(filter_match_rules(test_log, log_len, NULL, NULL), 0);
		}
	}
}

void test_regex_success()
{
	const char *valid_regex_hello = "<14> hello world";
	const char *invalid_regex_hello = "<14> world";
	const char *valid_regex_char_number = "<14> a1b";
	const char *invalid_regex_char_number = "<14> acb";

	printf("\n\n");
	// check if message "hello world" contains "hello"
	printf("Checking if message \"hello world\" contains \"hello\" ...\n");
	CU_ASSERT_NOT_EQUAL(filter_match_rules(valid_regex_hello, strlen(valid_regex_hello), NULL, NULL), 0);
	// check if message "world" doesn't contain "hello"
	printf("Checking if message \"world\" doean't contain \"hello\" ...\n");
	CU_ASSERT_NOT_EQUAL(filter_match_rules(invalid_regex_hello, strlen(invalid_regex_hello), NULL, NULL), !0);
	// check "a[0-9]b" regex against "a1b" message, shall pass
	printf("Checking \"a[0-9]b\" regex against \"a1b\" message, shall pass ...\n");
	CU_ASSERT_NOT_EQUAL(filter_match_rules(valid_regex_char_number, strlen(valid_regex_char_number), NULL, NULL), 0);
	// check "a[0-9]b" regex against "acb" message, shall fail
	printf("Checking \"a[0-9]b\" regex against \"acb\" message, shall fail ...\n");
	CU_ASSERT_NOT_EQUAL(filter_match_rules(invalid_regex_char_number, strlen(invalid_regex_char_number), NULL, NULL), !0);
}


int main()
{
	CU_pSuite pSuite = NULL;

	if (filter_init())
		return 1;

	if (CUE_SUCCESS != CU_initialize_registry()) {
		return CU_get_error();
	}

	pSuite = CU_add_suite("Logchewie Filter Suite", 0, 0);
	if (NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ((NULL == CU_add_test(pSuite, "Syslog facility and severity matrix test", test_facsev_matrix_success)) ||
		(NULL == CU_add_test(pSuite, "Syslog regex test", test_regex_success)))
	{
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();;
}
