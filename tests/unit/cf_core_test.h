#ifndef CF_CORE_TEST_H
#define CF_CORE_TEST_H

/* Each *_test.c file registers one CUnit suite. Returns 0 on success, -1 if
 * CUnit suite/test registration failed (out of memory, duplicate name,
 * etc.) -- the driver in cf_core_test.c bails out immediately in that case
 * since it means the test binary itself is broken, not that a test failed.
 */
int cf_sha256_register_suite(void);
int cf_event_id_register_suite(void);
int cf_log_register_suite(void);
int cf_time_register_suite(void);

#endif
