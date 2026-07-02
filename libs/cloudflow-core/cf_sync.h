#ifndef CF_SYNC_H
#define CF_SYNC_H

/* Process-wide shutdown coordination. Lifted from
 * import/network_syslog_collector/src/sync.c (stop-flag pattern), renamed
 * to the cf_ prefix and extended with signal handler installation. */

/* Notify stop from thread context. A non-zero code is sticky: the first
 * non-zero code wins and is retrievable via cf_stop_notified() semantics
 * are that the caller only needs to know "keep running or not", so the
 * code itself is not currently exposed via a getter -- add one if a
 * downstream WP needs it. */
void cf_stop_notify(int code);

/* Check if stop was notified. Returns 0 while the process should keep
 * running, non-zero once shutdown has been requested. Safe to call from
 * any thread, including from inside a signal handler's non-async-signal-safe
 * callers (the read itself is async-signal-safe). */
int cf_stop_notified(void);

/* Install SIGINT/SIGTERM handlers that call cf_stop_notify(0) from signal
 * context. Safe to call once at process startup. */
void cf_stop_install_signal_handlers(void);

#endif
