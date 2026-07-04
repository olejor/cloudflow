#ifndef CF_SYNC_H
#define CF_SYNC_H

/* Process-wide shutdown coordination. Lifted from a prior
 * syslog-collector prototype's stop-flag pattern, renamed
 * to the cf_ prefix and extended with signal handler installation. */

/* Notify stop from thread context. Sets the stop flag; a non-zero code
 * records an error code, while code == 0 (a plain shutdown request) never
 * clobbers a previously recorded non-zero code. Among non-zero codes the
 * last writer wins -- a later non-zero code overwrites an earlier one. The
 * code is not currently exposed via a getter (callers only need "keep
 * running or not", cf_stop_notified()) -- add one if a downstream WP needs
 * it. */
void cf_stop_notify(int code);

/* Check if stop was notified. Returns 0 while the process should keep
 * running, non-zero once shutdown has been requested. Safe to call from
 * any thread, including from inside a signal handler's non-async-signal-safe
 * callers (the read itself is async-signal-safe). */
int cf_stop_notified(void);

/* Install SIGINT/SIGTERM handlers that request shutdown from signal context.
 * The handler sets the stop flag directly with an async-signal-safe atomic
 * store (it does not call cf_stop_notify()), so the recorded code stays 0,
 * i.e. a clean shutdown. Safe to call once at process startup. */
void cf_stop_install_signal_handlers(void);

#endif
