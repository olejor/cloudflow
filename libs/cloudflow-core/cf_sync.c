#include "cf_sync.h"

#include <signal.h>
#include <stdatomic.h>
#include <string.h>

static volatile atomic_bool cf_stop_flag;
static volatile atomic_int cf_stop_code;

void cf_stop_notify(int code)
{
    atomic_store(&cf_stop_flag, 1);

    /* Store non-zero code only (indicates error), mirroring the legacy
     * stop_notify() behavior: a plain shutdown request (code == 0) never
     * clobbers a previously recorded error code. */
    if (code)
        atomic_store(&cf_stop_code, code);
}

int cf_stop_notified(void)
{
    return atomic_load(&cf_stop_flag);
}

/* Async-signal-safe: only touches an atomic flag, per signal-safety(7). */
static void cf_stop_signal_handler(int sig)
{
    (void)sig;

    atomic_store(&cf_stop_flag, 1);
}

void cf_stop_install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cf_stop_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}
