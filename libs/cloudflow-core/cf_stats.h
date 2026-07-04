#ifndef CF_STATS_H
#define CF_STATS_H

#include <stdatomic.h>

/* Atomic counter primitives (D8 in docs/architecture.md), modeled on
 * the ATOMIC_* macro pattern in a prior syslog-collector prototype. Core only provides these
 * primitives; each app defines its own stats struct out of atomic_ulong (or
 * similar) fields and builds a structured log line out of them with
 * cf_log() once per reporting interval. */

#define CF_ATOMIC_STORE(var, n)        atomic_store(&(var), (n))
#define CF_ATOMIC_ADD(var, n)          atomic_fetch_add(&(var), (n))
#define CF_ATOMIC_INC(var)             atomic_fetch_add(&(var), 1)
#define CF_ATOMIC_READ(var)            atomic_load(&(var))
#define CF_ATOMIC_READ_AND_ZERO(var)   atomic_exchange(&(var), 0)

#endif
