#ifndef CF_REDIS_CLUSTER_H
#define CF_REDIS_CLUSTER_H

#include <hiredis/hiredis.h>
#include <stddef.h>
#include <stdint.h>

/* Routing layer over one or more Redis endpoints. It transparently supports
 * both topologies the CloudFlow client must run against:
 *
 *   - STANDALONE (or primary-with-failover, decision D3): the seed list is a
 *     set of interchangeable endpoints tried in order. Exactly one connection
 *     is live at a time and every command goes to it -- byte-for-byte the
 *     legacy behavior.
 *   - CLUSTER: the seeds bootstrap a slot->node map (via CLUSTER SLOTS); each
 *     command is routed to the node owning its key's hash slot, and -MOVED /
 *     -ASK redirects are followed.
 *
 * Which mode is used is auto-detected at connect() time, so existing
 * deployments need no config change.
 *
 * Threading: a cluster handle is owned by a single thread (the producer
 * thread, or one sink consumer). It is not internally synchronized.
 */

typedef struct cf_redis_cluster cf_redis_cluster_t;

/* Create a router over `count` "host:port" seed endpoints (copied). No
 * connection is made yet. `timeout_sec` bounds each connect and command.
 * Returns NULL on bad args or OOM. */
cf_redis_cluster_t *cf_redis_cluster_new(const char *const *endpoints, size_t count,
                                          int timeout_sec);

void cf_redis_cluster_free(cf_redis_cluster_t *c);

/* Connect to a reachable seed and detect the topology. In cluster mode this
 * also loads the slot map. Returns 0 on success (either mode), -1 if no seed
 * was reachable. Safe to call again to re-bootstrap. */
int cf_redis_cluster_connect(cf_redis_cluster_t *c);

/* 1 if the detected topology is a Redis Cluster, 0 for standalone. Only
 * meaningful after a successful connect(). */
int cf_redis_cluster_is_cluster(const cf_redis_cluster_t *c);

/* The live connection that owns `key`'s slot (cluster) or the single active
 * connection (standalone), connecting the node lazily. Writes the computed
 * slot to *slot_out when non-NULL. Returns NULL if the owning node is
 * unreachable; the caller may cf_redis_cluster_reset()+retry. */
redisContext *cf_redis_cluster_conn(cf_redis_cluster_t *c, const char *key, size_t keylen,
                                     uint16_t *slot_out);

/* Reload the slot->node map from any reachable node (call after a -MOVED that
 * points at a node not in the current map). Returns 0 on success, -1 if no
 * node answered. No-op in standalone mode. */
int cf_redis_cluster_refresh(cf_redis_cluster_t *c);

/* Drop all node connections so the next cf_redis_cluster_conn() reconnects.
 * Use after a hard I/O error on a node. */
void cf_redis_cluster_reset(cf_redis_cluster_t *c);

/* Run one single-key command, routing it to the owning node and transparently
 * following -MOVED (refresh + retry) and -ASK (ASKING + retry) up to a small
 * bounded number of hops. `key`/`keylen` is the command's key (used only for
 * routing). Returns the redisReply (caller frees) or NULL on a hard failure.
 * Best for the sink's single-key ops (XAUTOCLAIM / XACK / dead-letter XADD /
 * XGROUP / XINFO); the pipelined producer routes at a lower level. */
redisReply *cf_redis_cluster_command_argv(cf_redis_cluster_t *c, const char *key, size_t keylen,
                                           int argc, const char **argv, const size_t *argvlen);

/* ---- redirect parsing (pure; exposed for the producer's pipeline path) ---- */

#define CF_REDIS_REDIRECT_NONE  0
#define CF_REDIS_REDIRECT_MOVED 1
#define CF_REDIS_REDIRECT_ASK   2

/* Classify a REDIS_REPLY_ERROR string. Returns CF_REDIS_REDIRECT_MOVED/ASK and
 * fills slot/host/port for "MOVED <slot> <host>:<port>" / "ASK ...", or
 * CF_REDIS_REDIRECT_NONE for any other error. host_cap must be >= the host
 * length + 1. */
int cf_redis_parse_redirect(const char *errstr, int *slot, char *host, size_t host_cap, int *port);

#endif
