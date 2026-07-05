#include "cf_redis_cluster.h"

#include <stdlib.h>
#include <string.h>

#include "cf_redis_slot.h"

#define CF_CLUSTER_MAX_NODES     256
#define CF_CLUSTER_MAX_REDIRECTS 5
#define CF_CLUSTER_HOST_MAX      256

typedef struct {
    char          host[CF_CLUSTER_HOST_MAX];
    int           port;
    redisContext *ctx; /* NULL until connected */
} cf_cluster_node_t;

struct cf_redis_cluster {
    char           **seeds;
    size_t           seed_count;
    size_t           seed_idx; /* round-robin cursor for standalone failover */
    int              timeout_sec;

    int              connected;
    int              is_cluster;

    cf_cluster_node_t nodes[CF_CLUSTER_MAX_NODES];
    size_t            node_count;

    int16_t          slot_node[CF_REDIS_NUM_SLOTS]; /* -1 = unknown */
};

/* ---- endpoint parsing --------------------------------------------------- */

static int parse_endpoint(const char *endpoint, char *host, size_t host_cap, int *port)
{
    const char *colon;
    size_t      host_len;
    char       *end = NULL;
    long        parsed;

    if (!endpoint)
        return -1;
    colon = strrchr(endpoint, ':');
    if (!colon || colon == endpoint)
        return -1;
    host_len = (size_t)(colon - endpoint);
    if (host_len == 0 || host_len >= host_cap)
        return -1;
    memcpy(host, endpoint, host_len);
    host[host_len] = '\0';
    parsed = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0' || parsed <= 0 || parsed > 65535)
        return -1;
    *port = (int)parsed;
    return 0;
}

/* ---- node pool ---------------------------------------------------------- */

static void set_timeout(cf_redis_cluster_t *c, redisContext *ctx)
{
    struct timeval tv;
    tv.tv_sec = c->timeout_sec;
    tv.tv_usec = 0;
    redisSetTimeout(ctx, tv);
}

static redisContext *connect_hostport(cf_redis_cluster_t *c, const char *host, int port)
{
    struct timeval tv;
    redisContext *ctx;

    tv.tv_sec = c->timeout_sec;
    tv.tv_usec = 0;
    ctx = redisConnectWithTimeout(host, port, tv);
    if (!ctx)
        return NULL;
    if (ctx->err) {
        redisFree(ctx);
        return NULL;
    }
    set_timeout(c, ctx);
    return ctx;
}

/* Find an existing node for host:port, or add one (ctx left NULL). Returns the
 * node index, or -1 if the table is full. */
static int node_find_or_add(cf_redis_cluster_t *c, const char *host, int port)
{
    size_t i;

    for (i = 0; i < c->node_count; i++)
        if (c->nodes[i].port == port && strcmp(c->nodes[i].host, host) == 0)
            return (int)i;

    if (c->node_count >= CF_CLUSTER_MAX_NODES)
        return -1;
    if (strlen(host) >= CF_CLUSTER_HOST_MAX)
        return -1;

    i = c->node_count++;
    snprintf(c->nodes[i].host, sizeof(c->nodes[i].host), "%s", host);
    c->nodes[i].port = port;
    c->nodes[i].ctx = NULL;
    return (int)i;
}

/* Ensure nodes[idx] has a live connection; (re)connect if needed. */
static redisContext *node_connect(cf_redis_cluster_t *c, int idx)
{
    cf_cluster_node_t *n;

    if (idx < 0 || (size_t)idx >= c->node_count)
        return NULL;
    n = &c->nodes[idx];
    if (n->ctx && !n->ctx->err)
        return n->ctx;
    if (n->ctx) {
        redisFree(n->ctx);
        n->ctx = NULL;
    }
    n->ctx = connect_hostport(c, n->host, n->port);
    return n->ctx;
}

static void free_all_ctx(cf_redis_cluster_t *c)
{
    size_t i;
    for (i = 0; i < c->node_count; i++) {
        if (c->nodes[i].ctx) {
            redisFree(c->nodes[i].ctx);
            c->nodes[i].ctx = NULL;
        }
    }
}

/* ---- topology ----------------------------------------------------------- */

static void clear_slot_map(cf_redis_cluster_t *c)
{
    size_t i;
    for (i = 0; i < CF_REDIS_NUM_SLOTS; i++)
        c->slot_node[i] = -1;
}

/* Parse a CLUSTER SLOTS reply into the node table + slot map. Each top-level
 * element is [start, end, [ip, port, id?], <replicas...>]; we route to the
 * master (element[2]). Returns 0 on success. */
static int parse_cluster_slots(cf_redis_cluster_t *c, const redisReply *reply)
{
    size_t i;

    if (!reply || reply->type != REDIS_REPLY_ARRAY)
        return -1;

    c->node_count = 0;
    clear_slot_map(c);

    for (i = 0; i < reply->elements; i++) {
        const redisReply *range = reply->element[i];
        const redisReply *master, *ip, *port;
        long long start, end, s;
        int idx;

        if (!range || range->type != REDIS_REPLY_ARRAY || range->elements < 3)
            continue;
        if (range->element[0]->type != REDIS_REPLY_INTEGER ||
            range->element[1]->type != REDIS_REPLY_INTEGER)
            continue;
        start = range->element[0]->integer;
        end = range->element[1]->integer;
        master = range->element[2];
        if (!master || master->type != REDIS_REPLY_ARRAY || master->elements < 2)
            continue;
        ip = master->element[0];
        port = master->element[1];
        if (!ip || ip->type != REDIS_REPLY_STRING || !port || port->type != REDIS_REPLY_INTEGER)
            continue;
        if (start < 0 || end >= (long long)CF_REDIS_NUM_SLOTS || start > end)
            continue;

        idx = node_find_or_add(c, ip->str, (int)port->integer);
        if (idx < 0)
            continue;
        for (s = start; s <= end; s++)
            c->slot_node[s] = (int16_t)idx;
    }

    return 0;
}

/* Ask one endpoint for CLUSTER SLOTS. On a successful array reply, load it and
 * set is_cluster=1. On the "cluster support disabled" error, set up standalone
 * mode wrapping this endpoint. Returns 0 if either succeeded (topology known),
 * -1 to try the next seed. `ctx` is consumed on success and freed on failure. */
static int bootstrap_from(cf_redis_cluster_t *c, redisContext *ctx, const char *host, int port)
{
    redisReply *reply = redisCommand(ctx, "CLUSTER SLOTS");

    if (!reply) {
        redisFree(ctx);
        return -1;
    }

    if (reply->type == REDIS_REPLY_ARRAY && reply->elements > 0) {
        parse_cluster_slots(c, reply);
        freeReplyObject(reply);
        redisFree(ctx); /* nodes reconnect lazily by host:port */
        c->is_cluster = 1;
        c->connected = 1;
        return 0;
    }

    /* Empty array or an error ("This instance has cluster support disabled",
     * or an older server without the command) => treat as standalone. Keep the
     * connection as the single node. */
    freeReplyObject(reply);
    c->node_count = 0;
    clear_slot_map(c);
    if (node_find_or_add(c, host, port) != 0) {
        redisFree(ctx);
        return -1;
    }
    c->nodes[0].ctx = ctx;
    c->is_cluster = 0;
    c->connected = 1;
    return 0;
}

/* ---- public API --------------------------------------------------------- */

cf_redis_cluster_t *cf_redis_cluster_new(const char *const *endpoints, size_t count, int timeout_sec)
{
    cf_redis_cluster_t *c;
    size_t i;

    if (!endpoints || count == 0)
        return NULL;

    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;

    c->seeds = calloc(count, sizeof(char *));
    if (!c->seeds) {
        free(c);
        return NULL;
    }
    for (i = 0; i < count; i++) {
        if (!endpoints[i]) {
            cf_redis_cluster_free(c);
            return NULL;
        }
        c->seeds[i] = strdup(endpoints[i]);
        if (!c->seeds[i]) {
            cf_redis_cluster_free(c);
            return NULL;
        }
        c->seed_count++;
    }
    c->timeout_sec = timeout_sec > 0 ? timeout_sec : 3;
    clear_slot_map(c);
    return c;
}

void cf_redis_cluster_free(cf_redis_cluster_t *c)
{
    size_t i;
    if (!c)
        return;
    free_all_ctx(c);
    for (i = 0; i < c->seed_count; i++)
        free(c->seeds[i]);
    free(c->seeds);
    free(c);
}

int cf_redis_cluster_connect(cf_redis_cluster_t *c)
{
    size_t attempt;

    if (!c)
        return -1;

    free_all_ctx(c);
    c->connected = 0;

    for (attempt = 0; attempt < c->seed_count; attempt++) {
        const char  *seed = c->seeds[(c->seed_idx + attempt) % c->seed_count];
        char         host[CF_CLUSTER_HOST_MAX];
        int          port;
        redisContext *ctx;

        if (parse_endpoint(seed, host, sizeof(host), &port) != 0)
            continue;
        ctx = connect_hostport(c, host, port);
        if (!ctx)
            continue;
        if (bootstrap_from(c, ctx, host, port) == 0) {
            c->seed_idx = (c->seed_idx + attempt) % c->seed_count;
            return 0;
        }
    }
    return -1;
}

int cf_redis_cluster_is_cluster(const cf_redis_cluster_t *c)
{
    return c ? c->is_cluster : 0;
}

int cf_redis_cluster_refresh(cf_redis_cluster_t *c)
{
    size_t i;

    if (!c || !c->is_cluster)
        return c && c->connected ? 0 : -1;

    /* Try any node we can reach; fall back to a fresh seed bootstrap. */
    for (i = 0; i < c->node_count; i++) {
        redisContext *ctx = node_connect(c, (int)i);
        redisReply   *reply;

        if (!ctx)
            continue;
        reply = redisCommand(ctx, "CLUSTER SLOTS");
        if (!reply)
            continue;
        if (reply->type == REDIS_REPLY_ARRAY && reply->elements > 0) {
            /* free_all_ctx would drop the ctx we are using; instead just rebuild
             * the map/table and let node_connect re-open as needed. */
            free_all_ctx(c);
            parse_cluster_slots(c, reply);
            freeReplyObject(reply);
            return 0;
        }
        freeReplyObject(reply);
    }
    return cf_redis_cluster_connect(c);
}

void cf_redis_cluster_reset(cf_redis_cluster_t *c)
{
    if (c)
        free_all_ctx(c);
}

redisContext *cf_redis_cluster_conn(cf_redis_cluster_t *c, const char *key, size_t keylen,
                                    uint16_t *slot_out)
{
    if (!c || !c->connected)
        return NULL;

    if (!c->is_cluster) {
        if (slot_out)
            *slot_out = 0;
        /* Standalone: keep the single node live, cycling seeds on failure so
         * D3 endpoint failover still works. */
        if (node_connect(c, 0))
            return c->nodes[0].ctx;
        if (cf_redis_cluster_connect(c) == 0)
            return node_connect(c, 0);
        return NULL;
    }

    {
        uint16_t slot = cf_redis_key_slot(key, keylen);
        int      idx = c->slot_node[slot];

        if (slot_out)
            *slot_out = slot;
        if (idx < 0) {
            if (cf_redis_cluster_refresh(c) != 0)
                return NULL;
            idx = c->slot_node[slot];
            if (idx < 0)
                return NULL;
        }
        return node_connect(c, idx);
    }
}

redisReply *cf_redis_cluster_command_argv(cf_redis_cluster_t *c, const char *key, size_t keylen,
                                          int argc, const char **argv, const size_t *argvlen)
{
    int hops;

    if (!c || !c->connected)
        return NULL;

    /* First attempt: routed to the slot owner (or the single node). */
    {
        redisContext *ctx = cf_redis_cluster_conn(c, key, keylen, NULL);
        redisReply   *reply;
        if (!ctx)
            return NULL;
        reply = redisCommandArgv(ctx, argc, argv, argvlen);
        if (!reply)
            return NULL;

        for (hops = 0; hops < CF_CLUSTER_MAX_REDIRECTS; hops++) {
            int  slot, port, kind;
            char host[CF_CLUSTER_HOST_MAX];
            int  idx;

            if (reply->type != REDIS_REPLY_ERROR)
                return reply;
            kind = cf_redis_parse_redirect(reply->str, &slot, host, sizeof(host), &port);
            if (kind == CF_REDIS_REDIRECT_NONE)
                return reply; /* a real error reply -- hand it back */

            freeReplyObject(reply);

            idx = node_find_or_add(c, host, port);
            if (idx < 0)
                return NULL;
            if (kind == CF_REDIS_REDIRECT_MOVED && slot >= 0 && slot < (int)CF_REDIS_NUM_SLOTS)
                c->slot_node[slot] = (int16_t)idx; /* remember the new owner */

            ctx = node_connect(c, idx);
            if (!ctx)
                return NULL;
            if (kind == CF_REDIS_REDIRECT_ASK) {
                redisReply *ask = redisCommand(ctx, "ASKING");
                if (ask)
                    freeReplyObject(ask);
            }
            reply = redisCommandArgv(ctx, argc, argv, argvlen);
            if (!reply)
                return NULL;
        }
        return reply; /* redirect limit hit: return whatever we last got */
    }
}

int cf_redis_parse_redirect(const char *errstr, int *slot, char *host, size_t host_cap, int *port)
{
    int         kind;
    const char *p;
    const char *colon;
    char       *end = NULL;
    long        s, pt;
    size_t      hl;

    if (!errstr)
        return CF_REDIS_REDIRECT_NONE;

    /* hiredis strips the leading '-', so errstr is e.g. "MOVED 3999 1.2.3.4:6379". */
    if (strncmp(errstr, "MOVED ", 6) == 0) {
        kind = CF_REDIS_REDIRECT_MOVED;
        p = errstr + 6;
    } else if (strncmp(errstr, "ASK ", 4) == 0) {
        kind = CF_REDIS_REDIRECT_ASK;
        p = errstr + 4;
    } else {
        return CF_REDIS_REDIRECT_NONE;
    }

    s = strtol(p, &end, 10);
    if (end == p || *end != ' ')
        return CF_REDIS_REDIRECT_NONE;
    p = end + 1;

    colon = strrchr(p, ':');
    if (!colon)
        return CF_REDIS_REDIRECT_NONE;
    hl = (size_t)(colon - p);
    if (hl == 0 || hl >= host_cap)
        return CF_REDIS_REDIRECT_NONE;

    pt = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0' || pt <= 0 || pt > 65535)
        return CF_REDIS_REDIRECT_NONE;

    memcpy(host, p, hl);
    host[hl] = '\0';
    if (slot)
        *slot = (int)s;
    if (port)
        *port = (int)pt;
    return kind;
}
