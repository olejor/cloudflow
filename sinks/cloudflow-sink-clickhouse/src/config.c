#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>

/* The ClickHouse sink is not a Splunk sink, so it cannot reuse the base
 * `splunk:`-section parser (cf_sink_config_load requires a HEC section). It
 * parses `service`, `redis` and `clickhouse` itself and fills the embedded
 * cf_sink_config_t so the shared spine sees an ordinary base config. The YAML
 * walk mirrors the base parser (libs/cloudflow-sink-core/cf_sink_config.c). */

#define DEFAULT_READ_COUNT 100
#define DEFAULT_BLOCK_MS 1000
#define DEFAULT_BATCH_SIZE 10000 /* ClickHouse strongly prefers large INSERT batches */
#define DEFAULT_FLUSH_INTERVAL_MS 1000
#define DEFAULT_REQUEST_TIMEOUT_MS 5000
#define DEADLETTER_STREAM_PREFIX "cloudflow:v1:deadletter:"

static void set_err(char *errbuf, size_t errcap, const char *msg)
{
    if (errbuf && errcap)
        snprintf(errbuf, errcap, "%s", msg);
}

static char *dup_str(const char *s)
{
    char *r;
    size_t n;

    if (!s)
        s = "";
    n = strlen(s) + 1;
    r = malloc(n);
    if (r)
        memcpy(r, s, n);
    return r;
}

/* A valid environment-variable *name* looks like FOO or FOO_BAR (decision D6):
 * a leading letter/underscore then letters/digits/underscores, <=64 chars.
 * Literal secrets (hex/base64 strings) fail this. */
static int looks_like_env_name(const char *s)
{
    size_t i;

    if (!s || !*s)
        return 0;
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_'))
        return 0;
    for (i = 1; s[i]; i++) {
        if (!(isalnum((unsigned char)s[i]) || s[i] == '_'))
            return 0;
        if (i >= 64)
            return 0;
    }
    return 1;
}

/* ---- minimal libyaml document walk -------------------------------------- */

static yaml_node_t *doc_node(yaml_document_t *doc, int idx)
{
    if (idx == 0)
        return NULL;
    return yaml_document_get_node(doc, idx);
}

static yaml_node_t *map_get(yaml_document_t *doc, yaml_node_t *map, const char *key)
{
    yaml_node_pair_t *pair;

    if (!map || map->type != YAML_MAPPING_NODE)
        return NULL;
    for (pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; pair++) {
        yaml_node_t *k = doc_node(doc, pair->key);
        if (k && k->type == YAML_SCALAR_NODE &&
            strcmp((const char *)k->data.scalar.value, key) == 0)
            return doc_node(doc, pair->value);
    }
    return NULL;
}

static const char *scalar_val(yaml_node_t *n)
{
    if (n && n->type == YAML_SCALAR_NODE)
        return (const char *)n->data.scalar.value;
    return NULL;
}

static int scalar_is_truthy(const char *v, int dflt)
{
    if (!v)
        return dflt;
    if (strcmp(v, "true") == 0 || strcmp(v, "True") == 0 || strcmp(v, "yes") == 0 ||
        strcmp(v, "1") == 0)
        return 1;
    if (strcmp(v, "false") == 0 || strcmp(v, "False") == 0 || strcmp(v, "no") == 0 ||
        strcmp(v, "0") == 0)
        return 0;
    return dflt;
}

static int scalar_int(yaml_node_t *map, yaml_document_t *doc, const char *key, int dflt)
{
    const char *v = scalar_val(map_get(doc, map, key));
    if (!v || !*v)
        return dflt;
    return (int)strtol(v, NULL, 10);
}

static int collect_seq(yaml_document_t *doc, yaml_node_t *seq, char ***out, size_t *out_n)
{
    yaml_node_item_t *item;
    size_t n = 0, cap = 4;
    char **arr;

    *out = NULL;
    *out_n = 0;
    if (!seq || seq->type != YAML_SEQUENCE_NODE)
        return -1;

    arr = malloc(cap * sizeof(*arr));
    if (!arr)
        return -1;

    for (item = seq->data.sequence.items.start; item < seq->data.sequence.items.top; item++) {
        const char *v = scalar_val(doc_node(doc, *item));
        if (!v)
            continue;
        if (n == cap) {
            char **tmp;
            cap *= 2;
            tmp = realloc(arr, cap * sizeof(*arr));
            if (!tmp) {
                for (size_t i = 0; i < n; i++)
                    free(arr[i]);
                free(arr);
                return -1;
            }
            arr = tmp;
        }
        arr[n] = dup_str(v);
        if (!arr[n]) {
            for (size_t i = 0; i < n; i++)
                free(arr[i]);
            free(arr);
            return -1;
        }
        n++;
    }

    *out = arr;
    *out_n = n;
    return 0;
}

/* Resolve one `clickhouse.<key>` env-var-NAME field into a malloc'd string,
 * validating it is an env-var name and not a literal secret (D6). Missing =>
 * "". Returns 0 on success, -1 on a fatal D6 violation. */
static int parse_env_name(yaml_document_t *doc, yaml_node_t *ch, const char *key, char **out,
                          char *errbuf, size_t errcap)
{
    const char *v = scalar_val(map_get(doc, ch, key));
    if (!v || !*v) {
        *out = dup_str("");
        return *out ? 0 : -1;
    }
    if (!looks_like_env_name(v)) {
        snprintf(errbuf, errcap,
                 "clickhouse.%s does not look like an environment variable name -- a literal "
                 "secret appears to have been pasted into YAML (D6)",
                 key);
        return -1;
    }
    *out = dup_str(v);
    return *out ? 0 : -1;
}

static int parse_document(yaml_document_t *doc, cf_config_t *out, char *errbuf, size_t errcap)
{
    yaml_node_t *root = yaml_document_get_root_node(doc);
    yaml_node_t *service, *redis, *ch;
    cf_sink_config_t *base = &out->base;
    const char *v;

    if (!root || root->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "top-level config must be a mapping");
        return -1;
    }

    service = map_get(doc, root, "service");
    redis = map_get(doc, root, "redis");
    ch = map_get(doc, root, "clickhouse");

    if (!service || service->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "service section is required");
        return -1;
    }
    if (!redis || redis->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "redis section is required");
        return -1;
    }
    if (!ch || ch->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "clickhouse section is required");
        return -1;
    }

    /* -- service -- */
    v = scalar_val(map_get(doc, service, "name"));
    if (!v || !*v) {
        set_err(errbuf, errcap, "service.name is required");
        return -1;
    }
    base->service.name = dup_str(v);
    v = scalar_val(map_get(doc, service, "consumer_name"));
    if (!v || !*v) {
        set_err(errbuf, errcap, "service.consumer_name is required");
        return -1;
    }
    base->service.consumer_name = dup_str(v);

    /* -- redis -- */
    if (collect_seq(doc, map_get(doc, redis, "endpoints"), &base->redis.endpoints,
                    &base->redis.endpoint_count) != 0 ||
        base->redis.endpoint_count == 0) {
        set_err(errbuf, errcap, "redis.endpoints must be a non-empty list");
        return -1;
    }
    if (collect_seq(doc, map_get(doc, redis, "streams"), &base->redis.streams,
                    &base->redis.stream_count) != 0 ||
        base->redis.stream_count == 0) {
        set_err(errbuf, errcap, "redis.streams must be a non-empty list");
        return -1;
    }
    v = scalar_val(map_get(doc, redis, "consumer_group"));
    base->redis.consumer_group = dup_str((v && *v) ? v : CF_SINK_CLICKHOUSE_CONSUMER_GROUP);
    base->redis.read_count = scalar_int(redis, doc, "read_count", DEFAULT_READ_COUNT);
    base->redis.block_ms = scalar_int(redis, doc, "block_ms", DEFAULT_BLOCK_MS);

    /* Dead-letter stream: explicit `redis.deadletter_stream` wins; otherwise
     * derive it from the consumer group (sink-clickhouse ->
     * cloudflow:v1:deadletter:sink-clickhouse). */
    v = scalar_val(map_get(doc, redis, "deadletter_stream"));
    if (v && *v) {
        base->redis.deadletter_stream = dup_str(v);
    } else if (base->redis.consumer_group) {
        size_t need = strlen(DEADLETTER_STREAM_PREFIX) + strlen(base->redis.consumer_group) + 1;
        base->redis.deadletter_stream = malloc(need);
        if (base->redis.deadletter_stream)
            snprintf(base->redis.deadletter_stream, need, "%s%s", DEADLETTER_STREAM_PREFIX,
                     base->redis.consumer_group);
    }

    /* -- clickhouse -- */
    /* D6: no literal secrets in YAML. */
    {
        static const char *const forbidden[] = {"password", "user_password", "key", "secret"};
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
            if (map_get(doc, ch, forbidden[i])) {
                set_err(errbuf, errcap,
                        "clickhouse secret key must not appear in YAML; credentials are read "
                        "only from the env vars named by clickhouse.user_env / "
                        "clickhouse.password_env (D6)");
                return -1;
            }
        }
    }

    v = scalar_val(map_get(doc, ch, "url"));
    if (!v || !*v) {
        set_err(errbuf, errcap, "clickhouse.url is required");
        return -1;
    }
    out->url = dup_str(v);

    v = scalar_val(map_get(doc, ch, "database"));
    out->database = dup_str((v && *v) ? v : CF_SINK_CLICKHOUSE_DEFAULT_DATABASE);
    v = scalar_val(map_get(doc, ch, "table"));
    out->table = dup_str((v && *v) ? v : CF_SINK_CLICKHOUSE_DEFAULT_TABLE);

    if (parse_env_name(doc, ch, "user_env", &out->user_env, errbuf, errcap) != 0)
        return -1;
    if (parse_env_name(doc, ch, "password_env", &out->password_env, errbuf, errcap) != 0)
        return -1;

    out->request_timeout_ms = scalar_int(ch, doc, "request_timeout_ms", DEFAULT_REQUEST_TIMEOUT_MS);
    out->tls_verify = scalar_is_truthy(scalar_val(map_get(doc, ch, "tls_verify")), 1);

    /* The spine's batch/flush tuning lives in the base hec struct. */
    base->hec.batch_size = scalar_int(ch, doc, "batch_size", DEFAULT_BATCH_SIZE);
    base->hec.flush_interval_ms = scalar_int(ch, doc, "flush_interval_ms", DEFAULT_FLUSH_INTERVAL_MS);
    base->hec.request_timeout_ms = out->request_timeout_ms;
    base->hec.tls_verify = out->tls_verify;
    /* The base HEC endpoint fields are unused by this sink but must be non-NULL
     * so cf_sink_config_free stays uniform. */
    base->hec.hec_url = dup_str("");
    base->hec.hec_path = dup_str("");
    base->hec.hec_token_env = dup_str("");
    base->hec.index = dup_str("");

    if (!base->service.name || !base->service.consumer_name || !base->redis.consumer_group ||
        !base->redis.deadletter_stream || !out->url || !out->database || !out->table ||
        !out->user_env || !out->password_env || !base->hec.hec_url || !base->hec.hec_path ||
        !base->hec.hec_token_env || !base->hec.index) {
        set_err(errbuf, errcap, "out of memory");
        return -1;
    }

    return 0;
}

static int load_from_parser(yaml_parser_t *parser, cf_config_t *out, char *errbuf, size_t errcap)
{
    yaml_document_t doc;
    int rc;

    if (!yaml_parser_load(parser, &doc)) {
        set_err(errbuf, errcap, "invalid YAML");
        return -1;
    }
    rc = parse_document(&doc, out, errbuf, errcap);
    yaml_document_delete(&doc);
    if (rc != 0)
        cf_config_free(out);
    return rc;
}

int cf_config_parse(const char *yaml_text, size_t yaml_len, cf_config_t *out, char *errbuf,
                    size_t errcap)
{
    yaml_parser_t parser;
    int rc;

    memset(out, 0, sizeof(*out));
    if (!yaml_parser_initialize(&parser)) {
        set_err(errbuf, errcap, "cannot initialize YAML parser");
        return -1;
    }
    yaml_parser_set_input_string(&parser, (const unsigned char *)yaml_text, yaml_len);
    rc = load_from_parser(&parser, out, errbuf, errcap);
    yaml_parser_delete(&parser);
    return rc;
}

int cf_config_load(const char *path, cf_config_t *out, char *errbuf, size_t errcap)
{
    yaml_parser_t parser;
    FILE *fh;
    int rc;

    memset(out, 0, sizeof(*out));
    fh = fopen(path, "rb");
    if (!fh) {
        snprintf(errbuf, errcap, "cannot open config file %s", path);
        return -1;
    }
    if (!yaml_parser_initialize(&parser)) {
        set_err(errbuf, errcap, "cannot initialize YAML parser");
        fclose(fh);
        return -1;
    }
    yaml_parser_set_input_file(&parser, fh);
    rc = load_from_parser(&parser, out, errbuf, errcap);
    yaml_parser_delete(&parser);
    fclose(fh);
    return rc;
}

void cf_config_free(cf_config_t *cfg)
{
    if (!cfg)
        return;
    cf_sink_config_free(&cfg->base);
    free(cfg->url);
    free(cfg->database);
    free(cfg->table);
    free(cfg->user_env);
    free(cfg->password_env);
    memset(cfg, 0, sizeof(*cfg));
}
