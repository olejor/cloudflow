#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>

/* Defaults mirror configs/examples/splunk-sink.yaml (docs/splunk-output.md). */
#define DEFAULT_CONSUMER_GROUP "sink-splunk"
#define DEFAULT_READ_COUNT 100
#define DEFAULT_BLOCK_MS 1000
#define DEFAULT_BATCH_SIZE 500
#define DEFAULT_FLUSH_INTERVAL_MS 1000
#define DEFAULT_REQUEST_TIMEOUT_MS 5000

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

/* A valid environment-variable *name* looks like FOO or FOO_BAR: a leading
 * letter/underscore then letters/digits/underscores, <=64 chars. HEC tokens
 * (GUIDs, hex strings) fail this -- if hec_token_env fails, someone pasted a
 * literal secret into YAML, which is a fatal startup error (decision D6). */
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

/* ---- minimal libyaml document model walk -------------------------------- */

/* We walk the parsed yaml_document_t node tree directly (rather than the
 * streaming event API) so scalars/mappings/sequences are easy to address by
 * key. Only the subset the schema needs is handled. */

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

/* Collect a YAML sequence of scalars into a newly-allocated char* array. */
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
        yaml_node_t *n_item = doc_node(doc, *item);
        const char *v = scalar_val(n_item);
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

static int parse_document(yaml_document_t *doc, cf_config_t *out, char *errbuf, size_t errcap)
{
    yaml_node_t *root = yaml_document_get_root_node(doc);
    yaml_node_t *service, *redis, *splunk;
    const char *v;

    memset(out, 0, sizeof(*out));

    if (!root || root->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "top-level config must be a mapping");
        return -1;
    }

    service = map_get(doc, root, "service");
    redis = map_get(doc, root, "redis");
    splunk = map_get(doc, root, "splunk");

    if (!service || service->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "service section is required");
        return -1;
    }
    if (!redis || redis->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "redis section is required");
        return -1;
    }
    if (!splunk || splunk->type != YAML_MAPPING_NODE) {
        set_err(errbuf, errcap, "splunk section is required");
        return -1;
    }

    /* -- service -- */
    v = scalar_val(map_get(doc, service, "name"));
    if (!v || !*v) {
        set_err(errbuf, errcap, "service.name is required");
        return -1;
    }
    out->service.name = dup_str(v);
    v = scalar_val(map_get(doc, service, "consumer_name"));
    if (!v || !*v) {
        set_err(errbuf, errcap, "service.consumer_name is required");
        return -1;
    }
    out->service.consumer_name = dup_str(v);

    /* -- redis -- */
    if (collect_seq(doc, map_get(doc, redis, "endpoints"), &out->redis.endpoints,
                    &out->redis.endpoint_count) != 0 ||
        out->redis.endpoint_count == 0) {
        set_err(errbuf, errcap, "redis.endpoints must be a non-empty list");
        return -1;
    }
    if (collect_seq(doc, map_get(doc, redis, "streams"), &out->redis.streams,
                    &out->redis.stream_count) != 0 ||
        out->redis.stream_count == 0) {
        set_err(errbuf, errcap, "redis.streams must be a non-empty list");
        return -1;
    }
    v = scalar_val(map_get(doc, redis, "consumer_group"));
    out->redis.consumer_group = dup_str((v && *v) ? v : DEFAULT_CONSUMER_GROUP);
    out->redis.read_count = scalar_int(redis, doc, "read_count", DEFAULT_READ_COUNT);
    out->redis.block_ms = scalar_int(redis, doc, "block_ms", DEFAULT_BLOCK_MS);

    /* -- splunk -- */
    /* D6: no literal secrets in YAML. */
    {
        static const char *const forbidden[] = {"hec_token", "token", "hec_secret", "secret"};
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
            if (map_get(doc, splunk, forbidden[i])) {
                set_err(errbuf, errcap,
                        "splunk secret key must not appear in YAML; the HEC token is "
                        "read only from the env var named by splunk.hec_token_env (D6)");
                return -1;
            }
        }
    }
    v = scalar_val(map_get(doc, splunk, "hec_url"));
    if (!v || !*v) {
        set_err(errbuf, errcap, "splunk.hec_url is required");
        return -1;
    }
    out->splunk.hec_url = dup_str(v);
    v = scalar_val(map_get(doc, splunk, "hec_token_env"));
    if (!v || !*v) {
        set_err(errbuf, errcap, "splunk.hec_token_env is required");
        return -1;
    }
    if (!looks_like_env_name(v)) {
        set_err(errbuf, errcap,
                "splunk.hec_token_env does not look like an environment variable "
                "name -- a literal secret appears to have been pasted into YAML (D6)");
        return -1;
    }
    out->splunk.hec_token_env = dup_str(v);

    v = scalar_val(map_get(doc, splunk, "index"));
    out->splunk.index = dup_str((v && *v) ? v : "");

    {
        yaml_node_t *st = map_get(doc, splunk, "sourcetypes");
        if (st && st->type == YAML_MAPPING_NODE) {
            size_t n = 0, cap = 4;
            yaml_node_pair_t *pair;
            out->splunk.st_keys = malloc(cap * sizeof(char *));
            out->splunk.st_vals = malloc(cap * sizeof(char *));
            if (!out->splunk.st_keys || !out->splunk.st_vals) {
                set_err(errbuf, errcap, "out of memory");
                return -1;
            }
            for (pair = st->data.mapping.pairs.start; pair < st->data.mapping.pairs.top; pair++) {
                const char *k = scalar_val(doc_node(doc, pair->key));
                const char *val = scalar_val(doc_node(doc, pair->value));
                if (!k || !val)
                    continue;
                if (n == cap) {
                    cap *= 2;
                    out->splunk.st_keys = realloc(out->splunk.st_keys, cap * sizeof(char *));
                    out->splunk.st_vals = realloc(out->splunk.st_vals, cap * sizeof(char *));
                    if (!out->splunk.st_keys || !out->splunk.st_vals) {
                        set_err(errbuf, errcap, "out of memory");
                        return -1;
                    }
                }
                out->splunk.st_keys[n] = dup_str(k);
                out->splunk.st_vals[n] = dup_str(val);
                n++;
            }
            out->splunk.st_count = n;
        } else if (st && st->type != YAML_NO_NODE) {
            set_err(errbuf, errcap, "splunk.sourcetypes must be a mapping");
            return -1;
        }
    }

    out->splunk.batch_size = scalar_int(splunk, doc, "batch_size", DEFAULT_BATCH_SIZE);
    out->splunk.flush_interval_ms =
        scalar_int(splunk, doc, "flush_interval_ms", DEFAULT_FLUSH_INTERVAL_MS);
    out->splunk.request_timeout_ms =
        scalar_int(splunk, doc, "request_timeout_ms", DEFAULT_REQUEST_TIMEOUT_MS);
    out->splunk.tls_verify =
        scalar_is_truthy(scalar_val(map_get(doc, splunk, "tls_verify")), 1);
    out->splunk.include_raw_payload =
        scalar_is_truthy(scalar_val(map_get(doc, splunk, "include_raw_payload")), 0);

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

int cf_config_parse(const char *yaml_text, size_t yaml_len, cf_config_t *out,
                    char *errbuf, size_t errcap)
{
    yaml_parser_t parser;
    int rc;

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

static void free_arr(char **arr, size_t n)
{
    if (!arr)
        return;
    for (size_t i = 0; i < n; i++)
        free(arr[i]);
    free(arr);
}

void cf_config_free(cf_config_t *cfg)
{
    if (!cfg)
        return;
    free(cfg->service.name);
    free(cfg->service.consumer_name);
    free_arr(cfg->redis.endpoints, cfg->redis.endpoint_count);
    free_arr(cfg->redis.streams, cfg->redis.stream_count);
    free(cfg->redis.consumer_group);
    free(cfg->splunk.hec_url);
    free(cfg->splunk.hec_token_env);
    free(cfg->splunk.index);
    free_arr(cfg->splunk.st_keys, cfg->splunk.st_count);
    free_arr(cfg->splunk.st_vals, cfg->splunk.st_count);
    memset(cfg, 0, sizeof(*cfg));
}

const char *cf_splunk_sourcetype_for(const cf_splunk_config_t *s, const char *source_type,
                                     char *buf, size_t cap)
{
    if (!source_type)
        source_type = "";
    for (size_t i = 0; i < s->st_count; i++) {
        if (strcmp(s->st_keys[i], source_type) == 0 && s->st_vals[i][0] != '\0')
            return s->st_vals[i];
    }
    snprintf(buf, cap, "cloudflow:%s", source_type);
    return buf;
}

const char *cf_splunk_resolve_token(const cf_splunk_config_t *s)
{
    const char *tok;

    if (!s || !s->hec_token_env)
        return NULL;
    tok = getenv(s->hec_token_env);
    if (!tok || !*tok)
        return NULL;
    return tok;
}
