#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>

/* The base config (service/redis/hec) is parsed by cf_sink_config_*. This
 * module owns only the event-sink-specific keys under `splunk`: the
 * `sourcetypes` map and `include_raw_payload`. It re-walks the same YAML in a
 * small second pass (the config is tiny and read once at startup) so the base
 * library stays free of event-specific schema. */

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

/* ---- minimal libyaml document walk (event-specific keys only) ----------- */

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

static int parse_extra(yaml_document_t *doc, cf_config_t *out, char *errbuf, size_t errcap)
{
    yaml_node_t *root = yaml_document_get_root_node(doc);
    yaml_node_t *splunk = map_get(doc, root, "splunk");
    yaml_node_t *st;

    /* The base parser already validated that `splunk` exists and is a
     * mapping; if it somehow isn't, there is simply nothing extra to parse. */
    if (!splunk || splunk->type != YAML_MAPPING_NODE)
        return 0;

    st = map_get(doc, splunk, "sourcetypes");
    if (st && st->type == YAML_MAPPING_NODE) {
        size_t n = 0, cap = 4;
        yaml_node_pair_t *pair;
        out->st_keys = malloc(cap * sizeof(char *));
        out->st_vals = malloc(cap * sizeof(char *));
        if (!out->st_keys || !out->st_vals) {
            set_err(errbuf, errcap, "out of memory");
            return -1;
        }
        for (pair = st->data.mapping.pairs.start; pair < st->data.mapping.pairs.top; pair++) {
            const char *k = scalar_val(doc_node(doc, pair->key));
            const char *val = scalar_val(doc_node(doc, pair->value));
            if (!k || !val)
                continue;
            if (n == cap) {
                char **kt, **vt;
                cap *= 2;
                kt = realloc(out->st_keys, cap * sizeof(char *));
                vt = realloc(out->st_vals, cap * sizeof(char *));
                if (!kt || !vt) {
                    free(kt ? kt : out->st_keys);
                    free(vt ? vt : out->st_vals);
                    out->st_keys = NULL;
                    out->st_vals = NULL;
                    out->st_count = 0;
                    set_err(errbuf, errcap, "out of memory");
                    return -1;
                }
                out->st_keys = kt;
                out->st_vals = vt;
            }
            out->st_keys[n] = dup_str(k);
            out->st_vals[n] = dup_str(val);
            n++;
        }
        out->st_count = n;
    } else if (st && st->type != YAML_NO_NODE) {
        set_err(errbuf, errcap, "splunk.sourcetypes must be a mapping");
        return -1;
    }

    out->include_raw_payload =
        scalar_is_truthy(scalar_val(map_get(doc, splunk, "include_raw_payload")), 0);
    return 0;
}

static int load_extra(yaml_parser_t *parser, cf_config_t *out, char *errbuf, size_t errcap)
{
    yaml_document_t doc;
    int rc;

    if (!yaml_parser_load(parser, &doc)) {
        set_err(errbuf, errcap, "invalid YAML");
        return -1;
    }
    rc = parse_extra(&doc, out, errbuf, errcap);
    yaml_document_delete(&doc);
    return rc;
}

int cf_config_load(const char *path, cf_config_t *out, char *errbuf, size_t errcap)
{
    yaml_parser_t parser;
    FILE *fh;
    int rc;

    memset(out, 0, sizeof(*out));
    if (cf_sink_config_load(path, &out->base, errbuf, errcap) != 0)
        return -1;

    fh = fopen(path, "rb");
    if (!fh) {
        snprintf(errbuf, errcap, "cannot open config file %s", path);
        cf_config_free(out);
        return -1;
    }
    if (!yaml_parser_initialize(&parser)) {
        set_err(errbuf, errcap, "cannot initialize YAML parser");
        fclose(fh);
        cf_config_free(out);
        return -1;
    }
    yaml_parser_set_input_file(&parser, fh);
    rc = load_extra(&parser, out, errbuf, errcap);
    yaml_parser_delete(&parser);
    fclose(fh);
    if (rc != 0) {
        cf_config_free(out);
        return -1;
    }
    return 0;
}

int cf_config_parse(const char *yaml_text, size_t yaml_len, cf_config_t *out, char *errbuf,
                    size_t errcap)
{
    yaml_parser_t parser;
    int rc;

    memset(out, 0, sizeof(*out));
    if (cf_sink_config_parse(yaml_text, yaml_len, &out->base, errbuf, errcap) != 0)
        return -1;

    if (!yaml_parser_initialize(&parser)) {
        set_err(errbuf, errcap, "cannot initialize YAML parser");
        cf_config_free(out);
        return -1;
    }
    yaml_parser_set_input_string(&parser, (const unsigned char *)yaml_text, yaml_len);
    rc = load_extra(&parser, out, errbuf, errcap);
    yaml_parser_delete(&parser);
    if (rc != 0) {
        cf_config_free(out);
        return -1;
    }
    return 0;
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
    cf_sink_config_free(&cfg->base);
    free_arr(cfg->st_keys, cfg->st_count);
    free_arr(cfg->st_vals, cfg->st_count);
    memset(cfg, 0, sizeof(*cfg));
}

const char *cf_splunk_sourcetype_for(const cf_config_t *cfg, const char *source_type, char *buf,
                                     size_t cap)
{
    if (!source_type)
        source_type = "";
    for (size_t i = 0; i < cfg->st_count; i++) {
        if (strcmp(cfg->st_keys[i], source_type) == 0 && cfg->st_vals[i][0] != '\0')
            return cfg->st_vals[i];
    }
    snprintf(buf, cap, "cloudflow:%s", source_type);
    return buf;
}
