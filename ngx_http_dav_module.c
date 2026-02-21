#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);

typedef struct {
        ngx_flag_t    create_full_path;
        ngx_array_t  *dav_methods;
        ngx_array_t  *dav_access;
        ngx_uint_t    min_delete_depth;
    ngx_uint_t    methods_mask;
    ngx_array_t  *parsed_access;
} ngx_http_dav_loc_conf_t;

static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_dav_commands[] = {
        { ngx_string("dav_create_full_path"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
            ngx_conf_set_flag_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, create_full_path),
            NULL },

        { ngx_string("dav_methods"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
            ngx_conf_set_str_array_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, dav_methods),
            NULL },

        { ngx_string("dav_access"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
            ngx_conf_set_str_array_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, dav_access),
            NULL },

        { ngx_string("dav_delete_depth"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_num_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, min_delete_depth),
            NULL },

        ngx_null_command
};

static ngx_http_module_t ngx_http_dav_module_ctx = {
        NULL,
        ngx_http_dav_init,
        NULL,
        NULL,
        NULL,
        NULL,
        ngx_http_dav_create_loc_conf,
        ngx_http_dav_merge_loc_conf
};

ngx_module_t ngx_http_dav_module = {
        NGX_MODULE_V1,
        &ngx_http_dav_module_ctx,
        ngx_http_dav_commands,
        NGX_HTTP_MODULE,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_dav_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_uint_t                bit = 0;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_DECLINED;
    }

    if (r->method == NGX_HTTP_PUT) {
        bit = 0x01;
    } else if (r->method == NGX_HTTP_DELETE) {
        bit = 0x02;
    } else if (r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0) {
        bit = 0x04;
    } else if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"COPY", 4) == 0) {
        bit = 0x08;
    } else if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"MOVE", 4) == 0) {
        bit = 0x10;
    } else {
        return NGX_DECLINED;
    }

    if ((dlcf->methods_mask & bit) == 0) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_str_t    resp = ngx_string("dav: method allowed\n");
    ngx_buf_t   *b;
    ngx_chain_t  out;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = resp.len;
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *)"text/plain";

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, resp.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, resp.data, resp.len);
    b->last = b->pos + resp.len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_dav_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_handler;

    return NGX_OK;
}

static void *
ngx_http_dav_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dav_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->create_full_path = NGX_CONF_UNSET;
    conf->dav_methods = NGX_CONF_UNSET_PTR;
    conf->dav_access = NGX_CONF_UNSET_PTR;
    conf->min_delete_depth = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_loc_conf_t *prev = parent;
    ngx_http_dav_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->create_full_path, prev->create_full_path, 0);
    ngx_conf_merge_uint_value(conf->min_delete_depth, prev->min_delete_depth, 0);

    if (conf->dav_methods == NGX_CONF_UNSET_PTR) {
        if (prev->dav_methods != NGX_CONF_UNSET_PTR) {
            conf->dav_methods = prev->dav_methods;
        } else {
            conf->dav_methods = NULL;
        }
    }

    if (conf->dav_access == NGX_CONF_UNSET_PTR) {
        if (prev->dav_access != NGX_CONF_UNSET_PTR) {
            conf->dav_access = prev->dav_access;
        } else {
            conf->dav_access = NULL;
        }
    }

    conf->methods_mask = 0;

    if (conf->dav_methods) {
        ngx_str_t *elts = conf->dav_methods->elts;
        ngx_uint_t i;

        for (i = 0; i < conf->dav_methods->nelts; i++) {
            ngx_str_t *m = &elts[i];

            if (m->len == 3 && ngx_strncasecmp(m->data, (u_char *)"PUT", 3) == 0) {
                conf->methods_mask |= 0x01;
                continue;
            }

            if (m->len == 6 && ngx_strncasecmp(m->data, (u_char *)"DELETE", 6) == 0) {
                conf->methods_mask |= 0x02;
                continue;
            }

            if (m->len == 5 && ngx_strncasecmp(m->data, (u_char *)"MKCOL", 5) == 0) {
                conf->methods_mask |= 0x04;
                continue;
            }

            if (m->len == 4 && ngx_strncasecmp(m->data, (u_char *)"COPY", 4) == 0) {
                conf->methods_mask |= 0x08;
                continue;
            }

            if (m->len == 4 && ngx_strncasecmp(m->data, (u_char *)"MOVE", 4) == 0) {
                conf->methods_mask |= 0x10;
                continue;
            }

            if (m->len == 3 && ngx_strncasecmp(m->data, (u_char *)"off", 3) == 0) {
                conf->methods_mask = 0;
                break;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid dav_methods token \"%V\"", m);
            return NGX_CONF_ERROR;
        }
    }

    if (conf->dav_access) {
        ngx_str_t *elts = conf->dav_access->elts;
        ngx_uint_t i;

        conf->parsed_access = ngx_array_create(cf->pool, conf->dav_access->nelts, sizeof(ngx_keyval_t));
        if (conf->parsed_access == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < conf->dav_access->nelts; i++) {
            ngx_str_t *entry = &elts[i];
            u_char *p = (u_char *) ngx_strlchr(entry->data, entry->data + entry->len, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid dav_access token \"%V\"", entry);
                return NGX_CONF_ERROR;
            }

            ngx_keyval_t *kv = ngx_array_push(conf->parsed_access);
            if (kv == NULL) {
                return NGX_CONF_ERROR;
            }

            kv->key.len = p - entry->data;
            kv->key.data = ngx_pnalloc(cf->pool, kv->key.len);
            if (kv->key.data == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(kv->key.data, entry->data, kv->key.len);

            kv->value.len = entry->len - kv->key.len - 1;
            kv->value.data = ngx_pnalloc(cf->pool, kv->value.len);
            if (kv->value.data == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(kv->value.data, p + 1, kv->value.len);
        }
    }

    return NGX_CONF_OK;
}
