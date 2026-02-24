#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);

typedef struct {
        ngx_flag_t    create_full_path;
        ngx_array_t  *dav_methods;
        ngx_array_t  *dav_access;
        ngx_uint_t    min_delete_depth;
    ngx_uint_t    methods_mask;
    ngx_array_t  *parsed_access;
} ngx_http_dav_loc_conf_t;

typedef struct {
    ngx_flag_t   done;
    ngx_int_t    status;
} ngx_http_dav_ctx_t;

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

    ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx && ctx->done) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "dav: finishing request with status=%i", ctx->status);
        ngx_http_finalize_request(r, ctx->status);
        return NGX_DONE;
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
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "dav: method not allowed, methods_mask=%ui method=\"%V\"",
                      dlcf->methods_mask, &r->method_name);
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: method allowed, methods_mask=%ui method=\"%V\"",
                  dlcf->methods_mask, &r->method_name);

    if (r->method == NGX_HTTP_PUT) {
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
            if (ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ctx->done = 0;
            ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
        }

        ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_dav_put_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    return NGX_DECLINED;
}

static void
ngx_http_dav_put_body_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t                 path;
    u_char                   *last;
    ngx_fd_t                  fd;
    ngx_file_t                file;
    ssize_t                   n;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
            if (ctx == NULL) {
                return;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
        }
        ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ctx->done = 1;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
    if (last == NULL) {
        ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
            if (ctx == NULL) {
                return;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
        }
        ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ctx->done = 1;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "dav: mapped path \"%V\"", &path);

    if (dlcf->create_full_path) {
        u_char *p = path.data + path.len - 1;
        while (p > path.data && *p != '/') {
            p--;
        }

        if (p > path.data) {
            u_char saved = *p;
            *p = '\0';
            if (ngx_create_full_path(path.data, 0700) == NGX_FILE_ERROR) {
                *p = saved;
                ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
                if (ctx == NULL) {
                    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
                    if (ctx == NULL) {
                        return;
                    }
                    ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
                }
                ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                ctx->done = 1;
                r->write_event_handler = ngx_http_core_run_phases;
                ngx_http_core_run_phases(r);
                return;
            }
            *p = saved;
        }
    }

    /* create temp filename = path + ".tmp" */
    ngx_str_t tmp;
    tmp.len = path.len + sizeof(".tmp") - 1;
    tmp.data = ngx_pnalloc(r->pool, tmp.len + 1);
    if (tmp.data == NULL) {
        ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
            if (ctx == NULL) {
                return;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
        }
        ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ctx->done = 1;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }
    ngx_snprintf(tmp.data, tmp.len + 1, "%V.tmp", &path);

    ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "dav: creating temp file \"%s\"", tmp.data);
    fd = ngx_open_file(tmp.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, 0644);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "dav: cannot create temp file \"%s\"", tmp.data);
        ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
            if (ctx == NULL) {
                return;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
        }
        ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ctx->done = 1;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name.data = tmp.data;
    file.name.len = tmp.len;
    file.log = r->connection->log;
    file.offset = 0;

    n = ngx_write_chain_to_file(&file, r->request_body->bufs, 0, r->pool);
    if (n == NGX_ERROR) {
        ngx_close_file(fd);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: write to temp file failed");
        ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
            if (ctx == NULL) {
                return;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
        }
        ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ctx->done = 1;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "dav: wrote %z bytes to temp file", n);

    ngx_close_file(fd);

    if (ngx_rename_file(tmp.data, path.data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "dav: rename \"%s\" to \"%V\" failed", tmp.data, &path);
        ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
            if (ctx == NULL) {
                return;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
        }
        ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ctx->done = 1;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "dav: renamed \"%s\" -> \"%V\"", tmp.data, &path);

    ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
        if (ctx == NULL) {
            return;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
    }

    ctx->status = NGX_HTTP_CREATED;
    ctx->done = 1;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
    return;
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
