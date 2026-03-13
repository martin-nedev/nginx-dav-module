#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r);
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
static char *ngx_conf_set_dav_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_dav_commands[] = {
        { ngx_string("dav_create_full_path"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
            ngx_conf_set_flag_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, create_full_path),
            NULL },

        { ngx_string("dav_methods"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
            ngx_conf_set_dav_methods,
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

static char *
ngx_conf_set_dav_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dav_loc_conf_t *dlcf = conf;
    ngx_str_t *args = cf->args->elts;
    ngx_uint_t i, nargs = cf->args->nelts;

    if (nargs < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "dav_methods requires arguments");
        return NGX_CONF_ERROR;
    }

    /* args[0] is the directive name; args[1..nargs-1] are tokens */
    if (nargs == 2 && args[1].len == 3 && ngx_strncasecmp(args[1].data, (u_char *)"off", 3) == 0) {
        dlcf->dav_methods = NULL;
        dlcf->methods_mask = 0;
        return NGX_CONF_OK;
    }

    /* create an array to hold the method tokens */
    dlcf->dav_methods = ngx_array_create(cf->pool, nargs - 1, sizeof(ngx_str_t));
    if (dlcf->dav_methods == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < nargs; i++) {
        ngx_str_t *s = ngx_array_push(dlcf->dav_methods);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        s->len = args[i].len;
        s->data = ngx_pnalloc(cf->pool, s->len);
        if (s->data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(s->data, args[i].data, s->len);

        /* store token; minimal logging only for errors */
    }

    /* compute methods_mask immediately for this conf instance */
    dlcf->methods_mask = 0;
    if (dlcf->dav_methods) {
        ngx_str_t *elts2 = dlcf->dav_methods->elts;
        ngx_uint_t k;
        for (k = 0; k < dlcf->dav_methods->nelts; k++) {
            ngx_str_t *mm = &elts2[k];
            if (mm->len == 3 && ngx_strncasecmp(mm->data, (u_char *)"PUT", 3) == 0) {
                dlcf->methods_mask |= 0x01;
                continue;
            }
            if (mm->len == 6 && ngx_strncasecmp(mm->data, (u_char *)"DELETE", 6) == 0) {
                dlcf->methods_mask |= 0x02;
                continue;
            }
            if (mm->len == 5 && ngx_strncasecmp(mm->data, (u_char *)"MKCOL", 5) == 0) {
                dlcf->methods_mask |= 0x04;
                continue;
            }
            if (mm->len == 4 && ngx_strncasecmp(mm->data, (u_char *)"COPY", 4) == 0) {
                dlcf->methods_mask |= 0x08;
                continue;
            }
            if (mm->len == 4 && ngx_strncasecmp(mm->data, (u_char *)"MOVE", 4) == 0) {
                dlcf->methods_mask |= 0x10;
                continue;
            }
            if (mm->len == 3 && ngx_strncasecmp(mm->data, (u_char *)"off", 3) == 0) {
                dlcf->methods_mask = 0;
                break;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid dav_methods token \"%V\"", mm);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dav_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_uint_t                bit = 0;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_DECLINED;
    }

    /* minimal runtime info: log method denied at info level elsewhere */

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

        /* prefer temp-file request body like original nginx dav module */
        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_dav_put_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    if (r->method == NGX_HTTP_DELETE) {
        return ngx_http_dav_delete_handler(r);
    }

    if (r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0) {
        return ngx_http_dav_mkcol_handler(r);
    }

    return NGX_DECLINED;
}

static void
ngx_http_dav_put_body_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t                 path, tmpname;
    u_char                   *last;
    ngx_flag_t                exists = 0;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
    if (last == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* ensure parent path exists when requested */
    if (dlcf->create_full_path) {
        u_char *p = path.data + path.len - 1;
        while (p > path.data && *p != '/') p--;
        if (p > path.data) {
            u_char saved = *p;
            *p = '\0';
            if (ngx_create_full_path(path.data, 0700) == NGX_FILE_ERROR) {
                *p = saved;
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            *p = saved;
        }
    }

    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: PUT request body must be in a file");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* detect existing destination */
    ngx_file_info_t  fi;
    if (ngx_file_info((char *) path.data, &fi) != NGX_FILE_ERROR) {
        exists = 1;
    }

    ngx_ext_rename_file_t ext;
    ext.access = 0;
    ext.path_access = 0;
    ext.time = -1;
    ext.create_path = dlcf->create_full_path;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (ngx_ext_rename_file(&r->request_body->temp_file->file.name, &path, &ext) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: rename failed for '%V'", &path);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    tmpname = r->request_body->temp_file->file.name;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "dav: renamed '%V' -> '%V'", &tmpname, &path);

    ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
        if (ctx == NULL) {
            return;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
    }

    ctx->status = exists ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
    ctx->done = 1;
    ngx_http_finalize_request(r, ctx->status);
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

    /* Delete is dispatched from ngx_http_dav_handler; do not register a
     * separate delete handler here to avoid duplicate handling/ordering
     * issues. */

    return NGX_OK;
}

static ngx_int_t
    ngx_http_dav_delete_handler(ngx_http_request_t *r)
    {
        if (r->method != NGX_HTTP_DELETE) {
            return NGX_DECLINED;
        }

        ngx_http_dav_loc_conf_t  *dlcf;
        ngx_str_t                 path;
        u_char                   *last;

        dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
        if (dlcf == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        size_t root_len;
        last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
        if (last == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* enforce dav_access parsed entries (prefix match); if parsed_access
         * exists then require at least one matching prefix to allow deletion */
        if (dlcf->parsed_access) {
            ngx_keyval_t *kvs = dlcf->parsed_access->elts;
            ngx_uint_t i;
            ngx_flag_t allowed = 0;

            for (i = 0; i < dlcf->parsed_access->nelts; i++) {
                ngx_keyval_t *kv = &kvs[i];

                if (path.len >= kv->key.len
                    && ngx_memcmp(path.data, kv->key.data, kv->key.len) == 0)
                {
                    allowed = 1;
                    break;
                }
            }

            if (!allowed) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "dav: delete denied by dav_access for '%V'", &path);
                ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
                return NGX_HTTP_FORBIDDEN;
            }
        }

        if (dlcf->min_delete_depth) {
            size_t i, depth = 0;
            u_char *p = r->uri.data;
            ngx_flag_t in_seg = 0;

            for (i = 0; i < r->uri.len; i++) {
                if (p[i] != '/') {
                    if (!in_seg) {
                        in_seg = 1;
                        depth++;
                    }
                } else {
                    in_seg = 0;
                }
            }

            if (depth < dlcf->min_delete_depth) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "dav: delete denied, depth %uz < min %ui",
                              depth, (unsigned) dlcf->min_delete_depth);
                return NGX_HTTP_FORBIDDEN;
            }
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "dav: delete target '%V'", &path);

        /* stat target using nginx helper */
        ngx_file_info_t sb;
        if (ngx_file_info((char *) path.data, &sb) == NGX_FILE_ERROR) {
            if (ngx_errno == ENOENT) {
                return NGX_HTTP_NOT_FOUND;
            }
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "dav: stat('%V') failed", &path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* file or directory removal */
        if (S_ISDIR(sb.st_mode)) {
            if (rmdir((char *) path.data) == 0) {
                return NGX_HTTP_NO_CONTENT;
            }
            if (ngx_errno == ENOENT) {
                return NGX_HTTP_NOT_FOUND;
            }
            if (ngx_errno == EEXIST || ngx_errno == ENOTEMPTY) {
                return NGX_HTTP_CONFLICT;
            }
            if (ngx_errno == EACCES) {
                return NGX_HTTP_FORBIDDEN;
            }
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "dav: rmdir('%V') failed", &path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* remove regular file using nginx wrapper */
        if (ngx_delete_file((char *) path.data) == 0) {
            return NGX_HTTP_NO_CONTENT;
        }

        if (ngx_errno == ENOENT) {
            return NGX_HTTP_NOT_FOUND;
        }
        if (ngx_errno == EACCES || ngx_errno == EPERM) {
            return NGX_HTTP_FORBIDDEN;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "dav: unlink('%V') failed", &path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

static ngx_int_t
ngx_http_dav_mkcol_handler(ngx_http_request_t *r)
{
    if (!(r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0)) {
        return NGX_DECLINED;
    }

    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t                 path;
    u_char                   *last;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* enforce dav_access if configured (prefix match) */
    if (dlcf->parsed_access) {
        ngx_keyval_t *kvs = dlcf->parsed_access->elts;
        ngx_uint_t i;
        ngx_flag_t allowed = 0;

        for (i = 0; i < dlcf->parsed_access->nelts; i++) {
            ngx_keyval_t *kv = &kvs[i];
            if (path.len >= kv->key.len && ngx_memcmp(path.data, kv->key.data, kv->key.len) == 0) {
                allowed = 1;
                break;
            }
        }

        if (!allowed) {
            return NGX_HTTP_FORBIDDEN;
        }
    }

    /* if target exists, MKCOL must fail */
    ngx_file_info_t sb;
    if (ngx_file_info((char *) path.data, &sb) != NGX_FILE_ERROR) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* ensure parent exists */
    {
        u_char *p = path.data + path.len - 1;
        while (p > path.data && *p != '/') p--;
        if (p <= path.data) {
            return NGX_HTTP_FORBIDDEN;
        }

        char parent[PATH_MAX];
        size_t plen = p - path.data;
        if (plen >= sizeof(parent)) plen = sizeof(parent) - 1;
        ngx_memcpy(parent, path.data, plen);
        parent[plen] = '\0';

        if (ngx_file_info(parent, &sb) == NGX_FILE_ERROR) {
            if (ngx_errno == ENOENT) {
                return NGX_HTTP_CONFLICT; /* parent doesn't exist */
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* create directory */
    if (mkdir((char *) path.data, 0755) == 0) {
        return NGX_HTTP_CREATED;
    }

    if (ngx_errno == EEXIST) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    if (ngx_errno == ENOENT) {
        return NGX_HTTP_CONFLICT;
    }
    if (ngx_errno == EACCES || ngx_errno == EPERM) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
    conf->methods_mask = NGX_CONF_UNSET_UINT;

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

    ngx_conf_merge_uint_value(conf->methods_mask, prev->methods_mask, 0);

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

    /* Debug: log merged dav_methods and methods_mask to help runtime checks */
    if (conf->dav_methods) {
        ngx_str_t *m_elts = conf->dav_methods->elts;
        ngx_uint_t j;

        ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                      "dav: merged dav_methods nelts=%ui",
                      conf->dav_methods->nelts);

        for (j = 0; j < conf->dav_methods->nelts; j++) {
            ngx_str_t *m = &m_elts[j];
            ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                          "dav: merged dav_methods[%ui]=len=%uz val=%V",
                          j, m->len, m);

            /* dump first bytes in hex to spot hidden/trailing chars */
            {
                size_t i, dump_len = m->len;
                u_char hexbuf[256];
                if (dump_len > 64) dump_len = 64;
                for (i = 0; i < dump_len; i++) {
                    ngx_sprintf(&hexbuf[i*2], "%02xd", m->data[i]);
                }
                hexbuf[dump_len*2] = '\0';
                ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                              "dav: merged dav_methods[%ui] hex(first %uz)=%s",
                              j, dump_len, hexbuf);
            }
        }
    }

    /* keep merge phase quiet in production; no verbose logging */

    return NGX_CONF_OK;
}
