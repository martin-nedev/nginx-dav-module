#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <utime.h>
#include <stdio.h>

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_move_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_dav_copy_file_atomic(ngx_http_request_t *r, const char *src, const char *dst);
static ngx_int_t ngx_http_dav_copy_dir(ngx_http_request_t *r, const char *src, const char *dst);
static ngx_int_t ngx_http_dav_remove_tree(ngx_http_request_t *r, const char *path);
static ngx_int_t ngx_http_dav_unlink_if_unchanged(ngx_http_request_t *r, const char *path, const ngx_file_info_t *orig_st);

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
    if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"MOVE", 4) == 0) {
        return ngx_http_dav_move_handler(r);
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

    /* ensure parent exists (or create it when requested) */
    {
        u_char *p = path.data + path.len - 1;
        while (p > path.data && *p != '/') p--;
        if (p <= path.data) {
            return NGX_HTTP_FORBIDDEN;
        }

        if (dlcf->create_full_path) {
            /* create parent path components if needed */
            u_char saved = *p;
            *p = '\0';
            if (ngx_create_full_path(path.data, 0755) == NGX_FILE_ERROR) {
                *p = saved;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            *p = saved;
        } else {
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
    }

    /* create directory (final component) */
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

static ngx_int_t
ngx_http_dav_move_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t src, dst, dest_hdr = ngx_null_string;
    u_char *last;
    ngx_uint_t overwrite = 1;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* find Destination and Overwrite headers */
    {
        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *h = part->elts;
        ngx_uint_t i = 0;
        for ( ;; ) {
            if (i >= part->nelts) {
                if (part->next == NULL) break;
                part = part->next; h = part->elts; i = 0;
            }
            if (h[i].key.len == 11 && ngx_strncasecmp(h[i].key.data, (u_char *)"Destination", 11) == 0) {
                dest_hdr = h[i].value;
            }
            if (h[i].key.len == 9 && ngx_strncasecmp(h[i].key.data, (u_char *)"Overwrite", 9) == 0) {
                if (h[i].value.len && (h[i].value.data[0] == 'F' || h[i].value.data[0] == 'f')) {
                    overwrite = 0;
                }
            }
            i++;
        }
    }

    if (dest_hdr.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* map source URI to filesystem path */
    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &src, &root_len, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* derive destination URI (strip scheme/host if present), percent-decode
     * and normalize duplicate slashes before mapping to filesystem */
    /* don't log Destination header contents in normal operation */
    {
        u_char *start = dest_hdr.data;
        u_char *end = dest_hdr.data + dest_hdr.len;
        u_char *path_start = NULL;

        /* If Destination is an absolute URI (scheme://authority/path)
         * find the first '/' after the authority. Support network-path
         * references that start with '//' as well. */
        u_char *scheme = (u_char *) ngx_strnstr(start, "://", dest_hdr.len);
        if (scheme) {
            u_char *after = scheme + 3;
            path_start = ngx_strlchr(after, end, '/');
            if (path_start == NULL) {
                return NGX_HTTP_BAD_REQUEST;
            }
        } else if (dest_hdr.len >= 2 && start[0] == '/' && start[1] == '/') {
            /* network-path reference: skip '//' and authority */
            path_start = ngx_strlchr(start + 2, end, '/');
            if (path_start == NULL) return NGX_HTTP_BAD_REQUEST;
        } else if (dest_hdr.len >= 1 && start[0] == '/') {
            /* absolute-path */
            path_start = start;
        } else {
            /* fallback: find first '/' anywhere */
            path_start = ngx_strlchr(start, end, '/');
            if (path_start == NULL) return NGX_HTTP_BAD_REQUEST;
        }

        /* percent-decode into pool-allocated buffer */
        size_t raw_len = (size_t)(end - path_start);
        u_char *raw = ngx_pnalloc(r->pool, raw_len + 1);
        if (raw == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_memcpy(raw, path_start, raw_len);
        raw[raw_len] = '\0';

        u_char *dec = ngx_pnalloc(r->pool, raw_len + 1);
        if (dec == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

        /* simple percent-decode */
        size_t di = 0;
        for (size_t ri = 0; ri < raw_len; ri++) {
            u_char c = raw[ri];
            if (c == '%' && ri + 2 < raw_len) {
                u_char hi = raw[ri+1];
                u_char lo = raw[ri+2];
                int vhi = -1, vlo = -1;
                if (hi >= '0' && hi <= '9') vhi = hi - '0';
                else if (hi >= 'A' && hi <= 'F') vhi = hi - 'A' + 10;
                else if (hi >= 'a' && hi <= 'f') vhi = hi - 'a' + 10;
                if (lo >= '0' && lo <= '9') vlo = lo - '0';
                else if (lo >= 'A' && lo <= 'F') vlo = lo - 'A' + 10;
                else if (lo >= 'a' && lo <= 'f') vlo = lo - 'a' + 10;

                if (vhi >= 0 && vlo >= 0) {
                    dec[di++] = (u_char) ((vhi << 4) | vlo);
                    ri += 2;
                    continue;
                }
            }
            dec[di++] = c;
        }
        dec[di] = '\0';

        /* normalize duplicate slashes (collapse '//' to '/') */
        u_char *norm = ngx_pnalloc(r->pool, di + 1);
        if (norm == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        size_t ni = 0;
        for (size_t i = 0; i < di; i++) {
            if (dec[i] == '/' && i + 1 < di && dec[i+1] == '/') continue;
            norm[ni++] = dec[i];
        }
        norm[ni] = '\0';

        ngx_str_t dest_uri;
        dest_uri.data = norm;
        dest_uri.len = ni;

        if (dest_uri.len == 0 || dest_uri.data[0] != '/') {
            return NGX_HTTP_BAD_REQUEST;
        }

        /* reject path traversal attempts ("..") and backslashes */
        {
            size_t pos = 0;
            while (pos < dest_uri.len) {
                if (dest_uri.data[pos] == '/') { pos++; continue; }
                size_t seg_start = pos;
                while (pos < dest_uri.len && dest_uri.data[pos] != '/') pos++;
                size_t seg_len = pos - seg_start;
                if (seg_len == 2 && dest_uri.data[seg_start] == '.' && dest_uri.data[seg_start+1] == '.') {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "dav: dest contains '..' segment, rejecting");
                    return NGX_HTTP_FORBIDDEN;
                }
                for (size_t i = seg_start; i < seg_start + seg_len; i++) {
                    if (dest_uri.data[i] == '\\') {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                }
            }
        }

        /* dest_uri mapping is intentionally not logged at debug level */

        /* temporarily set r->uri to destination and map it */
        ngx_str_t old_uri = r->uri;
        r->uri = dest_uri;
        last = ngx_http_map_uri_to_path(r, &dst, &root_len, 0);
        r->uri = old_uri;
        if (last == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

        /* mapped dst intentionally not logged to avoid noisy output */
    }

    /* enforce dav_access if configured (both src and dst) */
    if (dlcf->parsed_access) {
        ngx_keyval_t *kvs = dlcf->parsed_access->elts; ngx_uint_t i; ngx_flag_t ok = 0;
        for (i = 0; i < dlcf->parsed_access->nelts; i++) {
            if (src.len >= kvs[i].key.len && ngx_memcmp(src.data, kvs[i].key.data, kvs[i].key.len) == 0) { ok = 1; break; }
        }
        if (!ok) return NGX_HTTP_FORBIDDEN;
        ok = 0;
        for (i = 0; i < dlcf->parsed_access->nelts; i++) {
            if (dst.len >= kvs[i].key.len && ngx_memcmp(dst.data, kvs[i].key.data, kvs[i].key.len) == 0) { ok = 1; break; }
        }
        if (!ok) return NGX_HTTP_FORBIDDEN;
    }

    /* destination existence */
    ngx_file_info_t fi;
    ngx_flag_t dest_exists = (ngx_file_info((char *) dst.data, &fi) == 0);
    if (dest_exists && !overwrite) return NGX_HTTP_PRECONDITION_FAILED;
    ngx_ext_rename_file_t ext;
    ext.access = 0;
    ext.path_access = 0;
    ext.time = -1;
    ext.create_path = 0; /* parent ensured earlier */
    ext.delete_file = 0; /* do not delete source on failure */
    ext.log = r->connection->log;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "dav: MOVE attempt src='%V' dst='%V' overwrite=%d",
                  &src, &dst, (int) overwrite);

    if (ngx_ext_rename_file(&src, &dst, &ext) != NGX_OK) {
        /* cross-device link? try copy+unlink fallback */
        if (ngx_errno == EXDEV) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "dav: rename EXDEV, attempting copy fallback src='%V' dst='%V'",
                          &src, &dst);

            /* open source without following symlinks to mitigate TOCTOU */
            int infd = open((char *) src.data, O_RDONLY | O_NOFOLLOW);
            if (infd == -1) {
                if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_file_info_t sst;
            if (ngx_file_info((char *) src.data, &sst) == NGX_FILE_ERROR) {
                close(infd);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* handle directory copy recursively */
            if (S_ISDIR(sst.st_mode)) {
                if (ngx_http_dav_copy_dir(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
                    close(infd);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                close(infd);
                if (ngx_http_dav_remove_tree(r, (char *) src.data) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: remove src tree failed '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                return dest_exists ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
            }

            /* create a temp file in the destination directory for atomic replace */
            size_t tpl_len = dst.len + sizeof(".davXXXXXX") + 1;
            char *tmp_path = ngx_pnalloc(r->pool, tpl_len);
            if (tmp_path == NULL) { close(infd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            /* copy dst path and append template */
            ngx_memcpy(tmp_path, dst.data, dst.len);
            ngx_memcpy(tmp_path + dst.len, ".davXXXXXX", sizeof(".davXXXXXX"));
            tmp_path[dst.len + sizeof(".davXXXXXX") - 1] = '\0';

            int outfd = mkstemp(tmp_path);
            if (outfd == -1) {
                close(infd);
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* set mode on temp file */
            if (fchmod(outfd, sst.st_mode & 0777) == -1) {
                close(infd); close(outfd); ngx_delete_file(tmp_path);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ssize_t nread;
            char buf[8192];
            while ((nread = read(infd, buf, sizeof(buf))) > 0) {
                char *p = buf;
                ssize_t nw;
                ssize_t towrite = nread;
                while (towrite > 0) {
                    nw = write(outfd, p, towrite);
                    if (nw <= 0) break;
                    towrite -= nw; p += nw;
                }
                if (nw <= 0) break;
            }

            if (nread < 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "dav: copy fallback failed src='%V' dst='%V'", &src, &dst);
                close(infd); close(outfd); ngx_delete_file(tmp_path);
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* ensure data flushed */
            fsync(outfd);
            close(outfd);
            close(infd);

            /* atomic rename temp -> dst */
            if (rename(tmp_path, (char *) dst.data) != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "dav: rename(temp->dst) failed src='%V' dst='%V'", &src, &dst);
                ngx_delete_file(tmp_path);
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* verify source unchanged (avoid unlinking a different file) */
            {
                struct stat sb2;
                if (lstat((char *) src.data, &sb2) == -1) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "dav: lstat(src) failed after copy '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (sb2.st_ino != sst.st_ino || sb2.st_dev != sst.st_dev) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "dav: src changed during copy; refusing to unlink '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                /* prefer unlinking via parent dir fd to avoid races */
                if (ngx_http_dav_unlink_if_unchanged(r, (char *) src.data, &sst) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "dav: copy succeeded but unlink(src) failed '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            return dest_exists ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
        }

        /* if destination exists and overwrite requested, try remove dst then retry */
        if (ngx_errno == EEXIST && dest_exists && overwrite) {
            /* perform atomic replace: copy src -> temp in dst dir, rename temp->dst */
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "dav: atomic replace dst '%V' to honor Overwrite=T", &dst);

            int infd = open((char *) src.data, O_RDONLY | O_NOFOLLOW);
            if (infd == -1) {
                if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_file_info_t sst;
            if (fstat(infd, &sst) == -1) { close(infd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            if (S_ISLNK(sst.st_mode)) { close(infd); return NGX_HTTP_FORBIDDEN; }

            size_t tpl_len = dst.len + sizeof(".davXXXXXX") + 1;
            char *tmp_path = ngx_pnalloc(r->pool, tpl_len);
            if (tmp_path == NULL) { close(infd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            ngx_memcpy(tmp_path, dst.data, dst.len);
            ngx_memcpy(tmp_path + dst.len, ".davXXXXXX", sizeof(".davXXXXXX"));
            tmp_path[dst.len + sizeof(".davXXXXXX") - 1] = '\0';

            int outfd = mkstemp(tmp_path);
            if (outfd == -1) { close(infd); if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN; return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            if (fchmod(outfd, sst.st_mode & 0777) == -1) { close(infd); close(outfd); ngx_delete_file(tmp_path); return NGX_HTTP_INTERNAL_SERVER_ERROR; }

            ssize_t nread;
            char buf[8192];
            while ((nread = read(infd, buf, sizeof(buf))) > 0) {
                char *p = buf; ssize_t nw; ssize_t towrite = nread;
                while (towrite > 0) {
                    nw = write(outfd, p, towrite);
                    if (nw <= 0) break;
                    towrite -= nw; p += nw;
                }
                if (nw <= 0) break;
            }
            if (nread < 0) { close(infd); close(outfd); ngx_delete_file(tmp_path); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            fsync(outfd); close(outfd); close(infd);

            if (rename(tmp_path, (char *) dst.data) != 0) {
                ngx_delete_file(tmp_path);
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* verify source unchanged before unlinking */
            {
                struct stat sb2;
                if (lstat((char *) src.data, &sb2) == -1) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "dav: lstat(src) failed after atomic replace '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (sb2.st_ino != sst.st_ino || sb2.st_dev != sst.st_dev) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "dav: src changed during atomic replace; refusing to unlink '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (ngx_http_dav_unlink_if_unchanged(r, (char *) src.data, &sst) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "dav: atomic replace succeeded but unlink(src) failed '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            return NGX_HTTP_NO_CONTENT;
        }

        /* map common errno to HTTP */
        if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
        if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "dav: MOVE success src='%V' dst='%V'", &src, &dst);
    return dest_exists ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

/* Copy a regular file from src -> dst atomically using a temp file in dst's directory. */
static ngx_int_t
ngx_http_dav_copy_file_atomic(ngx_http_request_t *r, const char *src, const char *dst)
{
    int infd = open(src, O_RDONLY | O_NOFOLLOW);
    if (infd == -1) {
        return NGX_ERROR;
    }

    struct stat st;
    if (fstat(infd, &st) == -1) { close(infd); return NGX_ERROR; }
    if (S_ISLNK(st.st_mode)) { close(infd); return NGX_ERROR; }

    size_t dstlen = ngx_strlen(dst);
    size_t tpl_len = dstlen + sizeof(".davXXXXXX") + 1;
    char *tmp_path = ngx_pnalloc(r->pool, tpl_len);
    if (tmp_path == NULL) { close(infd); return NGX_ERROR; }
    ngx_memcpy(tmp_path, dst, dstlen);
    ngx_memcpy(tmp_path + dstlen, ".davXXXXXX", sizeof(".davXXXXXX"));
    tmp_path[dstlen + sizeof(".davXXXXXX") - 1] = '\0';

    int outfd = mkstemp(tmp_path);
    if (outfd == -1) { close(infd); return NGX_ERROR; }
    if (fchmod(outfd, st.st_mode & 0777) == -1) { close(infd); close(outfd); ngx_delete_file(tmp_path); return NGX_ERROR; }

    ssize_t nread;
    char buf[8192];
    while ((nread = read(infd, buf, sizeof(buf))) > 0) {
        ssize_t towrite = nread;
        char *p = buf;
        while (towrite > 0) {
            ssize_t nw = write(outfd, p, towrite);
            if (nw <= 0) { close(infd); close(outfd); ngx_delete_file(tmp_path); return NGX_ERROR; }
            towrite -= nw; p += nw;
        }
    }

    if (nread < 0) { close(infd); close(outfd); ngx_delete_file(tmp_path); return NGX_ERROR; }

    fsync(outfd);
    close(outfd);
    close(infd);

    if (rename(tmp_path, dst) != 0) { ngx_delete_file(tmp_path); return NGX_ERROR; }

    /* preserve timestamps */
    struct utimbuf times;
    times.actime = st.st_atime;
    times.modtime = st.st_mtime;
    utime(dst, &times);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_copy_dir(ngx_http_request_t *r, const char *src, const char *dst)
{
    DIR *d = opendir(src);
    if (d == NULL) return NGX_ERROR;

    struct stat st;
    if (stat(src, &st) == -1) { closedir(d); return NGX_ERROR; }
    if (mkdir(dst, st.st_mode & 0777) == -1) {
        if (errno != EEXIST) { closedir(d); return NGX_ERROR; }
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ngx_strcmp(ent->d_name, ".") == 0 || ngx_strcmp(ent->d_name, "..") == 0) continue;
        size_t slen = strlen(src);
        size_t dlen = strlen(dst);
        size_t entry_len = slen + 1 + strlen(ent->d_name) + 1;
        char *src_entry = ngx_pnalloc(r->pool, entry_len);
        if (src_entry == NULL) { closedir(d); return NGX_ERROR; }
        ngx_snprintf((u_char *) src_entry, entry_len, "%s/%s", src, ent->d_name);

        size_t dst_entry_len = dlen + 1 + strlen(ent->d_name) + 1;
        char *dst_entry = ngx_pnalloc(r->pool, dst_entry_len);
        if (dst_entry == NULL) { closedir(d); return NGX_ERROR; }
        ngx_snprintf((u_char *) dst_entry, dst_entry_len, "%s/%s", dst, ent->d_name);

        struct stat est;
        if (lstat(src_entry, &est) == -1) { closedir(d); return NGX_ERROR; }
        if (S_ISLNK(est.st_mode)) { closedir(d); return NGX_ERROR; }
        if (S_ISDIR(est.st_mode)) {
            if (ngx_http_dav_copy_dir(r, src_entry, dst_entry) != NGX_OK) { closedir(d); return NGX_ERROR; }
        } else if (S_ISREG(est.st_mode)) {
            if (ngx_http_dav_copy_file_atomic(r, src_entry, dst_entry) != NGX_OK) { closedir(d); return NGX_ERROR; }
        } else {
            /* skip special files */
        }
    }

    closedir(d);

    /* preserve directory times */
    struct utimbuf times;
    times.actime = st.st_atime;
    times.modtime = st.st_mtime;
    utime(dst, &times);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_remove_tree(ngx_http_request_t *r, const char *path)
{
    DIR *d = opendir(path);
    if (d == NULL) return NGX_ERROR;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ngx_strcmp(ent->d_name, ".") == 0 || ngx_strcmp(ent->d_name, "..") == 0) continue;
        size_t plen = strlen(path);
        size_t elen = strlen(ent->d_name);
        size_t buf_len = plen + 1 + elen + 1;
        char *p = ngx_pnalloc(r->pool, buf_len);
        if (p == NULL) { closedir(d); return NGX_ERROR; }
        ngx_snprintf((u_char *) p, buf_len, "%s/%s", path, ent->d_name);

        struct stat st;
        if (lstat(p, &st) == -1) { closedir(d); return NGX_ERROR; }
        if (S_ISDIR(st.st_mode)) {
            if (ngx_http_dav_remove_tree(r, p) != NGX_OK) { closedir(d); return NGX_ERROR; }
            if (rmdir(p) == -1) { closedir(d); return NGX_ERROR; }
        } else {
            if (unlink(p) == -1) { closedir(d); return NGX_ERROR; }
        }
    }

    closedir(d);
    return NGX_OK;
}

/* Unlink path only if it still refers to the original inode/dev. Uses parent dir fd + unlinkat. */
static ngx_int_t
ngx_http_dav_unlink_if_unchanged(ngx_http_request_t *r, const char *path, const ngx_file_info_t *orig_st)
{
    const char *slash = strrchr(path, '/');
    const char *name;
    char *parent = NULL;
    int dfd = -1;

    if (slash == NULL) {
        return NGX_ERROR;
    }

    if (slash == path) {
        /* parent is root */
        parent = (char *)"/";
        name = slash + 1;
    } else {
        size_t plen = (size_t)(slash - path);
        parent = ngx_pnalloc(r->pool, plen + 1);
        if (parent == NULL) return NGX_ERROR;
        ngx_memcpy(parent, path, plen);
        parent[plen] = '\0';
        name = slash + 1;
    }

    dfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd == -1) {
        return NGX_ERROR;
    }

    struct stat sb;
    if (fstatat(dfd, name, &sb, AT_SYMLINK_NOFOLLOW) == -1) {
        close(dfd);
        return NGX_ERROR;
    }

    if (sb.st_ino != orig_st->st_ino || sb.st_dev != orig_st->st_dev) {
        close(dfd);
        return NGX_ERROR;
    }

    int flags = 0;
    if (S_ISDIR(orig_st->st_mode)) flags = AT_REMOVEDIR;

    if (unlinkat(dfd, name, flags) == -1) {
        close(dfd);
        return NGX_ERROR;
    }

    close(dfd);
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
