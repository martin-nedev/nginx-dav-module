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

    return NGX_DECLINED;
}

static void
ngx_http_dav_put_body_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t                 path;
    u_char                   *last;
    ngx_str_t                 tmpname;
    ngx_flag_t                exists = 0;

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
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            *p = saved;
        }
    }

    {
        ngx_ext_rename_file_t ext;

        if (r->request_body == NULL || r->request_body->temp_file == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: PUT request body must be in a file");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }


        {
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

        ngx_file_info_t  fi;

        if (ngx_file_info((char *) path.data, &fi) != NGX_FILE_ERROR) {
            exists = 1;
        }

        ext.access = 0;
        ext.path_access = 0;
        ext.time = -1;
        ext.create_path = dlcf->create_full_path;
        ext.delete_file = 1;
        ext.log = r->connection->log;

        {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "dav: cwd='%s'", cwd);
            } else {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, ngx_errno,
                              "dav: getcwd failed");
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "dav: pre-rename src='%V' dst='%V' src_len=%z dst_len=%z",
                          &r->request_body->temp_file->file.name, &path,
                          r->request_body->temp_file->file.name.len, path.len);

            if (access((char *) r->request_body->temp_file->file.name.data, F_OK) == 0) {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "dav: access(src) ok");
            } else {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, ngx_errno,
                              "dav: access(src) failed");
            }

            {
                size_t i, dump_len;
                u_char hexbuf[512];
                u_char *s = r->request_body->temp_file->file.name.data;
                u_char *d = path.data;

                dump_len = r->request_body->temp_file->file.name.len;
                if (dump_len > 64) dump_len = 64;
                for (i = 0; i < dump_len; i++) {
                    ngx_sprintf(&hexbuf[i*2], "%02xd", s[i]);
                }
                hexbuf[dump_len*2] = '\0';
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "dav: src hex(first %uz)=%s", dump_len, hexbuf);

                dump_len = path.len;
                if (dump_len > 64) dump_len = 64;
                for (i = 0; i < dump_len; i++) {
                    ngx_sprintf(&hexbuf[i*2], "%02xd", d[i]);
                }
                hexbuf[dump_len*2] = '\0';
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "dav: dst hex(first %uz)=%s", dump_len, hexbuf);
            }

                struct stat sb;
                if (stat((char *) r->request_body->temp_file->file.name.data, &sb) == 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "dav: stat(src) ok ino=%llu size=%lld",
                                  (unsigned long long) sb.st_ino,
                                  (long long) sb.st_size);
                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "dav: stat(src) failed");
                }

                /* parent dir */
                u_char *p = path.data + path.len - 1;
                char parent[PATH_MAX];
                size_t plen = 0;
                while (p > path.data && *p != '/') p--;
                if (p > path.data) {
                    plen = p - path.data;
                    if (plen >= sizeof(parent)) plen = sizeof(parent) - 1;
                    ngx_memcpy(parent, path.data, plen);
                    parent[plen] = '\0';
                    if (stat(parent, &sb) == 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "dav: stat(parent) ok ino=%llu",
                                      (unsigned long long) sb.st_ino);
                    } else {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                      "dav: stat(parent) failed '%s'", parent);
                    }
                }
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "dav: temp fd=%d", (int) r->request_body->temp_file->file.fd);

            /* check destination and its parent dir */
            if (access((char *) path.data, F_OK) == 0) {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "dav: access(dst) ok");
            } else {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, ngx_errno,
                              "dav: access(dst) failed");
            }

            /* parent dir existence */
            {
                u_char *p = path.data + path.len - 1;
                char parent[PATH_MAX];
                size_t plen = 0;
                while (p > path.data && *p != '/') p--;
                if (p > path.data) {
                    plen = p - path.data;
                    if (plen >= sizeof(parent)) plen = sizeof(parent) - 1;
                    ngx_memcpy(parent, path.data, plen);
                    parent[plen] = '\0';
                    if (access(parent, F_OK) == 0) {
                        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                      "dav: access(parent) ok '%s'", parent);
                    } else {
                        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, ngx_errno,
                                      "dav: access(parent) failed '%s'", parent);
                    }
                }
            }
        }

        if (ngx_ext_rename_file(&r->request_body->temp_file->file.name, &path, &ext) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

         /* closing/deleting the temp file as appropriate. */

        tmpname = r->request_body->temp_file->file.name;
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "dav: destination existed=%d", (int) exists);
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "dav: renamed \"%V\" -> \"%V\"", &tmpname, &path);

    ngx_http_dav_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
        if (ctx == NULL) {
            return;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
    }

    if (exists) {
        ctx->status = NGX_HTTP_NO_CONTENT;
    } else {
        ctx->status = NGX_HTTP_CREATED;
    }
    ctx->done = 1;
    
    /* ensure proper cleanup */
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
