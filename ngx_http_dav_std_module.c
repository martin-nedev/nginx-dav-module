
/* === WebDAV module for nginx
       Written by Martin Nedev, 2026 === */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_DAV_MULTI_STATUS           207

#define NGX_HTTP_DAV_ZERO_DEPTH             0
#define NGX_HTTP_DAV_INFINITY_DEPTH        -1
#define NGX_HTTP_DAV_INVALID_DEPTH         -2

#define NGX_HTTP_DAV_LOCKED                 423

#define NGX_HTTP_DAV_LOCK_TOKEN_PREFIX     "opaquelocktoken:"

#define NGX_HTTP_DAV_LOCK_DEFAULT_SIZE     (5 * 1024 * 1024)
#define NGX_HTTP_DAV_LOCK_MAX_SIZE         (128 * 1024 * 1024)

#define NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT  (1 * 60 * 60)
#define NGX_HTTP_DAV_LOCK_MAX_TIMEOUT      (24 * 60 * 60)

#define NGX_HTTP_DAV_OFF                    2

#define NGX_HTTP_DAV_ALL  (NGX_HTTP_PUT|NGX_HTTP_DELETE|\
                           NGX_HTTP_MKCOL|\
                           NGX_HTTP_COPY|NGX_HTTP_MOVE|\
                           NGX_HTTP_PROPFIND|NGX_HTTP_PROPPATCH|\
                           NGX_HTTP_OPTIONS|\
                           NGX_HTTP_LOCK|NGX_HTTP_UNLOCK)

typedef struct {
    ngx_str_t  path;
    size_t     len;
} ngx_http_dav_copy_ctx_t;

typedef struct {
    ngx_str_t  name;
    ngx_str_t  xml;
} ngx_http_dav_prop_t;

typedef struct {
    ngx_array_t  *req_props;
    ngx_str_t     req_xmlns;
    ngx_uint_t    prop_req;
    ngx_uint_t    allprop;
    ngx_uint_t    propname;
} ngx_http_dav_propfind_ctx_t;

typedef struct {
    ngx_queue_t  queue;
    time_t       expire;
    ngx_uint_t   infinite;
    ngx_uint_t   shared;
    size_t       path_len;
    size_t       token_len;
    u_char       data[1];
} ngx_http_dav_lock_node_t;

typedef struct {
    ngx_queue_t  queue;
    ngx_uint_t   active_locks;
    ngx_uint_t   allocated_count;
    ngx_uint_t   expired_count;
    ngx_uint_t   freed_count;
    ngx_uint_t   alloc_failures;
} ngx_http_dav_lock_shctx_t;

typedef struct {
    ngx_http_dav_lock_shctx_t  *sh;
    ngx_slab_pool_t            *shpool;
    ssize_t                     size;
    ngx_int_t                   timeout;
} ngx_http_dav_lock_shm_t;

typedef struct {
    ngx_flag_t       create_full_path;
    ngx_uint_t       access;
    ngx_uint_t       min_delete_depth;
    ngx_shm_zone_t  *shm_zone;
    ngx_int_t        lock_timeout;
    ngx_uint_t       methods;
    ngx_flag_t       enabled;
} ngx_http_dav_loc_conf_t;

typedef struct {
    ngx_http_dav_lock_shm_t          *shm;
    ngx_http_output_header_filter_pt  next_header_filter;
} ngx_http_dav_main_conf_t;

/* === Config === */

static ngx_conf_bitmask_t  ngx_http_dav_methods_mask[] = {
    { ngx_string("off"), NGX_HTTP_DAV_OFF },
    { ngx_string("on"), NGX_HTTP_DAV_ALL },
    { ngx_string("put"), NGX_HTTP_PUT },
    { ngx_string("delete"), NGX_HTTP_DELETE },
    { ngx_string("mkcol"), NGX_HTTP_MKCOL },
    { ngx_string("copy"), NGX_HTTP_COPY },
    { ngx_string("move"), NGX_HTTP_MOVE },
    { ngx_string("propfind"), NGX_HTTP_PROPFIND },
    { ngx_string("proppatch"), NGX_HTTP_PROPPATCH },
    { ngx_string("options"), NGX_HTTP_OPTIONS },
    { ngx_string("lock"), NGX_HTTP_LOCK },
    { ngx_string("unlock"), NGX_HTTP_UNLOCK },
    { ngx_null_string, 0 }
};

static char *
ngx_http_dav_lock_zone(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);

static ngx_command_t  ngx_http_dav_commands[] = {
    { ngx_string("dav_create_full_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dav_loc_conf_t, create_full_path),
        NULL },
    { ngx_string("create_full_put_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dav_loc_conf_t, create_full_path),
        NULL },
    { ngx_string("dav_access"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_access_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dav_loc_conf_t, access),
        NULL },
    { ngx_string("dav_min_delete_depth"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dav_loc_conf_t, min_delete_depth),
        NULL },
    { ngx_string("min_delete_depth"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dav_loc_conf_t, min_delete_depth),
        NULL },
    { ngx_string("dav_lock_zone"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_http_dav_lock_zone,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    { ngx_string("dav_methods"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dav_loc_conf_t, methods),
        &ngx_http_dav_methods_mask },
    ngx_null_command
};

/* === Init === */

static ngx_int_t
ngx_http_dav_init(ngx_conf_t *cf);

static void *
ngx_http_dav_create_main_conf(ngx_conf_t *cf);

static void *
ngx_http_dav_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_http_module_t  ngx_http_dav_module_ctx = {
    NULL,
    ngx_http_dav_init,
    ngx_http_dav_create_main_conf,
    NULL, NULL, NULL,
    ngx_http_dav_create_loc_conf,
    ngx_http_dav_merge_loc_conf
};

ngx_module_t  ngx_http_dav_module = {
    NGX_MODULE_V1,
    &ngx_http_dav_module_ctx,
    ngx_http_dav_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* === PUT === */

static ngx_table_elt_t *
ngx_http_dav_find_header(ngx_http_request_t *r, const char *name, size_t len)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == len &&
            ngx_strncasecmp(h[i].key.data, (u_char *) name, len) == 0) {
            return &h[i];
        }
    }

    return NULL;
}

static ngx_int_t
ngx_http_dav_location(ngx_http_request_t *r)
{
    u_char    *p;
    size_t     len;
    uintptr_t  escape;

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.location->hash = 1;
    r->headers_out.location->next = NULL;

    ngx_str_set(&r->headers_out.location->key, "Location");

    escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
    if (escape) {
        len = r->uri.len + escape;

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            ngx_http_clear_location(r);
            return NGX_ERROR;
        }

        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = p;

        ngx_escape_uri(p, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
    } else {
        r->headers_out.location->value = r->uri;
    }

    return NGX_OK;
}

static void
ngx_http_dav_put_finalize(ngx_http_request_t *r)
{
    size_t                    root;
    time_t                    date;
    ngx_str_t                *temp, path;
    ngx_uint_t                status;
    ngx_file_info_t           fi;
    ngx_ext_rename_file_t     ext;
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_table_elt_t          *date_header;

    if (r->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "PUT request body is unavailable");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    if (r->request_body->temp_file == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "PUT request body must be in a file");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    path.len--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http put filename: \"%s\"", path.data);

    temp = &r->request_body->temp_file->file.name;

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        status = NGX_HTTP_CREATED;
    } else {
        status = NGX_HTTP_NO_CONTENT;

        if (ngx_is_dir(&fi)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
                "\"%s\" could not be created", path.data);

            if (ngx_delete_file(temp->data) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                    ngx_delete_file_n " \"%s\" failed", temp->data);
            }

            ngx_http_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    ext.access = dlcf->access;
    ext.path_access = dlcf->access;
    ext.time = -1;
    ext.create_path = dlcf->create_full_path;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    date_header = ngx_http_dav_find_header(r, "Date", sizeof("Date") - 1);
    if (date_header) {
        date = ngx_parse_http_time(date_header->value.data,
            date_header->value.len);

        if (date != NGX_ERROR) {
            ext.time = date;
            ext.fd = r->request_body->temp_file->file.fd;
        }
    }

    if (ngx_ext_rename_file(temp, &path, &ext) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
            ngx_rename_file_n "\"%s\" failed", temp->data);

        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (status == NGX_HTTP_CREATED) {
        if (ngx_http_dav_location(r) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    ngx_http_finalize_request(r, ngx_http_send_header(r));
}

static ngx_int_t
ngx_http_dav_put_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->uri.data[r->uri.len - 1] == '/') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "cannot PUT to a collection");
        return NGX_HTTP_CONFLICT;
    }
    if (r->headers_in.content_range) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "PUT with range is unsupported");
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    r->request_body_in_file_only = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;
    r->request_body_file_group_access = 1;
    r->request_body_file_log_level = 0;

    rc = ngx_http_read_client_request_body(r, ngx_http_dav_put_finalize);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

/* === DELETE === */

static ngx_int_t
ngx_http_dav_error(ngx_log_t *log, ngx_err_t err,
    ngx_int_t not_found, char *failed, u_char *path)
{
    ngx_uint_t  level;
    ngx_int_t   rc;

    if (err == NGX_ENOENT || err == NGX_ENOTDIR || err == NGX_ENAMETOOLONG) {
        level = NGX_LOG_ERR;
        rc = not_found;
    } else if (err == NGX_EACCES || err == NGX_EPERM) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_FORBIDDEN;
    } else if (err == NGX_EEXIST) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_NOT_ALLOWED;
    } else if (err == NGX_ENOSPC) {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INSUFFICIENT_STORAGE;
    } else {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(level, log, err, "%s \"%s\" failed", failed, path);

    return rc;
}

static ngx_int_t
ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt)
{
    ngx_table_elt_t  *h;

#if (NGX_HTTP_DAV)
    h = r->headers_in.depth;
    if (h == NULL) {
        h = ngx_http_dav_find_header(r, "Depth", sizeof("Depth") - 1);
    }

#else
    h = ngx_http_dav_find_header(r, "Depth", sizeof("Depth") - 1);
#endif
    if (h == NULL) {
        return dflt;
    }
    if (h->value.len == 0) {
        return NGX_HTTP_DAV_INVALID_DEPTH;
    }
    if (h->value.len == 1 && h->value.data[0] == '0') {
        return 0;
    }
    if (h->value.len == 1 && h->value.data[0] == '1') {
        return 1;
    }
    if (h->value.len == sizeof("infinity") - 1 &&
        ngx_strncasecmp(h->value.data, (u_char *) "infinity",
            sizeof("infinity") - 1) == 0) {
        return NGX_HTTP_DAV_INFINITY_DEPTH;
    }

    return NGX_HTTP_DAV_INVALID_DEPTH;
}

static ngx_int_t
ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0, "http delete file: \"%s\"",
        path->data);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0,
            ngx_delete_file_n, path->data);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_pre_tree(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_post_tree(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0, "http delete dir: \"%s\"",
        path->data);

    if (ngx_delete_dir(path->data) == NGX_FILE_ERROR) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_delete_dir_n,
            path->data);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_path(ngx_http_request_t *r, ngx_str_t *path, ngx_uint_t dir)
{
    ngx_tree_ctx_t  tree;

    if (dir) {
        tree.init_handler = NULL;
        tree.file_handler = ngx_http_dav_delete_file;
        tree.pre_tree_handler = ngx_http_dav_delete_pre_tree;
        tree.post_tree_handler = ngx_http_dav_delete_post_tree;
        tree.spec_handler = ngx_http_dav_delete_file;
        tree.data = NULL;
        tree.alloc = 0;
        tree.log = r->connection->log;

        if (ngx_walk_tree(&tree, path) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (ngx_delete_dir(path->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        return ngx_http_dav_error(r->connection->log, ngx_errno,
            NGX_HTTP_NOT_FOUND, ngx_delete_dir_n, path->data);
    }

    tree.data = NULL;
    return ngx_http_dav_delete_file(&tree, path);
}

static ngx_int_t
ngx_http_dav_props_path(ngx_http_request_t *r, ngx_str_t *path,
    ngx_str_t *ppath)
{
    size_t                     len, root_len, base_len, path_len;
    u_char                    *p, *s, *slash;
    ngx_str_t                  name, dir, base;
    ngx_http_core_loc_conf_t  *clcf;

    path_len = path->len;
    if (path_len && path->data[path_len - 1] == '\0') {
        path_len--;
    }

    if (path_len < r->uri.len) {
        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->alias && r->uri.len >= clcf->name.len) {
        root_len = path_len - (r->uri.len - clcf->name.len);
    } else {
        root_len = path_len - r->uri.len;
    }

    if (root_len > path_len) {
        return NGX_ERROR;
    }

    base_len = root_len;

    name.data = path->data + base_len;
    name.len = path_len - base_len;
    if (name.len && name.data[0] == '/') {
        name.data++;
        name.len--;
    }
    if (name.len && name.data[name.len - 1] == '/') {
        name.len--;
    }
    if (name.len == 0) {
        ngx_str_set(&name, "root");
    }

    slash = NULL;

    for (s = name.data + name.len; s > name.data; s--) {
        if (*(s - 1) == '/') {
            slash = s - 1;
            break;
        }
    }

    if (slash) {
        dir.data = name.data;
        dir.len = (size_t) (slash - name.data);
        base.data = slash + 1;
        base.len = (size_t) ((name.data + name.len) - base.data);
    } else {
        dir.len = 0;
        base = name;
    }

    if (root_len > 0 && path->data[root_len - 1] == '\0') {
        root_len--;
    }

    len = root_len
        + (root_len && path->data[root_len - 1] != '/' ? 1 : 0)
        + dir.len
        + (dir.len ? 1 : 0)
        + (sizeof(".props/") - 1)
        + base.len
        + (sizeof(".props") - 1);

    p = ngx_pnalloc(r->pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(p, path->data, root_len);

    if (root_len && path->data[root_len - 1] != '/') {
        *p++ = '/';
    }

    if (dir.len) {
        p = ngx_cpymem(p, dir.data, dir.len);
        *p++ = '/';
    }

    p = ngx_cpymem(p, ".props/", sizeof(".props/") - 1);
    p = ngx_cpymem(p, base.data, base.len);
    p = ngx_cpymem(p, ".props", sizeof(".props") - 1);
    *p = '\0';

    ppath->data = p - len;
    ppath->len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_props_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_http_request_t  *r;
    ngx_str_t            ppath;

    r = ctx->data;
    if (ngx_http_dav_props_path(r, path, &ppath) == NGX_OK) {
        (void) ngx_delete_file(ppath.data);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_props_pre_tree(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_props_post_tree(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_http_request_t  *r;
    ngx_str_t            ppath;
    u_char              *dir, *p, *root;
    size_t               len, min_len;

    (void) ngx_http_dav_delete_props_file(ctx, path);

    r = ctx->data;
    if (ngx_http_dav_props_path(r, path, &ppath) != NGX_OK) {
        return NGX_OK;
    }

    dir = ngx_pnalloc(r->pool, ppath.len + 1);
    if (dir == NULL) {
        return NGX_OK;
    }

    p = ngx_cpymem(dir, ppath.data, ppath.len);
    *p = '\0';

    p = dir + ngx_strlen(dir);
    while (p > dir && *(p - 1) != '/') {
        p--;
    }

    if (p == dir) {
        return NGX_OK;
    }

    *(p - 1) = '\0';
    len = (size_t) ((p - 1) - dir);

    root = (u_char *) ngx_strnstr(dir, "/.props/", len);
    if (root == NULL) {
        root = (u_char *) ngx_strnstr(dir, "/.props", len);
        if (root == NULL) {
            return NGX_OK;
        }
    }

    min_len = (root - dir) + (sizeof("/.props") - 1);
    while (len > min_len) {

        if (ngx_delete_dir(dir) == NGX_FILE_ERROR) {
            if (ngx_errno == ENOTEMPTY || ngx_errno == NGX_EEXIST) {
                break;
            }
        }

        p = dir + len;
        while (p > dir && *(p - 1) != '/') {
            p--;
        }

        if (p == dir) {
            break;
        }

        *(p - 1) = '\0';
        len = (size_t) ((p - 1) - dir);
    }

    if (ppath.len > sizeof(".props") - 1) {
        p = ngx_cpymem(dir, ppath.data, ppath.len);
        *p = '\0';

        if (ppath.len >= sizeof(".props") - 1 &&
            ngx_strncmp(dir + (ppath.len - (sizeof(".props") - 1)), ".props",
                sizeof(".props") - 1) == 0) {
            dir[ppath.len - (sizeof(".props") - 1)] = '\0';
        } else {
            return NGX_OK;
        }

        len = ppath.len - (sizeof(".props") - 1);

        root = (u_char *) ngx_strnstr(dir, "/.props/", len);
        if (root == NULL) {
            root = (u_char *) ngx_strnstr(dir, "/.props", len);
            if (root == NULL) {
                return NGX_OK;
            }
        }

        min_len = (root - dir) + (sizeof("/.props") - 1);
        while (len > min_len) {

            if (ngx_delete_dir(dir) == NGX_FILE_ERROR) {
                if (ngx_errno == ENOTEMPTY || ngx_errno == NGX_EEXIST) {
                    break;
                }
            }

            p = dir + len;
            while (p > dir && *(p - 1) != '/') {
                p--;
            }

            if (p == dir) {
                break;
            }

            *(p - 1) = '\0';
            len = (size_t) ((p - 1) - dir);
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_props(ngx_http_request_t *r, ngx_str_t *path, ngx_uint_t dir)
{
    ngx_tree_ctx_t  tree;

    if (dir) {
        tree.init_handler = NULL;
        tree.file_handler = ngx_http_dav_delete_props_file;
        tree.pre_tree_handler = ngx_http_dav_delete_props_pre_tree;
        tree.post_tree_handler = ngx_http_dav_delete_props_post_tree;
        tree.spec_handler = ngx_http_dav_delete_props_file;
        tree.data = r;
        tree.alloc = 0;
        tree.log = r->connection->log;

        (void) ngx_walk_tree(&tree, path);
        (void) ngx_http_dav_delete_props_post_tree(&tree, path);

        return NGX_OK;
    }

    tree.data = r;

    return ngx_http_dav_delete_props_file(&tree, path);
}

static ngx_int_t
ngx_http_dav_delete_handler(ngx_http_request_t *r)
{
    size_t                    root;
    ngx_err_t                 err;
    ngx_str_t                 path;
    ngx_int_t                 rc;
    ngx_uint_t                d;
    ngx_uint_t                dir;
    ngx_file_info_t           fi;
    ngx_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "DELETE with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
    if (r->unparsed_uri.len && ngx_strlchr(r->unparsed_uri.data,
            r->unparsed_uri.data + r->unparsed_uri.len, '#') != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "DELETE with fragment is unsupported");
        return NGX_HTTP_BAD_REQUEST;
    }
    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http delete filename: \"%s\"", path.data);

    d = 0;
    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    if (r->uri.len) {
        u_char *p = r->uri.data + 1;
        u_char *last = r->uri.data + r->uri.len;
        while (p < last) {
            if (*p++ == '/') {
                d++;
            }
        }
    }

    if (d < dlcf->min_delete_depth) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "insufficient URI depth:%i to DELETE", d);
        return NGX_HTTP_CONFLICT;
    }

    if (ngx_link_info(path.data, &fi) == NGX_FILE_ERROR) {
        err = ngx_errno;
        if (err == NGX_ENOTDIR) {
            return NGX_HTTP_CONFLICT;
        }
        return NGX_HTTP_NOT_FOUND;
    }

    if (ngx_is_dir(&fi)) {
        ngx_int_t  depth;

        if (r->uri.data[r->uri.len - 1] != '/') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "DELETE on collection without trailing slash: \"%V\"", &r->uri);
        }

        depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
        if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "\"Depth\" header must be infinity");
            return NGX_HTTP_BAD_REQUEST;
        }

        if (path.len > 0 && path.data[path.len - 1] == '/') {
            path.len--;
            path.data[path.len] = '\0';
        }

        dir = 1;
    } else {
        ngx_int_t  depth;

        depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_ZERO_DEPTH);
        if (depth != NGX_HTTP_DAV_ZERO_DEPTH && depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "\"Depth\" header must be 0 or infinity");
            return NGX_HTTP_BAD_REQUEST;
        }

        dir = 0;
    }

    rc = ngx_http_dav_delete_path(r, &path, dir);
    if (rc != NGX_OK) {
        return rc;
    }

    (void) ngx_http_dav_delete_props(r, &path, dir);

    if (dir) {
        ngx_str_t  ppath;

        if (ngx_http_dav_props_path(r, &path, &ppath) == NGX_OK) {
            u_char  *prefix, *p, *root;
            size_t   len, min_len;

            prefix = ngx_pnalloc(r->pool, ppath.len + 1);
            if (prefix == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = ngx_cpymem(prefix, ppath.data, ppath.len);
            *p = '\0';

            if (ppath.len >= sizeof(".props") - 1 &&
                ngx_strncmp(prefix + (ppath.len - (sizeof(".props") - 1)),
                    ".props", sizeof(".props") - 1) == 0) {
                prefix[ppath.len - (sizeof(".props") - 1)] = '\0';
            } else {
                return NGX_HTTP_NO_CONTENT;
            }

            len = ngx_strlen(prefix);

            root = (u_char *) ngx_strnstr(prefix, "/.props/", len);
            if (root == NULL) {
                root = (u_char *) ngx_strnstr(prefix, "/.props", len);
                if (root == NULL) {
                    return NGX_HTTP_NO_CONTENT;
                }
            }

            min_len = (root - prefix) + (sizeof("/.props") - 1);
            while (len > min_len) {

                if (ngx_delete_dir(prefix) == NGX_FILE_ERROR) {
                    if (ngx_errno == ENOTEMPTY || ngx_errno == NGX_EEXIST) {
                        break;
                    }
                }

                p = prefix + len;
                while (p > prefix && *(p - 1) != '/') {
                    p--;
                }

                if (p == prefix) {
                    break;
                }

                *(p - 1) = '\0';
                len = ngx_strlen(prefix);
            }
        }
    }

    return NGX_HTTP_NO_CONTENT;
}

/* === MKCOL === */

static ngx_int_t
ngx_http_dav_mkcol_handler(ngx_http_request_t *r, ngx_http_dav_loc_conf_t *dlcf)
{
    u_char     *p;
    size_t      root;
    ngx_str_t   path;
    ngx_uint_t  add_slash;
    ngx_int_t   rc;

    if (r->headers_in.chunked) {
        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "MKCOL with request body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (r->headers_in.content_length) {
        off_t  cl;

        cl = ngx_atoi(r->headers_in.content_length->value.data,
            r->headers_in.content_length->value.len);
        if (cl == NGX_ERROR) {
            return NGX_HTTP_BAD_REQUEST;
        }

        if (cl > 0) {
            rc = ngx_http_discard_request_body(r);
            if (rc != NGX_OK) {
                return rc;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "MKCOL with request body is unsupported");
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }
    }

    add_slash = 0;

    if (r->uri.len && r->uri.data[r->uri.len - 1] != '/') {
        add_slash = 1;
    }

    p = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (p > path.data && *(p - 1) == '/') {
        *(p - 1) = '\0';
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http mkcol path: \"%s\"", path.data);

    if (ngx_create_dir(path.data, ngx_dir_access(dlcf->access)) != NGX_FILE_ERROR) {

        if (add_slash) {
            u_char *u = ngx_pnalloc(r->pool, r->uri.len + 1);

            if (u == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            u = ngx_cpymem(u, r->uri.data, r->uri.len);
            *u++ = '/';

            r->uri.data = u - (r->uri.len + 1);
            r->uri.len = r->uri.len + 1;
        }

        if (ngx_http_dav_location(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_HTTP_CREATED;
    }

    return ngx_http_dav_error(r->connection->log, ngx_errno,
                              NGX_HTTP_CONFLICT, ngx_create_dir_n, path.data);
}

/* === COPY === */

static ngx_int_t
ngx_http_dav_copy_props(ngx_http_request_t *r, ngx_str_t *src, ngx_str_t *dst)
{
    ngx_str_t                 spath, dpath;
    ngx_copy_file_t           cf;
    ngx_file_info_t           fi;
    ngx_http_dav_loc_conf_t  *dlcf;
    u_char                   *dir;
    u_char                   *last;

    if (ngx_http_dav_props_path(r, src, &spath) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_http_dav_props_path(r, dst, &dpath) != NGX_OK) {
        return NGX_ERROR;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    dir = ngx_pnalloc(r->pool, dpath.len + 1);
    if (dir == NULL) {
        return NGX_ERROR;
    }

    last = ngx_cpymem(dir, dpath.data, dpath.len);
    *last = '\0';

    last = dir + ngx_strlen(dir);
    while (last > dir && *(last - 1) != '/') {
        last--;
    }

    if (last > dir) {
        *last = '\0';
        (void) ngx_create_full_path(dir, ngx_dir_access(dlcf->access));
    }

    if (ngx_file_info(spath.data, &fi) == NGX_FILE_ERROR) {
        if (ngx_errno == NGX_ENOENT) {
            return NGX_OK;
        }
        return NGX_ERROR;
    }

    cf.size = ngx_file_size(&fi);
    cf.buf_size = 0;
    cf.access = ngx_file_access(&fi);
    cf.time = ngx_file_mtime(&fi);
    cf.log = r->connection->log;

    if (ngx_copy_file(spath.data, dpath.data, &cf) == NGX_OK) {
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_dav_parse_destination(ngx_http_request_t *r, ngx_str_t *duri)
{
    u_char           *p, *host, *last;
    size_t            len;
    ngx_uint_t        flags;
    ngx_str_t         args;
    ngx_table_elt_t  *dest;

#if (NGX_HTTP_DAV)
    dest = r->headers_in.destination;
    if (dest == NULL) {
        dest = ngx_http_dav_find_header(r, "Destination",
            sizeof("Destination") - 1);
    }
#else
    dest = ngx_http_dav_find_header(r, "Destination",
        sizeof("Destination") - 1);
#endif

    if (dest == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "client sent no \"Destination\" header");
        return NGX_HTTP_BAD_REQUEST;
    }

    p = dest->value.data;
    if (p[0] == '/') {
        last = p + dest->value.len;
    } else {
        len = r->headers_in.server.len;
        if (len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "client sent no \"Host\" header");
            return NGX_HTTP_BAD_REQUEST;
        }
#if (NGX_HTTP_SSL)
        if (r->connection->ssl) {
            if (ngx_strncmp(dest->value.data, "https://",
                sizeof("https://") - 1) != 0) {

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "client sent invalid \"Destination\" header: \"%V\"",
                    &dest->value);
                return NGX_HTTP_BAD_REQUEST;
            }
            host = dest->value.data + sizeof("https://") - 1;
        } else
#endif
        {
            if (ngx_strncmp(dest->value.data,
                "http://", sizeof("http://") - 1) != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "client sent invalid \"Destination\" header: \"%V\"",
                    &dest->value);
                return NGX_HTTP_BAD_REQUEST;
            }
            host = dest->value.data + sizeof("http://") - 1;
        }

        if (ngx_strncmp(host, r->headers_in.server.data, len) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "\"Destination\" URI \"%V\" is handled by "
                "different repository than the source URI", &dest->value);
            return NGX_HTTP_BAD_REQUEST;
        }

        last = dest->value.data + dest->value.len;

        for (p = host + len; p < last; p++) {
            if (*p == '/') {
                break;
            }
        }

        if (p >= last) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "client sent invalid \"Destination\" header: \"%V\"",
                &dest->value);
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    duri->len = last - p;
    duri->data = p;
    flags = NGX_HTTP_LOG_UNSAFE;

    if (ngx_http_parse_unsafe_uri(r, duri, &args, &flags) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "client sent invalid \"Destination\" header: \"%V\"", &dest->value);
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_parse_overwrite(ngx_http_request_t *r, ngx_uint_t *overwrite)
{
    ngx_table_elt_t  *over;

    *overwrite = 1;

    over = ngx_http_dav_find_header(r, "Overwrite", sizeof("Overwrite") - 1);
    if (over) {

        if (over->value.len == 1) {
            if (over->value.data[0] == 'T' || over->value.data[0] == 't') {
                *overwrite = 1;
            } else {
                if (over->value.data[0] == 'F' || over->value.data[0] == 'f') {
                    *overwrite = 0;
                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "client sent invalid \"Overwrite\" header: \"%V\"",
                        &over->value);
                    return NGX_HTTP_BAD_REQUEST;
                }
            }
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "client sent invalid \"Overwrite\" header: \"%V\"",
                &over->value);
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    return NGX_OK;
}

static void
ngx_http_dav_trim_trailing_slash(ngx_str_t *path)
{
    if (path->len == 0) {
        return;
    }

    path->len--;
    if (path->len > 0 && path->data[path->len - 1] == '/') {
        path->len--;
    }

    path->data[path->len] = '\0';
}

static ngx_int_t
ngx_http_dav_map_destination_path(ngx_http_request_t *r, ngx_str_t *duri,
    ngx_str_t *dpath, size_t *root)
{
    ngx_str_t  uri;

    uri = r->uri;
    r->uri = *duri;

    if (ngx_http_map_uri_to_path(r, dpath, root, 0) == NULL) {
        r->uri = uri;
        return NGX_ERROR;
    }

    r->uri = uri;

    ngx_http_dav_trim_trailing_slash(dpath);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_prepare_destination(ngx_http_request_t *r, ngx_str_t *dpath,
    ngx_uint_t overwrite, ngx_uint_t *dest_is_dir, ngx_uint_t *replaced)
{
    ngx_err_t        err;
    ngx_int_t        rc;
    ngx_file_info_t  dfi;

    *replaced = 0;

    if (ngx_link_info(dpath->data, &dfi) != NGX_FILE_ERROR) {
        *dest_is_dir = ngx_is_dir(&dfi) ? 1 : 0;

        if (!overwrite) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        rc = ngx_http_dav_delete_path(r, dpath, *dest_is_dir);
        if (rc != NGX_OK) {
            return rc;
        }

        (void) ngx_http_dav_delete_props(r, dpath, *dest_is_dir);

        *replaced = 1;
    } else {
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            return ngx_http_dav_error(r->connection->log, err,
                NGX_HTTP_NOT_FOUND, ngx_link_info_n, dpath->data);
        }

        *dest_is_dir = 0;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_copy_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *file;
    size_t                    len;
    ngx_copy_file_t           cf;
    ngx_http_dav_copy_ctx_t  *copy;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
        "http copy file: \"%s\"", path->data);

    copy = ctx->data;
    len = copy->path.len + path->len;

    file = ngx_alloc(len + 1, ctx->log);
    if (file == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(file, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
        "http copy file to: \"%s\"", file);

    cf.size = ctx->size;
    cf.buf_size = 0;
    cf.access = ctx->access;
    cf.time = ctx->mtime;
    cf.log = ctx->log;

    (void) ngx_copy_file(path->data, file, &cf);
    ngx_free(file);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_copy_pre_tree(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    ngx_http_dav_copy_ctx_t  *copy;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
        "http copy dir: \"%s\"", path->data);

    copy = ctx->data;
    len = copy->path.len + path->len;

    dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
        "http copy dir to: \"%s\"", dir);

    if (ngx_create_dir(dir, ngx_dir_access(ctx->access)) == NGX_FILE_ERROR) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_create_dir_n,
            dir);
    }

    ngx_free(dir);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_copy_post_tree(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    ngx_http_dav_copy_ctx_t  *copy;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
        "http copy dir time: \"%s\"", path->data);

    copy = ctx->data;
    len = copy->path.len + path->len;

    dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
        "http copy dir time to: \"%s\"", dir);

#if (NGX_WIN32)
    ngx_fd_t  fd;

    fd = ngx_open_file(dir, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_open_file_n, dir);
    } else {
        if (ngx_set_file_time(NULL, fd, ctx->mtime) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                ngx_set_file_time_n " \"%s\" failed", dir);
        }
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                ngx_close_file_n " \"%s\" failed", dir);
        }
    }
#else
    if (ngx_set_file_time(dir, 0, ctx->mtime) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
            ngx_set_file_time_n " \"%s\" failed", dir);
    }
#endif

    ngx_free(dir);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_copy_path(ngx_http_request_t *r, ngx_str_t *path,
    ngx_http_dav_copy_ctx_t *copy, ngx_http_dav_loc_conf_t *dlcf,
    ngx_file_info_t *sfi, ngx_int_t depth, ngx_uint_t is_move, ngx_uint_t dir)
{
    if (dir) {
        ngx_tree_ctx_t  tree;

        if (path->len > 0) {
            ngx_http_dav_trim_trailing_slash(path);
        }

        copy->len = path->len;

        if (ngx_create_dir(copy->path.data, ngx_file_access(sfi)) ==
            NGX_FILE_ERROR) {
            return ngx_http_dav_error(r->connection->log, ngx_errno,
                NGX_HTTP_CONFLICT, ngx_create_dir_n, copy->path.data);
        }
        if (!is_move && depth == NGX_HTTP_DAV_ZERO_DEPTH) {
            (void) ngx_http_dav_copy_props(r, path, &copy->path);
            return NGX_OK;
        }

        tree.init_handler = NULL;
        tree.file_handler = ngx_http_dav_copy_file;
        tree.pre_tree_handler = ngx_http_dav_copy_pre_tree;
        tree.post_tree_handler = ngx_http_dav_copy_post_tree;
        tree.spec_handler = ngx_http_dav_copy_file;
        tree.data = copy;
        tree.alloc = 0;
        tree.log = r->connection->log;
        tree.access = dlcf->access;
        tree.mtime = ngx_file_mtime(sfi);

        if (ngx_walk_tree(&tree, path) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        (void) ngx_http_dav_copy_props(r, path, &copy->path);

        return NGX_OK;
    } else {
        ngx_err_t        err;
        ngx_copy_file_t  cf;

        cf.size = ngx_file_size(sfi);
        cf.buf_size = 0;
        cf.access = ngx_file_access(sfi);
        cf.time = ngx_file_mtime(sfi);
        cf.log = r->connection->log;

        if (ngx_copy_file(path->data, copy->path.data, &cf) != NGX_OK) {
            err = ngx_errno;
            if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
                return NGX_HTTP_CONFLICT;
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        (void) ngx_http_dav_copy_props(r, path, &copy->path);

        return NGX_OK;
    }
}

static ngx_int_t
ngx_http_dav_copy_handler(ngx_http_request_t *r)
{
    size_t                    root;
    ngx_int_t                 rc, depth;
    ngx_uint_t                overwrite;
    ngx_uint_t                replaced, src_is_dir, dest_is_dir;
    ngx_str_t                 path, duri;
    ngx_file_info_t           sfi;
    ngx_http_dav_copy_ctx_t   copy;
    ngx_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "COPY with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    rc = ngx_http_dav_parse_destination(r, &duri);
    if (rc != NGX_OK) {
        return rc;
    }

    depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
    if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
        if (depth != NGX_HTTP_DAV_ZERO_DEPTH) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "\"Depth\" header must be 0 or infinity");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_dav_parse_overwrite(r, &overwrite);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http copy from: \"%s\"", path.data);

    if (ngx_http_dav_map_destination_path(r, &duri, &copy.path, &root) !=
        NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http copy to: \"%s\"", copy.path.data);

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    if (ngx_link_info(path.data, &sfi) == NGX_FILE_ERROR) {
        return ngx_http_dav_error(r->connection->log, ngx_errno,
            NGX_HTTP_NOT_FOUND, ngx_link_info_n, path.data);
    }

    src_is_dir = ngx_is_dir(&sfi) ? 1 : 0;

    rc = ngx_http_dav_prepare_destination(r, &copy.path, overwrite,
        &dest_is_dir, &replaced);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_dav_copy_path(r, &path, &copy, dlcf, &sfi, depth, 0, src_is_dir);
    if (rc != NGX_OK) {
        return rc;
    }

    return replaced ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

/* === MOVE === */

static ngx_int_t
ngx_http_dav_move_handler(ngx_http_request_t *r)
{
    size_t                    root;
    ngx_int_t                 rc, depth;
    ngx_uint_t                overwrite;
    ngx_uint_t                replaced, src_is_dir, dest_is_dir;
    ngx_str_t                 path, duri;
    ngx_file_info_t           sfi;
    ngx_http_dav_copy_ctx_t   copy;
    ngx_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "MOVE with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    rc = ngx_http_dav_parse_destination(r, &duri);
    if (rc != NGX_OK) {
        return rc;
    }

    depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
    if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "\"Depth\" header must be infinity");
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_dav_parse_overwrite(r, &overwrite);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http move from: \"%s\"", path.data);

    if (ngx_http_dav_map_destination_path(r, &duri, &copy.path, &root)
        != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http move to: \"%s\"", copy.path.data);

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    if (ngx_link_info(path.data, &sfi) == NGX_FILE_ERROR) {
        return ngx_http_dav_error(r->connection->log, ngx_errno,
            NGX_HTTP_NOT_FOUND, ngx_link_info_n, path.data);
    }

    src_is_dir = ngx_is_dir(&sfi) ? 1 : 0;

    rc = ngx_http_dav_prepare_destination(r, &copy.path, overwrite,
        &dest_is_dir, &replaced);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_dav_copy_path(r, &path, &copy, dlcf, &sfi,
        NGX_HTTP_DAV_INFINITY_DEPTH, 1, src_is_dir);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_dav_delete_path(r, &path, src_is_dir);
    if (rc != NGX_OK) {
        return rc;
    }

    (void) ngx_http_dav_delete_props(r, &path, src_is_dir);

    return replaced ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

/* === PROPFIND === */

static ngx_int_t
ngx_http_dav_xml_extract_tag(ngx_http_request_t *r, ngx_str_t *body,
    const char *tag, ngx_str_t *out)
{
    u_char  *p, *last, *prop, *prop_end, *start, *close, *name_end, *name, *end;
    u_char  *buf;
    size_t   tag_len;

    out->len = 0;
    out->data = NULL;

    if (body == NULL || body->len == 0) {
        return NGX_OK;
    }

    p = body->data;
    last = body->data + body->len;
    tag_len = ngx_strlen(tag);

    buf = ngx_pnalloc(r->pool, body->len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    out->data = buf;
    out->len = 0;

    while (p < last) {
        if (*p != '<') {
            p++;
            continue;
        }

        name = p + 1;

        name_end = name;
        while (name_end < last && *name_end != '>' && *name_end != ' ' &&
              *name_end != '\t' && *name_end != '\r' && *name_end != '\n' &&
              *name_end != '/') {
            name_end++;
        }

        if (name_end <= name) {
            p++;
            continue;
        }

        if ((size_t) (name_end - name) >= tag_len) {
            u_char *t = name_end - tag_len;

            if ((t == name || *(t - 1) == ':') &&
                ngx_strncasecmp(t, (u_char *) tag, tag_len) == 0) {
                prop = name_end;

                while (prop < last) {
                    if (*prop != '<') {
                        prop++;
                        continue;
                    }

                    name = prop + 1;
                    prop_end = name;

                    while (prop_end < last && *prop_end != '>' &&
                          *prop_end != ' ' && *prop_end != '\t' &&
                          *prop_end != '\r' && *prop_end != '\n' &&
                          *prop_end != '/') {
                        prop_end++;
                    }

                    if (prop_end > name) {
                        u_char *t = prop_end - (sizeof("prop") - 1);

                        if ((size_t) (prop_end - name) >= sizeof("prop") - 1 &&
                            (t == name || *(t - 1) == ':') &&
                            ngx_strncasecmp(t, (u_char *) "prop",
                                sizeof("prop") - 1) == 0) {
                            u_char *end_tag;
                            size_t  end_len;

                            end = ngx_strnstr(prop_end, ">", last - prop_end);
                            if (end == NULL) {
                                return NGX_ERROR;
                            }

                            start = end + 1;
                            end_len = sizeof("</>") - 1 + (prop_end - name);

                            end_tag = ngx_pnalloc(r->pool, end_len + 1);
                            if (end_tag == NULL) {
                                return NGX_ERROR;
                            }

                            end_tag[0] = '<';
                            end_tag[1] = '/';
                            ngx_memcpy(end_tag + 2, name, prop_end - name);
                            end_tag[2 + (prop_end - name)] = '>';
                            end_tag[3 + (prop_end - name)] = '\0';

                            close = ngx_strnstr(start, (char *) end_tag,
                                                last - start);
                            if (close == NULL) {
                                return NGX_ERROR;
                            }

                            ngx_memcpy(out->data + out->len, start, close - start);
                            out->len += close - start;
                            p = close;
                            break;
                        }
                    }

                    prop = prop_end;
                }
            }
        }

        p = name_end;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_xml_extract_ns(ngx_http_request_t *r, ngx_str_t *body,
    ngx_str_t *out)
{
    u_char       *p, *last, *name_end, *q, quote, *prefix, *prefix_end;
    size_t        len;
    ngx_array_t  *prefixes;
    ngx_str_t    *item;
    ngx_uint_t    i;

    out->len = 0;
    out->data = NULL;

    if (body == NULL || body->len == 0) {
        return NGX_OK;
    }
    out->data = ngx_pnalloc(r->pool, body->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    prefixes = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (prefixes == NULL) {
        return NGX_ERROR;
    }

    p = body->data;
    last = body->data + body->len;
    len = 0;

    while (p < last) {
        p = ngx_strnstr(p, "xmlns", last - p);
        if (p == NULL) {
            break;
        }

        prefix = NULL;
        prefix_end = NULL;

        name_end = p + sizeof("xmlns") - 1;
        if (name_end < last && *name_end == ':') {
            prefix = name_end + 1;
            prefix_end = prefix;

            while (prefix_end < last && *prefix_end != '=' &&
                  *prefix_end != ' ' && *prefix_end != '\t' &&
                  *prefix_end != '\r' && *prefix_end != '\n') {
                prefix_end++;
            }
        }

        while (name_end < last && *name_end != '=') {
            name_end++;
        }

        if (name_end >= last) {
            break;
        }

        q = name_end + 1;
        while (q < last && (*q == ' ' || *q == '\t' || *q == '\r' ||
              *q == '\n')) {
            q++;
        }

        if (q >= last) {
            break;
        }

        quote = *q;
        if (quote != '"' && quote != '\'') {
            p = name_end + 1;
            continue;
        }

        q++;
        while (q < last && *q != quote) {
            q++;
        }

        if (q >= last) {
            break;
        }

        if (prefix && prefix_end && prefix_end > prefix) {
            if (prefix_end - prefix == 1 && *prefix == 'D') {
                p = q + 1;
                continue;
            }

            item = prefixes->elts;

            for (i = 0; i < prefixes->nelts; i++) {
                if (item[i].len == (size_t) (prefix_end - prefix) &&
                    ngx_strncmp(item[i].data, prefix, item[i].len) == 0) {
                    break;
                }
            }

            if (i == prefixes->nelts) {
                item = ngx_array_push(prefixes);
                if (item == NULL) {
                    return NGX_ERROR;
                }

                item->len = prefix_end - prefix;

                item->data = ngx_pnalloc(r->pool, item->len);
                if (item->data == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(item->data, prefix, item->len);

                if (len) {
                    out->data[len++] = ' ';
                }

                ngx_memcpy(out->data + len, p, (q + 1) - p);
                len += (q + 1) - p;
            }
        } else {
            item = prefixes->elts;

            for (i = 0; i < prefixes->nelts; i++) {
                if (item[i].len == 0) {
                    break;
                }
            }

            if (i == prefixes->nelts) {
                item = ngx_array_push(prefixes);
                if (item == NULL) {
                    return NGX_ERROR;
                }

                item->len = 0;
                item->data = NULL;

                if (len) {
                    out->data[len++] = ' ';
                }

                ngx_memcpy(out->data + len, p, (q + 1) - p);
                len += (q + 1) - p;
            }
        }

        p = q + 1;
    }

    out->len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_xml_parse_props(ngx_pool_t *pool, ngx_str_t *src, ngx_array_t *props)
{
    u_char               *p, *last, *name, *tag_end, *end;
    u_char               *local, *colon, *attr, *val, *val_end, *prefix;
    size_t                prefix_len;
    ngx_http_dav_prop_t  *prop;
    ngx_str_t             pname, pxml, ns;

    if (src == NULL || src->len == 0) {
        return NGX_OK;
    }

    if (src->len >= sizeof("XMLNS ") - 1 &&
        ngx_strncmp(src->data, "XMLNS ", sizeof("XMLNS ") - 1) == 0) {
        u_char *nl = ngx_strnstr(src->data, "\n", src->len);

        if (nl == NULL) {
            return NGX_OK;
        }
        {
            size_t header_len = (nl + 1) - src->data;
            src->data = nl + 1;
            src->len = src->len - header_len;
        }
    }

    p = src->data;
    last = src->data + src->len;
    while (p < last) {

        while (p < last && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
            p++;
        }

        if (p >= last || *p != '<') {
            break;
        }
        if (p + 1 < last && p[1] == '/') {
            break;
        }

        name = p + 1;

        tag_end = name;
        while (tag_end < last && *tag_end != '>' && *tag_end != ' ' &&
              *tag_end != '\t' && *tag_end != '\r' && *tag_end != '\n' &&
              *tag_end != '/') {
            tag_end++;
        }

        pname.data = name;
        pname.len = tag_end - name;

        ns.len = 0;
        ns.data = NULL;

        colon = NULL;

        for (local = pname.data; local < pname.data + pname.len; local++) {
            if (*local == ':') {
                colon = local;
                break;
            }
        }

        local = (colon ? colon + 1 : pname.data);
        prefix = (colon ? pname.data : NULL);
        prefix_len = (colon ? (size_t) (colon - pname.data) : 0);

        end = ngx_strnstr(tag_end, ">", last - tag_end);
        if (end == NULL) {
            return NGX_ERROR;
        }
        {
            u_char *tag_end_pos = end;

            if (end > src->data && *(end - 1) == '/') {
                pxml.data = p;
                pxml.len = end + 1 - p;
                p = end + 1;
            } else {
                u_char *close_tag;
                size_t  close_len;

                close_len = pname.len + sizeof("</>") - 1;

                close_tag = ngx_pnalloc(pool, close_len + 1);
                if (close_tag == NULL) {
                    return NGX_ERROR;
                }

                close_tag[0] = '<';
                close_tag[1] = '/';

                ngx_memcpy(close_tag + 2, pname.data, pname.len);

                close_tag[2 + pname.len] = '>';
                close_tag[3 + pname.len] = '\0';

                end = ngx_strnstr(end + 1, (char *) close_tag, last - (end + 1));
                if (end == NULL) {
                    return NGX_ERROR;
                }

                end += close_len;
                pxml.data = p;
                pxml.len = end - p;
                p = end;
            }

            attr = tag_end;
            while (attr < tag_end_pos) {
                attr = ngx_strnstr(attr, "xmlns", tag_end_pos - attr);
                if (attr == NULL) {
                    break;
                }

                val = attr + sizeof("xmlns") - 1;
                if (val < tag_end_pos && *val == ':') {
                    val++;

                    if (prefix == NULL || prefix_len
                        != (size_t) (val - (attr + sizeof("xmlns") - 1) - 1)) {
                        attr = val;
                        continue;
                    }
                    if (ngx_strncmp(val, prefix, prefix_len) != 0) {
                        attr = val;
                        continue;
                    }

                    val = val + prefix_len;
                } else {
                    if (prefix != NULL) {
                        attr = val;
                        continue;
                    }
                }

                while (val < tag_end_pos && *val != '=') {
                    val++;
                }
                if (val >= tag_end_pos) {
                    break;
                }

                val++;
                while (val < tag_end_pos && (*val == ' ' || *val == '\t' ||
                      *val == '\r' || *val == '\n')) {
                    val++;
                }
                if (val >= tag_end_pos || (*val != '"' && *val != '\'')) {
                    break;
                }

                val_end = val + 1;
                while (val_end < tag_end_pos && *val_end != *val) {
                    val_end++;
                }
                if (val_end >= tag_end_pos) {
                    break;
                }

                ns.data = val + 1;
                ns.len = val_end - (val + 1);

                break;
            }
        }

        prop = ngx_array_push(props);
        if (prop == NULL) {
            return NGX_ERROR;
        }

        prop->name.data = ngx_pnalloc(pool,
            ns.len + 1 + (pname.data + pname.len - local));
        if (prop->name.data == NULL) {
            return NGX_ERROR;
        }

        if (ns.len) {
            ngx_memcpy(prop->name.data, ns.data, ns.len);
        }

        prop->name.data[ns.len] = '|';

        ngx_memcpy(prop->name.data + ns.len + 1, local,
            pname.data + pname.len - local);

        prop->name.len = ns.len + 1 + (pname.data + pname.len - local);

        prop->xml.data = ngx_pnalloc(pool, pxml.len);
        if (prop->xml.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(prop->xml.data, pxml.data, pxml.len);
        prop->xml.len = pxml.len;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_read_props(ngx_http_request_t *r, ngx_str_t *ppath, ngx_str_t *out)
{
    ssize_t          n;
    ngx_file_t       file;
    ngx_file_info_t  fi;

    out->len = 0;
    out->data = NULL;

    if (ngx_file_info(ppath->data, &fi) == NGX_FILE_ERROR) {
        if (ngx_errno == NGX_ENOENT) {
            return NGX_OK;
        }
        return NGX_ERROR;
    }
    out->len = (size_t) ngx_file_size(&fi);
    if (out->len == 0) {
        return NGX_OK;
    }
    out->data = ngx_pnalloc(r->pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    file.fd = ngx_open_file(ppath->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        if (ngx_errno == NGX_ENOENT) {
            out->len = 0;
            out->data = NULL;
            return NGX_OK;
        }
        return NGX_ERROR;
    }

    file.name = *ppath;
    file.log = r->connection->log;

    n = ngx_read_file(&file, out->data, out->len, 0);

    (void) ngx_close_file(file.fd);

    if (n == NGX_ERROR || (size_t) n != out->len) {
        return NGX_ERROR;
    }

    out->data[out->len] = '\0';

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_propfind_collect_props(ngx_http_request_t *r, ngx_str_t *path,
    ngx_http_dav_propfind_ctx_t *ctx, ngx_str_t *props, ngx_str_t *xmlns,
    ngx_array_t **miss_props, size_t *miss_len)
{
    ngx_str_t             ppath, stored, stored_xmlns;
    ngx_array_t          *entries;
    ngx_http_dav_prop_t  *prop, *reqp;
    ngx_uint_t            i, j;
    size_t                len;
    u_char               *p;

    props->len = 0;
    props->data = NULL;
    xmlns->len = 0;
    xmlns->data = NULL;
    *miss_props = NULL;
    *miss_len = 0;

    if (ngx_http_dav_props_path(r, path, &ppath) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_http_dav_read_props(r, &ppath, &stored) != NGX_OK) {
        return NGX_ERROR;
    }

    stored_xmlns.len = 0;
    stored_xmlns.data = NULL;

    if (stored.len >= sizeof("XMLNS ") - 1 &&
        ngx_strncmp(stored.data, "XMLNS ", sizeof("XMLNS ") - 1) == 0) {
        u_char *nl = ngx_strnstr(stored.data, "\n", stored.len);
        if (nl != NULL) {
            size_t header_len = (nl + 1) - stored.data;

            stored_xmlns.data = stored.data + (sizeof("XMLNS ") - 1);
            stored_xmlns.len = nl - stored_xmlns.data;
            stored.data = nl + 1;
            stored.len -= header_len;
        }
    }

    xmlns->len = 0;
    xmlns->data = NULL;

    if (!ctx->prop_req) {
        *props = stored;
        return NGX_OK;
    }
    entries = ngx_array_create(r->pool, 4, sizeof(ngx_http_dav_prop_t));
    if (entries == NULL) {
        return NGX_ERROR;
    }
    if (stored.len && ngx_http_dav_xml_parse_props(r->pool, &stored,
        entries) != NGX_OK) {
        return NGX_ERROR;
    }
    *miss_props = ngx_array_create(r->pool, 4, sizeof(ngx_http_dav_prop_t));
    if (*miss_props == NULL) {
        return NGX_ERROR;
    }

    len = 0;

    reqp = ctx->req_props ? ctx->req_props->elts : NULL;
    if (reqp != NULL) {

        for (i = 0; i < ctx->req_props->nelts; i++) {
            prop = entries->elts;

            for (j = 0; j < entries->nelts; j++) {

                if (prop[j].name.len == reqp[i].name.len &&
                    ngx_strncmp(prop[j].name.data, reqp[i].name.data,
                        prop[j].name.len) == 0) {
                    len += prop[j].xml.len + 1;
                    break;
                }
            }

            if (j == entries->nelts) {
                ngx_http_dav_prop_t *mp;

                mp = ngx_array_push(*miss_props);
                if (mp == NULL) {
                    return NGX_ERROR;
                }

                *mp = reqp[i];
                *miss_len += reqp[i].xml.len + 1;
            }
        }
    }

    if (len) {
        props->data = ngx_pnalloc(r->pool, len);
        if (props->data == NULL) {
            return NGX_ERROR;
        }

        p = props->data;
        prop = entries->elts;

        for (i = 0; i < ctx->req_props->nelts; i++) {
            for (j = 0; j < entries->nelts; j++) {
                if (prop[j].name.len == reqp[i].name.len &&
                    ngx_strncmp(prop[j].name.data, reqp[i].name.data,
                        prop[j].name.len) == 0) {
                    p = ngx_cpymem(p, prop[j].xml.data, prop[j].xml.len);
                    *p++ = '\n';
                    break;
                }
            }
        }

        props->len = p - props->data;
    }

    return NGX_OK;
}

static ngx_buf_t *
ngx_http_dav_propfind_build_fragment(ngx_http_request_t *r, ngx_str_t *href,
    ngx_file_info_t *fi, ngx_str_t *props, ngx_str_t *xmlns,
    ngx_array_t *miss_props, size_t miss_len)
{
    u_char               *p;
    size_t                len, escape;
    ngx_buf_t            *b;
    ngx_http_dav_prop_t  *missp;
    ngx_uint_t            i;

    escape = ngx_escape_uri(NULL, href->data, href->len, NGX_ESCAPE_URI);

    len = 512 + href->len + escape + props->len + xmlns->len;

    if (miss_props && miss_props->nelts) {
         len += miss_len
             + (sizeof("    <D:propstat>\n      <D:prop>\n") - 1)
             + (sizeof("      </D:prop>\n"
                 "      <D:status>HTTP/1.1 404 Not Found</D:status>\n"
                 "    </D:propstat>\n") - 1);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    p = b->last;

    p = ngx_cpymem(p, "  <D:response>\n    <D:href>",
        sizeof("  <D:response>\n    <D:href>") - 1);

    p = (u_char *) ngx_escape_uri(p, href->data, href->len, NGX_ESCAPE_URI);

    p = ngx_cpymem(p, "</D:href>\n    <D:propstat>\n      <D:prop",
        sizeof("</D:href>\n    <D:propstat>\n      <D:prop") - 1);

    if (xmlns->len) {
        *p++ = ' ';
        p = ngx_cpymem(p, xmlns->data, xmlns->len);
    }

    p = ngx_cpymem(p, ">\n", sizeof(">\n") - 1);

    if (ngx_is_dir(fi)) {
        p = ngx_cpymem(p,
            "        <D:resourcetype><D:collection/></D:resourcetype>\n",
            sizeof("        <D:resourcetype><D:collection/></D:resourcetype>\n") - 1);
    } else {
        p = ngx_cpymem(p, "        <D:resourcetype/>\n",
            sizeof("        <D:resourcetype/>\n") - 1);
    }

    p = ngx_cpymem(p, "        <D:getcontentlength>",
        sizeof("        <D:getcontentlength>") - 1);

    p = ngx_sprintf(p, "%O", ngx_is_dir(fi) ? (off_t) 0 : ngx_file_size(fi));

    p = ngx_cpymem(p, "</D:getcontentlength>\n",
        sizeof("</D:getcontentlength>\n") - 1);
    p = ngx_cpymem(p, "        <D:getlastmodified>",
        sizeof("        <D:getlastmodified>") - 1);

    p = ngx_http_time(p, ngx_file_mtime(fi));

    p = ngx_cpymem(p, "</D:getlastmodified>\n",
        sizeof("</D:getlastmodified>\n") - 1);

    if (props->len) {
        p = ngx_cpymem(p, props->data, props->len);
        *p++ = '\n';
    }

    p = ngx_cpymem(p,
        "      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n",
        sizeof("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n") - 1);
    p = ngx_cpymem(p, "    </D:propstat>\n", sizeof("    </D:propstat>\n") - 1);

    if (miss_props && miss_props->nelts) {
        p = ngx_cpymem(p, "    <D:propstat>\n      <D:prop>\n",
            sizeof("    <D:propstat>\n      <D:prop>\n") - 1);

        missp = miss_props->elts;

        for (i = 0; i < miss_props->nelts; i++) {
            p = ngx_cpymem(p, missp[i].xml.data, missp[i].xml.len);
            *p++ = '\n';
        }

        p = ngx_cpymem(p, "      </D:prop>\n"
            "      <D:status>HTTP/1.1 404 Not Found</D:status>\n"
            "    </D:propstat>\n", sizeof("      </D:prop>\n"
            "      <D:status>HTTP/1.1 404 Not Found</D:status>\n"
            "    </D:propstat>\n") - 1);
    }

    p = ngx_cpymem(p, "  </D:response>\n", sizeof("  </D:response>\n") - 1);

    b->last = p;
    return b;
}

static ngx_int_t
ngx_http_dav_propfind_walk_tree(ngx_http_request_t *r, ngx_str_t *base_uri,
    ngx_str_t *base_path, ngx_int_t depth, ngx_http_dav_propfind_ctx_t *ctx,
    ngx_chain_t **last, size_t *total)
{
    ngx_dir_t        dir;
    ngx_str_t        path;
    ngx_str_t        uri;
    ngx_str_t        props, xmlns;
    ngx_array_t     *miss_props;
    size_t           miss_len;
    ngx_buf_t       *b;
    ngx_chain_t     *cl;
    ngx_file_info_t  fi;
    u_char          *p;
    size_t           len;
    ngx_int_t        next_depth;

    if (depth == NGX_HTTP_DAV_ZERO_DEPTH) {
        return NGX_OK;
    }

    path = *base_path;
    path.data[path.len] = '\0';

    if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            if (ngx_errno != NGX_ENOMOREFILES) {
                ngx_close_dir(&dir);
                return NGX_ERROR;
            }
            break;
        }

        if (ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        len = ngx_de_namelen(&dir);

        path.len = base_path->len + 1 + len;

        path.data = ngx_pnalloc(r->pool, path.len + 1);
        if (path.data == NULL) {
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        p = ngx_cpymem(path.data, base_path->data, base_path->len);
        if (p > path.data && *(p - 1) != '/') {
            *p++ = '/';
        }

        p = ngx_cpymem(p, ngx_de_name(&dir), len);
        *p = '\0';

        if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
            continue;
        }

        uri.len = base_uri->len + len + (ngx_is_dir(&fi) ? 1 : 0);

        uri.data = ngx_pnalloc(r->pool, uri.len);
        if (uri.data == NULL) {
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        p = ngx_cpymem(uri.data, base_uri->data, base_uri->len);
        p = ngx_cpymem(p, ngx_de_name(&dir), len);

        if (ngx_is_dir(&fi)) {
            *p++ = '/';
        }

        if (ngx_http_dav_propfind_collect_props(r, &path, ctx, &props, &xmlns,
            &miss_props, &miss_len) != NGX_OK) {
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        b = ngx_http_dav_propfind_build_fragment(r, &uri, &fi, &props, &xmlns,
            miss_props, miss_len);
        if (b == NULL) {
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        (*last)->next = cl;
        *last = cl;

        *total += b->last - b->pos;

        if (ngx_is_dir(&fi)) {
            next_depth = depth;

            if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
                next_depth = depth - 1;
            }

            if (next_depth != NGX_HTTP_DAV_ZERO_DEPTH) {
                if (ngx_http_dav_propfind_walk_tree(r, &uri, &path, next_depth,
                    ctx, last, total) != NGX_OK) {
                    ngx_close_dir(&dir);
                    return NGX_ERROR;
                }
            }
        }
    }

    ngx_close_dir(&dir);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_propfind_response(ngx_http_request_t *r,
    ngx_str_t *href, ngx_file_info_t *fi, ngx_str_t *props, ngx_str_t *xmlns,
    ngx_array_t *miss_props, size_t miss_len)
{
    u_char     *p;
    ngx_buf_t  *head_b, *frag_b, *tail_b;
    ngx_chain_t *cl_head, *cl_frag, *cl_tail;
    ngx_int_t    rc;

    head_b = ngx_create_temp_buf(r->pool,
        sizeof("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n") - 1
      + sizeof("<D:multistatus xmlns:D=\"DAV:\">\n") - 1);
    if (head_b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = head_b->last;
    p = ngx_cpymem(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
        sizeof("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n") - 1);
    p = ngx_cpymem(p, "<D:multistatus xmlns:D=\"DAV:\">\n",
        sizeof("<D:multistatus xmlns:D=\"DAV:\">\n") - 1);
    head_b->last = p;

    frag_b = ngx_http_dav_propfind_build_fragment(r, href, fi, props, xmlns,
        miss_props, miss_len);
    if (frag_b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tail_b = ngx_create_temp_buf(r->pool, sizeof("</D:multistatus>\n") - 1);
    if (tail_b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    tail_b->last = ngx_cpymem(tail_b->last, "</D:multistatus>\n",
                              sizeof("</D:multistatus>\n") - 1);
    tail_b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_DAV_MULTI_STATUS;
    ngx_str_set(&r->headers_out.content_type, "text/xml; charset=utf-8");

    r->headers_out.content_type_len = sizeof("text/xml; charset=utf-8") - 1;
    r->headers_out.content_length_n = (head_b->last - head_b->pos)
        + (frag_b->last - frag_b->pos) + (tail_b->last - tail_b->pos);

    cl_head = ngx_alloc_chain_link(r->pool);
    cl_frag = ngx_alloc_chain_link(r->pool);
    cl_tail = ngx_alloc_chain_link(r->pool);

    if (cl_head == NULL || cl_frag == NULL || cl_tail == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl_head->buf = head_b;
    cl_head->next = cl_frag;

    cl_frag->buf = frag_b;
    cl_frag->next = cl_tail;

    cl_tail->buf = tail_b;
    cl_tail->next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, cl_head);
}

static ngx_int_t
ngx_http_dav_propfind(ngx_http_request_t *r, ngx_str_t *body)
{
    u_char                      *p;
    size_t                       len, root, total;
    ngx_int_t                    depth;
    ngx_str_t                    path, href;
    ngx_file_info_t              fi;
    ngx_str_t                    props, xmlns, req_prop, req_xmlns;
    ngx_array_t                 *req_props;
    ngx_array_t                 *miss_props;
    size_t                       miss_len;
    ngx_chain_t                  out;
    ngx_chain_t                 *cl;
    ngx_buf_t                   *b;
    ngx_http_dav_propfind_ctx_t  ctx;

    ngx_memzero(&ctx, sizeof(ctx));

    req_props = NULL;
    req_prop.len = 0;
    req_prop.data = NULL;
    req_xmlns.len = 0;
    req_xmlns.data = NULL;

    if (body == NULL || body->len == 0) {
        ctx.allprop = 1;
    } else {
        if (ngx_strnstr(body->data, "<propfind", body->len) == NULL &&
            ngx_strnstr(body->data, "<D:propfind", body->len) == NULL &&
            ngx_strnstr(body->data, "<d:propfind", body->len) == NULL) {
            return NGX_HTTP_BAD_REQUEST;
        }
        if (ngx_strnstr(body->data, "propname", body->len) != NULL) {
            ctx.propname = 1;
        }
        if (ngx_strnstr(body->data, "allprop", body->len) != NULL) {
            ctx.allprop = 1;
        }
        if (ngx_strnstr(body->data, "<prop", body->len) != NULL ||
            ngx_strnstr(body->data, "<D:prop", body->len) != NULL ||
            ngx_strnstr(body->data, "<d:prop", body->len) != NULL) {
            ctx.prop_req = 1;
        }
        if (ngx_strnstr(body->data, "xmlns:", body->len) != NULL) {
            if (ngx_strnstr(body->data, "=\"\"", body->len) != NULL ||
                ngx_strnstr(body->data, "=''", body->len) != NULL) {
                return NGX_HTTP_BAD_REQUEST;
            }
        }
        if (ctx.prop_req) {
            if (ngx_http_dav_xml_extract_tag(r, body, "propfind", &req_prop) !=
                NGX_OK) {
                ctx.prop_req = 0;
                ctx.allprop = 1;
            } else {
                (void) ngx_http_dav_xml_extract_ns(r, body, &req_xmlns);

                req_props = ngx_array_create(r->pool, 4,
                    sizeof(ngx_http_dav_prop_t));
                if (req_props == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (req_prop.len &&
                    ngx_http_dav_xml_parse_props(r->pool, &req_prop,
                        req_props) != NGX_OK) {
                    ctx.prop_req = 0;
                    ctx.allprop = 1;
                }
                if (ctx.prop_req && req_props->nelts == 0) {
                    ctx.prop_req = 0;
                }
            }
        }
        if (!ctx.prop_req && !ctx.propname && !ctx.allprop) {
            ctx.allprop = 1;
        }
    }

    ctx.req_props = req_props;
    ctx.req_xmlns = req_xmlns;

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len--;

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        return ngx_http_dav_error(r->connection->log, ngx_errno,
            NGX_HTTP_NOT_FOUND, ngx_file_info_n, path.data);
    }

    href = r->uri;

    if (ngx_is_dir(&fi)) {
        if (href.len == 0 || href.data[href.len - 1] != '/') {
            p = ngx_pnalloc(r->pool, href.len + 1);
            if (p == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = ngx_cpymem(p, href.data, href.len);
            *p++ = '/';

            href.data = p - (href.len + 1);
            href.len = href.len + 1;
        }
    }

    depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_ZERO_DEPTH);
    if (!ngx_is_dir(&fi) || depth == NGX_HTTP_DAV_ZERO_DEPTH) {
        if (ngx_http_dav_propfind_collect_props(r, &path, &ctx, &props, &xmlns,
            &miss_props, &miss_len) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return ngx_http_dav_propfind_response(r, &href, &fi, &props, &xmlns,
            miss_props, miss_len);
    }

    len = sizeof("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n") - 1
        + sizeof("<D:multistatus xmlns:D=\"DAV:\">\n") - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->last;

    p = ngx_cpymem(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
        sizeof("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n") - 1);
    p = ngx_cpymem(p, "<D:multistatus xmlns:D=\"DAV:\">\n",
        sizeof("<D:multistatus xmlns:D=\"DAV:\">\n") - 1);

    b->last = p;

    out.buf = b;
    out.next = NULL;
    cl = &out;

    total = b->last - b->pos;

    if (ngx_http_dav_propfind_collect_props(r, &path, &ctx, &props, &xmlns,
        &miss_props, &miss_len) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_http_dav_propfind_build_fragment(r, &href, &fi, &props, &xmlns, miss_props,
        miss_len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->next = ngx_alloc_chain_link(r->pool);
    if (cl->next == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = cl->next;
    cl->buf = b;
    cl->next = NULL;
    total += b->last - b->pos;

    if (ngx_http_dav_propfind_walk_tree(r, &href, &path, depth, &ctx,
        &cl, &total) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("</D:multistatus>\n") - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, "</D:multistatus>\n", len);
    b->last_buf = 1;

    cl->next = ngx_alloc_chain_link(r->pool);
    if (cl->next == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = cl->next;
    cl->buf = b;
    cl->next = NULL;

    total += b->last - b->pos;

    r->headers_out.status = NGX_HTTP_DAV_MULTI_STATUS;

    ngx_str_set(&r->headers_out.content_type, "text/xml; charset=utf-8");

    r->headers_out.content_type_len = sizeof("text/xml; charset=utf-8") - 1;
    r->headers_out.content_length_n = total;

    return ngx_http_send_header(r) == NGX_ERROR
                                    ? NGX_HTTP_INTERNAL_SERVER_ERROR
                                    : ngx_http_output_filter(r, &out);
}

static void
ngx_http_dav_propfind_finalize(ngx_http_request_t *r)
{
    size_t        len;
    u_char       *p, *last;
    ngx_buf_t    *buf;
    ngx_chain_t  *cl;
    ngx_str_t     body;
    ngx_int_t     rc;

    body.len = 0;
    body.data = NULL;

    if (r->request_body && r->request_body->bufs) {
        len = 0;

        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            buf = cl->buf;
            len += buf->last - buf->pos;
        }

        if (len) {
            p = ngx_pnalloc(r->pool, len + 1);
            if (p == NULL) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            last = p;

            for (cl = r->request_body->bufs; cl; cl = cl->next) {
                buf = cl->buf;
                last = ngx_cpymem(last, buf->pos, buf->last - buf->pos);
            }

            *last = '\0';

            body.data = p;
            body.len = len;
        }
    }

    rc = ngx_http_dav_propfind(r, (body.len ? &body : NULL));

    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_dav_propfind_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->uri.len && r->uri.data[r->uri.len - 1] != '/') {
        ngx_http_core_loc_conf_t *clcf;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (r->uri.len == clcf->name.len) {
            u_char *u = ngx_pnalloc(r->pool, r->uri.len + 1);
            if (u == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            u = ngx_cpymem(u, r->uri.data, r->uri.len);
            *u++ = '/';

            r->uri.data = u - (r->uri.len + 1);
            r->uri.len = r->uri.len + 1;

            if (ngx_http_dav_location(r) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_HTTP_MOVED_PERMANENTLY;
        }
    }

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        r->request_body_in_single_buf = 1;

        rc = ngx_http_read_client_request_body(r,
            ngx_http_dav_propfind_finalize);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;
    }

    return ngx_http_dav_propfind(r, NULL);
}

/* === PROPPATCH === */

static u_char *
ngx_http_dav_xml_find_tag(ngx_str_t *body, const char *tag)
{
    u_char  *p, *last, *name_end, *name;
    size_t   tag_len;

    if (body == NULL || body->len == 0) {
        return NULL;
    }

    tag_len = ngx_strlen(tag);

    p = body->data;
    last = body->data + body->len;
    while (p < last) {
        if (*p != '<') {
            p++;
            continue;
        }

        name = p + 1;

        name_end = name;
        while (name_end < last && *name_end != '>' && *name_end != ' ' &&
              *name_end != '\t' && *name_end != '\r' && *name_end != '\n' &&
              *name_end != '/') {
            name_end++;
        }

        if (name_end > name) {
            u_char *t = name_end - tag_len;

            if ((size_t) (name_end - name) >= tag_len &&
                (t == name || *(t - 1) == ':') &&
                ngx_strncasecmp(t, (u_char *) tag, tag_len) == 0) {
                return p;
            }
        }

        p = name_end;
    }

    return NULL;
}

static ngx_int_t
ngx_http_dav_write_props(ngx_http_request_t *r, ngx_str_t *ppath,
    ngx_str_t *data)
{
    ssize_t                   n;
    ngx_file_t                file;
    u_char                   *dir;
    u_char                   *last;
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    dir = ngx_pnalloc(r->pool, ppath->len + 1);
    if (dir == NULL) {
        return NGX_ERROR;
    }

    last = ngx_cpymem(dir, ppath->data, ppath->len);
    *last = '\0';

    last = dir + ngx_strlen(dir);
    while (last > dir && *(last - 1) != '/') {
        last--;
    }

    if (last > dir) {
        *last = '\0';
        (void) ngx_create_full_path(dir, ngx_dir_access(dlcf->access));
    }

    file.fd = ngx_open_file(ppath->data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
        0600);
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    file.name = *ppath;
    file.log = r->connection->log;

    n = ngx_write_file(&file, data->data, data->len, 0);
    (void) ngx_close_file(file.fd);

    if (n == NGX_ERROR || (size_t) n != data->len) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_proppatch_response(ngx_http_request_t *r,
    ngx_str_t *href, ngx_str_t *setp, ngx_str_t *remp, ngx_str_t *xmlns)
{
    u_char      *p;
    size_t       len, escape;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    escape = ngx_escape_uri(NULL, href->data, href->len, NGX_ESCAPE_URI);
    len = 512 + href->len + escape + setp->len + remp->len + xmlns->len;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->last;

    p = ngx_cpymem(p, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
        sizeof("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n") - 1);
    p = ngx_cpymem(p, "<D:multistatus xmlns:D=\"DAV:\">\n",
        sizeof("<D:multistatus xmlns:D=\"DAV:\">\n") - 1);
    p = ngx_cpymem(p, "  <D:response>\n    <D:href>",
        sizeof("  <D:response>\n    <D:href>") - 1);

    p = (u_char *) ngx_escape_uri(p, href->data, href->len, NGX_ESCAPE_URI);

    p = ngx_cpymem(p, "</D:href>\n    <D:propstat>\n      <D:prop",
        sizeof("</D:href>\n    <D:propstat>\n      <D:prop") - 1);

    if (xmlns->len) {
        *p++ = ' ';
        p = ngx_cpymem(p, xmlns->data, xmlns->len);
    }

    p = ngx_cpymem(p, ">\n", sizeof(">\n") - 1);

    if (setp->len) {
        p = ngx_cpymem(p, setp->data, setp->len);
        *p++ = '\n';
    }

    if (remp->len) {
        p = ngx_cpymem(p, remp->data, remp->len);
        *p++ = '\n';
    }

    p = ngx_cpymem(p,
        "      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n",
        sizeof("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n") - 1);
    p = ngx_cpymem(p,
        "    </D:propstat>\n  </D:response>\n</D:multistatus>\n",
        sizeof("    </D:propstat>\n  </D:response>\n</D:multistatus>\n") - 1);

    b->last = p;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_DAV_MULTI_STATUS;
    ngx_str_set(&r->headers_out.content_type, "text/xml; charset=utf-8");
    r->headers_out.content_type_len = sizeof("text/xml; charset=utf-8") - 1;
    r->headers_out.content_length_n = b->last - b->pos;

    out.buf = b;
    out.next = NULL;

    return ngx_http_send_header(r) == NGX_ERROR
                                    ? NGX_HTTP_INTERNAL_SERVER_ERROR
                                    : ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_dav_proppatch(ngx_http_request_t *r, ngx_str_t *body)
{
    u_char               *p;
    size_t                len, root;
    ngx_str_t             path, href, ppath;
    ngx_str_t             props, setp, remp, newprops, xmlns;
    ngx_array_t          *entries, *set_entries, *rem_entries;
    ngx_http_dav_prop_t  *prop, *sprop, *rprop;
    ngx_uint_t            i, j;

    if (body == NULL || body->len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (ngx_strcasestrn(body->data, "propertyupdate", 14 - 1) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_http_dav_props_path(r, &path, &ppath) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    props.len = 0;
    props.data = NULL;

    if (ngx_http_dav_read_props(r, &ppath, &props) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_http_dav_xml_extract_tag(r, body, "set", &setp) != NGX_OK ||
        ngx_http_dav_xml_extract_tag(r, body, "remove", &remp) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (ngx_http_dav_xml_extract_ns(r, body, &xmlns) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    entries = ngx_array_create(r->pool, 4, sizeof(ngx_http_dav_prop_t));
    if (entries == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (props.len && ngx_http_dav_xml_parse_props(r->pool, &props,
            entries) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    set_entries = ngx_array_create(r->pool, 4, sizeof(ngx_http_dav_prop_t));
    if (set_entries == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (setp.len && ngx_http_dav_xml_parse_props(r->pool, &setp,
            set_entries) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rem_entries = ngx_array_create(r->pool, 4, sizeof(ngx_http_dav_prop_t));
    if (rem_entries == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (remp.len && ngx_http_dav_xml_parse_props(r->pool, &remp,
            rem_entries) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }
    {
        u_char     *set_pos, *rem_pos;
        ngx_uint_t  set_first;

        set_pos = ngx_http_dav_xml_find_tag(body, "set");
        rem_pos = ngx_http_dav_xml_find_tag(body, "remove");
        set_first = (set_pos && rem_pos && set_pos < rem_pos);

        if (!set_pos || !rem_pos) {
            set_first = (set_pos != NULL);
        }

        if (set_first) {
            sprop = set_entries->elts;

            for (i = 0; i < set_entries->nelts; i++) {
                prop = entries->elts;

                for (j = 0; j < entries->nelts;) {

                    if (prop[j].name.len == sprop[i].name.len &&
                        ngx_strncmp(prop[j].name.data, sprop[i].name.data,
                            prop[j].name.len) == 0) {
                        if (j != entries->nelts - 1) {
                            prop[j] = prop[entries->nelts - 1];
                        }
                        entries->nelts--;
                        continue;
                    }
                    j++;
                }

                prop = ngx_array_push(entries);
                if (prop == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                *prop = sprop[i];
            }

            rprop = rem_entries->elts;

            for (i = 0; i < rem_entries->nelts; i++) {
                prop = entries->elts;

                for (j = 0; j < entries->nelts;) {

                    if (prop[j].name.len == rprop[i].name.len &&
                        ngx_strncmp(prop[j].name.data, rprop[i].name.data,
                            prop[j].name.len) == 0) {
                        if (j != entries->nelts - 1) {
                            prop[j] = prop[entries->nelts - 1];
                        }
                        entries->nelts--;
                        continue;
                    }
                    j++;
                }
            }
        } else {
            rprop = rem_entries->elts;

            for (i = 0; i < rem_entries->nelts; i++) {
                prop = entries->elts;

                for (j = 0; j < entries->nelts;) {

                    if (prop[j].name.len == rprop[i].name.len &&
                        ngx_strncmp(prop[j].name.data, rprop[i].name.data,
                            prop[j].name.len) == 0) {
                        if (j != entries->nelts - 1) {
                            prop[j] = prop[entries->nelts - 1];
                        }
                        entries->nelts--;
                        continue;
                    }
                    j++;
                }
            }

            sprop = set_entries->elts;

            for (i = 0; i < set_entries->nelts; i++) {
                prop = entries->elts;

                for (j = 0; j < entries->nelts;) {

                    if (prop[j].name.len == sprop[i].name.len &&
                        ngx_strncmp(prop[j].name.data, sprop[i].name.data,
                            prop[j].name.len) == 0) {
                        if (j != entries->nelts - 1) {
                            prop[j] = prop[entries->nelts - 1];
                        }
                        entries->nelts--;
                        continue;
                    }
                    j++;
                }

                prop = ngx_array_push(entries);
                if (prop == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                *prop = sprop[i];
            }
        }
    }

    prop = entries->elts;
    len = 0;

    for (i = 0; i < entries->nelts; i++) {
        len += prop[i].xml.len + 1;
    }

    if (len || xmlns.len) {
        len += xmlns.len ? (sizeof("XMLNS ") - 1 + xmlns.len + 1) : 0;

        newprops.data = ngx_pnalloc(r->pool, len);
        if (newprops.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        p = newprops.data;

        if (xmlns.len) {
            p = ngx_cpymem(p, "XMLNS ", sizeof("XMLNS ") - 1);
            p = ngx_cpymem(p, xmlns.data, xmlns.len);
           *p++ = '\n';
        }

        for (i = 0; i < entries->nelts; i++) {
            p = ngx_cpymem(p, prop[i].xml.data, prop[i].xml.len);
           *p++ = '\n';
        }

        newprops.len = p - newprops.data;

        if (ngx_http_dav_write_props(r, &ppath, &newprops) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        (void) ngx_delete_file(ppath.data);
    }

    href = r->uri;

    if (href.len == 0 || href.data[href.len - 1] != '/') {
        if (r->uri.data[r->uri.len - 1] == '/') {
            href = r->uri;
        }
    }

    return ngx_http_dav_proppatch_response(r, &href, &setp, &remp, &xmlns);
}

static void
ngx_http_dav_proppatch_finalize(ngx_http_request_t *r)
{
    size_t        len;
    u_char       *p, *last;
    ngx_buf_t    *buf;
    ngx_chain_t  *cl;
    ngx_str_t     body;
    ngx_int_t     rc;

    body.len = 0;
    body.data = NULL;

    if (r->request_body && r->request_body->bufs) {
        len = 0;

        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            buf = cl->buf;
            len += buf->last - buf->pos;
        }

        if (len) {
            p = ngx_pnalloc(r->pool, len + 1);
            if (p == NULL) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            last = p;

            for (cl = r->request_body->bufs; cl; cl = cl->next) {
                buf = cl->buf;
                last = ngx_cpymem(last, buf->pos, buf->last - buf->pos);
            }

            *last = '\0';

            body.data = p;
            body.len = len;
        }
    }

    rc = ngx_http_dav_proppatch(r, (body.len ? &body : NULL));

    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_dav_proppatch_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->uri.len && r->uri.data[r->uri.len - 1] != '/') {
        ngx_http_core_loc_conf_t *clcf;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (r->uri.len == clcf->name.len) {
            u_char *u = ngx_pnalloc(r->pool, r->uri.len + 1);

            if (u == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            u = ngx_cpymem(u, r->uri.data, r->uri.len);
            *u++ = '/';

            r->uri.data = u - (r->uri.len + 1);
            r->uri.len = r->uri.len + 1;

            if (ngx_http_dav_location(r) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_HTTP_MOVED_PERMANENTLY;
        }
    }

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        r->request_body_in_single_buf = 1;

        rc = ngx_http_read_client_request_body(r, ngx_http_dav_proppatch_finalize);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;
    }

    rc = ngx_http_dav_proppatch(r, NULL);
    return rc;
}

/* === LOCK === */

static ngx_http_dav_lock_node_t *
ngx_http_dav_find_token(ngx_http_dav_lock_shm_t *lock, ngx_str_t *uri,
    ngx_str_t *token, ngx_uint_t exact)
{
    size_t                     len;
    ngx_queue_t               *q;
    ngx_http_dav_lock_node_t  *node;

    len = uri->len;

    for (q = ngx_queue_head(&lock->sh->queue);
         q != ngx_queue_sentinel(&lock->sh->queue);
         q = ngx_queue_next(q)) {

        node = (ngx_http_dav_lock_node_t *) q;

        if (len < node->path_len) {
            continue;
        }
        if (ngx_memcmp(uri->data, node->data, node->path_len) != 0) {
            continue;
        }
        if (exact && len != node->path_len) {
            continue;
        }
        if (!exact && len != node->path_len && !node->infinite) {
            continue;
        }
        if (len != node->path_len && node->data[node->path_len - 1] != '/' &&
            uri->data[node->path_len] != '/') {
            continue;
        }
        if (token->len != node->token_len) {
            continue;
        }
        if (ngx_memcmp(node->data + node->path_len,
            token->data, token->len) == 0) {
            return node;
        }
    }

    return NULL;
}

static ngx_http_dav_lock_node_t *
ngx_http_dav_find_lock(ngx_http_dav_lock_shm_t *lock, ngx_str_t *uri,
    ngx_uint_t exclusive)
{
    size_t                     len;
    ngx_queue_t               *q;
    ngx_http_dav_lock_node_t  *node;

    len = uri->len;

    for (q = ngx_queue_head(&lock->sh->queue);
         q != ngx_queue_sentinel(&lock->sh->queue);
         q = ngx_queue_next(q)) {

        node = (ngx_http_dav_lock_node_t *) q;

        if (exclusive && node->shared) {
            continue;
        }

        if (len < node->path_len) {
            continue;
        }
        if (ngx_memcmp(uri->data, node->data, node->path_len) != 0) {
            continue;
        }
        if (len == node->path_len) {
            return node;
        }
        if (!node->infinite) {
            continue;
        }
        if (node->data[node->path_len - 1] != '/' &&
            uri->data[node->path_len] != '/') {
            continue;
        }
        return node;
    }

    return NULL;
}

static void
ngx_http_dav_lock_cleanup(ngx_http_dav_lock_shm_t *lock, time_t now)
{
    ngx_queue_t               *q;
    ngx_http_dav_lock_node_t  *node;

    while (!ngx_queue_empty(&lock->sh->queue)) {
        q = ngx_queue_head(&lock->sh->queue);
        node = (ngx_http_dav_lock_node_t *) q;

        if (node->expire >= now) {
            break;
        }

        ngx_queue_remove(q);

        ngx_slab_free_locked(lock->shpool, node);

        if (lock->sh) {
            if (lock->sh->expired_count < (ngx_uint_t) -1) {
                lock->sh->expired_count++;
            }
            if (lock->sh->freed_count < (ngx_uint_t) -1) {
                lock->sh->freed_count++;
            }
            if (lock->sh->active_locks > 0) {
                lock->sh->active_locks--;
            }
        }
    }
}

static ngx_int_t
ngx_http_dav_if_header_match(ngx_http_request_t *r, ngx_http_dav_lock_shm_t *lock,
    ngx_str_t *uri, ngx_uint_t exact, ngx_http_dav_lock_node_t **matched,
    ngx_uint_t *has_if, ngx_uint_t *has_valid, ngx_uint_t *negated_match,
    ngx_uint_t *unmatched, ngx_uint_t *malformed)
{
    ngx_table_elt_t           *h;
    u_char                    *p, *last, *start, *end, *q;
    ngx_str_t                  token;
    ngx_uint_t                 negated;
    ngx_http_dav_lock_node_t  *node;
    ngx_str_t                  etag;
    ngx_uint_t                 etag_ready;
    ngx_int_t                  lock_present;

    *has_if = 0;
    *has_valid = 0;
    *negated_match = 0;
    *unmatched = 0;
    *malformed = 0;
    *matched = NULL;
    etag_ready = 0;
    lock_present = -1;

    h = ngx_http_dav_find_header(r, "If", sizeof("If") - 1);
    if (h == NULL) {
        return NGX_OK;
    }

    *has_if = 1;

    p = h->value.data;
    last = p + h->value.len;
    while (p < last) {

        if (*p == '[') {
            u_char *rb, *q1, *q2;

            rb = ngx_strlchr(p, last, ']');
            if (rb == NULL) {
                *malformed = 1;
                return NGX_OK;
            }
            q1 = ngx_strlchr(p, rb, '"');
            if (q1 == NULL) {
                *malformed = 1;
                return NGX_OK;
            }
            q2 = ngx_strlchr(q1 + 1, rb, '"');
            if (q2 == NULL) {
                *malformed = 1;
                return NGX_OK;
            }

            if (!etag_ready) {
                ngx_str_t path;
                size_t root;
                ngx_file_info_t fi;
                u_char *pl;

                pl = ngx_http_map_uri_to_path(r, &path, &root, 0);
                if (pl == NULL) {
                    *unmatched = 1;
                    return NGX_OK;
                }

                path.len = pl - path.data;

                if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
                    *unmatched = 1;
                    return NGX_OK;
                }

                etag.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + NGX_TIME_T_LEN + 3);
                if (etag.data == NULL) {
                    *unmatched = 1;
                    return NGX_OK;
                }

                etag.len = ngx_sprintf(etag.data, "\"%xT-%xO\"",
                    ngx_file_mtime(&fi), ngx_file_size(&fi)) - etag.data;

                etag_ready = 1;
            }

            if (etag_ready) {
                ngx_str_t tag;
                tag.data = q1;
                tag.len = q2 - q1 + 1;

                if (tag.len != etag.len ||
                    ngx_strncmp(tag.data, etag.data, tag.len) != 0) {
                    *unmatched = 1;
                }
            }

            p = rb + 1;
            continue;
        }

        if (*p != '<') {
            p++;
            continue;
        }

        start = p + 1;

        end = ngx_strlchr(start, last, '>');
        if (end == NULL) {
            *malformed = 1;
            return NGX_OK;
        }

        negated = 0;

        q = p;
        while (q > h->value.data &&
              (q[-1] == ' ' ||
               q[-1] == '\t' ||
               q[-1] == '(')) {
            q--;
        }

        if (q - h->value.data >= 3 && ngx_strncasecmp(q - 3,
            (u_char *) "Not", 3) == 0) {
            negated = 1;
        }

        if ((size_t) (end - start) >= sizeof(NGX_HTTP_DAV_LOCK_TOKEN_PREFIX) - 1 &&
            ngx_strncasecmp(start, (u_char *) NGX_HTTP_DAV_LOCK_TOKEN_PREFIX,
                sizeof(NGX_HTTP_DAV_LOCK_TOKEN_PREFIX) - 1) == 0) {

           *has_valid = 1;
            token.data = start;
            token.len = end - start;

            if (token.len != (sizeof(NGX_HTTP_DAV_LOCK_TOKEN_PREFIX) - 1) + 32) {
                *malformed = 1;
                return NGX_OK;
            }

            node = ngx_http_dav_find_token(lock, uri, &token, exact);
            if (node != NULL) {
                if (negated) {
                    *negated_match = 1;
                    return NGX_OK;
                }
                *matched = node;
            } else {
                *unmatched = 1;
            }
        } else {
            if ((end - start == sizeof("DAV:no-lock") - 1) &&
                ngx_strncasecmp(start, (u_char *) "DAV:no-lock",
                    sizeof("DAV:no-lock") - 1) == 0) {
                *has_valid = 1;

                if (lock_present == -1) {
                    lock_present = ngx_http_dav_find_lock(lock, uri, 0) != NULL;
                }
                if (negated) {
                    if (!lock_present) {
                        *unmatched = 1;
                    }
                } else {
                    if (lock_present) {
                        *unmatched = 1;
                    }
                }
            } else {
                if (!(((size_t) (end - start) >= sizeof("http://") - 1) &&
                    ngx_strncasecmp(start, (u_char *) "http://",
                        sizeof("http://") - 1) == 0) &&
                    !(((size_t) (end - start) >= sizeof("https://") - 1) &&
                    ngx_strncasecmp(start, (u_char *) "https://",
                        sizeof("https://") - 1) == 0) &&
                    !(start < end && *start == '/')) {
                    *unmatched = 1;
                }
            }
        }

        p = end + 1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_generate_token(ngx_http_request_t *r, ngx_str_t *token)
{
    u_char     *p;
    u_char      rand_bytes[16];
    ngx_uint_t  i;

    token->len = (sizeof(NGX_HTTP_DAV_LOCK_TOKEN_PREFIX) - 1) + 32;

    token->data = ngx_pnalloc(r->pool, token->len);
    if (token->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < 16; i++) {
        rand_bytes[i] = (u_char) ngx_random();
    }

    p = ngx_cpymem(token->data, NGX_HTTP_DAV_LOCK_TOKEN_PREFIX,
        sizeof(NGX_HTTP_DAV_LOCK_TOKEN_PREFIX) - 1);

    ngx_hex_dump(p, rand_bytes, 16);

    return NGX_OK;
}

static time_t
ngx_http_dav_parse_timeout(ngx_http_request_t *r)
{
    ngx_table_elt_t          *h;
    u_char                   *p, *last;
    ngx_int_t                 n;
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_int_t                 max_timeout;

    h = ngx_http_dav_find_header(r, "Timeout", sizeof("Timeout") - 1);
    if (h == NULL) {
        dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
        if (dlcf && dlcf->lock_timeout != NGX_CONF_UNSET) {
            return (time_t) dlcf->lock_timeout;
        }
        return NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT;
    }

    p = h->value.data;
    last = p + h->value.len;

    p = ngx_strlcasestrn(p, last, (u_char *) "Second-", sizeof("Second-") - 1);
    if (p == NULL) {
        return NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT;
    }

    p += sizeof("Second-") - 1;
    n = ngx_atoi(p, last - p);
    if (n <= 0) {
        return NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    max_timeout = (dlcf && dlcf->lock_timeout != NGX_CONF_UNSET)
                ? dlcf->lock_timeout : NGX_HTTP_DAV_LOCK_MAX_TIMEOUT;
    if (n > max_timeout) {
        n = max_timeout;
    }

    return (time_t) n;
}

static ngx_int_t
ngx_http_dav_parse_depth(ngx_http_request_t *r, ngx_uint_t *infinite)
{
    ngx_table_elt_t  *h;

    *infinite = 1;

#if (NGX_HTTP_DAV)
    h = r->headers_in.depth;
    if (h == NULL) {
        h = ngx_http_dav_find_header(r, "Depth", sizeof("Depth") - 1);
    }
#else
    h = ngx_http_dav_find_header(r, "Depth", sizeof("Depth") - 1);
#endif
    if (h == NULL) {
        return NGX_OK;
    }
    if (h->value.len == 1 && h->value.data[0] == '0') {
        *infinite = 0;
        return NGX_OK;
    }
    if (h->value.len == sizeof("infinity") - 1 &&
        ngx_strncasecmp(h->value.data, (u_char *) "infinity",
            sizeof("infinity") - 1) == 0) {
        *infinite = 1;
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_dav_resource_exists(ngx_http_request_t *r)
{
    u_char          *last;
    ngx_str_t        path;
    size_t           root;
    ngx_file_info_t  fi;

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_ERROR;
    }

    path.len = last - path.data;

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        return 0;
    }

    return 1;
}

static ngx_int_t
ngx_http_dav_lock_response(ngx_http_request_t *r, ngx_str_t *token,
    time_t timeout, ngx_uint_t infinite, ngx_uint_t shared, ngx_uint_t status)
{
    size_t            lockscope_len;
    size_t            len;
    ngx_buf_t        *b;
    ngx_chain_t       out;
    ngx_table_elt_t  *h;
    u_char           *p;
    u_char           *timeout_buf;
    ngx_int_t         rc;

    lockscope_len = shared
                  ? (sizeof("<D:lockscope><D:shared/></D:lockscope>\n") - 1)
                  : (sizeof("<D:lockscope><D:exclusive/></D:lockscope>\n") - 1);

    len = sizeof("<D:prop xmlns:D=\"DAV:\">\n") - 1
          + sizeof("<D:lockdiscovery>\n") - 1
          + sizeof("<D:activelock>\n") - 1
          + sizeof("<D:locktype><D:write/></D:locktype>\n") - 1
          + lockscope_len
          + sizeof("<D:depth>Infinity</D:depth>\n") - 1
          + sizeof("<D:timeout>Second-</D:timeout>\n") - 1
          + NGX_TIME_T_LEN
          + sizeof("<D:locktoken><D:href>") - 1
          + token->len
          + sizeof("</D:href></D:locktoken>\n") - 1
          + sizeof("</D:activelock>\n</D:lockdiscovery>\n</D:prop>\n") - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->pos;

    p = ngx_cpymem(p, "<D:prop xmlns:D=\"DAV:\">\n",
        sizeof("<D:prop xmlns:D=\"DAV:\">\n") - 1);
    p = ngx_cpymem(p, "<D:lockdiscovery>\n", sizeof("<D:lockdiscovery>\n") - 1);
    p = ngx_cpymem(p, "<D:activelock>\n", sizeof("<D:activelock>\n") - 1);
    p = ngx_cpymem(p, "<D:locktype><D:write/></D:locktype>\n",
        sizeof("<D:locktype><D:write/></D:locktype>\n") - 1);
    if (shared) {
        p = ngx_cpymem(p, "<D:lockscope><D:shared/></D:lockscope>\n",
            sizeof("<D:lockscope><D:shared/></D:lockscope>\n") - 1);
    } else {
        p = ngx_cpymem(p, "<D:lockscope><D:exclusive/></D:lockscope>\n",
            sizeof("<D:lockscope><D:exclusive/></D:lockscope>\n") - 1);
    }
    if (infinite) {
        p = ngx_cpymem(p, "<D:depth>Infinity</D:depth>\n",
            sizeof("<D:depth>Infinity</D:depth>\n") - 1);
    } else {
        p = ngx_cpymem(p, "<D:depth>0</D:depth>\n",
            sizeof("<D:depth>0</D:depth>\n") - 1);
    }
    p = ngx_cpymem(p, "<D:timeout>Second-",
        sizeof("<D:timeout>Second-") - 1);

    p = ngx_sprintf(p, "%T", timeout);

    p = ngx_cpymem(p, "</D:timeout>\n",
        sizeof("</D:timeout>\n") - 1);
    p = ngx_cpymem(p, "<D:locktoken><D:href>",
        sizeof("<D:locktoken><D:href>") - 1);
    p = ngx_cpymem(p, token->data, token->len);
    p = ngx_cpymem(p, "</D:href></D:locktoken>\n",
        sizeof("</D:href></D:locktoken>\n") - 1);
    p = ngx_cpymem(p, "</D:activelock>\n</D:lockdiscovery>\n</D:prop>\n",
        sizeof("</D:activelock>\n</D:lockdiscovery>\n</D:prop>\n") - 1);

    b->last = p;
    b->last_buf = 1;

    ngx_str_set(&r->headers_out.content_type, "text/xml; charset=utf-8");
    r->headers_out.status = status;
    r->headers_out.content_length_n = b->last - b->pos;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "Lock-Token");
    h->hash = 1;
    h->value.len = token->len + 2;

    h->value.data = ngx_pnalloc(r->pool, h->value.len);
    if (h->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->value.data[0] = '<';
    ngx_memcpy(h->value.data + 1, token->data, token->len);
    h->value.data[h->value.len - 1] = '>';

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "Timeout");
    h->hash = 1;

    timeout_buf = ngx_pnalloc(r->pool, sizeof("Second-") + NGX_TIME_T_LEN);
    if (timeout_buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->value.data = timeout_buf;
    h->value.len = ngx_sprintf(timeout_buf, "Second-%T", timeout) - timeout_buf;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_dav_is_shared(ngx_http_request_t *r)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;
    u_char       *p, *last;
    u_char        carry[8];
    size_t        carry_len;

    if (r->request_body == NULL) {
        return 0;
    }

    carry_len = 0;

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        b = cl->buf;
        if (b->pos && b->last && b->pos < b->last) {
            p = b->pos;
            last = b->last;

            if (ngx_strlcasestrn(p, last, (u_char *) "shared",
                sizeof("shared") - 2)) {

                return 1;
            }
            if (ngx_strlcasestrn(p, last, (u_char *) "exclusive",
                sizeof("exclusive") - 2)) {

                return 0;
            }
            if (carry_len > 0) {
                u_char  tmp[16];
                size_t  n, need;

                need = sizeof(tmp) - carry_len;

                n = (size_t) (last - p);
                if (n > need) {
                    n = need;
                }

                ngx_memcpy(tmp, carry, carry_len);
                ngx_memcpy(tmp + carry_len, p, n);

                if (ngx_strlcasestrn(tmp, tmp + carry_len + n,
                    (u_char *) "shared", sizeof("shared") - 2)) {

                    return 1;
                }

                if (ngx_strlcasestrn(tmp, tmp + carry_len + n,
                    (u_char *) "exclusive", sizeof("exclusive") - 2)) {

                    return 0;
                }
            }

            if ((size_t) (last - p) >= sizeof(carry)) {
                ngx_memcpy(carry, last - sizeof(carry), sizeof(carry));
                carry_len = sizeof(carry);
            } else {
                carry_len = (size_t) (last - p);
                ngx_memcpy(carry, p + ((size_t) (last - p) - carry_len),
                    carry_len);
            }
        } else {
            if (ngx_buf_in_memory(b) && b->start && b->end &&
                b->start < b->end) {

                p = b->start;
                last = b->end;
                if (ngx_strlcasestrn(p, last, (u_char *) "shared",
                    sizeof("shared") - 2)) {
                    return 1;
                }
                if (ngx_strlcasestrn(p, last, (u_char *) "exclusive",
                    sizeof("exclusive") - 2)) {
                    return 0;
                }
            }
        }
        if (b->in_file && b->file) {
            u_char   tbuf[4096];
            ssize_t  n;
            off_t    off, end;

            if (b->file->fd == NGX_INVALID_FILE) {
                b->file->fd = ngx_open_file(b->file->name.data, NGX_FILE_RDONLY,
                    NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
                if (b->file->fd == NGX_INVALID_FILE) {
                    continue;
                }
            }

            off = b->file_pos;
            end = b->file_last;

            while (off < end) {
                size_t  size;

                size = (size_t) (end - off);
                if (size > sizeof(tbuf)) {
                    size = sizeof(tbuf);
                }

                n = ngx_read_file(b->file, tbuf, size, off);
                if (n <= 0) {
                    break;
                }

                if (ngx_strlcasestrn(tbuf, tbuf + n, (u_char *) "shared",
                    sizeof("shared") - 2)) {
                    return 1;
                }
                if (ngx_strlcasestrn(tbuf, tbuf + n, (u_char *) "exclusive",
                    sizeof("exclusive") - 2)) {
                    return 0;
                }

                if (carry_len > 0) {
                    u_char  tmp[16];
                    size_t  need, n2;

                    need = sizeof(tmp) - carry_len;

                    n2 = (size_t) n;
                    if (n2 > need) {
                        n2 = need;
                    }

                    ngx_memcpy(tmp, carry, carry_len);
                    ngx_memcpy(tmp + carry_len, tbuf, n2);

                    if (ngx_strlcasestrn(tmp, tmp + carry_len + n2,
                        (u_char *) "shared", sizeof("shared") - 1)) {
                        return 1;
                    }
                    if (ngx_strlcasestrn(tmp, tmp + carry_len + n2,
                        (u_char *) "exclusive", sizeof("exclusive") - 1)) {
                        return 0;
                    }
                }

                if ((size_t) n >= sizeof(carry)) {
                    ngx_memcpy(carry, tbuf + n - sizeof(carry), sizeof(carry));
                    carry_len = sizeof(carry);
                } else {
                    carry_len = (size_t) n;
                    ngx_memcpy(carry, tbuf + n - carry_len, carry_len);
                }

                off += n;
            }
        }
    }

    if (r->request_body->temp_file) {
        ngx_temp_file_t  *tf;
        ngx_file_info_t   fi;
        u_char            tbuf[4096];
        ssize_t           n;
        off_t             off, end;

        tf = r->request_body->temp_file;
        if (tf->file.fd == NGX_INVALID_FILE) {
            tf->file.fd = ngx_open_file(tf->file.name.data, NGX_FILE_RDONLY,
                NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
            if (tf->file.fd == NGX_INVALID_FILE) {
                return 0;
            }
        }
        if (ngx_file_info(tf->file.name.data, &fi) == NGX_FILE_ERROR) {
            return 0;
        }

        end = (off_t) ngx_file_size(&fi);
        if (end == 0) {
            return 0;
        }

        carry_len = 0;
        off = 0;

        while (off < end) {
            size_t  size;

            size = (size_t) (end - off);
            if (size > sizeof(tbuf)) {
                size = sizeof(tbuf);
            }

            n = ngx_read_file(&tf->file, tbuf, size, off);
            if (n <= 0) {
                return 0;
            }
            if (ngx_strlcasestrn(tbuf, tbuf + n, (u_char *) "shared",
                sizeof("shared") - 2)) {
                return 1;
            }
            if (ngx_strlcasestrn(tbuf, tbuf + n, (u_char *) "exclusive",
                sizeof("exclusive") - 2)) {
                return 0;
            }

            if (carry_len > 0) {
                u_char  tmp[16];
                size_t  need, n2;

                need = sizeof(tmp) - carry_len;

                n2 = (size_t) n;
                if (n2 > need) {
                    n2 = need;
                }

                ngx_memcpy(tmp, carry, carry_len);
                ngx_memcpy(tmp + carry_len, tbuf, n2);

                if (ngx_strlcasestrn(tmp, tmp + carry_len + n2,
                    (u_char *) "shared", sizeof("shared") - 2)) {
                    return 1;
                }
                if (ngx_strlcasestrn(tmp, tmp + carry_len + n2,
                    (u_char *) "exclusive", sizeof("exclusive") - 2)) {
                    return 0;
                }
            }

            if ((size_t) n >= sizeof(carry)) {
                ngx_memcpy(carry, tbuf + n - sizeof(carry), sizeof(carry));
                carry_len = sizeof(carry);
            } else {
                carry_len = (size_t) n;
                ngx_memcpy(carry, tbuf + n - carry_len, carry_len);
            }

            off += n;
        }
    }

    return 0;
}

static ngx_int_t
ngx_http_dav_lock_resolve(ngx_http_request_t *r)
{
    ngx_uint_t                 infinite;
    time_t                     timeout;
    ngx_str_t                  uri;
    ngx_http_dav_loc_conf_t   *dlcf;
    ngx_http_dav_lock_shm_t   *lock;
    ngx_http_dav_lock_node_t  *node;
    ngx_http_dav_lock_node_t  *match;
    ngx_uint_t                 has_if, has_valid, negated_match, unmatched, malformed;
    ngx_str_t                  token;
    ngx_uint_t                 status;
    ngx_int_t                  exists;
    ngx_uint_t                 shared;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    shared = ngx_http_dav_is_shared(r);

    if (ngx_http_dav_parse_depth(r, &infinite) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    timeout = ngx_http_dav_parse_timeout(r);

    uri = r->uri;

    exists = ngx_http_dav_resource_exists(r);
    status = (exists == 0) ? NGX_HTTP_CREATED : NGX_HTTP_OK;

    lock = dlcf->shm_zone->data;

    ngx_shmtx_lock(&lock->shpool->mutex);
    ngx_http_dav_lock_cleanup(lock, ngx_time());

    has_if = 0;
    has_valid = 0;
    negated_match = 0;
    unmatched = 0;
    malformed = 0;
    match = NULL;

    (void) ngx_http_dav_if_header_match(r, lock, &uri, 0, &match, &has_if, &has_valid,
        &negated_match, &unmatched, &malformed);

    if (match != NULL && has_if && !negated_match && !unmatched && !malformed) {
        token.data = match->data + match->path_len;
        token.len = match->token_len;

        match->expire = ngx_time() + timeout;

        ngx_shmtx_unlock(&lock->shpool->mutex);

        return ngx_http_dav_lock_response(r, &token, timeout, match->infinite,
            match->shared, NGX_HTTP_OK);
    }

    node = ngx_http_dav_find_lock(lock, &uri, shared);

    if (node != NULL) {
        if (!has_if || malformed) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_DAV_LOCKED;
        }
        if (!has_valid && match == NULL) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        if (negated_match || unmatched || match == NULL) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }
    }

    if (ngx_http_dav_generate_token(r, &token) != NGX_OK) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    node = ngx_slab_alloc_locked(lock->shpool,
        sizeof(ngx_http_dav_lock_node_t) + uri.len + token.len);

    if (node == NULL) {

        if (lock->sh && lock->sh->alloc_failures < (ngx_uint_t) -1) {
            lock->sh->alloc_failures++;
        }
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    node->expire = ngx_time() + timeout;
    node->infinite = infinite;
    node->shared = shared;
    node->path_len = uri.len;
    node->token_len = token.len;

    ngx_memcpy(node->data, uri.data, uri.len);
    ngx_memcpy(node->data + uri.len, token.data, token.len);

    ngx_queue_insert_tail(&lock->sh->queue, &node->queue);

    if (lock->sh) {
        lock->sh->allocated_count++;
        lock->sh->active_locks++;
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return ngx_http_dav_lock_response(r, &token, timeout, infinite, shared,
        status);
}

static void
ngx_http_dav_lock_finalize(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    rc = ngx_http_dav_lock_resolve(r);
    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_dav_lock_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (!dlcf->enabled || dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    if (!(r->method & NGX_HTTP_LOCK)) {
        return NGX_DECLINED;
    }

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 0;
    r->request_body_in_file_only = 0;

    rc = ngx_http_read_client_request_body(r, ngx_http_dav_lock_finalize);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

/* === UNLOCK === */

static ngx_int_t
ngx_http_dav_parse_token(ngx_str_t *src, ngx_str_t *token)
{
    u_char  *p, *last, *end;

    p = ngx_strlchr(src->data, src->data + src->len, '<');
    if (p == NULL) {
        return NGX_ERROR;
    }

    p++;
    last = src->data + src->len;

    end = ngx_strlchr(p, last, '>');
    if (end == NULL) {
        return NGX_ERROR;
    }

    if ((size_t) (end - p) < sizeof(NGX_HTTP_DAV_LOCK_TOKEN_PREFIX) - 1 ||
        ngx_strncasecmp(p, (u_char *) NGX_HTTP_DAV_LOCK_TOKEN_PREFIX,
            sizeof(NGX_HTTP_DAV_LOCK_TOKEN_PREFIX) - 1) != 0) {
        return NGX_ERROR;
    }

    token->data = p;
    token->len = end - p;

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_unlock_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_table_elt_t           *h;
    ngx_http_dav_loc_conf_t   *dlcf;
    ngx_http_dav_lock_shm_t   *lock;
    ngx_http_dav_lock_node_t  *node;
    ngx_str_t                  token;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (!dlcf->enabled || dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }
    if (r->method != NGX_HTTP_UNLOCK) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    h = ngx_http_dav_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
    if (h == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (ngx_http_dav_parse_token(&h->value, &token) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    lock = dlcf->shm_zone->data;
    ngx_shmtx_lock(&lock->shpool->mutex);
    ngx_http_dav_lock_cleanup(lock, ngx_time());

    node = ngx_http_dav_find_token(lock, &r->uri, &token, 1);
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_CONFLICT;
    }

    ngx_queue_remove(&node->queue);
    ngx_slab_free_locked(lock->shpool, node);

    if (lock->sh) {

        if (lock->sh->freed_count < (ngx_uint_t) -1) {
            lock->sh->freed_count++;
        }

        if (lock->sh->active_locks > 0) {
            lock->sh->active_locks--;
        }
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_HTTP_NO_CONTENT;
}

/* === OPTIONS === */

static ngx_int_t
ngx_http_dav_options_handler(ngx_http_request_t *r, ngx_http_dav_loc_conf_t *dlcf)
{
    ngx_table_elt_t  *h;
    ngx_uint_t        methods;
    ngx_uint_t        lock_enabled;
    size_t            len;
    u_char           *p;
    ngx_str_t         allow;

    methods = dlcf->methods;
    lock_enabled = (dlcf->enabled && dlcf->shm_zone != NULL);
    len = sizeof("OPTIONS") - 1;

    if (methods & NGX_HTTP_PUT) {
        len += sizeof(", PUT") - 1;
    }
    if (methods & NGX_HTTP_DELETE) {
        len += sizeof(", DELETE") - 1;
    }
    if (methods & NGX_HTTP_MKCOL) {
        len += sizeof(", MKCOL") - 1;
    }
    if (methods & NGX_HTTP_COPY) {
        len += sizeof(", COPY") - 1;
    }
    if (methods & NGX_HTTP_MOVE) {
        len += sizeof(", MOVE") - 1;
    }
    if (lock_enabled && (methods & NGX_HTTP_LOCK)) {
        len += sizeof(", LOCK") - 1;
    }
    if (lock_enabled && (methods & NGX_HTTP_UNLOCK)) {
        len += sizeof(", UNLOCK") - 1;
    }
    if (methods & NGX_HTTP_PROPFIND) {
        len += sizeof(", PROPFIND") - 1;
    }
    if (methods & NGX_HTTP_PROPPATCH) {
        len += sizeof(", PROPPATCH") - 1;
    }

    allow.data = ngx_pnalloc(r->pool, len);
    if (allow.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(allow.data, "OPTIONS", sizeof("OPTIONS") - 1);

    if (methods & NGX_HTTP_PUT) {
        p = ngx_cpymem(p, ", PUT", sizeof(", PUT") - 1);
    }
    if (methods & NGX_HTTP_DELETE) {
        p = ngx_cpymem(p, ", DELETE", sizeof(", DELETE") - 1);
    }
    if (methods & NGX_HTTP_MKCOL) {
        p = ngx_cpymem(p, ", MKCOL", sizeof(", MKCOL") - 1);
    }
    if (methods & NGX_HTTP_COPY) {
        p = ngx_cpymem(p, ", COPY", sizeof(", COPY") - 1);
    }
    if (methods & NGX_HTTP_MOVE) {
        p = ngx_cpymem(p, ", MOVE", sizeof(", MOVE") - 1);
    }
    if (methods & NGX_HTTP_PROPFIND) {
        p = ngx_cpymem(p, ", PROPFIND", sizeof(", PROPFIND") - 1);
    }
    if (methods & NGX_HTTP_PROPPATCH) {
        p = ngx_cpymem(p, ", PROPPATCH", sizeof(", PROPPATCH") - 1);
    }
    if (lock_enabled && (methods & NGX_HTTP_LOCK)) {
        p = ngx_cpymem(p, ", LOCK", sizeof(", LOCK") - 1);
    }
    if (lock_enabled && (methods & NGX_HTTP_UNLOCK)) {
        p = ngx_cpymem(p, ", UNLOCK", sizeof(", UNLOCK") - 1);
    }

    allow.len = p - allow.data;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "Allow");
    h->hash = 1;
    h->value = allow;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "DAV");
    h->hash = 1;

    if (lock_enabled && (methods & (NGX_HTTP_LOCK|NGX_HTTP_UNLOCK))) {
        ngx_str_set(&h->value, "1,2");
    } else {
        ngx_str_set(&h->value, "1");
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    return ngx_http_send_header(r);
}

/* === HANDLER === */

static ngx_int_t
ngx_http_dav_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (!(r->method & dlcf->methods)) {
        if ((dlcf->methods & (NGX_HTTP_PUT|NGX_HTTP_DELETE|
                              NGX_HTTP_MKCOL|
                              NGX_HTTP_COPY|NGX_HTTP_MOVE)) == 0) {
            return NGX_DECLINED;
        }
        if ((dlcf->methods & (NGX_HTTP_PROPFIND|NGX_HTTP_PROPPATCH)) == 0) {
            return NGX_DECLINED;
        }
        if (r->method != NGX_HTTP_OPTIONS) {
            return NGX_DECLINED;
        }
    }
    if ((r->method == NGX_HTTP_LOCK || r->method == NGX_HTTP_UNLOCK) &&
        (!dlcf->enabled || dlcf->shm_zone == NULL)) {
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    switch (r->method) {
        case NGX_HTTP_PUT:
            return ngx_http_dav_put_handler(r);

        case NGX_HTTP_DELETE:
            return ngx_http_dav_delete_handler(r);

        case NGX_HTTP_MKCOL:
            return ngx_http_dav_mkcol_handler(r, dlcf);

        case NGX_HTTP_COPY:
            return ngx_http_dav_copy_handler(r);

        case NGX_HTTP_MOVE:
            return ngx_http_dav_move_handler(r);

        case NGX_HTTP_LOCK:
            return ngx_http_dav_lock_handler(r);

        case NGX_HTTP_UNLOCK:
            return ngx_http_dav_unlock_handler(r);

        case NGX_HTTP_PROPFIND:
            return ngx_http_dav_propfind_handler(r);

        case NGX_HTTP_PROPPATCH:
            return ngx_http_dav_proppatch_handler(r);

        case NGX_HTTP_OPTIONS:
            return ngx_http_dav_options_handler(r, dlcf);
    }

    return NGX_DECLINED;
}

/* === Config === */

static ngx_int_t
ngx_http_dav_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_dav_lock_shm_t  *octx = data;
    ngx_http_dav_lock_shm_t  *ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }
    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    if (ctx->shpool == NULL) {
        return NGX_ERROR;
    }
    if (ctx->shpool->data) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }
    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_dav_lock_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_queue_init(&ctx->sh->queue);

    ctx->sh->active_locks = 0;
    ctx->sh->allocated_count = 0;
    ctx->sh->expired_count = 0;
    ctx->sh->freed_count = 0;
    ctx->sh->alloc_failures = 0;

    return NGX_OK;
}

static char *
ngx_http_dav_lock_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dav_loc_conf_t  *dlcf = conf;
    ngx_str_t                *value;
    ngx_str_t                 name;
    ngx_shm_zone_t           *shm_zone;
    ngx_http_dav_lock_shm_t  *lock_shm;
    ssize_t                   size;
    ngx_int_t                 timeout;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        dlcf->enabled = 0;
        return NGX_CONF_OK;
    }
    if (value[1].len > sizeof("zone=") - 1 &&
        ngx_strncmp(value[1].data, "zone=", sizeof("zone=") - 1) == 0) {
        name.len = value[1].len - (sizeof("zone=") - 1);

        name.data = ngx_pnalloc(cf->pool, name.len);
        if (name.data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(name.data, value[1].data + sizeof("zone=") - 1, name.len);
    } else {
        name = value[1];
    }

    size = NGX_HTTP_DAV_LOCK_DEFAULT_SIZE;
    timeout = NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT;

    if (cf->args->nelts >= 3) {
        ngx_str_t s = value[2];
        if (s.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid dav_lock_zone size \"%V\"", &s);
            return NGX_CONF_ERROR;
        }
        if (s.data[s.len - 1] == 'm' || s.data[s.len - 1] == 'M') {
            ssize_t parsed = ngx_parse_size(&s);
            if (parsed <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid dav_lock_zone size \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            size = parsed;
        } else {
            ngx_int_t v = ngx_atoi(s.data, s.len);
            if (v == NGX_ERROR || v <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid dav_lock_zone size \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            size = (ssize_t) v * 1024 * 1024;
        }
    }

    if (size <= 0 || size > NGX_HTTP_DAV_LOCK_MAX_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid dav_lock_zone size, must be > 0 and <= %uz",
            NGX_HTTP_DAV_LOCK_MAX_SIZE);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts >= 4) {
        ngx_int_t  v;
        ngx_int_t  multiplier = 1;
        ngx_str_t  t = value[3];

        if (t.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid dav_lock_zone timeout \"%V\"", &t);
            return NGX_CONF_ERROR;
        }

        if (t.data[t.len - 1] == 's' || t.data[t.len - 1] == 'S') {
            multiplier = 1;
            t.len--;
        } else if (t.data[t.len - 1] == 'm' || t.data[t.len - 1] == 'M') {
            multiplier = 60;
            t.len--;
        } else if (t.data[t.len - 1] == 'h' || t.data[t.len - 1] == 'H') {
            multiplier = 3600;
            t.len--;
        }

        v = ngx_atoi(t.data, t.len);
        if (v == NGX_ERROR || v <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid dav_lock_zone timeout \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }
        if (v > NGX_HTTP_DAV_LOCK_MAX_TIMEOUT / multiplier) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid dav_lock_zone timeout \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }

        timeout = v * multiplier;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_dav_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data == NULL) {
        lock_shm = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_lock_shm_t));
        if (lock_shm == NULL) {
            return NGX_CONF_ERROR;
        }

        lock_shm->sh = NULL;
        lock_shm->shpool = NULL;
        lock_shm->timeout = timeout;
        lock_shm->size = size;

        shm_zone->init = ngx_http_dav_init_zone;
        shm_zone->data = lock_shm;
    } else {
        if (cf->args->nelts >= 3 || cf->args->nelts >= 4) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "dav_lock_zone: parameters ignored for existing zone \"%V\"",
                &name);
        }
    }

    dlcf->enabled = 1;
    dlcf->shm_zone = shm_zone;

    if (shm_zone->data) {
        ngx_http_dav_lock_shm_t *z = shm_zone->data;
        dlcf->lock_timeout = (z->timeout > 0)
                           ? z->timeout
                           : NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT;
    } else {
        dlcf->lock_timeout = timeout;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_dav_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dav_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->min_delete_depth = NGX_CONF_UNSET_UINT;
    conf->access = NGX_CONF_UNSET_UINT;
    conf->create_full_path = NGX_CONF_UNSET;
    conf->enabled = NGX_CONF_UNSET;
    conf->shm_zone = NULL;
    conf->lock_timeout = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_loc_conf_t  *prev = parent;
    ngx_http_dav_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
        (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_OFF));
    ngx_conf_merge_uint_value(conf->min_delete_depth,
        prev->min_delete_depth, 0);
    ngx_conf_merge_uint_value(conf->access, prev->access, 0600);
    ngx_conf_merge_value(conf->create_full_path, prev->create_full_path, 0);
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    ngx_conf_merge_value(conf->lock_timeout, prev->lock_timeout,
                             NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT);

    if (conf->lock_timeout <= 0 || conf->lock_timeout > 86400) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid dav_lock_timeout \"%i\"", conf->lock_timeout);
        return NGX_CONF_ERROR;
    }
    if ((conf->methods & NGX_HTTP_LOCK) && !(conf->methods & NGX_HTTP_UNLOCK)) {
        conf->methods &= ~NGX_HTTP_LOCK;
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "dav_methods: LOCK ignored because UNLOCK is not enabled");
    }
    if ((conf->methods & NGX_HTTP_UNLOCK) && !(conf->methods & NGX_HTTP_LOCK)) {
        conf->methods &= ~NGX_HTTP_UNLOCK;
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "dav_methods: UNLOCK ignored because LOCK is not enabled");
    }

    if ((conf->methods & (NGX_HTTP_LOCK|NGX_HTTP_UNLOCK)) &&
        conf->shm_zone == NULL) {

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "dav_lock_zone: creating default zone \"dav_lock\" (%uz, %is)",
            (size_t) NGX_HTTP_DAV_LOCK_DEFAULT_SIZE,
            (ngx_int_t) NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT);

        ngx_str_t name = ngx_string("dav_lock");
        ngx_shm_zone_t           *shm_zone;
        ngx_http_dav_lock_shm_t  *lock_shm;

        shm_zone = ngx_shared_memory_add(cf, &name,
            NGX_HTTP_DAV_LOCK_DEFAULT_SIZE, &ngx_http_dav_module);
        if (shm_zone == NULL) {
            return NGX_CONF_ERROR;
        }

        if (shm_zone->data == NULL) {
            lock_shm = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_lock_shm_t));
            if (lock_shm == NULL) {
                return NGX_CONF_ERROR;
            }

            lock_shm->sh = NULL;
            lock_shm->shpool = NULL;
            lock_shm->timeout = NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT;
            lock_shm->size = NGX_HTTP_DAV_LOCK_DEFAULT_SIZE;

            shm_zone->init = ngx_http_dav_init_zone;
            shm_zone->data = lock_shm;
        }

        conf->enabled = 1;
        conf->shm_zone = shm_zone;
        conf->lock_timeout = NGX_HTTP_DAV_LOCK_DEFAULT_TIMEOUT;
    }

    return NGX_CONF_OK;
}

static void *ngx_http_dav_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dav_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

/* === Init === */

static ngx_int_t
ngx_http_dav_verify(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_uint_t delete_lock)
{
    ngx_http_dav_loc_conf_t   *dlcf;
    ngx_http_dav_lock_shm_t   *lock;
    ngx_http_dav_lock_node_t  *node;
    ngx_http_dav_lock_node_t  *match;
    ngx_uint_t                 has_if, has_valid, negated_match, unmatched, malformed;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    lock = dlcf->shm_zone->data;

    ngx_shmtx_lock(&lock->shpool->mutex);
    ngx_http_dav_lock_cleanup(lock, ngx_time());

    node = ngx_http_dav_find_lock(lock, uri, 0);

    has_if = 0;
    has_valid = 0;
    negated_match = 0;
    unmatched = 0;
    malformed = 0;
    match = NULL;

    (void) ngx_http_dav_if_header_match(r, lock, uri, 0, &match, &has_if, &has_valid,
        &negated_match, &unmatched, &malformed);

    if (node != NULL) {
        if (!has_if || malformed) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_DAV_LOCKED;
        }
        if (!has_valid && match == NULL) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        if (negated_match || unmatched) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        if (match == NULL) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        node = match;
    } else {
        if (has_if) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_OK;
    }

    if (delete_lock && node->path_len == uri->len &&
        ngx_memcmp(node->data, uri->data, uri->len) == 0) {
        ngx_queue_remove(&node->queue);
        ngx_slab_free_locked(lock->shpool, node);

        if (lock->sh) {
            if (lock->sh->freed_count < (ngx_uint_t) -1) {
                lock->sh->freed_count++;
            }
            if (lock->sh->active_locks > 0) {
                lock->sh->active_locks--;
            }
        }
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_strip_uri(ngx_http_request_t *r, ngx_str_t *uri)
{
    u_char  *p, *last, *host;

    if (uri->data[0] == '/') {
        return NGX_OK;
    }

    if (ngx_strncmp(uri->data, "http://", sizeof("http://") - 1) == 0) {
        host = uri->data + sizeof("http://") - 1;
    } else {
        if (ngx_strncmp(uri->data, "https://", sizeof("https://") - 1) == 0) {
            host = uri->data + sizeof("https://") - 1;
        } else {
            return NGX_DECLINED;
        }
    }

    last = uri->data + uri->len;

    for (p = host; p < last; p++) {
        if (*p == '/') {
            uri->data = p;
            uri->len = last - p;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_dav_precontent_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_str_t                 uri;
    ngx_table_elt_t          *dest;
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (!dlcf->enabled || dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    (void) ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    if (r->method & (NGX_HTTP_PUT|NGX_HTTP_DELETE|
                     NGX_HTTP_MKCOL|
                     NGX_HTTP_MOVE|NGX_HTTP_PROPPATCH)) {
        rc = ngx_http_dav_verify(r, &r->uri,
            (r->method & (NGX_HTTP_DELETE|NGX_HTTP_MOVE)) ? 1 : 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (r->method & (NGX_HTTP_COPY|NGX_HTTP_MOVE)) {
#if (NGX_HTTP_DAV)
        dest = r->headers_in.destination;
        if (dest == NULL) {
            dest = ngx_http_dav_find_header(r, "Destination",
                sizeof("Destination") - 1);
        }
#else
        dest = ngx_http_dav_find_header(r, "Destination",
            sizeof("Destination") - 1);
#endif
        if (dest == NULL) {
            return NGX_DECLINED;
        }

        uri.data = dest->value.data;
        uri.len = dest->value.len;

        if (ngx_http_dav_strip_uri(r, &uri) != NGX_OK) {
            return NGX_DECLINED;
        }

        rc = ngx_http_dav_verify(r, &uri, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_DECLINED;
}

static ngx_flag_t
ngx_http_dav_header_contains(ngx_str_t *value, const char *token, size_t len)
{
    u_char  *p, *last;

    if (value->len < len) {
        return 0;
    }

    p = value->data;
    last = value->data + value->len;

    return ngx_strlcasestrn(p, last, (u_char *) token, len - 1) != NULL;
}

static ngx_int_t
ngx_http_dav_header_filter(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t          *dlcf;
    ngx_http_dav_main_conf_t         *mcf;
    ngx_http_output_header_filter_pt  next;
    ngx_table_elt_t                  *h;
    ngx_str_t                         new_value;
    size_t                            extra;
    u_char                           *p;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    if (!dlcf->enabled || dlcf->shm_zone == NULL) {
        mcf = ngx_http_get_module_main_conf(r, ngx_http_dav_module);
        next = mcf ? mcf->next_header_filter : NULL;
        return next ? next(r) : NGX_OK;
    }
    if (r->method != NGX_HTTP_OPTIONS) {
        mcf = ngx_http_get_module_main_conf(r, ngx_http_dav_module);
        next = mcf ? mcf->next_header_filter : NULL;
        return next ? next(r) : NGX_OK;
    }

    h = ngx_http_dav_find_header(r, "DAV", sizeof("DAV") - 1);
    if (h == NULL) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_str_set(&h->key, "DAV");
        h->hash = 1;
    }

    new_value.len = sizeof("1,2") - 1;

    new_value.data = ngx_pnalloc(r->pool, new_value.len);
    if (new_value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(new_value.data, "1,2", new_value.len);
    h->value = new_value;

    h = ngx_http_dav_find_header(r, "Allow", sizeof("Allow") - 1);
    if (h != NULL) {
        extra = 0;

        if (!ngx_http_dav_header_contains(&h->value, "LOCK",
            sizeof("LOCK") - 1)) {
            extra += sizeof(", LOCK") - 1;
        }
        if (!ngx_http_dav_header_contains(&h->value, "UNLOCK",
            sizeof("UNLOCK") - 1)) {
            extra += sizeof(", UNLOCK") - 1;
        }

        if (extra) {
            new_value.len = h->value.len + extra;

            new_value.data = ngx_pnalloc(r->pool, new_value.len);
            if (new_value.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = ngx_cpymem(new_value.data, h->value.data, h->value.len);

            if (!ngx_http_dav_header_contains(&h->value, "LOCK",
                sizeof("LOCK") - 1)) {
                p = ngx_cpymem(p, ", LOCK", sizeof(", LOCK") - 1);
            }
            if (!ngx_http_dav_header_contains(&h->value, "UNLOCK",
                sizeof("UNLOCK") - 1)) {
                p = ngx_cpymem(p, ", UNLOCK", sizeof(", UNLOCK") - 1);
            }

            h->value = new_value;
        }
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_dav_module);
    next = mcf ? mcf->next_header_filter : NULL;

    return next ? next(r) : NGX_OK;
}

static ngx_int_t
ngx_http_dav_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_dav_main_conf_t   *mcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_precontent_handler;

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dav_module);
    if (mcf && mcf->next_header_filter == NULL) {
        mcf->next_header_filter = ngx_http_top_header_filter;
    }

    ngx_http_top_header_filter = ngx_http_dav_header_filter;

    return NGX_OK;
}