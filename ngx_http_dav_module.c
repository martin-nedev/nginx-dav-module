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
#include <time.h>

extern ngx_module_t ngx_http_dav_module;

typedef struct ngx_http_dav_propfind_req_s ngx_http_dav_propfind_req_t;
typedef struct ngx_http_dav_proppatch_req_s ngx_http_dav_proppatch_req_t;
typedef struct ngx_http_dav_loc_conf_s ngx_http_dav_loc_conf_t;
typedef struct ngx_http_dav_lock_s ngx_http_dav_lock_t;
typedef struct ngx_http_dav_lock_shctx_s ngx_http_dav_lock_shctx_t;
typedef struct ngx_http_dav_lock_zone_ctx_s ngx_http_dav_lock_zone_ctx_t;

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_propfind_handler(ngx_http_request_t *r);
static void ngx_http_dav_propfind_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_proppatch_handler(ngx_http_request_t *r);
static void ngx_http_dav_proppatch_body_handler(ngx_http_request_t *r);
static void ngx_http_dav_lock_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_options_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_copy_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_move_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_lock_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_unlock_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_dav_copy_file_atomic(ngx_http_request_t *r,
    const char *src, const char *dst);
static ngx_int_t ngx_http_dav_copy_dir(ngx_http_request_t *r,
    const char *src, const char *dst);
static ngx_int_t ngx_http_dav_remove_tree(ngx_http_request_t *r, const char *path);
static ngx_str_t ngx_http_dav_xml_escape(ngx_pool_t *pool, const u_char *src, size_t len);
static ngx_table_elt_t *ngx_http_dav_find_header(ngx_http_request_t *r,
    const char *name, size_t len);
static ngx_int_t ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt);
static ngx_int_t ngx_http_dav_parse_overwrite(ngx_http_request_t *r,
    ngx_uint_t *overwrite);
static ngx_int_t ngx_http_dav_parse_destination(ngx_http_request_t *r,
    ngx_str_t *duri);
static ngx_int_t ngx_http_dav_map_destination_path(ngx_http_request_t *r,
    ngx_str_t *duri, ngx_str_t *path);
static ngx_int_t ngx_http_dav_prepare_destination_parent(ngx_http_request_t *r,
    ngx_str_t *path, ngx_http_dav_loc_conf_t *dlcf);
static ngx_int_t ngx_http_dav_prepare_source_path(ngx_http_request_t *r,
    ngx_str_t *path, ngx_file_info_t *st, ngx_flag_t log_symlink_refusal);
static ngx_int_t ngx_http_dav_chain_append(ngx_http_request_t *r, ngx_chain_t ***ll,
    off_t *total, const u_char *data, size_t len);
static ngx_int_t ngx_http_dav_propfind_collect_body(ngx_http_request_t *r, ngx_str_t *body);
static ngx_int_t ngx_http_dav_propfind_parse_body(const u_char *data, size_t len,
    ngx_http_dav_propfind_req_t *preq);
static ngx_int_t ngx_http_dav_proppatch_parse_body(const u_char *data, size_t len,
    ngx_http_dav_proppatch_req_t *preq);
static ngx_int_t ngx_http_dav_propfind_append_unknown_propstat(ngx_http_request_t *r,
    ngx_chain_t ***ll, off_t *total, ngx_http_dav_propfind_req_t *preq);
static ngx_int_t ngx_http_dav_propfind_emit_children(ngx_http_request_t *r,
    ngx_chain_t ***ll, off_t *content_length, ngx_http_dav_propfind_req_t *preq,
    const char *dir_path, const ngx_str_t *parent_uri,
    ngx_uint_t current_depth, ngx_uint_t max_depth,
    ngx_uint_t *responses_emitted, ngx_uint_t max_responses);
static ngx_int_t ngx_http_dav_lock_normalize_uri(ngx_pool_t *pool,
    const ngx_str_t *in, ngx_str_t *out);
static ngx_flag_t ngx_http_dav_lock_uri_is_descendant(const ngx_str_t *child,
    const ngx_str_t *parent);
static ngx_uint_t ngx_http_dav_lock_prune_expired(void);
static ngx_int_t ngx_http_dav_lock_prune_and_sync(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_lock_extract_token_from_if(ngx_http_request_t *r,
    ngx_str_t *token);
static ngx_int_t ngx_http_dav_lock_extract_lock_token_header(ngx_http_request_t *r,
    ngx_str_t *token);
static ngx_int_t ngx_http_dav_lock_find_covering(const ngx_str_t *uri,
    ngx_int_t *idx);
static ngx_int_t ngx_http_dav_lock_find_exact(const ngx_str_t *uri,
    const ngx_str_t *token, ngx_int_t *idx);
static ngx_int_t ngx_http_dav_lock_enforce_write(ngx_http_request_t *r,
    const ngx_str_t *uri);
static ngx_int_t ngx_http_dav_lock_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static char *ngx_http_dav_lock_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_dav_lock_store_load(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_lock_store_save(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_lock_remove_prefix(ngx_http_request_t *r,
    const ngx_str_t *uri);
static ngx_int_t ngx_http_dav_lock_move_prefix(ngx_http_request_t *r,
    ngx_pool_t *pool,
    const ngx_str_t *src_uri, const ngx_str_t *dst_uri);
static ngx_int_t ngx_http_dav_lock_build_discovery_xml(ngx_http_request_t *r,
    const ngx_str_t *uri, ngx_str_t *out, ngx_flag_t propname_only);
static ngx_int_t ngx_http_dav_lock_add_response_headers(ngx_http_request_t *r,
    const ngx_str_t *token);

#define NGX_DAV_PROPFIND_ALLPROP  0
#define NGX_DAV_PROPFIND_PROPNAME 1
#define NGX_DAV_PROPFIND_PROP     2
#define NGX_HTTP_DAV_ZERO_DEPTH 0
#define NGX_HTTP_DAV_INFINITY_DEPTH -1
#define NGX_HTTP_DAV_INVALID_DEPTH -2
#define NGX_DAV_PROPFIND_MAX_RECURSION 32
#define NGX_DAV_PROPFIND_MAX_RESPONSES 4096

#define NGX_DAV_METHOD_PUT       0x001
#define NGX_DAV_METHOD_DELETE    0x002
#define NGX_DAV_METHOD_MKCOL     0x004
#define NGX_DAV_METHOD_COPY      0x008
#define NGX_DAV_METHOD_MOVE      0x010
#define NGX_DAV_METHOD_PROPFIND  0x020
#define NGX_DAV_METHOD_PROPPATCH 0x040
#define NGX_DAV_METHOD_OPTIONS   0x080
#define NGX_DAV_METHOD_LOCK      0x100
#define NGX_DAV_METHOD_UNLOCK    0x200

#define NGX_DAV_PROP_DISPLAYNAME      0x01
#define NGX_DAV_PROP_RESOURCETYPE     0x02
#define NGX_DAV_PROP_GETCONTENTLENGTH 0x04
#define NGX_DAV_PROP_GETLASTMODIFIED  0x08
#define NGX_DAV_PROP_GETETAG          0x10
#define NGX_DAV_PROP_CREATIONDATE     0x20
#define NGX_DAV_PROP_GETCONTENTTYPE   0x40
#define NGX_DAV_PROP_LOCKDISCOVERY    0x80
#define NGX_DAV_PROP_SUPPORTEDLOCK    0x100
#define NGX_DAV_PROP_ALL_KNOWN (NGX_DAV_PROP_DISPLAYNAME | NGX_DAV_PROP_RESOURCETYPE \
    | NGX_DAV_PROP_GETCONTENTLENGTH | NGX_DAV_PROP_GETLASTMODIFIED \
    | NGX_DAV_PROP_GETETAG | NGX_DAV_PROP_CREATIONDATE \
    | NGX_DAV_PROP_GETCONTENTTYPE | NGX_DAV_PROP_LOCKDISCOVERY \
    | NGX_DAV_PROP_SUPPORTEDLOCK)

#define NGX_DAV_LOCK_DEFAULT_TIMEOUT 600

struct ngx_http_dav_lock_s {
    ngx_str_t   uri;
    ngx_str_t   token;
    ngx_str_t   owner;
    time_t      expires;
    ngx_flag_t  depth_infinity;
    ngx_flag_t  exclusive;
};

struct ngx_http_dav_lock_shctx_s {
    size_t      blob_len;
    size_t      blob_cap;
    size_t      blob_off;
    ngx_uint_t  default_timeout;
};

struct ngx_http_dav_lock_zone_ctx_s {
    ngx_slab_pool_t          *shpool;
    ngx_http_dav_lock_shctx_t *sh;
    size_t                    size;
    ngx_uint_t                timeout;
};

static ngx_array_t *ngx_http_dav_locks;

#define NGX_DAV_PROPFIND_UNKNOWN_MAX 32
#define NGX_DAV_PROPPATCH_PROPS_MAX 64
#define NGX_DAV_PROPPATCH_OP_SET    1
#define NGX_DAV_PROPPATCH_OP_REMOVE 2

struct ngx_http_dav_propfind_req_s {
    ngx_uint_t mode;
    ngx_uint_t props_mask;
    ngx_uint_t unknown_n;
    ngx_str_t  unknown[NGX_DAV_PROPFIND_UNKNOWN_MAX];
    ngx_str_t  unknown_xml[NGX_DAV_PROPFIND_UNKNOWN_MAX];
};

struct ngx_http_dav_proppatch_req_s {
    ngx_uint_t props_n;
    ngx_str_t  props[NGX_DAV_PROPPATCH_PROPS_MAX];
    ngx_str_t  prop_xml[NGX_DAV_PROPPATCH_PROPS_MAX];
    u_char     ops[NGX_DAV_PROPPATCH_PROPS_MAX];
};

struct ngx_http_dav_loc_conf_s {
        ngx_flag_t    create_full_path;
        ngx_uint_t    min_delete_depth;
    ngx_uint_t    methods_mask;
    ngx_uint_t    access_file_mode;
    ngx_uint_t    access_dir_mode;
    ngx_uint_t    lock_max_entries;
    ngx_uint_t    lock_timeout_min;
    ngx_uint_t    lock_timeout_max;
    ngx_uint_t    lock_zone_timeout;
    ngx_shm_zone_t *lock_zone;
};

typedef struct {
    ngx_flag_t   done;
    ngx_int_t    status;
    ngx_flag_t   propfind_body_attempted;
    ngx_flag_t   proppatch_body_attempted;
    ngx_flag_t   lock_body_attempted;
} ngx_http_dav_ctx_t;

static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_conf_bitmask_t ngx_http_dav_methods_mask[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), NGX_DAV_METHOD_PUT | NGX_DAV_METHOD_DELETE
        | NGX_DAV_METHOD_MKCOL | NGX_DAV_METHOD_COPY | NGX_DAV_METHOD_MOVE
        | NGX_DAV_METHOD_PROPFIND | NGX_DAV_METHOD_PROPPATCH
        | NGX_DAV_METHOD_OPTIONS | NGX_DAV_METHOD_LOCK | NGX_DAV_METHOD_UNLOCK },
    { ngx_string("put"), NGX_DAV_METHOD_PUT },
    { ngx_string("delete"), NGX_DAV_METHOD_DELETE },
    { ngx_string("mkcol"), NGX_DAV_METHOD_MKCOL },
    { ngx_string("copy"), NGX_DAV_METHOD_COPY },
    { ngx_string("move"), NGX_DAV_METHOD_MOVE },
    { ngx_string("propfind"), NGX_DAV_METHOD_PROPFIND },
    { ngx_string("proppatch"), NGX_DAV_METHOD_PROPPATCH },
    { ngx_string("options"), NGX_DAV_METHOD_OPTIONS },
    { ngx_string("lock"), NGX_DAV_METHOD_LOCK },
    { ngx_string("unlock"), NGX_DAV_METHOD_UNLOCK },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_dav_commands[] = {
        { ngx_string("dav_create_full_path"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
            ngx_conf_set_flag_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, create_full_path),
            NULL },

        { ngx_string("dav_methods"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
            ngx_conf_set_bitmask_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, methods_mask),
            &ngx_http_dav_methods_mask },

        { ngx_string("dav_access"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
            ngx_conf_set_access_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, access_file_mode),
            NULL },

        { ngx_string("dav_delete_depth"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_num_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, min_delete_depth),
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

        { ngx_string("dav_lock_max_entries"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_num_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, lock_max_entries),
            NULL },

        { ngx_string("dav_lock_timeout_min"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_num_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, lock_timeout_min),
            NULL },

        { ngx_string("dav_lock_timeout_max"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_num_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_dav_loc_conf_t, lock_timeout_max),
            NULL },

        { ngx_string("dav_lock_zone"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
            ngx_http_dav_lock_zone,
            NGX_HTTP_LOC_CONF_OFFSET,
            0,
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

    static ngx_int_t ngx_http_dav_delete_tree_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
    static ngx_int_t ngx_http_dav_delete_tree_pre(ngx_tree_ctx_t *ctx, ngx_str_t *path);
    static ngx_int_t ngx_http_dav_delete_tree_post(ngx_tree_ctx_t *ctx, ngx_str_t *path);

static ngx_table_elt_t *
ngx_http_dav_find_header(ngx_http_request_t *r, const char *name, size_t len)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h = part->elts;
    ngx_uint_t i = 0;

    for ( ;; ) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == len
            && ngx_strncasecmp(h[i].key.data, (u_char *) name, len) == 0)
        {
            return &h[i];
        }

        i++;
    }

    return NULL;
}

static ngx_int_t
ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt)
{
    ngx_table_elt_t *h;

    h = ngx_http_dav_find_header(r, "Depth", sizeof("Depth") - 1);
    if (h == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (over->value.data[0] == 'T' || over->value.data[0] == 't') {
        *overwrite = 1;
        return NGX_OK;
    }

    if (over->value.data[0] == 'F' || over->value.data[0] == 'f') {
        *overwrite = 0;
        return NGX_OK;
    }

    return NGX_HTTP_BAD_REQUEST;
}

static ngx_int_t
ngx_http_dav_parse_destination(ngx_http_request_t *r, ngx_str_t *duri)
{
    ngx_table_elt_t *dest;
    u_char *p, *last, *scheme;
    ngx_str_t args = ngx_null_string;
    ngx_uint_t flags = NGX_HTTP_LOG_UNSAFE;

    dest = ngx_http_dav_find_header(r, "Destination", sizeof("Destination") - 1);
    if (dest == NULL || dest->value.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    p = dest->value.data;
    last = p + dest->value.len;

    scheme = (u_char *) ngx_strnstr(p, "://", dest->value.len);
    if (scheme) {
        p = ngx_strlchr(scheme + 3, last, '/');
        if (p == NULL) {
            return NGX_HTTP_BAD_REQUEST;
        }

    } else if (dest->value.len >= 2 && p[0] == '/' && p[1] == '/') {
        p = ngx_strlchr(p + 2, last, '/');
        if (p == NULL) {
            return NGX_HTTP_BAD_REQUEST;
        }

    } else if (dest->value.len >= 1 && p[0] == '/') {
        /* already an absolute path */

    } else {
        p = ngx_strlchr(p, last, '/');
        if (p == NULL) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    duri->data = p;
    duri->len = last - p;

    if (ngx_http_parse_unsafe_uri(r, duri, &args, &flags) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_map_destination_path(ngx_http_request_t *r, ngx_str_t *duri,
    ngx_str_t *path)
{
    size_t root_len;
    u_char *last;
    size_t dlen;
    u_char *stable;
    ngx_str_t old_uri;

    old_uri = r->uri;
    r->uri = *duri;
    last = ngx_http_map_uri_to_path(r, path, &root_len, 0);
    r->uri = old_uri;

    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dlen = ngx_strlen(path->data);
    while (dlen > 1 && path->data[dlen - 1] == '/') {
        dlen--;
    }
    stable = ngx_pnalloc(r->pool, dlen + 1);
    if (stable == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(stable, path->data, dlen);
    stable[dlen] = '\0';
    path->data = stable;
    path->len = dlen;

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_prepare_destination_parent(ngx_http_request_t *r, ngx_str_t *path,
    ngx_http_dav_loc_conf_t *dlcf)
{
    u_char *p, *end;

    if (path->len == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    end = path->data + path->len;
    while (end > path->data + 1 && *(end - 1) == '/') {
        end--;
    }

    if (end <= path->data) {
        return NGX_HTTP_FORBIDDEN;
    }

    p = end - 1;
    while (p > path->data && *p != '/') {
        p--;
    }

    if (p <= path->data) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (dlcf->create_full_path) {
        u_char saved = *p;
        *p = '\0';
        if (ngx_create_full_path(path->data, dlcf->access_dir_mode)
            == NGX_FILE_ERROR)
        {
            *p = saved;
            if (ngx_errno == EACCES || ngx_errno == EPERM) {
                return NGX_HTTP_FORBIDDEN;
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        *p = saved;

    } else {
        char parent[PATH_MAX];
        size_t plen = (size_t) (p - path->data);
        ngx_file_info_t psb;

        if (plen >= sizeof(parent)) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memcpy(parent, path->data, plen);
        parent[plen] = '\0';

        if (ngx_file_info(parent, &psb) == NGX_FILE_ERROR) {
            if (ngx_errno == ENOENT) {
                return NGX_HTTP_CONFLICT;
            }
            if (ngx_errno == EACCES || ngx_errno == EPERM) {
                return NGX_HTTP_FORBIDDEN;
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (!S_ISDIR(psb.st_mode)) {
            return NGX_HTTP_CONFLICT;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_prepare_source_path(ngx_http_request_t *r, ngx_str_t *path,
    ngx_file_info_t *st, ngx_flag_t log_symlink_refusal)
{
    size_t root_len;
    u_char *last;
    size_t slen;
    u_char *stable;
    ngx_file_info_t sb;

    last = ngx_http_map_uri_to_path(r, path, &root_len, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    slen = ngx_strlen(path->data);
    stable = ngx_pnalloc(r->pool, slen + 1);
    if (stable == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(stable, path->data, slen);
    stable[slen] = '\0';
    path->data = stable;
    path->len = slen;

    if (lstat((char *) path->data, &sb) == -1) {
        if (ngx_errno == ENOENT) {
            return NGX_HTTP_NOT_FOUND;
        }
        if (ngx_errno == EACCES || ngx_errno == EPERM) {
            return NGX_HTTP_FORBIDDEN;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISLNK(sb.st_mode)) {
        if (log_symlink_refusal) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "dav: refusing to operate on symlink src='%V'", path);
        }
        return NGX_HTTP_FORBIDDEN;
    }

    if (st != NULL) {
        *st = sb;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_remove_tree(ngx_http_request_t *r, const char *path)
{
    ngx_tree_ctx_t  tree;
    ngx_str_t       p;

    p.data = (u_char *) path;
    p.len = ngx_strlen(path);

    tree.init_handler = NULL;
    tree.file_handler = ngx_http_dav_delete_tree_file;
    tree.pre_tree_handler = ngx_http_dav_delete_tree_pre;
    tree.post_tree_handler = ngx_http_dav_delete_tree_post;
    tree.spec_handler = ngx_http_dav_delete_tree_file;
    tree.data = NULL;
    tree.alloc = 0;
    tree.log = r->connection->log;

    if (ngx_walk_tree(&tree, &p) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_delete_dir(path) == NGX_FILE_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_tree_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_tree_pre(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    (void) ctx;
    (void) path;
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_delete_tree_post(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    if (ngx_delete_dir(path->data) == NGX_FILE_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_str_t
ngx_http_dav_xml_escape(ngx_pool_t *pool, const u_char *src, size_t len)
{
    ngx_str_t out;
    out.data = NULL;
    out.len = 0;

    size_t i, extra = 0;
    for (i = 0; i < len; i++) {
        switch (src[i]) {
            case '&': extra += sizeof("amp;") - 1; break;
            case '<': extra += sizeof("lt;") - 1; break;
            case '>': extra += sizeof("gt;") - 1; break;
            case '"': extra += sizeof("quot;") - 1; break;
            case '\'': extra += sizeof("apos;") - 1; break;
            default: break;
        }
    }

    out.data = ngx_pnalloc(pool, len + extra + 1);
    if (out.data == NULL) {
        return out;
    }

    u_char *p = out.data;
    for (i = 0; i < len; i++) {
        switch (src[i]) {
            case '&':
                p = ngx_cpymem(p, "&amp;", sizeof("&amp;") - 1);
                break;
            case '<':
                p = ngx_cpymem(p, "&lt;", sizeof("&lt;") - 1);
                break;
            case '>':
                p = ngx_cpymem(p, "&gt;", sizeof("&gt;") - 1);
                break;
            case '"':
                p = ngx_cpymem(p, "&quot;", sizeof("&quot;") - 1);
                break;
            case '\'':
                p = ngx_cpymem(p, "&apos;", sizeof("&apos;") - 1);
                break;
            default:
                *p++ = src[i];
                break;
        }
    }

    *p = '\0';
    out.len = p - out.data;
    return out;
}

static ngx_int_t
ngx_http_dav_chain_append(ngx_http_request_t *r, ngx_chain_t ***ll,
    off_t *total, const u_char *data, size_t len)
{
    if (len == 0) {
        return NGX_OK;
    }

    u_char *p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, data, len);

    ngx_buf_t *b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = p;
    b->last = p + len;
    b->start = p;
    b->end = p + len;
    b->memory = 1;

    ngx_chain_t *cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    **ll = cl;
    *ll = &cl->next;
    *total += (off_t) len;

    return NGX_OK;
}

static ngx_flag_t
ngx_http_dav_tag_name_char(u_char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '_' || c == '-'
        || c == ':' || c == '.')
    {
        return 1;
    }

    return 0;
}

static ngx_flag_t
ngx_http_dav_lname_eq(const u_char *name, size_t len, const char *lit)
{
    size_t i;
    size_t llen = ngx_strlen(lit);

    if (len != llen) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        u_char a = name[i];
        u_char b = (u_char) lit[i];

        if (a >= 'A' && a <= 'Z') {
            a = (u_char) (a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (u_char) (b - 'A' + 'a');
        }

        if (a != b) {
            return 0;
        }
    }

    return 1;
}

static ngx_flag_t
ngx_http_dav_is_live_prop(const ngx_str_t *name)
{
    if (ngx_http_dav_lname_eq(name->data, name->len, "displayname")
        || ngx_http_dav_lname_eq(name->data, name->len, "resourcetype")
        || ngx_http_dav_lname_eq(name->data, name->len, "getcontentlength")
        || ngx_http_dav_lname_eq(name->data, name->len, "getlastmodified")
        || ngx_http_dav_lname_eq(name->data, name->len, "getetag")
        || ngx_http_dav_lname_eq(name->data, name->len, "creationdate")
        || ngx_http_dav_lname_eq(name->data, name->len, "getcontenttype")
        || ngx_http_dav_lname_eq(name->data, name->len, "lockdiscovery")
        || ngx_http_dav_lname_eq(name->data, name->len, "supportedlock"))
    {
        return 1;
    }

    return 0;
}

static ngx_flag_t
ngx_http_dav_str_ieq(const ngx_str_t *a, const ngx_str_t *b)
{
    size_t i;

    if (a->len != b->len) {
        return 0;
    }

    for (i = 0; i < a->len; i++) {
        u_char ca = a->data[i];
        u_char cb = b->data[i];

        if (ca >= 'A' && ca <= 'Z') {
            ca = (u_char) (ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (u_char) (cb - 'A' + 'a');
        }

        if (ca != cb) {
            return 0;
        }
    }

    return 1;
}

static ngx_int_t
ngx_http_dav_lock_normalize_uri(ngx_pool_t *pool, const ngx_str_t *in,
    ngx_str_t *out)
{
    size_t   len;
    u_char  *p;

    if (in == NULL || in->data == NULL || in->len == 0) {
        return NGX_ERROR;
    }

    len = in->len;
    while (len > 1 && in->data[len - 1] == '/') {
        len--;
    }

    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, in->data, len);
    out->data = p;
    out->len = len;

    return NGX_OK;
}

static ngx_flag_t
ngx_http_dav_lock_uri_is_descendant(const ngx_str_t *child,
    const ngx_str_t *parent)
{
    if (parent->len == 1 && parent->data[0] == '/') {
        return 1;
    }

    if (child->len < parent->len) {
        return 0;
    }

    if (ngx_strncmp(child->data, parent->data, parent->len) != 0) {
        return 0;
    }

    if (child->len == parent->len) {
        return 1;
    }

    return child->data[parent->len] == '/';
}

static ngx_uint_t
ngx_http_dav_lock_prune_expired(void)
{
    ngx_uint_t         i, n;
    ngx_http_dav_lock_t *locks;
    time_t              now;
    ngx_uint_t          removed = 0;

    if (ngx_http_dav_locks == NULL || ngx_http_dav_locks->nelts == 0) {
        return 0;
    }

    now = ngx_time();
    locks = ngx_http_dav_locks->elts;
    n = ngx_http_dav_locks->nelts;

    for (i = 0; i < n; ) {
        if (locks[i].expires >= now) {
            i++;
            continue;
        }

        if (i + 1 < n) {
            ngx_memmove(&locks[i], &locks[i + 1], (n - i - 1) * sizeof(ngx_http_dav_lock_t));
        }
        n--;
        removed++;
        ngx_http_dav_locks->nelts = n;
    }

    return removed;
}

static ngx_int_t
ngx_http_dav_lock_prune_and_sync(ngx_http_request_t *r)
{
    if (ngx_http_dav_lock_prune_expired() == 0) {
        return NGX_OK;
    }

    return ngx_http_dav_lock_store_save(r);
}

static ngx_int_t
ngx_http_dav_lock_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_dav_lock_zone_ctx_t *octx = data;
    ngx_http_dav_lock_zone_ctx_t *ctx = shm_zone->data;
    ngx_slab_pool_t              *shpool;
    ngx_http_dav_lock_shctx_t    *sh;
    u_char                       *blob;
    size_t                        cap;

    if (octx) {
        ctx->shpool = octx->shpool;
        ctx->sh = octx->sh;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shpool->data) {
        ctx->shpool = shpool;
        ctx->sh = shpool->data;
        return NGX_OK;
    }

    ctx->shpool = shpool;

    ngx_shmtx_lock(&shpool->mutex);

    sh = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_dav_lock_shctx_t));
    if (sh == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    cap = shm_zone->shm.size / 2;
    if (cap < 4096) {
        cap = 4096;
    }

    blob = ngx_slab_alloc_locked(shpool, cap);
    if (blob == NULL) {
        ngx_slab_free_locked(shpool, sh);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    sh->blob_len = 0;
    sh->blob_cap = cap;
    sh->blob_off = (size_t) (blob - (u_char *) shpool);
    sh->default_timeout = ctx->timeout;

    shpool->data = sh;
    ctx->sh = sh;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

static char *
ngx_http_dav_lock_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dav_loc_conf_t      *dlcf = conf;
    ngx_str_t                    *value;
    ngx_shm_zone_t               *shm_zone;
    ngx_http_dav_lock_zone_ctx_t *ctx;
    size_t                        size = 5 * 1024 * 1024;
    ngx_uint_t                    timeout = 60 * 60;

    if (dlcf->lock_zone != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts >= 3) {
        ngx_str_t *s = &value[2];
        ngx_int_t n;

        if (s->len == 0) {
            return NGX_CONF_ERROR;
        }

        if (s->data[s->len - 1] == 'm' || s->data[s->len - 1] == 'M') {
            n = ngx_atoi(s->data, s->len - 1);
        } else {
            n = ngx_atoi(s->data, s->len);
        }

        if (n == NGX_ERROR || n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dav_lock_zone size \"%V\"", s);
            return NGX_CONF_ERROR;
        }

        size = (size_t) n * 1024 * 1024;
    }

    if (cf->args->nelts >= 4) {
        ngx_str_t *t = &value[3];
        ngx_int_t n;
        ngx_uint_t mult = 1;

        if (t->len == 0) {
            return NGX_CONF_ERROR;
        }

        if (t->data[t->len - 1] == 's' || t->data[t->len - 1] == 'S') {
            mult = 1;
            n = ngx_atoi(t->data, t->len - 1);
        } else if (t->data[t->len - 1] == 'm' || t->data[t->len - 1] == 'M') {
            mult = 60;
            n = ngx_atoi(t->data, t->len - 1);
        } else if (t->data[t->len - 1] == 'h' || t->data[t->len - 1] == 'H') {
            mult = 3600;
            n = ngx_atoi(t->data, t->len - 1);
        } else {
            n = ngx_atoi(t->data, t->len);
        }

        if (n == NGX_ERROR || n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dav_lock_zone timeout \"%V\"", t);
            return NGX_CONF_ERROR;
        }

        timeout = (ngx_uint_t) n * mult;
    }

    shm_zone = ngx_shared_memory_add(cf, &value[1], size, &ngx_http_dav_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data == NULL) {
        ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_lock_zone_ctx_t));
        if (ctx == NULL) {
            return NGX_CONF_ERROR;
        }

        ctx->size = size;
        ctx->timeout = timeout;
        shm_zone->init = ngx_http_dav_lock_init_zone;
        shm_zone->data = ctx;
    }

    dlcf->lock_zone = shm_zone;
    dlcf->lock_zone_timeout = timeout;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dav_lock_store_load(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t *dlcf;
    ngx_array_t             *lock_array;
    u_char                  *file_buf, *file_last, *line, *line_end;
    ngx_http_dav_lock_zone_ctx_t *zctx;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

    lock_array = ngx_array_create(r->pool, 16, sizeof(ngx_http_dav_lock_t));
    if (lock_array == NULL) {
        return NGX_ERROR;
    }

    ngx_http_dav_locks = lock_array;

    if (dlcf->lock_zone != NULL && dlcf->lock_zone->data != NULL) {
        size_t blob_len;
        u_char *blob;

        zctx = dlcf->lock_zone->data;
        if (zctx->shpool == NULL || zctx->sh == NULL) {
            return NGX_ERROR;
        }

        ngx_shmtx_lock(&zctx->shpool->mutex);
        blob_len = zctx->sh->blob_len;
        blob = (u_char *) zctx->shpool + zctx->sh->blob_off;

        if (blob_len == 0) {
            ngx_shmtx_unlock(&zctx->shpool->mutex);
            return NGX_OK;
        }

        file_buf = ngx_pnalloc(r->pool, blob_len + 1);
        if (file_buf == NULL) {
            ngx_shmtx_unlock(&zctx->shpool->mutex);
            return NGX_ERROR;
        }

        ngx_memcpy(file_buf, blob, blob_len);
        file_buf[blob_len] = '\0';
        file_last = file_buf + blob_len;
        ngx_shmtx_unlock(&zctx->shpool->mutex);
    } else {
        return NGX_OK;
    }

    line = file_buf;
    while (line < file_last) {
        ngx_http_dav_lock_t *lock_entry;
        u_char              *field_token, *field_expires, *field_depth;
        u_char              *field_scope, *field_owner;
        ngx_int_t            is_exclusive, is_infinite_depth, expires;

        line_end = ngx_strlchr(line, file_last, '\n');
        if (line_end == NULL) {
            line_end = file_last;
        }

        if (line_end == line) {
            line = (line_end < file_last) ? (line_end + 1) : file_last;
            continue;
        }

        *line_end = '\0';
        field_token = (u_char *) ngx_strlchr(line, line_end, '\t');
        if (field_token == NULL) { goto next_line; }
        *field_token++ = '\0';

        field_expires = (u_char *) ngx_strlchr(field_token, line_end, '\t');
        if (field_expires == NULL) { goto next_line; }
        *field_expires++ = '\0';

        field_depth = (u_char *) ngx_strlchr(field_expires, line_end, '\t');
        if (field_depth == NULL) { goto next_line; }
        *field_depth++ = '\0';

        field_scope = (u_char *) ngx_strlchr(field_depth, line_end, '\t');
        if (field_scope == NULL) { goto next_line; }
        *field_scope++ = '\0';

        field_owner = (u_char *) ngx_strlchr(field_scope, line_end, '\t');
        if (field_owner == NULL) { goto next_line; }
        *field_owner++ = '\0';

        expires = ngx_atoi(field_expires, ngx_strlen(field_expires));
        is_infinite_depth = ngx_atoi(field_depth, ngx_strlen(field_depth));
        is_exclusive = ngx_atoi(field_scope, ngx_strlen(field_scope));

        if (expires == NGX_ERROR || is_infinite_depth == NGX_ERROR
            || is_exclusive == NGX_ERROR)
        {
            goto next_line;
        }

        lock_entry = ngx_array_push(lock_array);
        if (lock_entry == NULL) {
            return NGX_ERROR;
        }

        lock_entry->uri.len = ngx_strlen(line);
        lock_entry->uri.data = ngx_pnalloc(r->pool, lock_entry->uri.len);
        if (lock_entry->uri.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(lock_entry->uri.data, line, lock_entry->uri.len);

        lock_entry->token.len = ngx_strlen(field_token);
        lock_entry->token.data = ngx_pnalloc(r->pool, lock_entry->token.len);
        if (lock_entry->token.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(lock_entry->token.data, field_token, lock_entry->token.len);

        lock_entry->expires = (time_t) expires;
        lock_entry->depth_infinity = (is_infinite_depth == 1) ? 1 : 0;
        lock_entry->exclusive = (is_exclusive == 1) ? 1 : 0;

        if (field_owner[0] == '-' && field_owner[1] == '\0') {
            lock_entry->owner.data = NULL;
            lock_entry->owner.len = 0;
        } else {
            lock_entry->owner.len = ngx_strlen(field_owner);
            lock_entry->owner.data = ngx_pnalloc(r->pool, lock_entry->owner.len);
            if (lock_entry->owner.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(lock_entry->owner.data, field_owner, lock_entry->owner.len);
        }

next_line:
        line = (line_end < file_last) ? (line_end + 1) : file_last;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_lock_store_save(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t *dlcf;
    ngx_http_dav_lock_t     *locks;
    ngx_uint_t               i;
    ngx_http_dav_lock_zone_ctx_t *zctx;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

    if (dlcf->lock_zone == NULL || dlcf->lock_zone->data == NULL) {
        return NGX_OK;
    }
    zctx = dlcf->lock_zone->data;
    if (zctx->shpool == NULL || zctx->sh == NULL) {
        return NGX_ERROR;
    }

    {
        size_t cap = 128;
        size_t need = 0;
        u_char *buf, *q;

        if (ngx_http_dav_locks != NULL && ngx_http_dav_locks->nelts != 0) {
            locks = ngx_http_dav_locks->elts;
            for (i = 0; i < ngx_http_dav_locks->nelts; i++) {
                need += locks[i].uri.len + locks[i].token.len + locks[i].owner.len + 64;
            }
            if (need > cap) {
                cap = need;
            }
        }

        buf = ngx_pnalloc(r->pool, cap + 1);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        q = buf;
        if (ngx_http_dav_locks != NULL && ngx_http_dav_locks->nelts != 0) {
            locks = ngx_http_dav_locks->elts;
            for (i = 0; i < ngx_http_dav_locks->nelts; i++) {
                q = ngx_cpymem(q, locks[i].uri.data, locks[i].uri.len);
                *q++ = '\t';
                q = ngx_cpymem(q, locks[i].token.data, locks[i].token.len);
                *q++ = '\t';
                q = ngx_snprintf(q, cap - (q - buf), "%T\t%ud\t%ud\t",
                                 locks[i].expires,
                                 (ngx_uint_t) locks[i].depth_infinity,
                                 (ngx_uint_t) locks[i].exclusive);
                if (locks[i].owner.len == 0 || locks[i].owner.data == NULL) {
                    *q++ = '-';
                } else {
                    q = ngx_cpymem(q, locks[i].owner.data, locks[i].owner.len);
                }
                *q++ = '\n';
            }
        }

        ngx_shmtx_lock(&zctx->shpool->mutex);
        if ((size_t) (q - buf) > zctx->sh->blob_cap) {
            ngx_shmtx_unlock(&zctx->shpool->mutex);
            return NGX_ERROR;
        }
        ngx_memcpy((u_char *) zctx->shpool + zctx->sh->blob_off, buf,
                   (size_t) (q - buf));
        zctx->sh->blob_len = (size_t) (q - buf);
        ngx_shmtx_unlock(&zctx->shpool->mutex);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_lock_extract_token_range(const u_char *data, size_t len,
    ngx_str_t *token)
{
    const u_char  *p, *last, *s, *e;
    static const char *prefix = "opaquelocktoken:";
    size_t         plen;

    plen = sizeof("opaquelocktoken:") - 1;
    p = data;
    last = data + len;

    while (p < last) {
        s = (const u_char *) ngx_strnstr((u_char *) p, (char *) prefix,
                         (size_t) (last - p));
        if (s == NULL) {
            break;
        }

        e = s + plen;
        while (e < last && *e != '>' && *e != ')' && *e != ' ' && *e != '\t') {
            e++;
        }

        if (e > s + plen) {
            token->data = (u_char *) s;
            token->len = (size_t) (e - s);
            return NGX_OK;
        }

        p = s + plen;
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_dav_lock_extract_token_from_if(ngx_http_request_t *r, ngx_str_t *token)
{
    ngx_table_elt_t *h;

    token->data = NULL;
    token->len = 0;

    h = ngx_http_dav_find_header(r, "If", sizeof("If") - 1);
    if (h == NULL || h->value.len == 0) {
        return NGX_DECLINED;
    }

    return ngx_http_dav_lock_extract_token_range(h->value.data, h->value.len, token);
}

static ngx_int_t
ngx_http_dav_lock_extract_lock_token_header(ngx_http_request_t *r, ngx_str_t *token)
{
    ngx_table_elt_t *h;

    token->data = NULL;
    token->len = 0;

    h = ngx_http_dav_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
    if (h == NULL || h->value.len == 0) {
        return NGX_DECLINED;
    }

    return ngx_http_dav_lock_extract_token_range(h->value.data, h->value.len, token);
}

static ngx_int_t
ngx_http_dav_lock_find_covering(const ngx_str_t *uri, ngx_int_t *idx)
{
    ngx_uint_t          i;
    ngx_http_dav_lock_t *locks;

    *idx = -1;

    if (ngx_http_dav_locks == NULL || ngx_http_dav_locks->nelts == 0) {
        return NGX_DECLINED;
    }

    locks = ngx_http_dav_locks->elts;
    for (i = 0; i < ngx_http_dav_locks->nelts; i++) {
        if (locks[i].uri.len == uri->len
            && ngx_strncmp(locks[i].uri.data, uri->data, uri->len) == 0)
        {
            *idx = (ngx_int_t) i;
            return NGX_OK;
        }

        if (locks[i].depth_infinity
            && ngx_http_dav_lock_uri_is_descendant(uri, &locks[i].uri))
        {
            *idx = (ngx_int_t) i;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_dav_lock_find_exact(const ngx_str_t *uri, const ngx_str_t *token,
    ngx_int_t *idx)
{
    ngx_uint_t          i;
    ngx_http_dav_lock_t *locks;

    *idx = -1;

    if (ngx_http_dav_locks == NULL || ngx_http_dav_locks->nelts == 0) {
        return NGX_DECLINED;
    }

    locks = ngx_http_dav_locks->elts;

    for (i = 0; i < ngx_http_dav_locks->nelts; i++) {
        if (locks[i].uri.len != uri->len
            || ngx_strncmp(locks[i].uri.data, uri->data, uri->len) != 0)
        {
            continue;
        }

        if (token != NULL
            && (locks[i].token.len != token->len
                || ngx_strncmp(locks[i].token.data, token->data, token->len) != 0))
        {
            continue;
        }

        *idx = (ngx_int_t) i;
        return NGX_OK;
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_dav_lock_enforce_write(ngx_http_request_t *r, const ngx_str_t *uri)
{
    ngx_uint_t           i;
    ngx_table_elt_t     *ifh;
    ngx_http_dav_lock_t *locks;
    ngx_uint_t           covering = 0;
    ngx_uint_t           lists = 0;
    ngx_flag_t           saw_etag_condition = 0;
    ngx_file_info_t      sb;
    ngx_str_t            path;
    size_t               root_len;
    u_char              *last;
    u_char               etagbuf[64];
    ngx_str_t            etag;

    if (ngx_http_dav_lock_store_load(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_dav_lock_prune_and_sync(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ifh = ngx_http_dav_find_header(r, "If", sizeof("If") - 1);

    etag.data = NULL;
    etag.len = 0;

    last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
    if (last != NULL && lstat((char *) path.data, &sb) != -1) {
        int n = snprintf((char *) etagbuf, sizeof(etagbuf), "\"%lx-%lx\"",
                         (unsigned long) sb.st_mtime,
                         (unsigned long) sb.st_size);
        if (n > 0 && (size_t) n < sizeof(etagbuf)) {
            etag.len = (size_t) n;
            etag.data = etagbuf;
        }
    }

    if (ngx_http_dav_locks == NULL || ngx_http_dav_locks->nelts == 0) {
        if (ifh && ifh->value.len) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        return NGX_OK;
    }

    locks = ngx_http_dav_locks->elts;

    for (i = 0; i < ngx_http_dav_locks->nelts; i++) {
        if ((locks[i].uri.len == uri->len
             && ngx_strncmp(locks[i].uri.data, uri->data, uri->len) == 0)
            || (locks[i].depth_infinity
                && ngx_http_dav_lock_uri_is_descendant(uri, &locks[i].uri)))
        {
            covering = 1;
        }
    }

    if (ifh && ifh->value.len) {
        u_char *p = ifh->value.data;
        u_char *end = ifh->value.data + ifh->value.len;
        ngx_flag_t all_lists_true = 1;

        if (ngx_strlchr(ifh->value.data,
                        ifh->value.data + ifh->value.len,
                        '[') != NULL)
        {
            saw_etag_condition = 1;
        }

        while (p < end) {
            u_char *ls, *le;
            ngx_flag_t list_true = 1;

            while (p < end && *p != '(') {
                p++;
            }
            if (p >= end) {
                break;
            }

            ls = ++p;
            while (p < end && *p != ')') {
                p++;
            }
            if (p >= end) {
                return NGX_HTTP_PRECONDITION_FAILED;
            }
            le = p++;
            lists++;

            while (ls < le) {
                ngx_flag_t negate = 0;
                ngx_flag_t cond = 0;

                while (ls < le && (*ls == ' ' || *ls == '\t')) {
                    ls++;
                }
                if (ls >= le) {
                    break;
                }

                if ((size_t) (le - ls) >= 3
                    && ngx_strncasecmp(ls, (u_char *) "Not", 3) == 0
                    && ((size_t) (le - ls) == 3 || ls[3] == ' ' || ls[3] == '\t'))
                {
                    negate = 1;
                    ls += 3;
                    while (ls < le && (*ls == ' ' || *ls == '\t')) {
                        ls++;
                    }
                }

                if (ls >= le) {
                    list_true = 0;
                    break;
                }

                if (*ls == '<') {
                    u_char *ts = ++ls;
                    u_char *te;
                    ngx_uint_t j;

                    while (ls < le && *ls != '>') {
                        ls++;
                    }
                    if (ls >= le) {
                        list_true = 0;
                        break;
                    }
                    te = ls++;

                    if ((size_t) (te - ts) == sizeof("DAV:no-lock") - 1
                        && ngx_strncasecmp(ts, (u_char *) "DAV:no-lock",
                                           sizeof("DAV:no-lock") - 1) == 0)
                    {
                        cond = 0;
                    } else {
                        for (j = 0; j < ngx_http_dav_locks->nelts; j++) {
                            if ((locks[j].uri.len == uri->len
                                 && ngx_strncmp(locks[j].uri.data, uri->data, uri->len) == 0)
                                || (locks[j].depth_infinity
                                    && ngx_http_dav_lock_uri_is_descendant(uri, &locks[j].uri)))
                            {
                                if ((size_t) (te - ts) == locks[j].token.len
                                    && ngx_strncmp(ts, locks[j].token.data,
                                                   locks[j].token.len) == 0)
                                {
                                    cond = 1;
                                    break;
                                }
                            }
                        }
                    }

                } else if (*ls == '[') {
                    u_char *es = ++ls;
                    u_char *ee;

                    while (ls < le && *ls != ']') {
                        ls++;
                    }
                    if (ls >= le) {
                        list_true = 0;
                        break;
                    }
                    ee = ls++;

                    if (etag.data != NULL
                        && (size_t) (ee - es) == etag.len
                        && ngx_strncmp(es, etag.data, etag.len) == 0)
                    {
                        cond = 1;
                    } else {
                        cond = 0;
                    }

                } else {
                    list_true = 0;
                    break;
                }

                if (negate) {
                    cond = !cond;
                }

                if (!cond) {
                    list_true = 0;
                    break;
                }
            }

            if (!list_true) {
                all_lists_true = 0;
                break;
            }
        }

        if (lists == 0 || !all_lists_true) {
            return (covering && !saw_etag_condition)
                   ? 423
                   : NGX_HTTP_PRECONDITION_FAILED;
        }

        return NGX_OK;
    }

    if (covering) {
        return 423;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_lock_remove_prefix(ngx_http_request_t *r, const ngx_str_t *uri)
{
    ngx_uint_t          i, n;
    ngx_http_dav_lock_t *locks;

    if (ngx_http_dav_lock_store_load(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_dav_locks == NULL || ngx_http_dav_locks->nelts == 0) {
        return NGX_OK;
    }

    locks = ngx_http_dav_locks->elts;
    n = ngx_http_dav_locks->nelts;

    for (i = 0; i < n; ) {
        if (!(locks[i].uri.len == uri->len
              && ngx_strncmp(locks[i].uri.data, uri->data, uri->len) == 0)
            && !ngx_http_dav_lock_uri_is_descendant(&locks[i].uri, uri))
        {
            i++;
            continue;
        }

        if (i + 1 < n) {
            ngx_memmove(&locks[i], &locks[i + 1], (n - i - 1) * sizeof(ngx_http_dav_lock_t));
        }
        n--;
        ngx_http_dav_locks->nelts = n;
    }

    return ngx_http_dav_lock_store_save(r);
}

static ngx_int_t
ngx_http_dav_lock_move_prefix(ngx_http_request_t *r, ngx_pool_t *pool,
    const ngx_str_t *src_uri,
    const ngx_str_t *dst_uri)
{
    ngx_uint_t          i;
    ngx_http_dav_lock_t *locks;

    if (ngx_http_dav_lock_store_load(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_dav_locks == NULL || ngx_http_dav_locks->nelts == 0) {
        return NGX_OK;
    }

    locks = ngx_http_dav_locks->elts;

    for (i = 0; i < ngx_http_dav_locks->nelts; i++) {
        size_t   suffix_len, new_len;
        u_char  *p;

        if (!(locks[i].uri.len == src_uri->len
              && ngx_strncmp(locks[i].uri.data, src_uri->data, src_uri->len) == 0)
            && !ngx_http_dav_lock_uri_is_descendant(&locks[i].uri, src_uri))
        {
            continue;
        }

        suffix_len = locks[i].uri.len - src_uri->len;
        new_len = dst_uri->len + suffix_len;
        p = ngx_pnalloc(pool, new_len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, dst_uri->data, dst_uri->len);
        if (suffix_len) {
            ngx_memcpy(p + dst_uri->len, locks[i].uri.data + src_uri->len, suffix_len);
        }

        locks[i].uri.data = p;
        locks[i].uri.len = new_len;
    }

    return ngx_http_dav_lock_store_save(r);
}

static ngx_int_t
ngx_http_dav_lock_build_discovery_xml(ngx_http_request_t *r, const ngx_str_t *uri,
    ngx_str_t *out, ngx_flag_t propname_only)
{
    ngx_int_t            idx;
    ngx_http_dav_lock_t *locks;
    u_char              *buf, *p;
    size_t               cap;
    time_t               ttl;

    if (propname_only) {
        ngx_str_set(out, "<D:lockdiscovery/>");
        return NGX_OK;
    }

    if (ngx_http_dav_lock_store_load(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_dav_lock_prune_and_sync(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_dav_lock_find_covering(uri, &idx) != NGX_OK) {
        ngx_str_set(out, "<D:lockdiscovery/>");
        return NGX_OK;
    }

    locks = ngx_http_dav_locks->elts;
    cap = sizeof("<D:lockdiscovery><D:activelock>"
                 "<D:locktype><D:write/></D:locktype>"
                 "<D:lockscope><D:exclusive/></D:lockscope>"
                 "<D:depth>infinity</D:depth>"
                 "<D:timeout>Second-999999</D:timeout>"
                 "<D:locktoken><D:href></D:href></D:locktoken>"
                 "</D:activelock></D:lockdiscovery>") - 1
            + locks[idx].token.len + locks[idx].owner.len + 96;

    buf = ngx_pnalloc(r->pool, cap);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ttl = locks[idx].expires - ngx_time();
    if (ttl < 0) {
        ttl = 0;
    }

    p = ngx_snprintf(buf, cap,
                     "<D:lockdiscovery><D:activelock>"
                     "<D:locktype><D:write/></D:locktype>"
                     "<D:lockscope><D:%s/></D:lockscope>"
                     "<D:depth>%s</D:depth>"
                     "<D:timeout>Second-%T</D:timeout>"
                     "%s"
                     "<D:locktoken><D:href>%V</D:href></D:locktoken>"
                     "</D:activelock></D:lockdiscovery>",
                     locks[idx].exclusive ? "exclusive" : "shared",
                     locks[idx].depth_infinity ? "infinity" : "0",
                     ttl,
                     locks[idx].owner.len ? "<D:owner>litmus test suite</D:owner>" : "",
                     &locks[idx].token);

    out->data = buf;
    out->len = (size_t) (p - buf);
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_lock_add_response_headers(ngx_http_request_t *r, const ngx_str_t *token)
{
    ngx_table_elt_t *h;

    if (token != NULL && token->data != NULL && token->len != 0) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        ngx_str_set(&h->key, "Lock-Token");
        h->hash = 1;

        h->value.len = token->len + 2;
        h->value.data = ngx_pnalloc(r->pool, h->value.len);
        if (h->value.data == NULL) {
            return NGX_ERROR;
        }

        h->value.data[0] = '<';
        ngx_memcpy(h->value.data + 1, token->data, token->len);
        h->value.data[h->value.len - 1] = '>';
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_props_path(ngx_http_request_t *r, ngx_str_t *path, ngx_str_t *ppath)
{
    (void) r;
    (void) path;
    if (ppath) {
        ppath->data = NULL;
        ppath->len = 0;
    }
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_dav_read_props_blob(ngx_http_request_t *r, ngx_str_t *ppath, ngx_str_t *out)
{
    (void) r;
    (void) ppath;
    out->len = 0;
    out->data = NULL;
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_props_path_fs(ngx_pool_t *pool, const ngx_str_t *path, ngx_str_t *ppath)
{
    (void) pool;
    (void) path;
    if (ppath) {
        ppath->data = NULL;
        ppath->len = 0;
    }
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_dav_write_props_blob(ngx_http_request_t *r, ngx_str_t *ppath, ngx_str_t *data)
{
    (void) r;
    (void) ppath;
    (void) data;
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_dav_propfind_parse_body(const u_char *data, size_t len,
    ngx_http_dav_propfind_req_t *preq)
{
    size_t i = 0;
    ngx_flag_t seen_propfind = 0;
    ngx_flag_t seen_allprop = 0;
    ngx_flag_t seen_propname = 0;
    ngx_flag_t seen_prop = 0;
    ngx_uint_t props_mask = 0;
    ngx_uint_t propfind_depth = 0;
    ngx_uint_t prop_depth = 0;

    while (i < len) {
        size_t tag_start = i;

        if (data[i] != '<') {
            i++;
            continue;
        }

        i++;
        if (i >= len) {
            break;
        }

        if (data[i] == '?') {
            i++;
            while (i + 1 < len) {
                if (data[i] == '?' && data[i + 1] == '>') {
                    i += 2;
                    break;
                }
                i++;
            }
            continue;
        }

        if (data[i] == '!') {
            if (i + 2 < len && data[i + 1] == '-' && data[i + 2] == '-') {
                i += 3;
                while (i + 2 < len) {
                    if (data[i] == '-' && data[i + 1] == '-' && data[i + 2] == '>') {
                        i += 3;
                        break;
                    }
                    i++;
                }
            } else {
                while (i < len && data[i] != '>') {
                    i++;
                }
                if (i < len) {
                    i++;
                }
            }
            continue;
        }

        ngx_flag_t closing = 0;
        if (data[i] == '/') {
            closing = 1;
            i++;
        }

        while (i < len && (data[i] == ' ' || data[i] == '\t'
               || data[i] == '\r' || data[i] == '\n'))
        {
            i++;
        }

        size_t name_start = i;
        while (i < len && ngx_http_dav_tag_name_char(data[i])) {
            i++;
        }

        if (i == name_start) {
            while (i < len && data[i] != '>') {
                i++;
            }
            if (i < len) {
                i++;
            }
            continue;
        }

        size_t lname_start = name_start;
        size_t j;
        for (j = name_start; j < i; j++) {
            if (data[j] == ':') {
                lname_start = j + 1;
            }
        }

        size_t lname_len = i - lname_start;

        ngx_flag_t self_closing = 0;
        size_t k = i;
        ngx_flag_t in_quote = 0;
        u_char quote = 0;

        while (k < len && data[k] != '>') {
            if (!in_quote && (data[k] == '"' || data[k] == '\'')) {
                in_quote = 1;
                quote = data[k];
                k++;
                continue;
            }

            if (in_quote && data[k] == quote) {
                in_quote = 0;
                k++;
                continue;
            }

            if (!in_quote && data[k] == '/') {
                size_t t = k + 1;
                while (t < len && (data[t] == ' ' || data[t] == '\t'
                       || data[t] == '\r' || data[t] == '\n'))
                {
                    t++;
                }
                if (t < len && data[t] == '>') {
                    self_closing = 1;
                }
            }

            if (!in_quote
                && k + 7 < len
                && data[k] == 'x' && data[k + 1] == 'm'
                && data[k + 2] == 'l' && data[k + 3] == 'n'
                && data[k + 4] == 's' && data[k + 5] == ':')
            {
                size_t p = k + 6;

                while (p < len && ngx_http_dav_tag_name_char(data[p])) {
                    p++;
                }

                while (p < len && (data[p] == ' ' || data[p] == '\t'
                       || data[p] == '\r' || data[p] == '\n'))
                {
                    p++;
                }

                if (p < len && data[p] == '=') {
                    p++;
                    while (p < len && (data[p] == ' ' || data[p] == '\t'
                           || data[p] == '\r' || data[p] == '\n'))
                    {
                        p++;
                    }

                    if (p + 1 < len
                        && ((data[p] == '"' && data[p + 1] == '"')
                            || (data[p] == '\'' && data[p + 1] == '\'')))
                    {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                }
            }

            k++;
        }

        if (k < len) {
            i = k + 1;
        } else {
            i = len;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "propfind")) {
            if (closing) {
                if (propfind_depth == 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }

                propfind_depth--;

                if (prop_depth > 0 && propfind_depth == 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }

            } else {
                seen_propfind = 1;
                propfind_depth++;

                if (self_closing && propfind_depth > 0) {
                    propfind_depth--;
                }
            }

            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "allprop")) {
            if (!closing && propfind_depth > 0) {
                seen_allprop = 1;
            }
            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "propname")) {
            if (!closing && propfind_depth > 0) {
                seen_propname = 1;
            }
            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "prop")) {
            if (propfind_depth == 0) {
                continue;
            }

            if (closing) {
                if (prop_depth > 0) {
                    prop_depth--;
                } else {
                    return NGX_HTTP_BAD_REQUEST;
                }
            } else {
                prop_depth++;
                seen_prop = 1;
                if (self_closing && prop_depth > 0) {
                    prop_depth--;
                }
            }
            continue;
        }

        if (!closing && propfind_depth > 0 && prop_depth > 0) {
            if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "displayname")) {
                props_mask |= NGX_DAV_PROP_DISPLAYNAME;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "resourcetype")) {
                props_mask |= NGX_DAV_PROP_RESOURCETYPE;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "getcontentlength")) {
                props_mask |= NGX_DAV_PROP_GETCONTENTLENGTH;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "getlastmodified")) {
                props_mask |= NGX_DAV_PROP_GETLASTMODIFIED;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "getetag")) {
                props_mask |= NGX_DAV_PROP_GETETAG;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "creationdate")) {
                props_mask |= NGX_DAV_PROP_CREATIONDATE;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "getcontenttype")) {
                props_mask |= NGX_DAV_PROP_GETCONTENTTYPE;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "lockdiscovery")) {
                props_mask |= NGX_DAV_PROP_LOCKDISCOVERY;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "supportedlock")) {
                props_mask |= NGX_DAV_PROP_SUPPORTEDLOCK;
            } else if (preq->unknown_n < NGX_DAV_PROPFIND_UNKNOWN_MAX) {
                ngx_uint_t n;
                ngx_flag_t dup = 0;

                for (n = 0; n < preq->unknown_n; n++) {
                    if (preq->unknown[n].len == lname_len) {
                        size_t m;
                        dup = 1;

                        for (m = 0; m < lname_len; m++) {
                            u_char a = preq->unknown[n].data[m];
                            u_char b = data[lname_start + m];

                            if (a >= 'A' && a <= 'Z') {
                                a = (u_char) (a - 'A' + 'a');
                            }
                            if (b >= 'A' && b <= 'Z') {
                                b = (u_char) (b - 'A' + 'a');
                            }

                            if (a != b) {
                                dup = 0;
                                break;
                            }
                        }

                        if (dup) {
                            break;
                        }
                    }
                }

                if (!dup) {
                    preq->unknown[preq->unknown_n].data = (u_char *) (data + lname_start);
                    preq->unknown[preq->unknown_n].len = lname_len;
                    preq->unknown_xml[preq->unknown_n].data = (u_char *) (data + tag_start);
                    preq->unknown_xml[preq->unknown_n].len = i - tag_start;
                    preq->unknown_n++;
                }
            }
        }
    }

    if (!seen_propfind) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (propfind_depth != 0 || prop_depth != 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (seen_propname) {
        preq->mode = NGX_DAV_PROPFIND_PROPNAME;
        preq->props_mask = NGX_DAV_PROP_ALL_KNOWN;
        return NGX_OK;
    }

    if (seen_prop) {
        preq->mode = NGX_DAV_PROPFIND_PROP;
        preq->props_mask = props_mask;
        return (props_mask != 0 || preq->unknown_n != 0) ? NGX_OK : NGX_HTTP_BAD_REQUEST;
    }

    if (seen_allprop || seen_propfind) {
        preq->mode = NGX_DAV_PROPFIND_ALLPROP;
        preq->props_mask = NGX_DAV_PROP_ALL_KNOWN;
        return NGX_OK;
    }

    return NGX_HTTP_BAD_REQUEST;
}

static ngx_int_t
ngx_http_dav_propfind_append_unknown_propstat(ngx_http_request_t *r,
    ngx_chain_t ***ll, off_t *total, ngx_http_dav_propfind_req_t *preq)
{
    ngx_uint_t i;

    if (preq->mode != NGX_DAV_PROPFIND_PROP || preq->unknown_n == 0) {
        return NGX_OK;
    }

    if (ngx_http_dav_chain_append(r, ll, total,
            (const u_char *) "<D:propstat>\n<D:prop>\n",
            sizeof("<D:propstat>\n<D:prop>\n") - 1) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < preq->unknown_n; i++) {

        if (preq->unknown_xml[i].data != NULL && preq->unknown_xml[i].len != 0) {
            if (ngx_http_dav_chain_append(r, ll, total,
                    preq->unknown_xml[i].data, preq->unknown_xml[i].len) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_http_dav_chain_append(r, ll, total,
                    (const u_char *) "\n", sizeof("\n") - 1) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else {
            if (ngx_http_dav_chain_append(r, ll, total,
                    (const u_char *) "<D:", sizeof("<D:") - 1) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_http_dav_chain_append(r, ll, total,
                    preq->unknown[i].data, preq->unknown[i].len) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_http_dav_chain_append(r, ll, total,
                    (const u_char *) "/>\n", sizeof("/>\n") - 1) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (ngx_http_dav_chain_append(r, ll, total,
            (const u_char *) "</D:prop>\n<D:status>HTTP/1.1 404 Not Found</D:status>\n</D:propstat>\n",
            sizeof("</D:prop>\n<D:status>HTTP/1.1 404 Not Found</D:status>\n</D:propstat>\n") - 1) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_proppatch_parse_body(const u_char *data, size_t len,
    ngx_http_dav_proppatch_req_t *preq)
{
    size_t i = 0;
    ngx_flag_t seen_propertyupdate = 0;
    ngx_uint_t propertyupdate_depth = 0;
    ngx_uint_t set_depth = 0;
    ngx_uint_t remove_depth = 0;
    ngx_uint_t prop_depth = 0;
    ngx_uint_t prop_member_depth = 0;
    ngx_int_t active_prop_idx = -1;
    size_t active_prop_start = 0;

    preq->props_n = 0;

    while (i < len) {
        size_t tag_start;

        if (data[i] != '<') {
            i++;
            continue;
        }

        tag_start = i;
        i++;
        if (i >= len) {
            return NGX_HTTP_BAD_REQUEST;
        }

        if (data[i] == '?') {
            while (i + 1 < len && !(data[i] == '?' && data[i + 1] == '>')) {
                i++;
            }
            if (i + 1 >= len) {
                return NGX_HTTP_BAD_REQUEST;
            }
            i += 2;
            continue;
        }

        if (data[i] == '!') {
            if (i + 2 < len && data[i + 1] == '-' && data[i + 2] == '-') {
                i += 3;
                while (i + 2 < len && !(data[i] == '-' && data[i + 1] == '-' && data[i + 2] == '>')) {
                    i++;
                }
                if (i + 2 >= len) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                i += 3;
                continue;
            }

            while (i < len && data[i] != '>') {
                i++;
            }
            if (i >= len) {
                return NGX_HTTP_BAD_REQUEST;
            }
            i++;
            continue;
        }

        ngx_flag_t closing = 0;
        if (data[i] == '/') {
            closing = 1;
            i++;
            if (i >= len) {
                return NGX_HTTP_BAD_REQUEST;
            }
        }

        if (!ngx_http_dav_tag_name_char(data[i])) {
            return NGX_HTTP_BAD_REQUEST;
        }

        size_t name_start = i;
        while (i < len && ngx_http_dav_tag_name_char(data[i])) {
            i++;
        }
        size_t name_end = i;

        size_t lname_start = name_start;
        size_t k;
        for (k = name_start; k < name_end; k++) {
            if (data[k] == ':') {
                lname_start = k + 1;
            }
        }
        size_t lname_len = name_end - lname_start;

        ngx_flag_t in_quote = 0;
        u_char quote = 0;
        ngx_flag_t self_closing = 0;

        while (i < len) {
            u_char c = data[i];

            if (!in_quote && c == '>') {
                break;
            }

            if (!in_quote && (c == '"' || c == '\'')) {
                in_quote = 1;
                quote = c;
                i++;
                continue;
            }

            if (in_quote && c == quote) {
                in_quote = 0;
                i++;
                continue;
            }

            if (!in_quote && c == '/' && i + 1 < len && data[i + 1] == '>') {
                self_closing = 1;
                i += 2;
                break;
            }

            i++;
        }

        if (!self_closing) {
            if (i >= len || data[i] != '>') {
                return NGX_HTTP_BAD_REQUEST;
            }
            i++;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "propertyupdate")) {
            if (closing) {
                if (propertyupdate_depth == 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                propertyupdate_depth--;
                if ((prop_depth > 0 || prop_member_depth > 0)
                    && propertyupdate_depth == 0)
                {
                    return NGX_HTTP_BAD_REQUEST;
                }
            } else {
                seen_propertyupdate = 1;
                propertyupdate_depth++;
                if (self_closing && propertyupdate_depth > 0) {
                    propertyupdate_depth--;
                }
            }

            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "prop")) {
            if (!closing && propertyupdate_depth > 0) {
                if (set_depth == 0 && remove_depth == 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }

                if (prop_member_depth > 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                prop_depth++;
                if (self_closing && prop_depth > 0) {
                    prop_depth--;
                }
            } else if (closing) {
                if (prop_depth == 0 || prop_member_depth > 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                prop_depth--;
            }

            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "set")) {
            if (propertyupdate_depth == 0) {
                continue;
            }

            if (closing) {
                if (set_depth == 0 || prop_depth > 0 || prop_member_depth > 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                set_depth--;

            } else {
                if (prop_depth > 0 || prop_member_depth > 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                set_depth++;
                if (self_closing && set_depth > 0) {
                    set_depth--;
                }
            }

            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "remove")) {
            if (propertyupdate_depth == 0) {
                continue;
            }

            if (closing) {
                if (remove_depth == 0 || prop_depth > 0 || prop_member_depth > 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                remove_depth--;

            } else {
                if (prop_depth > 0 || prop_member_depth > 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                remove_depth++;
                if (self_closing && remove_depth > 0) {
                    remove_depth--;
                }
            }

            continue;
        }

        if (propertyupdate_depth > 0 && prop_depth > 0) {
            if (closing) {
                if (prop_member_depth == 0) {
                    return NGX_HTTP_BAD_REQUEST;
                }

                if (prop_member_depth == 1 && active_prop_idx >= 0) {
                    preq->prop_xml[active_prop_idx].data = (u_char *) (data + active_prop_start);
                    preq->prop_xml[active_prop_idx].len = i - active_prop_start;
                    active_prop_idx = -1;
                }

                prop_member_depth--;

            } else {
                /* only direct children of <prop> are properties */
                if (prop_member_depth == 0) {
                    u_char op;

                    if (set_depth > 0 && remove_depth == 0) {
                        op = NGX_DAV_PROPPATCH_OP_SET;
                    } else if (remove_depth > 0 && set_depth == 0) {
                        op = NGX_DAV_PROPPATCH_OP_REMOVE;
                    } else {
                        return NGX_HTTP_BAD_REQUEST;
                    }

                    if (preq->props_n < NGX_DAV_PROPPATCH_PROPS_MAX) {
                        preq->props[preq->props_n].data = (u_char *) (data + lname_start);
                        preq->props[preq->props_n].len = lname_len;
                        preq->ops[preq->props_n] = op;

                        if (self_closing) {
                            preq->prop_xml[preq->props_n].data = (u_char *) (data + tag_start);
                            preq->prop_xml[preq->props_n].len = i - tag_start;
                        } else {
                            active_prop_idx = (ngx_int_t) preq->props_n;
                            active_prop_start = tag_start;
                            preq->prop_xml[preq->props_n].data = NULL;
                            preq->prop_xml[preq->props_n].len = 0;
                        }

                        preq->props_n++;
                    }
                }

                prop_member_depth++;
                if (self_closing && prop_member_depth > 0) {
                    prop_member_depth--;
                }
            }
        }
    }

    if (!seen_propertyupdate) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (propertyupdate_depth != 0 || set_depth != 0 || remove_depth != 0
        || prop_depth != 0 || prop_member_depth != 0 || active_prop_idx >= 0)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (preq->props_n == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_propfind_emit_children(ngx_http_request_t *r,
    ngx_chain_t ***ll, off_t *content_length, ngx_http_dav_propfind_req_t *preq,
    const char *dir_path, const ngx_str_t *parent_uri,
    ngx_uint_t current_depth, ngx_uint_t max_depth,
    ngx_uint_t *responses_emitted, ngx_uint_t max_responses)
{
#define NGX_DAV_XML_APPEND_LIT2(_s)                                              \
    if (ngx_http_dav_chain_append(r, ll, content_length,                         \
            (const u_char *) (_s), sizeof(_s) - 1) != NGX_OK)                    \
    {                                                                             \
        return NGX_HTTP_INTERNAL_SERVER_ERROR;                                    \
    }

#define NGX_DAV_XML_APPEND_BUF2(_p, _n)                                          \
    if (ngx_http_dav_chain_append(r, ll, content_length,                         \
            (const u_char *) (_p), (_n)) != NGX_OK)                              \
    {                                                                             \
        return NGX_HTTP_INTERNAL_SERVER_ERROR;                                    \
    }

    DIR *d = opendir(dir_path);
    if (d == NULL) {
        if (errno == EACCES || errno == EPERM) {
            if (current_depth > 1) {
                return NGX_OK;
            }
            return NGX_HTTP_FORBIDDEN;
        }
        if (errno == ENOENT || errno == ENOTDIR) {
            return NGX_OK;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ngx_strcmp(ent->d_name, ".") == 0 || ngx_strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        char namebuf[NAME_MAX + 1];
        size_t nlen = strnlen(ent->d_name, NAME_MAX + 1);
        if (nlen == 0 || nlen > NAME_MAX) {
            continue;
        }
        ngx_memcpy(namebuf, ent->d_name, nlen);
        namebuf[nlen] = '\0';

        ngx_file_info_t csb;
        if (fstatat(dirfd(d), namebuf, &csb, AT_SYMLINK_NOFOLLOW) == -1) {
            continue;
        }
        if (S_ISLNK(csb.st_mode)) {
            continue;
        }

        char ctimebuf[64];
        size_t ctime_len = 0;
        u_char cetagbuf[64];
        size_t cetag_len = 0;
        u_char ccdatebuf[64];
        size_t ccdate_len = 0;
        u_char *cctype = (u_char *) "application/octet-stream";
        size_t cctype_len = sizeof("application/octet-stream") - 1;

        {
            u_char *ctlast = ngx_http_time((u_char *) ctimebuf, csb.st_mtime);
            ctime_len = (size_t) (ctlast - (u_char *) ctimebuf);

            u_char *celast = ngx_sprintf(cetagbuf, "\"%T-%O\"",
                                         (time_t) csb.st_mtime,
                                         (off_t) csb.st_size);
            cetag_len = (size_t) (celast - cetagbuf);

            struct tm t;
            time_t tt = (time_t) csb.st_ctime;
            if (gmtime_r(&tt, &t) == NULL) {
                closedir(d);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            u_char *ccdlast = ngx_snprintf(ccdatebuf, sizeof(ccdatebuf),
                                           "%4d-%02d-%02dT%02d:%02d:%02dZ",
                                           t.tm_year + 1900,
                                           t.tm_mon + 1,
                                           t.tm_mday,
                                           t.tm_hour,
                                           t.tm_min,
                                           t.tm_sec);
            ccdate_len = (size_t) (ccdlast - ccdatebuf);

            if (S_ISDIR(csb.st_mode)) {
                cctype = (u_char *) "httpd/unix-directory";
                cctype_len = sizeof("httpd/unix-directory") - 1;
            }
        }

        u_char *child_rtype = (u_char *) "";
        u_char *child_clen = (u_char *) "0";
        size_t child_clen_len = 1;
        if (S_ISDIR(csb.st_mode)) {
            child_rtype = (u_char *) "<D:collection/>";
        } else {
            child_clen = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + 1);
            if (child_clen == NULL) {
                closedir(d);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            u_char *cclast = ngx_sprintf(child_clen, "%O", (off_t) csb.st_size);
            child_clen_len = (size_t) (cclast - child_clen);
        }

        size_t urilen = parent_uri->len;
        ngx_flag_t has_trailing = (urilen > 0 && parent_uri->data[urilen - 1] == '/');
        size_t href_extra = (has_trailing ? 0 : 1) + nlen + (S_ISDIR(csb.st_mode) ? 1 : 0);
        if (urilen > (size_t) -1 - href_extra) {
            closedir(d);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        size_t href_len = urilen + href_extra;
        u_char *href_raw = ngx_pnalloc(r->pool, href_len + 1);
        if (href_raw == NULL) {
            closedir(d);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (has_trailing) {
            (void) ngx_snprintf(href_raw, href_len + 1, "%V%s%s", parent_uri,
                                namebuf, S_ISDIR(csb.st_mode) ? "/" : "");
        } else {
            (void) ngx_snprintf(href_raw, href_len + 1, "%V/%s%s", parent_uri,
                                namebuf, S_ISDIR(csb.st_mode) ? "/" : "");
        }

        ngx_str_t child_href_esc = ngx_http_dav_xml_escape(r->pool, href_raw, href_len);
        if (child_href_esc.data == NULL) {
            closedir(d);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_t child_disp_esc = ngx_http_dav_xml_escape(r->pool,
            (u_char *) namebuf, nlen);
        if (child_disp_esc.data == NULL) {
            closedir(d);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_t child_uri;
        child_uri.data = href_raw;
        child_uri.len = href_len;

        if (*responses_emitted >= max_responses) {
            closedir(d);
            return NGX_HTTP_INSUFFICIENT_STORAGE;
        }
        (*responses_emitted)++;

        NGX_DAV_XML_APPEND_LIT2("<D:response>\n");
        NGX_DAV_XML_APPEND_LIT2("<D:href>");
        NGX_DAV_XML_APPEND_BUF2(child_href_esc.data, child_href_esc.len);
        NGX_DAV_XML_APPEND_LIT2("</D:href>\n");

        if (preq->mode != NGX_DAV_PROPFIND_PROP || preq->props_mask != 0) {
            NGX_DAV_XML_APPEND_LIT2("<D:propstat>\n");
            NGX_DAV_XML_APPEND_LIT2("<D:prop>\n");
            if (preq->props_mask & NGX_DAV_PROP_DISPLAYNAME) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:displayname/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2("<D:displayname>");
                    NGX_DAV_XML_APPEND_BUF2(child_disp_esc.data, child_disp_esc.len);
                    NGX_DAV_XML_APPEND_LIT2("</D:displayname>\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_RESOURCETYPE) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:resourcetype/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2("<D:resourcetype>");
                    NGX_DAV_XML_APPEND_BUF2(child_rtype, ngx_strlen(child_rtype));
                    NGX_DAV_XML_APPEND_LIT2("</D:resourcetype>\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_GETCONTENTLENGTH) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:getcontentlength/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2("<D:getcontentlength>");
                    NGX_DAV_XML_APPEND_BUF2(child_clen, child_clen_len);
                    NGX_DAV_XML_APPEND_LIT2("</D:getcontentlength>\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_GETLASTMODIFIED) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:getlastmodified/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2("<D:getlastmodified>");
                    NGX_DAV_XML_APPEND_BUF2((u_char *) ctimebuf, ctime_len);
                    NGX_DAV_XML_APPEND_LIT2("</D:getlastmodified>\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_GETETAG) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:getetag/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2("<D:getetag>");
                    NGX_DAV_XML_APPEND_BUF2(cetagbuf, cetag_len);
                    NGX_DAV_XML_APPEND_LIT2("</D:getetag>\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_CREATIONDATE) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:creationdate/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2("<D:creationdate>");
                    NGX_DAV_XML_APPEND_BUF2(ccdatebuf, ccdate_len);
                    NGX_DAV_XML_APPEND_LIT2("</D:creationdate>\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_GETCONTENTTYPE) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:getcontenttype/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2("<D:getcontenttype>");
                    NGX_DAV_XML_APPEND_BUF2(cctype, cctype_len);
                    NGX_DAV_XML_APPEND_LIT2("</D:getcontenttype>\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_LOCKDISCOVERY) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:lockdiscovery/>\n");
                } else {
                    ngx_str_t lock_xml;
                    if (ngx_http_dav_lock_build_discovery_xml(r, &child_uri,
                                                              &lock_xml, 0)
                        != NGX_OK)
                    {
                        closedir(d);
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }
                    NGX_DAV_XML_APPEND_BUF2(lock_xml.data, lock_xml.len);
                    NGX_DAV_XML_APPEND_LIT2("\n");
                }
            }

            if (preq->props_mask & NGX_DAV_PROP_SUPPORTEDLOCK) {
                if (preq->mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT2("<D:supportedlock/>\n");
                } else {
                    NGX_DAV_XML_APPEND_LIT2(
                        "<D:supportedlock><D:lockentry>"
                        "<D:lockscope><D:exclusive/></D:lockscope>"
                        "<D:locktype><D:write/></D:locktype>"
                        "</D:lockentry></D:supportedlock>\n");
                }
            }

            NGX_DAV_XML_APPEND_LIT2("</D:prop>\n");
            NGX_DAV_XML_APPEND_LIT2("<D:status>HTTP/1.1 200 OK</D:status>\n");
            NGX_DAV_XML_APPEND_LIT2("</D:propstat>\n");
        }

        {
            ngx_int_t urc = ngx_http_dav_propfind_append_unknown_propstat(r, ll,
                                                                           content_length,
                                                                           preq,
                                                                           NULL);
            if (urc != NGX_OK) {
                closedir(d);
                return urc;
            }
        }

        NGX_DAV_XML_APPEND_LIT2("</D:response>\n");

        if (S_ISDIR(csb.st_mode) && current_depth < max_depth) {
            size_t dplen = ngx_strlen(dir_path);
            if (dplen > (size_t) -1 - 1 - nlen) {
                closedir(d);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            size_t child_path_len = dplen + 1 + nlen;
            u_char *child_path = ngx_pnalloc(r->pool, child_path_len + 1);
            if (child_path == NULL) {
                closedir(d);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            u_char *cplast = ngx_snprintf(child_path, child_path_len + 1,
                                          "%s/%s", dir_path, namebuf);
            if (cplast >= child_path + child_path_len + 1) {
                closedir(d);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            *cplast = '\0';

            ngx_int_t rc = ngx_http_dav_propfind_emit_children(r, ll, content_length,
                                                               preq, (char *) child_path,
                                                               &child_uri,
                                                               current_depth + 1,
                                                               max_depth,
                                                               responses_emitted,
                                                               max_responses);
            if (rc != NGX_OK) {
                closedir(d);
                return rc;
            }
        }
    }

    closedir(d);

#undef NGX_DAV_XML_APPEND_LIT2
#undef NGX_DAV_XML_APPEND_BUF2

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_propfind_collect_body(ngx_http_request_t *r, ngx_str_t *body)
{
    body->data = NULL;
    body->len = 0;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        if (r->request_body == NULL || r->request_body->temp_file == NULL) {
            return NGX_OK;
        }
    }

    if (r->request_body->temp_file) {
        ngx_str_t *fname = &r->request_body->temp_file->file.name;
        if (fname->len == 0 || fname->data == NULL) {
            return NGX_HTTP_BAD_REQUEST;
        }

        int fd = open((char *) fname->data, O_RDONLY);
        if (fd == -1) {
            return NGX_HTTP_BAD_REQUEST;
        }

        struct stat st;
        if (fstat(fd, &st) == -1) {
            close(fd);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (st.st_size <= 0) {
            close(fd);
            return NGX_OK;
        }

        if (st.st_size > 128 * 1024) {
            close(fd);
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        size_t n = (size_t) st.st_size;
        u_char *p = ngx_pnalloc(r->pool, n + 1);
        if (p == NULL) {
            close(fd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        size_t got = 0;
        while (got < n) {
            ssize_t rd = read(fd, p + got, n - got);
            if (rd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return NGX_HTTP_BAD_REQUEST;
            }
            if (rd == 0) {
                break;
            }
            got += (size_t) rd;
        }

        close(fd);

        p[got] = '\0';
        body->data = p;
        body->len = got;
        return NGX_OK;
    }

    size_t total = 0;
    ngx_chain_t *cl;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        if (cl->buf == NULL) {
            continue;
        }

        if (cl->buf->in_file && cl->buf->file && cl->buf->file_last > cl->buf->file_pos) {
            total += (size_t) (cl->buf->file_last - cl->buf->file_pos);
            if (total > 128 * 1024) {
                return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
            continue;
        }

        if (cl->buf->last == NULL) {
            continue;
        }

        u_char *s = cl->buf->pos;
        u_char *e = cl->buf->last;

        if ((s == NULL || s == e) && cl->buf->start && e > cl->buf->start) {
            s = cl->buf->start;
        }

        if (s && e >= s) {
            total += (size_t) (e - s);
            if (total > 128 * 1024) {
                return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
        }
    }

    if (total == 0) {
        return NGX_OK;
    }

    u_char *p = ngx_pnalloc(r->pool, total + 1);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u_char *d = p;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        if (cl->buf == NULL) {
            continue;
        }

        if (cl->buf->in_file && cl->buf->file && cl->buf->file_last > cl->buf->file_pos) {
            off_t pos = cl->buf->file_pos;
            off_t end = cl->buf->file_last;
            int fd = cl->buf->file->fd;
            ngx_flag_t close_fd = 0;

            if (fd == NGX_INVALID_FILE) {
                fd = open((char *) cl->buf->file->name.data, O_RDONLY);
                if (fd == -1) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                close_fd = 1;
            }

            while (pos < end) {
                size_t want = (size_t) (end - pos);
                ssize_t rd = pread(fd, d, want, pos);
                if (rd < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    if (close_fd) {
                        close(fd);
                    }
                    return NGX_HTTP_BAD_REQUEST;
                }
                if (rd == 0) {
                    break;
                }
                d += rd;
                pos += rd;
            }

            if (close_fd) {
                close(fd);
            }
            continue;
        }

        if (cl->buf->last == NULL) {
            continue;
        }

        u_char *s = cl->buf->pos;
        u_char *e = cl->buf->last;

        if ((s == NULL || s == e) && cl->buf->start && e > cl->buf->start) {
            s = cl->buf->start;
        }

        if (s && e > s) {
            size_t n = (size_t) (e - s);
            d = ngx_cpymem(d, s, n);
        }
    }

    *d = '\0';
    body->data = p;
    body->len = total;
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_uint_t                bit;
    ngx_http_dav_ctx_t       *ctx;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx && ctx->done) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "dav: finishing request with status=%i", ctx->status);
        ngx_http_finalize_request(r, ctx->status);
        return NGX_DONE;
    }

    if (r->method == NGX_HTTP_PUT) {
        bit = NGX_DAV_METHOD_PUT;
    } else if (r->method == NGX_HTTP_DELETE) {
        bit = NGX_DAV_METHOD_DELETE;
    } else if (r->method == NGX_HTTP_OPTIONS) {
        bit = NGX_DAV_METHOD_OPTIONS;
    } else if (r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0) {
        bit = NGX_DAV_METHOD_MKCOL;
    } else if (r->method_name.len == 8 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPFIND", 8) == 0) {
        bit = NGX_DAV_METHOD_PROPFIND;
    } else if (r->method_name.len == 9 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPPATCH", 9) == 0) {
        bit = NGX_DAV_METHOD_PROPPATCH;
    } else if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"COPY", 4) == 0) {
        bit = NGX_DAV_METHOD_COPY;
    } else if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"MOVE", 4) == 0) {
        bit = NGX_DAV_METHOD_MOVE;
    } else if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"LOCK", 4) == 0) {
        bit = NGX_DAV_METHOD_LOCK;
    } else if (r->method_name.len == 6 && ngx_strncasecmp(r->method_name.data, (u_char *)"UNLOCK", 6) == 0) {
        bit = NGX_DAV_METHOD_UNLOCK;
    } else {
        return NGX_DECLINED;
    }

    if ((dlcf->methods_mask & bit) == 0) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->method == NGX_HTTP_PUT) {
        {
            ngx_str_t nuri;
            if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_int_t lrc = ngx_http_dav_lock_enforce_write(r, &nuri);
            if (lrc != NGX_OK) {
                return lrc;
            }
        }

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

    if (r->method == NGX_HTTP_OPTIONS) {
        return ngx_http_dav_options_handler(r);
    }

    if (r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0) {
        return ngx_http_dav_mkcol_handler(r);
    }
    if (r->method_name.len == 8 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPFIND", 8) == 0) {
        return ngx_http_dav_propfind_handler(r);
    }
    if (r->method_name.len == 9 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPPATCH", 9) == 0) {
        return ngx_http_dav_proppatch_handler(r);
    }
    if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"COPY", 4) == 0) {
        return ngx_http_dav_copy_handler(r);
    }
    if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"MOVE", 4) == 0) {
        return ngx_http_dav_move_handler(r);
    }
    if (r->method_name.len == 4 && ngx_strncasecmp(r->method_name.data, (u_char *)"LOCK", 4) == 0) {
        return ngx_http_dav_lock_handler(r);
    }
    if (r->method_name.len == 6 && ngx_strncasecmp(r->method_name.data, (u_char *)"UNLOCK", 6) == 0) {
        return ngx_http_dav_unlock_handler(r);
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

    {
        ngx_str_t nuri;
        if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        ngx_int_t lrc = ngx_http_dav_lock_enforce_write(r, &nuri);
        if (lrc != NGX_OK) {
            ngx_http_finalize_request(r, lrc);
            return;
        }
    }

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
            if (ngx_create_full_path(path.data, dlcf->access_dir_mode) == NGX_FILE_ERROR) {
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
    ext.path_access = dlcf->access_dir_mode;
    ext.time = -1;
    ext.create_path = dlcf->create_full_path;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (ngx_ext_rename_file(&r->request_body->temp_file->file.name, &path, &ext) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: rename failed for '%V'", &path);
        if (ngx_errno == ENOENT || ngx_errno == NGX_ENOPATH) {
            ngx_http_finalize_request(r, NGX_HTTP_CONFLICT);
        } else if (ngx_errno == EACCES || ngx_errno == EPERM) {
            ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        } else {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    tmpname = r->request_body->temp_file->file.name;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "dav: renamed '%V' -> '%V'", &tmpname, &path);

    if (chmod((char *) path.data, dlcf->access_file_mode) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "dav: chmod failed for '%V'", &path);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

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

static void
ngx_http_dav_propfind_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc = ngx_http_dav_propfind_handler(r);
    ngx_http_finalize_request(r, rc);
}

static void
ngx_http_dav_proppatch_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc = ngx_http_dav_proppatch_handler(r);
    ngx_http_finalize_request(r, rc);
}

static void
ngx_http_dav_lock_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc = ngx_http_dav_lock_handler(r);
    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_dav_proppatch_handler(ngx_http_request_t *r)
{
    ngx_str_t                 path;
    u_char                   *last;
    ngx_chain_t              *out = NULL;
    ngx_chain_t             **ll = &out;
    ngx_chain_t              *cl;
    ngx_file_info_t           sb;
    off_t                     content_length = 0;
    ngx_http_dav_proppatch_req_t preq;
    ngx_str_t                 req_body;
    ngx_http_dav_ctx_t       *ctx;
    ngx_str_t                 href_esc;
    ngx_uint_t                i;
    ngx_flag_t                has_set = 0;
    ngx_flag_t                has_remove = 0;
    ngx_flag_t                has_live_failure = 0;
    ngx_uint_t                first_live = 0;

#define NGX_DAV_XML_APPEND_LIT3(_s)                                              \
    if (ngx_http_dav_chain_append(r, &ll, &content_length,                       \
            (const u_char *) (_s), sizeof(_s) - 1) != NGX_OK)                    \
    {                                                                             \
        return NGX_HTTP_INTERNAL_SERVER_ERROR;                                    \
    }

#define NGX_DAV_XML_APPEND_BUF3(_p, _n)                                          \
    if (ngx_http_dav_chain_append(r, &ll, &content_length,                       \
            (const u_char *) (_p), (_n)) != NGX_OK)                              \
    {                                                                             \
        return NGX_HTTP_INTERNAL_SERVER_ERROR;                                    \
    }

    if (!(r->method_name.len == 9
          && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPPATCH", 9) == 0))
    {
        return NGX_DECLINED;
    }

    {
        ngx_str_t nuri;
        if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_int_t lrc = ngx_http_dav_lock_enforce_write(r, &nuri);
        if (lrc != NGX_OK) {
            return lrc;
        }
    }

    {
        ngx_int_t d = ngx_http_dav_depth(r, NGX_HTTP_DAV_ZERO_DEPTH);
        if (d == NGX_HTTP_DAV_INVALID_DEPTH || d != NGX_HTTP_DAV_ZERO_DEPTH) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
    }

    if ((r->request_body == NULL
         || (r->request_body->bufs == NULL && r->request_body->temp_file == NULL))
        && !ctx->proppatch_body_attempted)
    {
        ctx->proppatch_body_attempted = 1;

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        ngx_int_t rb = ngx_http_read_client_request_body(r,
                                                         ngx_http_dav_proppatch_body_handler);
        if (rb >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rb;
        }
        return NGX_DONE;
    }

    req_body.data = NULL;
    req_body.len = 0;

    {
        ngx_int_t body_rc = ngx_http_dav_propfind_collect_body(r, &req_body);
        if (body_rc != NGX_OK) {
            return body_rc;
        }
    }

    if (req_body.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    {
        ngx_int_t prc = ngx_http_dav_proppatch_parse_body(req_body.data, req_body.len, &preq);
        if (prc != NGX_OK) {
            return prc;
        }
    }

    {
        size_t root_len;
        last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
        if (last == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (lstat((char *) path.data, &sb) == -1) {
        if (ngx_errno == ENOENT || ngx_errno == ENOTDIR || ngx_errno == ENAMETOOLONG) {
            return NGX_HTTP_NOT_FOUND;
        }
        if (ngx_errno == EACCES || ngx_errno == EPERM) {
            return NGX_HTTP_FORBIDDEN;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISLNK(sb.st_mode)) {
        return NGX_HTTP_FORBIDDEN;
    }

    href_esc = ngx_http_dav_xml_escape(r->pool, r->uri.data, r->uri.len);
    if (href_esc.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    NGX_DAV_XML_APPEND_LIT3("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    NGX_DAV_XML_APPEND_LIT3("<D:multistatus xmlns:D=\"DAV:\">\n");
    NGX_DAV_XML_APPEND_LIT3("<D:response>\n");
    NGX_DAV_XML_APPEND_LIT3("<D:href>");
    NGX_DAV_XML_APPEND_BUF3(href_esc.data, href_esc.len);
    NGX_DAV_XML_APPEND_LIT3("</D:href>\n");

    for (i = 0; i < preq.props_n; i++) {
        if (!has_live_failure && ngx_http_dav_is_live_prop(&preq.props[i])) {
            has_live_failure = 1;
            first_live = i;
        }

        if (preq.ops[i] == NGX_DAV_PROPPATCH_OP_SET) {
            has_set = 1;
        } else if (preq.ops[i] == NGX_DAV_PROPPATCH_OP_REMOVE) {
            has_remove = 1;
        }
    }

    if (has_live_failure) {
        NGX_DAV_XML_APPEND_LIT3("<D:propstat>\n");
        NGX_DAV_XML_APPEND_LIT3("<D:prop>\n");
        NGX_DAV_XML_APPEND_LIT3("<D:");
        NGX_DAV_XML_APPEND_BUF3(preq.props[first_live].data,
                                preq.props[first_live].len);
        NGX_DAV_XML_APPEND_LIT3("/>\n");
        NGX_DAV_XML_APPEND_LIT3("</D:prop>\n");
        NGX_DAV_XML_APPEND_LIT3("<D:status>HTTP/1.1 403 Forbidden</D:status>\n");
        NGX_DAV_XML_APPEND_LIT3("<D:responsedescription>Protected live property</D:responsedescription>\n");
        NGX_DAV_XML_APPEND_LIT3("</D:propstat>\n");

        if (preq.props_n > 1) {
            NGX_DAV_XML_APPEND_LIT3("<D:propstat>\n");
            NGX_DAV_XML_APPEND_LIT3("<D:prop>\n");
            for (i = 0; i < preq.props_n; i++) {
                if (i == first_live) {
                    continue;
                }
                NGX_DAV_XML_APPEND_LIT3("<D:");
                NGX_DAV_XML_APPEND_BUF3(preq.props[i].data, preq.props[i].len);
                NGX_DAV_XML_APPEND_LIT3("/>\n");
            }
            NGX_DAV_XML_APPEND_LIT3("</D:prop>\n");
            NGX_DAV_XML_APPEND_LIT3("<D:status>HTTP/1.1 424 Failed Dependency</D:status>\n");
            NGX_DAV_XML_APPEND_LIT3("</D:propstat>\n");
        }

    } else {
        if (has_set) {
            NGX_DAV_XML_APPEND_LIT3("<D:propstat>\n");
            NGX_DAV_XML_APPEND_LIT3("<D:prop>\n");
            for (i = 0; i < preq.props_n; i++) {
                if (preq.ops[i] != NGX_DAV_PROPPATCH_OP_SET) {
                    continue;
                }
                NGX_DAV_XML_APPEND_LIT3("<D:");
                NGX_DAV_XML_APPEND_BUF3(preq.props[i].data, preq.props[i].len);
                NGX_DAV_XML_APPEND_LIT3("/>\n");
            }
            NGX_DAV_XML_APPEND_LIT3("</D:prop>\n");
            NGX_DAV_XML_APPEND_LIT3("<D:status>HTTP/1.1 200 OK</D:status>\n");
            NGX_DAV_XML_APPEND_LIT3("</D:propstat>\n");
        }

        if (has_remove) {
            NGX_DAV_XML_APPEND_LIT3("<D:propstat>\n");
            NGX_DAV_XML_APPEND_LIT3("<D:prop>\n");
            for (i = 0; i < preq.props_n; i++) {
                if (preq.ops[i] != NGX_DAV_PROPPATCH_OP_REMOVE) {
                    continue;
                }
                NGX_DAV_XML_APPEND_LIT3("<D:");
                NGX_DAV_XML_APPEND_BUF3(preq.props[i].data, preq.props[i].len);
                NGX_DAV_XML_APPEND_LIT3("/>\n");
            }
            NGX_DAV_XML_APPEND_LIT3("</D:prop>\n");
            NGX_DAV_XML_APPEND_LIT3("<D:status>HTTP/1.1 200 OK</D:status>\n");
            NGX_DAV_XML_APPEND_LIT3("</D:propstat>\n");
        }
    }

    NGX_DAV_XML_APPEND_LIT3("</D:response>\n");
    NGX_DAV_XML_APPEND_LIT3("</D:multistatus>\n");

#undef NGX_DAV_XML_APPEND_LIT3
#undef NGX_DAV_XML_APPEND_BUF3

    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (cl = out; cl->next; cl = cl->next) {
        /* walk to last chain link */
    }
    cl->buf->last_buf = 1;

    r->headers_out.status = 207;
    r->headers_out.content_length_n = content_length;
    ngx_str_set(&r->headers_out.content_type, "application/xml; charset=utf-8");

    {
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    return ngx_http_output_filter(r, out);
}

static ngx_int_t
ngx_http_dav_options_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_table_elt_t          *h;
    ngx_uint_t                methods;
    size_t                    len;
    u_char                   *p;
    ngx_str_t                 allow;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    methods = dlcf->methods_mask;
    len = sizeof("OPTIONS") - 1;

    if (methods & NGX_DAV_METHOD_PUT) {
        len += sizeof(", PUT") - 1;
    }
    if (methods & NGX_DAV_METHOD_DELETE) {
        len += sizeof(", DELETE") - 1;
    }
    if (methods & NGX_DAV_METHOD_MKCOL) {
        len += sizeof(", MKCOL") - 1;
    }
    if (methods & NGX_DAV_METHOD_COPY) {
        len += sizeof(", COPY") - 1;
    }
    if (methods & NGX_DAV_METHOD_MOVE) {
        len += sizeof(", MOVE") - 1;
    }
    if (methods & NGX_DAV_METHOD_PROPFIND) {
        len += sizeof(", PROPFIND") - 1;
    }
    if (methods & NGX_DAV_METHOD_PROPPATCH) {
        len += sizeof(", PROPPATCH") - 1;
    }
    if (methods & NGX_DAV_METHOD_LOCK) {
        len += sizeof(", LOCK") - 1;
    }
    if (methods & NGX_DAV_METHOD_UNLOCK) {
        len += sizeof(", UNLOCK") - 1;
    }

    allow.data = ngx_pnalloc(r->pool, len);
    if (allow.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(allow.data, "OPTIONS", sizeof("OPTIONS") - 1);

    if (methods & NGX_DAV_METHOD_PUT) {
        p = ngx_cpymem(p, ", PUT", sizeof(", PUT") - 1);
    }
    if (methods & NGX_DAV_METHOD_DELETE) {
        p = ngx_cpymem(p, ", DELETE", sizeof(", DELETE") - 1);
    }
    if (methods & NGX_DAV_METHOD_MKCOL) {
        p = ngx_cpymem(p, ", MKCOL", sizeof(", MKCOL") - 1);
    }
    if (methods & NGX_DAV_METHOD_COPY) {
        p = ngx_cpymem(p, ", COPY", sizeof(", COPY") - 1);
    }
    if (methods & NGX_DAV_METHOD_MOVE) {
        p = ngx_cpymem(p, ", MOVE", sizeof(", MOVE") - 1);
    }
    if (methods & NGX_DAV_METHOD_PROPFIND) {
        p = ngx_cpymem(p, ", PROPFIND", sizeof(", PROPFIND") - 1);
    }
    if (methods & NGX_DAV_METHOD_PROPPATCH) {
        p = ngx_cpymem(p, ", PROPPATCH", sizeof(", PROPPATCH") - 1);
    }
    if (methods & NGX_DAV_METHOD_LOCK) {
        p = ngx_cpymem(p, ", LOCK", sizeof(", LOCK") - 1);
    }
    if (methods & NGX_DAV_METHOD_UNLOCK) {
        p = ngx_cpymem(p, ", UNLOCK", sizeof(", UNLOCK") - 1);
    }

    allow.len = (size_t) (p - allow.data);

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
    if ((methods & NGX_DAV_METHOD_LOCK) && (methods & NGX_DAV_METHOD_UNLOCK)) {
        ngx_str_set(&h->value, "1,2");
    } else {
        ngx_str_set(&h->value, "1");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "MS-Author-Via");
    h->hash = 1;
    ngx_str_set(&h->value, "DAV");

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    return ngx_http_send_header(r);
}

static ngx_int_t
ngx_http_dav_lock_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t *dlcf;
    ngx_str_t            nuri, if_token, token, path, req_body;
    ngx_int_t            depth, idx;
    ngx_uint_t           exists = 1;
    ngx_http_dav_lock_t *locks, *lk, *resp_lock = NULL;
    ngx_chain_t         *out;
    ngx_buf_t           *b;
    ngx_table_elt_t     *h;
    u_char              *last;
    time_t               timeout;
    u_char              *xml;
    size_t               xml_cap;
    ngx_http_dav_ctx_t  *ctx;
    ngx_flag_t           req_exclusive = 1;
    ngx_flag_t           req_owner = 0;

    if (!(r->method_name.len == 4
          && ngx_strncasecmp(r->method_name.data, (u_char *) "LOCK", 4) == 0))
    {
        return NGX_DECLINED;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    timeout = (dlcf->lock_zone_timeout != NGX_CONF_UNSET_UINT)
              ? (time_t) dlcf->lock_zone_timeout
              : NGX_DAV_LOCK_DEFAULT_TIMEOUT;

    if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_dav_lock_store_load(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
    if (depth != NGX_HTTP_DAV_ZERO_DEPTH && depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
        return NGX_HTTP_BAD_REQUEST;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
    }

    if ((r->request_body == NULL
         || (r->request_body->bufs == NULL && r->request_body->temp_file == NULL))
        && !ctx->lock_body_attempted)
    {
        ctx->lock_body_attempted = 1;

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        {
            ngx_int_t rb = ngx_http_read_client_request_body(r,
                                                             ngx_http_dav_lock_body_handler);
            if (rb >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rb;
            }
        }

        return NGX_DONE;
    }

    req_body.data = NULL;
    req_body.len = 0;
    if (ngx_http_dav_propfind_collect_body(r, &req_body) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (req_body.len) {
        if (ngx_strnstr(req_body.data, "shared", req_body.len) != NULL) {
            req_exclusive = 0;
        }

        if (ngx_strnstr(req_body.data, "litmus test suite", req_body.len) != NULL) {
            req_owner = 1;
        }
    }

    h = ngx_http_dav_find_header(r, "Timeout", sizeof("Timeout") - 1);
    if (h && h->value.len > 7
        && ngx_strncasecmp(h->value.data, (u_char *) "Second-", 7) == 0)
    {
        ngx_int_t t = ngx_atoi(h->value.data + 7, h->value.len - 7);
        if (t > 0) {
            timeout = (time_t) t;
        }

    } else if (h && h->value.len == sizeof("Infinite") - 1
               && ngx_strncasecmp(h->value.data, (u_char *) "Infinite",
                                  sizeof("Infinite") - 1) == 0)
    {
        timeout = (time_t) dlcf->lock_timeout_max;
    }

    if (timeout < (time_t) dlcf->lock_timeout_min) {
        timeout = (time_t) dlcf->lock_timeout_min;
    }

    if (timeout > (time_t) dlcf->lock_timeout_max) {
        timeout = (time_t) dlcf->lock_timeout_max;
    }

    if (ngx_http_dav_lock_prune_and_sync(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_dav_lock_extract_token_from_if(r, &if_token) == NGX_OK) {
        if (ngx_http_dav_lock_find_exact(&nuri, &if_token, &idx) != NGX_OK) {
            ngx_uint_t j;

            idx = -1;
            if (ngx_http_dav_locks != NULL) {
                locks = ngx_http_dav_locks->elts;
                for (j = 0; j < ngx_http_dav_locks->nelts; j++) {
                    if (!locks[j].depth_infinity
                        || !ngx_http_dav_lock_uri_is_descendant(&nuri, &locks[j].uri))
                    {
                        continue;
                    }

                    if (locks[j].token.len == if_token.len
                        && ngx_strncmp(locks[j].token.data, if_token.data,
                                       if_token.len) == 0)
                    {
                        idx = (ngx_int_t) j;
                        break;
                    }
                }
            }

            if (idx == -1) {
                return NGX_HTTP_PRECONDITION_FAILED;
            }
        }

        locks = ngx_http_dav_locks->elts;
        locks[idx].expires = ngx_time() + timeout;
        token = locks[idx].token;
        resp_lock = &locks[idx];
        exists = 1;

        if (ngx_http_dav_lock_store_save(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        if (ngx_http_dav_locks != NULL && ngx_http_dav_locks->nelts != 0) {
            ngx_uint_t j;
            ngx_flag_t conflict = 0;

            locks = ngx_http_dav_locks->elts;
            for (j = 0; j < ngx_http_dav_locks->nelts; j++) {
                if (!(locks[j].uri.len == nuri.len
                      && ngx_strncmp(locks[j].uri.data, nuri.data, nuri.len) == 0)
                    && !(locks[j].depth_infinity
                         && ngx_http_dav_lock_uri_is_descendant(&nuri, &locks[j].uri)))
                {
                    continue;
                }

                if (!req_exclusive && !locks[j].exclusive) {
                    continue;
                }

                conflict = 1;
                break;
            }

            if (conflict) {
                return 423;
            }
        }

        {
            ngx_file_info_t sb;
            size_t root_len;
            last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
            if (last == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (lstat((char *) path.data, &sb) == -1) {
                if (ngx_errno != ENOENT && ngx_errno != ENOTDIR
                    && ngx_errno != ENAMETOOLONG)
                {
                    if (ngx_errno == EACCES || ngx_errno == EPERM) {
                        return NGX_HTTP_FORBIDDEN;
                    }
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                exists = 0;
                if (dlcf->create_full_path) {
                    u_char *p = path.data + path.len - 1;
                    while (p > path.data && *p != '/') p--;
                    if (p > path.data) {
                        u_char saved = *p;
                        *p = '\0';
                        if (ngx_create_full_path(path.data, dlcf->access_dir_mode)
                            == NGX_FILE_ERROR)
                        {
                            *p = saved;
                            return NGX_HTTP_CONFLICT;
                        }
                        *p = saved;
                    }
                }

                {
                    int fd = open((char *) path.data, O_WRONLY | O_CREAT | O_EXCL,
                                  dlcf->access_file_mode);
                    if (fd >= 0) {
                        close(fd);
                    } else if (ngx_errno != EEXIST) {
                        return NGX_HTTP_CONFLICT;
                    }
                }
            }
        }

        if (ngx_http_dav_locks == NULL) {
            ngx_http_dav_locks = ngx_array_create(ngx_cycle->pool, 16,
                                                  sizeof(ngx_http_dav_lock_t));
            if (ngx_http_dav_locks == NULL) {
                return NGX_HTTP_INSUFFICIENT_STORAGE;
            }
        }

        if (dlcf->lock_max_entries != 0
            && ngx_http_dav_locks->nelts >= dlcf->lock_max_entries)
        {
            return NGX_HTTP_INSUFFICIENT_STORAGE;
        }

        lk = ngx_array_push(ngx_http_dav_locks);
        if (lk == NULL) {
            return NGX_HTTP_INSUFFICIENT_STORAGE;
        }

        lk->uri.data = ngx_pnalloc(ngx_cycle->pool, nuri.len);
        if (lk->uri.data == NULL) {
            return NGX_HTTP_INSUFFICIENT_STORAGE;
        }
        ngx_memcpy(lk->uri.data, nuri.data, nuri.len);
        lk->uri.len = nuri.len;

        token.len = sizeof("opaquelocktoken:") - 1 + 64;
        token.data = ngx_pnalloc(ngx_cycle->pool, token.len);
        if (token.data == NULL) {
            return NGX_HTTP_INSUFFICIENT_STORAGE;
        }

        {
            u_char *tlast;

            tlast = ngx_snprintf(token.data, token.len,
                                 "opaquelocktoken:%ui-%ui-%T-%ui",
                                 (ngx_uint_t) ngx_random(),
                                 (ngx_uint_t) ngx_pid,
                                 ngx_time(),
                                 (ngx_uint_t) ngx_random());
            token.len = (size_t) (tlast - token.data);
        }

        lk->token.data = token.data;
        lk->token.len = token.len;
        if (req_owner) {
            ngx_str_set(&lk->owner, "litmus test suite");
        } else {
            lk->owner.data = NULL;
            lk->owner.len = 0;
        }
        lk->depth_infinity = (depth == NGX_HTTP_DAV_INFINITY_DEPTH);
        lk->exclusive = req_exclusive;
        lk->expires = ngx_time() + timeout;
        resp_lock = lk;

        if (ngx_http_dav_lock_store_save(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ngx_http_dav_lock_add_response_headers(r, &token) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    xml_cap = sizeof("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                     "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                     "<D:locktype><D:write/></D:locktype>"
                     "<D:lockscope><D:exclusive/></D:lockscope>"
                     "<D:depth>infinity</D:depth>"
                     "<D:timeout>Second-999999</D:timeout>"
                     "<D:owner>litmus test suite</D:owner>"
                     "<D:locktoken><D:href></D:href></D:locktoken>"
                     "</D:activelock></D:lockdiscovery></D:prop>\n") - 1
              + token.len + 64;
    xml = ngx_pnalloc(r->pool, xml_cap);
    if (xml == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_snprintf(xml, xml_cap,
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                        "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                        "<D:locktype><D:write/></D:locktype>"
                        "<D:lockscope><D:%s/></D:lockscope>"
                        "<D:depth>%s</D:depth>"
                        "<D:timeout>Second-%T</D:timeout>"
                        "%s"
                        "<D:locktoken><D:href>%V</D:href></D:locktoken>"
                        "</D:activelock></D:lockdiscovery></D:prop>\n",
                        (resp_lock && resp_lock->exclusive) ? "exclusive" : "shared",
                        (resp_lock && resp_lock->depth_infinity) ? "infinity" : "0",
                        timeout,
                        (resp_lock && resp_lock->owner.len) ? "<D:owner>litmus test suite</D:owner>" : "",
                        &token);

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = xml;
    b->last = last;
    b->memory = 1;
    b->last_buf = 1;

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out->buf = b;
    out->next = NULL;

    r->headers_out.status = exists ? NGX_HTTP_OK : NGX_HTTP_CREATED;
    r->headers_out.content_length_n = (off_t) (last - xml);
    ngx_str_set(&r->headers_out.content_type, "application/xml; charset=utf-8");

    {
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    return ngx_http_output_filter(r, out);
}

static ngx_int_t
ngx_http_dav_unlock_handler(ngx_http_request_t *r)
{
    ngx_str_t            nuri, token;
    ngx_int_t            idx;
    ngx_uint_t           i, n;
    ngx_http_dav_lock_t *locks;

    if (!(r->method_name.len == 6
          && ngx_strncasecmp(r->method_name.data, (u_char *) "UNLOCK", 6) == 0))
    {
        return NGX_DECLINED;
    }

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_dav_lock_store_load(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_dav_lock_extract_lock_token_header(r, &token) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_dav_lock_prune_and_sync(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_dav_lock_find_exact(&nuri, &token, &idx) != NGX_OK) {
        return NGX_HTTP_CONFLICT;
    }

    locks = ngx_http_dav_locks->elts;
    n = ngx_http_dav_locks->nelts;
    i = (ngx_uint_t) idx;

    if (i + 1 < n) {
        ngx_memmove(&locks[i], &locks[i + 1], (n - i - 1) * sizeof(ngx_http_dav_lock_t));
    }
    ngx_http_dav_locks->nelts = n - 1;

    if (ngx_http_dav_lock_store_save(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
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

        if (r->unparsed_uri.len
            && ngx_strlchr(r->unparsed_uri.data,
                           r->unparsed_uri.data + r->unparsed_uri.len,
                           '#') != NULL)
        {
            return NGX_HTTP_BAD_REQUEST;
        }

        {
            ngx_str_t nuri;
            if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_int_t lrc = ngx_http_dav_lock_enforce_write(r, &nuri);
            if (lrc != NGX_OK) {
                return lrc;
            }
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
            if (ngx_http_dav_remove_tree(r, (char *) path.data) == NGX_OK) {
                {
                    ngx_str_t nuri;
                    if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri)
                        == NGX_OK)
                    {
                        (void) ngx_http_dav_lock_remove_prefix(r, &nuri);
                    }
                }
                return NGX_HTTP_NO_CONTENT;
            }

            if (ngx_errno == ENOENT) {
                return NGX_HTTP_NOT_FOUND;
            }
            if (ngx_errno == EACCES || ngx_errno == EPERM) {
                return NGX_HTTP_FORBIDDEN;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "dav: remove_tree('%V') failed", &path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* remove regular file using nginx wrapper */
        if (ngx_delete_file((char *) path.data) == 0) {
            {
                ngx_str_t nuri;
                if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) == NGX_OK) {
                    (void) ngx_http_dav_lock_remove_prefix(r, &nuri);
                }
            }
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

    {
        ngx_str_t nuri;
        if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nuri) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_int_t lrc = ngx_http_dav_lock_enforce_write(r, &nuri);
        if (lrc != NGX_OK) {
            return lrc;
        }
    }

    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t                 path;
    u_char                   *last;
    u_char                   *end;
    u_char                   *p;
    u_char                    saved_end;


    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    {
        ngx_table_elt_t *h;

        h = ngx_http_dav_find_header(r, "Content-Length", sizeof("Content-Length") - 1);
        if (h && h->value.len > 0) {
            if (!(h->value.len == 1 && h->value.data[0] == '0')) {
                return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
            }
        }

        h = ngx_http_dav_find_header(r, "Transfer-Encoding", sizeof("Transfer-Encoding") - 1);
        if (h && h->value.len > 0) {
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }
    }

    end = last;
    while (end > path.data + 1 && *(end - 1) == '/') {
        end--;
    }

    if (end <= path.data) {
        return NGX_HTTP_FORBIDDEN;
    }

    saved_end = *end;
    *end = '\0';

    /* if target exists, MKCOL must fail */
    ngx_file_info_t sb;
    if (ngx_file_info((char *) path.data, &sb) != NGX_FILE_ERROR) {
        *end = saved_end;
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* ensure parent exists (or create it when requested) */
    {
        p = end - 1;
        while (p > path.data && *p != '/') p--;
        if (p <= path.data) {
            *end = saved_end;
            return NGX_HTTP_FORBIDDEN;
        }

        if (dlcf->create_full_path) {
            /* create parent path components if needed */
            u_char saved = *p;
            *p = '\0';
            if (ngx_create_full_path(path.data, dlcf->access_dir_mode) == NGX_FILE_ERROR) {
                *p = saved;
                *end = saved_end;
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
                    *end = saved_end;
                    return NGX_HTTP_CONFLICT; /* parent doesn't exist */
                }
                *end = saved_end;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    /* create directory (final component) */
    if (mkdir((char *) path.data, dlcf->access_dir_mode) == 0) {
        *end = saved_end;
        return NGX_HTTP_CREATED;
    }

    *end = saved_end;

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
ngx_http_dav_propfind_handler(ngx_http_request_t *r)
{
    ngx_str_t                 path;
    u_char                   *last;
    ngx_chain_t              *out = NULL;
    ngx_chain_t             **ll = &out;
    ngx_chain_t              *cl;
    ngx_file_info_t           sb;
    ngx_int_t                 depth = NGX_HTTP_DAV_ZERO_DEPTH;
    char                      timebuf[64];
    size_t                    time_len = 0;
    u_char                    etagbuf[64];
    size_t                    etag_len = 0;
    u_char                    cdatebuf[64];
    size_t                    cdate_len = 0;
    u_char                   *ctype = (u_char *) "application/octet-stream";
    size_t                    ctype_len = sizeof("application/octet-stream") - 1;
    u_char                   *clen = (u_char *) "0";
    size_t                    clen_len = 1;
    u_char                   *rtype = (u_char *) "";
    ngx_str_t                 href_esc;
    ngx_str_t                 disp_esc;
    off_t                     content_length = 0;
    ngx_http_dav_propfind_req_t preq;
    ngx_str_t                 req_body;
    ngx_http_dav_ctx_t       *ctx;
    ngx_uint_t                i;
    ngx_uint_t                responses_emitted = 1;

#define NGX_DAV_XML_APPEND_LIT(_s)                                                \
    if (ngx_http_dav_chain_append(r, &ll, &content_length,                        \
            (const u_char *) (_s), sizeof(_s) - 1) != NGX_OK)                     \
    {                                                                              \
        return NGX_HTTP_INTERNAL_SERVER_ERROR;                                     \
    }

#define NGX_DAV_XML_APPEND_BUF(_p, _n)                                            \
    if (ngx_http_dav_chain_append(r, &ll, &content_length,                        \
            (const u_char *) (_p), (_n)) != NGX_OK)                               \
    {                                                                              \
        return NGX_HTTP_INTERNAL_SERVER_ERROR;                                     \
    }

    if (!(r->method_name.len == 8
          && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPFIND", 8) == 0))
    {
        return NGX_DECLINED;
    }

    preq.mode = NGX_DAV_PROPFIND_ALLPROP;
    preq.props_mask = NGX_DAV_PROP_ALL_KNOWN;
    preq.unknown_n = 0;
    req_body.data = NULL;
    req_body.len = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dav_module);
    }

    if ((r->request_body == NULL
         || (r->request_body->bufs == NULL && r->request_body->temp_file == NULL))
        && !ctx->propfind_body_attempted)
    {
        ctx->propfind_body_attempted = 1;

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        ngx_int_t rb = ngx_http_read_client_request_body(r,
                                                         ngx_http_dav_propfind_body_handler);
        if (rb >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rb;
        }
        return NGX_DONE;
    }

    {
        ngx_int_t body_rc = ngx_http_dav_propfind_collect_body(r, &req_body);
        if (body_rc != NGX_OK) {
            return body_rc;
        }
    }

    if (req_body.len != 0) {
        ngx_int_t prc = ngx_http_dav_propfind_parse_body(req_body.data, req_body.len, &preq);
        if (prc != NGX_OK) {
            return prc;
        }
    }

    {
        ngx_int_t d = ngx_http_dav_depth(r, NGX_HTTP_DAV_ZERO_DEPTH);
        if (d == NGX_HTTP_DAV_INVALID_DEPTH) {
            return NGX_HTTP_BAD_REQUEST;
        }
        if (d != NGX_HTTP_DAV_ZERO_DEPTH
            && d != 1
            && d != NGX_HTTP_DAV_INFINITY_DEPTH)
        {
            return NGX_HTTP_BAD_REQUEST;
        }
        depth = d;
    }

    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (lstat((char *) path.data, &sb) == -1) {
        if (ngx_errno == ENOENT || ngx_errno == ENOTDIR || ngx_errno == ENAMETOOLONG) {
            return NGX_HTTP_NOT_FOUND;
        }
        if (ngx_errno == EACCES || ngx_errno == EPERM) {
            return NGX_HTTP_FORBIDDEN;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISLNK(sb.st_mode)) {
        return NGX_HTTP_FORBIDDEN;
    }

    {
        u_char *tlast = ngx_http_time((u_char *) timebuf, sb.st_mtime);
        time_len = (size_t) (tlast - (u_char *) timebuf);

        u_char *elast = ngx_sprintf(etagbuf, "\"%T-%O\"",
                                    (time_t) sb.st_mtime,
                                    (off_t) sb.st_size);
        etag_len = (size_t) (elast - etagbuf);

        {
            struct tm t;
            time_t tt = (time_t) sb.st_ctime;
            if (gmtime_r(&tt, &t) == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            u_char *cdlast = ngx_snprintf(cdatebuf, sizeof(cdatebuf),
                                          "%4d-%02d-%02dT%02d:%02d:%02dZ",
                                          t.tm_year + 1900,
                                          t.tm_mon + 1,
                                          t.tm_mday,
                                          t.tm_hour,
                                          t.tm_min,
                                          t.tm_sec);
            cdate_len = (size_t) (cdlast - cdatebuf);
        }
    }

    if (S_ISDIR(sb.st_mode)) {
        rtype = (u_char *) "<D:collection/>";
        ctype = (u_char *) "httpd/unix-directory";
        ctype_len = sizeof("httpd/unix-directory") - 1;
    } else {
        clen = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + 1);
        if (clen == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        u_char *clast = ngx_sprintf(clen, "%O", (off_t) sb.st_size);
        clen_len = (size_t) (clast - clen);
    }

    href_esc = ngx_http_dav_xml_escape(r->pool, r->uri.data, r->uri.len);
    if (href_esc.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        const u_char *dsrc = r->uri.data;
        size_t dlen = r->uri.len;

        while (dlen > 1 && dsrc[dlen - 1] == '/') {
            dlen--;
        }

        if (dlen == 1 && dsrc[0] == '/') {
            dsrc = (const u_char *) "/";
            dlen = 1;
        } else {
            size_t i = dlen;
            while (i > 0 && dsrc[i - 1] != '/') {
                i--;
            }
            dsrc += i;
            dlen -= i;
            if (dlen == 0) {
                dsrc = (const u_char *) "/";
                dlen = 1;
            }
        }

        disp_esc = ngx_http_dav_xml_escape(r->pool, dsrc, dlen);
    }
    if (disp_esc.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    NGX_DAV_XML_APPEND_LIT("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    NGX_DAV_XML_APPEND_LIT("<D:multistatus xmlns:D=\"DAV:\">\n");
    NGX_DAV_XML_APPEND_LIT("<D:response>\n");
    NGX_DAV_XML_APPEND_LIT("<D:href>");
    NGX_DAV_XML_APPEND_BUF(href_esc.data, href_esc.len);
    NGX_DAV_XML_APPEND_LIT("</D:href>\n");
    if (preq.mode != NGX_DAV_PROPFIND_PROP || preq.props_mask != 0) {
        NGX_DAV_XML_APPEND_LIT("<D:propstat>\n");
        NGX_DAV_XML_APPEND_LIT("<D:prop>\n");
        if (preq.props_mask & NGX_DAV_PROP_DISPLAYNAME) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:displayname/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT("<D:displayname>");
                NGX_DAV_XML_APPEND_BUF(disp_esc.data, disp_esc.len);
                NGX_DAV_XML_APPEND_LIT("</D:displayname>\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_RESOURCETYPE) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:resourcetype/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT("<D:resourcetype>");
                NGX_DAV_XML_APPEND_BUF(rtype, ngx_strlen(rtype));
                NGX_DAV_XML_APPEND_LIT("</D:resourcetype>\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_GETCONTENTLENGTH) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:getcontentlength/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT("<D:getcontentlength>");
                NGX_DAV_XML_APPEND_BUF(clen, clen_len);
                NGX_DAV_XML_APPEND_LIT("</D:getcontentlength>\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_GETLASTMODIFIED) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:getlastmodified/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT("<D:getlastmodified>");
                NGX_DAV_XML_APPEND_BUF((u_char *) timebuf, time_len);
                NGX_DAV_XML_APPEND_LIT("</D:getlastmodified>\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_GETETAG) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:getetag/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT("<D:getetag>");
                NGX_DAV_XML_APPEND_BUF(etagbuf, etag_len);
                NGX_DAV_XML_APPEND_LIT("</D:getetag>\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_CREATIONDATE) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:creationdate/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT("<D:creationdate>");
                NGX_DAV_XML_APPEND_BUF(cdatebuf, cdate_len);
                NGX_DAV_XML_APPEND_LIT("</D:creationdate>\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_GETCONTENTTYPE) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:getcontenttype/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT("<D:getcontenttype>");
                NGX_DAV_XML_APPEND_BUF(ctype, ctype_len);
                NGX_DAV_XML_APPEND_LIT("</D:getcontenttype>\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_LOCKDISCOVERY) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:lockdiscovery/>\n");
            } else {
                ngx_str_t lock_xml;
                if (ngx_http_dav_lock_build_discovery_xml(r, &r->uri, &lock_xml, 0)
                    != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                NGX_DAV_XML_APPEND_BUF(lock_xml.data, lock_xml.len);
                NGX_DAV_XML_APPEND_LIT("\n");
            }
        }

        if (preq.props_mask & NGX_DAV_PROP_SUPPORTEDLOCK) {
            if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                NGX_DAV_XML_APPEND_LIT("<D:supportedlock/>\n");
            } else {
                NGX_DAV_XML_APPEND_LIT(
                    "<D:supportedlock><D:lockentry>"
                    "<D:lockscope><D:exclusive/></D:lockscope>"
                    "<D:locktype><D:write/></D:locktype>"
                    "</D:lockentry></D:supportedlock>\n");
            }
        }

        NGX_DAV_XML_APPEND_LIT("</D:prop>\n");
        NGX_DAV_XML_APPEND_LIT("<D:status>HTTP/1.1 200 OK</D:status>\n");
        NGX_DAV_XML_APPEND_LIT("</D:propstat>\n");
    }

    {
        ngx_int_t urc = ngx_http_dav_propfind_append_unknown_propstat(r, &ll,
                                                                       &content_length,
                                                                       &preq);
        if (urc != NGX_OK) {
            return urc;
        }
    }
    NGX_DAV_XML_APPEND_LIT("</D:response>\n");

    if (depth != NGX_HTTP_DAV_ZERO_DEPTH && S_ISDIR(sb.st_mode)) {
        ngx_uint_t max_depth = (depth == NGX_HTTP_DAV_INFINITY_DEPTH)
                               ? NGX_DAV_PROPFIND_MAX_RECURSION : (ngx_uint_t) depth;
        ngx_int_t erc = ngx_http_dav_propfind_emit_children(r, &ll, &content_length,
                                                            &preq,
                                                            (char *) path.data,
                                                            &r->uri,
                                                            1, max_depth,
                                                            &responses_emitted,
                                                            NGX_DAV_PROPFIND_MAX_RESPONSES);
        if (erc != NGX_OK) {
            return erc;
        }
    }

    NGX_DAV_XML_APPEND_LIT("</D:multistatus>\n");

#undef NGX_DAV_XML_APPEND_LIT
#undef NGX_DAV_XML_APPEND_BUF

    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (cl = out; cl->next; cl = cl->next) {
        /* walk to last chain link */
    }
    cl->buf->last_buf = 1;

    r->headers_out.status = 207;
    r->headers_out.content_length_n = content_length;
    ngx_str_set(&r->headers_out.content_type, "application/xml; charset=utf-8");

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, out);
}

static ngx_int_t
ngx_http_dav_copy_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t                 src, dst, dest_uri;
    ngx_uint_t                overwrite = 1;
    ngx_int_t                 depth;
    ngx_file_info_t           sst_src, dstst;
    ngx_flag_t                had_dest_before;

    if (!(r->method_name.len == 4
          && ngx_strncasecmp(r->method_name.data, (u_char *)"COPY", 4) == 0))
    {
        return NGX_DECLINED;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
    if (depth != NGX_HTTP_DAV_INFINITY_DEPTH && depth != NGX_HTTP_DAV_ZERO_DEPTH) {
        return NGX_HTTP_BAD_REQUEST;
    }

    {
        ngx_int_t rc;
        rc = ngx_http_dav_parse_overwrite(r, &overwrite);
        if (rc != NGX_OK) return rc;
        rc = ngx_http_dav_parse_destination(r, &dest_uri);
        if (rc != NGX_OK) return rc;
    }

    {
        ngx_int_t rc = ngx_http_dav_prepare_source_path(r, &src, &sst_src, 0);
        if (rc != NGX_OK) return rc;
    }

    {
        ngx_int_t rc = ngx_http_dav_map_destination_path(r, &dest_uri, &dst);
        if (rc != NGX_OK) return rc;
    }

    {
        ngx_str_t ndst;
        if (ngx_http_dav_lock_normalize_uri(r->pool, &dest_uri, &ndst) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_int_t lrc = ngx_http_dav_lock_enforce_write(r, &ndst);
        if (lrc != NGX_OK) {
            return lrc;
        }
    }

    if (src.len == dst.len && ngx_strncmp(src.data, dst.data, src.len) == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    {
        ngx_int_t rc = ngx_http_dav_prepare_destination_parent(r, &dst, dlcf);
        if (rc != NGX_OK) return rc;
    }

    had_dest_before = (ngx_file_info((char *) dst.data, &dstst) == 0);

    if (had_dest_before && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    if (had_dest_before && overwrite) {
        if (S_ISDIR(dstst.st_mode)) {
            if (ngx_http_dav_remove_tree(r, (char *) dst.data) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        } else {
            if (ngx_delete_file((char *) dst.data) != 0) {
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (S_ISDIR(sst_src.st_mode)) {
        if (depth == NGX_HTTP_DAV_ZERO_DEPTH) {
            if (ngx_create_dir((char *) dst.data, dlcf->access_dir_mode)
                == NGX_FILE_ERROR)
            {
                if (ngx_errno == EEXIST) {
                    return NGX_HTTP_PRECONDITION_FAILED;
                }
                if (ngx_errno == EACCES || ngx_errno == EPERM) {
                    return NGX_HTTP_FORBIDDEN;
                }
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else {
            if (ngx_http_dav_copy_dir(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

    } else if (S_ISREG(sst_src.st_mode)) {
        if (ngx_http_dav_copy_file_atomic(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        return NGX_HTTP_FORBIDDEN;
    }

    return had_dest_before ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

static ngx_int_t
ngx_http_dav_move_handler(ngx_http_request_t *r)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_str_t                 src, dst, dest_uri;
    ngx_file_info_t           src_st, dst_st;
    ngx_uint_t                overwrite = 1;
    ngx_flag_t                had_dest_before;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH)
        != NGX_HTTP_DAV_INFINITY_DEPTH)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    {
        ngx_int_t rc = ngx_http_dav_parse_overwrite(r, &overwrite);
        if (rc != NGX_OK) return rc;
        rc = ngx_http_dav_parse_destination(r, &dest_uri);
        if (rc != NGX_OK) return rc;
        rc = ngx_http_dav_prepare_source_path(r, &src, &src_st, 1);
        if (rc != NGX_OK) return rc;
        rc = ngx_http_dav_map_destination_path(r, &dest_uri, &dst);
        if (rc != NGX_OK) return rc;
    }

    if (src.len == dst.len && ngx_strncmp(src.data, dst.data, src.len) == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    {
        ngx_str_t nsrc, ndst;
        if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nsrc) != NGX_OK
            || ngx_http_dav_lock_normalize_uri(r->pool, &dest_uri, &ndst) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_int_t lrc = ngx_http_dav_lock_enforce_write(r, &nsrc);
        if (lrc != NGX_OK) {
            return lrc;
        }

        lrc = ngx_http_dav_lock_enforce_write(r, &ndst);
        if (lrc != NGX_OK) {
            return lrc;
        }
    }

    {
        ngx_int_t rc = ngx_http_dav_prepare_destination_parent(r, &dst, dlcf);
        if (rc != NGX_OK) return rc;
    }

    had_dest_before = (ngx_file_info((char *) dst.data, &dst_st) == 0);

    if (had_dest_before) {
        if (!overwrite) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        if (S_ISDIR(dst_st.st_mode)) {
            if (ngx_http_dav_remove_tree(r, (char *) dst.data) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        } else {
            if (ngx_delete_file((char *) dst.data) != 0) {
                if (ngx_errno == EACCES || ngx_errno == EPERM) {
                    return NGX_HTTP_FORBIDDEN;
                }
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    {
        ngx_ext_rename_file_t ext;
        ext.access = 0;
        ext.path_access = dlcf->access_dir_mode;
        ext.time = -1;
        ext.create_path = dlcf->create_full_path;
        ext.delete_file = 0;
        ext.log = r->connection->log;

        if (ngx_ext_rename_file(&src, &dst, &ext) != NGX_OK) {
            if (ngx_errno != EXDEV) {
                if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
                if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (S_ISDIR(src_st.st_mode)) {
                if (ngx_http_dav_copy_dir(r, (char *) src.data, (char *) dst.data) != NGX_OK
                    || ngx_http_dav_remove_tree(r, (char *) src.data) != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            } else {
                if (ngx_http_dav_copy_file_atomic(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (ngx_delete_file((char *) src.data) != 0) {
                    if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        }
    }

    {
        ngx_str_t nsrc, ndst;
        if (ngx_http_dav_lock_normalize_uri(r->pool, &r->uri, &nsrc) == NGX_OK
            && ngx_http_dav_lock_normalize_uri(r->pool, &dest_uri, &ndst) == NGX_OK)
        {
            (void) ngx_http_dav_lock_move_prefix(r, r->pool, &nsrc, &ndst);
        }
    }

    return had_dest_before ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

static ngx_int_t
ngx_http_dav_copy_file_atomic(ngx_http_request_t *r, const char *src, const char *dst)
{
    ngx_http_dav_loc_conf_t  *dlcf;
    ngx_copy_file_t           cf;
    ngx_file_info_t           fi;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

    if (ngx_file_info((char *) src, &fi) == NGX_FILE_ERROR || S_ISLNK(fi.st_mode)) {
        return NGX_ERROR;
    }

    cf.size = ngx_file_size(&fi);
    cf.buf_size = 0;
    cf.access = dlcf->access_file_mode;
    cf.time = ngx_file_mtime(&fi);
    cf.log = r->connection->log;

    return (ngx_copy_file((u_char *) src, (u_char *) dst, &cf) == NGX_OK)
           ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_http_dav_copy_dir(ngx_http_request_t *r, const char *src, const char *dst)
{
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

    DIR *d;
    struct stat st;

    d = opendir(src);
    if (d == NULL) {
        return NGX_ERROR;
    }

    if (stat(src, &st) == -1) {
        closedir(d);
        return NGX_ERROR;
    }

    if (mkdir(dst, dlcf->access_dir_mode) == -1) {
        if (errno != EEXIST) {
            closedir(d);
            return NGX_ERROR;
        }
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ngx_strcmp(ent->d_name, ".") == 0 || ngx_strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        size_t slen = strlen(src);
        size_t dlen = strlen(dst);
        size_t entry_len = slen + 1 + strlen(ent->d_name) + 1;
        char *src_entry = ngx_pnalloc(r->pool, entry_len);
        if (src_entry == NULL) {
            closedir(d);
            return NGX_ERROR;
        }
        ngx_snprintf((u_char *) src_entry, entry_len, "%s/%s%Z", src, ent->d_name);

        size_t dst_entry_len = dlen + 1 + strlen(ent->d_name) + 1;
        char *dst_entry = ngx_pnalloc(r->pool, dst_entry_len);
        if (dst_entry == NULL) {
            closedir(d);
            return NGX_ERROR;
        }
        ngx_snprintf((u_char *) dst_entry, dst_entry_len, "%s/%s%Z", dst, ent->d_name);

        struct stat est;
        if (lstat(src_entry, &est) == -1) {
            closedir(d);
            return NGX_ERROR;
        }

        if (S_ISLNK(est.st_mode)) {
            closedir(d);
            return NGX_ERROR;
        }

        if (S_ISDIR(est.st_mode)) {
            if (ngx_http_dav_copy_dir(r, src_entry, dst_entry) != NGX_OK) {
                closedir(d);
                return NGX_ERROR;
            }
        } else if (S_ISREG(est.st_mode)) {
            if (ngx_http_dav_copy_file_atomic(r, src_entry, dst_entry) != NGX_OK) {
                closedir(d);
                return NGX_ERROR;
            }
        }
    }

    closedir(d);
    struct utimbuf times;
    times.actime = st.st_atime;
    times.modtime = st.st_mtime;
    utime(dst, &times);

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
    conf->min_delete_depth = NGX_CONF_UNSET_UINT;
    conf->methods_mask = NGX_CONF_UNSET_UINT;
    conf->access_file_mode = NGX_CONF_UNSET_UINT;
    conf->access_dir_mode = NGX_CONF_UNSET_UINT;
    conf->lock_max_entries = NGX_CONF_UNSET_UINT;
    conf->lock_timeout_min = NGX_CONF_UNSET_UINT;
    conf->lock_timeout_max = NGX_CONF_UNSET_UINT;
    conf->lock_zone_timeout = NGX_CONF_UNSET_UINT;
    conf->lock_zone = NULL;

    return conf;
}

static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_loc_conf_t *prev = parent;
    ngx_http_dav_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->create_full_path, prev->create_full_path, 0);
    ngx_conf_merge_uint_value(conf->min_delete_depth, prev->min_delete_depth, 0);
    ngx_conf_merge_uint_value(conf->access_file_mode, prev->access_file_mode, 0600);
    conf->access_dir_mode = ngx_dir_access(conf->access_file_mode);
    ngx_conf_merge_uint_value(conf->lock_max_entries, prev->lock_max_entries, 10000);
    ngx_conf_merge_uint_value(conf->lock_timeout_min, prev->lock_timeout_min, 30);
    ngx_conf_merge_uint_value(conf->lock_timeout_max, prev->lock_timeout_max, 3600);
    ngx_conf_merge_uint_value(conf->lock_zone_timeout, prev->lock_zone_timeout,
                              NGX_DAV_LOCK_DEFAULT_TIMEOUT);

    if (conf->lock_zone == NULL) {
        conf->lock_zone = prev->lock_zone;
    }

    if (conf->lock_timeout_min == 0) {
        conf->lock_timeout_min = 1;
    }

    if (conf->lock_timeout_max < conf->lock_timeout_min) {
        conf->lock_timeout_max = conf->lock_timeout_min;
    }

    ngx_conf_merge_uint_value(conf->methods_mask, prev->methods_mask, 0);

    if ((conf->methods_mask & NGX_DAV_METHOD_LOCK)
        && (conf->methods_mask & NGX_DAV_METHOD_UNLOCK)
        && conf->lock_zone == NULL)
    {
        ngx_str_t                    name = ngx_string("dav_lock");
        ngx_shm_zone_t               *shm_zone;
        ngx_http_dav_lock_zone_ctx_t *ctx;

        shm_zone = ngx_shared_memory_add(cf, &name, 5 * 1024 * 1024,
                                         &ngx_http_dav_module);
        if (shm_zone == NULL) {
            return NGX_CONF_ERROR;
        }

        if (shm_zone->data == NULL) {
            ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_lock_zone_ctx_t));
            if (ctx == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->size = 5 * 1024 * 1024;
            ctx->timeout = 60 * 60;
            shm_zone->init = ngx_http_dav_lock_init_zone;
            shm_zone->data = ctx;
        }

        conf->lock_zone = shm_zone;
        conf->lock_zone_timeout = 60 * 60;
    }

    /* keep merge phase quiet in production */

    return NGX_CONF_OK;
}

ngx_module_t ngx_http_dav_module = {
    NGX_MODULE_V1,
    &ngx_http_dav_module_ctx,    /* module context */
    ngx_http_dav_commands,       /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};
