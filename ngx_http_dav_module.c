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
#include <ctype.h>
#include <time.h>

extern ngx_module_t ngx_http_dav_module;

typedef struct ngx_http_dav_propfind_req_s ngx_http_dav_propfind_req_t;
typedef struct ngx_http_dav_proppatch_req_s ngx_http_dav_proppatch_req_t;
typedef struct ngx_http_dav_dead_props_s ngx_http_dav_dead_props_t;
typedef struct ngx_http_dav_loc_conf_s ngx_http_dav_loc_conf_t;

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_propfind_handler(ngx_http_request_t *r);
static void ngx_http_dav_propfind_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_proppatch_handler(ngx_http_request_t *r);
static void ngx_http_dav_proppatch_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_options_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_copy_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_move_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_dav_copy_file_atomic(ngx_http_request_t *r, const char *src, const char *dst);
static ngx_int_t ngx_http_dav_copy_dir(ngx_http_request_t *r, const char *src, const char *dst);
static ngx_int_t ngx_http_dav_remove_tree(ngx_http_request_t *r, const char *path);
static ngx_int_t ngx_http_dav_unlink_if_unchanged(ngx_http_request_t *r, const char *path, const ngx_file_info_t *orig_st);
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
    ngx_chain_t ***ll, off_t *total, ngx_http_dav_propfind_req_t *preq,
    ngx_http_dav_dead_props_t *dead);
static ngx_int_t ngx_http_dav_props_path(ngx_http_request_t *r, ngx_str_t *path,
    ngx_str_t *ppath);
static ngx_int_t ngx_http_dav_props_path_fs(ngx_pool_t *pool, const ngx_str_t *path,
    ngx_str_t *ppath);
static ngx_int_t ngx_http_dav_read_props_blob(ngx_http_request_t *r,
    ngx_str_t *ppath, ngx_str_t *out);
static ngx_int_t ngx_http_dav_write_props_blob(ngx_http_request_t *r,
    ngx_str_t *ppath, ngx_str_t *data);
static ngx_int_t ngx_http_dav_sync_dead_props_between_paths(ngx_http_request_t *r,
    ngx_str_t *src_path, ngx_str_t *dst_path, ngx_flag_t move);
static ngx_int_t ngx_http_dav_sync_dead_props_tree(ngx_http_request_t *r,
    const char *src, const char *dst, ngx_flag_t move);
static void ngx_http_dav_prune_props_dirs(ngx_http_request_t *r, ngx_str_t *ppath);
static void ngx_http_dav_delete_dead_props_for_path(ngx_http_request_t *r,
    ngx_str_t *path);
static ngx_int_t ngx_http_dav_dead_props_load(ngx_http_request_t *r,
    ngx_str_t *path, ngx_http_dav_dead_props_t *dead);
static ngx_int_t ngx_http_dav_dead_props_save(ngx_http_request_t *r,
    ngx_str_t *path, ngx_http_dav_dead_props_t *dead);
static ngx_flag_t ngx_http_dav_dead_props_contains(ngx_http_dav_dead_props_t *dead,
    const ngx_str_t *name);
static ngx_int_t ngx_http_dav_dead_props_find(ngx_http_dav_dead_props_t *dead,
    const ngx_str_t *name);
static ngx_int_t ngx_http_dav_xml_rewrite_to_d_namespace(ngx_pool_t *pool,
    const ngx_str_t *src, ngx_str_t *dst);
static ngx_int_t ngx_http_dav_dead_props_add(ngx_http_request_t *r,
    ngx_http_dav_dead_props_t *dead, const ngx_str_t *name, const ngx_str_t *xml);
static void ngx_http_dav_dead_props_remove(ngx_http_dav_dead_props_t *dead,
    const ngx_str_t *name);
static ngx_int_t ngx_http_dav_propfind_emit_children(ngx_http_request_t *r,
    ngx_chain_t ***ll, off_t *content_length, ngx_http_dav_propfind_req_t *preq,
    const char *dir_path, const ngx_str_t *parent_uri,
    ngx_uint_t current_depth, ngx_uint_t max_depth,
    ngx_uint_t *responses_emitted, ngx_uint_t max_responses);

#define NGX_DAV_PROPFIND_ALLPROP  0
#define NGX_DAV_PROPFIND_PROPNAME 1
#define NGX_DAV_PROPFIND_PROP     2
#define NGX_HTTP_DAV_ZERO_DEPTH 0
#define NGX_HTTP_DAV_INFINITY_DEPTH -1
#define NGX_HTTP_DAV_INVALID_DEPTH -2
#define NGX_DAV_PROPFIND_MAX_RECURSION 32
#define NGX_DAV_PROPFIND_MAX_RESPONSES 4096

#define NGX_DAV_PROP_DISPLAYNAME      0x01
#define NGX_DAV_PROP_RESOURCETYPE     0x02
#define NGX_DAV_PROP_GETCONTENTLENGTH 0x04
#define NGX_DAV_PROP_GETLASTMODIFIED  0x08
#define NGX_DAV_PROP_GETETAG          0x10
#define NGX_DAV_PROP_CREATIONDATE     0x20
#define NGX_DAV_PROP_GETCONTENTTYPE   0x40
#define NGX_DAV_PROP_ALL_KNOWN (NGX_DAV_PROP_DISPLAYNAME | NGX_DAV_PROP_RESOURCETYPE \
    | NGX_DAV_PROP_GETCONTENTLENGTH | NGX_DAV_PROP_GETLASTMODIFIED \
    | NGX_DAV_PROP_GETETAG | NGX_DAV_PROP_CREATIONDATE \
    | NGX_DAV_PROP_GETCONTENTTYPE)

#define NGX_DAV_PROPFIND_UNKNOWN_MAX 32
#define NGX_DAV_PROPPATCH_PROPS_MAX 64
#define NGX_DAV_PROPPATCH_OP_SET    1
#define NGX_DAV_PROPPATCH_OP_REMOVE 2

struct ngx_http_dav_propfind_req_s {
    ngx_uint_t mode;
    ngx_uint_t props_mask;
    ngx_uint_t unknown_n;
    ngx_str_t  unknown[NGX_DAV_PROPFIND_UNKNOWN_MAX];
};

struct ngx_http_dav_proppatch_req_s {
    ngx_uint_t props_n;
    ngx_str_t  props[NGX_DAV_PROPPATCH_PROPS_MAX];
    ngx_str_t  prop_xml[NGX_DAV_PROPPATCH_PROPS_MAX];
    u_char     ops[NGX_DAV_PROPPATCH_PROPS_MAX];
};

struct ngx_http_dav_dead_props_s {
    ngx_uint_t n;
    ngx_str_t  names[NGX_DAV_PROPPATCH_PROPS_MAX];
    ngx_str_t  xml[NGX_DAV_PROPPATCH_PROPS_MAX];
};

struct ngx_http_dav_loc_conf_s {
        ngx_flag_t    create_full_path;
        ngx_array_t  *dav_methods;
        ngx_array_t  *dav_access;
        ngx_uint_t    min_delete_depth;
    ngx_uint_t    methods_mask;
    ngx_uint_t    access_file_mode;
    ngx_uint_t    access_dir_mode;
};

typedef struct {
    ngx_flag_t   done;
    ngx_int_t    status;
    ngx_flag_t   propfind_body_attempted;
    ngx_flag_t   proppatch_body_attempted;
} ngx_http_dav_ctx_t;

static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_conf_set_dav_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_dav_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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
            ngx_conf_set_dav_access,
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

static ngx_int_t ngx_http_dav_remove_tree_fd(ngx_http_request_t *r, int dirfd);

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
        return dflt;
    }

    if (h->value.len == 0) {
        return NGX_HTTP_DAV_INVALID_DEPTH;
    }

    if (h->value.len == 1 && h->value.data[0] == '0') {
        return NGX_HTTP_DAV_ZERO_DEPTH;
    }

    if (h->value.len == 1 && h->value.data[0] == '1') {
        return 1;
    }

    if (h->value.len == sizeof("infinity") - 1
        && ngx_strncasecmp(h->value.data, (u_char *) "infinity",
                           sizeof("infinity") - 1) == 0)
    {
        return NGX_HTTP_DAV_INFINITY_DEPTH;
    }

    return NGX_HTTP_DAV_INVALID_DEPTH;
}

static ngx_int_t
ngx_http_dav_parse_overwrite(ngx_http_request_t *r, ngx_uint_t *overwrite)
{
    ngx_table_elt_t *over;

    *overwrite = 1;

    over = ngx_http_dav_find_header(r, "Overwrite", sizeof("Overwrite") - 1);
    if (over == NULL) {
        return NGX_OK;
    }

    if (over->value.len != 1) {
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
    ngx_str_t old_uri;

    old_uri = r->uri;
    r->uri = *duri;
    last = ngx_http_map_uri_to_path(r, path, &root_len, 0);
    r->uri = old_uri;

    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_prepare_destination_parent(ngx_http_request_t *r, ngx_str_t *path,
    ngx_http_dav_loc_conf_t *dlcf)
{
    u_char *p;

    if (path->len == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    p = path->data + path->len - 1;
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
    /* open directory as descriptor and operate on entries via *at calls to avoid path construction */
    int dfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd == -1) {
        return NGX_ERROR;
    }

    ngx_int_t rc = ngx_http_dav_remove_tree_fd(r, dfd);

    /* closedir equivalent: remove_tree_fd leaves dirfd open; close it */
    close(dfd);

    if (rc != NGX_OK) return NGX_ERROR;

    /* finally remove the now-empty directory itself */
    /* retry rmdir on transient failures */
    int attempts = 0;
    while (rmdir(path) == -1) {
        int err = ngx_errno;
        ngx_log_error(NGX_LOG_WARN, r->connection->log, err, "dav: rmdir failed (attempt %d) '%s'", attempts+1, path);
        if (err != ENOTEMPTY && err != EBUSY && err != EAGAIN && err != EINTR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, err, "dav: rmdir permanent failure '%s'", path);
            return NGX_ERROR;
        }
        if (++attempts > 5) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, err, "dav: rmdir retry exhausted '%s'", path);
            return NGX_ERROR;
        }
        ngx_msleep(10);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_remove_tree_fd(ngx_http_request_t *r, int dirfd)
{
    DIR *d = fdopendir(dup(dirfd));
    if (d == NULL) return NGX_ERROR;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ngx_strcmp(ent->d_name, ".") == 0 || ngx_strcmp(ent->d_name, "..") == 0) continue;

        /* copy name into a safe buffer to avoid reading past non-terminated/garbled dirent->d_name */
        char namebuf[NAME_MAX + 1];
        size_t nlen = strnlen(ent->d_name, NAME_MAX + 1);
        if (nlen == 0 || nlen > NAME_MAX) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "dav: skipping weird dirent name len=%uz", nlen);
            continue;
        }
        memcpy(namebuf, ent->d_name, nlen);
        namebuf[nlen] = '\0';

        struct stat st;
        if (fstatat(dirfd, namebuf, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            int ferr = ngx_errno;
            if (ferr == EACCES || ferr == EPERM) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ferr,
                              "dav: fstatat fatal '%s' (dirfd=%d)",
                              namebuf, dirfd);
                closedir(d);
                return NGX_ERROR;
            }
            ngx_log_error(NGX_LOG_WARN, r->connection->log, ferr,
                          "dav: fstatat failed, skipping '%s' (dirfd=%d)",
                          namebuf, dirfd);
            /* skip this entry and continue; do not abort the whole removal */
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            /* open child directory and recurse */
            int childfd = openat(dirfd, namebuf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (childfd == -1) {
                int err = ngx_errno;
                if (err == EACCES || err == EPERM) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                                  "dav: openat(child) fatal '%s'", namebuf);
                    closedir(d);
                    return NGX_ERROR;
                }
                ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                              "dav: openat(child) failed, skipping '%s'", namebuf);
                continue;
            }

            if (ngx_http_dav_remove_tree_fd(r, childfd) != NGX_OK) {
                close(childfd);
                /* on recursion failure, skip and continue rather than aborting whole tree */
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "dav: recursive remove failed for '%s', skipping", namebuf);
                continue;
            }

            close(childfd);

            /* remove directory by name from parent fd */
            int attempts = 0;
            while (unlinkat(dirfd, namebuf, AT_REMOVEDIR) == -1) {
                int err = ngx_errno;
                ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                              "dav: unlinkat(AT_REMOVEDIR) failed (attempt %d) '%s'", attempts+1, namebuf);
                if (err == EACCES || err == EPERM) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                                  "dav: unlinkat fatal '%s'", namebuf);
                    closedir(d);
                    return NGX_ERROR;
                }
                if (err != ENOTEMPTY && err != EBUSY && err != EAGAIN && err != EINTR) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                                  "dav: unlinkat permanent failure, skipping '%s'", namebuf);
                    break; /* give up on this entry and continue */
                }
                if (++attempts > 5) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                                  "dav: unlinkat retry exhausted, skipping '%s'", namebuf);
                    break;
                }
                ngx_msleep(10);
            }
        } else {
            int attempts = 0;
            while (unlinkat(dirfd, namebuf, 0) == -1) {
                int err = ngx_errno;
                ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                              "dav: unlinkat failed (attempt %d) '%s'", attempts+1, namebuf);
                if (err == EACCES || err == EPERM) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                                  "dav: unlinkat fatal '%s'", namebuf);
                    closedir(d);
                    return NGX_ERROR;
                }
                if (err != EBUSY && err != EAGAIN && err != EINTR) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                                  "dav: unlinkat permanent failure, skipping '%s'", namebuf);
                    break; /* skip this entry and continue */
                }
                if (++attempts > 5) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
                                  "dav: unlinkat retry exhausted, skipping '%s'", namebuf);
                    break;
                }
                ngx_msleep(10);
            }
        }
    }

    closedir(d);
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
        || ngx_http_dav_lname_eq(name->data, name->len, "getcontenttype"))
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
ngx_http_dav_props_path(ngx_http_request_t *r, ngx_str_t *path, ngx_str_t *ppath)
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
ngx_http_dav_read_props_blob(ngx_http_request_t *r, ngx_str_t *ppath, ngx_str_t *out)
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
ngx_http_dav_props_path_fs(ngx_pool_t *pool, const ngx_str_t *path, ngx_str_t *ppath)
{
    size_t path_len, end, slash, base_len, out_len;
    u_char *out, *p;
    ngx_str_t base;

    path_len = path->len;
    if (path_len && path->data[path_len - 1] == '\0') {
        path_len--;
    }

    end = path_len;
    while (end > 1 && path->data[end - 1] == '/') {
        end--;
    }

    slash = end;
    while (slash > 0 && path->data[slash - 1] != '/') {
        slash--;
    }

    if (slash == 0) {
        return NGX_ERROR;
    }

    base.data = (u_char *) path->data + slash;
    base.len = end - slash;
    if (base.len == 0) {
        ngx_str_set(&base, "root");
    }

    base_len = slash;
    out_len = base_len + (sizeof(".props/") - 1) + base.len + (sizeof(".props") - 1);

    out = ngx_pnalloc(pool, out_len + 1);
    if (out == NULL) {
        return NGX_ERROR;
    }

    p = out;
    p = ngx_cpymem(p, path->data, base_len);
    p = ngx_cpymem(p, ".props/", sizeof(".props/") - 1);
    p = ngx_cpymem(p, base.data, base.len);
    p = ngx_cpymem(p, ".props", sizeof(".props") - 1);
    *p = '\0';

    ppath->data = out;
    ppath->len = out_len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_sync_dead_props_between_paths(ngx_http_request_t *r, ngx_str_t *src_path,
    ngx_str_t *dst_path, ngx_flag_t move)
{
    ngx_str_t src_ppath, dst_ppath, blob;

    if (ngx_http_dav_props_path_fs(r->pool, src_path, &src_ppath) != NGX_OK
        || ngx_http_dav_props_path_fs(r->pool, dst_path, &dst_ppath) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_dav_read_props_blob(r, &src_ppath, &blob) != NGX_OK) {
        return NGX_ERROR;
    }

    if (blob.len == 0 || blob.data == NULL) {
        (void) ngx_delete_file(dst_ppath.data);
        ngx_http_dav_prune_props_dirs(r, &dst_ppath);
        if (move) {
            (void) ngx_delete_file(src_ppath.data);
            ngx_http_dav_prune_props_dirs(r, &src_ppath);
        }
        return NGX_OK;
    }

    if (ngx_http_dav_write_props_blob(r, &dst_ppath, &blob) != NGX_OK) {
        return NGX_ERROR;
    }

    if (move) {
        (void) ngx_delete_file(src_ppath.data);
        ngx_http_dav_prune_props_dirs(r, &src_ppath);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_sync_dead_props_tree(ngx_http_request_t *r, const char *src,
    const char *dst, ngx_flag_t move)
{
    ngx_str_t s, d;
    struct stat st;
    DIR *dir;
    struct dirent *ent;

    s.data = (u_char *) src;
    s.len = ngx_strlen(src);
    d.data = (u_char *) dst;
    d.len = ngx_strlen(dst);

    if (ngx_http_dav_sync_dead_props_between_paths(r, &s, &d, move) != NGX_OK) {
        return NGX_ERROR;
    }

    if (lstat(src, &st) == -1) {
        return NGX_ERROR;
    }

    if (!S_ISDIR(st.st_mode)) {
        return NGX_OK;
    }

    dir = opendir(src);
    if (dir == NULL) {
        return NGX_ERROR;
    }

    while ((ent = readdir(dir)) != NULL) {
        size_t slen, dlen, nlen;
        size_t src_entry_len, dst_entry_len;
        char *src_entry, *dst_entry;
        struct stat est;

        if (ngx_strcmp(ent->d_name, ".") == 0 || ngx_strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (ngx_strcmp(ent->d_name, ".props") == 0) {
            continue;
        }

        nlen = strnlen(ent->d_name, NAME_MAX + 1);
        if (nlen == 0 || nlen > NAME_MAX) {
            continue;
        }

        slen = ngx_strlen(src);
        dlen = ngx_strlen(dst);

        src_entry_len = slen + 1 + nlen + 1;
        src_entry = ngx_pnalloc(r->pool, src_entry_len);
        if (src_entry == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }
        ngx_snprintf((u_char *) src_entry, src_entry_len, "%s/%s", src, ent->d_name);

        dst_entry_len = dlen + 1 + nlen + 1;
        dst_entry = ngx_pnalloc(r->pool, dst_entry_len);
        if (dst_entry == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }
        ngx_snprintf((u_char *) dst_entry, dst_entry_len, "%s/%s", dst, ent->d_name);

        if (lstat(src_entry, &est) == -1) {
            closedir(dir);
            return NGX_ERROR;
        }

        if (!(S_ISDIR(est.st_mode) || S_ISREG(est.st_mode))) {
            continue;
        }

        if (ngx_http_dav_sync_dead_props_tree(r, src_entry, dst_entry, move) != NGX_OK) {
            closedir(dir);
            return NGX_ERROR;
        }
    }

    closedir(dir);

    return NGX_OK;
}

static void
ngx_http_dav_prune_props_dirs(ngx_http_request_t *r, ngx_str_t *ppath)
{
    u_char *dir, *p, *slash;
    size_t len;

    dir = ngx_pnalloc(r->pool, ppath->len + 1);
    if (dir == NULL) {
        return;
    }

    p = ngx_cpymem(dir, ppath->data, ppath->len);
    *p = '\0';

    slash = p;
    while (slash > dir && *(slash - 1) != '/') {
        slash--;
    }
    if (slash == dir) {
        return;
    }

    *(slash - 1) = '\0';
    len = (size_t) ((slash - 1) - dir);

    while (len > 0) {
        u_char *base = dir + len;
        while (base > dir && *(base - 1) != '/') {
            base--;
        }

        if (ngx_delete_dir((char *) dir) == NGX_FILE_ERROR) {
            if (ngx_errno == ENOTEMPTY || ngx_errno == NGX_EEXIST || ngx_errno == EACCES || ngx_errno == EPERM) {
                break;
            }
            break;
        }

        if (ngx_strcmp(base, ".props") == 0) {
            break;
        }

        if (base == dir) {
            break;
        }

        *(base - 1) = '\0';
        len = (size_t) ((base - 1) - dir);
    }
}

static void
ngx_http_dav_delete_dead_props_for_path(ngx_http_request_t *r, ngx_str_t *path)
{
    ngx_str_t ppath;

    if (ngx_http_dav_props_path_fs(r->pool, path, &ppath) == NGX_OK) {
        (void) ngx_delete_file(ppath.data);
        ngx_http_dav_prune_props_dirs(r, &ppath);
    }
}

static ngx_int_t
ngx_http_dav_write_props_blob(ngx_http_request_t *r, ngx_str_t *ppath, ngx_str_t *data)
{
    ssize_t                   n;
    ngx_file_t                file;
    u_char                   *dir;
    u_char                   *last;

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
        (void) ngx_create_full_path(dir, 0700);
    }

    file.fd = ngx_open_file(ppath->data, NGX_FILE_WRONLY,
                            NGX_FILE_TRUNCATE, 0600);
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

static ngx_flag_t
ngx_http_dav_dead_props_contains(ngx_http_dav_dead_props_t *dead,
    const ngx_str_t *name)
{
    return (ngx_http_dav_dead_props_find(dead, name) >= 0);
}

static ngx_int_t
ngx_http_dav_dead_props_find(ngx_http_dav_dead_props_t *dead, const ngx_str_t *name)
{
    ngx_uint_t i;

    for (i = 0; i < dead->n; i++) {
        if (ngx_http_dav_str_ieq(&dead->names[i], name)) {
            return (ngx_int_t) i;
        }
    }

    return -1;
}

static ngx_int_t
ngx_http_dav_xml_rewrite_to_d_namespace(ngx_pool_t *pool, const ngx_str_t *src,
    ngx_str_t *dst)
{
    size_t i, j, k, lname_start;
    ngx_flag_t closing, self_closing;
    u_char *out, *p;

    if (src == NULL || src->data == NULL || src->len == 0) {
        dst->data = NULL;
        dst->len = 0;
        return NGX_OK;
    }

    out = ngx_pnalloc(pool, src->len * 2 + 16);
    if (out == NULL) {
        return NGX_ERROR;
    }

    p = out;
    i = 0;
    while (i < src->len) {
        if (src->data[i] != '<') {
            *p++ = src->data[i++];
            continue;
        }

        *p++ = '<';
        i++;
        if (i >= src->len) {
            return NGX_ERROR;
        }

        if (src->data[i] == '!' || src->data[i] == '?') {
            while (i < src->len) {
                *p++ = src->data[i];
                if (src->data[i] == '>') {
                    i++;
                    break;
                }
                i++;
            }
            continue;
        }

        closing = 0;
        if (src->data[i] == '/') {
            closing = 1;
            *p++ = '/';
            i++;
        }

        while (i < src->len && (src->data[i] == ' ' || src->data[i] == '\t'
               || src->data[i] == '\r' || src->data[i] == '\n'))
        {
            i++;
        }

        j = i;
        while (j < src->len && ngx_http_dav_tag_name_char(src->data[j])) {
            j++;
        }
        if (j == i) {
            return NGX_ERROR;
        }

        lname_start = i;
        for (k = i; k < j; k++) {
            if (src->data[k] == ':') {
                lname_start = k + 1;
            }
        }

        *p++ = 'D';
        *p++ = ':';
        p = ngx_cpymem(p, src->data + lname_start, j - lname_start);

        self_closing = 0;
        i = j;
        while (i < src->len && src->data[i] != '>') {
            if (src->data[i] == '"' || src->data[i] == '\'') {
                u_char q = src->data[i++];
                while (i < src->len && src->data[i] != q) {
                    i++;
                }
                if (i < src->len) {
                    i++;
                }
                continue;
            }
            if (src->data[i] == '/' && i + 1 < src->len && src->data[i + 1] == '>') {
                self_closing = 1;
                i += 2;
                break;
            }
            i++;
        }

        if (!self_closing) {
            if (i >= src->len || src->data[i] != '>') {
                return NGX_ERROR;
            }
            i++;
        }

        if (!closing && self_closing) {
            *p++ = '/';
        }
        *p++ = '>';
    }

    dst->data = out;
    dst->len = (size_t) (p - out);
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_dead_props_add(ngx_http_request_t *r, ngx_http_dav_dead_props_t *dead,
    const ngx_str_t *name, const ngx_str_t *xml)
{
    size_t i;
    u_char *p, *x;
    ngx_int_t idx;
    ngx_str_t normalized;

    idx = ngx_http_dav_dead_props_find(dead, name);
    if (idx >= 0) {
        if (xml != NULL && xml->len > 0) {
            if (ngx_http_dav_xml_rewrite_to_d_namespace(r->pool, xml,
                                                        &normalized)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            dead->xml[idx] = normalized;
        }
        return NGX_OK;
    }

    if (dead->n >= NGX_DAV_PROPPATCH_PROPS_MAX) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, name->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < name->len; i++) {
        u_char c = name->data[i];
        if (c >= 'A' && c <= 'Z') {
            c = (u_char) (c - 'A' + 'a');
        }
        p[i] = c;
    }

    dead->names[dead->n].data = p;
    dead->names[dead->n].len = name->len;

    if (xml != NULL && xml->len > 0) {
        if (ngx_http_dav_xml_rewrite_to_d_namespace(r->pool, xml,
                                                    &normalized)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        dead->xml[dead->n] = normalized;
    } else {
        size_t xl = sizeof("<D:" ) - 1 + name->len + sizeof("/>" ) - 1;
        x = ngx_pnalloc(r->pool, xl);
        if (x == NULL) {
            return NGX_ERROR;
        }
        x = ngx_cpymem(x, "<D:", sizeof("<D:") - 1);
        x = ngx_cpymem(x, name->data, name->len);
        x = ngx_cpymem(x, "/>", sizeof("/>") - 1);
        dead->xml[dead->n].data = x - xl;
        dead->xml[dead->n].len = xl;
    }

    dead->n++;

    return NGX_OK;
}

static void
ngx_http_dav_dead_props_remove(ngx_http_dav_dead_props_t *dead, const ngx_str_t *name)
{
    ngx_uint_t i;

    for (i = 0; i < dead->n; ) {
        if (ngx_http_dav_str_ieq(&dead->names[i], name)) {
            if (i + 1 < dead->n) {
                dead->names[i] = dead->names[dead->n - 1];
                dead->xml[i] = dead->xml[dead->n - 1];
            }
            dead->n--;
            continue;
        }
        i++;
    }
}

static ngx_int_t
ngx_http_dav_dead_props_load(ngx_http_request_t *r, ngx_str_t *path,
    ngx_http_dav_dead_props_t *dead)
{
    ngx_str_t ppath, raw;
    ngx_str_t name, xml;
    size_t start, end, i, line_end;
    size_t name_start, name_end, lname_start;
    u_char *line;

    dead->n = 0;

    if (ngx_http_dav_props_path(r, path, &ppath) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_dav_read_props_blob(r, &ppath, &raw) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (raw.len == 0 || raw.data == NULL) {
        return NGX_OK;
    }

    start = 0;
    while (start < raw.len) {
        end = start;
        while (end < raw.len && raw.data[end] != '\n') {
            end++;
        }

        line_end = end;

        i = start;
        while (i < end && (raw.data[i] == ' ' || raw.data[i] == '\t' || raw.data[i] == '\r')) {
            i++;
        }

        while (end > i && (raw.data[end - 1] == ' ' || raw.data[end - 1] == '\t' || raw.data[end - 1] == '\r')) {
            end--;
        }

        if (end > i) {
            line = raw.data + i;

            if (*line == '<') {
                name_start = i + 1;
                if (name_start < end && raw.data[name_start] == '/') {
                    name_start++;
                }
                name_end = name_start;
                while (name_end < end && ngx_http_dav_tag_name_char(raw.data[name_end])) {
                    name_end++;
                }

                lname_start = name_start;
                while (lname_start < name_end) {
                    if (raw.data[lname_start] == ':') {
                        lname_start++;
                    } else {
                        break;
                    }
                }
                {
                    size_t k;
                    for (k = name_start; k < name_end; k++) {
                        if (raw.data[k] == ':') {
                            lname_start = k + 1;
                        }
                    }
                }

                if (name_end > lname_start) {
                    name.data = raw.data + lname_start;
                    name.len = name_end - lname_start;
                    xml.data = raw.data + i;
                    xml.len = end - i;
                    if (ngx_http_dav_dead_props_add(r, dead, &name, &xml) != NGX_OK) {
                        return NGX_HTTP_INSUFFICIENT_STORAGE;
                    }
                }

            } else {
                name.data = raw.data + i;
                name.len = end - i;
                if (ngx_http_dav_dead_props_add(r, dead, &name, NULL) != NGX_OK) {
                    return NGX_HTTP_INSUFFICIENT_STORAGE;
                }
            }

            if (dead->n > NGX_DAV_PROPPATCH_PROPS_MAX) {
                return NGX_HTTP_INSUFFICIENT_STORAGE;
            }
        }

        start = line_end;
        if (start < raw.len && raw.data[start] == '\n') {
            start++;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_dead_props_save(ngx_http_request_t *r, ngx_str_t *path,
    ngx_http_dav_dead_props_t *dead)
{
    ngx_str_t ppath, data;
    u_char *p;
    ngx_uint_t i;
    size_t len = 0;

    if (ngx_http_dav_props_path(r, path, &ppath) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (dead->n == 0) {
        (void) ngx_delete_file(ppath.data);
        return NGX_OK;
    }

    for (i = 0; i < dead->n; i++) {
        len += dead->xml[i].len + 1;
    }

    data.data = ngx_pnalloc(r->pool, len);
    if (data.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = data.data;
    for (i = 0; i < dead->n; i++) {
        p = ngx_cpymem(p, dead->xml[i].data, dead->xml[i].len);
        *p++ = '\n';
    }

    data.len = p - data.data;

    if (ngx_http_dav_write_props_blob(r, &ppath, &data) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
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
        while (k < len && data[k] != '>') {
            if (data[k] == '/') {
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
    ngx_chain_t ***ll, off_t *total, ngx_http_dav_propfind_req_t *preq,
    ngx_http_dav_dead_props_t *dead)
{
    ngx_uint_t i;
    ngx_uint_t found = 0;
    ngx_uint_t missing = 0;

    if (preq->mode != NGX_DAV_PROPFIND_PROP || preq->unknown_n == 0) {
        return NGX_OK;
    }

    for (i = 0; i < preq->unknown_n; i++) {
        if (dead != NULL && ngx_http_dav_dead_props_contains(dead, &preq->unknown[i])) {
            found++;
        } else {
            missing++;
        }
    }

    if (found > 0) {
        ngx_int_t idx;

        if (ngx_http_dav_chain_append(r, ll, total,
                (const u_char *) "<D:propstat>\n<D:prop>\n",
                sizeof("<D:propstat>\n<D:prop>\n") - 1) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        for (i = 0; i < preq->unknown_n; i++) {
            if (dead == NULL || !ngx_http_dav_dead_props_contains(dead, &preq->unknown[i])) {
                continue;
            }

            idx = ngx_http_dav_dead_props_find(dead, &preq->unknown[i]);
            if (idx < 0) {
                continue;
            }

            if (ngx_http_dav_chain_append(r, ll, total,
                    dead->xml[idx].data, dead->xml[idx].len) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_http_dav_chain_append(r, ll, total,
                    (const u_char *) "\n", sizeof("\n") - 1) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (ngx_http_dav_chain_append(r, ll, total,
                (const u_char *) "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n",
                sizeof("</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n") - 1) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (missing > 0) {
        if (ngx_http_dav_chain_append(r, ll, total,
                (const u_char *) "<D:propstat>\n<D:prop>\n",
                sizeof("<D:propstat>\n<D:prop>\n") - 1) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        for (i = 0; i < preq->unknown_n; i++) {
            if (dead != NULL && ngx_http_dav_dead_props_contains(dead, &preq->unknown[i])) {
                continue;
            }

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

        if (ngx_http_dav_chain_append(r, ll, total,
                (const u_char *) "</D:prop>\n<D:status>HTTP/1.1 404 Not Found</D:status>\n</D:propstat>\n",
                sizeof("</D:prop>\n<D:status>HTTP/1.1 404 Not Found</D:status>\n</D:propstat>\n") - 1) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
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

            ngx_str_t child_uri;
            child_uri.data = href_raw;
            child_uri.len = href_len;

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
        bit = 0x01;
    } else if (r->method == NGX_HTTP_DELETE) {
        bit = 0x02;
    } else if (r->method == NGX_HTTP_OPTIONS) {
        bit = 0x80;
    } else if (r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0) {
        bit = 0x04;
    } else if (r->method_name.len == 8 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPFIND", 8) == 0) {
        bit = 0x20;
    } else if (r->method_name.len == 9 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPPATCH", 9) == 0) {
        bit = 0x40;
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
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
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
    ngx_http_dav_dead_props_t dead_props;

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
        ngx_int_t drc;

        dead_props.n = 0;
        drc = ngx_http_dav_dead_props_load(r, &path, &dead_props);
        if (drc != NGX_OK) {
            return drc;
        }

        for (i = 0; i < preq.props_n; i++) {
            if (preq.ops[i] == NGX_DAV_PROPPATCH_OP_SET) {
                if (ngx_http_dav_dead_props_add(r, &dead_props,
                                               &preq.props[i],
                                               &preq.prop_xml[i]) != NGX_OK)
                {
                    return NGX_HTTP_INSUFFICIENT_STORAGE;
                }
            } else if (preq.ops[i] == NGX_DAV_PROPPATCH_OP_REMOVE) {
                ngx_http_dav_dead_props_remove(&dead_props, &preq.props[i]);
            }
        }

        drc = ngx_http_dav_dead_props_save(r, &path, &dead_props);
        if (drc != NGX_OK) {
            return drc;
        }

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

    if (methods & 0x01) {
        len += sizeof(", PUT") - 1;
    }
    if (methods & 0x02) {
        len += sizeof(", DELETE") - 1;
    }
    if (methods & 0x04) {
        len += sizeof(", MKCOL") - 1;
    }
    if (methods & 0x08) {
        len += sizeof(", COPY") - 1;
    }
    if (methods & 0x10) {
        len += sizeof(", MOVE") - 1;
    }
    if (methods & 0x20) {
        len += sizeof(", PROPFIND") - 1;
    }
    if (methods & 0x40) {
        len += sizeof(", PROPPATCH") - 1;
    }

    allow.data = ngx_pnalloc(r->pool, len);
    if (allow.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(allow.data, "OPTIONS", sizeof("OPTIONS") - 1);

    if (methods & 0x01) {
        p = ngx_cpymem(p, ", PUT", sizeof(", PUT") - 1);
    }
    if (methods & 0x02) {
        p = ngx_cpymem(p, ", DELETE", sizeof(", DELETE") - 1);
    }
    if (methods & 0x04) {
        p = ngx_cpymem(p, ", MKCOL", sizeof(", MKCOL") - 1);
    }
    if (methods & 0x08) {
        p = ngx_cpymem(p, ", COPY", sizeof(", COPY") - 1);
    }
    if (methods & 0x10) {
        p = ngx_cpymem(p, ", MOVE", sizeof(", MOVE") - 1);
    }
    if (methods & 0x20) {
        p = ngx_cpymem(p, ", PROPFIND", sizeof(", PROPFIND") - 1);
    }
    if (methods & 0x40) {
        p = ngx_cpymem(p, ", PROPPATCH", sizeof(", PROPPATCH") - 1);
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
    ngx_str_set(&h->value, "1");

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
                ngx_http_dav_delete_dead_props_for_path(r, &path);
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
            ngx_http_dav_delete_dead_props_for_path(r, &path);
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
            if (ngx_create_full_path(path.data, dlcf->access_dir_mode) == NGX_FILE_ERROR) {
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
    if (mkdir((char *) path.data, dlcf->access_dir_mode) == 0) {
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
    ngx_http_dav_dead_props_t dead_props;
    ngx_http_dav_dead_props_t *dead_ptr = NULL;
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

    dead_props.n = 0;
    if ((preq.mode == NGX_DAV_PROPFIND_PROP && preq.unknown_n > 0)
        || preq.mode == NGX_DAV_PROPFIND_ALLPROP
        || preq.mode == NGX_DAV_PROPFIND_PROPNAME)
    {
        ngx_int_t drc = ngx_http_dav_dead_props_load(r, &path, &dead_props);
        if (drc != NGX_OK) {
            return drc;
        }
        dead_ptr = &dead_props;
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

        if (dead_ptr != NULL
            && (preq.mode == NGX_DAV_PROPFIND_ALLPROP
                || preq.mode == NGX_DAV_PROPFIND_PROPNAME))
        {
            for (i = 0; i < dead_ptr->n; i++) {
                if (ngx_http_dav_is_live_prop(&dead_ptr->names[i])) {
                    continue;
                }

                if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                    NGX_DAV_XML_APPEND_LIT("<D:");
                    NGX_DAV_XML_APPEND_BUF(dead_ptr->names[i].data,
                                           dead_ptr->names[i].len);
                    NGX_DAV_XML_APPEND_LIT("/>\n");
                } else {
                    NGX_DAV_XML_APPEND_BUF(dead_ptr->xml[i].data,
                                           dead_ptr->xml[i].len);
                    NGX_DAV_XML_APPEND_LIT("\n");
                }
            }
        }

        NGX_DAV_XML_APPEND_LIT("</D:prop>\n");
        NGX_DAV_XML_APPEND_LIT("<D:status>HTTP/1.1 200 OK</D:status>\n");
        NGX_DAV_XML_APPEND_LIT("</D:propstat>\n");
    }

    {
        ngx_int_t urc = ngx_http_dav_propfind_append_unknown_propstat(r, &ll,
                                                                       &content_length,
                                                                       &preq,
                                                                       dead_ptr);
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
    ngx_str_t src, dst, dest_uri;
    ngx_uint_t overwrite = 1;

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

    {
        ngx_int_t depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
        if (depth != NGX_HTTP_DAV_INFINITY_DEPTH && depth != NGX_HTTP_DAV_ZERO_DEPTH) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    {
        ngx_int_t orc = ngx_http_dav_parse_overwrite(r, &overwrite);
        if (orc != NGX_OK) {
            return orc;
        }
    }

    {
        ngx_int_t drc = ngx_http_dav_parse_destination(r, &dest_uri);
        if (drc != NGX_OK) {
            return drc;
        }
    }

    ngx_file_info_t sst_src;
    {
        ngx_int_t src_rc = ngx_http_dav_prepare_source_path(r, &src, &sst_src, 0);
        if (src_rc != NGX_OK) {
            return src_rc;
        }
    }

    {
        ngx_int_t mrc = ngx_http_dav_map_destination_path(r, &dest_uri, &dst);
        if (mrc != NGX_OK) {
            return mrc;
        }
    }

    if (src.len == dst.len && ngx_strncmp(src.data, dst.data, src.len) == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    {
        ngx_int_t prc = ngx_http_dav_prepare_destination_parent(r, &dst, dlcf);
        if (prc != NGX_OK) {
            return prc;
        }
    }

    ngx_file_info_t dstst;
    ngx_flag_t dest_exists = (ngx_file_info((char *) dst.data, &dstst) == 0);
    ngx_flag_t had_dest_before = dest_exists;

    if (dest_exists && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    if (dest_exists && overwrite) {
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
        if (ngx_http_dav_copy_dir(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_http_dav_sync_dead_props_tree(r, (char *) src.data,
                                              (char *) dst.data, 0) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else if (S_ISREG(sst_src.st_mode)) {
        if (ngx_http_dav_copy_file_atomic(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 0) != NGX_OK) {
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
    ngx_str_t src, dst, dest_uri;
    ngx_file_info_t src_st;
    ngx_uint_t overwrite = 1;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    {
        ngx_int_t depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
        if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    {
        ngx_int_t orc = ngx_http_dav_parse_overwrite(r, &overwrite);
        if (orc != NGX_OK) {
            return orc;
        }
    }

    {
        ngx_int_t drc = ngx_http_dav_parse_destination(r, &dest_uri);
        if (drc != NGX_OK) {
            return drc;
        }
    }

    {
        ngx_int_t src_rc = ngx_http_dav_prepare_source_path(r, &src, &src_st, 1);
        if (src_rc != NGX_OK) {
            return src_rc;
        }
    }

    {
        ngx_int_t mrc = ngx_http_dav_map_destination_path(r, &dest_uri, &dst);
        if (mrc != NGX_OK) {
            return mrc;
        }
    }

    {
        ngx_int_t prc = ngx_http_dav_prepare_destination_parent(r, &dst, dlcf);
        if (prc != NGX_OK) {
            return prc;
        }
    }

    /* destination existence */
    ngx_file_info_t fi;
    ngx_flag_t dest_exists = (ngx_file_info((char *) dst.data, &fi) == 0);
    if (dest_exists && !overwrite) return NGX_HTTP_PRECONDITION_FAILED;
    ngx_ext_rename_file_t ext;
    ext.access = 0;
    ext.path_access = dlcf->access_dir_mode;
    ext.time = -1;
    ext.create_path = dlcf->create_full_path;
    ext.delete_file = 0; /* do not delete source on failure */
    ext.log = r->connection->log;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "dav: MOVE attempt src='%V' dst='%V' overwrite=%d",
                  &src, &dst, (int) overwrite);

    /* Pre-emptive handling for directory overwrite: remove existing dst and rename. */
    if (dest_exists && overwrite && S_ISDIR(src_st.st_mode)) {
            if (ngx_http_dav_remove_tree(r, (char *) dst.data) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: remove dst tree failed '%V'", &dst);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_ext_rename_file(&src, &dst, &ext) == NGX_OK) {
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "dav: MOVE success src='%V' dst='%V'", &src, &dst);
                if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                return NGX_HTTP_NO_CONTENT;
            }

            if (ngx_errno == EXDEV) {
                if (ngx_http_dav_copy_dir(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (ngx_http_dav_remove_tree(r, (char *) src.data) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: remove src tree failed '%V'", &src);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                return NGX_HTTP_NO_CONTENT;
            }

            if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
            if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_ext_rename_file(&src, &dst, &ext) != NGX_OK) {
        /* cross-device link? try copy+unlink fallback */
        if (ngx_errno == EXDEV) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
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
                if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
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
            if (fchmod(outfd, dlcf->access_file_mode) == -1) {
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

            if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return dest_exists ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
        }

        /* if destination exists and overwrite requested, try remove dst then retry */
        if ((ngx_errno == EEXIST || ngx_errno == ENOTEMPTY) && dest_exists && overwrite) {
            /* perform atomic replace: handle directories specially, files via temp-file replace */

            /* check if source is a directory (handle directory overwrite by removing dst then rename/copy) */
            {
                if (S_ISDIR(src_st.st_mode)) {
                    /* remove existing destination tree to allow rename into place */
                    if (ngx_http_dav_remove_tree(r, (char *) dst.data) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: remove dst tree failed '%V'", &dst);
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    /* try rename now that dst removed */
                    if (ngx_ext_rename_file(&src, &dst, &ext) == NGX_OK) {
                        if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                        return NGX_HTTP_NO_CONTENT;
                    }

                    /* if rename still fails due to EXDEV, fall back to recursive copy */
                    if (ngx_errno == EXDEV) {
                        if (ngx_http_dav_copy_dir(r, (char *) src.data, (char *) dst.data) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                        if (ngx_http_dav_remove_tree(r, (char *) src.data) != NGX_OK) {
                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: remove src tree failed '%V'", &src);
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                        if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                        return NGX_HTTP_NO_CONTENT;
                    }

                    /* map other errno */
                    if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
                    if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            /* perform atomic replace for regular files: copy src -> temp in dst dir, rename temp->dst */
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
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
            if (fchmod(outfd, dlcf->access_file_mode) == -1) { close(infd); close(outfd); ngx_delete_file(tmp_path); return NGX_HTTP_INTERNAL_SERVER_ERROR; }

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

            if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_HTTP_NO_CONTENT;
        }

        /* map common errno to HTTP */
        if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
        if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "dav: MOVE success src='%V' dst='%V'", &src, &dst);
    if (ngx_http_dav_sync_dead_props_between_paths(r, &src, &dst, 1) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return dest_exists ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

/* Copy a regular file from src -> dst atomically using a temp file in dst's directory. */
static ngx_int_t
ngx_http_dav_copy_file_atomic(ngx_http_request_t *r, const char *src, const char *dst)
{
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

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
    if (fchmod(outfd, dlcf->access_file_mode) == -1) { close(infd); close(outfd); ngx_delete_file(tmp_path); return NGX_ERROR; }

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
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (dlcf == NULL) {
        return NGX_ERROR;
    }

    DIR *d = opendir(src);
    if (d == NULL) return NGX_ERROR;

    struct stat st;
    if (stat(src, &st) == -1) { closedir(d); return NGX_ERROR; }
    if (mkdir(dst, dlcf->access_dir_mode) == -1) {
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
    conf->access_file_mode = NGX_CONF_UNSET_UINT;
    conf->access_dir_mode = NGX_CONF_UNSET_UINT;

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
    ngx_conf_merge_uint_value(conf->access_dir_mode, prev->access_dir_mode, 0700);

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

    /* keep merge phase quiet in production */

    return NGX_CONF_OK;
}

static char *
ngx_conf_set_dav_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dav_loc_conf_t *dlcf = conf;

    if (dlcf->dav_access != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    ngx_str_t *value = cf->args->elts;
    dlcf->dav_access = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
    if (dlcf->dav_access == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_uint_t file_mode = 0;
    ngx_uint_t dir_mode = 0;

    ngx_uint_t i;
    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *entry = &value[i];
        ngx_str_t *dst = ngx_array_push(dlcf->dav_access);
        if (dst == NULL) {
            return NGX_CONF_ERROR;
        }
        *dst = *entry;

        u_char *p = (u_char *) ngx_strlchr(entry->data, entry->data + entry->len, ':');
        if (p == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dav_access token \"%V\"", entry);
            return NGX_CONF_ERROR;
        }

        ngx_str_t who;
        who.data = entry->data;
        who.len = p - entry->data;

        ngx_str_t perm;
        perm.data = p + 1;
        perm.len = entry->len - who.len - 1;

        ngx_uint_t scope = 0;
        if ((who.len == 4 && ngx_strncasecmp(who.data, (u_char *) "user", 4) == 0)
            || (who.len == 1 && (who.data[0] == 'u' || who.data[0] == 'U')))
        {
            scope = 1;
        } else if ((who.len == 5 && ngx_strncasecmp(who.data, (u_char *) "group", 5) == 0)
                   || (who.len == 1 && (who.data[0] == 'g' || who.data[0] == 'G')))
        {
            scope = 2;
        } else if ((who.len == 3 && ngx_strncasecmp(who.data, (u_char *) "all", 3) == 0)
                   || (who.len == 5 && ngx_strncasecmp(who.data, (u_char *) "other", 5) == 0)
                   || (who.len == 1 && (who.data[0] == 'o' || who.data[0] == 'O')))
        {
            scope = 4;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dav_access subject \"%V\"", &who);
            return NGX_CONF_ERROR;
        }

        ngx_uint_t r = 0, w = 0, x = 0;
        ngx_uint_t j;
        for (j = 0; j < perm.len; j++) {
            u_char c = perm.data[j];
            if (c == 'r' || c == 'R') {
                r = 1;
            } else if (c == 'w' || c == 'W') {
                w = 1;
            } else if (c == 'x' || c == 'X') {
                x = 1;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid dav_access permission \"%V\"", &perm);
                return NGX_CONF_ERROR;
            }
        }

        if (scope & 1) {
            if (r) { file_mode |= S_IRUSR; dir_mode |= S_IRUSR; }
            if (w) { file_mode |= S_IWUSR; dir_mode |= S_IWUSR; }
            if (x || r || w) { dir_mode |= S_IXUSR; }
        }
        if (scope & 2) {
            if (r) { file_mode |= S_IRGRP; dir_mode |= S_IRGRP; }
            if (w) { file_mode |= S_IWGRP; dir_mode |= S_IWGRP; }
            if (x || r || w) { dir_mode |= S_IXGRP; }
        }
        if (scope & 4) {
            if (r) { file_mode |= S_IROTH; dir_mode |= S_IROTH; }
            if (w) { file_mode |= S_IWOTH; dir_mode |= S_IWOTH; }
            if (x || r || w) { dir_mode |= S_IXOTH; }
        }
    }

    dlcf->access_file_mode = file_mode;
    dlcf->access_dir_mode = dir_mode;

    return NGX_CONF_OK;
}

static char *
ngx_conf_set_dav_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dav_loc_conf_t *dlcf = conf;

    if (dlcf->methods_mask != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    ngx_str_t *value = cf->args->elts;

    dlcf->dav_methods = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
    if (dlcf->dav_methods == NULL) {
        return NGX_CONF_ERROR;
    }

    dlcf->methods_mask = 0;

    ngx_uint_t i;
    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *m = &value[i];
        ngx_str_t *dst = ngx_array_push(dlcf->dav_methods);
        if (dst == NULL) {
            return NGX_CONF_ERROR;
        }
        *dst = *m;

        if (m->len == 3 && ngx_strncasecmp(m->data, (u_char *)"off", 3) == 0) {
            if (cf->args->nelts != 2) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "dav_methods \"off\" cannot be mixed with other methods");
                return NGX_CONF_ERROR;
            }
            dlcf->methods_mask = 0;
        } else if (m->len == 3 && ngx_strncasecmp(m->data, (u_char *)"PUT", 3) == 0) {
            dlcf->methods_mask |= 0x01;
        } else if (m->len == 6 && ngx_strncasecmp(m->data, (u_char *)"DELETE", 6) == 0) {
            dlcf->methods_mask |= 0x02;
        } else if (m->len == 5 && ngx_strncasecmp(m->data, (u_char *)"MKCOL", 5) == 0) {
            dlcf->methods_mask |= 0x04;
        } else if (m->len == 8 && ngx_strncasecmp(m->data, (u_char *)"PROPFIND", 8) == 0) {
            dlcf->methods_mask |= 0x20;
        } else if (m->len == 9 && ngx_strncasecmp(m->data, (u_char *)"PROPPATCH", 9) == 0) {
            dlcf->methods_mask |= 0x40;
        } else if (m->len == 7 && ngx_strncasecmp(m->data, (u_char *)"OPTIONS", 7) == 0) {
            dlcf->methods_mask |= 0x80;
        } else if (m->len == 4 && ngx_strncasecmp(m->data, (u_char *)"COPY", 4) == 0) {
            dlcf->methods_mask |= 0x08;
        } else if (m->len == 4 && ngx_strncasecmp(m->data, (u_char *)"MOVE", 4) == 0) {
            dlcf->methods_mask |= 0x10;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid dav_methods token \"%V\"", m);
            return NGX_CONF_ERROR;
        }
    }

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
