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

extern ngx_module_t ngx_http_dav_module;

typedef struct ngx_http_dav_propfind_req_s ngx_http_dav_propfind_req_t;

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
static void ngx_http_dav_put_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_propfind_handler(ngx_http_request_t *r);
static void ngx_http_dav_propfind_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_copy_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_move_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_dav_copy_file_atomic(ngx_http_request_t *r, const char *src, const char *dst);
static ngx_int_t ngx_http_dav_copy_dir(ngx_http_request_t *r, const char *src, const char *dst);
static ngx_int_t ngx_http_dav_remove_tree(ngx_http_request_t *r, const char *path);
static ngx_int_t ngx_http_dav_unlink_if_unchanged(ngx_http_request_t *r, const char *path, const ngx_file_info_t *orig_st);
static ngx_str_t ngx_http_dav_xml_escape(ngx_pool_t *pool, const u_char *src, size_t len);
static ngx_int_t ngx_http_dav_chain_append(ngx_http_request_t *r, ngx_chain_t ***ll,
    off_t *total, const u_char *data, size_t len);
static ngx_int_t ngx_http_dav_propfind_collect_body(ngx_http_request_t *r, ngx_str_t *body);
static ngx_int_t ngx_http_dav_propfind_parse_body(const u_char *data, size_t len,
    ngx_http_dav_propfind_req_t *preq);
static ngx_int_t ngx_http_dav_propfind_append_unknown_propstat(ngx_http_request_t *r,
    ngx_chain_t ***ll, off_t *total, ngx_http_dav_propfind_req_t *preq);

#define NGX_DAV_PROPFIND_ALLPROP  0
#define NGX_DAV_PROPFIND_PROPNAME 1
#define NGX_DAV_PROPFIND_PROP     2

#define NGX_DAV_PROP_DISPLAYNAME      0x01
#define NGX_DAV_PROP_RESOURCETYPE     0x02
#define NGX_DAV_PROP_GETCONTENTLENGTH 0x04
#define NGX_DAV_PROP_GETLASTMODIFIED  0x08
#define NGX_DAV_PROP_ALL_KNOWN (NGX_DAV_PROP_DISPLAYNAME | NGX_DAV_PROP_RESOURCETYPE \
    | NGX_DAV_PROP_GETCONTENTLENGTH | NGX_DAV_PROP_GETLASTMODIFIED)

#define NGX_DAV_PROPFIND_UNKNOWN_MAX 32

struct ngx_http_dav_propfind_req_s {
    ngx_uint_t mode;
    ngx_uint_t props_mask;
    ngx_uint_t unknown_n;
    ngx_str_t  unknown[NGX_DAV_PROPFIND_UNKNOWN_MAX];
};

typedef struct {
        ngx_flag_t    create_full_path;
        ngx_array_t  *dav_methods;
        ngx_array_t  *dav_access;
        ngx_uint_t    min_delete_depth;
    ngx_uint_t    methods_mask;
    ngx_uint_t    access_file_mode;
    ngx_uint_t    access_dir_mode;
} ngx_http_dav_loc_conf_t;

typedef struct {
    ngx_flag_t   done;
    ngx_int_t    status;
    ngx_flag_t   propfind_body_attempted;
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
            if (!closing) {
                seen_propfind = 1;
            }
            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "allprop")) {
            if (!closing) {
                seen_allprop = 1;
            }
            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "propname")) {
            if (!closing) {
                seen_propname = 1;
            }
            continue;
        }

        if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "prop")) {
            if (closing) {
                if (prop_depth > 0) {
                    prop_depth--;
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

        if (!closing && prop_depth > 0) {
            if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "displayname")) {
                props_mask |= NGX_DAV_PROP_DISPLAYNAME;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "resourcetype")) {
                props_mask |= NGX_DAV_PROP_RESOURCETYPE;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "getcontentlength")) {
                props_mask |= NGX_DAV_PROP_GETCONTENTLENGTH;
            } else if (ngx_http_dav_lname_eq(data + lname_start, lname_len, "getlastmodified")) {
                props_mask |= NGX_DAV_PROP_GETLASTMODIFIED;
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
    if (preq->mode != NGX_DAV_PROPFIND_PROP || preq->unknown_n == 0) {
        return NGX_OK;
    }

    if (ngx_http_dav_chain_append(r, ll, total,
            (const u_char *) "<D:propstat>\n<D:prop>\n",
            sizeof("<D:propstat>\n<D:prop>\n") - 1) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_uint_t i;
    for (i = 0; i < preq->unknown_n; i++) {
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
    } else if (r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0) {
        bit = 0x04;
    } else if (r->method_name.len == 8 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPFIND", 8) == 0) {
        bit = 0x20;
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

    if (r->method_name.len == 5 && ngx_strncasecmp(r->method_name.data, (u_char *)"MKCOL", 5) == 0) {
        return ngx_http_dav_mkcol_handler(r);
    }
    if (r->method_name.len == 8 && ngx_strncasecmp(r->method_name.data, (u_char *)"PROPFIND", 8) == 0) {
        return ngx_http_dav_propfind_handler(r);
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
    ngx_uint_t                depth = 0;
    char                      timebuf[64];
    size_t                    time_len = 0;
    u_char                   *clen = (u_char *) "0";
    size_t                    clen_len = 1;
    u_char                   *rtype = (u_char *) "";
    ngx_str_t                 href_esc;
    ngx_str_t                 disp_esc;
    off_t                     content_length = 0;
    ngx_http_dav_propfind_req_t preq;
    ngx_str_t                 req_body;
    ngx_http_dav_ctx_t       *ctx;

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
        ngx_str_t depth_value = ngx_null_string;
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

            if (h[i].key.len == 5
                && ngx_strncasecmp(h[i].key.data, (u_char *) "Depth", 5) == 0)
            {
                depth_value = h[i].value;
                break;
            }

            i++;
        }

        if (depth_value.len != 0) {
            if (depth_value.len == 1 && depth_value.data[0] == '0') {
                depth = 0;
            } else if (depth_value.len == 1 && depth_value.data[0] == '1') {
                depth = 1;
            } else if (depth_value.len == 8
                       && ngx_strncasecmp(depth_value.data,
                                          (u_char *) "infinity", 8) == 0)
            {
                return NGX_HTTP_BAD_REQUEST;
            } else {
                return NGX_HTTP_BAD_REQUEST;
            }
        }
    }

    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &path, &root_len, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_file_info((char *) path.data, &sb) == NGX_FILE_ERROR) {
        if (ngx_errno == ENOENT) {
            return NGX_HTTP_NOT_FOUND;
        }
        if (ngx_errno == EACCES || ngx_errno == EPERM) {
            return NGX_HTTP_FORBIDDEN;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        u_char *tlast = ngx_http_time((u_char *) timebuf, sb.st_mtime);
        time_len = (size_t) (tlast - (u_char *) timebuf);
    }

    if (S_ISDIR(sb.st_mode)) {
        rtype = (u_char *) "<D:collection/>";
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

    disp_esc = ngx_http_dav_xml_escape(r->pool, r->uri.data, r->uri.len);
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

    if (depth == 1 && S_ISDIR(sb.st_mode)) {
        DIR *d = opendir((char *) path.data);
        if (d == NULL) {
            if (errno == EACCES || errno == EPERM) {
                return NGX_HTTP_FORBIDDEN;
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

            char ctimebuf[64];
            size_t ctime_len = 0;
            {
                u_char *ctlast = ngx_http_time((u_char *) ctimebuf, csb.st_mtime);
                ctime_len = (size_t) (ctlast - (u_char *) ctimebuf);
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

            size_t urilen = r->uri.len;
            ngx_flag_t has_trailing = (urilen > 0 && r->uri.data[urilen - 1] == '/');

            size_t href_len = urilen + (has_trailing ? 0 : 1) + nlen + (S_ISDIR(csb.st_mode) ? 1 : 0);
            u_char *href_raw = ngx_pnalloc(r->pool, href_len + 1);
            if (href_raw == NULL) {
                closedir(d);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (has_trailing) {
                (void) ngx_snprintf(href_raw, href_len + 1, "%V%s%s", &r->uri,
                                    namebuf, S_ISDIR(csb.st_mode) ? "/" : "");
            } else {
                (void) ngx_snprintf(href_raw, href_len + 1, "%V/%s%s", &r->uri,
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

            NGX_DAV_XML_APPEND_LIT("<D:response>\n");
            NGX_DAV_XML_APPEND_LIT("<D:href>");
            NGX_DAV_XML_APPEND_BUF(child_href_esc.data, child_href_esc.len);
            NGX_DAV_XML_APPEND_LIT("</D:href>\n");
            if (preq.mode != NGX_DAV_PROPFIND_PROP || preq.props_mask != 0) {
                NGX_DAV_XML_APPEND_LIT("<D:propstat>\n");
                NGX_DAV_XML_APPEND_LIT("<D:prop>\n");
                if (preq.props_mask & NGX_DAV_PROP_DISPLAYNAME) {
                    if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                        NGX_DAV_XML_APPEND_LIT("<D:displayname/>\n");
                    } else {
                        NGX_DAV_XML_APPEND_LIT("<D:displayname>");
                        NGX_DAV_XML_APPEND_BUF(child_disp_esc.data, child_disp_esc.len);
                        NGX_DAV_XML_APPEND_LIT("</D:displayname>\n");
                    }
                }

                if (preq.props_mask & NGX_DAV_PROP_RESOURCETYPE) {
                    if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                        NGX_DAV_XML_APPEND_LIT("<D:resourcetype/>\n");
                    } else {
                        NGX_DAV_XML_APPEND_LIT("<D:resourcetype>");
                        NGX_DAV_XML_APPEND_BUF(child_rtype, ngx_strlen(child_rtype));
                        NGX_DAV_XML_APPEND_LIT("</D:resourcetype>\n");
                    }
                }

                if (preq.props_mask & NGX_DAV_PROP_GETCONTENTLENGTH) {
                    if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                        NGX_DAV_XML_APPEND_LIT("<D:getcontentlength/>\n");
                    } else {
                        NGX_DAV_XML_APPEND_LIT("<D:getcontentlength>");
                        NGX_DAV_XML_APPEND_BUF(child_clen, child_clen_len);
                        NGX_DAV_XML_APPEND_LIT("</D:getcontentlength>\n");
                    }
                }

                if (preq.props_mask & NGX_DAV_PROP_GETLASTMODIFIED) {
                    if (preq.mode == NGX_DAV_PROPFIND_PROPNAME) {
                        NGX_DAV_XML_APPEND_LIT("<D:getlastmodified/>\n");
                    } else {
                        NGX_DAV_XML_APPEND_LIT("<D:getlastmodified>");
                        NGX_DAV_XML_APPEND_BUF((u_char *) ctimebuf, ctime_len);
                        NGX_DAV_XML_APPEND_LIT("</D:getlastmodified>\n");
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
                    closedir(d);
                    return urc;
                }
            }
            NGX_DAV_XML_APPEND_LIT("</D:response>\n");
        }

        closedir(d);
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
    ngx_str_t src, dst, dest_hdr = ngx_null_string;
    u_char *last;
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

    size_t root_len;
    last = ngx_http_map_uri_to_path(r, &src, &root_len, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        size_t slen = ngx_strlen(src.data);
        u_char *stable = ngx_pnalloc(r->pool, slen + 1);
        if (stable == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(stable, src.data, slen);
        stable[slen] = '\0';
        src.data = stable;
        src.len = slen;
    }

    struct stat sst_src;
    if (lstat((char *) src.data, &sst_src) == -1) {
        if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
        if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (S_ISLNK(sst_src.st_mode)) {
        return NGX_HTTP_FORBIDDEN;
    }

    /* derive destination URI and map destination path */
    {
        u_char *start = dest_hdr.data;
        u_char *end = dest_hdr.data + dest_hdr.len;
        u_char *path_start = NULL;

        u_char *scheme = (u_char *) ngx_strnstr(start, "://", dest_hdr.len);
        if (scheme) {
            u_char *after = scheme + 3;
            path_start = ngx_strlchr(after, end, '/');
            if (path_start == NULL) return NGX_HTTP_BAD_REQUEST;
        } else if (dest_hdr.len >= 2 && start[0] == '/' && start[1] == '/') {
            path_start = ngx_strlchr(start + 2, end, '/');
            if (path_start == NULL) return NGX_HTTP_BAD_REQUEST;
        } else if (dest_hdr.len >= 1 && start[0] == '/') {
            path_start = start;
        } else {
            path_start = ngx_strlchr(start, end, '/');
            if (path_start == NULL) return NGX_HTTP_BAD_REQUEST;
        }

        size_t raw_len = (size_t)(end - path_start);
        u_char *raw = ngx_pnalloc(r->pool, raw_len + 1);
        if (raw == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_memcpy(raw, path_start, raw_len);
        raw[raw_len] = '\0';

        u_char *dec = ngx_pnalloc(r->pool, raw_len + 1);
        if (dec == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

        size_t di = 0;
        for (size_t ri = 0; ri < raw_len; ri++) {
            u_char c = raw[ri];
            if (c == '%' && ri + 2 < raw_len) {
                u_char hi = raw[ri + 1];
                u_char lo = raw[ri + 2];
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

        u_char *norm = ngx_pnalloc(r->pool, di + 1);
        if (norm == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        size_t ni = 0;
        for (size_t i = 0; i < di; i++) {
            if (dec[i] == '/' && i + 1 < di && dec[i + 1] == '/') continue;
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
                if (seg_len == 2 && dest_uri.data[seg_start] == '.' && dest_uri.data[seg_start + 1] == '.') {
                    return NGX_HTTP_FORBIDDEN;
                }
                for (size_t k = seg_start; k < seg_start + seg_len; k++) {
                    if (dest_uri.data[k] == '\\') {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                }
            }
        }

        ngx_str_t old_uri = r->uri;
        r->uri = dest_uri;
        last = ngx_http_map_uri_to_path(r, &dst, &root_len, 0);
        r->uri = old_uri;
        if (last == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (src.len == dst.len && ngx_strncmp(src.data, dst.data, src.len) == 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    /* ensure destination parent path exists or can be created */
    {
        u_char *p = dst.data + dst.len - 1;
        while (p > dst.data && *p != '/') {
            p--;
        }

        if (p <= dst.data) {
            return NGX_HTTP_FORBIDDEN;
        }

        if (dlcf->create_full_path) {
            u_char saved = *p;
            *p = '\0';
            if (ngx_create_full_path(dst.data, dlcf->access_dir_mode) == NGX_FILE_ERROR) {
                *p = saved;
                if (ngx_errno == EACCES || ngx_errno == EPERM) {
                    return NGX_HTTP_FORBIDDEN;
                }
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            *p = saved;
        } else {
            char parent[PATH_MAX];
            size_t plen = (size_t) (p - dst.data);
            if (plen >= sizeof(parent)) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(parent, dst.data, plen);
            parent[plen] = '\0';

            ngx_file_info_t psb;
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

    /* copy source path to stable storage before destination mapping,
     * because subsequent ngx_http_map_uri_to_path() allocations may reuse
     * request-pool memory and invalidate/overwrite src.data. */
    {
        size_t slen = ngx_strlen(src.data);
        u_char *stable = ngx_pnalloc(r->pool, slen + 1);
        if (stable == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(stable, src.data, slen);
        stable[slen] = '\0';
        src.data = stable;
        src.len = slen;
    }

    /* reject moving symlinks early: lstat source before any further mapping
     * (mapping destination may allocate from the same pool memory). */
    {
        struct stat sst_src;
        if (lstat((char *) src.data, &sst_src) == -1) {
            if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
            if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (S_ISLNK(sst_src.st_mode)) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "dav: refusing to MOVE symlink src='%V'", &src);
            return NGX_HTTP_FORBIDDEN;
        }
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

    /* ensure destination parent path exists or can be created */
    {
        u_char *p = dst.data + dst.len - 1;
        while (p > dst.data && *p != '/') {
            p--;
        }

        if (p <= dst.data) {
            return NGX_HTTP_FORBIDDEN;
        }

        if (dlcf->create_full_path) {
            u_char saved = *p;
            *p = '\0';
            if (ngx_create_full_path(dst.data, dlcf->access_dir_mode) == NGX_FILE_ERROR) {
                *p = saved;
                if (ngx_errno == EACCES || ngx_errno == EPERM) {
                    return NGX_HTTP_FORBIDDEN;
                }
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            *p = saved;

        } else {
            char parent[PATH_MAX];
            size_t plen = (size_t) (p - dst.data);
            if (plen >= sizeof(parent)) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(parent, dst.data, plen);
            parent[plen] = '\0';

            ngx_file_info_t psb;
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
    if (dest_exists && overwrite) {
        struct stat sst_src_check;
        if (lstat((char *) src.data, &sst_src_check) == -1) {
            if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
            if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (S_ISDIR(sst_src_check.st_mode)) {
            if (ngx_http_dav_remove_tree(r, (char *) dst.data) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: remove dst tree failed '%V'", &dst);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_ext_rename_file(&src, &dst, &ext) == NGX_OK) {
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "dav: MOVE success src='%V' dst='%V'", &src, &dst);
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
                return NGX_HTTP_NO_CONTENT;
            }

            if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
            if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
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

            return dest_exists ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
        }

        /* if destination exists and overwrite requested, try remove dst then retry */
        if ((ngx_errno == EEXIST || ngx_errno == ENOTEMPTY) && dest_exists && overwrite) {
            /* perform atomic replace: handle directories specially, files via temp-file replace */

            /* check if source is a directory (handle directory overwrite by removing dst then rename/copy) */
            {
                struct stat sst_check;
                if (lstat((char *) src.data, &sst_check) == -1) {
                    if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
                    if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (S_ISDIR(sst_check.st_mode)) {
                    /* remove existing destination tree to allow rename into place */
                    if (ngx_http_dav_remove_tree(r, (char *) dst.data) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: remove dst tree failed '%V'", &dst);
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    /* try rename now that dst removed */
                    if (ngx_ext_rename_file(&src, &dst, &ext) == NGX_OK) {
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

            return NGX_HTTP_NO_CONTENT;
        }

        /* map common errno to HTTP */
        if (ngx_errno == ENOENT) return NGX_HTTP_NOT_FOUND;
        if (ngx_errno == EACCES || ngx_errno == EPERM) return NGX_HTTP_FORBIDDEN;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "dav: MOVE success src='%V' dst='%V'", &src, &dst);
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
