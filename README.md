## nginx-dav-std-module

## About

A WebDAV module for nginx.

Implemented methods: PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, OPTIONS, LOCK, UNLOCK.


## IMPORTANT

This module replaces the standard ngx_http_dav_module and is not compatible with it. They cannot be used simultaneously.


## Build

# replacement

copy ngx_http_dav_std_module.c to nginx/src/http/modules/ngx_http_dav_module.c (replace the existing file).

./configure --with-http_dav_module.

# static module

./configure --add-module=/path/to/nginx-dav-std-module

nginx must not be configured with --with-http_dav_module.

# dynamic module

./configure --add-dynamic-module=/path/to/nginx-dav-std-module

nginx must not be configured with --with-http_dav_module.


## Directives

# dav_create_full_path
Syntax: dav_create_full_path on | off  
Default: off  
Context: http, server, location  
Description: If enabled, Nginx creates all necessary intermediate directories for a file during a PUT request.  
Note: create_full_put_path is a legacy alias.

# dav_access
Syntax: dav_access user:permissions [group:permission] [all:permission]  
Default: user:rw  
Context: http, server, location  
Description: Sets access permissions for creating files and directories.

# dav_delete_depth
Syntax: dav_min_delete_depth number  
Default: 0  
Context: http, server, location  
Description: Restricts DELETE operations based on directory depth.  
Note: min_delete_depth is a legacy alias.

# dav_lock_zone
Syntax: dav_lock_zone name [size] [timeout]  
Default: none (when size and/or timeout are omitted, defaults are 5m and 1h).  
Context: http, server, location  
Description: Creates or reuses a shared memory zone. Size may be written with an m or M suffix (for example 5m). An integer without suffix is interpreted as megabytes. Timeout may be written with s/S, m/M, or h/H suffixes (for example 60s, 15m, 1h). An integer without suffix is interpreted as seconds. If a zone with the same name already exists, its size and timeout are preserved and any parameters provided on later declarations are ignored. If LOCK/UNLOCK are enabled and no zone is configured, a default zone named "dav_lock" is created with the default size and timeout.

# dav_methods
Syntax: dav_methods [on | off | method ...]  
Default: off  
Context: http, server, location  
Description: Enables the specified HTTP and WebDAV methods. Use "on" to enable all supported  methods: PUT, DELETE, MKCOL, COPY, MOVE, LOCK, UNLOCK, PROPFIND, PROPPATCH, OPTIONS.  
Note: LOCK and UNLOCK require a lock zone and must be enabled together.

## Example configuration

http {

    dav_create_full_path  on;                #  default is off
    dav_access            user:rw group:rw;  #  default is user:rw
    dav_min_delete_depth  1;                 #  default is 0
    dav_lock_zone         dav_lock 5m 1h;    #  default is 5m 1h

    server {

        listen  80;
        root    html;

        location  /files {

            alias  files;

            dav_methods  on;  #  default is off
        }
    }
}