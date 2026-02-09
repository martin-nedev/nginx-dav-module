# nginx-dav-module (skeleton)

This directory contains a minimal skeleton for an Nginx HTTP module that can
be built into the nginx binary in your workspace (no system install required).

Files:
- `config` — small script used by `./configure --add-module=...`
- `ngx_http_dav_module.c` — C skeleton for the module

Quick build & run (from the workspace root where `nginx` source lives):

```bash
cd nginx
./configure --add-module=../nginx-dav-module
make -j
# Run the built nginx binary with your config in `conf/nginx.conf`:
sudo ./objs/nginx -c ../conf/nginx.conf
```

Notes:
- The module currently registers a content-phase handler that returns
  `NGX_DECLINED`. Implement DAV methods and configuration as needed.
- Your `conf/nginx.conf` uses `logs/` for log files; ensure that path
  exists and is writable by the nginx worker user when running without
  `sudo`.
