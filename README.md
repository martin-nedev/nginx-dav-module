# nginx-dav-module (skeleton)


## Configuration Directives

# dav_create_full_path
Syntax: 	dav_create_full_path on | off;
Default:  dav_create_full_path off;
Context: 	http, server, location

This directive allows creating all needed intermediate directories. 

# dav_access
Syntax: 	dav_access users:permissions ...;
Default: 	dav_access user:rw;
Context: 	http, server, location

Sets access permissions for newly created files and directories.

# dav_delete_depth
Syntax: 	dav_delete_depth number;
Default: 	dav_delete_depth 0;
Context: 	http, server, location

Allows the DELETE method to remove files provided that the number of elements in a request path is not less than the specified number.

# dav_methods
Syntax: 	dav_methods off | method ...;
Default: 	dav_methods off;
Context: 	http, server, location

Allows the specified HTTP and WebDAV methods. The parameter off denies all methods processed by this module.

##
