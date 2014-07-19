ngx_http_subrange_module
========================

Split one big download file request to multiple subrange requests to avoid geting too
much data from upstream at one time.

Directive:
---------
```
syntax : subrange size
default: subrange 0 , 0 means disable
context: http, server, location
```

Example:
---------
```
  location /{  
    root html;  
    subrange 10k;  
  }
```
Introduction:
-------------
When nginx is used as a reverse proxy for file downloading service, it will
always run out the bandwidth between nginx and upstream when the user requests
a very large file. This is because nginx fetch a whole file at a time and buffer
the file if the client can not read in time. The bandwidth would be used up and
the disk iowait would be high.

Nginx has an option to turn off the buffer mechanism, for example set `proxy_buffering off`
or `fastcgi_buffering off`, and which directive depends on the type of your upstream.
However, this brings it with a problem. If your upstream is PHP or Java, it will
block your PHP fastcgi process or yourJava threads, especially when the client is
downloading a very large file and even worse he has a terrible speed.

The subrange module is created to solve this problem. It splits your HTTP request.
When you want to download a 1G file, the module will try to download a chunk of the
file from the upstream, for example downloads 5M first, and then the next 5M, until
the client receive the whole file. The whole process is non-sensible to client.
You can set the chunk size in the nginx configuration file.

The module sets the HTTP `Range` header to perform a Range request to get a chunk
from the upstream. So the supporting of Range request is needed by upstream. Supporting
`Range` is easy, all standard HTTP servers like nginx/apache have implemented it.
It is trivial to implement it yourself.

We just have one directive `subrange` which sets the size of chunk being fetched at a
time. The directive takes a `size` as the parameter(1024 or 1k), or a variable as
well. 0 meas disable subrange.
```
set $size 10m;
location /download{
    subrange $size;
}
```
Install:
--------
Compile nginx with `--add-module=/path/to/ngx_http_subrange_module`
