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

*Example:* 
---------
```
  location /{  
    root html;  
    subrange 10k;  
  }
```
