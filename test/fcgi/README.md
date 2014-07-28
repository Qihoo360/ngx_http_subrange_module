## Function tests of ngx_http_subrange_module
It is a little comple to run the test. There are three parts
involves and some manual operation is needed.

1. create_rand10m.py
 Run this script to generate a random 10M size file. It will 
 print two md5 values. The first one is the md5 of the first 
 1M part, the second one is the md5 of the whole file.

2. edit test_download.py
 Set firstmd5, and finalmd5 with the values got above

3. deploy download.py as the fastcgi application
 Use the nginx.conf as the configration file, and copy rand10m
 to the appropriate path.
 run python download.py to start the fastcgi
 run nginx which listens on 8805 to start a normal proxy backend
 run nginx which listens on 8804 with subrange on

Run python test_download.py


##TODO
Simplify the process

