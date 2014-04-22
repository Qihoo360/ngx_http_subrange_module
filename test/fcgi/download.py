#!/bin/env python
from flup.server.fcgi import WSGIServer
from cgi import parse_qs, escape
import os

def parse_range(rg):
	none,val = rg.split("=")
	start, end = val.split("-")
	return int(start),int(end)
def test_absent_content_length(start_response, start, end, total):
	hdrs = []
	status = "200 OK"
	size = end - start + 1
	content_range = "bytes %d-%d/%d"%(start, end, total)
	content_length = "%s"%size
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_absent_content_length"))
	return start_response(status, hdrs);
def test_absent_content_range(start_response, start, end, total):
	hdrs = []
	status = "206 Partial Content"
	size = end - start + 1
	content_range = "bytes %d-%d/%d"%(start, end, total)
	content_length = "%s"%size
	hdrs.append(("Content-Length",content_length))
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_absent_content_range"))
	return start_response(status, hdrs);
def test_return_200_ok(start_response, start, end, total):
	hdrs = []
	status = "200 OK"
	size = end - start + 1
	content_range = "bytes %d-%d/%d"%(start, end, total)
	content_length = "%s"%size
	hdrs.append(("Content-Length",content_length))
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_return_200_ok"))
	return start_response(status, hdrs);
def test_return_500_error(start_response, start, end, total):
	hdrs = []
	status = "500 Internal Server Error"
	size = end - start + 1
	content_range = "bytes %d-%d/%d"%(start, end, total)
	content_length = "%s"%size
	hdrs.append(("Content-Length",content_length))
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_return_500_error"))
	return start_response(status, hdrs);
def test_illegal_content_range(start_response, start, end, total):
	hdrs = []
	status = "206 Partial Content"
	size = end - start + 1
	content_range = "bytes %d-%d/%d"%(end, start, total) #exchange start, end , so start > end
	content_length = "%s"%size
	hdrs.append(("Content-Length",content_length))
	hdrs.append(("Content-Range",content_range))
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_illegal_content_range"))
	return start_response(status, hdrs);
def test_more_content_length(start_response, start, end, total):
	hdrs = []
	status = "206 Partial Content"
	size = end - start + 1
	content_range = "bytes %d-%d/%d"%(start, end, total) 
	content_length = "%s"%(size+100) #increase content-length  makes it be greater 
	hdrs.append(("Content-Length",content_length))
	hdrs.append(("Content-Range",content_range))
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_more_content_length"))
	return start_response(status, hdrs);

def test_normal(start_response, start, end, total):
	hdrs = []
	status = "206 Partial Content"
	size = end - start + 1
	content_range = "bytes %d-%d/%d"%(start, end, total)
	content_length = "%s"%size
	hdrs.append(("Content-Length",content_length))
	hdrs.append(("Content-Range",content_range))
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_normal"))

	return start_response(status, hdrs)
def test_http_request(start_response,start, end, total):
	hdrs = []
	status = "200 OK"
	content_length = "%s"%total
	hdrs.append(("Content-Length",content_length))
	hdrs.append(("Content-Type","application/octet-stream"))
	hdrs.append(("Test-Type","test_http_request"))
	return start_response(status, hdrs)


test_handlers = {
		'test_absent_content_length':test_absent_content_length,
		'test_absent_content_range':test_absent_content_range,
		'test_illegal_content_range':test_illegal_content_range,
		'test_more_content_length':test_more_content_length,
		'test_return_200_ok':test_return_200_ok,
		'test_return_500_error':test_return_500_error,

		'test_normal':test_normal
}

'''
Test script backend
Request:
	X-Test: testkey  
	 testkey can be test-absent-content_length, test-absent-content-range ...
Response:
	Test-Type: handler name 
	indicates which handler is used, used to verify the test type by client
Parameter:
	fname=
'''


def app(env, start_response):
	status = "206 Partial Content"
	resp = ''
	hdrs = []

	GET = parse_qs(env['QUERY_STRING'])
	rg = env.get('HTTP_RANGE')
	docroot = env['DOCUMENT_ROOT']
	fname = GET.get("fname")[0]
	testkey = env.get("HTTP_X_TEST")
	fname = docroot + '/' + fname
	total = os.path.getsize(fname)
	start, end = parse_range(rg)
	if end >= total:
		end = total - 1

	f = open(fname, "r")
	if not rg:
		resp = f.read()
		f.close()
		return [resp,None]
	f.seek(start)
	size = end - start + 1
	resp = f.read(size)
	f.close()
	print start, end, total, size,len(resp)

	handler = test_handlers.get(testkey)
	if handler:
		handler(start_response, start, end, total)
	else:
		test_normal(start_response, start, end , total)

	return [resp,None] # add None to avoid fcgi add Content-length for you
if __name__ == '__main__':
	WSGIServer(app, bindAddress = '/tmp/range-fcgi.sock').run()
