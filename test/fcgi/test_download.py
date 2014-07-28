#coding:utf8
import sys,os
import urllib
import hashlib
from httplib import HTTPConnection
from functools import wraps

uricgi = '/download.py?fname=rand10m'
uriproxy='/rand10m'
COLOR_PASS = "\033[94m"
COLOR_FAILED = "\033[91m"
COLOR_END = "\033[0m"
firstmd5 = '55c6d96e71759b713e23b3dae0c205a3'
finalmd5 = '5a812c35149308b8df79cedea72887ae'

def tpass(name):
	return 'test ' + name + COLOR_PASS + ' PASS' + COLOR_END
def tfailed(name):
	return 'test ' + name + COLOR_FAILED + ' FAILED' + COLOR_END
def tassertEqual(val, expect):
	if val != expect:
		print tfailed("'%s == %s'"%(val, expect))
		raise AssertionError

def tassert(expr, *args):
	if not expr:
		if len(args):
			print tfailed("expr:'%s' %s"%(expr, args))
		raise AssertionError
def tassertMd5(val, expect):
	md5 = hashlib.md5()
	md5.update(val)
	tassertEqual(md5.hexdigest(),expect)


def test(func):
	@wraps(func)
	def test_info(*args, **kwargs):
		sys.stdout.write('test %s... '%func.__name__)
		sys.stdout.flush()
		ret = func(*args, **kwargs)
		sys.stdout.write('%sPASS%s\n'%(COLOR_PASS,COLOR_END))
		return ret
	return test_info 

def http_download_get_request(uri, hdrs = {}):
	conn = HTTPConnection('localhost',8804)
	conn.set_debuglevel(1)
	conn.request("GET", uri, '',hdrs)
	resp = conn.getresponse()
	return resp

## begin test backend response ##
@test
def test_absent_content_length(uri):
	hdrs = {"X-Test":"test_absent_content_length"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 200)
	tassert(resp.getheader("Test-Type"), "test_absent_content_length")
	body = resp.read()
	tassertMd5(body, firstmd5) #md5 of first 1m

@test
def test_absent_content_range(uri):
	hdrs = {"X-Test":"test_absent_content_length"}
	resp = http_download_get_request(uri, hdrs)

	tassert(resp)
	tassertEqual(resp.status, 200)
	tassertEqual(resp.getheader("Test-Type"), "test_absent_content_length")
	tassertMd5(resp.read(), firstmd5)

@test
def test_illegal_content_range(uri):
	hdrs = {"X-Test":"test_illegal_content_range"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 502)
	tassertEqual(resp.getheader("Test-Type"), "test_illegal_content_range")

@test
def test_more_content_length(uri):
	hdrs = {"X-Test":"test_more_content_length"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 200)
	tassertEqual(resp.getheader("Test-Type"), "test_more_content_length")
	tassertMd5(resp.read(), finalmd5) #md5 of file

@test
def test_return_200_ok(uri):
	hdrs = {"X-Test":"test_return_200_ok"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 200)
	tassertEqual(resp.getheader("Test-Type"), "test_return_200_ok")
	tassertMd5(resp.read(), firstmd5)

@test
def test_return_500_error(uri):
	hdrs = {"X-Test":"test_return_500_error"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 500)
	tassertEqual(resp.getheader("Test-Type"), "test_return_500_error")

@test
def test_normal(uri):
	hdrs = {}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 200)
	tassert(resp.getheader("Test-Type"), "test_normal")
	tassertMd5(resp.read(), finalmd5)

## begin test client request ##
@test
def test_absent_range_end(uri):
	hdrs = {"Range": "Bytes=0-"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 206)
	tassertMd5(resp.read(), finalmd5)
@test
def test_absent_range_start(uri):
	hdrs = {"Range": "Bytes=-100"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 206)

@test
def test_illegal_range_header(uri):
	hdrs = {"Range": "Bytes=foo"}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassertEqual(resp.status, 416)

@test
def test_range_request(uri):
	hdrs = {"Range":"Bytes=0-%d"%(1024*1024*2)}
	resp = http_download_get_request(uri, hdrs)
	tassert(resp)
	tassert(len(resp.read()),1024*1024*2);
	tassertEqual(resp.status, 206)

if __name__ == '__main__':
	test_absent_content_length(uricgi)
	test_absent_content_range(uricgi)
	test_illegal_content_range(uricgi)
	test_more_content_length(uricgi)
	test_return_200_ok(uricgi)
	test_return_500_error(uricgi)
	test_normal(uricgi)
	test_range_request(uricgi)

	test_absent_range_start(uriproxy)
	test_absent_range_end(uriproxy)
	test_illegal_range_header(uriproxy)

