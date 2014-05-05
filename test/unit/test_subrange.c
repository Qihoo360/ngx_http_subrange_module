#include <nginx.h>
#include <assert.h>
#include "../../ngx_http_subrange_module.c"

void pass(const char *msg){
	printf("test %s \033[94mOK\033[0m \t\n",msg);
}
void failed(const char *msg){
	printf("test %s \033[91mFAILED\033[0m \t\n",msg);
}
void test_ngx_http_subrange_parse(){
	ngx_str_t rangekey = ngx_string("Range");
	ngx_str_t rangeval_normal = ngx_string("Bytes = 0-1023");
	ngx_str_t rangeval_absent_start = ngx_string("Bytes = -1023");
	ngx_str_t rangeval_absent_end = ngx_string("Bytes = 0-");
	ngx_str_t rangeval_invalid = ngx_string("Bytes = abc");

	ngx_table_elt_t		rangehdr;
	ngx_http_request_t	r;
	ngx_http_subrange_t range;
	ngx_http_subrange_filter_ctx_t ctx;

	rangehdr.key = rangekey;
	r.headers_in.range = &rangehdr;

	ngx_memzero(&ctx, sizeof(ngx_http_subrange_filter_ctx_t));
	ngx_memzero(&range, sizeof(ngx_http_subrange_t));

	/*test normal case*/
	rangehdr.value = rangeval_normal;
	ngx_http_subrange_parse(&r, &ctx, &range);
	assert(range.start == 0);
	assert(range.end == 1023);
	assert(range.total == 0);
	pass("test_ngx_http_subrange_parse: range normal");

	/*test absent range start case*/
	rangehdr.value = rangeval_absent_start;
	ngx_http_subrange_parse(&r, &ctx, &range);
	assert(range.start == (ngx_uint_t)-1);
	assert(range.end == 1023);
	assert(range.total == 0);
	pass("test_ngx_http_subrange_parse: range absent start");

	/*test absent range end case*/
	rangehdr.value = rangeval_absent_end;
	ngx_http_subrange_parse(&r, &ctx, &range);
	assert(range.start == 0);
	assert(range.end == (ngx_uint_t) -1);
	assert(range.total == 0);
	pass("test_ngx_http_subrange_parse: range absent end");

	/*test invalid range case*/
	ngx_memzero(&range, sizeof(ngx_http_subrange_t));
	rangehdr.value = rangeval_invalid;
	ngx_http_subrange_parse(&r, &ctx, &range);
	assert(range.start == 0);
	assert(range.end == 0);
	assert(range.total == 0);
	pass("test_ngx_http_subrange_parse: range invalid");
}
void test_ngx_http_subrange_parse_content_range(){
	ngx_str_t rangeval_normal = ngx_string("Bytes 0-1023/1024");
	ngx_str_t rangeval_absent_start = ngx_string("Bytes -1023/1024");
	ngx_str_t rangeval_absent_end = ngx_string("Bytes 0-/1024");
	ngx_str_t rangeval_invalid = ngx_string("Bytes abc");
	ngx_str_t rangeval_invalid_no_minus = ngx_string("Bytes 1023/1024");

	ngx_http_request_t	r;
	ngx_http_subrange_t crange;
	ngx_http_subrange_filter_ctx_t ctx;

	ngx_table_elt_t *h;
	ngx_table_elt_t crhdr = {
		0,
		ngx_string("Content-Range"),
		rangeval_normal,
		(unsigned char *)"content-range"
	};

	r.pool = ngx_create_pool(4096,NULL);

	ngx_list_init(&r.headers_out.headers,r.pool,1,sizeof(ngx_table_elt_t));
	h = ngx_list_push(&r.headers_out.headers);
	assert(h);
	*h = crhdr;

	ngx_memzero(&ctx, sizeof(ngx_http_subrange_filter_ctx_t));
	ngx_memzero(&crange, sizeof(ngx_http_subrange_t));

	ngx_http_subrange_parse_content_range(&r, &ctx, &crange);
	assert(crange.start == 0);
	assert(crange.end == 1023);
	assert(crange.total == 1024);
	pass("test_ngx_http_subrange_parse_content_range: range normal");

	h->value = rangeval_absent_start;
	ngx_http_subrange_parse_content_range(&r, &ctx, &crange);
	assert(crange.start == 0);
	assert(crange.end == 1023);
	assert(crange.total == 1024);
	pass("test_ngx_http_subrange_parse_content_range: range absent start");

	h->value = rangeval_absent_end;
	ngx_http_subrange_parse_content_range(&r, &ctx, &crange);
	assert(crange.start == 0);
	assert(crange.end == 0);
	assert(crange.total == 1024);
	pass("test_ngx_http_subrange_parse_content_range: range absent end");

	h->value = rangeval_invalid;
	ngx_http_subrange_parse_content_range(&r, &ctx, &crange);
	assert(crange.start == 0);
	assert(crange.end == 0);
	assert(crange.total == 0);
	pass("test_ngx_http_subrange_parse_content_range: range invalid");

	h->value = rangeval_invalid_no_minus;
	ngx_http_subrange_parse_content_range(&r, &ctx, &crange);
	assert(crange.start == 0);
	assert(crange.end == 1023);
	assert(crange.total == 1024);
	pass("test_ngx_http_subrange_parse_content_range: range invalid no minus");
}

void test_ngx_http_subrange_set_header(){
	ngx_http_request_t	r;
	ngx_str_t key = ngx_string("X-Test");
	ngx_str_t key_lowcase = ngx_string("x-test");
	ngx_str_t val = ngx_string("Test");
	ngx_str_t val_exist = ngx_string("Test-exist");
	ngx_table_elt_t *h;
	ngx_uint_t hash;

	r.pool = ngx_create_pool(4096, NULL);
	ngx_list_init(&r.headers_in.headers, r.pool, 2, sizeof(ngx_table_elt_t));
	hash = ngx_hash_key(key_lowcase.data, key_lowcase.len);

	ngx_http_subrange_set_header(&r, &r.headers_in.headers, key, val, &h);
	assert(h->hash == hash);
	assert(ngx_strncmp(h->key.data, "X-Test",h->key.len) == 0);
	assert(ngx_strncmp(h->lowcase_key, "x-test",h->key.len) == 0);
	assert(ngx_strncmp(h->value.data, "Test",h->value.len) == 0);
	pass("test_ngx_http_subrange_set_header: set key nonexist");

	ngx_http_subrange_set_header(&r, &r.headers_in.headers, key, val_exist, &h);
	assert(h->hash == hash);
	assert(ngx_strncmp(h->key.data, "X-Test",h->key.len) == 0);
	assert(ngx_strncmp(h->lowcase_key, "x-test",h->key.len) == 0);
	assert(ngx_strncmp(h->value.data, "Test-exist",h->value.len) == 0);
	pass("test_ngx_http_subrange_set_header: set key exist");
}

void test_ngx_http_subrange_rm_header(){
	ngx_http_request_t	r;
	ngx_str_t key = ngx_string("X-Test");
	ngx_str_t val = ngx_string("Test");
	ngx_str_t key_lowcase = ngx_string("x-test");
	ngx_table_elt_t *h;

	ngx_table_elt_t hdr = {
		0,
		key,
		val,
		key_lowcase.data
	};

	r.pool = ngx_create_pool(4096, NULL);
	ngx_list_init(&r.headers_in.headers, r.pool, 1, sizeof(ngx_table_elt_t));
	h = ngx_list_push(&r.headers_in.headers);
	*h = hdr;
	h = ngx_list_push(&r.headers_in.headers);
	*h = hdr;

	assert(r.headers_in.headers.part.nelts == 1);
	assert(r.headers_in.headers.last->nelts == 1);
	ngx_http_subrange_rm_header(&r.headers_in.headers, key);
	assert(r.headers_in.headers.part.nelts == 0);
	pass("test_ngx_http_subrange_rm_header: first");

	ngx_http_subrange_rm_header(&r.headers_in.headers, key);
	assert(r.headers_in.headers.last->nelts == 0);
	pass("test_ngx_http_subrange_rm_header: sencond");
}
void test_ngx_http_subrange_get_range(){
	ngx_http_request_t	r;
	ngx_str_t range;
	ngx_str_t range_cmp=ngx_string("bytes=0-1023");
	r.pool = ngx_create_pool(4096, NULL);

	range = ngx_http_subrange_get_range(&r, 0,1023);
	assert(ngx_strncmp(range.data, range_cmp.data, range.len)==0);
	pass("test_ngx_http_subrange_get_range");
}
void test_ngx_http_subrange_checkpoint_and_recovery(){
	int i;
	ngx_http_request_t	r;
	ngx_http_subrange_filter_ctx_t ctx;
	r.pool = ngx_create_pool(4096, NULL);
	r.main = &r;
	/*allocate pool blocks*/
	for(i = 0; i < 10; ++i){
		ngx_palloc(r.pool, 1024);
	}	
	/*allocate pool large blocks*/
	for(i = 0; i < 10; ++i){
		ngx_palloc(r.pool, 10240);
	}	
	assert(ngx_http_subrange_checkpoint(&r, &ctx) == NGX_OK);
	assert(ctx.checkpoint.current == r.pool->current);
	assert(ctx.checkpoint.large == r.pool->large);
	assert(ctx.checkpoint.chain == r.pool->chain);
	assert(ctx.checkpoint.pcleanup == r.pool->cleanup);
	assert(ctx.checkpoint.cleanup == r.cleanup);
	pass("checkpoint");
	for(i = 0; i < 10; ++i){
		ngx_palloc(r.pool, 1024);
	}	
	for(i = 0; i < 10; ++i){
		ngx_palloc(r.pool, 10240);
	}	
	assert(ngx_http_subrange_recovery(&r, &ctx) == NGX_OK);
	assert(ctx.checkpoint.current == r.pool->current);
	assert(ctx.checkpoint.large == r.pool->large);
	assert(ctx.checkpoint.chain == r.pool->chain);
	assert(ctx.checkpoint.pcleanup == r.pool->cleanup);
	assert(ctx.checkpoint.cleanup == r.cleanup);
	pass("checkpoint recovery");
}
void test_ngx_http_subrange_create_subrequest(){
	ngx_http_request_t	r;
	ngx_http_subrange_filter_ctx_t ctx;

	r.pool = ngx_create_pool(4096, NULL);
	assert(ngx_http_subrange_create_subrequest(&r, &ctx));
	assert(ctx.r != &r);
	assert(ctx.r->main == &r);
	pass("test_ngx_http_subrange_create_subrequest");
}
void test_ngx_http_subrange_set_header_handler(){
	ngx_http_request_t	r;
	ngx_conf_t cf;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_http_subrange_filter_ctx_t *fctx;
	void *loc_conf[16] = {0};
	void *ctx[16] = {0};
	ngx_uint_t i;
	ngx_uint_t valid_methods[] = {NGX_HTTP_GET, NGX_HTTP_POST};
	ngx_uint_t invalid_methods[] = {NGX_HTTP_PUT, NGX_HTTP_HEAD,
									NGX_HTTP_DELETE, NGX_HTTP_OPTIONS};

	ngx_memzero(&r, sizeof(ngx_http_request_t));
	ngx_http_subrange_module.ctx_index  = 0;
	ngx_http_subrange_filter_module.ctx_index = 1;
	r.pool = ngx_create_pool(4096, NULL);
	r.loc_conf = loc_conf;
	r.ctx = ctx;
	r.main = &r;
	cf.pool = r.pool;
	rlcf = ngx_http_subrange_create_loc_conf(&cf);
	loc_conf[ngx_http_subrange_module.ctx_index] = rlcf;
	ngx_list_init(&r.headers_in.headers, r.pool, 5, sizeof(ngx_table_elt_t));

	for(i = 0; i < sizeof(invalid_methods)/sizeof(ngx_uint_t); ++i){
		r.method = NGX_HTTP_PUT;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		fctx = ngx_http_get_module_ctx(r.main, ngx_http_subrange_filter_module);
		assert(fctx == NULL);
	}

	for(i = 0; i < sizeof(valid_methods)/sizeof(ngx_uint_t); ++i){
		r.method = valid_methods[i];
		rlcf->size = NGX_CONF_UNSET;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		fctx = ngx_http_get_module_ctx(r.main, ngx_http_subrange_filter_module);
		assert(fctx == NULL);

		rlcf->size = 0;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		fctx = ngx_http_get_module_ctx(r.main, ngx_http_subrange_filter_module);
		assert(fctx == NULL);

		rlcf->size = 16;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		assert(ngx_strncasecmp(r.headers_in.range->key.data, (u_char *)"range", sizeof("range")) == 0);
		assert(ngx_strncasecmp(r.headers_in.range->value.data, (u_char *)"bytes=0-15", sizeof("bytes=0-15")) == 0);
		fctx = ngx_http_get_module_ctx(r.main, ngx_http_subrange_filter_module);
		assert(fctx->touched == 1);
		assert(fctx->offset == 0);
		assert(fctx->done == 0);
		assert(fctx->subrequest_done == 0);
		assert(fctx->range_request == 0);
		/*recovery*/
		ngx_http_set_ctx((&r), NULL, ngx_http_subrange_filter_module);
		r.headers_in.range = NULL;
	}
	/*range request*/
	for(i = 0; i < sizeof(valid_methods)/sizeof(ngx_uint_t); ++i){
		ngx_table_elt_t rangehdr = {
			0,
			ngx_string("Range"),
			ngx_string("Bytes=0-15"),
			(u_char *)"range"
		};
		rlcf->size = 16;
		r.headers_in.range = &rangehdr;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		assert(ngx_strncasecmp(r.headers_in.range->key.data, (u_char *)"range", sizeof("range")) == 0);
		assert(ngx_strncasecmp(r.headers_in.range->value.data, (u_char *)"bytes=0-15", sizeof("bytes=0-15")) == 0);
		fctx = ngx_http_get_module_ctx(r.main, ngx_http_subrange_filter_module);
		assert(fctx->touched == 0);
		assert(fctx->offset == 0);
		assert(fctx->done == 0);
		assert(fctx->subrequest_done == 0);
		assert(fctx->range_request == 1);

		/*recovery*/
		ngx_http_set_ctx((&r), NULL, ngx_http_subrange_filter_module);
		r.headers_in.range = NULL;

		rlcf->size = 6;
		r.headers_in.range = &rangehdr;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		assert(ngx_strncasecmp(r.headers_in.range->key.data, (u_char *)"range", sizeof("range")) == 0);
		assert(ngx_strncasecmp(r.headers_in.range->value.data, (u_char *)"bytes=0-5", sizeof("bytes=0-5")) == 0);
		fctx = ngx_http_get_module_ctx(r.main, ngx_http_subrange_filter_module);
		assert(fctx->touched == 1);
		assert(fctx->offset == 0);
		assert(fctx->done == 0);
		assert(fctx->subrequest_done == 0);
		assert(fctx->range_request == 1);
		/*recovery*/
		ngx_http_set_ctx((&r), NULL, ngx_http_subrange_filter_module);
		r.headers_in.range = NULL;
	}
	pass("test_ngx_http_subrange_set_header_handler");
}

static ngx_int_t ngx_test_header_filter(ngx_http_request_t *r){
	return NGX_OK;
}
static ngx_int_t ngx_test_body_filter(ngx_http_request_t *r, ngx_chain_t *in){
	return NGX_OK;
}
static void ngx_test_init_request(ngx_http_request_t *r){
	ngx_conf_t cf;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_http_subrange_filter_ctx_t *fctx;
	void *loc_conf[16];
	void *ctx[16];

	r->pool = ngx_create_pool(4096, NULL);
	r->loc_conf = loc_conf;
	r->ctx = ctx;
	r->main = r;
	cf.pool = r->pool;
	rlcf = ngx_http_subrange_create_loc_conf(&cf);
	loc_conf[ngx_http_subrange_module.ctx_index] = rlcf;
	ngx_list_init(&r->headers_out.headers, r->pool, 5, sizeof(ngx_table_elt_t));
	fctx = ngx_palloc(r->pool, sizeof(ngx_http_subrange_filter_ctx_t));
	ngx_memzero(fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	ngx_http_set_ctx(r, fctx, ngx_http_subrange_filter_module);

	ngx_http_top_header_filter = ngx_test_header_filter;
	ngx_http_top_body_filter = ngx_test_body_filter;

	ngx_http_subrange_filter_init(&cf);

}
void test_ngx_http_subrange_header_filter(){
	ngx_http_request_t	r;
	ngx_conf_t cf;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_http_subrange_filter_ctx_t fctx;
	ngx_table_elt_t *h;
	void *loc_conf[16];
	void *ctx[16];

	r.pool = ngx_create_pool(4096, NULL);
	r.loc_conf = loc_conf;
	r.ctx = ctx;
	r.main = &r;
	cf.pool = r.pool;
	rlcf = ngx_http_subrange_create_loc_conf(&cf);
	loc_conf[ngx_http_subrange_module.ctx_index] = rlcf;
	ngx_list_init(&r.headers_out.headers, r.pool, 5, sizeof(ngx_table_elt_t));
	ngx_http_top_header_filter = ngx_test_header_filter;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	ngx_http_set_ctx((&r), (&fctx), ngx_http_subrange_filter_module);

	ngx_http_subrange_filter_init(&cf);

	rlcf->size = 16;
	fctx.touched = 1;

	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 16;
	ngx_table_elt_t crhdr = {
		0,
		ngx_string("Content-Range"),
		ngx_string("Bytes 0-15/16"),
		(u_char *)"content-range"
	};
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;

	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 0);
	assert(fctx.content_range.end == 15);
	assert(fctx.content_range.total == 16);
	assert(fctx.done == 1);

	ngx_str_t range_last = ngx_string("Bytes 1-5/6");
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;
	h->value = range_last;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	fctx.touched = 1;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 5;
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 1);
	assert(fctx.content_range.end == 5);
	assert(fctx.content_range.total == 6);
	assert(fctx.done == 1);

	ngx_str_t range_between = ngx_string("Bytes 2-3/6"); 
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;
	h->value = range_between;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	fctx.touched = 1;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 2;

	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 2);
	assert(fctx.content_range.end == 3);
	assert(fctx.content_range.total == 6);
	assert(fctx.offset == 4);
	assert(fctx.done == 0);

	ngx_str_t range_head = ngx_string("Bytes 0-3/6"); 
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;
	h->value = range_head;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	fctx.touched = 1;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 4;

	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 0);
	assert(fctx.content_range.end == 3);
	assert(fctx.content_range.total == 6);
	assert(fctx.offset == 4);
	assert(fctx.done == 0);
	pass("test_ngx_http_subrange_header_filter");
}
void test_ngx_http_subrange_body_filter(){
	ngx_chain_t *in;
	ngx_http_request_t r;
	ngx_http_subrange_filter_ctx_t *ctx;
	ngx_http_subrange_loc_conf_t *rlcf;

	ngx_test_init_request(&r);

	ctx = ngx_http_get_module_ctx((&r), ngx_http_subrange_filter_module);
	rlcf = ngx_http_get_module_loc_conf((&r), ngx_http_subrange_module);

	in = NULL;
	ngx_http_subrange_body_filter(&r, in);
}

int main(int argc, char *argv[]){
	test_ngx_http_subrange_parse();
	test_ngx_http_subrange_parse_content_range();
	test_ngx_http_subrange_set_header();
	test_ngx_http_subrange_rm_header();
	test_ngx_http_subrange_get_range();
	test_ngx_http_subrange_checkpoint_and_recovery();
	//test_ngx_http_subrange_create_subrequest();
	test_ngx_http_subrange_set_header_handler();
	test_ngx_http_subrange_header_filter();
	test_ngx_http_subrange_body_filter();
	return 0;
}
