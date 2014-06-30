#include <nginx.h>
#include <assert.h>
#include "../../ngx_http_subrange_module.c"

void pass(const char *msg){
	printf("test %s \033[94mOK\033[0m \t\n",msg);
}
static ngx_int_t ngx_test_header_filter(ngx_http_request_t *r){
	return NGX_OK;
}
static ngx_int_t ngx_test_body_filter(ngx_http_request_t *r, ngx_chain_t *in){
	return NGX_OK;
}
static void ngx_test_cleanup(void *data){
	return;
}
static void *ngx_test_http_core_create_srv_conf(ngx_conf_t *cf){
	ngx_http_core_srv_conf_t  *cscf;

	cscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_core_srv_conf_t));
	if (cscf == NULL) {
		return NULL;
	}    

	/*   
	 *        * set by ngx_pcalloc():
	 *             *
	 *                  *     conf->client_large_buffers.num = 0;
	 *                       */

	if (ngx_array_init(&cscf->server_names, cf->pool, 4,
				sizeof(ngx_http_server_name_t))
			!= NGX_OK)
	{    
		return NULL;
	}    

	cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
	cscf->request_pool_size = NGX_CONF_UNSET_SIZE;
	cscf->client_header_timeout = NGX_CONF_UNSET_MSEC;
	cscf->client_header_buffer_size = NGX_CONF_UNSET_SIZE;
	cscf->ignore_invalid_headers = NGX_CONF_UNSET;
	cscf->merge_slashes = NGX_CONF_UNSET;
	cscf->underscores_in_headers = NGX_CONF_UNSET;

	return cscf;
}
static void ngx_test_init_request(ngx_http_request_t *r){
	ngx_conf_t cf;
	ngx_http_core_srv_conf_t  *cscf;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_http_subrange_filter_ctx_t *fctx;
	ngx_connection_t *c;
	ngx_log_t *log;
	ngx_open_file_t *file;

	ngx_time_init();
	ngx_memzero(r, sizeof(ngx_http_request_t));
	r->pool = ngx_create_pool(4096, NULL);
	cf.pool = r->pool;
	r->main = r;
	/*Just support 16 modules in this test, it is enough*/
	r->loc_conf = ngx_palloc(r->pool, sizeof(void *) * 16);
	r->ctx = ngx_palloc(r->pool, sizeof(void *) * 16);
	r->srv_conf = ngx_palloc(r->pool, sizeof(void *) * 16);

	ngx_list_init(&r->headers_out.headers, r->pool, 5, sizeof(ngx_table_elt_t));
	ngx_list_init(&r->headers_in.headers, r->pool, 5, sizeof(ngx_table_elt_t));

	rlcf = ngx_http_subrange_create_loc_conf(&cf);
	r->loc_conf[ngx_http_subrange_module.ctx_index] = rlcf;
	
	ngx_http_core_module.ctx_index = 0;
	cscf = ngx_test_http_core_create_srv_conf(&cf);
	cscf->ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_conf_ctx_t));
	cscf->ctx->main_conf = 0;
	cscf->ctx->srv_conf = r->srv_conf;
	cscf->ctx->loc_conf = r->loc_conf;
	r->srv_conf[ngx_http_core_module.ctx_index] = cscf;

	fctx = ngx_pcalloc(r->pool, sizeof(ngx_http_subrange_filter_ctx_t));
	ngx_http_set_ctx(r, fctx, ngx_http_subrange_filter_module);

	file = ngx_pcalloc(r->pool, sizeof(ngx_open_file_t));
	file->fd = NGX_INVALID_FILE;
	log = ngx_pcalloc(r->pool, sizeof(ngx_log_t));
	log->file = file;
	c = ngx_pcalloc(r->pool,sizeof(ngx_connection_t));
	c->log = log;
	c->write = ngx_pcalloc(r->pool, sizeof(ngx_event_t));
	r->connection = c;

	ngx_http_top_header_filter = ngx_test_header_filter;
	ngx_http_top_body_filter = ngx_test_body_filter;
	ngx_http_subrange_filter_init(&cf);

}
void test_ngx_http_subrange_init(){
	ngx_conf_t cf;
	ngx_http_core_main_conf_t cmcf;
	ngx_http_conf_ctx_t ctx;
	void *main_conf[16];

	cf.pool = ngx_create_pool(4096, 0);
	ngx_array_init(&cmcf.phases[NGX_HTTP_ACCESS_PHASE].handlers, cf.pool, 1, sizeof(void *));
	main_conf[ngx_http_core_module.ctx_index] = &cmcf;
	ctx.main_conf = main_conf;
	cf.ctx = &ctx;

	assert(ngx_http_subrange_init(&cf) == NGX_OK);

	pass("test_ngx_http_subrange_init");
}
void test_ngx_http_subrange_parse(){
	ngx_str_t rangekey = ngx_string("Range");
	ngx_str_t rangeval_normal = ngx_string("Bytes = 0-1023");
	ngx_str_t rangeval_absent_start = ngx_string("Bytes = -1023");
	ngx_str_t rangeval_absent_end = ngx_string("Bytes = 5250276732-");
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
	assert(range.start == 5250276732);
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
	ngx_str_t rangeval_wrong_boundary = ngx_string("Bytes 0-2048/1024");

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
	ngx_table_elt_t foohdr = {
		0,
		ngx_string("Foo"),
		rangeval_normal,
		(unsigned char *)"foo"
	};

	r.pool = ngx_create_pool(4096,NULL);

	ngx_list_init(&r.headers_out.headers,r.pool,1,sizeof(ngx_table_elt_t));
	int i;
	for(i = 0; i < 5; ++i){
		h = ngx_list_push(&r.headers_out.headers);
		*h = foohdr;
	}
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

	h->value = rangeval_wrong_boundary;
	ngx_http_subrange_parse_content_range(&r, &ctx, &crange);
	assert(crange.start == 0);
	assert(crange.end == 1023);
	assert(crange.total == 1024);
	pass("test_ngx_http_subrange_parse_content_range: range invalid no minus");

	/*ctx.range.end is absent*/
	ctx.range.end = (ngx_uint_t)-1;
	ngx_http_subrange_parse_content_range(&r, &ctx, &crange);
	assert(crange.start == 0);
	assert(crange.end == 1023);
	assert(crange.total == 1024);
	pass("test_ngx_http_subrange_parse_content_range: range normal(fix range.end)");

}

void test_ngx_http_subrange_set_header(){
	ngx_http_request_t	r;
	ngx_str_t key = ngx_string("X-Test");
	ngx_str_t key_lowcase = ngx_string("x-test");
	ngx_str_t val = ngx_string("Test");
	ngx_str_t val_exist = ngx_string("Test-exist");
	ngx_table_elt_t *h;
	ngx_uint_t hash;

	ngx_table_elt_t foohdr = {
		0,
		ngx_string("Foo"),
		ngx_string("test"),
		(unsigned char *)"foo"
	};

	r.pool = ngx_create_pool(4096, NULL);
	ngx_list_init(&r.headers_in.headers, r.pool, 2, sizeof(ngx_table_elt_t));
	int i;
	for(i = 0; i < 5; ++i){
		h = ngx_list_push(&r.headers_in.headers);
		*h = foohdr;
	}

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
	ngx_pool_cleanup_t *pcln;
	ngx_http_cleanup_t *cln;
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
	for(i = 0; i < 10; ++i){
		pcln = ngx_pool_cleanup_add(r.pool, 0);
		pcln->handler = ngx_test_cleanup;

		cln = ngx_http_cleanup_add(&r, 0);
		cln->handler = ngx_test_cleanup;
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
	ngx_conf_t cf;
	ngx_http_request_t	r;
	ngx_http_subrange_filter_ctx_t ctx;
	ngx_http_subrange_loc_conf_t *rlcf;

	ngx_test_init_request(&r);
	assert(ngx_http_subrange_create_subrequest(&r, &ctx) == NGX_OK);
	assert(ctx.r != &r);
	assert(ctx.r->main == &r);

	/*range request with request size > range size*/
	cf.pool = r.pool;
	rlcf = ngx_http_get_module_loc_conf((&r), ngx_http_subrange_module);
	rlcf->size = 10;
	ctx.range.end = 16;
	ctx.offset = 10;
	ctx.range_request = 1;
	assert(ngx_http_subrange_create_subrequest(&r, &ctx) == NGX_OK);
	assert(ctx.done == 1);
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
		r.method = invalid_methods[i];
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
		/*range request which is NOT needed to touch(subrange size >= request size)*/
		rlcf->size = 20;
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

		/*range request which is needed to touch(subrange size < request size)*/
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

		ngx_table_elt_t invalid_hdr = {
			0,
			ngx_string("Range"),
			ngx_string("Bytes=abc"),
			(u_char*)"range"
		};
		rlcf->size = 16;
		r.headers_in.range = &invalid_hdr;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		fctx = ngx_http_get_module_ctx(r.main, ngx_http_subrange_filter_module);
		assert(fctx->touched == 0);
		ngx_http_set_ctx((&r), NULL, ngx_http_subrange_filter_module);
		r.headers_in.range = NULL;

		/*range request with start*/
		ngx_table_elt_t without_start = {
			0,
			ngx_string("Range"),
			ngx_string("Bytes=-15"),
			(u_char*)"range"
		};
		rlcf->size = 16;
		r.headers_in.range = &without_start;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		assert(fctx->touched == 0);
		ngx_http_set_ctx((&r), NULL, ngx_http_subrange_filter_module);
		r.headers_in.range = NULL;
		/*multipart range request*/
		ngx_table_elt_t multipart = {
			0,
			ngx_string("Range"),
			ngx_string("Bytes=0-10,11-15"),
			(u_char*)"range"
		};
		rlcf->size = 16;
		r.headers_in.range = &multipart;
		assert(ngx_http_subrange_set_header_handler(&r) == NGX_DECLINED);
		assert(fctx->touched == 0);
		ngx_http_set_ctx((&r), NULL, ngx_http_subrange_filter_module);
		r.headers_in.range = NULL;
	}
	pass("test_ngx_http_subrange_set_header_handler");
}
void test_ngx_http_subrange_merge_loc_conf(){
	ngx_conf_t cf;
	ngx_http_subrange_loc_conf_t parent, child;

	/*all unset*/
	parent.size = NGX_CONF_UNSET;
	child.size = NGX_CONF_UNSET;
	assert(ngx_http_subrange_merge_loc_conf(&cf, &parent, &child) == NGX_CONF_OK);
	assert(child.size == 0);

	/*parent unset, child is 16*/
	parent.size = NGX_CONF_UNSET;
	child.size = 16;
	assert(ngx_http_subrange_merge_loc_conf(&cf, &parent, &child) == NGX_CONF_OK);
	assert(child.size == 16);

	/*parent is 16, child is UNSET*/
	parent.size = 16;
	child.size = NGX_CONF_UNSET;
	assert(ngx_http_subrange_merge_loc_conf(&cf, &parent, &child) == NGX_CONF_OK);
	assert(child.size == 16);

	/*all set, parent is 10, child is 16*/
	parent.size = 10;
	child.size = 16;
	assert(ngx_http_subrange_merge_loc_conf(&cf, &parent, &child) == NGX_CONF_OK);
	assert(child.size == 16);
	pass("test_ngx_http_subrange_merge_loc_conf");
}

void test_ngx_http_subrange_header_filter(){
	ngx_http_request_t	r;
	ngx_conf_t cf;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_http_subrange_filter_ctx_t fctx;
	ngx_table_elt_t *h;
	void *loc_conf[16];
	void *ctx[16];

	ngx_test_init_request(&r);
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

	/*subrange turn off*/
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	rlcf->size = 16;
	/*subrange turn on , but untouched*/
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);

	/*subrange turn on and touched*/
	fctx.touched = 1;
	/*with WRONG HTTP code in response*/
	r.headers_out.status = NGX_HTTP_OK;
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.touched == 0);
	fctx.touched = 1;
	/*without content-length in response */
	r.headers_out.content_length_n = -1;
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.touched == 0);
	fctx.touched = 1;
	/*test about subrange of above 2 cases*/
	ngx_http_request_t sr;
	ngx_test_init_request(&sr);
	sr.main = &r;
	/*with WRONG HTTP code in response*/
	sr.headers_out.status = NGX_HTTP_OK;
	assert(ngx_http_subrange_header_filter(&sr) == NGX_OK);
	assert(fctx.touched == 1);
	assert(fctx.done == 1);
	/*without content-length in response */
	r.headers_out.content_length_n = -1;
	assert(ngx_http_subrange_header_filter(&sr) == NGX_OK);
	assert(fctx.touched == 1);
	assert(fctx.done == 1);

	/*all OK test*/
	r.main = &r;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 16;
	ngx_table_elt_t crhdr = {
		0,
		ngx_string("Content-Range"),
		ngx_string("Bytes 0-15/16"),
		(u_char *)"content-range"
	};
	ngx_str_t content_range = ngx_string("Content-Range");
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;

	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 0);
	assert(fctx.content_range.end == 15);
	assert(fctx.content_range.total == 16);
	assert(fctx.done == 1);
	ngx_http_subrange_rm_header(&r.headers_out.headers, content_range);
	
	/*get the tail range*/
	ngx_str_t range_last = ngx_string("Bytes 1-5/6");
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;
	h->value = range_last;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	fctx.range_request = 1;
	fctx.touched = 1;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 5;
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 1);
	assert(fctx.content_range.end == 5);
	assert(fctx.content_range.total == 6);
	assert(fctx.done == 1);
	ngx_http_subrange_rm_header(&r.headers_out.headers, content_range);

	/*get range which is not at head or tail*/
	ngx_str_t range_between = ngx_string("Bytes 2-3/6"); 
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;
	h->value = range_between;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	fctx.range_request = 1;
	fctx.touched = 1;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 2;
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 2);
	assert(fctx.content_range.end == 3);
	assert(fctx.content_range.total == 6);
	assert(fctx.offset == 4);
	assert(fctx.done == 0);
	ngx_http_subrange_rm_header(&r.headers_out.headers, content_range);

	/*get the head range*/
	ngx_str_t range_head = ngx_string("Bytes 0-3/6"); 
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;
	h->value = range_head;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	fctx.range_request = 1;
	fctx.touched = 1;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 4;

	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.content_range.start == 0);
	assert(fctx.content_range.end == 3);
	assert(fctx.content_range.total == 6);
	assert(fctx.offset == 4);
	assert(fctx.done == 0);
	ngx_http_subrange_rm_header(&r.headers_out.headers, content_range);

	/*without content-range header*/
	assert(ngx_http_subrange_header_filter(&r) == NGX_OK);
	assert(fctx.done == 1);

	/*with invalid content-range header*/
	ngx_str_t range_invalid = ngx_string("Bytes 5-0/6"); 
	h = ngx_list_push(&r.headers_out.headers);
	*h = crhdr;
	h->value = range_invalid;
	ngx_memzero(&fctx, sizeof(ngx_http_subrange_filter_ctx_t));
	fctx.range_request = 1;
	fctx.touched = 1;
	r.headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
	r.headers_out.content_length_n = 6;
	assert(ngx_http_subrange_header_filter(&r) ==  NGX_HTTP_BAD_GATEWAY);
	assert(fctx.done == 1);
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

	/*untouched*/
	in = NULL;
	ctx->touched = 0;
	assert(ngx_http_subrange_body_filter(&r, in) == NGX_OK);

	/*touched , no output*/
	ctx->touched = 1;
	in = NULL;
	assert(ngx_http_subrange_body_filter(&r, in) == NGX_OK);

	/*normal output*/
	in = ngx_alloc_chain_link(r.pool);
	in->buf = ngx_pcalloc(r.pool, sizeof(ngx_buf_t));
	assert(ngx_http_subrange_body_filter(&r, in) == NGX_OK);
	assert(ctx->done == 0);
	assert(ctx->subrequest_done == 0);
	/*last buf*/
	in->buf->last_buf = 1;
	assert(ngx_http_subrange_body_filter(&r, in) == NGX_OK);
	assert(ctx->done == 0);
	assert(ctx->subrequest_done == 0);
	/*subrequest done*/
	in->buf->last_buf = 0;
	ctx->subrequest_done = 1;
	r.connection->buffered = 0;
	assert(ngx_http_subrange_body_filter(&r, in) == NGX_OK);

	/*test subrequest*/
	ngx_http_request_t sr;
	ngx_test_init_request(&sr);
	sr.main = &r;
	assert(ngx_http_subrange_body_filter(&sr, in) == NGX_OK);
	/*test subrequest when request is done*/
	ctx->done = 1;
	assert(ngx_http_subrange_body_filter(&sr, in) == NGX_OK);

	pass("test_ngx_http_subrange_body_filter");
}
void test_ngx_http_subrange_post_subrequest(){
	ngx_http_request_t r,mr;
	ngx_http_subrange_filter_ctx_t *ctx;
	ngx_test_init_request(&r);
	ngx_test_init_request(&mr);
	assert(ngx_http_subrange_post_subrequest(&r, NULL, NGX_OK) == NGX_OK);
	assert(ngx_http_subrange_post_subrequest(&r, NULL, NGX_AGAIN) == NGX_OK);
	assert(ngx_http_subrange_post_subrequest(&r, NULL, NGX_HTTP_BAD_GATEWAY) == NGX_HTTP_BAD_GATEWAY);
	ctx = ngx_http_get_module_ctx((&r), ngx_http_subrange_filter_module);
	assert(ctx && ctx->subrequest_done == 0);
	r.main = &mr;
	ctx = ngx_http_get_module_ctx((&mr), ngx_http_subrange_filter_module);
	assert(ngx_http_subrange_post_subrequest(&r, NULL, NGX_OK) == NGX_OK);
	assert(ctx && ctx->subrequest_done == 1);

	r.main = &r;
	assert(ngx_http_subrange_post_subrequest(&r, NULL, NGX_HTTP_BAD_GATEWAY) == NGX_HTTP_BAD_GATEWAY);
	ngx_http_set_ctx((&r), NULL, ngx_http_subrange_filter_module);
	assert(ngx_http_subrange_post_subrequest(&r, NULL, NGX_AGAIN) == NGX_ERROR);
	pass("test_ngx_http_subrange_post_subrequest");
}

int main(int argc, char *argv[]){	
	test_ngx_http_subrange_init();
	test_ngx_http_subrange_parse();
	test_ngx_http_subrange_parse_content_range();
	test_ngx_http_subrange_set_header();
	test_ngx_http_subrange_rm_header();
	test_ngx_http_subrange_get_range();
	test_ngx_http_subrange_checkpoint_and_recovery();
	test_ngx_http_subrange_create_subrequest();
	test_ngx_http_subrange_set_header_handler();
	test_ngx_http_subrange_header_filter();
	test_ngx_http_subrange_body_filter();
	test_ngx_http_subrange_post_subrequest();
	test_ngx_http_subrange_merge_loc_conf();
	return 0;
}
