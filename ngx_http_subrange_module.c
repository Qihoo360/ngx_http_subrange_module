#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/*
 * This module is used to split a normal http request to multiple Range request to upstreams
 * We do this by modifing the http header and adding the Range header to issue multiple range reqeusts.
 * This is insensitive to client. 
 *
 * We send the output of main request first which is different from the default behavior that 
 * at last. So there is three problems we should pay attention to:
 * 1.We should clear the buf->last_buf flag after the main request because this is not the last 
 *   buffer in our case. 
 * 2.Set buf->last_buf of the last subrequest's last buf. Nginx do not set buf->last_buf of 
 *   subrequest.
 * 3.Fix r->connection->write->delayed and set to 0 if all the data are sent actually
 * */

static ngx_int_t ngx_http_subrange_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_subrange_filter_init(ngx_conf_t *cf);
static void * ngx_http_subrange_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_subrange_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_subrange_set_header_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_subrange_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_subrange_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_subrange_post_subrequest(ngx_http_request_t *r, void *data, ngx_int_t rc);

static ngx_command_t ngx_http_subrange_commands[] = { 
	{ ngx_string("subrange"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,               
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,      
		0,
		NULL },
	ngx_null_command
};

static ngx_http_module_t ngx_http_subrange_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_subrange_init,                   /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_subrange_create_loc_conf,        /* create location configuration */
	ngx_http_subrange_merge_loc_conf          /* merge location configuration */
};

ngx_module_t ngx_http_subrange_module = {
	NGX_MODULE_V1,
	&ngx_http_subrange_module_ctx,            /* module context */
	ngx_http_subrange_commands,               /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_http_module_t ngx_http_subrange_filter_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_subrange_filter_init,         /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	NULL,                                  /* create location configuration */
	NULL                                   /* merge location configuration */
};
ngx_module_t ngx_http_subrange_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_subrange_filter_module_ctx,  /* module context */
	NULL,                                  /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

/*------------- the api implements ------------*/
#define NGX_HTTP_RANGE_ON   0x01;
#define NGX_HTTP_RANGE_OFF  0x02;
#define NGX_HTTP_RANGE_AUTO 0x04;
#define NGX_DEFAULT_RANGE_SIZE 524288 //512*1024
#define NGX_RANGE_KEY "Range"
#define NGX_RANGE_KEY_SIZE sizeof(NGX_RANGE_KEY)
typedef struct ngx_http_subrange_loc_conf_s{
	ngx_int_t size;
}ngx_http_subrange_loc_conf_t;

typedef struct ngx_http_subrange_s{
	ngx_uint_t start;
	ngx_uint_t end;
	ngx_uint_t total;
}ngx_http_subrange_t;

typedef struct ngx_http_subrange_filter_ctx_s{
	ngx_uint_t offset;
	ngx_uint_t total;
	ngx_uint_t sn;				/*sequence number of subrequest*/
	ngx_http_subrange_t range;
	ngx_http_subrange_t content_range;
	ngx_http_request_t *r;
	ngx_uint_t range_request:1; /*Is this original a range request*/
	ngx_uint_t singlepart:1;    /*Is this a single part range, we only process single part range request now*/
	ngx_uint_t touched:1;       /*request has been touched by this module*/
	ngx_uint_t processed:1;     /*subrequest has been processed*/
	ngx_uint_t done:1;     /*subrequest has been processed*/
	ngx_uint_t subrequest_done:1;     /*subrequest has been processed*/
}ngx_http_subrange_filter_ctx_t;

static ngx_http_post_subrequest_t ngx_http_subrange_post_subrequest_handler = 
{ngx_http_subrange_post_subrequest,NULL};

static ngx_str_t ngx_http_status_lines[] = {
	ngx_string("200 OK"),
	ngx_string("201 Created"),
	ngx_string("202 Accepted"),
	ngx_null_string,  /* "203 Non-Authoritative Information" */
	ngx_string("204 No Content"),
	ngx_null_string,  /* "205 Reset Content" */
	ngx_string("206 Partial Content"),
	ngx_null_string,  /* terminated */
};

static ngx_int_t ngx_http_subrange_init(ngx_conf_t *cf){
	ngx_http_handler_pt             *h;
	ngx_http_core_main_conf_t       *cmcf;
	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if(h == NULL){
		return NGX_ERROR;
	}
	*h = ngx_http_subrange_set_header_handler;
	return NGX_OK;
}
static ngx_int_t ngx_http_subrange_filter_init(ngx_conf_t *cf){
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_subrange_header_filter;

	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_subrange_body_filter;
	return NGX_OK;
}

static void * ngx_http_subrange_create_loc_conf(ngx_conf_t *cf){
	ngx_http_subrange_loc_conf_t *rlcf;
	rlcf = ngx_palloc(cf->pool, sizeof(ngx_http_subrange_loc_conf_t));
	if(rlcf == NULL){
		return NULL;
	}
	rlcf->size = NGX_CONF_UNSET;
	return rlcf;
}
static char * ngx_http_subrange_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child){
	ngx_http_subrange_loc_conf_t *prev,*conf;
	prev = parent;
	conf = child;
	ngx_conf_merge_value(conf->size, prev->size, 0);
	return NGX_CONF_OK;
}
static ngx_int_t ngx_http_subrange_parse(ngx_http_request_t *r, ngx_http_subrange_filter_ctx_t
		*ctx, ngx_http_subrange_t *range){

	u_char *p, c;
	ngx_uint_t start, end, val, len, i;
	enum parse_state{
		R_NONE,
		R_START,
		R_END,
		R_FIN,
	} state;

	start = 0;
	end = 0;
	val = 0;

	state = R_NONE;

	p = r->headers_in.range->value.data;
	len = r->headers_in.range->value.len;

	ctx->singlepart = 1;
	for(i = 0; i < len; ++i){
		c = p[i];
		if(c >= '0' && c <= '9'){
			if(state == R_NONE){
				state = R_START;
			}
			if(state == R_END){
				state = R_FIN;
			}
			val = val*10+(c-'0');
		}
		if(c == '-'){
			if(state == R_START){
				start = val;
				state = R_END;
			}
			if(state == R_NONE){
				start = (ngx_uint_t)-1;
				state = R_END;
			}
			val = 0;
		}
		if(c == ','){
			ctx->singlepart = 0;
			break;
		}
	}
	if(state == R_FIN){
		end = val;
	}
	if(state == R_END){
		end = (ngx_uint_t)-1;
	}
	range->start = start;
	range->end= end;
	return NGX_OK;
}
static ngx_int_t ngx_http_subrange_parse_content_range(ngx_http_request_t *r, ngx_http_subrange_filter_ctx_t
		*ctx, ngx_http_subrange_t *range){
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	u_char *p, c;
	ngx_uint_t start, end, val, total, len, i;
	start = 0;
	end   = 0;
	val   = 0;
	total = 0;

	//part = &r->upstream->headers_in.headers.part;
	part = &r->headers_out.headers.part;
	h = part->elts;
	for(i = 0;/* void */; ++i){
		if(i >= part->nelts){
			if(part->next == NULL){
				break;
			}
			part = part->next;
			h = part->elts;
			i = 0;
		}
		if(ngx_strncasecmp((u_char *)"content-range",h[i].lowcase_key,h[i].key.len)==0){
			h = &h[i];
			break;
		}
	}

	p = h->value.data;
	len = h->value.len;
	
	for(i = 0; i < len; ++i){
		c = p[i];
		if(c >= '0' && c <= '9'){
			val = val*10+(c-'0');
		}
		if(c == '-'){
			start = val;
			val = 0;
		}
		if(c == '/'){
			end = val;
			val = 0;
		}
	}
	total = val;

	range->start = start;
	range->end = end;
	range->total = total;
	if(ctx->range.end == (ngx_uint_t)-1){
		ctx->range.end = total - 1;	
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange body filter: set range end boundary:%ui",
				ctx->range.end);
	}
	return NGX_OK;
}
static ngx_int_t ngx_http_subrange_set_header(ngx_http_request_t *r, ngx_list_t *headers, ngx_str_t key, ngx_str_t val,
		ngx_table_elt_t **hdr){
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_uint_t i;
	part = &headers->part;
	h = part->elts;
	for(i = 0;/**/; ++i){
		if(i >= part->nelts){
			if(part->next == NULL){
				break;
			}
			part = part->next;
			h = part->elts;
			i = 0;
		}
		if(ngx_strncasecmp(key.data, h[i].lowcase_key, h[i].key.len) == 0){
			h[i].value = val;
			if(hdr){
				*hdr = &h[i];
			}
			return NGX_OK;
		}
	}
	h = ngx_list_push(headers);
	if(h == NULL){
		return NGX_ERROR;
	}
	if(hdr){
		*hdr = h;
	}
	h->key = key;
	h->value = val;
	h->lowcase_key = ngx_palloc(r->pool, h->key.len);
	ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
	h->hash = ngx_hash_key(h->lowcase_key, h->key.len);
	return NGX_OK;
}
static ngx_int_t ngx_http_subrange_rm_header(ngx_list_t *headers, ngx_str_t key){
	ngx_list_part_t *part, *prev;
	ngx_table_elt_t *h;
	ngx_uint_t i,j;

	part = &headers->part;
	h = part->elts;
	prev = NULL;
	for(i = 0;/* void */; ++i){
		if(i >= part->nelts){
			if(part->next == NULL){
				break;
			}
			prev = part;
			part = part->next;
			h = part->elts;
			i = 0;
		}
		if(ngx_strncasecmp(key.data, h[i].lowcase_key, h[i].key.len) == 0){
			if(part->nelts == 1){ //just skip if we have one header in the part
				prev->next = part->next;
				break;
			}
			j = i + 1;
			while(j <= part->nelts){
				h[i++] = h[j++];
			}
			part->nelts -= 1;
			break;
		}
	}
	return NGX_OK;
}
static ngx_str_t ngx_http_subrange_get_range(ngx_http_request_t *r, ngx_int_t start, ngx_int_t offset){
	u_char *data;
	ngx_str_t range = ngx_null_string;
	ngx_str_t p = ngx_string("bytes=");
	ngx_int_t size;

	size  = p.len + 2*NGX_SIZE_T_LEN + 1;
	data = ngx_palloc(r->pool, size);
	if(!data){
		range.len = 0;
		range.data = NULL;
		return range;
	}
	range.data = data;
	range.len = ngx_snprintf(range.data, range.len, "bytes=%ud-%ud", start, offset)
		- range.data;
	return range;
}
static ngx_int_t ngx_http_subrange_create_subrequest(ngx_http_request_t *r, ngx_http_subrange_filter_ctx_t *ctx){
	ngx_str_t uri;
	ngx_str_t args;
	ngx_uint_t flags;
	ngx_http_request_t *sr;
	ngx_str_t range_key = ngx_string("Range");
	ngx_str_t range_value;
	ngx_int_t size;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_table_elt_t *hdr;

	uri = r->uri;
	args = r->args;
	flags = NGX_HTTP_SUBREQUEST_WAITED;
	if(ngx_http_subrequest(r, &uri, &args, &sr, &ngx_http_subrange_post_subrequest_handler, flags)==NGX_ERROR){
		return NGX_ERROR;
	}
	if(sr){
		/*There is a bug in ngx_http_subrequest when assgin r->headers_in to sr->headers_in due to assginment problem of ngx_list_t:
		 * ngx_list_t has the 'part' member which is not a pointer , two ngx_list_t objects have different address of 'part',
		 * ngx_list_t use the 'last' member which is a pointer point to the last node('part'). If we just have a signle part, the 'last''s
		 * value is the address of 'part', so  when doing assignment: a = b; a.last points to &b.part which we expect it points to &a.part,
		 * because the assignment copys the pointer from b.last to a.last; 
		 *
		 * At this time , when we use ngx_list_push to push new element, the element is actually added to list b.
		 * Here , we want to push new header to sr->headers_in.headers ,however, this is failed because we have pushed
		 * it to the main request r->headers_in.headers
		 *
		 * Now do something to work around this and do not forget to submit an issue to nginx community
		 * */
		if(sr->headers_in.headers.last == &r->headers_in.headers.part){
			sr->headers_in.headers.last = &sr->headers_in.headers.part;
		}
		rlcf = ngx_http_get_module_loc_conf(r->main, ngx_http_subrange_module);
		size = sizeof("bytes=-") + 2*NGX_SIZE_T_LEN;
		range_value.data = ngx_palloc(sr->pool, size);
		range_value.len = ngx_sprintf(range_value.data, "bytes=%i-%i", ctx->offset, ctx->offset + rlcf->size - 1)
			- range_value.data;
		ngx_http_subrange_set_header(sr, &sr->headers_in.headers, range_key, range_value, &hdr);
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange body filter: subrequest:%ud subrange:%i-%i",
				ctx->sn, ctx->offset, ctx->offset + rlcf->size -1);
		if(hdr){
			sr->headers_in.range = hdr;
		}

		sr->header_in = r->header_in;
	}
	ctx->sn += 1;
	ctx->subrequest_done = 0;
	ctx->r = sr;
	return NGX_OK;
}
static ngx_int_t ngx_http_subrange_set_header_handler(ngx_http_request_t *r){
	ngx_table_elt_t *h;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_http_subrange_filter_ctx_t *ctx;
	ngx_int_t rstart,rend;
	ngx_str_t key = ngx_string("Range");

	rstart = 0;
	rend   = 0;

	/*Only support GET or POST*/
	if(!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST))){
		return NGX_DECLINED;
	}
	rlcf = ngx_http_get_module_loc_conf(r, ngx_http_subrange_module);
	if(rlcf->size == NGX_CONF_UNSET || rlcf->size == 0){
		return NGX_DECLINED;
	}
	ctx = ngx_palloc(r->pool, sizeof(ngx_http_subrange_filter_ctx_t));
	if(ctx == NULL){
		return NGX_ERROR;
	}
	ctx->r = r;
	ctx->range_request = 0;
	ctx->offset = 0;
	ctx->touched = 0; // the request has been split to subrange request
	ctx->processed = 0; //the request/subrequest has been processed
	ctx->done = 0;  // all subrequest done 
	ctx->sn = 1;    // subrange sequence number
	ctx->subrequest_done = 0; //the request/subrequest has been processed

	ngx_http_set_ctx(r, ctx, ngx_http_subrange_filter_module);
	if(r == r->main){
		if(r->internal && r->headers_in.range){ //internal redirect main request, Range has been added
			return NGX_DECLINED;
		}
	}
	/*TODO process if-range*/

	/*Not a range request*/
	if(r->headers_in.range == NULL){

		h = ngx_list_push(&r->headers_in.headers);
		if(h == NULL){
			return NGX_ERROR;
		}
		h->key = key;
		h->lowcase_key = ngx_palloc(r->pool, h->key.len);
		ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
		h->hash = ngx_hash_key(h->lowcase_key, h->key.len);
		h->value = ngx_http_subrange_get_range(r, ctx->offset, ctx->offset + rlcf->size - 1);
		r->headers_in.range = h;
		ctx->touched = 1;
		ctx->range.start = ctx->offset;
		ctx->range.end = ctx->offset + rlcf->size - 1;

	}else{
		ctx->range_request = 1;
		if(ngx_http_subrange_parse(r, ctx, &ctx->range)!= NGX_OK){
			return NGX_ERROR;
		}
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange filter: parse range s:%ui,e:%ui",
				ctx->range.start, ctx->range.end);
		if(ctx->range.start == (ngx_uint_t)-1){
			return NGX_DECLINED;
		}
		/*Do not support multipart ranges*/
		if(ctx->singlepart == 0){
			return NGX_DECLINED;
		}
		ctx->offset = ctx->range.start;
		if(ctx->range.end > ctx->offset + rlcf->size){
			r->headers_in.range->value = ngx_http_subrange_get_range(r, ctx->offset, ctx->offset + rlcf->size -1);
			ctx->touched = 1;
		}else{
			return NGX_DECLINED;
		}
	}
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange filter: mainrequest subrange:%i-%i",
			ctx->offset, ctx->offset + rlcf->size -1);
	return NGX_DECLINED;
}
static ngx_int_t ngx_http_subrange_header_filter(ngx_http_request_t *r){
	ngx_int_t rstart,rend,rtotal,size;
	ngx_http_subrange_loc_conf_t *rlcf;
	ngx_http_subrange_filter_ctx_t *ctx;
	ngx_str_t content_length;
	ngx_str_t content_length_key = ngx_string("Content-Length");
	ngx_str_t range_key = ngx_string("Range");
	ngx_str_t content_range_key = ngx_string("Content-Range");
	ngx_str_t content_range;

	rstart = 0;
	rtotal = 0;
	rend   = 0;
	size   = 0;

	rlcf = ngx_http_get_module_loc_conf(r->main, ngx_http_subrange_module);
	if(rlcf->size == NGX_CONF_UNSET ||  rlcf->size == 0){
		return ngx_http_next_header_filter(r);
	}
	ctx = ngx_http_get_module_ctx(r->main, ngx_http_subrange_filter_module);
	if(ctx == NULL || !ctx->touched){
		return ngx_http_next_header_filter(r);
	}
	if(r->headers_out.content_length_n == -1){
		return ngx_http_next_header_filter(r);
	}
	if(r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT)
	{
		if(r == r->main){
			ctx->touched = 0; //upstream do not support subrange , untouch the request
		}else{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange header filter: subrequest error ,terminate request");
			ctx->done = 1; //some errors occur, finish the request;
			r->main->connection->error = 1; // terminate the main request forcely
		}
		return ngx_http_next_header_filter(r);
	}
	ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange header filter: p:%d,t:%d,d:%d,sd:%d",
			ctx->processed, ctx->touched, ctx->done, ctx->subrequest_done);
	ngx_http_subrange_parse_content_range(r, ctx, &ctx->content_range);
	/*Get the content range, and update the progress*/
	if(r == r->main && !ctx->range_request){
		r->headers_out.status = NGX_HTTP_OK; //Change 206 to 200
		r->headers_out.content_length_n = ctx->content_range.total;

		content_length.data = ngx_palloc(r->pool, NGX_SIZE_T_LEN);
		content_length.len = ngx_sprintf(content_length.data, "%ui", ctx->content_range.total)
							- content_length.data;
		ngx_http_subrange_set_header(r, &r->headers_out.headers, content_length_key, content_length,NULL);

		r->headers_out.status_line = ngx_http_status_lines[0];
		r->headers_in.range = NULL; // clear the request range header to surpress ngx_http_range_filter_module
		r->headers_out.content_range = NULL;
		ngx_http_subrange_rm_header(&r->headers_in.headers, range_key);
		ngx_http_subrange_rm_header(&r->headers_out.headers, content_range_key);
	}else if(ctx->content_range.end + 1 < ctx->content_range.total){
		r->headers_out.content_length_n = ctx->range.end - ctx->range.start + 1;
		content_length.data = ngx_palloc(r->pool, NGX_SIZE_T_LEN);
		content_length.len = ngx_sprintf(content_length.data, "%ui", r->headers_out.content_length_n)
							 - content_length.data;
		ngx_http_subrange_set_header(r, &r->headers_out.headers, content_length_key, content_length, NULL);

		size = 0;
		size += sizeof("bytes -/") - 1 + 3 * NGX_SIZE_T_LEN;
		content_range.data = ngx_palloc(r->pool, size);
		content_range.len = ngx_sprintf(content_range.data, "bytes %ui-%ui/%ui",
				ctx->range.start, ctx->range.end, ctx->content_range.total) - content_range.data;

		ngx_http_subrange_set_header(r, &r->headers_out.headers, content_range_key, content_range, NULL);
		ctx->done = 0;
	}
	if(ctx->content_range.end + 1 >= ctx->content_range.total){
		ctx->done = 1;
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange header filter: request done e:%ui,l:%ui",
				ctx->content_range.end, ctx->content_range.total);
		return ngx_http_next_header_filter(r);
	}
	ctx->offset = ctx->content_range.end + 1;
    return ngx_http_next_header_filter(r);
}
static ngx_int_t ngx_http_subrange_body_filter(ngx_http_request_t *r, ngx_chain_t *in){
	ngx_http_subrange_filter_ctx_t *ctx;
	ngx_chain_t *cl;
	ngx_int_t rc;

	ctx = ngx_http_get_module_ctx(r->main, ngx_http_subrange_filter_module);
	if(ctx == NULL || !ctx->touched){
		return ngx_http_next_body_filter(r, in);
	}
	ngx_log_debug7(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange body filter: p:%d,t:%d,d:%d,sd:%d,c:%p,r:%p,b:%d",
			ctx->processed, ctx->touched, ctx->done, ctx->subrequest_done, in, r, r->connection->buffered);
	if(r == r->main){
		for (cl = in; cl; cl = cl->next) {
			if (cl->buf->last_buf) {
				cl->buf->last_buf = 0;
				cl->buf->flush = 1;
				ctx->subrequest_done = 1;
				break;
			}   
		}
		rc = ngx_http_next_body_filter(r, in);
		ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange body filter: mainrequest p:%d, rc:%d, b:%d, d:%d",
				ctx->processed, rc, r->connection->buffered,r->connection->write->delayed);
		if(rc == NGX_ERROR || rc == NGX_AGAIN || ctx->done){
			return rc;
		}
		/* NGX_OK */
		if(!r->connection->buffered && ctx->subrequest_done){
			/*All data has been sent actually, remove the timer event and the delayed flag
			 *or sometimes it may invoke some unexpected handler
			 * */
			if(r->connection->write->delayed){
				if(r->connection->write->timer_set){
					ngx_del_timer(r->connection->write);
					r->connection->write->delayed = 0;
				}
			}
			/*clean up temporary files*/
			if(ctx->r->upstream->pipe->temp_file->file.fd != NGX_INVALID_FILE){
				ngx_pool_run_cleanup_file(ctx->r->pool, ctx->r->upstream->pipe->temp_file->file.fd);
				ctx->r->upstream->pipe->temp_file->file.fd = NGX_INVALID_FILE;
			}

			if(ngx_http_subrange_create_subrequest(r->main, ctx) != NGX_OK){
				return NGX_ERROR;
			}
		}
		return NGX_OK;

	}else{
		/*send last buf(nginx will set cl->buf->last_buf = 0 if it is a subrequest,we fix that)*/
		if(ctx && ctx->done && in){
			for(cl = in; cl->next; cl = cl->next){/*void*/}
			cl->buf->last_buf = 1;
		}
		rc = ngx_http_next_body_filter(r, in);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange body filter: after next body filter:rc:%d",
				rc);
		return rc;
	}
}
static  ngx_int_t ngx_http_subrange_post_subrequest(ngx_http_request_t *r, void *data, ngx_int_t rc){
	ngx_http_subrange_filter_ctx_t *ctx;
	ctx = ngx_http_get_module_ctx(r->main, ngx_http_subrange_filter_module);
	if(rc != NGX_OK && rc != NGX_AGAIN){
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange post subrequest :error of subrequest rc:%i", rc);
		return rc;
	}
	if(ctx == NULL){
		return NGX_ERROR;
	}
	if(r != r->main){
		ctx->subrequest_done = 1;
	}
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log,0, "http subrange post subrequest:c:%ui,rc:%i",r->main->count, rc);
	r->post_subrequest = NULL;
	return NGX_OK;
}
