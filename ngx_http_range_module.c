#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_range_init(ngx_conf_t *cf);
static char * ngx_http_range_switch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_range_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_http_range_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_range_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_range_commands[] = { 
	{ ngx_string("range"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,               
		ngx_http_range_switch,
		NGX_HTTP_LOC_CONF_OFFSET,      
		0,
		NULL },

	{ ngx_string("range_size"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,               
		ngx_http_range_size,
		NGX_HTTP_LOC_CONF_OFFSET,      
		0,
		NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_range_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_range_init,                   /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_range_create_loc_conf,        /* create location configuration */
	ngx_http_range_merge_loc_conf          /* merge location configuration */
};

ngx_module_t ngx_http_range_module = {
	NGX_MODULE_V1,
	&ngx_http_range_module_ctx,            /* module context */
	ngx_http_range_commands,               /* module directives */
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
typedef struct ngx_http_range_loc_conf_s{
	ngx_int_t range;
}ngx_http_range_loc_conf_t;

static ngx_int_t ngx_http_range_init(ngx_conf_t *cf){
	return NGX_OK;
}
static char * ngx_http_range_switch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	return NULL;
}

static char * ngx_http_range_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	return NULL;
}
static void * ngx_http_range_create_loc_conf(ngx_conf_t *cf){
	return NULL;
}
static char * ngx_http_range_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child){
	return NULL;
}

