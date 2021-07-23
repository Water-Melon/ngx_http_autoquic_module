/*
 * Copyright (C) Niklaus F.Schen.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_quic_connection.h>

#define NGX_HTTP_AUTOQUIC_DEFAULT_FALLBACK_PERIOD 30000 /*ms*/

typedef struct {
    ngx_flag_t               enable;
    ngx_flag_t               fallback;
    ngx_msec_t               period;
    uint32_t                 max_snd_ssthresh;
    ngx_array_t              headers;
    ngx_pool_t              *pool;
} ngx_http_autoquic_main_conf_t;

typedef struct {
    ngx_int_t                upgraded;
} ngx_http_autoquic_module_ctx_t;

typedef struct {
    ngx_str_t                key;
    ngx_http_complex_value_t val;
} ngx_http_autoquic_header_t;

typedef struct {
    unsigned long            time;
} ngx_http_autoquic_statis_t;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_int_t ngx_http_autoquic_pre_conf(ngx_conf_t *cf);
static void *ngx_http_autoquic_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_autoquic_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_autoquic_post_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_autoquic_header_filter(ngx_http_request_t *r);
static char *ngx_http_autoquic_header_directive_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_autoquic_add_header(ngx_http_request_t *r, ngx_http_autoquic_header_t *h);
static ngx_int_t ngx_http_autoquic_set_cookie(ngx_http_request_t *r, ngx_http_autoquic_statis_t *statis);
static int ngx_http_autoquic_parse_cookie_value(ngx_http_request_t *r, ngx_str_t *val, ngx_http_autoquic_statis_t *statis);

static ngx_str_t cookie = ngx_string("__autoquic_cookie__");

static ngx_command_t ngx_http_autoquic_commands[] = {
    {
        ngx_string("autoquic"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_autoquic_main_conf_t, enable),
        NULL
    },
    {
        ngx_string("autoquic_fallback"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_autoquic_main_conf_t, fallback),
        NULL
    },
    {
        ngx_string("autoquic_fallback_period"),/*configure in sec*/
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_autoquic_main_conf_t, period),
        NULL
    },
    {
        ngx_string("autoquic_header"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
        ngx_http_autoquic_header_directive_handler,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_autoquic_module_ctx = {
    ngx_http_autoquic_pre_conf,          /* preconfiguration */
    ngx_http_autoquic_post_conf,         /* postconfiguration */
    ngx_http_autoquic_create_main_conf,  /* create main configuration */
    ngx_http_autoquic_init_main_conf,    /* init main configuration */
    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */
    NULL,                                /* create location configuration */
    NULL                                 /* merge location configuration */
};

ngx_module_t ngx_http_autoquic_module = {
    NGX_MODULE_V1,
    &ngx_http_autoquic_module_ctx, /* module context */
    ngx_http_autoquic_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_autoquic_variables[] = {
    ngx_http_null_variable
};

static ngx_int_t ngx_http_autoquic_pre_conf(ngx_conf_t *cf)
{
    ngx_http_variable_t *cv, *v;
    for (cv = ngx_http_autoquic_variables; cv->name.len; cv++) {
        v = ngx_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) return NGX_ERROR;
        *v = *cv;
    }

    return NGX_OK;
}

static void *ngx_http_autoquic_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_autoquic_main_conf_t *amcf;

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_autoquic_main_conf_t));
    if (amcf == NULL) return NULL;
    amcf->pool = cf->pool;
    amcf->enable = NGX_CONF_UNSET;
    amcf->period = NGX_CONF_UNSET_MSEC;
    amcf->fallback = NGX_CONF_UNSET;
    amcf->max_snd_ssthresh = 0;
    if (ngx_array_init(&amcf->headers, cf->pool, 6, sizeof(ngx_http_autoquic_header_t)) != NGX_OK) {
        return NULL;
    }

    return amcf;
}

static char *ngx_http_autoquic_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_autoquic_main_conf_t *amcf = conf;

    if (amcf->enable == NGX_CONF_UNSET)
        amcf->enable = 0;
    if (amcf->fallback == NGX_CONF_UNSET)
        amcf->fallback = 0;
    if (amcf->period == NGX_CONF_UNSET_MSEC)
        amcf->period = NGX_HTTP_AUTOQUIC_DEFAULT_FALLBACK_PERIOD;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_autoquic_post_conf(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_autoquic_header_filter;
    return NGX_OK;
}

static char *ngx_http_autoquic_header_directive_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autoquic_main_conf_t    *amcf;
    ngx_http_autoquic_header_t       *h;
    ngx_str_t                        *value;
    ngx_http_compile_complex_value_t  ccv;

    value = cf->args->elts;
    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_autoquic_module);
    h = ngx_array_push(&amcf->headers);
    if (h == NULL) return NGX_CONF_ERROR;

    h->key = value[1];

    if (value[2].len == 0) {
        ngx_memzero(&h->val, sizeof(ngx_http_complex_value_t));
    } else {
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[2];
        ccv.complex_value = &h->val;
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_autoquic_header_filter(ngx_http_request_t *r)
{
    ngx_uint_t                      i;
    socklen_t                       tisize;
    struct tcp_info                 ti;
    ngx_str_t                       val;
    struct timeval                  tv;
    ngx_http_autoquic_header_t     *h;
    ngx_http_autoquic_main_conf_t  *amcf;
    ngx_http_autoquic_module_ctx_t *ctx;

    amcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_autoquic_module);
    if (!amcf->enable)
        return ngx_http_next_header_filter(r);

    ctx = ngx_http_get_module_ctx(r, ngx_http_autoquic_module);
    if (ctx == NULL) {
        ctx = (ngx_http_autoquic_module_ctx_t *)ngx_pcalloc(r->pool, sizeof(ngx_http_autoquic_module_ctx_t));
        if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_http_set_ctx(r, ctx, ngx_http_autoquic_module);
        ctx->upgraded = 0;
    }

    ngx_http_autoquic_statis_t statis;
#if (NGX_HTTP_QUIC)
    if (r->connection->quic) {
        if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie, &val) != NGX_DECLINED) {
            if (ngx_http_autoquic_parse_cookie_value(r, &val, &statis) != NGX_OK)
                return NGX_ERROR;
        } else {
            gettimeofday(&tv, NULL);
            statis.time = tv.tv_sec * 1000000 + tv.tv_usec;
            if (ngx_http_autoquic_set_cookie(r, &statis) != NGX_OK)
                return NGX_ERROR;
        }
    }

    gettimeofday(&tv, NULL);
    unsigned long now = tv.tv_sec * 1000000 + tv.tv_usec;
    if (r->connection->quic && amcf->fallback && now > statis.time && now-statis.time > amcf->period*1000)
    {
        ngx_connection_t *c = r->connection->quic->connection;
        if (c->udp == NULL) c = r->connection->quic->parent;
        ngx_quic_connection_t *qc = ngx_quic_get_connection(c);
        if (qc != NULL) {
            ngx_quic_send_ctx_t *send_ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_application);
            if (send_ctx->pnum < send_ctx->largest_pn || send_ctx->pnum - send_ctx->largest_pn <= 60) {
                ngx_quic_reset_stream(r->connection, NGX_HTTP_V3_ERR_VERSION_FALLBACK);
                return NGX_HTTP_VERSION_NOT_SUPPORTED;
            }
        }
    } else
#endif

    if (r->connection->udp == NULL
#if (NGX_HTTP_QUIC)
        && r->connection->quic == NULL
#endif
        && !ctx->upgraded)
    {
        tisize = sizeof(ti);
        getsockopt(r->connection->fd, IPPROTO_TCP, TCP_INFO, &ti, &tisize);
        if (ti.tcpi_snd_ssthresh > amcf->max_snd_ssthresh)
            amcf->max_snd_ssthresh = ti.tcpi_snd_ssthresh;
        if (ti.tcpi_snd_ssthresh && (ti.tcpi_retransmits || ti.tcpi_lost || ti.tcpi_retrans || ti.tcpi_total_retrans || ti.tcpi_snd_ssthresh < (amcf->max_snd_ssthresh >> 1))) {
            ctx->upgraded = 1;
            for (i = 0; i < amcf->headers.nelts; ++i) {
                h = &((ngx_http_autoquic_header_t *)(amcf->headers.elts))[i];
                if (ngx_http_autoquic_add_header(r, h) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
            gettimeofday(&tv, NULL);
            statis.time = tv.tv_sec * 1000000 + tv.tv_usec;
            if (ngx_http_autoquic_set_cookie(r, &statis) != NGX_OK)
                return NGX_ERROR;
        }
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_autoquic_add_header(ngx_http_request_t *r, ngx_http_autoquic_header_t *h)
{
    ngx_str_t         value;
    ngx_table_elt_t  *header;

    if (ngx_http_complex_value(r, &h->val, &value) != NGX_OK) {
        return NGX_ERROR;
    }
    if (value.len) {
        header = ngx_list_push(&r->headers_out.headers);
        if (header == NULL) return NGX_ERROR;

        header->hash = 1;
        header->key = h->key;
        header->value = value;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_autoquic_set_cookie(ngx_http_request_t *r, ngx_http_autoquic_statis_t *statis)
{
    u_char *buf;
    int n;
    ngx_table_elt_t *p;

    if ((buf = ngx_pcalloc(r->pool, 256)) == NULL) return NGX_ERROR;
    n = snprintf((char *)buf, 255, "%s=%lu", (char *)(cookie.data), statis->time);

    if ((p = ngx_list_push(&r->headers_out.headers)) == NULL) return NGX_ERROR;
    p->hash = 1;
    ngx_str_set(&p->key, "Set-Cookie");
    p->value.len = n;
    p->value.data = buf;
    return NGX_OK;
}

static int ngx_http_autoquic_parse_cookie_value(ngx_http_request_t *r, ngx_str_t *val, ngx_http_autoquic_statis_t *statis)
{
    char *buf = ngx_pcalloc(r->pool, val->len+1);
    if (buf == NULL) return NGX_ERROR;
    memcpy(buf, val->data, val->len);

    sscanf((char *)(val->data), "%lu", &(statis->time));

    return NGX_OK;
}

