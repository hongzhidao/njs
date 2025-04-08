
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Dmitry Volyntsev
 * Copyright (C) NGINX, Inc.
 */


#ifndef _NGX_JS_HTTP_H_INCLUDED_
#define _NGX_JS_HTTP_H_INCLUDED_


typedef struct ngx_js_http_s    ngx_js_http_t;
typedef struct ngx_js_tb_elt_s  ngx_js_tb_elt_t;


struct ngx_js_tb_elt_s {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    ngx_js_tb_elt_t  *next;
};


typedef struct {
    enum {
        GUARD_NONE = 0,
        GUARD_REQUEST,
        GUARD_IMMUTABLE,
        GUARD_RESPONSE,
    }                              guard;
    ngx_list_t                     header_list;
    ngx_js_tb_elt_t               *content_type;
} ngx_js_headers_t;


typedef struct {
    ngx_uint_t                     state;
    ngx_uint_t                     code;
    u_char                        *status_text;
    u_char                        *status_text_end;
    ngx_uint_t                     count;
    ngx_flag_t                     chunked;
    off_t                          content_length_n;

    u_char                        *header_name_start;
    u_char                        *header_name_end;
    u_char                        *header_start;
    u_char                        *header_end;
} ngx_js_http_parse_t;


typedef struct {
    u_char                        *pos;
    uint64_t                       chunk_size;
    uint8_t                        state;
    uint8_t                        last;
} ngx_js_http_chunk_parse_t;


typedef struct {
    njs_str_t                      url;
    ngx_int_t                      code;
    njs_str_t                      status_text;
    uint8_t                        body_used;
    njs_chb_t                      chain;
    ngx_js_headers_t               headers;
    void                           *header_value;
} ngx_js_response_t;


struct ngx_js_http_s {
    ngx_log_t                     *log;
    ngx_pool_t                    *pool;

    ngx_resolver_ctx_t            *ctx;
    in_port_t                      port;
    ngx_addr_t                     addr;
    ngx_addr_t                    *addrs;
    ngx_uint_t                     naddrs;
    ngx_uint_t                     naddr;

    ngx_peer_connection_t          peer;
    ngx_msec_t                     timeout;

    ngx_int_t                      buffer_size;
    ngx_int_t                      max_response_body_size;

#if (NGX_SSL)
    ngx_str_t                      tls_name;
    ngx_ssl_t                     *ssl;
    njs_bool_t                     ssl_verify;
#endif

    ngx_buf_t                     *buffer;
    ngx_buf_t                     *chunk;
    njs_chb_t                      chain;

    ngx_js_response_t              response;

    uint8_t                        header_only;
    uint8_t                        done;
    ngx_js_http_parse_t            http_parse;
    ngx_js_http_chunk_parse_t      http_chunk_parse;

    ngx_int_t                    (*process)(ngx_js_http_t *http);
    njs_int_t                    (*headers_append)(ngx_js_http_t *http,
                                                   ngx_js_headers_t *headers,
                                                   u_char *name, size_t len,
                                                   u_char *value, size_t vlen);
    void                         (*ready_handler)(ngx_js_http_t *http);
    void                         (*error_handler)(ngx_js_http_t *http, int err,
                                                  const char *fmt, ...);
};


void ngx_js_http_connect(ngx_js_http_t *http);
ngx_resolver_ctx_t *ngx_js_http_resolve(ngx_js_http_t *http, ngx_resolver_t *r,
    ngx_str_t *host, in_port_t port, ngx_msec_t timeout);
void ngx_js_http_done(ngx_js_http_t *http);

#endif /* _NGX_JS_HTTP_H_INCLUDED_ */
