## ngx_http_autoquic_module
The Nginx module to upgrade and fallback HTTP version automatically for nginx-quic.



### Installation

This module should be installed by adding option `--add-module`at `configure` phase.

```shell
$ cd nginx-quic
$ git clone https://github.com/Water-Melon/ngx_http_autoquic_module.git
$ ./auto/configure --with-debug --with-http_v3_module       \
                       --with-cc-opt="-I../boringssl/include"   \
                       --with-ld-opt="-L../boringssl/build/ssl  \
                                      -L../boringssl/build/crypto"
                       ...
                       --add-module=ngx_http_autoquic_module
$ make && make install
```



### Directives

1. #### autoquic

   - Syntax: `autoquic` `on|off`;
   - Default: `off`
   - Context: `http`
   - Description: to activate this module or not.

2. #### autoquic_header

   - Syntax: `autoquic` *header_key* "*header_value*";
   - Default: -
   - Context: `http`
   - Description: if upgrade is allowed, the header indicated by *header_key* and *header_value* will be added in response headers.

3. #### autoquic_fallback

   - Syntax: `autoquic_fallback` `on|off`;
   - Default: `off`
   - Context: `http`
   - Description: to activate version fallback or not.

4. #### autoquic_fallback_period

   - Syntax: `autoquic_fallback_period` *seconds*;
   - Default: 30s
   - Context: `http`
   - Description: to set the minimum duration time after verion upgraded.



### Example

```nginx
http {
    autoquic on;
    autoquic_fallback on;
    autoquic_header Alt-Svc '$http3=":443"; quic=":443"; h3=":443"; ma=86400';
    autoquic_header QUIC-Status $quic;
    autoquic_fallback_period 30;

    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen 443 ssl;              # TCP listener for HTTP/1.1
        listen 443 http3 reuseport;  # UDP listener for QUIC+HTTP/3

        server_name example.com;

        ssl_protocols       TLSv1.3; # QUIC requires TLS 1.3
        ssl_early_data      on;
        quic_retry          on;
        ssl_certificate     certs/example.com.crt;
        ssl_certificate_key certs/example.com.key;

        location / {
            root   html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }

}
```

