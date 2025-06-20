#include "network_transport.h"

#define TCP_SEND_RECV_TIMEOUT_MS  (2000) //Transport timeout in milliseconds for transport send and receive.
#define TLS_SEND_RECV_TIMEOUT_MS  (2000) //Transport timeout in milliseconds for transport send and receive.
#define AWS_ADA_MBEDTLS_DEBUG_LOG_LEVEL (0) // default 0, 0 - 5


typedef enum
{
    TP_RET_SUCCESS = 0,  // Successful return
    TP_ERR_INVALID_PARAM = -2,

    TP_ERR_TCP_SOCKET_FAILED   = -601,  // TLS TCP socket connect fail
    TP_ERR_TCP_UNKNOWN_HOST    = -602,  // TCP unknown host (DNS fail)
    TP_ERR_TCP_CONNECT         = -603,  // TCP/UDP socket connect fail
    TP_ERR_TCP_READ_TIMEOUT    = -604,  // TCP read timeout
    TP_ERR_TCP_WRITE_TIMEOUT   = -605,  // TCP write timeout
    TP_ERR_TCP_READ_FAIL       = -606,  // TCP read error
    TP_ERR_TCP_WRITE_FAIL      = -607,  // TCP write error
    TP_ERR_TCP_PEER_SHUTDOWN   = -608,  // TCP server close connection
    TP_ERR_TCP_NOTHING_TO_READ = -609,  // TCP socket nothing to read
    TP_ERR_TCP_GETADDR         = -610,  // TCP getaddrinfo error
    TP_ERR_TCP_DISCONN         = -611,  // TCP disconnect error


    TP_ERR_TLS_CONFIG          = -700,
    TP_ERR_TLS_INIT            = -701,  // TLS init fail
    TP_ERR_TLS_CERT            = -702,  // TLS certificate issue
    TP_ERR_TLS_CONNECT         = -703,  // TLS connect fail
    TP_ERR_TLS_CONNECT_TIMEOUT = -704,  // TLS connect timeout
    TP_ERR_TLS_WRITE_TIMEOUT   = -705,  // TLS write timeout
    TP_ERR_TLS_WRITE           = -706,  // TLS write error
    TP_ERR_TLS_READ_TIMEOUT    = -707,  // TLS read timeout
    TP_ERR_TLS_READ            = -708,  // TLS read error
    TP_ERR_TLS_NOTHING_TO_READ = -709,  // TLS nothing to read
    TP_ERR_TLS_HANDSHAKE       = -710,
} transport_ret_e;



/*********************************************************************************************/
/*                                     TLS transport layer                                   */
/*********************************************************************************************/
#if TRANSPORT_USE_TLS
static void _mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ( void ) ctx; ( void ) file; ( void ) line;

    /* Send the debug string to the portable logger. */
    LOG(LOG_LVL_INFO, "mbedTLS: |%d| %s", level, str );
}

static int transport_tls_init(NetworkContext_t * nw_context)
{
    assert(nw_context != NULL);
    memset(&nw_context->tls, 0, sizeof(nw_context->tls));

    mbedtls_net_init(&nw_context->tls.ssl_fd);
    mbedtls_ssl_init(&nw_context->tls.ssl);
    mbedtls_ssl_config_init(&nw_context->tls.conf);
    mbedtls_x509_crt_init(&nw_context->tls.cacert);
    mbedtls_x509_crt_init(&nw_context->tls.clicert);
    mbedtls_ctr_drbg_init(&nw_context->tls.ctr_drbg);
    mbedtls_pk_init(&nw_context->tls.pkey);
    mbedtls_entropy_init( &nw_context->tls.entropy );

    nw_context->tls.inited = true;
    return 0;
}

static int transport_tls_deinit(NetworkContext_t * nw_context)
{
    assert(nw_context != NULL);

    if (!nw_context->tls.inited) {
        return 0;
    }

    mbedtls_net_free(&nw_context->tls.ssl_fd);
    mbedtls_ssl_free(&nw_context->tls.ssl);
    mbedtls_ssl_config_free(&nw_context->tls.conf);
    mbedtls_x509_crt_free(&nw_context->tls.cacert);
    mbedtls_x509_crt_free(&nw_context->tls.clicert);
    mbedtls_ctr_drbg_free(&nw_context->tls.ctr_drbg);
    mbedtls_pk_free(&nw_context->tls.pkey);
    mbedtls_entropy_free(&nw_context->tls.entropy);

    nw_context->tls.inited = false;
    return 0;
}

static int transport_tls_config(NetworkContext_t * nw_context)
{
    int ret = 0;

    ret = mbedtls_ssl_config_defaults(&nw_context->tls.conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if(ret != 0) {
        return ret;
    }

    nw_context->tls.certProfile = mbedtls_x509_crt_profile_default;

    if (nw_context->alpn_protos != NULL) {
        ret = mbedtls_ssl_conf_alpn_protocols(&nw_context->tls.conf, nw_context->alpn_protos);
        if(ret != 0) {
            LogError( ("Set ALPN failed!") );
            
            return ret;
        }
    }

    // mbedtls_ssl_conf_max_frag_len(&nw_context->tls.conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096); //MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    mbedtls_ssl_conf_authmode(&nw_context->tls.conf, MBEDTLS_SSL_VERIFY_NONE); //MBEDTLS_SSL_VERIFY_NONE, MBEDTLS_SSL_VERIFY_OPTIONAL, MBEDTLS_SSL_VERIFY_REQUIRED
    mbedtls_ssl_conf_rng(&nw_context->tls.conf, mbedtls_ctr_drbg_random, &nw_context->tls.ctr_drbg);
    mbedtls_ssl_conf_cert_profile(&nw_context->tls.conf, &nw_context->tls.certProfile);
    mbedtls_ssl_conf_read_timeout(&nw_context->tls.conf, TLS_SEND_RECV_TIMEOUT_MS);

    mbedtls_ssl_conf_dbg(&nw_context->tls.conf, _mbedtls_debug, NULL);          /* set debug log output api */
    mbedtls_debug_set_threshold(AWS_ADA_MBEDTLS_DEBUG_LOG_LEVEL);               /* set log output level: 0 - 5 */

    ret = mbedtls_ctr_drbg_seed(&nw_context->tls.ctr_drbg, mbedtls_entropy_func, &nw_context->tls.entropy, NULL, 0);
    if( ret != 0 ) {
        LogError( ("mbedtls_ctr_drbg_seed error, return -0x%x", -ret) );
        return ret;
    }

    /* parse [root_ca_cert] */
    if (nw_context->server_root_ca_pem != NULL) {
        ret = mbedtls_x509_crt_parse(&nw_context->tls.cacert, (const uint8_t*)nw_context->server_root_ca_pem, nw_context->server_root_ca_pem_size);
        if( ret != 0 ) {
            LogError( ("parse root ca cert error, return -0x%x", -ret) );
            return ret;
        }
        mbedtls_ssl_conf_ca_chain(&nw_context->tls.conf, &nw_context->tls.cacert, NULL);
    }

    /* parse [client_cert] [client_key] */
    if (nw_context->client_cert_pem != NULL && nw_context->client_key_pem != NULL) {
        ret = mbedtls_x509_crt_parse(&nw_context->tls.clicert, (const uint8_t*)nw_context->client_cert_pem, nw_context->client_cert_pem_size);
        if(ret != 0) {
            LogError( ("parse client cert error, return -0x%x", -ret) );
            return ret;
        }
        ret = mbedtls_pk_parse_key(&nw_context->tls.pkey, (const uint8_t*)nw_context->client_key_pem, nw_context->client_key_pem_size, NULL, 0);
        if (ret != 0) {
            LogError( ("parse client key error, return -0x%x", -ret) );
            return ret;
        }
        mbedtls_ssl_conf_own_cert(&(nw_context->tls.conf), &(nw_context->tls.clicert), &(nw_context->tls.pkey));
    }

    if ((ret = mbedtls_ssl_set_hostname(&nw_context->tls.ssl, (const char *)nw_context->hostname)) != 0) {
        LogError( ("set hostname error, return -0x%x", -ret) );
        return ret;
    }

    ret = mbedtls_ssl_setup(&nw_context->tls.ssl, &nw_context->tls.conf);
    if( ret != 0 ) {
        LogError( ("ssl setup error, return -0x%x", -ret) );
        return ret;
    }

    mbedtls_ssl_set_bio(&nw_context->tls.ssl, &nw_context->tls.ssl_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    return 0;
}

static int transport_tls_conn(NetworkContext_t *nw_context)
{
    int ret = 0;
    int status = TP_RET_SUCCESS;
    char port_string[6] = {0};

    if (nw_context == NULL) {
        return TP_ERR_INVALID_PARAM;
    }

    ret = transport_tls_init(nw_context);
    if (ret != 0) {
        return TP_ERR_TLS_INIT;
    }

    ret = transport_tls_config(nw_context);
    if (ret != 0) {
        status = TP_ERR_TLS_CONFIG;
        goto __exit;
    }

    snprintf(port_string, sizeof(port_string), "%u", nw_context->port);
    LogInfo( ( "-- tls conn <%s:%s> --\r\n", nw_context->hostname, port_string) );

    ret = mbedtls_net_connect(&nw_context->tls.ssl_fd, nw_context->hostname, (const char *)port_string, MBEDTLS_NET_PROTO_TCP);
    if(ret != 0) {
        LogError( ("Failed to conn <%s:%s>, return -0x%x", nw_context->hostname, port_string, -ret) );
        status = TP_ERR_TLS_CONNECT;
        goto __exit;
    }

    do {
        ret = mbedtls_ssl_handshake(&nw_context->tls.ssl);
    } while(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if ((ret != 0) || (mbedtls_ssl_get_verify_result(&nw_context->tls.ssl) != 0)) {
        LogError( ("TLS handshake failed! return -0x%x", -ret) );
        status = TP_ERR_TLS_HANDSHAKE;
        goto __exit;
    }
    LogInfo( ( "TLS conn to <%s> success!\r\n", nw_context->hostname) );

    return TP_RET_SUCCESS;
__exit:
    transport_tls_deinit(nw_context);
    return status;
}

static int transport_tls_disconn(NetworkContext_t *nw_context)
{
    int ret = 0;

    ret = mbedtls_ssl_close_notify(&nw_context->tls.ssl);
    if (ret == 0) {
        LogInfo( ( "Closing TLS connection: TLS close-notify sent.") );
    } else if ((ret == MBEDTLS_ERR_SSL_WANT_READ) && (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
        /* WANT_READ and WANT_WRITE can be ignored. Logging for debugging purposes. */
        LogInfo( ( "TLS close-notify sent; received %s as the TLS status " "which can be ignored for close-notify.",
                (ret == MBEDTLS_ERR_SSL_WANT_READ ) ? "WANT_READ" : "WANT_WRITE") );
    } else {
        /* Ignore the WANT_READ and WANT_WRITE return values. */
        LogError( ("Failed to send TLS close-notify: mbedTLSError= -%x.", ret) );
    }

    transport_tls_deinit(nw_context);
    return ret;
}

static int transport_tls_send(NetworkContext_t *nw_context, const void *data, size_t data_len)
{
    int ret = 0;
    assert(data != NULL);

    ret = mbedtls_ssl_write(&nw_context->tls.ssl, data, data_len);
    if ((ret == MBEDTLS_ERR_SSL_TIMEOUT) ||
        (ret == MBEDTLS_ERR_SSL_WANT_READ) ||
        (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
        ret = 0;
    } else if (ret < 0) {
        LogError( ("mbedtls_client_write data error, return -0x%x", -ret) );
    } else {
//        hexdump(1, "mq_send", (void *)data, ret);
    }

    return ret;
}

static int transport_tls_recv(NetworkContext_t *nw_context, void *data, size_t data_len)
{
    int ret = 0;
    assert(data != NULL);

    ret = mbedtls_ssl_read(&nw_context->tls.ssl, data, data_len);
    if ((ret == MBEDTLS_ERR_SSL_TIMEOUT) ||
        (ret == MBEDTLS_ERR_SSL_WANT_READ) ||
        (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
        ret = 0;
    } else if (ret < 0) {
        LogError( ("mbedtls_client_read data error, return -0x%x", -ret) );
    } else {
//        hexdump(1, "mq_recv", (void *)data, ret);
    }

    return ret;
}
#endif /* TRANSPORT_USE_TLS */


/*********************************************************************************************/
/*                                     TCP transport layer                                   */
/*********************************************************************************************/
#include <stdio.h>
#include <string.h>

#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#define STRING_PTR_PRINT_SANITY_CHECK(ptr) ((ptr) ? (ptr) : "null")

static uint32_t HAL_GetTimeMs(void) {
    return (uint32_t)(xTaskGetTickCount() * (1000/configTICK_RATE_HZ));
}

static uint32_t _time_left(uint32_t t_end, uint32_t t_now) {
    uint32_t t_left;

    if (t_end > t_now) {
        t_left = t_end - t_now;
    } else {
        t_left = 0;
    }

    return t_left;
}

static void tcp_keepalive_config(int fd)
{
#if 1
    int keepalive = 1;   //enable
    int keepidle  = 10;  //units: s
    int keepintvl = 5;   //units: s
    int keepcnt   = 8;   //retry count
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) != 0) {
        LogError( ("TCP (fd=%d) set SO_KEEPALIVE failed.", fd) );
    } else {
        LogInfo( ("TCP (fd=%d) set SO_KEEPALIVE :%d", fd, keepalive) );
    }

    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) != 0) {
        LogError( ("TCP (fd=%d) set TCP_KEEPIDLE failed.", fd) );
    } else {
        LogInfo( ("TCP (fd=%d) set TCP_KEEPIDLE :%d", fd, keepidle) );
    }

    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) != 0) {
        LogError( ("TCP (fd=%d) set TCP_KEEPINTVL failed.", fd) );
    } else {
        LogInfo( ("TCP (fd=%d) set TCP_KEEPINTVL:%d", fd, keepintvl) );
    }

    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) != 0) {
        LogError( ("TCP (fd=%d) set TCP_KEEPCNT failed.", fd) );
    } else {
        LogInfo( ("TCP (fd=%d) set TCP_KEEPCNT  :%d", fd, keepcnt) );
    }
#endif
}

static int transport_tcp_conn(NetworkContext_t *nw_context)
{
    NetworkContext_t *n = nw_context;
    const char *host = nw_context->hostname;
    uint16_t    port = nw_context->port;

    int ret;
    int fd;
    struct addrinfo hints, *addr_list, *cur;

    char port_str[6] = {0};
    snprintf(port_str, 6, "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    LogInfo( ("--- tcp conn <%s:%s> ---", nw_context->hostname, port_str) );

    ret = getaddrinfo(host, port_str, &hints, &addr_list);
    if (ret) {
        LogError( ("getaddrinfo(%s:%s) error ret=%d\r\n", STRING_PTR_PRINT_SANITY_CHECK(host), port_str, ret) );
        return TP_ERR_TCP_GETADDR;
    }

    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            ret = TP_ERR_TCP_SOCKET_FAILED;
            continue;
        }

        fd = n->tcp.fd;
        tcp_keepalive_config(fd);
        if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            ret = TP_RET_SUCCESS;
            break;
        }

        close(fd);
        ret = TP_ERR_TCP_CONNECT;
    }

    if (ret == TP_RET_SUCCESS) {
        LogInfo( ("TCP conn to <%s:%s> success!", STRING_PTR_PRINT_SANITY_CHECK(host), port_str) );
    } else {
        LogError( ("Failed to conn <%s:%s>, return %d", STRING_PTR_PRINT_SANITY_CHECK(host), port_str, ret) );
    }

    freeaddrinfo(addr_list);
    return ret;
}

static int transport_tcp_disconn(NetworkContext_t *nw_context)
{
    int rc;
    NetworkContext_t *n = nw_context;

    /* Shutdown both send and receive operations. */
    rc = shutdown(n->tcp.fd, 2);
    if (0 != rc) {
        LogError( ("tcp shutdown error: %s", STRING_PTR_PRINT_SANITY_CHECK(strerror(errno))) );
        return TP_ERR_TCP_DISCONN;
    }

    rc = close(n->tcp.fd);
    if (0 != rc) {
        LogError( ("tcp closesocket error: %s", STRING_PTR_PRINT_SANITY_CHECK(strerror(errno))) );
        return TP_ERR_TCP_DISCONN;
    }

    return TP_RET_SUCCESS;
}

static int transport_tcp_send(NetworkContext_t *nw_context, const void *data, size_t data_len)
{
    int      ret;
    int len_sent;
    uint32_t t_end, t_left;
    fd_set   sets;
    NetworkContext_t *n = nw_context;
    const uint8_t *buf = (const uint8_t *)data;

    t_end    = HAL_GetTimeMs() + TCP_SEND_RECV_TIMEOUT_MS;
    len_sent = 0;
    ret      = 1; /* send one time if timeout_ms is value 0 */

    do {
        t_left = _time_left(t_end, HAL_GetTimeMs());

        if (0 != t_left) {
            struct timeval timeout;

            FD_ZERO(&sets);
            FD_SET(n->tcp.fd, &sets);

            timeout.tv_sec  = t_left / 1000;
            timeout.tv_usec = (t_left % 1000) * 1000;

            ret = select(n->tcp.fd + 1, NULL, &sets, NULL, &timeout);
            if (ret > 0) {
                if (0 == FD_ISSET(n->tcp.fd, &sets)) {
                    LogError( ("Should NOT arrive") );
                    /* If timeout in next loop, it will not sent any data */
                    ret = 0;
                    continue;
                }
            } else if (0 == ret) {
                ret = TP_ERR_TCP_WRITE_TIMEOUT;
                LogError( ("select-write timeout %d", n->tcp.fd) );
                break;
            } else {
                if (EINTR == errno) {
                    LogError( ("EINTR be caught") );
                    continue;
                }

                ret = TP_ERR_TCP_WRITE_FAIL;
                LogError( ("tcp select-write fail: %s", STRING_PTR_PRINT_SANITY_CHECK(strerror(errno))) );
                break;
            }
        } else {
            ret = TP_ERR_TCP_WRITE_TIMEOUT;
        }

        if (ret > 0) {
            ret = send(n->tcp.fd, buf + len_sent, data_len - len_sent, 0);
            if (ret > 0) {
                len_sent += ret;
            } else if (0 == ret) {
                LogError( ("No data be sent. Should NOT arrive") );
            } else {
                if (EINTR == errno) {
                    LogError( ("EINTR be caught") );
                    continue;
                }

                ret = TP_ERR_TCP_WRITE_FAIL;
                LogError( ("send fail: %s", STRING_PTR_PRINT_SANITY_CHECK(strerror(errno))) );
                break;
            }
        }
    } while ((len_sent < data_len) && (_time_left(t_end, HAL_GetTimeMs()) > 0));

    return (len_sent >= 0) ? len_sent : ret;
}

static int transport_tcp_recv(NetworkContext_t *nw_context, void *data, size_t data_len)
{
    int            ret, err_code;
    int            len_recv;
    uint32_t       t_end, t_left;
    fd_set         sets;
    struct timeval timeout;
    NetworkContext_t *n = nw_context;
    uint8_t *buf = (uint8_t *)data;

    t_end    = HAL_GetTimeMs() + TCP_SEND_RECV_TIMEOUT_MS;
    len_recv = 0;
    err_code = 0;

    do {
        t_left = _time_left(t_end, HAL_GetTimeMs());
        if (0 == t_left) {
            err_code = TP_ERR_TCP_READ_TIMEOUT;
            break;
        }

        FD_ZERO(&sets);
        FD_SET(n->tcp.fd, &sets);

        timeout.tv_sec  = t_left / 1000;
        timeout.tv_usec = (t_left % 1000) * 1000;

        ret = select(n->tcp.fd + 1, &sets, NULL, NULL, &timeout);
        if (ret > 0) {
            ret = recv(n->tcp.fd, buf + len_recv, data_len - len_recv, 0);
            if (ret > 0) {
                len_recv += ret;
            } else if (0 == ret) {
                struct sockaddr_in peer;
                socklen_t          sLen      = sizeof(peer);
                int                peer_port = 0;
                getpeername(n->tcp.fd, (struct sockaddr *)&peer, &sLen);
                peer_port = ntohs(peer.sin_port);

                LogError( ("connection is closed by server: %s:%d", STRING_PTR_PRINT_SANITY_CHECK(inet_ntoa(peer.sin_addr)), peer_port) );

                err_code = TP_ERR_TCP_PEER_SHUTDOWN;
                break;
            } else {
                if (EINTR == errno) {
                    LogError( ("EINTR be caught") );
                    continue;
                }
                LogError( ("recv error: %s", STRING_PTR_PRINT_SANITY_CHECK(strerror(errno))) );
                err_code = TP_ERR_TCP_READ_FAIL;
                break;
            }
        } else if (0 == ret) {
            err_code = TP_ERR_TCP_READ_TIMEOUT;
            break;
        } else {
            LogError( ("select-recv error: %s", STRING_PTR_PRINT_SANITY_CHECK(strerror(errno))) );
            err_code = TP_ERR_TCP_READ_FAIL;
            break;
        }
    } while ((len_recv < data_len));

    if (err_code == TP_ERR_TCP_READ_TIMEOUT && len_recv == 0)
        err_code = TP_ERR_TCP_NOTHING_TO_READ;

    return (len_recv >= 0) ? len_recv : err_code;
}


/*********************************************************************************************/
/*                                      transport layer API                                  */
/*********************************************************************************************/
// int transport_tls_conn(NetworkContext_t *nw_context);
// int transport_tls_disconn(NetworkContext_t *nw_context);
// int transport_tls_send(NetworkContext_t *nw_context, const void *data, size_t data_len);
// int transport_tls_recv(NetworkContext_t *nw_context, void *data, size_t data_len);

// int transport_tcp_conn(NetworkContext_t *nw_context);
// int transport_tcp_disconn(NetworkContext_t *nw_context);
// int transport_tcp_send(NetworkContext_t *nw_context, const void *data, size_t data_len);
// int transport_tcp_recv(NetworkContext_t *nw_context, void *data, size_t data_len);

int transport_conn(NetworkContext_t *nw_context)
{
    if (nw_context->port == 1883) {
        return transport_tcp_conn(nw_context);
    } else if (nw_context->port == 8883) {
#if TRANSPORT_USE_TLS
        return transport_tls_conn(nw_context);
#endif /* TRANSPORT_USE_TLS */
    }
    return TP_ERR_INVALID_PARAM;
}

int transport_disconn(NetworkContext_t *nw_context)
{
    if (nw_context->port == 1883) {
        return transport_tcp_disconn(nw_context);
    } else if (nw_context->port == 8883) {
#if TRANSPORT_USE_TLS
        return transport_tls_disconn(nw_context);
#endif /* TRANSPORT_USE_TLS */
    }
    return TP_ERR_INVALID_PARAM;
}

int transport_send(NetworkContext_t *nw_context, const void *data, size_t data_len)
{
    if (nw_context->port == 1883) {
        return transport_tcp_send(nw_context, data, data_len);
    } else if (nw_context->port == 8883) {
#if TRANSPORT_USE_TLS
        return transport_tls_send(nw_context, data, data_len);
#endif /* TRANSPORT_USE_TLS */
    }
    return TP_ERR_INVALID_PARAM;
}

int transport_recv(NetworkContext_t *nw_context, void *data, size_t data_len)
{
    if (nw_context->port == 1883) {
        return transport_tcp_recv(nw_context, data, data_len);
    } else if (nw_context->port == 8883) {
#if TRANSPORT_USE_TLS
        return transport_tls_recv(nw_context, data, data_len);
#endif /* TRANSPORT_USE_TLS */
    }
    return TP_ERR_INVALID_PARAM;
}
