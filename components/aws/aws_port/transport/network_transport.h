
#ifndef __NETWORK_TRANSPORT_H__
#define __NETWORK_TRANSPORT_H__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "transport_interface.h"
#include "core_mqtt_config.h"

#ifdef __cplusplus
    extern "C" {
#endif


#if TRANSPORT_USE_TLS
    #include "mbedtls/net.h"
    #include "mbedtls/entropy.h"
    #include "mbedtls/ctr_drbg.h"
    #include "mbedtls/certs.h"
    #include "mbedtls/x509_crt.h"
    #include "mbedtls/error.h"
    #include "mbedtls/debug.h"
    typedef struct {
        bool                        inited;
        mbedtls_net_context         ssl_fd;
        mbedtls_entropy_context     entropy;
        mbedtls_ctr_drbg_context    ctr_drbg;
        mbedtls_ssl_context         ssl;
        mbedtls_ssl_config          conf;
        mbedtls_x509_crt            cacert;
        mbedtls_x509_crt            clicert;
        mbedtls_pk_context          pkey;
        mbedtls_x509_crt_profile    certProfile;
    } _tls_context;
#endif /* TRANSPORT_USE_TLS */

typedef struct {
    int  fd;
} _tcp_context;

struct NetworkContext {
    const char *hostname;
    int         port;

    const char *server_root_ca_pem;
    const char *client_cert_pem;
    const char *client_key_pem;
    int         server_root_ca_pem_size; //strlen(root_ca)
    int         client_cert_pem_size;    //strlen(client_cert)
    int         client_key_pem_size;     //strlen(client_key)
    const char **alpn_protos;

#if TRANSPORT_USE_TLS
    _tls_context tls;
#endif /* TRANSPORT_USE_TLS */
    _tcp_context tcp;
};

int transport_conn(NetworkContext_t *nw_context);
int transport_disconn(NetworkContext_t *nw_context);
int transport_send(NetworkContext_t *nw_context, const void *data, size_t data_len);
int transport_recv(NetworkContext_t *nw_context, void *data, size_t data_len);

#ifdef __cplusplus
    }
#endif

#endif /* __NETWORK_TRANSPORT_H__ */
