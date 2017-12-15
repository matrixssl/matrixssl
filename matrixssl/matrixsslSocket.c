/* matrixsslSocket.c
 *
 * Build psSocket_t based on matrixsslNet.
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*****************************************************************************/

#define _GNU_SOURCE
#include "core/coreApi.h"
#include "matrixssl/matrixsslImpl.h"
#include "matrixsslNet.h"
#include "matrixsslSocket.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

#define USE_MATRIX_NET_DEBUG
#undef DEBUGF                /* Protect against possible multiple definition. */
#ifdef USE_MATRIX_NET_DEBUG
# define DEBUGF(...) printf(__VA_ARGS__)
#else
# define DEBUGF(...) do {} while (0)
#endif

#ifdef USE_PS_NETWORKING

/* The flags used by this program for TLS versions. */
# define FLAG_TLS_1_0 (1 << 10)
# define FLAG_TLS_1_1 (1 << 11)
# define FLAG_TLS_1_2 (1 << 12)

static psSocketFunctions_t psSocketFunctionsTLS;

static const int ciphers_default = 1;
static const psCipher16_t cipherlist_default[] = { 47 };

# define logMessage(l, t, ...) do { printf(#l " " #t ": " __VA_ARGS__); printf("\n"); } while (0) /* Log_Verbose, TAG, "Wrote %d bytes", transferred */

# ifdef USE_CLIENT_SIDE_SSL
/* The MatrixSSL certificate validation callback. */
static int32 ssl_cert_auth_default(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
    return MATRIXSSL_SUCCESS;
}

static int32 extensionCb(ssl_t *ssl, uint16_t extType, uint8_t extLen, void *e)
{
    if (extType == EXT_SNI)
    {
        logMessage(Log_Info, TAG, "SNI extension callback called");
    }
    return PS_SUCCESS;
}
# endif /* USE_CLIENT_SIDE_SSL */

sslKeys_t *keys = NULL;
sslSessionId_t *sid = NULL;
static const char *node_global;

# ifdef USE_CLIENT_SIDE_SSL

static void uninit_client_tls(void)
{
    /* Free all allocated/opened resources. */
    matrixSslDeleteSessionId(sid);

    matrixSslDeleteKeys(keys);
    matrixSslClose();
}

static void set_tls_options_version(sslSessOpts_t *options_p, int tls)
{
    if ((tls & FLAG_TLS_1_0) || tls == 0)
    {
        options_p->versionFlag |= SSL_FLAGS_TLS_1_0;
    }
    if ((tls & FLAG_TLS_1_1) || tls == 0)
    {
        options_p->versionFlag |= SSL_FLAGS_TLS_1_1;
    }
    if ((tls & FLAG_TLS_1_2) || tls == 0)
    {
        options_p->versionFlag |= SSL_FLAGS_TLS_1_2;
    }
}

static int init_client_tls(psSocket_t *sock, const char *capath, int tls)
{
    int32 rc = PS_SUCCESS;
    sslSessOpts_t options;
    tlsExtension_t *extension;
    unsigned char *ext = NULL;
    int32 extLen;
    ssl_t *ssl = NULL;
    const char *host = (const char *) node_global;
    int32 (*ssl_cert_auth_cb)(ssl_t *ssl, psX509Cert_t *cert, int32 alert);

    memset(&options, 0x0, sizeof(sslSessOpts_t));
    set_tls_options_version(&options, tls);

    if (matrixSslOpen() < 0)
    {
        DEBUGF("Error initializing MatrixSSL\n");
        return 3;
    }

    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        DEBUGF("Error initializing MatrixSSL: "
            "matrixSslNewKeys error\n");
        return 3;
    }
    if (matrixSslNewSessionId(&sid, NULL) < 0)
    {
        DEBUGF("Error initializing MatrixSSL: "
            "matrixSslNewSessionId error\n");
        return 3;
    }

    if (capath != NULL)
    {
#  ifdef USE_RSA
        rc = matrixSslLoadRsaKeys(keys, NULL, NULL, NULL, capath);
#  else
#   ifdef USE_ECC
        rc = matrixSslLoadEcKeys(keys, NULL, NULL, NULL, capath);
#    warning either USE_RSA or USE_ECC needed in matrixsslSocket.c
#   endif
#  endif
        if (rc != PS_SUCCESS)
        {
            DEBUGF("No certificate material loaded.\n");
            uninit_client_tls();
            return rc;
        }
    }

    matrixSslNewHelloExtension(&extension, NULL);
    matrixSslCreateSNIext(NULL, (unsigned char *) host, (uint32) strlen(host),
        &ext, &extLen);
    if (ext)
    {
        matrixSslLoadHelloExtension(extension, ext, extLen, EXT_SNI);
        psFree(ext, NULL);
    }

    ssl_cert_auth_cb = sock->extra.tls->ssl_socket_cert_auth;
    if (ssl_cert_auth_cb == NULL)
    {
        ssl_cert_auth_cb = &ssl_cert_auth_default;
    }

    rc = matrixSslNewClientSession(&ssl, keys, sid,
        sock->extra.tls->cipherlist,
        sock->extra.tls->ciphers,
        ssl_cert_auth_cb, NULL,
        extension,
        extensionCb, &options);
    matrixSslDeleteHelloExtension(extension);

    if (rc < PS_SUCCESS)
    {
        DEBUGF("SSL Client Session failed: rc=%d\n", rc);
        uninit_client_tls();
        return rc;
    }
    matrixSslInteractBegin(&(sock->extra.tls->msi), ssl, sock);
    return rc;
}
# endif /* USE_CLIENT_SIDE_SSL */

static int32 do_tls_handshake_socket(matrixSslInteract_t *msi_p, int32 rc)
{
    fd_set fds;

    if (rc < PS_SUCCESS)
    {
        return rc;
    }


    do
    {
        int sockfd = psSocketGetFd(msi_p->sock);
        if (rc == MATRIXSSL_REQUEST_RECV)
        {
            DEBUGF("wait for data from peer\n");
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);
            select(sockfd + 1, &fds, NULL, NULL, NULL);
        }
        else if (rc ==  MATRIXSSL_REQUEST_SEND ||
                 msi_p->send_len_left > 0)
        {
            DEBUGF("wait for sending data to peer\n");
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);
            select(sockfd + 1, NULL, &fds, NULL, NULL);
        }
/*              if (rc != 0) */
        DEBUGF("hs rc code: %d\n", rc);
        if (rc == MATRIXSSL_REQUEST_RECV)
        {
            rc = matrixSslInteractHandshake(msi_p, PS_FALSE, PS_TRUE);
        }
        else
        {
            rc = matrixSslInteractHandshake(msi_p, PS_TRUE, PS_TRUE);
        }
        DEBUGF("hs msi rc code: %d\n", rc);
    }
    while (rc > PS_SUCCESS && rc != MATRIXSSL_RECEIVED_ALERT);
    return rc;
}

static const char *getCapath(psSocket_t *sock)
{
    if (sock && sock->type == PS_SOCKET_TLS && sock->extra.tls)
    {
        return sock->extra.tls->capath;
    }
    return NULL;
}

void setSocketTlsCertAuthCb(
        psSocket_t *sock,
        int32 (*ssl_cert_auth_cb)(ssl_t *ssl, psX509Cert_t *cert, int32 alert))
{
    if (sock && sock->type == PS_SOCKET_TLS && sock->extra.tls)
    {
        sock->extra.tls->ssl_socket_cert_auth = ssl_cert_auth_cb;
    }
}

static int getTlsVersion(psSocket_t *sock)
{
    if (sock && sock->type == PS_SOCKET_TLS && sock->extra.tls)
    {
        return sock->extra.tls->tls_version;
    }
    return 0;
}

static int psSocketTLS(psSocket_t *sock,
    int domain, psSocketType_t type,
    int protocol, void *typespecific)
{
    int32 rc;
    const psSocketFunctions_t *orig = psGetSocketFunctionsDefault();

    /* Validate arguments here. */
    if (type == PS_SOCKET_TLS && typespecific != NULL)
    {
        type = PS_SOCKET_STREAM;
    }
    else
    {
        type = PS_SOCKET_UNKNOWN; /* Causes lower layer to set errors in
                                     platform specific way. */

    }
    rc = (orig->psSocket)(sock, domain, type, protocol, typespecific);
    if (rc >= 0)
    {
        sock->type = PS_SOCKET_TLS;
        sock->extra.tls->nested_call = 0;
        sock->extra.tls->handshaked = 0;
        if (sock->extra.tls->cipherlist == NULL)
        {
            sock->extra.tls->ciphers = ciphers_default;
            sock->extra.tls->cipherlist = cipherlist_default;
        }
    }
    return rc;
}

static ssize_t psWriteTLS(psSocket_t *sock, const void *buf, size_t len)
{
    int32 rc;

    if (sock->extra.tls->nested_call == 1)
    {
        /* Nested data writes are writes to actual socket. */
        const psSocketFunctions_t *orig = psGetSocketFunctionsDefault();
        return (orig->psWrite)(sock, buf, len);
    }

    DEBUGF("Called psWriteTLS(%d bytes), "
        "with capath: %s; tls_global: %d; handshaked: %d\n",
        (int) len, getCapath(sock), getTlsVersion(sock),
        sock->extra.tls->handshaked);

    sock->extra.tls->nested_call = 1;
    if (sock->extra.tls->handshaked == 0)
    {
# ifdef USE_CLIENT_SIDE_SSL
        rc = init_client_tls(sock, getCapath(sock), getTlsVersion(sock));
# else  /* !(USE_CLIENT_SIDE_SSL) */
        DEBUGF("USE_CLIENT_SIDE_SSL required\n");
        rc = PS_FAILURE;
# endif /* USE_CLIENT_SIDE_SSL */

        DEBUGF("Next: handshake\n");
        if (rc >= PS_SUCCESS)
        {
            rc = do_tls_handshake_socket(&(sock->extra.tls->msi), rc);
            if (rc < PS_SUCCESS)
            {
                DEBUGF("Handshake failure\n");
                sock->extra.tls->nested_call = 0;
                return rc;
            }
        }
        DEBUGF("handshake done\n");
        sock->extra.tls->handshaked = 1;
    }

    if (matrixSslInteractWrite(&(sock->extra.tls->msi), buf, len) < 0)
    {
        sock->extra.tls->nested_call = 0;
        return PS_FAILURE;
    }

    rc = matrixSslInteract(&(sock->extra.tls->msi), PS_TRUE, PS_FALSE);
    DEBUGF("Got rc: %d\n", rc);
    if (rc == MATRIXSSL_RECEIVED_ALERT)
    {
        sock->extra.tls->nested_call = 0;
        DEBUGF("Unexpected alert\n");
        return PS_FAILURE;
    }
    else if (matrixSslInteractReadLeft(&(sock->extra.tls->msi)))
    {
        sock->extra.tls->nested_call = 0;
        DEBUGF("Unexpected data to read\n");
        return PS_FAILURE;
    }
    else if (rc == MATRIXSSL_NET_DISCONNECTED)
    {
        sock->extra.tls->nested_call = 0;
        DEBUGF("The peer has disconnected\n");
        return PS_FAILURE;
    }

    if (rc > PS_SUCCESS)
    {
        /* Continue handling. */
        abort();
    }
    sock->extra.tls->nested_call = 0;
    return len; /* All len bytes sent. */
}

static ssize_t psReadTLS(psSocket_t *sock, void *buf, size_t len)
{
    int32 rc;
    int can_read = PS_TRUE;
    int can_write = PS_TRUE;

    if (sock->extra.tls->nested_call == 1)
    {
        /* Nested data writes are writes to actual socket. */
        const psSocketFunctions_t *orig = psGetSocketFunctionsDefault();
        return (orig->psRead)(sock, buf, len);
    }

    DEBUGF("Called psReadTLS(%d bytes), "
        "with capath: %s; tls_global: %d; handshaked: %d\n",
        (int) len,
        getCapath(sock), getTlsVersion(sock), sock->extra.tls->handshaked);

    /* First check if there is already previously read data waiting for
       reading. */
    if (matrixSslInteractReadLeft(&(sock->extra.tls->msi)))
    {
read_data_left:
        rc = matrixSslInteractRead(&(sock->extra.tls->msi), buf, len);
        if (rc < 0)
        {
            DEBUGF("Read error: rc=%d\n", rc);
            return PS_FAILURE;
        }
        return (ssize_t) rc;
    }

    /* Perform interaction with ssl, including sending and reception of
       packets. */
interact_again:
    sock->extra.tls->nested_call = 1;
    rc = matrixSslInteract(&(sock->extra.tls->msi), can_write, can_read);
    DEBUGF("Got rc: %d\n", rc);
    if (rc == MATRIXSSL_RECEIVED_ALERT)
    {
        sock->extra.tls->nested_call = 0;
        DEBUGF("Unexpected alert\n");
        return PS_FAILURE;
    }
    else if (matrixSslInteractReadLeft(&(sock->extra.tls->msi)))
    {
        sock->extra.tls->nested_call = 0;
        goto read_data_left;
    }
    sock->extra.tls->nested_call = 0;
    if (rc == MATRIXSSL_REQUEST_SEND ||
        rc == MATRIXSSL_REQUEST_RECV)
    {

        int sockfd = psSocketGetFd(sock);
        int process_more;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        /* set can_read and can_write according to requested direction. */

        can_read = rc == MATRIXSSL_REQUEST_RECV;
        can_write = rc == MATRIXSSL_REQUEST_SEND;
        /* Wait for input or being able to output. */
        process_more = select(sockfd + 1,
            can_read ? &fds : NULL,
            can_write ? &fds : NULL,
            NULL, NULL);
        if (process_more == 1)
        {
            goto interact_again;
        }
    }
    else if (rc == MATRIXSSL_REQUEST_CLOSE)
    {
        return 0;
    }
    else if (rc == MATRIXSSL_NET_DISCONNECTED)
    {
        return 0;
    }
    else if (rc < 0)
    {
        return rc;
    }

    /* Nothing to return, so we wait for more data (blocking). */
    rc = MATRIXSSL_REQUEST_RECV;
    goto interact_again;
    return 0;
}

int psGetaddrinfoTLS(const char *node, const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res)
{
    const psSocketFunctions_t *orig = psGetSocketFunctionsDefault();

    node_global = node;
    return (orig->psGetaddrinfo)(node, service, hints, res);
}

const psSocketFunctions_t *psGetSocketFunctionsTLS(void)
{
    const psSocketFunctions_t *orig = psGetSocketFunctionsDefault();
    psSocketFunctions_t new;

    /* Currently orig cannot be NULL, but check for future. */
    if (orig == NULL)
    {
        return NULL;
    }

    memcpy(&new, orig, sizeof(psSocketFunctions_t));
    /* Replace IO related functionality.
       Sockets themselves work identically (blocking, using fd, etc.) */
    new.psSocket = &psSocketTLS;
    new.psWrite = &psWriteTLS;
    new.psRead = &psReadTLS;
    /* TODO. */
    /* new->psShutdown = psShutdownTLS; */
    /* Not using memmove, because on some platforms, if copying same
       data over the same data, during copying the data may be different
       [for instance zeroized]. Using memove is more likely to guarantee that
       the data is not invalidated during overwriting exactly the same bytes.
     */
    new.psGetaddrinfo = &psGetaddrinfoTLS;
    memmove(&psSocketFunctionsTLS, &new, sizeof(psSocketFunctions_t));
    return &psSocketFunctionsTLS;
}

#endif /* USE_PS_NETWORKING */

/* end of file matrixsslSocket.c */
