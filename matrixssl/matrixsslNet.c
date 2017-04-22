/* matrixsslNet.c
 *
 * Socket-based networking with MatrixSSL.
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

#include "matrixsslNet.h"

#ifdef USE_PS_NETWORKING

# include <signal.h> /* Defines SIGTERM, etc. */
# include <sys/types.h>
# include <sys/socket.h>
# include <unistd.h>

# ifndef MATRIXSSL_INTERACT_MAX_TRANSFER
#  define MATRIXSSL_INTERACT_MAX_TRANSFER 64000
# endif

# ifdef USE_MATRIX_NET_DEBUG
#  define MATRIXSSL_NET_DEBUGF(...) printf(__VA_ARGS__)
# else
#  define MATRIXSSL_NET_DEBUGF(...) do {} while (0)
# endif


void matrixSslInteractBegin(matrixSslInteract_t *i, ssl_t *ssl,
    psSocket_t *sock)
{
    /* Clear all except the ssl storage. */
    memset(i, 0, sizeof(*i));
    i->ssl = ssl;
    i->sock = sock;
    i->prev_rc = PS_SUCCESS;
    i->handshake_complete = PS_FALSE;
}

static int32 matrixSslInteractGotData(matrixSslInteract_t *i, int32 rc)
{
    /* Cook the received data from behalf of caller.
       The data we handle here are alerts. */

    MATRIXSSL_NET_DEBUGF("Got Data: rc=%d, bytes left: %d\n",
        rc, (int) i->receive_len_left);
    if (rc != MATRIXSSL_RECEIVED_ALERT)
    {
        return rc;
    }

    i->ch2[0] = 255;
    i->ch2[1] = 255;
    rc = matrixSslInteractRead(i, i->ch2, 2);
    MATRIXSSL_NET_DEBUGF("Alert code read: %d:%d\n", i->ch2[0], i->ch2[1]);
    if (rc < 2)
    {
        MATRIXSSL_NET_DEBUGF("Broken Alert\n");
        i->ch2[0] = 255; /* 255, 255 is used as generic code
                            for alerts not processed correctly. */
        return MATRIXSSL_RECEIVED_ALERT;
    }

    /* Close connection if: */
    if (i->ch2[0] == 1 && i->ch2[1] == 0)
    {
        return MATRIXSSL_REQUEST_CLOSE;
    }
    return MATRIXSSL_RECEIVED_ALERT;
}

static
int32 matrixSslInteractInt(matrixSslInteract_t *i,
    int can_send, int can_receive)
{
    ssize_t transferred;
    unsigned char *buf;
    int32 rc;

# ifdef USE_MATRIX_NET_DEBUG
    int block = 1;
# endif /* USE_MATRIX_NET_DEBUG */

    if (i->receive_buf && i->receive_len_left == 0)
    {
        /* Continuation of previous receive operation: */
        uint32_t len = i->receive_len;

        buf = i->receive_buf - len;
        rc = matrixSslProcessedData(i->ssl, &buf, &len);
        if (buf != NULL || len != 0)
        {
            MATRIXSSL_NET_DEBUGF("processed some data, but pending processing:\n"
                "rc=%d buf=%p len=%u\n",
                (int) rc, (const void *) buf, (unsigned int) len);
            if (rc == MATRIXSSL_APP_DATA ||
                rc == MATRIXSSL_RECEIVED_ALERT)
            {
                i->receive_buf = buf;
                i->receive_len = len;
                i->receive_len_left = len;
                return matrixSslInteractGotData(i, rc);
            }
            else
            {
                return PS_FAILURE;
            }
        }
        /* Mark buffer as processed. */
        i->receive_buf = NULL;
        i->receive_len = 0;
        i->receive_len_left = 0;
        MATRIXSSL_NET_DEBUGF("Acked processed data, got: rc=%d\n", rc);
        return rc;
    }
    else if (can_receive && i->receive_buf && i->receive_len_left > 0)
    {
        MATRIXSSL_NET_DEBUGF("Signal more data ready for reading.\n");
        /* Maybe there is remaining application data? */
        rc = MATRIXSSL_APP_DATA;
        return rc;
    }

    if (can_send && i->send_len_left == 0)
    {
        int32 len;
        len = matrixSslGetOutdata(i->ssl, &buf);
        if (len > 0)
        {
            MATRIXSSL_NET_DEBUGF("To be sent: %d bytes\n", (int) len);
            i->send_buf = buf;
            i->send_len_left = i->send_len = len;
        }
# ifdef USE_MATRIX_NET_DEBUG
        block = 0;
# endif /* USE_MATRIX_NET_DEBUG */
    }
    if (can_send && i->send_len_left > 0)
    {
        int32 len;
        buf = i->send_buf;
        len = i->send_len_left;

        transferred = psSocketWriteData(
            i->sock, buf,
            len < MATRIXSSL_INTERACT_MAX_TRANSFER ? len :
            MATRIXSSL_INTERACT_MAX_TRANSFER, 0);
        if (transferred < 0)
        {
            return PS_PLATFORM_FAIL;
        }
        MATRIXSSL_NET_DEBUGF("Sent%s: %d bytes\n", block ? " cont" : "",
            (int) transferred);
        i->send_buf += transferred;
        i->send_len_left -= transferred;
        if (i->send_len_left > 0)
        {
            return MATRIXSSL_REQUEST_SEND;
        }
        rc = matrixSslSentData(i->ssl, (uint32) i->send_len);
        if (rc < 0 || rc == MATRIXSSL_REQUEST_CLOSE ||
            rc == MATRIXSSL_HANDSHAKE_COMPLETE ||
            rc == MATRIXSSL_REQUEST_SEND)
        {
            return rc;
        }
    }
    else
    {
        rc = PS_SUCCESS;
    }
    if (can_receive)
    {
        int32 len;
        len = matrixSslGetReadbuf(i->ssl, &buf);
        if (len <= 0)
        {
            return PS_PLATFORM_FAIL;
        }
        transferred = (int32) psSocketReadData(i->sock, buf, len, 0);
        if (transferred >= 0)
        {
            MATRIXSSL_NET_DEBUGF("Received from peer %d bytes\n",
                (int) transferred);
        }
        if (transferred > 0)
        {
            rc = matrixSslReceivedData(i->ssl,
                (int32) transferred,
                &buf, (uint32 *) &len);
            if (rc == MATRIXSSL_APP_DATA ||
                rc == MATRIXSSL_RECEIVED_ALERT)
            {
                i->receive_buf = buf;
                i->receive_len = len;
                i->receive_len_left = len;
                return matrixSslInteractGotData(i, rc);
            }
            if (rc == MATRIXSSL_APP_DATA_COMPRESSED)
            {
                return PS_PLATFORM_FAIL; /* Unsupported. */
            }
        }
        else if (transferred == 0)
        {
            /* Connection has closed down unexpectedly. */
            MATRIXSSL_NET_DEBUGF("Connection cut off.\n");
            return MATRIXSSL_NET_DISCONNECTED;
        }
        else if (rc < 0)
        {
            return PS_PLATFORM_FAIL;
        }
    }
    return rc;
}

int32 matrixSslInteract(matrixSslInteract_t *i, int can_send, int can_receive)
{
    int32 rc = matrixSslInteractInt(i, can_send, can_receive);

    if (rc == PS_SUCCESS && i->handshake_complete == PS_FALSE)
    {
        /* If handshaking, guide the caller to wait reading. */
        rc = MATRIXSSL_REQUEST_RECV;
    }
    else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
    {
        i->handshake_complete = PS_TRUE;
    }
    i->prev_rc = rc;
    return rc;
}

int32 matrixSslInteractHandshake(matrixSslInteract_t *i,
    int can_send, int can_receive)
{
    int32 rc = PS_SUCCESS;

    while (i->handshake_complete == PS_FALSE && rc == PS_SUCCESS)
    {
        rc = matrixSslInteract(i, can_send, can_receive);
        if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
        {
            rc = PS_SUCCESS;
        }
    }
    return rc;
}

size_t matrixSslInteractReadLeft(matrixSslInteract_t *i)
{
    return i->receive_len_left;
}
int32 matrixSslInteractRead(matrixSslInteract_t *i,
    unsigned char *target,
    size_t max_length)
{
    size_t real = matrixSslInteractReadLeft(i);

    if (real > max_length)
    {
        real = max_length;
    }
    if (real > MATRIXSSL_INTERACT_MAX_TRANSFER)
    {
        real = MATRIXSSL_INTERACT_MAX_TRANSFER;
    }
    memcpy(target, i->receive_buf, real);
    i->receive_buf += real;
    i->receive_len_left -= real;
    if (i->receive_buf && i->receive_len_left == 0)
    {
        MATRIXSSL_NET_DEBUGF("All app data read. Will ack soon.\n");
    }
    else if (i->receive_buf)
    {
        MATRIXSSL_NET_DEBUGF("Remaining application data: %d bytes\n",
            (int) i->receive_len_left);
    }
    return real;
}
int32 matrixSslInteractPeek(matrixSslInteract_t *i,
    unsigned char *target,
    size_t max_length)
{
    size_t real = matrixSslInteractReadLeft(i);

    if (real > max_length)
    {
        real = max_length;
    }
    if (real > MATRIXSSL_INTERACT_MAX_TRANSFER)
    {
        real = MATRIXSSL_INTERACT_MAX_TRANSFER;
    }
    memcpy(target, i->receive_buf, real);
    return real;
}
int32 matrixSslInteractWrite(matrixSslInteract_t *i,
    const unsigned char *target,
    size_t length)
{
    unsigned char *buf;
    int32 rc;
    int32 rc2;
    int32 len;

    rc = matrixSslGetWritebuf(i->ssl, &buf, length);
    if (rc <= 0)
    {
        return rc;
    }
    if (rc > length)
    {
        rc = length;
    }
    memcpy(buf, target, rc);
    length -= (size_t) rc;
    rc2 = matrixSslEncodeWritebuf(i->ssl, rc);
    if (rc2 < 0)
    {
        MATRIXSSL_NET_DEBUGF("couldn't encode data %d\n", rc2);
        return rc2;
    }
    if (i->send_len_left == 0)
    {
        len = matrixSslGetOutdata(i->ssl, &buf);
        if (len > 0)
        {
            MATRIXSSL_NET_DEBUGF("To be sent: %d bytes (for %d bytes)\n",
                (int) len, (int) length);
            i->send_buf = buf;
            i->send_len_left = i->send_len = len;
        }
        rc = len;
    }
    return rc;
}

void matrixSslInteractClose(matrixSslInteract_t *i)
{
    if (i->sock)
    {
        psSocketShutdown(i->sock, 0);
    }
    memset(i, 0, sizeof(*i));
}

void matrixSslInteractCloseErr(matrixSslInteract_t *i, int32 status)
{
    if (i->sock)
    {
        psSocketShutdown(i->sock, 0);
    }
    memset(i, 0, sizeof(*i));
}

/**/
int32 matrixSslInteractSendCloseNotify(matrixSslInteract_t *i)
{
    ssl_t *ssl;
    int32 rc;

    ssl = i->ssl;
    rc = matrixSslEncodeClosureAlert(ssl);
    if (rc >= 0)
    {
        rc = matrixSslInteract(i, PS_TRUE, PS_FALSE);
        if (rc < 0)
        {
            return rc;
        }
    }

    return rc;
}

int32 matrixSslInteractReceiveCloseNotify(matrixSslInteract_t *i)
{
    int32 rc;

    rc = matrixSslInteract(i, PS_FALSE, PS_TRUE);
    if (rc < 0)
    {
        return rc;
    }

    return rc;
}

# ifdef USE_CLIENT_SIDE_SSL
int32 matrixSslInteractBeginConnected(matrixSslInteract_t *msi_p,
    const char *hostname, const char *port,
    psSocketOptions_t opts,
    const psSocketFunctions_t *func,
    const sslKeys_t *keys,
    sslSessionId_t *sid,
    const psCipher16_t cipherSpec[],
    uint8_t cSpecLen,
    sslCertCb_t certCb,
    const char *expectedName,
    tlsExtension_t *extensions,
    sslExtCb_t extCb,
    sslSessOpts_t *options)
{
    psSocket_t *sock;
    int32 rc;
    ssl_t *ssl = NULL;

    memset(msi_p, 0, sizeof(*msi_p));
    rc = psSocketConnect(hostname, port, opts,
        PS_SOCKET_STREAM, NULL, func, &sock);
    if (rc == PS_SUCCESS)
    {
        /* Got connection, create SSL client session for it. */
        rc = matrixSslNewClientSession(&ssl, keys, sid,
            cipherSpec, cSpecLen,
            certCb, expectedName,
            extensions,
            extCb, options);
        if (rc < 0)
        {
            psSocketShutdown(sock, 0);
            return rc; /* Failure. */
        }
        matrixSslInteractBegin(msi_p, ssl, sock);
        MATRIXSSL_NET_DEBUGF("Connected and has SSL session, rc=%d\n", (int) rc);
        return rc;
    }
    return rc; /* Failure. */
}
# endif /* USE_CLIENT_SIDE_SSL */

# ifdef USE_SERVER_SIDE_SSL
int32 matrixSslInteractBeginAccept(matrixSslInteract_t *msi_p,
    psSocket_t *sock,
    psSocketOptions_t opts,
    const sslKeys_t *keys,
    sslCertCb_t certCb,
    sslSessOpts_t *options)
{
    psSocket_t *new;
    int32 rc;
    ssl_t *ssl = NULL;

    memset(msi_p, 0, sizeof(*msi_p));
    rc = psSocketAccept(sock, 0, &new);
    if (rc != PS_SUCCESS)
    {
        return rc;
    }

    /* Got connection, create SSL server session for it. */
    rc = matrixSslNewServerSession(&ssl, keys, certCb, options);
    if (rc < PS_SUCCESS)
    {
        psSocketShutdown(new, 0);
        return rc;
    }

    matrixSslInteractBegin(msi_p, ssl, new);
    MATRIXSSL_NET_DEBUGF("Accepted and has SSL session, rc=%d ssl=%p\n",
        (int) rc, ssl);
    return rc;
}
# endif /* USE_SERVER_SIDE_SSL */

#endif  /* USE_PS_NETWORKING */

/* end of file matrixsslNet.c */
