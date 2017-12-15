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
# include "core/psUtil.h"

# ifndef MATRIXSSL_INTERACT_READBUF_SIZE
#  define MATRIXSSL_INTERACT_READBUF_SIZE (1024 * 18)
# endif

# ifndef MATRIXSSL_INTERACT_MAX_TRANSFER
#  define MATRIXSSL_INTERACT_MAX_TRANSFER 64000
# endif

# ifdef USE_MATRIX_NET_DEBUG
#  include <stdio.h>
#  define MATRIXSSL_NET_DEBUGF(...) printf(__VA_ARGS__)
# else
#  define MATRIXSSL_NET_DEBUGF(...) do {} while (0)
# endif

/* Defines for constants of TLS record format.
   These are needed when readahead mode is turned off. */
#define MSI_TLS_REC_LEN 5 /* Record length of TLS.
                             1 * type, 2 * version, 2 * content length. */
#define MSI_TLS_REC_CONTENT_LEN_HIGH 3 /* Offset from beginning. */
#define MSI_TLS_REC_CONTENT_LEN_LOW 4 /* Offset from beginning. */
#define MSI_TLS_MAX_CONTENT_LEN (16384 + 2048) /* See RFC 5246. */

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

/* Adjust amount to read according to record header size or
   record size if in no read-ahead mode. */
static
int32
matrixSslInteractBeforeSocketRead(matrixSslInteract_t *i, int32 len)
{
    if (!i->no_readahead)
    {
        /* No adjustment appropriate, just read input as much as possible. */
        return len;
    }
    else
    {
        /* Adjust amount of input to read to hold either record header or
           record content. */

        if (i->rechdrlen < MSI_TLS_REC_LEN)
        {
            /* Reading record header: read at the most missing part of
               5 header bytes, less if read buffer is too small
               (should not happen). */
            i->hdrread = 1;
            return PS_MIN(len, MSI_TLS_REC_LEN - i->rechdrlen);
        }

        if (i->recleft > 0)
        {
            /* Constrain amount of bytes to process according to the record
               length left. */
            return PS_MIN(i->recleft, len);
        }
    }

    /* Fallback: The rechdrlen or recleft is not set properly.
       We fallback to process the input just as if readahead was not set.
       Then core of MatrixSSL will decide how to deal with the packet.
    */
    return len;
}

/* Process result of socket read. */
static
void
matrixSslInteractAfterSocketRead(matrixSslInteract_t *i,
                                 const unsigned char *buf, int32 transferred)
{
    i->recvretry = 0; /* Typically: do not retry after receive. */

    if (transferred <= 0)
    {
        return; /* No data available. */
    }

    if (i->no_readahead)
    {
        if (i->hdrread)
        {
            /* The request was for reading record header.
               Process record header. */
            i->hdrread = 0;

            /* Keep a copy of the record header inside matrixsslNet.
               We use this private copy to determine record length. */
            memcpy(i->rechdr + i->rechdrlen, buf, transferred);
            i->rechdrlen += transferred;

            if (i->rechdrlen == MSI_TLS_REC_LEN)
            {
                int32 reclen;
                
                /* Interpret record length (the record type and the TLS version
                   are ignored here.) */
                reclen = i->rechdr[MSI_TLS_REC_CONTENT_LEN_HIGH] << 8;
                reclen |= i->rechdr[MSI_TLS_REC_CONTENT_LEN_LOW];

                /* Check we do not read beyond TLS maximal encrypted record
                   length. */
                if (reclen <= MSI_TLS_MAX_CONTENT_LEN && reclen != 0)
                {
                    /* We have received record header that is of a valid
                       size. We constrain amount of data to transfer
                       with the next transfer to the record size. */
                    if (i->recleft == 0)
                    {
                        i->recleft = reclen;
                        i->recvretry = 1; /* After providing the record
                                             header bytes to matrixssl, 
                                             continue with the read for record
                                             content. */
                        MATRIXSSL_NET_DEBUGF(
                                "Parsed record header: need to read %u "
                                "bytes of record content.\n",
                                (unsigned) reclen);
                        return;
                    }
                }
            }
            else
            {
                /* Full record header not received yet. */
            }
        }

        if (i->no_readahead && i->recleft)
        {
            psAssert(transferred <= i->recleft);
            i->recleft -= (uint32_t) transferred;
            if (i->recleft == 0)
            {
                /* Entire record received =>
                   Coming up next: read a record header again.
                   Set length of record header read to 0. */
                i->rechdrlen = 0;
            }
        }
    }
}

/* Check if we should retry receive. */
static
psBool_t
matrixSslInteractSocketReadRetry(matrixSslInteract_t *i, int32 rc)
{
    if (i->recvretry)
    {
        /* We have performed partial read for record header, and
           we should retry the reading in case MatrixSSL agrees
           there is a partial record. */
        if (rc == MATRIXSSL_REQUEST_RECV)
        {
            /* We have read a record header and passed it to MatrixSSL.
               MatrixSSL returned that it needs to receive more bytes.
               In this case we will read the record itself,
               without returning MATRIXSSL_REQUEST_RECV.
            */

            i->recvretry = 0; /* Mark we do not do retry again. */
            MATRIXSSL_NET_DEBUGF("Record header read. Repeating "
                                 "receive for record content (%d bytes)"
                                 "\n",
                                 (int) i->recleft);
            return true;
        }
    }
    return false; /* Common case: no read retry. */
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
int32 matrixSslInteractInt3(matrixSslInteract_t *i,
                            int can_send, int can_receive,
                            int can_receive_local)
{
    ssize_t transferred;
    unsigned char *buf;
    int32 rc;
    uint32_t transferlen;

# ifdef USE_MATRIX_NET_DEBUG
    int block = 1;
# endif /* USE_MATRIX_NET_DEBUG */

    if (i->receive_buf && i->receive_len_left == 0)
    {
        /* Continuation of previous receive operation: */
        uint32_t len = i->receive_len;

        buf = i->receive_buf - len;
    again_zero_app_data:
        rc = matrixSslProcessedData(i->ssl, &buf, &len);
        if (buf != NULL && len != 0)
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
                rc = matrixSslInteractGotData(i, rc);
                if (i->send_close_notify == false)
                {
                    return rc;
                }
            }
            else
            {
                return PS_FAILURE;
            }
        }
        if (rc == MATRIXSSL_APP_DATA && len == 0)
        {
            MATRIXSSL_NET_DEBUGF("ignored zero length APP data\n");
            goto again_zero_app_data;
        }
        /* Mark buffer as processed. */
        i->receive_buf = NULL;
        i->receive_len = 0;
        i->receive_len_left = 0;
        MATRIXSSL_NET_DEBUGF("Acked processed data, got: rc=%d\n", rc);
        if (i->send_close_notify == false && rc != MATRIXSSL_REQUEST_RECV)
        {
            return rc;
        }
    }
    else if (can_receive_local && i->receive_buf && i->receive_len_left > 0)
    {
        MATRIXSSL_NET_DEBUGF("Signal more data ready for reading.\n");
        /* Maybe there is remaining application data? */
        rc = MATRIXSSL_APP_DATA;
        if (matrixSslHandshakeIsComplete(i->ssl))
        {
            i->handshake_complete = PS_TRUE;
        }
        if (i->send_close_notify == false)
        {
            return rc;
        }
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
        if (transferred == PS_EAGAIN)
        {
            return MATRIXSSL_REQUEST_SEND;
        }
        if (transferred < 0)
        {
            return PS_PLATFORM_FAIL;
        }
        MATRIXSSL_NET_DEBUGF("Sent%s: %d bytes\n", block ? " cont" : "",
            (int) transferred);
        if (i->send_close_notify)
        {
            MATRIXSSL_NET_DEBUGF("Successfully sent close_notify\n");
            i->send_close_notify = PS_FALSE;
        }
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
            if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
            {
#ifdef ENABLE_FALSE_START
                /* If false start is enabled, there may be
                   some data from client received during
                   handshake. Query for such data. */
                unsigned char *buf = NULL;
                uint32_t len = 0;
                i->handshake_complete = PS_TRUE;
                rc = matrixSslReceivedData(i->ssl, 0, &buf, &len);
                while(rc == MATRIXSSL_APP_DATA && len == 0)
                {
					MATRIXSSL_NET_DEBUGF("Ignored zero length false start data record");
                    rc = matrixSslProcessedData(i->ssl, &buf, &len);
                }
                if (rc == MATRIXSSL_APP_DATA && len > 0)
                {
                    MATRIXSSL_NET_DEBUGF("Received false start data (%u bytes)",
                                         (unsigned) len);
                    i->receive_buf = buf;
                    i->receive_len = len;
                    i->receive_len_left = len;
                    return MATRIXSSL_HANDSHAKE_COMPLETE;
                }
#endif /* ENABLE_FALSE_START */
                return MATRIXSSL_HANDSHAKE_COMPLETE;
            }
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

    receive_repeat:
# ifdef MATRIXSSL_INTERACT_READBUF_SIZE
        /* Use MatrixsslNet's read buffer size. */
        len = matrixSslGetReadbufOfSize(i->ssl,
                                        MATRIXSSL_INTERACT_READBUF_SIZE,
                                        &buf);
# else
        /* Use standard buffer size (usually SSL_DEFAULT_IN_BUF_SIZE). */
        len = matrixSslGetReadbuf(i->ssl, &buf);
#endif
        if (len <= 0)
        {
            return PS_PLATFORM_FAIL;
        }

        /* Read from socket, either up-to full read buffer, or
           record header or record content size if in no_readahead mode. */
        transferlen = matrixSslInteractBeforeSocketRead(i, len);
        MATRIXSSL_NET_DEBUGF("Reading input from socket, up-to %u bytes%s\n",
                             (unsigned) transferlen,
                             i->hdrread ?
                             " (the record header)" :
                             (i->recleft > 0 ?
                              " (the remaining part of a record)" : ""));
        transferred = (int32) psSocketReadData(i->sock, buf, transferlen, 0);
        matrixSslInteractAfterSocketRead(i, buf, transferred);

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

            /* Check if there are more read operations to perform. */
            if (matrixSslInteractSocketReadRetry(i, rc))
            {
                /* Clear transferred variable because we have handled
                   all bytes this far. */
                transferred = 0;
                goto receive_repeat;
            }
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
#       ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
            if (rc == PS_PENDING && matrixSslNeedClientCert(i->ssl))
            {
                i->num_last_read_transferred = transferred;
                MATRIXSSL_NET_DEBUGF("Client cert needed in response to " \
                        "CertificateRequest. Returning PS_PENDING\n");
                return PS_PENDING;
            }
#       endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
        }
        else if (transferred == 0)
        {
            /* Connection has closed down unexpectedly. */
            MATRIXSSL_NET_DEBUGF("Connection cut off.\n");
            return MATRIXSSL_NET_DISCONNECTED;
        }
        else if (transferred == PS_EAGAIN)
        {
            return PS_SUCCESS; /* This operation ok, but more data needed. */
        }
        else if (transferred == PS_MEM_FAIL)
        {
            return PS_MEM_FAIL;
        }
        else if (transferred < 0)
        {
            return PS_PLATFORM_FAIL;
        }
    }
    return rc;
}

static
psBool_t handshake_is_complete(matrixSslInteract_t *i)
{
#ifdef ENABLE_SECURE_REHANDSHAKES
    if (matrixSslRehandshaking(i->ssl))
    {
        return PS_FALSE;
    }
#endif
    return i->handshake_complete;
}

int32 matrixSslInteract(matrixSslInteract_t *i, int can_send, int can_receive)
{
    int32 rc = matrixSslInteractInt3(i, can_send, can_receive, can_receive);

    if (rc == PS_SUCCESS && !handshake_is_complete(i))
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

int32 matrixSslInteract3(matrixSslInteract_t *i,
                         int can_send_net, int can_receive_net,
                         int can_receive_local)
{
    int32 rc = matrixSslInteractInt3(i, can_send_net, can_receive_net,
                                     can_receive_local);

    if (rc == PS_SUCCESS && !handshake_is_complete(i))
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

    while (rc == PS_SUCCESS && !handshake_is_complete(i))
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
    size_t total_read = 0;
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
    total_read = real;

    if (i->receive_buf && i->receive_len_left == 0)
    {
        MATRIXSSL_NET_DEBUGF("Read single record (last_part_len=%d).\n",
                             (int) total_read);
    }
    else if (i->receive_buf)
    {
        MATRIXSSL_NET_DEBUGF("Remaining application data: %d bytes "
                             "(this_part_len=%d)\n",
                             (int) i->receive_len_left,
                             (int) total_read);
    }
    return total_read;
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
    size_t in_len)
{
    unsigned char *buf;
    int32 bytesToEncrypt;
    int32 rc;
    int32 out_len;

    rc = matrixSslGetWritebuf(i->ssl, &buf, in_len);
    if (rc <= 0)
    {
        return rc;
    }
    bytesToEncrypt = rc;
    if (bytesToEncrypt > in_len)
    {
        bytesToEncrypt = in_len;
    }
    memcpy(buf, target, bytesToEncrypt);

    /* Encrypt. */
    rc = matrixSslEncodeWritebuf(i->ssl, bytesToEncrypt);
    if (rc < 0)
    {
        MATRIXSSL_NET_DEBUGF("couldn't encode data %d\n", rc);
        return rc;
    }

    if (i->send_len_left == 0)
    {
        /* Encode into TLS records. */
        out_len = matrixSslGetOutdata(i->ssl, &buf);
        if (out_len > 0)
        {
            MATRIXSSL_NET_DEBUGF("matrixSslInteractWrite: " \
                    "%d plaintext bytes (from a total of %zu) " \
                    "encoded into %d bytes\n",
                    bytesToEncrypt, in_len, out_len);
            i->send_buf = buf;
            i->send_len_left = i->send_len = out_len;
        }
        rc = out_len;
    }

    /* Store how many plaintext bytes we were able to encrypt
       and encode. Caller can use this to measure progress. */
    i->last_encoded_pt_bytes = bytesToEncrypt;

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

    MATRIXSSL_NET_DEBUGF("Sending connection closure alert.\n");
    ssl = i->ssl;
    rc = matrixSslEncodeClosureAlert(ssl);
    if (rc >= 0)
    {
        i->send_close_notify = PS_TRUE;
        rc = matrixSslInteract3(i, PS_TRUE, PS_FALSE, PS_TRUE);
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

void matrixSslInteractSetReadahead(matrixSslInteract_t *i,
                                   psBool_t readahead_on)
{
    if (i)
    {
        i->no_readahead = !readahead_on;
    }
}

#endif  /* USE_PS_NETWORKING */

/* end of file matrixsslNet.c */
