/* matrixsslNet.h
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

#ifndef INCLUDE_GUARD_MATRIXSSLNET_H
#define INCLUDE_GUARD_MATRIXSSLNET_H

#include "core/coreApi.h"
#include "matrixssl/matrixsslApi.h"
#include <stdbool.h>

#ifdef USE_PS_NETWORKING

/* Send or receive. */
typedef struct matrixSslInteract
{
    ssl_t *ssl;
    psSocket_t *sock;
    unsigned char *send_buf;
    ssize_t send_len;
    ssize_t send_len_left;
    unsigned char *receive_buf;   /* Points current read position. */
    size_t receive_len;
    size_t receive_len_left;
    unsigned char ch2[2];
    int32 prev_rc;
    int32 last_encoded_pt_bytes;
    psBool_t handshake_complete;
    psBool_t send_close_notify;
    /* State variables for processing input as TLS records. */
    psBool_t no_readahead; /* read all input (false) or TLS records (true). */
    unsigned int recleft; /* bytes left in record. */
    unsigned char rechdr[5]; /* The latest received record header. */
    unsigned char rechdrlen; /* The length of the latest received
                                record header. */
    unsigned char hdrread; /* Reading record header bytes. */
    unsigned char recvretry; /* Should retry receive, with record content. */
#ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
    /* Need this for the extra call to matrixSslReceivedData,
       to be performed after new client cert and key have been
       loaded. */
    size_t num_last_read_transferred;
#endif
} matrixSslInteract_t;

/* Lower-level API for interacting with MatrixSSL API. */
void matrixSslInteractBegin(matrixSslInteract_t *i, ssl_t *ssl,
                            psSocket_t *sock);
int32 matrixSslInteract(matrixSslInteract_t *i, int can_send, int can_receive);
int32 matrixSslInteract3(matrixSslInteract_t *i,
                         int can_send_net, int can_receive_net,
                         int can_receive_local);
int32 matrixSslInteractHandshake(matrixSslInteract_t *i,
                                 int can_send, int can_receive);
size_t matrixSslInteractReadLeft(matrixSslInteract_t *i);
int32 matrixSslInteractRead(matrixSslInteract_t *i,
                            unsigned char *target,
                            size_t max_length);
int32 matrixSslInteractPeek(matrixSslInteract_t *i,
                            unsigned char *target,
                            size_t max_length);
int32 matrixSslInteractWrite(matrixSslInteract_t *i,
                             const unsigned char *target,
                             size_t length);
void matrixSslInteractClose(matrixSslInteract_t *i);
void matrixSslInteractCloseErr(matrixSslInteract_t *i, int32 status);
int32 matrixSslInteractSendCloseNotify(matrixSslInteract_t *i);
int32 matrixSslInteractReceiveCloseNotify(matrixSslInteract_t *i);
void matrixSslInteractSetReadahead(matrixSslInteract_t *i,
                                   psBool_t readahead_on);

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
                                      sslSessOpts_t *options);
# endif /* USE_CLIENT_SIDE_SSL */

# ifdef USE_SERVER_SIDE_SSL
int32 matrixSslInteractBeginAccept(matrixSslInteract_t *msi_p,
                                   psSocket_t *socket,
                                   psSocketOptions_t opts,
                                   const sslKeys_t *keys,
                                   sslCertCb_t certCb,
                                   sslSessOpts_t *options);
# endif /* USE_SERVER_SIDE_SSL */

/*
   Negative return codes must be between -920 and -939 in the
   MatrixNet module
 */

/* When remote host has disconnected. */
# define MATRIXSSL_NET_DISCONNECTED -920

#endif /* USE_PS_NETWORKING */

#endif /* INCLUDE_GUARD_MATRIXSSLNET_H */

/* end of file matrixsslNet.h */
