/**
 *      @file    matrixsslApi.c
 *      @version $Format:%h%d$
 *
 *      MatrixSSL Public API Layer.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "matrixsslImpl.h"

/******************************************************************************/
/*
    Create a new client SSL session
    This creates internal SSL buffers and cipher structures
    Clients initiate the connection with a 'HelloRequest', and this data
        is placed in the outgoing buffer for the caller to send.

    ssl         The ssl_t session structure is returned using this value, on success

    keys        Keys structure initialized with matrixSslReadKeys

    sid         A pointer to storage for a session ID. If there is not yet session
            cache information, the sid.cipherId should be set to
            SSL_NULL_WITH_NULL_NULL. After a successful connection to a server,
            this sid structure will be populated with session cache credentials
            and for subsequent connections should be used without modification
            of the cipherId.

    cipherSpec  Array of requested ciphers to negotiate to (0 for server's choice)
                If non-zero, and server doesn't have it, conn will fail

    certCb      Optional callback to call when validating cert

    expectedName Optional certificate subject name to validate in the remote
            certificate. Typically a client would specify the hostname or
            IP address it is connecting to.

    extensions  Optional TLS extensions (usually NULL)

    extCb       TLS reply extensions from the server

    flags       TODO out of date

    Return      MATRIXSSL_REQUEST_SEND on success
            < 0 on error. Do not need to call DeleteSession on failure
 */

#ifdef USE_CLIENT_SIDE_SSL
int32_t matrixSslNewClientSession(ssl_t **ssl, const sslKeys_t *keys,
    sslSessionId_t *sid,
    const psCipher16_t cipherSpec[], uint8_t cipherSpecLen,
    sslCertCb_t certCb,
    const char *expectedName, tlsExtension_t *extensions,
    sslExtCb_t extCb,
    sslSessOpts_t *options)
{
    ssl_t *lssl;
    psBuf_t tmp;
    uint32 len;
    int32 rc, i;

    if (!ssl)
    {
        return PS_ARG_FAIL;
    }
    if (cipherSpecLen > 0 && (cipherSpec == NULL || cipherSpec[0] == 0))
    {
        return PS_ARG_FAIL;
    }
    if (options == NULL)
    {
        return PS_ARG_FAIL;
    }

    *ssl = NULL;
    lssl = NULL;

# ifdef USE_EAP_FAST
    if (sid && sid->sessionTicketState == SESS_TICKET_STATE_EAP_FAST)
    {
        /* EAP-FAST mode places some restrictions on session resumption */
        if (sid->cipherId != 0 || sid->sessionTicket == NULL ||
            sid->sessionTicketLen == 0 ||
            sid->sessionTicketLifetimeHint != 0)
        {
            return PS_ARG_FAIL;
        }
    }
# endif
    /* Give priority to cipher suite if session id is provided and doesn't match */
    if (cipherSpec != NULL && cipherSpec[0] != 0 && sid != NULL &&
        sid->cipherId != 0)
    {
        rc = 1;
        for (i = 0; i < cipherSpecLen; i++)
        {
            if (cipherSpec[i] == sid->cipherId)
            {
                rc = 0;
            }
        }
        if (rc)
        {
            psTraceInfo("Explicit cipher suite will override session cache\n");
            memset(sid->id, 0, SSL_MAX_SESSION_ID_SIZE);
            memset(sid->masterSecret, 0, SSL_HS_MASTER_SIZE);
            sid->cipherId = 0;
        }
    }

    if ((rc = matrixSslNewSession(&lssl, keys, sid, options)) < 0)
    {
        return rc;
    }
    lssl->userPtr = options->userPtr;

    if (options->clientRejectVersionDowngrade)
    {
        lssl->clientRejectVersionDowngrade = 1;
    }

# ifndef USE_ONLY_PSK_CIPHER_SUITE
    if (expectedName)
    {
        if (psX509ValidateGeneralName((char *) expectedName) < 0)
        {
            matrixSslDeleteSession(lssl);
            return rc;
        }
        rc = strlen(expectedName);
        lssl->expectedName = psMalloc(lssl->sPool, rc + 1);
        strcpy(lssl->expectedName, expectedName);
        memcpy(&lssl->validateCertsOpts,
            &options->validateCertsOpts,
            sizeof(matrixValidateCertsOptions_t));
    }
    if (certCb)
    {
        matrixSslSetCertValidator(lssl, certCb);
    }
# endif
    if (extCb)
    {
        lssl->extCb = extCb;
    }
# ifdef USE_EAP_FAST
    if (sid && sid->sessionTicketState == SESS_TICKET_STATE_EAP_FAST)
    {
        /* Flag for EncodeClientHello that we want to resume with a ticket */
        sid->sessionTicketState = SESS_TICKET_STATE_INIT;
        options->ticketResumption = 1;
        /* Indicate we're tunnelled below EAP_FAST */
        lssl->flags |= SSL_FLAGS_EAP_FAST;
    }
# endif
RETRY_HELLO:
    tmp.size = lssl->outsize;
    tmp.buf = tmp.start = tmp.end = lssl->outbuf;
    if ((rc = matrixSslEncodeClientHello(lssl, &tmp, cipherSpec, cipherSpecLen,
             &len, extensions, options)) < 0)
    {
        if (rc == SSL_FULL)
        {
            if ((tmp.buf = psRealloc(lssl->outbuf, len, lssl->bufferPool))
                == NULL)
            {
                matrixSslDeleteSession(lssl);
                return PS_MEM_FAIL;
            }
            lssl->outbuf = tmp.buf;
            lssl->outsize = len;
            goto RETRY_HELLO;
        }
        else
        {
            matrixSslDeleteSession(lssl);
            return rc;
        }
    }
    psAssert(tmp.start == tmp.buf);
    lssl->outlen = tmp.end - tmp.start;
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    /*
       Private key size is used by MatrixSSL to estimate the Cv
       signature size. When using external Cv signing, we do not
       have access to the private key. However, we can use the
       public key size instead, since it is the same.
       If we don't have a cert, we are likely using a PSK ciphersuite
       in which case a Cv message is not needed.
     */
    if (options->useExtCvSigOp)
    {
        if (lssl->keys->cert)
        {
            lssl->keys->privKey.keysize = lssl->keys->cert->publicKey.keysize;
        }
        /*
           Enable external Cv signature generation for this connection.
         */
        lssl->extCvSigOpInUse = 1;
    }
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
    *ssl = lssl;
    return MATRIXSSL_REQUEST_SEND;
}

/* SessionID management functions for clients that wish to perform
    session resumption.  This structure handles both the traditional resumption
    mechanism and the server-stateless session ticket mechanism
 */
int32 matrixSslNewSessionId(sslSessionId_t **sess, void *poolUserPtr)
{
    sslSessionId_t *ses;
    psPool_t *pool = NULL;

    if ((ses = psMalloc(pool, sizeof(sslSessionId_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }
    memset(ses, 0x0, sizeof(sslSessionId_t));
    ses->pool = pool;
    *sess = ses;
    return PS_SUCCESS;
}

void matrixSslClearSessionId(sslSessionId_t *sess)
{
    psPool_t *pool;

    pool = sess->pool;
    memset(sess, 0x0, sizeof(sslSessionId_t));
    sess->pool = pool;
}

void matrixSslDeleteSessionId(sslSessionId_t *sess)
{

    if (sess == NULL)
    {
        return;
    }
#  ifdef USE_STATELESS_SESSION_TICKETS
    if (sess->sessionTicket)
    {
        psFree(sess->sessionTicket, sess->pool);
    }
#  endif

    memset(sess, 0x0, sizeof(sslSessionId_t));
    psFree(sess, NULL);
}

#  ifdef USE_EAP_FAST
/**
    Set the TLS connection to connect using an externally provisioned EAP-FAST
    Protected Access Credential (PAC).
    @see https://tools.ietf.org/html/rfc4851
    @param[in,out] sess SessionID structure to fill in with PAC.
    @param[in] pac_key 32 byte secret key shared between the EAP-FAST peers.
        This is used by EAP-FAST peers to do session key derivation and is
        never sent over the wire (encrypted or unencrypted) by TLS.
    @param[in] pac_opaque Opaque value to be sent as plaintext to the server
        within the SessionTicket ClientHello Extension so the server can
        choose the correct pac_key.
    @param[in] pac_opaque_len Length in bytes of 'pac_opaque'
 */
void matrixSslSetSessionIdEapFast(sslSessionId_t *sess,
    const unsigned char pac_key[EAP_FAST_PAC_KEY_LEN],
    const unsigned char *pac_opaque, psSize_t pac_opaque_len)
{
    psAssert(sess && pac_key && pac_opaque && (pac_opaque_len > 0));

    /* Indicate we're overriding the default Ticket fields and behavior */
    sess->sessionTicketState = SESS_TICKET_STATE_EAP_FAST;
#   if EAP_TLS_PAC_KEY_LEN > SSL_HS_MASTER_SIZE
#    error EAP_TLS_PAC_KEY_LEN too large
#   endif
    /** @note, sess->master_secret must go through tprf() before being used */
    memcpy(sess->masterSecret, pac_key, EAP_FAST_PAC_KEY_LEN);
    sess->sessionTicket = psMalloc(sess->pool, pac_opaque_len);
    memcpy(sess->sessionTicket, pac_opaque, pac_opaque_len);
    sess->sessionTicketLen = pac_opaque_len;
}

int32_t matrixSslGetEapFastSKS(const ssl_t *ssl,
    unsigned char session_key_seed[EAP_FAST_SESSION_KEY_SEED_LEN])
{
    if (!ssl || !session_key_seed)
    {
        psAssert(ssl && session_key_seed);
        return PS_FAIL;
    }
    if (!ssl->sec.eap_fast_session_key_seed ||
        matrixSslHandshakeIsComplete(ssl) != PS_TRUE)
    {
        return PS_EAGAIN;
    }
    memcpy(session_key_seed, ssl->sec.eap_fast_session_key_seed,
        EAP_FAST_SESSION_KEY_SEED_LEN);
    return PS_SUCCESS;
}
#  endif /* USE_EAP_FAST */

# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
int32_t matrixSslNeedClientCert(ssl_t *ssl)
{
    if (ssl->extClientCertKeyStateFlags ==
            EXT_CLIENT_CERT_KEY_STATE_WAIT_FOR_CERT_KEY_UPDATE)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}
int32_t matrixSslNeedClientPrivKey(ssl_t *ssl)
{
    if (ssl->extClientCertKeyStateFlags ==
            EXT_CLIENT_CERT_KEY_STATE_WAIT_FOR_CERT_KEY_UPDATE)
    {
#  ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
        /*
          Not going to need priv key loading when we are signing
          the CertificateVerify message externally - we won't need
          direct access to the priv key in that case.
        */
        if (matrixSslNeedCvSignature(ssl))
        {
            return PS_FALSE;
        }
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}
int32_t matrixSslClientCertUpdated(ssl_t *ssl)
{
    if (ssl->extClientCertKeyStateFlags !=
            EXT_CLIENT_CERT_KEY_STATE_WAIT_FOR_CERT_KEY_UPDATE)
    {
        psTraceInfo("Error: wrong state for client cert update\n");
        return PS_FALSE;
    }
    else
    {
        ssl->extClientCertKeyStateFlags =
            EXT_CLIENT_CERT_KEY_STATE_GOT_CERT_KEY_UPDATE;
        /*
          We will assume the client has loaded a cert that is
          compatible with the server's expectations.
          By-pass MatrixSSL checks.
        */
        /**/
        if (ssl->keys && ssl->keys->cert)
        {
            ssl->sec.certMatch = 1;
        }

        return PS_TRUE;
    }
}

int32_t matrixSslClientPrivKeyUpdated(ssl_t *ssl)
{
    if (ssl->extClientCertKeyStateFlags !=
            EXT_CLIENT_CERT_KEY_STATE_WAIT_FOR_CERT_KEY_UPDATE)
    {
        psTraceInfo("Error: wrong state for client key update\n");
        return PS_FALSE;
    }
    else
    {
        ssl->extClientCertKeyStateFlags =
            EXT_CLIENT_CERT_KEY_STATE_GOT_CERT_KEY_UPDATE;
        return PS_TRUE;
    }
}
# endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */

# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
int32_t matrixSslNeedCvSignature(ssl_t *ssl)
{
    psAssert(ssl != NULL);

    if (ssl->extCvSigOpPending)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

int32_t matrixSslGetHSMessagesHash(ssl_t *ssl, unsigned char *hash, size_t *hash_len)
{
    psAssert(ssl != NULL || hash != NULL || hash_len != NULL);

    if (!ssl->extCvSigOpPending)
    {
        return PS_FAILURE;
    }

    psAssert(ssl->extCvHash != NULL);

    psAssert(ssl->extCvHashLen == 20 || ssl->extCvHashLen == 32 ||
        ssl->extCvHashLen == 36 || ssl->extCvHashLen == 48 ||
        ssl->extCvHashLen == 64);

    if (*hash_len < ssl->extCvHashLen)
    {
        return PS_OUTPUT_LENGTH;
    }

    memcpy(hash, ssl->extCvHash, ssl->extCvHashLen);
    *hash_len = ssl->extCvHashLen;

    return PS_SUCCESS;
}

int32_t matrixSslGetCvSignatureAlg(ssl_t *ssl)
{
    psAssert(ssl != NULL);

    if (!matrixSslNeedCvSignature(ssl))
    {
        return PS_FAILURE;
    }

    return ssl->extCvSigAlg;
}

int32_t matrixSslGetPubKeySize(ssl_t *ssl)
{
    int32_t type;

    psAssert(ssl != NULL);

    if (!matrixSslNeedCvSignature(ssl))
    {
        return PS_FAILURE;
    }

    type = matrixSslGetCvSignatureAlg(ssl);
    if (type < 0)
    {
        return type;
    }

    switch (type)
    {
#  ifdef USE_RSA
    case PS_RSA:
        return ssl->keys->cert->publicKey.keysize;
#  endif
#  ifdef USE_ECC
    case PS_ECC:
        return ssl->keys->cert->publicKey.key.ecc.curve->size;
#  endif
    default:
        psTraceIntInfo("matrixSslGetPubKeySize: unsupported alg type: %d\n", type);
        return PS_UNSUPPORTED_FAIL;
    }
}

int32_t matrixSslSetCvSignature(ssl_t *ssl, const unsigned char *sig, const size_t sig_len)
{
    psAssert(ssl != NULL || sig != NULL || sig_len > 0);

    if (!ssl->extCvSigOpPending)
    {
        return PS_FAILURE;
    }

    psAssert(ssl->extCvSigAlg == PS_RSA || ssl->extCvSigAlg == PS_ECC);

    if (ssl->extCvSigAlg == PS_RSA)
    {
        ssl->extCvSig = psMalloc(NULL, sig_len);
    }
    else
    {
        ssl->extCvSig = psMalloc(NULL, sig_len + 2); /* See below. */

    }
    if (ssl->extCvSig == NULL)
    {
        return PS_MEM_FAIL;
    }

/*
      struct {
           digitally-signed struct {
               opaque handshake_messages[handshake_messages_length];
           }
      } CertificateVerify;

      struct {
         SignatureAndHashAlgorithm algorithm;
         opaque signature<0..2^16-1>;
      } DigitallySigned;
 */

    switch (ssl->extCvSigAlg)
    {
#  ifdef USE_ECC
    case PS_ECC:
        /*
           The "signature" vector in the DigitallySigned struct
           needs a two-byte length specifier (see the struct defs above).

           @note For RSA, the length bytes are added already in
           WriteCertificateVerify. For ECDSA, we do not know the size
           of the signature at that point. That's why we need at add the
           length encoding here.

           @note When computing the signature internally (i.e. when
           USE_EXT_CERTIFICATE_VERIFY_SIGNING is not enabled, psEccDsaSign
           adds the length bytes (the includeSize parameter).
         */
        ssl->extCvSig[0] = (sig_len & 0xFF00) >> 8;
        ssl->extCvSig[1] = (sig_len & 0xFF);
        memcpy(ssl->extCvSig + 2, sig, sig_len);
        ssl->extCvSigLen = sig_len + 2;
        break;
#  endif
#  ifdef USE_RSA
    case PS_RSA:
        memcpy(ssl->extCvSig, sig, sig_len);
        ssl->extCvSigLen = sig_len;
        break;
#  endif
    default:
        psTraceIntInfo("matrixSslSetCvSignature: unsupported alg type: %d\n",
            ssl->extCvSigAlg);
        return PS_UNSUPPORTED_FAIL;
    }

    return PS_SUCCESS;
}
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
#endif  /* USE_CLIENT_SIDE_SSL */

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    Create a new server SSL session
    This creates internal SSL buffers and cipher structures
    Internal SSL state is set to expect an incoming 'HelloRequest'

    Return      MATRIXSSL_SUCCESS on success
            < 0 on error
 */

int32 matrixSslNewServer(ssl_t **ssl,
    pubkeyCb_t pubkeyCb, pskCb_t pskCb, sslCertCb_t certCb,
    sslSessOpts_t *options)
{
    int32 rc;

    if ((rc = matrixSslNewServerSession(ssl, NULL, certCb, options)) < 0)
    {
        return rc;
    }

    (*ssl)->sec.pskCb = (pskCb_t) pskCb;
# ifndef USE_ONLY_PSK_CIPHER_SUITE
    (*ssl)->sec.pubkeyCb = (pubkeyCb_t) pubkeyCb;
# endif
    return MATRIXSSL_SUCCESS;
}

int32 matrixSslNewServerSession(ssl_t **ssl, const sslKeys_t *keys,
    sslCertCb_t certCb,
    sslSessOpts_t *options)
{
    ssl_t *lssl;
    int32 providedVersionFlag;

    if (!ssl)
    {
        return PS_ARG_FAIL;
    }
    if (options == NULL)
    {
        return PS_ARG_FAIL;
    }

    providedVersionFlag = options->versionFlag;

    /* Add SERVER_FLAGS to versionFlag member of options */
    options->versionFlag |= SSL_FLAGS_SERVER;
    *ssl = NULL;
    lssl = NULL;

# ifdef USE_CLIENT_AUTH
    if (certCb)
    {
        options->versionFlag |= SSL_FLAGS_CLIENT_AUTH;
        if (matrixSslNewSession(&lssl, keys, NULL, options) < 0)
        {
            goto NEW_SVR_ERROR;
        }
        matrixSslSetCertValidator(lssl, (sslCertCb_t) certCb);
    }
    else if (matrixSslNewSession(&lssl, keys, NULL, options) < 0)
    {
        goto NEW_SVR_ERROR;
    }
# else
    psAssert(certCb == NULL);
    if (matrixSslNewSession(&lssl, keys, NULL, options) < 0)
    {
        goto NEW_SVR_ERROR;
    }
# endif /* USE_CLIENT_AUTH */

    /*
      Server-specific options that can be used to restrict the
      supported protocol version range. These are only applicable
      when the library user did not set any specific version to
      versionFlag.
    */
# if defined(USE_TLS_1_2_TOGGLE) || defined(USE_TLS_1_0_TOGGLE)
    if (providedVersionFlag == 0)
    {
#  ifdef USE_TLS_1_2_TOGGLE
        if (options->serverDisableTls1_2)
        {
            lssl->disable_tls_1_2 = PS_TRUE;
        }
#  endif
#  ifdef USE_TLS_1_0_TOGGLE
        if (options->disableTls1_0)
        {
            lssl->disable_tls_1_0 = PS_TRUE;
        }
#  endif
    }
# endif /* USE_TLS_1_2_TOGGLE || USE_TLS_1_0_TOGGLE */
    /*
        For the server, ssl->expectedName can only be populated with
        the server name parsed from the Server Name Indication
        extension sent by the client. Clearly, the client cert
        should not be validated against that.
     */
    lssl->validateCertsOpts.flags |= VCERTS_FLAG_SKIP_EXPECTED_NAME_VALIDATION;

    lssl->userPtr = options->userPtr;
    if (options->maxFragLen < 0)
    {
        /* User wants to deny a client request for changing max frag len */
        lssl->extFlags.deny_max_fragment_len = 1;
    }
    lssl->maxPtFrag = SSL_MAX_PLAINTEXT_LEN;

    if (options->truncHmac < 0)
    {
        lssl->extFlags.deny_truncated_hmac = 1;
    }

    /* Extended master secret is enabled by default.  If user sets to 1 this
        is a flag to REQUIRE its use */
    if (options->extendedMasterSecret > 0)
    {
        lssl->extFlags.require_extended_master_secret = 1;
    }

    *ssl = lssl;
    return MATRIXSSL_SUCCESS;

NEW_SVR_ERROR:
    if (lssl)
    {
        matrixSslDeleteSession(lssl);
    }
    return PS_FAILURE;
}

void matrixSslRegisterSNICallback(ssl_t *ssl, void (*sni_cb)(void *ssl,
        char *hostname, int32 hostnameLen, sslKeys_t **newKeys))
{
    ssl->sni_cb = sni_cb;
}

#  ifdef USE_ALPN
void matrixSslRegisterALPNCallback(ssl_t *ssl,
    void (*srv_alpn_cb)(void *ssl, short protoCount,
        char *proto[MAX_PROTO_EXT], int32 protoLen[MAX_PROTO_EXT],
        int32 *index))
{
    ssl->srv_alpn_cb = srv_alpn_cb;
}
#  endif

#endif  /* USE_SERVER_SIDE_SSL */



/******************************************************************************/
/*
    Caller is asking for allocated buffer storage to recv data into

    buf         Populated with a transient area where data can be read into

    Return      > 0, size of 'buf' in bytes
            <= 0 on error
 */
int32 matrixSslGetReadbuf(ssl_t *ssl, unsigned char **buf)
{
    if (!ssl || !buf)
    {
        return PS_ARG_FAIL;
    }
    psAssert(ssl && ssl->insize > 0 && ssl->inbuf != NULL);
    /* If there's unprocessed data in inbuf, have caller append to it */
    *buf = ssl->inbuf + ssl->inlen;
    return ssl->insize - ssl->inlen;
}

/* If the required size is known, grow the buffer here so the caller doesn't
    have to go through the REQUEST_RECV logic of matrixSslReceivedData

    The return value MAY be larger than the requested size if the inbuf
    is already larger than what was requested.
 */
int32 matrixSslGetReadbufOfSize(ssl_t *ssl, int32 size, unsigned char **buf)
{
    unsigned char *p;

    if (!ssl || !buf)
    {
        return PS_ARG_FAIL;
    }
    psAssert(ssl && ssl->insize > 0 && ssl->inbuf != NULL);

    if ((ssl->insize - ssl->inlen) >= size)
    {
        /* Already enough room in current buffer */
        return matrixSslGetReadbuf(ssl, buf);
    }

    /* Going to have to grow... but do we have to realloc to save data? */
    if (ssl->inlen == 0)
    {
        /* buffer is empty anyway so can free before alloc and help keep high
            water mark down */
        psFree(ssl->inbuf, ssl->bufferPool);
        ssl->inbuf = NULL;
        if ((ssl->inbuf = psMalloc(ssl->bufferPool, size)) == NULL)
        {
            ssl->insize = 0;
            return PS_MEM_FAIL;
        }
        ssl->insize = size;
        *buf = ssl->inbuf;
        return ssl->insize;
    }
    else
    {
        /* realloc with: total size = current size + requested size */
        if ((p = psRealloc(ssl->inbuf, ssl->inlen + size, ssl->bufferPool))
            == NULL)
        {
            ssl->inbuf = NULL; ssl->insize = 0; ssl->inlen = 0;
            return PS_MEM_FAIL;
        }
        ssl->inbuf = p;
        ssl->insize = ssl->inlen + size;
        *buf = ssl->inbuf + ssl->inlen;
        return size;
    }
    return PS_FAILURE; /* can't hit */
}

/******************************************************************************/
/*
    Caller is asking if there is any encoded, outgoing SSL data that should be
        sent out the transport layer.

    buf         if provided, is updated to point to the data to be sent

    Return      > 0, the number of bytes to send
            0 if there is no pending data
            < 0 on error
 */
int32 matrixSslGetOutdata(ssl_t *ssl, unsigned char **buf)
{
    if (!ssl)
    {
        return PS_ARG_FAIL;
    }
    psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);
    if (buf)
    {
        *buf = ssl->outbuf;
    }
    return ssl->outlen; /* Can be 0 */
}

/******************************************************************************/
/*
    Caller is asking for an allocated buffer to write plaintext into.
        That plaintext will then be encoded when the caller subsequently calls
        matrixSslEncodeWritebuf()

    This is also explicitly called by matrixSslEncodeToOutdata

    ssl         SSL session context

    buf         The data storage to write into will be populated here on success

    requestedLen        The amount of buffer space the caller would like to use

    Return      > 0, success returns # bytes available for plaintext at buf
            PS_MEM_FAIL if requiredLen too large for current memory
            <= 0 on error
 */
int32 matrixSslGetWritebuf(ssl_t *ssl, unsigned char **buf, uint32 requestedLen)
{
    uint32 requiredLen, sz, overhead;

# ifdef USE_DTLS
    int32 pmtu;
# endif
    unsigned char *p;

    if (!ssl || !buf)
    {
        return PS_ARG_FAIL;
    }
    psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);

# ifdef USE_BEAST_WORKAROUND
    /* This is a client-only feature */
    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
        /* Not a problem at all beginning in TLS 1.1 (version 3.2) and never
            a problem on stream ciphers */
        if ((ssl->majVer == SSL3_MAJ_VER) && (ssl->minVer <= TLS_MIN_VER)
            && (ssl->enBlockSize > 1) && (requestedLen > 1) &&
            !(ssl->bFlags & BFLAG_STOP_BEAST))
        {
            ssl->bFlags |= BFLAG_STOP_BEAST;
        }
    }
# endif

/*
    First thing is to ensure under the maximum allowed plaintext len according
    to the SSL specification (or the negotiated max).  If not, set it to the
    max for the calculations and make sure that exact max is returned to the
    caller.  The responsibilty for fragmenting the message is left to them
 */
    if (requestedLen > (uint32) ssl->maxPtFrag)
    {
        requestedLen = ssl->maxPtFrag;
    }

/*
    What is the total encoded size for a plaintext requestedLen.  The overhead
    includes leading header as well as trailing MAC and pad

    We want to tweak the overhead an extra block to account for a
    padding miscalculation in matrixSslGetEncodedSize.  If that call was
    made on an exact-sized message and the user decides to use a
    different record size than requested, we'll need to make sure
    there is enough available room for any potential padding length.
 */
    requiredLen = matrixSslGetEncodedSize(ssl, requestedLen + ssl->enBlockSize);

    psAssert(requiredLen >= requestedLen);
    overhead = requiredLen - requestedLen;

# ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        pmtu = matrixDtlsGetPmtu();
        if (requiredLen > (uint32) pmtu)
        {
            overhead = matrixSslGetEncodedSize(ssl, 0) + ssl->enBlockSize;
            requiredLen = matrixSslGetEncodedSize(ssl, pmtu - overhead);
        }
    }
# endif

/*
    Get current available space in outbuf
 */
    if (ssl->outsize < ssl->outlen)
    {
        return PS_FAILURE;
    }
    sz = ssl->outsize - ssl->outlen;

/*
    If not enough free space for requiredLen, grow the buffer
 */
    if (sz < requiredLen)
    {
        if ((p = psRealloc(ssl->outbuf, ssl->outsize +
                 (requiredLen - sz), ssl->bufferPool)) == NULL)
        {
            return PS_MEM_FAIL;
        }
        ssl->outbuf = p;
        ssl->outsize = ssl->outsize + (requiredLen - sz);
/*
        Recalculate available free space
 */
        if (ssl->outsize < ssl->outlen)
        {
            return PS_FAILURE;
        }
        sz = ssl->outsize - ssl->outlen;
    }

/*
    Now that requiredLen has been confirmed/created, return number of available
    plaintext bytes
 */
    if (requestedLen <= (uint32) ssl->maxPtFrag)
    {
        requestedLen = sz - overhead;
        if (requestedLen > (uint32) ssl->maxPtFrag)
        {
            requestedLen = ssl->maxPtFrag;
        }
    }

/*
    Now return the pointer that has skipped past the record header
 */
# ifdef USE_TLS_1_1
/*
    If a block cipher is being used TLS 1.1 requires the use
    of an explicit IV.  This is an extra random block of data
    prepended to the plaintext before encryption.  Account for
    that extra length here.
 */
    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
        (ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->enBlockSize > 1))
    {
        *buf = ssl->outbuf + ssl->outlen + ssl->recordHeadLen + ssl->enBlockSize;
        return requestedLen; /* may not be what was passed in */
    }
    /* GCM mode will need to save room for the nonce */
    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        *buf = ssl->outbuf + ssl->outlen + ssl->recordHeadLen +
               AEAD_NONCE_LEN(ssl);
        return requestedLen; /* may not be what was passed in */
    }
# endif /* USE_TLS_1_1 */

# ifdef USE_BEAST_WORKAROUND
    if (ssl->bFlags & BFLAG_STOP_BEAST)
    {
        /* The reserved space accounts for a full encoding of a 1 byte record.
            The final -1 is so that when the second encrypt arrives it will
            land as an in-situ */
        overhead = ((ssl->enMacSize + 1) % ssl->enBlockSize) ?
                   ssl->enBlockSize : 0;
        *buf = ssl->outbuf + ssl->outlen + (2 * ssl->recordHeadLen) + overhead +
               (ssl->enBlockSize * ((ssl->enMacSize + 1) / ssl->enBlockSize)) - 1;
    }
    else
    {
        *buf = ssl->outbuf + ssl->outlen + ssl->recordHeadLen;
    }
# else
    *buf = ssl->outbuf + ssl->outlen + ssl->recordHeadLen;
# endif
    return requestedLen; /* may not be what was passed in */
}

/******************************************************************************/
/*
    ptBuf = plaintext buffer
    ptLen = length of plaintext in bytes
    ctBuf = allocated ciphertext destination buffer
    ctLen = INPUT ctBuf buffer size and OUTPUT is length of ciphertext

    Return value = SUCCESS is > 0 and FAILURE is < 0
 */
int32 matrixSslEncodeToUserBuf(ssl_t *ssl, unsigned char *ptBuf, uint32 ptLen,
    unsigned char *ctBuf, uint32 *ctLen)
{
    int32 rc;

    rc = matrixSslEncode(ssl, ctBuf, *ctLen, ptBuf, &ptLen);
    if (rc > 0)
    {
        *ctLen = ptLen;
    }
    return rc;
}

/******************************************************************************/
/*
    Encode (encrypt) 'len' bytes of plaintext data that has been placed into
    the buffer given by matrixSslGetWritebuf().  This is an in-situ encode.

    CAN ONLY BE CALLED AFTER A PREVIOUS CALL TO matrixSslGetWritebuf

    len         >= 0.If len is zero, we send out a blank ssl record
            len must be <= size returned by matrixSslGetWritebuf()

    Returns < 0 on error, total #bytes in outgoing data buf on success
 */
int32 matrixSslEncodeWritebuf(ssl_t *ssl, uint32 len)
{
    unsigned char *origbuf;
    int32 rc, reserved;

    if (!ssl || ((int32) len < 0))
    {
        return PS_ARG_FAIL;
    }
    if (ssl->bFlags & BFLAG_CLOSE_AFTER_SENT)
    {
        return PS_PROTOCOL_FAIL;
    }
    psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);
    /* Caller was given proper locations and lengths in GetWritebuf() */
    origbuf = ssl->outbuf + ssl->outlen;
    if (ssl->outbuf == NULL || (ssl->outsize - ssl->outlen) < (int32) len)
    {
        return PS_FAILURE;
    }

    reserved = ssl->recordHeadLen;
# ifdef USE_BEAST_WORKAROUND
    if (ssl->bFlags & BFLAG_STOP_BEAST)
    {
        rc = ((ssl->enMacSize + 1) % ssl->enBlockSize) ? ssl->enBlockSize : 0;
        reserved += ssl->recordHeadLen + rc +
                    (ssl->enBlockSize * ((ssl->enMacSize + 1) / ssl->enBlockSize)) - 1;
    }
# endif

# ifdef USE_TLS_1_1
/*
    If a block cipher is being used TLS 1.1 requires the use
    of an explicit IV.  This is an extra random block of data
    prepended to the plaintext before encryption.  Account for
    that extra length here.
 */
    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
        (ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->enBlockSize > 1))
    {
        reserved += ssl->enBlockSize;
    }
    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        reserved += AEAD_NONCE_LEN(ssl);
    }
# endif /* USE_TLS_1_1 */

    rc = matrixSslEncode(ssl, origbuf, (ssl->outsize - ssl->outlen),
        origbuf + reserved, &len);
    if (rc < 0)
    {
        psAssert(rc != SSL_FULL);   /* should not happen */
        return PS_FAILURE;
    }
# ifdef USE_MATRIXSSL_STATS
    matrixsslUpdateStat(ssl, APP_DATA_SENT_STAT, len);
# endif
    ssl->outlen += len;
    return ssl->outlen;
}

/******************************************************************************/
/*
    This public API allows the user to encrypt the plaintext buffer of their
    choice into the internal outbuf that is retrieved when matrixSslGetOutdata
    is called.  This is non-in-situ support and will leave the callers
    plaintext buffer intact

    ptBuf       The plaintext buffer to be converted into an SSL application data
            record.
    len         The length, in bytes, of the ptBuf plaintext data

    Returns < 0 on error, total #bytes in outgoing data buf on success
 */
int32 matrixSslEncodeToOutdata(ssl_t *ssl, unsigned char *ptBuf, uint32 len)
{
    unsigned char *internalBuf;
    int32 rc, fragLen, recLen, index;

    if (!ssl || !ptBuf)
    {
        return PS_ARG_FAIL;
    }
    if (ssl->bFlags & BFLAG_CLOSE_AFTER_SENT)
    {
        return PS_PROTOCOL_FAIL;
    }

# ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        rc = matrixSslGetEncodedSize(ssl, len);
        if (rc > matrixDtlsGetPmtu())
        {
            return PS_LIMIT_FAIL;
        }
    }
# endif

    /* Fragmentation support */
    index = 0;
    while (len > 0)
    {
        /*      We just call matrixSslGetWritebuf to prepare the buffer */
        if ((rc = matrixSslGetWritebuf(ssl, &internalBuf, len)) < 0)
        {
            psTraceIntInfo("matrixSslEncodeToOutbuf allocation error: %d\n",
                rc);
            return rc;
        }
        recLen = fragLen = min((uint32) rc, len);
        psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);

        if (ssl->outbuf == NULL ||
            (ssl->outsize - ssl->outlen) < (int32) fragLen)
        {
            return PS_FAILURE;
        }
        internalBuf = ssl->outbuf + ssl->outlen;

        rc = matrixSslEncode(ssl, internalBuf, (ssl->outsize - ssl->outlen),
            ptBuf + index, (uint32 *) &fragLen);
        if (rc < 0)
        {
            psAssert(rc != SSL_FULL);   /* should not happen */
            return PS_FAILURE;
        }
        index += recLen;
        len -= recLen;
# ifdef USE_MATRIXSSL_STATS
        matrixsslUpdateStat(ssl, APP_DATA_SENT_STAT, fragLen);
# endif
        ssl->outlen += fragLen;
    }
    return ssl->outlen;
}

/******************************************************************************/
/*
    Helper to shrink buffers down to default size
 */
#define SSL_INBUF   0
#define SSL_OUTBUF  1

static void revertToDefaultBufsize(ssl_t *ssl, uint16 inOrOut)
{
    int32 defaultSize;

    unsigned char *p;

    if (inOrOut == SSL_INBUF)
    {
#ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            defaultSize = matrixDtlsGetPmtu();
        }
        else
        {
            defaultSize = SSL_DEFAULT_IN_BUF_SIZE;
        }
#else
        defaultSize = SSL_DEFAULT_IN_BUF_SIZE;
#endif
        if (ssl->insize > defaultSize && ssl->inlen < defaultSize)
        {
            /* It's not fatal if we can't realloc it smaller */
            if ((p = psRealloc(ssl->inbuf, defaultSize, ssl->bufferPool))
                != NULL)
            {
                ssl->inbuf = p;
                ssl->insize  = defaultSize;
            }
        }
    }
    else
    {
#ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            defaultSize = matrixDtlsGetPmtu();
        }
        else
        {
            defaultSize = SSL_DEFAULT_OUT_BUF_SIZE;
        }
#else
        defaultSize = SSL_DEFAULT_OUT_BUF_SIZE;
#endif
        if (ssl->outsize > defaultSize && ssl->outlen < defaultSize)
        {
            /* It's not fatal if we can't realloc it smaller */
            if ((p = psRealloc(ssl->outbuf, defaultSize, ssl->bufferPool))
                != NULL)
            {
                ssl->outbuf = p;
                ssl->outsize = defaultSize;
            }
        }
    }
}

/******************************************************************************/
/*
    Caller has received data from the network and is notifying the SSL layer
 */
int32 matrixSslReceivedData(ssl_t *ssl, uint32 bytes, unsigned char **ptbuf,
    uint32 *ptlen)
{
    unsigned char *buf, *prevBuf;
    int32 rc, decodeRet, size, sanity, decodeErr;
    uint32 processed, start, len, reqLen;
    unsigned char alertLevel, alertDesc;

    unsigned char *p;

    if (!ssl || !ptbuf || !ptlen)
    {
        return PS_ARG_FAIL;
    }

    psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);
    psAssert(ssl->insize > 0 && ssl->inbuf != NULL);
    *ptbuf = NULL;
    *ptlen = 0;
    ssl->inlen += bytes;
    if (ssl->inlen == 0)
    {
        return PS_SUCCESS; /* Nothing to do.  Basically a poll */
    }
    /* This is outside the loop b/c we may want to parse within inbuf later */
    buf = ssl->inbuf;
DECODE_MORE:
    /* Parameterized sanity check to avoid infinite loops */
    if (matrixSslHandshakeIsComplete(ssl))
    {
        /* Minimum possible record size once negotiated */
        sanity = ssl->inlen / (SSL3_HEADER_LEN + MD5_HASH_SIZE);
    }
    else
    {
        /* Even with an SSLv2 hello, the sanity check will let 1 pass through */
        sanity = ssl->inlen / (SSL3_HEADER_LEN + SSL3_HANDSHAKE_HEADER_LEN);
    }
    if (sanity-- < 0)
    {
        return PS_PROTOCOL_FAIL;    /* We've tried to decode too many times */
    }
    len = ssl->inlen;
    size = ssl->insize - (buf - ssl->inbuf);
    prevBuf = buf;
    decodeRet = matrixSslDecode(ssl, &buf, &len, size, &start, &reqLen,
        &decodeErr, &alertLevel, &alertDesc);

#if defined(USE_HARDWARE_CRYPTO_RECORD) || defined(USE_HARDWARE_CRYPTO_PKA) || defined(USE_EXT_CLIENT_CERT_KEY_LOADING)
    if (decodeRet == PS_PENDING || decodeRet == PS_EAGAIN)
    {
        return decodeRet;
    }
HW_ASYNC_RESUME:
#endif
/*
    Convenience for the cases that expect buf to have moved
        - calculate the number of encoded bytes that were decoded
 */
    processed = buf - prevBuf;
    rc = PS_PROTOCOL_FAIL;
    switch (decodeRet)
    {

    case MATRIXSSL_SUCCESS:

        ssl->inlen -= processed;
        if (ssl->inlen > 0)
        {
            psAssert(buf > ssl->inbuf);
/*
            Pack ssl->inbuf so there is immediate maximum room for potential
            outgoing data that needs to be written
 */
            memmove(ssl->inbuf, buf, ssl->inlen);
            buf = ssl->inbuf;
            goto DECODE_MORE;   /* More data in buffer to process */
        }
/*
        In this case, we've parsed a finished message and no additional data is
        available to parse. We let the client know the handshake is complete,
        which can be used as a trigger to begin for example a HTTP request.
 */
        if (!(ssl->bFlags & BFLAG_HS_COMPLETE))
        {
            if (matrixSslHandshakeIsComplete(ssl))
            {
                ssl->bFlags |= BFLAG_HS_COMPLETE;
#ifdef USE_CLIENT_SIDE_SSL
                matrixSslGetSessionId(ssl, ssl->sid);
#endif          /* USE_CLIENT_SIDE_SSL */
                rc = MATRIXSSL_HANDSHAKE_COMPLETE;
            }
            else
            {
                rc = MATRIXSSL_REQUEST_RECV; /* Need to recv more handshake data */
            }
        }
        else
        {
#ifdef USE_DTLS
            rc = MATRIXSSL_REQUEST_RECV; /* Got FINISHED without CCS */
#else
            /* This is an error - we shouldn't get here */
#endif
        }
        break;

#ifdef USE_DTLS
    case DTLS_RETRANSMIT:
        /* Only request a resend if last record in buffer */
        ssl->inlen -= processed;
        if (ssl->inlen > 0)
        {
            psAssert(buf > ssl->inbuf);
/*
            Pack ssl->inbuf so there is immediate maximum room for potential
            outgoing data that needs to be written
 */
            memmove(ssl->inbuf, buf, ssl->inlen);
            buf = ssl->inbuf;
            goto DECODE_MORE;   /* More data in buffer to process */
        }

        /* Flight will be rebuilt when matrixDtlsGetOutdata is called while
           outbuf is empty.  This is the return case where we are actually
           seeing a repeat handshake message so we know something was lost in
           flight. */
        return MATRIXSSL_REQUEST_SEND;
#endif

    case SSL_SEND_RESPONSE:
#ifdef ENABLE_FALSE_START
        /*
            If FALSE START is supported, there may be APPLICATION_DATA directly
            following the FINISHED message, even though we haven't sent our
            CHANGE_CIPHER_SPEC or FINISHED message. This is signalled by buf
            having been moved forward, and our response being put directly into
            ssl->outbuf, rather than in buf (ssl->inbuf). Return a REQUEST_SEND
            so that the data in outbuf is flushed before the remaining data in
            ssl->inbuf is parsed.
         */
        if ((ssl->flags & SSL_FLAGS_FALSE_START) && buf != prevBuf)
        {
            ssl->inlen -= processed;
            psAssert(ssl->inlen > 0);
            psAssert((uint32) ssl->inlen == start);
            psAssert(buf > ssl->inbuf);
            memmove(ssl->inbuf, buf, ssl->inlen);   /* Pack ssl->inbuf */
            buf = ssl->inbuf;
            return MATRIXSSL_REQUEST_SEND;
        }
#endif
        /*
            This must be handshake data (or alert) or we'd be in PROCESS_DATA
            so there is no way there is anything left inside inbuf to process.
            ...so processed isn't valid because the output params are outbuf
            related and we simply reset inlen
         */
        ssl->inlen = 0;

        /* If alert, close connection after sending */
        if (alertDesc != SSL_ALERT_NONE)
        {
            ssl->bFlags |= BFLAG_CLOSE_AFTER_SENT;
        }
        psAssert(prevBuf == buf);
        psAssert(ssl->insize >= (int32) len);
        psAssert(start == 0);
        psAssert(buf == ssl->inbuf);
        if (ssl->outlen > 0)
        {
            /* If data's in outbuf, append inbuf.  This is a corner case that
                can happen if application data is queued but then incoming data
                is processed and discovered to be a re-handshake request.
                matrixSslDecode will have constructed the response flight but
                we don't want to forget about the app data we haven't sent */
            if (ssl->outlen + (int32) len > ssl->outsize)
            {
                if ((p = psRealloc(ssl->outbuf, ssl->outlen + len,
                         ssl->bufferPool)) == NULL)
                {
                    return PS_MEM_FAIL;
                }
                ssl->outbuf = p;
                ssl->outsize = ssl->outlen + len;
            }
            memcpy(ssl->outbuf + ssl->outlen, ssl->inbuf, len);
            ssl->outlen += len;
        }
        else     /* otherwise, swap inbuf and outbuf */
        {
            buf = ssl->outbuf; ssl->outbuf = ssl->inbuf; ssl->inbuf = buf;
            ssl->outlen = len;
            len = ssl->outsize; ssl->outsize = ssl->insize; ssl->insize = len;
            buf = ssl->inbuf;
            len = ssl->outlen;
        }
        rc = MATRIXSSL_REQUEST_SEND;    /* We queued data to send out */
        break;

    case MATRIXSSL_ERROR:
        if (decodeErr >= 0)
        {
            /* printf("THIS SHOULD BE A NEGATIVE VALUE?\n"); */
        }
        return decodeErr; /* Will be a negative value */

    case SSL_ALERT:
        if (alertLevel == SSL_ALERT_LEVEL_FATAL)
        {
            psTraceIntInfo("Received FATAL alert %d.\n", alertDesc);
        }
        else
        {
            /* Closure notify is the normal case */
            if (alertDesc == SSL_ALERT_CLOSE_NOTIFY)
            {
                psTraceInfo("Normal SSL closure alert\n");
            }
            else
            {
                psTraceIntInfo("Received WARNING alert %d\n", alertDesc);
            }
        }
        /* Let caller access the 2 data bytes (severity and description) */
# ifdef USE_TLS_1_1
        /* Been ignoring the explicit IV up to this final return point. */
        if ((ssl->flags & SSL_FLAGS_READ_SECURE) &&
            (ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->enBlockSize > 1))
        {
            prevBuf += ssl->enBlockSize;
        }
# endif /* USE_TLS_1_1 */
        psAssert(len == 2);
        *ptbuf = prevBuf;
        *ptlen = len;
        ssl->inlen -= processed;
        return MATRIXSSL_RECEIVED_ALERT;

    case SSL_PARTIAL:
        if (reqLen > SSL_MAX_BUF_SIZE)
        {
            return PS_MEM_FAIL;
        }
        if (reqLen > (uint32) ssl->insize)
        {
            if ((p = psRealloc(ssl->inbuf, reqLen, ssl->bufferPool)) == NULL)
            {
                return PS_MEM_FAIL;
            }
            ssl->inbuf = p;
            ssl->insize = reqLen;
            buf = ssl->inbuf;
            /* Don't need to change inlen */
        }

        rc = MATRIXSSL_REQUEST_RECV;    /* Expecting more data */
        break;

    /* We've got outgoing data that's larger than our buffer */
    case SSL_FULL:
        if (reqLen > SSL_MAX_BUF_SIZE)
        {
            return PS_MEM_FAIL;
        }
        /* We balk if we get a large handshake message */
        if (reqLen > SSL_MAX_PLAINTEXT_LEN &&
            !matrixSslHandshakeIsComplete(ssl))
        {
            if (reqLen > SSL_MAX_PLAINTEXT_LEN)
            {
                return PS_MEM_FAIL;
            }
        }
        /*
            Can't envision any possible case where there is remaining data
            in inbuf to process and are getting SSL_FULL.
         */
        ssl->inlen = 0;

        /* Grow inbuf */
        if (reqLen > (uint32) ssl->insize)
        {
            len = ssl->inbuf - buf;
            if ((p = psRealloc(ssl->inbuf, reqLen, ssl->bufferPool)) == NULL)
            {
                return PS_MEM_FAIL;
            }
            ssl->inbuf = p;
            ssl->insize = reqLen;
            buf = ssl->inbuf + len;
            /* Note we leave inlen untouched here */
        }
        else
        {
            psTraceInfo("Encoding error. Possible wrong flight messagSize\n");
            return PS_PROTOCOL_FAIL;    /* error in our encoding */
        }
        goto DECODE_MORE;

    case SSL_PROCESS_DATA:
/*
        Possible we received a finished message and app data in the same
        flight. In this case, the caller is not notified that the handshake
        is complete, but rather is notified that there is application data to
        process.
 */
        if (!(ssl->bFlags & BFLAG_HS_COMPLETE) &&
            matrixSslHandshakeIsComplete(ssl))
        {
            ssl->bFlags |= BFLAG_HS_COMPLETE;
#ifdef USE_CLIENT_SIDE_SSL
            matrixSslGetSessionId(ssl, ssl->sid);
#endif      /* USE_CLIENT_SIDE_SSL */
        }
/*
         .      prevbuf points to start of unencrypted data
         .      buf points to start of any remaining unencrypted data
         .      start is length of remaining encrypted data yet to decode
         .      len is length of unencrypted data ready for user processing
 */
        ssl->inlen -= processed;
        psAssert((uint32) ssl->inlen == start);

        /* Call user plaintext data handler */
#ifdef USE_TLS_1_1
        /* Been ignoring the explicit IV up to this final return point. */
        /* NOTE: This test has been on enBlockSize for a very long time but
            it looks like it should be on deBlockSize since this a decryption.
            Changed and added an assert to see if these ever don't match */
        psAssert(ssl->enBlockSize == ssl->deBlockSize);
        if ((ssl->flags & SSL_FLAGS_READ_SECURE) &&
            (ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->deBlockSize > 1))
        {
            len -= ssl->deBlockSize;
            prevBuf += ssl->deBlockSize;
        }
        /* END enBlockSize to deBlockSize change */
#endif  /* USE_TLS_1_1 */
        *ptbuf = prevBuf;
        *ptlen = len;
#ifdef USE_DTLS
/*
        This flag is used in conjuction with flightDone in the buffer
        management API set to determine whether we are still in a handshake
        state for attempting flight resends. If we are getting app data we
        know for certain we are out of the hs states. Testing HandshakeComplete
        is not enough because you never know if the other side got FINISHED.
 */
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            ssl->appDataExch = 1;
        }
#endif
#ifdef USE_ZLIB_COMPRESSION
        if (ssl->compression > 0)
        {
            return MATRIXSSL_APP_DATA_COMPRESSED;
        }
#endif
        return MATRIXSSL_APP_DATA;
    } /* switch decodeRet */

    if (ssl->inlen > 0 && (buf != ssl->inbuf))
    {
        psAssert(0);
    }
/*
    Shrink inbuf to default size once inlen < default size, and we aren't
    expecting any more data in the buffer. If SSL_PARTIAL, don't shrink the
    buffer, since we expect to fill it up shortly.
 */
    if (decodeRet != SSL_PARTIAL)
    {
        revertToDefaultBufsize(ssl, SSL_INBUF);
    }

    return rc;
}

/******************************************************************************/
/*
    Plaintext data has been processed as a response to MATRIXSSL_APP_DATA or
    MATRIXSSL_RECEIVED_ALERT return codes from matrixSslReceivedData()
    Return:
        < 0 on error
        0 if there is no more incoming ssl data in the buffer
            Caller should take whatever action is appropriate to the specific
            protocol implementation, eg. read for more data, close, etc.
        > 0 error code is same meaning as from matrixSslReceivedData()
            In this case, ptbuf and ptlen will be modified and caller should
            handle return code identically as from matrixSslReceivedData()
            This is the case when more than one SSL record is in the buffer
 */
int32 matrixSslProcessedData(ssl_t *ssl, unsigned char **ptbuf, uint32 *ptlen)
{
    uint32 ctlen;

    if (!ssl || !ptbuf || !ptlen)
    {
        return PS_ARG_FAIL;
    }
    *ptbuf = NULL;
    *ptlen = 0;

    psAssert(ssl->insize > 0 && ssl->inbuf != NULL);
    /* Move any remaining data to the beginning of the buffer */
    if (ssl->inlen > 0)
    {
        ctlen = ssl->rec.len + ssl->recordHeadLen;
        if (ssl->flags & SSL_FLAGS_AEAD_R)
        {
            /* This overhead was removed from rec.len after the decryption
                to keep buffer logic working. */
            ctlen += AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl);
        }
        memmove(ssl->inbuf, ssl->inbuf + ctlen, ssl->inlen);
    }
    /* Shrink inbuf to default size once inlen < default size */
    revertToDefaultBufsize(ssl, SSL_INBUF);

    /* If there's more data, try to decode it here and return that code */
    if (ssl->inlen > 0)
    {
        /* NOTE: ReceivedData cannot return 0 */
        return matrixSslReceivedData(ssl, 0, ptbuf, ptlen);
    }
    return MATRIXSSL_SUCCESS;
}


/******************************************************************************/
/*
    Returns < 0 on error
 */
int32 matrixSslEncodeClosureAlert(ssl_t *ssl)
{
    sslBuf_t sbuf;
    int32 rc;
    uint32 reqLen, newLen;

    unsigned char *p;

    if (!ssl)
    {
        return PS_ARG_FAIL;
    }
    psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);
/*
    Only encode the closure alert if we aren't already flagged for close
    If we are flagged, we do not want to send any more data
 */
    newLen = 0;
    if (!(ssl->bFlags & BFLAG_CLOSE_AFTER_SENT))
    {
        ssl->bFlags |= BFLAG_CLOSE_AFTER_SENT;
L_CLOSUREALERT:
        sbuf.buf = sbuf.start = sbuf.end = ssl->outbuf + ssl->outlen;
        sbuf.size = ssl->outsize - ssl->outlen;
        rc = sslEncodeClosureAlert(ssl, &sbuf, &reqLen);
        if (rc == SSL_FULL && newLen == 0)
        {
            newLen = ssl->outlen + reqLen;
            if ((p = psRealloc(ssl->outbuf, newLen, ssl->bufferPool)) == NULL)
            {
                return PS_MEM_FAIL;
            }
            ssl->outbuf = p;
            ssl->outsize = newLen;
            goto L_CLOSUREALERT; /* Try one more time */
        }
        else if (rc != PS_SUCCESS)
        {
            return rc;
        }
        ssl->outlen += sbuf.end - sbuf.start;
    }
    return MATRIXSSL_SUCCESS;
}

# ifdef SSL_REHANDSHAKES_ENABLED
/******************************************************************************/
/*
    Encode a CLIENT_HELLO or HELLO_REQUEST to re-handshake an existing
    connection.

    Can't "downgrade" the re-handshake.  This means if keys or certCb are
    NULL we stick with whatever the session already has loaded.

    keys should be NULL if no change in key material is being made

    cipherSpec is only used by clients
 */
int32_t matrixSslEncodeRehandshake(ssl_t *ssl, sslKeys_t *keys,
    int32 (*certCb)(ssl_t *ssl, psX509Cert_t *cert, int32 alert),
    uint32 sessionOption,
    const psCipher16_t cipherSpec[], uint8_t cipherSpecLen)
{
    sslBuf_t sbuf;
    int32 rc, i;
    uint32 reqLen, newLen;

    unsigned char *p;
    sslSessOpts_t options;

    /* Clear extFlags for rehandshakes */
    ssl->extFlags.truncated_hmac = 0;
    ssl->extFlags.sni = 0;

    if (!ssl)
    {
        return PS_ARG_FAIL;
    }
    if (cipherSpecLen > 0 && (cipherSpec == NULL || cipherSpec[0] == 0))
    {
        return PS_ARG_FAIL;
    }
    if (ssl->bFlags & BFLAG_CLOSE_AFTER_SENT)
    {
        return PS_PROTOCOL_FAIL;
    }
    psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);

#  ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
#  endif  /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */

#  ifdef USE_ZLIB_COMPRESSION
    /* Re-handshakes are not currently supported for compressed sessions. */
    if (ssl->compression > 0)
    {
        psTraceInfo("Re-handshakes not supported for compressed sessions\n");
        return PS_UNSUPPORTED_FAIL;
    }
#  endif
/*
    The only explicit option that can be passsed in is
    SSL_OPTION_FULL_HANDSHAKE to indicate no resumption is allowed
 */
    if (sessionOption == SSL_OPTION_FULL_HANDSHAKE)
    {
        matrixSslSetSessionOption(ssl, sessionOption, NULL);
    }
/*
    If the key material or cert callback are provided we have to assume it
    was intentional to "upgrade" the re-handshake and we force full handshake
    No big overhead calling SetSessionOption with FULL_HS multiple times.
 */
    if (keys != NULL)
    {
        ssl->keys = keys;
        matrixSslSetSessionOption(ssl, SSL_OPTION_FULL_HANDSHAKE, NULL);
    }

#  ifndef USE_ONLY_PSK_CIPHER_SUITE
    if (certCb != NULL)
    {
        matrixSslSetSessionOption(ssl, SSL_OPTION_FULL_HANDSHAKE, NULL);
#   if defined(USE_CLIENT_AUTH) || defined(USE_CLIENT_SIDE_SSL)
        matrixSslSetCertValidator(ssl, certCb);
#   endif /* USE_CLIENT_AUTH || USE_CLIENT_SIDE_SSL */
#   if defined(USE_CLIENT_AUTH) && defined(USE_SERVER_SIDE_SSL)
/*
        If server, a certCb is an explicit flag to set client auth just as
        it is in matrixSslNewServerSession
 */
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            matrixSslSetSessionOption(ssl, SSL_OPTION_ENABLE_CLIENT_AUTH, NULL);
        }
#   endif /* USE_CLIENT_AUTH && USE_SERVER_SIDE_SSL */
    }
#  endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

/*
    If cipher spec is explicitly different from current, force a full handshake
 */
    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
        rc = 0;
        if (cipherSpecLen > 0)
        {
            rc = 1;
            for (i = 0; i < cipherSpecLen; i++)
            {
                if (cipherSpec[i] == ssl->cipher->ident)
                {
                    rc = 0;
                }
            }
        }
        if (rc)
        {
            matrixSslSetSessionOption(ssl, SSL_OPTION_FULL_HANDSHAKE, NULL);
        }
    }
#  ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        /* Resend epoch should be brought up-to-date with new epoch */
        ssl->resendEpoch[0] = ssl->epoch[0];
        ssl->resendEpoch[1] = ssl->epoch[1];

        ssl->msn = ssl->resendMsn = 0;
    }
#  endif /* USE_DTLS */
/*
    Options are set.  Encode the HELLO message
 */
    newLen = 0;
L_REHANDSHAKE:
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        sbuf.buf = sbuf.start = sbuf.end = ssl->outbuf + ssl->outlen;
        sbuf.size = ssl->outsize - ssl->outlen;
        if ((rc = matrixSslEncodeHelloRequest(ssl, &sbuf, &reqLen)) < 0)
        {
            if (rc == SSL_FULL && newLen == 0)
            {
                newLen = ssl->outlen + reqLen;
                if (newLen < SSL_MAX_BUF_SIZE)
                {
                    if ((p = psRealloc(ssl->outbuf, newLen, ssl->bufferPool))
                        == NULL)
                    {
                        return PS_MEM_FAIL;
                    }
                    ssl->outbuf = p;
                    ssl->outsize = newLen;
                    goto L_REHANDSHAKE;
                }
            }
            return rc;
        }
    }
    else
    {
        sbuf.buf = sbuf.start = sbuf.end = ssl->outbuf + ssl->outlen;
        sbuf.size = ssl->outsize - ssl->outlen;
        memset(&options, 0x0, sizeof(sslSessOpts_t));
#  ifdef USE_ECC_CIPHER_SUITE
        options.ecFlags = ssl->ecInfo.ecFlags;
#  endif
        /* Use extended master secret if original connection used it */
        if (ssl->extFlags.extended_master_secret == 1)
        {
            options.extendedMasterSecret = 1;
            ssl->extFlags.extended_master_secret = 0;
        }
        else
        {
            options.extendedMasterSecret = -1;
        }

        if ((rc = matrixSslEncodeClientHello(ssl, &sbuf, cipherSpec,
                 cipherSpecLen, &reqLen, NULL, &options)) < 0)
        {
            if (rc == SSL_FULL && newLen == 0)
            {
                newLen = ssl->outlen + reqLen;
                if (newLen < SSL_MAX_BUF_SIZE)
                {
                    if ((p = psRealloc(ssl->outbuf, newLen, ssl->bufferPool))
                        == NULL)
                    {
                        return PS_MEM_FAIL;
                    }
                    ssl->outbuf = p;
                    ssl->outsize = newLen;
                    goto L_REHANDSHAKE;
                }
            }
            return rc;
        }
    }
    ssl->outlen += sbuf.end - sbuf.start;
    return MATRIXSSL_SUCCESS;
}

/* Disabling and re-enabling of re-handshakes is a receive feature.  In other
    words, a NO_RENEGOTIATION alert will be sent if a request is sent from the
    peer. */
int32 matrixSslDisableRehandshakes(ssl_t *ssl)
{
    if (ssl == NULL)
    {
        return PS_ARG_FAIL;
    }
    matrixSslSetSessionOption(ssl, SSL_OPTION_DISABLE_REHANDSHAKES, NULL);
    return PS_SUCCESS;
}

int32 matrixSslReEnableRehandshakes(ssl_t *ssl)
{
    if (ssl == NULL)
    {
        return PS_ARG_FAIL;
    }
    matrixSslSetSessionOption(ssl, SSL_OPTION_REENABLE_REHANDSHAKES, NULL);
    return PS_SUCCESS;
}

/* Undocumented helper functions to manage rehandshake credits for testing */
int32 matrixSslGetRehandshakeCredits(ssl_t *ssl)
{
    if (ssl)
    {
        return ssl->rehandshakeCount;
    }
    return -1;
}

void matrixSslAddRehandshakeCredits(ssl_t *ssl, int32 credits)
{
    if (ssl)
    {
        /* User must re-enable rehandshaking before adding credits */
        if (ssl->rehandshakeCount >= 0)
        {
            if ((ssl->rehandshakeCount + credits) < 0x8000)
            {
                ssl->rehandshakeCount += credits;
            }
        }
    }
}

# else /* !SSL_REHANDSHAKES_ENABLED */
int32_t matrixSslEncodeRehandshake(ssl_t *ssl, sslKeys_t *keys,
    int32 (*certCb)(ssl_t *ssl, psX509Cert_t *cert, int32 alert),
    uint32_t sessionOption,
    const psCipher16_t cipherSpec[], uint8_t cipherSpecLen)
{
    psTraceInfo("Rehandshaking is disabled.  matrixSslEncodeRehandshake off\n");
    return PS_FAILURE;
}
int32 matrixSslDisableRehandshakes(ssl_t *ssl)
{
    psTraceInfo("Rehandshaking is not compiled into library at all.\n");
    return PS_FAILURE;
}

int32 matrixSslReEnableRehandshakes(ssl_t *ssl)
{
    psTraceInfo("Rehandshaking is not compiled into library at all.\n");
    return PS_FAILURE;
}
# endif /* SSL_REHANDSHAKES_ENABLED */

/******************************************************************************/
/*
    Caller is indicating 'bytes' of data was written
 */
int32 matrixSslSentData(ssl_t *ssl, uint32 bytes)
{
    int32 rc;

    if (!ssl)
    {
        return PS_ARG_FAIL;
    }
    if (bytes == 0)
    {
        if (ssl->outlen > 0)
        {
            return MATRIXSSL_REQUEST_SEND;
        }
        else
        {
            return MATRIXSSL_SUCCESS;   /* Nothing to do */
        }
    }
    psAssert(ssl->outsize > 0 && ssl->outbuf != NULL);
    ssl->outlen -= bytes;

    rc = MATRIXSSL_SUCCESS;
    if (ssl->outlen > 0)
    {
        memmove(ssl->outbuf, ssl->outbuf + bytes, ssl->outlen);
        /* This was changed during 3.7.1 DTLS work.  The line below used to be:
            rc = MATRIXSSL_REQUEST_SEND; and it was possible for it to be
            overridden with HANDSHAKE_COMPLETE below.  This was a problem
            if only the ChangeCipherSpec portion of the final flight was
            just set becuase matrixSslHandshakeIsComplete would return 1
            because the state looks right. However, there would still be a
            FINISHED message sitting in outbuf when COMPLETE is returned.

            This seemed like a bigger problem than just the DTLS test case
            that caught it.  If the transport layer of straight TLS sent off
            only the CCS message for some reason, this would cause the same
            odd combo of COMPLETE but with a FINISHED message that hasn't
            been sent.

            It seems fine to return REQUEST_SEND whenever there is data left
            in the outgoing buffer but it is suspecious it wasn't written
            this way to begin with so maybe there was another corner case
            the COMPLETE was solving.  Hope not.

            In any case, it looks safe to make this a global change but if you
            are reading this because you are trying to track down a change in
            behavior in matrixSslSentData, maybe this documentation will help.
         */
        return MATRIXSSL_REQUEST_SEND;
    }
    /*  If there's nothing left to flush, reallocate the buffer smaller. */
    if ((ssl->outlen == 0) && (ssl->bFlags & BFLAG_CLOSE_AFTER_SENT))
    {
        /* We want to close the connection now */
        rc = MATRIXSSL_REQUEST_CLOSE;
    }
    else
    {
        revertToDefaultBufsize(ssl, SSL_OUTBUF);
    }
    /* Indicate the handshake is complete, in this case, the finished message
        is being/has been just sent. Occurs in session resumption. */
    if (!(ssl->bFlags & BFLAG_HS_COMPLETE) &&
        matrixSslHandshakeIsComplete(ssl))
    {
        ssl->bFlags |= BFLAG_HS_COMPLETE;
# ifdef USE_CLIENT_SIDE_SSL
        matrixSslGetSessionId(ssl, ssl->sid);
# endif /* USE_CLIENT_SIDE_SSL */
        rc = MATRIXSSL_HANDSHAKE_COMPLETE;
# ifdef USE_SSL_INFORMATIONAL_TRACE
        /* Client side resumed completion or server standard completion */
        matrixSslPrintHSDetails(ssl);
# endif
    }
    return rc;
}

# ifdef USE_ZLIB_COMPRESSION
int32 matrixSslIsSessionCompressionOn(ssl_t *ssl)
{
    if (ssl->compression > 0)
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}
# endif

/******************************************************************************/

