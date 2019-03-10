/**
 *      @file    sslEncode.c
 *      @version $Format:%h%d$
 *
 *      Secure Sockets Layer protocol message encoding portion of MatrixSSL.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
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

# ifdef USE_IDENTITY_CERTIFICATES
static int32 writeCertificate(ssl_t *ssl, sslBuf_t *out, int32 notEmpty);
#  if defined(USE_OCSP_RESPONSE) && defined(USE_SERVER_SIDE_SSL)
static int32 writeCertificateStatus(ssl_t *ssl, sslBuf_t *out);
#  endif
# endif

static int32 writeChangeCipherSpec(ssl_t *ssl, sslBuf_t *out);
static int32 writeFinished(ssl_t *ssl, sslBuf_t *out);
static int32 writeAlert(ssl_t *ssl, unsigned char level,
                        unsigned char description, sslBuf_t *out, uint32 *requiredLen);
int32_t writeRecordHeader(ssl_t *ssl, uint8_t type, uint8_t hsType,
        psSize_t *messageSize, uint8_t *padLen,
        unsigned char **encryptStart,
        const unsigned char *end, unsigned char **c);
# ifdef USE_DTLS
#  ifdef USE_SERVER_SIDE_SSL
static int32 writeHelloVerifyRequest(ssl_t *ssl, sslBuf_t *out);
#  endif
# endif /* USE_DTLS */

int32 encryptRecord(ssl_t *ssl, int32 type, int32 hsMsgType,
        int32 messageSize,  int32 padLen, unsigned char *pt,
        sslBuf_t *out, unsigned char **c);

# ifdef USE_CLIENT_SIDE_SSL
static int32 writeClientKeyExchange(ssl_t *ssl, sslBuf_t *out);
# endif /* USE_CLIENT_SIDE_SSL */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
static int32 writeCertificateRequest(ssl_t *ssl, sslBuf_t *out, int32 certLen,
                                     int32 certCount);
static int32 writeMultiRecordCertRequest(ssl_t *ssl, sslBuf_t *out,
                                         int32 certLen, int32 certCount, int32 sigHashLen);
#  endif
#  if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
static int32 writeCertificateVerify(ssl_t *ssl, sslBuf_t *out);
static int32 nowDoCvPka(ssl_t *ssl, psBuf_t *out);
#   ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
static int32_t handleAsyncCvSigOp(ssl_t *ssl, pkaAfter_t *pka, unsigned char *hash);
#   endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
#  endif
# endif   /* !USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_SERVER_SIDE_SSL
static int32 writeServerHello(ssl_t *ssl, sslBuf_t *out);
static int32 writeServerHelloDone(ssl_t *ssl, sslBuf_t *out);
#  ifdef USE_PSK_CIPHER_SUITE
static int32 writePskServerKeyExchange(ssl_t *ssl, sslBuf_t *out);
#  endif /* USE_PSK_CIPHER_SUITE */
#  ifdef USE_DHE_CIPHER_SUITE
static int32 writeServerKeyExchange(ssl_t *ssl, sslBuf_t *out, uint32 pLen,
                                    unsigned char *p, uint32 gLen, unsigned char *g);
#  endif /* USE_DHE_CIPHER_SUITE */
#  ifdef USE_STATELESS_SESSION_TICKETS /* Already inside a USE_SERVER_SIDE block */
static int32 writeNewSessionTicket(ssl_t *ssl, sslBuf_t *out);
#  endif
# endif /* USE_SERVER_SIDE_SSL */

static int32 secureWriteAdditions(ssl_t *ssl, int32 numRecs);
static int32 encryptFlight(ssl_t *ssl, unsigned char **end);

# ifdef USE_TLS_1_3
extern int32_t tls13EncodeResponse(ssl_t *ssl,
        psBuf_t *out,
        uint32 *requiredLen);
extern int32_t tls13EncryptMessage(ssl_t *ssl,
        flightEncode_t *msg,
        unsigned char **end);
# endif

# ifdef USE_ZLIB_COMPRESSION
#  define MAX_ZLIB_COMPRESSED_OH  128/* Only FINISHED message supported */
# endif
/******************************************************************************/
/*
    This works for both in-situ and external buf

    buf         in      Start of allocated buffer (header bytes beyond are overwritten)
            out Start of encrypted data on function success

    size        in      Total size of the allocated buffer

    ptBuf       in      Pointer to front of the plain text data to be encrypted

    len         in      Length of incoming plain text
            out Length of encypted text on function success
            out Length of required 'size' on SSL_FULL
 */
int32 matrixSslEncode(ssl_t *ssl, unsigned char *buf, uint32 size,
    unsigned char *ptBuf, uint32 *len)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    int32_t rc;
    psBuf_t tmpout;

# ifdef USE_TLS_1_3
    if (USING_TLS_1_3(ssl))
    {
        return tls13EncodeAppData(ssl, buf, size, ptBuf, len);
    }
# endif

    /* If we've had a protocol error, don't allow further use of the session
        Also, don't allow a application data record to be encoded unless the
        handshake is complete.
     */
    if (ssl->flags & SSL_FLAGS_ERROR || ssl->hsState != SSL_HS_DONE ||
        ssl->flags & SSL_FLAGS_CLOSED)
    {
        psTraceInfo("Bad SSL state for matrixSslEncode call attempt: ");
        psTracePrintSslFlags(ssl->flags);
        psTracePrintHsState(ssl->hsState, PS_TRUE);
        return MATRIXSSL_ERROR;
    }

    c = buf;
    end = buf + size;

# ifdef USE_BEAST_WORKAROUND
    if (ssl->bFlags & BFLAG_STOP_BEAST)
    {
        messageSize = ssl->recordHeadLen + 1; /* single byte is the fix */
        if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
                 &messageSize, &padLen, &encryptStart, end, &c)) < 0)
        {
            if (rc == SSL_FULL)
            {
                *len = messageSize;
            }
            return rc;
        }
        psAssert(encryptStart == buf + ssl->recordHeadLen);
        c += 1;
        *len -= 1;

        tmpout.buf = tmpout.start = tmpout.end = buf;
        tmpout.size = size;
        if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
                 messageSize, padLen, ptBuf, &tmpout, &c)) < 0)
        {
            return rc;
        }
        ptBuf += 1;
        tmpout.end = tmpout.end + (c - buf);

    }
# endif
/*
    writeRecordHeader will determine SSL_FULL cases.  The expected
    messageSize to writeRecored header is the plain text length plus the
    record header length
 */
    messageSize = ssl->recordHeadLen + *len;

    if (messageSize > SSL_MAX_BUF_SIZE)
    {
        psTraceIntInfo("Message too large for matrixSslEncode: %d\n",
            messageSize);
        return PS_MEM_FAIL;
    }
    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
             &messageSize, &padLen, &encryptStart, end, &c)) < 0)
    {
        if (rc == SSL_FULL)
        {
            *len = messageSize;
        }
        return rc;
    }

    c += *len;
# ifdef USE_BEAST_WORKAROUND
    if (ssl->bFlags & BFLAG_STOP_BEAST)
    {
        /* The tmpout buf already contains the single byte record and has
            updated pointers for current location.  Disable at this time */
        ssl->bFlags &= ~BFLAG_STOP_BEAST;
    }
    else
    {
        tmpout.buf = tmpout.start = tmpout.end = buf;
        tmpout.size = size;
    }
# else
    tmpout.buf = tmpout.start = tmpout.end = buf;
    tmpout.size = size;
# endif

    if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
             messageSize, padLen, ptBuf, &tmpout, &c)) < 0)
    {
        return rc;
    }
    *len = (int32) (c - buf);

# ifdef SSL_REHANDSHAKES_ENABLED
    ssl->rehandshakeBytes += *len;
    if (ssl->rehandshakeBytes >= BYTES_BEFORE_RH_CREDIT)
    {
        if (ssl->rehandshakeCount < 0x8000)
        {
            /* Don't increment if disabled (-1) */
            if (ssl->rehandshakeCount >= 0)
            {
                ssl->rehandshakeCount++;
            }
        }
        ssl->rehandshakeBytes = 0;
    }
# endif /* SSL_REHANDSHAKES_ENABLED */
    return *len;
}

/******************************************************************************/
/*
    A helper function for matrixSslGetWritebuf to determine the correct
    destination size before allocating an output buffer.
 */
int32 matrixSslGetEncodedSize(ssl_t *ssl, uint32 len)
{
# ifdef USE_TLS_1_3
    uint32 ptLen = len;
# endif

    len += ssl->recordHeadLen;
    if (ssl->flags & SSL_FLAGS_WRITE_SECURE)
    {
        len += ssl->enMacSize;
# ifdef USE_TLS_1_1
/*
        If a block cipher is being used TLS 1.1 requires the use
        of an explicit IV.  This is an extra random block of data
        prepended to the plaintext before encryption.  Account for
        that extra length here.
 */
        if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
                ACTV_VER(ssl, v_tls_explicit_iv) && (ssl->enBlockSize > 1))
        {
            len += ssl->enBlockSize;
        }
        /* Add AEAD overhead. */
        if (ssl->flags & SSL_FLAGS_AEAD_W)
        {
            len += AEAD_TAG_LEN(ssl);

#  ifdef USE_TLS_1_3
            if (ACTV_VER(ssl, v_tls_1_3_any))
            {
                /* TLS 1.3 does not send any part of the nonce over the
                   wire, but requires one additional byte and possibly
                   room for the padding. */
                if (ssl->tls13BlockSize > 0)
                {
                    ssl->tls13PadLen = tls13GetPadLen(ssl, ptLen);
                }
                len += 1; /* InnerPlaintext.type */
                len += ssl->tls13PadLen; /* InnerPlaintext.zeros */
            }
            else
            {
                len += AEAD_NONCE_LEN(ssl);
            }
#   else
            len += AEAD_NONCE_LEN(ssl);
#   endif /* USE_TLS_1_3 */
        }
# endif /* USE_TLS_1_1 */

# ifdef USE_BEAST_WORKAROUND
        if (ssl->bFlags & BFLAG_STOP_BEAST)
        {
            /* Original message less one */
            len += psPadLenPwr2(len - 1 - ssl->recordHeadLen, ssl->enBlockSize);
            /* The single byte record overhead */
            len += ssl->recordHeadLen + ssl->enMacSize;
            len += psPadLenPwr2(1 + ssl->enMacSize, ssl->enBlockSize);
        }
        else
        {
            len += psPadLenPwr2(len - ssl->recordHeadLen, ssl->enBlockSize);
        }
# else
        len += psPadLenPwr2(len - ssl->recordHeadLen, ssl->enBlockSize);
# endif
    }
    return len;
}

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)

/* Second parameter includes handshake header length */
static int32 addCertFragOverhead(ssl_t *ssl, int32 totalCertLen)
{
    int32 oh = 0;

    /* For each additional record, we'll need a record header and
        secureWriteAdditions.  Borrowing ssl->fragIndex and ssl->fragTotal */
    ssl->fragTotal = totalCertLen;
    ssl->fragIndex = 0;
    while (ssl->fragTotal > 0)
    {
        if (ssl->fragIndex == 0)
        {
            /* First one is accounted for below as normal */
            ssl->fragTotal -= ssl->maxPtFrag;
            ssl->fragIndex++;
        }
        else
        {
            /* Remember this stage is simply for SSL_FULL test
               so just incr totalCertLen to add overhead */
            oh += secureWriteAdditions(ssl, 1);
            oh += ssl->recordHeadLen;
            if (ssl->fragTotal > (uint32) ssl->maxPtFrag)
            {
                ssl->fragTotal -= ssl->maxPtFrag;
            }
            else
            {
                ssl->fragTotal = 0;
            }
        }
    }
    return oh;
}

#   ifdef USE_ECC
/* ECDSA signature is two DER INTEGER values.  Either integer could result
    in the high bit being set which is interpreted as a negative number
    unless proceeded by a 0x0 byte.  MatrixSSL predicts one of the two will
    be negative when creating the empty buffer spot where the signature
    will be written.  If this guess isn't correct, this function is called
    to correct the buffer size */
int accountForEcdsaSizeChange(ssl_t *ssl,
        pkaAfter_t *pka,
        int real,
        unsigned char *sig,
        psBuf_t *out,
        int hsMsg)
{
    flightEncode_t *flightMsg;
    unsigned char *whereToMoveFrom, *whereToMoveTo, *msgLenLoc;
    int howMuchToMove, howFarToMove, msgLen, addOrSub;
    int sigSizeChange, newPadLen;

    if (real > pka->user)
    {
        /* ECDSA SIGNATURE IS LONGER THAN DEFAULT */
        addOrSub = 1;
        /* Push outbuf backwards */
        sigSizeChange = real - pka->user;
    }
    else
    {
        /* ECDSA SIGNATURE IS SHORTER THAN DEFAULT */
        addOrSub = 0;
        /* Pull outbuf forward */
        sigSizeChange = pka->user - real;
    }
#    ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        /* Needed somewhere to store the size change for DTLS retransmits */
        ssl->ecdsaSizeChange = real - pka->user;
    }
#    endif
    if (sigSizeChange > 12)
    {
        /* Sanity */
        psTraceIntInfo("ECDSA sig length change too big: %d\n", sigSizeChange);
        return MATRIXSSL_ERROR;
    }
    /* Get the flightEncode for this message early because the
        distance to shift things could depend on the padding bytes in
        addition to the basic ECDSA mismatch if we are rehandshaking */
    flightMsg = ssl->flightEncode;
    while (flightMsg != NULL && flightMsg->hsMsg != hsMsg)
    {
        flightMsg = flightMsg->next;
    }
    if (flightMsg == NULL)
    {
        return MATRIXSSL_ERROR;
    }

    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) && (ssl->enBlockSize > 1))
    {
        /* rehandshaking with block cipher */
        msgLen = (flightMsg->messageSize - ssl->recordHeadLen) -
                 flightMsg->padLen;
        if (addOrSub)
        {
            msgLen += sigSizeChange;
        }
        else
        {
            msgLen -= sigSizeChange;
        }
        newPadLen = psPadLenPwr2(msgLen, ssl->enBlockSize);
        flightMsg->padLen = newPadLen;
        msgLen += newPadLen + ssl->recordHeadLen;

        if (flightMsg->messageSize >= msgLen)
        {
            howFarToMove = flightMsg->messageSize - msgLen;
        }
        else
        {
            howFarToMove = msgLen - flightMsg->messageSize;
        }
    }
    else
    {
        howFarToMove = sigSizeChange;
    }

    howMuchToMove = out->end - (pka->outbuf + pka->user);
    psAssert(howMuchToMove > 0);
    whereToMoveFrom = pka->outbuf + pka->user;

    if (addOrSub)
    {
        whereToMoveTo = whereToMoveFrom + howFarToMove;
        /* enough room to push into? Extra two bytes should already
            have been accounted for but this is still nice for sanity */
        if (((out->start + out->size) - out->end) < howFarToMove)
        {
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        whereToMoveTo = whereToMoveFrom - howFarToMove;
    }
    Memmove(whereToMoveTo, whereToMoveFrom, howMuchToMove);
    if (addOrSub)
    {
        out->end += howFarToMove;
        flightMsg->len += sigSizeChange;
        flightMsg->messageSize += howFarToMove;
    }
    else
    {
        out->end -= howFarToMove;
        flightMsg->len -= sigSizeChange;
        flightMsg->messageSize -= howFarToMove;
    }
    /* Now put in ECDSA sig */
    Memcpy(pka->outbuf, sig, real);

    /* Now update the record message length - We can use the
        flightEncode entry to help us find the handshake header
        start. The record header len is only 2 bytes behind here...
        subtract nonce for AEAD */
    msgLenLoc = flightMsg->start - 2;
    msgLen = flightMsg->messageSize - ssl->recordHeadLen;

    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
        (ssl->flags & SSL_FLAGS_AEAD_W))
    {
        msgLenLoc -= AEAD_NONCE_LEN(ssl);
    }

    msgLenLoc[0] = msgLen >> 8;
    msgLenLoc[1] = msgLen;

    /* Now update the handshake header length with same techique. */
    msgLenLoc = flightMsg->start + 1; /* Skip hsType byte */
    msgLen = flightMsg->len - ssl->hshakeHeadLen;
#    ifdef USE_TLS_1_1
    /* Account for explicit IV in TLS_1_1 and above. */
    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
            ACTV_VER(ssl, v_tls_explicit_iv) && (ssl->enBlockSize > 1))
    {
        msgLen -= ssl->enBlockSize;
        msgLenLoc += ssl->enBlockSize;
    }
#    endif

#    ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        /* Will also be a fragment length to update in handshake header.
            Only supporting     if there is no fragmentation here.  The magic
            5 is skipping over the 3 byte length iteself, 2 byte sequence
            and 3 byte offset */
        if (Memcmp(msgLenLoc, msgLenLoc + 8, 3) != 0)
        {
            psTraceInfo("ERROR: ECDSA SKE DTLS fragmentation unsupported\n");
            return MATRIXSSL_ERROR;
        }
    }
#    endif

    msgLenLoc[0] = msgLen >> 16;
    msgLenLoc[1] = msgLen >> 8;
    msgLenLoc[2] = msgLen;

#    ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        /* Update the fragLen as well.  Sanity test was performed above */
        msgLenLoc[8] = msgLen >> 16;
        msgLenLoc[9] = msgLen >> 8;
        msgLenLoc[10] = msgLen;
    }
#    endif

    /* All messages that follow in the flight have to be updated now */
    flightMsg = flightMsg->next;
    while (flightMsg != NULL)
    {
        if (addOrSub)
        {
            flightMsg->start += howFarToMove;
            if (flightMsg->seqDelay)
            {
                flightMsg->seqDelay += howFarToMove;
            }
        }
        else
        {
            flightMsg->start -= howFarToMove;
            if (flightMsg->seqDelay)
            {
                flightMsg->seqDelay -= howFarToMove;
            }
        }
        if (flightMsg->hsMsg == SSL_HS_FINISHED)
        {
            /* The finished message has set aside a pointer as well */
            if (addOrSub)
            {
                ssl->delayHsHash += howFarToMove;
            }
            else
            {
                ssl->delayHsHash -= howFarToMove;
            }
        }
        flightMsg = flightMsg->next;
    }
    return PS_SUCCESS;
}
#    endif   /* USE_ECC */

#  endif  /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
# endif /* !USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_SERVER_SIDE_SSL
/* The ServerKeyExchange delayed PKA op */
static int32 nowDoSkePka(ssl_t *ssl, psBuf_t *out)
{
    int32_t rc = PS_SUCCESS;

#  ifndef USE_ONLY_PSK_CIPHER_SUITE
    pkaAfter_t *pka;
#   ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (ssl->retransmit)
        {
            /* Was already copied out in writeServerKeyExchange */
            /* Would not expect to see this because pkaAfter.type should
                never be set */
            return PS_SUCCESS;
        }
    }
#   endif /* USE_DTLS */

    /* Always first one.  clearPkaAfter will move 1 to 0 if needed */
    pka = &ssl->pkaAfter[0];
    rc = tlsMakeSkeSignature(ssl, pka, out);
#  endif /* USE_ONLY_PSK_CIPHER_SUITE */

    return rc;
}
# endif /* USE_SERVER_SIDE_SSL */

# ifdef USE_CLIENT_SIDE_SSL

psResSize_t calcCkeSize(ssl_t *ssl)
{
    psResSize_t ckeSize = 0;

    if ((ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) != 0)
    {
#   ifdef USE_DTLS
        if ((ACTV_VER(ssl, v_dtls_any)) && ssl->retransmit == 1)
        {
            return ssl->ckeSize; /* Keys have been freed - use cached. */
        }
#   endif /* USE_DTLS */

#   ifdef USE_ECC_CIPHER_SUITE
        if ((ssl->flags & SSL_FLAGS_ECC_CIPHER) != 0)
        {
            return (ssl->sec.eccKeyPriv->curve->size * 2) + 2;
        }
#   endif /* USE_ECC_CIPHER_SUITE */

#   ifdef REQUIRE_DH_PARAMS
        ckeSize += ssl->sec.dhKeyPriv->size;
#   endif /* REQUIRE_DH_PARAMS */

#   ifdef USE_PSK_CIPHER_SUITE
        /* This is the DHE_PSK suite case.  PSK suites add the key
           identity with psSize_t size */
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            ckeSize += (SSL_PSK_MAX_ID_SIZE + 2);
        }
#   endif /* USE_PSK_CIPHER_SUITE */
        return ckeSize;
    }

    if ((ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) == 0)
    {
#  ifdef USE_PSK_CIPHER_SUITE
        /* This is the basic PSK case. PSK suites add the key identity
           with psSize_t size */
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            ckeSize += SSL_PSK_MAX_ID_SIZE + 2;
        }
#  endif /* USE_PSK_CIPHER_SUITE */

#  ifndef USE_ONLY_PSK_CIPHER_SUITE
#   ifdef USE_ECC_CIPHER_SUITE
        if (ssl->cipher->type == CS_ECDH_ECDSA || ssl->cipher->type == CS_ECDH_RSA)
        {
            ckeSize = (ssl->sec.cert->publicKey.key.ecc.curve->size * 2) + 2;
        }
#   endif /* USE_ECC_CIPHER_SUITE */
        if (ckeSize == 0)
        {
            /* Normal RSA auth cipher suite case */
            if (ssl->sec.cert == NULL)
            {
                return MATRIXSSL_ERROR;
            }
            ckeSize = ssl->sec.cert->publicKey.keysize;
        }
#  endif /* USE_ONLY_PSK_CIPHER_SUITE */
        return ckeSize;
    }
    return MATRIXSSL_ERROR;
}

            /*********/
/* A test feature to allow clients to reuse the CKE RSA encryption output
    for each connection to remove the CPU overhead of pubkey operation when
    testing against high performance servers. The same premaster must be
    used each time as well though. */
/* #define REUSE_CKE */
#  ifdef REUSE_CKE
#   pragma message("!! DO NOT USE REUSE_CKE IN PRODUCTION !!")
static char g_reusePremaster[SSL_HS_RSA_PREMASTER_SIZE] = { 0 };
static int16 g_reusePreLen = 0;
static char g_reuseRSAEncrypt[512] = { 0 }; /* Encrypted pre-master */
static int16 g_reuseRSALen = 0;
static psRsaKey_t g_reuseRSAKey;
#  endif
/*********/

/* The ClientKeyExchange delayed PKA ops */
static int32 nowDoCkePka(ssl_t *ssl)
{
    int32 rc = PS_FAIL;
    pkaAfter_t *pka;

#  ifdef REQUIRE_DH_PARAMS
    uint8_t cleared = 0;
#  endif

#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (ssl->retransmit)
        {
            /* Was already copied out in writeClientKeyExchange */
            /* In fact, would not expect to hit this because pkaAfter.type
                should never be set to re-enter this routine */
            psAssert(0);
            return PS_SUCCESS;
        }
    }
#  endif /* USE_DTLS */

    /* Always the first one.  clearPkaAfter will move 1 to 0 if needed */
    pka = &ssl->pkaAfter[0];

    /* The flags logic is used for the cipher type and then the pkaAfter.type
        value is validated */
#  ifdef USE_DHE_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {

#   ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            /* ECDHE suite */
            psAssert(pka->outbuf == ssl->sec.premaster);
            if (pka->type == PKA_AFTER_ECDH_SECRET_GEN)
            {
                if ((rc = psEccGenSharedSecret(ssl->sec.eccDhKeyPool,
                         ssl->sec.eccKeyPriv, ssl->sec.eccKeyPub,
                         ssl->sec.premaster, &ssl->sec.premasterSize,
                         pka->data)) < 0)
                {
                    if (rc != PS_PENDING)
                    {
                        psFree(ssl->sec.premaster, ssl->hsPool);
                        ssl->sec.premaster = NULL;
                        return MATRIXSSL_ERROR;
                    }
                    pka->type = PKA_AFTER_ECDH_SECRET_GEN_DONE; /* Bypass next*/
                    return rc;
                }
            }
            clearPkaAfter(ssl);
            psEccDeleteKey(&ssl->sec.eccKeyPub);
            psEccDeleteKey(&ssl->sec.eccKeyPriv);
        }
        else
        {
#   endif  /* USE_ECC_CIPHER_SUITE */

#   ifdef REQUIRE_DH_PARAMS

        psAssert(pka->outbuf == ssl->sec.premaster);
        psAssert(pka->type == PKA_AFTER_DH_KEY_GEN);

        if ((rc = psDhGenSharedSecret(ssl->sec.dhKeyPool,
                 ssl->sec.dhKeyPriv, ssl->sec.dhKeyPub,  ssl->sec.dhP,
                 ssl->sec.dhPLen, ssl->sec.premaster,
                 &ssl->sec.premasterSize, pka->data)) < 0)
        {

            if (rc != PS_PENDING)
            {
                return MATRIXSSL_ERROR;
            }
            return rc;
        }

#    ifdef USE_PSK_CIPHER_SUITE
        /* DHE PSK ciphers make dual use of the pkaAfter storage */
        if (!(ssl->flags & SSL_FLAGS_PSK_CIPHER))
        {
            if (cleared == 0)
            {
                clearPkaAfter(ssl); cleared = 1;
            }
        }
#    else
        if (cleared == 0)
        {
            clearPkaAfter(ssl); cleared = 1;
        }
#    endif

        psFree(ssl->sec.dhP, ssl->hsPool);
        ssl->sec.dhP = NULL; ssl->sec.dhPLen = 0;
        psDhClearKey(ssl->sec.dhKeyPub);
        psFree(ssl->sec.dhKeyPub, ssl->hsPool);
        ssl->sec.dhKeyPub = NULL;
        psDhClearKey(ssl->sec.dhKeyPriv);
        psFree(ssl->sec.dhKeyPriv, ssl->sec.dhKeyPool);
        ssl->sec.dhKeyPriv = NULL;

#    ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {

            unsigned char *pskKey;
            uint8_t pskIdLen;

            /* RFC4279: The premaster secret is formed as follows.
               First, perform the Diffie-Hellman computation in the same way
               as for other Diffie-Hellman-based ciphersuites.  Let Z be the
               value produced by this computation.  Concatenate a uint16
               containing the length of Z (in octets), Z itself, a uint16
               containing the length of the PSK (in octets), and the PSK itself.

                The pskId is held in the pkaAfter inbuf */
            rc = matrixSslPskGetKey(ssl, pka->inbuf, pka->inlen, &pskKey,
                &pskIdLen);
            if (rc < 0 || pskKey == NULL)
            {
                psFree(ssl->sec.premaster, ssl->hsPool);
                ssl->sec.premaster = NULL;
                return MATRIXSSL_ERROR;
            }
            /* Need to prepend a psSize_t length to the premaster key. */
            Memmove(&ssl->sec.premaster[2], ssl->sec.premaster,
                ssl->sec.premasterSize);
            ssl->sec.premaster[0] = (ssl->sec.premasterSize & 0xFF00) >> 8;
            ssl->sec.premaster[1] = (ssl->sec.premasterSize & 0xFF);
            /*  Next, uint8_t length of PSK and key itself */
            ssl->sec.premaster[ssl->sec.premasterSize + 2] = 0;
            ssl->sec.premaster[ssl->sec.premasterSize + 3] =
                (pskIdLen & 0xFF);
            Memcpy(&ssl->sec.premaster[ssl->sec.premasterSize + 4], pskKey,
                pskIdLen);
            /*  Lastly, adjust the premasterSize */
            ssl->sec.premasterSize += pskIdLen + 4;
        }
        if (cleared == 0)
        {
            clearPkaAfter(ssl); cleared = 1; /* Standard and PSK DHE */
        }
#    else
        if (cleared == 0)
        {
            clearPkaAfter(ssl); /* Standard DHE, PSK disabled*/
        }
#    endif                                   /* PSK */

#   endif                                    /* REQUIRE_DH_PARAMS       */

#   ifdef USE_ECC_CIPHER_SUITE
    }
#   endif  /* USE_ECC_CIPHER_SUITE */

    }
    else
    {
#  endif /* USE_DHE_CIPHER_SUITE */

    /* Else case for non-DHE, which still could mean ECDH static or
        standard RSA */
#  ifdef USE_ECC_CIPHER_SUITE
    if (ssl->cipher->type == CS_ECDH_ECDSA ||
        ssl->cipher->type == CS_ECDH_RSA)
    {

        /* This case is unique becuase it has two PKA ops for a single CKE
            message.  The key generation is done and then secret is
            generated.  The 'type' will change after the first one */

        if (pka->type == PKA_AFTER_ECDH_KEY_GEN)
        {
            if (psEccNewKey(pka->pool, &ssl->sec.eccKeyPriv,
                    ssl->sec.cert->publicKey.key.ecc.curve) < 0)
            {
                return PS_MEM_FAIL;
            }
            if ((rc = matrixSslGenEphemeralEcKey(ssl->keys,
                     ssl->sec.eccKeyPriv,
                     ssl->sec.cert->publicKey.key.ecc.curve,
                     pka->data)) < 0)
            {

                if (rc == PS_PENDING)
                {
                    return rc;
                }
                psEccDeleteKey(&ssl->sec.eccKeyPriv);
                psTraceInfo("GenEphemeralEcc failed\n");
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                return MATRIXSSL_ERROR;
            }

            /* key len must be valid */
            if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv,
                    pka->outbuf, &pka->user) < 0)
            {
                psTraceInfo("psEccX963ExportKey in CKE failed\n");
                return MATRIXSSL_ERROR;
            }
            /* Does written len equal stated len? */
            psAssert(pka->user == (int32) * (pka->outbuf - 1));

#   ifdef USE_DTLS
            /* Save aside for retransmits */
            if (ACTV_VER(ssl, v_dtls_any))
            {
                ssl->ckeSize = pka->user + 1;     /* The size is wrote first */
                ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize);
                if (ssl->ckeMsg == NULL)
                {
                    return SSL_MEM_ERROR;
                }
                ssl->ckeMsg[0] = pka->user & 0xFF;
                Memcpy(ssl->ckeMsg + 1, pka->outbuf, ssl->ckeSize - 1);
            }
#   endif          /* USE_DTLS */

            /* NOTE: Do not clearPkaAfter.  We will just use the current
                context since there is no special state data required
                for this next EccGenSharedSecret call.  We don't clear
                because the certificateVerify info might be     sitting in the
                second pkaAfter slot */
            /* Set for the next operation now using same pkaAfter slot */
            pka->type = PKA_AFTER_ECDH_SECRET_GEN;
        }

        /* Second PKA operation */
        if (pka->type == PKA_AFTER_ECDH_SECRET_GEN)
        {

            if ((rc = psEccGenSharedSecret(pka->pool,
                     ssl->sec.eccKeyPriv, &ssl->sec.cert->publicKey.key.ecc,
                     ssl->sec.premaster, &ssl->sec.premasterSize,
                     pka->data)) < 0)
            {
                if (rc == PS_PENDING)
                {
                    pka->type = PKA_AFTER_ECDH_SECRET_GEN_DONE;     /* Bypass */
                    return rc;
                }
                psFree(ssl->sec.premaster, ssl->hsPool);
                ssl->sec.premaster = NULL;
                return MATRIXSSL_ERROR;
            }
        }
        /* Successfully completed both PKA operations and key write */
        psEccDeleteKey(&ssl->sec.eccKeyPriv);
        clearPkaAfter(ssl);
    }
    else
    {
#  endif   /* USE_ECC_CIPHER_SUITE */

#  ifdef USE_RSA_CIPHER_SUITE
    /* Standard RSA suite entry point */
    psAssert(pka->type == PKA_AFTER_RSA_ENCRYPT);

#   ifdef REUSE_CKE
    if (g_reusePreLen)
    {
        if (psRsaCmpPubKey(&g_reuseRSAKey, &ssl->sec.cert->publicKey.key.rsa) == 0)
        {
            Memcpy(ssl->sec.premaster, g_reusePremaster, g_reusePreLen);
            Memcpy(pka->outbuf, g_reuseRSAEncrypt, g_reuseRSALen);
        }
        else
        {
            memzero_s(g_reusePremaster, g_reusePreLen);
            g_reusePreLen = 0;
            memzero_s(g_reuseRSAEncrypt, g_reuseRSALen);
            g_reuseRSALen = 0;
            psRsaClearKey(&g_reuseRSAKey);
        }
    }
    else
    {
#   endif
    /* pkaAfter.user is buffer len */
    if ((rc = psRsaEncryptPub(pka->pool,
             &ssl->sec.cert->publicKey.key.rsa,
             ssl->sec.premaster, ssl->sec.premasterSize, pka->outbuf,
             pka->user, pka->data)) < 0)
    {
        if (rc == PS_PENDING)
        {
            /* For these ClientKeyExchange paths, we do want to come
                back through nowDoCkePka for a double pass so each
                case can manage its own pkaAfter and to make sure
                psX509FreeCert and sslCreateKeys() are hit below. */
            return rc;
        }
        psTraceIntInfo("psRsaEncryptPub in CKE failed %d\n", rc);
        return MATRIXSSL_ERROR;
    }
#   ifdef REUSE_CKE
}
if (g_reusePreLen == 0)
{
    Printf("REUSE_CKE ENABLED!! NOT FOR PRODUCTION USE\n");
    g_reusePreLen = ssl->sec.premasterSize;
    g_reuseRSALen = psRsaSize(&ssl->sec.cert->publicKey.key.rsa);
    Memcpy(g_reusePremaster, ssl->sec.premaster,  g_reusePreLen);
    Memcpy(g_reuseRSAEncrypt, pka->outbuf, g_reuseRSALen);
    /* TODO this key is allocated once and leaked */
    if (psRsaCopyKey(&g_reuseRSAKey, &ssl->sec.cert->publicKey.key.rsa) < 0)
    {
        return MATRIXSSL_ERROR;
    }
}
#   endif
    /* RSA closed the pool on second pass */
    /* CHANGE NOTE: This comment looks specific to async and this
        pool is not being closed in clearPkaAfter if set to NULL here
        on the normal case.  So commenting this line out for now */
    /* pka->pool = NULL; */
#   ifdef USE_DTLS
    /* This was first pass for DH ckex so set it aside */

    if (ACTV_VER(ssl, v_dtls_any))
    {

        ssl->ckeMsg = psMalloc(ssl->hsPool, pka->user);
        if (ssl->ckeMsg == NULL)
        {
            return SSL_MEM_ERROR;
        }
        ssl->ckeSize = pka->user;
        Memcpy(ssl->ckeMsg, pka->outbuf, pka->user);
    }
#   endif      /* USE_DTLS */
    clearPkaAfter(ssl);
#  else /* RSA is the 'default' so if that didn't get hit there is a problem */
    psTraceInfo("There is no handler for writeClientKeyExchange.  ERROR\n");
    return MATRIXSSL_ERROR;
#  endif /* USE_RSA_CIPHER_SUITE */


#  ifdef USE_ECC_CIPHER_SUITE
}
#  endif   /* USE_ECC_CIPHER_SUITE */

#  ifdef USE_DHE_CIPHER_SUITE
}
#  endif /* USE_DHE_CIPHER_SUITE */

/*
    Now that we've got the premaster secret, derive the various symmetric
    keys using it and the client and server random values.

    However, if extended_master_secret is being used we must delay the
    master secret creation until the CKE handshake message has been added
    to the rolling handshake hash.  Key generation will be done in encryptRecord
 */
    if (ssl->extFlags.extended_master_secret == 0)
    {
        if ((rc = sslCreateKeys(ssl)) < 0)
        {
            return rc;
        }
    }

#  ifdef USE_DTLS
    /* Can't free cert in DTLS in case of retransmit */
    if (ACTV_VER(ssl, v_dtls_any))
    {
        return rc;
    }
#  endif

#  ifndef USE_ONLY_PSK_CIPHER_SUITE
    /* This used to be freed in writeFinished but had to stay around longer
        for key material in PKA after ops */
    if (!(ssl->bFlags & BFLAG_KEEP_PEER_CERTS))
    {
        if (ssl->sec.cert)
        {
            psX509FreeCert(ssl->sec.cert);
            ssl->sec.cert = NULL;
        }
    }
#  endif /* !USE_ONLY_PSK_CIPHER_SUITE */

    return rc;
}
# endif /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/
/*
    We indicate to the caller through return codes in sslDecode when we need
    to write internal data to the remote host.  The caller will call this
    function to generate a message appropriate to our state.
 */
int32 sslEncodeResponse(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen)
{
    int32 messageSize = 0;
    int32 rc = MATRIXSSL_ERROR;
    uint32 alertReqLen;

# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    int32 ncerts;
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
    psX509Cert_t *cert;
#  endif /* USE_ONLY_PSK_CIPHER_SUITE */
# endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

# if defined(USE_SERVER_SIDE_SSL)
    int32 extSize;
    int32 stotalCertLen;
    int32 srvKeyExLen;
# endif /* USE_SERVER_SIDE_SSL */

# ifdef USE_CLIENT_SIDE_SSL
    int32 ckeSize;
#  ifdef USE_CLIENT_AUTH
    int32 ctotalCertLen;
#  endif
# endif /* USE_CLIENT_SIDE_SSL */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
    psX509Cert_t *CAcert;
    int32 certCount = 0, certReqLen = 0, CAcertLen = 0;
#  endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */
# endif  /* USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_DTLS
    sslSessOpts_t options;
    Memset(&options, 0x0, sizeof(sslSessOpts_t));
# endif /* USE_DTLS */

    /*
      We may be trying to encode an alert response if there is an error marked
      on the connection.
    */
    if (ssl->err != SSL_ALERT_NONE)
    {
        rc = writeAlert(ssl, SSL_ALERT_LEVEL_FATAL, (unsigned char) ssl->err,
            out, requiredLen);
        if (rc == MATRIXSSL_ERROR)
        {
            /* We'll be returning an error code from this call so the typical
                alert SEND_RESPONSE handler will not be hit to set this error
                flag for us.  We do it ourself to prevent further session use
                and the result of this error will be that the connection is
                silently closed rather than this alert making it out */
            ssl->flags |= SSL_FLAGS_ERROR;
        }
# ifdef USE_SERVER_SIDE_SSL
/*
        Writing a fatal alert on this session.  Let's remove this client from
        the session table as a precaution.  Additionally, if this alert is
        happening mid-handshake the master secret might not even be valid
 */
#  ifdef SERVER_IGNORE_UNRECOGNIZED_SNI
        if (ssl->err == SSL_ALERT_NONE)
        {
            /* Warning level alert. Ignore. */
            goto ok;
        }
#  endif
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            matrixClearSession(ssl, 1);
        }
# endif /* USE_SERVER_SIDE_SSL */
        return rc;
    }

# ifdef SERVER_IGNORE_UNRECOGNIZED_SNI
ok:
# endif

# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    if (ssl->hwflags & SSL_HWFLAGS_PENDING_PKA_W &&
        ssl->extCvSigOpPending)
    {
        psAssert(ssl->extCvSigOpInUse);
        /* Case of delayed PKA operation in a flight WRITE */
        ssl->hwflags &= ~SSL_HWFLAGS_PENDING_PKA_W;
        goto resumeFlightEncryption;
    }
# endif

# ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        /*      This function takes care of writing out entire flights so we know
            to capture the current MSN and Epoch as the resends so that a
            resend of this flight will contain the identical MSN and Epoch
            for each resent message. */
        ssl->resendMsn = ssl->msn;
        ssl->resendEpoch[0] = ssl->epoch[0];
        ssl->resendEpoch[1] = ssl->epoch[1];
    }
# endif /* USE_DTLS */

#ifdef USE_TLS_1_3
    if (USING_TLS_1_3(ssl))
    {
        rc = tls13EncodeResponse(ssl, out, requiredLen);
        if (rc == SSL_FULL)
        {
            *requiredLen = tls13EstimateNextFlightSize(ssl);
            psTraceIntInfo("Need larger write buffer: %d\n", *requiredLen);
            /* Return to matrixSslReceivedData for buffer enlargement.
               Next time, we shall continue from where we left. */
            ssl->tls13NextMsgRequiredLen = 0;
            return SSL_FULL;
        }
        goto flightEncode;
    }
#endif /* USE_TLS_1_3 */

/*
    We encode a set of response messages based on our current state
    We have to pre-verify the size of the outgoing buffer against
    all the messages to make the routine transactional.  If the first
    write succeeds and the second fails because of size, we cannot
    rollback the state of the cipher and MAC.
 */
    switch (ssl->hsState)
    {
        /* If we're waiting for the ClientKeyExchange message, then we
           need to send the messages that would prompt that result on
           the client */

# ifdef USE_SERVER_SIDE_SSL
    case SSL_HS_CLIENT_KEY_EXCHANGE:

#  ifdef USE_CLIENT_AUTH
        /*
          This message is also suitable for the client authentication case
          where the server is in the CERTIFICATE state.
        */
    case SSL_HS_CERTIFICATE:
        /*
          Account for the certificateRequest message if client auth is on.
          First two bytes are the certificate_types member (rsa_sign (1) and
          ecdsa_sign (64) are supported).  Remainder of length is the list of
          BER encoded distinguished names this server is willing to accept
          children certificates of.  If there are no valid CAs to work with,
          client auth can't be done.
        */
#   ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
        {
            CAcert = ssl->keys->CAcerts;
            certCount = certReqLen = CAcertLen = 0;
#    ifdef USE_TLS_1_2
            if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
            {
                /* TLS 1.2 has a SigAndHashAlgorithm member in certRequest */
                certReqLen += 2;
#     ifdef USE_ECC
#      ifdef USE_SHA384
                certReqLen += 6;
#      else
                certReqLen += 4;
#      endif /* USE_SHA */
#     endif  /* USE_ECC */
#     ifdef USE_RSA
#      ifdef USE_SHA384
                certReqLen += 6;
#      else
                certReqLen += 4;
#      endif /* USE_SHA */
#     endif  /* USE_RSA */
            }
#    endif   /* USE_TLS_1_2 */

            if (CAcert)
            {
                certReqLen += 4 + ssl->recordHeadLen + ssl->hshakeHeadLen;
#    ifdef USE_ECC
                certReqLen += 1; /* Add on ECDSA_SIGN support */
#    endif /* USE_ECC */
                while (CAcert)
                {
                    if (CAcert->parseStatus == PS_X509_PARSE_SUCCESS)
                    {
                        certReqLen += 2; /* 2 bytes for specifying each cert len */
                        CAcertLen += CAcert->subject.dnencLen;
                        certCount++;
                    }
                    CAcert = CAcert->next;
                }
#    ifdef USE_DTLS
                /* if (ACTV_VER(ssl, v_dtls_any)) { */
                /*      if (certReqLen + CAcertLen > ssl->pmtu) { */
                /*              / * Decrease the CA count or contact support if a */
                /*                      needed requirement * / */
                /*              psTraceDtls("ERROR: No fragmentation support for "); */
                /*              psTraceDtls("CERTIFICATE_REQUEST message/n"); */
                /*              return MATRIXSSL_ERROR; */
                /*      } */
                /* } */
#    endif
            }
            else
            {
#    ifdef SERVER_CAN_SEND_EMPTY_CERT_REQUEST
                certReqLen += 4 + ssl->recordHeadLen + ssl->hshakeHeadLen;
#     ifdef USE_ECC
                certReqLen += 1; /* Add on ECDSA_SIGN support */
#     endif /* USE_ECC */
#    else
                psTraceInfo("No server CAs loaded for client authentication\n");
                return MATRIXSSL_ERROR;
#    endif
            }
        }
#   endif /* USE_ONLY_PSK_CIPHER_SUITE */
#  endif  /* USE_CLIENT_AUTH */

        srvKeyExLen = 0;

        if ((ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) != 0)
        {
#  ifdef USE_DHE_CIPHER_SUITE
            if (!(ssl->flags & SSL_FLAGS_ECC_CIPHER))
            { /* DHE without ECC */
#   ifdef REQUIRE_DH_PARAMS
                /*
                  Extract p and g parameters from key to session context.
                  Going to send these in the SERVER_KEY_EXCHANGE message.
                  This is wrapped in a test of whether or not the values have
                  already been extracted because an SSL_FULL scenario below
                  will cause this code to be executed again with a larger
                  buffer. */
                if (ssl->sec.dhPLen == 0 && ssl->sec.dhP == NULL)
                {
                    if (psDhExportParameters(ssl->hsPool, &ssl->keys->dhParams,
                                             &ssl->sec.dhP, &ssl->sec.dhPLen,
                                             &ssl->sec.dhG, &ssl->sec.dhGLen) < 0)
                    {
                        return MATRIXSSL_ERROR;
                    }
                }
#   endif /* REQUIRE_DH_PARAMS */
            }
            if ((ssl->flags & SSL_FLAGS_ANON_CIPHER) != 0)
            {
#   ifdef USE_ANON_DH_CIPHER_SUITE
                /*
                  If we are an anonymous cipher, we don't send the
                  certificate.  The messages are simply SERVER_HELLO,
                  SERVER_KEY_EXCHANGE, and SERVER_HELLO_DONE
                */
                stotalCertLen = 0;
                srvKeyExLen = ssl->sec.dhPLen + 2 +
                    ssl->sec.dhGLen + 2 +
                    ssl->sec.dhKeyPriv->size + 2;

#    ifdef USE_PSK_CIPHER_SUITE
                if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
                {
/*
 *                                      struct {
 *                                              Select (KeyExchangeAlgorithm) {
 *                                                      case diffie_hellman_psk:  * NEW *
 *                                                      opaque psk_identity_hint<0..2^16-1>;
 *                                                      ServerDHParams params;
 *                                              };
 *                                      } ServerKeyExchange;
 */
                    if (SSL_PSK_MAX_HINT_SIZE > 0)
                    {
                        srvKeyExLen += SSL_PSK_MAX_HINT_SIZE + 2;
                    }
                }
#    endif      /* USE_PSK_CIPHER_SUITE */

                messageSize =
                    3 * ssl->recordHeadLen +
                    3 * ssl->hshakeHeadLen +
                    38 + SSL_MAX_SESSION_ID_SIZE +     /* server hello */
                    srvKeyExLen;                       /* server key exchange */
                messageSize += secureWriteAdditions(ssl, 3);
#   endif   /* USE_ANON_DH_CIPHER_SUITE */
            } /* anonymous DHE */

            if ((ssl->flags & SSL_FLAGS_ANON_CIPHER) == 0)
            { /* DHE with authentication */

                if ((ssl->flags & SSL_FLAGS_ECC_CIPHER) != 0)
                { /* DHE with ECC */
#   ifdef USE_ECC_CIPHER_SUITE
                    if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA)
                    {
                        /*
                          Magic 7: 1byte ECCurveType named, 2bytes NamedCurve id
                          1 byte pub key len, 2 byte privkeysize len,
                          1 byte 0x04 inside the eccKey itself
                        */
                        srvKeyExLen =
                            (ssl->sec.eccKeyPriv->curve->size * 2) +
                            7 +
                            ssl->chosenIdentity->privKey.keysize;
                    }
                    else if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA)
                    {
                        /* ExportKey plus signature */
                        srvKeyExLen = (ssl->sec.eccKeyPriv->curve->size * 2) + 7 +
                            6 + /* 6 = 2 ASN_SEQ, 4 ASN_BIG */
                            ssl->chosenIdentity->privKey.keysize;
                        if (ssl->chosenIdentity->privKey.keysize >= 128)
                        {
                            srvKeyExLen += 1;     /* Extra len byte in ASN.1 sig */
                        }
                        /* NEGATIVE ECDSA - For purposes of SSL_FULL we
                           add 2 extra bytes to account for the two possible
                           0x0     bytes in signature */
                        srvKeyExLen += 2;
                    }
#    ifdef USE_TLS_1_2
                    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
                    {
                        srvKeyExLen += 2;     /* hashSigAlg */
                    }
#    endif /* USE_TLS_1_2 */
#   endif /* USE_ECC_CIPHER_SUITE */
                }
                if ((ssl->flags & SSL_FLAGS_ECC_CIPHER) == 0)
                { /* DHE without ECC */
#   ifdef REQUIRE_DH_PARAMS
                    /*
                      The AUTH versions of the DHE cipher suites include a
                      signature value in the SERVER_KEY_EXCHANGE message.
                      Account for that length here.  Also, the CERTIFICATE
                      message is sent in this flight as well for normal
                      authentication.
                    */
                    srvKeyExLen =
                        ssl->sec.dhPLen + 2 +
                        ssl->sec.dhGLen + 2 +
                        ssl->sec.dhKeyPriv->size + 2;
#    ifdef USE_IDENTITY_CERTIFICATES
                    srvKeyExLen += (ssl->chosenIdentity->privKey.keysize + 2);
#    endif
#    ifdef USE_TLS_1_2
                    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
                    {
                        srvKeyExLen += 2;     /* hashSigAlg */
                    }
#    endif /* USE_TLS_1_2 */
#   endif   /* REQUIRE_DH_PARAMS */
                }
            } /* authenticated DHE */

            stotalCertLen = ncerts = 0;
#   ifdef USE_IDENTITY_CERTIFICATES
            if ((ssl->flags & SSL_FLAGS_PSK_CIPHER) == 0)
            {
                if (ssl->chosenIdentity)
                {
                    for (cert = ssl->chosenIdentity->cert, ncerts = 0;
                         cert != NULL;
                         cert = cert->next, ncerts++)
                    {
                        stotalCertLen += cert->binLen;
                    }
                    /* Are we going to have to fragment the CERTIFICATE message? */
                    if ((stotalCertLen + 3 + (ncerts * 3) + ssl->hshakeHeadLen) >
                        ssl->maxPtFrag)
                    {
                        stotalCertLen += addCertFragOverhead(
                                ssl,
                                stotalCertLen + 3 + (ncerts * 3) + ssl->hshakeHeadLen);
                    }
                }
            }
#   endif /* USE_IDENTITY_CERTIFICATES */
            messageSize =
                4 * ssl->recordHeadLen +
                4 * ssl->hshakeHeadLen +
                38 + SSL_MAX_SESSION_ID_SIZE +     /* server hello */
                srvKeyExLen +                      /* server key exchange */
                3 + (ncerts * 3) + stotalCertLen;  /* certificate */
#   ifdef USE_CLIENT_AUTH
#    ifndef USE_ONLY_PSK_CIPHER_SUITE
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                /* Are we going to have to fragment the
                    CERTIFICATE_REQUEST message? */
                if (certReqLen + CAcertLen > ssl->maxPtFrag)
                {
                    certReqLen += addCertFragOverhead(ssl,
                        certReqLen + CAcertLen);
                }
                /* Account for the CertificateRequest message */
                messageSize += certReqLen + CAcertLen;
                messageSize += secureWriteAdditions(ssl, 1);
            }
#    endif /* USE_ONLY_PSK_CIPHER_SUITE */
#   endif  /* USE_CLIENT_AUTH */
            messageSize += secureWriteAdditions(ssl, 4);
#  endif  /* USE_DHE_CIPHER_SUITE */
        } /* DHE key exchange */

        if ((ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) == 0)
        {
            /*
              This is the entry point for a server encoding the first flight
              of a non-DH, non-client-auth handshake.
            */
            stotalCertLen = 0;
            if ((ssl->flags & SSL_FLAGS_PSK_CIPHER) != 0)
            {
#  ifdef USE_PSK_CIPHER_SUITE
                /*
                  Omit the CERTIFICATE message but (possibly) including the
                  SERVER_KEY_EXCHANGE.
                */
                messageSize =
                    2 * ssl->recordHeadLen +
                    2 * ssl->hshakeHeadLen +
                    38 + SSL_MAX_SESSION_ID_SIZE;              /* server hello */
                if (SSL_PSK_MAX_HINT_SIZE > 0)
                {
                    messageSize += 2 + SSL_PSK_MAX_HINT_SIZE + /* SKE */
                        ssl->recordHeadLen + ssl->hshakeHeadLen;
                }
                else
                {
                    /*
                      Assuming 3 messages below when only two are going to exist
                    */
                    messageSize -= secureWriteAdditions(ssl, 1);
                }
#  endif
            } /* PSK cipher */

            if ((ssl->flags & SSL_FLAGS_PSK_CIPHER) == 0)
            {
#  ifdef USE_IDENTITY_CERTIFICATES
                if (ssl->chosenIdentity)
                {
                    for (cert = ssl->chosenIdentity->cert, ncerts = 0;
                         cert != NULL; cert = cert->next, ncerts++)
                    {
                        psAssert(cert->unparsedBin != NULL);
                        stotalCertLen += cert->binLen;
                    }
                    /* Are we going to have to fragment the CERTIFICATE message? */
                    if ((stotalCertLen + 3 + (ncerts * 3) + ssl->hshakeHeadLen) > ssl->maxPtFrag)
                    {
                        stotalCertLen += addCertFragOverhead(
                                ssl,
                                stotalCertLen + 3 + (ncerts * 3) + ssl->hshakeHeadLen);
                    }
                    messageSize =
                        3 * ssl->recordHeadLen +
                        3 * ssl->hshakeHeadLen +
                        38 + SSL_MAX_SESSION_ID_SIZE +        /* server hello */
                        3 + (ncerts * 3) + stotalCertLen;    /* certificate */
                }
#  endif /* USE_IDENTITY_CERTIFICATES */
            } /* not PSK cipher */

#  ifdef USE_CLIENT_AUTH
#   ifndef USE_ONLY_PSK_CIPHER_SUITE
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                /* Are we going to have to fragment the CERTIFICATE_REQUEST
                   message? This is the SSL fragment level */
                if (certReqLen + CAcertLen > ssl->maxPtFrag)
                {
                    certReqLen += addCertFragOverhead(ssl,
                                                      certReqLen + CAcertLen);
                }
                messageSize += certReqLen + CAcertLen;     /* certificate request */
                messageSize += secureWriteAdditions(ssl, 1);
#    ifdef USE_DTLS
                if (ACTV_VER(ssl, v_dtls_any))
                {
                    /*      DTLS pmtu CERTIFICATE_REQUEST */
                    messageSize += (MAX_FRAGMENTS - 1) *
                        (ssl->recordHeadLen + ssl->hshakeHeadLen);
                    if (ssl->flags & SSL_FLAGS_WRITE_SECURE)
                    {
                        messageSize += secureWriteAdditions(ssl,
                                                            MAX_FRAGMENTS - 1);
                    }
                }
#    endif /* USE_DTLS */
            }
#   endif  /* USE_ONLY_PSK_CIPHER_SUITE */
#  endif   /* USE_CLIENT_AUTH */
            messageSize += secureWriteAdditions(ssl, 3);
        } /* not DHE key exchange */

#  ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any))
        {
            /*
              If DTLS, make sure the max fragment overhead is accounted for on
              any flight containing the CERTIFICATE message.  If SSL_FULL is
              hit mid-flight creation, the updates that happen on the
              handshake hash on that first pass will really mess us up
            */
            messageSize += (MAX_FRAGMENTS - 1) *
                (ssl->recordHeadLen + ssl->hshakeHeadLen);
            if (ssl->flags & SSL_FLAGS_WRITE_SECURE)
            {
                messageSize += secureWriteAdditions(ssl, MAX_FRAGMENTS - 1);
            }
        }
#  endif /* USE_DTLS */

        /*
          Add extensions
        */
        extSize = 0; /* Two byte total length for all extensions */
        if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN)
        {
            extSize = 2;
            messageSize += 5; /* 2 type, 2 length, 1 value */
        }

        if (ssl->extFlags.truncated_hmac)
        {
            extSize = 2;
            messageSize += 4; /* 2 type, 2 length, 0 value */
        }

        if (ssl->extFlags.extended_master_secret)
        {
            extSize = 2;
            messageSize += 4; /* 2 type, 2 length, 0 value */
        }

#  ifdef USE_OCSP_RESPONSE
        /* If we are sending the OCSP status_request extension, we are also
           sending the CERTIFICATE_STATUS handshake message */
        if (ssl->extFlags.status_request)
        {
            extSize = 2;
            messageSize += 4; /* 2 type, 2 length, 0 value */

            /* And the handshake message oh.  1 type, 3 len, x OCSPResponse
               The status_request flag will only have been set if a
               ssl->keys->OCSPResponseBuf was present during extension parse */
            messageSize += ssl->hshakeHeadLen + ssl->recordHeadLen + 4 +
                ssl->keys->OCSPResponseBufLen;
            messageSize += secureWriteAdditions(ssl, 1);
        }
#  endif /* USE_OCSP_RESPONSE */

#  ifdef USE_STATELESS_SESSION_TICKETS
        if (ssl->sid &&
            ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT)
        {
            extSize = 2;
            messageSize += 4; /* 2 type, 2 length, 0 value */
        }
#  endif
        if (ssl->extFlags.sni)
        {
            extSize = 2;
            messageSize += 4;
        }

#  ifdef USE_ALPN
        if (ssl->alpnLen)
        {
            extSize = 2;
            messageSize += 6 + 1 + ssl->alpnLen; /* 6 type/len + 1 len + data */
        }
#  endif

#  ifdef ENABLE_SECURE_REHANDSHAKES
        /*
          The RenegotiationInfo extension lengths are well known
        */
        if (ssl->secureRenegotiationFlag == PS_TRUE && ssl->myVerifyDataLen == 0)
        {
            extSize = 2;
            messageSize += 5; /* ff 01 00 01 00 */
        }
        else if (ssl->secureRenegotiationFlag == PS_TRUE &&
                 ssl->myVerifyDataLen > 0)
        {
            extSize = 2;
            messageSize += 5 +
                ssl->myVerifyDataLen +
                ssl->peerVerifyDataLen; /* 2 for total len, 5 for type+len */
        }
#  endif /* ENABLE_SECURE_REHANDSHAKES */

#  ifdef USE_ECC_CIPHER_SUITE
        /*
          Server Hello ECC extension
        */
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            if (ssl->extFlags.got_elliptic_points == 1)
            {
                extSize = 2;
                messageSize += 6; /* 00 0B 00 02 01 00 */
            }
        }
#  endif /* USE_ECC_CIPHER_SUITE */
        /*
          Done with extensions.  If had some, add the two byte total length
        */
        messageSize += extSize;

        if ((out->buf + out->size) - out->end < messageSize)
        {
            *requiredLen = messageSize;
            return SSL_FULL;
        }
        /*
          Message size complete.  Begin the flight write
        */
        rc = writeServerHello(ssl, out);

        if ((ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) != 0)
        {
#  ifdef USE_DHE_CIPHER_SUITE
#   ifdef USE_IDENTITY_CERTIFICATES
            if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA || ssl->flags & SSL_FLAGS_DHE_WITH_DSA)
            {
                if (rc == MATRIXSSL_SUCCESS)
                {
                    rc = writeCertificate(ssl, out, 1);
                }
#    ifdef USE_OCSP_RESPONSE
                if (rc == MATRIXSSL_SUCCESS)
                {
                    rc = writeCertificateStatus(ssl, out);
                }
#    endif
            }
#  endif /* USE_IDENTITY_CERTIFICATES */
            if (rc == MATRIXSSL_SUCCESS)
            {
                if ((ssl->flags & SSL_FLAGS_ECC_CIPHER) != 0)
                {
                    rc = writeServerKeyExchange(ssl, out, 0, NULL, 0, NULL);
                }
                else
                {
#  ifdef REQUIRE_DH_PARAMS
                    rc = writeServerKeyExchange(ssl,
                                                out, ssl->sec.dhPLen,
                                                ssl->sec.dhP, ssl->sec.dhGLen, ssl->sec.dhG);
#  endif /* REQUIRE_DH_PARAMS */
                }
            }
#  endif /* USE_DHE_CIPHER_SUITE */
        } /* DHE key exchange/write certificates */

        if ((ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) == 0)
        {
#  ifdef USE_PSK_CIPHER_SUITE
            if ((ssl->flags & SSL_FLAGS_PSK_CIPHER) != 0)
            {
                if (rc == MATRIXSSL_SUCCESS)
                {
                    rc = writePskServerKeyExchange(ssl, out);
                }
            }
#  endif /* USE_PSK_CIPHER_SUITE */
            if ((ssl->flags & SSL_FLAGS_PSK_CIPHER) == 0)
            {
#  ifdef USE_IDENTITY_CERTIFICATES
                if (rc == MATRIXSSL_SUCCESS)
                {
                    rc = writeCertificate(ssl, out, 1);
                }
#   ifdef USE_OCSP_RESPONSE
                if (rc == MATRIXSSL_SUCCESS)
                {
                    rc = writeCertificateStatus(ssl, out);
                }
#   endif /* USE_OCSP_RESPONSE */
#  endif /* USE_IDENTITY_CERTIFICATES */
            }
        } /* not DHE key exchange; write PSK/certificates */

#  ifndef USE_ONLY_PSK_CIPHER_SUITE
#   ifdef USE_CLIENT_AUTH
        if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
        {
            if (rc == MATRIXSSL_SUCCESS)
            {
                rc = writeCertificateRequest(ssl, out, CAcertLen, certCount);
            }
        }
#   endif /* USE_CLIENT_AUTH */
#  endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

        if (rc == MATRIXSSL_SUCCESS)
        {
            rc = writeServerHelloDone(ssl, out);
        }
        if (rc == SSL_FULL)
        {
            psTraceInfo("Bad flight messageSize calculation");
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            out->end = out->start;
            alertReqLen = out->size;
            /* Going recursive */
            return sslEncodeResponse(ssl, out, &alertReqLen);
        }
        break;

#  ifdef USE_DTLS
        /*
          Got a cookie-less CLIENT_HELLO, need a HELLO_VERIFY_REQUEST message
        */
    case SSL_HS_CLIENT_HELLO:
        messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
            DTLS_COOKIE_SIZE + 3;
        messageSize += secureWriteAdditions(ssl, 1);

        if ((out->buf + out->size) - out->end < messageSize)
        {
            *requiredLen = messageSize;
            return SSL_FULL;
        }
        rc = writeHelloVerifyRequest(ssl, out);
        break;
#  endif /* USE_DTLS */
# endif /* USE_SERVER_SIDE_SSL */

        /*
          If we're not waiting for any message from client, then we need to
          send our finished message
        */
    case SSL_HS_DONE:
        messageSize = 2 * ssl->recordHeadLen +
            ssl->hshakeHeadLen +
            1 +                             /* change cipher spec */
            MD5_HASH_SIZE + SHA1_HASH_SIZE; /* finished */
        /*
          Account for possible overhead in CCS message with secureWriteAdditions
          then always account for the encryption overhead on FINISHED message.
          Correct to use ssl->cipher values for mac and block since those will
          be the ones used when encrypting FINISHED
        */
        messageSize += secureWriteAdditions(ssl, 1);
        messageSize += ssl->cipher->macSize + ssl->cipher->blockSize;

# if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            if (ssl->sid &&
                (ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT))
            {
                messageSize += ssl->recordHeadLen +
                    ssl->hshakeHeadLen + matrixSessionTicketLen() + 6;
            }
        }
# endif

# ifdef USE_TLS
        /*
          Account for the smaller finished message size for TLS.
        */
        if (!NGTD_VER(ssl, v_ssl_3_0))
        {
            messageSize += TLS_HS_FINISHED_SIZE -
                (MD5_HASH_SIZE + SHA1_HASH_SIZE);
        }
# endif /* USE_TLS */
# ifdef USE_TLS_1_1
        /*
          Adds explict IV overhead to the FINISHED message
        */
        if (NGTD_VER(ssl, v_tls_explicit_iv))
        {
            if (ssl->flags & SSL_FLAGS_AEAD_W)
            {
                /* The magic 1 back into messageSize is because the
                   macSize + blockSize above ends up subtracting one on AEAD */
                messageSize += AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl) + 1;
            }
            else
            {
                messageSize += ssl->cipher->blockSize;
            }
        }
# endif /* USE_TLS_1_1 */

# ifdef USE_ZLIB_COMPRESSION
        /* Lastly, add the zlib overhead for the FINISHED message */
        if (ssl->compression)
        {
            messageSize += MAX_ZLIB_COMPRESSED_OH;
        }
# endif
        if ((out->buf + out->size) - out->end < messageSize)
        {
            *requiredLen = messageSize;
            return SSL_FULL;
        }
        rc = MATRIXSSL_SUCCESS;

# if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            if (ssl->sid &&
                (ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT))
            {
                rc = writeNewSessionTicket(ssl, out);
            }
        }
# endif
        if (rc == MATRIXSSL_SUCCESS)
        {
            rc = writeChangeCipherSpec(ssl, out);
        }
        if (rc == MATRIXSSL_SUCCESS)
        {
            rc = writeFinished(ssl, out);
        }

        if (rc == SSL_FULL)
        {
            psTraceInfo("Bad flight messageSize calculation");
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            out->end = out->start;
            alertReqLen = out->size;
            /* Going recursive */
            return sslEncodeResponse(ssl, out, &alertReqLen);
        }
        break;
/*
    If we're expecting a Finished message, as a server we're doing
    session resumption.  As a client, we're completing a normal
    handshake
 */
    case SSL_HS_FINISHED:
# ifdef USE_SERVER_SIDE_SSL
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            messageSize =
                3 * ssl->recordHeadLen +
                2 * ssl->hshakeHeadLen +
                38 + SSL_MAX_SESSION_ID_SIZE +      /* server hello */
                1 +                                 /* change cipher spec */
                MD5_HASH_SIZE + SHA1_HASH_SIZE;     /* finished */
            /*
              Account for possible overhead with secureWriteAdditions
              then always account for the encrypted FINISHED message.  Correct
              to use the ssl->cipher values for mac and block since those will
              always be the values used to encrypt the FINISHED message
            */
            messageSize += secureWriteAdditions(ssl, 2);
            messageSize += ssl->cipher->macSize + ssl->cipher->blockSize;
#  ifdef ENABLE_SECURE_REHANDSHAKES
            /*
              The RenegotiationInfo extension lengths are well known
            */
            if (ssl->secureRenegotiationFlag == PS_TRUE &&
                ssl->myVerifyDataLen == 0)
            {
                messageSize += 7; /* 00 05 ff 01 00 01 00 */
            }
            else if (ssl->secureRenegotiationFlag == PS_TRUE &&
                     ssl->myVerifyDataLen > 0)
            {
                messageSize += 2 + 5 + ssl->myVerifyDataLen +
                               ssl->peerVerifyDataLen; /* 2 for tot len, 5 for type+len */
            }
#  endif /* ENABLE_SECURE_REHANDSHAKES */

#  ifdef USE_ECC_CIPHER_SUITE
            if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
            {
                if (ssl->extFlags.got_elliptic_points == 1)
                {
#   ifndef ENABLE_SECURE_REHANDSHAKES
                    messageSize += 2; /* ext 2 byte len has not been included */
#   endif /* ENABLE_SECURE_REHANDSHAKES */
                    /* EXT_ELLIPTIC_POINTS - hardcoded to 'uncompressed' support */
                    messageSize += 6; /* 00 0B 00 02 01 00 */
                }
            }
#  endif /* USE_ECC_CIPHER_SUITE */

#  ifdef USE_TLS
            /*
              Account for the smaller finished message size for TLS.
              The MD5+SHA1 is SSLv3.  TLS is 12 bytes.
            */
            if (!NGTD_VER(ssl, v_ssl_3_0))
            {
                messageSize += TLS_HS_FINISHED_SIZE -
                               (MD5_HASH_SIZE + SHA1_HASH_SIZE);
            }
#  endif    /* USE_TLS */

#  ifdef USE_TLS_1_1
            /*
              Adds explict IV overhead to the FINISHED message.
              Always added because FINISHED is never accounted for in
              secureWriteAdditions */
            if (NGTD_VER(ssl, v_tls_explicit_iv))
            {
                if (ssl->cipher->flags &
                    (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM))
                {
                    /* The magic 1 back into messageSize is because the
                        blockSize -1 above ends up subtracting one on AEAD */
                    messageSize += AEAD_TAG_LEN(ssl) + TLS_EXPLICIT_NONCE_LEN + 1;
                }
                else if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA)
                {
                    messageSize += AEAD_TAG_LEN(ssl) + 1;
                }
                else
                {
                    messageSize += ssl->cipher->blockSize; /* explicitIV */
                }
            }
#  endif    /* USE_TLS_1_1 */

#  ifdef USE_ZLIB_COMPRESSION
            /* Lastly, add the zlib overhead for the FINISHED message */
            if (ssl->compression)
            {
                messageSize += MAX_ZLIB_COMPRESSED_OH;
            }
#  endif
            if ((out->buf + out->size) - out->end < messageSize)
            {
                *requiredLen = messageSize;
                return SSL_FULL;
            }
            rc = writeServerHello(ssl, out);
            if (rc == MATRIXSSL_SUCCESS)
            {
                rc = writeChangeCipherSpec(ssl, out);
            }
            if (rc == MATRIXSSL_SUCCESS)
            {
                rc = writeFinished(ssl, out);
            }
        }
# endif /* USE_SERVER_SIDE_SSL */

# ifdef USE_CLIENT_SIDE_SSL
        /*
          Encode entry point for client side final flight encodes.
          First task here is to find out size of ClientKeyExchange message
        */
        if (!(ssl->flags & SSL_FLAGS_SERVER))
        {
            ckeSize = calcCkeSize(ssl);
            if (ckeSize < 0)
            {
                ssl->flags |= SSL_FLAGS_ERROR;
                return ckeSize;
            }

            messageSize = 0;

            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
#  if defined(USE_IDENTITY_CERTIFICATES) && defined(USE_CLIENT_AUTH)
                /*
                  Client authentication requires the client to send a
                  CERTIFICATE and CERTIFICATE_VERIFY message.  Account for the
                  length.  It is possible the client didn't have a match for
                  the requested cert.  Send an empty certificate message in
                  that case (or alert for SSLv3)
                */
                if (ssl->sec.certMatch > 0)
                {
                    /*
                      Account for the certificate and certificateVerify messages
                    */
                    ctotalCertLen = ncerts = 0;
                    if (ssl->chosenIdentity)
                    {
                        for (cert = ssl->chosenIdentity->cert; cert; cert = cert->next, ncerts++)
                        {
                            ctotalCertLen += cert->binLen;
                        }
                    }
                    /* Are we going to have to fragment the CERT message? */
                    if ((ctotalCertLen + 3 + (ncerts * 3) + ssl->hshakeHeadLen) >
                        ssl->maxPtFrag)
                    {
                        ctotalCertLen += addCertFragOverhead(ssl,
                            ctotalCertLen + 3 + (ncerts * 3) + ssl->hshakeHeadLen);
                    }
                    messageSize =
                        2 * ssl->recordHeadLen +
                        2 * ssl->hshakeHeadLen +
                        3 + (ncerts * 3) + ctotalCertLen +
                        (ssl->chosenIdentity ? (2 + ssl->chosenIdentity->privKey.keysize): 0);

#    ifdef USE_ECC
                    /* Overhead ASN.1 in psEccSignHash */
                    if (ssl->chosenIdentity
                        && ssl->chosenIdentity->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
                    {
                        /* NEGATIVE ECDSA - For purposes of SSL_FULL we
                            add 2 extra bytes to account for the two 0x0
                            bytes in signature */
                        messageSize += 6 + 2;
                        if (ssl->chosenIdentity->privKey.keysize >= 128)
                        {
                            messageSize += 1; /* Extra len byte in ASN.1 sig */
                        }
                    }
#    endif          /* USE_ECC */
                }
                if (ssl->sec.certMatch == 0)
                {
                    /*
                      SSLv3 sends a no_certificate warning alert for no match
                    */
                    if (NGTD_VER(ssl, v_ssl_3_0))
                    {
                        messageSize += 2 + ssl->recordHeadLen;
                    }
                    else
                    {
                        /*
                          TLS just sends an empty certificate message
                        */
                        messageSize += 3 + ssl->recordHeadLen + ssl->hshakeHeadLen;
                    }
                }
#  endif /* USE_IDENTITY_CERTIFICATES */
            }

            /*
              Account for the header and message size for all records.  The
              finished message will always be encrypted, so account for one
              largest possible MAC size and block size.  The finished message
              is not accounted for in the writeSecureAddition calls below
              since it is accounted for here.*/
            messageSize +=
                3 * ssl->recordHeadLen +
                2 * ssl->hshakeHeadLen +             /* change cipher has no hsHead */
                ckeSize +                            /* client key exchange */
                1 +                                  /* change cipher spec */
                MD5_HASH_SIZE + SHA1_HASH_SIZE +     /* SSLv3 finished payload */
                ssl->cipher->macSize +
                ssl->cipher->blockSize;              /* finished overhead */
#  ifdef USE_TLS
            /*
              Must add the 2 bytes key size length to the client key exchange
              message. Also, at this time we can account for the smaller
              finished message size for TLS.  The MD5+SHA1 is SSLv3.  TLS is
              12 bytes. */
            if (!NGTD_VER(ssl, v_ssl_3_0))
            {
                messageSize += 2 - MD5_HASH_SIZE - SHA1_HASH_SIZE +
                    TLS_HS_FINISHED_SIZE;
            }
#  endif    /* USE_TLS */
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                /*
                  Secure write for ClientKeyExchange, ChangeCipherSpec,
                  Certificate, and CertificateVerify.  Don't account for
                  Certificate and/or CertificateVerify message if no auth
                  cert.  This will also cover the NO_CERTIFICATE alert sent in
                  replacement of the NULL certificate message in SSLv3.
                */
                if (ssl->sec.certMatch > 0)
                {
#  ifdef USE_TLS_1_2
                    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
                    {
                        messageSize += 2; /* hashSigAlg in CertificateVerify */
                    }
#  endif
                    messageSize += secureWriteAdditions(ssl, 4);
                }
                else
                {
                    messageSize += secureWriteAdditions(ssl, 3);
                }
            }
            else
            {
                messageSize += secureWriteAdditions(ssl, 2);
            }

#  ifdef USE_DTLS
            if (ACTV_VER(ssl, v_dtls_any))
            {
                /*
                  If DTLS, make sure the max fragment overhead is accounted
                  for on any flight containing the CERTIFICATE message.  If
                  SSL_FULL is hit mid-flight creation, the updates that happen
                  on the handshake hash on that first pass will really mess us
                  up */
                messageSize += (MAX_FRAGMENTS - 1) *
                    (ssl->recordHeadLen + ssl->hshakeHeadLen);
                if (ssl->flags & SSL_FLAGS_WRITE_SECURE)
                {
                    messageSize += secureWriteAdditions(ssl, MAX_FRAGMENTS - 1);
                }
            }
#  endif    /* USE_DTLS */
#  ifdef USE_TLS_1_1
            /*
              Adds explict IV overhead to the FINISHED message.  Always added
              because FINISHED is never accounted for in secureWriteAdditions
            */
            if (NGTD_VER(ssl, v_tls_explicit_iv))
            {
                if (ssl->cipher->flags &
                    (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM))
                {
                    /* The magic 1 back into messageSize is because the
                       blockSize -1 above ends up subtracting one on AEAD */
                    messageSize += AEAD_TAG_LEN(ssl) + TLS_EXPLICIT_NONCE_LEN + 1;
                }
                else if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA)
                {
                    messageSize += AEAD_TAG_LEN(ssl) + 1;
                }
                else
                {
                    messageSize += ssl->cipher->blockSize; /* explicitIV */
                }
            }
#  endif    /* USE_TLS_1_1 */
#  ifdef USE_ZLIB_COMPRESSION
            /* Lastly, add the zlib overhead for the FINISHED message */
            if (ssl->compression)
            {
                messageSize += MAX_ZLIB_COMPRESSED_OH;
            }
#  endif
            /*
              The actual buffer size test to hold this flight
            */
            if ((out->buf + out->size) - out->end < messageSize)
            {
                *requiredLen = messageSize;
                return SSL_FULL;
            }

            rc = MATRIXSSL_SUCCESS;
#  ifdef USE_IDENTITY_CERTIFICATES
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                /* The TLS RFC is fairly clear that an empty certificate
                   message be sent if there is no certificate match.  SSLv3
                   tends to lean toward a NO_CERTIFIATE warning alert message
                */
                if (ssl->sec.certMatch == 0 && NGTD_VER(ssl, v_ssl_3_0))
                {
                    rc = writeAlert(ssl, SSL_ALERT_LEVEL_WARNING,
                                    SSL_ALERT_NO_CERTIFICATE, out, requiredLen);
                }
                else
                {
                    rc = writeCertificate(ssl, out, ssl->sec.certMatch);
                }
            }
#  endif /* USE_IDENTITY_CERTIFICATES */
            if (rc == MATRIXSSL_SUCCESS)
            {
                rc = writeClientKeyExchange(ssl, out);
            }
#  if defined(USE_IDENTITY_CERTIFICATES) && defined(USE_CLIENT_AUTH)
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                if (rc == MATRIXSSL_SUCCESS
                    && ssl->sec.certMatch > 0
                    && ssl->chosenIdentity)
                {
                    rc = writeCertificateVerify(ssl, out);
                }
            }
#  endif  /* USE_IDENTITY_CERTIFICATES */
            if (rc == MATRIXSSL_SUCCESS)
            {
                rc = writeChangeCipherSpec(ssl, out);
            }
            if (rc == MATRIXSSL_SUCCESS)
            {
                rc = writeFinished(ssl, out);
            }
        }
# endif /* USE_CLIENT_SIDE_SSL */
        if (rc == SSL_FULL)
        {
            psTraceInfo("Bad flight messageSize calculation");
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            out->end = out->start;
            alertReqLen = out->size;
            /* Going recursive */
            return sslEncodeResponse(ssl, out, &alertReqLen);
        }
        break;
# ifdef USE_DTLS
        /*
          If we a client being invoked from here in the HS_SERVER_HELLO state,
          we are being asked for a CLIENT_HELLO with a cookie.  It's already
          been parsed out of the server HELLO_VERIFY_REQUEST message, so we
          can simply call matrixSslEncodeClientHello again and essentially
          start over again.
        */
    case SSL_HS_SERVER_HELLO:
        rc = matrixSslEncodeClientHello(
                ssl, out, ssl->cipherSpec,
                ssl->cipherSpecLen, requiredLen, NULL, &options);
        break;
# endif /* USE_DTLS */
    }
    goto flightEncode;

flightEncode:
    if (rc < MATRIXSSL_SUCCESS && rc != SSL_FULL)
    {
        /* Indication one of the message creations failed and setting the flag
           to prevent other API calls from working.  We want to send a fatal
           internal error alert in this case.  Make sure to write to front of
           buffer since we can't trust the data in there due to the creation
           failure. */
        psTraceIntInfo("ERROR: Handshake flight creation failed %d\n", rc);
        if (rc == PS_UNSUPPORTED_FAIL)
        {
            /* Single out this particular error as a handshake failure because
               there are combinations of cipher negotiations where we don't
               know until handshake creation that we can't support.  For
               example, the server key material test will be bypassed if an
               SNI callback is registered.  We won't know until SKE creation
               that we can't support the requested cipher.  This is a user
               error so don't report an INTERNAL_ERROR */
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        }
        else
        {
            /* let tls13 set errors, others use internal error here. */
            ssl->err = (USING_TLS_1_3(ssl) && ssl->err != SSL_ALERT_NONE) ? ssl->err : SSL_ALERT_INTERNAL_ERROR;
        }
        out->end = out->start;
        alertReqLen = out->size;
        /* Going recursive */
        return sslEncodeResponse(ssl, out, &alertReqLen);
    }

# if defined(USE_HARDWARE_CRYPTO_RECORD) || defined(USE_HARDWARE_CRYPTO_PKA) || defined(USE_EXT_CERTIFICATE_VERIFY_SIGNING)
resumeFlightEncryption:
# endif

# ifdef USE_SERVER_SIDE_SSL
    /* Post-flight write PKA operation.  Support is for the signature
       generation during ServerKeyExchange write.  */
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        if (ssl->pkaAfter[0].type > 0)
        {
            if ((rc = nowDoSkePka(ssl, out)) < 0)
            {
                return rc;
            }
        }
    }
# endif /* USE_SERVER_SIDE_SSL */

# ifdef USE_CLIENT_SIDE_SSL
    /* Post-flight write PKA operation. */
    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
#  ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
        /* Handle delayed CertificateVerify write. */
        if (ssl->extCvSigOpInUse &&
            (ssl->pkaAfter[0].type == PKA_AFTER_RSA_SIG_GEN_ELEMENT ||
             ssl->pkaAfter[0].type == PKA_AFTER_ECDSA_SIG_GEN))
        {
            /* Ensure that the signature is now ready. No point in
               continuing if it is not. */
            if (ssl->extCvSigOpPending &&
                ssl->extCvSigLen == 0)
            {
                psTraceInfo("sslEncodeResponse called too soon; " \
                    "CertificateVerify signature has not been set " \
                    "with matrixSslSetCvSignature().\n");
                return PS_PENDING;
            }
        }
        else
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
         /*
           Handle delayed ClientKeyExchange PKA operation.
           None needed when using a PSK suite.
         */
            if (ssl->pkaAfter[0].type > 0)
            {
                rc = nowDoCkePka(ssl);
                if (rc < 0)
                {
                    return rc;
                }
        }
    }
# endif /* USE_CLIENT_SIDE_SSL */

    /* Encrypt Flight */
    if (ssl->flightEncode)
    {
        if ((rc = encryptFlight(ssl, &out->end)) < 0)
        {
            return rc;
        }
    }

    return rc;
}

void clearFlightList(ssl_t *ssl)
{
    flightEncode_t *msg, *next;

    msg = ssl->flightEncode;
    while (msg)
    {
        next = msg->next;
        psFree(msg, ssl->flightPool);
        msg = next;
    }
    ssl->flightEncode = NULL;
}

static inline
int32_t processFinished(ssl_t *ssl, flightEncode_t *msg)
{
    int32_t rc;

# ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (msg->hsMsg == SSL_HS_FINISHED)
        {
            /*      Epoch is incremented and the sequence numbers are reset for
                    this message */
            incrTwoByte(ssl, ssl->epoch, 1);
            zeroSixByte(ssl->rsn);
        }
#ifdef psTracefDtls
        psTracefDtls("Flight Encode: RSN %d, MSN %d, Epoch %d\n",
                ssl->rsn[5], ssl->msn, ssl->epoch[1]);
#else
        psTraceIntDtls("RSN %d, ", ssl->rsn[5]);
        psTraceIntDtls("MSN %d, ", ssl->msn);
        psTraceIntDtls("Epoch %d\n", ssl->epoch[1]);
#endif
        *msg->seqDelay = ssl->epoch[0]; msg->seqDelay++;
        *msg->seqDelay = ssl->epoch[1]; msg->seqDelay++;
        *msg->seqDelay = ssl->rsn[0]; msg->seqDelay++;
        *msg->seqDelay = ssl->rsn[1]; msg->seqDelay++;
        *msg->seqDelay = ssl->rsn[2]; msg->seqDelay++;
        *msg->seqDelay = ssl->rsn[3]; msg->seqDelay++;
        *msg->seqDelay = ssl->rsn[4]; msg->seqDelay++;
        *msg->seqDelay = ssl->rsn[5]; msg->seqDelay++;
        msg->seqDelay++;
        msg->seqDelay++; /* Last two incremements skipped recLen */
    }
# endif /* USE_DTLS */
    if (msg->hsMsg == SSL_HS_FINISHED)
    {
        /* If it was just a ChangeCipherSpec message that was encoded we can
           activate the write cipher */
        if ((rc = sslActivateWriteCipher(ssl)) < 0)
        {
            psTraceInfo("Error Activating Write Cipher\n");
            clearFlightList(ssl);
            return rc;
        }

        /* The finished message had to hold off snapshoting the handshake
           hash because those updates are done in the encryptRecord call
           below for each message.  THAT was done because of a possible
           delay in a PKA op */
        rc = sslSnapshotHSHash(ssl, ssl->delayHsHash,
                ssl->flags & SSL_FLAGS_SERVER);
        if (rc <= 0)
        {
            psTraceErrr("Error snapshotting HS hash flight\n");
            psTraceIntInfo("sslSnapshotHSHash%d\n", rc);
            clearFlightList(ssl);
            return rc;
        }

# ifdef ENABLE_SECURE_REHANDSHAKES
        /* The rehandshake verify data is the previous handshake msg hash */
#  ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any))
        {
            if (ssl->myVerifyDataLen > 0)
            {
                Memcpy(ssl->omyVerifyData, ssl->myVerifyData,
                        ssl->myVerifyDataLen);
                ssl->omyVerifyDataLen = ssl->myVerifyDataLen;
            }
        }
#  endif    /* USE_DTLS */
        Memcpy(ssl->myVerifyData, ssl->delayHsHash, rc);
        ssl->myVerifyDataLen = rc;
# endif /* ENABLE_SECURE_REHANDSHAKES */
    } /* End SSL_HS_FINISHED processing */

    return PS_SUCCESS;
}

static int32 encryptFlight(ssl_t *ssl, unsigned char **end)
{
    flightEncode_t *msg, *remove;
    sslBuf_t out;

# if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
    sslBuf_t cvFlight;
# endif
    unsigned char *c, *origEnd;
    int32 rc;

    /* NEGATIVE ECDSA - save the end of the flight buffer */
    origEnd = *end;
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    if (!ssl->extCvSigOpPending)
    {
        ssl->extCvOrigFlightEnd = origEnd;
    }
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
        /* PS_VARIABLE_SET_BUT_UNUSED(origEnd); */

    msg = ssl->flightEncode;
    while (msg)
    {
# ifdef USE_TLS_1_3
        if (USING_TLS_1_3(ssl))
        {
            rc = tls13EncryptMessage(ssl, msg, end);
            if (rc < 0)
            {
                psTraceInfo("encryptFlightTls13 failed\n");
                clearFlightList(ssl);
                return rc;
            }
            goto encrypted;
        }
# endif
        c = msg->start + msg->len;

        rc = processFinished(ssl, msg);
        if (rc < 0)
        {
            return rc;
        }

        if (ssl->flags & SSL_FLAGS_NONCE_W
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
            && !ssl->extCvSigOpPending
# endif
            )
        {
            out.start = out.buf = out.end = msg->start - ssl->recordHeadLen -
                                            TLS_EXPLICIT_NONCE_LEN;
# ifdef USE_DTLS
            if (ACTV_VER(ssl, v_dtls_any))
            {
                /* nonce */
                *msg->seqDelay = ssl->epoch[0]; msg->seqDelay++;
                *msg->seqDelay = ssl->epoch[1]; msg->seqDelay++;
                *msg->seqDelay = ssl->rsn[0]; msg->seqDelay++;
                *msg->seqDelay = ssl->rsn[1]; msg->seqDelay++;
                *msg->seqDelay = ssl->rsn[2]; msg->seqDelay++;
                *msg->seqDelay = ssl->rsn[3]; msg->seqDelay++;
                *msg->seqDelay = ssl->rsn[4]; msg->seqDelay++;
                *msg->seqDelay = ssl->rsn[5]; msg->seqDelay++;
            }
            else
            {
# endif
            *msg->seqDelay = ssl->sec.seq[0]; msg->seqDelay++;
            *msg->seqDelay = ssl->sec.seq[1]; msg->seqDelay++;
            *msg->seqDelay = ssl->sec.seq[2]; msg->seqDelay++;
            *msg->seqDelay = ssl->sec.seq[3]; msg->seqDelay++;
            *msg->seqDelay = ssl->sec.seq[4]; msg->seqDelay++;
            *msg->seqDelay = ssl->sec.seq[5]; msg->seqDelay++;
            *msg->seqDelay = ssl->sec.seq[6]; msg->seqDelay++;
            *msg->seqDelay = ssl->sec.seq[7];
# ifdef USE_DTLS
        }
# endif
        }
        else
        {
            out.start = out.buf = out.end = msg->start - ssl->recordHeadLen;
        }

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
        if (msg->hsMsg == SSL_HS_CERTIFICATE_VERIFY)
        {
            /* This delayed PKA op has to be done mid flight encode because
                the contents of the signature is the hash of the handshake
                messages. */
            /* NEGATIVE ECDSA - Need psBuf_t to work in */
            cvFlight.start = cvFlight.buf = out.start;
#   ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
            if (ssl->extCvSigOpInUse)
            {
                cvFlight.end = ssl->extCvOrigFlightEnd;
            }
            else
#   endif   /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
            cvFlight.end = origEnd;
            cvFlight.size = ssl->insize - (cvFlight.end - cvFlight.buf);

            rc = nowDoCvPka(ssl, &cvFlight);
#   ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
            if (rc == PS_PENDING)
            {
                psAssert(ssl->extCvSigOpInUse);
                psAssert(ssl->extCvHash != NULL);
                psAssert(ssl->extCvHashLen >= 20);
                /* Now it's up to the caller of the library to provide
                   the signature and then retry. */
                return rc;
            }
#   endif   /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
            if (rc < 0)
                return rc;

            /* NEGATIVE ECDSA - account for message may have changed size */
            c = msg->start + msg->len;
            if (ssl->flags & SSL_FLAGS_AEAD_W)
            {
                out.start = out.buf = out.end
                    = (msg->start - ssl->recordHeadLen) - AEAD_NONCE_LEN(ssl);
            }
            else
            {
                out.start = out.buf = out.end = msg->start - ssl->recordHeadLen;
            }
        }
#  endif /* Client */
# endif  /* !PSK_ONLY */

# ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any) && msg->fragCount > 0)
        {
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
#   if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
            rc = dtlsEncryptFragRecord(ssl, msg, &out, &c);
#   endif /* SERVER || CLIENT_AUTH */
#  endif  /* PSK_ONLY */
        }
        else
        {
            rc = encryptRecord(ssl, msg->type, msg->hsMsg, msg->messageSize,
                msg->padLen, msg->start, &out, &c);
        }
# else
        rc = encryptRecord(ssl, msg->type, msg->hsMsg, msg->messageSize, msg->padLen,
            msg->start, &out, &c);
# endif /* DTLS */

        *end = c;
        goto encrypted;
    encrypted:
        if (rc == PS_PENDING)
        {
            /* Eat this message from flight encode, moving next to the front */
            /* Save how far along we are to be picked up next time */
            *end = msg->start + msg->messageSize - ssl->recordHeadLen;
            if (ssl->flags & SSL_FLAGS_AEAD_W)
            {
                *end -= AEAD_NONCE_LEN(ssl);
            }
            ssl->flightEncode = msg->next;
            psFree(msg, ssl->flightPool);
            return rc;
        }
        if (rc < 0)
        {
            psTraceIntInfo("Error encrypting record from flight %d\n", rc);
            clearFlightList(ssl);
            return rc;
        }
        remove = msg;
        ssl->flightEncode = msg = msg->next;
        psFree(remove, ssl->flightPool);
    }
    clearFlightList(ssl);

    return PS_SUCCESS;
}

/* One message flight requires 2 PKA "after" operations so need to store both */
pkaAfter_t *getPkaAfter(ssl_t *ssl)
{
    if (ssl->pkaAfter[0].type == 0)
    {
        return &ssl->pkaAfter[0];
    }
    else if (ssl->pkaAfter[1].type == 0)
    {
        return &ssl->pkaAfter[1];
    }
    else
    {
        return NULL;
    }
}

pkaAfter_t *getPkaAfterCv(ssl_t *ssl)
{
    int i;

    /* First look for the pkaAfter that was used previously by
       writeCertificateVerify. Reuse if found. */
    for (i = 0; i < 2; i++)
    {
        if (ssl->pkaAfter[i].type == PKA_AFTER_RSA_SIG_GEN_ELEMENT
            || ssl->pkaAfter[i].type == PKA_AFTER_ECDSA_SIG_GEN
            || ssl->pkaAfter[i].type == PKA_AFTER_RSA_SIG_GEN)
        {
            return &ssl->pkaAfter[i];
        }
    }
    /* Reusable pkaAfter not found, use a clean one. */
    return getPkaAfter(ssl);
}

void freePkaAfter(ssl_t *ssl)
{
    /* Just call clear twice */
    clearPkaAfter(ssl);
    clearPkaAfter(ssl);
}


/* Clear pkaAfter[0] and move pkaAfter[1] to [0].  Will be zeroed if no [1] */
void clearPkaAfter(ssl_t *ssl)
{
    if (ssl->pkaAfter[0].inbuf)
    {
        /* If it was a TMP_PKI pool with PENDING, it will have been saved
            aside in the pkaAfter.pool.  Otherwise, it's in handshake pool */
        if (ssl->pkaAfter[0].pool)
        {
            psFree(ssl->pkaAfter[0].inbuf, ssl->pkaAfter[0].pool);
        }
        else
        {
            psFree(ssl->pkaAfter[0].inbuf, ssl->hsPool);
        }
        ssl->pkaAfter[0].inbuf = NULL;
    }
    if (ssl->pkaAfter[0].pool)
    {
    }
    ssl->pkaAfter[0].type = 0;
    ssl->pkaAfter[0].outbuf = NULL;
    ssl->pkaAfter[0].data = NULL;
    ssl->pkaAfter[0].inlen = 0;
    ssl->pkaAfter[0].user = 0;

    if (ssl->pkaAfter[1].type != 0)
    {
        ssl->pkaAfter[0].type = ssl->pkaAfter[1].type;
        ssl->pkaAfter[0].outbuf = ssl->pkaAfter[1].outbuf;
        ssl->pkaAfter[0].data = ssl->pkaAfter[1].data;
        ssl->pkaAfter[0].inlen = ssl->pkaAfter[1].inlen;
        ssl->pkaAfter[0].user = ssl->pkaAfter[1].user;

        ssl->pkaAfter[1].type = 0;
        ssl->pkaAfter[1].outbuf = NULL;
        ssl->pkaAfter[1].data = NULL;
        ssl->pkaAfter[1].inlen = 0;
        ssl->pkaAfter[1].user = 0;
    }
}

/******************************************************************************/
/*
    Message size must account for any additional length a secure-write
    would add to the message.  It would be too late to check length in
    the writeRecordHeader() call since some of the handshake hashing could
    have already taken place and we can't rewind those hashes.
 */
static int32 secureWriteAdditions(ssl_t *ssl, int32 numRecs)
{
    int32 add = 0;

/*
    There is a slim chance for a false FULL message due to the fact that
    the maximum padding is being calculated rather than the actual number.
    Caller must simply grow buffer and try again.  Not subtracting 1 for
    the padding overhead to support NULL ciphers that will have 0 enBlockSize
 */
    if (ssl->flags & SSL_FLAGS_WRITE_SECURE)
    {
        add += (numRecs * ssl->enMacSize) +     /* handshake msg hash */
               (numRecs * (ssl->enBlockSize));  /* padding */
# ifdef USE_TLS_1_1
/*
         Checks here for TLS1.1 with block cipher for explict IV additions.
 */
        if (NGTD_VER(ssl, v_tls_explicit_iv) && (ssl->enBlockSize > 1))
        {
            add += (numRecs * ssl->enBlockSize); /* explicitIV */
        }
# endif /* USE_TLS_1_1 */
        if (ssl->flags & SSL_FLAGS_AEAD_W)
        {
            add += (numRecs * (AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl)));
        }
    }
    return add;
}

/******************************************************************************/
/*
    Write out a closure alert message (the only user initiated alert message)
    The user would call this when about to initate a socket close
    NOTICE: This is the internal function, there is a similarly named public
        API called matrixSslEncodeClosureAlert
 */
int32 sslEncodeClosureAlert(ssl_t *ssl, sslBuf_t *out, uint32 *reqLen)
{
/*
    If we've had a protocol error, don't allow further use of the session
 */
    if (ssl->flags & SSL_FLAGS_ERROR)
    {
        return MATRIXSSL_ERROR;
    }
    return writeAlert(ssl, SSL_ALERT_LEVEL_WARNING, SSL_ALERT_CLOSE_NOTIFY,
        out, reqLen);
}

/******************************************************************************/
/*
    Generic record header construction for alerts, handshake messages, and
    change cipher spec.  Determines message length for encryption and
    writes out to buffer up to the real message data.

    The FINISHED message is given special treatment here to move through the
    encrypted stages because the postponed flight encoding mechanism will
    not have moved to the SECURE_WRITE state until the CHANGE_CIPHER_SPEC
    has been encoded.  This means we have to look at the hsType and the
    ssl->cipher profile to see what is needed.

    Incoming messageSize is the plaintext message length plus the header
    lengths.
 */
int32_t writeRecordHeader(ssl_t *ssl, uint8_t type, uint8_t hsType,
    psSize_t *messageSize, uint8_t *padLen,
    unsigned char **encryptStart, const unsigned char *end,
    unsigned char **c)
{
    int32 messageData, msn;

    messageData = *messageSize - ssl->recordHeadLen;
    if (type == SSL_RECORD_TYPE_HANDSHAKE)
    {
        messageData -= ssl->hshakeHeadLen;
    }
    if (type == SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG)
    {
        messageData -= ssl->hshakeHeadLen;
        *messageSize = ssl->maxPtFrag + ssl->recordHeadLen;
        type = SSL_RECORD_TYPE_HANDSHAKE;
    }

# ifdef USE_TLS_1_1
/*
    If a block cipher is being used TLS 1.1 requires the use
    of an explicit IV.  This is an extra random block of data
    prepended to the plaintext before encryption.  Account for
    that extra length here. */
    if (hsType == SSL_HS_FINISHED && ACTV_VER(ssl, v_tls_explicit_iv))
    {
        if (ssl->cipher->blockSize > 1)
        {
            *messageSize += ssl->cipher->blockSize;
        }
    }
    else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
            ACTV_VER(ssl, v_tls_explicit_iv) &&
            (ssl->enBlockSize > 1))
    {
        *messageSize += ssl->enBlockSize;
    }
# endif /* USE_TLS_1_1 */

    /* This is to catch the FINISHED write for the postponed encode */
    if (hsType == SSL_HS_FINISHED)
    {
        if (ssl->cipher->flags &
            (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM))
        {
            *messageSize += AEAD_TAG_LEN(ssl) + TLS_EXPLICIT_NONCE_LEN;
        }
        else if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA)
        {
            *messageSize += AEAD_TAG_LEN(ssl);
        }
    }
    else if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        *messageSize += AEAD_TAG_LEN(ssl);

        /* In TLS 1.2, part of the nonce is explicit and must be
           sent over-the-wire. In TLS 1.3, it is fully implicit. */
        if (ACTV_VER(ssl, v_tls_explicit_iv))
        {
            *messageSize += AEAD_NONCE_LEN(ssl);
        }
    }
/*
    If this session is already in a secure-write state, determine padding.
    Again, the FINISHED message is explicitly checked due to the delay
    of the ActivateWriteCipher for flight encodings.  In this case, cipher
    sizes are taken from ssl->cipher rather than the active values
 */
    *padLen = 0;
    if (hsType == SSL_HS_FINISHED)
    {
        if (ssl->cipher->macSize > 0)
        {
            if (ssl->extFlags.truncated_hmac)
            {
                *messageSize += 10;
            }
            else
            {
                *messageSize += ssl->cipher->macSize;
            }
        }
        *padLen = psPadLenPwr2(*messageSize - ssl->recordHeadLen,
            ssl->cipher->blockSize);
        *messageSize += *padLen;
    }
    else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
             !(ssl->flags & SSL_FLAGS_AEAD_W))
    {
        *messageSize += ssl->enMacSize;
        *padLen = psPadLenPwr2(*messageSize - ssl->recordHeadLen,
            ssl->enBlockSize);
        *messageSize += *padLen;
    }

    if (end - *c < *messageSize)
    {
/*
        Callers other than sslEncodeResponse do not necessarily check for
        FULL before calling.  We do it here for them.
 */
        return SSL_FULL;
    }

# ifdef USE_DTLS
/*
    This routine does not deal with DTLS fragmented messages, but it was
    necessary to call for all the length computations to happen in here.
 */
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (*messageSize > ssl->pmtu)
        {
            psTraceIntDtls("Datagram size %d ", ssl->pmtu);
            psTraceIntDtls("too small for message: %d\n", *messageSize);
            return DTLS_MUST_FRAG;
        }
    }
# endif /* USE_DTLS */

    *c += psWriteRecordInfo(ssl, (unsigned char) type,
        *messageSize - ssl->recordHeadLen, *c, hsType);

/*
    All data written after this point is to be encrypted (if secure-write)
 */
    *encryptStart = *c;
    msn = 0;

# ifdef USE_TLS_1_1
/*
    Explicit IV notes taken from TLS 1.1 ietf draft.

    Generate a cryptographically strong random number R of
    length CipherSpec.block_length and prepend it to the plaintext
    prior to encryption. In this case either:

    The CBC residue from the previous record may be used
    as the mask. This preserves maximum code compatibility
    with TLS 1.0 and SSL 3. It also has the advantage that
    it does not require the ability to quickly reset the IV,
    which is known to be a problem on some systems.

    The data (R || data) is fed into the encryption process.
    The first cipher block containing E(mask XOR R) is placed
    in the IV field. The first block of content contains
    E(IV XOR data)
 */

    if (hsType == SSL_HS_FINISHED)
    {
        if (ACTV_VER(ssl, v_tls_explicit_iv) && (ssl->cipher->blockSize > 1))
        {
            if (psGetPrngLocked(*c, ssl->cipher->blockSize,
                    ssl->userPtr) < 0)
            {
                psTraceInfo("WARNING: psGetPrngLocked failed\n");
            }
            *c += ssl->cipher->blockSize;
        }
    }
    else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
             ACTV_VER(ssl, v_tls_explicit_iv) &&
             (ssl->enBlockSize > 1))
    {
        if (psGetPrngLocked(*c, ssl->enBlockSize, ssl->userPtr) < 0)
        {
            psTraceInfo("WARNING: psGetPrngLocked failed\n");
        }
        *c += ssl->enBlockSize;
    }
# endif /* USE_TLS_1_1 */

/*
    Handshake records have another header layer to write here
 */
    if (type == SSL_RECORD_TYPE_HANDSHAKE)
    {
# ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any))
        {
/*
            A message sequence number is unique for each handshake message. It
            is not incremented on a resend; that is the record sequence number.
 */
            msn = ssl->msn;
            ssl->msn++;
            /* These aren't useful anymore because of the seqDelay mechanism */
            /* psTraceIntDtls("RSN %d, ", ssl->rsn[5]); */
            /* psTraceIntDtls("MSN %d, ", msn); */
            /* psTraceIntDtls("Epoch %d\n", ssl->epoch[1]); */
        }
# endif /* USE_DTLS */
        *c += psWriteHandshakeHeader(ssl, (unsigned char) hsType, messageData,
            msn, 0, messageData, *c);
    }

    return PS_SUCCESS;
}


# ifdef USE_ZLIB_COMPRESSION
static int32 encryptCompressedRecord(ssl_t *ssl, int32 type, int32 messageSize,
    unsigned char *pt, sslBuf_t *out, unsigned char **c)
{
    unsigned char *encryptStart, *dataToMacAndEncrypt;
    int32 rc, ptLen, divLen, modLen, dataToMacAndEncryptLen;
    int32 zret, ztmp;
    int32 padLen;


    encryptStart = out->end + ssl->recordHeadLen;
    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        encryptStart += AEAD_NONCE_LEN(ssl); /* Move past the plaintext nonce */
        ssl->outRecType = (unsigned char) type;
    }
    ptLen = *c - encryptStart;

#  ifdef USE_TLS_1_1
    if (ACTV_VER(ssl, v_tls_explicit_iv) && (ssl->enBlockSize > 1))
    {
        /* Do not compress IV */
        if (type == SSL_RECORD_TYPE_APPLICATION_DATA)
        {
            /* FUTURE: Application data is passed in with real pt from user but
                with the length of the explict IV added already. Can just
                encrypt IV in-siture now since the rest of the encypts will be
                coming from zlibBuffer */
            rc = ssl->encrypt(ssl, encryptStart, encryptStart,
                ssl->enBlockSize);
            if (rc < 0)
            {
                psTraceIntInfo("Error encrypting IV: %d\n", rc);
                return MATRIXSSL_ERROR;
            }
            ptLen -= ssl->enBlockSize;
            encryptStart += ssl->enBlockSize;
        }
        else
        {
            /* Handshake messages have been passed in with plaintext that
                begins with the explicit IV and size included.  Can just
                encrypt IV in-situ now since the rest of the encypts will be
                coming from zlibBuffer */
            rc = ssl->encrypt(ssl, pt, pt, ssl->enBlockSize);
            if (rc < 0)
            {
                psTraceIntInfo("Error encrypting IV: %d\n", rc);
                return MATRIXSSL_ERROR;
            }
            pt += ssl->enBlockSize;
            ptLen -= ssl->enBlockSize;
            encryptStart += ssl->enBlockSize;
        }
    }
#  endif

    /* Compression is done only on the data itself so the prior work that
        was just put into message size calcuations and padding length will
        need to be done again after deflate */
    ssl->zlibBuffer = psMalloc(ssl->bufferPool, ptLen + MAX_ZLIB_COMPRESSED_OH);
    Memset(ssl->zlibBuffer, 0, ptLen + MAX_ZLIB_COMPRESSED_OH);
    if (ssl->zlibBuffer == NULL)
    {
        psTraceInfo("Error allocating compression buffer\n");
        return MATRIXSSL_ERROR;
    }
    dataToMacAndEncrypt = ssl->zlibBuffer;
    dataToMacAndEncryptLen = ssl->deflate.total_out; /* tmp for later */
    /* psTraceBytes("pre deflate", pt, ptLen); */
    ssl->deflate.avail_out = ptLen + MAX_ZLIB_COMPRESSED_OH;
    ssl->deflate.next_out = dataToMacAndEncrypt;
    ssl->deflate.avail_in = ztmp = ptLen;
    ssl->deflate.next_in = pt;

    /* FUTURE: Deflate would need to be in a smarter loop if large amounts
        of data are ever passed through here */
    if ((zret = deflate(&ssl->deflate, Z_SYNC_FLUSH)) != Z_OK)
    {
        psTraceIntInfo("ZLIB deflate error %d\n", zret);
        psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
        return MATRIXSSL_ERROR;
    }
    if (ssl->deflate.avail_in != 0)
    {
        psTraceIntInfo("ZLIB didn't deflate %d bytes in single pass\n", ptLen);
        psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
        deflateEnd(&ssl->deflate);
        return MATRIXSSL_ERROR;
    }

    dataToMacAndEncryptLen = ssl->deflate.total_out - dataToMacAndEncryptLen;
    /* psTraceBytes("post deflate", dataToMacAndEncrypt,
        dataToMacAndEncryptLen); */
    if (dataToMacAndEncryptLen > ztmp)
    {
        /* Case where compression grew the data.  Push out end */
        *c += dataToMacAndEncryptLen - ztmp;
    }
    else
    {
        /* Compression did good job to shrink. Pull back in */
        *c -= ztmp - dataToMacAndEncryptLen;
    }

    /* Can now calculate new padding length */
    padLen = psPadLenPwr2(dataToMacAndEncryptLen + ssl->enMacSize,
        ssl->enBlockSize);

    /* Now see how this has changed the data lengths */
    ztmp = dataToMacAndEncryptLen + ssl->recordHeadLen + ssl->enMacSize + padLen;

#  ifdef USE_TLS_1_1
    if (ACTV_VER(ssl, v_tls_explicit_iv) && (ssl->enBlockSize > 1))
    {
        ztmp += ssl->enBlockSize;
    }
#  endif

    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        psAssert(padLen == 0);
        /* This += works fine because padLen will be zero because enBlockSize
            and enMacSize are 0 */
        ztmp += AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl);

    }

    /* Possible the length hasn't changed if compression didn't do much */
    if (messageSize != ztmp)
    {
        messageSize = ztmp;
        ztmp -= ssl->recordHeadLen;
        out->end[3] = (ztmp & 0xFF00) >> 8;
        out->end[4] = ztmp & 0xFF;
    }

    if (type == SSL_RECORD_TYPE_HANDSHAKE)
    {
        sslUpdateHSHash(ssl, pt, ptLen);
    }

    if (ssl->generateMac)
    {
        *c += ssl->generateMac(ssl, (unsigned char) type,
            dataToMacAndEncrypt, dataToMacAndEncryptLen, *c);
    }

    *c += sslWritePad(*c, (unsigned char) padLen);

    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        *c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
                                    tag has not yet been accounted for */
    }

    /* Will always be non-insitu since the compressed data is in zlibBuffer.
        Requres two encrypts, one for plaintext and one for the
        any < blockSize remainder of the plaintext and the mac and pad  */
    if (ssl->cipher->blockSize > 1)
    {
        divLen = dataToMacAndEncryptLen & ~(ssl->cipher->blockSize - 1);
        modLen = dataToMacAndEncryptLen & (ssl->cipher->blockSize - 1);
    }
    else
    {
        if (ssl->flags & SSL_FLAGS_AEAD_W)
        {
            divLen = dataToMacAndEncryptLen + AEAD_TAG_LEN(ssl);
            modLen = 0;
        }
        else
        {
            divLen = dataToMacAndEncryptLen;
            modLen = 0;
        }
    }
    if (divLen > 0)
    {
        rc = ssl->encrypt(ssl, dataToMacAndEncrypt, encryptStart,
            divLen);
        if (rc < 0)
        {
            psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
            deflateEnd(&ssl->deflate);
            psTraceIntInfo("Error encrypting 2: %d\n", rc);
            return MATRIXSSL_ERROR;
        }
    }
    if (modLen > 0)
    {
        Memcpy(encryptStart + divLen, dataToMacAndEncrypt + divLen,
            modLen);
    }
    rc = ssl->encrypt(ssl, encryptStart + divLen,
        encryptStart + divLen, modLen + ssl->enMacSize + padLen);

    if (rc < 0 || (*c - out->end != messageSize))
    {
        psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
        deflateEnd(&ssl->deflate);
        psTraceIntInfo("Error encrypting 3: %d\n", rc);
        return MATRIXSSL_ERROR;
    }
    psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
    /* Will not need the context any longer since FINISHED is the only
        supported message */
    deflateEnd(&ssl->deflate);

#  ifdef USE_DTLS
/*
    Waited to increment record sequence number until completely finished
    with the encoding because the HMAC in DTLS uses the rsn of current record
 */
    if (ACTV_VER(ssl, v_dtls_any))
    {
        dtlsIncrRsn(ssl);
    }
#  endif /* USE_DTLS */

    return MATRIXSSL_SUCCESS;
}
# endif /* USE_ZLIB_COMPRESSION */

/******************************************************************************/
/*
    Flights are encypted after they are fully written so this function
    just moves the buffer forward to account for the encryption overhead that
    will be filled in later
 */
int32 postponeEncryptRecord(ssl_t *ssl, int32 type, int32 hsMsg,
    int32 messageSize, int32 padLen, unsigned char *pt,
    sslBuf_t *out, unsigned char **c)
{
    flightEncode_t *flight, *prev;
    unsigned char *encryptStart;
    int32 ptLen;

    if ((flight = psMalloc(ssl->flightPool, sizeof(flightEncode_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(flight, 0x0, sizeof(flightEncode_t));
    if (ssl->flightEncode == NULL)
    {
        ssl->flightEncode = flight;
    }
    else
    {
        prev = ssl->flightEncode;
        while (prev->next)
        {
            prev = prev->next;
        }
        prev->next = flight;
    }
    encryptStart = out->end + ssl->recordHeadLen;

    if (!(USING_TLS_1_3(ssl)))
    {
        if (hsMsg == SSL_HS_FINISHED)
        {
            if (ssl->cipher->flags & (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM))
            {
                encryptStart += TLS_EXPLICIT_NONCE_LEN;
            }
        }
        else if (ssl->flags & SSL_FLAGS_AEAD_W)
        {
             /* Move past the plaintext nonce */
            encryptStart += AEAD_NONCE_LEN(ssl);
        }
    }

    ptLen = (int32) (*c - encryptStart);

    flight->start = pt;
    flight->len = ptLen;
    flight->type = type;
    flight->padLen = padLen;
    flight->messageSize = messageSize;
    flight->hsMsg = hsMsg;
    flight->seqDelay = ssl->seqDelay;

    if (hsMsg == SSL_HS_FINISHED)
    {
        if (!(ssl->cipher->flags &
              (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_CCM)))
        {
            if (ssl->extFlags.truncated_hmac)
            {
                *c += 10;
            }
            else
            {
                *c += ssl->cipher->macSize;
            }
        }
        else
        {
            *c += ssl->cipher->macSize;
        }
    }
    else
    {
        *c += ssl->enMacSize;
    }
    *c += padLen;

    if (hsMsg == SSL_HS_FINISHED)
    {
        if (ssl->cipher->flags &
            (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_CCM))
        {
            *c += AEAD_TAG_LEN(ssl);
        }
    }
    else if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        *c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
                                    tag has not yet been accounted for */
    }

# ifdef USE_TLS_1_1
# endif /* USE_TLS_1_1 */

    if (*c - out->end != messageSize)
    {
        psTraceIntInfo("postponeEncryptRecord length test failed: wanted %d ",
            messageSize);
        psTraceIntInfo("but generated %d\n", (int32) (*c - out->end));
        return MATRIXSSL_ERROR;
    }
    return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
    Encrypt the message using the current cipher.  This call is used in
    conjunction with the writeRecordHeader() function above to finish writing
    an SSL record.  Updates handshake hash if necessary, generates message
    MAC, writes the padding, and does the encryption.

    messageSize is the final size, with header, mac and padding of the output
    messageSize - 5 = ssl.recLen
 * c - encryptStart = plaintext length
 */
int32 encryptRecord(ssl_t *ssl, int32 type, int32 hsMsgType,
    int32 messageSize, int32 padLen, unsigned char *pt,
    sslBuf_t *out, unsigned char **c)
{
    unsigned char *encryptStart;
    int32 rc, ptLen, divLen, modLen;

# ifdef USE_ZLIB_COMPRESSION
    /* In the current implementation, MatrixSSL will only internally handle
        the compression and decompression of the FINISHED message.  Application
        data will be compressed and decompressed by the caller.
        Re-handshakes are not supported and this would have been caught
        earlier in the state machine so if the record type is HANDSHAKE we
        can be sure this is the FINISHED message

        This should allow compatibility with SSL implementations that support
        ZLIB compression */
    if (ssl->flags & SSL_FLAGS_WRITE_SECURE && ssl->compression &&
        type == SSL_RECORD_TYPE_HANDSHAKE)
    {
        return encryptCompressedRecord(ssl, type, messageSize, pt, out, c);
    }
# endif

    encryptStart = out->end + ssl->recordHeadLen;

    if (!USING_TLS_1_3(ssl))
    {
        if (ssl->flags & SSL_FLAGS_AEAD_W)
        {
             /* Move past the plaintext nonce */
            encryptStart += AEAD_NONCE_LEN(ssl);
            ssl->outRecType = (unsigned char) type; /* Needed for AAD. */
        }
    }

    ptLen = (int32) (*c - encryptStart);
# ifdef USE_TLS
#  ifdef USE_TLS_1_1
    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
            ACTV_VER(ssl, v_tls_explicit_iv) && (ssl->enBlockSize > 1))
    {
/*
        Don't add the random bytes into the hash of the message.  Makes
        things very easy on the other side to simply discard the randoms
 */
        if (type == SSL_RECORD_TYPE_HANDSHAKE)
        {
            sslUpdateHSHash(ssl, pt + ssl->enBlockSize,
                ptLen - ssl->enBlockSize);
            if (hsMsgType == SSL_HS_CLIENT_KEY_EXCHANGE &&
                ssl->extFlags.extended_master_secret == 1)
            {
                if (tlsExtendedDeriveKeys(ssl) < 0)
                {
                    return MATRIXSSL_ERROR;
                }
            }
        }
        if (type == SSL_RECORD_TYPE_APPLICATION_DATA)
        {
            /* Application data is passed in with real pt from user but
                with the length of the explict IV added already */
            *c += ssl->generateMac(ssl, (unsigned char) type,
                pt, ptLen - ssl->enBlockSize, *c);
            /* While we are in here, let's see if this is an in-situ case */
            if (encryptStart + ssl->enBlockSize == pt)
            {
                pt = encryptStart;
            }
            else
            {
                /* Not in-situ.  Encrypt the explict IV now */
                if ((rc = ssl->encrypt(ssl, encryptStart,
                         encryptStart, ssl->enBlockSize)) < 0)
                {
                    psTraceIntInfo("Error encrypting explicit IV: %d\n", rc);
                    return MATRIXSSL_ERROR;
                }
                encryptStart += ssl->enBlockSize;
                ptLen -= ssl->enBlockSize;
            }
        }
        else
        {
            /* Handshake messages have been passed in with plaintext that
                begins with the explicit IV and size included */
            *c += ssl->generateMac(ssl, (unsigned char) type,
                pt + ssl->enBlockSize, ptLen - ssl->enBlockSize, *c);
        }
    }
    else
    {
#  endif /* USE_TLS_1_1 */
    if (type == SSL_RECORD_TYPE_HANDSHAKE)
    {
        if ((rc = sslUpdateHSHash(ssl, pt, ptLen)) < 0)
        {
            return rc;
        }
        /* Explicit state test for peforming the extended master secret
            calculation.  The sslUpdateHsHash immediately above has just
            ran the ClientKeyExchange message through the hash so now
            we can snapshot and create the key block */
        if (hsMsgType == SSL_HS_CLIENT_KEY_EXCHANGE &&
            ssl->extFlags.extended_master_secret == 1)
        {
            if (tlsExtendedDeriveKeys(ssl) < 0)
            {
                return MATRIXSSL_ERROR;
            }
        }
    }
    if (ssl->generateMac)
    {
        *c += ssl->generateMac(ssl, (unsigned char) type, pt, ptLen, *c);
    }
#  ifdef USE_TLS_1_1
}
#  endif /* USE_TLS_1_1 */
# else /* USE_TLS */
    if (type == SSL_RECORD_TYPE_HANDSHAKE)
    {
        sslUpdateHSHash(ssl, pt, ptLen);
    }
    *c += ssl->generateMac(ssl, (unsigned char) type, pt,
        ptLen, *c);
# endif /* USE_TLS */

    *c += sslWritePad(*c, (unsigned char) padLen);

    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        *c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
                                    tag has not yet been accounted for */
    }

    if (pt == encryptStart)
    {
        /* In-situ encode */
        rc = ssl->encrypt(ssl,
                pt,
                encryptStart,
                (uint32) (*c - encryptStart));
        if (rc < 0 || *c - out->end != messageSize)
        {
            psTraceIntInfo("Error encrypting 1: %d\n", rc);
            psTraceIntInfo("messageSize is %d\n", messageSize);
            psTraceIntInfo("pointer diff %d\n", (int) (*c - out->end));
            psTraceIntInfo("cipher suite %d\n", ssl->cipher->ident);
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        /*
            Non-insitu requres two encrypts, one for plaintext and one for the
            any < blockSize remainder of the plaintext and the mac and pad
         */
        if (ssl->flags & SSL_FLAGS_WRITE_SECURE)
        {
            if (ssl->cipher->blockSize > 1)
            {
                divLen = ptLen & ~(ssl->cipher->blockSize - 1);
                modLen = ptLen & (ssl->cipher->blockSize - 1);
            }
            else
            {
                if (ssl->flags & SSL_FLAGS_AEAD_W)
                {
                    divLen = ptLen + AEAD_TAG_LEN(ssl);
                    modLen = 0;
                }
                else
                {
                    divLen = ptLen;
                    modLen = 0;
                }
            }
            if (divLen > 0)
            {
                rc = ssl->encrypt(ssl, pt, encryptStart, divLen);
                if (rc < 0)
                {
                    psTraceIntInfo("Error encrypting 2: %d\n", rc);
                    return MATRIXSSL_ERROR;
                }
            }
            if (modLen > 0)
            {
                Memcpy(encryptStart + divLen, pt + divLen, modLen);
            }
            rc = ssl->encrypt(ssl, encryptStart + divLen,
                encryptStart + divLen, modLen + ssl->enMacSize + padLen);
        }
        else
        {
            rc = ssl->encrypt(ssl, pt, encryptStart,
                (uint32) (*c - encryptStart));
        }
        if (rc < 0 || (*c - out->end != messageSize))
        {
            psTraceIntInfo("Error encrypting 3: %d\n", rc);
            return MATRIXSSL_ERROR;
        }
    }
# ifdef USE_DTLS
/*
    Waited to increment record sequence number until completely finished
    with the encoding because the HMAC in DTLS uses the rsn of current record
 */
    if (ACTV_VER(ssl, v_dtls_any))
    {
        dtlsIncrRsn(ssl);
    }
# endif /* USE_DTLS */

    if (*c - out->end != messageSize)
    {
        psTraceInfo("encryptRecord length sanity test failed\n");
        return MATRIXSSL_ERROR;
    }
    return MATRIXSSL_SUCCESS;
}

# ifdef USE_SERVER_SIDE_SSL
int32 psGenerateServerRandom(ssl_t *ssl)
{
    /**
       @security RFC says to set the first 4 bytes to time, but best common practice is
       to use full 32 bytes of random. This is forward looking to TLS 1.3, and also works
       better for embedded platforms and FIPS secret key material.
       @see https://www.ietf.org/mail-archive/web/tls/current/msg09861.html
    */
#  ifdef SEND_HELLO_RANDOM_TIME
    /* First 4 bytes of the serverRandom are the unix time to prevent replay
       attacks, the rest are random */
    t = psGetTime(NULL, ssl->userPtr);
    ssl->sec.serverRandom[0] = (unsigned char) ((t & 0xFF000000) >> 24);
    ssl->sec.serverRandom[1] = (unsigned char) ((t & 0xFF0000) >> 16);
    ssl->sec.serverRandom[2] = (unsigned char) ((t & 0xFF00) >> 8);
    ssl->sec.serverRandom[3] = (unsigned char) (t & 0xFF);
    if (psGetPrngLocked(ssl->sec.serverRandom + 4,
                    SSL_HS_RANDOM_SIZE - 4, ssl->userPtr) < 0)
    {
        return MATRIXSSL_ERROR;
    }
#  else
    if (psGetPrngLocked(ssl->sec.serverRandom,
                    SSL_HS_RANDOM_SIZE, ssl->userPtr) < 0)
    {
        return MATRIXSSL_ERROR;
    }
#  endif

#  ifdef USE_TLS_1_3
    /*
      TLS 1.3 downgrade protection from 4.1.3:
      If we support TLS 1.3, but negotiated <1.3, we must set the last
      8 bytes of our server_random specially to indicate a downgrade.
      The client will check the 8-byte suffix; if present, and if the
      client also supports TLS 1.3, it will abort the handshake.
      The goal is to prevent active adversaries from downgrading the
      connection.
    */
    if (SUPP_VER(ssl, v_tls_1_3)) /* RFC, not draft. */
    {
        if (!NGTD_VER(ssl, v_tls_1_3_any))
        {
            const char *suffix;

            if (NGTD_VER(ssl, v_tls_1_2 | v_dtls_1_2))
            {
                suffix = TLS13_DOWNGRADE_PROT_TLS12;
            }
            else
            {
                suffix = TLS13_DOWNGRADE_PROT_TLS11_OR_BELOW;
            }
            Memcpy(ssl->sec.serverRandom + 24, suffix, 8);
        }
    }
#  endif /* USE_TLS_1_3 */

    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Write out the ServerHello message
 */
static int32 writeServerHello(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    psSize_t messageSize;
    uint8_t padLen;
    int32 t, rc, extLen = 0;

    psTracePrintHsMessageCreate(ssl, SSL_HS_SERVER_HELLO);

    c = out->end;
    end = out->buf + out->size;
/*
    Calculate the size of the message up front, and verify we have room
    We assume there will be a sessionId in the message, and make adjustments
    below if there is no sessionId.
 */
    messageSize =
        ssl->recordHeadLen +
        ssl->hshakeHeadLen +
        38 + SSL_MAX_SESSION_ID_SIZE;

#  ifdef ENABLE_SECURE_REHANDSHAKES
#   ifdef USE_DTLS
/*
    Can run into a problem if doing a new resumed handshake because the flight
    is SERVER_HELLO, CCS, and FINISHED which will populate myVerifyData
    which will confuse the resend logic here that we are doing a rehandshake.
    If peerVerifyData isn't available and we're doing a retransmit we know
    this is the problematic case so forget we have a myVerifyData
 */
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if ((ssl->secureRenegotiationFlag == PS_TRUE) && (ssl->retransmit == 1)
            && (ssl->myVerifyDataLen > 0) && (ssl->peerVerifyDataLen == 0))
        {
            ssl->myVerifyDataLen = 0;
        }
    }
#   endif
/*
    The RenegotiationInfo extension lengths are well known
 */
    if (ssl->secureRenegotiationFlag == PS_TRUE && ssl->myVerifyDataLen == 0)
    {
        extLen = 7; /* 00 05 ff 01 00 01 00 */
    }
    else if (ssl->secureRenegotiationFlag == PS_TRUE &&
             ssl->myVerifyDataLen > 0)
    {
        extLen = 2 + 5 + ssl->myVerifyDataLen + ssl->peerVerifyDataLen;
    }
#  endif /* ENABLE_SECURE_REHANDSHAKES */

#  ifdef USE_ECC_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
    {
        if (ssl->extFlags.got_elliptic_points == 1)
        {
            if (extLen == 0)
            {
                extLen = 2; /* if first extension, add two byte total len */
            }
            /* EXT_ELLIPTIC_POINTS - hardcoded to 'uncompressed' support */
            extLen += 6; /* 00 0B 00 02 01 00 */
        }
    }
#  endif /* USE_ECC_CIPHER_SUITE */

    if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN)
    {
        if (extLen == 0)
        {
            extLen = 2;
        }
        extLen += 5;
    }

    if (ssl->extFlags.truncated_hmac)
    {
        if (extLen == 0)
        {
            extLen = 2;
        }
        extLen += 4;
    }

    if (ssl->extFlags.extended_master_secret)
    {
        if (extLen == 0)
        {
            extLen = 2;
        }
        extLen += 4;
    }

#  ifdef USE_STATELESS_SESSION_TICKETS
    if (ssl->sid && ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT)
    {
        if (extLen == 0)
        {
            extLen = 2;
        }
        extLen += 4;
    }
#  endif

    /*
      Second condition is for renegotiations. Otherwise we would
      send an empty SNI extension as a response during renegotation,
      even when the latest ClientHello did not actually contain SNI.
    */
    if (ssl->extFlags.sni && ssl->extFlags.sni_in_last_client_hello)
    {
        if (extLen == 0)
        {
            extLen = 2;
        }
        extLen += 4;
    }
#  ifdef USE_OCSP_RESPONSE
    if (ssl->extFlags.status_request)
    {
        if (extLen == 0)
        {
            extLen = 2;
        }
        extLen += 4;
    }
#  endif /* USE_OCSP_RESPONSE */

#  ifdef USE_ALPN
    if (ssl->alpnLen)
    {
        if (extLen == 0)
        {
            extLen = 2;
        }
        extLen += 6 + 1 + ssl->alpnLen; /* 6 type/len + 1 len + data */
    }
#  endif

    messageSize += extLen;
    t = 1;
#  ifdef USE_DTLS
    if ((ACTV_VER(ssl, v_dtls_any)) && (ssl->retransmit == 1))
    {
/*
        All retransmits must generate identical handshake messages as the
        original.  This is to ensure both sides are running the same material
        through the handshake hash
 */
        t = 0;
    }
#  endif /* USE_DTLS */

    if (t)
    {
        rc = psGenerateServerRandom(ssl);
        if (rc < 0)
        {
            return rc;
        }
    }

/*
    We register session here because at this point the serverRandom value is
    populated.  If we are able to register the session, the sessionID and
    sessionIdLen fields will be non-NULL, otherwise the session couldn't
    be registered.
 */
    if (!(ssl->flags & SSL_FLAGS_RESUMED))
    {
        matrixRegisterSession(ssl);
    }
    messageSize -= (SSL_MAX_SESSION_ID_SIZE - ssl->sessionIdLen);

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_SERVER_HELLO, &messageSize, &padLen, &encryptStart,
             end, &c)) < 0)
    {
        return rc;
    }
/*
    First two fields in the ServerHello message are the major and minor
    SSL protocol versions we agree to talk with
 */
    *c = psEncodeVersionMaj(GET_ACTV_VER(ssl)); c++;
    *c = psEncodeVersionMin(GET_ACTV_VER(ssl)); c++;

    psTracePrintProtocolVersion(INDENT_HS_MSG,
            "server_version",
            *(c - 2), *(c - 1), 1);

/*
    The next 32 bytes are the server's random value, to be combined with
    the client random and premaster for key generation later
 */
    Memcpy(c, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
    c += SSL_HS_RANDOM_SIZE;
    psTracePrintHex(INDENT_HS_MSG,
            "random",
            ssl->sec.serverRandom,
            SSL_HS_RANDOM_SIZE,
            PS_TRUE);
/*
    The next data is a single byte containing the session ID length,
    and up to 32 bytes containing the session id.
    First register the session, which will give us a session id and length
    if not all session slots in the table are used
 */
    *c = (unsigned char) ssl->sessionIdLen; c++;
    if (ssl->sessionIdLen > 0)
    {
        Memcpy(c, ssl->sessionId, ssl->sessionIdLen);
        c += ssl->sessionIdLen;
    }
    psTracePrintHex(INDENT_HS_MSG,
            "session_id",
            ssl->sessionId,
            ssl->sessionIdLen,
            PS_TRUE);

/*
    Two byte cipher suite we've chosen based on the list sent by the client
    and what we support.
    One byte compression method (always zero)
 */
    *c = (ssl->cipher->ident & 0xFF00) >> 8; c++;
    *c = ssl->cipher->ident & 0xFF; c++;
#  ifdef USE_ZLIB_COMPRESSION
    if (ssl->compression)
    {
        *c = 1; c++;
    }
    else
    {
        *c = 0; c++;
    }
#  else
    *c = 0; c++;
#  endif

    if (extLen != 0)
    {
        extLen -= 2; /* Don't add self to total extension len */
        *c = (extLen & 0xFF00) >> 8; c++;
        *c = extLen & 0xFF; c++;

        if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN)
        {
            *c = 0x0; c++;
            *c = 0x1; c++;
            *c = 0x0; c++;
            *c = 0x1; c++;

            if (ssl->maxPtFrag == 0x200)
            {
                *c = 0x1; c++;
            }
            if (ssl->maxPtFrag == 0x400)
            {
                *c = 0x2; c++;
            }
            if (ssl->maxPtFrag == 0x800)
            {
                *c = 0x3; c++;
            }
            if (ssl->maxPtFrag == 0x1000)
            {
                *c = 0x4; c++;
            }
        }
        if (ssl->extFlags.truncated_hmac)
        {
            psTracePrintExtensionCreate(ssl, EXT_TRUNCATED_HMAC);
            *c = (EXT_TRUNCATED_HMAC & 0xFF00) >> 8; c++;
            *c = EXT_TRUNCATED_HMAC & 0xFF; c++;
            *c = 0; c++;
            *c = 0; c++;
        }
        if (ssl->extFlags.extended_master_secret)
        {
            psTracePrintExtensionCreate(ssl, EXT_EXTENDED_MASTER_SECRET);
            *c = (EXT_EXTENDED_MASTER_SECRET & 0xFF00) >> 8; c++;
            *c = EXT_EXTENDED_MASTER_SECRET & 0xFF; c++;
            *c = 0; c++;
            *c = 0; c++;
        }

#  ifdef USE_STATELESS_SESSION_TICKETS
        if (ssl->sid &&
            ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT)
        {
            /* This empty extension is ALWAYS an indication to the client that
                a NewSessionTicket handshake message will be sent */
            psTracePrintExtensionCreate(ssl, EXT_SESSION_TICKET);
            *c = (EXT_SESSION_TICKET & 0xFF00) >> 8; c++;
            *c = EXT_SESSION_TICKET & 0xFF; c++;
            *c = 0; c++;
            *c = 0; c++;
        }
#  endif

        /* For the second condition, see comment above. */
        if (ssl->extFlags.sni && ssl->extFlags.sni_in_last_client_hello)
        {
            psTracePrintExtensionCreate(ssl, EXT_SNI);
            *c = (EXT_SNI & 0xFF00) >> 8; c++;
            *c = EXT_SNI & 0xFF; c++;
            *c = 0; c++;
            *c = 0; c++;
        }
#  ifdef USE_OCSP_RESPONSE
        if (ssl->extFlags.status_request)
        {
            psTracePrintExtensionCreate(ssl, EXT_STATUS_REQUEST);
            *c = (EXT_STATUS_REQUEST & 0xFF00) >> 8; c++;
            *c = EXT_STATUS_REQUEST & 0xFF; c++;
            *c = 0; c++;
            *c = 0; c++;
        }
#  endif /* USE_OCSP_RESPONSE */

#  ifdef USE_ALPN
        if (ssl->alpnLen)
        {
            psTracePrintExtensionCreate(ssl, EXT_ALPN);
            *c = (EXT_ALPN & 0xFF00) >> 8; c++;
            *c = EXT_ALPN & 0xFF; c++;
            /* Total ext len can be hardcoded +3 because only one proto reply */
            *c = ((ssl->alpnLen + 3) & 0xFF00) >> 8; c++;
            *c = (ssl->alpnLen + 3) & 0xFF; c++;
            /* Can only ever be a reply of one proto so explict len +1 works */
            *c = ((ssl->alpnLen + 1) & 0xFF00) >> 8; c++;
            *c = (ssl->alpnLen + 1) & 0xFF; c++;
            *c = ssl->alpnLen; c++;
            Memcpy(c, ssl->alpn, ssl->alpnLen);
            c += ssl->alpnLen;
            psFree(ssl->alpn, ssl->sPool); ssl->alpn = NULL; /* app must store if needed */
            ssl->alpnLen = 0;
        }
#  endif

#  ifdef ENABLE_SECURE_REHANDSHAKES
        if (ssl->secureRenegotiationFlag == PS_TRUE)
        {
            /* RenegotiationInfo*/
            psTracePrintExtensionCreate(ssl, EXT_RENEGOTIATION_INFO);
            *c = (EXT_RENEGOTIATION_INFO & 0xFF00) >> 8; c++;
            *c = EXT_RENEGOTIATION_INFO & 0xFF; c++;
            if (ssl->myVerifyDataLen == 0)
            {
                *c = 0; c++;
                *c = 1; c++;
                *c = 0; c++;
            }
            else
            {
                *c = ((ssl->myVerifyDataLen + ssl->peerVerifyDataLen + 1) & 0xFF00) >> 8;
                c++;
                *c = (ssl->myVerifyDataLen + ssl->peerVerifyDataLen + 1) & 0xFF;
                c++;
                *c = (ssl->myVerifyDataLen + ssl->peerVerifyDataLen) & 0xFF; c++;
                Memcpy(c, ssl->peerVerifyData, ssl->peerVerifyDataLen);
                c += ssl->peerVerifyDataLen;
                Memcpy(c, ssl->myVerifyData, ssl->myVerifyDataLen);
                c += ssl->myVerifyDataLen;
                ssl->secureRenegotiationInProgress = PS_TRUE;
            }
        }
#  endif /* ENABLE_SECURE_REHANDSHAKES */

#  ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            if (ssl->extFlags.got_elliptic_points == 1)
            {
               /*
                  The ec_point_formats extension. We can hardcode this,
                  since we only support the uncompressed format.*/
                psTracePrintExtensionCreate(ssl, EXT_ELLIPTIC_POINTS);
                *c = (EXT_ELLIPTIC_POINTS & 0xFF00) >> 8; c++;
                *c = EXT_ELLIPTIC_POINTS & 0xFF; c++;
                *c = 0x00; c++;
                *c = 0x02; c++;
                *c = 0x01; c++;
                *c = 0x00; c++;
            }
        }
#  endif /* USE_ECC_CIPHER_SUITE */
    }

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_SERVER_HELLO, messageSize, padLen, encryptStart, out, &c))
        < 0)
    {
        return rc;
    }
/*
    If we're resuming a session, we now have the clientRandom, master and
    serverRandom, so we can derive keys which we'll be using shortly.
 */
    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        if ((rc = sslCreateKeys(ssl)) < 0)
        {
            return rc;
        }
    }
    out->end = c;

#  ifdef USE_MATRIXSSL_STATS
    matrixsslUpdateStat(ssl, SH_SENT_STAT, 1);
#  endif
    return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
    ServerHelloDone message is a blank handshake message
 */
static int32 writeServerHelloDone(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    int32_t rc;

    psTracePrintHsMessageCreate(ssl, SSL_HS_SERVER_HELLO_DONE);

    c = out->end;
    end = out->buf + out->size;
    messageSize =
        ssl->recordHeadLen +
        ssl->hshakeHeadLen;

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_SERVER_HELLO_DONE, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        return rc;
    }

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_SERVER_HELLO_DONE, messageSize, padLen, encryptStart, out,
             &c)) < 0)
    {
        return rc;
    }
    out->end = c;
    return MATRIXSSL_SUCCESS;
}
#  ifdef USE_PSK_CIPHER_SUITE
/******************************************************************************/
/*
    The PSK cipher version of ServerKeyExchange.  Was able to single this
    message out with a dedicated write simply due to the flight
    logic of DH ciphers.  The ClientKeyExchange message for PSK was rolled
    into the generic function, for example.
 */
static int32 writePskServerKeyExchange(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    unsigned char *hint;
    psSize_t messageSize;
    uint8_t padLen, hintLen;
    int32_t rc;

    psTracePrintHsMessageCreate(ssl, SSL_HS_SERVER_KEY_EXCHANGE);

#   ifdef USE_DHE_CIPHER_SUITE
/*
    This test prevents a second ServerKeyExchange from being written if a
    PSK_DHE cipher was choosen.  This is an ugly side-effect of the many
    combinations of cipher suites being supported in the 'flight' based
    state machine model
 */
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
        return MATRIXSSL_SUCCESS;
    }
#   endif /* USE_DHE_CIPHER_SUITE */

    if (matrixPskGetHint(ssl, &hint, &hintLen) < 0)
    {
        return MATRIXSSL_ERROR;
    }
    if (hint == NULL || hintLen == 0)
    {
        return MATRIXSSL_SUCCESS;
    }

    c = out->end;
    end = out->buf + out->size;

    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + hintLen + 2;

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_SERVER_KEY_EXCHANGE, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        return rc;
    }

    *c = 0; c++;
    *c = (hintLen & 0xFF); c++;
    Memcpy(c, hint, hintLen);
    c += hintLen;

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_SERVER_KEY_EXCHANGE, messageSize, padLen, encryptStart,
             out, &c)) < 0)
    {
        return rc;
    }
    out->end = c;
    return MATRIXSSL_SUCCESS;
}
#  endif /* USE_PSK_CIPHER_SUITE */

#  ifdef USE_STATELESS_SESSION_TICKETS /* Already inside a USE_SERVER_SIDE block */
static int32 writeNewSessionTicket(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    int32_t rc;

    psTracePrintHsMessageCreate(ssl, SSL_HS_NEW_SESSION_TICKET);

    c = out->end;
    end = out->buf + out->size;

    /* magic 6 is 4 bytes lifetime hint and 2 bytes len */
    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                  matrixSessionTicketLen() + 6;

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_NEW_SESSION_TICKET, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        return rc;
    }

    rc = (int32) (end - c);
    if (matrixCreateSessionTicket(ssl, c, &rc) < 0)
    {
        psTraceInfo("Error generating session ticket\n");
        return MATRIXSSL_ERROR;
    }
    c += rc;

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_NEW_SESSION_TICKET, messageSize, padLen, encryptStart, out,
             &c)) < 0)
    {
        return rc;
    }
    out->end = c;

    ssl->sid->sessionTicketState = SESS_TICKET_STATE_USING_TICKET;

    return PS_SUCCESS;
}
#  endif /* USE_STATELESS_SESSION_TICKETS */

#  ifdef USE_DHE_CIPHER_SUITE /* Already inside a USE_SERVER_SIDE block */
/******************************************************************************/
/*
    Write out the ServerKeyExchange message.
 */
static int32 writeServerKeyExchange(ssl_t *ssl, sslBuf_t *out, uint32 pLen,
    unsigned char *p, uint32 gLen, unsigned char *g)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize = 0;
    int32_t rc;

#   ifndef USE_ONLY_PSK_CIPHER_SUITE
    unsigned char *tbsStart;
    sslIdentity_t *chosen = ssl->chosenIdentity;
    int32_t skeSigAlg;
#   endif

#   if defined(USE_PSK_CIPHER_SUITE) && defined(USE_ANON_DH_CIPHER_SUITE)
    unsigned char *hint = NULL;
    uint8_t hintLen = 0;
#   endif /* USE_PSK_CIPHER_SUITE && USE_ANON_DH_CIPHER_SUITE */
#   ifdef USE_ECC_CIPHER_SUITE
    psSize_t eccPubKeyLen = 0;
#   endif /* USE_ECC_CIPHER_SUITE */

    psTracePrintHsMessageCreate(ssl, SSL_HS_SERVER_KEY_EXCHANGE);

    c = out->end;
    end = out->buf + out->size;

/*
    Calculate the size of the message up front, and verify we have room
 */
#   ifdef USE_ANON_DH_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_ANON_CIPHER)
    {
        messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                      6 + pLen + gLen + ssl->sec.dhKeyPriv->size;
#    ifdef USE_TLS_1_2
        if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
        {
            messageSize -= 2; /* hashSigAlg not going to be needed */
        }
#    endif

#    ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            if (matrixPskGetHint(ssl, &hint, &hintLen) < 0)
            {
                return MATRIXSSL_ERROR;
            }
            /*
              RFC4279: In the absence of an application profile specification
              specifying otherwise, servers SHOULD NOT provide an identity hint
              and clients MUST ignore the identity hint field.  Applications that
              do use this field MUST specify its contents, how the value is
              chosen by the TLS server, and what the TLS client is expected to do
              with the value.
              @note Unlike pure PSK cipher which will omit the ServerKeyExchange
              message if the hint is NULL, the DHE_PSK exchange simply puts
              two zero bytes in this case, since the message must still be sent
              to exchange the DHE public key.
            */
            messageSize += 2; /* length of hint (even if zero) */
            if (hintLen != 0 && hint != NULL)
            {
                messageSize += hintLen;
            }
        }
#    endif /* USE_PSK_CIPHER_SUITE */
    }
    else
    {
#   endif  /* USE_ANON_DH_CIPHER_SUITE */

#   ifdef USE_ECC_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
    {
        /* ExportKey portion */
        eccPubKeyLen = (ssl->sec.eccKeyPriv->curve->size * 2) + 1;

        if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA)
        {
            messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                eccPubKeyLen + 4 + chosen->privKey.keysize + 2;
        }
        else if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA)
        {
            messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + 6 +
                          eccPubKeyLen;
            /* NEGATIVE ECDSA - Adding ONE spot for a 0x0 byte in the
                ECDSA signature.  This will allow us to be right ~50% of
                the time and not require any manual manipulation

                However, if this is a 521 curve there is no chance
                the final byte could be negative if the full 66
                bytes are needed because there can only be a single
                low bit for that sig size.  So subtract that byte
                back out to stay around the 50% no-move goal */
            if (chosen->privKey.keysize != 132)
            {
                messageSize += 1;
            }
            messageSize += chosen->privKey.keysize;
            /* Signature portion */
            messageSize += 6;     /* 6 = 2 ASN_SEQ, 4 ASN_BIG */
            /* BIG EC KEY.  The sig is 2 bytes len, 1 byte SEQ,
                1 byte length (+1 OPTIONAL byte if length is >=128),
                1 byte INT, 1 byte rLen, r, 1 byte INT, 1 byte sLen, s.
                So the +4 here are the 2 INT and 2 rLen/sLen bytes on
                top of the keysize */
            if (chosen->privKey.keysize + 4 >= 128)
            {
                messageSize++;     /* Extra byte for 'long' asn.1 encode */
            }
#    ifdef USE_DTLS
            if ((ACTV_VER(ssl, v_dtls_any)) && (ssl->retransmit == 1))
            {
                /* We already know if this signature got resized */
                messageSize += ssl->ecdsaSizeChange;
            }
#    endif
        }
    }
    else
    {
#   endif  /* USE_ECC_CIPHER_SUITE */
#   ifdef REQUIRE_DH_PARAMS
    messageSize =
      ssl->recordHeadLen + ssl->hshakeHeadLen +
      8 + pLen + gLen + ssl->sec.dhKeyPriv->size;
#    ifdef USE_IDENTITY_CERTIFICATES
    messageSize += chosen->privKey.keysize;
#    endif
#   endif  /* REQUIRE_DH_PARAMS */

#   ifdef USE_ECC_CIPHER_SUITE
}
#   endif  /* USE_ECC_CIPHER_SUITE */
#   ifdef USE_ANON_DH_CIPHER_SUITE
}
#   endif /* USE_ANON_DH_CIPHER_SUITE */

    if (messageSize == 0)
    {
        /* This api was called without DHE, PSK and ECC enabled */
        return MATRIXSSL_ERROR;
    }
#   ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        messageSize += 2; /* hashSigAlg */
    }
#   endif
    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_SERVER_KEY_EXCHANGE, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        return rc;
    }
#   ifndef USE_ONLY_PSK_CIPHER_SUITE
    tbsStart = c;
#   endif

#   if defined(USE_PSK_CIPHER_SUITE) && defined(USE_ANON_DH_CIPHER_SUITE)
    /* PSK suites have a leading PSK identity hint (may be zero length) */
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {
        *c = 0; c++;
        *c = (hintLen & 0xFF); c++;
        if (hintLen != 0 && hint != NULL)
        {
            Memcpy(c, hint, hintLen);
            c += hintLen;
        }
    }
#   endif /* USE_PSK_CIPHER_SUITE && USE_ANON_DH_CIPHER_SUITE */

#   ifdef USE_ECC_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
    {
/*
        1 byte - ECCurveType (NamedCurve enum is 3)
         2 byte - NamedCurve id
 */
        *c = 3; c++; /* NamedCurve enum */
        *c = (ssl->sec.eccKeyPriv->curve->curveId & 0xFF00) >> 8; c++;
        *c = (ssl->sec.eccKeyPriv->curve->curveId & 0xFF); c++;
        *c = eccPubKeyLen & 0xFF; c++;
        if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv, c,
                &eccPubKeyLen) != 0)
        {
            return MATRIXSSL_ERROR;
        }
        c += eccPubKeyLen;

    }
    else
    {
#   endif
#   ifdef REQUIRE_DH_PARAMS
/*
        The message itself;
            2 bytes p len, p, 2 bytes g len, g, 2 bytes pubKeyLen, pubKey

        Size tests have all ready been taken care of a level up from this
 */
    *c = (pLen & 0xFF00) >> 8; c++;
    *c = pLen & 0xFF; c++;
    Memcpy(c, p, pLen);
    c += pLen;
    *c = (gLen & 0xFF00) >> 8; c++;
    *c = gLen & 0xFF; c++;
    Memcpy(c, g, gLen);
    c += gLen;
    *c = (ssl->sec.dhKeyPriv->size & 0xFF00) >> 8; c++;
    *c = ssl->sec.dhKeyPriv->size & 0xFF; c++;
    {
        psSize_t dhLen = end - c;
        if (psDhExportPubKey(ssl->hsPool, ssl->sec.dhKeyPriv, c, &dhLen) < 0)
        {
            return MATRIXSSL_ERROR;
        }
        psAssert(dhLen == ssl->sec.dhKeyPriv->size);
    }
    c += ssl->sec.dhKeyPriv->size;
#   endif /* REQUIRE_DH_PARAMS */
#   ifdef USE_ECC_CIPHER_SUITE
}
#   endif /* USE_ECC_CIPHER_SUITE */

# ifndef USE_ONLY_PSK_CIPHERSUITE
    if (ssl->flags & (SSL_FLAGS_DHE_WITH_RSA | SSL_FLAGS_DHE_WITH_DSA))
    {
        /* Message length been pre-computed, and we have written the public
           value and/or the PSK hint. Next we shall choose the signature
           algorithm, write the signature algorithm identifier (if (D)TLS 1.2)
           and setup pkaAfter for later signature generation. */

        /* 1. Determine hash and signature algorithm to use. */
        skeSigAlg = chooseSkeSigAlg(ssl, ssl->chosenIdentity);
        if (skeSigAlg < 0)
        {
            return skeSigAlg;
        }

        /* 2. Compute the hash. */
        /* 3. Setup pkaAfter_t for delayed signing op. */
        rc = tlsPrepareSkeSignature(ssl,
                skeSigAlg,
                tbsStart,
                c);
        if (rc < 0)
        {
            return rc;
        }
        c += rc;
    }
# endif /* USE_ONLY_PSK_CIPHERSUITE */

    rc = postponeEncryptRecord(ssl,
            SSL_RECORD_TYPE_HANDSHAKE,
            SSL_HS_SERVER_KEY_EXCHANGE,
            messageSize,
            padLen,
            encryptStart,
            out,
            &c);
    if (rc < 0)
    {
        return rc;
    }
    out->end = c;
    return MATRIXSSL_SUCCESS;
}
#  endif /* USE_DHE_CIPHER_SUITE */

/******************************************************************************/
/*
    Server initiated rehandshake public API call.
 */
int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out,
    uint32 *requiredLen)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    int32_t rc;

    *requiredLen = 0;
    psTracePrintHsMessageCreate(ssl, SSL_HS_HELLO_REQUEST);

    if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED)
    {
        psTraceInfo("SSL flag error in matrixSslEncodeHelloRequest\n");
        return MATRIXSSL_ERROR;
    }
    if (!(ssl->flags & SSL_FLAGS_SERVER) || (ssl->hsState != SSL_HS_DONE))
    {
        psTraceInfo("SSL state error in matrixSslEncodeHelloRequest\n");
        return MATRIXSSL_ERROR;
    }

    c = out->end;
    end = out->buf + out->size;
    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen;
    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_HELLO_REQUEST, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        *requiredLen = messageSize;
        return rc;
    }

    if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE, 0, messageSize,
             padLen, encryptStart, out, &c)) < 0)
    {
        return rc;
    }
    out->end = c;

    return MATRIXSSL_SUCCESS;
}
# else /* USE_SERVER_SIDE_SSL */
int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out,
    uint32 *requiredLen)
{
    psTraceInfo("Library not built with USE_SERVER_SIDE_SSL\n");
    return PS_UNSUPPORTED_FAIL;
}
# endif /* USE_SERVER_SIDE_SSL */


# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/*
    A fragmented write of the CERTIFICATE handhshake message.  This is the
    only handshake message that supports fragmentation because it is the only
    message where the 512byte plaintext max of the max_fragment extension can
    be exceeded.
 */
static int32 writeMultiRecordCertificate(ssl_t *ssl, sslBuf_t *out,
    int32 notEmpty, int32 totalClen, int32 lsize)
{
    psX509Cert_t *cert, *future;
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    uint32_t certLen;
    int32_t rc;
    int32 midWrite, midSizeWrite, countDown, firstOne = 1;

    c = out->end;
    end = out->buf + out->size;

    midSizeWrite = midWrite = certLen = 0;
    cert = NULL;

    while (totalClen > 0)
    {
        if (firstOne)
        {
            firstOne = 0;
            countDown = ssl->maxPtFrag;
            messageSize = totalClen + lsize + ssl->recordHeadLen + ssl->hshakeHeadLen;
            if ((rc = writeRecordHeader(ssl,
                     SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG, SSL_HS_CERTIFICATE,
                     &messageSize, &padLen, &encryptStart, end, &c)) < 0)
            {
                return rc;
            }
            /*  Write out the certs     */
            *c = (unsigned char) (((totalClen + (lsize - 3)) & 0xFF0000) >> 16);
            c++;
            *c = ((totalClen + (lsize - 3)) & 0xFF00) >> 8; c++;
            *c = ((totalClen + (lsize - 3)) & 0xFF); c++;
            countDown -= ssl->hshakeHeadLen + 3;

            if (notEmpty)
            {
                cert = ssl->chosenIdentity->cert;
                while (cert)
                {
                    if (cert->unparsedBin == NULL)
                    {
                        continue;
                    }
                    certLen = cert->binLen;
                    midWrite = 0;
                    if (certLen > 0)
                    {
                        if (countDown <= 3)
                        {
                            /* Fragment falls right on cert len write.  Has
                                to be at least one byte or countDown would have
                                been 0 and got us out of here already*/
                            *c = (unsigned char) ((certLen & 0xFF0000) >> 16);
                            c++; countDown--;
                            midSizeWrite = 2;
                            if (countDown != 0)
                            {
                                *c = (certLen & 0xFF00) >> 8; c++; countDown--;
                                midSizeWrite = 1;
                                if (countDown != 0)
                                {
                                    *c = (certLen & 0xFF); c++; countDown--;
                                    midSizeWrite = 0;
                                }
                            }
                            break;
                        }
                        else
                        {
                            *c = (unsigned char) ((certLen & 0xFF0000) >> 16);
                            c++;
                            *c = (certLen & 0xFF00) >> 8; c++;
                            *c = (certLen & 0xFF); c++;
                            countDown -= 3;
                        }
                        midWrite = min(certLen, countDown);
                        Memcpy(c, cert->unparsedBin, midWrite);
                        certLen -= midWrite;
                        c += midWrite;
                        totalClen -= midWrite;
                        countDown -= midWrite;
                        if (countDown == 0)
                        {
                            break;
                        }
                    }
                    cert = cert->next;
                }
            }
            if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
                     SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
                     &c)) < 0)
            {
                return rc;
            }
            out->end = c;
        }
        else
        {
            /* Not-first fragments */
            if (!cert)
            {
                return PS_FAIL;
            }
            if (midSizeWrite > 0)
            {
                messageSize = midSizeWrite;
            }
            else
            {
                messageSize = 0;
            }
            if ((certLen + messageSize) > ssl->maxPtFrag)
            {
                messageSize += ssl->maxPtFrag;
            }
            else
            {
                messageSize += certLen;
                if (cert->next != NULL)
                {
                    future = cert->next;
                    while (future != NULL)
                    {
                        if (messageSize + future->binLen + 3 >
                            (uint32) ssl->maxPtFrag)
                        {
                            messageSize = ssl->maxPtFrag;
                            future = NULL;
                        }
                        else
                        {
                            messageSize += 3 + future->binLen;
                            future = future->next;
                        }

                    }
                }
            }

            countDown = messageSize;
            messageSize += ssl->recordHeadLen;
            /* Second, etc... */
            if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE_FRAG,
                     SSL_HS_CERTIFICATE, &messageSize, &padLen, &encryptStart,
                     end, &c)) < 0)
            {
                return rc;
            }

            if (midSizeWrite > 0)
            {
                if (midSizeWrite == 2)
                {
                    *c = (certLen & 0xFF00) >> 8; c++;
                    *c = (certLen & 0xFF); c++;
                    countDown -= 2;
                }
                else
                {
                    *c = (certLen & 0xFF); c++;
                    countDown -= 1;
                }
                midSizeWrite = 0;
            }

            if (countDown < certLen)
            {
                Memcpy(c, cert->unparsedBin + midWrite, countDown);
                certLen -= countDown;
                c += countDown;
                totalClen -= countDown;
                midWrite += countDown;
                countDown = 0;
            }
            else
            {
                Memcpy(c, cert->unparsedBin + midWrite, certLen);
                c += certLen;
                totalClen -= certLen;
                countDown -= certLen;
                certLen -= certLen;
            }

            while (countDown > 0)
            {
                cert = cert->next;
                if (!cert)
                {
                    return PS_FAIL;
                }
                certLen = cert->binLen;
                midWrite = 0;
                if (countDown <= 3)
                {
                    /* Fragment falls right on cert len write */
                    *c = (unsigned char) ((certLen & 0xFF0000) >> 16);
                    c++; countDown--;
                    midSizeWrite = 2;
                    if (countDown != 0)
                    {
                        *c = (certLen & 0xFF00) >> 8; c++; countDown--;
                        midSizeWrite = 1;
                        if (countDown != 0)
                        {
                            *c = (certLen & 0xFF); c++; countDown--;
                            midSizeWrite = 0;
                        }
                    }
                    break;
                }
                else
                {
                    *c = (unsigned char) ((certLen & 0xFF0000) >> 16);
                    c++;
                    *c = (certLen & 0xFF00) >> 8; c++;
                    *c = (certLen & 0xFF); c++;
                    countDown -= 3;
                }
                midWrite = min(certLen, countDown);
                Memcpy(c, cert->unparsedBin, midWrite);
                certLen -= midWrite;
                c += midWrite;
                totalClen -= midWrite;
                countDown -= midWrite;
                if (countDown == 0)
                {
                    break;
                }

            }
            if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
                     SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
                     &c)) < 0)
            {
                return rc;
            }
            out->end = c;
        }
    }

    out->end = c;
    return MATRIXSSL_SUCCESS;
}
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
# endif /* USE_ONLY_PSK_CIPHER_SUITE */

#  if defined(USE_OCSP_RESPONSE) && defined(USE_SERVER_SIDE_SSL)
static int32 writeCertificateStatus(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    int32 rc;
    psSize_t messageSize, ocspLen;


    /* Easier to exclude this message internally rather than futher muddy the
        numerous #ifdef and ssl_t tests in the caller */
    if (ssl->extFlags.status_request == 0)
    {
        return MATRIXSSL_SUCCESS;
    }

    psTracePrintHsMessageCreate(ssl, SSL_HS_CERTIFICATE_STATUS);

    c = out->end;
    end = out->buf + out->size;

    ocspLen = ssl->keys->OCSPResponseBufLen;
    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + 4 + ocspLen;

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CERTIFICATE_STATUS, &messageSize, &padLen, &encryptStart,
             end, &c)) < 0)
    {
        return rc;
    }
    /*  struct {
          CertificateStatusType status_type;
          Select (status_type) {
              case ocsp: OCSPResponse;
          } response;
       } CertificateStatus; */
    *c = 0x1; c++;
    /* ocspLen is 16 bit value. */
    *c = 0; c++;
    *c = (ocspLen & 0xFF00) >> 8; c++;
    *c = (ocspLen & 0xFF); c++;
    Memcpy(c, ssl->keys->OCSPResponseBuf, ocspLen);
    c += ocspLen;

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CERTIFICATE_STATUS, messageSize, padLen, encryptStart, out,
             &c)) < 0)
    {
        return rc;
    }
    out->end = c;
    return MATRIXSSL_SUCCESS;

}
#  endif /* OCSP && SERVER_SIDE_SSL */

# ifdef USE_IDENTITY_CERTIFICATES
/******************************************************************************/
/*
    Write a Certificate message.
    The encoding of the message is as follows:
        3 byte length of certificate data (network byte order)
        If there is no certificate,
            3 bytes of 0
        If there is one certificate,
            3 byte length of certificate + 3
            3 byte length of certificate
            certificate data
        For more than one certificate:
            3 byte length of all certificate data
            3 byte length of first certificate
            first certificate data
            3 byte length of second certificate
            second certificate data
    Certificate data is the base64 section of an X.509 certificate file
    in PEM format decoded to binary.  No additional interpretation is required.
 */
static int32 writeCertificate(ssl_t *ssl, sslBuf_t *out, int32 notEmpty)
{
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    psX509Cert_t *cert;
    uint32 certLen;
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    int32 totalCertLen, lsize, ncerts = 0, rc;
    psSize_t messageSize;

    psTracePrintHsMessageCreate(ssl, SSL_HS_CERTIFICATE);

    if (!notEmpty)
    {
        psTraceInfo("No suitable cert available, so encoding an empty cert\n");
    }
#  ifdef USE_PSK_CIPHER_SUITE
/*
    Easier to exclude this message internally rather than futher muddy the
    numerous #ifdef and ssl->flags tests for DH, CLIENT_AUTH, and PSK states.
    A PSK or DHE_PSK cipher will never send this message
 */
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {
        return MATRIXSSL_SUCCESS;
    }
#  endif /* USE_PSK_CIPHER_SUITE */

    c = out->end;
    end = out->buf + out->size;

/*
    Determine total length of certs
 */
    totalCertLen = 0;
    if (notEmpty)
    {
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        if (ssl->chosenIdentity)
        {
            for (cert = ssl->chosenIdentity->cert, ncerts = 0;
                 cert;
                 cert = cert->next, ncerts++)
            {
                psAssert(cert->unparsedBin != NULL);
                totalCertLen += cert->binLen;
            }
        }
#  else
        return PS_DISABLED_FEATURE_FAIL;
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
    }

/*
    Account for the 3 bytes of certChain len for each cert and get messageSize
 */
    lsize = 3 + (ncerts * 3);

    /* TODO DTLS: Make sure this maxPtFrag is consistent with the fragment
        extension and is not interfering with DTLS notions of fragmentation */
    if ((totalCertLen + lsize + ssl->hshakeHeadLen) > ssl->maxPtFrag)
    {
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        return writeMultiRecordCertificate(ssl, out, notEmpty,
            totalCertLen, lsize);
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
    }
    else
    {
        messageSize =
            ssl->recordHeadLen +
            ssl->hshakeHeadLen +
            lsize + totalCertLen;

        if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
                 SSL_HS_CERTIFICATE, &messageSize, &padLen, &encryptStart,
                 end, &c)) < 0)
        {
#  ifdef USE_DTLS
            if (ACTV_VER(ssl, v_dtls_any))
            {
/*
                Is this the fragment case?
 */
                if (rc == DTLS_MUST_FRAG)
                {
                    rc = dtlsWriteCertificate(ssl, totalCertLen, lsize, c);
                    if (rc < 0)
                    {
                        return rc;
                    }
                    c += rc;
                    out->end = c;
                    return MATRIXSSL_SUCCESS;
                }
            }
#  endif    /* USE_DTLS */
            return rc;
        }

/*
        Write out the certs
 */
        *c = (unsigned char) (((totalCertLen + (lsize - 3)) & 0xFF0000) >> 16);
        c++;
        *c = ((totalCertLen + (lsize - 3)) & 0xFF00) >> 8; c++;
        *c = ((totalCertLen + (lsize - 3)) & 0xFF); c++;

#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        if (notEmpty)
        {
            if (ssl->chosenIdentity)
            {
                for (cert = ssl->chosenIdentity->cert; cert; cert = cert->next)
                {
                    if (!cert->unparsedBin)
                        continue;

                    certLen = cert->binLen;
                    if (certLen > 0)
                    {
                        *c = (unsigned char) ((certLen & 0xFF0000) >> 16); c++;
                        *c = (certLen & 0xFF00) >> 8; c++;
                        *c = (certLen & 0xFF); c++;
                        Memcpy(c, cert->unparsedBin, certLen);
                        c += certLen;
                    }
                }
            }
        }
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

        if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
                 SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
                 &c)) < 0)
        {
            return rc;
        }
        out->end = c;
    }
    return MATRIXSSL_SUCCESS;
}
# endif /* USE_IDENTITY_CERTIFICATES */

/******************************************************************************/
/*
    Write the ChangeCipherSpec message.  It has its own message type
    and contains just one byte of value one.  It is not a handshake
    message, so it isn't included in the handshake hash.
 */
static int32_t writeChangeCipherSpec(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    int32_t rc;

    psTracePrintChangeCipherSpecCreate(ssl);

    c = out->end;
    end = out->buf + out->size;
    messageSize = ssl->recordHeadLen + 1;

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC, 0,
             &messageSize, &padLen, &encryptStart, end, &c)) < 0)
    {
        return rc;
    }
    *c = 1; c++;

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC,
             0, messageSize, padLen, encryptStart, out, &c)) < 0)
    {
        return rc;
    }
    out->end = c;

    return MATRIXSSL_SUCCESS;
}

static int32 postponeSnapshotHSHash(ssl_t *ssl, unsigned char *c, int32 sender)
{
    ssl->delayHsHash = c;
# ifdef USE_TLS
    if (!ACTV_VER(ssl, v_ssl_3_0))
    {
        return TLS_HS_FINISHED_SIZE;
    }
    else
    {
# endif /* USE_TLS */
    return MD5_HASH_SIZE + SHA1_HASH_SIZE;
# ifdef USE_TLS
}
# endif /* USE_TLS */

}

/******************************************************************************/
/*
    Write the Finished message
    The message contains the 36 bytes, the 16 byte MD5 and 20 byte SHA1 hash
    of all the handshake messages so far (excluding this one!)
 */
static int32 writeFinished(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize, verifyLen;
    int32_t rc;

    psTracePrintHsMessageCreate(ssl, SSL_HS_FINISHED);

    c = out->end;
    end = out->buf + out->size;

    verifyLen = MD5_HASH_SIZE + SHA1_HASH_SIZE;
# ifdef USE_TLS
    if (!ACTV_VER(ssl, v_ssl_3_0))
    {
        verifyLen = TLS_HS_FINISHED_SIZE;
    }
# endif /* USE_TLS */
    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + verifyLen;

    rc = writeRecordHeader(ssl,
            SSL_RECORD_TYPE_HANDSHAKE,
            SSL_HS_FINISHED,
            &messageSize,
            &padLen,
            &encryptStart,
            end,
            &c);
    if (rc < 0)
    {
        return rc;
    }
/*
    Output the hash of messages we've been collecting so far into the buffer
 */
    c += postponeSnapshotHSHash(ssl, c, ssl->flags & SSL_FLAGS_SERVER);

    rc = postponeEncryptRecord(ssl,
            SSL_RECORD_TYPE_HANDSHAKE,
            SSL_HS_FINISHED,
            messageSize,
            padLen,
            encryptStart,
            out,
            &c);
    if (rc < 0)
    {
        return rc;
    }
    out->end = c;


# ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
/*
        Can't free the sec.cert buffer or close the handshake pool if
        using DTLS as we may be coming back around through this flight on
        a retransmit.  These frees are only taken care of once DTLS is
        positive the handshake has completed.
 */
        return MATRIXSSL_SUCCESS;
    }
# endif /* USE_DTLS */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    /* In client cases, there will be an outstanding PKA operation that
        could require the key from the cert so we can't free it yet */
    if (ssl->pkaAfter[0].type == 0)
    {
        if (!(ssl->bFlags & BFLAG_KEEP_PEER_CERTS))
        {
            if (ssl->sec.cert)
            {
                psX509FreeCert(ssl->sec.cert);
                ssl->sec.cert = NULL;
            }
        }
    }
#  endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
# endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

# ifdef ENABLE_SECURE_REHANDSHAKES
    /* Check if this was the last message in the handshake,
       indicating that the handshake is over. */
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        if (!(ssl->flags & SSL_FLAGS_RESUMED))
        {
            ssl->secureRenegotiationInProgress = PS_FALSE;
        }
    }
    else /* We're the client. */
    {
        if (ssl->flags & SSL_FLAGS_RESUMED)
        {
            ssl->secureRenegotiationInProgress = PS_FALSE;
        }
    }
# endif
    return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
    Write an Alert message
    The message contains two bytes: AlertLevel and AlertDescription
 */
static int32 writeAlert(ssl_t *ssl, unsigned char level,
    unsigned char description, sslBuf_t *out,
    uint32 *requiredLen)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    int32_t rc;

# ifdef USE_TLS_1_3
    if (USING_TLS_1_3(ssl))
    {
        return tls13EncodeAlert(ssl, description, out, requiredLen);
    }
# endif

    psTracePrintAlertEncodeInfo(ssl, description);

    c = out->end;
    end = out->buf + out->size;
    messageSize = 2 + ssl->recordHeadLen;

    /* Force the alert to WARNING if the spec says the alert MUST be that */
    if (description == (unsigned char) SSL_ALERT_NO_RENEGOTIATION)
    {
        level = (unsigned char) SSL_ALERT_LEVEL_WARNING;
        ssl->err = SSL_ALERT_NONE;
    }
#  ifdef SERVER_IGNORE_UNRECOGNIZED_SNI
    else if (description == (unsigned char) SSL_ALERT_UNRECOGNIZED_NAME)
    {
        level = (unsigned char) SSL_ALERT_LEVEL_WARNING;
        ssl->err = SSL_ALERT_NONE;
    }
#  endif
    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_ALERT, 0, &messageSize,
             &padLen, &encryptStart, end, &c)) < 0)
    {
        *requiredLen = messageSize;
        return rc;
    }
    *c = level; c++;
    *c = description; c++;

    if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_ALERT, 0, messageSize,
             padLen, encryptStart, out, &c)) < 0)
    {
        *requiredLen = messageSize;
        return rc;
    }
    out->end = c;
# ifdef USE_MATRIXSSL_STATS
    matrixsslUpdateStat(ssl, ALERT_SENT_STAT, (int32) (description));
# endif
    return MATRIXSSL_SUCCESS;
}

#ifdef USE_CLIENT_SIDE_SSL
# ifdef USE_TRUSTED_CA_INDICATION
static int32_t trustedCAindicationExtLen(psX509Cert_t *certs)
{
    psX509Cert_t *next;
    int32_t len;

    len = 0;
    /* Using the cert_sha1_hash identifier_type */
    next = certs;
    while (next)
    {
        len += 21;  /* 1 id_type, 20 hash */
        next = next->next;
    }
    return len;
}

static void writeTrustedCAindication(psX509Cert_t *certs, unsigned char **pp)
{
    psX509Cert_t *next;
    int32_t len;
    unsigned char *p = *pp;

    len = trustedCAindicationExtLen(certs);
    *p = (len & 0xFF00) >> 8; p++;
    *p = len & 0xFF; p++;

    next = certs;
    while (next)
    {
        *p = 0x3; p++; /* cert_sha1_hash */
        Memcpy(p, next->sha1CertHash, 20);
        p += 20;
        next = next->next;
    }
    psAssert((p - *pp) == (len + 2));
    *pp = p;
}
# endif /* USE_TRUSTED_CA_INDICATION */

/******************************************************************************/
/*
    Write out the ClientHello message to a buffer
 */
int32_t matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
    const psCipher16_t cipherSpecs[], uint8_t cipherSpecLen,
    uint32 *requiredLen, tlsExtension_t *userExt, sslSessOpts_t *options)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    int32 rc, t;
    psSize_t messageSize, cipherLen, cookieLen, addRenegotiationScsv;
    tlsExtension_t *ext;
    uint32 extLen;
    short i, useTicket;
#  ifdef USE_TLS_1_2
    psSize_t sigHashLen, sigHashFlags;
    /* 2b len + 2b * MAX sig hash combos */
    unsigned char sigHash[2 + TLS_MAX_SIGNATURE_ALGORITHMS * 2];
#  endif
#  ifdef USE_ECC_CIPHER_SUITE
    unsigned char eccCurveList[32];
    uint8_t curveListLen;
#  endif /* USE_ECC_CIPHER_SUITE */
#  ifdef USE_DTLS
    unsigned char *extStart = NULL;
    int cipherCount;
#  endif

    psTracePrintHsMessageCreate(ssl, SSL_HS_CLIENT_HELLO);

    *requiredLen = 0;
    if (out == NULL || out->buf == NULL || ssl == NULL || options == NULL)
    {
        return PS_ARG_FAIL;
    }
    if (cipherSpecLen > 0 && (cipherSpecs == NULL || cipherSpecs[0] == 0))
    {
        return PS_ARG_FAIL;
    }
    if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED)
    {
        psTraceInfo("SSL flag error in matrixSslEncodeClientHello\n");
        return MATRIXSSL_ERROR;
    }
    if (ssl->flags & SSL_FLAGS_SERVER || (ssl->hsState != SSL_HS_SERVER_HELLO &&
                                          ssl->hsState != SSL_HS_DONE &&
                                          ssl->hsState != SSL_HS_HELLO_REQUEST ))
    {
        psTraceInfo("SSL state error in matrixSslEncodeClientHello\n");
        return MATRIXSSL_ERROR;
    }

    sslInitHSHash(ssl);

    cookieLen = 0;
#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        /* TODO DTLS make sure a block cipher suite is being used */
        if (ssl->haveCookie)
        {
            cookieLen = ssl->cookieLen + 1; /* account for length byte */
        }
        else
        {
            cookieLen = 1; /* Always send the length (0) even if no cookie */
        }
        /* save for next time called for VERIFY_REQUEST response */
        ssl->cipherSpecLen = min(8, cipherSpecLen); /* 8 is arbitrary limit */
        for (cipherCount = 0; cipherCount < ssl->cipherSpecLen; cipherCount++)
        {
            ssl->cipherSpec[cipherCount] = cipherSpecs[cipherCount];
        }
    }
#  endif
    /* If no resumption, clear the RESUMED flag in case the caller is
        attempting to bypass matrixSslEncodeRehandshake. */
    if (ssl->sessionIdLen <= 0)
    {
        ssl->flags &= ~SSL_FLAGS_RESUMED;
    }

    if (cipherSpecLen == 0 || cipherSpecs == NULL || cipherSpecs[0] == 0)
    {
        if ((cipherLen = sslGetCipherSpecListLen(ssl)) == 2)
        {
            psTraceInfo("No cipher suites enabled (or no key material)\n");
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        /* If ciphers are specified it is two bytes length and two bytes data */
        cipherLen = 2;
        for (i = 0; i < cipherSpecLen; i++)
        {
            const sslCipherSpec_t *cipherDetails;

            cipherDetails = sslGetCipherSpec(ssl, cipherSpecs[i]);
            if (cipherDetails == NULL)
            {
                psTracePrintCiphersuiteName(0,
                        "Ciphersuite not supported",
                        cipherSpecs[i],
                        PS_TRUE);
                return PS_UNSUPPORTED_FAIL;
            }
            cipherLen += 2;
        }
    }

    addRenegotiationScsv = 0;
#  ifdef ENABLE_SECURE_REHANDSHAKES
    /* Initial CLIENT_HELLO will use the SCSV mechanism for greatest compat */
    if (ssl->myVerifyDataLen == 0)
    {
        cipherLen += 2; /* signalling cipher id 0x00FF */
        addRenegotiationScsv = 1;
    }
#  endif
    if (options->fallbackScsv)
    {
        if (ACTV_VER(ssl, psVerGetHighestTls(v_compiled_in)))
        {
            /** If a client sets ClientHello.client_version to its highest
               supported protocol version, it MUST NOT include TLS_FALLBACK_SCSV.
               @see https://tools.ietf.org/html/rfc7507#section-4 */
            psTraceInfo("Cannot set fallbackScsv if using maximum supported TLS version.\n");
            return MATRIXSSL_ERROR;
        }
        if (ssl->sessionIdLen > 0)
        {
            /** when a client intends to resume a session and sets ClientHello.client_version
               to the protocol version negotiated for that session, it MUST NOT include
               TLS_FALLBACK_SCSV.
               @see https://tools.ietf.org/html/rfc7507#section-4 */
            psTraceInfo("Cannot set fallbackScsv if attempting to resume a connection.\n");
            return MATRIXSSL_ERROR;
        }
        cipherLen += 2; /* signalling cipher id 0x5600 */
        ssl->extFlags.req_fallback_scsv = 1;
    }
    else
    {
        /** If a client sends a ClientHello.client_version containing a lower
           value than the latest (highest-valued) version supported by the
           client, it SHOULD include the TLS_FALLBACK_SCSV.
           @see https://tools.ietf.org/html/rfc7507#section-4
           We warn because this is a SHOULD not a MUST.
           @security The only reason (outside testing) that we should propose a TLS version
           lower than what we support is if we had already tried to negotiate the highest
           version but the server did not support it. In that case, the fallbackScsv
           option should have been specified to mitigate version rollback attacks.
         */
        if (!ACTV_VER(ssl, psVerGetHighestTls(v_compiled_in)))
        {
            psTraceInfo("Warning, if this is a fallback connection, set fallbackScsv?\n");
        }
    }

    /* Calculate the size of the message up front, and write header */
    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                  5 + SSL_HS_RANDOM_SIZE + ssl->sessionIdLen + cipherLen + cookieLen;

#  ifdef USE_ZLIB_COMPRESSION
    messageSize += 1;
#  endif

    /* Extension lengths */
    extLen = 0;

    /* Max Fragment extension request */
    ssl->maxPtFrag = SSL_MAX_PLAINTEXT_LEN;
    if (!ACTV_VER(ssl, v_ssl_3_0) && (options->maxFragLen > 0) &&
        (options->maxFragLen < SSL_MAX_PLAINTEXT_LEN))
    {
        if (options->maxFragLen == 0x200 ||
            options->maxFragLen == 0x400 ||
            options->maxFragLen == 0x800 ||
            options->maxFragLen == 0x1000)
        {
            extLen = 2 + 5; /* 2 for total ext len + 5 for ourselves */
            ssl->maxPtFrag = options->maxFragLen;
            /* Also indicate that we're requesting a different plaintext size */
            ssl->maxPtFrag |= 0x10000;
        }
        else
        {
            psTraceInfo("Unsupported maxFragLen value to session options\n");
            return PS_ARG_FAIL;
        }
    }

    if (options->truncHmac)
    {
        if (extLen == 0)
        {
            extLen = 2; /* First extension found so total len */
        }
        extLen += 4;    /* empty "extension_data" */
    }

    if (options->extendedMasterSecret >= 0)
    {
        if (extLen == 0)
        {
            extLen = 2; /* First extension found so total len */
        }
        extLen += 4;    /* empty extension */
    }

#  ifdef USE_TRUSTED_CA_INDICATION
    if (options->trustedCAindication)
    {
        if (extLen == 0)
        {
            extLen = 2; /* First extension found so total len */
        }
        /* Magic 4 is extension id and length as usual */
        extLen += trustedCAindicationExtLen(ssl->keys->CAcerts) + 4;
    }
#  endif

#  ifdef ENABLE_SECURE_REHANDSHAKES
    /* Subsequent CLIENT_HELLOs must use a populated RenegotiationInfo extension */
    if (ssl->myVerifyDataLen != 0)
    {
        if (extLen == 0)
        {
            extLen = 2;                     /* First extension found so total len */
        }
        extLen += ssl->myVerifyDataLen + 5; /* 5 type/len/len */
    }
#  endif /* ENABLE_SECURE_REHANDSHAKES */

#  ifdef USE_ECC_CIPHER_SUITE
    curveListLen = 0;
    if (eccSuitesSupported(ssl, cipherSpecs, cipherSpecLen))
    {
        uint32_t ecFlags = options->ecFlags;

        /* Getting the curve list from crypto directly */
        curveListLen = sizeof(eccCurveList);
# ifdef USE_SEC_CONFIG
        /* Allow security profile to override the ECC curve list. */
        if (ssl->ecFlagsOverride != 0)
        {
            ecFlags = ssl->ecFlagsOverride;
        }
# endif
        if (ecFlags)
        {
            userSuppliedEccList(eccCurveList, &curveListLen, ecFlags);
        }
        else
        {
            /* Use all that are enabled */
            psGetEccCurveIdList(eccCurveList, &curveListLen);
        }
        if (curveListLen > 0)
        {
            if (extLen == 0)
            {
                extLen = 2; /* First extension found so total len */
            }
            /* EXT_ELLIPTIC_CURVE */
            extLen += curveListLen + 6; /* 2 id, 2 for ext len, 2 len */
            /* EXT_ELLIPTIC_POINTS - hardcoded to 'uncompressed' support */
            extLen += 6;                /* 00 0B 00 02 01 00 */
        }
    }
#  endif /* USE_ECC_CIPHER_SUITE */

    useTicket = 0;
#  ifdef USE_STATELESS_SESSION_TICKETS
    if (options && options->ticketResumption == 1)
    {
        useTicket = 1;
    }
    if (useTicket && ssl->sid)
    {
        if (extLen == 0)
        {
            extLen = 2; /* First extension found so total len */
        }
        extLen += 4;    /* 2 type, 2 length */
        if (ssl->sid->sessionTicketLen > 0 &&
            ssl->sid->sessionTicketState == SESS_TICKET_STATE_USING_TICKET)
        {
            extLen += ssl->sid->sessionTicketLen;
        }
    }
#  endif

#  ifdef USE_OCSP_RESPONSE
    if (options && options->OCSPstapling == 1)
    {
        if (extLen == 0)
        {
            extLen = 2;  /* First extension found so total len */
        }
        /* Currently only supporting an empty status_request extension */
        extLen += 9;
    }
#  endif /* USE_OCSP_RESPONSE */

#  ifdef USE_TLS_1_2
    /*
        TLS 1.2 clients must add the SignatureAndHashAlgorithm extension,
        (although not sending them implies SHA-1, and it's unused for
        non-certificate based ciphers like PSK).
        Sending all the algorithms that are enabled at compile time unless
        restricted by the matrixSslSessOptsSetSigAlgs API.
        enum {
          none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
          sha512(6), (255)
        } HashAlgorithm;
        enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SigAlgorithm;
     */

#   define ADD_SIG_HASH(A, B) \
    { \
        sigHashFlags |= HASH_SIG_MASK(A, B); \
        sigHash[sigHashLen] = A; \
        sigHash[sigHashLen + 1] = B; \
        sigHashLen += 2; \
    }
    sigHashFlags = 0;
    sigHashLen = 2;     /* Length of buffer, Start with 2b len */

    for (i = 0; i < ssl->supportedSigAlgsLen; i++)
    {
        ADD_SIG_HASH((ssl->supportedSigAlgs[i] & 0xff00) >> 8,
                     ssl->supportedSigAlgs[i] & 0xff);
    }
#   undef ADD_SIG_HASH

    /* First two bytes is the byte count of remaining data */
    /* Note that in PSK mode, there will be no supported sig alg hashes */
    sigHash[0] = 0x0;
    sigHash[1] = sigHashLen - 2;    /* 2 b len*/

    if (extLen == 0)
    {
        extLen = 2;               /* First extension found so total len */
    }
    extLen += 2 + 2 + sigHashLen; /* 2 ext type, 2 ext length */

    /* On the client side, the value is set to the algorithms offered */
    ssl->hashSigAlg = sigHashFlags;

# ifdef USE_SSL_INFORMATIONAL_TRACE_VERBOSE
    psTracePrintSigAlgs(ssl->hashSigAlg, "Our ClientHello");
# endif
#  endif /* USE_TLS_1_2 */

    /* Add any user-provided extensions. */
    psAddUserExtToSession(ssl, userExt);
    ext = userExt;
    if (ext && extLen == 0)
    {
        extLen = 2; /* Start with the initial len */
    }
    while (ext)
    {
        extLen += ext->extLen + 4; /* +4 for type and length of each */
        ext = ext->next;
    }

#  ifdef USE_DTLS
    if ((ACTV_VER(ssl, v_dtls_any)) && (ssl->helloExtLen > 0))
    {
        /* Override all the extension calculations and just grab what was
            sent the first time.  Can't rebuild because there is no good line
            between the extensions we add and the extensions the user adds and
            no user extensions will have been passed in here on a retransmit */
        extLen = ssl->helloExtLen;
    }
#  endif
    messageSize += extLen;

    c = out->end;
    end = out->buf + out->size;

    rc = writeRecordHeader(ssl,
            SSL_RECORD_TYPE_HANDSHAKE,
            SSL_HS_CLIENT_HELLO,
            &messageSize,
            &padLen,
            &encryptStart,
            end,
            &c);
    if (rc < 0)
    {
        *requiredLen = messageSize;
        return rc;
    }

    t = 1;
#  ifdef USE_DTLS
/*
    Test if this is DTLS response to the HelloVerify server message.
    If so, we use the exact same one (+cookie) as before to prove to the
    server we are legit.  The only thing that should change in this message
    is the client random so we make sure to use the original one

      struct {
        ProtocolVersion client_version;
        Random random;
        SessionID session_id;
        opaque cookie<0..32>;                             // New field
        CipherSuite cipher_suites<2..2^16-1>;
        CompressionMethod compression_methods<1..2^8-1>;
      } ClientHello;
 */
    if ((ACTV_VER(ssl, v_dtls_any)) && (ssl->haveCookie))
    {
        t = 0;
    }
    /* Also test for retransmit */
    if ((ACTV_VER(ssl, v_dtls_any)) && (ssl->retransmit == 1))
    {
        t = 0;
    }
#  endif

    if (t)
    {
        /**     @security RFC says to set the first 4 bytes to time, but best common practice is
            to use full 32 bytes of random. This is forward looking to TLS 1.3, and also works
            better for embedded platforms and FIPS secret key material.
            @see https://www.ietf.org/mail-archive/web/tls/current/msg09861.html */
#  ifdef SEND_HELLO_RANDOM_TIME
        /*      First 4 bytes of the serverRandom are the unix time to prevent
            replay attacks, the rest are random */
        t = psGetTime(NULL, ssl->userPtr);
        ssl->sec.clientRandom[0] = (unsigned char) ((t & 0xFF000000) >> 24);
        ssl->sec.clientRandom[1] = (unsigned char) ((t & 0xFF0000) >> 16);
        ssl->sec.clientRandom[2] = (unsigned char) ((t & 0xFF00) >> 8);
        ssl->sec.clientRandom[3] = (unsigned char) (t & 0xFF);
        if ((rc = psGetPrngLocked(ssl->sec.clientRandom + 4,
                 SSL_HS_RANDOM_SIZE - 4, ssl->userPtr)) < PS_SUCCESS)
        {
            return rc;
        }
#  else
        if ((rc = psGetPrngLocked(ssl->sec.clientRandom,
                 SSL_HS_RANDOM_SIZE, ssl->userPtr)) < PS_SUCCESS)
        {
            return rc;
        }
#  endif
    }

/*
    First two fields in the ClientHello message are the maximum major
    and minor SSL protocol versions we support.
 */
    *c = psEncodeVersionMaj(GET_ACTV_VER(ssl)); c++;
    *c = psEncodeVersionMin(GET_ACTV_VER(ssl)); c++;
    psTracePrintProtocolVersionNew(INDENT_HS_MSG,
            "client_version",
            GET_ACTV_VER(ssl),
            PS_TRUE);
    /* Active version may get overridden by the result of the version
       negotiation, so save it. ClientHello.client_version is needed
       for RSA premaster calculation in TLS 1.2 and below. */
    ssl->ourHelloVersion = GET_ACTV_VER(ssl);

/*
    The next 32 bytes are the server's random value, to be combined with
    the client random and premaster for key generation later
 */
    Memcpy(c, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
    c += SSL_HS_RANDOM_SIZE;
    psTracePrintHex(INDENT_HS_MSG,
            "client_random",
            ssl->sec.clientRandom,
            SSL_HS_RANDOM_SIZE,
            PS_TRUE);

/*
    The next data is a single byte containing the session ID length,
    and up to 32 bytes containing the session id.
    If we are asking to resume a session, then the sessionId would have
    been set at session creation time.
 */
    *c = (unsigned char) ssl->sessionIdLen; c++;
    if (ssl->sessionIdLen > 0)
    {
        Memcpy(c, ssl->sessionId, ssl->sessionIdLen);
        c += ssl->sessionIdLen;
#  ifdef USE_MATRIXSSL_STATS
        matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#  endif
    }
    psTracePrintHex(INDENT_HS_MSG,
            "session_id",
            ssl->sessionId,
            ssl->sessionIdLen,
            PS_TRUE);

#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (ssl->haveCookie)
        {
            *c = (unsigned char) ssl->cookieLen; c++;
            Memcpy(c, ssl->cookie, ssl->cookieLen);
            c += ssl->cookieLen;
        }
        else
        {
            /*  This condition is an empty cookie client hello.  Still must
                send a zero length specifier. */
            *c = 0; c++;
        }
        psTracePrintHex(INDENT_HS_MSG,
                "cookie",
                ssl->cookie,
                ssl->haveCookie ? ssl->cookieLen : 0,
                PS_TRUE);
    }
#  endif
/*
    Write out the length and ciphers we support
    Client can request a single specific cipher in the cipherSpec param
 */
    if (cipherSpecLen == 0 || cipherSpecs == NULL || cipherSpecs[0] == 0)
    {
        rc = sslGetCipherSpecList(ssl, c, (int32) (end - c), addRenegotiationScsv);
        if (rc < 0)
        {
            return SSL_FULL;
        }
        psTracePrintEncodedCipherList(INDENT_HS_MSG,
                "cipher_suites",
                c + 2, /* Skip over length encoding. */
                (psSize_t)rc - 2,
                PS_FALSE);
        c += rc;
    }
    else
    {
        if ((int32) (end - c) < cipherLen)
        {
            return SSL_FULL;
        }
        cipherLen -= 2; /* don't include yourself */
        *c = (cipherLen & 0xFF00) >> 8; c++;
        *c = cipherLen & 0xFF; c++;
        /* Safe to include all cipher suites in the list because they were
            checked above */
        psTracePrintCipherList(INDENT_HS_MSG,
                "cipher_suites",
                cipherSpecs,
                cipherSpecLen,
                PS_FALSE);
        for (i = 0; i < cipherSpecLen; i++)
        {
            *c = (cipherSpecs[i] & 0xFF00) >> 8; c++;
            *c = cipherSpecs[i] & 0xFF; c++;
        }
#  ifdef ENABLE_SECURE_REHANDSHAKES
        if (addRenegotiationScsv == 1)
        {
            ssl->extFlags.req_renegotiation_info = 1;
            *c = ((TLS_EMPTY_RENEGOTIATION_INFO_SCSV & 0xFF00) >> 8); c++;
            *c = TLS_EMPTY_RENEGOTIATION_INFO_SCSV  & 0xFF; c++;
        }
#  endif
        if (ssl->extFlags.req_fallback_scsv)
        {
            *c = (TLS_FALLBACK_SCSV >> 8) & 0xFF; c++;
            *c = TLS_FALLBACK_SCSV & 0xFF; c++;
            psTracePrintCiphersuiteName(INDENT_HS_MSG + 1,
                    NULL, TLS_FALLBACK_SCSV, PS_TRUE);
        }
    }
/*
    Compression.  Length byte and 0 for 'none' and possibly 1 for zlib
 */
#  ifdef USE_ZLIB_COMPRESSION
    *c = 2; c++;
    *c = 0; c++;
    *c = 1; c++;
#  else
    *c = 1; c++;
    *c = 0; c++;
#  endif

#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        /* Need to save aside (or recall) extensions because the resend
            path doesn't go     back to the user to rebuild them. */
        extStart = c;
    }
#  endif
/*
    Extensions
 */
    if (extLen > 0)
    {
        extLen -= 2;                      /* Don't include yourself in the length */
        *c = (extLen & 0xFF00) >> 8; c++; /* Total list length */
        *c = extLen & 0xFF; c++;

        /*      User-provided extensions.  Do them first in case something
            like a ServerNameIndication is here that will influence a
            later extension such as the sigHashAlgs */
        if (userExt)
        {
            ext = userExt;
            psTracePrintExtensionCreate(ssl, ext->extType);

            while (ext)
            {
                switch (ext->extType)
                {
                case EXT_SNI:
                    ssl->extFlags.req_sni = 1;
                    break;
                case EXT_ALPN:
                    ssl->extFlags.req_alpn = 1;
#  ifdef USE_ALPN
                    if (ssl->extCb == NULL)
                    {
                        psTraceInfo("WARNING: Providing ALPN extension without "
                            "registering extension callback to receive server reply\n");
                    }
#  endif
                    break;
                default:
                    break;
                }
                *c = (ext->extType & 0xFF00) >> 8; c++;
                *c = ext->extType & 0xFF; c++;

                *c = (ext->extLen & 0xFF00) >> 8; c++;
                *c = ext->extLen & 0xFF; c++;
                if (ext->extLen == 1 && ext->extData == NULL)
                {
                    Memset(c, 0x0, 1);
                }
                else
                {
                    Memcpy(c, ext->extData, ext->extLen);
                }
                c += ext->extLen;
                ext = ext->next;
            }
        }

        /* Max fragment extension */
        if (ssl->maxPtFrag & 0x10000)
        {
            psTracePrintExtensionCreate(ssl, EXT_MAX_FRAGMENT_LEN);

            ssl->extFlags.req_max_fragment_len = 1;
            *c = 0x00; c++;
            *c = 0x01; c++;
            *c = 0x00; c++;
            *c = 0x01; c++;
            if (options->maxFragLen == 0x200)
            {
                *c = 0x01; c++;
            }
            else if (options->maxFragLen == 0x400)
            {
                *c = 0x02; c++;
            }
            else if (options->maxFragLen == 0x800)
            {
                *c = 0x03; c++;
            }
            else if (options->maxFragLen == 0x1000)
            {
                *c = 0x04; c++;
            }
        }
#  ifdef ENABLE_SECURE_REHANDSHAKES
/*
        Populated RenegotiationInfo extension
 */
        if (ssl->myVerifyDataLen > 0)
        {
            psTracePrintExtensionCreate(ssl, EXT_RENEGOTIATION_INFO);
            ssl->extFlags.req_renegotiation_info = 1;
            *c = (EXT_RENEGOTIATION_INFO & 0xFF00) >> 8; c++;
            *c = EXT_RENEGOTIATION_INFO & 0xFF; c++;
            *c = ((ssl->myVerifyDataLen + 1) & 0xFF00) >> 8; c++;
            *c = (ssl->myVerifyDataLen + 1) & 0xFF; c++;
            *c = ssl->myVerifyDataLen & 0xFF; c++;
            Memcpy(c, ssl->myVerifyData, ssl->myVerifyDataLen);
            c += ssl->myVerifyDataLen;
            ssl->secureRenegotiationInProgress = PS_TRUE;
        }
#  endif /* ENABLE_SECURE_REHANDSHAKES */

#  ifdef USE_ECC_CIPHER_SUITE
        if (curveListLen > 0)
        {
            psTracePrintExtensionCreate(ssl, EXT_ELLIPTIC_CURVE);
            ssl->extFlags.req_elliptic_curve = 1;
            *c = (EXT_ELLIPTIC_CURVE & 0xFF00) >> 8; c++;
            *c = EXT_ELLIPTIC_CURVE & 0xFF; c++;
            *c = ((curveListLen + 2) & 0xFF00) >> 8; c++;
            *c = (curveListLen + 2) & 0xFF; c++;
            *c = 0; c++;    /* High byte always zero */
            *c = curveListLen & 0xFF; c++;
            Memcpy(c, eccCurveList, curveListLen);
            c += curveListLen;

            psTracePrintExtensionCreate(ssl, EXT_ELLIPTIC_POINTS);
            ssl->extFlags.req_elliptic_points = 1;
            *c = (EXT_ELLIPTIC_POINTS & 0xFF00) >> 8; c++;
            *c = EXT_ELLIPTIC_POINTS & 0xFF; c++;
            *c = 0x00; c++;
            *c = 0x02; c++;
            *c = 0x01; c++;
            *c = 0x00; c++;
        }
#  endif /* USE_ECC_CIPHER_SUITE */

#  ifdef USE_TLS_1_2
        /* Will always exist in some form if TLS 1.2 is enabled */
        psTracePrintExtensionCreate(ssl, EXT_SIGNATURE_ALGORITHMS);
        ssl->extFlags.req_signature_algorithms = 1;
        *c = (EXT_SIGNATURE_ALGORITHMS & 0xFF00) >> 8; c++;
        *c = EXT_SIGNATURE_ALGORITHMS & 0xFF; c++;
        *c = (sigHashLen & 0xFF00) >> 8; c++;
        *c = sigHashLen & 0xFF; c++;
        Memcpy(c, sigHash, sigHashLen);
        c += sigHashLen;
#  endif

#  ifdef USE_STATELESS_SESSION_TICKETS
        /* If ticket exists and is marked "USING" then it can be used */
        if (useTicket && ssl->sid)
        {
            if (ssl->sid->sessionTicketLen == 0 ||
                ssl->sid->sessionTicketState != SESS_TICKET_STATE_USING_TICKET)
            {
                psTracePrintExtensionCreate(ssl, EXT_SESSION_TICKET);
                ssl->extFlags.req_session_ticket = 1;
                *c = (EXT_SESSION_TICKET & 0xFF00) >> 8; c++;
                *c = EXT_SESSION_TICKET & 0xFF; c++;
                *c = 0x00; c++;
                *c = 0x00; c++;
                ssl->sid->sessionTicketState = SESS_TICKET_STATE_SENT_EMPTY;
            }
            else
            {
                psTracePrintExtensionCreate(ssl, EXT_SESSION_TICKET);
                ssl->extFlags.req_session_ticket = 1;
                *c = (EXT_SESSION_TICKET & 0xFF00) >> 8; c++;
                *c = EXT_SESSION_TICKET & 0xFF; c++;
                *c = (ssl->sid->sessionTicketLen & 0xFF00) >> 8; c++;
                *c = ssl->sid->sessionTicketLen & 0xFF; c++;
                Memcpy(c, ssl->sid->sessionTicket, ssl->sid->sessionTicketLen);
                c += ssl->sid->sessionTicketLen;
                ssl->sid->sessionTicketState = SESS_TICKET_STATE_SENT_TICKET;
#   ifdef USE_MATRIXSSL_STATS
                matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#   endif
            }
        }
#  endif /* USE_STATELESS_SESSION_TICKETS       */

#  ifdef USE_OCSP_RESPONSE
        if (options->OCSPstapling)
        {
            psTracePrintExtensionCreate(ssl, EXT_STATUS_REQUEST);
            ssl->extFlags.req_status_request = 1;
            *c = (EXT_STATUS_REQUEST & 0xFF00) >> 8; c++;
            *c = EXT_STATUS_REQUEST & 0xFF; c++;
            *c = 0x00; c++;
            *c = 0x05; c++;
            *c = 0x01; c++;
            *c = 0x00; c++;
            *c = 0x00; c++;
            *c = 0x00; c++;
            *c = 0x00; c++;
        }
#  endif /* USE_OCSP_RESPONSE */

#  ifdef USE_TRUSTED_CA_INDICATION
        if (options->trustedCAindication)
        {
            psTracePrintExtensionCreate(ssl, EXT_TRUSTED_CA_KEYS);
            *c = (EXT_TRUSTED_CA_KEYS & 0xFF00) >> 8; c++;
            *c = EXT_TRUSTED_CA_KEYS & 0xFF; c++;
            writeTrustedCAindication(ssl->keys->CAcerts, &c);
        }
#  endif
        if (options->truncHmac)
        {
            psTracePrintExtensionCreate(ssl, EXT_TRUNCATED_HMAC);
            ssl->extFlags.req_truncated_hmac = 1;
            *c = (EXT_TRUNCATED_HMAC & 0xFF00) >> 8; c++;
            *c = EXT_TRUNCATED_HMAC & 0xFF; c++;
            *c = 0x00; c++;
            *c = 0x00; c++;
        }

        if (options->extendedMasterSecret >= 0)
        {
            if (options->extendedMasterSecret > 0)
            {
                /* User is REQUIRING the server to support it */
                ssl->extFlags.require_extended_master_secret = 1;
            }
            psTracePrintExtensionCreate(ssl, EXT_EXTENDED_MASTER_SECRET);
            ssl->extFlags.req_extended_master_secret = 1;
            *c = (EXT_EXTENDED_MASTER_SECRET & 0xFF00) >> 8; c++;
            *c = EXT_EXTENDED_MASTER_SECRET & 0xFF; c++;
            *c = 0x00; c++;
            *c = 0x00; c++;
        }

    }

#  ifdef USE_DTLS
    if ((ACTV_VER(ssl, v_dtls_any)) && (extLen > 0) && extStart)
    {
        if (ssl->helloExtLen == 0)
        {
            ssl->helloExtLen = (int32) (c - extStart);
            ssl->helloExt = psMalloc(ssl->hsPool, ssl->helloExtLen);
            if (ssl->helloExt == NULL)
            {
                return SSL_MEM_ERROR;
            }
            Memcpy(ssl->helloExt, extStart, ssl->helloExtLen);
        }
        else
        {
            /* Forget the extensions we wrote above and use the saved ones */
            if (ssl->helloExt)
            {
                c = extStart;
                Memcpy(c, ssl->helloExt, ssl->helloExtLen);
                c += ssl->helloExtLen;
            }
        }
    }
#  endif /* USE_DTLS */

    if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE, 0, messageSize,
             padLen, encryptStart, out, &c)) < 0)
    {
        return rc;
    }
    out->end = c;

/*
    Could be a rehandshake so clean     up old context if necessary.
    Always explicitly set state to beginning.
 */
    if (ssl->hsState == SSL_HS_DONE)
    {
        sslResetContext(ssl);
    }

/*
    Could be a rehandshake on a previous connection that used client auth.
    Reset our local client auth state as the server is always the one
    responsible for initiating it.
 */
    ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
    ssl->hsState = SSL_HS_SERVER_HELLO;

#  ifdef USE_MATRIXSSL_STATS
    matrixsslUpdateStat(ssl, CH_SENT_STAT, 1);
#  endif
    return MATRIXSSL_SUCCESS;

}

/******************************************************************************/
/*
    Write a ClientKeyExchange message.
 */
static int32 writeClientKeyExchange(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t keyLen, messageSize, explicitLen;
    int32_t rc;
    pkaAfter_t *pkaAfter;

#  ifdef USE_PSK_CIPHER_SUITE
    unsigned char *pskId, *pskKey;
    uint8_t pskIdLen;
#  endif /* USE_PSK_CIPHER_SUITE */
    void *pkiData = ssl->userPtr;
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
#   if defined(USE_ECC_CIPHER_SUITE) || defined(USE_RSA_CIPHER_SUITE)
    psPool_t *pkiPool = NULL;
#   endif  /* USE_ECC_CIPHER_SUITE || USE_RSA_CIPHER_SUITE */
#  endif   /* !USE_ONLY_PSK_CIPHER_SUITE */

    psTracePrintHsMessageCreate(ssl, SSL_HS_CLIENT_KEY_EXCHANGE);

    c = out->end;
    end = out->buf + out->size;
    messageSize = keyLen = 0;

    if ((pkaAfter = getPkaAfter(ssl)) == NULL)
    {
        return PS_PLATFORM_FAIL;
    }

#  ifdef USE_PSK_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {
        /* Get the key id to send in the clientKeyExchange message.  */
        if (matrixSslPskGetKeyId(ssl, &pskId, &pskIdLen,
                ssl->sec.hint, ssl->sec.hintLen) < 0)
        {
            psFree(ssl->sec.hint, ssl->hsPool); ssl->sec.hint = NULL;
            return MATRIXSSL_ERROR;
        }
#   ifdef USE_DTLS
        /* Need to save for retransmit? */
        if (!(ACTV_VER(ssl, v_dtls_any)))
        {
            psFree(ssl->sec.hint, ssl->hsPool); ssl->sec.hint = NULL;
        }
#   else
        psFree(ssl->sec.hint, ssl->hsPool); ssl->sec.hint = NULL;
#   endif

    }
#  endif  /* USE_PSK_CIPHER_SUITE */

/*
    Determine messageSize for the record header
 */
#  ifdef USE_DHE_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
#   ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any) && ssl->retransmit == 1)
        {
            keyLen = ssl->ckeSize;
        }
        else
        {
#   endif
#   ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            keyLen = (ssl->sec.eccKeyPriv->curve->size * 2) + 2;
        }
        else
        {
#   endif /* USE_ECC_CIPHER_SUITE */
#   ifdef REQUIRE_DH_PARAMS
        keyLen += ssl->sec.dhKeyPriv->size;
#   endif /* REQUIRE_DH_PARAMS */
#   ifdef USE_ECC_CIPHER_SUITE
    }
#   endif /* USE_ECC_CIPHER_SUITE */
#   ifdef USE_DTLS
    }
#   endif
#   ifdef USE_PSK_CIPHER_SUITE
/*
        Leave keyLen as the native DH or RSA key to keep the write
        logic untouched below.  Just directly increment the messageSize
        for the PSK id information
 */
        /* DHE_PSK suites */
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            messageSize += pskIdLen + 2;
        }
#   endif /* USE_PSK_CIPHER_SUITE */
    }
    else
    {
#  endif  /* USE_DHE_CIPHER_SUITE */
#  ifdef USE_PSK_CIPHER_SUITE
    /* basic PSK suites */
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {
        messageSize += pskIdLen;     /* don't need the +2 */
    }
    else
    {
#  endif /* USE_PSK_CIPHER_SUITE */
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
#   ifdef USE_ECC_CIPHER_SUITE
    if (ssl->cipher->type == CS_ECDH_ECDSA ||
        ssl->cipher->type == CS_ECDH_RSA)
    {
        keyLen = (ssl->sec.cert->publicKey.key.ecc.curve->size * 2) + 2;
    }
    else
    {
#   endif /* USE_ECC_CIPHER_SUITE */
    /* Standard RSA auth suites */
    keyLen = ssl->sec.cert->publicKey.keysize;
#   ifdef USE_ECC_CIPHER_SUITE
}
#   endif /* USE_ECC_CIPHER_SUITE */
#  endif  /* !USE_PSK_CIPHER_SUITE */
#  ifdef USE_PSK_CIPHER_SUITE
}
#  endif /* USE_PSK_CIPHER_SUITE */
#  ifdef USE_DHE_CIPHER_SUITE
}
#  endif /* USE_DHE_CIPHER_SUITE */

    messageSize += ssl->recordHeadLen + ssl->hshakeHeadLen + keyLen;
    explicitLen = 0;
#  ifdef USE_TLS
    /*  Must always add the key size length to the message */
    if (!NGTD_VER(ssl, v_ssl_3_0))
    {
        messageSize += 2;
        explicitLen = 1;
    }
#  endif /* USE_TLS */

#  ifdef USE_DHE_CIPHER_SUITE
    /*  DHE must include the explicit key size regardless of protocol */
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
        if (explicitLen == 0)
        {
            messageSize += 2;
            explicitLen = 1;
        }
    }
#  endif /* USE_DHE_CIPHER_SUITE */

#  ifdef USE_PSK_CIPHER_SUITE
    /* Standard PSK suite in SSLv3 will not have accounted for +2 yet */
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {
        if (explicitLen == 0)
        {
            messageSize += 2;
            explicitLen = 1;
        }
    }
#  endif

#  ifdef USE_ECC_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
    {
        if (explicitLen == 1)
        {
            messageSize -= 2; /* For some reason, ECC CKE doesn't use 2 len */
            explicitLen = 0;
        }
    }
#  endif /* USE_ECC_CIPHER_SUITE */

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CLIENT_KEY_EXCHANGE, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        return rc;
    }

/*
    ClientKeyExchange message contains the encrypted premaster secret.
    The base premaster is the original SSL protocol version we asked for
    followed by 46 bytes of random data.
    These 48 bytes are padded to the current RSA key length and encrypted
    with the RSA key.
 */
    if (explicitLen == 1)
    {
#  ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            /* pskIdLen is uint8_t. */
            *c = 0; c++;
            *c = (pskIdLen & 0xFF); c++;
/*
            The cke message begins with the ID of the desired key
 */
            Memcpy(c, pskId, pskIdLen);
            c += pskIdLen;
        }
#  endif /* USE_PSK_CIPHER_SUITE */
/*
        Add the two bytes of key length
 */
        if (keyLen > 0)
        {
            *c = (keyLen & 0xFF00) >> 8; c++;
            *c = (keyLen & 0xFF); c++;
        }
    }

#  ifdef USE_DTLS
    if ((ACTV_VER(ssl, v_dtls_any)) && (ssl->retransmit == 1))
    {
/*
         Retransmit case.  Must use the cached encrypted msg from
         the first flight to keep handshake hash same
 */
        Memcpy(c, ssl->ckeMsg, ssl->ckeSize);
        c += ssl->ckeSize;
    }
    else
    {
#  endif /* USE_DTLS */

#  ifdef USE_DHE_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
        /* For DHE, the clientKeyExchange message is simply the public
            key for this client.  No public/private encryption here
            because there is no authentication (so not necessary or
            meaningful to activate public cipher). Just check ECDHE or DHE */
#   ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            keyLen--;
            *c = keyLen & 0xFF; c++;
            if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv, c,
                    &keyLen) < 0)
            {
                return MATRIXSSL_ERROR;
            }
            psAssert(keyLen == (uint32) * (c - 1));
#    ifdef USE_DTLS
            if (ACTV_VER(ssl, v_dtls_any))
            {
                /* Set aside retransmit for this case here since there is
                    nothing happening in nowDoCke related to the handshake
                    message output */
                ssl->ckeSize = keyLen + 1;
                ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize);
                if (ssl->ckeMsg == NULL)
                {
                    return SSL_MEM_ERROR;
                }
                Memcpy(ssl->ckeMsg, c - 1, ssl->ckeSize);
            }
#    endif
            c += keyLen;
/*
            Generate premaster and free ECC key material
 */
            ssl->sec.premasterSize = ssl->sec.eccKeyPriv->curve->size;
            ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
            if (ssl->sec.premaster == NULL)
            {
                return SSL_MEM_ERROR;
            }

            /* Schedule EC secret generation */
            pkaAfter->type = PKA_AFTER_ECDH_SECRET_GEN;
            pkaAfter->inbuf = NULL;
            pkaAfter->inlen = 0;
            pkaAfter->outbuf = ssl->sec.premaster;
            pkaAfter->data = pkiData;

        }
        else
        {
#   endif /* USE_ECC_CIPHER_SUITE */
#   ifdef REQUIRE_DH_PARAMS
        {
            psSize_t dhLen = end - c;
            /* Write out the public key part of our private key */
            if (psDhExportPubKey(ssl->hsPool, ssl->sec.dhKeyPriv, c, &dhLen) < 0)
            {
                return MATRIXSSL_ERROR;
            }
            psAssert(dhLen == keyLen);
        }
#    ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any))
        {
            /* Set aside retransmit for this case here since there is
                nothing happening in nowDoCke related to the handshake
                message output */
            ssl->ckeSize = keyLen;
            ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize);
            if (ssl->ckeMsg == NULL)
            {
                return SSL_MEM_ERROR;
            }
            Memcpy(ssl->ckeMsg, c, ssl->ckeSize);
        }
#    endif
        c += keyLen;

        /* Schedule DH secret gen.*/
        pkaAfter->type = PKA_AFTER_DH_KEY_GEN;
        pkaAfter->inbuf = NULL;
        pkaAfter->inlen = 0;
#    ifdef USE_PSK_CIPHER_SUITE
        /*  Borrowing the inbuf and inlen params to hold pskId information */
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            pkaAfter->inlen = pskIdLen;
            if ((pkaAfter->inbuf = psMalloc(ssl->hsPool, pskIdLen)) == NULL)
            {
                return PS_MEM_FAIL;
            }
            Memcpy(pkaAfter->inbuf, pskId, pskIdLen);
        }
#    endif
        pkaAfter->outbuf = ssl->sec.premaster;
        pkaAfter->user = ssl->sec.premasterSize;
        pkaAfter->data = pkiData;

#   endif /* REQUIRE_DH_PARAMS  */
#   ifdef USE_ECC_CIPHER_SUITE
    }
#   endif /* USE_ECC_CIPHER_SUITE */

    }
    else
    {
#  endif /* USE_DHE_CIPHER_SUITE */
#  ifdef USE_PSK_CIPHER_SUITE
/*
        Create the premaster for basic PSK suites
 */
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {
/*
            RFC4279: The premaster secret is formed as follows: if the PSK is
            N octets long, concatenate a uint16 with the value N, N zero octets,
            a second uint16 with the value N, and the PSK itself.
            @note pskIdLen will contain the length of pskKey after this call.
 */
        rc = matrixSslPskGetKey(ssl, pskId, pskIdLen, &pskKey, &pskIdLen);
        if (rc < 0 || pskKey == NULL)
        {
            return MATRIXSSL_ERROR;
        }
        ssl->sec.premasterSize = (pskIdLen * 2) + 4;
        ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
        if (ssl->sec.premaster == NULL)
        {
            return SSL_MEM_ERROR;
        }
        Memset(ssl->sec.premaster, 0, ssl->sec.premasterSize);
        ssl->sec.premaster[0] = 0;
        ssl->sec.premaster[1] = (pskIdLen & 0xFF);
        /* memset to 0 handled middle portion */
        ssl->sec.premaster[2 + pskIdLen] = 0;
        ssl->sec.premaster[3 + pskIdLen] = (pskIdLen & 0xFF);
        Memcpy(&ssl->sec.premaster[4 + pskIdLen], pskKey, pskIdLen);
        /*      Now that we've got the premaster secret, derive the various
            symmetrics.  Correct this is only a PSK requirement here because
            there is no pkaAfter to call it later

            However, if extended_master_secret is being used we must delay
            the master secret creation until the CKE handshake message has
            been added to the rolling handshake hash.  Key generation will
            be done in encryptRecord */
        if (ssl->extFlags.extended_master_secret == 0)
        {
            if ((rc = sslCreateKeys(ssl)) < 0)
            {
                return rc;
            }
        }

    }
    else
    {
#  endif /* USE_PSK_CIPHER_SUITE */
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
    /* Non-DHE cases below */
#   ifdef USE_ECC_CIPHER_SUITE
    if (ssl->cipher->type == CS_ECDH_ECDSA ||
        ssl->cipher->type == CS_ECDH_RSA)
    {

        /* Write key len */
        keyLen--;
        *c = keyLen & 0xFF; c++;

        /* Tricky case where a key generation, public key write, and
            then secret generation are needed.  Schedule the key gen.
            The combination of the cipher suite type and the pkaAfter
            type will be used to locate this case */
        pkaAfter->type = PKA_AFTER_ECDH_KEY_GEN;
        pkaAfter->outbuf = c;         /* Where the public key will be written */
        pkaAfter->pool = pkiPool;
        pkaAfter->data = pkiData;
        pkaAfter->user = keyLen;

        c += keyLen;

        /*      Allocate premaster and free ECC key material */

        ssl->sec.premasterSize =
            ssl->sec.cert->publicKey.key.ecc.curve->size;
        ssl->sec.premaster = psMalloc(ssl->hsPool,
            ssl->sec.premasterSize);
        if (ssl->sec.premaster == NULL)
        {
            return SSL_MEM_ERROR;
        }

    }
    else
    {
#   endif /* USE_ECC_CIPHER_SUITE */
#   ifdef USE_RSA_CIPHER_SUITE
/*
            Standard RSA suite
 */
    ssl->sec.premasterSize = SSL_HS_RSA_PREMASTER_SIZE;
    ssl->sec.premaster = psMalloc(ssl->hsPool,
        SSL_HS_RSA_PREMASTER_SIZE);
    if (ssl->sec.premaster == NULL)
    {
        return SSL_MEM_ERROR;
    }

    /* The version MUST be the same as the one we encoded in
       ClientHello.client_version. */
    ssl->sec.premaster[0] = psEncodeVersionMaj(ssl->ourHelloVersion);
    ssl->sec.premaster[1] = psEncodeVersionMin(ssl->ourHelloVersion);
    if (psGetPrngLocked(ssl->sec.premaster + 2,
            SSL_HS_RSA_PREMASTER_SIZE - 2, ssl->userPtr) < 0)
    {
        return MATRIXSSL_ERROR;
    }

    /* Shedule RSA encryption.  Put tmp pool under control of After */
    pkaAfter->type = PKA_AFTER_RSA_ENCRYPT;
    pkaAfter->outbuf = c;
    pkaAfter->data = pkiData;
    pkaAfter->pool = pkiPool;
    pkaAfter->user = keyLen;         /* Available space */

    c += keyLen;
#   else /* RSA is the 'default' so if that didn't get hit there is a problem */
    psTraceInfo("There is no handler for writeClientKeyExchange.  ERROR\n");
    return MATRIXSSL_ERROR;
#   endif /* USE_RSA_CIPHER_SUITE */
#  endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

#  ifdef USE_ECC_CIPHER_SUITE
}
#  endif /* USE_ECC_CIPHER_SUITE */
#  ifdef USE_PSK_CIPHER_SUITE
}
#  endif /* USE_PSK_CIPHER_SUITE */
#  ifdef USE_DHE_CIPHER_SUITE
}
#  endif /* USE_DHE_CIPHER_SUITE */

#  ifdef USE_DTLS
}
#  endif /* USE_DTLS */

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CLIENT_KEY_EXCHANGE, messageSize, padLen, encryptStart, out,
             &c)) < 0)
    {
        return rc;
    }

    out->end = c;
# ifdef DEBUG_TLS_PREMASTER
    psTraceBytes("client premaster_secret",
            ssl->sec.premaster,
            SSL_HS_RSA_PREMASTER_SIZE);
# endif
    return MATRIXSSL_SUCCESS;
}

#  ifndef USE_ONLY_PSK_CIPHER_SUITE
#   ifdef USE_CLIENT_AUTH
#    ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
/** Handle the asynchronous signature operation for CertificateVerify.

    Precondition: ssl->extCvSigOp == 1
    (i.e. the run-time switch that enables this feature must be on.)
 */
static int32_t handleAsyncCvSigOp(ssl_t *ssl, pkaAfter_t *pka, unsigned char *hash)
{
    /*
       Case 1: First entry (for this connection).
       Setup state variables to request the external signature from the client
       application. Prepare to hand over the hash to sign to the client
       via the matrixSslGetHSMessagesHash function.
       The PS_PENDING return value gets passed down all the way to the client.
     */
    if (!ssl->extCvSigOpPending &&
        ssl->extCvSigLen == 0)
    {
        unsigned char *hash_tbs;
        size_t hash_tbs_len;

        ssl->extCvSigOpPending = 1;

        if (pka->type != PKA_AFTER_ECDSA_SIG_GEN)
        {
            pka->type = PKA_AFTER_RSA_SIG_GEN_ELEMENT;
            ssl->extCvSigAlg = PS_RSA;
        }
        else
        {
            ssl->extCvSigAlg = PS_ECC;
        }

        if (NGTD_VER(ssl, v_tls_with_signature_algorithmts)
                || ssl->extCvSigAlg == PS_RSA)
        {
            hash_tbs = hash;
            hash_tbs_len = pka->inlen;
        }
        else
        {
            /*
               TLS <1.2 uses the combined MD5-SHA1 handshake hash.
               But the ECDSA signature in CertificateVerify is computed
               only over the SHA-1 part (RFC 4492).
             */
            hash_tbs = hash + MD5_HASH_SIZE;
            hash_tbs_len = SHA1_HASH_SIZE;
        }

        ssl->extCvHash = psMalloc(NULL, hash_tbs_len);
        if (ssl->extCvHash == NULL)
        {
            return MATRIXSSL_ERROR;
        }

        Memcpy(ssl->extCvHash,
            hash_tbs,
            hash_tbs_len);
        ssl->extCvHashLen = hash_tbs_len;
        ssl->hwflags |= SSL_HWFLAGS_PENDING_PKA_W;
        return PS_PENDING;
    }
    /*
       Case 2. Previously asked for external signing.
       But the signature is not ready yet.
     */
    if (ssl->extCvSigOpPending &&
        ssl->extCvSigLen == 0)
    {
        return PS_PENDING;
    }
    /*
       Case 3. Previously asked for external signing.
       And now the signature is ready.
     */
    if (ssl->extCvSigOpPending &&
        ssl->extCvSigLen > 0)
    {
        if (ssl->extCvSigAlg == PS_RSA)
        {
            Memcpy(pka->outbuf,
                ssl->extCvSig,
                ssl->extCvSigLen);
            psFree(ssl->extCvHash, NULL);
            psFree(ssl->extCvSig, NULL);
        }
        /*
           For ECDSA, postpone do the memcpy and the psFrees
           to nowDoCvPka(). This is because we may need to adjust
           the output stream first with accountForEcdsaSizeChange.
         */
        ssl->extCvSigOpPending = 0;
        /*
           Continue the flight encoding.
         */
        return PS_SUCCESS;
    }

    return MATRIXSSL_ERROR;
}
#    endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

static int32 getSnapshotHSHash(ssl_t *ssl,
    unsigned char msgHash[SHA512_HASH_SIZE],
    pkaAfter_t *pka)
{
    /* Does a smart default hash automatically for us */
    if (sslSnapshotHSHash(ssl, msgHash, -1) <= 0)
    {
        psTraceInfo("Internal error: handshake hash failed\n");
        return MATRIXSSL_ERROR;
    }
#    ifdef USE_TLS_1_2
    /* Tweak if needed */
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        switch (pka->inlen)
        {
#     ifdef USE_SHA1
        case SHA1_HASH_SIZE:
            sslSha1SnapshotHSHash(ssl, msgHash);
            break;
#     endif
#     ifdef USE_SHA384
        case SHA384_HASH_SIZE:
            sslSha384SnapshotHSHash(ssl, msgHash);
            break;
#     endif
#     ifdef USE_SHA512
        case SHA512_HASH_SIZE:
            sslSha512SnapshotHSHash(ssl, msgHash);
            break;
#     endif
        default:
            break;
        }
    }
#    endif /* USE_TLS_1_2 */

    return PS_SUCCESS;
}

#    ifdef USE_ECC
static int nowDoCvPkaInnerECDSA(ssl_t *ssl, pkaAfter_t *pka,
    unsigned char msgHash[SHA512_HASH_SIZE], psBuf_t *out)
{
    psPool_t *pkiPool = NULL;

    int32_t rc = PS_SUCCESS;
    unsigned char *tmpEcdsa;
    psSize_t len, hashTbsLen;
    unsigned char *hashTbs;
    sslIdentity_t *chosen = ssl->chosenIdentity;

    if (chosen == NULL)
    {
        return PS_UNSUPPORTED_FAIL;
    }

#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    if (ssl->extCvSigOpInUse)
    {
        /*
           PS_SUCCESS: the externally computed signature is ready;
           continue execution of this function, but skip signature
           generation code.
           PS_PENDING or error: hand over to the caller.
         */
        rc = handleAsyncCvSigOp(ssl, pka, msgHash);
        if (rc == PS_SUCCESS)
        {
            len = ssl->extCvSigLen;
        }
        else
        {
            return rc;
        }
    }
    else
    {
        /*
           External signing not enabled for this connection;
           compute the signature internally as usual.
         */
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

    /* Only need to allocate 1 larger because 1 has already been added */
    if ((tmpEcdsa = psMalloc(ssl->hsPool, pka->user + 1)) == NULL)
    {
        return PS_MEM_FAIL;
    }

#     ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        /*
           TLS 1.2 defined and used.
         */
        hashTbs = msgHash;
        hashTbsLen = pka->inlen;
    }
    else
    {
        /*
           TLS 1.2 defined but not used.

           TLS <1.2 uses the combined MD5-SHA1 handshake hash.
           But the ECDSA signature in CertificateVerify is computed
           only over the SHA-1 part (RFC 4492).

           We need to skip over the first 16 bytes of MD5 that
           the SSL hash stores
         */
        hashTbs = msgHash + MD5_HASH_SIZE;
        hashTbsLen = SHA1_HASH_SIZE;
    }
#     else /* USE_TLS_1_2 */
           /*
              TLS 1.2 not defined (and thus, not used). See comment above.
            */
    hashTbs = msgHash + MD5_HASH_SIZE;
    hashTbsLen = SHA1_HASH_SIZE;
#     endif /* USE_TLS_1_2 */

#     ifdef USE_DTLS
    ssl->ecdsaSizeChange = 0;
#     endif

    /*
       NEGATIVE ECDSA: write the signature into a temp buffer (tmpEcdsa)
       instead of writing it directly into the output stream (pka->outbuf).
       Length of outbuf is increased by 1.
     */
    len = pka->user + 1;
    rc = psEccDsaSign(pkiPool, &chosen->privKey.key.ecc,
        hashTbs, hashTbsLen, tmpEcdsa, &len, 1, pka->data);
    if (rc != PS_SUCCESS)
    {
        goto out;
    }
#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
}     /* closing brace for: if (ssl->extCvSigOpInUse) { ... } else { */
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

    /*
       Now the ECDSA signature is ready (in tmpEcdsa or ssl->extCvSig)
       and len contains the actual length of the signature.
       We estimated the signature size earlier in writeCertificateVerify.
       Check whether our guess was correct.
     */

    if (len == pka->user)
    {
        /*
           Case 1: ECDSA signature is of expected size.
           Just copy the signature into the output buffer.
         */
#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
        if (ssl->extCvSigOpInUse)
        {
            Memcpy(pka->outbuf, ssl->extCvSig, pka->user);
        }
        else
        {
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
        Memcpy(pka->outbuf, tmpEcdsa, pka->user);
    }
#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
}
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
    else
    {
        unsigned char *sig_buf;

        /*
           Case 2: ECDSA signature has unexpected size.
           Ask accountForEcdsaSizeChange to fix up the output buffer
           and to copy the signature to the correct spot.
         */
#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
        if (ssl->extCvSigOpInUse)
        {
            sig_buf = ssl->extCvSig;
        }
        else
        {
            sig_buf = tmpEcdsa;
        }
#     else
        sig_buf = tmpEcdsa;
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

        rc = accountForEcdsaSizeChange(ssl, pka, len, sig_buf,
            out, SSL_HS_CERTIFICATE_VERIFY);
        if (rc < 0)
        {
            goto out;
        }
    } /* endif (len == pka->user) */

#     ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        int32_t saveSize;

        saveSize = len;

        ssl->certVerifyMsgLen = saveSize;
        ssl->certVerifyMsg = psMalloc(ssl->hsPool, saveSize);
        if (ssl->certVerifyMsg == NULL)
        {
            rc = SSL_MEM_ERROR;
            goto out;
        }
        Memcpy(ssl->certVerifyMsg, pka->outbuf, saveSize);
    }
#     endif /* USE_DTLS */

out:

#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    if (ssl->extCvSigOpInUse)
    {
        psFree(ssl->extCvHash, NULL);
        psFree(ssl->extCvSig, NULL);
    }
    else
    {
        psFree(tmpEcdsa, ssl->hsPool);
    }
#     else
    psFree(tmpEcdsa, ssl->hsPool);
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

    clearPkaAfter(ssl);

    return rc;
}
#    endif /* USE_ECC */

#    ifdef USE_RSA
static int nowDoCvPkaInnerRSA(ssl_t *ssl, pkaAfter_t *pka,
    unsigned char msgHash[SHA512_HASH_SIZE], psBuf_t *out)
{
    psPool_t *pkiPool = NULL;
    sslIdentity_t *chosen = ssl->chosenIdentity;
    int32_t rc;
    int32_t using_tls_1_2;

    if (chosen == NULL)
    {
        return PS_UNSUPPORTED_FAIL;
    }

#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    if (ssl->extCvSigOpInUse)
    {
        rc = handleAsyncCvSigOp(ssl, pka, msgHash);
        /*
           PS_SUCCESS: the externally computed signature is ready;
           continue execution of this function, but skip signature
           generation code.
           PS_PENDING or error: hand over to the caller.
         */
        if (rc != PS_SUCCESS)
        {
            return rc;
        }
    }
    else
    {
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

#     ifdef USE_TLS_1_2
        if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
        {
            /*      RFC:  "The hash and signature algorithms used in the
                    signature MUST be one of those present in the
                    supported_signature_algorithms field of the
                    CertificateRequest message.  In addition, the hash and
                    signature algorithms MUST be compatible with the key in the
                    client's end-entity certificate.

                    We've done the above tests in the parse of the
                    CertificateRequest message and wouldn't be here if our
                    certs didn't match the sigAlgs.  However, we do have
                    to test for both sig algorithm types here to find the
                    hash strength because the sig alg might not match the
                    pubkey alg.  This was also already confirmed in
                    CertRequest parse so wouldn't be here if not allowed */
            using_tls_1_2 = 1;     /* TLS 1.2 defined and used. */
        }
        else
        {
            using_tls_1_2 = 0;     /* TLS 1.2 defined but not used. */
        }
#     else /* ! USE_TLS_1_2 */
    using_tls_1_2 = 0;     /* TLS 1.2 not defined and thus not used. */
#     endif /* USE_TLS_1_2 */

    psAssert(using_tls_1_2 == 0 || using_tls_1_2 == 1);

#     ifdef USE_TLS_1_2
    /*
       In TLS 1.2, the RSASSA-PKCS1-v1_5 signature scheme must
       be used. In this scheme, the signed element is not the raw hash
       but a DER-encoded DigestInfo struct. Only privRsaEncryptSignedElement
       can handle this case.
     */
    if (using_tls_1_2)
    {
        rc = privRsaEncryptSignedElement(pkiPool, &chosen->privKey.key.rsa,
            msgHash, pka->inlen, pka->outbuf,
            chosen->privKey.keysize, pka->data);
    }
#     endif /* USE_TLS_1_2 */

    if (!using_tls_1_2)
    {
        rc = psRsaEncryptPriv(pkiPool, &chosen->privKey.key.rsa, msgHash,
            pka->inlen, pka->outbuf, chosen->privKey.keysize,
            pka->data);
    }

    if (rc < 0)
    {
        rc = MATRIXSSL_ERROR;
        goto out;
    }
#     ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
}     /* Closing brace for: if (ssl->extCvSigOpInUse) { } ... else { .. */
#     endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

#     ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        int32_t saveSize;

        saveSize = chosen->privKey.keysize;

        ssl->certVerifyMsgLen = saveSize;
        ssl->certVerifyMsg = psMalloc(ssl->hsPool, saveSize);
        if (ssl->certVerifyMsg == NULL)
        {
            rc = SSL_MEM_ERROR;
            goto out;
        }
        Memcpy(ssl->certVerifyMsg, pka->outbuf, saveSize);
    }
#     endif /* USE_DTLS */

out:
    clearPkaAfter(ssl);

    if (rc >= 0)
        return PS_SUCCESS;
    else
        return rc;
}
#    endif /* USE_RSA */

/******************************************************************************/
/*      Postponed CERTIFICATE_VERIFY PKA operation */
static int32 nowDoCvPka(ssl_t *ssl, psBuf_t *out)
{
    pkaAfter_t *pka;
    unsigned char msgHash[SHA512_HASH_SIZE];
    int32_t rc;

    pka = &ssl->pkaAfter[0];

#    ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (ssl->retransmit)
        {
            /* This call is not gated on pkaAfter.type so we test for
                retransmits manually.  The retransmit will have already been
                written in writeCertificateVerify if true */
            return PS_SUCCESS;
        }
    }
#    endif /* USE_DTLS */

    /*
       Compute the handshake_messages hash.
     */
    if (getSnapshotHSHash(ssl, msgHash, pka) < 0)
    {
        return MATRIXSSL_ERROR;
    }

    /*
       Sign it.
     */
    switch (pka->type)
    {
#    ifdef USE_ECC
    case PKA_AFTER_ECDSA_SIG_GEN:
        rc = nowDoCvPkaInnerECDSA(ssl, pka, msgHash, out);
        break;
#    endif /* USE_ECC */
#    ifdef USE_RSA
    case PKA_AFTER_RSA_SIG_GEN:
    case PKA_AFTER_RSA_SIG_GEN_ELEMENT:
        rc = nowDoCvPkaInnerRSA(ssl, pka, msgHash, out);
        break;
    default:
        psTraceInfo("Unsupported algorithm type in nowDoCvPka\n");
        return MATRIXSSL_ERROR;
#    endif /* USE_RSA */
    }

#    if !defined(USE_ECC) && !defined(USE_RSA)
    psTraceInfo("Error: no algorithm support for CertificateVerify signature\n");
    return MATRIXSSL_ERROR;
#    endif /* !USE_ECC && !USE_RSA */

    if (rc < 0)
    {
        return rc; /* PS_PENDING or error. */

    }
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Write the CertificateVerify message (client auth only)
    The message contains the signed hash of the handshake messages.

    The PKA operation is delayed
 */
static int32 writeCertificateVerify(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize, hashSize;
    int32_t rc;
    pkaAfter_t *pkaAfter;
    void *pkiData = ssl->userPtr;
    int32_t sigAlg = 0;
    sslIdentity_t *chosen = ssl->chosenIdentity;

    if (chosen == NULL)
    {
        return PS_UNSUPPORTED_FAIL;
    }

    psTracePrintHsMessageCreate(ssl, SSL_HS_CERTIFICATE_VERIFY);

    c = out->end;
    end = out->buf + out->size;

    if ((pkaAfter = getPkaAfterCv(ssl)) == NULL)
    {
        psTraceInfo("getPkaAfter error for certVerify\n");
        return MATRIXSSL_ERROR;
    }

    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                  2 + chosen->privKey.keysize;

#    ifdef USE_ECC
    /* Additional ASN.1 overhead from psEccSignHash */
    if (chosen->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        messageSize += 6;
        /* NEGATIVE ECDSA - Adding ONE spot for a 0x0 byte in the
            ECDSA signature.  This will allow us to be right ~50% of
            the time and not require any manual manipulation

            However, if this is a 521 curve there is no chance
            the final byte could be negative if the full 66
            bytes are needed because there can only be a single
            low bit for that sig size.  So subtract that byte
            back out to stay around the 50% no-move goal */
        if (chosen->privKey.keysize != 132)
        {
            messageSize += 1;
        }
        /* BIG EC KEY.  The sig is 2 bytes len, 1 byte SEQ,
            1 byte length (+1 OPTIONAL byte if length is >=128),
            1 byte INT, 1 byte rLen, r, 1 byte INT, 1 byte sLen, s.
            So the +4 here are the 2 INT and 2 rLen/sLen bytes on
            top of the keysize */
        if (chosen->privKey.keysize + 4 >= 128)
        {
            messageSize++; /* Extra byte for 'long' asn.1 encode */
        }
#     ifdef USE_DTLS
        if ((ACTV_VER(ssl, v_dtls_any)) && (ssl->retransmit == 1))
        {
            /* We already know if this signature got resized */
            messageSize += ssl->ecdsaSizeChange;
        }
#     endif
    }
#    endif /* USE_ECC */

#    ifdef USE_TLS_1_2
/*      RFC: "This is the concatenation of all the
    Handshake structures (as defined in Section 7.4) exchanged thus
    far.  Note that this requires both sides to either buffer the
    messages or compute running hashes for all potential hash
    algorithms up to the time of the CertificateVerify computation.
    Servers can minimize this computation cost by offering a
    restricted set of digest algorithms in the CertificateRequest
    message."

    We're certainly not going to buffer the messages so the
    handshake hash update and snapshot functions have to keep the
    running total.  Not a huge deal for the updating but
    the current snapshot framework didn't support this so there
    are one-off algorithm specific snapshots where needed. */
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        messageSize += 2; /* hashSigAlg */
    }
#    endif
    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CERTIFICATE_VERIFY, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        return rc;
    }

/*
    Correct to be looking at the child-most cert here because that is the
    one associated with the private key.
 */
#   ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        /*
          Pick the hash algorithm to use with the public key.
          Use the signature algorithm used in our certificate as
          the basis for the selection, because we have checked
          in parseCertificateRequest that the server supports that.
        */
        sigAlg = chooseSigAlg(chosen->cert, &chosen->privKey,
                ssl->serverSigAlgs);
        if (sigAlg <= 0)
        {
                psTraceInfo("Need more hash support for certVerify\n");
                return MATRIXSSL_ERROR;
        }
    }
    else
    {
        hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
    }
#   else /* USE_TLS_1_2 */
    hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
#   endif /* USE_TLS_1_2 */

#    ifdef USE_ECC
    if (chosen->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
#     ifdef USE_TLS_1_2
        if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
        {
            unsigned char b1, b2;

            if (getSignatureAndHashAlgorithmEncoding(sigAlg,
                            &b1, &b2, &hashSize) < 0)
            {
                return MATRIXSSL_ERROR;
            }
            *c = b1; c++;
            *c = b2; c++;
        }
#     endif /* USE_TLS_1_2 */


#     ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any) && ssl->retransmit)
        {
            Memcpy(c, ssl->certVerifyMsg, ssl->certVerifyMsgLen);
            c += ssl->certVerifyMsgLen;
        }
        else
        {
#     endif

        pkaAfter->inlen = hashSize;
        pkaAfter->type = PKA_AFTER_ECDSA_SIG_GEN;
        pkaAfter->data = pkiData;
        pkaAfter->outbuf = c;
        rc = chosen->privKey.keysize + 8;
        /* NEGATIVE ECDSA - Adding spot for ONE 0x0 byte in ECDSA so we'll
            be right 50% of the time.  521 curve doesn't need */
        if (chosen->privKey.keysize != 132)
        {
            rc += 1;
        }
        /* Above we added in the 8 bytes of overhead (2 sigLen, 1 SEQ,
            1 len (possibly 2!), 1 INT, 1 rLen, 1 INT, 1 sLen) and now
            subtract the first 3 bytes to see if the 1 len needs to be 2 */
        if (rc - 3 >= 128)
        {
            rc++;
        }
        pkaAfter->user = rc;
        c += rc;
#     ifdef USE_DTLS
        }
#     endif
    }
    else
    {
#    endif /* USE_ECC */

#    ifdef USE_RSA
#     ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        unsigned char b1, b2;

        if (chosen->cert->sigAlgorithm != OID_RSASSA_PSS)
        {
            if (getSignatureAndHashAlgorithmEncoding(sigAlg,
                            &b1, &b2, &hashSize) < 0)
            {
                psTraceInfo("Need additional hash support for certVerify\n");
                return MATRIXSSL_ERROR;
            }
            *c = b1; c++;
            *c = b2; c++;
        }
#      ifdef USE_PKCS1_PSS
        /* Special handling for OID_RSASSA_PSS, since it is not yet
           supported by the sigAlg functions. */
        else if (chosen->cert->sigAlgorithm == OID_RSASSA_PSS)
        {
            if (chosen->cert->pssHash == PKCS1_SHA1_ID ||
                chosen->cert->pssHash == PKCS1_MD5_ID)
            {
                *c = 0x2; c++;
                hashSize = SHA1_HASH_SIZE;
            }
            else if (chosen->cert->pssHash == PKCS1_SHA256_ID)
            {
                *c = 0x4; c++;
                hashSize = SHA256_HASH_SIZE;
#       ifdef USE_SHA384
            }
            else if (chosen->cert->pssHash == PKCS1_SHA384_ID)
            {
                *c = 0x5; c++;
                hashSize = SHA384_HASH_SIZE;
#       endif
#       ifdef USE_SHA512
            }
            else if (chosen->cert->pssHash == PKCS1_SHA512_ID)
            {
                *c = 0x6; c++;
                hashSize = SHA512_HASH_SIZE;
#       endif
            }
            else
            {
                psTraceInfo("Need additional hash support for certVerify\n");
                return MATRIXSSL_ERROR;
            }
            *c = 0x1; c++;     /* RSA */
        }
#      endif /* USE_PKCS1_PSS */
        else
        {
            psTraceInfo("Need additional hash support for certVerify\n");
            return MATRIXSSL_ERROR;
        }

        pkaAfter->type = PKA_AFTER_RSA_SIG_GEN_ELEMENT;     /* this one */
    }
    else
    {
        pkaAfter->type = PKA_AFTER_RSA_SIG_GEN;
    }
#     else /* ! USE_TLS_1_2 */
    pkaAfter->type = PKA_AFTER_RSA_SIG_GEN;
#     endif /* USE_TLS_1_2 */

    *c = (chosen->privKey.keysize & 0xFF00) >> 8; c++;
    *c = (chosen->privKey.keysize & 0xFF); c++;

#     ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any) && ssl->retransmit)
    {
        pkaAfter->type = 0;     /* reset so AFTER logic doesn't trigger */
        Memcpy(c, ssl->certVerifyMsg, ssl->certVerifyMsgLen);
        c += ssl->certVerifyMsgLen;
    }
    else
    {
#     endif
    pkaAfter->data = pkiData;
    pkaAfter->inlen = hashSize;
    pkaAfter->outbuf = c;
    c += chosen->privKey.keysize;
#     ifdef USE_DTLS
}
#     endif

#    else /* RSA is the 'default' so if that didn't get hit there is a problem */
    psTraceInfo("There is no handler for writeCertificateVerify.  ERROR\n");
    return MATRIXSSL_ERROR;
#    endif /* USE_RSA */
#    ifdef USE_ECC
}     /* Closing sigAlgorithm test */
#    endif /* USE_ECC */

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CERTIFICATE_VERIFY, messageSize, padLen, encryptStart, out,
             &c)) < 0)
    {
        return rc;
    }
    out->end = c;

    return MATRIXSSL_SUCCESS;
}
#   endif /* USE_CLIENT_AUTH */
#  endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

#else /* USE_CLIENT_SIDE_SSL */
/******************************************************************************/
/*
    Stub out this function rather than ifdef it out in the public header
 */
int32_t matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
    const psCipher16_t cipherSpec[], uint8_t cipherSpecLen,
    uint32 *requiredLen, tlsExtension_t *userExt,
    sslSessOpts_t *options)
{
    psTraceInfo("Library not built with USE_CLIENT_SIDE_SSL\n");
    return PS_UNSUPPORTED_FAIL;
}
#endif /* USE_CLIENT_SIDE_SSL */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
/******************************************************************************/
/*
    Write the CertificateRequest message (client auth only)
    The message contains the list of CAs the server is willing to accept
    children certificates of from the client.
 */
static int32 writeCertificateRequest(ssl_t *ssl, sslBuf_t *out, int32 certLen,
    int32 certCount)
{
    unsigned char *c, *end, *encryptStart;
    psX509Cert_t *cert;
    uint8_t padLen;
    psSize_t messageSize, sigHashLen = 0;
    int32_t rc;

    psTracePrintHsMessageCreate(ssl, SSL_HS_CERTIFICATE_REQUEST);

    c = out->end;
    end = out->buf + out->size;

    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                  4 + (certCount * 2) + certLen;
#   ifdef USE_ECC
    messageSize += 1; /* Adding ECDSA_SIGN type */
#   endif /* USE_ECC */

#   ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        /* TLS 1.2 has a SignatureAndHashAlgorithm type after CertType */
        sigHashLen = 2;
#    ifdef USE_ECC
#     ifdef USE_SHA384
        sigHashLen += 6;
#     else
        sigHashLen += 4;
#     endif /* USE_SHA */
#    endif  /* USE_ECC */
#    ifdef USE_RSA
#     ifdef USE_SHA384
        sigHashLen += 6;
#     else
        sigHashLen += 4;
#     endif /* USE_SHA */
#    endif  /* USE_RSA */
        messageSize += sigHashLen;
    }
#   endif /* TLS_1_2 */

    if ((messageSize - ssl->recordHeadLen) > ssl->maxPtFrag)
    {
        return writeMultiRecordCertRequest(ssl, out, certLen, certCount,
            sigHashLen);
    }

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
#   ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any))
        {
/*
                Is this the fragment case?
 */
            if (rc == DTLS_MUST_FRAG)
            {
#    ifdef USE_CLIENT_AUTH
                rc = dtlsWriteCertificateRequest(ssl->hsPool, ssl,
                    certLen, certCount, sigHashLen, c);
                if (rc < 0)
                {
                    return rc;
                }
                c += rc;
#    endif      /* USE_CLIENT_AUTH */
                out->end = c;
                return MATRIXSSL_SUCCESS;
            }
        }
#   endif /* USE_DTLS */
        return rc;
    }

#   ifdef USE_ECC
    *c++ = 2;
    *c++ = ECDSA_SIGN;
#   else
    *c++ = 1;
#   endif
    *c++ = RSA_SIGN;
#   ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        /* RFC: "The interaction of the certificate_types and
           supported_signature_algorithms fields is somewhat complicated.
           certificate_types has been present in TLS since SSLv3, but was
           somewhat underspecified.  Much of its functionality is superseded
           by supported_signature_algorithms."

           The spec says the cert must support the hash/sig algorithm but
           it's a bit confusing what this means for the hash portion.
           Just going to use SHA1, SHA256, and SHA384 support.

           We're just sending the raw list of all sig algorithms that are
           compiled into the library.  It might be smart to look through the
           individual CA files here only send the pub key operations that
           they use but the CA info is sent explicitly anyway so the client
           can confirm they have a proper match.

           If a new algorithm is added here it will require additions to
           messageSize  directly above in this function and in the flight
           calculation in sslEncodeResponse */
        *c++ = 0x0;
        *c++ = sigHashLen - 2;
#    ifdef USE_ECC
#     ifdef USE_SHA384
        *c++ = 0x5; /* SHA384 */
        *c++ = 0x3; /* ECDSA */
        *c++ = 0x4; /* SHA256 */
        *c++ = 0x3; /* ECDSA */
        *c++ = 0x2; /* SHA1 */
        *c++ = 0x3; /* ECDSA */
#     else
        *c++ = 0x4; /* SHA256 */
        *c++ = 0x3; /* ECDSA */
        *c++ = 0x2; /* SHA1 */
        *c++ = 0x3; /* ECDSA */
#     endif
#    endif

#    ifdef USE_RSA
#     ifdef USE_SHA384
        *c++ = 0x5; /* SHA384 */
        *c++ = 0x1; /* RSA */
        *c++ = 0x4; /* SHA256 */
        *c++ = 0x1; /* RSA */
        *c++ = 0x2; /* SHA1 */
        *c++ = 0x1; /* RSA */
#     else
        *c++ = 0x4; /* SHA256 */
        *c++ = 0x1; /* RSA */
        *c++ = 0x2; /* SHA1 */
        *c++ = 0x1; /* RSA */
#     endif
#    endif /* USE_RSA */
    }
#   endif /* TLS_1_2 */

    cert = ssl->keys->CAcerts;
    if (cert)
    {
        *c = ((certLen + (certCount * 2)) & 0xFF00) >> 8; c++;
        *c = (certLen + (certCount * 2)) & 0xFF; c++;
        while (cert)
        {
            if (cert->subject.dnenc == NULL)
            {
                return PS_FAIL;
            }
            *c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
            *c = cert->subject.dnencLen & 0xFF; c++;
            Memcpy(c, cert->subject.dnenc, cert->subject.dnencLen);
            c += cert->subject.dnencLen;
            cert = cert->next;
        }
    }
    else
    {
        *c++ = 0; /* Cert len */
        *c++ = 0;
    }
    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen, encryptStart, out,
             &c)) < 0)
    {
        return rc;
    }
    out->end = c;
    return MATRIXSSL_SUCCESS;
}



static int32 writeMultiRecordCertRequest(ssl_t *ssl, sslBuf_t *out,
    int32 certLen, int32 certCount, int32 sigHashLen)
{
    psX509Cert_t *cert = NULL;
    psX509Cert_t *future;
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize, dnencLen = 0;
    int32 midWrite, midSizeWrite, countDown, firstOne = 1;
    int32_t rc;

    c = out->end;
    end = out->buf + out->size;

    midSizeWrite = midWrite = 0;

    while (certLen > 0)
    {
        if (firstOne)
        {
            firstOne = 0;
            countDown = ssl->maxPtFrag;
            messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                          4 + (certCount * 2) + certLen + sigHashLen;
#   ifdef USE_ECC
            messageSize += 1; /* Adding ECDSA_SIGN type */
#   endif /* USE_ECC */
            if ((rc = writeRecordHeader(ssl,
                     SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG,
                     SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
                     &encryptStart, end, &c)) < 0)
            {
                return rc;
            }
#   ifdef USE_ECC
            *c++ = 2;
            *c++ = ECDSA_SIGN;
            countDown -= 2;
#   else
            *c++ = 1;
            countDown--;
#   endif
            *c++ = RSA_SIGN;
            countDown--;
#   ifdef USE_TLS_1_2
            if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
            {
                *c++ = 0x0;
                *c++ = sigHashLen - 2;
#    ifdef USE_ECC
#     ifdef USE_SHA384
                *c++ = 0x5; /* SHA384 */
                *c++ = 0x3; /* ECDSA */
                *c++ = 0x4; /* SHA256 */
                *c++ = 0x3; /* ECDSA */
                *c++ = 0x2; /* SHA1 */
                *c++ = 0x3; /* ECDSA */
#     else
                *c++ = 0x4; /* SHA256 */
                *c++ = 0x3; /* ECDSA */
                *c++ = 0x2; /* SHA1 */
                *c++ = 0x3; /* ECDSA */
#     endif
#    endif

#    ifdef USE_RSA
#     ifdef USE_SHA384
                *c++ = 0x5; /* SHA384 */
                *c++ = 0x1; /* RSA */
                *c++ = 0x4; /* SHA256 */
                *c++ = 0x1; /* RSA */
                *c++ = 0x2; /* SHA1 */
                *c++ = 0x1; /* RSA */
#     else
                *c++ = 0x4; /* SHA256 */
                *c++ = 0x1; /* RSA */
                *c++ = 0x2; /* SHA1 */
                *c++ = 0x1; /* RSA */
#     endif
#    endif /* USE_RSA */
                countDown -= sigHashLen;
            }
#   endif   /* TLS_1_2 */
            cert = ssl->keys->CAcerts;
            *c = ((certLen + (certCount * 2)) & 0xFF00) >> 8; c++;
            *c = (certLen + (certCount * 2)) & 0xFF; c++;
            countDown -= ssl->hshakeHeadLen + 2;
            while (cert)
            {
                if (cert->parseStatus != PS_X509_PARSE_SUCCESS)
                {
                    cert = cert->next;
                    continue;
                }
                if (cert->subject.dnenc == NULL)
                {
                    return PS_FAIL;
                }
                midWrite = 0;
                dnencLen = cert->subject.dnencLen;
                if (dnencLen > 0)
                {
                    if (countDown < 2)
                    {
                        /* Fragment falls right on dn len write.  Has
                            to be at least one byte or countDown would have
                            been 0 and got us out of here already*/
                        *c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
                        midSizeWrite = 1;
                        break;
                    }
                    else
                    {
                        *c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
                        *c = cert->subject.dnencLen & 0xFF; c++;
                        countDown -= 2;
                    }
                    midWrite = min(dnencLen, countDown);
                    Memcpy(c, cert->subject.dnenc, midWrite);
                    dnencLen -= midWrite;
                    c += midWrite;
                    certLen -= midWrite;
                    countDown -= midWrite;
                    if (countDown == 0)
                    {
                        break;
                    }
                }
                cert = cert->next;
            }
            if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
                     SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen,
                     encryptStart, out, &c)) < 0)
            {
                return rc;
            }
            out->end = c;
        }
        else
        {
            if (cert == NULL || cert->subject.dnenc == NULL)
            {
                return PS_FAIL;
            }
            /*  Not-first fragments */
            if (midSizeWrite > 0)
            {
                messageSize = midSizeWrite;
            }
            else
            {
                messageSize = 0;
            }
            if ((certLen + messageSize) > ssl->maxPtFrag)
            {
                messageSize += ssl->maxPtFrag;
            }
            else
            {
                messageSize += dnencLen;
                if (cert->next != NULL)
                {
                    future = cert->next;
                    while (future != NULL)
                    {
                        if (messageSize + future->subject.dnencLen + 2 >
                            (uint32) ssl->maxPtFrag)
                        {
                            messageSize = ssl->maxPtFrag;
                            future = NULL;
                        }
                        else
                        {
                            messageSize += 2 + future->subject.dnencLen;
                            future = future->next;
                        }

                    }
                }
            }
            countDown = messageSize;
            messageSize += ssl->recordHeadLen;
            /* Second, etc... */
            if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE_FRAG,
                     SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
                     &encryptStart, end, &c)) < 0)
            {
                return rc;
            }
            if (midSizeWrite > 0)
            {
                *c = (dnencLen & 0xFF); c++;
                countDown -= 1;
            }
            midSizeWrite = 0;
            if (countDown < dnencLen)
            {
                Memcpy(c, cert->subject.dnenc + midWrite, countDown);
                dnencLen -= countDown;
                c += countDown;
                certLen -= countDown;
                midWrite += countDown;
                countDown = 0;
            }
            else
            {
                Memcpy(c, cert->subject.dnenc + midWrite, dnencLen);
                c += dnencLen;
                certLen -= dnencLen;
                countDown -= dnencLen;
                dnencLen -= dnencLen;
            }
            while (countDown > 0)
            {
                cert = cert->next;
                if (cert == NULL || cert->subject.dnenc == NULL)
                {
                    return PS_FAIL;
                }
                dnencLen =  cert->subject.dnencLen;
                midWrite = 0;
                if (countDown < 2)
                {
                    /* Fragment falls right on cert len write */
                    *c = (unsigned char) ((dnencLen & 0xFF00) >> 8);
                    c++; countDown--;
                    midSizeWrite = 1;
                    break;
                }
                else
                {
                    *c = (unsigned char) ((dnencLen & 0xFF00) >> 8); c++;
                    *c = (dnencLen & 0xFF); c++;
                    countDown -= 2;
                }
                midWrite = min(dnencLen, countDown);
                Memcpy(c, cert->subject.dnenc, midWrite);
                dnencLen -= midWrite;
                c += midWrite;
                certLen -= midWrite;
                countDown -= midWrite;
                if (countDown == 0)
                {
                    break;
                }
            }
            if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
                     SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen,
                     encryptStart, out, &c)) < 0)
            {
                return rc;
            }
            out->end = c;

        }

    }
    out->end = c;
    return MATRIXSSL_SUCCESS;
}
#  endif /* USE_SERVER_SIDE && USE_CLIENT_AUTH */
# endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_DTLS
#  ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    DTLS specific handshake message to verify client existence
 */
static int32 writeHelloVerifyRequest(ssl_t *ssl, sslBuf_t *out)
{
    unsigned char *c, *end, *encryptStart;
    uint8_t padLen;
    psSize_t messageSize;
    int32_t rc;

    psTracePrintHsMessageCreate(ssl, SSL_HS_HELLO_VERIFY_REQUEST);

    c = out->end;
    end = out->buf + out->size;
/*
    The magic 3 bytes consist of the 2 byte TLS version and the 1 byte length
 */
    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
                  DTLS_COOKIE_SIZE + 3;

/*
    Always have to reset msn to zero because we don't know if this is a
    resend to a cookie-less CLIENT_HELLO that never receieved our verify
    request
 */
    ssl->msn = 0;

    if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_HELLO_VERIFY_REQUEST, &messageSize, &padLen,
             &encryptStart, end, &c)) < 0)
    {
        return rc;
    }

    /*
      Message content is version, cookie length, and cookie itself.

      RFC 6347, section 4.2.1 is contradictory regarding which version
      we should encode as server_version in HelloRetryRequest (see errata
      4103). We could either use DTLS 1.0 here or the negotiated version.
      We choose the former.
    */
    *c++ = DTLS_MAJ_VER;
    *c++ = DTLS_1_0_MIN_VER;
    *c++ = DTLS_COOKIE_SIZE;
    Memcpy(c, ssl->srvCookie, DTLS_COOKIE_SIZE);
    c += DTLS_COOKIE_SIZE;

    if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
             SSL_HS_HELLO_VERIFY_REQUEST, messageSize, padLen, encryptStart,
             out, &c)) < 0)
    {
        return rc;
    }
    out->end = c;
    return MATRIXSSL_SUCCESS;
}
#  endif /* USE_SERVER_SIDE_SSL */
# endif  /* USE_DTLS */

/******************************************************************************/
/*
    Write out a SSLv3 record header.
    Assumes 'c' points to a buffer of at least SSL3_HEADER_LEN bytes
        1 byte type (SSL_RECORD_TYPE_*)
        1 byte major version
        1 byte minor version
        2 bytes length (network byte order)
    Returns the number of bytes written
 */
int32 psWriteRecordInfo(ssl_t *ssl, unsigned char type, int32 len,
    unsigned char *c, int32 hsType)
{
    int32 explicitNonce = 0;

    if (type == SSL_RECORD_TYPE_HANDSHAKE_FRAG)
    {
        type = SSL_RECORD_TYPE_HANDSHAKE;
    }
    *c = type; c++;
    *c = psEncodeVersionMaj(GET_ACTV_VER(ssl)); c++;
    *c = psEncodeVersionMin(GET_ACTV_VER(ssl)); c++;
# ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        ssl->seqDelay = c;
        *c = ssl->epoch[0]; c++;
        *c = ssl->epoch[1]; c++;
        *c = ssl->rsn[0]; c++;
        *c = ssl->rsn[1]; c++;
        *c = ssl->rsn[2]; c++;
        *c = ssl->rsn[3]; c++;
        *c = ssl->rsn[4]; c++;
        *c = ssl->rsn[5]; c++;
    }
# endif /* USE_DTLS */
    *c = (len & 0xFF00) >> 8; c++;
    *c = (len & 0xFF);

    if (hsType == SSL_HS_FINISHED)
    {
        if (ssl->cipher->flags & (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM))
        {
            explicitNonce++;
        }
    }
    else if (ssl->flags & SSL_FLAGS_NONCE_W)
    {
        explicitNonce++;
    }
    if (explicitNonce)
    {
# ifdef USE_DTLS
        if (ACTV_VER(ssl, v_dtls_any))
        {
            c++;
            *c = ssl->epoch[0]; c++;
            *c = ssl->epoch[1]; c++;
            *c = ssl->rsn[0]; c++;
            *c = ssl->rsn[1]; c++;
            *c = ssl->rsn[2]; c++;
            *c = ssl->rsn[3]; c++;
            *c = ssl->rsn[4]; c++;
            *c = ssl->rsn[5]; c++;
        }
        else
        {
# endif /* USE_DTLS */
        c++;
        ssl->seqDelay = c; /* not being incremented in postpone mechanism */
        *c = ssl->sec.seq[0]; c++;
        *c = ssl->sec.seq[1]; c++;
        *c = ssl->sec.seq[2]; c++;
        *c = ssl->sec.seq[3]; c++;
        *c = ssl->sec.seq[4]; c++;
        *c = ssl->sec.seq[5]; c++;
        *c = ssl->sec.seq[6]; c++;
        *c = ssl->sec.seq[7];
# ifdef USE_DTLS
    }
# endif
        return ssl->recordHeadLen + TLS_EXPLICIT_NONCE_LEN;
    }

    return ssl->recordHeadLen;
}

/******************************************************************************/
/*
    Write out an ssl handshake message header.
    Assumes 'c' points to a buffer of at least ssl->hshakeHeadLen bytes
        1 byte type (SSL_HS_*)
        3 bytes length (network byte order)
    Returns the number of bytes written
 */
int32 psWriteHandshakeHeader(ssl_t *ssl, unsigned char type, int32 len,
    int32 seq, int32 fragOffset, int32 fragLen,
    unsigned char *c)
{
    *c = type; c++;
    *c = (unsigned char) ((len & 0xFF0000) >> 16); c++;
    *c = (len & 0xFF00) >> 8; c++;
# ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        *c = (len & 0xFF); c++;
        *c = (seq & 0xFF00) >> 8; c++;
        *c = (seq & 0xFF); c++;
        *c = (unsigned char) ((fragOffset & 0xFF0000) >> 16); c++;
        *c = (fragOffset & 0xFF00) >> 8; c++;
        *c = (fragOffset & 0xFF); c++;
        *c = (unsigned char) ((fragLen & 0xFF0000) >> 16); c++;
        *c = (fragLen & 0xFF00) >> 8; c++;
        *c = (fragLen & 0xFF);
    }
    else
    {
        *c = (len & 0xFF);
    }
# else
    *c = (len & 0xFF);
# endif /* USE_DTLS */

    ssl->encState = type;
    return ssl->hshakeHeadLen;
}

/******************************************************************************/
/*
    Write pad bytes and pad length per the TLS spec.  Most block cipher
    padding fills each byte with the number of padding bytes, but SSL/TLS
    pretends one of these bytes is a pad length, and the remaining bytes are
    filled with that length.  The end result is that the padding is identical
    to standard padding except the values are one less. For SSLv3 we are not
    required to have any specific pad values, but they don't hurt.

    PadLen      Result
    0
    1           00
    2           01 01
    3           02 02 02
    4           03 03 03 03
    5           04 04 04 04 04
    6           05 05 05 05 05 05
    7           06 06 06 06 06 06 06
    8           07 07 07 07 07 07 07 07
    9           08 08 08 08 08 08 08 08 08
    ...
    15          ...

    We calculate the length of padding required for a record using
    psPadLenPwr2()
 */
int32 sslWritePad(unsigned char *p, unsigned char padLen)
{
    unsigned char c = padLen;

    while (c > 0)
    {
        *p++ = padLen - 1;
        c--;
    }
    return padLen;
}

/******************************************************************************/

