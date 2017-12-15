/**
 *      @file    dtls.c
 *      @version $Format:%h%d$
 *
 *      DTLS specific code.
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

#ifdef USE_DTLS
/******************************************************************************/

static int32 globalPmtu;

# ifdef USE_SERVER_SIDE_SSL

#  ifndef DTLS_COOKIE_KEY_SIZE
#   define DTLS_COOKIE_KEY_SIZE 32
#  endif /* DTLS_COOKIE_KEY_SIZE */

#  if DTLS_COOKIE_KEY_SIZE < 16
#   error "DTLS_COOKIE_KEY_SIZE too small (recommended 32 or more)."
#  endif /* DTLS_COOKIE_KEY_SIZE */

/* The cookie key is generated once on startup. */
static unsigned char cookie_key[DTLS_COOKIE_KEY_SIZE] = { 0 };

int32 dtlsGenCookieSecret(void)
{
    int i;
    int32 res;

    /* Check if cookie_key appears ok from first octets.
       Retry at most three times if values appear not ok (too many zeroes). */
    for (i = 0; i < 4; i++)
    {
        res = psGetPrngLocked(cookie_key, DTLS_COOKIE_KEY_SIZE,
            NULL);
        if ((cookie_key[0] | cookie_key[1] | cookie_key[2] |
             cookie_key[3]) != 0)
        {
            return res;
        }
    }
    return PS_FAILURE; /* Unable to get cookie_key from RNG. */
}

int32_t dtlsComputeCookie(ssl_t *ssl, unsigned char *helloBytes, int32 helloLen)
{
    unsigned char hmacKey[SHA256_HASHLEN];
    unsigned char out[SHA256_HASHLEN];
    psSize_t hmacKeyLen;
    int32_t rc;

    /* Ensure cookie_key has been initialized.
       (Initialization at dtlsGenCookieSecret() makes sure one of first
       four bytes is non-zero if initialization succeeded. */
    if ((cookie_key[0] | cookie_key[1] | cookie_key[2] | cookie_key[3]) == 0)
    {
        return PS_FAIL;
    }
#  ifdef USE_HMAC_SHA256
#   if DTLS_COOKIE_SIZE > SHA256_HASHLEN
#    error "DTLS_COOKIE_SIZE too large"
#   endif
    rc = psHmacSha256(cookie_key, DTLS_COOKIE_KEY_SIZE, helloBytes, helloLen,
        out, hmacKey, &hmacKeyLen);
#  elif defined (USE_HMAC_SHA1)
#   if DTLS_COOKIE_SIZE > SHA1_HASHLEN
#    error "DTLS_COOKIE_SIZE too large"
#   endif
    rc = psHmacSha1(cookie_key, DTLS_COOKIE_KEY_SIZE, helloBytes, helloLen,
        out, hmacKey, &hmacKeyLen);
#  else
#   error Must define HMAC_SHA256 or HMAC_SHA1 with DTLS
#  endif
    if (rc >= 0)
    {
        /* Truncate hash output if necessary */
        memcpy(ssl->srvCookie, out, DTLS_COOKIE_SIZE);
    }
    memzero_s(out, DTLS_COOKIE_SIZE);
    return rc;
}
# endif /* USE_SERVER_SIDE_SSL */

/******************************************************************************/
/*
    The PS_MIN_PMTU value is enforced to keep all handshake messages other
    than CERTIFIATE to contained within a single datagram
 */
int32 matrixDtlsSetPmtu(int32 pmtu)
{
    if (pmtu < 0)
    {
        globalPmtu = DTLS_PMTU;
    }
    else
    {
        globalPmtu = pmtu;
    }
    if (globalPmtu < PS_MIN_PMTU)
    {
        psTraceIntDtls("PMTU set too small.  Defaulting to %d\n", PS_MIN_PMTU);
        globalPmtu = PS_MIN_PMTU;
    }
    return globalPmtu;
}

int32 matrixDtlsGetPmtu(void)
{
    return globalPmtu;
}

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
static int32 fragmentHSMessage(ssl_t *ssl, unsigned char *msg, int32 msgLen,
                               int32 hsType, unsigned char *c);
static int32 postponeEncryptFragRecord(ssl_t *ssl, int32 padLen,
                                       int32 fragCount, int32 fragLen, int32 msgLen, int32 type,
                                       int32 hsMsg, unsigned char *encryptStart, unsigned char **c);
#  endif
/******************************************************************************/
/*
    The certificate message spans records
 */
int32 dtlsWriteCertificate(ssl_t *ssl, int32 certLen, int32 lsize,
    unsigned char *c)
{
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    psX509Cert_t *cert;
    unsigned char *tmp, *tmpStart;
    int32 tmpLen, wLen;
/*
    DTLS fragmented writes are done backwards.  The message info is written
    to a temp buffer and the hs header and record header are wrapped around
    that as the fragmentation is done.
 */
    tmpLen = certLen + lsize;
    tmpStart = tmp = psMalloc(NULL, tmpLen);
    if (tmpStart == NULL)
    {
        return SSL_MEM_ERROR;
    }

    *tmp = (unsigned char) (((certLen + (lsize - 3)) & 0xFF0000) >> 16); tmp++;
    *tmp = ((certLen + (lsize - 3)) & 0xFF00) >> 8; tmp++;
    *tmp = ((certLen + (lsize - 3)) & 0xFF); tmp++;

    if (certLen > 0)
    {
        cert = ssl->keys->cert;
        while (cert)
        {
            certLen = cert->binLen;
            if (certLen > 0)
            {
                *tmp = (unsigned char) ((certLen & 0xFF0000) >> 16); tmp++;
                *tmp = (certLen & 0xFF00) >> 8; tmp++;
                *tmp = (certLen & 0xFF); tmp++;
                memcpy(tmp, cert->unparsedBin, certLen);
                tmp += certLen;
            }
            cert = cert->next;
        }
    }

/*
    Fragment it
 */
    wLen = fragmentHSMessage(ssl, tmpStart, tmpLen, SSL_HS_CERTIFICATE, c);
    psFree(tmpStart, NULL);
    return wLen;
#  else
    /* Wrapping in defines here to keep sslEncode a bit more clear.  Need
        this because 'cert' is not available on straight USE_CLIENT_SIDE
        and no danger here at all because an empty CERTIFICATE message will
        never need fragmentation.  This is just a compile issue */
    return 0;
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
}


#  if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
/******************************************************************************/
/*
    The certificate_request message spans records
 */
int32 dtlsWriteCertificateRequest(psPool_t *pool, ssl_t *ssl, int32 certLen,
    int32 certCount, int32 sigHashLen, unsigned char *c)
{
    psX509Cert_t *cert;
    unsigned char *tmp, *tmpStart;
    int32 tmpLen, wLen;

/*
    DTLS fragmented writes are done backwards.  The message info is written
    to a temp buffer and the hs header and record header are wrapped around
    that as the fragmentation is done.
 */
    tmpLen = certLen + 4 + (certCount * 2) + sigHashLen;
#   ifdef USE_ECC
    tmpLen++;
#   endif
    tmpStart = tmp = psMalloc(pool, tmpLen);
    if (tmpStart == NULL)
    {
        return SSL_MEM_ERROR;
    }

#   ifdef USE_ECC
    *tmp++ = 2;
    *tmp++ = ECDSA_SIGN;
#   else
    *tmp++ = 1;
#   endif
    *tmp++ = RSA_SIGN;
#   ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
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
        *tmp++ = 0x0;
        *tmp++ = sigHashLen - 2;
#    ifdef USE_ECC
#     ifdef USE_SHA384
        *tmp++ = 0x5; /* SHA384 */
        *tmp++ = 0x3; /* ECDSA */
        *tmp++ = 0x4; /* SHA256 */
        *tmp++ = 0x3; /* ECDSA */
        *tmp++ = 0x2; /* SHA1 */
        *tmp++ = 0x3; /* ECDSA */
#     else
        *tmp++ = 0x4; /* SHA256 */
        *tmp++ = 0x3; /* ECDSA */
        *tmp++ = 0x2; /* SHA1 */
        *tmp++ = 0x3; /* ECDSA */
#     endif
#    endif

#    ifdef USE_RSA
#     ifdef USE_SHA384
        *tmp++ = 0x5; /* SHA384 */
        *tmp++ = 0x1; /* RSA */
        *tmp++ = 0x4; /* SHA256 */
        *tmp++ = 0x1; /* RSA */
        *tmp++ = 0x2; /* SHA1 */
        *tmp++ = 0x1; /* RSA */
#     else
        *tmp++ = 0x4; /* SHA256 */
        *tmp++ = 0x1; /* RSA */
        *tmp++ = 0x2; /* SHA1 */
        *tmp++ = 0x1; /* RSA */
#     endif
#    endif /* USE_RSA */
    }
#   endif /* TLS_1_2 */

#   if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    cert = ssl->keys->CAcerts;
#   else
    cert = NULL;
#   endif
    if (cert)
    {
        *tmp = ((certLen + (certCount * 2)) & 0xFF00) >> 8; tmp++;
        *tmp = (certLen + (certCount * 2)) & 0xFF; tmp++;
        while (cert)
        {
            *tmp = (cert->subject.dnencLen & 0xFF00) >> 8; tmp++;
            *tmp = cert->subject.dnencLen & 0xFF; tmp++;
            memcpy(tmp, cert->subject.dnenc, cert->subject.dnencLen);
            tmp += cert->subject.dnencLen;
            cert = cert->next;
        }
    }
    else
    {
        *tmp++ = 0; /* Cert len */
        *tmp++ = 0;
    }

/*
    Fragment it
 */
    wLen = fragmentHSMessage(ssl, tmpStart, tmpLen, SSL_HS_CERTIFICATE_REQUEST,
        c);
    psFree(tmpStart, pool);
    return wLen;
}
#  endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */

#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/******************************************************************************/
/*
    Given the data message and lengths, chunk up the message into a
    multi-record handshake message
 */
static int32 fragmentHSMessage(ssl_t *ssl, unsigned char *msg, int32 msgLen,
    int32 hsType, unsigned char *c)
{
    unsigned char *msgStart, *encryptStart;
    int32 tmpLen, recordLen, fragLen, offset, fragCount,
          padLen, overhead, secureOverhead;

    offset = fragCount = padLen = secureOverhead = 0;
    msgStart = c;
    tmpLen = msgLen;

    overhead = ssl->recordHeadLen + ssl->hshakeHeadLen;

    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) && (ssl->enBlockSize > 1))
    {
        secureOverhead = ssl->enMacSize +        /* handshake msg hash */
                         (ssl->enBlockSize * 2); /* explictIV and max pad */

    }
    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        secureOverhead += AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl);
    }

    while (tmpLen > 0)
    {
        if (tmpLen >= (ssl->pmtu - overhead - secureOverhead))
        {
            recordLen = ssl->pmtu - ssl->recordHeadLen;
            fragLen = ssl->pmtu - overhead - secureOverhead;
        }
        else
        {
            recordLen = tmpLen + ssl->hshakeHeadLen;
            fragLen = tmpLen;
        }

        /* Make secure adjustments */
        if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) && (ssl->enBlockSize > 1))
        {
            recordLen = fragLen + ssl->hshakeHeadLen + ssl->enMacSize +
                        ssl->enBlockSize;
            padLen = psPadLenPwr2(recordLen, ssl->enBlockSize);
            recordLen += padLen;
        }
        /* Make secure adjustments for final fragment */
        if (ssl->flags & SSL_FLAGS_AEAD_W)
        {
            recordLen = fragLen + ssl->hshakeHeadLen + secureOverhead;
        }

        c += psWriteRecordInfo(ssl, SSL_RECORD_TYPE_HANDSHAKE, recordLen, c,
            hsType);
        encryptStart = c;

        if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) && (ssl->enBlockSize > 1))
        {
            if (psGetPrngLocked(c, ssl->enBlockSize, ssl->userPtr) < 0)
            {
                psTraceDtls("WARNING: psGetPrngLocked failed\n");
            }
            c += ssl->enBlockSize;
        }
        c += psWriteHandshakeHeader(ssl, (unsigned char) hsType, msgLen,
            ssl->msn, offset, fragLen, c);

        memcpy(c, msg, fragLen);
        msg += fragLen;
        c += fragLen;
        offset += fragLen;
        tmpLen -= fragLen;

        postponeEncryptFragRecord(ssl, padLen, fragCount, fragLen,
            msgLen, SSL_RECORD_TYPE_HANDSHAKE, hsType, encryptStart, &c);

        fragCount++;
    }
/*
    Can now safely increment the MSN now that all fragments are written
 */
    ssl->msn++;

/*
    In theory, there is no reason the sender of the fragmented messages
    should care how many fragments it used but we should warn if
    MAX_FRAGMENTS has been exceeded because if the DTLS peer was also
    linked with the same MatrixSSL library, there will be a problem on
    that side when parsing
 */
    if (fragCount > MAX_FRAGMENTS)
    {
        psTraceIntDtls("Warning:  MAX_FRAGMENTS exceeded %d\n",
            MAX_FRAGMENTS);
    }
    return (int32) (c - msgStart);
}

static int32 postponeEncryptFragRecord(ssl_t *ssl, int32 padLen,
    int32 fragCount, int32 fragLen, int32 msgLen, int32 type,
    int32 hsMsg, unsigned char *encryptStart, unsigned char **c)
{
    flightEncode_t *flight, *prev;

    if ((flight = psMalloc(ssl->flightPool, sizeof(flightEncode_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }
    memset(flight, 0x0, sizeof(flightEncode_t));
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

    flight->start = encryptStart;
    flight->len = fragLen;
    flight->type = type;
    flight->padLen = padLen;
    flight->messageSize = msgLen;
    flight->hsMsg = hsMsg;
    flight->seqDelay = ssl->seqDelay;
    flight->fragCount = ++fragCount; /* Add one to differentiate from 0 based */

    *c += ssl->enMacSize;
    *c += padLen;

    if (hsMsg == SSL_HS_FINISHED)
    {
        if (ssl->cipher->flags & (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_CCM))
        {
            *c += AEAD_TAG_LEN(ssl);
        }
    }
    else if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        *c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
                                    tag has not yet been accounted for */
    }

    return PS_SUCCESS;
}


int32 dtlsEncryptFragRecord(ssl_t *ssl, flightEncode_t *msg,
    sslBuf_t *out, unsigned char **c)
{
    unsigned char *updateHash, *encryptStart;
    unsigned char fakeHeader[SSL3_HANDSHAKE_HEADER_LEN + DTLS_HEADER_ADD_LEN];

    encryptStart = out->end + ssl->recordHeadLen;

    updateHash = msg->start;
    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) && (ssl->enBlockSize > 1))
    {
        updateHash += ssl->enBlockSize;
        /* The data has already been bypassed in c at this point, FYI */
        *c += ssl->enBlockSize;
    }

    if (msg->fragCount == 1)
    {
        /*
            Can snapshot hs hash now.  A bit tricky because we have to treat
            the message as if there is no fragmentation at all.  This means
            we actually are hashing a header format that isn't really
            sent at all.  We deal with this by flaging the first fragment
            and manually tweaking the fragLen value.
         */
        memcpy(fakeHeader, updateHash, ssl->hshakeHeadLen);
/*
        A bit ugly.  The fragLen is the final three bytes of the header
 */
        fakeHeader[ssl->hshakeHeadLen - 3] =
            (unsigned char) ((msg->messageSize & 0xFF0000) >> 16);
        fakeHeader[ssl->hshakeHeadLen - 2] = (msg->messageSize & 0xFF00) >> 8;
        fakeHeader[ssl->hshakeHeadLen - 1] = (msg->messageSize & 0xFF);
        sslUpdateHSHash(ssl, fakeHeader, ssl->hshakeHeadLen);
    }
    sslUpdateHSHash(ssl, updateHash + ssl->hshakeHeadLen, msg->len);
    *c += ssl->hshakeHeadLen;

    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        encryptStart += AEAD_NONCE_LEN(ssl);
        ssl->outRecType = (unsigned char) msg->type;
    }

    if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) && (ssl->enBlockSize > 1))
    {
        *c += ssl->generateMac(ssl, (unsigned char) msg->type,
            encryptStart + ssl->enBlockSize,
            (int32) (*c - encryptStart) - ssl->enBlockSize, *c);
    }
    *c += sslWritePad(*c, (unsigned char) msg->padLen);

    if (ssl->flags & SSL_FLAGS_AEAD_W)
    {
        *c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
                                    tag has not yet been accounted for */
    }

    if (ssl->encrypt(ssl, encryptStart, encryptStart,
            (int32) (*c - encryptStart)) < 0)
    {
        psTraceInfo("Error encrypting message for write\n");
        return PS_FAILURE;
    }

    dtlsIncrRsn(ssl);

    return 0;
}
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
# endif  /* !USE_ONLY_PSK_CIPHER_SUITES */

/******************************************************************************/
/*
    Have all the fragments and their headers.  Feed them through the
    UpdateHSHash routine in the order they were on the other side
 */
int32 dtlsHsHashFragMsg(ssl_t *ssl)
{
    unsigned char fakeHeader[SSL3_HANDSHAKE_HEADER_LEN + DTLS_HEADER_ADD_LEN];
    int32 i, nextOffset, headLen, totalLen;

/*
    Construct the message from the fragments (may be out of order)
 */
    nextOffset = i = totalLen = 0;
    while (i < MAX_FRAGMENTS)
    {
        if (ssl->fragHeaders[i].offset == nextOffset)
        {
/*
            We must send this message through the handshake hash mechanism
            as if there was no fragmentation at all.  A nextOffset value
            of 0 will always mean this is the first fragment.  This header
            has everything correct except the fragLen value.  This must
            be manually changed to be the full 'len' value.  The remainder
            of the fragment headers are not used.
 */
            if (nextOffset == 0)
            {
                headLen = SSL3_HANDSHAKE_HEADER_LEN + DTLS_HEADER_ADD_LEN;
                memcpy(fakeHeader, ssl->fragHeaders[i].hsHeader, headLen);
/*
                First byte is 'type'.  Next three are total length.  Final
                three are fragLen.
 */
                fakeHeader[headLen - 3] = fakeHeader[1];
                fakeHeader[headLen - 2] = fakeHeader[2];
                fakeHeader[headLen - 1] = fakeHeader[3];

                sslUpdateHSHash(ssl, fakeHeader, headLen);
/*
                Also grabbing the total length so we can make a smart loop exit
 */
                totalLen = fakeHeader[1] << 16;
                totalLen += fakeHeader[2] << 8;
                totalLen += fakeHeader[3];
            }
/*
            The remainder of the UpdateHS hash is simply the data from each frag
 */

            sslUpdateHSHash(ssl, ssl->fragMessage + ssl->fragHeaders[i].offset,
                ssl->fragHeaders[i].fragLen);

            nextOffset += ssl->fragHeaders[i].fragLen;
            i = 0;
        }
        else
        {
            if (nextOffset != 0 && nextOffset == totalLen)
            {
                break;
            }
            i++;
        }
    }
    return 0;
}

/******************************************************************************/
/*
 *      Replay detection, per IPSec
 *      http://www.faqs.org/rfcs/rfc2401.html Appendix C
 *      Returns 0 if packet disallowed, 1 if packet permitted
 */
enum
{
    ReplayWindowSize = 32
};
int32 dtlsChkReplayWindow(ssl_t *ssl, unsigned char *seq64)
{
    uint32_t diff, seq, lastSeq;
    unsigned char *ls64;

/*
    TODO DTLS - We truncate 48 bit sequence to 32bits to make it simpler here
 */
    seq = ((uint32_t) seq64[2] << 24) + ((uint32_t) seq64[3] << 16) +
          ((uint32_t) seq64[4] << 8) + (uint32_t) seq64[5];
    ls64 = ssl->lastRsn;
    lastSeq = ((uint32_t) ls64[2] << 24) + ((uint32_t) ls64[3] << 16) +
              ((uint32_t) ls64[4] << 8) + (uint32_t) ls64[5];

    if (seq == 0)
    {
        /* Need to differentiate between initial, duplicate, and epoch shift */
        if (lastSeq == 0 && ssl->rec.epoch[0] == 0 && ssl->rec.epoch[1] == 0)
        {
            ssl->dtlsBitmap = 0;
            return 1; /* initial one */
        }
        if (dtlsCompareEpoch(ssl->rec.epoch, ssl->resendEpoch) == 1 &&
            lastSeq > 0)
        {
            ssl->dtlsBitmap = 0;
            return 1; /* epoch shift */
        }
        if (lastSeq == 0xFFFFFFF)
        {
            ssl->dtlsBitmap = 0;
            return 1; /* wrapped */
        }
        return 0;     /* duplicate */
    }

    if (seq > lastSeq)                 /* new larger sequence number */
    {
        diff = seq - lastSeq;
        if (diff < ReplayWindowSize)   /* In window */
        {
            ssl->dtlsBitmap <<= diff;
            ssl->dtlsBitmap |= 1;      /* set bit for this packet */
        }
        else
        {
            ssl->lastRsn[0] = 1;       /* This packet has a "way larger" */
        }
        memcpy(ssl->lastRsn, seq64, 6);
        return 1;                   /* larger is good */
    }
    diff = lastSeq - seq;
    if (diff >= ReplayWindowSize)
    {
        return 0;                   /* too old or wrapped */
    }
    if (ssl->dtlsBitmap & ((int32) 1 << diff))
    {
        return 0;                                   /* already seen */
    }
    ssl->dtlsBitmap |= ((unsigned long) 1 << diff); /* mark as seen */
    return 1;                                       /* out of order but good */
}

/******************************************************************************/
/*
    Init ssl_t fragment members
 */
void dtlsInitFrag(ssl_t *ssl)
{
    int32 i;

/*
    This is also used for re-init so there may be memory to free here.
 */
    ssl->fragTotal = 0;
    for (i = 0; i < MAX_FRAGMENTS; i++)
    {
        ssl->fragHeaders[i].offset = -1;
        if (ssl->fragHeaders[i].hsHeader != NULL)
        {
            psFree(ssl->fragHeaders[i].hsHeader, ssl->hsPool);
            ssl->fragHeaders[i].hsHeader = NULL;
        }
    }
}

/******************************************************************************/
/*
    Return 1 if this fragment has been seen before.  Just reads the
    fragHeaders member.  Does not update.
 */
int32 dtlsSeenFrag(ssl_t *ssl, int32 fragOffset, int32 *hdrIndex)
{
    int32 i;

    for (i = 0; i < MAX_FRAGMENTS; i++)
    {
        if (ssl->fragHeaders[i].offset == -1)
        {
            *hdrIndex = i;
            return 0;
        }
        if (ssl->fragHeaders[i].offset == fragOffset)
        {
            return 1;
        }
    }
/*
    Max fragments exceeded error
 */
    return -1;
}

/******************************************************************************/
/*
    Treating this unsigned char array as a 48bit uint
 */
void dtlsIncrRsn(ssl_t *ssl)
{
    int32 i;

    for (i = 5; i >= 0; i--)
    {
        if ((int) ssl->rsn[i] < 0xFF)
        {
            ssl->rsn[i]++;
            if (ssl->rsn[i] > ssl->largestRsn[i])
            {
                ssl->largestRsn[i] = ssl->rsn[i];
            }
            break;
        }
        ssl->rsn[i] = 0;
    }
}

/*
    Treating this 2 byte unsigned char array as a uint16
 */
void incrTwoByte(ssl_t *ssl, unsigned char *c, int sending)
{
    int32 i;

    if (sending)
    {
        c[0] = ssl->largestEpoch[0];
        c[1] = ssl->largestEpoch[1];
    }

    for (i = 1; i >= 0; i--)
    {
        if ((int) c[i] < 0xFF)
        {
            c[i]++;
            if (sending)
            {
                if (c[i] > ssl->largestEpoch[i])
                {
                    ssl->largestEpoch[i] = c[i];
                }
            }
            break;
        }
        c[i] = 0;
    }
}

void zeroTwoByte(unsigned char *c)
{
    c[0] = 0;
    c[1] = 0;
}

void zeroSixByte(unsigned char *c)
{
    int32 i;

    for (i = 5; i >= 0; i--)
    {
        c[i] = 0;
    }
}

int32 dtlsCompareEpoch(unsigned char *incoming, unsigned char *expected)
{
    int32 i;

    for (i = 0; i < 2; i++)
    {
        if (incoming[i] < expected[i])
        {
            return -1;
        }
        if (incoming[i] > expected[i])
        {
            return 1;
        }
    }
    return 0;
}

/******************************************************************************/
/*
    Rewinding our context
 */
static int32 dtlsRevertWriteCipher(ssl_t *ssl)
{
    ssl->encrypt = ssl->oencrypt;
    ssl->generateMac = ssl->ogenerateMac;
    ssl->enMacSize = ssl->oenMacSize;
    ssl->nativeEnMacSize = ssl->oenNativeHmacSize;
    ssl->enIvSize = ssl->oenIvSize;
    ssl->enBlockSize = ssl->oenBlockSize;
    memcpy(ssl->sec.writeIV, ssl->owriteIV, ssl->oenIvSize);
# ifdef USE_NATIVE_TLS_ALGS
    memcpy(ssl->sec.writeMAC, ssl->owriteMAC, ssl->oenMacSize);
    memcpy(&ssl->sec.encryptCtx, &ssl->oencryptCtx,
        sizeof(psCipherContext_t));
# endif
# ifdef ENABLE_SECURE_REHANDSHAKES
    memcpy(ssl->myVerifyData, ssl->omyVerifyData, ssl->omyVerifyDataLen);
    ssl->myVerifyDataLen = ssl->omyVerifyDataLen;
# endif /* ENABLE_SECURE_REHANDSHAKES */

/*
    If the old versions of the write state indicate that we were in an
    unencrypted state, remove the SECURE_WRITE flags.  Block, MAC, and IV are
    sufficient tests for all potential cipher suites since only block ciphers
    are allowed for DTLS
 */
    if (ssl->oenMacSize == 0 && ssl->oenBlockSize == 0 && ssl->oenIvSize == 0)
    {
        ssl->flags &= ~SSL_FLAGS_WRITE_SECURE;
# ifdef USE_TLS_1_2
        ssl->flags &= ~SSL_FLAGS_AEAD_W;
        ssl->flags &= ~SSL_FLAGS_NONCE_W;
# endif /* USE_TLS_1_2 */
    }
    /* Case where moved to GCM on write FINISHED from CBC-SHA and need to get
        back to CBC-SHA */
    if (ssl->flags & SSL_FLAGS_AEAD_W && ssl->oenMacSize > 0)
    {
        ssl->flags &= ~SSL_FLAGS_AEAD_W;
        ssl->flags &= ~SSL_FLAGS_NONCE_W;
    }
    /* Case where moved to CBC-SHA on write FINISHED from GCM and need to get
        back to GCM */
    if (!(ssl->flags & SSL_FLAGS_AEAD_W) && ssl->oenMacSize == 0 &&
        ssl->oenIvSize > 0)
    {
        ssl->flags |= SSL_FLAGS_AEAD_W;
        ssl->flags |= SSL_FLAGS_NONCE_W;
    }

/*
    Toggle flag to reset the logic for determing HANDSHAKE_COMPLETE in
    the top level APIs
 */
    ssl->bFlags &= ~BFLAG_HS_COMPLETE;
    return 0;
}

/******************************************************************************/
/*

 */
static int32 dtlsResendFlight(ssl_t *ssl, psBuf_t *out)
{
    int32 rc;
    uint32 requiredLen = 0;      /* only added so far to get to compile */

/*
    Reset to the MSN and epoch of the first message in the current flight
 */
    ssl->msn = ssl->resendMsn;
    rc = dtlsCompareEpoch(ssl->epoch, ssl->resendEpoch);
    if (rc != 0)
    {
/*
        We are dealing with a CHANGE_CIPHER_SPEC flight resend so we must
        revert to the old write cipher
 */
        dtlsRevertWriteCipher(ssl);
/*
        It is also necessary to make sure rsn is updated to the largest
        previously sent record number because if this flight is a resend that
        includes the CHANGE_CIPHER_SPEC message so the rsn has been reset
 */
        ssl->rsn[0] = ssl->largestRsn[0];
        ssl->rsn[1] = ssl->largestRsn[1];
        ssl->rsn[2] = ssl->largestRsn[2];
        ssl->rsn[3] = ssl->largestRsn[3];
        ssl->rsn[4] = ssl->largestRsn[4];
        ssl->rsn[5] = ssl->largestRsn[5];
    }
    ssl->epoch[0] = ssl->resendEpoch[0];
    ssl->epoch[1] = ssl->resendEpoch[1];


encode:
    ssl->retransmit = 1;
    rc = sslEncodeResponse(ssl, out, &requiredLen);
    ssl->retransmit = 0;

    if (rc == PS_SUCCESS)
    {
        if (ssl->err != SSL_ALERT_NONE)
        {
            ssl->flags |= SSL_FLAGS_ERROR;
            return PS_FAILURE;
        }
    }

    if (rc == SSL_FULL)
    {
        psFree(out->buf, ssl->bufferPool);
        if ((out->buf = psMalloc(ssl->bufferPool, requiredLen)) == NULL)
        {
            return PS_MEM_FAIL;
        }
        out->start = out->end = out->buf;
        out->size = requiredLen;
        goto encode;
    }
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Takes a 'flight' of records and returns the length of how many full
    records from the front of the buffer can fit in a single pmtu.  Used
    by the sockets layer to send out an already fragmented flight with
    the proper byte lengths.
 */
static int32 dtlsGetNextRecordLen(ssl_t *ssl, int32 pmtu, sslBuf_t *out,
    int32 *recordLen)
{
    int32 tlen, len;
    unsigned char *newend;

    newend = out->start;
/*
    If pmtu is <= 0 the user wants a single record regardless
 */
    if (pmtu <= 0)
    {
        newend += ssl->recordHeadLen - 2; /* Find the last two bytes of len */
        len = (int32) (newend[0]) << 8;
        len += newend[1];
        len += ssl->recordHeadLen;  /* add record header length to the total */
        *recordLen = len;
        return 0;
    }

/*
    Could be called for non-fragmented cases as well.  Check to see if the
    whole thing will fit in a mtu and return that info if so
 */
    if ((out->end - out->start) < pmtu)
    {
        *recordLen = (int32) (out->end - out->start);
        return 0;
    }

/*
    Otherwise, send as much as will fit
 */
    tlen = len = 0;
    while (out->end > newend)
    {
        newend += ssl->recordHeadLen - 2; /* Find the last two bytes of len */
        len = (int32) * newend << 8; newend++;
        len += (int32) * newend; newend++;
        newend += len;
        len += ssl->recordHeadLen;  /* add record header length to the total */
/*
        See if more records can fit in this single write.  Just storing
        current length in temps and reading off the next one.  If it doesn't
        fit, just go with the temps.
 */
        if ((len + tlen) <= pmtu)
        {
            tlen += len;
            continue;
        }
        break;
    }
    *recordLen = tlen;

    return 0;
}

/******************************************************************************/
/*
    Manages the DTLS flight buffer to make sure each call will return data
    that is less than the PMTU (dtlsGetNextRecordLen).  Also, plays a role
    in determining whether a flight resend needs to happen. Basically, if there
    is no data in outbuf and this is the first call to this function under
    that condition, we assume this is the standard processing loop and return
    0 to indicate we are done with the flight.  Subsequent calls to this
    function in which no outdata exists (and not in an explicit app data mode)
    will rebuild the last handshake flight and start feeding it out again

    NOTE: This function must be called in a loop with a corresponding
    matrixDtlsSentData until this routine returns 0.
 */
int32 matrixDtlsGetOutdata(ssl_t *ssl, unsigned char **buf)
{
    psBuf_t tmp;
    int32 bytesToSend, rc;
    int16 safeToResend;

    if (!ssl || !buf)
    {
        return PS_ARG_FAIL;
    }

    tmp.buf = tmp.start = ssl->outbuf;
    tmp.end = tmp.buf + ssl->outlen;
    tmp.size = ssl->outsize;

/*
    First test is just to see if we are already in an app data mode with
    nothing in the outbuffer to send. Don't want to resend a handshake flight
 */
    if ((tmp.end == tmp.start) && (ssl->appDataExch == 1))
    {
        *buf = NULL;
        return 0;
    }

/*
    Next, if ssl->outbuf is empty and flightDone is set, this is the mechansim
    for the handshake loop to know the full flight has been sent.  Return
    0 and flag the flight as needing a resend for the cases in which we
    come back in here with a zero buffer (a timeout happen and resend needed)
 */
    if ((tmp.end == tmp.start) && (ssl->flightDone == 1))
    {
        ssl->flightDone = 0;
        *buf = NULL;
        return 0;
    }

/*
    If ssl->outbuf is empty and not in appDataExch mode this is a flight resend
 */
    if ((tmp.end == tmp.start) && (ssl->appDataExch == 0))
    {

        /* And now the ugly part.  If we have been receiving records that
           are sent individually and we are successfully midway through an
           incomming flight, we don't want to resend our previous flight.  We
           are still just waiting for the remainder of the flight from the peer.
           The only way to figure this out is to test our specific state to
           make sure we are on a flight boundary.  This gets somewhat complicated
           simply due to the different types of handshakes (standard, resumed,
           and client auth) having different flight boundaries.

           The state is always the handshake message you expect to be receiving
           from the peer.
         */
        safeToResend = 0;

        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            if (ssl->hsState == SSL_HS_CLIENT_HELLO)
            {
                safeToResend = 1; /* any handshake type */
            }
            if (!(ssl->flags & SSL_FLAGS_RESUMED))
            {
                if (ssl->hsState == SSL_HS_DONE)
                {
                    safeToResend = 1; /* DONE set on parse of peer FINISHED */
                }
            }

# ifdef USE_CLIENT_AUTH
            /* Different client auth boundary for second flight */
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                if (ssl->hsState == SSL_HS_CERTIFICATE)
                {
                    safeToResend = 1;
                }
            }
            else
            {
# endif     /* USE_CLIENT_AUTH */
            if (ssl->hsState == SSL_HS_CLIENT_KEY_EXCHANGE)
            {
                safeToResend = 1;
            }
# ifdef USE_CLIENT_AUTH
        }
# endif     /* USE_CLIENT_AUTH */

            if (ssl->flags & SSL_FLAGS_RESUMED)
            {
                if (ssl->hsState == SSL_HS_FINISHED)
                {
                    safeToResend = 1;
                }
            }

        }
        else
        {
            /* Client tests */
            if (ssl->hsState == SSL_HS_SERVER_HELLO)
            {
                safeToResend = 1;
            }
            if (!(ssl->flags & SSL_FLAGS_RESUMED))
            {
                if (ssl->hsState == SSL_HS_FINISHED)
                {
                    safeToResend = 1;
                }
            }
            if (ssl->hsState == SSL_HS_DONE)
            {
                safeToResend = 1; /* Done is set on parse of peer FINISHED */
            }

        }

        if (safeToResend == 0)
        {
            psTraceIntDtls("Refused a resend due to state %d\n", ssl->hsState);
            *buf = NULL;
            return 0;
        }

        /* A true flight resend is needed */
        if ((rc = dtlsResendFlight(ssl, &tmp)) < 0)
        {
            return rc;
        }
        ssl->outbuf = tmp.buf;
        ssl->outlen = tmp.end - tmp.start;
        ssl->outsize = tmp.size;
    }

/*
    Sending records individually is more of a test mode for being able to
    drop more packets to test re-ordering and resend logic.  In either case,
    PMTU size will always be adhered to.
 */
# ifdef DTLS_SEND_RECORDS_INDIVIDUALLY
    dtlsGetNextRecordLen(ssl, 0, &tmp, &bytesToSend);
# else
    dtlsGetNextRecordLen(ssl, matrixDtlsGetPmtu(), &tmp, &bytesToSend);
# endif

    *buf = ssl->outbuf;
    return bytesToSend;
}

/******************************************************************************/
/*
    Plays the other half in determining flight resends.  If this send ate all
    the bytes in outbuf AND we are known not to be in a appDataExch state, we
    flag flightDone so the next call to matrixDtlsGetOutdata will know to
    return 0 instead of resending the flight.

    NOTE: If this peer ONLY sends app data and never receives any in return it
    is possible to get into a state where flightDone is set after each app
    data send since appDataExch will never be flagged.  The consequence of this
    scenario would be that the ChangeCipherSpec and Finished message will be
    sent if matrixDtlsGetOutdata is called with no application data to send.
    Not really a big deal, actually, since it should be ignored by the peer
 */
int32 matrixDtlsSentData(ssl_t *ssl, uint32 bytes)
{
    int32 rc;

    rc = matrixSslSentData(ssl, bytes);
/*
    NOTE: appDataExch only gets set on the receipt of an application data
 */
    if (ssl->outlen == 0 && ssl->appDataExch == 0)
    {
        ssl->flightDone = 1;
    }
    return rc;
}

#endif /* USE_DTLS */

