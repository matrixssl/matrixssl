/**
 *      @file    tls13TrHash.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 Transcript-Hash, also called session hash or handshake hash.
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
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

#include "matrixsslImpl.h"

# ifdef USE_TLS_1_3

# ifndef DEBUG_TLS_1_3_TRANSCRIPT_HASH
/* #  define DEBUG_TLS_1_3_TRANSCRIPT_HASH */
# endif

static inline int32_t getHashAlg(ssl_t *ssl)
{
    /* Only supporting the ciphersuites defined in the TLS 1.3 draft spec.
       Only SHA-256 and SHA-384. */
    if (ssl->cipher == NULL)
    {
        return OID_SHA256_ALG;
    }

    if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3)
    {
        return OID_SHA384_ALG;
    }
    else
    {
        return OID_SHA256_ALG;
    }
}

int32_t tls13TranscriptHashInit(ssl_t *ssl)
{
    int32_t alg;

    if (ssl->cipher == NULL || ssl->cipher->ident == SSL_NULL_WITH_NULL_NULL)
    {
        /* When parsing ClientHello, the ciphersuite has not been negotiated
           yet, which means that do not know which hash we will end up using.
           Initialize both.*/
        psTraceInfo("Initialising Transcript-Hash with both SHA-256 and 384\n");
        psSha256Init(&ssl->sec.tls13msgHashSha256);
        psSha384Init(&ssl->sec.tls13msgHashSha384);
        return MATRIXSSL_SUCCESS;
    }

    alg = getHashAlg(ssl);

    switch(alg)
    {
    case OID_SHA256_ALG:
        psTraceInfo("Initialising Transcript-Hash with Hash == SHA256\n");
        psSha256Init(&ssl->sec.tls13msgHashSha256);
        break;
    case OID_SHA384_ALG:
        psTraceInfo("Initialising Transcript-Hash with Hash == SHA384\n");
        psSha384Init(&ssl->sec.tls13msgHashSha384);
        break;
    default:
        psTraceErrr("Unsupported TLS 1.3 hash alg\n");
        return PS_UNSUPPORTED_FAIL;
    }

    return MATRIXSSL_SUCCESS;
}

int32_t tls13TranscriptHashReinit(ssl_t *ssl)
{
    int32_t rc;
    int32_t alg;
    unsigned char messageHash[1 + 3 + MAX_TLS_1_3_HASH_SIZE];
    psSize_t messageHashLen;

    alg = getHashAlg(ssl);

    psTraceInfo("tls13TranscriptHashReinit\n");

    /*
      When the server responds to a
      ClientHello with a HelloRetryRequest, the value of ClientHello1 is
      replaced with a special synthetic handshake message of handshake type
      "message_hash" containing Hash(ClientHello1).  I.e.,

      Transcript-Hash(ClientHello1, HelloRetryRequest, ... MN) =
         Hash(message_hash ||        // Handshake type
              00 00 Hash.length ||   // Handshake message length (bytes)
              Hash(ClientHello1) ||  // Hash of ClientHello1
              HelloRetryRequest ... MN)
    */
    rc = tls13TranscriptHashFinish(ssl, ssl->sec.tls13TrHashSnapshotCH1);
    if (rc < 0)
    {
        return rc;
    }
    rc = tls13TranscriptHashInit(ssl);
    if (rc < 0)
    {
        return rc;
    }

    messageHashLen = 4; /* Header. */
    messageHash[0] = 254;
    messageHash[1] = messageHash[2] = 0;
    if (alg == OID_SHA256_ALG)
    {
        messageHash[3] = SHA256_HASH_SIZE;
        Memcpy(messageHash + 4,
                ssl->sec.tls13TrHashSnapshotCH1,
                SHA256_HASH_SIZE);
        messageHashLen += SHA256_HASH_SIZE;
    }
    else
    {
        messageHash[3] = SHA384_HASH_SIZE;
        Memcpy(messageHash + 4,
                ssl->sec.tls13TrHashSnapshotCH1,
                SHA384_HASH_SIZE);
        messageHashLen += SHA384_HASH_SIZE;
    }

    rc = tls13TranscriptHashUpdate(ssl,
            messageHash,
            messageHashLen);
    if (rc < 0)
    {
        return rc;
    }

    /* Caller should now call update for HelloRetryRequest. */

    return MATRIXSSL_SUCCESS;
}

int32_t tls13TranscriptHashUpdate(ssl_t *ssl,
                                  const unsigned char *in,
                                  psSize_t len)
{
    int32_t alg;

    /* Also the < 1.3 hash must be updated before we know that
       we end up with TLS1.3 */

    /* In case of client we originally send 1.3 ClientHello and thus
       update the legacy hash from 1.3 side to 1.2.
       In case of server we originally parse ClientHello in the 1.2 side
       and later move to 1.3. That's why the hash functions call each other
       both ways */
    if (!NGTD_VER(ssl, v_tls_1_3_any) && !IS_SERVER(ssl))
    {
        sslUpdateHSHash(ssl, in, len);
    }

    if (ssl->cipher == NULL || ssl->cipher->ident == SSL_NULL_WITH_NULL_NULL)
    {
        /* When parsing ClientHello, the ciphersuite has not been negotiated
           yet, which means that do not know which hash we will end up using.
           Update both.*/
        psSha256Update(&ssl->sec.tls13msgHashSha256, in, len);
        psSha384Update(&ssl->sec.tls13msgHashSha384, in, len);
# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
        psTracePrintTranscriptHashUpdate(ssl, in, len, OID_SHA256_ALG);
        psTracePrintTranscriptHashUpdate(ssl, in, len, OID_SHA384_ALG);
# endif
        return MATRIXSSL_SUCCESS;
    }

    alg = getHashAlg(ssl);

    switch(alg)
    {
    case OID_SHA256_ALG:
        psSha256Update(&ssl->sec.tls13msgHashSha256, in, len);
        break;
    case OID_SHA384_ALG:
        psSha384Update(&ssl->sec.tls13msgHashSha384, in, len);
        break;
    default:
        psTraceErrr("Unsupported TLS 1.3 hash alg\n");
        return PS_UNSUPPORTED_FAIL;
    }

# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
        psTracePrintTranscriptHashUpdate(ssl, in, len, alg);
# endif

    return MATRIXSSL_SUCCESS;
}

int32_t tls13TranscriptHashFinish(ssl_t *ssl,
                                  unsigned char *out)
{
    int32_t alg = getHashAlg(ssl);

    switch(alg)
    {
    case OID_SHA256_ALG:
        {
            psSha256_t sha256;

            psSha256Cpy(&sha256, &ssl->sec.tls13msgHashSha256);
            psSha256Final(&sha256, out);
# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
            psTraceBytes("Transcript-Hash SHA-256 snapshot", out, 32);
# endif
        }
        break;
    case OID_SHA384_ALG:
        {
            psSha384_t sha384;

            psSha384Cpy(&sha384, &ssl->sec.tls13msgHashSha384);
            psSha384Final(&sha384, out);
# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
            psTraceBytes("Transcript-Hash SHA-384 snapshot", out, 48);
# endif
        }
        break;
    default:
        psTraceErrr("Unsupported TLS 1.3 hash alg\n");
        return PS_UNSUPPORTED_FAIL;
    }

    return MATRIXSSL_SUCCESS;
}

int32_t tls13TranscriptHashSnapshotAlg(ssl_t *ssl,
        int32_t alg,
        unsigned char *out)
{

    switch(alg)
    {
    case OID_SHA256_ALG:
        {
            psSha256_t sha256;

            psSha256Sync(&ssl->sec.tls13msgHashSha256, 0);
            sha256 = ssl->sec.tls13msgHashSha256;
            psSha256Final(&sha256, out);
        }
        break;
    case OID_SHA384_ALG:
        {
            psSha384_t sha384;

            psSha384Sync(&ssl->sec.tls13msgHashSha384, 0);
            sha384 = ssl->sec.tls13msgHashSha384;
            psSha384Final(&sha384, out);
        }
        break;
    default:
        psTraceErrr("Unsupported TLS 1.3 hash alg\n");
        return PS_UNSUPPORTED_FAIL;
    }

    return MATRIXSSL_SUCCESS;
}

int32_t tls13TranscriptHashSnapshot(ssl_t *ssl,
                                    unsigned char *out)
{
    int32_t alg = getHashAlg(ssl);

    return tls13TranscriptHashSnapshotAlg(ssl, alg, out);
}

# endif /* USE_TLS_1_3 */
