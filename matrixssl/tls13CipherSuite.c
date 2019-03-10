/**
 *      @file    tls13CipherSuite.c
 *      @version $Format:%h%d$
 *
 *      Functions for TLS 1.3 ciphersuites.
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

# ifdef USE_TLS_1_3

/*
  5.3.  Per-Record Nonce:

  The per-record nonce for the AEAD
  construction is formed as follows:

  1.  The 64-bit record sequence number is encoded in network byte
  order and padded to the left with zeros to iv_length.

  2.  The padded sequence number is XORed with the static
  client_write_iv or server_write_iv, depending on the role.
*/
static inline
void tls13MakeWriteNonce(ssl_t *ssl, unsigned char nonceOut[12])
{
    psSize_t i;

    Memset(nonceOut, 0, 12);
    Memcpy(nonceOut + 4, ssl->sec.seq, 8);
    for (i = 0; i < 12; i++)
    {
        nonceOut[i] ^= ssl->sec.tls13WriteIv[i];
    }
}

static inline
void tls13MakeReadNonce(ssl_t *ssl, unsigned char nonceOut[12])
{
    psSize_t i;

    Memset(nonceOut, 0, 12);
    Memcpy(nonceOut + 4, ssl->sec.remSeq, 8);
    for (i = 0; i < 12; i++)
    {
        nonceOut[i] ^= ssl->sec.tls13ReadIv[i];
    }
}

static inline
void tls13MakeEncryptAad(ssl_t *ssl, unsigned char aadOut[5])
{
    aadOut[0] = SSL_RECORD_TYPE_APPLICATION_DATA;
    aadOut[1] = 0x03;
    aadOut[2] = 0x03;
    aadOut[3] = (ssl->outRecLen & 0xff00) >> 8;
    aadOut[4] = (ssl->outRecLen & 0xff);
}

static inline
void tls13MakeDecryptAad(ssl_t *ssl, unsigned char aadOut[5])
{
    aadOut[0] = SSL_RECORD_TYPE_APPLICATION_DATA;
    aadOut[1] = 0x03;
    aadOut[2] = 0x03;
    aadOut[3] = (ssl->rec.len & 0xff00) >> 8;
    aadOut[4] = (ssl->rec.len & 0xff);
}

int32 csAesGcmInitTls13(sslSec_t *sec, int32 type, uint32 keysize)
{
    int32 err;

    if (type == INIT_ENCRYPT_CIPHER)
    {
        Memset(&sec->encryptCtx.aesgcm, 0, sizeof(psAesGcm_t));
        if ((err = psAesInitGCM(&sec->encryptCtx.aesgcm, sec->writeKey,
                 keysize)) < 0)
        {
            return err;
        }
    }
    else
    {
        Memset(&sec->decryptCtx.aesgcm, 0, sizeof(psAesGcm_t));
        if ((err = psAesInitGCM(&sec->decryptCtx.aesgcm, sec->readKey,
                 keysize)) < 0)
        {
            return err;
        }
    }
    return 0;
}

int32 csAesGcmEncryptTls13(void *ssl, unsigned char *pt,
        unsigned char *ct, uint32 ptLen)
{
    ssl_t *lssl = ssl;
    psAesGcm_t *ctx;
    unsigned char nonce[12];
    unsigned char aad[5];
    int32 i;

    if (ptLen == 0)
    {
        return PS_SUCCESS;
    }

    ctx = &lssl->sec.encryptCtx.aesgcm;

    tls13MakeWriteNonce(lssl, nonce);

    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeEncryptAad(lssl, aad);
        psAesReadyGCM(ctx, nonce, aad, 5);
    }
    else
    {
        /* Before draft 25, no AAD was used. */
        psAesReadyGCM(ctx, nonce, NULL, 0);
    }
    psAesEncryptGCM(ctx, pt, ct, ptLen);
    psAesGetGCMTag(ctx, 16, ct + ptLen);

    /* Normally HMAC would increment the sequence */
    for (i = 7; i >= 0; i--)
    {
        lssl->sec.seq[i]++;
        if (lssl->sec.seq[i] != 0)
        {
            break;
        }
    }

#ifdef DEBUG_TLS_1_3_GCM
    psTraceBytes("csAesGcmEncryptTls13 output with tag", ct,
            ptLen + TLS_GCM_TAG_LEN);
    psTraceBytes("Encrypt AAD", aad, 5);
#endif

    return ptLen;
}

int32 csAesGcmDecryptTls13(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psAesGcm_t *ctx;
    int32 i, ctLen, bytes;
    unsigned char nonce[12];
    unsigned char aad[5];

    ctLen = len - TLS_GCM_TAG_LEN;
    if (ctLen <= 0)
    {
        return PS_LIMIT_FAIL;
    }

    ctx = &lssl->sec.decryptCtx.aesgcm;

    tls13MakeReadNonce(lssl, nonce);

    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeDecryptAad(lssl, aad);
        psAesReadyGCM(ctx, nonce, aad, 5);
    }
    else
    {
        /* Before draft 25, no AAD was used. */
        psAesReadyGCM(ctx, nonce, NULL, 0);
    }

    if ((bytes = psAesDecryptGCM(ctx, ct, len, pt, ctLen)) < 0)
    {
        return -1;
    }
    for (i = 7; i >= 0; i--)
    {
        lssl->sec.remSeq[i]++;
        if (lssl->sec.remSeq[i] != 0)
        {
            break;
        }
    }

#ifdef DEBUG_TLS_1_3_GCM
    psTraceBytes("csAesGcmDecryptTls13 output with tag", ct,
            ctLen);
    psTraceBytes("Decrypt AAD", aad, 5);
#endif

    return bytes;
}

#if defined(USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE)  || defined(USE_CHACHA20_POLY1305_IETF)
int32 csChacha20Poly1305IetfEncryptTls13(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psChacha20Poly1305Ietf_t *ctx;
    unsigned char nonce[TLS_AEAD_NONCE_MAXLEN];
    unsigned char aad[5];
    int32 i, ptLen;

    if (len == 0)
    {
        return PS_SUCCESS;
    }

    ptLen = len;
    ctx = &lssl->sec.encryptCtx.chacha20poly1305ietf;

    tls13MakeWriteNonce(lssl, nonce);
    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeEncryptAad(lssl, aad);
    }

#  ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceInfo("Entering csChacha20Poly1305IetfEncrypt IETF\n");
#  endif
    if (sizeof(lssl->sec.writeIV) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }
    if (sizeof(nonce) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }

# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceBytes("nonce", nonce, CHACHA20POLY1305_IETF_IV_FIXED_LENGTH);
    psTraceBytes("pt", pt, ptLen);
# endif

    /* Perform encryption and authentication tag computation */
    (void)psChacha20Poly1305IetfEncrypt(
            ctx,
            pt,
            ptLen,
            nonce,
            aad,
            5,
            ct);

# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceBytes("ct", ct, ptLen);
    psTraceBytes("tag", ct + ptLen, TLS_CHACHA20_POLY1305_IETF_TAG_LEN);
    psTraceBytes("aad", aad, 5);
# endif

    /* Normally HMAC would increment the sequence */
    for (i = (TLS_AEAD_SEQNB_LEN - 1); i >= 0; i--)
    {
        lssl->sec.seq[i]++;
        if (lssl->sec.seq[i] != 0)
        {
            break;
        }
    }
    return len;
}

int32 csChacha20Poly1305IetfDecryptTls13(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psChacha20Poly1305Ietf_t *ctx;
    int32 i, bytes;
#  ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    int32 ctLen;
#  endif
    unsigned char nonce[TLS_AEAD_NONCE_MAXLEN];
    unsigned char aad[5];

    ctx = &lssl->sec.decryptCtx.chacha20poly1305ietf;

    tls13MakeReadNonce(lssl, nonce);
    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeDecryptAad(lssl, aad);
    }

    /* Check https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-06 */

#  ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceInfo("Entering csChacha20Poly1305IetfDecrypt IETF\n");
#  endif

    if (sizeof(lssl->sec.readIV) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }
    if (sizeof(nonce) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }

    /* Update length of encrypted data: we have to remove tag's length */
    if (len < TLS_CHACHA20_POLY1305_IETF_TAG_LEN)
    {
        return PS_LIMIT_FAIL;
    }
# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    ctLen = len - TLS_CHACHA20_POLY1305_IETF_TAG_LEN;
    psTraceBytes("nonce", nonce, CHACHA20POLY1305_IETF_IV_FIXED_LENGTH);
    psTraceBytes("ct", ct, ctLen);
    psTraceBytes("tag", ct + ctLen, TLS_CHACHA20_POLY1305_IETF_TAG_LEN);
    psTraceBytes("aad", aad, 5);
# endif

    /* --- Check authentication tag and decrypt data ---// */
    if ((bytes = psChacha20Poly1305IetfDecrypt(ctx,
                            ct,
                            len,
                            nonce,
                            aad,
                            5,
                            pt)) < 0)
    {
# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
        psTraceInfo("Decrypt NOK\n");
# endif
        return -1;
    }

    for (i = (TLS_AEAD_SEQNB_LEN - 1); i >= 0; i--)
    {
        lssl->sec.remSeq[i]++;
        if (lssl->sec.remSeq[i] != 0)
        {
            break;
        }
    }

    return bytes + TLS_CHACHA20_POLY1305_IETF_TAG_LEN;
}
#endif /* DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE */

int32_t tls13GetCipherHmacAlg(ssl_t *ssl)
{
    if (ssl->cipher->ident == 0)
    {
        return 0;
    }

    if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3)
    {
        return HMAC_SHA384;
    }
    else
    {
        return HMAC_SHA256;
    }
}

psResSize_t tls13GetCipherHashSize(ssl_t *ssl)
{
    return (psGetOutputBlockLength(tls13GetCipherHmacAlg(ssl)));
}

int32_t tls13CipherIdToHmacAlg(uint32_t cipherId)
{
    switch(cipherId)
    {
    case TLS_AES_128_GCM_SHA256:
    case TLS_CHACHA20_POLY1305_SHA256:
    case TLS_AES_128_CCM_SHA_256:
    case TLS_AES_128_CCM_8_SHA256:
        return HMAC_SHA256;
    case TLS_AES_256_GCM_SHA384:
        return HMAC_SHA384;
    }

    return 0;
}

psBool_t isTls13Ciphersuite(uint16_t suite)
{
    switch (suite)
    {
    case TLS_AES_128_GCM_SHA256:
    case TLS_CHACHA20_POLY1305_SHA256:
    case TLS_AES_128_CCM_SHA_256:
    case TLS_AES_128_CCM_8_SHA256:
    case TLS_AES_256_GCM_SHA384:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }
}
# endif /* USE_TLS_1_3 */
