/**
 *      @file    cipherSuite.c
 *      @version $Format:%h%d$
 *
 *      Wrappers for the various cipher suites..
 *      Enable specific suites at compile time in matrixsslConfig.h
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
/*      Symmetric cipher initializtion wrappers for cipher suites */
/******************************************************************************/
/*
    SSL_NULL_WITH_NULL_NULL cipher functions
    Used in handshaking before SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC message
 */
static int32 csNullInit(sslSec_t *sec, int32 type, uint32 keysize)
{
    return 0;
}

/******************************************************************************/
#if defined(USE_ARC4) && defined(USE_ARC4_CIPHER_SUITE)
/******************************************************************************/
static int32 csArc4Init(sslSec_t *sec, int32 type, uint32 keysize)
{
    if (type == INIT_ENCRYPT_CIPHER)
    {
        psArc4Init(&(sec->encryptCtx.arc4), sec->writeKey, keysize);
    }
    else
    {
        psArc4Init(&(sec->decryptCtx.arc4), sec->readKey, keysize);
    }
    return PS_SUCCESS;
}
int32 csArc4Encrypt(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psArc4_t *ctx = &lssl->sec.encryptCtx.arc4;

    psArc4(ctx, pt, ct, len);
    return len;
}
int32 csArc4Decrypt(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psArc4_t *ctx = &lssl->sec.decryptCtx.arc4;

    psArc4(ctx, ct, pt, len);
    return len;
}

#endif /* USE_ARC4_CIPHER_SUITE */
/******************************************************************************/

/******************************************************************************/
#if defined(USE_3DES) && defined (USE_3DES_CIPHER_SUITE)
/******************************************************************************/
static int32 csDes3Init(sslSec_t *sec, int32 type, uint32 keysize)
{
    int32 err;

    psAssert(keysize == DES3_KEYLEN);

    if (type == INIT_ENCRYPT_CIPHER)
    {
        if ((err = psDes3Init(&(sec->encryptCtx.des3), sec->writeIV, sec->writeKey)) < 0)
        {
            return err;
        }
    }
    else
    {
        if ((err = psDes3Init(&(sec->decryptCtx.des3), sec->readIV, sec->readKey)) < 0)
        {
            return err;
        }
    }
    return PS_SUCCESS;
}

int32 csDes3Encrypt(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psDes3_t *ctx = &lssl->sec.encryptCtx.des3;

    if ((len & 0x7) != 0)
    {
        psTraceErrr("Invalid plaintext length in csDes3Encrypt\n");
        return PS_FAILURE;
    }

    psDes3Encrypt(ctx, pt, ct, len);
    return len;
}

int32 csDes3Decrypt(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psDes3_t *ctx = &lssl->sec.decryptCtx.des3;

    if ((len & 0x7) != 0)
    {
        psTraceErrr("Invalid ciphertext length in csDes3Decrypt\n");
        return PS_FAILURE;
    }

    psDes3Decrypt(ctx, ct, pt, len);
    return len;
}

#endif /* USE_3DES_CIPHER_SUITE */
/******************************************************************************/

#ifdef USE_AES_CIPHER_SUITE

# ifdef USE_NATIVE_AES
#  if defined(USE_TLS_1_2)
#   ifdef USE_AES_GCM
int32 csAesGcmInit(sslSec_t *sec, int32 type, uint32 keysize)
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

int32 csAesGcmEncrypt(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psAesGcm_t *ctx;
    unsigned char nonce[12];
    unsigned char aad[TLS_GCM_AAD_LEN];
    int32 i, ptLen, seqNotDone;

    if (len == 0)
    {
        return PS_SUCCESS;
    }

    if (len < 16 + 1)
    {
        return PS_LIMIT_FAIL;
    }
    ptLen = len - TLS_GCM_TAG_LEN;

    ctx = &lssl->sec.encryptCtx.aesgcm;

    Memcpy(nonce, lssl->sec.writeIV, 4);

    seqNotDone = 1;
    /* Each value of the nonce_explicit MUST be distinct for each distinct
        invocation of the GCM encrypt function for any fixed key.  Failure to
        meet this uniqueness requirement can significantly degrade security.
        The nonce_explicit MAY be the 64-bit sequence number. */
#     ifdef USE_DTLS
    if (NGTD_VER(lssl, v_dtls_any))
    {
        Memcpy(nonce + 4, lssl->epoch, 2);
        Memcpy(nonce + 4 + 2, lssl->rsn, 6);
        /* In the case of DTLS the counter is formed from the concatenation of
            the 16-bit epoch with the 48-bit sequence number.*/
        Memcpy(aad, lssl->epoch, 2);
        Memcpy(aad + 2, lssl->rsn, 6);
        seqNotDone = 0;
    }
#     endif

    if (seqNotDone)
    {
        Memcpy(nonce + 4, lssl->sec.seq, TLS_EXPLICIT_NONCE_LEN);
        Memcpy(aad, lssl->sec.seq, 8);
    }
    aad[8] = lssl->outRecType;
    aad[9] = psEncodeVersionMaj(GET_NGTD_VER(lssl));
    aad[10] = psEncodeVersionMin(GET_NGTD_VER(lssl));
    aad[11] = ptLen >> 8 & 0xFF;
    aad[12] = ptLen & 0xFF;

    psAesReadyGCM(ctx, nonce, aad, TLS_GCM_AAD_LEN);
    psAesEncryptGCM(ctx, pt, ct, ptLen);
    psAesGetGCMTag(ctx, 16, ct + ptLen);

#     ifdef USE_DTLS
    if (NGTD_VER(lssl, v_dtls_any))
    {
        return len;
    }
#     endif

    /* Normally HMAC would increment the sequence */
    for (i = 7; i >= 0; i--)
    {
        lssl->sec.seq[i]++;
        if (lssl->sec.seq[i] != 0)
        {
            break;
        }
    }
    return len;
}

int32 csAesGcmDecrypt(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psAesGcm_t *ctx;
    int32 i, ctLen, bytes, seqNotDone;
    unsigned char nonce[12];
    unsigned char aad[TLS_GCM_AAD_LEN];

    ctx = &lssl->sec.decryptCtx.aesgcm;

    seqNotDone = 1;
    Memcpy(nonce, lssl->sec.readIV, 4);
    Memcpy(nonce + 4, ct, TLS_EXPLICIT_NONCE_LEN);
    ct += TLS_EXPLICIT_NONCE_LEN;
    len -= TLS_EXPLICIT_NONCE_LEN;

#    ifdef USE_DTLS
    if (NGTD_VER(lssl, v_dtls_any))
    {
        /* In the case of DTLS the counter is formed from the concatenation of
            the 16-bit epoch with the 48-bit sequence number.  */
        Memcpy(aad, lssl->rec.epoch, 2);
        Memcpy(aad + 2, lssl->rec.rsn, 6);
        seqNotDone = 0;
    }
#    endif

    if (seqNotDone)
    {
        Memcpy(aad, lssl->sec.remSeq, 8);
    }
    ctLen = len - TLS_GCM_TAG_LEN;
    aad[8] = lssl->rec.type;
    aad[9] = psEncodeVersionMaj(GET_NGTD_VER(lssl));
    aad[10] = psEncodeVersionMin(GET_NGTD_VER(lssl));
    aad[11] = ctLen >> 8 & 0xFF;
    aad[12] = ctLen & 0xFF;

    psAesReadyGCM(ctx, nonce, aad, TLS_GCM_AAD_LEN);

    if ((bytes = psAesDecryptGCM(ctx, ct, len, pt, len - TLS_GCM_TAG_LEN)) < 0)
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
    return bytes;
}
#   endif /* USE_AES_GCM */
#  endif  /* USE_TLS_1_2 || USE_TLS_1_3 */

#  ifdef USE_AES_CBC
/******************************************************************************/
int32 csAesInit(sslSec_t *sec, int32 type, uint32 keysize)
{
    int32 err;

    if (type == INIT_ENCRYPT_CIPHER)
    {
        Memset(&(sec->encryptCtx), 0, sizeof(psAesCbc_t));
        if ((err = psAesInitCBC(&sec->encryptCtx.aes, sec->writeIV, sec->writeKey,
                 keysize, PS_AES_ENCRYPT)) < 0)
        {
            return err;
        }
    }
    else     /* Init for decrypt */
    {
        Memset(&(sec->decryptCtx), 0, sizeof(psAesCbc_t));
        if ((err = psAesInitCBC(&sec->decryptCtx.aes, sec->readIV, sec->readKey,
                 keysize, PS_AES_DECRYPT)) < 0)
        {
            return err;
        }
    }
    return PS_SUCCESS;
}

int32 csAesEncrypt(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psAesCbc_t *ctx = &lssl->sec.encryptCtx.aes;

    if ((len & 0xf) != 0)
    {
        psTraceErrr("Invalid plaintext size in csAesEncrypt.\n");
        return PS_FAILURE;
    }

    psAesEncryptCBC(ctx, pt, ct, len);
    return len;
}

int32 csAesDecrypt(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psAesCbc_t *ctx = &lssl->sec.decryptCtx.aes;

    if ((len & 0xf) != 0)
    {
        psTraceErrr("Invalid ciphertext size in csAesDecrypt.\n");
        return PS_FAILURE;
    }

    psAesDecryptCBC(ctx, ct, pt, len);
    return len;
}
#  endif /*USE_AES_CBC */
# endif  /* USE_NATIVE_AES */
#endif   /* USE_AES_CIPHER_SUITE */

/******************************************************************************/

/* #define DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE */
#if defined(USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE)  || defined(USE_CHACHA20_POLY1305_IETF)

int32 csChacha20Poly1305IetfInit(sslSec_t *sec, int32 type, uint32 keysize)
{
    psRes_t err;

    psAssert(keysize == PS_CHACHA20POLY1305_IETF_KEYBYTES);

    if (type == INIT_ENCRYPT_CIPHER)
    {
# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
        psTraceInfo("Entering csChacha20Poly1305IetfInit encrypt\n");
        psTraceBytes("sec->writeKey", sec->writeKey, keysize);
# endif
        err = psChacha20Poly1305IetfInit(&sec->encryptCtx.chacha20poly1305ietf, sec->writeKey);
    }
    else
    {
# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
        psTraceInfo("Entering csChacha20Poly1305IetfInit decrypt\n");
        psTraceBytes("sec->readKey", sec->readKey, keysize);
# endif
        err = psChacha20Poly1305IetfInit(&sec->decryptCtx.chacha20poly1305ietf, sec->readKey);
    }
    return err;
}

int32 csChacha20Poly1305IetfEncrypt(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psChacha20Poly1305Ietf_t *ctx;
    unsigned char nonce[TLS_AEAD_NONCE_MAXLEN];
    unsigned char aad[TLS_CHACHA20_POLY1305_IETF_AAD_LEN];
    int32 i, ptLen;

    if (len == 0)
    {
        return PS_SUCCESS;
    }
    if (len < 16 + 1)
    {
        return PS_LIMIT_FAIL;
    }
    ptLen = len - TLS_CHACHA20_POLY1305_IETF_TAG_LEN;
    ctx = &lssl->sec.encryptCtx.chacha20poly1305ietf;

    Memset(nonce, 0, TLS_AEAD_NONCE_MAXLEN);
    Memset(aad, 0, TLS_CHACHA20_POLY1305_IETF_AAD_LEN);

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

    /* The nonce is built according to:
       https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */

    Memcpy(nonce + (CHACHA20POLY1305_IETF_IV_FIXED_LENGTH - TLS_AEAD_SEQNB_LEN),
            lssl->sec.seq, TLS_AEAD_SEQNB_LEN);

    for (i = 0; i < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH; i++)
    {
        nonce[i] ^= lssl->sec.writeIV[i];
    }
    /* --- Fill Additional data ---// */
    Memcpy(aad, lssl->sec.seq, TLS_AEAD_SEQNB_LEN);
    i = TLS_AEAD_SEQNB_LEN;

    aad[i++] = lssl->outRecType;
    aad[i++] = psEncodeVersionMaj(GET_NGTD_VER(lssl));
    aad[i++] = psEncodeVersionMin(GET_NGTD_VER(lssl));
    aad[i++] = ptLen >> 8 & 0xFF;
    aad[i++] = ptLen & 0xFF;

# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceBytes("nonce", nonce, CHACHA20POLY1305_IETF_IV_FIXED_LENGTH);
    psTraceBytes("aad", aad, TLS_CHACHA20_POLY1305_IETF_AAD_LEN);
    psTraceBytes("pt", pt, ptLen);
# endif

    /* Perform encryption and authentication tag computation */
    (void)psChacha20Poly1305IetfEncrypt(
            ctx,
            pt,
            ptLen,
            nonce,
            aad,
            TLS_CHACHA20_POLY1305_IETF_AAD_LEN,
            ct);

# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceBytes("ct", ct, ptLen);
    psTraceBytes("tag", ct + ptLen, TLS_CHACHA20_POLY1305_IETF_TAG_LEN);
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

int32 csChacha20Poly1305IetfDecrypt(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psChacha20Poly1305Ietf_t *ctx;
    int32 i, ctLen, bytes;

    unsigned char nonce[TLS_AEAD_NONCE_MAXLEN];
    unsigned char aad[TLS_CHACHA20_POLY1305_IETF_AAD_LEN];

    ctx = &lssl->sec.decryptCtx.chacha20poly1305ietf;

    Memset(nonce, 0, TLS_AEAD_NONCE_MAXLEN);
    Memset(aad, 0, TLS_CHACHA20_POLY1305_IETF_AAD_LEN);

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

    /* The nonce is built according to: https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */

    Memcpy(nonce + (CHACHA20POLY1305_IETF_IV_FIXED_LENGTH - TLS_AEAD_SEQNB_LEN), lssl->sec.remSeq, TLS_AEAD_SEQNB_LEN);

    for (i = 0; i < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH; i++)
    {
        nonce[i] ^= lssl->sec.readIV[i];
    }


    /* --- Fill Additional data ---// */
    Memcpy(aad, lssl->sec.remSeq, TLS_AEAD_SEQNB_LEN);
    i = TLS_AEAD_SEQNB_LEN;

    /* Update length of encrypted data: we have to remove tag's length */
    if (len < TLS_CHACHA20_POLY1305_IETF_TAG_LEN)
    {
        return PS_LIMIT_FAIL;
    }
    ctLen = len - TLS_CHACHA20_POLY1305_IETF_TAG_LEN;

    aad[i++] = lssl->rec.type;
    aad[i++] = psEncodeVersionMaj(GET_NGTD_VER(lssl));
    aad[i++] = psEncodeVersionMin(GET_NGTD_VER(lssl));
    aad[i++] = ctLen >> 8 & 0xFF;
    aad[i++] = ctLen & 0xFF;

# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceBytes("nonce", nonce, CHACHA20POLY1305_IETF_IV_FIXED_LENGTH);
    psTraceBytes("aad", aad, TLS_CHACHA20_POLY1305_IETF_AAD_LEN);
    psTraceBytes("ct", ct, ctLen);
    psTraceBytes("tag", ct + ctLen, TLS_CHACHA20_POLY1305_IETF_TAG_LEN);
    if (pt != ct)
    {
        psTraceInfo("Warning: ChaCha20 decrypt requires in-situ" \
                " for overlapping plaintext and ciphertext bufs\n");
    }
# endif

    /* --- Check authentication tag and decrypt data ---// */
    if ((bytes = psChacha20Poly1305IetfDecrypt(ctx, ct, len, nonce, aad, TLS_CHACHA20_POLY1305_IETF_AAD_LEN, pt)) < 0)
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

    return bytes;
}
#endif /* USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE */

/******************************************************************************/

#if defined(USE_IDEA) && defined(USE_IDEA_CIPHER_SUITE)
int32 csIdeaInit(sslSec_t *sec, int32 type, uint32 keysize)
{
    int32 err;

    if (type == INIT_ENCRYPT_CIPHER)
    {
        Memset(&(sec->encryptCtx), 0, sizeof(psCipherContext_t));
        if ((err = psIdeaInit(&(sec->encryptCtx.idea), sec->writeIV, sec->writeKey)) < 0)
        {
            return err;
        }
    }
    else     /* Init for decrypt */
    {
        Memset(&(sec->decryptCtx), 0, sizeof(psCipherContext_t));
        if ((err = psIdeaInit(&(sec->decryptCtx.idea), sec->readIV, sec->readKey)) < 0)
        {
            return err;
        }
    }
    return PS_SUCCESS;
}

int32 csIdeaEncrypt(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psIdea_t *ctx = &lssl->sec.encryptCtx.idea;

    psIdeaEncrypt(ctx, pt, ct, len);
    return len;
}

int32 csIdeaDecrypt(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psIdea_t *ctx = &lssl->sec.encryptCtx.idea;

    psIdeaDecrypt(ctx, ct, pt, len);
    return len;
}
#endif /* USE_IDEA_CIPHER_SUITE */

/******************************************************************************/
#if defined(USE_SEED) && defined(USE_SEED_CIPHER_SUITE)
/******************************************************************************/
static int32 csSeedInit(sslSec_t *sec, int32 type, uint32 keysize)
{
    int32 err;

    psAssert(keysize == SEED_KEYLEN);

    if (type == INIT_ENCRYPT_CIPHER)
    {
        Memset(&(sec->encryptCtx), 0, sizeof(psSeed_t));
        if ((err = psSeedInit(&(sec->encryptCtx.seed), sec->writeIV, sec->writeKey)) < 0)
        {
            return err;
        }
    }
    else
    {
        Memset(&(sec->decryptCtx), 0, sizeof(psSeed_t));
        if ((err = psSeedInit(&(sec->decryptCtx.seed), sec->readIV, sec->readKey)) < 0)
        {
            return err;
        }
    }
    return 0;
}
int32 csSeedEncrypt(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psSeed_t *ctx = &lssl->sec.encryptCtx.seed;

    psSeedEncrypt(ctx, pt, ct, len);
    return len;
}

int32 csSeedDecrypt(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psSeed_t *ctx = &lssl->sec.encryptCtx.seed;

    psSeedDecrypt(ctx, ct, pt, len);
    return len;
}

#endif /* USE_SEED_CIPHER_SUITE */
/******************************************************************************/


/******************************************************************************/
/*      Null cipher crypto */
/******************************************************************************/
static int32 csNullEncrypt(void *ctx, unsigned char *in,
    unsigned char *out, uint32 len)
{
    if (out != in)
    {
        Memcpy(out, in, len);
    }
    return len;
}

static int32 csNullDecrypt(void *ctx, unsigned char *in,
    unsigned char *out, uint32 len)
{
    if (out != in)
    {
        Memmove(out, in, len);
    }
    return len;
}

/******************************************************************************/
/*      HMAC wrappers for cipher suites */
/******************************************************************************/
static int32 csNullGenerateMac(void *ssl, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac)
{
    return 0;
}

static int32 csNullVerifyMac(void *ssl, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac)
{
    return 0;
}

#ifdef USE_SHA_MAC
/******************************************************************************/
static int32 csShaGenerateMac(void *sslv, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *macOut)
{
    ssl_t *ssl = (ssl_t *) sslv;
    unsigned char mac[MAX_HASH_SIZE];

    if (NGTD_VER(ssl, v_tls_with_hmac))
    {
        switch (ssl->nativeEnMacSize)
        {
# ifdef USE_SHA256
        case SHA256_HASH_SIZE:
# ifdef USE_SHA384
        case SHA384_HASH_SIZE:
# endif
            tlsHMACSha2(ssl, HMAC_CREATE, type,
                    data, len, mac, ssl->nativeEnMacSize);
            break;
# endif /* USE_SHA256 */
#  ifdef USE_SHA1
        case SHA1_HASH_SIZE:
            tlsHMACSha1(ssl, HMAC_CREATE, type,
                    data, len, mac);
            break;
#  endif /* USE_SHA1 */
        default:
            return PS_ARG_FAIL;
        }
    }
    else
    {
# ifdef DISABLE_SSLV3
        return PS_ARG_FAIL;
# else
        ssl3HMACSha1(ssl->sec.writeMAC, ssl->sec.seq, type,
                data, len, mac);
# endif
    }


    Memcpy(macOut, mac, ssl->enMacSize);
    return ssl->enMacSize;
}

static int32 csShaVerifyMac(void *sslv, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac)
{
    unsigned char buf[MAX_HASH_SIZE];
    ssl_t *ssl = (ssl_t *) sslv;

    if (NGTD_VER(ssl, v_tls_with_hmac))
    {
        switch (ssl->nativeDeMacSize)
        {
# ifdef USE_SHA256
        case SHA256_HASH_SIZE:
        case SHA384_HASH_SIZE:
            tlsHMACSha2(ssl, HMAC_VERIFY, type, data, len, buf,
                ssl->nativeDeMacSize);
            break;
# endif
# ifdef USE_SHA1
        case SHA1_HASH_SIZE:
            tlsHMACSha1(ssl, HMAC_VERIFY, type, data, len, buf);
            break;
# endif
        default:
            memzero_s(buf, ssl->nativeDeMacSize); /* Will fail below */
            break;
        }
    }
    else
    {
# ifndef DISABLE_SSLV3
        ssl3HMACSha1(ssl->sec.readMAC, ssl->sec.remSeq, type, data, len, buf);
# else
        memzero_s(buf, SHA1_HASH_SIZE); /* Will fail below */
# endif /* DISABLE_SSLV3 */
    }
    if (memcmpct(buf, mac, ssl->deMacSize) == 0)
    {
        return PS_SUCCESS;
    }
    return PS_FAILURE;
}
#endif /* USE_SHA_MAC */
/******************************************************************************/

/******************************************************************************/
#if defined(USE_MD5) && defined(USE_MD5_MAC)
/******************************************************************************/
static int32 csMd5GenerateMac(void *sslv, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *macOut)
{
    unsigned char mac[MD5_HASH_SIZE];
    ssl_t *ssl = (ssl_t *) sslv;

# ifdef USE_TLS
    if (NGTD_VER(ssl, v_tls_with_hmac))
    {
        tlsHMACMd5(ssl, HMAC_CREATE, type, data, len, mac);
    }
    else
    {
# endif /* USE_TLS */
# ifndef DISABLE_SSLV3
    ssl3HMACMd5(ssl->sec.writeMAC, ssl->sec.seq, type, data,
        len, mac);
# else
    return PS_ARG_FAIL;
# endif /* DISABLE_SSLV3 */
# ifdef USE_TLS
}
# endif /* USE_TLS */
    Memcpy(macOut, mac, ssl->enMacSize);
    return ssl->enMacSize;
}

static int32 csMd5VerifyMac(void *sslv, unsigned char type, unsigned char *data,
    uint32 len, unsigned char *mac)
{
    unsigned char buf[MD5_HASH_SIZE];
    ssl_t *ssl = (ssl_t *) sslv;

# ifdef USE_TLS
    if (NGTD_VER(ssl, v_tls_with_hmac))
    {
        tlsHMACMd5(ssl, HMAC_VERIFY, type, data, len, buf);
    }
    else
    {
# endif /* USE_TLS */
# ifndef DISABLE_SSLV3
    ssl3HMACMd5(ssl->sec.readMAC, ssl->sec.remSeq, type, data, len, buf);
# endif /* DISABLE_SSLV3 */
# ifdef USE_TLS
}
# endif /* USE_TLS */
    if (memcmpct(buf, mac, ssl->deMacSize) == 0)
    {
        return PS_SUCCESS;
    }
    return PS_FAILURE;
}
#endif /* USE_MD5_MAC */

/******************************************************************************/

#ifdef USE_SERVER_SIDE_SSL
/* Set of bits corresponding to supported cipher ordinal. If set, it is
    globally disabled */
static uint32_t disabledCipherFlags[8] = { 0 }; /* Supports up to 256 ciphers */
#endif

const static sslCipherSpec_t supportedCiphers[] = {
/*
    New ciphers should be added here, similar to the ones below

    Ciphers are listed in order of greater security at top... this generally
    means the slower ones are on top as well.

    256 ciphers max.

    The ordering of the ciphers is grouped and sub-grouped by the following:
    1. TLS 1.3
     2. Non-deprecated
      3. Ephemeral
       4. Authentication Method (PKI > PSK > anon)
        5. Hash Strength (SHA384 > SHA256 > SHA > MD5)
         6. Cipher Strength (AES256 > AES128 > 3DES > ARC4 > SEED > IDEA > NULL)
          7. PKI Key Exchange (DHE > ECDHE > ECDH > RSA > PSK)
           8. Cipher Mode (GCM > CBC)
            9. PKI Authentication Method (ECDSA > RSA > PSK)
 */

#ifdef USE_TLS_1_3
/* TLS 1.3 ciphersuites. */
# ifdef USE_TLS_AES_128_GCM_SHA256
    { TLS_AES_128_GCM_SHA256,                                     /* ident */
      CS_TLS13,                                                   /* type */
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,    /* flags */
      0,                                                          /* macSize */
      16,                                                         /* keySize */
      12,                                                         /* ivSize */
      0,                                                          /* blocksize */
      csAesGcmInitTls13,                                          /* init */
      csAesGcmEncryptTls13,                                       /* encrypt */
      csAesGcmDecryptTls13,                                       /* decrypt */
      NULL,                                                       /* generateMac */
      NULL },                                                     /* verifyMac */
# endif /* TLS_AES_128_GCM_SHA256 */

# ifdef USE_TLS_AES_256_GCM_SHA384
    { TLS_AES_256_GCM_SHA384,                                     /* ident */
      CS_TLS13,                                                   /* type */
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3, /* flags */
      0,                                                          /* macSize */
      32,                                                         /* keySize */
      12,                                                         /* ivSize */
      0,                                                          /* blocksize */
      csAesGcmInitTls13,                                          /* init */
      csAesGcmEncryptTls13,                                       /* encrypt */
      csAesGcmDecryptTls13,                                       /* decrypt */
      NULL,                                                       /* generateMac */
      NULL },                                                     /* verifyMac */
# endif /* TLS_AES_128_GCM_SHA256 */

# ifdef USE_TLS_CHACHA20_POLY1305_SHA256
    { TLS_CHACHA20_POLY1305_SHA256,                               /* ident */
      CS_TLS13,                                                   /* type */
      CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_SHA2,                    /* flags */
      0,                                                          /* macSize */
      32,                                                         /* keySize */
      CHACHA20POLY1305_IETF_IV_FIXED_LENGTH,                      /* ivSize */
      0,                                                          /* blocksize */
      csChacha20Poly1305IetfInit,                                 /* init */
      csChacha20Poly1305IetfEncryptTls13,                         /* encrypt */
      csChacha20Poly1305IetfDecryptTls13,                         /* decrypt */
      NULL,                                                       /* generateMac */
      NULL },                                                     /* verifyMac */
# endif /* USE_TLS_CHACHA20_POLY1305_SHA256 */
#endif /* USE_TLS_1_3 */
/* Ephemeral ciphersuites */
#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    { TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,                    /* ident */
      CS_ECDHE_ECDSA,                                             /* type */
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3, /* flags */
      0,                                                          /* macSize */
      32,                                                         /* keySize */
      4,                                                          /* ivSize */
      0,                                                          /* blocksize */
      csAesGcmInit,                                               /* init */
      csAesGcmEncrypt,                                            /* encrypt */
      csAesGcmDecrypt,                                            /* decrypt */
      NULL,                                                       /* generateMac */
      NULL },                                                     /* verifyMac */
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    { TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
      0,            /* macSize */
      32,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    { TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      CS_ECDHE_ECDSA,
      CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_SHA2,
      0,                                /* macSize */
      32,                               /* keySize */
      CHACHA20POLY1305_IETF_IV_FIXED_LENGTH, /* ivSize */
      0,                                /* blocksize */
      csChacha20Poly1305IetfInit,
      csChacha20Poly1305IetfEncrypt,
      csChacha20Poly1305IetfDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    { TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_SHA2,
      0,                                /* macSize */
      32,                               /* keySize */
      CHACHA20POLY1305_IETF_IV_FIXED_LENGTH, /* ivSize */
      0,                                /* blocksize */
      csChacha20Poly1305IetfInit,
      csChacha20Poly1305IetfEncrypt,
      csChacha20Poly1305IetfDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    { TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
      CS_ECDHE_ECDSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
      48,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
      48,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    { TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
      CS_DHE_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
      0,            /* macSize */
      32,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    { TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
      CS_DHE_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
      CS_DHE_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    { TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      CS_ECDHE_ECDSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
      0,            /* macSize */
      16,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
      0,            /* macSize */
      16,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
      CS_ECDHE_ECDSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    { TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
      CS_DHE_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    { TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
      CS_ECDHE_ECDSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
      CS_DHE_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
      CS_ECDHE_ECDSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    { SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
      CS_DHE_RSA,
      CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      24,           /* keySize */
      8,            /* ivSize */
      8,            /* blocksize */
      csDes3Init,
      csDes3Encrypt,
      csDes3Decrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA */


#ifdef USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    { TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
      CS_ECDHE_RSA,
      CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      24,           /* keySize */
      8,            /* ivSize */
      8,            /* blocksize */
      csDes3Init,
      csDes3Encrypt,
      csDes3Decrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
    { TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
      CS_DHE_PSK,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    { TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
      CS_DHE_PSK,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA */

/* Non-ephemeral ciphersuites */

#ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
    { TLS_RSA_WITH_AES_256_GCM_SHA384,
      CS_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
      0,            /* macSize */
      32,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    { TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
      CS_ECDH_ECDSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
      0,            /* macSize */
      32,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    { TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
      CS_ECDH_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
      0,            /* macSize */
      32,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    { TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
      CS_ECDH_ECDSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
      48,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    { TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
      CS_ECDH_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
      48,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
    { TLS_RSA_WITH_AES_256_CBC_SHA256,
      CS_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    { TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
      CS_ECDH_ECDSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
      0,            /* macSize */
      16,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
    { TLS_RSA_WITH_AES_128_GCM_SHA256,
      CS_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
      0,            /* macSize */
      16,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    { TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
      CS_ECDH_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
      0,            /* macSize */
      16,           /* keySize */
      4,            /* ivSize */
      0,            /* blocksize */
      csAesGcmInit,
      csAesGcmEncrypt,
      csAesGcmDecrypt,
      NULL,
      NULL },
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    { TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
      CS_ECDH_ECDSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
    { TLS_RSA_WITH_AES_128_CBC_SHA256,
      CS_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    { TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
      CS_ECDH_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    { TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
      CS_ECDH_ECDSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA
    { TLS_RSA_WITH_AES_256_CBC_SHA,
      CS_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    { TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
      CS_ECDH_RSA,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    { TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
      CS_ECDH_ECDSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA
    { TLS_RSA_WITH_AES_128_CBC_SHA,
      CS_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    { TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
      CS_ECDH_RSA,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    { SSL_RSA_WITH_3DES_EDE_CBC_SHA,
      CS_RSA,
      CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      24,           /* keySize */
      8,            /* ivSize */
      8,            /* blocksize */
      csDes3Init,
      csDes3Encrypt,
      csDes3Decrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA384
    { TLS_PSK_WITH_AES_256_CBC_SHA384,
      CS_PSK,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
      48,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_PSK_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA256
    { TLS_PSK_WITH_AES_128_CBC_SHA256,
      CS_PSK,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
      32,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_PSK_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA
    { TLS_PSK_WITH_AES_256_CBC_SHA,
      CS_PSK,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_PSK_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA
    { TLS_PSK_WITH_AES_128_CBC_SHA,
      CS_PSK,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_PSK_WITH_AES_128_CBC_SHA */

/* @security Deprecated weak ciphers */

#ifdef USE_SSL_RSA_WITH_RC4_128_SHA
    { SSL_RSA_WITH_RC4_128_SHA,
      CS_RSA,
      CRYPTO_FLAGS_ARC4 | CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      0,            /* ivSize */
      1,            /* blocksize */
      csArc4Init,
      csArc4Encrypt,
      csArc4Decrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_SSL_RSA_WITH_RC4_128_SHA */

#ifdef USE_TLS_RSA_WITH_SEED_CBC_SHA
    { TLS_RSA_WITH_SEED_CBC_SHA,
      CS_RSA,
      CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csSeedInit,
      csSeedEncrypt,
      csSeedDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_SSL_RSA_WITH_SEED_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_IDEA_CBC_SHA
    { TLS_RSA_WITH_IDEA_CBC_SHA,
      CS_RSA,
      CRYPTO_FLAGS_IDEA | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      8,            /* ivSize */
      8,            /* blocksize */
      csIdeaInit,
      csIdeaEncrypt,
      csIdeaDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_SSL_RSA_WITH_IDEA_CBC_SHA */

#ifdef USE_SSL_RSA_WITH_RC4_128_MD5
    { SSL_RSA_WITH_RC4_128_MD5,
      CS_RSA,
      CRYPTO_FLAGS_ARC4 | CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_MD5,
      16,           /* macSize */
      16,           /* keySize */
      0,            /* ivSize */
      1,            /* blocksize */
      csArc4Init,
      csArc4Encrypt,
      csArc4Decrypt,
      csMd5GenerateMac,
      csMd5VerifyMac },
#endif /* USE_SSL_RSA_WITH_RC4_128_MD5 */

/* @security Deprecated unencrypted ciphers */

#ifdef USE_SSL_RSA_WITH_NULL_SHA
    { SSL_RSA_WITH_NULL_SHA,
      CS_RSA,
      CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      0,            /* keySize */
      0,            /* ivSize */
      0,            /* blocksize */
      csNullInit,
      csNullEncrypt,
      csNullDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_SSL_RSA_WITH_NULL_SHA */

#ifdef USE_SSL_RSA_WITH_NULL_MD5
    { SSL_RSA_WITH_NULL_MD5,
      CS_RSA,
      CRYPTO_FLAGS_MD5,
      16,           /* macSize */
      0,            /* keySize */
      0,            /* ivSize */
      0,            /* blocksize */
      csNullInit,
      csNullEncrypt,
      csNullDecrypt,
      csMd5GenerateMac,
      csMd5VerifyMac },
#endif /* USE_SSL_RSA_WITH_NULL_MD5 */

/* @security Deprecated unauthenticated ciphers */

#ifdef USE_TLS_DH_anon_WITH_AES_256_CBC_SHA
    { TLS_DH_anon_WITH_AES_256_CBC_SHA,
      CS_DH_ANON,
      CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      32,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DH_anon_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DH_anon_WITH_AES_128_CBC_SHA
    { TLS_DH_anon_WITH_AES_128_CBC_SHA,
      CS_DH_ANON,
      CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      16,           /* keySize */
      16,           /* ivSize */
      16,           /* blocksize */
      csAesInit,
      csAesEncrypt,
      csAesDecrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_TLS_DH_anon_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
    { SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,
      CS_DH_ANON,
      CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
      20,           /* macSize */
      24,           /* keySize */
      8,            /* ivSize */
      8,            /* blocksize */
      csDes3Init,
      csDes3Encrypt,
      csDes3Decrypt,
      csShaGenerateMac,
      csShaVerifyMac },
#endif /* USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_SSL_DH_anon_WITH_RC4_128_MD5
    { SSL_DH_anon_WITH_RC4_128_MD5,
      CS_DH_ANON,
      CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_MD5,
      16,           /* macSize */
      16,           /* keySize */
      0,            /* ivSize */
      1,            /* blocksize */
      csArc4Init,
      csArc4Encrypt,
      csArc4Decrypt,
      csMd5GenerateMac,
      csMd5VerifyMac },
#endif /* USE_SSL_DH_anon_WITH_RC4_128_MD5 */

/*
    The NULL Cipher suite must exist and be the last in this list
 */
    { SSL_NULL_WITH_NULL_NULL,
      CS_NULL,
      0,
      0,
      0,
      0,
      0,
      csNullInit,
      csNullEncrypt,
      csNullDecrypt,
      csNullGenerateMac,
      csNullVerifyMac }
};

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    Disable and re-enable ciphers suites on a global or per-session level.
    This is only a server-side feature because the client is always able to
    nominate the specific cipher it wishes to use.  Servers may want to disable
    specific ciphers for a given session (or globally without having to
    rebuild the library).

    This function must be called immediately after matrixSslNewServerSession

    If ssl is NULL, the setting will be global.  If a cipher is globally
    disabled, the per-session setting will be ignored.

    flags:
        PS_TRUE to reenable (always enabled by default if compiled in)
        PS_FALSE to disable cipher suite
 */
int32_t matrixSslSetCipherSuiteEnabledStatus(ssl_t *ssl, psCipher16_t cipherId,
    uint32_t flags)
{
    uint8_t i, j;

    if (ssl && !(ssl->flags & SSL_FLAGS_SERVER))
    {
        return PS_UNSUPPORTED_FAIL;
    }
    if (flags != PS_TRUE && flags != PS_FALSE)
    {
        return PS_ARG_FAIL;
    }
    for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++)
    {
        if (supportedCiphers[i].ident == cipherId)
        {
            if (ssl == NULL)
            {
/*
                Global status of cipher suite.  Disabled status takes
                precident over session setting
 */
                if (flags == PS_TRUE)
                {
                    /* Unset the disabled bit */
                    disabledCipherFlags[i >> 5] &= ~(1UL << (i & 31));
                }
                else
                {
                    /* Set the disabled bit */
                    disabledCipherFlags[i >> 5] |= 1UL << (i & 31);
                }
                return PS_SUCCESS;
            }
            else
            {
                /* Status of this suite for a specific session */
                for (j = 0; j < SSL_MAX_DISABLED_CIPHERS; j++)
                {
                    if (flags == PS_FALSE)
                    {
                        /* Find first empty spot to add disabled cipher */
                        if (ssl->disabledCiphers[j] == 0x0 ||
                            ssl->disabledCiphers[j] == cipherId)
                        {
                            ssl->disabledCiphers[j] = cipherId;
                            return PS_SUCCESS;
                        }
                    }
                    else
                    {
                        if (ssl->disabledCiphers[j] == cipherId)
                        {
                            ssl->disabledCiphers[j] = 0x0;
                            return PS_SUCCESS;
                        }
                    }
                }
                if (flags == PS_FALSE)
                {
                    return PS_LIMIT_FAIL; /* No empty spot in disabledCiphers */
                }
                else
                {
                    /* Tried to re-enabled a cipher that wasn't disabled */
                    return PS_SUCCESS;
                }
            }
        }
    }
    return PS_FAILURE; /* Cipher not found */
}
/*
    Convert the cipher suite "type" into what public key signature algorithm is
    required. Return values are from the sigAlgorithm of psX509_t:

    RSA_TYPE_SIG (User must also test for RSAPSS_TYPE_SIG!!)
    ECDSA_TYPE_SIG

    CS_NULL (0) if no public key signatures needed (PSK and DH_anon)

    The dhParamsRequired return paramater must hold whether standard DH
    is used in the suite.  The caller will have to load some during
    the callback if so

    The ecKeyExchange is to identify RSA signatures but EC key exchange
 */

static uint16 getKeyTypeFromCipherType(uint16 type, uint16 *dhParamsRequired,
    uint16 *ecKeyExchange)
{
    *dhParamsRequired = *ecKeyExchange = 0;
    switch (type)
    {
    case CS_RSA:
        return RSA_TYPE_SIG;

    case CS_DHE_RSA:
        *dhParamsRequired = 1;
        return RSA_TYPE_SIG;

    case CS_DH_ANON:
    case CS_DHE_PSK:
        *dhParamsRequired = 1;
        return CS_NULL;

    case CS_ECDHE_ECDSA:
    case CS_ECDH_ECDSA:
        return ECDSA_TYPE_SIG;

    case CS_ECDHE_RSA:
    case CS_ECDH_RSA:
        *ecKeyExchange = 1;
        return RSA_TYPE_SIG;

    default:            /* CS_NULL or CS_PSK type */
        return CS_NULL; /* a cipher suite with no pub key or DH */
    }
}
#endif  /* USE_SERVER_SIDE_SSL */

# define KEY_ALG_ANY     1
# define KEY_ALG_FIRST   2

#if defined(USE_SERVER_SIDE_SSL) && !defined(USE_ONLY_PSK_CIPHER_SUITE)

/*
    This is the signature algorithm that the client will be using to encrypt
    the key material based on what the cipher suite says it should be.
    Only looking at child most cert
 */
static int32 haveCorrectSigAlg(psX509Cert_t *cert, int32 sigType)
{
    if (sigType < 0)
        return PS_SUCCESS;

#ifdef USE_CERT_PARSE
    if (sigType == RSA_TYPE_SIG && cert->pubKeyAlgorithm == OID_RSA_KEY_ALG)
    {
        return PS_SUCCESS;
    }
    else if (sigType == ECDSA_TYPE_SIG && cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        return PS_SUCCESS;
    }
# else
    /* Without certificate parsing assume success by proper configuration */
    return PS_SUCCESS;
# endif
    return PS_FAILURE;
}

/* If using TLS 1.2 we need to test agains the sigHashAlg and eccParams */
static psRes_t validateKeyForExtensions(ssl_t *ssl, const sslCipherSpec_t *spec,
    sslIdentity_t *givenKey)
{
#  if defined(USE_TLS_1_2)
    psX509Cert_t *crt;
#  endif

    /* Can immediately weed out PSK suites and anon suites that don't use
       sigHashAlg or EC curves */
    if (spec->type == CS_PSK
            || spec->type == CS_DHE_PSK
            || spec->type == CS_DH_ANON)
    {
        return PS_SUCCESS;
    }

#  ifdef USE_TLS_1_3
    if (NGTD_VER(ssl, v_tls_1_3_any))
    {
        int32_t rc;

        rc = tls13TryNegotiateParams(ssl, spec, givenKey);
        if (rc != PS_SUCCESS)
        {
            return PS_UNSUPPORTED_FAIL;
        }
        return PS_SUCCESS;
    }
#  endif

#  ifdef USE_TLS_1_2
    /* hash and sig alg is a TLS 1.2 only extension */
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        /* Walk through each cert and confirm the client will be able to
            deal with them based on the algorithms provided in the extension */

        for (crt = givenKey->cert; crt; crt = crt->next)
        {
#   ifdef USE_DHE_CIPHER_SUITE
            /* Have to look out for the case where the public key alg doesn't
                match the sig algorithm.  This is only a concern for DHE based
                suites where we'll be sending a signature in the
                ServerKeyExchange message */
            if (spec->type == CS_DHE_RSA || spec->type == CS_ECDHE_RSA ||
                spec->type == CS_ECDHE_ECDSA)
            {
#    ifdef USE_CERT_PARSE
#     ifdef USE_RSA
                if (crt->pubKeyAlgorithm == OID_RSA_KEY_ALG)
                {
                    if (
#      ifdef USE_SHA1
                        !(ssl->hashSigAlg & HASH_SIG_SHA1_RSA_MASK) &&
#      endif
#      ifdef USE_SHA384
                        !(ssl->hashSigAlg & HASH_SIG_SHA384_RSA_MASK) &&
#      endif
#      ifdef USE_SHA512
                        !(ssl->hashSigAlg & HASH_SIG_SHA512_RSA_MASK) &&
#      endif
                        !(ssl->hashSigAlg & HASH_SIG_SHA256_RSA_MASK))
                    {
                        return PS_UNSUPPORTED_FAIL;
                    }
                }
#     endif /* RSA */
#     ifdef USE_ECC
                if (crt->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
                {
                    if (
#      ifdef USE_SHA1
                        !(ssl->hashSigAlg & HASH_SIG_SHA1_ECDSA_MASK) &&
#      endif
#      ifdef USE_SHA384
                        !(ssl->hashSigAlg & HASH_SIG_SHA384_ECDSA_MASK) &&
#      endif
#      ifdef USE_SHA512
                        !(ssl->hashSigAlg & HASH_SIG_SHA512_ECDSA_MASK) &&
#      endif
                        !(ssl->hashSigAlg & HASH_SIG_SHA256_ECDSA_MASK))
                    {
                        return PS_UNSUPPORTED_FAIL;
                    }
                }
#     endif /* USE_ECC */
#    endif /* USE_CERT_PARSE */
            }
#   endif  /* USE_DHE_CIPHER_SUITE */

            if (!peerSupportsSigAlg(crt->sigAlgorithm, ssl->hashSigAlg))
            {
                psTraceErrr("Peer doesn't support all sig/hash algorithm " \
                            "pairs in our certificate chain.\n");
                return PS_UNSUPPORTED_FAIL;
            }
#   ifdef USE_ECC
            /* EC suites have the added check of specific curves.  Just
                checking DH suites because the curve comes from the cert.
                ECDHE suites negotiate key exchange curve elsewhere */
            if (spec->type == CS_ECDH_ECDSA || spec->type == CS_ECDH_RSA)
            {
                if (ssl->ecInfo.ecFlags)
                {
#    ifdef USE_CERT_PARSE
                    /* Do negotiated curves work with our signatures. If not
                       parsing cert, opportunistically accept, and fail later. */
                    if (psTestUserEcID(crt->publicKey.key.ecc.curve->curveId,
                            ssl->ecInfo.ecFlags) < 0)
                    {
                        return PS_UNSUPPORTED_FAIL;
                    }
#    endif /* USE_CERT_PARSE */
                }
                else
                {
                    psTraceErrr("Don't share ANY EC curves with peer\n");
                    return PS_UNSUPPORTED_FAIL;
                }
            }
#   endif
        } /* for (crt = ...) */
    }
#  endif /* USE_TLS_1_2 */

    /* Must be good */
    return PS_SUCCESS;
}
# endif /* USE_SERVER_SIDE_SSL */

#if defined(USE_X509) && !defined(USE_ONLY_PSK_CIPHER_SUITE)
/* if firstMatch == true, then the subject cert keyAlg on the chain needs to
   match, else any cert keyAlg matching is sufficient (e.g. chain identifies
   trust anchors). Zero value for keyAlg matches any certificate. */
static psBool_t certValidForUse(psX509Cert_t *certs,
        int32 keyAlg,
        psBool_t firstMatch)
{
# if !defined(USE_ONLY_PSK_CIPHER_SUITE) && defined(USE_CERT_PARSE)
    psX509Cert_t *cert;

    for (cert = certs; cert; cert = cert->next)
    {
        if (keyAlg == 0 || cert->pubKeyAlgorithm == keyAlg)
        {
            return PS_TRUE;
        }
        if (firstMatch)
        {
            return PS_FALSE;
        }
    }
    return PS_FALSE;
#else
    /* PSK only or no certificate parsing - assume OK. */
    return PS_TRUE;
#endif
}
#endif

#if defined(USE_SERVER_SIDE_SSL) && !defined(USE_ONLY_PSK_CIPHER_SUITE)

/* anyOrFirst is basically a determination of whether we are looking through
   a collection of CA files for an algorithm (ANY) or a cert chain where
   we really only care about the child most cert because that is the one
   that ultimately determines the authentication algorithm (FIRST) */
static psRes_t haveCorrectKeyAlg(sslIdentity_t *idKey,
        int32 keyAlg,
        int32 sigType,
        int anyOrFirst)
{
    if (sigType == CS_NULL)
    {
        return PS_SUCCESS;
    }
#ifdef USE_X509
    if (certValidForUse(idKey->cert, keyAlg, (anyOrFirst == KEY_ALG_FIRST))
        && haveCorrectSigAlg(idKey->cert, sigType) == PS_SUCCESS)
    {
        return PS_SUCCESS;
    }
#endif
    return PS_FAILURE;
}

# ifdef VALIDATE_KEY_MATERIAL
static psRes_t haveKeyForAlg(sslKeys_t *keys,
        int32 keyAlg,
        int32 sigType,
        int anyOrFirst)
{
    sslIdentity_t *idKey;

    for (idKey = keys->identity; idKey; idKey = idKey->next)
    {
        if (haveCorrectKeyAlg(idKey, keyAlg, sigType, anyOrFirst) == PS_SUCCESS)
        {
            return PS_SUCCESS;
        }
    }
    return PS_FAILURE;
}
# endif
#endif

#ifdef VALIDATE_KEY_MATERIAL

/******************************************************************************/
/*
    Don't report a matching cipher suite if the user hasn't loaded the
    proper public key material to support it.  We do not check the client
    auth side of the algorithms because that authentication mechanism is
    negotiated within the handshake itself

    The annoying #ifdef USE_SERVER_SIDE and CLIENT_SIDE are because the
    structure members only exist one one side or the other and so are used
    for compiling.  You can't actually get into the wrong area of the
    SSL_FLAGS_SERVER test so no #else cases should be needed
 */
int32_t haveKeyMaterial(const ssl_t *ssl,
        const sslCipherSpec_t *cipher,
        short reallyTest)
{
    int32 cipherType = cipher->type;

# ifdef USE_TLS_1_3
    psResSize_t len;
    if (cipherType == CS_TLS13)
    {
        psSize_t hashLen;

        /* The only meaningful check we can make here for TLS1.3 is that
           when using PSK we choose such cipher suite that matches the
           chosen PSK length */
        if (ssl->sec.tls13ChosenPsk != NULL)
        {
            if (cipher->flags & CRYPTO_FLAGS_SHA3)
            {
                len = psGetOutputBlockLength(HASH_SHA384);
            }
            else
            {
                len = psGetOutputBlockLength(HMAC_SHA256);
            }
            if (len < 0)
            {
                return PS_FAILURE;
            }
            hashLen = len;
            if (hashLen != ssl->sec.tls13ChosenPsk->pskLen)
            {
                psTraceErrr("Ciphersuite doesn't match with PSK hash length\n");
                return PS_FAILURE;
            }
        }
        return PS_SUCCESS;
    }
# endif /* USE_TLS_1_3 */

# ifdef USE_SERVER_SIDE_SSL
    /* If the user has a ServerNameIndication callback registered we're
        going to skip the first test because they may not have loaded the
        final key material yet */
    if (ssl->sni_cb && reallyTest == 0)
    {
        return PS_SUCCESS;
    }
# endif
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
    if (!(ssl->flags & SSL_FLAGS_SERVER) && reallyTest == 0)
    {
        /* When using on-demand client cert and key loading, we may not
           have loaded any key or cert material yet. */
        return PS_SUCCESS;
    }
# endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
# ifndef USE_ONLY_PSK_CIPHER_SUITE

    /*  To start, capture all the cipherTypes where servers must have an
        identity and clients have a CA so we don't repeat them everywhere */
    if (cipherType == CS_RSA || cipherType == CS_DHE_RSA ||
        cipherType == CS_ECDHE_RSA || cipherType == CS_ECDH_RSA ||
        cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA)
    {
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
#  ifdef USE_SERVER_SIDE_SSL
            if (ssl->keys == NULL || ssl->keys->identity == NULL)
            {
                /* no server certificates, no play */
                return PS_FAILURE;
            }
#  endif
#  ifdef USE_CLIENT_SIDE_SSL
        }
        else
        {
            if (ssl->keys == NULL || ssl->keys->CAcerts == NULL)
            {
                return PS_FAILURE;
            }
#  endif
        }
    }

    /*  Standard RSA ciphers types - auth and exchange */
    if (cipherType == CS_RSA)
    {
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
#  ifdef USE_SERVER_SIDE_SSL
            if (haveKeyForAlg(ssl->keys,
                    OID_RSA_KEY_ALG, RSA_TYPE_SIG,
                    KEY_ALG_FIRST) < 0)
            {
                return PS_FAILURE;
            }
#  endif
#  ifdef USE_CLIENT_SIDE_SSL
        }
        else     /* Client */
        {
            if (!certValidForUse(ssl->keys->CAcerts, OID_RSA_KEY_ALG, PS_FALSE))
            {
                return PS_FAILURE;
            }
#  endif
        }
    }

#  ifdef USE_DHE_CIPHER_SUITE
/*
    DHE_RSA ciphers types
 */
    if (cipherType == CS_DHE_RSA)
    {
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
#   ifdef REQUIRE_DH_PARAMS
            if (ssl->keys->dhParams.size == 0)
            {
                return PS_FAILURE;
            }
#   endif
#   ifdef USE_SERVER_SIDE_SSL
            if (haveKeyForAlg(ssl->keys,
                    OID_RSA_KEY_ALG, -1,
                    KEY_ALG_FIRST) < 0)
            {
                return PS_FAILURE;
            }
#   endif
#   ifdef USE_CLIENT_SIDE_SSL
        }
        else
        {
            if (!certValidForUse(ssl->keys->CAcerts, OID_RSA_KEY_ALG, PS_FALSE))
            {
                return PS_FAILURE;
            }
#   endif
        }
    }

#   ifdef REQUIRE_DH_PARAMS
/*
    Anon DH ciphers don't need much
 */
    if (cipherType == CS_DH_ANON)
    {
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            if (ssl->keys == NULL || ssl->keys->dhParams.size == 0)
            {
                return PS_FAILURE;
            }
        }
    }
#   endif

#   ifdef USE_PSK_CIPHER_SUITE
    if (cipherType == CS_DHE_PSK)
    {
#    ifdef REQUIRE_DH_PARAMS
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            if (ssl->keys == NULL || ssl->keys->dhParams.size == 0)
            {
                return PS_FAILURE;
            }
        }
#    endif
        /* Only using these for clients at the moment */
        if (!(ssl->flags & SSL_FLAGS_SERVER))
        {
            if (ssl->keys == NULL || ssl->keys->pskKeys == NULL)
            {
                return PS_FAILURE;
            }
        }
    }
#   endif /* USE_PSK_CIPHER_SUITE */
#  endif  /* USE_DHE_CIPHER_SUITE */

#  ifdef USE_ECC_CIPHER_SUITE /* key exchange */
/*
    ECDHE_RSA ciphers use RSA keys
 */
    if (cipherType == CS_ECDHE_RSA)
    {
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
#   ifdef USE_SERVER_SIDE_SSL
            if (haveKeyForAlg(ssl->keys,
                    OID_RSA_KEY_ALG, RSA_TYPE_SIG,
                    KEY_ALG_FIRST) < 0)
            {
                return PS_FAILURE;
            }
#   endif
#   ifdef USE_CLIENT_SIDE_SSL
        }
        else
        {
            if (!certValidForUse(ssl->keys->CAcerts, OID_RSA_KEY_ALG, PS_FALSE))
            {
                return PS_FAILURE;
            }
#   endif
        }
    }

/*
    ECDH_RSA ciphers use ECDSA key exhange and RSA auth.
 */
    if (cipherType == CS_ECDH_RSA)
    {
        /* ECDH is a different beast - the actual authentication is done using
           static DH key (signed with RSA) as opposed to the ECDHE/RSA/DSA
           where the authentication is done using signature constructed with
           the key. */
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
#   ifdef USE_SERVER_SIDE_SSL
            sslIdentity_t *idKey;
            for (idKey = ssl->keys->identity; idKey; idKey = idKey->next)
            {
                if (idKey->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG
                    && (idKey->cert->sigAlgorithm == OID_SHA1_RSA_SIG
                        || idKey->cert->sigAlgorithm == OID_SHA256_RSA_SIG
                        || idKey->cert->sigAlgorithm == OID_SHA384_RSA_SIG
                        || idKey->cert->sigAlgorithm == OID_SHA512_RSA_SIG
                        || idKey->cert->sigAlgorithm == OID_MD5_RSA_SIG
                        || idKey->cert->sigAlgorithm == OID_MD2_RSA_SIG
                        || idKey->cert->sigAlgorithm == OID_RSASSA_PSS))
                {
                    break;
                }
            }
            if (idKey == NULL)
            {
                return PS_FAILURE;
            }
#   endif
#   ifdef USE_CLIENT_SIDE_SSL
        }
        else
        {
            if (!certValidForUse(ssl->keys->CAcerts, OID_RSA_KEY_ALG, PS_FALSE))
            {
                return PS_FAILURE;
            }
#   endif
        }
    }


/*
    ECDHE_ECDSA and ECDH_ECDSA ciphers must have ECDSA keys
 */
    if (cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA)
    {
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
#   ifdef USE_SERVER_SIDE_SSL
            if (haveKeyForAlg(ssl->keys,
                    OID_ECDSA_KEY_ALG, ECDSA_TYPE_SIG,
                    KEY_ALG_FIRST) < 0)
            {
                return PS_FAILURE;
            }
#   endif
#   ifdef USE_CLIENT_SIDE_SSL
        }
        else
        {
            if (!certValidForUse(ssl->keys->CAcerts, OID_ECDSA_KEY_ALG, PS_FALSE))
            {
                return PS_FAILURE;
            }
#   endif
        }
    }
#  endif /* USE_ECC_CIPHER_SUITE */
# endif  /* USE_ONLY_PSK_CIPHER_SUITE   */

# ifdef USE_PSK_CIPHER_SUITE
    if (cipherType == CS_PSK)
    {
        if (ssl->keys == NULL || ssl->keys->pskKeys == NULL)
        {
            return PS_FAILURE;
        }
    }
# endif /* USE_PSK_CIPHER_SUITE */

    return PS_SUCCESS;
}
#endif /* VALIDATE_KEY_MATERIAL */


/*      0 return is a key was found
    <0 is no luck
 */

# ifdef USE_SERVER_SIDE_SSL
/*
   The contributing factors here are:
   - peer (client) proposal
   - configured supported algorithms (built-time, global (FIPS or not), and session)
   - configured identification keys in order
     - server SniCb
     - server pubKeyCb
     - list of server pre-Configured Identities

   Key selection assumes, that TLS protocol versions have been set, and
   MatrixSsl uses built-time precedence order for server side,
   therefore server-configuration precedence order is not part of the
   selection algorithm.
*/
static psRes_t
chooseCS(ssl_t *ssl, uint32_t *suites, psSize_t nsuites)
{
    sslKeys_t *givenKey = NULL, *keys;
#ifdef USE_IDENTITY_CERTIFICATES
    sslIdentity_t *idKey;
#endif
    psBool_t sniUsed = PS_FALSE;
#ifdef USE_CS_FALLBACK
#ifdef USE_IDENTITY_CERTIFICATES
    sslIdentity_t  *fallbackId = NULL;
#endif
    const sslCipherSpec_t *fallbackSuite = NULL;
#endif
    int i;

    /* prefer keys loaded using SNI */
    if (ssl->expectedName)
    {
        givenKey = matrixServerGetKeysSNI(ssl,
                                          ssl->expectedName,
                                          Strlen(ssl->expectedName));
        if (ssl->extFlags.sni && givenKey == NULL)
        {
            psTraceErrr("Server didn't load SNI keys using SNI callback\n");
            ssl->err = SSL_ALERT_UNRECOGNIZED_NAME;
            return PS_UNSUPPORTED_FAIL;
        }
        sniUsed = PS_TRUE;
    }

    for (i = 0; i < nsuites; i++)
    {
        uint32 cipher = suites[i];
        const sslCipherSpec_t *spec;
        uint16 needDh, isEc, reqSigType;

        if ((spec = sslGetCipherSpec(ssl, cipher)) == NULL)
        {
            /* Not supported by build, configuration, or protocol version */
            continue;
        }

        if ((ssl->flags & SSL_FLAGS_HTTP2) && !isAlpnSuite(spec))
        {
            /* Not allowed with HTTP2 */
            continue;
        }

        /*
          When using TLS 1.3, just pick the first supported TLS 1.3 suite from
          the client's list. No need to check against key material.*/
# ifdef USE_TLS_1_3
        if (NGTD_VER(ssl, v_tls_1_3_any) && spec->type == CS_TLS13)
        {
            ssl->cipher = spec;
#  ifdef USE_IDENTITY_CERTIFICATES
            ssl->chosenIdentity = ssl->keys->identity;
#  endif
            goto out_ok;
        }
# endif /* USE_TLS_1_3 */

        reqSigType = getKeyTypeFromCipherType(spec->type, &needDh, &isEc);
        if (!sniUsed)
        {
# ifndef USE_ONLY_PSK_CIPHER_SUITE
            if (ssl->sec.pubkeyCb != NULL)
            {
                /* Check if the pubKeyCb has keys for this suite/server */
                sslPubkeyId_t wantKey;

                wantKey.serverName = ssl->expectedName;
                wantKey.hashAlg = ssl->hashSigAlg;
                wantKey.keyType = reqSigType;
                wantKey.dhParamsRequired = needDh;
                wantKey.curveFlags = 0;
#  ifdef USE_ECC_CIPHER_SUITE
                /* At this point ssl->ecInfo.ecFlags carries the shared curves */
                wantKey.curveFlags = ssl->ecInfo.ecFlags;
#  endif
                givenKey = (*ssl->sec.pubkeyCb)(ssl, &wantKey);
                if (givenKey == NULL)
                { /* pubKeyCb did not select key for this particular suite.  Try
                     next suite. */
                    continue;
                }
            }
# endif /* USE_ONLY_PSK_CIPHER_SUITE */
        }
        if (spec->type == CS_DH_ANON)
        {
            /* Anonymous does not require key material. */
            ssl->cipher = spec;
            ssl->keys = NULL;
#ifdef USE_IDENTITY_CERTIFICATES
            ssl->chosenIdentity = NULL;
#endif
            goto out_ok;
        }

        keys = (givenKey == NULL) ? ssl->keys : givenKey;
        if (keys == NULL)
        {
            /* No keys found for the suite, try the next one. */
            continue;
        }

#ifdef USE_PSK_CIPHER_SUITE
        if (spec->type == CS_PSK || spec->type == CS_DHE_PSK)
        {
            if (keys->pskKeys != NULL)
            {
                if (reqSigType == CS_NULL &&
                    (needDh == 0
# ifdef REQUIRE_DH_PARAMS
                     || (needDh == 1 && keys->dhParams.size > 0)
# endif /* REQUIRE_DH_PARAMS */
                     ))
                {
                    /* either doesn't do DH, or we have params preloaded */
                    ssl->cipher = spec;
                    ssl->keys = keys;
#ifdef USE_IDENTITY_CERTIFICATES
                    ssl->chosenIdentity = NULL;
#endif
                    goto out_ok;
                }
            }
            continue;
        }

# ifdef REQUIRE_DH_PARAMS
        if (needDh && keys->dhParams.size == 0)
        {
            /* need dhparams, but none provided */
            continue;
        }
# endif /* REQUIRE_DH_PARAMS */
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_IDENTITY_CERTIFICATES
        /* Now we have key-chain, either from SNI, pubKeyCb, or from server
           startup configuration. Check if it usable with the current
           suite. */
        for (idKey = keys->identity; idKey; idKey = idKey->next)
        {
            uint16 reqKeyAlg;
            if (spec->type == CS_ECDH_RSA || spec->type == CS_ECDH_ECDSA)
            {
                reqKeyAlg = OID_ECDSA_KEY_ALG;
                reqSigType = ECDSA_TYPE_SIG;
            }
            else
            {
                if (reqSigType == RSA_TYPE_SIG)
                {
                    reqKeyAlg = OID_RSA_KEY_ALG;
                }
                else if (reqSigType == ECDSA_TYPE_SIG)
                {
                    reqKeyAlg = OID_ECDSA_KEY_ALG;
                }
                else
                {
                    /* no requirements for key material */
                    reqKeyAlg = 0;
                }
            }

            if (haveCorrectKeyAlg(idKey,
                                  reqKeyAlg, reqSigType,
                                  KEY_ALG_FIRST) < 0 ||
                validateKeyForExtensions(ssl, spec, idKey) < 0)
            {
#ifdef USE_CS_FALLBACK
                /* This key is not suitable, but might be a good
                   fallback, if nothing else is found. */
                if (fallbackSuite == NULL)
                {
                    fallbackSuite = spec;
                    fallbackId = idKey;
                }
#endif
                continue;
            }
            /* this suite and key suits the requirements. */
            ssl->cipher = spec;
            ssl->keys = keys;
            /* Authenticate with the given key */
            ssl->chosenIdentity = idKey;
            goto out_ok;
        }
#endif /* USE_IDENTITY_CERTIFICATES */
    }

#ifdef USE_CS_FALLBACK
    /* XXX: MatrixSSL 3 series used to fall back to what client proposed on
       absense of key material. This is now gone. */
    if (fallbackSuite != NULL)
    {
        /* maybe productive to try the fallback. */
        ssl->cipher = fallbackSuite;
#ifdef USE_IDENTITY_CERTIFICATES
        ssl->chosenIdentity = fallbackId;
#endif
        goto out_ok;
    }
#endif

    psTraceErrr("No matching keys for any requested cipher suite.\n");
    return PS_UNSUPPORTED_FAIL; /* Server can't match anything */

out_ok:
    psTracePrintCiphersuiteName(INDENT_HS_MSG,
            "Chosen ciphersuite",
            ssl->cipher->ident, PS_TRUE);
    return PS_SUCCESS;
}

int32 chooseCipherSuite(ssl_t *ssl, unsigned char *listStart, int32 listLen)
{
    unsigned char *c = listStart;
    unsigned char *end;
    psSize_t nsuites = 0;
    uint32_t *suites, cipher;
    psRes_t rc;

    suites = psMalloc(ssl->hsPool, (listLen / 2) * sizeof(suites[0]));
    if (suites == NULL)
    {
        return PS_MEM_FAIL;
    }

    end = c + listLen;
    while (c < end)
    {
        if (ssl->rec.majVer > SSL2_MAJ_VER)
        {
            cipher = *c << 8; c++;
            cipher += *c; c++;
        }
        else
        {
            /* Deal with an SSLv2 hello message.  Ciphers are 3 bytes long */
            cipher = *c << 16; c++;
            cipher += *c << 8; c++;
            cipher += *c; c++;
        }
        suites[nsuites++] = cipher;
    }

    rc = chooseCS(ssl, suites, nsuites);
    psFree(suites, ssl->hsPool);
    return rc;
}
# endif /* USE_SERVER_SIDE */


#ifndef USE_ONLY_PSK_CIPHER_SUITE
# ifdef USE_ECC_CIPHER_SUITE
/*
    See if any of the EC suites are supported.  Needed by client very early on
    to know whether or not to add the EC client hello extensions
 */
int32_t eccSuitesSupported(const ssl_t *ssl,
    const psCipher16_t cipherSpecs[], uint8_t cipherSpecLen)
{
    int32 i = 0;

    if (cipherSpecLen == 0)
    {
        if (sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA) ||
            sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA) ||
            sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA) ||
            sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA) ||
#  ifdef USE_TLS_1_2
            sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) ||
            sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) ||
#  endif
            sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA))
        {
            return 1;
        }
    }
    else
    {
        while (i < cipherSpecLen)
        {
            if (cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ||
                cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA ||
                cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA ||
                cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA ||
                cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_CBC_SHA ||
#  ifdef USE_TLS_1_2
                cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ||
                cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ||
                cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 ||
                cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 ||
                cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 ||
                cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 ||
                cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
                cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
                cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 ||
                cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 ||
                cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 ||
                cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 ||
                cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ||
                cipherSpecs[i] == TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
#  endif
                cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_CBC_SHA)
            {
                return 1;
            }
            i++;
        }
    }
    return 0;
}
# endif /* USE_ECC_CIPHER_SUITE */

# ifdef USE_CLIENT_SIDE_SSL
/* Test if agreed upon cipher suite authentication is being adhered to */
int32 csCheckCertAgainstCipherSuite(int32 pubKey, int32 cipherType)
{
    if (cipherType == CS_TLS13)
    {
        /* In TLS 1.3, authentication algorithm is entirely separate from the
           cipher, so there is nothing we can check here. */
        return 1;
    }
    if (pubKey == PS_RSA)
    {
        if (cipherType == CS_DHE_RSA || cipherType == CS_RSA ||
            cipherType == CS_ECDHE_RSA)
        {
            return 1;
        }
    }
    if (pubKey == PS_ECC)
    {
        if (cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA ||
            cipherType == CS_ECDH_RSA)
        {
            return 1;
        }

    }
    return 0; /* no match */
}
# endif /* USE_CLIENT_SIDE_SSL */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/
/**
    Lookup the given cipher spec ID.
    @param[in] id The official ciphersuite id to find.
    @return A pointer to the cipher suite structure, if configured in build.
        If not defined, return NULL.
 */
const sslCipherSpec_t *sslGetDefinedCipherSpec(uint16_t id)
{
    uint8_t i;

    for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++)
    {
        if (supportedCiphers[i].ident == id)
        {
            return &supportedCiphers[i];
        }
    }
    return NULL;
}

/** Check restrictions by HTTP2 (set by ALPN extension).  This should filter
    out all ciphersuites specified in:
    https://tools.ietf.org/html/rfc7540#appendix-A "Note: This list was
    assembled from the set of registered TLS cipher suites at the time of
    writing.  This list includes those cipher suites that do not offer an
    ephemeral key exchange and those that are based on the TLS null, stream,
    or block cipher type (as defined in Section 6.2.3 of [TLS12]).  Additional
    cipher suites with these properties could be defined; these would not be
    explicitly prohibited." */
psBool_t isAlpnSuite(const sslCipherSpec_t *spec)
{
    /** Only allow AEAD ciphers. */
    if (!(spec->flags & CRYPTO_FLAGS_GCM) &&
        !(spec->flags & CRYPTO_FLAGS_CHACHA))
    {
        return PS_FALSE;
    }
    /** Only allow ephemeral key exchange. */
    switch (spec->type)
    {
    case CS_DHE_RSA:
    case CS_ECDHE_ECDSA:
    case CS_ECDHE_RSA:
        return PS_TRUE;
    default:
        break;
    }
    return PS_FALSE;
}

# ifdef USE_SEC_CONFIG
static
psBool_t ciphersuiteAllowedBySecConfig(ssl_t *ssl, const uint16_t id)
{
    psSize_t j;

    if (ssl->supportedCiphersLen > 0)
    {
        /* The NULL ciphersuite is used before encryption is turned on.
           We have to support that. */
        if (id == SSL_NULL_WITH_NULL_NULL)
        {
            return PS_TRUE;
        }
        for (j = 0; j < ssl->supportedCiphersLen; j++)
        {
            if (ssl->supportedCiphers[j] == id)
            {
                return PS_TRUE;
            }
        }
        return PS_FALSE;
    }

    return PS_TRUE;
}
# endif /* USE_SEC_CONFIG */

/******************************************************************************/
/**
    Lookup and validate the given cipher spec ID.
    Return a pointer to the structure if found and meeting constraints in 'ssl'.
    This is used when negotiating security, to find out what suites we support.
    @param[in] id The official ciphersuite id to find.
    @return A pointer to the cipher suite structure, if configured in build
        and appropriate for the constraints in 'ssl'.
        If not defined or appropriate, return NULL.
 */
const sslCipherSpec_t *sslGetCipherSpec(const ssl_t *ssl, uint16_t id)
{
    uint8_t i;

#ifdef USE_SERVER_SIDE_SSL
    uint8_t j;
#endif /* USE_SERVER_SIDE_SSL */

    /* Loop over the global supportedCiphers array. */
    i = 0;
    do
    {
        if (supportedCiphers[i].ident != id)
        {
            continue;
        }
        /* Double check we support the requsted hash algorithm */
#ifndef USE_MD5
        if (supportedCiphers[i].flags & CRYPTO_FLAGS_MD5)
        {
            return NULL;
        }
#endif
#ifndef USE_SHA1
        if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA1)
        {
            return NULL;
        }
#endif
#if !defined(USE_SHA256) && !defined(USE_SHA384)
        if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2)
        {
            return NULL;
        }
#endif
        /* Double check we support the requsted weak cipher algorithm */
#ifndef USE_ARC4
        if (supportedCiphers[i].flags &
            (CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD))
        {
            return NULL;
        }
#endif
#ifndef USE_3DES
        if (supportedCiphers[i].flags & CRYPTO_FLAGS_3DES)
        {
            return NULL;
        }
#endif

#ifdef USE_SEC_CONFIG
        if (!ciphersuiteAllowedBySecConfig(ssl, id))
        {
            psTracePrintCiphersuiteName(0,
                    "Ciphersuite not allowed by sec config",
                    id,
                    PS_TRUE);
            psTraceErrr("Invalid ciphersuite selection\n");
            return NULL;
        }
#endif /* USE_SEC_CONFIG */
#ifdef USE_SERVER_SIDE_SSL
        /* Globally disabled? */
        if (disabledCipherFlags[i >> 5] & (1UL << (i & 31)))
        {
            psTraceIntInfo("Matched cipher suite %d but disabled by user\n",
                id);
            return NULL;
        }
        /* Disabled for session? */
        if (id != 0)   /* Disable NULL_WITH_NULL_NULL not possible */
        {
            for (j = 0; j < SSL_MAX_DISABLED_CIPHERS; j++)
            {
                if (ssl->disabledCiphers[j] == id)
                {
                    psTraceIntInfo("Matched cipher suite %d but disabled by user\n",
                        id);
                    return NULL;
                }
            }
        }
#endif  /* USE_SERVER_SIDE_SSL */

        /*
          Unusable because protocol doesn't allow?

          Only perform this check if we already know which versions
          we have been configured to support. If we have been called
          during a resumption attempt to retrieve the ciphersuite stored
          in the sessionId_t struct, we have not initialized our list
          of supported versions yet. TODO: better fix.
        */
        if (GET_SUPP_VER(ssl) != v_undefined)
        {
#ifdef USE_TLS_1_2
            if (!SUPP_VER(ssl, v_tls_sha2) || NGTD_VER(ssl, v_tls_no_sha2))
            {
                if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
                        supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2)
                {
                    psTraceIntInfo("Matched cipher suite %d " \
                            "but not allowed in (D)TLS <1.2\n", id);
                    return NULL;
                }
            }
# ifdef USE_TLS_1_3
            /* Reject non-TLS1.3 cipher suites if TLS1.3 has been negotiated */
            if (NGTD_VER(ssl, v_tls_1_3_any))
            {
                if (supportedCiphers[i].type != CS_TLS13 &&
                        supportedCiphers[i].type != CS_NULL)
                {
                    return NULL;
                }
            }
            /* The server should reject TLS 1.3 cipher suites if TLS 1.3
               is not enabled. */
            if (IS_SERVER(ssl) && !SUPP_VER(ssl, v_tls_1_3_any))
            {
                if (supportedCiphers[i].type == CS_TLS13)
                {
                    return NULL;
                }
            }
# endif /* USE_TLS_1_3 */
            if (NGTD_VER(ssl, v_dtls_1_2 | v_tls_1_2 | v_tls_1_3_any))
            {
                if (supportedCiphers[i].flags & CRYPTO_FLAGS_MD5)
                {
                    psTraceIntInfo("Not allowing MD5 suite %d in TLS 1.2/1.3\n",
                            id);
                    return NULL;
                }
            }
#endif  /* TLS_1_2 */
        } /* if (GET_SUPP_VER(ssl) != v_undefined */

        /** Check restrictions by HTTP2 (set by ALPN extension).
            This should filter out all ciphersuites specified in:
                https://tools.ietf.org/html/rfc7540#appendix-A
           "Note: This list was assembled from the set of registered TLS
           cipher suites at the time of writing.  This list includes those
           cipher suites that do not offer an ephemeral key exchange and
           those that are based on the TLS null, stream, or block cipher type
           (as defined in Section 6.2.3 of [TLS12]).  Additional cipher
           suites with these properties could be defined; these would not be
           explicitly prohibited."
         */
        if (ssl->flags & SSL_FLAGS_HTTP2)
        {
            /** Only allow AEAD ciphers. */
            if (!(supportedCiphers[i].flags & CRYPTO_FLAGS_GCM) &&
                !(supportedCiphers[i].flags & CRYPTO_FLAGS_CHACHA))
            {

                return NULL;
            }
            /** Only allow ephemeral key exchange. */
            switch (supportedCiphers[i].type)
            {
            case CS_DHE_RSA:
            case CS_ECDHE_ECDSA:
            case CS_ECDHE_RSA:
                break;
            default:
                return NULL;
            }
        }

        /* The suite is available.  Want to reject if current key material
           does not support? */
#ifdef VALIDATE_KEY_MATERIAL
        if (ssl->keys != NULL)
        {
            if ((ssl->flags & SSL_FLAGS_SERVER) == 0)
            {
                /* Client: Just accept the cipher suite, because we do not
                   know of server public key yet. */
                return &supportedCiphers[i];
            }
            if (haveKeyMaterial(ssl, &supportedCiphers[i], 0)
                == PS_SUCCESS)
            {
                return &supportedCiphers[i];
            }
            psTraceIntInfo("Matched cipher suite %d but no supporting keys\n",
                id);
        }
        else
        {
            return &supportedCiphers[i];
        }
#else
        return &supportedCiphers[i];
#endif  /* VALIDATE_KEY_MATERIAL */
    }
    while (supportedCiphers[i++].ident != SSL_NULL_WITH_NULL_NULL);

    return NULL;
}


/******************************************************************************/
/*
    Write out a list of the supported cipher suites to the caller's buffer
    First 2 bytes are the number of cipher suite bytes, the remaining bytes are
    the cipher suites, as two byte, network byte order values.

    If called with encodeList == PS_FALSE, only returns lengths of the list.
 */
static
int32_t sslGetCipherSpecListExt(const ssl_t *ssl,
        unsigned char *c,
        int32 len,
        int32 addScsv,
        psBool_t encodeList)
{
    unsigned char *end, *p;
    unsigned short i;
    int32 ignored;

    if (encodeList)
    {
        if (len < 4)
        {
            return -1;
        }
        end = c + len;
        p = c; c += 2;
    }

    ignored = 0;
    for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++)
    {
#ifdef USE_TLS_1_2
        /* The SHA-2 based cipher suites are TLS 1.2 only so don't send
            those if the user has requested a lower protocol in
            NewClientSession */
        if (!SUPP_VER(ssl, v_tls_sha2))
        {
            if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
                supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2)
            {
                ignored += 2;
                continue;
            }
        }
#endif  /* TLS_1_2 */
# ifdef USE_TLS_1_3
        /* At this point remove the cipher if TLS1.3 is
           the only enabled version */
        if (!SUPP_VER(ssl, v_tls_legacy)
                && supportedCiphers[i].type != CS_TLS13)
        {
            ignored += 2;
            continue;
        }
        /* Remove TLS1.3 ciphers in case TLS1.3 is not enabled */
        if (!SUPP_VER(ssl, v_tls_1_3_any)
                && (supportedCiphers[i].type == CS_TLS13))
        {
            ignored += 2;
            continue;
        }
# endif /* USE_TLS_1_3 */
# ifdef USE_SEC_CONFIG
        if (!ciphersuiteAllowedBySecConfig(ssl, supportedCiphers[i].ident))
        {
            ignored += 2;
            continue;
        }
# endif /* USE_SEC_CONFIG */
#ifdef VALIDATE_KEY_MATERIAL
        if (haveKeyMaterial(ssl, &supportedCiphers[i], 0) != PS_SUCCESS)
        {
            ignored += 2;
            continue;
        }
#endif

        if (encodeList)
        {
            if (end - c < 2)
            {
                return PS_MEM_FAIL;
            }
            *c = (unsigned char) ((supportedCiphers[i].ident & 0xFF00) >> 8); c++;
            *c = (unsigned char) (supportedCiphers[i].ident & 0xFF); c++;
        }
    }

    i *= 2;
    i -= (unsigned short) ignored;

#ifdef ENABLE_SECURE_REHANDSHAKES
    if (addScsv == 1)
    {
# ifdef USE_CLIENT_SIDE_SSL
        ((ssl_t*)ssl)->extFlags.req_renegotiation_info = 1;
# endif
        if (encodeList)
        {
            if (end - c < 2)
            {
                return PS_MEM_FAIL;
            }
            *c = ((TLS_EMPTY_RENEGOTIATION_INFO_SCSV & 0xFF00) >> 8); c++;
            *c = TLS_EMPTY_RENEGOTIATION_INFO_SCSV  & 0xFF; c++;
        }
        i += 2;
    }
#endif

#ifdef USE_CLIENT_SIDE_SSL
    /* This flag is set in EncodeClientHello based on sslSessOpts_t.fallbackScsv */
    if (ssl->extFlags.req_fallback_scsv)
    {
        /** Add the fallback signalling ciphersuite.
           @see https://tools.ietf.org/html/rfc7507 */
        if (encodeList)
        {
            if (end - c < 2)
            {
                return PS_MEM_FAIL;
            }
            *c = (TLS_FALLBACK_SCSV >> 8) & 0xFF; c++;
            *c = TLS_FALLBACK_SCSV & 0xFF; c++;
        }
        i += 2;
    }
#endif

    if (encodeList)
    {
        *p = (unsigned char) (i >> 8); p++;
        *p = (unsigned char) (i & 0xFF);
    }

    return i + 2;
}

int32_t sslGetCipherSpecList(ssl_t *ssl,
        unsigned char *c,
        int32 len,
        int32 addScsv)
{
    return sslGetCipherSpecListExt(ssl,
            c,
            len,
            addScsv,
            PS_TRUE);
}

/******************************************************************************/
/*
    Return the length of the cipher spec list, including initial length bytes,
    (minus any suites that we don't have the key material to support)
 */
int32_t sslGetCipherSpecListLen(const ssl_t *ssl)
{
    return sslGetCipherSpecListExt(ssl,
            NULL,
            0,
            0,
            PS_FALSE);
}

/******************************************************************************/
/*
    Flag the session based on the agreed upon cipher suite
    NOTE: sslResetContext will have cleared these flags for re-handshakes
 */
void matrixSslSetKexFlags(ssl_t *ssl)
{

#ifdef USE_DHE_CIPHER_SUITE
/*
    Flag the specific DH ciphers so the correct key exchange
    mechanisms can be used.  And because DH changes the handshake
    messages as well.
 */
    if (ssl->cipher->type == CS_DHE_RSA)
    {
        ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
        ssl->flags |= SSL_FLAGS_DHE_WITH_RSA;
    }

# ifdef USE_PSK_CIPHER_SUITE
/*
    Set the PSK flags and DH kex.
    NOTE:  Although this isn't technically a DH_anon cipher, the handshake
    message order for DHE_PSK are identical and we can nicely piggy back
    on the handshake logic that already exists.
 */
    if (ssl->cipher->type == CS_DHE_PSK)
    {
        ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
        ssl->flags |= SSL_FLAGS_ANON_CIPHER;
        ssl->flags |= SSL_FLAGS_PSK_CIPHER;
#  ifdef USE_CLIENT_AUTH
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                psTraceInfo("No client auth TLS mode for DHE_PSK ciphers");
                psTraceInfo(". Disabling CLIENT_AUTH.\n");
                ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
            }
        }
#  endif /* USE_CLIENT_AUTH */
    }
# endif  /* USE_PSK_CIPHER_SUITE */

# ifdef USE_ECC_CIPHER_SUITE
    if (ssl->cipher->type == CS_ECDHE_RSA)
    {
        ssl->flags |= SSL_FLAGS_ECC_CIPHER;
        ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
        ssl->flags |= SSL_FLAGS_DHE_WITH_RSA;
    }
    if (ssl->cipher->type == CS_ECDHE_ECDSA)
    {
        ssl->flags |= SSL_FLAGS_ECC_CIPHER;
        ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
        ssl->flags |= SSL_FLAGS_DHE_WITH_DSA;
    }
# endif /* USE_ECC_CIPHER_SUITE */

# ifdef USE_ANON_DH_CIPHER_SUITE
    if (ssl->cipher->type == CS_DH_ANON)
    {
        ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
        ssl->flags |= SSL_FLAGS_ANON_CIPHER;
        ssl->sec.anon = 1;
    }
# endif /* USE_ANON_DH_CIPHER_SUITE */
#endif  /* USE_DHE_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
    if (ssl->cipher->type == CS_ECDH_ECDSA)
    {
        ssl->flags |= SSL_FLAGS_ECC_CIPHER;
    }
    if (ssl->cipher->type == CS_ECDH_RSA)
    {
        ssl->flags |= SSL_FLAGS_ECC_CIPHER;
    }
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
    if (ssl->cipher->type == CS_PSK)
    {
        ssl->flags |= SSL_FLAGS_PSK_CIPHER;
# ifdef USE_CLIENT_AUTH
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                psTraceInfo("No client auth TLS mode for basic PSK ciphers");
                psTraceInfo(". Disabling CLIENT_AUTH.\n");
                ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
            }
        }
# endif /* USE_CLIENT_AUTH */
    }
#endif  /* USE_PSK_CIPHER_SUITE */

    return;
}
/******************************************************************************/
