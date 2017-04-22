/**
 *      @file    prf.c
 *      @version $Format:%h%d$
 *
 *      "Native" Pseudo Random Function.
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

#if defined(USE_TLS_PRF) || defined(USE_TLS_PRF2)

# ifdef USE_TLS_PRF
int32_t prf(const unsigned char *sec, psSize_t secLen,
    const unsigned char *seed, psSize_t seedLen,
    unsigned char *out, psSize_t outLen)
{
    return psPrf(sec, secLen, seed, seedLen, out, outLen);
}
# endif

# ifdef USE_TLS_PRF2
int32_t prf2(const unsigned char *sec, psSize_t secLen,
    const unsigned char *seed, psSize_t seedLen,
    unsigned char *out, psSize_t outLen, uint32_t flags)
{
    return psPrf2(sec, secLen, seed, seedLen, out, outLen,
        (flags & CRYPTO_FLAGS_SHA3) ?
        SHA384_HASH_SIZE : SHA256_HASH_SIZE);
}
# endif

#else

# if defined(USE_NATIVE_TLS_ALGS) || defined(USE_NATIVE_TLS_HS_HASH)
#  ifdef USE_TLS
#   ifndef USE_ONLY_TLS_1_2
/******************************************************************************/
/*
    MD5 portions of the prf
 */
__inline static int32_t pMd5(const unsigned char *key, psSize_t keyLen,
    const unsigned char *text, psSize_t textLen,
    unsigned char *out, psSize_t outLen)
{
    psHmacMd5_t ctx;
    unsigned char a[MD5_HASH_SIZE];
    unsigned char mac[MD5_HASH_SIZE];
    unsigned char hmacKey[MD5_HASH_SIZE];
    int32_t rc = PS_FAIL;
    psSize_t hmacKeyLen, i, keyIter;

    for (keyIter = 1; (uint16_t) (MD5_HASH_SIZE * keyIter) < outLen; )
    {
        keyIter++;
    }
    if ((rc = psHmacMd5(key, keyLen, text, textLen, a,
             hmacKey, &hmacKeyLen)) < 0)
    {
        goto L_RETURN;
    }
    if (hmacKeyLen != keyLen)
    {
/*
        Support for keys larger than 64 bytes.  Must take the hash of
        the original key in these cases which is indicated by different
        outgoing values from the passed in key and keyLen values
 */
        psAssert(keyLen > 64);
        /* Typecast is OK, we don't update key below */
        key = (const unsigned char *) hmacKey;
        keyLen = hmacKeyLen;
    }
    for (i = 0; i < keyIter; i++)
    {
        if ((rc = psHmacMd5Init(&ctx, key, keyLen)) < 0)
        {
            goto L_RETURN;
        }
        psHmacMd5Update(&ctx, a, MD5_HASH_SIZE);
        psHmacMd5Update(&ctx, text, textLen);
        psHmacMd5Final(&ctx, mac);
        if (i == keyIter - 1)
        {
            memcpy(out + (MD5_HASH_SIZE * i), mac, outLen - (MD5_HASH_SIZE * i));
        }
        else
        {
            memcpy(out + (MD5_HASH_SIZE * i), mac, MD5_HASH_SIZE);
            if ((rc = psHmacMd5(key, keyLen, a, MD5_HASH_SIZE, a,
                     hmacKey, &hmacKeyLen)) < 0)
            {
                goto L_RETURN;
            }
        }
    }
    rc = PS_SUCCESS;
L_RETURN:
    memzero_s(a, MD5_HASH_SIZE);
    memzero_s(mac, MD5_HASH_SIZE);
    memzero_s(hmacKey, MD5_HASH_SIZE);
    if (rc < 0)
    {
        memzero_s(out, outLen); /* zero any partial result on error */
    }
    return rc;
}

/******************************************************************************/
/*
    SHA1 portion of the prf
 */
__inline static int32_t pSha1(const unsigned char *key, psSize_t keyLen,
    const unsigned char *text, psSize_t textLen,
    unsigned char *out, psSize_t outLen)
{
    psHmacSha1_t ctx;
    unsigned char a[SHA1_HASH_SIZE];
    unsigned char mac[SHA1_HASH_SIZE];
    unsigned char hmacKey[SHA1_HASH_SIZE];
    int32_t rc = PS_FAIL;
    psSize_t hmacKeyLen, i, keyIter;

    for (keyIter = 1; (uint16_t) (SHA1_HASH_SIZE * keyIter) < outLen; )
    {
        keyIter++;
    }
    if ((rc = psHmacSha1(key, keyLen, text, textLen, a,
             hmacKey, &hmacKeyLen)) < 0)
    {
        goto L_RETURN;
    }
    if (hmacKeyLen != keyLen)
    {
/*
        Support for keys larger than 64 bytes.  Must take the hash of
        the original key in these cases which is indicated by different
        outgoing values from the passed in key and keyLen values
 */
        psAssert(keyLen > 64);
        /* Typecast is OK, we don't update key below */
        key = (const unsigned char *) hmacKey;
        keyLen = hmacKeyLen;
    }
    for (i = 0; i < keyIter; i++)
    {
        if ((rc = psHmacSha1Init(&ctx, key, keyLen)) < 0)
        {
            goto L_RETURN;
        }
        psHmacSha1Update(&ctx, a, SHA1_HASH_SIZE);
        psHmacSha1Update(&ctx, text, textLen);
        psHmacSha1Final(&ctx, mac);
        if (i == keyIter - 1)
        {
            memcpy(out + (SHA1_HASH_SIZE * i), mac,
                outLen - (SHA1_HASH_SIZE * i));
        }
        else
        {
            memcpy(out + (SHA1_HASH_SIZE * i), mac, SHA1_HASH_SIZE);
            if ((rc = psHmacSha1(key, keyLen, a, SHA1_HASH_SIZE, a,
                     hmacKey, &hmacKeyLen)) < 0)
            {
                goto L_RETURN;
            }
        }
    }
    rc = PS_SUCCESS;
L_RETURN:
    memzero_s(a, SHA1_HASH_SIZE);
    memzero_s(mac, SHA1_HASH_SIZE);
    memzero_s(hmacKey, SHA1_HASH_SIZE);
    if (rc < 0)
    {
        memzero_s(out, outLen); /* zero any partial result on error */
    }
    return rc;
}

/******************************************************************************/
/*
    Psuedo-random function.  TLS uses this for key generation and hashing
 */
int32_t prf(const unsigned char *sec, psSize_t secLen,
    const unsigned char *seed, psSize_t seedLen,
    unsigned char *out, psSize_t outLen)
{
    const unsigned char *s1, *s2;
    unsigned char md5out[SSL_MAX_KEY_BLOCK_SIZE];
    unsigned char sha1out[SSL_MAX_KEY_BLOCK_SIZE];
    int32_t rc = PS_FAIL;
    psSize_t sLen, i;

    psAssert(outLen <= SSL_MAX_KEY_BLOCK_SIZE);

    sLen = (secLen / 2) + (secLen % 2);
    s1 = sec;
    s2 = (sec + sLen) - (secLen % 2);
    if ((rc = pMd5(s1, sLen, seed, seedLen, md5out, outLen)) < 0)
    {
        goto L_RETURN;
    }
    if ((rc = pSha1(s2, sLen, seed, seedLen, sha1out, outLen)) < 0)
    {
        goto L_RETURN;
    }
    for (i = 0; i < outLen; i++)
    {
        out[i] = md5out[i] ^ sha1out[i];
    }
    rc = outLen;
L_RETURN:
    memzero_s(md5out, SSL_MAX_KEY_BLOCK_SIZE);
    memzero_s(sha1out, SSL_MAX_KEY_BLOCK_SIZE);
    return rc;
}

#   endif /* !USE_ONLY_TLS_1_2 */

#   ifdef USE_TLS_1_2
/******************************************************************************/
/*
    SHA2 prf
 */
__inline static int32_t pSha2(const unsigned char *key, psSize_t keyLen,
    const unsigned char *text, psSize_t textLen,
    unsigned char *out, psSize_t outLen, uint32_t flags)
{
    /* Use a union to save a bit of stack space */
    union
    {
#    ifdef USE_SHA384
        psHmacSha384_t sha384;
#    endif
        psHmacSha256_t sha256;
    } u;
    unsigned char a[SHA384_HASH_SIZE];
    unsigned char mac[SHA384_HASH_SIZE];
    unsigned char hmacKey[SHA384_HASH_SIZE];
    int32_t rc = PS_FAIL;
    psSize_t hashSize, hmacKeyLen, i, keyIter;

#    ifdef USE_SHA384
    if (flags & CRYPTO_FLAGS_SHA3)
    {
        hashSize = SHA384_HASH_SIZE;
        if ((rc = psHmacSha384(key, keyLen, text, textLen, a,
                 hmacKey, &hmacKeyLen)) < 0)
        {
            goto L_RETURN;
        }
    }
    else
#    endif
    {

        hashSize = SHA256_HASH_SIZE;
        if ((rc = psHmacSha256(key, keyLen, text, textLen, a,
                 hmacKey, &hmacKeyLen)) < 0)
        {
            goto L_RETURN;
        }
    }
    for (keyIter = 1; (uint16_t) (hashSize * keyIter) < outLen; )
    {
        keyIter++;
    }
    if (hmacKeyLen != keyLen)
    {
/*
        Support for keys larger than 64 bytes.  Must take the hash of
        the original key in these cases which is indicated by different
        outgoing values from the passed in key and keyLen values
 */
        psAssert(keyLen > 64);
        /* Typecast is OK, we don't update key below */
        key = (const unsigned char *) hmacKey;
        keyLen = hmacKeyLen;
    }
    for (i = 0; i < keyIter; i++)
    {
#    ifdef USE_SHA384
        if (flags & CRYPTO_FLAGS_SHA3)
        {
            if ((rc = psHmacSha384Init(&u.sha384, key, keyLen)) < 0)
            {
                goto L_RETURN;
            }
            psHmacSha384Update(&u.sha384, a, hashSize);
            psHmacSha384Update(&u.sha384, text, textLen);
            psHmacSha384Final(&u.sha384, mac);
        }
        else
#    endif
        {
            if ((rc = psHmacSha256Init(&u.sha256, key, keyLen)) < 0)
            {
                goto L_RETURN;
            }
            psHmacSha256Update(&u.sha256, a, hashSize);
            psHmacSha256Update(&u.sha256, text, textLen);
            psHmacSha256Final(&u.sha256, mac);
        }
        if (i == keyIter - 1)
        {
            memcpy(out + (hashSize * i), mac,
                outLen - ((uint32_t) hashSize * i));
        }
        else
        {
            memcpy(out + ((uint32_t) hashSize * i), mac, hashSize);
#    ifdef USE_SHA384
            if (flags & CRYPTO_FLAGS_SHA3)
            {
                if ((rc = psHmacSha384(key, keyLen, a, hashSize, a,
                         hmacKey, &hmacKeyLen)) < 0)
                {
                    goto L_RETURN;
                }
            }
            else
#    endif
            {
                if ((rc = psHmacSha256(key, keyLen, a, hashSize, a,
                         hmacKey, &hmacKeyLen)) < 0)
                {
                    goto L_RETURN;
                }
            }
        }
    }
    rc =  PS_SUCCESS;
L_RETURN:
    memzero_s(a, SHA384_HASH_SIZE);
    memzero_s(mac, SHA384_HASH_SIZE);
    memzero_s(hmacKey, SHA384_HASH_SIZE);
    if (rc < 0)
    {
        memzero_s(out, outLen); /* zero any partial result on error */
    }
    return rc;
}

/******************************************************************************/
/*
    Psuedo-random function.  TLS uses this for key generation and hashing
 */
int32_t prf2(const unsigned char *sec, psSize_t secLen,
    const unsigned char *seed, psSize_t seedLen,
    unsigned char *out, psSize_t outLen, uint32_t flags)
{
    unsigned char sha2out[SSL_MAX_KEY_BLOCK_SIZE];
    int32_t rc;
    uint16_t i;

    psAssert(outLen <= SSL_MAX_KEY_BLOCK_SIZE);

    if ((rc = pSha2(sec, secLen, seed, seedLen, sha2out, outLen, flags)) < 0)
    {
        return rc;
    }
    /* Copy out of tmp buffer because outLen typically less than multiple of
        prf block size */
    for (i = 0; i < outLen; i++)
    {
        out[i] = sha2out[i];
    }
    memzero_s(sha2out, SSL_MAX_KEY_BLOCK_SIZE);
    return outLen;
}
#   endif /* USE_TLS_1_2 */

#   ifdef USE_EAP_FAST
/******************************************************************************/
/**
    EAP-FAST T-PRF function.
    This proprietary EAP protocol uses TLS to establish a session, but
    defines a modified SessionTicket mechansism that alters the generation
    of the TLS master secret.
    @see https://tools.ietf.org/html/rfc4851#section-5.5

    @param[in] key The PAC-Key, a shared secret provisioned out of band.
    @param[in] keyLen The length in bytes of PAC-Key.
    @param[in] seed The seed used for TLS master_secret generation.
    @param[in] seedLen For TLS this is always 64 bytes (server_random[32]
 + client_random[32])
    @param[out] out The derived master_secret.
    @return < on error. SSL_HS_MASTER_SIZE on success.

 */
int32_t tprf(const unsigned char *key, psSize_t keyLen,
    const unsigned char *seed, psSize_t seedLen,
    unsigned char out[SSL_HS_MASTER_SIZE])
{
    /** @note The 32 byte label includes the null terminator byte */
    static const unsigned char TPRF_LABEL[32] =
        "PAC to master secret label hash";

    psHmacSha1_t ctx;
    int32_t rc = PS_FAIL;
    unsigned char sha1out[SHA1_HASH_SIZE];
    unsigned char olen_iter[3];     /* outputlength[2] + iteration[1] */

    psAssert(seedLen == (SSL_HS_RANDOM_SIZE * 2));

    /**
        The first 20 bytes are generated as follows.
        T1 = HMAC-SHA1 (key, S + outputlength + 0x01)
            S = label + 0x00 + seed
                'label' is 31 bytes of [PAC to master secret label hash] and a
                    null byte (32 bytes total)
                'seed' as provided is server_random[32] + client_random[32]
            outputlength is a 2 byte big endian length of the output,
                always 48 bytes in TLS case.
        For our use, we simplify the above as:
        T1 = HMAC-SHA1 (key, label_with_0x0 + seed + 0x00 + 0x30 + 0x01
     */
    olen_iter[0] = 0x0;                 /* = ((outputlength >> 8) & 0xFF); */
    olen_iter[1] = SSL_HS_MASTER_SIZE;  /* = (outputlength & 0xFF); */
    olen_iter[2] = 0x01;
    if ((rc = psHmacSha1Init(&ctx, key, keyLen)) < 0)
    {
        goto L_RETURN;
    }
    psHmacSha1Update(&ctx, TPRF_LABEL, sizeof(TPRF_LABEL)); /* Includes 0x00 byte */
    psHmacSha1Update(&ctx, seed, seedLen);
    psHmacSha1Update(&ctx, olen_iter, sizeof(olen_iter));
    psHmacSha1Final(&ctx, out);

    /* T2 = HMAC-SHA1 (key, T1 + S + outputlength + 0x02) */
    olen_iter[2] = 0x02;
    if ((rc = psHmacSha1Init(&ctx, key, keyLen)) < 0)
    {
        goto L_RETURN;
    }
    psHmacSha1Update(&ctx, out, SHA1_HASH_SIZE);
    psHmacSha1Update(&ctx, TPRF_LABEL, sizeof(TPRF_LABEL));
    psHmacSha1Update(&ctx, seed, seedLen);
    psHmacSha1Update(&ctx, olen_iter, sizeof(olen_iter));
    psHmacSha1Final(&ctx, out + SHA1_HASH_SIZE);

    /* T3 = HMAC-SHA1 (key, T2 + S + outputlength + 0x03) */
    olen_iter[2] = 0x03;
    if ((rc = psHmacSha1Init(&ctx, key, keyLen)) < 0)
    {
        goto L_RETURN;
    }
    psHmacSha1Update(&ctx, out + SHA1_HASH_SIZE, SHA1_HASH_SIZE);
    psHmacSha1Update(&ctx, TPRF_LABEL, sizeof(TPRF_LABEL));
    psHmacSha1Update(&ctx, seed, seedLen);
    psHmacSha1Update(&ctx, olen_iter, sizeof(olen_iter));
    psHmacSha1Final(&ctx, sha1out);

    /* Copy the first 8 bytes from T3 to out, making 48 bytes total */
    memcpy(out + (2 * SHA1_HASH_SIZE), sha1out, 8);
    rc = SSL_HS_MASTER_SIZE;
L_RETURN:
    memzero_s(sha1out, sizeof(sha1out));
    if (rc < 0)
    {
        memzero_s(out, SSL_HS_MASTER_SIZE); /* zero any partial result on error */
    }
    return rc;
}
#   endif /* USE_EAP_FAST */
#  endif  /* USE_TLS */
# endif   /* USE_NATIVE_TLS_ALGS || USE_NATIVE_TLS_HS_HASH */
#endif    /* USE_TLS_PRF || USE_TLS_PRF2 */
/******************************************************************************/

