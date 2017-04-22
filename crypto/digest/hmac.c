/**
 *      @file    hmac.c
 *      @version $Format:%h%d$
 *
 *      HMAC implementation.
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

#include "../cryptoImpl.h"

int32_t psHmacInit(psHmac_t *ctx, psCipherType_e type,
    const unsigned char *key, psSize_t keyLen)
{
    ctx->type = (uint8_t) type;
    switch (type)
    {
#ifdef USE_HMAC_MD5
    case HMAC_MD5:
        return psHmacMd5Init(&ctx->u.md5, key, keyLen);
#endif
#ifdef USE_HMAC_SHA1
    case HMAC_SHA1:
        return psHmacSha1Init(&ctx->u.sha1, key, keyLen);
#endif
#ifdef USE_HMAC_SHA256
    case HMAC_SHA256:
        return psHmacSha256Init(&ctx->u.sha256, key, keyLen);
#endif
#ifdef USE_HMAC_SHA384
    case HMAC_SHA384:
        return psHmacSha384Init(&ctx->u.sha384, key, keyLen);
#endif
    default:
        return PS_ARG_FAIL;
    }
    /* Redundant return */
    return PS_ARG_FAIL;
}

void psHmacUpdate(psHmac_t *ctx, const unsigned char *buf, uint32_t len)
{
    switch ((psCipherType_e) ctx->type)
    {
#ifdef USE_HMAC_MD5
    case HMAC_MD5:
        psHmacMd5Update(&ctx->u.md5, buf, len);
        break;
#endif
#ifdef USE_HMAC_SHA1
    case HMAC_SHA1:
        psHmacSha1Update(&ctx->u.sha1, buf, len);
        break;
#endif
#ifdef USE_HMAC_SHA256
    case HMAC_SHA256:
        psHmacSha256Update(&ctx->u.sha256, buf, len);
        break;
#endif
#ifdef USE_HMAC_SHA384
    case HMAC_SHA384:
        psHmacSha384Update(&ctx->u.sha384, buf, len);
        break;
#endif
    default:
        break;
    }
}

void psHmacFinal(psHmac_t *ctx, unsigned char hash[MAX_HASHLEN])
{
    switch ((psCipherType_e) ctx->type)
    {
#ifdef USE_HMAC_MD5
    case HMAC_MD5:
        psHmacMd5Final(&ctx->u.md5, hash);
        break;
#endif
#ifdef USE_HMAC_SHA1
    case HMAC_SHA1:
        psHmacSha1Final(&ctx->u.sha1, hash);
        break;
#endif
#ifdef USE_HMAC_SHA256
    case HMAC_SHA256:
        psHmacSha256Final(&ctx->u.sha256, hash);
        break;
#endif
#ifdef USE_HMAC_SHA384
    case HMAC_SHA384:
        psHmacSha384Final(&ctx->u.sha384, hash);
        break;
#endif
    default:
        break;
    }
    ctx->type = 0;
}

#ifdef USE_MATRIX_HMAC_MD5
/******************************************************************************/
/*
    HMAC-MD5
    http://www.faqs.org/rfcs/rfc2104.html

    the HMAC_MD5 transform looks like:

        MD5(K XOR opad, MD5(K XOR ipad, text))

        where K is an n byte key
        ipad is the byte 0x36 repeated 64 times

        opad is the byte 0x5c repeated 64 times
        and text is the data being protected

    If the keyLen is > 64 bytes, we hash the key and use it instead
 */
# if !defined(USE_MATRIX_MD5) && !defined(USE_CL_DIGESTS)
#  error USE_MATRIX_MD5 or USE_CL_DIGESTS required
# endif
int32_t psHmacMd5(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[MD5_HASHLEN],
    unsigned char *hmacKey, psSize_t *hmacKeyLen)
{
    int32_t rc;

    union
    {
        psHmacMd5_t mac;
        psMd5_t md;
    } u;
    psHmacMd5_t *mac = &u.mac;
    psMd5_t *md = &u.md;
/*
    Support for keys larger than 64 bytes.  In this case, we take the
    hash of the key itself and use that instead.  Inform the caller by
    updating the hmacKey and hmacKeyLen outputs
 */
    if (keyLen > 64)
    {
        if ((rc = psMd5Init(md)) < 0)
        {
            return rc;
        }
        psMd5Update(md, key, keyLen);
        psMd5Final(md, hash);
        *hmacKeyLen = MD5_HASHLEN;
        memcpy(hmacKey, hash, *hmacKeyLen);
    }
    else
    {
        hmacKey = (unsigned char *) key;  /* @note typecasting from const */
        *hmacKeyLen = keyLen;
    }
    if ((rc = psHmacMd5Init(mac, hmacKey, *hmacKeyLen)) < 0)
    {
        return rc;
    }
    psHmacMd5Update(mac, buf, len);
    psHmacMd5Final(mac, hash);
    return PS_SUCCESS;
}

int32_t psHmacMd5Init(psHmacMd5_t *ctx,
    const unsigned char *key, psSize_t keyLen)
{
    int32_t rc, i;

# ifdef CRYPTO_ASSERT
    psAssert(keyLen <= 64);
# endif
    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x36;
    }
    for (i = keyLen; i < 64; i++)
    {
        ctx->pad[i] = 0x36;
    }
    if ((rc = psMd5Init(&ctx->md5)) < 0)
    {
        return rc;
    }
    psMd5Update(&ctx->md5, ctx->pad, 64);
    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x5c;
    }
    for (i = keyLen; i < 64; i++)
    {
        ctx->pad[i] = 0x5c;
    }
    return PS_SUCCESS;
}

void psHmacMd5Update(psHmacMd5_t *ctx,
    const unsigned char *buf, uint32_t len)
{
# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL && buf != NULL);
# endif
    psMd5Update(&ctx->md5, buf, len);
}

void psHmacMd5Final(psHmacMd5_t *ctx, unsigned char hash[MD5_HASHLEN])
{
    int32_t rc;

# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL);
    if (hash == NULL)
    {
        psTraceCrypto("NULL hash storage passed to psHmacMd5Final\n");
        return;
    }
# endif
    psMd5Final(&ctx->md5, hash);

    /* This Init should succeed, even if it allocates memory since an
        psMd5_t was just Finalized the line above */
    if ((rc = psMd5Init(&ctx->md5)) < 0)
    {
        psAssert(rc >= 0);
        return;
    }
    psMd5Update(&ctx->md5, ctx->pad, 64);
    psMd5Update(&ctx->md5, hash, MD5_HASHLEN);
    psMd5Final(&ctx->md5, hash);

    memset(ctx->pad, 0x0, sizeof(ctx->pad));
}

#endif /* USE_MATRIX_HMAC_MD5 */

#ifdef USE_MATRIX_HMAC_SHA1
/******************************************************************************/
/*
    HMAC-SHA1
    @see http://www.faqs.org/rfcs/rfc2104.html
 */
# ifndef USE_SHA1
#  error USE_SHA1 required
# endif

int32_t psHmacSha1(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[SHA1_HASHLEN],
    unsigned char *hmacKey, psSize_t *hmacKeyLen)
{
    int32_t rc;

    union
    {
        psHmacSha1_t mac;
        psSha1_t md;
    } u;
    psHmacSha1_t *mac = &u.mac;
    psSha1_t *md = &u.md;
/*
    Support for keys larger than 64 bytes.  In this case, we take the
    hash of the key itself and use that instead.  Inform the caller by
    updating the hmacKey and hmacKeyLen outputs
 */
    if (keyLen > 64)
    {
        if ((rc = psSha1Init(md)) < 0)
        {
            return rc;
        }
        psSha1Update(md, key, keyLen);
        psSha1Final(md, hash);
        *hmacKeyLen = SHA1_HASHLEN;
        memcpy(hmacKey, hash, *hmacKeyLen);
    }
    else
    {
        hmacKey = (unsigned char *) key;  /* @note typecasting from const */
        *hmacKeyLen = keyLen;
    }

    if ((rc = psHmacSha1Init(mac, hmacKey, *hmacKeyLen)) < 0)
    {
        return rc;
    }
    psHmacSha1Update(mac, buf, len);
    psHmacSha1Final(mac, hash);
    return PS_SUCCESS;
}

int32_t psHmacSha1Init(psHmacSha1_t *ctx,
    const unsigned char *key, psSize_t keyLen)
{
    int32_t rc, i;

# ifdef CRYPTO_ASSERT
    psAssert(keyLen <= 64);
# endif
    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x36;
    }
    for (i = keyLen; (uint32) i < 64; i++)
    {
        ctx->pad[i] = 0x36;
    }
    if ((rc = psSha1Init(&ctx->sha1)) < 0)
    {
        return rc;
    }
    psSha1Update(&ctx->sha1, ctx->pad, 64);
    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x5c;
    }
    for (i = keyLen; i < 64; i++)
    {
        ctx->pad[i] = 0x5c;
    }
    return PS_SUCCESS;
}

void psHmacSha1Update(psHmacSha1_t *ctx,
    const unsigned char *buf, uint32_t len)
{
# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL && buf != NULL);
# endif
    psSha1Update(&ctx->sha1, buf, len);
}

void psHmacSha1Final(psHmacSha1_t *ctx, unsigned char hash[SHA1_HASHLEN])
{
    int32_t rc;

# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL);
    if (hash == NULL)
    {
        psTraceCrypto("NULL hash storage passed to psHmacSha1Final\n");
        return;
    }
# endif
    psSha1Final(&ctx->sha1, hash);

    if ((rc = psSha1Init(&ctx->sha1)) < 0)
    {
        psAssert(rc >= 0);
        return;
    }
    psSha1Update(&ctx->sha1, ctx->pad, 64);
    psSha1Update(&ctx->sha1, hash, SHA1_HASHLEN);
    psSha1Final(&ctx->sha1, hash);

    memset(ctx->pad, 0x0, sizeof(ctx->pad));
}

#endif /* USE_MATRIX_HMAC_SHA1 */

#ifdef USE_MATRIX_HMAC_SHA256
/******************************************************************************/
/*
    HMAC-SHA256
 */
int32_t psHmacSha256(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[SHA256_HASHLEN], unsigned char *hmacKey,
    psSize_t *hmacKeyLen)
{
    int32 rc, padLen;

    union
    {
        psHmacSha256_t mac;
        psSha256_t md;
    } u;
    psHmacSha256_t *mac = &u.mac;
    psSha256_t *md = &u.md;

    padLen = 64;

/*
    Support for keys larger than hash block size.  In this case, we take the
    hash of the key itself and use that instead.  Inform the caller by
    updating the hmacKey and hmacKeyLen outputs
 */
    if (keyLen > (uint32) padLen)
    {
        if ((rc = psSha256Init(md)) < 0)
        {
            return rc;
        }
        psSha256Update(md, key, keyLen);
        psSha256Final(md, hash);
        memcpy(hmacKey, hash, SHA256_HASHLEN);
        *hmacKeyLen = SHA256_HASHLEN;
    }
    else
    {
        hmacKey = (unsigned char *) key;  /* @note typecasting from const */
        *hmacKeyLen = keyLen;
    }

    if ((rc = psHmacSha256Init(mac, hmacKey, *hmacKeyLen)) < 0)
    {
        return rc;
    }
    psHmacSha256Update(mac, buf, len);
    psHmacSha256Final(mac, hash);
    return PS_SUCCESS;
}

int32_t psHmacSha256Init(psHmacSha256_t *ctx,
    const unsigned char *key, psSize_t keyLen)
{
    int32_t rc, i, padLen = 64;

# ifdef CRYPTO_ASSERT
    psAssert(keyLen <= (uint32) padLen);
# endif
    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x36;
    }
    for (i = keyLen; i < padLen; i++)
    {
        ctx->pad[i] = 0x36;
    }
    if ((rc = psSha256Init(&ctx->sha256)) < 0)
    {
        return rc;
    }
    psSha256Update(&ctx->sha256, ctx->pad, padLen);
    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x5c;
    }
    for (i = keyLen; i < padLen; i++)
    {
        ctx->pad[i] = 0x5c;
    }
    return PS_SUCCESS;
}

void psHmacSha256Update(psHmacSha256_t *ctx,
    const unsigned char *buf, uint32_t len)
{
# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL && buf != NULL);
# endif
    psSha256Update(&ctx->sha256, buf, len);
}

void psHmacSha256Final(psHmacSha256_t *ctx,
    unsigned char hash[SHA256_HASHLEN])
{
    int32_t rc;

# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL);
    if (hash == NULL)
    {
        psTraceCrypto("NULL hash storage passed to psHmacSha256Final\n");
        return;
    }
# endif

    psSha256Final(&ctx->sha256, hash);

    if ((rc = psSha256Init(&ctx->sha256)) < 0)
    {
        psAssert(rc >= 0);
        return;
    }
    psSha256Update(&ctx->sha256, ctx->pad, 64);
    psSha256Update(&ctx->sha256, hash, SHA256_HASHLEN);
    psSha256Final(&ctx->sha256, hash);
    memset(ctx->pad, 0x0, sizeof(ctx->pad));
}
#endif /* USE_MATRIX_HMAC_SHA256 */

#ifdef USE_MATRIX_HMAC_SHA384
/******************************************************************************/
/*
    HMAC-SHA384
 */
int32_t psHmacSha384(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[SHA384_HASHLEN],
    unsigned char *hmacKey, psSize_t *hmacKeyLen)
{
    int32 rc, padLen;

    union
    {
        psHmacSha384_t mac;
        psSha384_t md;
    } u;
    psHmacSha384_t *mac = &u.mac;
    psSha384_t *md = &u.md;

    padLen = 128;

/*
    Support for keys larger than hash block size.  In this case, we take the
    hash of the key itself and use that instead.  Inform the caller by
    updating the hmacKey and hmacKeyLen outputs
 */
    if (keyLen > (uint32) padLen)
    {
        if ((rc = psSha384Init(md)) < 0)
        {
            return rc;
        }
        psSha384Update(md, key, keyLen);
        psSha384Final(md, hash);
        memcpy(hmacKey, hash, SHA384_HASHLEN);
        *hmacKeyLen = SHA384_HASHLEN;
    }
    else
    {
        hmacKey = (unsigned char *) key;  /* @note typecasting from const */
        *hmacKeyLen = keyLen;
    }

    if ((rc = psHmacSha384Init(mac, hmacKey, *hmacKeyLen)) < 0)
    {
        return rc;
    }
    psHmacSha384Update(mac, buf, len);
    psHmacSha384Final(mac, hash);
    return PS_SUCCESS;
}

int32_t psHmacSha384Init(psHmacSha384_t *ctx,
    const unsigned char *key, psSize_t keyLen)
{
    int32_t rc, i, padLen;

    padLen = 128;

# ifdef CRYPTO_ASSERT
    psAssert(keyLen <= (uint32) padLen);
# endif
    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x36;
    }
    for (i = keyLen; i < padLen; i++)
    {
        ctx->pad[i] = 0x36;
    }
    if ((rc = psSha384Init(&ctx->sha384)) < 0)
    {
        return rc;
    }
    psSha384Update(&ctx->sha384, ctx->pad, padLen);

    for (i = 0; (uint32) i < keyLen; i++)
    {
        ctx->pad[i] = key[i] ^ 0x5c;
    }
    for (i = keyLen; i < padLen; i++)
    {
        ctx->pad[i] = 0x5c;
    }
    return PS_SUCCESS;
}

void psHmacSha384Update(psHmacSha384_t *ctx,
    const unsigned char *buf, uint32_t len)
{
# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL && buf != NULL);
# endif
    psSha384Update(&ctx->sha384, buf, len);
}

void psHmacSha384Final(psHmacSha384_t *ctx,
    unsigned char hash[SHA384_HASHLEN])
{
    int32_t rc;

# ifdef CRYPTO_ASSERT
    psAssert(ctx != NULL);
    if (hash == NULL)
    {
        psTraceCrypto("NULL hash storage passed to psHmacSha256Final\n");
        return;
    }
# endif

    psSha384Final(&ctx->sha384, hash);

    if ((rc = psSha384Init(&ctx->sha384)) < 0)
    {
        psAssert(rc >= 0);
        return;
    }
    psSha384Update(&ctx->sha384, ctx->pad, 128);
    psSha384Update(&ctx->sha384, hash, SHA384_HASHLEN);
    psSha384Final(&ctx->sha384, hash);

    memset(ctx->pad, 0x0, sizeof(ctx->pad));
}
#endif /* USE_MATRIX_HMAC_SHA384 */

/******************************************************************************/

