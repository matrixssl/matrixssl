/**
 *      @file    digest_openssl.c
 *      @version $Format:%h%d$
 *
 *      Digest compatibility layer between MatrixSSL and OpenSSL.
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

/******************************************************************************/

#ifdef USE_OPENSSL_HMAC_MD5

int32_t psHmacMd5(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[MD5_HASHLEN], unsigned char *hmacKey,
    psSize_t *hmacKeyLen)
{
    psMd5_t md;

    /*
       Support for keys larger than 64 bytes.  In this case, we take the
       hash of the key itself and use that instead.  Inform the caller by
       updating the hmacKey and hmacKeyLen outputs
     */
    if (keyLen > 64)
    {
        psMd5Init(&md);
        psMd5Update(&md, key, keyLen);
        psMd5Final(&md, hash);
        *hmacKeyLen = MD5_HASHLEN;
        memcpy(hmacKey, hash, *hmacKeyLen);
    }
    else
    {
        hmacKey = (unsigned char *) key;
        *hmacKeyLen = keyLen;
    }
    if (HMAC(EVP_md5(), hmacKey, *hmacKeyLen, buf, len, hash, NULL) != NULL)
    {
        return PS_SUCCESS;
    }
    return PS_FAIL;
}

int32_t psHmacMd5Init(psHmacMd5_t *ctx, const unsigned char *key,
    psSize_t keyLen)
{
    HMAC_CTX_init(ctx);
    if (HMAC_Init_ex(ctx, key, keyLen, EVP_md5(), NULL) == 1)
    {
        return PS_SUCCESS;
    }
    HMAC_CTX_cleanup(ctx);
    psAssert(0);
    return PS_FAIL;
}

void psHmacMd5Update(psHmacMd5_t *ctx, const unsigned char *buf,
    uint32_t len)
{
    HMAC_Update(ctx, buf, len);
}

void psHmacMd5Final(psHmacMd5_t *ctx, unsigned char hash[MD5_HASHLEN])
{
    HMAC_Final(ctx, hash, NULL);
    HMAC_CTX_cleanup(ctx);
}

#endif /* USE_OPENSSL_HMAC_MD5 */

/******************************************************************************/

#ifdef USE_OPENSSL_SHA1

int32_t psHmacSha1(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[SHA1_HASHLEN], unsigned char *hmacKey,
    psSize_t *hmacKeyLen)
{
    psSha1_t sha;

/*
    Support for keys larger than 64 bytes.  In this case, we take the
    hash of the key itself and use that instead.  Inform the caller by
    updating the hmacKey and hmacKeyLen outputs
 */
    if (keyLen > 64)
    {
        psSha1Init(&sha);
        psSha1Update(&sha, key, keyLen);
        psSha1Final(&sha, hash);
        *hmacKeyLen = SHA1_HASHLEN;
        memcpy(hmacKey, hash, *hmacKeyLen);
    }
    else
    {
        hmacKey = (unsigned char *) key;
        *hmacKeyLen = keyLen;
    }
    if (HMAC(EVP_sha1(), hmacKey, *hmacKeyLen, buf, len, hash, NULL) != NULL)
    {
        return PS_SUCCESS;
    }
    return PS_FAIL;
}

int32_t psHmacSha1Init(psHmacSha1_t *ctx, const unsigned char *key,
    psSize_t keyLen)
{
    HMAC_CTX_init(ctx);
    if (HMAC_Init_ex(ctx, key, keyLen, EVP_sha1(), NULL) == 1)
    {
        return PS_SUCCESS;
    }
    HMAC_CTX_cleanup(ctx);
    return PS_FAIL;
}

void psHmacSha1Update(psHmacSha1_t *ctx, const unsigned char *buf,
    uint32_t len)
{
    HMAC_Update(ctx, buf, len);
}

void psHmacSha1Final(psHmacSha1_t *ctx, unsigned char hash[SHA1_HASHLEN])
{
    HMAC_Final(ctx, hash, NULL);
    HMAC_CTX_cleanup(ctx);
}
#endif /* USE_OPENSSL_HMAC_SHA1 */

/******************************************************************************/

#ifdef USE_OPENSSL_HMAC_SHA256
int32_t psHmacSha256(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[SHA256_HASHLEN], unsigned char *hmacKey,
    psSize_t *hmacKeyLen)
{
    psSha256_t sha;

    if (keyLen > 64)
    {
        psSha256Init(&sha);
        psSha256Update(&sha, key, keyLen);
        psSha256Final(&sha, hash);
        *hmacKeyLen = SHA256_HASHLEN;
        memcpy(hmacKey, hash, *hmacKeyLen);
    }
    else
    {
        hmacKey = (unsigned char *) key;
        *hmacKeyLen = keyLen;
    }
    if (HMAC(EVP_sha256(), hmacKey, *hmacKeyLen, buf, len, hash, NULL) != NULL)
    {
        return PS_SUCCESS;
    }
    psAssert(0);
    return PS_FAIL;
}

int32_t psHmacSha256Init(psHmacSha256_t *ctx,
    const unsigned char *key, psSize_t keyLen)
{
    HMAC_CTX_init(ctx);
    if (HMAC_Init_ex(ctx, key, keyLen, EVP_sha256(), NULL) == 1)
    {
        return PS_SUCCESS;
    }
    HMAC_CTX_cleanup(ctx);
    psAssert(0);
    return PS_FAIL;
}

void psHmacSha256Update(psHmacSha256_t *ctx,
    const unsigned char *buf, uint32_t len)
{
    if (HMAC_Update(ctx, buf, len) != 1)
    {
        HMAC_CTX_cleanup(ctx);
    }
}

void psHmacSha256Final(psHmacSha256_t *ctx,
    unsigned char hash[SHA256_HASHLEN])
{
    if (HMAC_Final(ctx, hash, NULL) != 1)
    {
        psAssert(0);
    }
    HMAC_CTX_cleanup(ctx);
}
#endif /* USE_OPENSSL_HMAC_SHA256 */

#ifdef USE_OPENSSL_HMAC_SHA384
int32_t psHmacSha384(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[SHA384_HASHLEN], unsigned char *hmacKey,
    psSize_t *hmacKeyLen)
{
    psSha384_t sha;

    if (keyLen > 64)
    {
        psSha384Init(&sha);
        psSha384Update(&sha, key, keyLen);
        psSha384Final(&sha, hash);
        *hmacKeyLen = SHA384_HASHLEN;
        memcpy(hmacKey, hash, *hmacKeyLen);
    }
    else
    {
        hmacKey = (unsigned char *) key;
        *hmacKeyLen = keyLen;
    }

    if (HMAC(EVP_sha384(), hmacKey, *hmacKeyLen, buf, len, hash, NULL) != NULL)
    {
        return PS_SUCCESS;
    }
    psAssert(0);
    return PS_FAIL;
}

int32_t psHmacSha384Init(psHmacSha384_t *ctx,
    const unsigned char *key, psSize_t keyLen)
{
    HMAC_CTX_init(ctx);
    if (HMAC_Init_ex(ctx, key, keyLen, EVP_sha384(), NULL) == 1)
    {
        return PS_SUCCESS;
    }
    HMAC_CTX_cleanup(ctx);
    psAssert(0);
    return PS_FAIL;
}

void psHmacSha384Update(psHmacSha384_t *ctx,
    const unsigned char *buf, uint32_t len)
{
    if (HMAC_Update(ctx, buf, len) != 1)
    {
        HMAC_CTX_cleanup(ctx);
    }
}

void psHmacSha384Final(psHmacSha384_t *ctx,
    unsigned char hash[SHA384_HASHLEN])
{
    if (HMAC_Final(ctx, hash, NULL) != 1)
    {
        psAssert(0);
    }
    HMAC_CTX_cleanup(ctx);
}
#endif /* USE_OPENSSL_HMAC_SHA384 */


#ifdef USE_OPENSSL_MD5
int32_t psMd5Init(psMd5_t *md5)
{
    if (MD5_Init(md5) != 1)
    {
        return PS_FAIL;
    }
    return PS_SUCCESS;
}
void psMd5Update(psMd5_t *md5, const unsigned char *buf, uint32_t len)
{
    if (MD5_Update(md5, buf, len) != 1)
    {
        memset(md5, 0x0, sizeof(psMd5_t));
    }
}
void psMd5Final(psMd5_t *md5, unsigned char hash[MD5_HASHLEN])
{
    if (MD5_Final(hash, md5) != 1)
    {
        memset(hash, 0x0, MD5_HASHLEN);
        memset(md5, 0x0, sizeof(psMd5_t));
    }
}
#endif

#ifdef USE_OPENSSL_MD5SHA1
int32_t psMd5Sha1Init(psMd5Sha1_t *md)
{
    if (MD5_Init(&md->md5) != 1 || SHA1_Init(&md->sha1) != 1)
    {
        memset(md, 0x0, sizeof(psMd5Sha1_t));
        return PS_FAIL;
    }
    return PS_SUCCESS;
}

void psMd5Sha1Update(psMd5Sha1_t *md,
    const unsigned char *buf, uint32_t len)
{
    if (MD5_Update(&md->md5, buf, len) != 1 || SHA1_Update(&md->sha1, buf, len) != 1 )
    {
        memset(md, 0x0, sizeof(psMd5Sha1_t));
    }
}

void psMd5Sha1Final(psMd5Sha1_t *md,
    unsigned char hash[MD5SHA1_HASHLEN])
{
    if (MD5_Final(hash, &md->md5) != 1 ||
        SHA1_Final(hash + MD5_HASHLEN, &md->sha1) != 1 )
    {
        memset(hash, 0x0, MD5SHA1_HASHLEN);
        memset(md, 0x0, sizeof(psMd5Sha1_t));
    }
}
#endif

#ifdef USE_OPENSSL_SHA1
int32_t psSha1Init(psSha1_t *sha1)
{
    if (SHA1_Init(sha1) != 1)
    {
        return PS_FAIL;
    }
    return PS_SUCCESS;
}
void psSha1Update(psSha1_t *sha1, const unsigned char *buf, uint32_t len)
{
    if (SHA1_Update(sha1, buf, len) != 1)
    {
        memset(sha1, 0x0, sizeof(psSha1_t));
    }
}
void psSha1Final(psSha1_t *sha1, unsigned char hash[SHA1_HASHLEN])
{
    if (SHA1_Final(hash, sha1) != 1)
    {
        memset(hash, 0x0, SHA1_HASHLEN);
        memset(sha1, 0x0, sizeof(psSha1_t));
    }
}
#endif

#ifdef USE_OPENSSL_SHA256
int32_t psSha256Init(psSha256_t *sha256)
{
    if (SHA256_Init(sha256) != 1)
    {
        return PS_FAIL;
    }
    return PS_SUCCESS;
}
void psSha256Update(psSha256_t *sha256, const unsigned char *buf, uint32_t len)
{
    if (SHA256_Update(sha256, buf, len) != 1)
    {
        memset(sha256, 0x0, sizeof(psSha256_t));
    }
}
void psSha256Final(psSha256_t *sha256, unsigned char hash[SHA256_HASHLEN])
{
    if (SHA256_Final(hash, sha256) != 1)
    {
        memset(hash, 0x0, SHA256_HASHLEN);
        memset(sha256, 0x0, sizeof(psSha256_t));
    }
}
#endif

#ifdef USE_OPENSSL_SHA384
int32_t psSha384Init(psSha384_t *sha384)
{
    if (SHA384_Init(sha384) != 1)
    {
        return PS_FAIL;
    }
    return PS_SUCCESS;
}
void psSha384Update(psSha384_t *sha384, const unsigned char *buf, uint32_t len)
{
    if (SHA384_Update(sha384, buf, len) != 1)
    {
        memset(sha384, 0x0, sizeof(psSha384_t));
    }
}
void psSha384Final(psSha384_t *sha384, unsigned char hash[SHA384_HASHLEN])
{
    if (SHA384_Final(hash, sha384) != 1)
    {
        memset(hash, 0x0, SHA384_HASHLEN);
        memset(sha384, 0x0, sizeof(psSha384_t));
    }
}
#endif

#ifdef USE_OPENSSL_SHA512
int32_t psSha512Init(psSha512_t *sha512)
{
    if (SHA512_Init(sha512) != 1)
    {
        return PS_FAIL;
    }
    return PS_SUCCESS;
}
void psSha512Update(psSha512_t *sha512, const unsigned char *buf, uint32_t len)
{
    if (SHA512_Update(sha512, buf, len) != 1)
    {
        memset(sha512, 0x0, sizeof(psSha512_t));
    }
}
void psSha512Final(psSha512_t *sha512, unsigned char hash[SHA512_HASHLEN])
{
    if (SHA512_Final(hash, sha512) != 1)
    {
        memset(hash, 0x0, SHA512_HASHLEN);
        memset(sha512, 0x0, sizeof(psSha512_t));
    }
}
#endif

/******************************************************************************/
