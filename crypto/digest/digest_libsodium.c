/**
 *      @file    digest_libsodium.c
 *      @version $Format:%h%d$
 *
 *      Digest compatibility layer between MatrixSSL and libsodium.
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

#ifdef USE_LIBSODIUM_SHA256
int32_t psSha256Init(psSha256_t *sha256)
{
    if (crypto_hash_sha256_init(sha256) != 0)
    {
        return PS_FAIL;
    }
    return PS_SUCCESS;
}

void psSha256Update(psSha256_t *sha256, const unsigned char *buf, uint32_t len)
{
    if (crypto_hash_sha256_update(sha256, buf, len) != 0)
    {
        memset(sha256, 0x0, sizeof(psSha256_t));
    }
}

void psSha256Final(psSha256_t *sha256, unsigned char hash[SHA256_HASHLEN])
{

    if (crypto_hash_sha256_final(sha256, hash) != 0)
    {
        memset(hash, 0x0, SHA256_HASHLEN);
        memset(sha256, 0x0, sizeof(psSha256_t));
    }
}
#endif /* USE_LIBSODIUM_SHA256 */

#ifdef USE_LIBSODIUM_SHA384
/**
    libsodium doesn't explicitly support sha384, but since 384 uses the
    same compression as 512, we can use it here.
    @note This uses an internal field of crypto_hash_sha512_state, which
    may change with different versions of libsodium.
 */
int32_t psSha384Init(psSha384_t *sha384)
{
    static const uint64_t sha384_initstate[8] = {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
        0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
        0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
    };

    /* Sanity check libsodium hash structure for what we expect */
    if (sizeof(sha384->state) != 64)
    {
        psAssert(sizeof(sha384->state) == 64);
        return PS_FAIL;
    }
    if (crypto_hash_sha512_init(sha384) != 0)
    {
        return PS_FAIL;
    }
    /* 384 uses a different initial state than 512 */
    memcpy(sha384->state, sha384_initstate, sizeof sha384_initstate);
    return PS_SUCCESS;
}
void psSha384Update(psSha384_t *sha384, const unsigned char *buf, uint32_t len)
{
    if (crypto_hash_sha512_update(sha384, buf, len) != 0)
    {
        memset(sha384, 0x0, sizeof(psSha384_t));
    }
}
void psSha384Final(psSha384_t *sha384, unsigned char hash[SHA384_HASHLEN])
{
    unsigned char buf[SHA512_HASHLEN];

    if (crypto_hash_sha512_final(sha384, buf) != 0)
    {
        memset(buf, 0x0, SHA512_HASHLEN);
        memset(sha384, 0x0, sizeof(psSha384_t));
    }
    memcpy(hash, buf, SHA384_HASHLEN);
    memzero_s(buf, SHA512_HASHLEN);
}
#endif /* USE_LIBSODIUM_SHA384 */

#ifdef USE_LIBSODIUM_SHA512
int32_t psSha512Init(psSha512_t *sha512)
{
    if (crypto_hash_sha512_init(sha512) != 0)
    {
        return PS_FAIL;
    }
    return PS_SUCCESS;
}
void psSha512Update(psSha512_t *sha512, const unsigned char *buf, uint32_t len)
{
    if (crypto_hash_sha512_update(sha512, buf, len) != 0)
    {
        memset(sha512, 0x0, sizeof(psSha512_t));
    }
}
void psSha512Final(psSha512_t *sha512, unsigned char hash[SHA512_HASHLEN])
{
    if (crypto_hash_sha512_final(sha512, hash) != 0)
    {
        memset(hash, 0x0, SHA512_HASHLEN);
        memset(sha512, 0x0, sizeof(psSha512_t));
    }
}
#endif /* USE_LIBSODIUM_SHA512 */

/******************************************************************************/

#ifdef USE_LIBSODIUM_HMAC_SHA256
int32_t psHmacSha256(const unsigned char *key, psSize_t keyLen,
    const unsigned char *buf, uint32_t len,
    unsigned char hash[SHA256_HASHLEN], unsigned char *hmacKey,
    psSize_t *hmacKeyLen)
{
    psHmacSha256_t sha256;

    if (crypto_auth_hmacsha256_init(&sha256, key, keyLen) != 0)
    {
        psAssert(0);
        return PS_FAIL;
    }
    crypto_auth_hmacsha256_update(&sha256, buf, len);
    crypto_auth_hmacsha256_final(&sha256, hash);

    if (keyLen > 64)
    {
        crypto_hash_sha256(hmacKey, key, keyLen);
        *hmacKeyLen = SHA256_HASHLEN;
    }
    else
    {
        hmacKey = (unsigned char *) key;
        *hmacKeyLen = keyLen;
    }

    return PS_SUCCESS;
}

int32_t psHmacSha256Init(psHmacSha256_t *ctx,
    const unsigned char *key, psSize_t keyLen)
{

    if (crypto_auth_hmacsha256_init(ctx, key, keyLen) != 0)
    {
        memset(ctx, 0x0, sizeof(psHmacSha256_t));
        psAssert(0);
        return PS_FAIL;
    }
    return PS_SUCCESS;

}

void psHmacSha256Update(psHmacSha256_t *ctx,
    const unsigned char *buf, uint32_t len)
{
    if (crypto_auth_hmacsha256_update(ctx, buf, len) != 0)
    {
        memset(ctx, 0x0, sizeof(psHmacSha256_t));
    }

}

void psHmacSha256Final(psHmacSha256_t *ctx,
    unsigned char hash[SHA256_HASHLEN])
{

    if (crypto_auth_hmacsha256_final(ctx, hash) != 0)
    {
        psAssert(0);
    }
    memset(ctx, 0x0, sizeof(psHmacSha256_t));
}
#endif /* USE_LIBSODIUM_HMAC_SHA256 */

/******************************************************************************/
