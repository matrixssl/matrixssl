/**
 *      @file    symmetric_openssl.c
 *      @version $Format:%h%d$
 *
 *      Symmetric compatibility layer between MatrixSSL and OpenSSL.
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

/* TODO aesni_cbc_sha256_enc */
#ifdef USE_OPENSSL_AES_CBC

__inline static const EVP_CIPHER *EVP_aes_cbc(uint8_t keylen)
{
    switch (keylen)
    {
    case AES128_KEYLEN:
        return EVP_get_cipherbyname("aes-128-cbc");
/*              return EVP_aes_128_cbc(); */
    case AES192_KEYLEN:
        return EVP_get_cipherbyname("aes-192-cbc");
/*              return EVP_aes_192_cbc(); */
    case AES256_KEYLEN:
        return EVP_get_cipherbyname("aes-256-cbc");
/*              return EVP_aes_256_cbc(); */
    }
    return NULL;
}

int32_t psAesInitCBC(psAesCbc_t *ctx,
    const unsigned char IV[AES_IVLEN],
    const unsigned char key[AES_MAXKEYLEN], uint8_t keylen,
    uint32_t flags)
{
    OpenSSL_add_all_algorithms();
    EVP_CIPHER_CTX_init(ctx);
    if (EVP_CipherInit_ex(ctx, EVP_aes_cbc(keylen), NULL, key, IV,
            flags & PS_AES_ENCRYPT ? 1 : 0))
    {
        /* Turn off padding so all the encrypted/decrypted data will be
            returned in the single call to Update.  This will require that
            all the incoming data be an exact block multiple (which is true
            for TLS usage where all padding is accounted for) */
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        return PS_SUCCESS;
    }
    EVP_CIPHER_CTX_cleanup(ctx);
    psAssert(0);
    return PS_FAIL;
}

void psAesClearCBC(psAesCbc_t *ctx)
{
    EVP_CIPHER_CTX_cleanup(ctx);
}

void psAesDecryptCBC(psAesCbc_t *ctx,
    const unsigned char *ct, unsigned char *pt,
    uint32_t len)
{
    int outl = len;

    if (!EVP_DecryptUpdate(ctx, pt, &outl, ct, len))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        psAssert(0);
    }
    psAssert(outl == len);
}

void psAesEncryptCBC(psAesCbc_t *ctx,
    const unsigned char *pt, unsigned char *ct,
    uint32_t len)
{
    int outl = len;

    if (!EVP_EncryptUpdate(ctx, ct, &outl, pt, len))
    {
        EVP_CIPHER_CTX_cleanup(ctx);
        psAssert(0);
    }
    psAssert(outl == len);
}

#endif /* USE_OPENSSL_AES_CBC */

/******************************************************************************/

