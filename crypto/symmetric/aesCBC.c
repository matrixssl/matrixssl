/**
 *      @file    aesCBC.c
 *      @version $Format:%h%d$
 *
 *      AES CBC block cipher implementation.
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

#ifdef USE_MATRIX_AES_CBC

/******************************************************************************/

void psAesClearCBC(psAesCbc_t *ctx)
{
    /* Only need to clear block if it's implemented externally, Matrix block
        is part of CipherContext and will be cleared below */
# ifndef USE_MATRIX_AES_BLOCK
    psAesClearBlockKey(&ctx->key);
# endif
    memset_s(ctx, sizeof(psAesCbc_t), 0x0, sizeof(psAesCbc_t));
}

/******************************************************************************/
/*
    Software implementation of AES CBC APIs
 */
int32_t psAesInitCBC(psAesCbc_t *ctx,
    const unsigned char IV[AES_IVLEN],
    const unsigned char key[AES_MAXKEYLEN], uint8_t keylen,
    uint32_t flags)
{
    int32_t x, err;

# ifdef CRYPTO_ASSERT
    if (IV == NULL || key == NULL || ctx == NULL ||
        !(flags & (PS_AES_ENCRYPT | PS_AES_DECRYPT)))
    {

        psTraceCrypto("psAesInitCBC arg fail\n");
        return PS_ARG_FAIL;
    }
# endif
    if ((err = psAesInitBlockKey(&ctx->key, key, keylen, flags)) != PS_SUCCESS)
    {
        return err;
    }
    for (x = 0; x < AES_BLOCKLEN; x++)
    {
        ctx->IV[x] = IV[x];
    }
    return PS_SUCCESS;
}

/******************************************************************************/

void psAesEncryptCBC(psAesCbc_t *ctx,
    const unsigned char *pt, unsigned char *ct,
    uint32_t len)
{
    uint32_t i, j;
    unsigned char tmp[AES_BLOCKLEN];

# ifdef CRYPTO_ASSERT
    if (pt == NULL || ct == NULL || ctx == NULL || (len & 0x7) != 0 ||
        ctx->key.type != PS_AES_ENCRYPT)
    {

        psTraceCrypto("Bad parameters to psAesEncryptCBC\n");
        return;
    }
# endif
    for (i = 0; i < len; i += AES_BLOCKLEN)
    {
        /* xor IV against plaintext */
        for (j = 0; j < AES_BLOCKLEN; j++)
        {
            tmp[j] = pt[j] ^ ctx->IV[j];
        }

        psAesEncryptBlock(&ctx->key, tmp, ct);

        /* store IV [ciphertext] for a future block */
        for (j = 0; j < AES_BLOCKLEN; j++)
        {
            ctx->IV[j] = ct[j];
        }
        ct += AES_BLOCKLEN;
        pt += AES_BLOCKLEN;
    }

    memset_s(tmp, sizeof(tmp), 0x0, sizeof(tmp));
}

/******************************************************************************/

void psAesDecryptCBC(psAesCbc_t *ctx,
    const unsigned char *ct, unsigned char *pt,
    uint32_t len)
{
    uint32_t i, j;
    unsigned char tmp[AES_BLOCKLEN], tmp2[AES_BLOCKLEN];

# ifdef CRYPTO_ASSERT
    if (pt == NULL || ct == NULL || ctx == NULL || (len & 0x7) != 0 ||
        ctx->key.type != PS_AES_DECRYPT)
    {

        psTraceCrypto("Bad parameters to psAesDecryptCBC\n");
        return;
    }
# endif

    for (i = 0; i < len; i += AES_BLOCKLEN)
    {
        psAesDecryptBlock(&ctx->key, ct, tmp);
        /* xor IV against the plaintext of the previous step */
        for (j = 0; j < AES_BLOCKLEN; j++)
        {
            /* copy CT in case ct == pt */
            tmp2[j] = ct[j];
            /* actually decrypt the byte */
            pt[j] = tmp[j] ^ ctx->IV[j];
        }
        /* replace IV with this current ciphertext */
        for (j = 0; j < AES_BLOCKLEN; j++)
        {
            ctx->IV[j] = tmp2[j];
        }
        ct += AES_BLOCKLEN;
        pt += AES_BLOCKLEN;
    }
    memset_s(tmp, sizeof(tmp), 0x0, sizeof(tmp));
    memset_s(tmp2, sizeof(tmp2), 0x0, sizeof(tmp2));
}

#endif /* USE_MATRIX_AES_CBC */

/******************************************************************************/

