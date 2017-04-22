/**
 *      @file    symmetric_libsodium.c
 *      @version $Format:%h%d$
 *
 *      Symmetric compatibility layer between MatrixSSL and libsodium.
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

#ifdef USE_LIBSODIUM_AES_GCM

/******************************************************************************/
/*
    Initialize an AES GCM context
 */

int32_t psAesInitGCM(psAesGcm_t *ctx,
    const unsigned char key[AES_MAXKEYLEN], uint8_t keylen)
{
    /* Check that structure is 16bytes aligned: */
    if (((uintptr_t) (const void *) (&(ctx->libSodiumCtx))) % 16 != 0)
    {
        psTraceCrypto("\nFAIL: libsodium structure not 16bytes aligned");
        printf("FAIL: libsodium structure not 16bytes aligned %p", &(ctx->libSodiumCtx));
        psAssert(0);
        return PS_FAIL;
    }

    /* libsodium only supports aes256, not aes128 */
    if (keylen != crypto_aead_aes256gcm_KEYBYTES)
    {
        psTraceCrypto("FAIL: libsodium-aes doesn't support this key length");
        psAssert(keylen == crypto_aead_aes256gcm_KEYBYTES);
        return PS_FAIL;
    }

    if (sodium_init() != 0)
    {
        /* libsodium is already initialized, no problem */
    }

    if (crypto_aead_aes256gcm_is_available() == 0)
    {
        psTraceCrypto("FAIL: libsodium-aes not supported");
        psAssert(0);
        return PS_FAIL;
    }

    memset(ctx, 0x00, sizeof(psAesGcm_t));

    if (crypto_aead_aes256gcm_beforenm(&(ctx->libSodiumCtx), key) != 0)
    {
        psTraceCrypto("FAIL: libsodium-aes init");
        psAssert(0);
        return PS_FAIL;
    }
    return PS_SUCCESS;
}

/******************************************************************************/

void psAesClearGCM(psAesGcm_t *ctx)
{
    /* Comment to add (todo) */
    memset_s(ctx, sizeof(psAesGcm_t), 0x0, sizeof(psAesGcm_t));
}

/******************************************************************************/
/*
    Specifiy the IV and additional data to an AES GCM context that was
    created with psAesInitGCM
 */
void psAesReadyGCM(psAesGcm_t *ctx,
    const unsigned char IV[AES_IVLEN],
    const unsigned char *aad, psSize_t aadLen)
{
    /* --- Set up context structure ---// */

    /* Set up IV (nonce) */
    memset(ctx->IV, 0, 16);
    memcpy(ctx->IV, IV, 12);

    if (aadLen > sizeof(ctx->Aad))
    {
        psTraceCrypto("FAIL: size issue");
        psAssert(0);
    }

    /* Set up additional data */
    memcpy(ctx->Aad, aad, aadLen);
    ctx->AadLen = aadLen;
}

/******************************************************************************/
/*
    Public GCM encrypt function.  This will just perform the encryption.  The
    tag should be fetched with psAesGetGCMTag
 */
void psAesEncryptGCM(psAesGcm_t *ctx, const unsigned char *pt, unsigned char *ct, uint32_t len)
{
    unsigned long long ciphertext_len;
    unsigned char *resultEncryption;

    resultEncryption = psMalloc(NULL, len + sizeof(ctx->Tag));

    /* libsodium will put the (cipher text and the tag) in the result, */
    crypto_aead_aes256gcm_encrypt_afternm(resultEncryption, &ciphertext_len,
        (const unsigned char *) pt, (unsigned long long) len,
        (const unsigned char *) ctx->Aad, (unsigned long long) ctx->AadLen,
        NULL, (const unsigned char *) ctx->IV,
        (crypto_aead_aes256gcm_state *) &(ctx->libSodiumCtx));

    /* Copy the authentication tag in context to be able to retrieve it later */
    memcpy(ctx->Tag, (resultEncryption + len), sizeof(ctx->Tag));

    /* Copy the ciphertext in destination */
    memcpy(ct, resultEncryption, len);

    psFree(resultEncryption, NULL);
}

/******************************************************************************/
/*
    After encryption this function is used to retreive the authentication tag
 */
void psAesGetGCMTag(psAesGcm_t *ctx, uint8_t tagBytes, unsigned char tag[AES_BLOCKLEN])
{
    memcpy(tag, ctx->Tag, tagBytes);
}

/* Just does the GCM decrypt portion.  Doesn't expect the tag to be at the end
    of the ct.  User will invoke psAesGetGCMTag seperately */
void psAesDecryptGCMtagless(psAesGcm_t *ctx,
    const unsigned char *ct, unsigned char *pt,
    uint32_t len)
{
    /* Not possible with libsodium ? */
    psAssert(0);
}


/******************************************************************************/
/*
    Decrypt from libsodium will perform itself the tag comparaison.
    So ct is holding: cipher text || tag . The provided length (ctLen) must reflect this
 */
int32_t psAesDecryptGCM(psAesGcm_t *ctx,
    const unsigned char *ct, uint32_t ctLen,
    unsigned char *pt, uint32_t ptLen)
{
    unsigned long long decrypted_len;

    if ((ctLen - ptLen) != crypto_aead_aes256gcm_ABYTES)
    {
        psTraceCrypto("Cipher text must include the tag\n");
        return PS_ARG_FAIL;
    }

    if (crypto_aead_aes256gcm_decrypt_afternm(pt,
            &decrypted_len,
            NULL,
            ct,
            (unsigned long long) ctLen,
            (const unsigned char *) ctx->Aad,
            (unsigned long long) ctx->AadLen,
            (const unsigned char *) ctx->IV,
            (crypto_aead_aes256gcm_state *) &(ctx->libSodiumCtx)) != 0)
    {
        psTraceCrypto("GCM didn't authenticate\n");
        return PS_AUTH_FAIL;

    }

    if (decrypted_len != ptLen)
    {
        psTraceCrypto("Problem during decryption\n");
        return PS_AUTH_FAIL;
    }

    return PS_SUCCESS;
}

#endif /* USE_LIBSODIUM_AES_GCM */

/******************************************************************************/

#ifdef USE_LIBSODIUM_CHACHA20_POLY1305
/*********************************************************************************/
/* chacha20-poly1305 AEAD low-level implementation, based on libsodium library   */
/* Refer to the following spec:                                                                                                  */
/* https://tools.ietf.org/html/rfc7539 $2.8 AEAD Construction                                    */
/*                                                                                                                                                               */
/*      !!! Note that if CHACHA20POLY1305_IETF is defined than the nonce must be     */
/*       96bits, if CHACHA20POLY1305_IETF not defined the nonce must be 64bits   */
/*********************************************************************************/
/**
    Initialize an chacha20 poly1305 context. Put the provided key in the context
    structure

    @param ctx Pointer on the cipher context structure. This structure holds the key, nonce & aad...
    @param key The algo's key
    @param keylen The key's length

    @return PS_SUCCESS if success
            PS_FAIL in case of key length problem

 */
int32_t psChacha20Poly1305Init(psChacha20Poly1305_t *ctx,
    const unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES], uint8_t keylen)
{
    if (keylen != crypto_aead_chacha20poly1305_KEYBYTES)
    {
        psTraceCrypto("FAIL: libsodium-chacha20-poly1305 not supporting this key length");
        psAssert(0);
        return PS_FAIL;
    }
    memset(ctx, 0x0, sizeof(psChacha20Poly1305_t));
    /* Copy the key */
    memcpy(ctx->key, key, crypto_aead_chacha20poly1305_KEYBYTES);

    return PS_SUCCESS;
}

/******************************************************************************/
/**
    Clear the provided context structure
    @param ctx context structure
 */
void psChacha20Poly1305Clear(psChacha20Poly1305_t *ctx)
{
    memset_s(ctx, sizeof(psChacha20Poly1305_t), 0x0, sizeof(psChacha20Poly1305_t));
}

/******************************************************************************/
/**
    Specifiy the IV and additional data to an chacha20 poly1305 context that was
    created with psChacha20Poly1305Init.


    @param ctx Pointer on the cipher context structure. This structure holds the key, nonce & aad...
    @param IV pointer on the provided IV
            (called nonce if referring to https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-03)
    @param aad pointer on buffer holding additional data, as specified in

 */
void psChacha20Poly1305Ready(psChacha20Poly1305_t *ctx,
    const unsigned char *IV,
    const unsigned char *aad, psSize_t aadLen)
{
    /* --- Set up context structure ---// */

    /* Set up IV */
# ifdef CHACHA20POLY1305_IETF
    memset(ctx->IV, 0, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    memcpy(ctx->IV, IV, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
# else
    memset(ctx->IV, 0, crypto_aead_chacha20poly1305_NPUBBYTES);
    memcpy(ctx->IV, IV, crypto_aead_chacha20poly1305_NPUBBYTES);
# endif

    if (aadLen > sizeof(ctx->Aad))
    {
        psTraceCrypto("FAIL: size issue with libsodium-chacha20-poly1305 additionnal data");
        psAssert(0);
    }

    /* Set up additional data */
    memcpy(ctx->Aad, aad, aadLen);
    ctx->AadLen = aadLen;
}

/******************************************************************************/
/*
        Public chacha20 poly1305 encrypt function.
        This will perform the encryption and compute the authentication tag at the
        same time. In the output pointer (ct), only the encrypted text is present, the
        tag should be fetched with psChacha20Poly1305GetTag

    @param ctx Pointer on the cipher context structure. This structure holds the key, nonce & aad...
    @param pt pointer on the text to encrypt
    @param ct pointer on encrypted text, output of this function
    @param len length of the text to encrypt
 */
void psChacha20Poly1305Encrypt(psChacha20Poly1305_t *ctx, const unsigned char *pt, unsigned char *ct, uint32_t len)
{
    unsigned long long ciphertext_len;
    unsigned char *resultEncryption;

    /* Allocate mem to store ciphertext and tag */
    resultEncryption = psMalloc(NULL, len + sizeof(ctx->Tag));

    /* libsodium will put the cipher text and the tag in the result. */
    /* resultEncryption = cipherText || tag */
# ifdef CHACHA20POLY1305_IETF
    crypto_aead_chacha20poly1305_ietf_encrypt(resultEncryption, &ciphertext_len,
        (const unsigned char *) pt, (unsigned long long) len,
        (const unsigned char *) ctx->Aad, (unsigned long long) ctx->AadLen,
        NULL, (const unsigned char *) ctx->IV, (const unsigned char *) ctx->key);
# else
    crypto_aead_chacha20poly1305_encrypt(resultEncryption, &ciphertext_len,
        (const unsigned char *) pt, (unsigned long long) len,
        (const unsigned char *) ctx->Aad, (unsigned long long) ctx->AadLen,
        NULL, (const unsigned char *) ctx->IV, (const unsigned char *) ctx->key);
# endif

    /* Copy the authentication tag in context to be able to retrieve it later */
    memcpy(ctx->Tag, (resultEncryption + len), sizeof(ctx->Tag));

    /* Copy the ciphertext in destination */
    memcpy(ct, resultEncryption, len);

    psFree(resultEncryption, NULL);
}

/************************************************************************************/
/*
   After encryption this function is used to retrieve the authentication tag
    @param ctx Pointer on the cipher context structure. This structure holds the key, nonce & aad...
    @param tagBytesLen length of tag to retrieve
    @param tag the provided buffer to hold the AEAD' authentication tag
 */
void psChacha20Poly1305GetTag(psChacha20Poly1305_t *ctx, uint8_t tagBytesLen, unsigned char tag[crypto_aead_chacha20poly1305_ABYTES])
{
    memcpy(tag, ctx->Tag, tagBytesLen);
}

/************************************************************************************/
/*
   Just does the chacha20 poly1305 decrypt portion.  Doesn't expect the tag to be
   at the end of the ct.  User will invoke psChacha20Poly1305GetTag seperately
                !!! Currently not available with libsodium      !!!!!
 */
void psChacha20Poly1305DecryptTagless(psChacha20Poly1305_t *ctx,
    const unsigned char *ct, unsigned char *pt,
    uint32_t len)
{
    /* Not possible with libsodium. */
    psAssert(0);
}

/******************************************************************************/
/*
    Decrypt function using libsodium library. This function will perform
    itself the tag comparaison.
    So the provided cipherText must hold: cipher text || tag .
    The provided length (ctLen) must reflect this.

    @param ctx Pointer on the cipher context structure. This structure holds the key, nonce & aad...
    @param ct pointer on: (cipherText || AEAD-Tag)
    @param ctLen length of data pointed by ct (so encrypted data + tag)
    @param pt pointer on decrypted data
    @param ptLen length of encrypted data

    @return length of decrypted data in case of success.
            PS_ARG_FAIL in case of parameter problem
            PS_AUTH_FAIL in case of problem during tag's authentication check or
                        during decryption operation
 */
int32_t psChacha20Poly1305Decrypt(psChacha20Poly1305_t *ctx,
    const unsigned char *ct, uint32_t ctLen,
    unsigned char *pt, uint32_t ptLen)
{
    unsigned long long decrypted_len;

    if ((ctLen - ptLen) != crypto_aead_chacha20poly1305_ABYTES)
    {
        psTraceCrypto("FAIL: Cipher text must include the tag\n");
        return PS_ARG_FAIL;
    }

# ifdef CHACHA20POLY1305_IETF
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &decrypted_len, NULL,
            ct, (unsigned long long) ctLen,
            (const unsigned char *) ctx->Aad, (unsigned long long) ctx->AadLen,
            (const unsigned char *) ctx->IV, (const unsigned char *) ctx->key) != 0)
    {

        psTraceCrypto("chacha20 poly1305 AEAD didn't authenticate\n");
        return PS_AUTH_FAIL;
    }
# else
    if (crypto_aead_chacha20poly1305_decrypt(pt, &decrypted_len, NULL,
            ct, (unsigned long long) ctLen,
            (const unsigned char *) ctx->Aad, (unsigned long long) ctx->AadLen,
            (const unsigned char *) ctx->IV,
            (const unsigned char *) ctx->key) != 0)
    {
        psTraceCrypto("chacha20 poly1305 AEAD didn't authenticate\n");
        return PS_AUTH_FAIL;
    }
# endif
    if (decrypted_len != ptLen)
    {
        psTraceCrypto("Problem during chacha20 poly1305 AEAD decryption\n");
        return PS_AUTH_FAIL;
    }

    return decrypted_len;
}

/************************************************************************************/

#endif /* USE_LIBSODIUM_CHACHA20_POLY1305 */

