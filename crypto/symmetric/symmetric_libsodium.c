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

#ifdef USE_LIBSODIUM_CHACHA20_POLY1305_IETF
/*********************************************************************************/
/* chacha20-poly1305 AEAD low-level implementation, based on libsodium library   */
/* For details, see                                                              */
/* https://tools.ietf.org/html/rfc7539 $2.8 AEAD Construction                    */
/*********************************************************************************/

/* Initialize psChacha20Poly1305Ietf for use. */
psRes_t psChacha20Poly1305IetfInit(
        psChacha20Poly1305Ietf_t *ctx,
        const unsigned char key[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_KEYBYTES)])
{
    /* Copy the key */
    memcpy(ctx->key, key, PS_CHACHA20POLY1305_IETF_KEYBYTES);

    return PS_SUCCESS;
}

/******************************************************************************/
/* Clear the provided context structure
 */
void psChacha20Poly1305IetfClear(psChacha20Poly1305Ietf_t *ctx)
{
    memset_s(ctx,
             sizeof(psChacha20Poly1305Ietf_t),
             0x0,
             sizeof(psChacha20Poly1305Ietf_t));
}

psResSize_t psChacha20Poly1305IetfEncryptDetached(
        psChacha20Poly1305Ietf_t *Context_p,
        const unsigned char *Plaintext_p,
        psSizeL_t PlaintextNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSize_t AadNBytes,
        unsigned char *Ciphertext_p,
        unsigned char Mac_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_ABYTES)])
{
    int ret;

    /* Check input is not too large for this API. */
    if (PlaintextNBytes > (psSizeL_t)PS_RES_SIZE_OK_MAX)
    {
        return PS_ARG_FAIL;
    }
    
    ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            Ciphertext_p,
            Mac_p,
            NULL,
            (const unsigned char *)Plaintext_p,
            (unsigned long long)PlaintextNBytes,
            (const unsigned char *)Aad_p,
            (unsigned long long)AadNBytes,
            NULL,
            (const unsigned char *)Iv_p,
            (const unsigned char *)Context_p->key);

    if (ret == 0)
    {
        return (psResSize_t) PlaintextNBytes;
    }
    return PS_FAIL;
}


psResSize_t psChacha20Poly1305IetfDecryptDetached(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)],
        const unsigned char *Ciphertext_p,
        psSizeL_t CiphertextNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSizeL_t AadNBytes,
        const unsigned char Mac_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_ABYTES)],
        unsigned char *Plaintext_p)
{
    psSizeL_t plaintextNBytes = CiphertextNBytes; /* Plaintext length is the same than ciphertext length. */

    /* Check input is not too large for this API. */
    if (plaintextNBytes > (psSizeL_t)(psResSize_t)PS_RES_SIZE_OK_MAX)
    {
        return PS_ARG_FAIL;
    }

    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                Plaintext_p,
                NULL,
                Ciphertext_p,
                (unsigned long long)CiphertextNBytes,
                (const unsigned char *)Mac_p,
                (const unsigned char *)Aad_p,
                (unsigned long long)AadNBytes,
                (const unsigned char *)Iv_p,
                (const unsigned char *)Context_p->key) != 0)
    {
        psTraceCrypto("chacha20 poly1305 AEAD didn't authenticate\n");
        return PS_AUTH_FAIL;
    }

    return (psResSize_t)plaintextNBytes;
}

/******************************************************************************/
/*
        Chacha20 poly1305 Ietf encryption function (ciphertext + mac in one sequence.)
 */
psResSize_t psChacha20Poly1305IetfEncrypt(
        psChacha20Poly1305Ietf_t *Context_p,
        const unsigned char *Plaintext_p,
        psSizeL_t PlaintextNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSizeL_t AadNBytes,
        unsigned char Ciphertext_p[PS_EXACTLY_EXPR(PlaintextLen + PS_CHACHA20POLY1305_IETF_ABYTES)])
{
#ifdef USE_PS_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ENCRYPT
    unsigned long long ciphertextNBytes = 0ULL;
    psResSize_t ret;

    /* Check input is not too large for this API. */
    if ((PlaintextNBytes + PS_CHACHA20POLY1305_IETF_ABYTES) >
        (psSizeL_t)PS_RES_SIZE_OK_MAX)
    {
        return PS_ARG_FAIL;
    }
    
    ret = crypto_aead_chacha20poly1305_ietf_encrypt(
            Ciphertext_p,
            &ciphertextNBytes,
            (const unsigned char *)Plaintext_p,
            (unsigned long long)PlaintextNBytes,
            (const unsigned char *)Aad_p,
            (unsigned long long)AadNBytes,
            NULL,
            (const unsigned char *)Iv_p,
            (const unsigned char *)Context_p->key);

    if (ret == 0)
    {
        return (psResSize_t) ciphertextNBytes;
    }
    return PS_FAIL;
#else
    psSizeL_t ciphertextNBytes =
        PlaintextNBytes + PS_CHACHA20POLY1305_IETF_ABYTES;
    psResSize_t ret;

    /* Check input is not too large for this API. */
    if (PlaintextNBytes > (psSizeL_t)PS_RES_SIZE_OK_MAX ||
        ciphertextNBytes > (psSizeL_t)PS_RES_SIZE_OK_MAX)
    {
        return PS_ARG_FAIL;
    }
    
    ret = psChacha20Poly1305IetfEncryptDetached(
            Context_p,
            Plaintext_p,
            PlaintextNBytes,
            Iv_p,
            Aad_p,
            AadNBytes,
            Ciphertext_p,
            Ciphertext_p + PlaintextNBytes);

    if (ret >= 0)
    {
        ret += PS_CHACHA20POLY1305_IETF_ABYTES;
    }
    return ret;
#endif
}

/******************************************************************************/
/*
    Decrypt data using chach20-poly1305 authenticated encryption function.
 */
psResSize_t psChacha20Poly1305IetfDecrypt(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)],
        const unsigned char Ciphertext_p[PS_EXACTLY_EXPR(CiphertextNBytes)],
        psSizeL_t CiphertextNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSizeL_t AadNBytes,
        unsigned char *Plaintext_p)
{
#ifdef USE_PS_CRYPTO_AEAD_CHACHA20POLY1305_IETF_DECRYPT
    /* Old path, which can be enabled by setting USE_PS_CRYPTO_AEAD_CHACHA20POLY1305_IETF_DECRYPT. */
    psSizeL_t plaintextNBytes = CiphertextNBytes - PS_CHACHA20POLY1305_IETF_ABYTES;
    if (CiphertextNBytes < PS_CHACHA20POLY1305_IETF_ABYTES)
    {
        return PS_ARG_FAIL;
    }
    /* Check input is not too large for this API. */
    if (plaintextNBytes > (psSizeL_t)(psResSize_t)PS_RES_SIZE_OK_MAX)
    {
        return PS_ARG_FAIL;
    }

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
                Plaintext_p,
                NULL,
                NULL,
                Ciphertext_p,
                (unsigned long long)CiphertextNBytes,
                (const unsigned char *)Aad_p,
                (unsigned long long)AadNBytes,
                (const unsigned char *)Iv_p,
                (const unsigned char *)Context_p->key) != 0)
    {
        psTraceCrypto("chacha20 poly1305 AEAD didn't authenticate\n");
        return PS_AUTH_FAIL;
    }

    return (psResSize_t)plaintextNBytes;
#else
    psSizeL_t plaintextNBytes;

    /* Ensure input is not too short. */
    if (CiphertextNBytes < PS_CHACHA20POLY1305_IETF_ABYTES)
    {
        return PS_ARG_FAIL;
    }

    plaintextNBytes = CiphertextNBytes - PS_CHACHA20POLY1305_IETF_ABYTES;
    return psChacha20Poly1305IetfDecryptDetached(
            Context_p,
            Ciphertext_p,
            plaintextNBytes,
            Iv_p,
            Aad_p,
            AadNBytes,
            Ciphertext_p + plaintextNBytes,
            Plaintext_p);
#endif
}
#endif /* USE_LIBSODIUM_CHACHA20_POLY1305_IETF */
