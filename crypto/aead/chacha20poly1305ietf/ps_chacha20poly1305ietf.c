/**
 *      @file    ps_chacha20poly1305ietf.c
 *      @version $Format:%h%d$
 *
 *      Provide CHACHA20-POLY1305 (IETF) Autenticated Encryption
 *      with Authenticated data to MatrixSSL.
 *      For algorithm, see RFC 7539 ChaCha20 and Poly1305 for IETF Protocols.
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

#include "../../cryptoImpl.h"
#include "ps_chacha20poly1305ietf.h"
#include "ps_chacha20poly1305ietf_config.h"
#include <stdlib.h>

/******************************************************************************/

#ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
# include "crypto_aead_chacha20poly1305.h"
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
    /* Ensure constants match. */
    static int pschacha2_initialized = 0;

    if (!pschacha2_initialized)
    {
        extern int psCrypto_stream_chacha20_pick_best_implementation(void);
        extern int psCrypto_onetimeauth_poly1305_pick_best_implementation(void);
        extern int psSodium_runtime_get_cpu_features(void);

        psAssert(crypto_aead_chacha20poly1305_ietf_KEYBYTES ==
                 PS_CHACHA20POLY1305_IETF_KEYBYTES);
        psAssert(crypto_aead_chacha20poly1305_IETF_NPUBBYTES ==
                 PS_CHACHA20POLY1305_IETF_NPUBBYTES);
        psAssert(crypto_aead_chacha20poly1305_ietf_ABYTES ==
                 PS_CHACHA20POLY1305_IETF_ABYTES);

        if (!getenv("MATRIX_CHACHA20POLY1305_REF"))
        {
            (void)psSodium_runtime_get_cpu_features();        
            (void)psCrypto_stream_chacha20_pick_best_implementation();
            (void)psCrypto_onetimeauth_poly1305_pick_best_implementation();
        }
        pschacha2_initialized = 1;
    }

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
    
    ret = psCrypto_aead_chacha20poly1305_ietf_encrypt_detached(
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

    if (psCrypto_aead_chacha20poly1305_ietf_decrypt_detached(
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
        unsigned char Ciphertext_p[PS_EXACTLY_EXPR(PlaintextNBytes + PS_CHACHA20POLY1305_IETF_ABYTES)])
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
    
    ret = psCrypto_aead_chacha20poly1305_ietf_encrypt(
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

    if (psCrypto_aead_chacha20poly1305_ietf_decrypt(
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


/************************************************************************************/

#endif /* USE_MATRIX_CHACHA20_POLY1305_IETF */

