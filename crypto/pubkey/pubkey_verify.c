/**
 *      @file    pubkey_verify.c
 *      @version $Format:%h%d$
 *
 *      Algorithm-independent verification API.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
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

#if defined(USE_RSA) || defined(USE_ECC)

psRes_t psVerifySig(psPool_t *pool,
    const unsigned char *msgIn,
    psSizeL_t msgInLen,
    const unsigned char *sig,
    psSize_t sigLen,
    psPubKey_t *key,
    int32_t signatureAlgorithm,
    psBool_t *verifyResult,
    psVerifyOptions_t *opts)
{
    unsigned char out[SHA512_HASH_SIZE] = { 0 };
# ifdef USE_ECC
    int32 eccRet;
# endif

    psRes_t rc = PS_SUCCESS;

    if (pool == NULL)
    {
    }

    *verifyResult = PS_FALSE;

    switch (key->type)
    {
# ifdef USE_RSA
    case PS_RSA:
#  ifdef USE_PKCS1_PSS
        if (opts && opts->useRsaPss)
        {
            rc = psRsaPssVerify(pool,
                    msgIn,
                    msgInLen,
                    sig,
                    sigLen,
                    key,
                    signatureAlgorithm,
                    verifyResult,
                    opts);
            if (rc != PS_SUCCESS)
            {
                psTraceCrypto("Error validating RSA-PSS signature\n");
                goto out;
            }
        }
        else
#  endif /* USE_PKCS1_PSS */
        {

            if (opts && opts->msgIsDigestInfo)
            {
                /* RSA PKCS 1.5 verification of TLS signed elements. */
                rc = pubRsaDecryptSignedElementExt(pool,
                        &key->key.rsa,
                        (unsigned char *) sig,
                        sigLen,
                        out,
                        msgInLen,
                        signatureAlgorithm,
                        NULL);
                if (rc < 0)
                {
                    psTraceIntCrypto("pubRsaDecryptSignedElementExt failed: %d\n",
                            rc);
                    rc = PS_FAILURE;
                    goto out;
                }
            }
            else
            {
                /* Standard RSA PKCS #1.5 verification. */
                rc = psRsaDecryptPub(pool,
                        &key->key.rsa,
                        (unsigned char *) sig,
                        sigLen,
                        out,
                        msgInLen,
                        NULL);
                if (rc < 0)
                {
                    psTraceIntCrypto("pubRsaDecryptPub failed: %d\n", rc);
                    rc = PS_FAILURE;
                    goto out;
                }

            }
            if (memcmpct(msgIn, out, msgInLen) != 0)
            {
                psTraceCrypto("RSA PKCS #1.5 signature verification failed\n");
                rc = PS_VERIFICATION_FAILED;
                *verifyResult = PS_FALSE;
                goto out;
            }
        }
        break;
# endif /* USE_RSA */
# ifdef USE_ECC
    case PS_ECC:
        rc = psEccDsaVerify(pool,
                &key->key.ecc,
                msgIn,
                msgInLen,
                sig,
                sigLen,
                &eccRet,
                NULL);
        if (rc < 0)
        {
            psTraceIntCrypto("psEccDsaVerify failed: %d\n", rc);
            rc = PS_FAILURE;
            goto out;
        }
        if (eccRet != 1)
        {
            psTraceCrypto("ECDSA signature verification failed\n");
            rc = PS_VERIFICATION_FAILED;
            *verifyResult = PS_FALSE;
            goto out;
        }
        break;
#  ifdef USE_ED25519
    case PS_ED25519:
        rc = psEd25519Verify(sig,
                msgIn,
                msgInLen,
                key->key.ed25519.pub);
        if (rc != PS_SUCCESS)
        {
            psTraceCrypto("Ed25519 signature verification failed\n");
            rc = PS_VERIFICATION_FAILED;
            *verifyResult = PS_FALSE;
            goto out;
        }
        break;
#  endif /* USE_ED25519 */
# endif /* USE_ECC */
    default:
        psTraceCrypto("Unsupported pubkey algorithm\n");
        rc = PS_UNSUPPORTED_FAIL;
        goto out;
    }

    *verifyResult = PS_TRUE;

out:
    return rc;
}

psRes_t psHashDataAndVerifySig(psPool_t *pool,
    const unsigned char *dataBegin,
    const psSizeL_t dataLen,
    const unsigned char *sig,
    psSize_t sigLen,
    psPubKey_t *key,
    int32_t signatureAlgorithm,
    psBool_t *verifyResult,
    psVerifyOptions_t *opts)
{
    unsigned char digest[SHA512_HASH_SIZE] = { 0 };
    psSize_t digestLen = sizeof(digest);
    psRes_t rc;

    *verifyResult = PS_FALSE;

    rc = psComputeHashForSig(dataBegin, dataLen,
        signatureAlgorithm, digest,
        &digestLen);
    if (rc != PS_SUCCESS)
    {
        return rc;
    }

    rc = psVerifySig(pool,
        digest, digestLen,
        sig, sigLen,
        key, signatureAlgorithm,
        verifyResult,
        opts);
    return rc;
}

# ifdef USE_PKCS1_PSS
static
int32_t get_pss_hash_sig_alg(psVerifyOptions_t *opts)
{
    switch (opts->rsaPssHashAlg)
    {
    case PKCS1_SHA1_ID:
        return OID_SHA1_RSA_SIG;
    case PKCS1_SHA256_ID:
        return OID_SHA256_RSA_SIG;
    case PKCS1_SHA384_ID:
        return OID_SHA384_RSA_SIG;
    case PKCS1_SHA512_ID:
        return OID_SHA512_RSA_SIG;
    default:
        return PS_UNSUPPORTED_FAIL;
    }
}
# endif /* USE_PKCS1_PSS */

psRes_t psVerify(psPool_t *pool,
        const unsigned char *dataBegin,
        const psSizeL_t dataLen,
        const unsigned char *sig,
        psSize_t sigLen,
        psPubKey_t *key,
        int32_t signatureAlgorithm,
        psBool_t *verifyResult,
        psVerifyOptions_t *opts)
{
    psBool_t needPreHash = PS_TRUE;

    *verifyResult = PS_FALSE;

    if (opts && opts->useRsaPss)
    {
# if defined (USE_PKCS1_PSS) && defined(USE_CL_RSA)
        /* The crypto-cl API for RSA-PSS verification does not support
           pre-hashing. */
        needPreHash = PS_FALSE;
# endif
        if (needPreHash && signatureAlgorithm == OID_RSASSA_PSS)
        {
            /* psComputeHashForSig called by psHashDataAndVerifySig below
               cannot operate on OID_RSASSA_PSS, since this ID does not
               indicate the hash alg. So translate to one of the
               OID_*_RSA_SIG IDs. */
            signatureAlgorithm = get_pss_hash_sig_alg(opts);
        }
    }

# ifdef USE_ED25519
    if (signatureAlgorithm == OID_ED25519_KEY_ALG)
    {
        /* The Ed25519 algorithm does not use pre-hashing. */
        needPreHash = PS_FALSE;
    }
# endif /* USE_ED25519 */

    if (needPreHash)
    {
        return psHashDataAndVerifySig(pool,
                dataBegin,
                dataLen,
                sig,
                sigLen,
                key,
                signatureAlgorithm,
                verifyResult,
                opts);
    }
    else
    {
        return psVerifySig(pool,
                dataBegin,
                dataLen,
                sig,
                sigLen,
                key,
                signatureAlgorithm,
                verifyResult,
                opts);
    }
}

/******************************************************************************/

#endif /* USE_RSA || USE_ECC */
