/**
 *      @file    tls13SigVer.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 specific functions for signature generation and signature
 *      verification.
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
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

#ifdef USE_TLS_1_3

# ifndef DEBUG_TLS_1_3_SIG_VER
//#  define DEBUG_TLS_1_3_SIG_VER
# endif

/** Choose signature algorithm to use when constructing authentication signature.

    @param ssl
    @param peerSigAlgs List parsed from the peer's
    supported_signature_algorithms extension. Must be in order of descending
    priority.
    @param peerSigAlgsLen Number of entries in peerSigAlgs.
 */
# ifdef USE_IDENTITY_CERTIFICATES
uint16_t tls13ChooseSigAlg(ssl_t *ssl,
        const uint16_t *peerSigAlgs,
        psSize_t peerSigAlgsLen)
{
    int32_t pubKeyAlg, rc;
    psBool_t foundMatch = PS_FALSE;
    uint16_t ourSigAlgs[8] = {0};
    psSize_t ourSigAlgsLen;
    uint16_t chosenSigAlg = 0;
    sslIdentity_t *p;

    /* Should only be generating signatures when NOT using a PSK. */
    psAssert(ssl->sec.tls13UsingPsk == PS_FALSE);
    /* Consider all the configured/present keys. */
    for (p = ssl->keys->identity; p && !foundMatch; p = p->next)
    {
# ifdef USE_CERT_PARSE
        pubKeyAlg = p->cert->pubKeyAlgorithm;
        if (pubKeyAlg != OID_ECDSA_KEY_ALG &&
            pubKeyAlg != OID_RSA_KEY_ALG &&
            pubKeyAlg != OID_RSASSA_PSS &&
            pubKeyAlg != OID_ED25519_KEY_ALG)
        {
            psTraceIntInfo("Unsupported pubkey algorithm in our cert: %d\n",
                           pubKeyAlg);
            return PS_UNSUPPORTED_FAIL;
        }
# else
        /* If not having USE_CERT_PARSE, we'll need to have just one
           IdKey, and that's what we're going to use. */
        foundMatch = PS_TRUE;
# endif
        /*
          MatrixSSL only allows the server to load a single cert chain.
          This means that the public key in our cert fully determines:
          - Public key algorithm (RSA or ECDSA)
          - The group parameters:
          - Modulus size (2048, 3072 or 4096)
          - Named curve (P-256 or P-384)

          In addition, in TLS 1.3, the curve also specifies the hash algorithm
          to use: we must use SHA-256 with P-256 and SHA-384 with P-384. So
          there is very little for us to choose here.
*/

        /* Build our list. */
# ifdef USE_ECC
        if (p->privKey.type == PS_ECC)
        {
            if (p->privKey.key.ecc.curve->curveId == IANA_SECP256R1)
            {
                ourSigAlgs[0] = sigalg_ecdsa_secp256r1_sha256;
                ourSigAlgsLen = 1;
            }
            else if (p->privKey.key.ecc.curve->curveId == IANA_SECP384R1)
            {
                ourSigAlgs[0] = sigalg_ecdsa_secp384r1_sha384;
                ourSigAlgsLen = 1;
            }
            else if (p->privKey.key.ecc.curve->curveId == IANA_SECP521R1)
            {
                ourSigAlgs[0] = sigalg_ecdsa_secp521r1_sha512;
                ourSigAlgsLen = 1;
            }
            else
            {
                psTraceInfo("TODO: add support for more curves in TLS 1.3\n");
                continue;
            }
        }
# endif
#  ifdef USE_RSA
        else if (p->privKey.type == PS_RSA)
        {
            /* The OID restrictions are from section 4.2.3 of the TLS 1.3 draft.
               The restrictions apply when the public key is carried in a
               certificate. We would not be here unless we are using
               a certificate to authenticate ourselves. */
#   ifdef USE_CERT_PARSE
            if (p->cert->pubKeyAlgorithm == OID_RSASSA_PSS)
            {
                /*
                  rsa_pss_pss_*: pub key MUST use the RSASSA-PSS OID
                */
                ourSigAlgs[0] = sigalg_rsa_pss_pss_sha256;
                ourSigAlgs[1] = sigalg_rsa_pss_pss_sha384;
                ourSigAlgs[2] = sigalg_rsa_pss_pss_sha512;
                ourSigAlgsLen = 3;
            }
            else if (p->cert->pubKeyAlgorithm == OID_RSA_KEY_ALG)
            {
                /*
                  rsa_pss_rsae_*: pub key MUST use the rsaEncryption OID
                */
                ourSigAlgs[0] = sigalg_rsa_pss_rsae_sha256;
                ourSigAlgs[1] = sigalg_rsa_pss_rsae_sha384;
                ourSigAlgs[2] = sigalg_rsa_pss_rsae_sha512;
                ourSigAlgsLen = 3;
            }
            else
            {
                psTraceInfo("tls13ChooseSigAlg: Priv key does not match " \
                            "the type of public key in cert\n");
                return PS_UNSUPPORTED_FAIL;
            }
#   else
            /* We can do PSS with RSAE, but not the otherway around, so
               default to PSS when we don't know. */
            ourSigAlgs[0] = sigalg_rsa_pss_pss_sha256;
            ourSigAlgs[1] = sigalg_rsa_pss_pss_sha384;
            ourSigAlgs[2] = sigalg_rsa_pss_pss_sha512;
            ourSigAlgsLen = 3;
#   endif
        }
# endif
# ifdef USE_ED25519
        else if (p->privKey.type == PS_ED25519)
        {
            ourSigAlgs[0] = sigalg_ed25519;
            ourSigAlgsLen = 1;
        }
# endif
        else
        {
            psTraceInfo("Key type not supported in TLS 1.3\n");
            continue;
        }

        rc = tls13IntersectionPrioritySelectU16(ourSigAlgs,
                ourSigAlgsLen,
                peerSigAlgs,
                peerSigAlgsLen,
                NULL,
                0,
                &chosenSigAlg);
        if (rc == PS_SUCCESS)
        {
            foundMatch = PS_TRUE;
        }

        if (foundMatch)
        {
            /* Return the first match, and mark it as my chosen
             * identity. XXX:tmo this should be more explicit on the
             * caller. */
            ssl->chosenIdentity = p;
            return chosenSigAlg;
        }
        /* or try the next key */
    }
    psTraceErrr("Unable to negotiate signature algorithm\n");
    return PS_FAILURE;
}

static int32_t tls13MakeTbs(psPool_t *pool,
        const char *contextString,
        psSize_t contextStringLen,
        const unsigned char trHash[MAX_TLS_1_3_HASH_SIZE],
        psSize_t trHashLen,
        unsigned char **out,
        psSize_t *outLen)
{
    unsigned char *tbs, *p;
    psSize_t tbsLen;
    psSize_t i;

    /*
      "The digital signature is then computed over the concatenation of:
      -  A string that consists of octet 32 (0x20) repeated 64 times
      -  The context string
      -  A single 0 byte which serves as the separator
      -  The content to be signed"
    */

    tbsLen = 64 + contextStringLen + 1 + trHashLen;
    tbs = psMalloc(pool, tbsLen);
    if (tbs == NULL)
    {
        return PS_MEM_FAIL;
    }

    p = tbs;
    for (i = 0; i < 64; i++)
    {
        *p++ = 0x20;
    }
    Memcpy(p, contextString, contextStringLen);
    p += contextStringLen;
    *p++ = 0x00;
    Memcpy(p, trHash, trHashLen);

    *out = tbs;
    *outLen = tbsLen;

    return PS_SUCCESS;
}

int32_t tls13Sign(psPool_t *pool,
        psPubKey_t *privKey,
        uint16_t sigAlg,
        const unsigned char trHash[MAX_TLS_1_3_HASH_SIZE],
        psSize_t trHashLen,
        const char *contextString,
        psSize_t contextStringLen,
        unsigned char **out,
        psSize_t *outLen)
{
    unsigned char *tbs = NULL;
    psSize_t tbsLen;
    unsigned char hashTbs[MAX_HASH_SIZE];
    psSize_t hashTbsLen = sizeof(hashTbs);
    int32_t rc;
    int32_t hashSigAlg, sigAlgOid;
    psSignOpts_t opts = {0};
    psBool_t needPreHash = PS_FALSE;

    rc = tls13MakeTbs(pool,
            contextString,
            contextStringLen,
            trHash,
            trHashLen,
            &tbs,
            &tbsLen);
    if (rc != PS_SUCCESS)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_SIG_VER
    psTraceBytes("tls13Sign tbs", tbs, tbsLen);
#endif

    /*
      In RSA-PSS, there is no separate OID for each hash variant.
      Since psComputeHashForSig uses an OID param to determine
      the hash alg to use, we need a separate variable for that.
    */

    switch (sigAlg)
    {
# ifdef USE_ECC
    case sigalg_ecdsa_secp256r1_sha256:
        hashSigAlg = OID_SHA256_ECDSA_SIG;
        sigAlgOid = hashSigAlg;
        break;
    case sigalg_ecdsa_secp384r1_sha384:
        hashSigAlg = OID_SHA384_ECDSA_SIG;
        sigAlgOid = hashSigAlg;
        break;
    case sigalg_ecdsa_secp521r1_sha512:
        hashSigAlg = OID_SHA512_ECDSA_SIG;
        sigAlgOid = hashSigAlg;
        break;
# endif
# ifdef USE_ED25519
    case sigalg_ed25519:
        /* No pre-hashing used with Ed25519. */
        sigAlgOid = OID_ED25519_KEY_ALG;
        break;
# endif
# ifdef USE_RSA
    case sigalg_rsa_pss_pss_sha256:
    case sigalg_rsa_pss_rsae_sha256:
        hashSigAlg = OID_SHA256_RSA_SIG;
        sigAlgOid = OID_RSASSA_PSS;
        opts.rsaPssHashAlg = PKCS1_SHA256_ID;
        opts.rsaPssSalt = NULL; /* Random salt. */
        opts.rsaPssSaltLen = SHA256_HASH_SIZE;
        break;
    case sigalg_rsa_pss_pss_sha384:
    case sigalg_rsa_pss_rsae_sha384:
        hashSigAlg = OID_SHA384_RSA_SIG;
        sigAlgOid = OID_RSASSA_PSS;
        opts.rsaPssHashAlg = PKCS1_SHA384_ID;
        opts.rsaPssSalt = NULL; /* Random salt. */
        opts.rsaPssSaltLen = SHA384_HASH_SIZE;
        break;
    case sigalg_rsa_pss_pss_sha512:
    case sigalg_rsa_pss_rsae_sha512:
        hashSigAlg = OID_SHA512_RSA_SIG;
        sigAlgOid = OID_RSASSA_PSS;
        opts.rsaPssHashAlg = PKCS1_SHA512_ID;
        opts.rsaPssSalt = NULL; /* Random salt. */
        opts.rsaPssSaltLen = SHA512_HASH_SIZE;
        break;
# endif /* USE_RSA */
    default:
        psTraceErrr("Unsupported sig alg\n");
        rc = PS_UNSUPPORTED_FAIL;
        goto out_fail;
    }

    if (tls13RequiresPreHash(sigAlg))
    {
        rc = psComputeHashForSig(tbs, tbsLen,
                hashSigAlg,
                hashTbs,
                &hashTbsLen);
        if (rc != PS_SUCCESS)
        {
            goto out_fail;
        }
        needPreHash = PS_TRUE;
#ifdef DEBUG_TLS_1_3_SIG_VER
        psTraceBytes("tls13Sign hashTbs", hashTbs, hashTbsLen);
#endif
    }

    rc = psSign(pool,
            privKey,
            sigAlgOid,
            needPreHash ? hashTbs : tbs,
            needPreHash ? hashTbsLen : tbsLen,
            out,
            outLen,
            &opts);
    if (rc < 0)
    {
        goto out_fail;
    }

#ifdef DEBUG_TLS_1_3_SIG_VER
    psTraceBytes("tls13Sign Signature", *out, *outLen);
#endif
    rc = PS_SUCCESS;

out_fail:
    if (tbs)
    {
        psFree(tbs, pool);
    }
    return rc;
}
/**

   @return PS_SUCCESS when signature was successfully verified;
   PS_VERIFICATION_FAILED is verification failed.
*/
int32_t tls13Verify(psPool_t *pool,
        psPubKey_t *pubKey,
        uint16_t sigAlg,
        unsigned char *signature,
        psSize_t signatureLen,
        const unsigned char trHash[MAX_TLS_1_3_HASH_SIZE],
        psSize_t trHashLen,
        const char *contextString,
        psSize_t contextStringLen)
{
    int32_t rc;
    psBool_t verificationOk = PS_FALSE;
    int32_t cryptoLayerSigAlg;
    unsigned char *tbs;
    psSize_t tbsLen;
    psVerifyOptions_t opts;

    /* Make our reference data. */
    rc = tls13MakeTbs(pool,
            contextString,
            contextStringLen,
            trHash,
            trHashLen,
            &tbs,
            &tbsLen);
    if (rc != PS_SUCCESS)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_SIG_VER
    psTraceBytes("tls13Verify tbs", tbs, tbsLen);
    psTraceBytes("tls13Verify signature", signature, signatureLen);
#endif

    Memset(&opts, 0, sizeof(opts));

    /* Translate TLS 1.3 signature algorithm encoding to what
       our crypto layer uses. */
#  ifdef USE_ECC
    if (sigAlg == sigalg_ecdsa_secp256r1_sha256)
    {
        cryptoLayerSigAlg = OID_SHA256_ECDSA_SIG;
        psAssert(pubKey->key.ecc.curve->curveId == IANA_SECP256R1);
    }
    else if (sigAlg == sigalg_ecdsa_secp384r1_sha384)
    {
        cryptoLayerSigAlg = OID_SHA384_ECDSA_SIG;
        psAssert(pubKey->key.ecc.curve->curveId == IANA_SECP384R1);
    }
    else if (sigAlg == sigalg_ecdsa_secp521r1_sha512)
    {
        cryptoLayerSigAlg = OID_SHA512_ECDSA_SIG;
        psAssert(pubKey->key.ecc.curve->curveId == IANA_SECP521R1);
    }
#  endif
#  ifdef USE_RSA
    else if (sigAlg == sigalg_rsa_pss_pss_sha256 ||
            sigAlg == sigalg_rsa_pss_rsae_sha256)
    {
        cryptoLayerSigAlg = OID_SHA256_RSA_SIG;
        opts.rsaPssHashAlg = PKCS1_SHA256_ID;
        opts.rsaPssSaltLen = SHA256_HASH_SIZE;
        opts.useRsaPss = PS_TRUE;
    }
    else if (sigAlg == sigalg_rsa_pss_pss_sha384 ||
            sigAlg == sigalg_rsa_pss_rsae_sha384)
    {
        cryptoLayerSigAlg = OID_SHA384_RSA_SIG;
        opts.rsaPssHashAlg = PKCS1_SHA384_ID;
        opts.rsaPssSaltLen = SHA384_HASH_SIZE;
        opts.useRsaPss = PS_TRUE;
    }
    else if (sigAlg == sigalg_rsa_pss_pss_sha512 ||
            sigAlg == sigalg_rsa_pss_rsae_sha512)
    {
        cryptoLayerSigAlg = OID_SHA512_RSA_SIG;
        opts.rsaPssHashAlg = PKCS1_SHA512_ID;
        opts.rsaPssSaltLen = SHA512_HASH_SIZE;
        opts.useRsaPss = PS_TRUE;
    }
#  endif
#ifdef USE_ED25519
    else if (sigAlg == sigalg_ed25519)
    {
        cryptoLayerSigAlg = OID_ED25519_KEY_ALG;
        psAssert(pubKey->type == PS_ED25519);
    }
#endif
    else
    {
        psTraceIntInfo("Unsupported sig alg in tls13Verify: %u\n",
                sigAlg);
        psFree(tbs, pool);
        return PS_UNSUPPORTED_FAIL;
    }

    rc = psVerify(pool,
            tbs,
            tbsLen,
            signature,
            signatureLen,
            pubKey,
            cryptoLayerSigAlg,
            &verificationOk,
            &opts);
    if (rc < 0)
    {
        psFree(tbs, pool);
        return rc;
    }
    psFree(tbs, pool);

    if (verificationOk)
    {
        return PS_SUCCESS;
    }
    else
    {
        return PS_VERIFICATION_FAILED;
    }
}

# endif /* USE_IDENTITY_CERTIFICATES */

# ifdef USE_RSA
psBool_t tls13IsRsaPssSigAlg(uint16_t alg)
{
    switch (alg)
    {
    case sigalg_rsa_pss_rsae_sha256:
    case sigalg_rsa_pss_rsae_sha384:
    case sigalg_rsa_pss_rsae_sha512:
    case sigalg_rsa_pss_pss_sha256:
    case sigalg_rsa_pss_pss_sha384:
    case sigalg_rsa_pss_pss_sha512:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }
}

psBool_t tls13IsRsaSigAlg(uint16_t alg)
{
    switch (alg)
    {
    case sigalg_rsa_pkcs1_sha256:
    case sigalg_rsa_pkcs1_sha384:
    case sigalg_rsa_pkcs1_sha512:
    case sigalg_rsa_pkcs1_sha1:
        return PS_TRUE;
    }

    return tls13IsRsaPssSigAlg(alg);
}
# endif
psBool_t tls13IsEcdsaSigAlg(uint16_t alg)
{
    switch (alg)
    {
    case sigalg_ecdsa_secp256r1_sha256:
    case sigalg_ecdsa_secp384r1_sha384:
    case sigalg_ecdsa_secp521r1_sha512:
    case sigalg_ecdsa_sha1:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }
}

psBool_t tls13IsInsecureSigAlg(uint16_t alg)
{
    switch (alg)
    {
    case sigalg_rsa_pkcs1_sha1:
    case sigalg_ecdsa_sha1:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }
}

psBool_t tls13RequiresPreHash(uint16_t alg)
{
    if (alg == sigalg_ed25519
        || alg == sigalg_ed448)
    {
        return PS_FALSE;
    }

# ifdef USE_RSA
    else if (tls13IsRsaPssSigAlg(alg))
    {
#  ifdef USE_CL_RSA
        /* Crypto-cl cannot sign pre-hashed data with PSS.
           So we shall sign the original message instead. */
        return PS_FALSE;
#  else
        return PS_TRUE;
#  endif /* USE_CL_RSA */
    }
# endif /* USE_RSA */
    else
    {
        return PS_TRUE;
    }
}
#endif
/* end of file tls13SigVer.c */
