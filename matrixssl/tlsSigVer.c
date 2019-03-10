/**
 *      @file    tlsSigVer.c
 *      @version $Format:%h%d$
 *
 *      Functions for signature generation and verification for TLS 1.2
 *      and below.
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

#include "matrixsslImpl.h"

# ifndef USE_ONLY_PSK_CIPHER_SUITE

uint32_t getDefaultSkeHashSize(ssl_t *ssl)
{
    uint32_t hashSize;

    hashSize = MD5SHA1_HASH_SIZE; /* Default for (D)TLS <1.2. */
#  ifdef USE_ECC_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA)
    {
        /* RFC 4492: SHA-1 is the default. */
        hashSize = SHA1_HASH_SIZE;
    }
#  endif /* USE_ECC_CIPHER_SUITE */

    return hashSize;
}

int32_t computeSkeHash(ssl_t *ssl,
        psDigestContext_t *digestCtx,
        uint32_t hashSize,
        const unsigned char *tbsStart, /* Start of ServerParams. */
        const unsigned char *tbsStop,
        unsigned char *hsMsgHash)
{
    /*
      In both TLS 1.2 and below, the SKE signature is computed
      over the hash of:
      ClientHello.random || ServerHello.random || ServerParams

      Unfortunately, we cannot use psComputeHashForSig, since
      it only supports single part operation - we would have to
      concatenate the above data into a single buffer, something
      which we are not willing to do here.
    */
    switch (hashSize)
    {
# ifdef USE_MD5SHA1
    case MD5SHA1_HASH_SIZE:
        psMd5Sha1PreInit(&digestCtx->md5sha1);
        psMd5Sha1Init(&digestCtx->md5sha1);
        psMd5Sha1Update(&digestCtx->md5sha1, ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE);
        psMd5Sha1Update(&digestCtx->md5sha1, ssl->sec.serverRandom,
                SSL_HS_RANDOM_SIZE);
        psMd5Sha1Update(&digestCtx->md5sha1, tbsStart,
                (uint32) (tbsStop - tbsStart));
        psMd5Sha1Final(&digestCtx->md5sha1, hsMsgHash);
        break;
# endif /* USE_MD5SHA1 */
# ifdef USE_SHA1
    case SHA1_HASH_SIZE:
        psSha1PreInit(&digestCtx->sha1);
        psSha1Init(&digestCtx->sha1);
        psSha1Update(&digestCtx->sha1, ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE);
        psSha1Update(&digestCtx->sha1, ssl->sec.serverRandom,
                SSL_HS_RANDOM_SIZE);
        psSha1Update(&digestCtx->sha1, tbsStart,
                (uint32) (tbsStop - tbsStart));
        psSha1Final(&digestCtx->sha1, hsMsgHash);
        break;
# endif /* USE_SHA1 */
# ifdef USE_TLS_1_2
    case SHA256_HASH_SIZE:
        psSha256PreInit(&digestCtx->sha256);
        psSha256Init(&digestCtx->sha256);
        psSha256Update(&digestCtx->sha256, ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE);
        psSha256Update(&digestCtx->sha256, ssl->sec.serverRandom,
                        SSL_HS_RANDOM_SIZE);
        psSha256Update(&digestCtx->sha256, tbsStart,
                (uint32) (tbsStop - tbsStart));
        psSha256Final(&digestCtx->sha256, hsMsgHash);
        break;
#  ifdef USE_SHA384
    case SHA384_HASH_SIZE:
        psSha384PreInit(&digestCtx->sha384);
        psSha384Init(&digestCtx->sha384);
        psSha384Update(&digestCtx->sha384, ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE);
        psSha384Update(&digestCtx->sha384, ssl->sec.serverRandom,
                SSL_HS_RANDOM_SIZE);
        psSha384Update(&digestCtx->sha384, tbsStart,
                (uint32) (tbsStop - tbsStart));
        psSha384Final(&digestCtx->sha384, hsMsgHash);
        break;
#  endif /* USE_SHA384 */
#  ifdef USE_SHA512
    case SHA512_HASH_SIZE:
        psSha512PreInit(&digestCtx->sha512);
        psSha512Init(&digestCtx->sha512);
        psSha512Update(&digestCtx->sha512, ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE);
        psSha512Update(&digestCtx->sha512, ssl->sec.serverRandom,
                SSL_HS_RANDOM_SIZE);
        psSha512Update(&digestCtx->sha512, tbsStart,
                (uint32) (tbsStop - tbsStart));
        psSha512Final(&digestCtx->sha512, hsMsgHash);
        break;
#  endif /* USE_SHA512 */
# endif /* USE_TLS_1_2 */
    default:
        psTraceErrr("Unsupported hash algorithm in SKE\n");
        psTraceIntInfo("Unsupported hash size: %u\n", hashSize);
        return PS_UNSUPPORTED_FAIL;
    }

    return PS_SUCCESS;
}

static inline
int32_t chooseSkeSigAlgTls12(ssl_t *ssl, sslIdentity_t *id)
{
    int32_t sigAlg;

    sigAlg = chooseSigAlg(id->cert, &id->privKey, ssl->hashSigAlg);
    if (sigAlg == PS_UNSUPPORTED_FAIL)
    {
        psTraceInfo("Unavailable sigAlgorithm for SKE write\n");
        return PS_UNSUPPORTED_FAIL;
    }
    return sigAlg;
}

static inline
int32_t chooseSkeSigAlgTls11(ssl_t *ssl, sslIdentity_t *id)
{
    if (id->privKey.type == PS_RSA)
    {
        return 0; /* MD5SHA1-RSA does not have an OID, so use 0. */
    }
    else
    {
        /* ECDSA uses SHA-1 by default. */
        return OID_SHA1_ECDSA_SIG;
    }
}

int32_t chooseSkeSigAlg(ssl_t *ssl, sslIdentity_t *id)
{
# ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        return chooseSkeSigAlgTls12(ssl, id);
    }
# endif

    return chooseSkeSigAlgTls11(ssl, id);
}

/** Prepare for a postponed SKE signing operation.

    @precond The function is only called when the SKE message needs
    a signature, i.e. only when using non-PSK (EC)DHE ciphersuites.
*/
psRes_t tlsPrepareSkeSignature(ssl_t *ssl,
        int32_t skeSigAlg,
        unsigned char *tbsStart,
        unsigned char *c)
{
    sslIdentity_t *chosen = ssl->chosenIdentity;
    unsigned char *orig = c;
    psDigestContext_t digestCtx;
    unsigned char *hsMsgHash, *tbsStop;
    int32_t rc;
    void *pkiData = ssl->userPtr;
    pkaAfter_t *pkaAfter;
    psSize_t hashSize;
    unsigned char sigAlgId[2];
    uint16_t pkaType = 0;

    /*
        ServerDHParams params;
          digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            ServerDHParams params;
          } signed_params;

      How we shall encode the signature (a digitally-signed struct):
         TLS 1.2 and below:
          struct {
            SignatureAndHashAlgorithm algorithm;
            opaque signature<0..2^16-1>;
          } DigitallySigned;
         TLS 1.1 and below:
          opaque vector <0..2^16-1>
    */

    /* [tbsStart, tbsStop] == signed_params. */
    tbsStop = c;

    /* Reserve space for the hash of signed_params. */
    hsMsgHash = psMalloc(ssl->hsPool, SHA512_HASH_SIZE);
    if (hsMsgHash == NULL)
    {
        return PS_MEM_FAIL;
    }

    hashSize = getDefaultSkeHashSize(ssl);

# ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        rc = getSignatureAndHashAlgorithmEncoding(skeSigAlg,
                &sigAlgId[0],
                &sigAlgId[1],
                &hashSize);
        if (rc < 0)
        {
            psFree(hsMsgHash, ssl->hsPool);
            return rc;
        }
        *c++ = sigAlgId[0];
        *c++ = sigAlgId[1];
    }
# endif

    /* Compute the hash. */
    rc = computeSkeHash(ssl,
            &digestCtx,
            hashSize,
            tbsStart,
            tbsStop,
            hsMsgHash);
    if (rc < 0)
    {
        psFree(hsMsgHash, ssl->hsPool);
        return rc;
    }

    /* Compute the signature lengths and write the signature length
       octets. */

#ifdef USE_RSA_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA)
    {
        /* Signature size == RSA private key modulus size. */
        *c = (chosen->privKey.keysize & 0xFF00) >> 8; c++;
        *c = chosen->privKey.keysize & 0xFF; c++;

        pkaType = PKA_AFTER_RSA_SIG_GEN;
#    ifdef USE_TLS_1_2
        if (NGTD_VER(ssl, v_tls_with_pkcs15_auth))
        {
            /* The protocol uses PKCS #1.5 signatures. */
            pkaType = PKA_AFTER_RSA_SIG_GEN_ELEMENT;
        }
#    endif /* USE_TLS_1_2 */
    }
#endif /* USE_RSA_CIPHER_SUITE */

# ifdef USE_ECC_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA)
    {
        /*
          For ECDSA, the signature length octets are written later by
          psEccDsaSign in nowDoSkePka. Not being consistent is bad. But,
          because of the "negative ECDSA" case, we do not completely
          know the signature length in advance.
        */
        pkaType = PKA_AFTER_ECDSA_SIG_GEN;
    }
# endif /* USE_ECC_CIPHER_SUITE */

# ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any) && (ssl->retransmit == 1))
    {
        /* It is not optimal to have run through the above digest updates
           again on a retransmit just to free the hash here but the
           saved message is ONLY the signature portion done in nowDoSke
           so the few hashSigAlg bytes and keysize done above during the
           hash are important to rewrite */
        psFree(hsMsgHash, ssl->hsPool);
        Memcpy(c, ssl->ckeMsg, ssl->ckeSize);
        c += ssl->ckeSize;
        return (c - orig);
    }
# endif /* USE_DTLS */

    pkaAfter = getPkaAfter(ssl);
    if (pkaAfter == NULL)
    {
        psTraceInfo("getPkaAfter error\n");
        psFree(hsMsgHash, ssl->hsPool);
        return PS_PLATFORM_FAIL;
    }
    pkaAfter->inbuf = hsMsgHash;
    pkaAfter->outbuf = c;
    pkaAfter->data = pkiData;
    pkaAfter->inlen = hashSize;
    pkaAfter->type = pkaType;

    /* Advance write pointer by the predicted size of the signature. */

# ifdef USE_RSA_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA)
    {
        c += chosen->privKey.keysize;
    }
# endif

# ifdef USE_ECC_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA)
    {
        rc = chosen->privKey.keysize + 8;
        /* NEGATIVE ECDSA - Adding spot for ONE 0x0 byte in ECDSA so we'll
           be right 50% of the time... 521 curve doesn't need */
        if (chosen->privKey.keysize != 132)
        {
            rc += 1;
        }
        /* Above we added in the 8 bytes of overhead (2 sigLen, 1 SEQ,
           1 len (possibly 2!), 1 INT, 1 rLen, 1 INT, 1 sLen) and now
           subtract the first 3 bytes to see if the 1 len needs to be 2 */
        if (rc - 3 >= 128)
        {
            rc++;
        }
        pkaAfter->user = rc; /* outlen for later */
        c += rc;
    }
# endif

    /* Return the predicted size of the digitally-signed struct. */
    return (c - orig);
}

static
psPool_t *getTmpPkiPool(ssl_t *ssl, pkaAfter_t *pka)
{
    return NULL;
}

psRes_t tlsMakeSkeSignature(ssl_t *ssl,
        pkaAfter_t *pka,
        psBuf_t *out)
{
    int32_t rc;
    psPool_t *pkiPool = getTmpPkiPool(ssl, pka);
    int32_t sigAlg = OID_RSA_TLS_SIG_ALG;
    sslIdentity_t *chosen = ssl->chosenIdentity;
    psPubKey_t *privKey = &chosen->privKey;
    unsigned char *sigBuf = pka->outbuf;
    psSize_t sigLen;
    psSignOpts_t opts = {0};
    /* New temp location for ECDSA sig which can be one len byte different
       than what we originally calculated (pka->user is holding) */
    unsigned char *tmpEcdsa = NULL;

    /* Prepare for the call to psSign. */
    switch (pka->type)
    {
# ifdef USE_RSA_CIPHER_SUITE
    case PKA_AFTER_RSA_SIG_GEN_ELEMENT:
        sigAlg = OID_RSA_PKCS15_SIG_ALG;
        sigLen = privKey->keysize;
        break;

    case PKA_AFTER_RSA_SIG_GEN:
        sigAlg = OID_RSA_TLS_SIG_ALG;
        sigLen = privKey->keysize;
        break;
# endif /* USE_RSA_CIPHER_SUITE */

# ifdef USE_ECC_CIPHER_SUITE
    case PKA_AFTER_ECDSA_SIG_GEN:
        sigAlg = OID_ECDSA_TLS_SIG_ALG;
        /* pka->user is the predicted ECDSA signature size. We predicted
           that one of the INTEGERs has a leading 0x00 octet, but there
           may actually be 0 to 2 extra octets. So allocate 1 larger
           than predicted. */
        tmpEcdsa = psMalloc(ssl->hsPool, pka->user + 1);
        if (tmpEcdsa == NULL)
        {
            return PS_MEM_FAIL;
        }
#    ifdef USE_DTLS
        ssl->ecdsaSizeChange = 0;
#    endif
        sigBuf = tmpEcdsa;
        /* We did not write the signature vector length octets earlier,
           because we cannot completely predict the signature legnth.
           Let psSign do this. */
        opts.flags |= PS_SIGN_OPTS_ECDSA_INCLUDE_SIZE;
        break;
# endif /* USE_ECC_CIPHER_SUITE */

    default:
        psTraceErrr("Unsupported type of PKA operation\n");
        return PS_UNSUPPORTED_FAIL;
    }
    opts.userData = pka->data;
    opts.flags |= PS_SIGN_OPTS_USE_PREALLOCATED_OUTBUF;

    /* Compute the signature. */
    rc = psSignHash(pkiPool,
            privKey,
            sigAlg,
            pka->inbuf,
            pka->inlen,
            &sigBuf,
            &sigLen,
            &opts);
    if (rc == PS_PENDING)
    {
        /* Async operation launched, but not complete. */
        /* If the result is going directly inline to the output
           buffer we unflag 'type' so this function isn't called
           again on the way back around. Also, we can safely
           free inbuf because it has been copied out */
        psFree(pka->inbuf, ssl->hsPool); pka->inbuf = NULL;
        pka->type = 0;
        psFree(tmpEcdsa, ssl->hsPool);
        return rc;
    }
    else if (rc < 0)
    {
        psFree(tmpEcdsa, ssl->hsPool);
        psTraceErrr("SKE signature generation failed\n");
        psTraceIntInfo("Signature return code: %d\n", rc);
        return MATRIXSSL_ERROR;
    }

    /* Signature is ready, either in tmpEcdsa or in pka->outbuf. */

    /* If the signature size is different than predicted, we need to
       tweak the previously encoded flight to account for this.
       This is a huge mess, but cannot be avoided with the current
       approach, where the entire flight is encoded before public
       key operations are used to fill the signature spots. */
# ifdef USE_ECC_CIPHER_SUITE
    if (pka->type == PKA_AFTER_ECDSA_SIG_GEN)
    {
        if (sigLen != pka->user)
        {
            /* Confirmed ECDSA is not default size */
            psTraceInfo("Need accountForEcdsaSizeChange\n");
            rc = accountForEcdsaSizeChange(ssl,
                    pka,
                    sigLen,
                    tmpEcdsa,
                    out,
                    SSL_HS_SERVER_KEY_EXCHANGE);
            if (rc < 0)
            {
                clearPkaAfter(ssl);
                psFree(tmpEcdsa, ssl->hsPool);
                return MATRIXSSL_ERROR;
            }
        }
        else
        {
            Memcpy(pka->outbuf, tmpEcdsa, pka->user);
        }
        psFree(tmpEcdsa, ssl->hsPool);
    }
#   endif /* USE_ECC_CIPHER_SUITE */

    /* Store the signature in case of a message retransmit in DTLS. */
# ifdef USE_DTLS
    if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 0))
    {
        /* Using existing ckeMsg and ckeSize that clients are using but
           this should be totally fine on the server side because it is
           freed at FINISHED parse */
        ssl->ckeSize = sigLen;
        ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize);
        if (ssl->ckeMsg == NULL)
        {
            psTraceInfo("Memory allocation error ckeMsg\n");
            return PS_MEM_FAIL;
        }
        Memcpy(ssl->ckeMsg, pka->outbuf, ssl->ckeSize);
    }
# endif /* USE_DTLS */

    clearPkaAfter(ssl);

    return rc;
}

psBool_t tlsIsSupportedRsaSigAlg(int32_t alg)
{
    switch (alg)
    {
    case OID_RSA_TLS_SIG_ALG:
    case sigalg_rsa_pkcs1_sha1:
    case sigalg_rsa_pkcs1_sha256:
    case sigalg_rsa_pkcs1_sha384:
    case sigalg_rsa_pkcs1_sha512:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }

    return PS_FALSE;
}

psBool_t tlsIsSupportedEcdsaSigAlg(int32_t alg)
{
    switch (alg)
    {
    case OID_ECDSA_TLS_SIG_ALG:
    case sigalg_ecdsa_sha1:
    case sigalg_ecdsa_secp256r1_sha256:
    case sigalg_ecdsa_secp384r1_sha384:
    case sigalg_ecdsa_secp521r1_sha512:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }
}

psSize_t tlsSigAlgToHashLen(uint16_t alg)
{
    /* Note: We are in TLS 1.2 context here. The sigalg_* names below
       are from TLS 1.3, but they are compatible with the TLS 1.2
       ones. Only difference is that the TLS 1.2 ECDSA sig algs
       do not specify the curve. So sigalg_ecdsa_secp256r1_sha256
       just means ECDSA-SHA256 here, for example. */
    switch (alg)
    {
    case sigalg_rsa_pkcs1_sha1:
    case sigalg_ecdsa_sha1:
        return SHA1_HASH_SIZE;
    case sigalg_rsa_pkcs1_sha256:
    case sigalg_ecdsa_secp256r1_sha256:
        return SHA256_HASH_SIZE;
    case sigalg_rsa_pkcs1_sha384:
    case sigalg_ecdsa_secp384r1_sha384:
        return SHA384_HASH_SIZE;
    case sigalg_rsa_pkcs1_sha512:
    case sigalg_ecdsa_secp521r1_sha512:
        return SHA512_HASH_SIZE;
    default:
        return PS_UNSUPPORTED_FAIL;
    }
}

int32_t tlsSigAlgToMatrix(uint16_t alg)
{
    switch (alg)
    {
    case sigalg_rsa_pkcs1_sha1:
        return OID_SHA1_RSA_SIG;
    case sigalg_rsa_pkcs1_sha256:
        return OID_SHA256_RSA_SIG;
    case sigalg_rsa_pkcs1_sha384:
        return OID_SHA384_RSA_SIG;
    case sigalg_rsa_pkcs1_sha512:
        return OID_SHA512_RSA_SIG;
    case sigalg_ecdsa_sha1:
        return OID_SHA1_ECDSA_SIG;
    case sigalg_ecdsa_secp256r1_sha256:
        return OID_SHA256_ECDSA_SIG;
    case sigalg_ecdsa_secp384r1_sha384:
        return OID_SHA384_ECDSA_SIG;
    case sigalg_ecdsa_secp521r1_sha512:
        return OID_SHA512_ECDSA_SIG;
    default:
        return PS_UNSUPPORTED_FAIL;
    }
}

int32_t tlsVerify(ssl_t *ssl,
        const unsigned char *tbs,
        psSizeL_t tbsLen,
        const unsigned char *c,
        const unsigned char *end,
        psPubKey_t *pubKey,
        psVerifyOptions_t *opts)
{
    int32_t rc;
    uint16_t sigAlgTls = 0;
    int32_t matrixSigAlg;
    psSize_t sigLen;
    psDigestContext_t digestCtx;
    psResSize_t hashLen = 0;
    unsigned char hashBuf[SHA512_HASH_SIZE];
    psVerifyOptions_t defaultOpts = {0};
    psBool_t verifyResult;
    const unsigned char *orig_c = c;
    psBool_t useRsa = PS_FALSE;;

    if (opts == NULL)
    {
        opts = &defaultOpts;
    }
    if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA)
    {
        useRsa = PS_TRUE; /* Default for TLS 1.1 and below. */
    }

    /*
      (D)TLS 1.2:
        struct {
          SignatureAndHashAlgorithm algorithm;
          opaque signature<0..2^16-1>;
        } DigitallySigned;

      TLS 1.1 and below:
        opaque vector <0..2^16-1>
    */

# ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_signature_algorithms))
    {
        if (end - c < 2)
        {
            goto out_decode_error;
        }
        sigAlgTls = *c << 8; c++;
        sigAlgTls += *c; c++;
        if (tlsIsSupportedRsaSigAlg(sigAlgTls))
        {
            useRsa = PS_TRUE;
        }
        /* Note: this a TLS sig alg ID. */
        hashLen = tlsSigAlgToHashLen(sigAlgTls);
        if (hashLen <= 0)
        {
            goto out_decode_error;
        }
    }
# endif /* USE_TLS_1_2 */

    /* Sig alg must match the ciphersuite auth alg. */
    if (!useRsa && (ssl->flags & SSL_FLAGS_DHE_WITH_RSA))
    {
        psTraceErrr("Peer used RSA signature for non-RSA suite\n");
        goto out_decode_error;
    }
    if (useRsa && (ssl->flags & SSL_FLAGS_DHE_WITH_DSA))
    {
        psTraceErrr("Peer used ECDSA signature for non-ECDSA suite\n");
        goto out_decode_error;
    }


# ifdef USE_SEC_CONFIG
    /* Ask the security callback whether the verify operation
       with this sig alg and key is allowed. */
    {
        psSecOperation_t secOp;
        psSizeL_t secOpBits;

        if (useRsa)
        {
            secOp = secop_rsa_verify;
            secOpBits = pubKey->keysize * 8;
        }
        else
        {
            secOp = secop_ecdsa_verify;
            secOpBits = pubKey->key.ecc.curve->size * 8;
        }

        rc = matrixSslCallSecurityCallback(ssl, secOp, secOpBits, NULL);
        if (rc < 0)
        {
            psTraceErrr("Operation forbidden by security callback\n");
            ssl->err = SSL_ALERT_INSUFFICIENT_SECURITY;
            return rc;
        }
    }
# endif /* USE_SEC_CONFIG */

    /* Parse signature vector length. */
    if (end - c < 2)
    {
        psTraceErrr("Could not decode TLS signature\n");
        goto out_decode_error;
    }
    sigLen = *c << 8; c++;
    sigLen |= *c; c++;

    /* Sanity check. */
    if (sigLen > (end - c))
    {
        psTraceErrr("Sig len sanity check failed\n");
        goto out_decode_error;
    }

    /* Now compute the reference hash. */

    if (hashLen == 0)
    {
        hashLen = getDefaultSkeHashSize(ssl);
    }
    rc = computeSkeHash(ssl,
            &digestCtx,
            hashLen,
            tbs,
            tbs + tbsLen,
            hashBuf);
    if (rc < 0)
    {
        goto out_illegal_parameter;
    }

    /* Now verify the signature. */

    if (NGTD_VER(ssl, v_tls_with_pkcs15_auth))
    {
        opts->msgIsDigestInfo = PS_TRUE;
    }
    if (sigAlgTls == 0)
    {
        matrixSigAlg = useRsa ? OID_RSA_TLS_SIG_ALG : OID_SHA1_ECDSA_SIG;
    }
    else
    {
        matrixSigAlg = tlsSigAlgToMatrix(sigAlgTls);
    }

    rc = psVerifySig(ssl->hsPool,
            hashBuf,
            hashLen,
            c,
            sigLen,
            pubKey,
            matrixSigAlg,
            &verifyResult,
            opts);
    if (rc < 0 || verifyResult != PS_TRUE)
    {
        psTraceErrr("Can't verify serverKeyExchange sig\n");
        goto out_decrypt_error;
    }

    c += sigLen;

    psAssert(c > orig_c);
    psAssert(c <= end);

    return (c - orig_c);

out_illegal_parameter:
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
out_decode_error:
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_decrypt_error:
    ssl->err = SSL_ALERT_DECRYPT_ERROR;
    return MATRIXSSL_ERROR;
}

#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)

/**
  Return PS_TRUE if sigAlg is in peerSigAlgs, PS_FALSE otherwise.

  peerSigAlgs should be the a set of masks we created after
  parsing the peer's supported_signature_algorithms list
  in ClientHello or CertificateRequest.
*/
psBool_t peerSupportsSigAlg(int32_t sigAlg,
                            uint16_t peerSigAlgs
                            /* , psSize_t peerSigAlgsLen) */
                            )
{
    uint16_t yes;

    if (sigAlg == OID_MD5_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_MD5_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA1_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA1_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA256_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA256_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA384_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA384_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA512_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA512_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA1_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA1_ECDSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA256_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA256_ECDSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA384_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA384_ECDSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA512_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA512_ECDSA_MASK) != 0);
    }
    else
    {
        return PS_FALSE; /* Unknown/unsupported sig alg. */
    }

    if (yes)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

/**
  Return PS_TRUE when we support sigAlg for signature generation,
  PS_FALSE otherwise.

  Compile-time switches as well as FIPS or non-FIPS mode is taken
  into account.

  @param[in] sigAlg The signature algorithm whose support is to
  be checked.
  @param[in] pubKeyAlgorithm The public key algorithm of our
  private/public key pair (OID_RSA_KEY_ALG or OID_ECDSA_KEY_ALG.)
*/
psBool_t weSupportSigAlg(int32_t sigAlg,
                         int32_t pubKeyAlgorithm)
{
    uint16_t we_support = 0;
    uint16_t is_non_fips = 0; /* 1 if not allowed in FIPS mode for
                                 signature generation. */

    PS_VARIABLE_SET_BUT_UNUSED(is_non_fips);

#ifndef USE_RSA
    if (pubKeyAlgorithm == OID_RSA_KEY_ALG)
    {
        return PS_FALSE;
    }
#endif
#ifndef USE_ECC
    if (pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        return PS_FALSE;
    }
#endif

    if (pubKeyAlgorithm == OID_RSA_KEY_ALG)
    {
        if (sigAlg == OID_MD2_RSA_SIG || sigAlg == OID_MD5_RSA_SIG)
        {
            /* No support for generating RSA-MD2 or RSA-MD5 signatures. */
            is_non_fips = 1;
            we_support = 0;
        }
        else if (sigAlg == OID_SHA1_RSA_SIG)
        {
            is_non_fips = 1;
#ifdef USE_SHA1
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA256_RSA_SIG)
        {
#ifdef USE_SHA256
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA384_RSA_SIG)
        {
#ifdef USE_SHA384
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA512_RSA_SIG)
        {
#ifdef USE_SHA512
            we_support = 1;
#endif
        }
        else
        {
            /* Our key does not support this algorithm. */
            return PS_FALSE;
        }
    }
    else if (pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        if (sigAlg == OID_SHA1_ECDSA_SIG)
        {
#ifdef USE_SHA1
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA256_ECDSA_SIG)
        {
#ifdef USE_SHA256
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA384_ECDSA_SIG)
        {
#ifdef USE_SHA384
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA512_ECDSA_SIG)
        {
#ifdef USE_SHA512
            we_support = 1;
#endif
        }
        else
        {
            /* Our key does not support this algorithm. */
            return PS_FALSE;
        }
    }
    else
    {
        return PS_FALSE; /* Unsupported public key alg, e.g. DSA. */
    }

    /* The basic capability is there. Now do some further checks
       if needed. */

    if (we_support)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

/** Return PS_TRUE when:
   - We support sigAlg for signature generation.
   - sigAlg is in peerSigAlgs.

   @param[in] sigAlg The signature algorithm whose support to check.
   @param[in] pubKeyAlgorithm The public key algorithm of our key.
   @param[in] peerSigAlgs The masks of the sigAlgs supported by the
     peer. This should be the one parsed from the peer's
     supported_signature_algorithms list in CertificateVerify or
     CertificateRequest. In this case, sigAlg \in peerSigAlgs
     means that the peer supports sigAlg for signature verification.
*/
psBool_t canUseSigAlg(int32_t sigAlg,
        int32_t pubKeyAlgorithm,
        uint16_t peerSigAlgs)
{
    return (weSupportSigAlg(sigAlg, pubKeyAlgorithm) &&
            peerSupportsSigAlg(sigAlg, peerSigAlgs));
}

/**
  Upgrade to a more secure signature algorithm. If the algorithm
  is already the strongest possible for the key type (i.e.
  RSA-SHA-512 or ECDSA-SHA-512) change to the most popular
  one (i.e. RSA-SHA-256 or ECDSA-SHA-256).
*/
int32_t upgradeSigAlg(int32_t sigAlg, int32_t pubKeyAlgorithm)
{
    /*
      RSA:
      MD2 -> SHA256
      MD5 -> SHA256
      SHA1 -> SHA256
      SHA256 -> SHA384
      SHA384 -> SHA512
      SHA512 -> SHA256
    */
    if (pubKeyAlgorithm == OID_RSA_KEY_ALG)
    {
        if (sigAlg == OID_MD2_RSA_SIG ||
                sigAlg == OID_MD5_RSA_SIG ||
                sigAlg == OID_SHA1_RSA_SIG)
        {
            return OID_SHA256_RSA_SIG;
        }
        else if (sigAlg == OID_SHA256_RSA_SIG)
        {
            return OID_SHA384_RSA_SIG;
        }
        else if (sigAlg == OID_SHA384_RSA_SIG)
        {
            return OID_SHA512_RSA_SIG;
        }
        else if (sigAlg == OID_SHA512_RSA_SIG)
        {
            return OID_SHA256_RSA_SIG;
        }
        else
        {
            return PS_UNSUPPORTED_FAIL;
        }
    }
    /*
      ECDSA:
      SHA1 -> SHA256
      SHA256 -> SHA384
      SHA384 -> SHA512
      SHA512 -> SHA256
    */
    else if (pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        if (sigAlg == OID_SHA1_ECDSA_SIG)
        {
            return OID_SHA256_ECDSA_SIG;
        }
        else if (sigAlg == OID_SHA256_ECDSA_SIG)
        {
            return OID_SHA384_ECDSA_SIG;
        }
        else if (sigAlg == OID_SHA384_ECDSA_SIG)
        {
            return OID_SHA512_ECDSA_SIG;
        }
        else if (sigAlg == OID_SHA512_ECDSA_SIG)
        {
            return OID_SHA256_ECDSA_SIG;
        }
        else
        {
            return PS_UNSUPPORTED_FAIL;
        }
    }
    else
    {
        return PS_UNSUPPORTED_FAIL;
    }
}

static
int32_t sigAlgRsaToEcdsa(int32_t sigAlg)
{
    if (sigAlg == OID_SHA1_RSA_SIG)
    {
        return OID_SHA1_ECDSA_SIG;
    }
    if (sigAlg == OID_SHA256_RSA_SIG)
    {
        return OID_SHA256_ECDSA_SIG;
    }
    if (sigAlg == OID_SHA384_RSA_SIG)
    {
        return OID_SHA384_ECDSA_SIG;
    }
    if (sigAlg == OID_SHA512_RSA_SIG)
    {
        return OID_SHA512_ECDSA_SIG;
    }
    else
    {
        return OID_SHA256_ECDSA_SIG;
    }
}

static
int32_t ecdsaToRsa(int32_t sigAlg)
{
    if (sigAlg == OID_SHA1_ECDSA_SIG)
    {
        return OID_SHA1_RSA_SIG;
    }
    if (sigAlg == OID_SHA256_ECDSA_SIG)
    {
        return OID_SHA256_RSA_SIG;
    }
    if (sigAlg == OID_SHA384_ECDSA_SIG)
    {
        return OID_SHA384_RSA_SIG;
    }
    if (sigAlg == OID_SHA512_ECDSA_SIG)
    {
        return OID_SHA512_RSA_SIG;
    }
    else
    {
        return OID_SHA256_RSA_SIG;
    }
}

/**
  Determine signature algorithm to use in the CertificateVerify or
  ServerKeyExchange handshake messages in TLS 1.2.

  TODO: add support for RSASSA-PSS.

  This function should only be called when using TLS 1.2.

  @param[in] certSigAlg The signature algorithm with which our
  certificate was signed.
  @param[in] keySize The size of our private key in bytes. For RSA,
  this is modulus; for ECDSA, this is the curve size.
  @param[in] pubKeyAlgorithm The public key algorithm to use for
  authentication. This should the same algorithm our public/private key
  pair is meant for. Must be either OID_RSA_KEY_ALG or
  OID_ECDSA_KEY_ALG.
  @param[in] peerSigAlg The list of signature algorithm masks
  the peer supports (e.g. HASH_SIG_SHA*_RSA_MASK). This should
  be the list created during parsing of the ClientHello or
  CertificateRequest message.
  @return The signature algorithm to use.
*/
int32_t chooseSigAlgInt(int32_t certSigAlg,
        psSize_t keySize,
        int32_t keyAlgorithm,
        uint16_t peerSigAlgs)
{
    int32 a = certSigAlg;
    psResSize_t hashLen;

#ifndef USE_RSA
    if (keyAlgorithm == OID_RSA_KEY_ALG)
    {
        return PS_UNSUPPORTED_FAIL;
    }
#endif
#ifndef USE_ECC
    if (keyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        return PS_UNSUPPORTED_FAIL;
    }
#endif

    /*
      We are going to use certSigAlg as the basis of our choice.
      This is because the SSL layer must ensure anyway that the peer
      supports this algorithm.
    */
    if (keyAlgorithm == OID_RSA_KEY_ALG)
    {
        if (certSigAlg == OID_SHA1_ECDSA_SIG ||
                certSigAlg == OID_SHA256_ECDSA_SIG ||
                certSigAlg == OID_SHA384_ECDSA_SIG ||
                certSigAlg == OID_SHA512_ECDSA_SIG)
        {
            /* Pubkey is RSA, but cert is signed with ECDSA.
               Convert certSigAlg to corresponding RSA alg. */
            a = ecdsaToRsa(certSigAlg);
        }
    }
    else if (keyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        if (certSigAlg != OID_SHA1_ECDSA_SIG &&
                certSigAlg != OID_SHA256_ECDSA_SIG &&
                certSigAlg != OID_SHA384_ECDSA_SIG &&
                certSigAlg != OID_SHA512_ECDSA_SIG)
        {
            /* Pubkey is ECDSA, but cert is signed with RSA.
               Convert to corresponding ECDSA alg. */
            a = sigAlgRsaToEcdsa(certSigAlg);
        }
    }

    hashLen = psSigAlgToHashLen(a);
    if (hashLen < 0)
    { /* unknown sigAlg; error on hashLen */
        return hashLen;
    }

    /*
      For RSA signatures, RFC 5746 allows to pick any hash algorithm,
      as long as it is supported by the peer, i.e. included in the
      peer's signature_algorithms list.

      We use this opportunity to switch from the insecure MD5 and
      SHA-1 to SHA-256, if possible. We don't want to contribute
      to the longevity of obsolete hash algorithms.
    */
    if (psIsInsecureSigAlg(a, keyAlgorithm, keySize, hashLen)
        || !canUseSigAlg(a, keyAlgorithm, peerSigAlgs))
    {
        /* Try to upgrade: This won't select inscure ones. */
        a = upgradeSigAlg(a, keyAlgorithm);
        if (!canUseSigAlg(a, keyAlgorithm, peerSigAlgs))
        {
            /* Stil not supported. Try the next alternative. */
            a = upgradeSigAlg(a, keyAlgorithm);
            if (!canUseSigAlg(a, keyAlgorithm, peerSigAlgs))
            {
                /* Unable to upgrade insecure alg. Have to use the
                   server cert sig alg. */
                a = certSigAlg;
                psTraceIntInfo("Fallback to certificate sigAlg: %d\n", a);
            }
        }
    }
    psTraceIntInfo("Chose sigAlg %d\n", a);
    return a;
}

int32_t chooseSigAlg(psX509Cert_t *cert,
        psPubKey_t *privKey,
        uint16_t peerSigAlgs)
{
    int32 pubKeyAlg;

# ifdef USE_CERT_PARSE
    pubKeyAlg = cert->pubKeyAlgorithm;
# else
    if (privKey->type == PS_RSA)
    {
        pubKeyAlg = OID_RSA_KEY_ALG;
    }
    else if (privKey->type == PS_ECC)
    {
        pubKeyAlg = OID_ECDSA_KEY_ALG;
    }
    else
    {
        return PS_UNSUPPORTED_FAIL;
    }
# endif /* USE_CERT_PARSE */

    return chooseSigAlgInt(cert->sigAlgorithm,
            privKey->keysize,
            pubKeyAlg,
            peerSigAlgs);
}


/* Return the TLS 1.2 SignatureAndHashAlgorithm encoding for the
   given algorithm OID. */
int32_t getSignatureAndHashAlgorithmEncoding(uint16_t sigAlgOid,
     unsigned char *octet1,
     unsigned char *octet2,
     uint16_t *hashSize)
{
    unsigned char b1, b2;
    uint16_t hLen = 0;

     switch (sigAlgOid)
    {
#ifdef USE_SHA1
    case OID_SHA1_ECDSA_SIG:
        b1 = 0x2; /* SHA-1 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA1_HASH_SIZE;
        break;
    case OID_SHA1_RSA_SIG:
        b1 = 0x2; /* SHA-1 */
        b2 = 0x1; /* RSA */
        hLen = SHA1_HASH_SIZE;
        break;
#endif
#ifdef USE_SHA256
    case OID_SHA256_ECDSA_SIG:
        b1 = 0x4; /* SHA-256 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA256_HASH_SIZE;
        break;
    case OID_SHA256_RSA_SIG:
        b1 = 0x4; /* SHA-256 */
        b2 = 0x1; /* RSA */
        hLen = SHA256_HASH_SIZE;
        break;
#endif
#ifdef USE_SHA384
    case OID_SHA384_ECDSA_SIG:
        b1 = 0x5; /* SHA-384 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA384_HASH_SIZE;
        break;
    case OID_SHA384_RSA_SIG:
        b1 = 0x5; /* SHA-384 */
        b2 = 0x1; /* RSA */
        hLen = SHA384_HASH_SIZE;
        break;
#endif
#ifdef USE_SHA512
    case OID_SHA512_ECDSA_SIG:
        b1 = 0x6; /* SHA-512 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA512_HASH_SIZE;
        break;
    case OID_SHA512_RSA_SIG:
        b1 = 0x6; /* SHA-512 */
        b2 = 0x1; /* RSA */
        hLen = SHA512_HASH_SIZE;
        break;
#endif
    default:
        return PS_UNSUPPORTED_FAIL; /* algorithm not supported */
    }

     if (octet1 && octet2 && hashSize)
     {
         *octet1 = b1;
         *octet2 = b2;
         *hashSize = hLen;
         return PS_SUCCESS;
     }
     return PS_ARG_FAIL;
}

#endif /* ! USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
