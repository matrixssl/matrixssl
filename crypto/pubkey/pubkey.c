/**
 *      @file    pubkey.c
 *      @version $Format:%h%d$
 *
 *      Public and Private key operations shared by crypto implementations.
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

#if defined(USE_RSA) || defined(USE_ECC)

/******************************************************************************/

int32_t psInitPubKey(psPool_t *pool, psPubKey_t *key, uint8_t type)
{
    if (!key)
    {
        return PS_ARG_FAIL;
    }
    switch (type)
    {
# ifdef USE_RSA
    case PS_RSA:
        psRsaInitKey(pool, &key->key.rsa);
        break;
# endif
# ifdef USE_ECC
    case PS_ECC:
        psEccInitKey(pool, &key->key.ecc, NULL);
        break;
# endif
    default:
        break;
    }
    key->pool = pool;
    key->type = type;
    key->keysize = 0;
    return PS_SUCCESS;
}

/******************************************************************************/

void psClearPubKey(psPubKey_t *key)
{
    if (!key)
    {
        return;
    }
    switch (key->type)
    {
# ifdef USE_RSA
    case PS_RSA:
        psRsaClearKey(&key->key.rsa);
        break;
# endif
# ifdef USE_ECC
    case PS_ECC:
        psEccClearKey(&key->key.ecc);
        break;
# endif
    default:
        break;
    }
    key->pool = NULL;
    key->keysize = 0;
    key->type = 0;
}

int32_t psNewPubKey(psPool_t *pool, uint8_t type, psPubKey_t **key)
{
    int32_t rc;

    if ((*key = psMalloc(pool, sizeof(psPubKey_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }

    if ((rc = psInitPubKey(pool, *key, type)) < 0)
    {
        psFree(*key, pool);
    }
    return rc;
}

void psDeletePubKey(psPubKey_t **key)
{
    psClearPubKey(*key);
    psFree(*key, NULL);
    *key = NULL;
}

# if defined(USE_PRIVATE_KEY_PARSING) && defined(MATRIX_USE_FILE_SYSTEM)
#  if defined(USE_ECC) || defined(USE_RSA)

#ifdef USE_RSA
static psBool_t possiblyRSAKey(unsigned char *keyBuf, int32 keyBufLen)
{
    /* Guess if this can be RSA key based on length of encoding and content.
       Even the smallest (obsolete 512-bit modulus) RSA private keys are >
       256 bytes.
    */
    return (keyBufLen > 256 && keyBuf[0] == 0x30 && keyBuf[1] >= 0x82);
}
#endif /* USE_RSA */

/*
  Helpers for trial and error private key parse
  Return codes:
  1 RSA key
  2 ECC key
  < 0 error
 */
static int32_t psTryParsePrivKeyMem(psPool_t *pool,
        unsigned char *keyBuf, int32 keyBufLen,
        const char *password, psPubKey_t *privkey)
{
#ifdef USE_RSA
    /* Examine data to ensure parses which could not succeed are not tried. */
    if (possiblyRSAKey(keyBuf, keyBufLen)) {
        if (psRsaParsePkcs1PrivKey(pool, keyBuf, keyBufLen, &privkey->key.rsa)
            >= PS_SUCCESS)
        {
            privkey->type = PS_RSA;
            privkey->keysize = psRsaSize(&privkey->key.rsa);
            privkey->pool = pool;
            return 1; /* RSA */
        }
    }
#endif /* USE_RSA */

#ifdef USE_ECC
    if (psEccParsePrivKey(pool, keyBuf, keyBufLen, &privkey->key.ecc, NULL)
        >= PS_SUCCESS)
    {
        privkey->type = PS_ECC;
        privkey->keysize = psEccSize(&privkey->key.ecc);
        privkey->pool = pool;
        return 2; /* ECC */
    }
#endif /* USE_ECC */

#ifdef USE_PKCS8
     if (psPkcs8ParsePrivBin(pool, keyBuf, keyBufLen,
         (char*)password, privkey) >= PS_SUCCESS)
     {
# ifdef USE_RSA
         if (privkey->type == PS_RSA)
         {
             return 1; /* RSA */
         }
# endif /* USE_RSA */

# ifdef USE_ECC
         if (privkey->type == PS_ECC)
         {
             return 2; /* ECC */
         }
# endif /* USE_ECC */

         return -1; /* Success, but keytype unknown? */
     }
#endif /* USE_PKCS8 */

    return -1; /* Error */
}

static int32_t psTryParsePrivKeyFilePEM(psPool_t *pool, const char *keyfile,
        const char *password, psPubKey_t *privkey)
{
#ifdef USE_RSA
    if (psPkcs1ParsePrivFile(pool, keyfile, password, &privkey->key.rsa) >= PS_SUCCESS)
    {
        privkey->type = PS_RSA;
        privkey->keysize = psRsaSize(&privkey->key.rsa);
        privkey->pool = pool;
        return 1; /* RSA */
    }
#endif /* USE_RSA */

#ifdef USE_ECC
    /* psEccParsePrivFile will also try psPkcs8ParsePrivBin. */
    if (psEccParsePrivFile(pool, keyfile, password, &privkey->key.ecc) >= PS_SUCCESS)
    {
        privkey->type = PS_ECC;
        privkey->keysize = psEccSize(&privkey->key.ecc);
        privkey->pool = pool;
        return 2; /* ECC */
    }
#endif /* USE_ECC */

    return -1; /* Error */
}

static int32_t psTryParsePubKeyFilePEM(psPool_t *pool, const char *keyfile,
        const char *password, psPubKey_t *pubkey)
{
#ifdef USE_RSA
    /* PEM file. */
    if (psPkcs1ParsePubFile(pool, keyfile, &pubkey->key.rsa) >= PS_SUCCESS)
    {
        pubkey->type = PS_RSA;
        pubkey->keysize = psRsaSize(&pubkey->key.rsa);
        return 1; /* RSA */
    }
#endif /* USE_RSA */

    PS_VARIABLE_SET_BUT_UNUSED(password);
#ifndef USE_RSA
    PS_VARIABLE_SET_BUT_UNUSED(pool);
    PS_VARIABLE_SET_BUT_UNUSED(keyfile);
    PS_VARIABLE_SET_BUT_UNUSED(pubkey);
#endif /* !USE_RSA */

    return -1; /* Error */
}

/*
  Trial and error private key parse for when ECC or RSA is unknown.
  keyBuf must point to a buffer of length keyBufLen, containing
  a DER-encoded key.

  Return codes:
  1 RSA key
  2 ECC key
  < 0 error
 */
int32_t psParseUnknownPrivKeyMem(psPool_t *pool,
        unsigned char *keyBuf, int32 keyBufLen,
        const char *password, psPubKey_t *privkey)
{
    int32_t keytype;

    if (keyBuf == NULL || keyBufLen <= 0)
        return PS_ARG_FAIL;

     privkey->keysize = 0;

     keytype = psTryParsePrivKeyMem(pool, keyBuf, keyBufLen, password, privkey);

     if (keytype < 0)
     {
         psTraceCrypto("Unable to parse private key. " \
                 "Supported formats are RSAPrivateKey, " \
                 "ECPrivateKey and PKCS #8.\n");
         return PS_FAILURE;
     }

     return keytype;
}

/* Trial and error private key parse for when ECC or RSA is unknown.

    pemOrDer should be 1 if PEM

    Return codes:
        1 RSA key
        2 ECC key
        < 0 error
 */
int32_t psParseUnknownPrivKey(psPool_t *pool, int pemOrDer,
        const char *keyfile, const char *password,
        psPubKey_t *privkey)
{
    int keytype = -1;
    unsigned char *keyBuf;
    int32 keyBufLen;
    int32_t rc;

    privkey->keysize = 0;
    if (pemOrDer == 1)
    {
        /* PEM file */
        keytype = psTryParsePrivKeyFilePEM(pool, keyfile, password, privkey);

        if (keytype < 0)
        {
            psTraceStrCrypto("Unable to parse private key file %s\n",
                keyfile);
            return PS_FAILURE;
        }
    }
    else
    {
        /* DER file. */
        if (psGetFileBuf(pool, keyfile, &keyBuf, &keyBufLen) < PS_SUCCESS)
        {
            psTraceStrCrypto("Unable to open private key file %s\n", keyfile);
            return -1;
        }
        rc = psParseUnknownPrivKeyMem(pool, keyBuf, keyBufLen, password,
                privkey);
        psFree(keyBuf, pool);

        /* Continue examining result of private key parsing. */
        if (rc < 0)
        {
            psTraceStrCrypto("Unable to parse private key file %s\n", keyfile);
            return -1;
        }
        keytype = rc;
    }

    return keytype;
}

/* Trial and error public key parse for when ECC or RSA is unknown.

    pemOrDer should be 1 if PEM

    Note: The current version of this function only supports RSA when
    MatrixSSL's stock cryptographic library is used and
    additionally ECC when CL cryptographic library is used.

    Return codes:
        1 RSA key
        2 ECC key
        -1 error
 */
int32_t psParseUnknownPubKey(psPool_t *pool, int pemOrDer, char *keyfile,
    const char *password, psPubKey_t *pubkey)
{
    int keytype = -1;
    unsigned char *keyBuf;
    int32 keyBufLen;

    /* flps_parseUnknownPubKey() is similar function.
       First try to invoke that. */

    (void) password; /* password is for future extensions. */
    pubkey->keysize = 0;
    if (pemOrDer == 1)
    {
        /* PEM file */
        keytype = psTryParsePubKeyFilePEM(pool, keyfile, password, pubkey);

        if (keytype < 0)
        {
            psTraceStrCrypto("Unable to parse public key file %s\n", keyfile);
            return PS_FAILURE;
        }
    }
    else
    {
        /* DER file. */
        if (psGetFileBuf(pool, keyfile, &keyBuf, &keyBufLen) < PS_SUCCESS)
        {
            psTraceStrCrypto("Unable to open public key file %s\n", keyfile);
            return -1;
        }
        /* Processing DER files not handled by current implementation of
           the function the input shall be in PEM format. */
        psFree(keyBuf, pool);
    }

    return keytype;
}

#  endif /* USE_ECC || USE_RSA */
# else
int32_t psParseUnknownPrivKeyMem(psPool_t *pool,
        unsigned char *keyBuf, int32 keyBufLen,
        const char *password, psPubKey_t *privkey)
{
    PS_VARIABLE_SET_BUT_UNUSED(pool);
    PS_VARIABLE_SET_BUT_UNUSED(keyBuf);
    PS_VARIABLE_SET_BUT_UNUSED(keyBufLen);
    PS_VARIABLE_SET_BUT_UNUSED(password);
    PS_VARIABLE_SET_BUT_UNUSED(privkey);
    return -1; /* Not implemented */
}

int32_t psParseUnknownPrivKey(psPool_t *pool, int pemOrDer,
        const char *keyfile, const char *password,
        psPubKey_t *privkey)
{
    PS_VARIABLE_SET_BUT_UNUSED(pool);
    PS_VARIABLE_SET_BUT_UNUSED(pemOrDer);
    PS_VARIABLE_SET_BUT_UNUSED(keyfile);
    PS_VARIABLE_SET_BUT_UNUSED(password);
    PS_VARIABLE_SET_BUT_UNUSED(privkey);
    return -1; /* Not implemented */
}

int32_t psParseUnknownPubKey(psPool_t *pool, int pemOrDer, char *keyfile,
    const char *password, psPubKey_t *pubkey)
{
    PS_VARIABLE_SET_BUT_UNUSED(pool);
    PS_VARIABLE_SET_BUT_UNUSED(pemOrDer);
    PS_VARIABLE_SET_BUT_UNUSED(keyfile);
    PS_VARIABLE_SET_BUT_UNUSED(password);
    PS_VARIABLE_SET_BUT_UNUSED(pubkey);
    return -1; /* Not implemented */
}
# endif   /* USE_PRIVATE_KEY_PARSING && MATRIX_USE_FILE_SYSTEM */

int32_t psHashLenToSigAlg(psSize_t hash_len,
    uint8_t key_type)
{
    int32_t signatureAlgorithm;

    /**/
    psAssert(key_type == PS_RSA || key_type == PS_ECC);

    switch (hash_len)
    {
# if defined(USE_MD2) || defined(USE_MD5)
    case MD2_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            psTraceCrypto("pubRsaDecryptSignedElement cannot handle ");
            psTraceCrypto("RSA-MD2 or RSA-MD5 signatures; please use ");
            psTraceCrypto("pubRsaDecryptSignedElementExt instead.\n");
            return PS_ARG_FAIL;
        }
        else
        {
            psTraceCrypto("ECDSA-MD2 and ECDSA-MD5 not supported\n");
            return PS_UNSUPPORTED_FAIL;
        }
        break;
# endif /* USE_MD2 || USE_MD5 */
    case SHA1_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA1_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA1_ECDSA_SIG;
        }
        break;
# if 0
    case SHA224_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA224_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA224_ECDSA_SIG;
        }
        break;
# endif
    case SHA256_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA256_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA256_ECDSA_SIG;
        }
        break;
    case SHA384_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA384_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA384_ECDSA_SIG;
        }
        break;
    case SHA512_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA512_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA512_ECDSA_SIG;
        }
        break;
    default:
        psTraceCrypto("Unsupported hash size in RSA signature\n");
        return PS_UNSUPPORTED_FAIL;
    }

    return signatureAlgorithm;
}


psRes_t psComputeHashForSig(const unsigned char *dataBegin,
    psSizeL_t dataLen,
    int32_t signatureAlgorithm,
    unsigned char hashOut[SHA512_HASH_SIZE],
    psSize_t *hashOutLen)
{
    psDigestContext_t hash;

    if (hashOut == NULL || hashOutLen == NULL)
    {
        return PS_ARG_FAIL;
    }

    if (dataLen < 1)
    {
        return PS_ARG_FAIL;
    }

    switch (signatureAlgorithm)
    {
# ifdef ENABLE_MD5_SIGNED_CERTS
#  ifdef USE_MD2
    case OID_MD2_RSA_SIG:
        psMd2Init(&hash.md2);
        if (psMd2Update(&hash.md2, dataBegin, dataLen) < 0)
        {
            return PS_FAILURE;
        }
        if (psMd2Final(&hash.md2, hashOut) < 0)
        {
            return PS_FAILURE;
        }
        *hashOutLen = MD5_HASH_SIZE;
        break;
#  endif /* USE_MD2 */
    case OID_MD5_RSA_SIG:
        if (psMd5Init(&hash.md5) < 0)
        {
            return PS_FAILURE;
        }
        psMd5Update(&hash.md5, dataBegin, dataLen);
        psMd5Final(&hash.md5, hashOut);
        *hashOutLen = MD5_HASH_SIZE;
        break;
# endif /* ENABLE_MD5_SIGNED_CERTS */
    case OID_SHA1_RSA_SIG:
    case OID_SHA1_RSA_SIG2:
    case OID_SHA1_ECDSA_SIG:
        psSha1PreInit(&hash.sha1);
        psSha1Init(&hash.sha1);
        psSha1Update(&hash.sha1, dataBegin, dataLen);
        psSha1Final(&hash.sha1, hashOut);
        *hashOutLen = SHA1_HASH_SIZE;
        break;
#ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
    case OID_SHA224_ECDSA_SIG:
        psSha224PreInit(&hash.sha256);
        psSha224Init(&hash.sha256);
        psSha224Update(&hash.sha256, dataBegin, dataLen);
        psSha224Final(&hash.sha256, hashOut);
        *hashOutLen = SHA224_HASH_SIZE;
        break;
#endif /* USE_SHA224 */
    case OID_SHA256_RSA_SIG:
    case OID_SHA256_ECDSA_SIG:
        psSha256PreInit(&hash.sha256);
        psSha256Init(&hash.sha256);
        psSha256Update(&hash.sha256, dataBegin, dataLen);
        psSha256Final(&hash.sha256, hashOut);
        *hashOutLen = SHA256_HASH_SIZE;
        break;
# ifdef USE_SHA384
    case OID_SHA384_RSA_SIG:
    case OID_SHA384_ECDSA_SIG:
        psSha384PreInit(&hash.sha384);
        psSha384Init(&hash.sha384);
        psSha384Update(&hash.sha384, dataBegin, dataLen);
        psSha384Final(&hash.sha384, hashOut);
        *hashOutLen = SHA384_HASH_SIZE;
        break;
# endif
# ifdef USE_SHA512
    case OID_SHA512_RSA_SIG:
    case OID_SHA512_ECDSA_SIG:
        psSha512PreInit(&hash.sha512);
        psSha512Init(&hash.sha512);
        psSha512Update(&hash.sha512, dataBegin, dataLen);
        psSha512Final(&hash.sha512, hashOut);
        *hashOutLen = SHA512_HASH_SIZE;
        break;
# endif
    default:
        psTraceCrypto("Unsupported sig alg\n");
        return PS_UNSUPPORTED_FAIL;
    }

    return PS_SUCCESS;
}

psRes_t psVerifySig(psPool_t *pool,
    const unsigned char hashIn[SHA512_HASH_SIZE],
    psSize_t hashInLen,
    const unsigned char *sig,
    psSize_t sigLen,
    psPubKey_t *key,
    int32_t signatureAlgorithm,
    psBool_t *verifyResult,
    psVerifySigOptions_t *opts)
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
        if (pubRsaDecryptSignedElementExt(pool, &key->key.rsa,
                (unsigned char *) sig, sigLen, out,
                hashInLen, signatureAlgorithm, NULL) < 0)
        {
            psTraceCrypto("Error decrypting request signature\n");
            rc = PS_FAILURE;
            goto out;
        }
        if (memcmpct(hashIn, out, hashInLen) != 0)
        {
            rc = PS_VERIFICATION_FAILED;
            *verifyResult = PS_FALSE;
            goto out;
        }
        break;
# endif /* USE_RSA */
# ifdef USE_ECC
    case PS_ECC:
        if (psEccDsaVerify(pool, &key->key.ecc, hashIn,
                hashInLen, sig, sigLen, &eccRet, NULL) < 0)
        {
            psTraceCrypto("Error decrypting request signature\n");
            rc = PS_FAILURE;
            goto out;
        }
        if (eccRet != 1)
        {
            psTraceCrypto("Error validating signature\n");
            rc = PS_VERIFICATION_FAILED;
            *verifyResult = PS_FALSE;
            goto out;
        }
        break;
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
    psVerifySigOptions_t *opts)
{
    unsigned char digest[SHA512_HASH_SIZE] = { 0 };
    psSize_t digestLen = 0;
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

/******************************************************************************/

#endif /* USE_RSA || USE_ECC */

