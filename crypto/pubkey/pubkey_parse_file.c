/**
 *      @file    pubkey_parse_file.c
 *      @version $Format:%h%d$
 *
 *      Generic public and private key parsing from file.
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

# if defined(USE_RSA) || defined(USE_ECC)
#  ifdef MATRIX_USE_FILE_SYSTEM
#   ifdef USE_PRIVATE_KEY_PARSING

static int32_t psTryParsePrivKeyFilePEM(psPool_t *pool, const char *keyfile,
        const char *password, psPubKey_t *privkey);
static int32_t psTryParsePubKeyFilePEM(psPool_t *pool, const char *keyfile,
        const char *password, psPubKey_t *pubkey);

/* Trial and error private key parse for when ECC or RSA is unknown.

    pemOrDer should be 1 if PEM

    Return codes:
        1 RSA key
        2 ECC key
        3 ED25519 key
        < 0 error
 */
int32_t psParseUnknownPrivKey(psPool_t *pool, int pemOrDer,
        const char *keyfile, const char *password,
        psPubKey_t *privkey)
{
    int keytype = -1;
    unsigned char *keyBuf;
    psSizeL_t keyBufLen;
    psRes_t rc;

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
    psSizeL_t keyBufLen;

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

#    ifdef USE_PKCS8

static int32 pkcs8parse_unknown(
        psPool_t *pool,
        unsigned char *buf,
        int32 size,
        psPubKey_t *key)
{
    /* When PKCS #8 header appears correct, but format is not
       RSA or ECDSA this function is called.
       The function may be extended to parse public key formats usually
       not processed by MatrixSSL. */

    psTraceCrypto("Unsupported public key type in PKCS#8 parse\n");
    return PS_UNSUPPORTED_FAIL;
}

/******************************************************************************/
/**
    Parse PKCS#8 format keys (from DER formatted binary)

    'key' is dynamically allocated and must be freed with psFreePubKey() if
        no error is returned from this API

    Unencrypted private keys are supported if 'pass' is NULL
    Encrypted private keys are supported if 'pass' is non-null for the
        des-EDE3-CBC algorithm only (3DES). Other PKCS#5 symmetric algorithms
        are not supported.

    @return < 0 on error, private keysize in bytes on success.
 */
psRes_t psPkcs8ParsePrivBin(psPool_t *pool,
                            const unsigned char *buf, psSizeL_t size,
    char *pass, psPubKey_t *key)
{
    const unsigned char *end, *p;
    int32 version, oi;
    psSize_t seqlen, len, plen;
#  ifdef USE_ECC
    int32 coi;
    const psEccCurve_t *eccSet;
#  endif
#  ifdef USE_PKCS5
    unsigned char desKeyBin[24];
    psCipherContext_t ctx;
    char iv[8], salt[8];
    int32 icount;
#  endif /* USE_PKCS5 */

    /* Check for too large (invalid) inputs, unparseable with uint16_t */
    if (size > 65535)
    {
        return PS_FAILURE;
    }

    p = buf;
    end = p + size;

    if (pass)
    {
        psSize_t i;

#  ifdef USE_PKCS5
/*              An encrypted PKCS#8 key has quite a bit more information we must parse
        We actually parse a good bit of PKCS#5 structures here
 */
        if (getAsnSequence(&p, (int32) (end - p), &seqlen) < 0)
        {
            return PS_FAILURE;
        }
        if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi, &plen) < 0)
        {
            psTraceCrypto("Couldn't parse PKCS#8 algorithm identifier\n");
            return PS_FAILURE;
        }
        if (oi != OID_PKCS_PBES2 || plen != 53)
        {
            psTraceCrypto("Only supporting PKCS#8 id-PBES2 OID\n");
            return PS_FAILURE;
        }
        if (getAsnSequence(&p, (int32) (end - p), &seqlen) < 0)
        {
            return PS_FAILURE;
        }
        if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi, &plen) < 0)
        {
            psTraceCrypto("Couldn't parse PKCS#8 keyDerivationFunc\n");
            return PS_FAILURE;
        }
        if (oi != OID_PKCS_PBKDF2 || plen != 16)
        {
            psTraceCrypto("Only support PKCS#8 id-PBKDF2 OID\n");
            return PS_FAILURE;
        }
        if (getAsnSequence(&p, (int32) (end - p), &seqlen) < 0)
        {
            return PS_FAILURE;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &len) < 0 ||
            (uint32) (end - p) < len ||
            len != 8)
        {

            psTraceCrypto("Couldn't parse PKCS#8 param salt\n");
            return PS_FAILURE;
        }
        /* Get the PBKDF2 Salt */
        Memcpy(salt, p, 8); p += 8;
        /* Get the PBKDF2 Iteration count (rounds) */
        if (getAsnInteger(&p, (int32) (end - p), &icount) < 0)
        {
            psTraceCrypto("Couldn't parse PKCS#8 param iterationCount\n");
            return PS_FAILURE;
        }
        /* Get encryptionScheme */
        if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi, &plen)
            < 0)
        {
            psTraceCrypto("Couldn't parse PKCS#8 encryptionScheme\n");
            return PS_FAILURE;
        }
        if (oi != OID_DES_EDE3_CBC || plen != 10)
        {
            psTraceCrypto("Only support des-EDE3-CBC OID\n");
            return PS_FAILURE;
        }
        if ((uint32) (end - p) < 1)
        {
            psTraceCrypto("Couldn't parse PKCS#8 param CBC IV\n");
            return PS_FAILURE;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &len) < 0 ||
            (uint32) (end - p) < len ||
            len != DES3_IVLEN)
        {

            psTraceCrypto("Couldn't parse PKCS#8 param CBC IV\n");
            return PS_FAILURE;
        }
        /* Get the 3DES IV */
        Memcpy(iv, p, DES3_IVLEN); p += DES3_IVLEN;

        /* Now p points to the 3DES encrypted RSA key */
        if ((uint32) (end - p) < 1)
        {
            psTraceCrypto("Couldn't parse PKCS#8 param CBC IV\n");
            return PS_FAILURE;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &len) < 0 ||
            (uint32) (end - p) < len ||
#   ifdef USE_ECC
            /* May actually be an RSA key, but this check will be OK for now */
            len < MIN_ECC_BITS / 8)
        {
#   else
            len < MIN_RSA_BITS / 8) {
#   endif

            psTraceCrypto("PKCS#8 decryption error\n");
            return PS_FAILURE;
        }
        /* Derive the 3DES key and decrypt the RSA key*/
        psPkcs5Pbkdf2((unsigned char *) pass, (int32) Strlen(pass),
            (unsigned char *) salt, 8, icount, (unsigned char *) desKeyBin,
            DES3_KEYLEN);
        psDes3Init(&ctx.des3, (unsigned char *) iv, desKeyBin);
        psDes3Decrypt(&ctx.des3, p, (unsigned char *) p, len);
        /* @security SECURITY - we zero out des3 key when done with it */
        memset_s(&ctx, sizeof(psCipherContext_t), 0x0, sizeof(psCipherContext_t));
        memset_s(desKeyBin, DES3_KEYLEN, 0x0, DES3_KEYLEN);

        /* Remove padding.
           This implementation allows up-to 16 bytes padding, for
           compatibility with 3DES and AES algorithms. */
        /* Start by checking length. */
        /* coverity[dead_error_condition] */
        /* With the current value for MIN_ECC_BITS and MIN_RSA_BITS
           this path can never be taken. This code path is ready in
           case the values change in the future. */
        if (len < 1)
        {
            /* coverity[dead_error_begin] */
            psTraceCrypto("PKCS#8 padding error\n");
            return PS_FAILURE;
        }
        plen = (unsigned char) p[len - 1];
        if (plen < 1 || plen > 16)
        {
            psTraceCrypto("PKCS#8 padding error\n");
            return PS_FAILURE;
        }
        /* coverity[dead_error_condition] */
        /* With the current value for MIN_ECC_BITS and MIN_RSA_BITS
           this path can never be taken. This code path is ready in
           case the values change in the future. */
        if (len < plen)
        {
            /* coverity[dead_error_begin] */
            psTraceCrypto("PKCS#8 padding error\n");
            return PS_FAILURE;
        }
        for(i = 0; i < plen; i++)
        {
            if (p[len - i - 1] != (unsigned char) plen)
            {
                psTraceCrypto("PKCS#8 padding error\n");
                return PS_FAILURE;
            }
        }

        /* The padding has been processed. */
        size = len - plen;
        end = p + size;
        buf = (unsigned char *)p;
#  else /* !USE_PKCS5 */
/*
        The private key is encrypted, but PKCS5 support has been turned off
 */
        psTraceCrypto("USE_PKCS5 must be enabled for key file password\n");
        return PS_UNSUPPORTED_FAIL;
#  endif /* USE_PKCS5 */
    }

    /* PrivateKeyInfo per PKCS#8 Section 6. */
    if (getAsnSequence(&p, (int32) (end - p), &seqlen) < 0)
    {
        psTraceCrypto("Initial PrivateKeyInfo parse failure\n");
#  ifdef USE_PKCS5
        if (pass)
        {
            psTraceCrypto("Is it possible the password is incorrect?\n");
        }
#  endif /* USE_PKCS5 */
        return PS_FAILURE;
    }
    /* Version */
    if (getAsnInteger(&p, (int32) (end - p), &version) < 0 || version != 0)
    {
        psTraceCrypto("Couldn't parse PKCS#8 algorithm identifier\n");
        return PS_FAILURE;
    }
    /* privateKeyAlgorithmIdentifier */
    if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi, &plen) < 0)
    {
        psTraceCrypto("Couldn't parse PKCS#8 algorithm identifier\n");
        return PS_FAILURE;
    }
#  ifdef USE_ECC
    if (oi != OID_ECDSA_KEY_ALG && oi != OID_RSA_KEY_ALG)
    {
        return pkcs8parse_unknown(pool, (unsigned char *)buf, size, key);
    }
    if (oi == OID_ECDSA_KEY_ALG)
    {
        /* Still a curve identifier sitting as param in the SEQUENCE */
        if ((uint32) (end - p) < 1 || *p++ != ASN_OID)
        {
            psTraceCrypto("Expecting EC curve OID next\n");
            return PS_PARSE_FAIL;
        }
        if (getAsnLength(&p, (uint32) (end - p), &len) < 0 ||
            (uint32) (end - p) < len)
        {
            psTraceCrypto("Malformed extension length\n");
            return PS_PARSE_FAIL;
        }
        coi = 0;
        while (len > 0)
        {
            coi += *p; p++;
            len--;
        }
        if (getEccParamByOid(coi, &eccSet) < 0)
        {
            psTraceCrypto("Unsupported EC curve OID\n");
            return PS_UNSUPPORTED_FAIL;
        }
    }
#  else
    if (oi != OID_RSA_KEY_ALG || plen != 0)
    {
        return pkcs8parse_unknown(pool, (unsigned char *)buf, size, key);
    }
#  endif
    /* PrivateKey Octet Stream */
    if ((uint32) (end - p) < 1)
    {
        psTraceCrypto("Private Key len failure\n");
        return PS_PARSE_FAIL;
    }
    if ((*p++ != ASN_OCTET_STRING) ||
        getAsnLength(&p, (int32) (end - p), &len) < 0 ||
        (uint32) (end - p) < len)
    {
        psTraceCrypto("getAsnLength parse error in psPkcs8ParsePrivBin\n");
        return PS_FAILURE;
    }
    /* Note len can be zero here */
#  ifdef USE_RSA
    if (oi == OID_RSA_KEY_ALG)
    {
        /* Create the actual key here from the octet string */
        psRsaInitKey(pool, &key->key.rsa);
        if (psRsaParsePkcs1PrivKey(pool, p, len, &key->key.rsa) < 0)
        {
            psRsaClearKey(&key->key.rsa);
            return PS_FAILURE;
        }
        key->type = PS_RSA;
        key->keysize = psRsaSize(&key->key.rsa);
    }
#  endif
#  ifdef USE_ECC
    if (oi == OID_ECDSA_KEY_ALG)
    {
        psEccInitKey(pool, &key->key.ecc, eccSet);
        if (psEccParsePrivKey(pool, p, len, &key->key.ecc, eccSet) < 0)
        {
            return PS_FAILURE;
        }
        key->type = PS_ECC;
        key->keysize = psEccSize(&key->key.ecc);
    }
#  endif
    p += len;

#if 0
    /* attributest are not here, they are on the next element - what
       remains is the crypto padding. */
    plen = (int32) (end - p);
    if (plen > 0)
    {
        /* attributes [0] Attributes OPTIONAL */
        if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
        {
            p++;
            if (getAsnLength(&p, (int32) (end - p), &len) < 0 ||
                (uint32) (end - p) < len)
            {

                psTraceCrypto("Error parsing pkcs#8 PrivateKey attributes\n");
                return PS_FAILURE;
            }
            /* Ignore any attributes */
            p += len;
            plen = (int32) (end - p);
        }

        if (plen > 0)
        {
            /* Unexpected extra data remains. Treat it as an error. */
            goto PKCS8_FAIL;
        }
    }
#endif

    return PS_SUCCESS;

#if 0
PKCS8_FAIL:
    psClearPubKey(key);
    psTraceCrypto("Did not parse key in PKCS#8 parse\n");
    return PS_FAILURE;
#endif
}
#    endif /* USE_PKCS8 */

static int32_t psTryParsePrivKeyFilePEM(psPool_t *pool, const char *keyfile,
        const char *password, psPubKey_t *privkey)
{
    int32_t rc;

#ifdef USE_RSA
    rc = psPkcs1ParsePrivFile(pool, keyfile, password, &privkey->key.rsa);
    if (rc >= PS_SUCCESS)
    {
        privkey->type = PS_RSA;
        privkey->keysize = psRsaSize(&privkey->key.rsa);
        privkey->pool = pool;
        return 1; /* RSA */
    }
#endif /* USE_RSA */

#ifdef USE_ECC
    /* psEccParsePrivFile will also try psPkcs8ParsePrivBin. */
    rc = psEccParsePrivFile(pool, keyfile, password, &privkey->key.ecc);
    if (rc >= PS_SUCCESS)
    {
        privkey->type = PS_ECC;
        privkey->keysize = psEccSize(&privkey->key.ecc);
        privkey->pool = pool;
        return 2; /* ECC */
    }

# ifdef USE_ED25519
    rc = psEd25519ParsePrivFile(pool, keyfile, password, &privkey->key.ed25519);
    if (rc >= PS_SUCCESS)
    {
        privkey->type = PS_ED25519;
        privkey->keysize = 32;
        privkey->pool = pool;
        return 3; /* ED25519 */
    }
# endif /* USE_ED25519 */
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
        pubkey->pool = pool;
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

/******************************************************************************/

/**
    Return the DER stream from a private key PEM file.

    Despite Pkcs1 in the name, not an RSA-specific function.

    Memory info:
        Caller must call psFree on DERout on function success
 */
int32_t psPkcs1DecodePrivFile(psPool_t *pool, const char *fileName,
    const char *password, unsigned char **DERout, psSize_t *DERlen)
{
    psSizeL_t DERlen2 = 0;
    int32_t rc;

# ifdef USE_PEM_DECODE
    if (DERlen == NULL)
    {
        return PS_ARG_FAIL;
    }
    rc = psPemFileToDer(pool,
            fileName,
            password,
            PEM_TYPE_KEY,
            DERout,
            &DERlen2);
    *DERlen = DERlen2;

    return rc;
# else
    psTraceCrypto("Need USE_PEM_DECODE for psPkcs1DecodePrivFile\n");
    return PS_UNSUPPORTED_FAIL;
# endif
}

# else   /* ==> !USE_PRIVATE_KEY_PARSING */
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
#   endif   /* USE_PRIVATE_KEY_PARSING */
#  endif /* MATRIX_USE_FILE_SYSTEM */
# endif /* USE_RSA || USE_ECC */
