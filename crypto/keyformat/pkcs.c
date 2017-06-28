/**
 *      @file    pkcs.c
 *      @version $Format:%h%d$
 *
 *      Collection of RSA PKCS standards .
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
/*
    Pad a value to be encrypted by RSA, according to PKCS#1 v1.5
    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/
    When encrypting a value with RSA, the value is first padded to be
    equal to the public key size using the following method:
        00 <id> <data> 00 <value to be encrypted>
    - id denotes a public or private key operation
    - if id is private, data is however many non-zero bytes it takes to pad the
        value to the key length (randomLen = keyLen - 3 - valueLen).
    - if id is public, data is FF for the same length as described above
    - There must be at least 8 bytes of data.
 */
int32_t pkcs1Pad(const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    uint8_t cryptType, void *userPtr)
{
    unsigned char *c;
    uint32_t randomLen;

    randomLen = outlen - 3 - inlen;
    if (randomLen < 8)
    {
        psTraceCrypto("pkcs1Pad failure\n");
        return PS_LIMIT_FAIL;
    }
    c = out;
    *c = 0x00;
    c++;
    *c = (unsigned char) cryptType;
    c++;
    if (cryptType == PS_PUBKEY)
    {
        while (randomLen > 0)
        {
            *c++ = 0xFF;
            randomLen--;
        }
    }
    else
    {
        if (psGetPrngLocked(c, randomLen, userPtr) < 0)
        {
            return PS_PLATFORM_FAIL;
        }
/*
        SECURITY:  Read through the random data and change all 0x0 to 0x01.
        This is per spec that no random bytes should be 0
 */
        while (randomLen > 0)
        {
            if (*c == 0x0)
            {
                *c = 0x01;
            }
            randomLen--;
            c++;
        }
    }
    *c = 0x00;
    c++;
    memcpy(c, in, inlen);

    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Unpad a value decrypted by RSA, according to PKCS#1 v1.5
    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/

    When decrypted, the data will look like the pad, including the inital
    byte (00).  Form:
        00 <decryptType> <random data (min 8 bytes)> 00 <value to be encrypted>

    We don't worry about v2 rollback issues because we don't support v2
 */
int32_t pkcs1Unpad(const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    uint8_t decryptType)
{
    const unsigned char *c, *end;

    if (inlen < outlen + 10)
    {
        psTraceCrypto("pkcs1Unpad failure\n");
        return PS_ARG_FAIL;
    }
    c = in;
    end = in + inlen;

    /* Verify the first byte (block type) is correct.  */
    if (*c++ != 0x00 || *c != decryptType)
    {
        psTraceCrypto("pkcs1Unpad parse failure\n");
        return PS_FAILURE;
    }
    c++;

    /* Skip over the random, non-zero bytes used as padding */
    while (c < end && *c != 0x0)
    {
        if (decryptType == PS_PUBKEY)
        {
            if (*c != 0xFF)
            {
                psTraceCrypto("pkcs1Unpad pubkey parse failure\n");
                return PS_FAILURE;
            }
        }
        c++;
    }
    c++;
/*
    The length of the remaining data should be equal to what was expected
    Combined with the initial length check, there must be >= 8 bytes of pad
    ftp://ftp.rsa.com/pub/pdfs/bulletn7.pdf
 */
    if ((uint32) (end - c) != outlen)
    {
        psTraceCrypto("pkcs1Unpad verification failure\n");
        return PS_LIMIT_FAIL;
    }

    /* Copy the value bytes to the out buffer */
    while (c < end)
    {
        *out = *c;
        out++; c++;
    }
    return PS_SUCCESS;
}

#ifdef USE_PRIVATE_KEY_PARSING

# ifdef USE_PKCS8

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
int32 psPkcs8ParsePrivBin(psPool_t *pool, unsigned char *buf, int32 size,
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
        memcpy(salt, p, 8); p += 8;
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
        memcpy(iv, p, DES3_IVLEN); p += DES3_IVLEN;

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
        psPkcs5Pbkdf2((unsigned char *) pass, (int32) strlen(pass),
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
        return pkcs8parse_unknown(pool, buf, size, key);
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
        return pkcs8parse_unknown(pool, buf, size, key);
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

    return PS_SUCCESS;

PKCS8_FAIL:
    psClearPubKey(key);
    psTraceCrypto("Did not parse key in PKCS#8 parse\n");
    return PS_FAILURE;
}

#  ifdef MATRIX_USE_FILE_SYSTEM
#   ifdef USE_PKCS12
/******************************************************************************/
/*
    A PKCS #7 ContentInfo, whose contentType is signedData in public-key
    integrity mode and data in password integrity mode.

    Returns integrity mode or < 0 on failure
 */
#    define PASSWORD_INTEGRITY  1
#    define PUBKEY_INTEGRITY    2
static int32 psParseIntegrityMode(const unsigned char **buf, int32 totLen)
{
    const unsigned char *p, *end;
    psSize_t totcontentlen, len, oiLen;
    int32 rc, oi;

    p = *buf;
    end = p + totLen;

    if ((rc = getAsnAlgorithmIdentifier(&p, totLen, &oi, &oiLen)) < 0)
    {
        psTraceCrypto("Initial integrity parse error\n");
        return rc;
    }

    if (oi == OID_PKCS7_DATA)
    {
        /* Data ::= OCTET STRING */
        if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
        {
            return PS_PARSE_FAIL;
        }
        if ((rc = getAsnLength(&p, (int32) (end - p), &len)) < 0)
        {
            return PS_PARSE_FAIL;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &totcontentlen) < 0)
        {
            psTraceCrypto("Couldn't parse data from ContentInfo\n");
            return PS_FAILURE;
        }
        rc = PASSWORD_INTEGRITY;
    }
    else if (oi == OID_PKCS7_SIGNED_DATA)
    {
        psTraceCrypto("SignedData integrity mode not supported\n");
        return PS_UNSUPPORTED_FAIL;
        /* rc = PUBKEY_INTEGRITY; */
    }
    else
    {
        psTraceCrypto("Unknown integrity mode\n");
        return PS_UNSUPPORTED_FAIL;
    }

    *buf = (unsigned char *) p;
    return rc;
}

/******************************************************************************/
/*
    Generate a key given a password, salt and iteration value.

    B.2 General method from PKCS#12

    Assumptions:  hash is SHA-1, password is < 128 bytes
 */
static int32 pkcs12pbe(psPool_t *pool, unsigned char *password, uint32 passLen,
    unsigned char *salt, int saltLen, int32 iter, int32 id,
    unsigned char **out, uint32 *outlen)
{
    psSha1_t ctx;
    pstm_int bigb, bigone, bigtmp;
    unsigned char diversifier[64], saltpass[192], hash[SHA1_HASH_SIZE];
    unsigned char B[65];
    unsigned char *p, *front;
    int32 i, j, copy, count, cpyLen, binsize, plen;

    *out = NULL;
    memset(diversifier, id, 64);

    for (i = 0; i < 64; )
    {
        if ((64 - i) < saltLen)
        {
            memcpy(&saltpass[i], salt, 64 - i);
            i = 64;
        }
        else
        {
            memcpy(&saltpass[i], salt, saltLen);
            i += saltLen;
        }
    }

    plen = 64 * ((passLen + 64 - 1) / 64);
    if (plen + 64 > 192)
    {
        return PS_UNSUPPORTED_FAIL;
    }
    for (i = 0; i < plen; i++)
    {
        saltpass[64 + i] = password[i % passLen];
    }

    if (*outlen == SHA1_HASH_SIZE)
    {
        count = 1;
    }
    else
    {
        count = (*outlen / SHA1_HASH_SIZE) + 1;
    }
    cpyLen = *outlen;

    front = p = psMalloc(pool, cpyLen);
    if (front == NULL)
    {
        return PS_MEM_FAIL;
    }

    while (count)
    {
        psSha1Init(&ctx);
        psSha1Update(&ctx, diversifier, 64);
        psSha1Update(&ctx, saltpass, 64 + plen);
        psSha1Final(&ctx, hash);
        for (j = 1; j < iter; j++)
        {
            psSha1Init(&ctx);
            psSha1Update(&ctx, hash, SHA1_HASH_SIZE);
            psSha1Final(&ctx, hash);
        }
        /* Copy into outgoing key now */
        copy = min(cpyLen, SHA1_HASH_SIZE);
        memcpy(p, hash, copy);
        p += copy;
        count--;
        cpyLen -= copy;

        if (cpyLen > 0)
        {
            /* manipulate saltpass */
            for (j = 0; j < 64; j++)
            {
                B[j] = hash[j % SHA1_HASH_SIZE];
            }
            if (pstm_init_for_read_unsigned_bin(pool, &bigb, 64) < 0)
            {
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            if (pstm_read_unsigned_bin(&bigb, B, 64) < 0)
            {
                pstm_clear(&bigb);
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            if (pstm_init_for_read_unsigned_bin(pool, &bigone, 1) < 0)
            {
                pstm_clear(&bigb);
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            pstm_set(&bigone, 1);
            if (pstm_add(&bigb, &bigone, &bigb) < 0)
            {
                pstm_clear(&bigone);
                pstm_clear(&bigb);
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            pstm_clear(&bigone);
            for (j = 0; j < 64 + plen; j += 64)
            {
                if (pstm_init_for_read_unsigned_bin(pool, &bigtmp, 64) < 0)
                {
                    pstm_clear(&bigone);
                    pstm_clear(&bigb);
                    psFree(front, pool);
                    return PS_MEM_FAIL;
                }
                if (pstm_read_unsigned_bin(&bigtmp, saltpass + j, 64) < 0)
                {
                    pstm_clear(&bigone);
                    pstm_clear(&bigb);
                    pstm_clear(&bigtmp);
                    psFree(front, pool);
                    return PS_MEM_FAIL;
                }
                if (pstm_add(&bigb, &bigtmp, &bigtmp) < 0)
                {
                    pstm_clear(&bigone);
                    pstm_clear(&bigb);
                    pstm_clear(&bigtmp);
                    psFree(front, pool);
                    return PS_MEM_FAIL;
                }
                binsize = pstm_unsigned_bin_size(&bigtmp);
                if (binsize > 64)
                {
                    psAssert(binsize == 65);
                    if (pstm_to_unsigned_bin(pool, &bigtmp, B) < 0)
                    {
                        pstm_clear(&bigone);
                        pstm_clear(&bigb);
                        pstm_clear(&bigtmp);
                        psFree(front, pool);
                        return PS_MEM_FAIL;
                    }
                    memcpy(saltpass + j, B + 1, 64); /* truncate */
                }
                else if (binsize < 64)
                {
                    psAssert(binsize == 63);
                    memset(saltpass + j, 0x0, 1); /* pad with a zero */
                    if (pstm_to_unsigned_bin(pool, &bigtmp, saltpass + j + 1) < 0)
                    {
                        pstm_clear(&bigone);
                        pstm_clear(&bigb);
                        pstm_clear(&bigtmp);
                        psFree(front, pool);
                        return PS_MEM_FAIL;
                    }
                }
                else
                {
                    if (pstm_to_unsigned_bin(pool, &bigtmp, saltpass + j) < 0)
                    {
                        pstm_clear(&bigone);
                        pstm_clear(&bigb);
                        pstm_clear(&bigtmp);
                        psFree(front, pool);
                        return PS_MEM_FAIL;
                    }
                }
                pstm_clear(&bigtmp);
            }
            pstm_clear(&bigone);
            pstm_clear(&bigb);
        }
    }

    *out = front;
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Return value is how many bytes were parsed out of buf
 */
static int32 pkcs12import(psPool_t *pool, const unsigned char **buf,
    psSize_t bufLen, unsigned char *password, psSize_t passLen,
    unsigned char **plaintext, psSize_t *ptLen)
{
    psCipherContext_t ctx;
    const unsigned char *p, *start, *end;
    unsigned char *iv, *decryptKey, *pt;
    unsigned char salt[8];
    int32 rc, oi, asnint;
    uint32_t keyLen, ivLen;
    psSize_t tmplen, tmpint;
    short cipher;
    const short armor = PBE12;

    *plaintext = NULL;
    *ptLen = 0;
    decryptKey = NULL;

    p = start = *buf;
    end = p + bufLen;

    /* Encryption Algorithm */
    if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi,
             &tmpint)) < 0)
    {
        psTraceCrypto("Initial pkcs12import parse failure\n");
        return rc;
    }

    if (oi == OID_PKCS_PBESHA40RC2)
    {
#    ifdef USE_RC2
        cipher = AUTH_SAFE_RC2;
        keyLen = 8;
#    else
        psTraceCrypto("Must enable USE_RC2 in cryptoConfig.h to parse\n");
        return PS_UNSUPPORTED_FAIL;
#    endif
    }
    else if (oi == OID_PKCS_PBESHA3DES3)
    {
        cipher = AUTH_SAFE_3DES;
        keyLen = DES3_KEYLEN;
    }
    else
    {
        psTraceIntCrypto("Unsupported PBE algorithm %d\n", oi);
        return PS_UNSUPPORTED_FAIL;
    }

    if (armor == PBE12)
    {
        /* If PKCS12 param will be
           pkcs-12PbeParams ::= SEQUENCE {
            salt OCTET STRING,
            iterations INTEGER
           }
         */
        if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
        {
            psTraceCrypto("Initial PBE12 parse failure\n");
            return rc;
        }
        /* salt len */
        if ((uint32) (end - p) < 1 || (*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0 ||
            (uint32) (end - p) < tmplen ||
            tmplen != 8)
        {

            psTraceCrypto("Bad salt length parsing import\n");
            return PS_PARSE_FAIL;
        }
        memcpy(salt, p, tmplen);
        p += tmplen;
        /* iteration count */
        if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0)
        {
            return PS_PARSE_FAIL;
        }
        if (pkcs12pbe(pool, password, passLen, salt, 8, asnint,
                PKCS12_KEY_ID, &decryptKey, &keyLen) < 0)
        {
            psTraceCrypto("Error generating pkcs12 key\n");
            return PS_UNSUPPORTED_FAIL;
        }
        ivLen = 8;
        if (pkcs12pbe(pool, password, passLen, salt, 8, asnint,
                PKCS12_IV_ID, &iv, &ivLen) < 0)
        {
            psTraceCrypto("Error generating pkcs12 iv\n");
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            return PS_UNSUPPORTED_FAIL;
        }
    }

    /* Got the keys but we still need to find the start of the encrypted data.
        Have seen a few different BER variations at this point in the spec
        depending on what wrapper we are in. Try all that we know about
     */
    if ((uint32) (end - p) < 1)
    {
        return PS_PARSE_FAIL;
    }
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE))
    {
        p++;
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
    }
    else if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
    {
        p++;
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
        if ((uint32) (end - p) < 1 ||
            *p++ != ASN_OCTET_STRING ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
    }
    else if (*p == ASN_OCTET_STRING)
    {
        p++;
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
    }
    else
    {
        psTraceCrypto("Error finding ciphertext in pkcs12import\n");
        if (decryptKey)
        {
            memset_s(decryptKey, keyLen, 0x0, keyLen);
            psFree(decryptKey, pool);
        }
        psFree(iv, pool);
        return PS_PARSE_FAIL;
    }

    if (tmplen < 1 || (uint32) (end - p) < tmplen)
    {
        return PS_PARSE_FAIL;
    }

    /* Don't decrypt in-situ because we'll need to MAC this all later */
    if ((pt = psMalloc(pool, tmplen)) == NULL)
    {
        psTraceCrypto("Out-of-memory.  Increase SSL_KEY_POOL_SIZE\n");
        if (decryptKey)
        {
            memset_s(decryptKey, keyLen, 0x0, keyLen);
            psFree(decryptKey, pool);
        }
        psFree(iv, pool);
        return PS_MEM_FAIL;
    }
    if (cipher == AUTH_SAFE_3DES)
    {
        if ((rc = psDes3Init(&ctx.des3, iv, decryptKey)) < 0)
        {
            memset_s(&ctx, sizeof(psCipherContext_t), 0x0, sizeof(psCipherContext_t));
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            psFree(pt, pool);
            return rc;
        }
        psDes3Decrypt(&ctx.des3, p, pt, tmplen);
    }
#    ifdef USE_RC2
    if (cipher == AUTH_SAFE_RC2)
    {

        /* This is a 40-bit RC2! */
        if ((rc = psRc2Init(&ctx.rc2, iv, decryptKey, 5)) < 0)
        {
            memset_s(&ctx, sizeof(psCipherContext_t), 0x0, sizeof(psCipherContext_t));
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            psFree(pt, pool);
            return rc;
        }
        if ((rc = psRc2Decrypt(&ctx.rc2, p, pt, tmplen)) < 0)
        {
            memset_s(&ctx, sizeof(psCipherContext_t), 0x0, sizeof(psCipherContext_t));
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            psFree(pt, pool);
            return rc;
        }
    }
#    endif /* USE_RC2 */

    if (decryptKey)
    {
        memset_s(decryptKey, keyLen, 0x0, keyLen);
        psFree(decryptKey, pool);
    }
    psFree(iv, pool);

    *plaintext = pt;
    *ptLen = tmplen;
    return (int32) (p - start);
}

/******************************************************************************/
/*
    Determines what the safebag is and loads the material into the users
    data structure (cert or private key)
 */
static int32 parseSafeContents(psPool_t *pool, unsigned char *password,
    uint32 passLen, psX509Cert_t **cert, psPubKey_t *privKey,
    unsigned char *buf, uint32 totlen)
{
    psX509Cert_t *currCert, *frontCert;
    const unsigned char *p, *end;
    unsigned char *pt, *safeLen;
    psSize_t tmplen, cryptlen, tmpint;
    int32 rc, bagoi, certoi;

#    ifdef PARSE_PKCS12_SAFE_ATTRIBS
    uint32 attriblen;
    int32 attriboi;
#    endif

    p = buf;
    end = p + totlen;

    /*  SafeContents ::= SEQUENCE OF SafeBag

        SafeBag ::= SEQUENCE {
            bagId     BAG-TYPE.&id ({PKCS12BagSet})
            bagValue  [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
            bagAttributes SET OF PKCS12Attribute OPTIONAL
       } */
    if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
    {
        psTraceCrypto("Initial SafeContents parse failure\n");
        return rc;
    }

    end = p + tmplen;

    while (p < end)
    {
        /*
           bagtypes OBJECT IDENTIFIER ::= {pkcs-12 10 1}

           BAG-TYPE ::= TYPE-IDENTIFIER
            keyBag BAG-TYPE ::= {KeyBag IDENTIFIED BY {bagtypes 1}}
            pkcs8ShroudedKeyBag BAG-TYPE ::= {PKCS8ShroudedKeyBag IDENTIFIED BY
                {bagtypes 2}}
            certBag BAG-TYPE ::= {CertBag IDENTIFIED BY {bagtypes 3}}
            crlBag BAG-TYPE ::= {CRLBag IDENTIFIED BY {bagtypes 4}}
            secretBag BAG-TYPE ::= {SecretBag IDENTIFIED BY {bagtypes 5}}
            safeContentsBag BAG-TYPE ::= {SafeContents IDENTIFIED BY
                {bagtypes 6}}

           PKCS12BagSet BAG-TYPE ::= {
            keyBag | pkcs8ShroudedKeyBag | certBag | crlBag | secretBag |
                safeContentsBag, ... -- For future extensions}

         */
        if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &bagoi,
                 &tmpint)) < 0)
        {
            psTraceCrypto("Initial BagType parse failure\n");
            return rc;
        }
        safeLen = (unsigned char *) p + tmpint;
        if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
        {
            return PS_PARSE_FAIL;
        }
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            return PS_PARSE_FAIL;
        }

        switch (bagoi)
        {
        case OID_PKCS12_BAG_TYPE_CERT:
            /*
               CertBag ::= SEQUENCE {
               certId    BAG-TYPE.&id   ({CertTypes}),
               certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId}) }

               x509Certificate BAG-TYPE ::=
                {OCTET STRING IDENTIFIED BY {certTypes 1}}
                -- DER-encoded X.509 certificate stored in OCTET STRING
               sdsiCertificate BAG-TYPE ::=
                {IA5String IDENTIFIED BY {certTypes 2}}
                -- Base64-encoded SDSI certificate stored in IA5String

               CertTypes BAG-TYPE ::= {
                x509Certificate |
                sdsiCertificate,
                ... -- For future extensions
               }
             */
            if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p),
                     &certoi, &tmpint)) < 0)
            {
                psTraceCrypto("Initial CertBag parse failure\n");
                return rc;
            }
            if (certoi != OID_PKCS9_CERT_TYPE_X509)
            {
                psTraceIntCrypto("Unsupported CertBag type %d\n", certoi);
                return PS_UNSUPPORTED_FAIL;
            }
            if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
            {
                return PS_PARSE_FAIL;
            }
            if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return rc;
            }
            if ((*p++ != ASN_OCTET_STRING) ||
                getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
            {
                psTraceCrypto("Couldn't extract X509 CertBag\n");
                return PS_FAILURE;
            }
            /* Support cert chains */
            currCert = frontCert = *cert;
            while (currCert != NULL)
            {
                currCert = currCert->next;
            }
            if ((rc = psX509ParseCert(pool, p, tmplen, &currCert,
                     CERT_STORE_UNPARSED_BUFFER)) < 0)
            {
                psX509FreeCert(currCert);
                *cert = NULL;
                psTraceCrypto("Couldn't parse certificate from CertBag\n");
                return rc;
            }
            if (*cert == NULL)
            {
                *cert = currCert;
            }
            else
            {
                while (frontCert->next != NULL)
                {
                    frontCert = frontCert->next;
                }
                frontCert->next = currCert;
            }
            p += rc;
            break;

        case OID_PKCS12_BAG_TYPE_SHROUD:
            /* A PKCS8ShroudedKeyBag holds a private key, which has been
                shrouded in accordance with PKCS #8.  Note that a
                PKCS8ShroudedKeyBag holds only one shrouded private key. */
            if (getAsnSequence(&p, (int32) (end - p), &tmplen) < 0)
            {
                psTraceCrypto("Initial PKCS8 ShroudKeyBag parse failure\n");
                return PS_PARSE_FAIL;
            }
            if ((rc = pkcs12import(pool, &p,
                     (int32) (end - p), password, passLen, &pt, &cryptlen)) < 0)
            {
                psTraceIntCrypto("Import failed from AuthSafe %d\n", rc);
                return rc;
            }
            p += rc;
            /* Result of decrypt will be a PKCS#8 key */
            if ((rc = psPkcs8ParsePrivBin(pool, pt, cryptlen, NULL, privKey))
                < 0)
            {
                psFree(pt, pool);
                psTraceIntCrypto("Failed shroud PKCS8 key parse %d\n", rc);
                return rc;
            }
            psFree(pt, pool);
            p += cryptlen;
            break;
        case OID_PKCS12_BAG_TYPE_KEY:
            if ((rc = psPkcs8ParsePrivBin(pool, (unsigned char *) p, tmplen,
                     NULL, privKey)) < 0)
            {
                psTraceIntCrypto("Failed PKCS8 key parse %d\n", rc);
                return rc;
            }
            p += tmplen;
            break;
        default:
            psTraceIntCrypto("Unsupported BAG_TYPE %d\n", bagoi);
            return PS_UNSUPPORTED_FAIL;
        }

        /* Attributes are at the end of the data */
        while (p != safeLen)
        {
#    ifdef PARSE_PKCS12_SAFE_ATTRIBS
            /**/
            if ((rc = getAsnSet(&p, (int32) (end - p), &attriblen)) < 0)
            {
                return rc;
            }
            if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &attriboi,
                     &pLen)) < 0)
            {
                return rc;
            }
            if ((rc = getAsnSet(&p, (int32) (end - p), &attriblen)) < 0)
            {
                return rc;
            }
            if ((*p++ != ASN_OCTET_STRING) ||
                getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
            {
                psTraceCrypto("Couldn't parse PKCS#8 param salt\n");
                return PS_FAILURE;
            }
            p += tmplen;
#    else
            p = safeLen;
#    endif
        }
    }
    return totlen;
}

/******************************************************************************/
/*
    AuthenticatedSafe ::= SEQUENCE OF ContentInfo
        -- Data if unencrypted
        -- EncryptedData if password-encrypted
        -- EnvelopedData if public key-encrypted
 */
static int32 psParseAuthenticatedSafe(psPool_t *pool, psX509Cert_t **cert,
    psPubKey_t *privKey, unsigned char *importPass, int32 ipassLen,
    unsigned char **buf, int32 totLen)
{
    const unsigned char *p, *end;
    unsigned char *pt;
    psSize_t tmplen, tmpint;
    int32_t asnint;
    int32 rc, oi;

    p = *buf;
    end = p + totLen;
    if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
    {
        psTraceCrypto("Initial authenticated safe parse failure\n");
        return rc;
    }

    end = p + tmplen; /* Set end to be end of authSafe for list walk */

    while (p < end)
    {
        if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi,
                 &tmpint)) < 0)
        {
            psTraceCrypto("Initial content info parse failure\n");
            return rc;
        }
        if (oi == OID_PKCS7_ENCRYPTED_DATA)
        {
            /* password protected mode */
            if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
            {
                psTraceCrypto("Initial pkcs7 encrypted data parse failure\n");
                return PS_PARSE_FAIL;
            }
            if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return PS_PARSE_FAIL;
            }
            /* EncryptedData ::= SEQUENCE {
                version Version,
                encryptedContentInfo EncryptedContentInfo } */
            if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return rc;
            }
            /* Version */
            if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0 ||
                asnint != 0)
            {
                psTraceIntCrypto("Unsupported encryptd data version %d\n",
                    asnint);
                return PS_UNSUPPORTED_FAIL;
            }
            /*
               EncryptedContentInfo ::= SEQUENCE {
                contentType     ContentType,
                contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
                encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

               5.1 2b) If SCi is to be encrypted with a password, make a
               ContentInfo CIi of type EncryptedData.  The encryptedContentInfo
               field of CIi has its contentType field set to data and its
               encryptedContent field set to the encryption of the BER-encoding
               of SCi (note that the tag and length octets shall be present). */
            if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi,
                     &tmpint)) < 0)
            {
                psTraceCrypto("Initial EncryptedContentInfo parse failure\n");
                return rc;
            }
            psAssert(oi == OID_PKCS7_DATA);

            if ((rc = pkcs12import(pool, &p, (int32) (end - p), importPass,
                     ipassLen, &pt, &tmplen)) < 0)
            {
                psTraceIntCrypto("Import failed from AuthSafe %d\n", rc);
                return rc;
            }
            p += rc;

            /* pt is now a BER-encoded SafeContents */
            if ((rc = parseSafeContents(pool, importPass, ipassLen, cert,
                     privKey, pt, tmplen)) < 0)
            {
                psTraceCrypto("Error parsing encrypted safe contents\n");
                psTraceCrypto("Is it possible the password is incorrect?\n");
                psFree(pt, pool);
                return rc;
            }
            psFree(pt, pool);
            p += rc;
        }
        else if (oi == OID_PKCS7_DATA)
        {
            /* Data ::= OCTET STRING */
            if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
            {
                psTraceCrypto("Initial pkcs7 data parse failure\n");
                return PS_PARSE_FAIL;
            }
            if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return PS_PARSE_FAIL;
            }
            if (*p++ != ASN_OCTET_STRING || getAsnLength(&p,
                    (int32) (end - p), &tmplen) < 0)
            {
                return PS_PARSE_FAIL;
            }
            if ((rc = parseSafeContents(pool, importPass, ipassLen, cert,
                     privKey, (unsigned char *) p, tmplen)) < 0)
            {
                psTraceCrypto("Error parsing plaintext safe contents\n");
                return rc;
            }
            p += rc;
        }
        else
        {
            psTraceIntCrypto("Unsupported PKCS7 data type parse %d\n", oi);
            return PS_UNSUPPORTED_FAIL;
        }
    }

    *buf = (unsigned char *) p;
    return PS_SUCCESS;
}

/******************************************************************************/
/*

    MacData ::= SEQUENCE {
        mac DigestInfo,
        macSalt OCTET STRING,
        iterations INTEGER DEFAULT 1
    }
 */
int32 psPkcs12Parse(psPool_t *pool, psX509Cert_t **cert, psPubKey_t *privKey,
    const unsigned char *file, int32 flags, unsigned char *password,
    int32 pLen, unsigned char *macPass, int32 macPassLen)
{
    psHmacSha1_t hmac;
    const unsigned char *p, *end, *macStart, *macEnd;
    unsigned char *fileBuf, *macKey;
    unsigned char iwidePass[128];   /* 63 char password max */
    unsigned char mwidePass[128];
    unsigned char mac[SHA1_HASH_SIZE];
    unsigned char macSalt[20];
    unsigned char digest[SHA1_HASH_SIZE];
    psSize_t tmplen, tmpint;
    uint32 digestLen, macKeyLen;
    int32 fsize, i, j, rc, mpassLen, ipassLen, integrity, oi, asnint;

    *cert = NULL;
    if ((rc = psGetFileBuf(pool, (char *) file, &fileBuf, &fsize)) < PS_SUCCESS)
    {
        psTraceStrCrypto("Couldn't open PKCS#12 file %s\n", (char *) file);
        return rc;
    }
    p = fileBuf;
    end = p + fsize;

    /* Begin with a PFX
        PFX ::= SEQUENCE {
        version INTEGER {v3(3)}(v3,...),
        authSafe ContentInfo,
        macData    MacData OPTIONAL } */
    if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
    {
        psTraceCrypto("Initial PKCS#12 parse fail\n");
        goto ERR_FBUF;
    }
    /* Version */
    if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0 || asnint != 3)
    {
        psTraceIntCrypto("Unsupported PKCS#12 version %d\n", asnint);
        rc = PS_UNSUPPORTED_FAIL;
        goto ERR_FBUF;
    }

    /* Content type is the integrity mode (4 of the spec).
        signedData for public-key integrity or data for password integrity */
    if ((integrity = psParseIntegrityMode(&p, (int32) (end - p)))
        < PS_SUCCESS)
    {
        psTraceCrypto("Couldn't determine PKCS#12 integrity\n");
        rc = integrity;
        goto ERR_FBUF;
    }

    /* Passwords are wide BMPString types
        ipass is import password
        mpass is MAC password */
    ipassLen = (pLen * 2) + 2; /* 2 for each char put double 0x0 to terminate */
    memset(iwidePass, 0x0, ipassLen);
    for (i = 1, j = 0; i < ipassLen - 1; i += 2, j++)
    {
        iwidePass[i] = password[j];
    }

    /* Content data is an AuthenticatedSafe */
    macStart = p;
    if ((rc = psParseAuthenticatedSafe(pool, cert, privKey, iwidePass, ipassLen,
             (unsigned char **) &p, (int32) (end - p))) < PS_SUCCESS)
    {
        psTraceIntCrypto("PKCS#12 AuthenticatedSafe parse failure %d\n", rc);
        goto ERR_FBUF;
    }
    macEnd = p;

    /* Integrity validation */
    if (integrity == PASSWORD_INTEGRITY)
    {
        mpassLen = (macPassLen * 2) + 2;
        memset(mwidePass, 0x0, mpassLen);
        for (i = 1, j = 0; i < mpassLen - 1; i += 2, j++)
        {
            mwidePass[i] = macPass[j];
        }
        /* MacData ::= SEQUENCE {
            mac                 DigestInfo,
            macSalt             OCTET STRING,
            iterations  INTEGER DEFAULT 1
            -- Note: The default is for historical reasons and its use is
            -- deprecated. A higher value, like 1024 is recommended. } */
        if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
        {
            psTraceCrypto("Initial password integrity parse failure\n");
            goto ERR_FBUF;
        }
        /* DigestInfo ::= SEQUENCE {
            digestAlgorithm DigestAlgorithmIdentifier,
            digest          Digest } */
        if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
        {
            psTraceCrypto("Sequence password integrity parse failure\n");
            goto ERR_FBUF;
        }
        if ((rc = getAsnAlgorithmIdentifier(&p, (uint32) (end - p),
                 &oi, &tmpint)) < 0)
        {
            psTraceCrypto("Algorithm password integrity parse failure\n");
            goto ERR_FBUF;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
        {
            psTraceCrypto("Octet digest password integrity parse failure\n");
            rc = PS_PARSE_FAIL;
            goto ERR_FBUF;
        }
        memcpy(digest, p, tmplen);
        p += tmplen;
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
        {
            psTraceCrypto("Octet macSalt password integrity parse failure\n");
            rc = PS_PARSE_FAIL;
            goto ERR_FBUF;
        }
        if (tmplen > 20)
        {
            psTraceCrypto("macSalt length too long\n");
            rc = PS_PARSE_FAIL;
            goto ERR_FBUF;
        }
        memcpy(macSalt, p, tmplen);
        p += tmplen;
        /* Iteration count */
        if (p != end)
        {
            if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0)
            {
                psTraceCrypto("Iteration password integrity parse failure\n");
                rc = PS_PARSE_FAIL;
                goto ERR_FBUF;
            }
        }
        else
        {
            asnint = 0;
        }
        psAssert(p == end); /* That's all folks */

        if (oi == OID_SHA1_ALG)
        {
            /* When password integrity mode is used to secure a PFX PDU,
                an SHA-1 HMAC is computed on the BER-encoding of the contents
                of the content field of the authSafe field in the PFX PDU */
            macKeyLen = 20;
            if (pkcs12pbe(pool, mwidePass, mpassLen, macSalt, tmplen,
                    asnint, PKCS12_MAC_ID, &macKey, &macKeyLen) < 0)
            {
                psTraceCrypto("Error generating pkcs12 hmac key\n");
                rc = PS_UNSUPPORTED_FAIL;
                goto ERR_FBUF;
            }
            digestLen = (uint32) (macEnd - macStart);
            psHmacSha1Init(&hmac, macKey, macKeyLen);
            psHmacSha1Update(&hmac, macStart, digestLen);
            psHmacSha1Final(&hmac, mac);
            psFree(macKey, pool);
            if (memcmp(digest, mac, SHA1_HASH_SIZE) != 0)
            {
                psTraceCrypto("CAUTION: PKCS#12 MAC did not validate\n");
            }
        }
        else
        {
            psTraceCrypto("PKCS#12 must use SHA1 HMAC validation\n");
            rc = PS_UNSUPPORTED_FAIL;
            goto ERR_FBUF;
        }

    }
    rc = PS_SUCCESS;
ERR_FBUF:
    memset_s(iwidePass, sizeof(iwidePass), 0x0, sizeof(iwidePass));
    memset_s(mwidePass, sizeof(mwidePass), 0x0, sizeof(mwidePass));
    psFree(fileBuf, pool);
    return rc;
}

#   endif /* USE_PKCS12 */
#  endif  /* MATRIX_USE_FILE_SYSTEM */

# endif   /* USE_PKCS8 */

# ifdef MATRIX_USE_FILE_SYSTEM

#  if defined(USE_PKCS5) && defined(USE_PBKDF1)
/******************************************************************************/
/*
    Convert an ASCII hex representation to a binary buffer.
    Decode enough data out of 'hex' buffer to produce 'binlen' bytes in 'bin'
    Two digits of ASCII hex map to the high and low nybbles (in that order),
    so this function assumes that 'hex' points to 2x 'binlen' bytes of data.
    Return the number of bytes processed from hex (2x binlen) or < 0 on error.
 */
static int32 hexToBinary(unsigned char *hex, unsigned char *bin, int32 binlen)
{
    unsigned char *end, c, highOrder;

    highOrder = 1;
    for (end = hex + binlen * 2; hex < end; hex++)
    {
        c = *hex;
        if ('0' <= c && c <= '9')
        {
            c -= '0';
        }
        else if ('a' <= c && c <= 'f')
        {
            c -= ('a' - 10);
        }
        else if ('A' <= c && c <= 'F')
        {
            c -= ('A' - 10);
        }
        else
        {
            psTraceCrypto("hexToBinary failure\n");
            return PS_FAILURE;
        }
        if (highOrder++ & 0x1)
        {
            *bin = c << 4;
        }
        else
        {
            *bin |= c;
            bin++;
        }
    }
    return binlen * 2;
}
#  endif /* USE_PKCS5 && USE_PBKDF1 */

#  ifdef USE_RSA
int32_t psPkcs1ParsePubFile(psPool_t *pool, const char *fileName, psRsaKey_t *key)
{
    unsigned char *DERout;
    unsigned char sha1KeyHash[SHA1_HASH_SIZE];
    const unsigned char *p, *end;
    int32_t rc, oi;
    psSize_t DERlen, seqlen, plen;

    /* Had to tweak psPkcs1DecodePrivFile to accept PUBLIC KEY headers */
    if ((rc = psPkcs1DecodePrivFile(pool, fileName, NULL, &DERout, &DERlen))
        < PS_SUCCESS)
    {
        return rc;
    }

    p = DERout;
    end = p + DERlen;

    if (getAsnSequence(&p, (int32) (end - p), &seqlen) < 0)
    {
        psTraceCrypto("Couldn't parse PKCS#1 RSA public key file\n");
        goto pubKeyFail;
    }
    if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi, &plen) < 0)
    {
        psTraceCrypto("Couldn't parse PKCS#1 RSA public key file\n");
        goto pubKeyFail;
    }
    if (oi != OID_RSA_KEY_ALG)
    {
        psTraceCrypto("Couldn't parse PKCS#1 RSA public key file\n");
        goto pubKeyFail;
    }
    if (psRsaParseAsnPubKey(pool, &p, (int32) (end - p), key, sha1KeyHash) < 0)
    {
        psTraceCrypto("Couldn't parse PKCS#1 RSA public key file\n");
        goto pubKeyFail;
    }

    psFree(DERout, pool);
    return PS_SUCCESS;

pubKeyFail:
    psFree(DERout, pool);
    return PS_PARSE_FAIL;
}
/******************************************************************************/
/**
    Parse a PEM format private key file.

    @pre File must be a PEM format RSA keys.
    @return < 0 on error
 */
int32_t psPkcs1ParsePrivFile(psPool_t *pool, const char *fileName,
    const char *password, psRsaKey_t *key)
{
    unsigned char *DERout;
    int32_t rc;
    psSize_t DERlen;

#   ifdef USE_PKCS8
    psPubKey_t pubkey;
#   endif

    if ((rc = psPkcs1DecodePrivFile(pool, fileName, password, &DERout, &DERlen))
        < PS_SUCCESS)
    {
        return rc;
    }

    if ((rc = psRsaParsePkcs1PrivKey(pool, DERout, DERlen, key)) < 0)
    {
#   ifdef USE_PKCS8
        /* This logic works for processing PKCS#8 files because the above file
            and bin decodes will always leave the unprocessed buffer intact and
            the password protection is done in the internal ASN.1 encoding */
        if ((rc = psPkcs8ParsePrivBin(pool, DERout, DERlen, (char *) password,
                 &pubkey)) < 0)
        {
            psFree(DERout, pool);
            return rc;
        }
        rc = psRsaCopyKey(key, &pubkey.key.rsa);
        psClearPubKey(&pubkey);
#   else
        psFree(DERout, pool);
        return rc;
#   endif
    }

    psFree(DERout, pool);
    return rc;
}
#  endif /* USE_RSA */

/******************************************************************************/
/**
    Return the DER stream from a private key PEM file.

    Memory info:
        Caller must call psFree on DERout on function success
 */
int32_t psPkcs1DecodePrivFile(psPool_t *pool, const char *fileName,
    const char *password, unsigned char **DERout, psSize_t *DERlen)
{
    unsigned char *keyBuf, *dout;
    char *start, *end, *endTmp;
    int32 keyBufLen, rc;
    uint32 PEMlen = 0;

#  if defined(USE_PKCS5) && defined(USE_PBKDF1)
    psDes3_t dctx;
    psAesCbc_t actx;
    unsigned char passKey[32];   /* AES-256 max */
    unsigned char cipherIV[16];  /* AES-256 max */
    int32 tmp, encrypted = 0;

    static const char des3encryptHeader[]   = "DEK-Info: DES-EDE3-CBC,";
    static const char aes128encryptHeader[] = "DEK-Info: AES-128-CBC,";
#  endif /* USE_PKCS5 && USE_PBKDF1 */

    if (fileName == NULL)
    {
        psTraceCrypto("No fileName passed to psPkcs1DecodePrivFile\n");
        return PS_ARG_FAIL;
    }
    if ((rc = psGetFileBuf(pool, fileName, &keyBuf, &keyBufLen)) < PS_SUCCESS)
    {
        return rc;
    }
    start = end = NULL;

    /* Check header and encryption parameters. */
    if (((start = strstr((char *) keyBuf, "-----BEGIN")) != NULL) &&
        ((start = strstr((char *) keyBuf, "PRIVATE KEY-----")) != NULL) &&
        ((end = strstr(start, "-----END")) != NULL) &&
        ((endTmp = strstr(end, "PRIVATE KEY-----")) != NULL))
    {
        start += strlen("PRIVATE KEY-----");
        while (*start == '\x0d' || *start == '\x0a')
        {
            start++;
        }
        PEMlen = (uint32) (end - start);
    }
    else if (((start = strstr((char *) keyBuf, "-----BEGIN")) != NULL) &&
             ((start = strstr((char *) keyBuf, "PUBLIC KEY-----")) != NULL) &&
             ((end = strstr(start, "-----END")) != NULL) &&
             ((endTmp = strstr(end, "PUBLIC KEY-----")) != NULL))
    {
        start += strlen("PUBLIC KEY-----");
        while (*start == '\x0d' || *start == '\x0a')
        {
            start++;
        }
        PEMlen = (uint32) (end - start);
    }
    else
    {
        psTraceCrypto("File buffer does not look to be in PKCS#1 PEM format\n");
        psFree(keyBuf, pool);
        return PS_PARSE_FAIL;
    }

    if (strstr((char *) keyBuf, "Proc-Type:") &&
        strstr((char *) keyBuf, "4,ENCRYPTED"))
    {
#  if defined(USE_PKCS5) && defined(USE_PBKDF1)
        if (password == NULL)
        {
            psTraceCrypto("No password given for encrypted private key file\n");
            psFree(keyBuf, pool);
            return PS_ARG_FAIL;
        }
        if ((start = strstr((char *) keyBuf, des3encryptHeader)) != NULL)
        {
            start += strlen(des3encryptHeader);
            encrypted = 1;
            /* we assume here that header points to at least 16 bytes of data */
            tmp = hexToBinary((unsigned char *) start, cipherIV, DES3_IVLEN);
        }
        else if ((start = strstr((char *) keyBuf, aes128encryptHeader))
                 != NULL)
        {
            start += strlen(aes128encryptHeader);
            encrypted = 2;
            /* we assume here that header points to at least 32 bytes of data */
            tmp = hexToBinary((unsigned char *) start, cipherIV, 16);
        }
        else
        {
            psTraceCrypto("Unrecognized private key file encoding\n");
            psFree(keyBuf, pool);
            return PS_PARSE_FAIL;
        }

        if (tmp < 0)
        {
            psTraceCrypto("Invalid private key file salt\n");
            psFree(keyBuf, pool);
            return PS_FAILURE;
        }
        start += tmp;
        if (psPkcs5Pbkdf1((unsigned char *) password, strlen(password),
                cipherIV, 1, (unsigned char *) passKey) < 0)
        {
            psTraceCrypto("psPkcs5Pbkdf1 failed\n");
            psFree(keyBuf, pool);
            return PS_FAILURE;
        }
        PEMlen = (int32) (end - start);
#  else /* !USE_PKCS5 || !USE_PBKDF1 */
        /* The private key is encrypted, but PKCS5 support has been turned off */
#   ifndef USE_PKCS5
        psTraceCrypto("USE_PKCS5 must be enabled for key file password\n");
#   endif /* USE_PKCS5 */
#   ifndef USE_PBKDF1
        psTraceCrypto("USE_PBKDF1 must be enabled for key file password\n");
#   endif /* USE_PBKDF1 */
        psFree(keyBuf, pool);
        return PS_UNSUPPORTED_FAIL;
#  endif /* USE_PKCS5 && USE_PBKDF1 */
    }

    /* Take the raw input and do a base64 decode */
    dout = psMalloc(pool, PEMlen);
    if (dout == NULL)
    {
        psFree(keyBuf, pool);
        psError("Memory allocation error in psPkcs1DecodePrivFile\n");
        return PS_MEM_FAIL;
    }
    *DERlen = PEMlen;
    if ((rc = psBase64decode((unsigned char *) start, PEMlen, dout,
             DERlen)) < 0)
    {
        psTraceCrypto("Error base64 decode of private key\n");
        if (password)
        {
            psTraceCrypto("Is it possible the password is incorrect?\n");
        }
        psFree(dout, pool);
        psFree(keyBuf, pool);
        return rc;
    }
    psFree(keyBuf, pool);

#  if defined(USE_PKCS5) && defined(USE_PBKDF1)
    if (encrypted == 1 && password)
    {
        psDes3Init(&dctx, cipherIV, passKey);
        psDes3Decrypt(&dctx, dout, dout, *DERlen);
        memset_s(&dctx, sizeof(psDes3_t), 0x0, sizeof(psDes3_t));
    }
    if (encrypted == 2 && password)
    {
        /* AES 128 */
        psAesInitCBC(&actx, cipherIV, passKey, 16, PS_AES_DECRYPT);
        psAesDecryptCBC(&actx, dout, dout, *DERlen);
        memset_s(&actx, sizeof(psAesCbc_t), 0x0, sizeof(psAesCbc_t));
    }
    /* SECURITY - zero out keys when finished */
    memset_s(passKey, sizeof(passKey), 0x0, sizeof(passKey));
#  endif /* USE_PKCS5 && USE_PBKDF1 */
    *DERout = dout;

    return PS_SUCCESS;
}

# endif /* MATRIX_USE_FILE_SYSTEM */
#endif  /* USE_PRIVATE_KEY_PARSING */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_PKCS5
# ifdef USE_PBKDF1
/******************************************************************************/
/*
   Generate a key given a password and salt value.
   PKCS#5 2.0 PBKDF1 key derivation format with MD5 and count == 1 per:
   http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html

   This key is compatible with the algorithm used by OpenSSL to encrypt keys
   generated with 'openssl genrsa'.  If other encryption formats are used
   (for example PBKDF2), or an iteration count != 1 is used, they are not
   compatible with this simple implementation.  OpenSSL provides many options
   for converting key formats to the one used here.

   A 3DES key is 24 bytes long, to generate it with this algorithm,
   we md5 hash the password and salt for the first 16 bytes.  We then
   hash these first 16 bytes with the password and salt again, generating
   another 16 bytes.  We take the first 16 bytes and 8 of the second 16 to
   form the 24 byte key.

   salt is assumed to point to 8 bytes of data
   key is assumed to point to 24 bytes of data
 */
int32_t psPkcs5Pbkdf1(unsigned char *pass, uint32 passlen, unsigned char *salt,
    int32 iter, unsigned char *key)
{
    int32_t rc;
    psDigestContext_t md;
    unsigned char md5[MD5_HASH_SIZE];

    psAssert(iter == 1);

    rc = psMd5Init(&md.md5);
    if (rc != PS_SUCCESS)
    {
        psTraceCrypto("psMd5Init failed. Please ensure non-FIPS mode.\n");
        return rc;
    }
    psMd5Update(&md.md5, pass, passlen);
    psMd5Update(&md.md5, salt, 8);
    psMd5Final(&md.md5, md5);
    memcpy(key, md5, MD5_HASH_SIZE);

    rc = psMd5Init(&md.md5);
    if (rc != PS_SUCCESS)
    {
        psTraceCrypto("psMd5Init failed. Please ensure non-FIPS mode.\n");
        return rc;
    }

    psMd5Update(&md.md5, md5, MD5_HASH_SIZE);
    psMd5Update(&md.md5, pass, passlen);
    psMd5Update(&md.md5, salt, 8);
    psMd5Final(&md.md5, md5);
    memcpy(key + MD5_HASH_SIZE, md5, 24 - MD5_HASH_SIZE);

    memset_s(md5, MD5_HASH_SIZE, 0x0, MD5_HASH_SIZE);
    memset_s(&md, sizeof(psDigestContext_t), 0x0, sizeof(psDigestContext_t));
    return PS_SUCCESS;
}
# endif /* USE_PBKDF1 */

# if defined(USE_HMAC_SHA1)
/******************************************************************************/
/*
    Generate a key given a password, salt and iteration value.
    PKCS#5 2.0 PBKDF2 key derivation format with HMAC-SHA per:
    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html

    Given a password, a salt, and an iteration count (rounds), generate a
    key suitable for encrypting data with 3DES, AES, etc.
    key should point to storage as large as kLen
 */
void psPkcs5Pbkdf2(unsigned char *password, uint32 pLen,
    unsigned char *salt, uint32 sLen, int32 rounds,
    unsigned char *key, uint32 kLen)
{
    int32 itts;
    uint32 blkno;
    unsigned long stored, left, i;
    unsigned char buf[2][SHA1_HASH_SIZE];
    psHmacSha1_t hmac;

    psAssert(password && salt && key && kLen);

    left   = kLen;
    blkno  = 1;
    stored = 0;
    while (left != 0)
    {
        /* process block number blkno */
        memset(buf[0], 0x0, SHA1_HASH_SIZE * 2);

        /* store current block number and increment for next pass */
        STORE32H(blkno, buf[1]);
        ++blkno;

        /* get PRF(P, S||int(blkno)) */
        psHmacSha1Init(&hmac, password, pLen);
        psHmacSha1Update(&hmac, salt, sLen);
        psHmacSha1Update(&hmac, buf[1], 4);
        psHmacSha1Final(&hmac, buf[0]);

        /* now compute repeated and XOR it in buf[1] */
        memcpy(buf[1], buf[0], SHA1_HASH_SIZE);
        for (itts = 1; itts < rounds; ++itts)
        {
            psHmacSha1Init(&hmac, password, pLen);
            psHmacSha1Update(&hmac, buf[0], SHA1_HASH_SIZE);
            psHmacSha1Final(&hmac, buf[0]);
            for (i = 0; i < SHA1_HASH_SIZE; i++)
            {
                buf[1][i] ^= buf[0][i];
            }
        }
        /* now emit upto x bytes of buf[1] to output */
        for (i = 0; i < SHA1_HASH_SIZE && left != 0; ++i)
        {
            key[stored++] = buf[1][i];
            --left;
        }
    }

    memset_s(buf, SHA1_HASH_SIZE * 2, 0x0, SHA1_HASH_SIZE * 2);
    memset_s(&hmac, sizeof(psHmacSha1_t), 0x0, sizeof(psHmacSha1_t));
}
# endif /* USE_HMAC && USE_SHA1 */
#endif  /* USE_PKCS5 */

#if defined(USE_DH) && defined(MATRIX_USE_FILE_SYSTEM)
/******************************************************************************/
/**
    Extract Diffie-Hellman parameters from a PEM encoded file.
    This API decodes the PEM format and passes the ASN.1 encoded parameters
    to psPkcs3ParseDhParamBin() to parse the ASN.1.

    @param pool Memory pool
    @param[in] fileName File name of PEM encoded ASN.1 to load.
    @param[in,out] params Allocated parameter structure to receive parsed
        params.
    @return < on error.
 */
int32_t psPkcs3ParseDhParamFile(psPool_t *pool, const char *fileName, psDhParams_t *params)
{
    unsigned char *pemOut, *p;
    char *dhFileBuf, *start, *end;
    int32_t rc;
    psSize_t baseLen, pemOutLen;
    int32_t dhFileLen;

    if (!params || !fileName)
    {
        return PS_ARG_FAIL;
    }
    /* This is part of key assignment at startup.  Base pool is fine here */
    if ((rc = psGetFileBuf(pool, fileName,
             (unsigned char **) &dhFileBuf, &dhFileLen)) < 0)
    {
        return rc;
    }
    /* Set end to end of file buffer */
    end = dhFileBuf + dhFileLen;
    /* Set start to start of token */
    if ((start = strstr(dhFileBuf, "-----BEGIN DH PARAMETERS-----")) == NULL)
    {
        psTraceStrCrypto("Error parsing dh file buffer header: %s\n", fileName);
        psFree(dhFileBuf, pool);
        return PS_PARSE_FAIL;
    }
    /* Move start to start of PEM data, skipping CR/LF */
    start += 29; /* strlen("-----BEGIN DH PARAMETERS-----"); */
    while (start < end && (*start == '\x0d' || *start == '\x0a'))
    {
        start++;
    }
    /* Set end to end token */
    if ((end = strstr(start, "-----END DH PARAMETERS-----")) == NULL)
    {
        psTraceStrCrypto("Error parsing dh file buffer footer: %s\n", fileName);
        psFree(dhFileBuf, pool);
        return PS_PARSE_FAIL;
    }
    baseLen = (uint16_t) (end - start);

    p = NULL;
    p = pemOut = psMalloc(pool, baseLen);
    if (p == NULL)
    {
        psError("Memory allocation error in psPkcs3ParseDhParamFile\n");
        psFree(dhFileBuf, pool);
        return PS_MEM_FAIL;
    }

    pemOutLen = baseLen;
    if (psBase64decode((unsigned char *) start, baseLen, p, &pemOutLen) != 0)
    {
        psFree(dhFileBuf, pool);
        psFree(pemOut, pool);
        return PS_PARSE_FAIL;
    }
    psFree(dhFileBuf, pool);

    if ((rc = psPkcs3ParseDhParamBin(pool, p, pemOutLen, params)) < 0)
    {
        psFree(pemOut, pool);
        return rc;
    }
    psFree(pemOut, pool);
    return 0;
}
#endif /* USE_DH && MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/

/******************************************************************************/
#if defined(USE_PKCS1_OAEP) || defined(USE_PKCS1_PSS)
/*
    The reason we weren't able to create a callback structure for the hash
    routines was because of the Mac relocation build errors related to
    the register usage when assembly code is used in pstm
 */
/******************************************************************************/
/*
    Perform PKCS #1 Mask Generation Function (internal)
    pool                Memory pool
    seed        The seed for MGF1
    seedlen     The length of the seed
    hash_idx    The index of the hash desired
    mask        [out] The destination
    masklen     The length of the mask desired
    return 0 if successful
 */
static int32 pkcs_1_mgf1(psPool_t *pool, const unsigned char *seed,
    unsigned long seedlen, int32 hash_idx, unsigned char *mask,
    unsigned long masklen)
{
    unsigned long hLen, x;
    uint32 counter;
    psDigestContext_t md;
    unsigned char *buf;

    if ((seed == NULL) || (mask == NULL))
    {
        return -1;
    }
    hLen = 0;
/*
    Get hash output size.  Index has already been verified by caller so
    don't need 'else' error cases
 */
    if (hash_idx == PKCS1_SHA1_ID)
    {
        hLen = SHA1_HASH_SIZE;
    }
    else if (hash_idx == PKCS1_MD5_ID)
    {
        hLen = MD5_HASH_SIZE;
# ifdef USE_SHA256
    }
    else if (hash_idx == PKCS1_SHA256_ID)
    {
        hLen = SHA256_HASH_SIZE;
# endif
# ifdef USE_SHA384
    }
    else if (hash_idx == PKCS1_SHA384_ID)
    {
        hLen = SHA384_HASH_SIZE;
# endif
# ifdef USE_SHA512
    }
    else if (hash_idx == PKCS1_SHA512_ID)
    {
        hLen = SHA512_HASH_SIZE;
# endif
    }
    else
    {
        return PS_UNSUPPORTED_FAIL;
    }

    buf = psMalloc(pool, hLen);
    if (buf == NULL)
    {
        psTraceCrypto("Memory allocation error in MGF\n");
        return -1;
    }
/*
    Start counter
 */
    counter = 0;

    while (masklen > 0)
    {
        /* handle counter */
        STORE32H(counter, buf);
        ++counter;

/*
        Get hash of seed || counter
 */
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.sha1);
            psSha1Update(&md.sha1, seed, seedlen);
            psSha1Update(&md.sha1, buf, 4);
            psSha1Final(&md.sha1, buf);
# ifdef USE_MD5
        }
        else if (hash_idx == PKCS1_MD5_ID)
        {
            psMd5Init(&md.md5);
            psMd5Update(&md.md5, seed, seedlen);
            psMd5Update(&md.md5, buf, 4);
            psMd5Final(&md.md5, buf);
# endif     /* USE_MD5 */
# ifdef USE_SHA256
        }
        else if (hash_idx == PKCS1_SHA256_ID)
        {
            psSha256Init(&md.sha256);
            psSha256Update(&md.sha256, seed, seedlen);
            psSha256Update(&md.sha256, buf, 4);
            psSha256Final(&md.sha256, buf);
# endif
# ifdef USE_SHA384
        }
        else if (hash_idx == PKCS1_SHA384_ID)
        {
            psSha384Init(&md.sha384);
            psSha384Update(&md.sha384, seed, seedlen);
            psSha384Update(&md.sha384, buf, 4);
            psSha384Final(&md.sha384, buf);
# endif
# ifdef USE_SHA512
        }
        else if (hash_idx == PKCS1_SHA512_ID)
        {
            psSha512Init(&md.sha512);
            psSha512Update(&md.sha512, seed, seedlen);
            psSha512Update(&md.sha512, buf, 4);
            psSha512Final(&md.sha512, buf);
# endif
        }

        /* store it */
        for (x = 0; x < hLen && masklen > 0; x++, masklen--)
        {
            *mask++ = buf[x];
        }
    }

    psFree(buf, pool);
    return PS_SUCCESS;
}
#endif /* defined(USE_PKCS1_OAEP) || defined(USE_PKCS1_PSS) */


#ifdef USE_PKCS1_OAEP
/******************************************************************************/
/*
    PKCS #1 v2.00 OAEP encode
    pool                        Memory pool
    msg             The data to encode
    msglen          The length of the data to encode (octets)
    lparam          A session or system parameter (can be NULL)
    lparamlen       The length of the lparam data
    seed                        Reserved for vector testing.  Should be NULL
    seedLen                     Reserved for vector testing.  Should be 0
    modulus_bitlen  The bit length of the RSA modulus
    hash_idx        The index of the hash desired (see psHashList table above)
    out             [out] The destination for the encoded data
    outlen          [in/out] The max size and resulting size of the encoded data

    return 0 if successful, -1 on failure
 */
int32 psPkcs1OaepEncode(psPool_t *pool, const unsigned char *msg, uint32 msglen,
    const unsigned char *lparam, uint32 lparamlen,
    unsigned char *seed, uint32 seedLen,
    uint32 modulus_bitlen, int32 hash_idx,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char *DB, *lseed, *mask;
    uint32 hLen, x, y, modulus_len;
    int32 err;
    psDigestContext_t md;

    if ((msg == NULL) || (out == NULL) || (outlen == NULL) || (hash_idx < 0))
    {
        psTraceStrCrypto("Bad parameter to OAEP encode\n", NULL);
        return PS_ARG_FAIL;
    }
/*
    Verify hash routines
 */
    if (hash_idx == PKCS1_SHA1_ID)
    {
        hLen = SHA1_HASH_SIZE;
    }
    else if (hash_idx == PKCS1_MD5_ID)
    {
# ifdef USE_MD5
        hLen = MD5_HASH_SIZE;
# else
        psTraceCrypto("MD5 not supported in this build.");
        psTraceCrypto(" Please enable USE_MD5\n");
        return PS_UNSUPPORTED_FAIL;
# endif /* USE_MD5 */
    }
    else
    {
        psTraceStrCrypto("Bad hash index to OAEP encode\n", NULL);
        return PS_ARG_FAIL;
    }
/*
    Seed should be generated randomly below but this helps for test vectors
 */
    if (seed != NULL && seedLen != hLen)
    {
        psTraceIntCrypto("Seed must be length of %d\n", hLen);
        return PS_ARG_FAIL;
    }

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

/*
    Test message size
 */
    if ((2 * hLen >= (modulus_len - 2)) || (msglen > (modulus_len - 2 * hLen - 2)))
    {
        psTraceStrCrypto("Bad message size to OAEP encode\n", NULL);
        return PS_LIMIT_FAIL;
    }

/*
    Allocate ram for DB/mask/salt of size modulus_len
 */
    lseed = NULL;
    DB   = psMalloc(pool, modulus_len);
    mask = psMalloc(pool, modulus_len);
    if (DB == NULL || mask == NULL)
    {
        if (DB != NULL)
        {
            psFree(DB, pool);
        }
        if (mask != NULL)
        {
            psFree(mask, pool);
        }
        psTraceCrypto("Memory allocation error in OAEP encode\n");
        return PS_MEM_FAIL;
    }

/*
    Create lhash for DB block format:

    DB == lhash || PS || 0x01 || M, PS == k - mlen - 2hlen - 2 zeroes
 */
    x = modulus_len;

    if (lparam != NULL)
    {
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.sha1);
            psSha1Update(&md.sha1, lparam, lparamlen);
            psSha1Final(&md.sha1, DB);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.md5);
            psMd5Update(&md.md5, lparam, lparamlen);
            psMd5Final(&md.md5, DB);
        }
# endif /* USE_MD5 */
    }
    else
    {
        /* can't pass hash a NULL so use DB with zero length */
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.sha1);
            psSha1Update(&md.sha1, DB, 0);
            psSha1Final(&md.sha1, DB);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.md5);
            psMd5Update(&md.md5, DB, 0);
            psMd5Final(&md.md5, DB);
        }
# endif /* USE_MD5 */
    }

/*
    Append PS then 0x01 (to lhash)
 */
    x = hLen;
    y = modulus_len - msglen - 2 * hLen - 2;
    memset(DB + x, 0, y);
    x += y;

    DB[x++] = 0x01;

/*
    Message (length = msglen)
 */
    memcpy(DB + x, msg, msglen);
    x += msglen;

/*
    Use psGetPrngLocked to choose a random seed (if not provided)
 */
    if (seed != NULL)
    {
        lseed = seed;
    }
    else
    {
        lseed = psMalloc(pool, hLen);
        if (lseed == NULL)
        {
            err = PS_MEM_FAIL;
            goto LBL_ERR;
        }
        if (psGetPrngLocked(lseed, hLen, NULL) != (int32) hLen)
        {
            psTraceCrypto("psGetPrngLocked fail in OAEP encode\n");
            err = PS_PLATFORM_FAIL;
            goto LBL_ERR;
        }
    }

/*
    Compute MGF1 of seed (k - hlen - 1)
 */
    if ((err = pkcs_1_mgf1(pool, lseed, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        psTraceStrCrypto("MGF for seed failed in OAEP encode\n", NULL);
        goto LBL_ERR;
    }

/*
    xor against DB
 */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

/*
    Compute MGF1 of maskedDB (hLen)
 */
    if ((err = pkcs_1_mgf1(pool, DB, modulus_len - hLen - 1, hash_idx,
             mask, hLen)) != PS_SUCCESS)
    {
        psTraceStrCrypto("MGF for DB failed in OAEP encode\n", NULL);
        goto LBL_ERR;
    }

/*
    XOR against seed
 */
    for (y = 0; y < hLen; y++)
    {
        lseed[y] ^= mask[y];
    }

/*
    Create string of length modulus_len
 */
    if (*outlen < modulus_len)
    {
        psTraceStrCrypto("Bad outlen in OAEP encode\n", NULL);
        err = -1;
        goto LBL_ERR;
    }

/*
    Start output which is 0x00 || maskedSeed || maskedDB
 */
    x = 0;
    out[x++] = 0x00;
    memcpy(out + x, lseed, hLen);
    x += hLen;
    memcpy(out + x, DB, modulus_len - hLen - 1);
    x += modulus_len - hLen - 1;

    *outlen = x;

    err = PS_SUCCESS;

LBL_ERR:
    if (seed == NULL)
    {
        psFree(lseed, pool);
    }
    psFree(mask, pool);
    psFree(DB, pool);

    return err;
}

/******************************************************************************/
/*
    PKCS #1 v2.00 OAEP decode
    pool                         Memory pool
    msg              The encoded data to decode
    msglen           The length of the encoded data (octets)
    lparam           The session or system data (can be NULL)
    lparamlen        The length of the lparam
    modulus_bitlen   The bit length of the RSA modulus
    hash_idx         The index of the hash desired
    out              [out] Destination of decoding
    outlen           [in/out] The max size and resulting size of the decoding

    return 0 if successful
 */
int32 psPkcs1OaepDecode(psPool_t *pool, const unsigned char *msg, uint32 msglen,
    const unsigned char *lparam, uint32 lparamlen,
    uint32 modulus_bitlen, int32 hash_idx,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char *DB, *seed, *mask;
    uint32 hLen, x, y, modulus_len;
    int32 err;
    psDigestContext_t md;

    if ((msg == NULL) || (out == NULL) || (outlen == NULL) || (hash_idx < 0))
    {
        psTraceCrypto("Bad parameter to OAEP decode\n");
        return PS_ARG_FAIL;
    }
/*
    Verify hash routines
 */
    if (hash_idx == PKCS1_SHA1_ID)
    {
        hLen = SHA1_HASH_SIZE;
    }
    else if (hash_idx == PKCS1_MD5_ID)
    {
# ifdef USE_MD5
        hLen = MD5_HASH_SIZE;
# else
        psTraceCrypto("MD5 not supported in this build.");
        psTraceCrypto(" Please enable USE_MD5\n");
        return PS_UNSUPPORTED_FAIL;
# endif /* USE_MD5 */
    }
    else
    {
        psTraceStrCrypto("Bad hash index to OAEP decode\n", NULL);
        return PS_ARG_FAIL;
    }

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

/*
    Test hash/message size
 */
    if ((2 * hLen >= (modulus_len - 2)) || (msglen != modulus_len))
    {
        psTraceCrypto("Message/Modulus length mismatch in OAEP decode\n");
        return PS_LIMIT_FAIL;
    }

/*
    Allocate ram for DB/mask/salt of size modulus_len
 */
    DB   = psMalloc(pool, modulus_len);
    mask = psMalloc(pool, modulus_len);
    seed = psMalloc(pool, hLen);
    if (DB == NULL || mask == NULL || seed == NULL)
    {
        if (DB != NULL)
        {
            psFree(DB, pool);
        }
        if (mask != NULL)
        {
            psFree(mask, pool);
        }
        if (seed != NULL)
        {
            psFree(seed, pool);
        }
        psTraceCrypto("Memory allocation error in OAEP decode\n");
        return -1;
    }

/*
    It's now in the form

    0x00  || maskedseed || maskedDB

    1    ||   hLen     ||  modulus_len - hLen - 1
 */
    if (msg[0] != 0x00)
    {
        psTraceCrypto("Message format error in OAEP decode\n");
        err = PS_FAILURE;
        goto LBL_ERR;
    }

/*
    Now read the masked seed
 */
    x = 1;
    memcpy(seed, msg + x, hLen);
    x += hLen;

/*
    Now read the masked DB
 */
    memcpy(DB, msg + x, modulus_len - hLen - 1);
    x += modulus_len - hLen - 1;

/*
    Compute MGF1 of maskedDB (hLen)
 */
    if ((err = pkcs_1_mgf1(pool, DB, modulus_len - hLen - 1, hash_idx,
             mask, hLen)) != PS_SUCCESS)
    {
        psTraceCrypto("MGF for DB failed in OAEP decode\n");
        goto LBL_ERR;
    }

/*
    XOR against seed
 */
    for (y = 0; y < hLen; y++)
    {
        seed[y] ^= mask[y];
    }

/*
    Compute MGF1 of seed (k - hlen - 1)
 */
    if ((err = pkcs_1_mgf1(pool, seed, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        psTraceCrypto("MGF for seed failed in OAEP decode\n");
        goto LBL_ERR;
    }

/*
    xor against DB
 */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

/*
    compute lhash and store it in seed [reuse temps!]

    DB == lhash || PS || 0x01 || M, PS == k - mlen - 2hlen - 2 zeroes
 */
    x = modulus_len;

    if (lparam != NULL)
    {
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.sha1);
            psSha1Update(&md.sha1, lparam, lparamlen);
            psSha1Final(&md.sha1, seed);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.md5);
            psMd5Update(&md.md5, lparam, lparamlen);
            psMd5Final(&md.md5, seed);
        }
# endif /* USE_MD5 */
    }
    else
    {
        /* can't pass hash routine a NULL so use DB with zero length */
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.sha1);
            psSha1Update(&md.sha1, DB, 0);
            psSha1Final(&md.sha1, seed);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.md5);
            psMd5Update(&md.md5, DB, 0);
            psMd5Final(&md.md5, seed);
        }
# endif /* USE_MD5 */
    }

/*
    Compare the lhash'es
 */
    if (memcmp(seed, DB, hLen) != 0)
    {
        psTraceCrypto("Seed/DB mismatch in OAEP decode\n");
        err = -1;
        goto LBL_ERR;
    }

/*
    Now zeroes before a 0x01
 */
    for (x = hLen; x < (modulus_len - hLen - 1) && DB[x] == 0x00; x++)
    {
        /* step... */
    }

/*
    Error out if wasn't 0x01
 */
    if (x == (modulus_len - hLen - 1) || DB[x] != 0x01)
    {
        psTraceCrypto("DB format error in OAEP decode\n");
        err = -1;
        goto LBL_ERR;
    }

/*
    Rest is the message (and skip 0x01)
 */
    if ((modulus_len - hLen - 1) - ++x > *outlen)
    {
        psTraceCrypto("Bad outlen in OAEP decode\n");
        err = -1;
        goto LBL_ERR;
    }

/*
    Copy message
 */
    *outlen = (modulus_len - hLen - 1) - x;
    memcpy(out, DB + x, modulus_len - hLen - 1 - x);
    x += modulus_len - hLen - 1;

    err = PS_SUCCESS;
LBL_ERR:

    psFree(seed, pool);
    psFree(mask, pool);
    psFree(DB, pool);

    return err;
}
#endif /* USE_PKCS1_OAEP */
/******************************************************************************/

#ifdef USE_PKCS1_PSS
/******************************************************************************/
/*
    PKCS #1 v2.00 Signature Encoding
    @param msghash          The hash to encode
    @param msghashlen       The length of the hash (octets)
    @param saltlen          The length of the salt desired (octets)
    @param hash_idx         The index of the hash desired
    @param modulus_bitlen   The bit length of the RSA modulus
    @param out              [out] The destination of the encoding
    @param outlen           [in/out] The max size and resulting size of the encoded data
    @return CRYPT_OK if successful
 */
int32 psPkcs1PssEncode(psPool_t *pool, const unsigned char *msghash,
    uint32 msghashlen, unsigned char *tsalt, uint32 saltlen,
    int32 hash_idx, uint32 modulus_bitlen, unsigned char *out,
    psSize_t *outlen)
{
    unsigned char *DB, *mask, *salt, *hash;
    uint32 x, y, hLen, modulus_len;
    int32 err;
    psDigestContext_t md;

    if ((msghash == NULL) || (out == NULL) || (outlen == NULL))
    {
        psTraceCrypto("Bad parameter to PSS encode\n");
        return PS_ARG_FAIL;
    }

    if (hash_idx == PKCS1_SHA1_ID)
    {
        hLen = SHA1_HASH_SIZE;
    }
    else if (hash_idx == PKCS1_MD5_ID)
    {
# ifdef USE_MD5
        hLen = MD5_HASH_SIZE;
# else
        psTraceCrypto("MD5 not supported in this build.");
        psTraceCrypto(" Please enable USE_MD5\n");
        return PS_UNSUPPORTED_FAIL;
# endif /* USE_MD5 */
# ifdef USE_SHA256
    }
    else if (hash_idx == PKCS1_SHA256_ID)
    {
        hLen = SHA256_HASH_SIZE;
# endif
    }
    else
    {
        psTraceStrCrypto("Bad hash index to PSS encode\n", NULL);
        return PS_ARG_FAIL;
    }

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

    /* check sizes */
    if ((saltlen > modulus_len) || (modulus_len < hLen + saltlen + 2))
    {
        psTraceCrypto("Bad saltlen or modulus len to PSS encode\n");
        return PS_ARG_FAIL;
    }

    /* allocate ram for DB/mask/salt/hash of size modulus_len */
    err = PS_MEM_FAIL;
    if ((DB = psMalloc(pool, modulus_len)) == NULL)
    {
        return err;
    }
    memset(DB, 0x0, modulus_len);
    if ((mask = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_DB;
    }
    memset(mask, 0x0, modulus_len);
    if ((salt = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_MASK;
    }
    memset(salt, 0x0, modulus_len);
    if ((hash = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_SALT;
    }
    memset(hash, 0x0, modulus_len);

    /* generate random salt */
    if (saltlen > 0)
    {
        if (tsalt != NULL)
        {
            memcpy(salt, tsalt, saltlen);
        }
        else
        {
            if (psGetPrngLocked(salt, saltlen, NULL) != (int32) saltlen)
            {
                err = PS_PLATFORM_FAIL;
                goto LBL_ERR;
            }
        }
    }

    /* M = (eight) 0x00 || msghash || salt, hash = H(M) */
    if (hash_idx == PKCS1_SHA1_ID)
    {
        psSha1Init(&md.sha1);
        psSha1Update(&md.sha1, DB, 8); /* 8 0's */
        psSha1Update(&md.sha1, msghash, msghashlen);
        psSha1Update(&md.sha1, salt, saltlen);
        psSha1Final(&md.sha1, hash);
    }
# ifdef USE_MD5
    if (hash_idx == PKCS1_MD5_ID)
    {
        psMd5Init(&md.md5);
        psMd5Update(&md.md5, DB, 8); /* 8 0's */
        psMd5Update(&md.md5, msghash, msghashlen);
        psMd5Update(&md.md5, salt, saltlen);
        psMd5Final(&md.md5, hash);
    }
# endif /* USE_MD5 */
# ifdef USE_SHA256
    if (hash_idx == PKCS1_SHA256_ID)
    {
        psSha256Init(&md.sha256);
        psSha256Update(&md.sha256, DB, 8); /* 8 0's */
        psSha256Update(&md.sha256, msghash, msghashlen);
        psSha256Update(&md.sha256, salt, saltlen);
        psSha256Final(&md.sha256, hash);
    }
# endif

    /* generate DB = PS || 0x01 || salt
        PS == modulus_len - saltlen - hLen - 2 zero bytes */
    x = 0;
    memset(DB + x, 0, modulus_len - saltlen - hLen - 2);
    x += modulus_len - saltlen - hLen - 2;
    DB[x++] = 0x01;
    memcpy(DB + x, salt, saltlen);
    x += saltlen;

    /* generate mask of length modulus_len - hLen - 1 from hash */
    if ((err = pkcs_1_mgf1(pool, hash, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        goto LBL_ERR;
    }

    /* xor against DB */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

    /* output is DB || hash || 0xBC */
    if (*outlen < modulus_len)
    {
        *outlen = modulus_len;
        err = PS_LIMIT_FAIL;
        goto LBL_ERR;
    }

    /* DB len = modulus_len - hLen - 1 */
    y = 0;
    memcpy(out + y, DB, modulus_len - hLen - 1);
    y += modulus_len - hLen - 1;

    /* hash */
    memcpy(out + y, hash, hLen);
    y += hLen;

    /* 0xBC */
    out[y] = 0xBC;

    /* now clear the 8*modulus_len - modulus_bitlen most significant bits */
    out[0] &= 0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1));

    /* store output size */
    *outlen = modulus_len;
    err = PS_SUCCESS;

LBL_ERR: psFree(hash, pool);
LBL_SALT: psFree(salt, pool);
LBL_MASK: psFree(mask, pool);
LBL_DB: psFree(DB, pool);

    return err;
}

/******************************************************************************/
/**
    PKCS #1 v2.00 PSS decode
   @param  msghash         The hash to verify
   @param  msghashlen      The length of the hash (octets)
   @param  sig             The signature data (encoded data)
   @param  siglen          The length of the signature data (octets)
   @param  saltlen         The length of the salt used (octets)
   @param  hash_idx        The index of the hash desired
   @param  modulus_bitlen  The bit length of the RSA modulus
   @param  res             [out] The result of the comparison, 1==valid, 0==invalid

 */
int32 psPkcs1PssDecode(psPool_t *pool, const unsigned char *msghash,
    uint32 msghashlen, const unsigned char *sig, uint32 siglen,
    uint32 saltlen, int32 hash_idx, uint32 modulus_bitlen, int32 *res)
{
    unsigned char *DB, *mask, *salt, *hash;
    uint32 x, y, hLen, modulus_len;
    int32 err;
    psDigestContext_t md;

    if ((msghash == NULL) || (res == NULL))
    {
        psTraceCrypto("Bad parameters to psPkcs1PssDecode\n");
        return PS_ARG_FAIL;
    }

    /* default to invalid */
    *res = 0;

    if (hash_idx == PKCS1_SHA1_ID)
    {
        hLen = SHA1_HASH_SIZE;
    }
    else if (hash_idx == PKCS1_MD5_ID)
    {
# ifdef USE_MD5
        hLen = MD5_HASH_SIZE;
# else
        psTraceCrypto("MD5 not supported in this build.");
        psTraceCrypto(" Please enable USE_MD5\n");
        return PS_UNSUPPORTED_FAIL;
# endif /* USE_MD5 */
# ifdef USE_SHA256
    }
    else if (hash_idx == PKCS1_SHA256_ID)
    {
        hLen = SHA256_HASH_SIZE;
# endif
# ifdef USE_SHA384
    }
    else if (hash_idx == PKCS1_SHA384_ID)
    {
        hLen = SHA384_HASH_SIZE;
# endif
# ifdef USE_SHA512
    }
    else if (hash_idx == PKCS1_SHA512_ID)
    {
        hLen = SHA512_HASH_SIZE;
# endif
    }
    else
    {
        psTraceStrCrypto("Bad hash index to PSS decode\n", NULL);
        return PS_ARG_FAIL;
    }

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

    /* check sizes */
    if ((saltlen > modulus_len) ||
        (modulus_len < hLen + saltlen + 2) || (siglen != modulus_len))
    {
        psTraceCrypto("Bad saltlen or modulus len to PSS decode\n");
        return PS_ARG_FAIL;
    }

    /* allocate ram for DB/mask/salt/hash of size modulus_len */
    err = PS_MEM_FAIL;
    if ((DB = psMalloc(pool, modulus_len)) == NULL)
    {
        return err;
    }
    memset(DB, 0x0, modulus_len);
    if ((mask = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_DB;
    }
    memset(mask, 0x0, modulus_len);
    if ((salt = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_MASK;
    }
    memset(salt, 0x0, modulus_len);
    if ((hash = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_SALT;
    }
    memset(hash, 0x0, modulus_len);

    /* ensure the 0xBC byte */
    if (sig[siglen - 1] != 0xBC)
    {
        err = PS_FAILURE;
        goto LBL_ERR;
    }

    /* copy out the DB */
    x = 0;
    memcpy(DB, sig + x, modulus_len - hLen - 1);
    x += modulus_len - hLen - 1;

    /* copy out the hash */
    memcpy(hash, sig + x, hLen);
    x += hLen;

    /* check the MSB */
    if ((sig[0] & ~(0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1)))) != 0)
    {
        err = PS_FAILURE;
        goto LBL_ERR;
    }

    /* generate mask of length modulus_len - hLen - 1 from hash */
    if ((err = pkcs_1_mgf1(pool, hash, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        goto LBL_ERR;
    }

    /* xor against DB */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

    /* now clear the first byte [make sure smaller than modulus] */
    DB[0] &= 0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1));

    /* DB = PS || 0x01 || salt,
        PS == modulus_len - saltlen - hLen - 2 zero bytes */

    /* check for zeroes and 0x01 */
    for (x = 0; x < modulus_len - saltlen - hLen - 2; x++)
    {
        if (DB[x] != 0x00)
        {
            err = PS_FAILURE;
            goto LBL_ERR;
        }
    }

    /* check for the 0x01 */
    if (DB[x++] != 0x01)
    {
        err = PS_FAILURE;
        goto LBL_ERR;
    }

    /* M = (eight) 0x00 || msghash || salt, mask = H(M) */
    if (hash_idx == PKCS1_SHA1_ID)
    {
        psSha1Init(&md.sha1);
        memset(mask, 0x0, 8);
        psSha1Update(&md.sha1, mask, 8);
        psSha1Update(&md.sha1, msghash, msghashlen);
        psSha1Update(&md.sha1, DB + x, saltlen);
        psSha1Final(&md.sha1, mask);
    }
# ifdef USE_MD5
    if (hash_idx == PKCS1_MD5_ID)
    {
        psMd5Init(&md.md5);
        memset(mask, 0x0, 8);
        psMd5Update(&md.md5, mask, 8);
        psMd5Update(&md.md5, msghash, msghashlen);
        psMd5Update(&md.md5, DB + x, saltlen);
        psMd5Final(&md.md5, mask);
    }
# endif /* USE_MD5 */

# ifdef USE_SHA256
    if (hash_idx == PKCS1_SHA256_ID)
    {
        psSha256Init(&md.sha256);
        memset(mask, 0x0, 8);
        psSha256Update(&md.sha256, mask, 8);
        psSha256Update(&md.sha256, msghash, msghashlen);
        psSha256Update(&md.sha256, DB + x, saltlen);
        psSha256Final(&md.sha256, mask);
    }
# endif
# ifdef USE_SHA384
    if (hash_idx == PKCS1_SHA384_ID)
    {
        psSha384Init(&md.sha384);
        memset(mask, 0x0, 8);
        psSha384Update(&md.sha384, mask, 8);
        psSha384Update(&md.sha384, msghash, msghashlen);
        psSha384Update(&md.sha384, DB + x, saltlen);
        psSha384Final(&md.sha384, mask);
    }
# endif
# ifdef USE_SHA512
    if (hash_idx == PKCS1_SHA512_ID)
    {
        psSha512Init(&md.sha512);
        memset(mask, 0x0, 8);
        psSha512Update(&md.sha512, mask, 8);
        psSha512Update(&md.sha512, msghash, msghashlen);
        psSha512Update(&md.sha512, DB + x, saltlen);
        psSha512Final(&md.sha512, mask);
    }
# endif

    /* mask == hash means valid signature */
    if (memcmp(mask, hash, hLen) == 0)
    {
        *res = 1;
    }

    err = PS_SUCCESS;

LBL_ERR:
    psFree(hash, pool);
LBL_SALT:
    psFree(salt, pool);
LBL_MASK:
    psFree(mask, pool);
LBL_DB:
    psFree(DB, pool);
    memset_s(&md, sizeof(psDigestContext_t), 0x0, sizeof(psDigestContext_t));

    return err;
}
#endif /* USE_PKCS1_PSS */

/******************************************************************************/

/******************************************************************************/

