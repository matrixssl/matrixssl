/**
 *      @file    rsa_priv.c
 *      @version $Format:%h%d$
 *
 *      RSA private key operations.
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

/******************************************************************************/
/* TODO - the following functions are not implementation layer specific...
    move to a common file?

    Matrix-specific starts at #ifdef USE_MATRIX_RSA
 */

#define ASN_OVERHEAD_LEN_RSA_SHA2   19
#define ASN_OVERHEAD_LEN_RSA_SHA1   15

#ifdef USE_MATRIX_RSA

/*
    ASN wrappers around standard hash signatures.  These versions sign
    a BER wrapped hash.  Here are the well-defined wrappers:
 */
static const unsigned char asn256dsWrap[] =
{
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

# ifdef USE_SHA384
static const unsigned char asn384dsWrap[] =
{
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00,  0x04, 0x30
};
# endif

static const unsigned char asn1dsWrap[] =
{
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
    0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
};

int32_t privRsaEncryptSignedElement(psPool_t *pool, psRsaKey_t *key,
    const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    unsigned char c[MAX_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2];
    uint32_t inlenWithAsn;

    switch (inlen)
    {
# ifdef USE_SHA256
    case SHA256_HASH_SIZE:
        inlenWithAsn = inlen + ASN_OVERHEAD_LEN_RSA_SHA2;
        Memcpy(c, asn256dsWrap, ASN_OVERHEAD_LEN_RSA_SHA2);
        Memcpy(c + ASN_OVERHEAD_LEN_RSA_SHA2, in, inlen);
        break;
# endif
# ifdef USE_SHA1
    case SHA1_HASH_SIZE:
        inlenWithAsn = inlen + ASN_OVERHEAD_LEN_RSA_SHA1;
        Memcpy(c, asn1dsWrap, ASN_OVERHEAD_LEN_RSA_SHA1);
        Memcpy(c + ASN_OVERHEAD_LEN_RSA_SHA1, in, inlen);
        break;
# endif
# ifdef USE_SHA384
    case SHA384_HASH_SIZE:
        inlenWithAsn = inlen + ASN_OVERHEAD_LEN_RSA_SHA2;
        Memcpy(c, asn384dsWrap, ASN_OVERHEAD_LEN_RSA_SHA2);
        Memcpy(c + ASN_OVERHEAD_LEN_RSA_SHA2, in, inlen);
        break;
# endif
    default:
        return PS_UNSUPPORTED_FAIL;
    }
    if (psRsaEncryptPriv(pool, key, c, inlenWithAsn,
            out, outlen, data) < 0)
    {
        psTraceCrypto("privRsaEncryptSignedElement failed\n");
        memzero_s(c, sizeof(c));
        return PS_PLATFORM_FAIL;
    }
    memzero_s(c, sizeof(c));
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    RSA private encryption. This is used by a private key holder to sign
    data that can be verified by psRsaDecryptPub().

    @param[in] pool Pool to use for temporary memory allocation for this op.
    @param[in] key RSA key to use for this operation.
    @param[in] in Pointer to allocated buffer to encrypt.
    @param[in] inlen Number of bytes pointed to by 'in' to encrypt.
    @param[out] out Pointer to allocated buffer to store encrypted data.
    @param[out] outlen Number of bytes written to 'out' buffer.
    @param[in] data TODO Hardware context.

    @return 0 on success, < 0 on failure.
 */
int32_t psRsaEncryptPriv(psPool_t *pool, psRsaKey_t *key,
    const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    unsigned char *verify = NULL;
    unsigned char *tmpout = NULL;
    int32_t err;
    psSize_t size, olen;

    /** @security We follow the FIPS 186 recommendation for minimum data to sign. */
    if (inlen < 28)
    {
        psTraceCrypto("Error inlen < 28 bytes in psRsaEncryptPriv\n");
        return PS_ARG_FAIL;
    }
    size = key->size;
    if (outlen < size)
    {
        psTraceCrypto("Error on bad outlen parameter to psRsaEncryptPriv\n");
        return PS_ARG_FAIL;
    }
    olen = outlen;  /* Save in case we zero 'out' later */
    if ((err = pkcs1Pad(in, inlen, out, size, PS_PUBKEY, data)) < PS_SUCCESS)
    {
        psTraceCrypto("Error padding psRsaEncryptPriv. Likely data too long\n");
        return err;
    }
    if ((err = psRsaCrypt(pool, key, out, size, out, &outlen,
             PS_PRIVKEY, data)) < PS_SUCCESS)
    {
        psTraceCrypto("Error performing psRsaEncryptPriv\n");
        return err;
    }
    if (outlen != size)
    {
        goto L_FAIL;
    }

    /**
        @security Verify the signature we just made before it is used
        by the caller. If the signature is invalid for some reason
        (hardware or software error or memory overrun), it can
        leak information on the private key.
     */
    if ((verify = psMalloc(pool, inlen)) == NULL)
    {
        goto L_FAIL;
    }
    /* psRsaDecryptPub overwrites the input, so duplicate it here */
    if ((tmpout = psMalloc(pool, outlen)) == NULL)
    {
        goto L_FAIL;
    }
    Memcpy(tmpout, out, outlen);
    if (psRsaDecryptPub(pool, key,
            tmpout, outlen, verify, inlen, data) < 0)
    {
        goto L_FAIL;
    }
    if (memcmpct(in, verify, inlen) != 0)
    {
        goto L_FAIL;
    }
    memzero_s(verify, inlen);
    psFree(verify, pool);
    memzero_s(tmpout, outlen);
    psFree(tmpout, pool);

    return PS_SUCCESS;

L_FAIL:
    memzero_s(out, olen); /* Clear, to ensure bad result isn't used */
    if (tmpout)
    {
        memzero_s(tmpout, outlen);
        psFree(tmpout, pool);
    }
    if (verify)
    {
        memzero_s(verify, inlen);
        psFree(verify, pool);
    }
    psTraceCrypto("Signature mismatch in psRsaEncryptPriv\n");
    return PS_FAIL;
}

/******************************************************************************/
/**
    RSA private decryption. This is used by a private key holder to decrypt
    a key exchange with the public key holder, which encodes the key using
    psRsaEncryptPub().

    @param[in] pool Pool to use for temporary memory allocation for this op.
    @param[in] key RSA key to use for this operation.
    @param[in,out] in Pointer to allocated buffer to encrypt.
    @param[in] inlen Number of bytes pointed to by 'in' to encrypt.
    @param[out] out Pointer to allocated buffer to store encrypted data.
    @param[out] outlen Number of bytes written to 'out' buffer.
    @param[in] data TODO Hardware context.

    @return 0 on success, < 0 on failure.

    TODO -fix
    @note this function writes over the 'in' buffer
 */
int32_t psRsaDecryptPriv(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    int32_t err;
    psSize_t ptLen;

    if (inlen != key->size)
    {
        psTraceCrypto("Error on bad inlen parameter to psRsaDecryptPriv\n");
        return PS_ARG_FAIL;
    }
    ptLen = inlen;
    if ((err = psRsaCrypt(pool, key, in, inlen, in, &ptLen,
             PS_PRIVKEY, data)) < PS_SUCCESS)
    {
        psTraceCrypto("Error performing psRsaDecryptPriv\n");
        return err;
    }
    if (ptLen != inlen)
    {
        psTraceCrypto("Decrypted size error in psRsaDecryptPriv\n");
        return PS_FAILURE;
    }
    err = pkcs1Unpad(in, inlen, out, outlen, PS_PRIVKEY);
    Memset(in, 0x0, inlen);
    return err;
}

# ifdef USE_PKCS1_PSS
/* Sign a hash using RSASSA-PSS (PKCS #2.1) */
int32_t psRsaPssSignHash(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSizeL_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts)
{
    unsigned char *em, *sig;
    psSize_t emLen, sigLen;
    psSize_t modNBytes = privKey->keysize;
    psSize_t modNBits = modNBytes * 8;
    int32_t rc;

    psAssert(opts != NULL);

    em = psMalloc(pool, modNBytes);
    if (em == NULL)
    {
        return PS_MEM_FAIL;
    }
    emLen = modNBytes;

    rc = psPkcs1PssEncode(pool,
            in,
            inLen,
            opts->rsaPssSalt,
            opts->rsaPssSaltLen,
            opts->rsaPssHashAlg,
            modNBits,
            em,
            &emLen);
    if (rc < 0)
    {
        psFree(em, pool);
        return rc;
    }

    sig = psMalloc(pool, modNBytes);
    if (sig == NULL)
    {
        psFree(em, pool);
        return PS_MEM_FAIL;
    }
    sigLen = modNBytes;

    rc = psRsaCrypt(pool,
            &privKey->key.rsa,
            em,
            emLen,
            sig,
            &sigLen,
            PS_PRIVKEY,
            NULL);
    if (rc < 0)
    {
        psFree(em, pool);
        psFree(sig, pool);
        return rc;
    }

    psFree(em, pool);

    *out = sig;
    *outLen = sigLen;

# ifdef DEBUG_RSA_PSS
    psTraceBytes("psRsaPssSignHash in", in, inLen);
    psTraceBytes("psRsaPssSignHash sig", sig, sigLen);
    psTraceIntCrypto("psRsaPssSignHash saltLen: %hu\n", opts->rsaPssSaltLen);
# endif

    return PS_SUCCESS;
}
# endif

#endif  /* USE_MATRIX_RSA */

/******************************************************************************/

