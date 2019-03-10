/**
 *      @file    rsa_pub.c
 *      @version $Format:%h%d$
 *
 *      RSA public key operations.
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
 */

#ifdef USE_MATRIX_RSA

#define ASN_OVERHEAD_LEN_RSA_SHA2   19
#define ASN_OVERHEAD_LEN_RSA_SHA1   15

static
int32_t psRsaDecryptPubExt(psPool_t *pool,
        psRsaKey_t *key,
        unsigned char *in,
        psSize_t inlen,
        unsigned char *out,
        psSize_t *outlen,
        psSize_t expectedLen,
        void *data)
{
    int32_t err;
    psSize_t ptLen, unpaddedLen;

    if (inlen != key->size)
    {
        psTraceCrypto("Error on bad inlen parameter to psRsaDecryptPub\n");
        return PS_ARG_FAIL;
    }

    ptLen = inlen;

    /* Raw, in-place RSA decryption. */
    err = psRsaCrypt(pool,
            key,
            in,
            inlen,
            in,
            &ptLen,
            PS_PUBKEY,
            data);
    if (err < PS_SUCCESS)
    {
        psTraceCrypto("Error performing psRsaDecryptPub\n");
        return err;
    }

    /* In raw RSA decryption, size of the decrypted plaintext must equal
       the size of the ciphertext. */
    if (ptLen != inlen)
    {
        psTraceIntCrypto("Decrypted size error in psRsaDecryptPub %d\n", ptLen);
        return PS_FAILURE;
    }

    /* Remove PKCS #1 padding and copy the decrypted and de-padded data
       to out. */
    err = pkcs1UnpadExt(in,
            inlen,
            out,
            *outlen,
            PS_PUBKEY,
            PS_FALSE,
            &unpaddedLen);
    if (err < 0)
    {
        return err;
    }

    *outlen = unpaddedLen;

    return PS_SUCCESS;
}

int32_t pubRsaDecryptSignedElement(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    int32_t signatureAlgorithm, rc;

    rc = psHashLenToSigAlg(outlen, PS_RSA);
    if (rc < 0)
    {
        return rc;
    }

    signatureAlgorithm = rc;

    return pubRsaDecryptSignedElementExt(pool, key, in, inlen,
        out, outlen,
        signatureAlgorithm, data);
}

int32_t pubRsaDecryptSignedElementExt(psPool_t *pool,
        psRsaKey_t *key,
        unsigned char *in,
        psSize_t inlen,
        unsigned char *hashOut,
        psSize_t hashOutLen,
        int32_t signatureAlgorithm,
        void *data)
{
    int32_t rc;
    /* Reserve enough room for the largest supported decrypted and de-padded
       plaintext: a SHA-512 DigestInfo (with NULL parameters). */
    unsigned char decrypted[SHA512_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2];
    psSize_t decryptedLen = sizeof(decrypted);
    const unsigned char *prefix;
    unsigned char *decPrefixStart;
    psSize_t decPrefixLen;


    /*
      Check input arguments
     */
    if (key == NULL || in == NULL || hashOut == NULL)
    {
        psTraceCrypto(
            "ERROR: invalid argument in pubRsaDecryptSignedElement\n");
        return PS_ARG_FAIL;
    }

    /*
      Check that the hash length + signatureAlgorithm combination
      is valid and that signatureAlgorithm is supported.
    */
    if (!psIsValidHashLenSigAlgCombination(hashOutLen, signatureAlgorithm))
    {
        psTraceCrypto("Invalid hash length + signature alg combination: ");
        psTraceIntCrypto("hash length: %d, ", hashOutLen);
        psTraceIntCrypto("sig alg: %d\n", signatureAlgorithm);
        return PS_ARG_FAIL;
    }

    /*
      Perform RSA decryption + de-padding. After this, decryptedLen
      becomes the length of the actual recovered DigestInfo.
    */
    rc = psRsaDecryptPubExt(pool,
            key,
            in,
            inlen,
            decrypted,
            &decryptedLen,
            hashOutLen,
            data);
    if (rc < 0)
    {
        psTraceCrypto("Couldn't public decrypt signed element\n");
        return rc;
    }

    /*
      Two alternatives for verifying the decrypted RSA message
      representative:

      - Comparison-based: directly compare the known parts of the
        DigestInfo against a reference DigestInfo.
      - Parsing based: parse the decrypted DigestInfo and check that
        each component is as expected.

      In both approaches, the variable part (the embedded digest itself)
      needs to be directly compared against the reference digest. We don't
      perform that part here; this must be done by the caller.

      We use the comparison-based approach, since its safer and easier
      to implement correctly, see e.g. Kühn et al.: "Variants of
      Bleichenbacher's Low-Exponent Attack on PKCS#1 RSA Signatures".
    */

    /*
      Based on the signatureAlgorithm we were given, get a reference
      DigestInfo prefix to compare against.
    */
    prefix = psGetDigestInfoPrefix(decryptedLen, signatureAlgorithm);
    if (prefix == NULL)
    {
        return PS_ARG_FAIL;
    }

    /*
      Check that the decrypted DigestInfo prefix is valid.
      If yes, copy the decrypted digest to out.
    */
    decPrefixStart = decrypted;
    decPrefixLen = decryptedLen - hashOutLen;
    if (memcmpct(prefix, decPrefixStart, decPrefixLen) == 0)
    {
        Memcpy(hashOut, decrypted + decPrefixLen, hashOutLen);
        rc = PS_SUCCESS;
    }
    else
    {
        rc = PS_FAILURE;
    }

    Memset(decrypted, 0, sizeof(decrypted));

    return rc;
}

/******************************************************************************/
/**
    RSA public encryption. This is used by a public key holder to do
    key exchange with the private key holder, which can access the key using
    psRsaDecryptPriv().

    @param[in] pool Pool to use for temporary memory allocation for this op.
    @param[in] key RSA key to use for this operation.
    @param[in] in Pointer to allocated buffer to encrypt.
    @param[in] inlen Number of bytes pointed to by 'in' to encrypt.
    @param[out] out Pointer to allocated buffer to store encrypted data.
    @param[in] expected output length
    @param[in] data TODO Hardware context.

    @return 0 on success, < 0 on failure.
 */
int32_t psRsaEncryptPub(psPool_t *pool, psRsaKey_t *key,
    const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    int32_t err;
    psSize_t size;

    size = key->size;
    if (outlen < size)
    {
        psTraceCrypto("Error on bad outlen parameter to psRsaEncryptPub\n");
        return PS_ARG_FAIL;
    }

    if ((err = pkcs1Pad(in, inlen, out, size, PS_PRIVKEY, data))
        < PS_SUCCESS)
    {
        psTraceCrypto("Error padding psRsaEncryptPub. Likely data too long\n");
        return err;
    }
    if ((err = psRsaCrypt(pool, key, out, size, out, &outlen,
             PS_PUBKEY, data)) < PS_SUCCESS)
    {
        psTraceCrypto("Error performing psRsaEncryptPub\n");
        return err;
    }
    if (outlen != size)
    {
        psTraceCrypto("Encrypted size error in psRsaEncryptPub\n");
        return PS_FAILURE;
    }
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    RSA public decryption. This is used by a public key holder to verify
    a signature by the private key holder, who signs using psRsaEncryptPriv().

    @param[in] pool Pool to use for temporary memory allocation for this op.
    @param[in] key RSA key to use for this operation.
    @param[in,out] in Pointer to allocated buffer to encrypt.
    @param[in] inlen Number of bytes pointed to by 'in' to encrypt.
    @param[out] out Pointer to allocated buffer to store encrypted data.
    @param[in] outlen length of expected output.
    @param[in] data TODO Hardware context.

    @return 0 on success, < 0 on failure.

    TODO -fix
    @note this function writes over the 'in' buffer
 */
int32_t psRsaDecryptPub(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    int32_t rc;
    psSize_t expectedOutLen = outlen;

    rc = psRsaDecryptPubExt(pool,
            key,
            in,
            inlen,
            out,
            &outlen,
            expectedOutLen,
            data);
    if (rc != PS_SUCCESS)
    {
        return rc;
    }

    if (outlen != expectedOutLen)
    {
        psTraceIntCrypto("Decrypted size error in psRsaDecryptPub %hu\n",
                outlen);
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}

# ifdef USE_PKCS1_PSS
psRes_t psRsaPssVerify(psPool_t *pool,
    const unsigned char *msgIn,
    psSizeL_t msgInLen,
    const unsigned char *sig,
    psSize_t sigLen,
    psPubKey_t *key,
    int32_t signatureAlgorithm,
    psBool_t *verifyResult,
    psVerifyOptions_t *opts)
{
    int32_t pssVerificationOk = 0;
    unsigned char *em;
    psSize_t emLen;
    int32_t rc = PS_SUCCESS;

    if (opts == NULL)
    {
        return PS_ARG_FAIL;
    }
    em = psMalloc(pool, key->keysize);
    if (em == NULL)
    {
        return PS_MEM_FAIL;
    }
    emLen = key->keysize;
    rc = psRsaCrypt(pool,
            &key->key.rsa,
            sig, sigLen,
            em, &emLen,
            PS_PUBKEY,
            NULL);
    if (rc < 0)
    {
        psFree(em, pool);
        return rc;
    }
    rc = psPkcs1PssDecode(pool,
            msgIn,
            msgInLen,
            em,
            emLen,
            opts->rsaPssSaltLen,
            opts->rsaPssHashAlg,
            key->keysize * 8,
            &pssVerificationOk);
    if (rc < 0)
    {
        psTraceCrypto("psRsaPssVerify: error decrypting signature\n");
        psFree(em, pool);
        rc = PS_FAILURE;
        goto out;
    }
    psFree(em, pool);

    if (pssVerificationOk == 1)
    {
        *verifyResult = PS_TRUE;
    }
    else
    {
        psTraceCrypto("psRsaPssVerify: signature verification failed\n");
        rc = PS_VERIFICATION_FAILED;
        *verifyResult = PS_FALSE;
    }

out:
    return rc;
}
# endif /* USE_PKCS1_PSS */

#endif  /* USE_MATRIX_RSA */

/******************************************************************************/

