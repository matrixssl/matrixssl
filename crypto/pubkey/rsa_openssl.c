/**
 *      @file    rsa_openssl.c
 *      @version $Format:%h%d$
 *
 *      RSA compatibility layer between MatrixSSL and OpenSSL.
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

#ifdef USE_OPENSSL_RSA
# include "openssl/bn.h"

/**
    @note It bears mention that the DER parsing functions
    are defined in this header via macro:

    DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
    DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPrivateKey)

    They are implemented in openssl/crypto/rsa/rsa_asn1.c:
    ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
        ASN1_SIMPLE(RSA, version, LONG),
        ASN1_SIMPLE(RSA, n, BIGNUM),
        ASN1_SIMPLE(RSA, e, BIGNUM),
        ASN1_SIMPLE(RSA, d, BIGNUM),
        ASN1_SIMPLE(RSA, p, BIGNUM),
        ASN1_SIMPLE(RSA, q, BIGNUM),
        ASN1_SIMPLE(RSA, dmp1, BIGNUM),
        ASN1_SIMPLE(RSA, dmq1, BIGNUM),
        ASN1_SIMPLE(RSA, iqmp, BIGNUM)
    } ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)

    ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
        ASN1_SIMPLE(RSA, n, BIGNUM),
        ASN1_SIMPLE(RSA, e, BIGNUM),
    } ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)

    In turn, the asn BIGNUM creation is in crypto/asn1/x_bignum.c
 */

# include "openssl/rsa.h"

/**
    Note that in this case psRsaKey_t is a pointer type, so 'key' is
    effectively a double pointer. We just set it to NULL for now, the actual
    key will be allocated by the parse functions below.

    @param[in] pool Unused in this implementation.
    @param[in,out] key A pointer to an allocated (statically or dynamically)
    psRsaKey_t, which in this case is just a pointer to an RSA structure.
 */
int32_t psRsaInitKey(psPool_t *pool, psRsaKey_t *key)
{
    *key = NULL;
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    RSA_free() frees and zeroes the RSA structure and associated BIGNUM values.
 */
void psRsaClearKey(psRsaKey_t *key)
{
    if (key && *key)
    {
        RSA_free(*key);
        *key = NULL;
    }
}

/******************************************************************************/
/**
 */
int32_t psRsaCopyKey(psRsaKey_t *to, const psRsaKey_t *from)
{
    RSA *t = *to;
    RSA *f = *from;

    if (!from || !f || !to)
    {
        return PS_ARG_FAIL;
    }
    /* If to already contained a key, free it */
    if (t)
    {
        RSA_free(t);
    }
    /* Allocate a new key */
    if ((t = RSA_new()) == NULL)
    {
        return PS_MEM_FAIL;
    }
    /* Duplicate the parts that must always be present (n, e) */
    if ((t->n = BN_dup(f->n)) == NULL)
    {
        RSA_free(t);
        return PS_FAIL;
    }
    if ((t->e = BN_dup(f->e)) == NULL)
    {
        RSA_free(t);
        return PS_FAIL;
    }
    /* Duplicate the private/optimized parts. Ok if they are NULL */
    t->d = BN_dup(f->d);
    t->p = BN_dup(f->p);
    t->q = BN_dup(f->q);
    t->dmp1 = BN_dup(f->dmp1);
    t->dmq1 = BN_dup(f->dmq1);
    t->iqmp = BN_dup(f->iqmp);
    *to = t;
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    Returns the size of the RSA public modulus in bytes.
    @return 0 on uninitalized key, or >= for valid key
        (eg. 128 for 1024 bit key, etc)
 */
psSize_t psRsaSize(const psRsaKey_t *key)
{
    if (key && *key)
    {
        return RSA_size(*key);
    }
    return 0;
}

/******************************************************************************/

int32_t psRsaCmpPubKey(const psRsaKey_t *k1, const psRsaKey_t *k2)
{
    /* BN_cmp() returns -1 if a < b, 0 if a == b and 1 if a > b. */
    if ((BN_cmp((*k1)->n, (*k2)->n) == 0) &&
        (BN_cmp((*k1)->e, (*k2)->e) == 0))
    {
        return PS_SUCCESS;
    }
    return PS_FAIL;
}

# ifndef USE_D2I
/******************************************************************************/
/**
    Convert big endian binary data to a native big number type.
    BN_bin2bn() converts the positive integer in big-endian form of length len
    at s into a BIGNUM and places it in ret.
    If ret is NULL, a new BIGNUM is created.
    BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
 */
static int32_t getBig(const unsigned char **pp, psSize_t len, BIGNUM **big)
{
    const unsigned char *p = *pp;
    psSize_t vlen;
    BIGNUM *bn;

    if (len < 1 || *(p++) != ASN_INTEGER ||
        getAsnLength(&p, len - 1, &vlen) < 0 || (len - 1) < vlen)
    {
        return PS_PARSE_FAIL;
    }
    if ((bn = BN_bin2bn(p, vlen, NULL)) == NULL)
    {
        return PS_MEM_FAIL;
    }
    /* BN_print_fp(stdout, bn); */
    *big = bn;
    *pp = p + vlen;
    return PS_SUCCESS;
}
# endif
/******************************************************************************/
/*
    Parse DER encoded asn.1 RSA public key out of a certificate stream.
    We reach here with 'pp' pointing to the byte after the algorithm identifier.
 */
int32_t psRsaParseAsnPubKey(psPool_t *pool,
    const unsigned char **pp, psSize_t len,
    psRsaKey_t *key, unsigned char sha1KeyHash[SHA1_HASH_SIZE])
{
# ifdef USE_SHA1
    psDigestContext_t dc;
# endif
    const unsigned char *p = *pp;
    RSA *rsa;
    psSize_t keylen;
# ifndef USE_D2I
    psSize_t seqlen;
# endif

    if (len < 1 || (*(p++) != ASN_BIT_STRING) ||
        getAsnLength(&p, len - 1, &keylen))
    {
        goto L_FAIL;
    }
    /* ignored bits field should be zero */
    if (*p++ != 0)
    {
        goto L_FAIL;
    }
    keylen--;
# ifdef USE_SHA1
    /* A public key hash is used in PKI tools (OCSP, Trusted CA indication).
        Standard RSA form - SHA-1 hash of the value of the BIT STRING
        subjectPublicKey [excluding the tag, length, and number of unused
        bits] */
    psSha1Init(&dc.sha1);
    psSha1Update(&dc.sha1, p, keylen);
    psSha1Final(&dc.sha1, sha1KeyHash);
# endif

# ifdef USE_D2I
    /* OpenSSL expects to parse after the ignored bits field */
    if ((rsa = d2i_RSAPublicKey(NULL, &p, keylen)) == NULL)
    {
        goto L_FAIL;
    }
# else
    /* We can manually create the structures as OpenSSL would */
    rsa = RSA_new();
    if (getAsnSequence(&p, keylen, &seqlen) < 0 ||
        getBig(&p, seqlen, &rsa->n) < 0 ||
        getBig(&p, seqlen, &rsa->e) < 0)
    {

        RSA_free(rsa);
        goto L_FAIL;
    }
# endif
    /* RSA_print_fp(stdout, rsa, 0); */
    *pp = p;
    *key = rsa;
    return PS_SUCCESS;
L_FAIL:
    psTraceIntCrypto("psRsaParseAsnPubKey error on byte %d\n", p - *pp);
    return PS_PARSE_FAIL;
}

# ifdef USE_PRIVATE_KEY_PARSING
/******************************************************************************/
/**
    Parse an RSA private key from a PKCS#1 byte stream.
    @see ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
 */
int32_t psRsaParsePkcs1PrivKey(psPool_t *pool,
    const unsigned char *p, psSize_t size,
    psRsaKey_t *key)
{
    RSA *rsa;

#  ifndef USE_D2I
    const unsigned char *end, *seq;
    int32_t version;
    psSize_t seqlen;
#  endif

#  ifdef USE_D2I
    if ((rsa = d2i_RSAPrivateKey(NULL, &p, size)) == NULL)
    {
        return PS_PARSE_FAIL;
    }
#  else
    if ((rsa = RSA_new()) == NULL)
    {
        return PS_MEM_FAIL;
    }
    end = p + size;
    if (getAsnSequence(&p, size, &seqlen) < 0)
    {
        RSA_free(rsa);
        goto L_FAIL;
    }
    seq = p;
    if (getAsnInteger(&p, (uint16_t) (end - p), &version) < 0 || version != 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->n) < 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->e) < 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->d) < 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->p) < 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->q) < 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->dmp1) < 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->dmq1) < 0 ||
        getBig(&p, (uint16_t) (end - p), &rsa->iqmp) < 0 ||
        (uint16_t) (p - seq) != seqlen)
    {

        RSA_free(rsa);
        goto L_FAIL;
    }
    rsa->version = version;
#  endif
    /* RSA_print_fp(stdout, rsa, 0); */
    *key = rsa;
    return PS_SUCCESS;
L_FAIL:
    psTraceIntCrypto("psRsaParsePkcs1PrivKey error on byte %d\n", p - (end - size));
    return PS_PARSE_FAIL;
}
# endif /* USE_PRIVATE_KEY_PARSING */

/******************************************************************************/

int32_t psRsaEncryptPriv(psPool_t *pool, psRsaKey_t *key,
    const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    return RSA_private_encrypt(inlen, in, out, *key, RSA_PKCS1_PADDING);
}

int32_t psRsaEncryptPub(psPool_t *pool, psRsaKey_t *key,
    const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    return RSA_public_encrypt(inlen, in, out, *key, RSA_PKCS1_PADDING);
}

int32_t psRsaDecryptPriv(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    return RSA_private_decrypt(inlen, in, out, *key, RSA_PKCS1_PADDING);
}

int32_t psRsaDecryptPub(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    return RSA_public_decrypt(inlen, in, out, *key, RSA_PKCS1_PADDING);
}

#endif /* USE_OPENSSL_RSA */
/******************************************************************************/

