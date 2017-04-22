/**
 *      @file    rsa.c
 *      @version $Format:%h%d$
 *
 *      RSA crypto.
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
/* TODO - the following functions are not implementation layer specific...
    move to a common file?

    Matrix-specific starts at #ifdef USE_MATRIX_RSA
 */

#define ASN_OVERHEAD_LEN_RSA_SHA2   19
#define ASN_OVERHEAD_LEN_RSA_SHA1   15

#ifdef USE_MATRIX_RSA
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

int32_t pubRsaDecryptSignedElementExt(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    int32_t signatureAlgorithm, void *data)
{
    unsigned char *c, *front, *end;
    uint16_t outlenWithAsn, len, plen;
    int32_t oi, rc;

    /* The      issue here is that the standard RSA decryption routine requires
       the user to know the output length (usually just a hash size).  With
       these "digitally signed elements" there is an algorithm
       identifier surrounding the hash so we use the known magic numbers as
       additional lengths of the wrapper since it is a defined ASN sequence,
       ASN algorithm oid, and ASN octet string */
    if (outlen == SHA256_HASH_SIZE)
    {
        outlenWithAsn = SHA256_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2;
    }
    else if (outlen == SHA1_HASH_SIZE)
    {
        outlenWithAsn = SHA1_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA1;
    }
    else if (outlen == SHA384_HASH_SIZE)
    {
        outlenWithAsn = SHA384_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2;
    }
    else if (outlen == SHA512_HASH_SIZE)
    {
        outlenWithAsn = SHA512_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2;
    }
    else
    {
        psTraceIntCrypto("Unsupported decryptSignedElement hash %d\n", outlen);
        return PS_FAILURE;
    }

    front = c = psMalloc(pool, outlenWithAsn);
    if (front == NULL)
    {
        return PS_MEM_FAIL;
    }

    if ((rc = psRsaDecryptPub(pool, key, in, inlen, c, outlenWithAsn, data)) < 0)
    {
        psFree(front, pool);
        psTraceCrypto("Couldn't public decrypt signed element\n");
        return rc;
    }

    /* Parse it */
    end = c + outlenWithAsn;

    /* @note Below we do a typecast to const to avoid a compiler warning,
        although it should be fine to pass a non const pointer into an
        api declaring it const, since it is just the API declaring the
        contents will not be modified within the API. */
    if (getAsnSequence((const unsigned char **) &c,
            (uint16_t) (end - c), &len) < 0)
    {
        psTraceCrypto("Couldn't parse signed element sequence\n");
        psFree(front, pool);
        return PS_FAILURE;
    }
    if (getAsnAlgorithmIdentifier((const unsigned char **) &c,
            (uint16_t) (end - c), &oi, &plen) < 0)
    {
        psTraceCrypto("Couldn't parse signed element octet string\n");
        psFree(front, pool);
        return PS_FAILURE;
    }

    if (oi == OID_SHA256_ALG)
    {
        psAssert(outlen == SHA256_HASH_SIZE);
    }
    else if (oi == OID_SHA1_ALG)
    {
        psAssert(outlen == SHA1_HASH_SIZE);
    }
    else if (oi == OID_SHA384_ALG)
    {
        psAssert(outlen == SHA384_HASH_SIZE);
    }
# ifdef USE_MD2
    else if (oi == OID_MD2_ALG)
    {
        psAssert(outlen == MD5_HASH_SIZE);
    }
# endif /* USE_MD2 */
# ifdef USE_MD5
    else if (oi == OID_MD5_ALG)
    {
        psAssert(outlen == MD5_HASH_SIZE);
    }
# endif /* USE_MD5 */
    else
    {
        psAssert(outlen == SHA512_HASH_SIZE);
    }

    /* Note the last test here requires the buffer to be exactly outlen bytes */
    if ((end - c) < 1 || (*c++ != ASN_OCTET_STRING) ||
        getAsnLength((const unsigned char **) &c, (uint16_t) (end - c), &len) < 0 ||
        (uint32_t) (end - c) != outlen)
    {

        psTraceCrypto("Couldn't parse signed element octet string\n");
        psFree(front, pool);
        return PS_FAILURE;
    }
    /* Will finally be sitting at the hash now */
    memcpy(out, c, outlen);
    psFree(front, pool);
    return PS_SUCCESS;
}

/*
    ASN wrappers around standard hash signatures.  These versions sign
    a BER wrapped hash.  Here are the well-defined wrappers:
 */
static const unsigned char asn256dsWrap[] = { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                              0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,0x01,  0x05,  0x00,  0x04, 0x20 };
# ifdef USE_SHA384
static const unsigned char asn384dsWrap[] = { 0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                              0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,0x02,  0x05,  0x00,  0x04, 0x30 };
# endif
static const unsigned char asn1dsWrap[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B,
                                            0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };

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
        memcpy(c, asn256dsWrap, ASN_OVERHEAD_LEN_RSA_SHA2);
        memcpy(c + ASN_OVERHEAD_LEN_RSA_SHA2, in, inlen);
        break;
# endif
# ifdef USE_SHA1
    case SHA1_HASH_SIZE:
        inlenWithAsn = inlen + ASN_OVERHEAD_LEN_RSA_SHA1;
        memcpy(c, asn1dsWrap, ASN_OVERHEAD_LEN_RSA_SHA1);
        memcpy(c + ASN_OVERHEAD_LEN_RSA_SHA1, in, inlen);
        break;
# endif
# ifdef USE_SHA384
    case SHA384_HASH_SIZE:
        inlenWithAsn = inlen + ASN_OVERHEAD_LEN_RSA_SHA2;
        memcpy(c, asn384dsWrap, ASN_OVERHEAD_LEN_RSA_SHA2);
        memcpy(c + ASN_OVERHEAD_LEN_RSA_SHA2, in, inlen);
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
    Initialize an allocated RSA key.

    @note that in this case, a psRsaKey_t is a structure type.
    This means that the caller must have statically or dynamically allocated
    the structure before calling this Api.

    TODO, may not be necessary, since crypt apis also take pool.
    @param[in] pool The pool to use to allocate any temporary working memory
    beyond what is provided in the 'key' structure.

    @param[in,out] key A pointer to an allocated (statically or dynamically)
    key structure to be initalized as a blank RSA keypair.
 */
int32_t psRsaInitKey(psPool_t *pool, psRsaKey_t *key)
{
    if (!key)
    {
        return PS_MEM_FAIL;
    }
    memset(key, 0x0, sizeof(psRsaKey_t));
    key->pool = pool;
    return PS_SUCCESS;
}

/*
    Zero an RSA key. The caller is responsible for freeing 'key' if it is
    allocated (or not if it is static, or stack based).
 */
void psRsaClearKey(psRsaKey_t *key)
{
    pstm_clear(&(key->N));
    pstm_clear(&(key->e));
    pstm_clear(&(key->d));
    pstm_clear(&(key->p));
    pstm_clear(&(key->q));
    pstm_clear(&(key->dP));
    pstm_clear(&(key->dQ));
    pstm_clear(&(key->qP));
    key->size = 0;
    key->optimized = 0;
    key->pool = NULL;
}

/* 'to' key digits are allocated here */
int32_t psRsaCopyKey(psRsaKey_t *to, const psRsaKey_t *from)
{
    int32_t err = 0;

    if ((err = pstm_init_copy(from->pool, &to->N, &from->N, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    if ((err = pstm_init_copy(from->pool, &to->e, &from->e, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    if ((err = pstm_init_copy(from->pool, &to->d, &from->d, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    if ((err = pstm_init_copy(from->pool, &to->p, &from->p, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    if ((err = pstm_init_copy(from->pool, &to->q, &from->q, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    if ((err = pstm_init_copy(from->pool, &to->dP, &from->dP, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    if ((err = pstm_init_copy(from->pool, &to->dQ, &from->dQ, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    if ((err = pstm_init_copy(from->pool, &to->qP, &from->qP, 0)) != PSTM_OKAY)
    {
        goto error;
    }
    to->size = from->size;
    to->optimized = from->optimized;
    to->pool = from->pool;
error:
    if (err < 0)
    {
        psRsaClearKey(to);
    }
    return err;
}
#endif /* USE_MATRIX_RSA */

#ifdef USE_RSA
/******************************************************************************/
/**
    Get the size in bytes of the RSA public exponent.
    Eg. 128 for 1024 bit RSA keys, 256 for 2048 and 512 for 4096 bit keys.
    @param[in] key RSA key
    @return Number of bytes of public exponent.
 */
psSize_t psRsaSize(const psRsaKey_t *key)
{
    return key->size;
}

/******************************************************************************/
/**
    Compare if the public modulus and exponent is the same between two keys.

    @return < 0 on failure, >= 0 on success.
 */
int32_t psRsaCmpPubKey(const psRsaKey_t *k1, const psRsaKey_t *k2)
{
    if ((pstm_cmp(&k1->N, &k2->N) == PSTM_EQ) &&
        (pstm_cmp(&k1->e, &k2->e) == PSTM_EQ))
    {
        return PS_SUCCESS;
    }
    return PS_FAIL;
}

# ifdef OLD
/******************************************************************************/
/*
 */
static int32_t getBig(psPool_t *pool, const unsigned char **pp, psSize_t len,
    pstm_int *big)
{
    const unsigned char *p = *pp;
    psSize_t vlen;

    if (len < 1 || *(p++) != ASN_INTEGER ||
        getAsnLength(&p, len - 1, &vlen) < 0 || (len - 1) < vlen)
    {
        return PS_PARSE_FAIL;
    }
    /* Make a smart size since we know the length */
    if (pstm_init_for_read_unsigned_bin(pool, big, vlen) != PSTM_OKAY)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_read_unsigned_bin(big, p, vlen) != 0)
    {
        pstm_clear(big);
        psTraceCrypto("ASN getBig failed\n");
        return PS_PARSE_FAIL;
    }
    *pp = p + vlen;
    return PS_SUCCESS;
}
# endif

/******************************************************************************/
/**
    Parse an RSA public key from an ASN.1 byte stream.
    @return < 0 on error, >= 0 on success.
 */
int32_t psRsaParseAsnPubKey(psPool_t *pool,
    const unsigned char **pp, psSize_t len,
    psRsaKey_t *key, unsigned char sha1KeyHash[SHA1_HASH_SIZE])
{
# ifdef USE_SHA1
    psDigestContext_t dc;
# endif
    const unsigned char *p = *pp;
    const unsigned char *end;
    psSize_t keylen, seqlen;

    if (len < 1 || (*(p++) != ASN_BIT_STRING) ||
        getAsnLength(&p, len - 1, &keylen) < 0 ||
        (len - 1) < keylen)
    {
        goto L_FAIL;
    }
    if (*p++ != 0)
    {
        goto L_FAIL;
    }
    if (keylen < 1)
    {
        goto L_FAIL;
    }
# ifdef USE_SHA1
    /* A public key hash is used in PKI tools (OCSP, Trusted CA indication).
        Standard RSA form - SHA-1 hash of the value of the BIT STRING
        subjectPublicKey [excluding the tag, length, and number of unused
        bits] */
    psSha1PreInit(&dc.sha1);
    psSha1Init(&dc.sha1);
    psSha1Update(&dc.sha1, p, keylen - 1);
    psSha1Final(&dc.sha1, sha1KeyHash);
# endif

    if (getAsnSequence(&p, keylen, &seqlen) < 0)
    {
        goto L_FAIL;
    }

    end = p + seqlen;
    if (pstm_read_asn(pool, &p, (uint16_t) (end - p), &key->N) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &key->e) < 0)
    {

        goto L_FAIL;
    }
    key->size = pstm_unsigned_bin_size(&key->N);
    key->pool = pool;
# ifdef USE_TILERA_RSA
#  ifdef USE_RSA_PUBLIC_NONBLOCKING
    key->nonBlock = 1;
#  else
    key->nonBlock = 0;
#  endif
# endif
    *pp = p;
    return PS_SUCCESS;
L_FAIL:
    psTraceIntCrypto("psRsaReadAsnPubKey error on byte %d\n", p - *pp);
    return PS_PARSE_FAIL;
}

# ifdef USE_PRIVATE_KEY_PARSING
/******************************************************************************/
/**
    Parse a a private key structure in DER formatted ASN.1
    Per ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
    RSAPrivateKey ::= SEQUENCE {
        version Version,
        modulus INTEGER, -- n
        publicExponent INTEGER, -- e
        privateExponent INTEGER, -- d
        prime1 INTEGER, -- p
        prime2 INTEGER, -- q
        exponent1 INTEGER, -- d mod (p-1)
        exponent2 INTEGER, -- d mod (q-1)
        coefficient INTEGER, -- (inverse of q) mod p
        otherPrimeInfos OtherPrimeInfos OPTIONAL
    }
    Version ::= INTEGER { two-prime(0), multi(1) }
      (CONSTRAINED BY {-- version must be multi if otherPrimeInfos present --})

    Which should look something like this in hex (pipe character
    is used as a delimiter):
    ftp://ftp.rsa.com/pub/pkcs/ascii/layman.asc
    30  Tag in binary: 00|1|10000 -> UNIVERSAL | CONSTRUCTED | SEQUENCE (16)
    82  Length in binary: 1 | 0000010 -> LONG LENGTH | LENGTH BYTES (2)
    04 A4       Length Bytes (1188)
    02  Tag in binary: 00|0|00010 -> UNIVERSAL | PRIMITIVE | INTEGER (2)
    01  Length in binary: 0|0000001 -> SHORT LENGTH | LENGTH (1)
    00  INTEGER value (0) - RSAPrivateKey.version
    02  Tag in binary: 00|0|00010 -> UNIVERSAL | PRIMITIVE | INTEGER (2)
    82  Length in binary: 1 | 0000010 -> LONG LENGTH | LENGTH BYTES (2)
    01 01       Length Bytes (257)
    []  257 Bytes of data - RSAPrivateKey.modulus (2048 bit key)
    02  Tag in binary: 00|0|00010 -> UNIVERSAL | PRIMITIVE | INTEGER (2)
    03  Length in binary: 0|0000011 -> SHORT LENGTH | LENGTH (3)
    01 00 01    INTEGER value (65537) - RSAPrivateKey.publicExponent
    ...

    OtherPrimeInfos is not supported in this routine, and an error will be
    returned if they are present

    @return < 0 on error, >= 0 on success.
 */
int32_t psRsaParsePkcs1PrivKey(psPool_t *pool,
    const unsigned char *p, psSize_t size,
    psRsaKey_t *key)
{
    const unsigned char *end, *seq;
    int32_t version;
    psSize_t seqlen;

    if (psRsaInitKey(pool, key) < 0)
    {
        return PS_MEM_FAIL;
    }
    end = p + size;
    if (getAsnSequence(&p, size, &seqlen) < 0)
    {
        psRsaClearKey(key);
        return PS_PARSE_FAIL;
    }
    seq = p;
    if (getAsnInteger(&p, (uint16_t) (end - p), &version) < 0 || version != 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->N)) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->e)) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->d)) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->p)) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->q)) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->dP)) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->dQ)) < 0 ||
        pstm_read_asn(pool, &p, (uint16_t) (end - p), &(key->qP)) < 0 ||
        (uint16_t) (p - seq) != seqlen)
    {

        psTraceCrypto("ASN RSA private key extract parse error\n");
        psRsaClearKey(key);
        return PS_PARSE_FAIL;
    }

#  ifdef USE_TILERA_RSA
    /*  EIP-54 usage limitation that some operands must be larger than others.
        If you are seeing RSA unpad failures after decryption, try toggling
        this swap.  It does seem to work 100% of the time by either performing
        or not performing this swap.  */
    /* EIP-24 requires dP > dQ.  Swap and recalc qP */
    if (pstm_cmp_mag(&key->p, &key->q) == PSTM_LT)
    {
        pstm_exch(&key->dP, &key->dQ);
        pstm_exch(&key->p, &key->q);
        pstm_zero(&key->qP);
        pstm_invmod(pool, &key->q, &key->p, &key->qP);
    }
#   ifdef USE_RSA_PRIVATE_NONBLOCKING
    key->nonBlock = 1;
#   else
    key->nonBlock = 0;
#   endif
#  endif /* USE_TILERA_RSA */

/*
     If we made it here, the key is ready for optimized decryption
     Set the key length of the key
 */
    key->optimized = 1;
    key->size = pstm_unsigned_bin_size(&key->N);

    /* Should be at the end */
    if (end != p)
    {
        /* If this stream came from an encrypted file, there could be
            padding bytes on the end */
        seqlen = (uint16_t) (end - p);
        while (p < end)
        {
            if (*p != seqlen)
            {
                psTraceCrypto("Problem at end of private key parse\n");
            }
            p++;
        }
    }

    return PS_SUCCESS;
}
# endif /* USE_PRIVATE_KEY_PARSING */
#endif  /* USE_RSA */

#ifdef USE_MATRIX_RSA
/******************************************************************************/
/**
    Primary RSA crypto routine, with either public or private key.

    @param[in] pool Pool to use for temporary memory allocation for this op.
    @param[in] key RSA key to use for this operation.
    @param[in] in Pointer to allocated buffer to encrypt.
    @param[in] inlen Number of bytes pointed to by 'in' to encrypt.
    @param[out] out Pointer to allocated buffer to store encrypted data.
    @param[out] outlen Number of bytes written to 'out' buffer.
    @param[in] type PS_PRIVKEY or PS_PUBKEY.
    @param[in] data TODO Hardware context.

    @return 0 on success, < 0 on failure.

    @note 'out' and 'in' can be equal for in-situ operation.
 */
int32_t psRsaCrypt(psPool_t *pool, psRsaKey_t *key,
    const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t *outlen,
    uint8_t type, void *data)
{
    pstm_int tmp, tmpa, tmpb;
    int32_t res;
    uint32_t x;

    if (in == NULL || out == NULL || outlen == NULL || key == NULL)
    {
        psTraceCrypto("NULL parameter error in psRsaCrypt\n");
        return PS_ARG_FAIL;
    }

    tmp.dp = tmpa.dp = tmpb.dp = NULL;

        /* Init and copy into tmp */
    if (pstm_init_for_read_unsigned_bin(pool, &tmp, inlen + sizeof(pstm_digit))
        != PS_SUCCESS)
    {
        return PS_FAILURE;
    }
    if (pstm_read_unsigned_bin(&tmp, (unsigned char *) in, inlen) != PS_SUCCESS)
    {
        pstm_clear(&tmp);
        return PS_FAILURE;
    }
    /* Sanity check on the input */
    if (pstm_cmp(&key->N, &tmp) == PSTM_LT)
    {
        res = PS_LIMIT_FAIL;
        goto done;
    }
    if (type == PS_PRIVKEY)
    {
        if (key->optimized)
        {
            if (pstm_init_size(pool, &tmpa, key->p.alloc) != PS_SUCCESS)
            {
                res = PS_FAILURE;
                goto done;
            }
            if (pstm_init_size(pool, &tmpb, key->q.alloc) != PS_SUCCESS)
            {
                pstm_clear(&tmpa);
                res = PS_FAILURE;
                goto done;
            }
            if (pstm_exptmod(pool, &tmp, &key->dP, &key->p, &tmpa) !=
                PS_SUCCESS)
            {
                psTraceCrypto("decrypt error: pstm_exptmod dP, p\n");
                goto error;
            }
            if (pstm_exptmod(pool, &tmp, &key->dQ, &key->q, &tmpb) !=
                PS_SUCCESS)
            {
                psTraceCrypto("decrypt error: pstm_exptmod dQ, q\n");
                goto error;
            }
            if (pstm_sub(&tmpa, &tmpb, &tmp) != PS_SUCCESS)
            {
                psTraceCrypto("decrypt error: sub tmpb, tmp\n");
                goto error;
            }
            if (pstm_mulmod(pool, &tmp, &key->qP, &key->p, &tmp) != PS_SUCCESS)
            {
                psTraceCrypto("decrypt error: pstm_mulmod qP, p\n");
                goto error;
            }
            if (pstm_mul_comba(pool, &tmp, &key->q, &tmp, NULL, 0)
                != PS_SUCCESS)
            {
                psTraceCrypto("decrypt error: pstm_mul q \n");
                goto error;
            }
            if (pstm_add(&tmp, &tmpb, &tmp) != PS_SUCCESS)
            {
                psTraceCrypto("decrypt error: pstm_add tmp \n");
                goto error;
            }
        }
        else
        {
            if (pstm_exptmod(pool, &tmp, &key->d, &key->N, &tmp) !=
                PS_SUCCESS)
            {
                psTraceCrypto("psRsaCrypt error: pstm_exptmod\n");
                goto error;
            }
        }
    }
    else if (type == PS_PUBKEY)
    {
        if (pstm_exptmod(pool, &tmp, &key->e, &key->N, &tmp) != PS_SUCCESS)
        {
            psTraceCrypto("psRsaCrypt error: pstm_exptmod\n");
            goto error;
        }
    }
    else
    {
        psTraceCrypto("psRsaCrypt error: invalid type param\n");
        goto error;
    }
    /* Read it back */
    x = pstm_unsigned_bin_size(&key->N);

    if ((uint32) x > *outlen)
    {
        res = -1;
        psTraceCrypto("psRsaCrypt error: pstm_unsigned_bin_size\n");
        goto done;
    }
    /* We want the encrypted value to always be the key size.  Pad with 0x0 */
    while ((uint32) x < (unsigned long) key->size)
    {
        *out++ = 0x0;
        x++;
    }

    *outlen = x;
    /* Convert it */
    memset(out, 0x0, x);

    if (pstm_to_unsigned_bin(pool, &tmp, out + (x - pstm_unsigned_bin_size(&tmp)))
        != PS_SUCCESS)
    {
        psTraceCrypto("psRsaCrypt error: pstm_to_unsigned_bin\n");
        goto error;
    }
    /* Clean up and return */
    res = PS_SUCCESS;
    goto done;
error:
    res = PS_FAILURE;
done:
    if (type == PS_PRIVKEY && key->optimized)
    {
        pstm_clear_multi(&tmpa, &tmpb, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    pstm_clear(&tmp);
    return res;
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
    memcpy(tmpout, out, outlen);
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
    memset(in, 0x0, inlen);
    return err;
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
    int32_t err;
    psSize_t ptLen;

    if (inlen != key->size)
    {
        psTraceCrypto("Error on bad inlen parameter to psRsaDecryptPub\n");
        return PS_ARG_FAIL;
    }
    ptLen = inlen;
    if ((err = psRsaCrypt(pool, key, in, inlen, in, &ptLen,
             PS_PUBKEY, data)) < PS_SUCCESS)
    {
        psTraceCrypto("Error performing psRsaDecryptPub\n");
        return err;
    }
    if (ptLen != inlen)
    {
        psTraceIntCrypto("Decrypted size error in psRsaDecryptPub %d\n", ptLen);
        return PS_FAILURE;
    }
    if ((err = pkcs1Unpad(in, inlen, out, outlen, PS_PUBKEY)) < 0)
    {
        return err;
    }
    return PS_SUCCESS;
}

#endif  /* USE_MATRIX_RSA */

/******************************************************************************/

