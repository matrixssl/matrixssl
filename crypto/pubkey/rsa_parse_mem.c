/**
 *      @file    rsa_parse_mem.c
 *      @version $Format:%h%d$
 *
 *      Functions for parsing RSA keys from memory.
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

#ifdef USE_RSA

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

int32_t psRsaParsePubKeyMem(psPool_t *pool,
        unsigned char *pemOrDerBuf,
        psSizeL_t pemOrDerBufLen,
        const char *password,
        psRsaKey_t *key)
{
    int32_t rc;
    unsigned char *der;
    psSizeL_t derLen;
    const unsigned char *pubKeyBitString;
    unsigned char sha1KeyHash[SHA1_HASHLEN];
    int32_t algId;

    rc = psPemTryDecode(pool,
            pemOrDerBuf,
            pemOrDerBufLen,
            PEM_TYPE_PUBLIC_KEY,
            password,
            &der,
            &derLen);
    if (rc != PS_SUCCESS)
    {
        /* Input not PEM. */
        der = pemOrDerBuf;
        derLen = pemOrDerBufLen;
    }

    rc = psParseSubjectPublicKeyInfo(pool,
            der,
            derLen,
            &algId,
            NULL, NULL,
            &pubKeyBitString);
    if (rc != PS_SUCCESS)
    {
        psTraceCrypto("psRsaParsePubKeyMem: SPKI parse failed\n");
        goto out;
    }

    rc = psRsaParseAsnPubKey(pool,
            &pubKeyBitString,
            derLen - (pubKeyBitString - pemOrDerBuf),
            key,
            sha1KeyHash);
    if (rc != PS_SUCCESS)
    {
        psTraceCrypto("psRsaParseAsnPubKey failed\n");
        goto out;
    }

    rc = PS_SUCCESS;

out:
    if (der != pemOrDerBuf)
    {
        psFree(der, pool);
    }
    return rc;
}

# endif /* USE_PRIVATE_KEY_PARSING */

#endif  /* USE_RSA */

/******************************************************************************/

