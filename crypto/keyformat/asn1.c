/**
 *      @file    asn1.c
 *      @version $Format:%h%d$
 *
 *      DER/BER coding.
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

/* Compute tag length when it is known that p points to valid ASN.1 DER
   encoding, no larger than 16 megabytes. */
uint32_t getAsnTagLenUnsafe(const unsigned char *p)
{
    uint32_t len;

    /* Return 0 for uninitialized data or NULL. */
    if (p == NULL || *p == 0)
    {
        return 0;
    }
    len = p[1];
    if (len >= 0x80)
    {
        unsigned char lenbytes[3] = { 0, 0, 0 }; /* Size up-to 16 Mbytes. */
        len -= 0x80; /* Compute number of bytes in encoding. */
        if (len == 0 || len >= 4)
        {
            /* Although the function is "Unsafe", check for too long
               length encoding, because in future some parser may accept
               input > 4 gigabytes. */
            return 0; /* Too large length. */
        }
        /* Note: */
        memcpy(lenbytes + 3 - len, p + 2, len);
        len =
            len + 2 +
            ((lenbytes[0] << 16) |
             (lenbytes[1] << 8) |
             (lenbytes[2] << 0));
    }
    else
    {
        len += 2; /* Tag and length byte. */
    }
    return len;
}

/******************************************************************************/
/*
    On success, p will be updated to point to first character of value and
    len will contain number of bytes in value.

    Indefinite length formats return ASN_UNKNOWN_LEN and *len will simply
    be updated with the overall remaining length
 */
int32_t getAsnLength(const unsigned char **pp, psSize_t size, psSize_t *len)
{
    uint32_t len32 = 0;
    int32_t rc;

    if ((rc = getAsnLength32(pp, size, &len32, 0)) < 0)
    {
        return rc;
    }
    *len = (uint16_t) (len32 & 0xFFFF);
    return PS_SUCCESS;
}

int32_t getAsnLength32(const unsigned char **pp, uint32_t size, uint32_t *len,
    uint32_t indefinite)
{
    const unsigned char *c, *end;
    uint32_t l;

    c = *pp;
    end = c + size;
    *len = 0;
    if (end - c < 1)
    {
        psTraceCrypto("getAsnLength called on empty buffer\n");
        return PS_LIMIT_FAIL;
    }
/*
    If the high bit is set, the lower 7 bits represent the number of
    bytes that follow defining length
    If the high bit is not set, the lower 7 represent the actual length
 */
    l = *c & 0x7F;
    if (*c & 0x80)
    {
        /* Point c at first length byte */
        c++;
        /* Ensure we have that many bytes left in the buffer.  */
        if (end - c < l)
        {
            psTraceCrypto("Malformed stream in getAsnLength\n");
            return PS_LIMIT_FAIL;
        }

        switch (l)
        {
        case 4:
            l = *c << 24; c++;
            l |= *c << 16; c++;
            l |= *c << 8; c++;
            l |= *c; c++;
            break;
        case 3:
            l = *c << 16; c++;
            l |= *c << 8; c++;
            l |= *c; c++;
            break;
        case 2:
            l = *c << 8; c++;
            l |= *c; c++;
            break;
        case 1:
            l = *c; c++;
            break;
/*
        If the length byte has high bit only set, it's an indefinite
        length. If allowed, return the number of bytes remaining in buffer.
 */
        case 0:
            if (indefinite)
            {
                *pp = c;
                *len = size - 1;
                return ASN_UNKNOWN_LEN;
            }
            return PS_LIMIT_FAIL;

        /* Make sure there aren't more than 4 bytes of length specifier. */
        default:
            psTraceCrypto("Malformed stream in getAsnLength\n");
            return PS_LIMIT_FAIL;
        }
    }
    else
    {
        c++;
    }

    /* Stream parsers will not require the entire data to be present */
    if (!indefinite && (end - c < l))
    {
        psTraceCrypto("getAsnLength longer than remaining buffer.\n");
        return PS_LIMIT_FAIL;
    }

    *pp = c;
    *len = l;
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Callback to extract a sequence length from the DER stream
    Verifies that 'len' bytes are >= 'seqlen'
    Move pp to the first character in the sequence
 */
/* #define DISABLE_STRICT_ASN_LENGTH_CHECK */
int32_t getAsnSequence32(const unsigned char **pp, uint32_t size,
    uint32_t *len, uint32_t indefinite)
{
    const unsigned char *p = *pp;
    int32_t rc;

    rc = PS_PARSE_FAIL;
    if (size < 1 || *(p++) != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
        ((rc = getAsnLength32(&p, size - 1, len, indefinite)) < 0))
    {
        psTraceCrypto("ASN getSequence failed\n");
        return rc;
    }
#ifndef DISABLE_STRICT_ASN_LENGTH_CHECK
    /* The (p - *pp) is taking the length encoding bytes into account */
    if (!indefinite && (size - ((uint32_t) (p - *pp))) < *len)
    {
        /* It isn't cool but some encodings have an outer length layer that
            is smaller than the inner.  Normally you'll want this check but if
            you're hitting this case, you could try skipping it to see if there
            is an error in the encoding */
        psTraceCrypto("ASN_SEQUENCE parse found length greater than total\n");
        psTraceCrypto("Could try enabling DISABLE_STRICT_ASN_LENGTH_CHECK\n");
        return PS_LIMIT_FAIL;
    }
#endif
    *pp = p;
    return rc;
}

int32_t getAsnSequence(const unsigned char **pp, psSize_t size, psSize_t *len)
{
    uint32_t len32 = 0;
    int32_t rc;

    if ((rc = getAsnSequence32(pp, size, &len32, 0)) < 0)
    {
        return rc;
    }
    *len = (uint16_t) (len32 & 0xFFFF);
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Extract a set length from the DER stream.  Will also test that there
    is enough data available to hold it all.  Returns LIMIT_FAIL if not.
 */
int32_t getAsnSet32(const unsigned char **pp, uint32_t size, uint32_t *len,
    uint32_t indefinite)
{
    const unsigned char *p = *pp;
    int32_t rc;

    rc = PS_PARSE_FAIL;
    if (size < 1 || *(p++) != (ASN_SET | ASN_CONSTRUCTED) ||
        ((rc = getAsnLength32(&p, size - 1, len, indefinite)) < 0))
    {
        psTraceCrypto("ASN getSet failed\n");
        return rc;
    }
    /* Account for overhead needed to get the length */
    if (size < ((uint32_t) (p - *pp) + *len))
    {
        return PS_LIMIT_FAIL;
    }
    *pp = p;
    return rc;
}

int32_t getAsnSet(const unsigned char **pp, psSize_t size, psSize_t *len)
{
    uint32_t len32 = 0;
    int32_t rc;

    if ((rc = getAsnSet32(pp, size, &len32, 0)) < 0)
    {
        return rc;
    }
    *len = (uint16_t) (len32 & 0xFFFF);
    return PS_SUCCESS;
}
/******************************************************************************/
/*
    Get an enumerated value
 */
int32_t getAsnEnumerated(const unsigned char **pp, uint32_t len, int32_t *val)
{
    const unsigned char *p = *pp, *end;
    uint32_t ui, slen;
    int32_t rc;
    uint32_t vlen;

    rc = PS_PARSE_FAIL;
    end = p + len;
    if (len < 1 || *(p++) != ASN_ENUMERATED ||
        ((rc = getAsnLength32(&p, len - 1, &vlen, 0)) < 0))
    {
        psTraceCrypto("ASN getInteger failed from the start\n");
        return rc;
    }
/*
    This check prevents us from having a big positive integer where the
    high bit is set because it will be encoded as 5 bytes (with leading
    blank byte).  If that is required, a getUnsigned routine should be used
 */
    if (vlen > sizeof(int32_t) || (uint32_t) (end - p) < vlen)
    {
        psTraceCrypto("ASN getInteger had limit failure\n");
        return PS_LIMIT_FAIL;
    }
    ui = 0;
/*
    If high bit is set, it's a negative integer, so perform the two's compliment
    Otherwise do a standard big endian read (most likely case for RSA)
 */
    if (*p & 0x80)
    {
        while (vlen > 0)
        {
            ui = (ui << 8) | (*p ^ 0xFF);
            p++;
            vlen--;
        }
        slen = ui;
        slen++;
        slen = -slen;
        *val = slen;
    }
    else
    {
        while (vlen > 0)
        {
            ui = (ui << 8) | *p;
            p++;
            vlen--;
        }
        *val = ui;
    }
    *pp = p;
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Get an integer
 */
int32_t getAsnInteger(const unsigned char **pp, uint32_t len, int32_t *val)
{
    const unsigned char *p = *pp, *end;
    uint32_t ui, slen;
    int32_t rc;
    uint32_t vlen;

    rc = PS_PARSE_FAIL;
    end = p + len;
    if (len < 1 || *(p++) != ASN_INTEGER ||
        ((rc = getAsnLength32(&p, len - 1, &vlen, 0)) < 0))
    {
        psTraceCrypto("ASN getInteger failed from the start\n");
        return rc;
    }
/*
    This check prevents us from having a big positive integer where the
    high bit is set because it will be encoded as 5 bytes (with leading
    blank byte).  If that is required, a getUnsigned routine should be used
 */
    if (vlen > sizeof(int32_t) || (uint32_t) (end - p) < vlen)
    {
        psTraceCrypto("ASN getInteger had limit failure\n");
        return PS_LIMIT_FAIL;
    }
    ui = 0;
/*
    If high bit is set, it's a negative integer, so perform the two's compliment
    Otherwise do a standard big endian read (most likely case for RSA)
 */
    if (*p & 0x80)
    {
        while (vlen > 0)
        {
            ui = (ui << 8) | (*p ^ 0xFF);
            p++;
            vlen--;
        }
        slen = ui;
        slen++;
        slen = -slen;
        *val = slen;
    }
    else
    {
        while (vlen > 0)
        {
            ui = (ui << 8) | *p;
            p++;
            vlen--;
        }
        *val = ui;
    }
    *pp = p;
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Implementation specific OID parser
 */
int32_t getAsnAlgorithmIdentifier(const unsigned char **pp, uint32_t len,
    int32_t *oi, psSize_t *paramLen)
{
    const unsigned char *p = *pp, *end;
    int32_t rc;
    uint32_t llen;

    rc = PS_PARSE_FAIL;
    end = p + len;
    if (len < 1 || (rc = getAsnSequence32(&p, len, &llen, 0)) < 0)
    {
        psTraceCrypto("getAsnAlgorithmIdentifier failed on inital parse\n");
        return rc;
    }
    /* Always checks for parameter length */
    if (end - p < 1)
    {
        return PS_LIMIT_FAIL;
    }
    rc = getAsnOID(&p, llen, oi, 1, paramLen);
    *pp = p;
    return rc;
}

/******************************************************************************/
/**
    Parse ASN.1 DER encoded OBJECT bytes into an OID array.
    @param[in] der Pointer to start of OBJECT encoding.
    @param[in] derlen Number of bytes pointed to by 'der'.
    @param[out] oid Caller allocated array to receive OID, of
    at least MAX_OID_LEN elements.
    @return Number of OID elements written to 'oid', 0 on error.
 */
uint8_t asnParseOid(const unsigned char *der, psSize_t derlen,
    uint32_t oid[MAX_OID_LEN])
{
    const unsigned char *end;
    uint8_t n, sanity;

    if (derlen < 1)
    {
        return 0;
    }
    end = der + derlen;
    /* First two OID elements are single octet, base 40 for some reason */
    oid[0] = *der / 40;
    oid[1] = *der % 40;
    der++;
    /* Zero the remainder of OID and leave n == 2 */
    for (n = MAX_OID_LEN - 1; n > 2; n--)
    {
        oid[n] = 0;
    }
    while (der < end && n < MAX_OID_LEN)
    {
        /* If the high bit is 0, it's short form variable length quantity */
        if (!(*der & 0x80))
        {
            oid[n++] = *der++;
        }
        else
        {
            sanity = 0;
            /* Long form. High bit means another (lower) 7 bits following */
            do
            {
                oid[n] |= (*der & 0x7F);
                /* A clear high bit ends the byte sequence */
                if (!(*der & 0x80))
                {
                    break;
                }
                /* Allow a maximum of 4 x 7 bit shifts (28 bits) */
                if (++sanity > 4)
                {
                    return 0;
                }
                /* Make room for the next 7 bits */
                oid[n] <<= 7;
                der++;
            }
            while (der < end);
            der++;
            n++;
        }
    }
    if (n < MAX_OID_LEN)
    {
        return n;
    }
    return 0;
}

#ifndef MATRIXSSL_NO_OID_DATABASE

/* This function uses computed OID sums as base and adds suitable number of
   multiples of OID_COLLISION in case the first known oid with the number
   did not match. If function fails the value will be >= 32768. */
static void checkAsnOidDatabase(int32_t *oi,
    const unsigned char *oidStart,
    uint32_t oidLen)
{
    /* The values are represented as C strings, although they contain
       binary data. Therefore the type needs to be const char *. */
    const char *oid_hex;

    /* Loop until match is found, adding multiples of OID_COLLISION in case of
       mismatch. */
    while (1)
    {
        switch (*oi)
        {
        case OID_SHA1_ALG: oid_hex = OID_SHA1_ALG_HEX; break;
        case OID_SHA224_ALG: oid_hex = OID_SHA224_ALG_HEX; break;
        case OID_SHA256_ALG: oid_hex = OID_SHA256_ALG_HEX; break;
        case OID_SHA384_ALG: oid_hex = OID_SHA384_ALG_HEX; break;
        case OID_SHA512_ALG: oid_hex = OID_SHA512_ALG_HEX; break;
        case OID_MD2_ALG: oid_hex = OID_MD2_ALG_HEX; break;
        case OID_MD5_ALG: oid_hex = OID_MD5_ALG_HEX; break;
        case OID_MD2_RSA_SIG: oid_hex = OID_MD2_RSA_SIG_HEX; break;
        case OID_MD5_RSA_SIG: oid_hex = OID_MD5_RSA_SIG_HEX; break;
        case OID_SHA1_RSA_SIG: oid_hex = OID_SHA1_RSA_SIG_HEX; break;
        case OID_SHA1_RSA_SIG2: oid_hex = OID_SHA1_RSA_SIG2_HEX; break;
        case OID_ID_MGF1: oid_hex = OID_ID_MGF1_HEX; break;
        case OID_RSASSA_PSS: oid_hex = OID_RSASSA_PSS_HEX; break;
        case OID_SHA224_RSA_SIG: oid_hex = OID_SHA224_RSA_SIG_HEX; break;
        case OID_SHA256_RSA_SIG: oid_hex = OID_SHA256_RSA_SIG_HEX; break;
        case OID_SHA384_RSA_SIG: oid_hex = OID_SHA384_RSA_SIG_HEX; break;
        case OID_SHA512_RSA_SIG: oid_hex = OID_SHA512_RSA_SIG_HEX; break;
        case OID_SHA1_DSA_SIG: oid_hex = OID_SHA1_DSA_SIG_HEX; break;
        case OID_SHA1_ECDSA_SIG: oid_hex = OID_SHA1_ECDSA_SIG_HEX; break;
        case OID_SHA224_ECDSA_SIG: oid_hex = OID_SHA224_ECDSA_SIG_HEX; break;
        case OID_SHA256_ECDSA_SIG: oid_hex = OID_SHA256_ECDSA_SIG_HEX; break;
        case OID_SHA384_ECDSA_SIG: oid_hex = OID_SHA384_ECDSA_SIG_HEX; break;
        case OID_SHA512_ECDSA_SIG: oid_hex = OID_SHA512_ECDSA_SIG_HEX; break;
        case OID_RSA_KEY_ALG: oid_hex = OID_RSA_KEY_ALG_HEX; break;
        case OID_DSA_KEY_ALG: oid_hex = OID_DSA_KEY_ALG_HEX; break;
        case OID_ECDSA_KEY_ALG: oid_hex = OID_ECDSA_KEY_ALG_HEX; break;
        case OID_DES_EDE3_CBC: oid_hex = OID_DES_EDE3_CBC_HEX; break;
        case OID_AES_128_CBC: oid_hex = OID_AES_128_CBC_HEX; break;
        case OID_AES_128_WRAP: oid_hex = OID_AES_128_WRAP_HEX; break;
        case OID_AES_128_GCM: oid_hex = OID_AES_128_GCM_HEX; break;
        case OID_AES_192_CBC: oid_hex = OID_AES_192_CBC_HEX; break;
        case OID_AES_192_WRAP: oid_hex = OID_AES_192_WRAP_HEX; break;
        case OID_AES_192_GCM: oid_hex = OID_AES_192_GCM_HEX; break;
        case OID_AES_256_CBC: oid_hex = OID_AES_256_CBC_HEX; break;
        case OID_AES_256_WRAP: oid_hex = OID_AES_256_WRAP_HEX; break;
        case OID_AES_256_GCM: oid_hex = OID_AES_256_GCM_HEX; break;
        case OID_AES_CMAC: oid_hex = OID_AES_CMAC_HEX; break;
        case OID_AES_CBC_CMAC_128: oid_hex = OID_AES_CBC_CMAC_128_HEX; break;
        case OID_AES_CBC_CMAC_192: oid_hex = OID_AES_CBC_CMAC_192_HEX; break;
        case OID_AES_CBC_CMAC_256: oid_hex = OID_AES_CBC_CMAC_256_HEX; break;
        case OID_AUTH_ENC_256_SUM: oid_hex = OID_AUTH_ENC_256_SUM_HEX; break;
        case OID_PKCS_PBKDF2: oid_hex = OID_PKCS_PBKDF2_HEX; break;
        case OID_PKCS_PBES2: oid_hex = OID_PKCS_PBES2_HEX; break;
        case OID_PKCS_PBESHA128RC4: oid_hex = OID_PKCS_PBESHA128RC4_HEX; break;
        case OID_PKCS_PBESHA40RC4: oid_hex = OID_PKCS_PBESHA40RC4_HEX; break;
        case OID_PKCS_PBESHA3DES3: oid_hex = OID_PKCS_PBESHA3DES3_HEX; break;
        case OID_PKCS_PBESHA2DES3: oid_hex = OID_PKCS_PBESHA2DES3_HEX; break;
        case OID_PKCS_PBESHA128RC2: oid_hex = OID_PKCS_PBESHA128RC2_HEX; break;
        case OID_PKCS_PBESHA40RC2: oid_hex = OID_PKCS_PBESHA40RC2_HEX; break;
        case OID_PKCS12_BAG_TYPE_KEY: oid_hex = OID_PKCS12_BAG_TYPE_KEY_HEX; break;
        case OID_PKCS12_BAG_TYPE_SHROUD: oid_hex = OID_PKCS12_BAG_TYPE_SHROUD_HEX; break;
        case OID_PKCS12_BAG_TYPE_CERT: oid_hex = OID_PKCS12_BAG_TYPE_CERT_HEX; break;
        case OID_PKCS12_BAG_TYPE_CRL: oid_hex = OID_PKCS12_BAG_TYPE_CRL_HEX; break;
        case OID_PKCS12_BAG_TYPE_SECRET: oid_hex = OID_PKCS12_BAG_TYPE_SECRET_HEX; break;
        case OID_PKCS12_BAG_TYPE_SAFE: oid_hex = OID_PKCS12_BAG_TYPE_SAFE_HEX; break;
        case OID_PKCS9_CERT_TYPE_X509: oid_hex = OID_PKCS9_CERT_TYPE_X509_HEX; break;
        case OID_PKCS9_CERT_TYPE_SDSI: oid_hex = OID_PKCS9_CERT_TYPE_SDSI_HEX; break;
        case OID_PKCS7_DATA: oid_hex = OID_PKCS7_DATA_HEX; break;
        case OID_PKCS7_SIGNED_DATA: oid_hex = OID_PKCS7_SIGNED_DATA_HEX; break;
        case OID_PKCS7_ENVELOPED_DATA: oid_hex = OID_PKCS7_ENVELOPED_DATA_HEX; break;
        case OID_PKCS7_SIGNED_ENVELOPED_DATA: oid_hex = OID_PKCS7_SIGNED_ENVELOPED_DATA_HEX; break;
        case OID_PKCS7_DIGESTED_DATA: oid_hex = OID_PKCS7_DIGESTED_DATA_HEX; break;
        case OID_PKCS7_ENCRYPTED_DATA: oid_hex = OID_PKCS7_ENCRYPTED_DATA_HEX; break;
        case OID_OCSP: oid_hex = OID_OCSP_HEX; break;
        case OID_BASIC_OCSP_RESPONSE: oid_hex = OID_BASIC_OCSP_RESPONSE_HEX; break;
        case OID_ECKA_EG_X963KDF_SHA256: oid_hex = OID_ECKA_EG_X963KDF_SHA256_HEX; break;
        case OID_ECKA_EG_X963KDF_SHA384: oid_hex = OID_ECKA_EG_X963KDF_SHA384_HEX; break;
        case OID_ECKA_EG_X963KDF_SHA512: oid_hex = OID_ECKA_EG_X963KDF_SHA512_HEX; break;
        case OID_DHSINGLEPASS_STDDH_SHA1KDF_SCHEME: oid_hex = OID_DHSINGLEPASS_STDDH_SHA1KDF_SCHEME_HEX; break;
        case OID_DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME: oid_hex = OID_DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME_HEX; break;
        case OID_MQVSINGLEPASS_SHA1KDF_SCHEME: oid_hex = OID_MQVSINGLEPASS_SHA1KDF_SCHEME_HEX; break;
        case OID_DHSINGLEPASS_STDDH_SHA256KDF_SCHEME: oid_hex = OID_DHSINGLEPASS_STDDH_SHA256KDF_SCHEME_HEX; break;
        case OID_DHSINGLEPASS_STDDH_SHA384KDF_SCHEME: oid_hex = OID_DHSINGLEPASS_STDDH_SHA384KDF_SCHEME_HEX; break;
        case OID_DHSINGLEPASS_STDDH_SHA512KDF_SCHEME: oid_hex = OID_DHSINGLEPASS_STDDH_SHA512KDF_SCHEME_HEX; break;   
        default:
            /* No possible matches: bitwise-add not found constant to OID. */
            *oi |= OID_NOT_FOUND;
            return;
        }
        /* Ignore tag, but use length byte and data from binary oid. */
        if (oidLen == oid_hex[1] && !memcmp(oidStart, &oid_hex[2], oidLen))
        {
            return; /* Success */
        }
        *oi += OID_COLLISION;
    }
}
#endif /* MATRIXSSL_NO_OID_DATABASE */

/******************************************************************************/

int32_t getAsnOID(const unsigned char **pp, uint32_t len, int32_t *oi,
    uint8_t checkForParams, psSize_t *paramLen)
{
    const unsigned char *p = *pp, *end;
    int32_t plen, rc;
    uint32_t arcLen;
    const unsigned char *oidStart;
    uint32_t oidLen;

    rc = PS_PARSE_FAIL;
    end = p + len;
    plen = end - p;

    if (len < 1)
    {
        psTraceCrypto("Malformed algorithmId 1\n");
        return rc;
    }

    if (*(p++) != ASN_OID || (rc = getAsnLength32(&p, (uint32_t) (end - p), &arcLen, 0))
        < 0)
    {
        psTraceCrypto("Malformed algorithmId 2\n");
        return rc;
    }
    if (end - p < arcLen)
    {
        return PS_LIMIT_FAIL;
    }
    if (end - p < 2)
    {
        psTraceCrypto("Malformed algorithmId 3\n");
        return PS_LIMIT_FAIL;
    }
    *oi = 0;
    oidStart = p;
    oidLen = arcLen;
    while (arcLen > 0)
    {
        *oi += *p;
        p++;
        arcLen--;
    }

#ifndef MATRIXSSL_NO_OID_DATABASE
    checkAsnOidDatabase(oi, oidStart, oidLen);
#endif /* MATRIXSSL_NO_OID_DATABASE */

    if (checkForParams)
    {
        plen -= (end - p);
        *paramLen = len - plen;

        if (*paramLen < 1 || *p != ASN_NULL)
        {
            *pp = p;
            /* paramLen tells whether params exist or completely missing (0) */
            if (*paramLen > 0)
            {
                /* psTraceIntCrypto("OID %d has parameters to process\n", *oi); */
            }
            return PS_SUCCESS;
        }
        /* NULL parameter case.  Somewhat common.  Skip it for the caller */
        if (end - p < 2)
        {
            psTraceCrypto("Malformed algorithmId 4\n");
            return PS_LIMIT_FAIL;
        }
        if (*paramLen < 2)
        {
            psTraceCrypto("Malformed algorithmId 5\n");
            return PS_LIMIT_FAIL;
        }
        *paramLen -= 2; /* 1 for the OID tag and 1 for the NULL */
        *pp = p + 2;
    }
    else
    {
        *paramLen = 0;
        *pp = p;
    }
    return PS_SUCCESS;
}

/******************************************************************************/

