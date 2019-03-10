/**
 *      @file    ecc_parse_mem.c
 *      @version $Format:%h%d$
 *
 *      Functions for parsing ECC keys from memory.
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

#ifdef USE_MATRIX_ECC

/*****************************************************************************/
/*
    Called from the cert parse.  The initial bytes in this stream are
    technically the EcpkParameters from the ECDSA pub key OBJECT IDENTIFIER
    that name the curve.  The asnGetAlgorithmIdentifier call right before
    this just stripped out the OID
 */
int32_t getEcPubKey(psPool_t *pool, const unsigned char **pp, psSize_t len,
    psEccKey_t *pubKey, unsigned char sha1KeyHash[SHA1_HASH_SIZE])
{
# ifdef USE_SHA1
    psDigestContext_t dc;
# endif
    const psEccCurve_t *eccCurve;
    const unsigned char *p = *pp, *end;
    int32_t oid;
    psSize_t arcLen;
    uint8_t ignore_bits;

    end = p + len;
    if (len < 1 ||
        *(p++) != ASN_OID ||
        getAsnLength(&p, (uint16_t) (end - p), &arcLen) < 0 ||
        (uint16_t) (end - p) < arcLen)
    {

        psTraceCrypto("Only namedCurve types are supported in EC certs\n");
        return PS_PARSE_FAIL;
    }
/*
    NamedCurve OIDs

    ansi-x9-62 OBJECT IDENTIFER ::= {
        iso(1) member-body(2) us(840) 10045
    }

    secp192r1 OBJECT IDENTIFIER ::= { ansi-x9-62 curves(3) prime(1) 1 }
        2a8648ce3d030101 -> sum = 520

    secp256r1 OBJECT IDENTIFIER ::= { ansi-x9-62 curves(3) prime(1) 7 }
        2a8648ce3d030107 -> sum = 526
 */
    /* Note arcLen could be zero here */
    oid = 0;
    while (arcLen > 0)
    {
        oid += *p++;
        arcLen--;
    }
    /* Match the sum against our list of curves to make sure we got it */
    if (getEccParamByOid(oid, &eccCurve) < 0)
    {
        psTraceCrypto("Cert named curve not found in eccCurve list\n");
        return PS_UNSUPPORTED_FAIL;
    }

    if ((uint16_t) (end - p) < 1 || (*(p++) != ASN_BIT_STRING) ||
        getAsnLength(&p, len - 1, &arcLen) < 0 ||
        (uint16_t) (end - p) < arcLen ||
        arcLen < 1)
    {

        psTraceCrypto("Unexpected ECC pubkey format\n");
        return PS_PARSE_FAIL;
    }
    ignore_bits = *p++;
    arcLen--;
    if (ignore_bits != 0)
    {
        psTraceCrypto("Unexpected ECC ignore_bits\n");
    }

# ifdef USE_SHA1
    /* A public key hash is used in PKI tools (OCSP, Trusted CA indication).
        Standard form - SHA-1 hash of the value of the BIT STRING
        subjectPublicKey [excluding the tag, length, and number of unused
        bits] */
    psSha1PreInit(&dc.sha1);
    psSha1Init(&dc.sha1);
    psSha1Update(&dc.sha1, p, arcLen);
    psSha1Final(&dc.sha1, sha1KeyHash);
# endif

    /* Note arcLen could again be zero here */
    if (psEccX963ImportKey(pool, p, arcLen, pubKey, eccCurve) < 0)
    {
        psTraceCrypto("Unable to parse ECC pubkey from cert\n");
        return PS_PARSE_FAIL;
    }
    p += arcLen;

    *pp = p;

    return PS_SUCCESS;
}

# ifdef USE_ED25519
int32_t psEd25519ParsePrivKey(psPool_t *pool,
        const unsigned char *keyBuf,
        psSize_t keyBufLen,
        psCurve25519Key_t *key)
{
    psParseBuf_t pb, pb2, pb3;
    int32_t rc;
    size_t len;
    unsigned char version;
    psCurve25519Key_t pubKey;

    /*
      RFC 5958:

      OneAsymmetricKey ::= SEQUENCE {
         version Version,
         privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
         privateKey PrivateKey,
         attributes [0] IMPLICIT Attributes OPTIONAL,
         ...,
         [[2: publicKey [1] IMPLICIT PublicKey OPTIONAL ]],
         ...
      }
      Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)
      PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
                                        { PUBLIC-KEY,
                                          { PrivateKeyAlgorithms } }
      Attributes ::= SET OF Attribute { { OneAsymmetricKeyAttributes } }
      PrivateKey ::= OCTET STRING
      PublicKey ::= BIT STRING

      draft-ietf-curdle-pkix-08:

      CurvePrivateKey ::= OCTET STRING
      "For the keys defined in this document, the private key is always an
      opaque byte sequence.  The ASN.1 type CurvePrivateKey is defined in
      this document to hold the byte sequence.  Thus when encoding a
      OneAsymmetricKey object, the private key is wrapped in an
      CurvePrivateKey object and wrapped by the OCTET STRING of the
      "privateKey" field."
    */
    psAssert(key);

    rc = psParseBufFromStaticData(&pb, keyBuf, keyBufLen);
    if (rc < 0)
    {
        psTraceCrypto("Unable to init parse buf\n");
        return rc;
    }

    len = psParseBufTryReadTagSub(&pb, &pb2, 0x30);
    if (len == 0)
    {
        psTraceCrypto("Error: no SEQUENCE tag\n");
        return PS_PARSE_FAIL;
    }

    /* version Version
       Only handle single octet version numbers 0, 1 and 2. */
    len = psParseBufTrySkipBytes(&pb2,
            (const unsigned char *)
            "\x02\x01", 2);
    if (len != 2)
    {
        psTraceCrypto("Error: invalid version encoding.\n");
        return PS_PARSE_FAIL;
    }
    if (psParseOctet(&pb2, &version) != 1
            || (version != 0 && version != 1 && version != 2))
    {
        psTraceCrypto("Error: wrong version. Only 0, 1 and 2 are supported\n");
        return PS_PARSE_FAIL;
    }

    /* Try to parse the id-Ed25519 OID (1.3.101.112) */
    len = psParseBufTrySkipBytes(&pb2,
            (const unsigned char *)
            "\x30\x05" OID_ED25519_KEY_ALG_HEX, 7);
    if (len != 7)
    {
        psTraceCrypto("Error: valid id-Ed25519 OID not found\n");
        return PS_PARSE_FAIL;
    }

    /* Parse the private key. */

    /* Parse the TL octets of the outer and inner OCTET STRING.
       The length of the private key is 32 octets in Ed25519. */
    len = psParseBufTrySkipBytes(&pb2,
            (const unsigned char *)
            "\x04\x22\x04\x20", 4);
    if (len != 4)
    {
        psTraceCrypto("Error: failed to parse private key TL\n");
        return PS_PARSE_FAIL;
    }

    len = sizeof(key->priv);
    psAssert(len == 32);

    rc = psParseBufCopyN(&pb2, 32, key->priv, &len);
    if (rc < 0 || len != 32)
    {
        psTraceCrypto("Error: failed to parse private key value\n");
        return PS_PARSE_FAIL;
    }

    rc = psParseTryForward(&pb2, len);
    if (rc != len)
    {
        return PS_PARSE_FAIL;
    }

    len = psParseBufTryReadTagSub(&pb2, &pb3,
            ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0);
    if (len > 0)
    {
        psTraceCrypto("Found params in Ed25519 priv key. Ignoring...\n");
        rc = psParseTryForward(&pb2, len);
        if (rc != len)
        {
            psTraceCrypto("Error: parse fail\n");
            return PS_PARSE_FAIL;
        }
    }

    len = psParseBufTryReadTagSub(&pb2, &pb3,
            ASN_CONTEXT_SPECIFIC | 1);
    if (len > 0)
    {
        psTraceCrypto("Found embedded pub key in Ed25519 priv key\n");
        if (version != 2)
        {
            psTraceCrypto("Warning: OneAsymmetricKey contains a public key " \
                    "although version != 2\n");
        }
        rc = psEd25519ParsePubKeyContent(pool,
                &pb3,
                &pubKey,
                NULL);
        if (rc < 0)
        {
            psTraceCrypto("Error: failed to parse embedded pub key\n");
            return PS_PARSE_FAIL;
        }
        Memcpy(key->pub, pubKey.pub, 32);
        key->havePub = PS_TRUE;
    }

    key->havePriv = PS_TRUE;
    return PS_SUCCESS;
}

/*
  Parse the *content octets* from the following:
  subjectPublicKey     BIT STRING

  Note: not expecting the data to start with a tag.
  The first octet should the number of unused bits in the
  final octet.
*/
int32_t psEd25519ParsePubKeyContent(psPool_t *pool,
        psParseBuf_t *pb,
        psCurve25519Key_t *key,
        unsigned char *hash)
{
    size_t len;
    int32_t rc;

    /* The number of unused bits must be 0. */
    len = psParseBufTrySkipBytes(pb,
            (const unsigned char*)
            "\x00", 1);
    if (len != 1)
    {
        psTraceCrypto("Error: failed to parse pub key TL\n");
        return PS_PARSE_FAIL;
    }

    len = sizeof(key->pub);
    psAssert(len == 32);

    rc = psParseBufCopyN(pb, 32, key->pub, &len);
    if (rc < 0 || len != 32)
    {
        psTraceCrypto("Error: failed to parse public key value\n");
        return PS_PARSE_FAIL;
    }

    rc = psParseTryForward(pb, len);
    if (rc != len)
    {
        psTraceCrypto("Error: failed to parse public key value\n");
        return PS_PARSE_FAIL;
    }

    return PS_SUCCESS;
}


/*
  Parse the public key part from a SubjectPublicKeyInfo with
  algorithm OID_ED25519_KEY_ALG:

  subjectPublicKey     BIT STRING
*/
int32_t psEd25519ParsePubKey(psPool_t *pool,
        const unsigned char **keyBuf,
        psSize_t keyBufLen,
        psCurve25519Key_t *key,
        unsigned char *hash)
{
    int32_t rc;
    size_t len;
    psParseBuf_t pb;

    psAssert(keyBuf && *keyBuf && key);

    rc = psParseBufFromStaticData(&pb, *keyBuf, keyBufLen);
    if (rc < 0)
    {
        psTraceCrypto("Unable to init parse buf\n");
        return rc;
    }

    /*
      The Ed25519 public key consists of exactly 32 octets.
      Thus the initial octet in the BIT STRING (number of bits
      to ignore in the last content octet) must be 0.
      --> length = 32 + 1 = 0x21.
    */
    len = psParseBufTrySkipBytes(&pb,
            (const unsigned char*)
            "\x03\x21", 2);
    if (len != 2)
    {
        psTraceCrypto("Error: failed to parse pub key TL\n");
        return PS_PARSE_FAIL;
    }

    rc = psEd25519ParsePubKeyContent(pool,
            &pb,
            key,
            hash);
    if (rc < 0)
    {
        psTraceCrypto("Error: failed to parse pub key V\n");
        return PS_PARSE_FAIL;
    }

    *keyBuf = pb.buf.start;

    key->havePub = PS_TRUE;
    return PS_SUCCESS;
}
#endif /* USE_ED25519 */

int32_t psEccParsePrivKey(psPool_t *pool,
    const unsigned char *keyBuf, psSize_t keyBufLen,
    psEccKey_t *key, const psEccCurve_t *curve)
{
    const psEccCurve_t *eccCurve;
    const unsigned char *buf, *end;
    uint8_t ignore_bits;
    uint32_t oid;
    int32_t asnInt;
    psSize_t len;
    size_t privkey_len;

    buf = keyBuf;
    end = buf + keyBufLen;

    if (getAsnSequence(&buf, (uint16_t) (end - buf), &len) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 1\n");
        return PS_FAILURE;
    }
    if (getAsnInteger(&buf, (uint16_t) (end - buf), &asnInt) < 0 ||
        asnInt != 1)
    {
        psTraceCrypto("Expecting private key flag\n");
        return PS_FAILURE;
    }
    /* Initial curve check */
    if ((*buf++ != ASN_OCTET_STRING) ||
        getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
        (uint16_t) (end - buf) < len ||
        len < (MIN_ECC_BITS / 8))
    {
        psTraceCrypto("Expecting private key octet string\n");
        return PS_FAILURE;
    }
    privkey_len = len;

    psEccInitKey(pool, key, curve);
    if (pstm_init_for_read_unsigned_bin(pool, &key->k, len) != PS_SUCCESS)
    {
        goto L_FAIL;
    }
    /* Key material */
    if (pstm_read_unsigned_bin(&key->k, buf, len) != PS_SUCCESS)
    {
        psTraceCrypto("Unable to read private key octet string\n");
        goto L_FAIL;
    }
    key->type = PS_PRIVKEY;
    buf += len;

    if (*buf == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
    {

        /* optional parameters are present */
        buf++;
        if (getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len ||
            len < 1)
        {

            psTraceCrypto("Bad private key format\n");
            goto L_FAIL;
        }
        if (*(buf++) != ASN_OID ||
            getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len)
        {

            psTraceCrypto("Only namedCurves are supported in EC keys\n");
            goto L_FAIL;
        }
        /* Note len can be 0 here */
        oid = 0;
        while (len > 0)
        {
            oid += *buf++;
            len--;
        }
        if (getEccParamByOid(oid, &eccCurve) < 0)
        {
            psTraceCrypto("Cert named curve not found in eccCurve list\n");
            goto L_FAIL;
        }
        if (curve != NULL && curve != eccCurve)
        {
            psTraceCrypto("PrivKey named curve doesn't match desired\n");
            goto L_FAIL;
        }
        key->curve = eccCurve;

    }
    else if (curve != NULL)
    {
        key->curve = curve;
    }
    else
    {
        psTraceCrypto("No curve found in EC private key\n");
        goto L_FAIL;
    }

    if (*buf == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        /* optional public key is present */
        buf++;
        if (getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len ||
            len < 1)
        {

            psTraceCrypto("Bad private key format\n");
            goto L_FAIL;
        }
        if (*(buf++) != ASN_BIT_STRING ||
            getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len ||
            len < 1)
        {

            goto L_FAIL;
        }
        ignore_bits = *buf++;
        len--;
        if (ignore_bits != 0)
        {
            psTraceCrypto("Unexpected ECC pubkey format\n");
            goto L_FAIL;
        }

        /* Note len can be 0 here */
        if (psEccX963ImportKey(pool, buf, len, key, key->curve) < 0)
        {
            psTraceCrypto("Unable to parse ECC pubkey from cert\n");
            goto L_FAIL;
        }
        buf += len;
    }
    /* Try to parse 'implicitly' encoded optional public key with no
       DER header, i.e. assume that all the remaining bytes are public
       key bytes. This is not valid ASN.1, but sometimes appears in
       practice and parsing it is a requirement for some users. */
    if (buf < end &&
        *buf == ANSI_UNCOMPRESSED &&                  /* Uncompressed is the only format we support. */
        ((end - (buf + 1)) == privkey_len * 2))       /* Pubkey must be 2x privkey size. */
    {
        if (psEccX963ImportKey(pool, buf, (end - buf), key, key->curve) < 0)
        {
            psTraceCrypto("Unable to parse ECC pubkey from cert\n");
            goto L_FAIL;
        }
        buf += (end - buf);
    }

    /* Should be at the end */
    if (end != buf)
    {
        /* If this stream came from an encrypted file, there could be
            padding bytes on the end */
        len = (uint16_t) (end - buf);
        while (buf < end)
        {
            if (*buf != len)
            {
                psTraceCrypto("Problem at end of private key parse\n");
                goto L_FAIL;
            }
            buf++;
        }
    }
    return PS_SUCCESS;

L_FAIL:
    psEccClearKey(key);
    return PS_FAIL;
}

#endif  /* USE_MATRIX_ECC */

