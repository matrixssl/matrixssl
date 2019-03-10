/**
 *      @file    pubkey_parse_mem.c
 *      @version $Format:%h%d$
 *
 *      Generic public and private key parsing from memory.
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

#if defined(USE_RSA) || defined(USE_ECC)
#ifdef USE_PRIVATE_KEY_PARSING

#ifdef USE_RSA
static psBool_t possiblyRSAKey(const unsigned char *keyBuf,
        int32 keyBufLen)
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
  3 ED25519 key
  < 0 error
 */
static int32_t psTryParsePrivKeyMem(psPool_t *pool,
        const unsigned char *keyBuf,
        int32 keyBufLen,
        const char *password,
        psPubKey_t *privkey)
{
    int32_t rc;

#ifdef USE_RSA
    /* Examine data to ensure parses which could not succeed are not tried. */
    if (possiblyRSAKey(keyBuf, keyBufLen)) {
        rc = psRsaParsePkcs1PrivKey(pool, keyBuf, keyBufLen, &privkey->key.rsa);
        if (rc >= PS_SUCCESS)
        {
            privkey->type = PS_RSA;
            privkey->keysize = psRsaSize(&privkey->key.rsa);
            privkey->pool = pool;
            return 1; /* RSA */
        }
    }
#endif /* USE_RSA */

#ifdef USE_ECC
    rc = psEccParsePrivKey(pool, keyBuf, keyBufLen, &privkey->key.ecc, NULL);
    if (rc >= PS_SUCCESS)
    {
        privkey->type = PS_ECC;
        privkey->keysize = psEccSize(&privkey->key.ecc);
        privkey->pool = pool;
        return 2; /* ECC */
    }
# ifdef USE_ED25519
    rc = psEd25519ParsePrivKey(pool, keyBuf, keyBufLen,
            &privkey->key.ed25519);
    if (rc >= PS_SUCCESS)
    {
        privkey->type = PS_ED25519;
        privkey->keysize = 32;
        privkey->pool = pool;
        return 3;
    }
# endif /* USE_ED25519 */
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

/*
  Trial and error private key parse for when ECC or RSA is unknown.
  keyBuf must point to a buffer of length keyBufLen, containing
  a DER-encoded key.

  Return codes:
  1 RSA key
  2 ECC key
  3 ED25519 key
  < 0 error
 */
int32_t psParseUnknownPrivKeyMem(psPool_t *pool,
        const unsigned char *keyBuf,
        int32 keyBufLen,
        const char *password,
        psPubKey_t *privkey)
{
    int32_t keytype;

    if (keyBuf == NULL || keyBufLen <= 0)
        return PS_ARG_FAIL;

     privkey->keysize = 0;

     keytype = psTryParsePrivKeyMem(pool,
             keyBuf,
             keyBufLen,
             password,
             privkey);

     if (keytype < 0)
     {
         psTraceCrypto("Unable to parse private key. " \
                 "Supported formats are RSAPrivateKey, " \
                 "ECPrivateKey and PKCS #8.\n");
         return PS_FAILURE;
     }

     return keytype;
}

int32_t
psParseSubjectPublicKeyInfo(psPool_t *pool,
        const unsigned char *in,
        psSizeL_t inLen,
        int32_t *algId,
        unsigned char **algIdParams,
        psSizeL_t *algIdParamsLen,
        const unsigned char **pubKeyBitString)
{
    const unsigned char *p = in;
    const unsigned char *end = in + inLen;
    psSize_t seqLen, paramLen;
    int32_t rc, oid;
    unsigned char *pubKeyStart = NULL;
    unsigned char *paramsStart = NULL;

    /*
      PublicKeyInfo ::= SEQUENCE {
      algorithm       AlgorithmIdentifier,
      PublicKey       BIT STRING
      }

      AlgorithmIdentifier ::= SEQUENCE {
      algorithm       OBJECT IDENTIFIER,
      parameters      ANY DEFINED BY algorithm OPTIONAL
      }
    */

    if (in == NULL || algId == NULL || pubKeyBitString == NULL)
    {
        return PS_ARG_FAIL;
    }

    rc = getAsnSequence(&p, (int32) (end - p), &seqLen);
    if (rc < 0)
    {
        psTraceCrypto("psParseSubjectPublicKeyInfo: initial SEQ parse fail\n");
        goto out_fail;
    }
    rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oid, &paramLen);
    if (rc < 0)
    {
        psTraceCrypto("psParseSubjectPublicKeyInfo: alg OID parse fail\n");
        goto out_fail;
    }
    if (paramLen > 0)
    {
        paramsStart = (unsigned char*)p;
        p += paramLen;
    }
    if (p >= end)
    {
        psTraceCrypto("psParseSubjectPublicKeyInfo: invalid length\n");
        goto out_fail;
    }

    pubKeyStart = (unsigned char*)p;

    *algId = oid;
    *pubKeyBitString = pubKeyStart;

    /* Only give out params if caller is interested. */
    if (algIdParams != NULL)
    {
        *algIdParams = paramsStart;
    }
    if (algIdParamsLen != NULL)
    {
        *algIdParamsLen = paramLen;
    }

    return PS_SUCCESS;

out_fail:
    return PS_PARSE_FAIL;
}

PSPUBLIC int32_t
psParseUnknownPubKeyMem(psPool_t *pool,
                        const unsigned char *keyBuf, int32 keyBufLen,
                        const char *password, psPubKey_t *pubkey)
{
    int32_t rc;
    unsigned char *data;
    psSizeL_t data_len;
# if defined USE_RSA || defined USE_ECC
    unsigned char hashBuf[SHA1_HASH_SIZE];
# endif

    rc = psPemTryDecode(pool,
            keyBuf,
            keyBufLen,
            PEM_TYPE_PUBLIC_KEY,
            password,
            &data,
            &data_len);
    if (rc != PS_SUCCESS)
    {
        /* Not PEM or PEM decoding not supported. Try DER. */
        data = (unsigned char *)keyBuf;
        data_len = keyBufLen;
    }

# ifdef USE_RSA
    rc = psRsaParseAsnPubKey(pool,
                             (const unsigned char **)&data, data_len,
                             &pubkey->key.rsa,
                             hashBuf);
# endif
# ifdef USE_ECC
    if (rc < PS_SUCCESS)
    {
        rc = getEcPubKey(pool,
                         (const unsigned char **)&data, data_len,
                         &pubkey->key.ecc, hashBuf);
        if (rc < PS_SUCCESS)
        {
            rc = psEccParsePrivKey(pool, data, data_len,
                                   &pubkey->key.ecc, NULL);
        }
    }
# endif

    if (data != keyBuf)
    {
        psFree(data, pool);
    }

    return rc;
}

# else /* USE_PRIVATE_KEY_PARSING */
PSPUBLIC int32_t psParseUnknownPrivKeyMem(psPool_t *pool,
        const unsigned char *keyBuf, int32 keyBufLen,
        const char *password, psPubKey_t *privkey)
{
    PS_VARIABLE_SET_BUT_UNUSED(pool);
    PS_VARIABLE_SET_BUT_UNUSED(keyBuf);
    PS_VARIABLE_SET_BUT_UNUSED(keyBufLen);
    PS_VARIABLE_SET_BUT_UNUSED(password);
    PS_VARIABLE_SET_BUT_UNUSED(privkey);
    return -1; /* Not implemented */
}
# endif   /* USE_PRIVATE_KEY_PARSING */
#endif /* USE_RSA || USE_ECC */
