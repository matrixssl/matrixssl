/**
 *      @file    alg_info.c
 *      @version $Format:%h%d$
 *
 *      Convenience functions and macros that provide information about
 *      algorithms such as output length.
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
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

#include "../cryptoImpl.h"


psResSize_t psGetOutputBlockLength(psCipherType_e alg)
{
    switch (alg)
    {
    case AES_CBC_ENC:
    case AES_CBC_DEC:
    case AES_GCM_ENC:
    case AES_GCM_DEC:
        return 16;
    case CHACHA20_POLY1305_IETF_ENC:
    case CHACHA20_POLY1305_IETF_DEC:
    case DES3:
        return 8;
    case IDEA:
        return 8;
    case SEED:
        return 16;
    case HASH_MD2:
        return MD2_HASHLEN;
    case HASH_MD5:
    case HMAC_MD5:
        return MD5_HASHLEN;
    case HASH_SHA1:
    case HMAC_SHA1:
        return SHA1_HASHLEN;
    case HASH_MD5SHA1:
        return MD5SHA1_HASHLEN;
    case HASH_SHA256:
    case HMAC_SHA256:
        return SHA256_HASHLEN;
    case HASH_SHA384:
    case HMAC_SHA384:
        return SHA384_HASHLEN;
    case HASH_SHA512:
        return SHA512_HASHLEN;
    default:
        return PS_ARG_FAIL;
    }
}

/* Return length of hash used in a signature algorithm. */
psResSize_t psSigAlgToHashLen(int32_t sigAlg)
{
    switch(sigAlg)
    {
    case OID_MD2_RSA_SIG:
    case OID_MD5_RSA_SIG:
        return MD5_HASH_SIZE;
    case OID_SHA1_RSA_SIG:
    case OID_SHA1_ECDSA_SIG:
        return SHA1_HASH_SIZE;
    case OID_SHA256_RSA_SIG:
    case OID_SHA256_ECDSA_SIG:
        return SHA256_HASH_SIZE;
    case OID_SHA384_RSA_SIG:
    case OID_SHA384_ECDSA_SIG:
        return SHA384_HASH_SIZE;
    case OID_SHA512_RSA_SIG:
    case OID_SHA512_ECDSA_SIG:
        return SHA512_HASH_SIZE;
# ifdef USE_PKCS1_PSS
    /*
      The PSS IDs are not part of the same range as the above OIDs,
      but they do not conflict with the OIDs either. Support them here
      for convenience. Now one can always map e.g. cert->sigAlgorithm
      to hash length.
    */
    case PKCS1_SHA1_ID:
        return SHA1_HASH_SIZE;
    case PKCS1_SHA256_ID:
        return SHA256_HASH_SIZE;
    case PKCS1_SHA384_ID:
        return SHA384_HASH_SIZE;
    case PKCS1_SHA512_ID:
        return SHA512_HASH_SIZE;
# endif
    default:
        return PS_UNSUPPORTED_FAIL;
    }
}

# ifdef USE_PKCS1_PSS
psResSize_t psPssHashAlgToHashLen(int32_t pssHashAlg)
{
    switch(pssHashAlg)
    {
    case PKCS1_SHA1_ID:
        return SHA1_HASH_SIZE;
    case PKCS1_SHA256_ID:
        return SHA256_HASH_SIZE;
    case PKCS1_SHA384_ID:
        return SHA384_HASH_SIZE;
    case PKCS1_SHA512_ID:
        return SHA512_HASH_SIZE;
    default:
        return PS_UNSUPPORTED_FAIL;
    }
}
# endif

/** Given a public key type and a hash length, return the MatrixSSL OID
    of the corresponding signature algorithm. */
int32_t psHashLenToSigAlg(psSize_t hash_len,
    uint8_t key_type)
{
    int32_t signatureAlgorithm;

    /**/
    psAssert(key_type == PS_RSA
            || key_type == PS_ECC
            || key_type == PS_ED25519);

    if (key_type == PS_ED25519)
    {
        /* Only one OID for Ed25519. */
        return OID_ED25519_KEY_ALG;
    }

    switch (hash_len)
    {
# if defined(USE_MD2) || defined(USE_MD5)
    case MD2_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            psTraceCrypto("pubRsaDecryptSignedElement cannot handle ");
            psTraceCrypto("RSA-MD2 or RSA-MD5 signatures; please use ");
            psTraceCrypto("pubRsaDecryptSignedElementExt instead.\n");
            return PS_ARG_FAIL;
        }
        else
        {
            psTraceCrypto("ECDSA-MD2 and ECDSA-MD5 not supported\n");
            return PS_UNSUPPORTED_FAIL;
        }
        break;
# endif /* USE_MD2 || USE_MD5 */
    case SHA1_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA1_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA1_ECDSA_SIG;
        }
        break;
# if 0
    case SHA224_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA224_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA224_ECDSA_SIG;
        }
        break;
# endif
    case SHA256_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA256_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA256_ECDSA_SIG;
        }
        break;
    case SHA384_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA384_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA384_ECDSA_SIG;
        }
        break;
    case SHA512_HASH_SIZE:
        if (key_type == PS_RSA)
        {
            signatureAlgorithm = OID_SHA512_RSA_SIG;
        }
        else
        {
            signatureAlgorithm = OID_SHA512_ECDSA_SIG;
        }
        break;
    default:
        psTraceCrypto("Unsupported hash size in RSA signature\n");
        return PS_UNSUPPORTED_FAIL;
    }

    return signatureAlgorithm;
}

/** Return PS_TRUE if sigAlg is deemed insecure.
    Return PS_FALSE otherwise.
*/
psBool_t psIsInsecureSigAlg(int32_t sigAlg,
        int keyAlgorithm,
        psSize_t keySize,
        psSize_t hashSize)
{
    if (sigAlg == OID_MD2_RSA_SIG
            || sigAlg == OID_MD5_RSA_SIG
            || sigAlg == OID_SHA1_RSA_SIG
            || sigAlg == OID_SHA1_ECDSA_SIG)
    {
        return PS_TRUE;
    }

    if (keyAlgorithm == OID_RSA_KEY_ALG)
    {
        if (hashSize == 0 || keySize < (hashSize + 11))
            return PS_TRUE;
    }
    return PS_FALSE;
}

/* Return PS_TRUE if hashLen is valid for sigAlg,
   e.g. OID_SHA256_RSA_SIG requires hashLen == 32. */
psBool_t psIsValidHashLenSigAlgCombination(psSize_t hashLen,
    int32_t sigAlg)
{
    switch (sigAlg)
    {
#  ifdef USE_MD2
    case OID_MD2_RSA_SIG:
        if (hashLen != MD2_HASH_SIZE)
        {
            return PS_FALSE;
        }
        break;
#  endif /* USE_MD2 */
#  ifdef USE_MD5
    case OID_MD5_RSA_SIG:
        if (hashLen != MD5_HASH_SIZE)
        {
            return PS_FALSE;
        }
        break;
#  endif /* USE_MD5 */
    case OID_SHA1_RSA_SIG:
        if (hashLen != SHA1_HASH_SIZE)
        {
            return PS_FALSE;
        }
        break;
#ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
        if (hashLen != SHA224_HASH_SIZE)
        {
            return PS_FALSE;
        }
        break;
#endif /* USE_SHA224 */
    case OID_SHA256_RSA_SIG:
        if (hashLen != SHA256_HASH_SIZE)
        {
            return PS_FALSE;
        }
        break;
    case OID_SHA384_RSA_SIG:
        if (hashLen != SHA384_HASH_SIZE)
        {
            return PS_FALSE;
        }
        break;
    case OID_SHA512_RSA_SIG:
        if (hashLen != SHA512_HASH_SIZE)
        {
            return PS_FALSE;
        }
        break;
    default:
        psTraceIntCrypto("Unsupported RSA signature alg: %d\n", sigAlg);
        return PS_FALSE;
    }

    return PS_TRUE;
}

/** Given the name of a signature algorithm (section 4.3.2 in TLS 1.3
    draft #28), return its two-byte SignatureScheme identifier. */
uint16_t psGetNamedSigAlgId(const char *name)
{
    if (!Strcmp(name, "rsa_pkcs1_sha256"))
    {
        return sigalg_rsa_pkcs1_sha256;
    }
    if (!Strcmp(name, "rsa_pkcs1_sha384"))
    {
        return sigalg_rsa_pkcs1_sha384;
    }
    if (!Strcmp(name, "rsa_pkcs1_sha512"))
    {
        return sigalg_rsa_pkcs1_sha512;
    }
    if (!Strcmp(name, "ecdsa_secp256r1_sha256"))
    {
        return sigalg_ecdsa_secp256r1_sha256;
    }
    if (!Strcmp(name, "ecdsa_secp384r1_sha384"))
    {
        return sigalg_ecdsa_secp384r1_sha384;
    }
    if (!Strcmp(name, "ecdsa_secp521r1_sha512"))
    {
        return sigalg_ecdsa_secp521r1_sha512;
    }
    if (!Strcmp(name, "rsa_pss_rsae_sha256"))
    {
        return sigalg_rsa_pss_rsae_sha256;
    }
    if (!Strcmp(name, "rsa_pss_rsae_sha384"))
    {
        return sigalg_rsa_pss_rsae_sha384;
    }
    if (!Strcmp(name, "rsa_pss_rsae_sha512"))
    {
        return sigalg_rsa_pss_rsae_sha512;
    }
    if (!Strcmp(name, "ed25519"))
    {
        return sigalg_ed25519;
    }
    if (!Strcmp(name, "ed448"))
    {
        return sigalg_ed448;
    }
    if (!Strcmp(name, "rsa_pss_pss_sha256"))
    {
        return sigalg_rsa_pss_pss_sha256;
    }
    if (!Strcmp(name, "rsa_pss_pss_sha384"))
    {
        return sigalg_rsa_pss_pss_sha384;
    }
    if (!Strcmp(name, "rsa_pss_pss_sha512"))
    {
        return sigalg_rsa_pss_pss_sha512;
    }
    if (!Strcmp(name, "rsa_pkcs1_sha1"))
    {
        return sigalg_rsa_pkcs1_sha1;
    }
    if (!Strcmp(name, "ecdsa_sha1"))
    {
        return sigalg_ecdsa_sha1;
    }
    return 0;
}

psBool_t psIsEcdheGroup(uint16_t namedGroup)
{
    if (namedGroup == namedgroup_secp256r1 ||
            namedGroup == namedgroup_secp384r1 ||
            namedGroup == namedgroup_secp521r1 ||
            namedGroup == namedgroup_x25519)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

psBool_t psIsSigAlgSupported(uint16_t sigAlg)
{
    psBool_t supported = PS_FALSE;
    psBool_t isNonFips = PS_FALSE; /* TRUE if not allowed in FIPS mode for
                                 signature generation. */
    psBool_t canUsePss = PS_FALSE;

    PS_VARIABLE_SET_BUT_UNUSED(isNonFips);

#ifdef USE_PKCS1_PSS
    canUsePss = PS_TRUE;
#endif

#ifdef USE_RSA
# ifdef USE_SHA1
    if (sigAlg == sigalg_rsa_pkcs1_sha1)
    {
        supported = PS_TRUE;
        isNonFips = PS_TRUE;
    }
# endif
# ifdef USE_SHA256
    if (sigAlg == sigalg_rsa_pkcs1_sha256)
    {
        supported = PS_TRUE;
    }
    if (sigAlg == sigalg_rsa_pss_rsae_sha256 && canUsePss)
    {
        supported = PS_TRUE;
    }
    if (sigAlg == sigalg_rsa_pss_pss_sha256 && canUsePss)
    {
        supported = PS_TRUE;
    }
# endif
# ifdef USE_SHA384
    if (sigAlg == sigalg_rsa_pkcs1_sha384)
    {
        supported = PS_TRUE;
    }
    if (sigAlg == sigalg_rsa_pss_rsae_sha384 && canUsePss)
    {
        supported = PS_TRUE;
    }
    if (sigAlg == sigalg_rsa_pss_pss_sha384 && canUsePss)
    {
        supported = PS_TRUE;
    }
# endif
# ifdef USE_SHA512
    if (sigAlg == sigalg_rsa_pkcs1_sha512)
    {
        supported = PS_TRUE;
    }
    if (sigAlg == sigalg_rsa_pss_rsae_sha512 && canUsePss)
    {
        supported = PS_TRUE;
    }
    if (sigAlg == sigalg_rsa_pss_pss_sha512 && canUsePss)
    {
        supported = PS_TRUE;
    }
# endif
#endif
#ifdef USE_ECC
# ifdef USE_SHA1
    if (sigAlg == sigalg_ecdsa_sha1)
    {
        supported = PS_TRUE;
    }
# endif
# ifdef USE_SHA256
    if (sigAlg == sigalg_ecdsa_secp256r1_sha256)
    {
        supported = PS_TRUE;
    }
# endif
# ifdef USE_SHA384
    if (sigAlg == sigalg_ecdsa_secp384r1_sha384)
    {
        supported = PS_TRUE;
    }
# endif
# ifdef USE_SHA512
    if (sigAlg == sigalg_ecdsa_secp521r1_sha512)
    {
        supported = PS_TRUE;
    }
# endif
    if (sigAlg == sigalg_ed25519)
    {
# ifdef USE_X25519
        supported = PS_TRUE;
# else
        supported = PS_FALSE;
# endif
    }
    if (sigAlg == sigalg_ed448)
    {
        supported = PS_FALSE;
    }
#endif
    return supported;
}

psBool_t psIsGroupSupported(uint16_t namedGroup)
{
# ifdef USE_SECP256R1
    if (namedGroup == namedgroup_secp256r1)
    {
        return PS_TRUE;
    }
# endif
# ifdef USE_SECP384R1
    if (namedGroup == namedgroup_secp384r1)
    {
        return PS_TRUE;
    }
# endif
# ifdef USE_SECP521R1
    if (namedGroup == namedgroup_secp521r1)
    {
        return PS_TRUE;
    }
# endif
# ifdef USE_X25519
    if (namedGroup == namedgroup_x25519)
    {
        return PS_TRUE;
    }
# endif
# ifdef USE_DH
    if (namedGroup == namedgroup_ffdhe2048
        || namedGroup == namedgroup_ffdhe3072
        || namedGroup == namedgroup_ffdhe4096
        || namedGroup == namedgroup_ffdhe6144
        || namedGroup == namedgroup_ffdhe8192)
    {
        return PS_TRUE;
    }
# endif

    return PS_FALSE;
}

uint16_t psGetNamedGroupId(const char *name)
{
    if (!Strcmp(name, "secp256r1"))
    {
        return namedgroup_secp256r1;
    }
    if (!Strcmp(name, "secp384r1"))
    {
        return namedgroup_secp384r1;
    }
    if (!Strcmp(name, "secp521r1"))
    {
        return namedgroup_secp521r1;
    }
    if (!Strcmp(name, "x25519") || !Strcmp(name, "X25519"))
    {
        return namedgroup_x25519;
    }
    if (!Strcmp(name, "ffdhe2048"))
    {
        return namedgroup_ffdhe2048;
    }
    if (!Strcmp(name, "ffdhe3072"))
    {
        return namedgroup_ffdhe3072;
    }
    if (!Strcmp(name, "ffdhe4096"))
    {
        return namedgroup_ffdhe4096;
    }
    if (!Strcmp(name, "ffdhe6144"))
    {
        return namedgroup_ffdhe6144;
    }
    if (!Strcmp(name, "ffdhe8192"))
    {
        return namedgroup_ffdhe8192;
    }
    return 0;
}
