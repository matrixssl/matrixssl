/**
 *      @file    cryptoApi.h
 *      @version $Format:%h%d$
 *
 *      Prototypes for the Matrix crypto public APIs.
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

#ifndef _h_PS_CRYPTOAPI
# define _h_PS_CRYPTOAPI

# ifdef __cplusplus
extern "C" {
# endif

# include "coreApi.h" /* Must be included first */
# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <cryptoConfig.h>   /* Must be included second */
# else
#  include "cryptoConfig.h"   /* Must be included second */
# endif
# include "cryptolib.h"
# include "pscompilerdep.h"
# include "scalarmult/ps_x25519.h"
# include "crypto_sign/ps_ed25519.h"

/* Use optional constant time modular exponentiation algorithm.
   The setting is set here unless explicitly requested not to. */
# ifndef USE_NON_CONSTANT_TIME_MODEXP
#  define USE_CONSTANT_TIME_MODEXP
# endif

/******************************************************************************/
/**
    Public return codes.
    These are in addition to those in core/
    Failure codes MUST be < 0
    @note The range for crypto error codes must be between -30 and -49
 */
# define PS_PARSE_FAIL           -31
/**
    @note Any future additions to certificate authentication failures
    must be carried through to MatrixSSL code
 */
# define PS_CERT_AUTH_PASS           PS_TRUE
# define PS_CERT_AUTH_FAIL_BC        -32     /* BasicConstraint failure */
# define PS_CERT_AUTH_FAIL_DN        -33     /* DistinguishedName failure */
# define PS_CERT_AUTH_FAIL_SIG       -34     /* Signature validation failure */
# define PS_CERT_AUTH_FAIL_REVOKED   -35     /* Revoked via CRL or OCSP */
# define PS_CERT_AUTH_FAIL           -36     /* Generic cert auth fail */
# define PS_CERT_AUTH_FAIL_EXTENSION -37     /* extension permission problem */
# define PS_CERT_AUTH_FAIL_PATH_LEN  -38     /* pathLen exceeded */
# define PS_CERT_AUTH_FAIL_AUTHKEY   -39     /* subjectKeyid != issuer authKeyid */

# define PS_SIGNATURE_MISMATCH   -40         /* Algorithms all work but sig not a match */

# define PS_AUTH_FAIL            -41         /* An AEAD or HASH authentication fail */
# define PS_MESSAGE_UNSUPPORTED          -42 /* Request/Response format/type is unsupported. */
# define PS_VERSION_UNSUPPORTED          -43 /* Request/Response version is unsupported. */

# define PS_SELFTEST_FAILED              -44 /* Selftest, such as FIPS 140-2
                                                Powerup selftest has failed.
                                                Software initialization has
                                                failed. */

/** Public return value codes for OCSP.

    These are additional possible return values from OCSP parsing.
    Currently these values are for OCSP Response and thus map directly to
    RFC 6960, section 4.2.1 (values -86 ... -81 correspond to 1 ... 6.)
    When one of these values is returned by psOcspParseResponse(), function
    psOcspResponseGetStatus() can be used to map it into an OCSP Response Status
    code.

    @note The additional range used by OCSP error codes is between -80 and -89.
 */
# define PS_OCSP_UNAUTHORIZED      -81 /* Request unauthorized */
# define PS_OCSP_SIG_REQUIRED      -82 /* Must sign the request */
/*                                -83    Is reserved for future extensions. */
# define PS_OCSP_TRY_LATER         -84 /* Try again later */
# define PS_OCSP_INTERNAL_ERROR    -85 /* Internal error in issuer */
# define PS_OCSP_MALFORMED_REQUEST -86 /* Illegal confirmation request */

/******************************************************************************/

/* Set as authStatusFlags to certificate callback when authStatus
    is PS_CERT_AUTH_FAIL_EXTENSION */
# define PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG    0x01
# define PS_CERT_AUTH_FAIL_EKU_FLAG          0x02
# define PS_CERT_AUTH_FAIL_SUBJECT_FLAG      0x04
# define PS_CERT_AUTH_FAIL_DATE_FLAG         0x08
/* Set as authStatusFlags to certificate callback when authStatus
   is PS_CERT_AUTH_FAIL_PATH_LEN. This flag indicates that the maximum
   peer cert chain verification depth specified in session options
   was exceeded.
*/
# define PS_CERT_AUTH_FAIL_VERIFY_DEPTH_FLAG 0x10

/******************************************************************************/
/**
    Build the configuration string with the relevant build options for
    runtime validation of compile-time configuration.
 */
# if defined PSTM_X86 || defined PSTM_X86_64 || defined PSTM_ARM || \
    defined PSTM_MIPS
#  define PSTM_ASM_CONFIG_STR "Y"
# else
#  define PSTM_ASM_CONFIG_STR "N"
# endif
# ifdef PSTM_64BIT
#  define PSTM_64_CONFIG_STR "Y"
# else
#  define PSTM_64_CONFIG_STR "N"
# endif
# ifdef USE_AESNI_CRYPTO
#  define AESNI_CONFIG_STR "Y"
# else
#  define AESNI_CONFIG_STR "N"
# endif
#  define HW_PKA_CONFIG_STR "N"
#  define PKCS11_CONFIG_STR "N"
#  define FIPS_CONFIG_STR "N"

# define PSCRYPTO_CONFIG \
    "Y" \
    PSTM_ASM_CONFIG_STR \
    PSTM_64_CONFIG_STR \
    AESNI_CONFIG_STR \
    HW_PKA_CONFIG_STR \
    PKCS11_CONFIG_STR \
    FIPS_CONFIG_STR \
    PSCORE_CONFIG

/******************************************************************************/
/*
    Crypto module open/close
 */
PSPUBLIC int32_t psCryptoOpen(const char *config);
PSPUBLIC void psCryptoClose(void);

/******************************************************************************/
/*
    Crypto module control (only available with CLS crypto)
 */

/******************************************************************************/
/*
    Abstract Cipher API
    Handles symmetric crypto, aead ciphers, hashes and macs.
 */
typedef enum
{

    AES_CBC_ENC = 1,
    AES_CBC_DEC,
    AES_GCM_ENC,
    AES_GCM_DEC,
    CHACHA20_POLY1305_IETF_ENC,
    CHACHA20_POLY1305_IETF_DEC,
    ARC4,
    DES3,
    IDEA,
    SEED,

    HASH_MD2,
    HASH_MD5,
    HASH_SHA1,
    HASH_MD5SHA1,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,

    HMAC_MD5,
    HMAC_SHA1,
    HMAC_SHA256,
    HMAC_SHA384,

} psCipherType_e;

/******************************************************************************/
/*
    Symmetric Cipher Algorithms
 */
# ifdef USE_AES

#  define PS_AES_ENCRYPT  0x1
#  define PS_AES_DECRYPT  0x2

#  ifdef USE_AES_BLOCK
/******************************************************************************/
PSPUBLIC int32_t psAesInitBlockKey(psAesKey_t *key,
                                   const unsigned char ckey[AES_MAXKEYLEN], uint8_t keylen,
                                   uint32_t flags);
PSPUBLIC void psAesEncryptBlock(psAesKey_t *key, const unsigned char *pt,
                                unsigned char *ct);
PSPUBLIC void psAesDecryptBlock(psAesKey_t *key, const unsigned char *ct,
                                unsigned char *pt);
PSPUBLIC void psAesClearBlockKey(psAesKey_t *key);
#  endif

#  ifdef USE_AES_CBC
/******************************************************************************/
PSPUBLIC int32_t psAesInitCBC(psAesCbc_t *ctx,
                              const unsigned char IV[AES_IVLEN],
                              const unsigned char key[AES_MAXKEYLEN], uint8_t keylen,
                              uint32_t flags);
PSPUBLIC void psAesDecryptCBC(psAesCbc_t *ctx,
                              const unsigned char *ct, unsigned char *pt,
                              uint32_t len);
PSPUBLIC void psAesEncryptCBC(psAesCbc_t *ctx,
                              const unsigned char *pt, unsigned char *ct,
                              uint32_t len);
PSPUBLIC void psAesClearCBC(psAesCbc_t *ctx);
#  endif

#  ifdef USE_AES_GCM
/******************************************************************************/
PSPUBLIC int32_t psAesInitGCM(psAesGcm_t *ctx,
                              const unsigned char key[AES_MAXKEYLEN], uint8_t keylen);
PSPUBLIC void psAesReadyGCM(psAesGcm_t *ctx,
                            const unsigned char IV[AES_IVLEN],
                            const unsigned char *aad, psSize_t aadLen);
PSPUBLIC int32_t psAesReadyGCMRandomIV(psAesGcm_t * ctx,
                                       unsigned char IV[12],
                                       const unsigned char *aad, psSize_t aadLen,
                                       void *poolUserPtr);
PSPUBLIC void psAesEncryptGCM(psAesGcm_t *ctx,
                              const unsigned char *pt, unsigned char *ct,
                              uint32_t len);
# define psAesEncryptGCMImplicitIV psAesEncryptGCM
PSPUBLIC int32_t psAesDecryptGCM(psAesGcm_t *ctx,
                                 const unsigned char *ct, uint32_t ctLen,
                                 unsigned char *pt, uint32_t ptLen);

PSPUBLIC int32_t psAesDecryptGCM2(psAesGcm_t *ctx,
                                  const unsigned char *ct,
                                  unsigned char *pt, uint32_t len,
                                  const unsigned char *tag, uint32_t tagLen);

PSPUBLIC void psAesDecryptGCMtagless(psAesGcm_t *ctx,
                                     const unsigned char *ct, unsigned char *pt,
                                     uint32_t len);
PSPUBLIC void psAesGetGCMTag(psAesGcm_t * ctx,
                             uint8_t tagBytes, unsigned char tag[AES_BLOCKLEN]);
PSPUBLIC void psAesClearGCM(psAesGcm_t *ctx);

#  endif /* USE_AES_GCM */

# endif   /* USE_AES */

# ifdef USE_CHACHA20_POLY1305_IETF
/******************************************************************************/
PSPUBLIC psRes_t psChacha20Poly1305IetfInit(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)],
        const unsigned char Key_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_KEYBYTES)]);

PSPUBLIC psResSize_t psChacha20Poly1305IetfEncryptDetached(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)],
        const unsigned char *Plaintext_p,
        psSizeL_t PlaintextNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSize_t AadNBytes,
        unsigned char *Ciphertext_p,
        unsigned char Mac_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_ABYTES)]);

PSPUBLIC psResSize_t psChacha20Poly1305IetfDecryptDetached(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)],
        const unsigned char *Ciphertext_p,
        psSizeL_t CiphertextNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSizeL_t AadNBytes,
        const unsigned char Mac_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_ABYTES)],
        unsigned char *Plaintext_p);

PSPUBLIC psResSize_t psChacha20Poly1305IetfEncrypt(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)],
        const unsigned char *Plaintext_p,
        psSizeL_t PlaintextNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSizeL_t AadNBytes,
        unsigned char Ciphertext_p[PS_EXACTLY_EXPR(PlaintextNBytes + PS_CHACHA20POLY1305_IETF_ABYTES)]);

PSPUBLIC psResSize_t psChacha20Poly1305IetfDecrypt(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)],
        const unsigned char CiphertextWithTag_p[PS_EXACTLY_EXPR(CiphertextNBytes)],
        psSizeL_t CiphertextWithTagNBytes,
        const unsigned char Iv_p[PS_EXACTLY(PS_CHACHA20POLY1305_IETF_NPUBBYTES)],
        const unsigned char *Aad_p,
        psSizeL_t AadNBytes,
        unsigned char *Plaintext_p);

PSPUBLIC void psChacha20Poly1305IetfClear(
        psChacha20Poly1305Ietf_t Context_p[PS_EXACTLY(1)]);
# endif

# ifdef USE_3DES
/******************************************************************************/
PSPUBLIC int32_t psDes3Init(psDes3_t *ctx, const unsigned char IV[DES3_IVLEN],
                            const unsigned char key[DES3_KEYLEN]);
PSPUBLIC void psDes3Decrypt(psDes3_t *ctx, const unsigned char *ct,
                            unsigned char *pt, uint32_t len);
PSPUBLIC void psDes3Encrypt(psDes3_t *ctx, const unsigned char *pt,
                            unsigned char *ct, uint32_t len);
PSPUBLIC void psDes3Clear(psDes3_t *ctx);
# endif

#ifndef PS_PARAMETER_UNUSED
# define PS_PARAMETER_UNUSED(x) do { (void) (x); } while (0)
#endif

/******************************************************************************/
/*
    Hash Digest Algorithms
 */
# ifdef USE_MD5
/******************************************************************************/
static inline void psMd5PreInit(psMd5_t *md5)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(md5);
}
PSPUBLIC int32_t psMd5Init(psMd5_t *md5);
PSPUBLIC void psMd5Update(psMd5_t *md5, const unsigned char *buf, uint32_t len);
PSPUBLIC void psMd5Final(psMd5_t * md, unsigned char hash[MD5_HASHLEN]);
# endif

# ifdef USE_SHA1
/******************************************************************************/
/* Pre-init should be called for uninitialized, e.g. function local
   digest contexts, before calling the initialization function. */
static inline void psSha1PreInit(psSha1_t *sha1)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(sha1);
}
PSPUBLIC int32_t psSha1Init(psSha1_t *sha1);
PSPUBLIC void psSha1Update(psSha1_t *sha1,
                           const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha1Final(psSha1_t * sha1, unsigned char hash[SHA1_HASHLEN]);
static inline void psSha1Sync(psSha1_t *ctx, int sync_all)
{
    PS_PARAMETER_UNUSED(ctx);
    PS_PARAMETER_UNUSED(sync_all);
}
static inline void psSha1Cpy(psSha1_t *d, const psSha1_t *s)
{
    Memcpy(d, s, sizeof(psSha1_t));
}
# endif  /* USE_SHA1 */

# ifdef USE_MD5SHA1
/******************************************************************************/
/* Pre-init should be called for uninitialized, e.g. function local
   digest contexts, before calling the initialization function. */
static inline void psMd5Sha1PreInit(psMd5Sha1_t *md)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(md);
}
PSPUBLIC int32_t psMd5Sha1Init(psMd5Sha1_t *md);
PSPUBLIC void psMd5Sha1Update(psMd5Sha1_t *md,
                              const unsigned char *buf, uint32_t len);
PSPUBLIC void psMd5Sha1Final(psMd5Sha1_t * md,
                             unsigned char hash[MD5SHA1_HASHLEN]);
static inline void psMd5Sha1Sync(psMd5Sha1_t *ctx, int sync_all)
{
    PS_PARAMETER_UNUSED(ctx);
    PS_PARAMETER_UNUSED(sync_all);
}
static inline void psMd5Sha1Cpy(psMd5Sha1_t *d, const psMd5Sha1_t *s)
{
    Memcpy(d, s, sizeof(psMd5Sha1_t));
}
# endif  /* USE_MD5SHA1 */

# ifdef USE_SHA224
/******************************************************************************/
/* Pre-init should be called for uninitialized, e.g. function local
   digest contexts, before calling the initialization function. */
static inline void psSha224PreInit(psSha256_t *sha224)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(sha224);
}
PSPUBLIC void psSha224Init(psSha256_t *sha224);
PSPUBLIC void psSha224Update(psSha256_t *sha224,
                             const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha224Final(psSha256_t * sha224,
                            unsigned char hash[SHA224_HASHLEN]);
static inline void psSha224Sync(psSha256_t *md, int sync_all)
{
    PS_PARAMETER_UNUSED(md);
    PS_PARAMETER_UNUSED(sync_all);
}
static inline void psSha224Cpy(psSha256_t *d, const psSha256_t *s)
{
    Memcpy(d, s, sizeof(psSha256_t));
}
# endif  /* USE_SHA224 */

# ifdef USE_SHA256
/******************************************************************************/
/* Pre-init should be called for uninitialized, e.g. function local
   digest contexts, before calling the initialization function. */
static inline void psSha256PreInit(psSha256_t *sha256)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(sha256);
}
PSPUBLIC int32_t psSha256Init(psSha256_t *sha256);
PSPUBLIC void psSha256Update(psSha256_t *sha256,
                             const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha256Final(psSha256_t * sha256,
                            unsigned char hash[SHA256_HASHLEN]);
static inline void psSha256Sync(psSha256_t *md, int sync_all)
{
    PS_PARAMETER_UNUSED(md);
    PS_PARAMETER_UNUSED(sync_all);
}
static inline void psSha256Cpy(psSha256_t *d, const psSha256_t *s)
{
    Memcpy(d, s, sizeof(psSha256_t));
}
# endif  /* USE_SHA256 */

/******************************************************************************/
# ifdef USE_SHA384
/* Pre-init should be called for uninitialized, e.g. function local
   digest contexts, before calling the initialization function. */
static inline void psSha384PreInit(psSha384_t *sha384)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(sha384);
}
PSPUBLIC int32_t psSha384Init(psSha384_t *sha384);
PSPUBLIC void psSha384Update(psSha384_t *sha384,
                             const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha384Final(psSha384_t * sha384,
                            unsigned char hash[SHA384_HASHLEN]);
static inline void psSha384Sync(psSha384_t *md, int sync_all)
{
    PS_PARAMETER_UNUSED(md);
    PS_PARAMETER_UNUSED(sync_all);
}
static inline void psSha384Cpy(psSha384_t *d, const psSha384_t *s)
{
    Memcpy(d, s, sizeof(psSha384_t));
}
# endif  /* USE_SHA384 */

# ifdef USE_SHA512
/******************************************************************************/
/* Pre-init should be called for uninitialized, e.g. function local
   digest contexts, before calling the initialization function. */
static inline void psSha512PreInit(psSha512_t *sha512)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(sha512);
}
PSPUBLIC int32_t psSha512Init(psSha512_t *md);
PSPUBLIC void psSha512Update(psSha512_t *md,
                             const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha512Final(psSha512_t * md,
                            unsigned char hash[SHA512_HASHLEN]);
static inline void psSha512Sync(psSha512_t *md, int sync_all)
{
    PS_PARAMETER_UNUSED(md);
    PS_PARAMETER_UNUSED(sync_all);
}
static inline void psSha512Cpy(psSha512_t *d, const psSha512_t *s)
{
    Memcpy(d, s, sizeof(psSha512_t));
}
void psSha512Single(const unsigned char *in,
        uint32_t inLen,
        unsigned char out[SHA512_HASHLEN]);
# endif  /* USE_SHA512 */

/******************************************************************************/
/*
    HMAC Algorithms
 */
/* Generic HMAC algorithms, specify cipher by type. */
PSPUBLIC int32_t psHmac(psCipherType_e type, const unsigned char *key, psSize_t keyLen,
                        const unsigned char *buf, uint32_t len,
                        unsigned char hash[MAX_HASHLEN]);

PSPUBLIC int32_t psHmacInit(psHmac_t *ctx, psCipherType_e type,
                            const unsigned char *key, psSize_t keyLen);
PSPUBLIC void psHmacUpdate(psHmac_t *ctx,
                           const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacFinal(psHmac_t * ctx,
                          unsigned char hash[MAX_HASHLEN]);
PSPUBLIC int32_t psHmacSingle(psHmac_t *ctx,
        psCipherType_e hmacAlg,
        const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *in,
        psSizeL_t inLen,
        unsigned char out[MAX_HASHLEN]);

# ifdef USE_HKDF
PSPUBLIC int32_t psHkdfExpand(psCipherType_e hmacAlg,
        const unsigned char *prk,
        psSize_t prkLen,
        const unsigned char *info,
        psSize_t infoLen,
        unsigned char *okm,
        psSize_t okmLen);
PSPUBLIC int32_t psHkdfExtract(psCipherType_e hmacAlg,
        const unsigned char *salt,
        psSize_t saltLen,
        const unsigned char *ikm,
        psSize_t ikmLen,
        unsigned char prk[MAX_HASHLEN],
        psSize_t *prkLen);
PSPUBLIC int32_t psHkdfExpandLabel(psPool_t *pool,
        psCipherType_e hmacAlg,
        const unsigned char *secret,
        psSize_t secretLen,
        const char *label,
        psSize_t labelLen,
        const unsigned char *context,
        psSize_t contextLen,
        psSize_t length,
        unsigned char *out);
# endif /* USE_HKDF */

# ifdef USE_HMAC_MD5
/******************************************************************************/
PSPUBLIC int32_t psHmacMd5(const unsigned char *key, psSize_t keyLen,
                           const unsigned char *buf, uint32_t len,
                           unsigned char hash[MD5_HASHLEN],
                           unsigned char *hmacKey, psSize_t * hmacKeyLen);
PSPUBLIC int32_t psHmacMd5Init(psHmacMd5_t *ctx,
                               const unsigned char *key, psSize_t keyLen);
PSPUBLIC void psHmacMd5Update(psHmacMd5_t *ctx,
                              const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacMd5Final(psHmacMd5_t * ctx,
                             unsigned char hash[MD5_HASHLEN]);
# endif

# ifdef USE_HMAC_SHA1
/******************************************************************************/
PSPUBLIC int32_t psHmacSha1(const unsigned char *key, psSize_t keyLen,
                            const unsigned char *buf, uint32_t len,
                            unsigned char hash[SHA1_HASHLEN],
                            unsigned char *hmacKey, psSize_t * hmacKeyLen);
#  ifdef USE_HMAC_TLS
PSPUBLIC int32_t psHmacSha1Tls(const unsigned char *key, uint32_t keyLen,
                               const unsigned char *buf1, uint32_t len1,
                               const unsigned char *buf2, uint32_t len2,
                               const unsigned char *buf3, uint32_t len3,
                               uint32_t len3_alt, unsigned char *hmac);
#  endif
PSPUBLIC int32_t psHmacSha1Init(psHmacSha1_t *ctx,
                                const unsigned char *key, psSize_t keyLen);
PSPUBLIC void psHmacSha1Update(psHmacSha1_t *ctx,
                               const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacSha1Final(psHmacSha1_t * ctx,
                              unsigned char hash[SHA1_HASHLEN]);
# endif

# ifdef USE_HMAC_SHA256
/******************************************************************************/
PSPUBLIC int32_t psHmacSha256(const unsigned char *key, psSize_t keyLen,
                              const unsigned char *buf, uint32_t len,
                              unsigned char hash[SHA256_HASHLEN],
                              unsigned char *hmacKey, psSize_t * hmacKeyLen);
#  ifdef USE_HMAC_TLS
PSPUBLIC int32 psHmacSha2Tls(const unsigned char *key, uint32 keyLen,
                             const unsigned char *buf1, uint32 len1,
                             const unsigned char *buf2, uint32 len2,
                             const unsigned char *buf3, uint32 len3,
                             uint32 len3_alt, unsigned char *hmac,
                             uint32 hashSize);
#  endif
PSPUBLIC int32_t psHmacSha256Init(psHmacSha256_t *ctx,
                                  const unsigned char *key, psSize_t keyLen);
PSPUBLIC void psHmacSha256Update(psHmacSha256_t *ctx,
                                 const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacSha256Final(psHmacSha256_t * ctx,
                                unsigned char hash[SHA256_HASHLEN]);
# endif
# ifdef USE_HMAC_SHA384
/******************************************************************************/
PSPUBLIC int32_t psHmacSha384(const unsigned char *key, psSize_t keyLen,
                              const unsigned char *buf, uint32_t len,
                              unsigned char hash[SHA384_HASHLEN],
                              unsigned char *hmacKey, psSize_t * hmacKeyLen);
PSPUBLIC int32_t psHmacSha384Init(psHmacSha384_t *ctx,
                                  const unsigned char *key, psSize_t keyLen);
PSPUBLIC void psHmacSha384Update(psHmacSha384_t *ctx,
                                 const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacSha384Final(psHmacSha384_t * ctx,
                                unsigned char hash[SHA384_HASHLEN]);
# endif

#  ifdef USE_PEM_DECODE
typedef enum {
    PEM_TYPE_ANY = 0,
    PEM_TYPE_KEY,
    PEM_TYPE_PRIVATE_KEY,
    PEM_TYPE_PUBLIC_KEY,
    PEM_TYPE_CERTIFICATE
} psPemType_t;


PSPUBLIC int32_t
psPemFileToDer(psPool_t *pool,
        const char *fileName,
        const char *password,
        psPemType_t expectedPemType,
        unsigned char **derOut,
        psSizeL_t *derOutLen);

PSPUBLIC psBool_t
psPemCheckOk(const unsigned char *pemBuf,
        psSizeL_t pemBufLen,
        psPemType_t pemType,
        char **startp,
        char **endp,
        psSizeL_t *pemlen);

PSPUBLIC int32_t
psPemDecode(psPool_t *pool,
        const unsigned char *pemBufIn,
        psSizeL_t pemBufLen,
        const char *password,
        unsigned char **out,
        psSizeL_t *outlen);

PSPUBLIC psRes_t
psPemCertBufToList(psPool_t *pool,
        const unsigned char *buf,
        psSizeL_t len,
        psList_t **x509certList);

PSPUBLIC int32_t
psPemTryDecode(psPool_t *pool,
        const unsigned char *in,
        psSizeL_t inLen,
        psPemType_t pemType,
        const char *password,
        unsigned char **out,
        psSizeL_t *outlen);

#  endif /* USE_PEM_DECODE */

/******************************************************************************/
/*
    Private Key Parsing
    PKCS#1 - RSA specific
    PKCS#8 - General private key storage format
 */
# ifdef USE_PRIVATE_KEY_PARSING
#  ifdef MATRIX_USE_FILE_SYSTEM
#   ifdef USE_RSA
PSPUBLIC int32_t psPkcs1ParsePrivFile(psPool_t *pool, const char *fileName,
                                      const char *password, psRsaKey_t *key);
PSPUBLIC int32_t psPkcs1ParsePubFile(psPool_t *pool, const char *fileName,
                                     psRsaKey_t *key);
#   endif
PSPUBLIC int32_t psPkcs1DecodePrivFile(psPool_t *pool, const char *fileName,
                                       const char *password, unsigned char **DERout, psSize_t *DERlen);
#  endif /* MATRIX_USE_FILESYSTEM */
#  ifdef USE_PKCS8
PSPUBLIC psRes_t psPkcs8ParsePrivBin(psPool_t *pool,
                                     const unsigned char *p, psSizeL_t size,
                                     char *pass, psPubKey_t *key);
#   if defined(MATRIX_USE_FILE_SYSTEM) && defined (USE_PKCS12)
PSPUBLIC int32 psPkcs12Parse(psPool_t *pool, psX509Cert_t **cert,
                             psPubKey_t *privKey, const unsigned char *file, int32 flags,
                             unsigned char *importPass, int32 ipasslen,
                             unsigned char *privkeyPass, int32 kpasslen);
PSPUBLIC int32 psPkcs12ParseMem(psPool_t *pool, psX509Cert_t **cert, psPubKey_t *privKey,
                             const unsigned char *buf, int32 bufsize, int32 flags,
                             unsigned char *importPass, int32 ipasslen,
                             unsigned char *privkeyPass, int32 kpasslen);
#   endif
#  endif /* USE_PKCS8 */
# endif  /* USE_PRIVATE_KEY_PARSING */

# ifdef USE_PKCS5
/******************************************************************************/
/*
    PKCS#5 PBKDF v1 and v2 key generation
 */
PSPUBLIC int32_t psPkcs5Pbkdf1(unsigned char *pass, uint32 passlen,
                               unsigned char *salt, int32 iter, unsigned char *key);
PSPUBLIC void psPkcs5Pbkdf2(unsigned char *password, uint32 pLen,
                            unsigned char *salt, uint32 sLen, int32 rounds,
                            unsigned char *key, uint32 kLen);
# endif /* USE_PKCS5 */

/******************************************************************************/
/*
    Public Key Cryptography
 */

# if defined(USE_RSA) || defined(USE_ECC) || defined(USE_DH) || defined(USE_X25519) || defined(USE_ED25519)
PSPUBLIC int32_t psInitPubKey(psPool_t *pool, psPubKey_t *key, uint8_t type);
PSPUBLIC void psClearPubKey(psPubKey_t *key);
PSPUBLIC int32_t psNewPubKey(psPool_t *pool, uint8_t type, psPubKey_t **key);
PSPUBLIC void psDeletePubKey(psPubKey_t **key);

PSPUBLIC int32_t
psParseSubjectPublicKeyInfo(psPool_t *pool,
        const unsigned char *in,
        psSizeL_t inLen,
        int32_t *algId,
        unsigned char **algIdParams,
        psSizeL_t *algIdParamsLen,
        const unsigned char **pubKeyBitString);
PSPUBLIC int32_t psParseUnknownPrivKey(psPool_t *pool, int pemOrDer,
        const char *keyfile, const char *password,
        psPubKey_t *privkey);
PSPUBLIC int32_t psParseUnknownPrivKeyMem(psPool_t *pool,
        const unsigned char *keyBuf, int32 keyBufLen,
        const char *password, psPubKey_t *privkey);

/** psParseUnknownPubKey() function imports a public key of supported
    types (rsa, dsa, ecc) from a file into the underlying
    cryptographic provider (fips, cl, or matrix). Content of the file
    may be binary data, or PEM armored data (pemOrDer == 1). The memory
    pool is used for the new pubkey object.

    @param[in] pool for the memory
    @param[in] pemOrDer one if the file content is PEM encoded, zero for DER.
    @param[in] keyfile path to the file containing key
    @param[in] password for decryping PEM envelopes (unusual for public keys).
    @param[out] pubkey the resulting imported public key.
*/
PSPUBLIC int32_t
psParseUnknownPubKey(psPool_t *pool,
                     int pemOrDer, char *keyfile,
                     const char *password, psPubKey_t *pubkey);

/** psParseUnknownPubKeyMem() function imports a public key of
    supported types (rsa, dsa, ecc) from a memory region. Content of
    the memory may be binary data, or PEM armored data.

    @param[in] pool for the memory
    @param[in] keyBuf pointer to memory area containing public key
    @param[in] keyBufLen length of the key data in memory
    @param[in] password for decryping PEM envelopes (unusual for public keys).
    @param[out] pubkey the resulting imported public key.
*/
PSPUBLIC int32_t
psParseUnknownPubKeyMem(psPool_t *pool,
                        const unsigned char *keyBuf, int32 keyBufLen,
                        const char *password, psPubKey_t *pubkey);

# endif

# ifdef USE_RSA
/******************************************************************************/

PSPUBLIC int32_t psRsaInitKey(psPool_t *pool, psRsaKey_t *key);
PSPUBLIC void psRsaClearKey(psRsaKey_t *key);
PSPUBLIC int32_t psRsaCopyKey(psRsaKey_t *to, const psRsaKey_t *from);

PSPUBLIC int32_t psRsaParsePkcs1PrivKey(psPool_t *pool,
                                        const unsigned char *p, psSize_t size,
                                        psRsaKey_t *key);
PSPUBLIC int32_t psRsaParseAsnPubKey(psPool_t * pool,
                                     const unsigned char **pp, psSize_t len,
                                     psRsaKey_t * key, unsigned char sha1KeyHash[SHA1_HASHLEN]);
PSPUBLIC int32_t
psRsaParsePubKeyMem(psPool_t *pool,
        unsigned char *pemOrDerBuf,
        psSizeL_t pemOrDerBufLen,
        const char *password,
        psRsaKey_t *key);
PSPUBLIC psSize_t psRsaSize(const psRsaKey_t *key);
PSPUBLIC int32_t psRsaCmpPubKey(const psRsaKey_t *k1, const psRsaKey_t *k2);

PSPUBLIC int32_t psRsaEncryptPriv(psPool_t *pool, psRsaKey_t *key,
                                  const unsigned char *in, psSize_t inlen,
                                  unsigned char *out, psSize_t outlen,
                                  void *data);
PSPUBLIC int32_t psRsaEncryptPub(psPool_t *pool, psRsaKey_t *key,
                                 const unsigned char *in, psSize_t inlen,
                                 unsigned char *out, psSize_t outlen,
                                 void *data);
PSPUBLIC int32_t psRsaDecryptPriv(psPool_t *pool, psRsaKey_t *key,
                                  unsigned char *in, psSize_t inlen,
                                  unsigned char *out, psSize_t outlen,
                                  void *data);
PSPUBLIC int32_t psRsaDecryptPub(psPool_t *pool, psRsaKey_t *key,
                                 unsigned char *in, psSize_t inlen,
                                 unsigned char *out, psSize_t outlen,
                                 void *data);

PSPUBLIC int32_t psRsaCrypt(psPool_t *pool, psRsaKey_t *key,
                            const unsigned char *in, psSize_t inlen,
                            unsigned char *out, psSize_t *outlen,
                            uint8_t type, void *data);

PSPUBLIC int32_t pubRsaDecryptSignedElement(psPool_t *pool, psRsaKey_t *key,
                                            unsigned char *in, psSize_t inlen,
                                            unsigned char *out, psSize_t outlen,
                                            void *data);
PSPUBLIC int32_t pubRsaDecryptSignedElementExt(psPool_t *pool, psRsaKey_t *key,
                                               unsigned char *in, psSize_t inlen,
                                               unsigned char *out, psSize_t outlen,
                                               int32_t signatureAlgorithm, void *data);
PSPUBLIC int32_t privRsaEncryptSignedElement(psPool_t *pool, psRsaKey_t *key,
                                             const unsigned char *in, psSize_t inlen,
                                             unsigned char *out, psSize_t outlen,
                                             void *data);
#  ifdef USE_PKCS1_OAEP
PSPUBLIC int32 psPkcs1OaepEncode(psPool_t *pool, const unsigned char *msg,
                                 uint32 msglen, const unsigned char *lparam,
                                 uint32 lparamlen, unsigned char *seed, uint32 seedLen,
                                 uint32 modulus_bitlen, int32 hash_idx,
                                 unsigned char *out, psSize_t *outlen);
PSPUBLIC int32 psPkcs1OaepDecode(psPool_t *pool, const unsigned char *msg,
                                 uint32 msglen, const unsigned char *lparam, uint32 lparamlen,
                                 uint32 modulus_bitlen, int32 hash_idx,
                                 unsigned char *out, psSize_t *outlen);
#  endif /* USE_PKCS1_OAEP */
#  ifdef USE_PKCS1_PSS
PSPUBLIC int32_t psRsaPssSignHash(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSizeL_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts);
PSPUBLIC psRes_t psRsaPssVerify(psPool_t *pool,
        const unsigned char *msgIn,
        psSizeL_t msgInLen,
        const unsigned char *sig,
        psSize_t sigLen,
        psPubKey_t *key,
        int32_t signatureAlgorithm,
        psBool_t *verifyResult,
        psVerifyOptions_t *opts);
PSPUBLIC int32 psPkcs1PssEncode(psPool_t *pool,
        const unsigned char *msghash,
        uint32 msghashlen,
        unsigned char *salt,
        uint32 saltlen,
        int32 hash_idx,
        uint32 modulus_bitlen,
        unsigned char *out,
        psSize_t *outlen);
PSPUBLIC int32 psPkcs1PssDecode(psPool_t *pool,
        const unsigned char *msghash,
        uint32 msghashlen,
        const unsigned char *sig,
        uint32 siglen,
        uint32 saltlen,
        int32 hash_idx,
        uint32 modulus_bitlen,
        int32 *res);
#  endif /* USE_PKCS1_PSS */
# endif  /* USE_RSA */

# ifdef USE_DSA_VERIFY
psRes_t psDsaVerify(psPool_t *pool,
        const unsigned char *msgIn,
        psSizeL_t msgInLen,
        const unsigned char *sig,
        psSize_t sigLen,
        psPubKey_t *key,
        int32_t signatureAlgorithm,
        psBool_t *verifyResult,
        psVerifyOptions_t *opts);
# endif

# ifdef USE_ECC
/******************************************************************************/

PSPUBLIC int32_t psEccInitKey(psPool_t *pool, psEccKey_t *key,
                              const psEccCurve_t *curve);
PSPUBLIC void psEccClearKey(psEccKey_t *key);
PSPUBLIC int32_t psEccNewKey(psPool_t *pool, psEccKey_t **key,
                             const psEccCurve_t *curve);
PSPUBLIC void psEccDeleteKey(psEccKey_t **key);
PSPUBLIC int32 psEccCopyKey(psEccKey_t *to, psEccKey_t *from);
PSPUBLIC uint8_t psEccSize(const psEccKey_t *key);

PSPUBLIC int32_t psEccGenKey(psPool_t *pool, psEccKey_t *key,
                             const psEccCurve_t *curve, void *usrData);

PSPUBLIC int32_t psEccParsePrivKey(psPool_t *pool,
                                   const unsigned char *keyBuf, psSize_t keyBufLen,
                                   psEccKey_t *keyPtr, const psEccCurve_t *curve);
PSPUBLIC int32_t psEccParsePrivFile(psPool_t *pool,
                                    const char *fileName, const char *password,
                                    psEccKey_t *key);

PSPUBLIC int32_t psEccX963ImportKey(psPool_t *pool,
                                    const unsigned char *in, psSize_t inlen,
                                    psEccKey_t *key, const psEccCurve_t *curve);
PSPUBLIC int32_t psEccX963ExportKey(psPool_t *pool, const psEccKey_t *key,
                                    unsigned char *out, psSize_t *outlen);

PSPUBLIC int32_t psEccGenSharedSecret(psPool_t *pool,
                                      const psEccKey_t *privKey, const psEccKey_t *pubKey,
                                      unsigned char *outbuf, psSize_t *outlen, void *usrData);

PSPUBLIC int32_t psEccDsaSign(psPool_t *pool, const psEccKey_t *privKey,
                              const unsigned char *buf, psSize_t buflen,
                              unsigned char *sig, psSize_t *siglen,
                              uint8_t includeSize, void *usrData);
PSPUBLIC int32_t psEccDsaVerify(psPool_t *pool, const psEccKey_t *key,
                                const unsigned char *buf, psSize_t bufLen,
                                const unsigned char *sig, psSize_t siglen,
                                int32_t *status, void *usrData);
#  ifdef USE_ED25519
PSPUBLIC int32_t psEd25519ParsePrivKey(psPool_t *pool,
        const unsigned char *keyBuf,
        psSize_t keyBufLen,
        psCurve25519Key_t *key);
PSPUBLIC int32_t psEd25519ParsePubKey(psPool_t *pool,
        const unsigned char **keyBuf,
        psSize_t keyBufLen,
        psCurve25519Key_t *key,
        unsigned char *hash);
PSPUBLIC int32_t psEd25519ParsePubKeyContent(psPool_t *pool,
        psParseBuf_t *pb,
        psCurve25519Key_t *key,
        unsigned char *hash);
PSPUBLIC int32_t psEd25519ParsePrivFile(psPool_t *pool,
        const char *fileName,
        const char *password,
        psCurve25519Key_t *key);
#  endif /* USE_ED25519 */
# endif /* USE_ECC */

# ifdef USE_DH
/******************************************************************************/
/*
    PKCS#3 - Diffie-Hellman parameters
 */
PSPUBLIC int32_t psPkcs3ParseDhParamBin(psPool_t *pool,
                                        const unsigned char *dhBin, psSize_t dhBinLen,
                                        psDhParams_t *params);
#  ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32_t psPkcs3ParseDhParamFile(psPool_t *pool, const char *fileName,
                                         psDhParams_t *params);
#  endif
PSPUBLIC int32_t psDhExportParameters(psPool_t *pool,
                                      const psDhParams_t *params,
                                      unsigned char **pp, psSize_t *pLen,
                                      unsigned char **pg, psSize_t *gLen);
PSPUBLIC void psPkcs3ClearDhParams(psDhParams_t *params);

PSPUBLIC int32_t psDhImportPubKey(psPool_t *pool,
                                  const unsigned char *inbuf, psSize_t inlen,
                                  psDhKey_t *key);
PSPUBLIC int32_t psDhExportPubKey(psPool_t *pool, const psDhKey_t *key,
                                  unsigned char *out, psSize_t *outlen);
PSPUBLIC int32_t psDhImportPrivKey(psPool_t *pool,
                                   const unsigned char *in, psSize_t inlen,
                                   psDhKey_t *key);
PSPUBLIC void psDhClearKey(psDhKey_t *key);
PSPUBLIC psSize_t psDhSize(const psDhKey_t *key);

PSDEPRECATED /* Prefer to use psDhGenKeyParams, if full Diffie-Hellman
                parameters are available. */
PSPUBLIC int32_t psDhGenKey(psPool_t *pool, psSize_t keysize,
                            const unsigned char *pBin, psSize_t pLen,
                            const unsigned char *gBin, psSize_t gLen,
                            psDhKey_t *key, void *usrData);
PSDEPRECATED_WARN /* Use psDhGenKeyParams instead where possible. */
PSPUBLIC int32_t psDhGenKeyInts(psPool_t *pool, psSize_t keysize,
                                const pstm_int *p, const pstm_int *g,
                                psDhKey_t *key, void *usrData);
PSDEPRECATED /* Prefer to use psDhGenKeyParams instead where possible. */
int32_t psDhGenKeyIntsSize(psPool_t *pool, psSize_t keysize,
                           const pstm_int *p, const pstm_int *g,
                           int privsize, psDhKey_t *key, void *usrData);
PSPUBLIC int32_t psDhGenKeyParams(psPool_t *pool, const psDhParams_t *params,
                                  psDhKey_t *key, void *usrData);
PSDEPRECATED /* Prefer to use psDhGenSharedSecretParams, if full Diffie-Hellman
                parameters are available. */
PSPUBLIC int32_t psDhGenSharedSecret(psPool_t *pool,
                                     const psDhKey_t *privKey,
                                     const psDhKey_t *pubKey,
                                     const unsigned char *pBin,
                                     psSize_t pBinLen,
                                     unsigned char *out, psSize_t *outlen,
                                     void *usrData);
PSPUBLIC int32_t psDhGenSharedSecretParams(psPool_t *pool,
                                           const psDhKey_t *privKey,
                                           const psDhKey_t *pubKey,
                                           const psDhParams_t *params,
                                           unsigned char *out, psSize_t *outlen,
                                           void *usrData);

# endif /* USE_DH */

# ifdef USE_X509
/******************************************************************************/
/*
    X.509 Certificate support
 */

/* Parse a certificate bundle from a file. The file content is expected to be
   a sequence (catenation) for PEM encoded certificates. */
PSPUBLIC psRes_t psX509ParseCertFile(psPool_t *pool, const char *fileName,
                                   psX509Cert_t **outcert, int32 flags);
/* Parse a certificate bundle from a memory buffer.  The content of given
   memory region is expected to be a sequence (catenation) for PEM or binary
   DER encoded certificates. This function may be called multiple times with
   the same 'outcert' chain to allow adding of certificates from multiple
   source. The *outcert MUST be NULL for the first call.

   psX509Cert_t *certs = NULL;
   psX509ParseCertData(pool, data1, len1, &certs, flags);
   psX509ParseCertData(pool, data2, len2, &certs, flags); */
PSPUBLIC psRes_t psX509ParseCertData(psPool_t *pool,
                                     const unsigned char *data, psSizeL_t data_len,
                                     psX509Cert_t **outcert, int32 flags);
/* Parse a certificate bundle from a memory buffer that is expected to be a
   binary DER encoding. */
PSPUBLIC int32 psX509ParseCert(psPool_t *pool, const unsigned char *pp, uint32 size,
                               psX509Cert_t **outcert, int32 flags);
PSPUBLIC void psX509FreeCert(psX509Cert_t *cert);
#  ifdef USE_CERT_PARSE
PSPUBLIC int32 psX509GetCertPublicKeyDer(psX509Cert_t *cert,
                                         unsigned char *der_out,
                                         psSize_t *der_out_len);
PSPUBLIC int32 psX509AuthenticateCert(psPool_t *pool, psX509Cert_t *subjectCert,
                                      psX509Cert_t *issuerCert, psX509Cert_t **foundIssuer,
                                      void *hwCtx, void *poolUserPtr);
#  endif
#  ifdef USE_CRL
#   define CRL_CHECK_EXPECTED  5                    /* cert had a dist point but not fetched yet */
#   define CRL_CHECK_NOT_EXPECTED  6                /* cert didn't have dist point */
#   define CRL_CHECK_PASSED_AND_AUTHENTICATED 7     /* all completely good */
#   define CRL_CHECK_PASSED_BUT_NOT_AUTHENTICATED 8 /* had CRL but no auth done */
#   define CRL_CHECK_REVOKED_AND_AUTHENTICATED 9
#   define CRL_CHECK_REVOKED_BUT_NOT_AUTHENTICATED 10
#   define CRL_CHECK_CRL_EXPIRED   11/* CRL expired.  Revocation not tested */


PSPUBLIC int32 psX509GetCRLVersion(const unsigned char *crlBin,
                                   int32 crlBinLen);
PSPUBLIC int32_t psX509ParseCRL(psPool_t *pool, psX509Crl_t **crl,
                                unsigned char *crlBin, int32 crlBinLen);
PSPUBLIC void    psX509FreeCRL(psX509Crl_t *crl);
PSPUBLIC int32_t psX509GetCRLdistURL(psX509Cert_t *cert, char **url,
                                     uint32_t *urlLen);
PSPUBLIC int32_t psX509AuthenticateCRL(psX509Cert_t *CA, psX509Crl_t *CRL,
                                       void *poolUserPtr);

/* CRL global cache management */
PSPUBLIC int psCRL_Update(psX509Crl_t *crl, int deleteExisting);
PSPUBLIC int psCRL_Insert(psX509Crl_t *crl);
PSPUBLIC int psCRL_Remove(psX509Crl_t *crl);   /* Doesn't delete! */
PSPUBLIC int psCRL_Delete(psX509Crl_t *crl);
PSPUBLIC void psCRL_RemoveAll(void);
PSPUBLIC void psCRL_DeleteAll(void);
PSPUBLIC psX509Crl_t *psCRL_GetCRLForCert(psX509Cert_t *cert);
PSPUBLIC int32_t psCRL_isRevoked(psX509Cert_t *cert, psX509Crl_t *CRL);
PSPUBLIC int32_t psCRL_determineRevokedStatus(psX509Cert_t *cert);
PSPUBLIC int32_t psCRL_determineRevokedStatusBDT(psX509Cert_t *cert,
                                                 psBrokenDownTime_t *bdt);

#  endif /* USE_CRL */
# endif  /* USE_X509 */

/******************************************************************************/
/*
    Pseudorandom Number Generation
 */
PSPUBLIC int32_t psInitPrng(psRandom_t *ctx, void *userPtr);
PSPUBLIC int32_t psGetPrng(psRandom_t *ctx, unsigned char *bytes, psSize_t size,
                           void *userPtr);

# ifdef USE_YARROW
/******************************************************************************/
PSPUBLIC int32 psYarrowStart(psYarrow_t *ctx);
PSPUBLIC int32 psYarrowAddEntropy(unsigned char *in, uint32 inlen,
                                  psYarrow_t *prng);
PSPUBLIC int32 psYarrowReseed(psYarrow_t *ctx);
PSPUBLIC uint32 psYarrowRead(unsigned char *out, uint32 outlen, psYarrow_t *cx);
PSPUBLIC int32 psYarrowDone(psYarrow_t *ctx);
PSPUBLIC int32 psYarrowExport(unsigned char *out, uint32 *outlen,
                              psYarrow_t *ctx);
PSPUBLIC int32 psYarrowImport(unsigned char *in, uint32 inlen, psYarrow_t *ctx);
# endif /* USE_YARROW */

/******************************************************************************/
/*
    Deprecated Algorithms
 */
# ifdef USE_ARC4
/******************************************************************************/
PSPUBLIC int32_t psArc4Init(psArc4_t *ctx,
                            const unsigned char *key, uint8_t keylen);
PSPUBLIC void psArc4(psArc4_t *ctx, const unsigned char *in,
                     unsigned char *out, uint32_t len);
PSPUBLIC void psArc4Clear(psArc4_t *ctx);
# endif

# ifdef USE_SEED
/******************************************************************************/
PSPUBLIC int32_t psSeedInit(psSeed_t *ctx, const unsigned char IV[SEED_IVLEN],
                            const unsigned char key[SEED_KEYLEN]);
PSPUBLIC void psSeedDecrypt(psSeed_t *ctx, const unsigned char *ct,
                            unsigned char *pt, uint32_t len);
PSPUBLIC void psSeedEncrypt(psSeed_t *ctx, const unsigned char *pt,
                            unsigned char *ct, uint32_t len);
PSPUBLIC void psSeedClear(psSeed_t *ctx);
# endif

# ifdef USE_IDEA
/******************************************************************************/
PSPUBLIC int32_t psIdeaInit(psIdea_t *ctx, const unsigned char IV[IDEA_IVLEN],
                            const unsigned char key[IDEA_KEYLEN]);
PSPUBLIC void psIdeaDecrypt(psIdea_t *ctx, const unsigned char *ct,
                            unsigned char *pt, uint32_t len);
PSPUBLIC void psIdeaEncrypt(psIdea_t *ctx, const unsigned char *pt,
                            unsigned char *ct, uint32_t len);
PSPUBLIC void psIdeaClear(psIdea_t *ctx);
# endif

# ifdef USE_RC2
/******************************************************************************/
PSPUBLIC int32_t psRc2Init(psRc2Cbc_t *ctx, const unsigned char *IV,
                           const unsigned char *key, uint8_t keylen);
PSPUBLIC int32_t psRc2Decrypt(psRc2Cbc_t *ctx, const unsigned char *ct,
                              unsigned char *pt, uint32_t len);
PSPUBLIC int32_t psRc2Encrypt(psRc2Cbc_t *ctx, const unsigned char *pt,
                              unsigned char *ct, uint32_t len);
# endif

# ifdef USE_MD4
/******************************************************************************/
PSPUBLIC void psMd4Init(psMd4_t *md);
PSPUBLIC void psMd4Update(psMd4_t *md, const unsigned char *buf, uint32_t len);
PSPUBLIC int32_t psMd4Final(psMd4_t *md, unsigned char *hash);
# endif

/** Return output block length of an algorithm. */
PSPUBLIC psResSize_t psGetOutputBlockLength(psCipherType_e alg);
/** Return length of hash used in a signature algorithm. */
PSPUBLIC psResSize_t psSigAlgToHashLen(int32_t sigAlg);
/** Return the length of hash used in an RSASSA-PSS signature algorithm. */
PSPUBLIC psResSize_t psPssHashAlgToHashLen(int32_t pssHashAlg);
/** Return PS_TRUE if the given sigAlg is supported by the
    compile-time config. */
PSPUBLIC psBool_t psIsSigAlgSupported(uint16_t sigAlg);
/** Return PS_TRUE if sigAlg is deemed insecure.
    Return PS_FALSE otherwise. */
PSPUBLIC psBool_t psIsInsecureSigAlg(int32_t sigAlg,
        int32 keyAlgorithm,
        psSize_t keySize,
        psSize_t hashSize);
/** Return PS_TRUE if the given TLS 1.3 NamedGroup is supported by the
    compile-time config. */
PSPUBLIC psBool_t psIsGroupSupported(uint16_t namedGroup);
PSPUBLIC psBool_t psIsEcdheGroup(uint16_t namedGroup);
/** Map a TLS 1.3 group name to NamedGroup id. */
PSPUBLIC uint16_t psGetNamedGroupId(const char *name);
/** Map TLS specification's signature_algorithm name to algorithm id. */
PSPUBLIC uint16_t psGetNamedSigAlgId(const char *name);

PSPUBLIC psBool_t psIsValidHashLenSigAlgCombination(psSize_t hashLen,
        int32_t sigAlg);

# ifdef USE_RSA
/* Return the correct reference DigestInfo prefix for sigAlg,
   when len bytes were RSA-decrypted. */
PSPUBLIC const unsigned char *psGetDigestInfoPrefix(int32_t len,
        int32_t sigAlg);
# endif /* USE_RSA */

# ifdef USE_MD2
/******************************************************************************/
static inline void psMd2PreInit(psMd2_t *md2)
{
    /* Nothing to pre-initialize for native crypto. */
    PS_PARAMETER_UNUSED(md2);
}
PSPUBLIC void psMd2Init(psMd2_t *md);
PSPUBLIC int32_t psMd2Update(psMd2_t *md, const unsigned char *buf,
                             uint32_t len);
PSPUBLIC int32_t psMd2Final(psMd2_t *md, unsigned char *hash);
# endif

/* MatrixSSL 3.9.0 has cleaned up namespaces used by MatrixSSL crypto library.
   These aliases are provided for backwards compatibility with applications
   using MatrixSSL 3.8.x API. */
# ifndef NO_MATRIXSSL_3_8_API_COMPATIBILITY
#  define pkcs1OaepEncode psPkcs1OaepEncode
#  define pkcs1OaepDecode psPkcs1OaepDecode
#  define pkcs1PssEncode psPkcs1PssEncode
#  define pkcs1PssDecode psPkcs1PssDecode
#  define pkcs1ParsePrivFile psPkcs1ParsePrivFile
#  define pkcs1DecodePrivFile psPkcs1DecodePrivFile
#  define pkcs8ParsePrivBin psPkcs8ParsePrivBin
#  define pkcs5pbkdf1 psPkcs5Pbkdf1
#  define pkcs5pbkdf2 psPkcs5Pbkdf2
#  define pkcs3ParseDhParamBin psPkcs3ParseDhParamBin
#  define pkcs3ParseDhParamFile psPkcs3ParseDhParamFile
#  define pkcs3ClearDhParams psPkcs3ClearDhParams
#  define matrixSslWriteOCSPRequest psOcspRequestWriteOld
#  define matrixSslWriteOCSPRequestInfoSetSigning \
    psOcspRequestWriteInfoSetSigning
#  define matrixSslWriteOCSPRequestInfoSetRequestorId \
    psOcspRequestWriteInfoSetRequestorId
#  define matrixSslWriteOCSPRequestInfoFreeRequestorId \
    psOcspRequestWriteInfoFreeRequestorId
#  define matrixSslWriteOCSPRequestExt psOcspRequestWrite
#  define matrixSslWriteOCSPRequestVersion \
    psOcspRequestWriteVersion
#  define matrixSslOCSPNonceExtension psOcspWriteNonceExtension
#  define validateOCSPResponse psOcspResponseValidateOld
#  define validateOCSPResponse_ex psOcspResponseValidate
#  define parseOCSPResponse psOcspParseResponse
#  define getOCSPResponseStatus psOcspResponseGetStatus
#  define checkOCSPResponseDates psOcspResponseCheckDates
#  define uninitOCSPResponse psOcspResponseUninit
#  define matrixCryptoGetPrngData psGetPrngLocked
#  define s_pstm_sub pstm_sub_s
#  define mOCSPResponse_t psOcspResponse_t
#  define mOCSPSingleResponse_t psOcspSingleResponse_t

# endif   /* NO_MATRIXSSL_3_8_API_COMPATIBILITY */

# ifdef __cplusplus
}
# endif

#endif /* _h_PS_CRYPTOAPI */

/******************************************************************************/
