/**
 *      @file    cryptolib.h
 *      @version $Format:%h%d$
 *
 *      Header file for definitions used with crypto lib.
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

#ifndef _h_PS_CRYPTOLIB
# define _h_PS_CRYPTOLIB

/******************************************************************************/
/*
    Additional 'hidden' algorithm configuration here for deprecated support
 */

/** Symmetric. @security These are generally insecure and not enabled by default. */
/* #define USE_RC2 */
/* #define USE_ARC4 */
/* #define USE_SEED */
/* #define USE_IDEA */
# ifdef USE_PKCS12
/* #define USE_RC2      / * Only PKCS#12 parse should ever want this algorithm * / */
# endif

/** Digest. @security These are generally insecure and not enabled by default */
/* #define USE_MD4 */
/* #define USE_MD2 */

/** PRNG. @security By default the OS PRNG will be used directly. */
# define USE_PRNG
/* #define USE_YARROW */

/******************************************************************************/
/*
    Additional configuration that is usually not modified.
 */
# define OCSP_VALID_TIME_WINDOW 604800 /* In seconds (1 week default window) */

/******************************************************************************/
/*
    Include crypto provider layer headers
 */
# include "layer/layer.h"

/* Configuration validation/sanity checks */
# include "cryptoCheck.h"

/* Implementation layer */
# include "symmetric/symmetric.h"
# include "digest/digest.h"
# include "math/pstm.h"
# include "pubkey/pubkey.h"
# include "keyformat/asn1.h"
# include "keyformat/x509.h"
# include "prng/prng.h"

/******************************************************************************/
/*
    Crypto trace
 */
# ifdef USE_PS_LOGF_COMMON
#   define psTraceCrypto(x) PS_LOGF_COMMON(Log_Trace, PS_CRYPTO, PS_LOGF_FMT, \
                                           PS_LOGF_FILELINE, "%s", x)
#   define psTraceIntCrypto(x, i) PS_LOGF_COMMON(Log_Trace, PS_CRYPTO, \
                                                 PS_LOGF_FMT,          \
                                                 PS_LOGF_FILELINE, x, i)
#   define psTraceStrCrypto(x, s) PS_LOGF_COMMON(Log_Trace, PS_CRYPTO, \
                                                 PS_LOGF_FMT,          \
                                                 PS_LOGF_FILELINE, x, s)
#   define psTracePtrCrypto(x, p) PS_LOGF_COMMON(Log_Trace, PS_CRYPTO, \
                                                 PS_LOGF_FMT,          \
                                                 PS_LOGF_FILELINE, x, p)
#   define psTracefCrypto(x, ...) PS_LOGF_COMMON(Log_Trace, PS_CRYPTO, \
                                                 PS_LOGF_FMT,          \
                                                 PS_LOGF_FILELINE, x,  \
                                                 __VA_ARGS__)
# else
#  ifndef USE_CRYPTO_TRACE
#   define psTraceCrypto(x)
#   define psTraceStrCrypto(x, y)
#   define psTraceIntCrypto(x, y)
#   define psTracePtrCrypto(x, y)
#   define psTracefCrypto(x, y)
#  else
#   define psTraceCrypto(x) _psTrace(x)
#   define psTraceStrCrypto(x, y) _psTraceStr(x, y)
#   define psTraceIntCrypto(x, y) _psTraceInt(x, y)
#   define psTracePtrCrypto(x, y) _psTracePtr(x, y)
#   define psTracefCrypto(x, y) /* Only available via PS_LOGF_COMMON. */
#  endif /* USE_CRYPTO_TRACE */
# endif /* PS_LOGF_COMMON */

/******************************************************************************/
/*
    Helpers
 */
extern int32_t psBase64decode(const unsigned char *in, psSize_t len,
                              unsigned char *out, psSize_t *outlen);
extern void psOpenPrng(void);
extern void psClosePrng(void);
extern int32_t psGetPrngLocked(unsigned char *bytes, psSize_t size,
                               void *userPtr);

/******************************************************************************/
/*
    RFC 3279 OID and PKCS standards OIDs
    Matrix uses an oid summing mechanism to arrive at these defines.
    The byte values of the OID are summed and compared with OID database
    entries to produce a unique numbers (assuming MATRIXSSL_NO_OID_DATABASE
    is not set.)
 */

# ifdef MATRIXSSL_NO_OID_DATABASE
/* Without OID database, some entries will be duplicates. */
#  define OID_COLLISION 0
# else
/* To prevent collisions, some oids are added a sufficient multiple of this
   to make them unique. */
#  define OID_COLLISION 1024

/* Marking for OIDs that have not been discovered in the database.
   The OIDs not discovered are guaranteed to be this value or larger. */
#  define OID_NOT_FOUND 32768
# endif /* MATRIXSSL_NO_OID_DATABASE */

/* Raw digest algorithms */

# define OID_SHA1_ALG_STR                 "1.3.14.3.2.26"
# define OID_SHA1_ALG                     88
# define OID_SHA1_ALG_HEX                 "\x06\x05\x2B\x0E\x03\x02\x1A"
# define OID_SHA224_ALG_STR               "2.16.840.1.101.3.4.2.4"
# define OID_SHA224_ALG                   (417 + OID_COLLISION)
# define OID_SHA224_ALG_HEX               "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04"
# define OID_SHA256_ALG_STR               "2.16.840.1.101.3.4.2.1"
# define OID_SHA256_ALG                   414
# define OID_SHA256_ALG_HEX               "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
# define OID_SHA384_ALG_STR               "2.16.840.1.101.3.4.2.2"
# define OID_SHA384_ALG                   415
# define OID_SHA384_ALG_HEX               "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02"
# define OID_SHA512_ALG_STR               "2.16.840.1.101.3.4.2.3"
# define OID_SHA512_ALG                   416
# define OID_SHA512_ALG_HEX               "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"
# define OID_MD2_ALG_STR                  "1.2.840.113549.2.2"
# define OID_MD2_ALG                      646
# define OID_MD2_ALG_HEX                  "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02"
# define OID_MD5_ALG_STR                  "1.2.840.113549.2.5"
# define OID_MD5_ALG                      649
# define OID_MD5_ALG_HEX                  "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x05"

/* Signature algorithms */
# define OID_MD2_RSA_SIG_STR              "1.2.840.113549.1.1.2"
# define OID_MD2_RSA_SIG                  (646 + OID_COLLISION)
# define OID_MD2_RSA_SIG_HEX              "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x02"
# define OID_MD5_RSA_SIG_STR              "1.2.840.113549.1.1.4"
# define OID_MD5_RSA_SIG                  648
# define OID_MD5_RSA_SIG_HEX              "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04"
# define OID_SHA1_RSA_SIG_STR             "1.2.840.113549.1.1.5"
# define OID_SHA1_RSA_SIG                 (649 + OID_COLLISION)
# define OID_SHA1_RSA_SIG_HEX             "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05"
# define OID_SHA1_RSA_SIG2_STR            "1.3.14.3.2.29"
# define OID_SHA1_RSA_SIG2                91/* Older, alternate for SHA1_RSA */
# define OID_SHA1_RSA_SIG2_HEX            "\x06\x05\x2B\x0E\x03\x02\x1D"
# define OID_ID_MGF1_STR                  "1.2.840.113549.1.1.8"
# define OID_ID_MGF1                      (652 + OID_COLLISION * 2)
# define OID_ID_MGF1_HEX                  "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x08"
# define OID_RSASSA_PSS_STR               "1.2.840.113549.1.1.10"
# define OID_RSASSA_PSS                   (654 + OID_COLLISION)
# define OID_RSASSA_PSS_HEX               "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0A"
# define OID_SHA224_RSA_SIG_STR           "1.2.840.113549.1.1.14"
# define OID_SHA224_RSA_SIG               (658 + OID_COLLISION)
# define OID_SHA224_RSA_SIG_HEX           "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0E"
# define OID_SHA256_RSA_SIG_STR           "1.2.840.113549.1.1.11"
# define OID_SHA256_RSA_SIG               (655 + OID_COLLISION)
# define OID_SHA256_RSA_SIG_HEX           "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B"
# define OID_SHA384_RSA_SIG_STR           "1.2.840.113549.1.1.12"
# define OID_SHA384_RSA_SIG               (656 + OID_COLLISION)
# define OID_SHA384_RSA_SIG_HEX           "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0C"
# define OID_SHA512_RSA_SIG_STR           "1.2.840.113549.1.1.13"
# define OID_SHA512_RSA_SIG               (657 + OID_COLLISION)
# define OID_SHA512_RSA_SIG_HEX           "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0D"
# define OID_SHA1_DSA_SIG_STR             "1.2.840.10040.4.3"
# define OID_SHA1_DSA_SIG                 517
# define OID_SHA1_DSA_SIG_HEX             "\x06\x07\x2A\x86\x48\xCE\x38\x04\x03"
# define OID_SHA1_ECDSA_SIG_STR           "1.2.840.10045.4.1"
# define OID_SHA1_ECDSA_SIG               520
# define OID_SHA1_ECDSA_SIG_HEX           "\x06\x07\x2A\x86\x48\xCE\x3D\x04\x01"
# define OID_SHA224_ECDSA_SIG_STR         "1.2.840.10045.4.3.1"
# define OID_SHA224_ECDSA_SIG             523
# define OID_SHA224_ECDSA_SIG_HEX         "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x01"
# define OID_SHA256_ECDSA_SIG_STR         "1.2.840.10045.4.3.2"
# define OID_SHA256_ECDSA_SIG             524
# define OID_SHA256_ECDSA_SIG_HEX         "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02"
# define OID_SHA384_ECDSA_SIG_STR         "1.2.840.10045.4.3.3"
# define OID_SHA384_ECDSA_SIG             525
# define OID_SHA384_ECDSA_SIG_HEX         "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x03"
# define OID_SHA512_ECDSA_SIG_STR         "1.2.840.10045.4.3.4"
# define OID_SHA512_ECDSA_SIG             526
# define OID_SHA512_ECDSA_SIG_HEX         "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x04"

/* Public key algorithms */
# define OID_RSA_KEY_ALG_STR              "1.2.840.113549.1.1.1"
# define OID_RSA_KEY_ALG                  645
# define OID_RSA_KEY_ALG_HEX              "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
# define OID_DSA_KEY_ALG_STR              "1.2.840.10040.4.1"
# define OID_DSA_KEY_ALG                  515
# define OID_DSA_KEY_ALG_HEX              "\x06\x07\x2A\x86\x48\xCE\x38\x04\x01"
# define OID_ECDSA_KEY_ALG_STR            "1.2.840.10045.2.1"
# define OID_ECDSA_KEY_ALG                518
# define OID_ECDSA_KEY_ALG_HEX            "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01"

/* Encryption algorithms */
# define OID_DES_EDE3_CBC_STR             "1.2.840.113549.3.7"
# define OID_DES_EDE3_CBC                 (652 + OID_COLLISION)
# define OID_DES_EDE3_CBC_HEX             "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x07"

# define OID_AES_128_CBC_STR              "2.16.840.1.101.3.4.1.2"
# define OID_AES_128_CBC                  (414 + OID_COLLISION)
# define OID_AES_128_CBC_HEX              "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02"
# define OID_AES_128_WRAP_STR             "2.16.840.1.101.3.4.1.5"
# define OID_AES_128_WRAP                 417
# define OID_AES_128_WRAP_HEX             "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x05"
# define OID_AES_128_GCM_STR              "2.16.840.1.101.3.4.1.6"
# define OID_AES_128_GCM                  418
# define OID_AES_128_GCM_HEX              "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x06"
# define OID_AES_192_CBC_STR              "2.16.840.1.101.3.4.1.22"
# define OID_AES_192_CBC                  434
# define OID_AES_192_CBC_HEX              "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x16"
# define OID_AES_192_WRAP_STR             "2.16.840.1.101.3.4.1.25"
# define OID_AES_192_WRAP                 437
# define OID_AES_192_WRAP_HEX             "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x19"
# define OID_AES_192_GCM_STR              "2.16.840.1.101.3.4.1.26"
# define OID_AES_192_GCM                  438
# define OID_AES_192_GCM_HEX              "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x1A"
# define OID_AES_256_CBC_STR              "2.16.840.1.101.3.4.1.42"
# define OID_AES_256_CBC                  454
# define OID_AES_256_CBC_HEX              "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2A"
# define OID_AES_256_WRAP_STR             "2.16.840.1.101.3.4.1.45"
# define OID_AES_256_WRAP                 457
# define OID_AES_256_WRAP_HEX             "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2D"
# define OID_AES_256_GCM_STR              "2.16.840.1.101.3.4.1.46"
# define OID_AES_256_GCM                  458
# define OID_AES_256_GCM_HEX              "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2E"

# define OID_AES_CMAC_STR        "2.16.840.1.101.3.4.1.200_alt"
# define OID_AES_CMAC            612
# define OID_AES_CMAC_HEX        "\x06\x0A\x60\x86\x48\x01\x65\x03\x04\x01\xC8"

# define OID_AES_CBC_CMAC_128_STR         "0.4.0.127.0.7.1.1.1.2"
# define OID_AES_CBC_CMAC_128             143
# define OID_AES_CBC_CMAC_128_HEX         "\x06\x09\x04\x00\x7F\x00\x07\x01\x01\x01\x02"
# define OID_AES_CBC_CMAC_192_STR         "0.4.0.127.0.7.1.1.1.3"
# define OID_AES_CBC_CMAC_192             144
# define OID_AES_CBC_CMAC_192_HEX         "\x06\x09\x04\x00\x7F\x00\x07\x01\x01\x01\x03"
# define OID_AES_CBC_CMAC_256_STR         "0.4.0.127.0.7.1.1.1.4"
# define OID_AES_CBC_CMAC_256             145
# define OID_AES_CBC_CMAC_256_HEX         "\x06\x09\x04\x00\x7F\x00\x07\x01\x01\x01\x04"

# define OID_AUTH_ENC_256_SUM_STR         "1.2.840.113549.1.9.16.3.16"
# define OID_AUTH_ENC_256_SUM             687/* See RFC 6476 */
# define OID_AUTH_ENC_256_SUM_HEX         "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x10"

# define OID_PKCS_PBKDF2_STR              "1.2.840.113549.1.5.12"
# define OID_PKCS_PBKDF2                  (660 + OID_COLLISION)
# define OID_PKCS_PBKDF2_HEX              "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C"
# define OID_PKCS_PBES2_STR               "1.2.840.113549.1.5.13"
# define OID_PKCS_PBES2                   (661 + OID_COLLISION)
# define OID_PKCS_PBES2_HEX               "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0D"

# define OID_PKCS_PBESHA128RC4_STR        "1.2.840.113549.1.12.1.1"
# define OID_PKCS_PBESHA128RC4            657
# define OID_PKCS_PBESHA128RC4_HEX        "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x01"
# define OID_PKCS_PBESHA40RC4_STR         "1.2.840.113549.1.12.1.2"
# define OID_PKCS_PBESHA40RC4             658
# define OID_PKCS_PBESHA40RC4_HEX         "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x02"
# define OID_PKCS_PBESHA3DES3_STR         "1.2.840.113549.1.12.1.3"
# define OID_PKCS_PBESHA3DES3             659
# define OID_PKCS_PBESHA3DES3_HEX         "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x03"
# define OID_PKCS_PBESHA2DES3_STR         "1.2.840.113549.1.12.1.4"
# define OID_PKCS_PBESHA2DES3             660
# define OID_PKCS_PBESHA2DES3_HEX         "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x04"
# define OID_PKCS_PBESHA128RC2_STR        "1.2.840.113549.1.12.1.5"
# define OID_PKCS_PBESHA128RC2            661
# define OID_PKCS_PBESHA128RC2_HEX        "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x05"
# define OID_PKCS_PBESHA40RC2_STR         "1.2.840.113549.1.12.1.6"
# define OID_PKCS_PBESHA40RC2             662
# define OID_PKCS_PBESHA40RC2_HEX         "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x06"

# define OID_PKCS12_BAG_TYPE_KEY_STR      "1.2.840.113549.1.12.10.1.1"
# define OID_PKCS12_BAG_TYPE_KEY          667
# define OID_PKCS12_BAG_TYPE_KEY_HEX      "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x01"
# define OID_PKCS12_BAG_TYPE_SHROUD_STR   "1.2.840.113549.1.12.10.1.2"
# define OID_PKCS12_BAG_TYPE_SHROUD       668
# define OID_PKCS12_BAG_TYPE_SHROUD_HEX   "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x02"
# define OID_PKCS12_BAG_TYPE_CERT_STR     "1.2.840.113549.1.12.10.1.3"
# define OID_PKCS12_BAG_TYPE_CERT         669
# define OID_PKCS12_BAG_TYPE_CERT_HEX     "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x03"
# define OID_PKCS12_BAG_TYPE_CRL_STR      "1.2.840.113549.1.12.10.1.4"
# define OID_PKCS12_BAG_TYPE_CRL          670
# define OID_PKCS12_BAG_TYPE_CRL_HEX      "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x04"
# define OID_PKCS12_BAG_TYPE_SECRET_STR   "1.2.840.113549.1.12.10.1.5"
# define OID_PKCS12_BAG_TYPE_SECRET       671
# define OID_PKCS12_BAG_TYPE_SECRET_HEX   "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x05"
# define OID_PKCS12_BAG_TYPE_SAFE_STR     "1.2.840.113549.1.12.10.1.6"
# define OID_PKCS12_BAG_TYPE_SAFE         672
# define OID_PKCS12_BAG_TYPE_SAFE_HEX     "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x06"

# define OID_PKCS9_CERT_TYPE_X509_STR     "1.2.840.113549.1.9.22.1"
# define OID_PKCS9_CERT_TYPE_X509         675
# define OID_PKCS9_CERT_TYPE_X509_HEX     "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x16\x01"
# define OID_PKCS9_CERT_TYPE_SDSI_STR     "1.2.840.113549.1.9.22.2"
# define OID_PKCS9_CERT_TYPE_SDSI         676
# define OID_PKCS9_CERT_TYPE_SDSI_HEX     "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x16\x02"

# define OID_PKCS7_DATA_STR               "1.2.840.113549.1.7.1"
# define OID_PKCS7_DATA                   651
# define OID_PKCS7_DATA_HEX               "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01"
# define OID_PKCS7_SIGNED_DATA_STR        "1.2.840.113549.1.7.2"
# define OID_PKCS7_SIGNED_DATA            652
# define OID_PKCS7_SIGNED_DATA_HEX        "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02"
# define OID_PKCS7_ENVELOPED_DATA_STR     "1.2.840.113549.1.7.3"
# define OID_PKCS7_ENVELOPED_DATA         653
# define OID_PKCS7_ENVELOPED_DATA_HEX     "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03"
# define OID_PKCS7_SIGNED_ENVELOPED_DATA_STR "1.2.840.113549.1.7.4"
# define OID_PKCS7_SIGNED_ENVELOPED_DATA  654
# define OID_PKCS7_SIGNED_ENVELOPED_DATA_HEX "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x04"
# define OID_PKCS7_DIGESTED_DATA_STR      "1.2.840.113549.1.7.5"
# define OID_PKCS7_DIGESTED_DATA          655
# define OID_PKCS7_DIGESTED_DATA_HEX      "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05"
# define OID_PKCS7_ENCRYPTED_DATA_STR     "1.2.840.113549.1.7.6"
# define OID_PKCS7_ENCRYPTED_DATA         656
# define OID_PKCS7_ENCRYPTED_DATA_HEX     "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06"

# define OID_OCSP_STR                     "1.3.6.1.5.5.7.48.1"
# define OID_OCSP                         116
# define OID_OCSP_HEX                     "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x01"
# define OID_BASIC_OCSP_RESPONSE_STR      "1.3.6.1.5.5.7.48.1.1"
# define OID_BASIC_OCSP_RESPONSE          117
# define OID_BASIC_OCSP_RESPONSE_HEX      "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01"

/* These definitions are for MatrixCMS (optional component). */
# define OID_ECKA_EG_X963KDF_SHA256_STR              "0.4.0.127.0.7.1.1.5.1.1.3"
# define OID_ECKA_EG_X963KDF_SHA256                  150
# define OID_ECKA_EG_X963KDF_SHA256_HEX              "\x06\x0B\x04\x00\x7F\x00\x07\x01\x01\x05\x01\x01\x03"
# define OID_ECKA_EG_X963KDF_SHA384_STR              "0.4.0.127.0.7.1.1.5.1.1.4"
# define OID_ECKA_EG_X963KDF_SHA384                  151
# define OID_ECKA_EG_X963KDF_SHA384_HEX              "\x06\x0B\x04\x00\x7F\x00\x07\x01\x01\x05\x01\x01\x04"
# define OID_ECKA_EG_X963KDF_SHA512_STR              "0.4.0.127.0.7.1.1.5.1.1.5"
# define OID_ECKA_EG_X963KDF_SHA512                  152
# define OID_ECKA_EG_X963KDF_SHA512_HEX              "\x06\x0B\x04\x00\x7F\x00\x07\x01\x01\x05\x01\x01\x05"
# define OID_DHSINGLEPASS_STDDH_SHA1KDF_SCHEME_STR   "1.3.133.16.840.63.0.2"
# define OID_DHSINGLEPASS_STDDH_SHA1KDF_SCHEME       464
# define OID_DHSINGLEPASS_STDDH_SHA1KDF_SCHEME_HEX   "\x06\x09\x2B\x81\x05\x10\x86\x48\x3F\x00\x02"
# define OID_DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME_STR "1.3.133.16.840.63.0.3"
# define OID_DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME  465
# define OID_DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME_HEX "\x06\x09\x2B\x81\x05\x10\x86\x48\x3F\x00\x03"
# define OID_MQVSINGLEPASS_SHA1KDF_SCHEME_STR        "1.3.133.16.840.63.0.16"
# define OID_MQVSINGLEPASS_SHA1KDF_SCHEME            478
# define OID_MQVSINGLEPASS_SHA1KDF_SCHEME_HEX        "\x06\x09\x2B\x81\x05\x10\x86\x48\x3F\x00\x10"
# define OID_DHSINGLEPASS_STDDH_SHA256KDF_SCHEME_STR "1.3.132.1.11.1"
# define OID_DHSINGLEPASS_STDDH_SHA256KDF_SCHEME     189
# define OID_DHSINGLEPASS_STDDH_SHA256KDF_SCHEME_HEX "\x06\x06\x2B\x81\x04\x01\x0B\x01"
# define OID_DHSINGLEPASS_STDDH_SHA384KDF_SCHEME_STR "1.3.132.1.11.2"
# define OID_DHSINGLEPASS_STDDH_SHA384KDF_SCHEME     190
# define OID_DHSINGLEPASS_STDDH_SHA384KDF_SCHEME_HEX "\x06\x06\x2B\x81\x04\x01\x0B\x02"
# define OID_DHSINGLEPASS_STDDH_SHA512KDF_SCHEME_STR "1.3.132.1.11.3"
# define OID_DHSINGLEPASS_STDDH_SHA512KDF_SCHEME     191
# define OID_DHSINGLEPASS_STDDH_SHA512KDF_SCHEME_HEX "\x06\x06\x2B\x81\x04\x01\x0B\x03"

# define PBE12                       1
# define PBES2                       2
# define AUTH_SAFE_3DES              1
# define AUTH_SAFE_RC2               2

# define PKCS12_KEY_ID               1
# define PKCS12_IV_ID                2
# define PKCS12_MAC_ID               3

# if defined(USE_PKCS1_OAEP) || defined(USE_PKCS1_PSS)
#  define PKCS1_SHA1_ID   0
#  define PKCS1_MD5_ID    1
#  define PKCS1_SHA256_ID 2
#  define PKCS1_SHA384_ID 3
#  define PKCS1_SHA512_ID 4
#  define PKCS1_SHA224_ID 5
# endif

/******************************************************************************/
/* These values are all mutually exlusive bits to define Cipher flags */
# define CRYPTO_FLAGS_AES    (1 << 0)
# define CRYPTO_FLAGS_AES256 (1 << 1)
# define CRYPTO_FLAGS_3DES   (1 << 2)
# define CRYPTO_FLAGS_ARC4   (1 << 3)
# define CRYPTO_FLAGS_SEED   (1 << 4)
# define CRYPTO_FLAGS_IDEA   (1 << 5)
# define CRYPTO_FLAGS_CHACHA (1 << 6) /* Short for CHACHA20_POLY1305_IETF */

# define CRYPTO_FLAGS_SHA1   (1 << 8)
# define CRYPTO_FLAGS_SHA2   (1 << 9)
# define CRYPTO_FLAGS_SHA3   (1 << 10)
# define CRYPTO_FLAGS_GCM    (1 << 11)
# define CRYPTO_FLAGS_CCM    (1 << 12)
# define CRYPTO_FLAGS_CCM8   (1 << 13)/* CCM mode with 8 byte ICV */
# define CRYPTO_FLAGS_MD5    (1 << 14)

# define CRYPTO_FLAGS_TLS        (1 << 16)
# define CRYPTO_FLAGS_TLS_1_1    (1 << 17)
# define CRYPTO_FLAGS_TLS_1_2    (1 << 18)

# define CRYPTO_FLAGS_INBOUND    (1 << 24)
# define CRYPTO_FLAGS_ARC4INITE  (1 << 25)
# define CRYPTO_FLAGS_ARC4INITD  (1 << 26)
# define CRYPTO_FLAGS_BLOCKING   (1 << 27)

# define CRYPTO_FLAGS_DISABLED   (1 << 30)

/******************************************************************************/

# define CRYPT_INVALID_KEYSIZE   -21
# define CRYPT_INVALID_ROUNDS    -22

/******************************************************************************/
/* 32-bit Rotates */
/******************************************************************************/
# if defined(_MSC_VER)
/******************************************************************************/

/* instrinsic rotate */
#  include <stdlib.h>
#  pragma intrinsic(_lrotr,_lrotl)
#  define ROR(x, n) _lrotr(x, n)
#  define ROL(x, n) _lrotl(x, n)

/******************************************************************************/
# elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)) && \
    !defined(INTEL_CC) && !defined(PS_NO_ASM)

static __inline unsigned ROL(unsigned word, int i)
{
    asm ("roll %%cl,%0"
         : "=r" (word)
         : "0" (word), "c" (i));
    return word;
}

static __inline unsigned ROR(unsigned word, int i)
{
    asm ("rorl %%cl,%0"
         : "=r" (word)
         : "0" (word), "c" (i));
    return word;
}

/******************************************************************************/
# else

/* rotates the hard way */
#  define ROL(x, y) \
    ( (((unsigned long) (x) << (unsigned long) ((y) & 31)) | \
       (((unsigned long) (x) & 0xFFFFFFFFUL) >> (unsigned long) (32 - ((y) & 31)))) & \
      0xFFFFFFFFUL)
#  define ROR(x, y) \
    ( ((((unsigned long) (x) & 0xFFFFFFFFUL) >> (unsigned long) ((y) & 31)) | \
       ((unsigned long) (x) << (unsigned long) (32 - ((y) & 31)))) & 0xFFFFFFFFUL)

# endif /* 32-bit Rotates */
/******************************************************************************/

# ifdef HAVE_NATIVE_INT64
#  ifdef _MSC_VER
#   define CONST64(n) n ## ui64
#  else
#   define CONST64(n) n ## ULL
#  endif
# endif

/******************************************************************************/
/*
    Endian helper macros
 */
# if defined (ENDIAN_NEUTRAL)
#  define STORE32L(x, y) { \
        (y)[3] = (unsigned char) (((x) >> 24) & 255); \
        (y)[2] = (unsigned char) (((x) >> 16) & 255);  \
        (y)[1] = (unsigned char) (((x) >> 8) & 255); \
        (y)[0] = (unsigned char) ((x) & 255); \
}

#  define LOAD32L(x, y) { \
        x = ((unsigned long) ((y)[3] & 255) << 24) | \
            ((unsigned long) ((y)[2] & 255) << 16) | \
            ((unsigned long) ((y)[1] & 255) << 8)  | \
            ((unsigned long) ((y)[0] & 255)); \
}

#  define STORE64L(x, y) { \
        (y)[7] = (unsigned char) (((x) >> 56) & 255); \
        (y)[6] = (unsigned char) (((x) >> 48) & 255); \
        (y)[5] = (unsigned char) (((x) >> 40) & 255); \
        (y)[4] = (unsigned char) (((x) >> 32) & 255); \
        (y)[3] = (unsigned char) (((x) >> 24) & 255); \
        (y)[2] = (unsigned char) (((x) >> 16) & 255); \
        (y)[1] = (unsigned char) (((x) >> 8) & 255); \
        (y)[0] = (unsigned char) ((x) & 255); \
}

#  define LOAD64L(x, y) { \
        x = (((uint64) ((y)[7] & 255)) << 56) | (((uint64) ((y)[6] & 255)) << 48) | \
            (((uint64) ((y)[5] & 255)) << 40) | (((uint64) ((y)[4] & 255)) << 32) | \
            (((uint64) ((y)[3] & 255)) << 24) | (((uint64) ((y)[2] & 255)) << 16) | \
            (((uint64) ((y)[1] & 255)) << 8) | (((uint64) ((y)[0] & 255))); \
}

#  define STORE32H(x, y) { \
        (y)[0] = (unsigned char) (((x) >> 24) & 255); \
        (y)[1] = (unsigned char) (((x) >> 16) & 255); \
        (y)[2] = (unsigned char) (((x) >> 8) & 255); \
        (y)[3] = (unsigned char) ((x) & 255); \
}

#  define LOAD32H(x, y) { \
        x = ((unsigned long) ((y)[0] & 255) << 24) | \
            ((unsigned long) ((y)[1] & 255) << 16) | \
            ((unsigned long) ((y)[2] & 255) << 8)  | \
            ((unsigned long) ((y)[3] & 255)); \
}

#  define STORE64H(x, y) { \
        (y)[0] = (unsigned char) (((x) >> 56) & 255); \
        (y)[1] = (unsigned char) (((x) >> 48) & 255); \
        (y)[2] = (unsigned char) (((x) >> 40) & 255); \
        (y)[3] = (unsigned char) (((x) >> 32) & 255); \
        (y)[4] = (unsigned char) (((x) >> 24) & 255); \
        (y)[5] = (unsigned char) (((x) >> 16) & 255); \
        (y)[6] = (unsigned char) (((x) >> 8) & 255); \
        (y)[7] = (unsigned char) ((x) & 255); \
}

#  define LOAD64H(x, y) { \
        x = (((uint64) ((y)[0] & 255)) << 56) | (((uint64) ((y)[1] & 255)) << 48) | \
            (((uint64) ((y)[2] & 255)) << 40) | (((uint64) ((y)[3] & 255)) << 32) | \
            (((uint64) ((y)[4] & 255)) << 24) | (((uint64) ((y)[5] & 255)) << 16) | \
            (((uint64) ((y)[6] & 255)) << 8) | (((uint64) ((y)[7] & 255))); \
}

# endif /* ENDIAN_NEUTRAL */

# ifdef ENDIAN_LITTLE
#  define STORE32H(x, y) { \
        (y)[0] = (unsigned char) (((x) >> 24) & 255); \
        (y)[1] = (unsigned char) (((x) >> 16) & 255); \
        (y)[2] = (unsigned char) (((x) >> 8) & 255); \
        (y)[3] = (unsigned char) ((x) & 255); \
}

#  define LOAD32H(x, y) { \
        x = ((unsigned long) ((y)[0] & 255) << 24) | \
            ((unsigned long) ((y)[1] & 255) << 16) | \
            ((unsigned long) ((y)[2] & 255) << 8)  | \
            ((unsigned long) ((y)[3] & 255)); \
}

#  define STORE64H(x, y) { \
        (y)[0] = (unsigned char) (((x) >> 56) & 255); \
        (y)[1] = (unsigned char) (((x) >> 48) & 255); \
        (y)[2] = (unsigned char) (((x) >> 40) & 255); \
        (y)[3] = (unsigned char) (((x) >> 32) & 255); \
        (y)[4] = (unsigned char) (((x) >> 24) & 255); \
        (y)[5] = (unsigned char) (((x) >> 16) & 255); \
        (y)[6] = (unsigned char) (((x) >> 8) & 255); \
        (y)[7] = (unsigned char) ((x) & 255); \
}

#  define LOAD64H(x, y) { \
        x = (((uint64) ((y)[0] & 255)) << 56) | (((uint64) ((y)[1] & 255)) << 48) | \
            (((uint64) ((y)[2] & 255)) << 40) | (((uint64) ((y)[3] & 255)) << 32) | \
            (((uint64) ((y)[4] & 255)) << 24) | (((uint64) ((y)[5] & 255)) << 16) | \
            (((uint64) ((y)[6] & 255)) << 8) | (((uint64) ((y)[7] & 255))); }

#  ifdef ENDIAN_32BITWORD
#   define STORE32L(x, y) { \
        unsigned long __t = (x); memcpy(y, &__t, 4); \
}

#   define LOAD32L(x, y)  memcpy(&(x), y, 4);

#   define STORE64L(x, y) { \
        (y)[7] = (unsigned char) (((x) >> 56) & 255); \
        (y)[6] = (unsigned char) (((x) >> 48) & 255); \
        (y)[5] = (unsigned char) (((x) >> 40) & 255); \
        (y)[4] = (unsigned char) (((x) >> 32) & 255); \
        (y)[3] = (unsigned char) (((x) >> 24) & 255); \
        (y)[2] = (unsigned char) (((x) >> 16) & 255); \
        (y)[1] = (unsigned char) (((x) >> 8) & 255); \
        (y)[0] = (unsigned char) ((x) & 255); \
}

#   define LOAD64L(x, y) { \
        x = (((uint64) ((y)[7] & 255)) << 56) | (((uint64) ((y)[6] & 255)) << 48) | \
            (((uint64) ((y)[5] & 255)) << 40) | (((uint64) ((y)[4] & 255)) << 32) | \
            (((uint64) ((y)[3] & 255)) << 24) | (((uint64) ((y)[2] & 255)) << 16) | \
            (((uint64) ((y)[1] & 255)) << 8) | (((uint64) ((y)[0] & 255))); \
}

#  else /* 64-bit words then  */
#   define STORE32L(x, y) \
    { unsigned int __t = (x); memcpy(y, &__t, 4); }

#   define LOAD32L(x, y) \
    { memcpy(&(x), y, 4); x &= 0xFFFFFFFF; }

#   define STORE64L(x, y) \
    { uint64 __t = (x); memcpy(y, &__t, 8); }

#   define LOAD64L(x, y) \
    { memcpy(&(x), y, 8); }

#  endif /* ENDIAN_64BITWORD */
# endif  /* ENDIAN_LITTLE */

/******************************************************************************/

# ifdef ENDIAN_BIG
#  define STORE32L(x, y) { \
        (y)[3] = (unsigned char) (((x) >> 24) & 255); \
        (y)[2] = (unsigned char) (((x) >> 16) & 255); \
        (y)[1] = (unsigned char) (((x) >> 8) & 255); \
        (y)[0] = (unsigned char) ((x) & 255); \
}

#  define LOAD32L(x, y) { \
        x = ((unsigned long) ((y)[3] & 255) << 24) | \
            ((unsigned long) ((y)[2] & 255) << 16) | \
            ((unsigned long) ((y)[1] & 255) << 8)  | \
            ((unsigned long) ((y)[0] & 255)); \
}

#  define STORE64L(x, y) { \
        (y)[7] = (unsigned char) (((x) >> 56) & 255); \
        (y)[6] = (unsigned char) (((x) >> 48) & 255); \
        (y)[5] = (unsigned char) (((x) >> 40) & 255); \
        (y)[4] = (unsigned char) (((x) >> 32) & 255); \
        (y)[3] = (unsigned char) (((x) >> 24) & 255); \
        (y)[2] = (unsigned char) (((x) >> 16) & 255); \
        (y)[1] = (unsigned char) (((x) >> 8) & 255); \
        (y)[0] = (unsigned char) ((x) & 255); \
}

#  define LOAD64L(x, y) { \
        x = (((uint64) ((y)[7] & 255)) << 56) | (((uint64) ((y)[6] & 255)) << 48) | \
            (((uint64) ((y)[5] & 255)) << 40) | (((uint64) ((y)[4] & 255)) << 32) | \
            (((uint64) ((y)[3] & 255)) << 24) | (((uint64) ((y)[2] & 255)) << 16) | \
            (((uint64) ((y)[1] & 255)) << 8) | (((uint64) ((y)[0] & 255))); \
}

/******************************************************************************/

#  ifdef ENDIAN_32BITWORD
#   define STORE32H(x, y) \
    { unsigned int __t = (x); memcpy(y, &__t, 4); }

#   define LOAD32H(x, y) memcpy(&(x), y, 4);

#   define STORE64H(x, y) { \
        (y)[0] = (unsigned char) (((x) >> 56) & 255); \
        (y)[1] = (unsigned char) (((x) >> 48) & 255); \
        (y)[2] = (unsigned char) (((x) >> 40) & 255); \
        (y)[3] = (unsigned char) (((x) >> 32) & 255); \
        (y)[4] = (unsigned char) (((x) >> 24) & 255); \
        (y)[5] = (unsigned char) (((x) >> 16) & 255); \
        (y)[6] = (unsigned char) (((x) >> 8) & 255); \
        (y)[7] = (unsigned char) ((x) & 255); \
}

#   define LOAD64H(x, y) { \
        x = (((uint64) ((y)[0] & 255)) << 56) | (((uint64) ((y)[1] & 255)) << 48) | \
            (((uint64) ((y)[2] & 255)) << 40) | (((uint64) ((y)[3] & 255)) << 32) | \
            (((uint64) ((y)[4] & 255)) << 24) | (((uint64) ((y)[5] & 255)) << 16) | \
            (((uint64) ((y)[6] & 255)) << 8) | (((uint64) ((y)[7] & 255))); \
}

/******************************************************************************/

#  else /* 64-bit words then  */

#   define STORE32H(x, y) \
    { unsigned int __t = (x); memcpy(y, &__t, 4); }

#   define LOAD32H(x, y) \
    { memcpy(&(x), y, 4); x &= 0xFFFFFFFF; }

#   define STORE64H(x, y) \
    { uint64 __t = (x); memcpy(y, &__t, 8); }

#   define LOAD64H(x, y) \
    { memcpy(&(x), y, 8); }

#  endif /* ENDIAN_64BITWORD */
# endif  /* ENDIAN_BIG */

/******************************************************************************/

# ifdef HAVE_NATIVE_INT64
#  define ROL64c(x, y) \
    ( (((x) << ((uint64) (y) & 63)) | \
       (((x) & CONST64(0xFFFFFFFFFFFFFFFF)) >> ((uint64) 64 - ((y) & 63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#  define ROR64c(x, y) \
    ( ((((x) & CONST64(0xFFFFFFFFFFFFFFFF)) >> ((uint64) (y) & CONST64(63))) | \
       ((x) << ((uint64) (64 - ((y) & CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))
# endif /* HAVE_NATIVE_INT64 */

/******************************************************************************/
/*
    Return the length of padding bytes required for a record of 'LEN' bytes
    The name Pwr2 indicates that calculations will work with 'BLOCKSIZE'
    that are powers of 2.
    Because of the trailing pad length byte, a length that is a multiple
    of the pad bytes
 */
# define psPadLenPwr2(LEN, BLOCKSIZE) \
    BLOCKSIZE <= 1 ? (unsigned char) 0 : \
    (unsigned char) (BLOCKSIZE - ((LEN) &(BLOCKSIZE - 1)))

# ifdef  USE_CRL
extern int32_t psCrlOpen();
extern void psCrlClose();
# endif

#endif /* _h_PS_CRYPTOLIB */

/******************************************************************************/

