/**
 *      @file    cryptoConfig.h
 *      @version $Format:%h%d$
 *
 *      Configuration file for crypto features.
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

#ifndef _h_PS_CRYPTOCONFIG
# define _h_PS_CRYPTOCONFIG

/******************************************************************************/
/* Configurable features */
/******************************************************************************/
/**
    Define to enable psTrace*Crypto APIs for debugging the crypto module.
 */
/* #define USE_CRYPTO_TRACE */

#  ifdef DEBUG
/* #define CRYPTO_ASSERT	 *//**< Extra sanity asserts */
#  endif

/******************************************************************************/
/*
    Use built-in cryptographic library delivered with MatrixSSL
 */
#   define USE_NATIVE_RSA /* Default built-in software support */

/******************************************************************************/
/**
    Security related settings.

    @security MIN_*_BITS is the minimum supported key sizes in bits, weaker
    keys will be rejected.
 */
#  define MIN_ECC_BITS 192/**< @security Affects ECC curves below */

#   define MIN_RSA_BITS    1024

#    define MIN_DH_BITS 1024

#  define USE_BURN_STACK/**< @security Zero sensitive data from the stack. */

/******************************************************************************/
/**
    Public-Key Algorithm Support.
 */
#  define USE_RSA
/* #define USE_ECC */
#  define USE_DH
/**< @note Enable verification of DSA signatures in certificate validation.
   Works only when using the CL/SL library. @pre USE_CERT_PARSE. */
/* #define USE_DSA_VERIFY */

/******************************************************************************/
/**
    Build the PKCS and ASN1 extra CL sublibraries.
    These are needed by the CL_PKCS API.
 */

/******************************************************************************/

/**
    Define to enable the individual NIST Prime curves.
    @see http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
 */
#  ifdef USE_ECC
#    define USE_SECP192R1/**< @security FIPS allowed for sig ver only. */
#   define USE_SECP224R1
#   define USE_SECP256R1/**< @security NIST_SHALL */
#   define USE_SECP384R1/**< @security NIST_SHALL */
#   define USE_SECP521R1
#  endif

/**
    Define to enable the individual Brainpool curves.
    @see https://tools.ietf.org/html/rfc5639
    @security WARNING: Public points on Brainpool curves are not validated
 */
#  ifdef USE_ECC
/* #define USE_BRAIN224R1 */
/* #define USE_BRAIN256R1 */
/* #define USE_BRAIN384R1 */
/* #define USE_BRAIN512R1 */
#  endif

/******************************************************************************/
/**
    Symmetric and AEAD ciphers.
    @security Deprecated ciphers must be enabled in cryptolib.h
 */
/* #define USE_AES  *//* Enable/Disable AES */
#  define USE_AES_CBC
#  define USE_AES_GCM

/** If you want new ciphersuites specified in RFC 7539 enable this.
    Currently CHACHA20-based cipher suites are only supported by the newest
    TLS clients and servers. These cipher suites are not allowed in FIPS
    mode of operation.
*/
/* #define USE_CHACHA20_POLY1305_IETF */

/** @security 3DES is still relatively secure, however is deprecated for TLS */
#  define USE_3DES

/******************************************************************************/
/**
    Digest algorithms.

    @note SHA256 and above are used with TLS 1.2, and also used for
    certificate signatures on some certificates regardless of TLS version.

    @security MD5 is deprecated, but still required in combination with SHA-1
    for TLS handshakes before TLS 1.2, meaning that the strength is at least
    that of SHA-1 in this usage. The define USE_MD5SHA1 can be used to enable
    MD5 only for this purpose. The only other usage of MD5 by TLS is for
    certificate signatures and MD5 based cipher suites. Both of which are
    disabled at compile time by default.

    @security SHA1 will be deprecated in the future, but is still required in
    combination with MD5 for versions prior to TLS 1.2. In addition, SHA1
    certificates are still commonly used, so SHA1 support may be needed
    to validate older certificates. It is possible to completely disable
    SHA1 using TLS 1.2 and SHA2 based ciphersuites, and interacting
    only with newer certificates.
 */
/* #define USE_SHA224	 *//**< @note Used only for cert signature */
#  define USE_SHA256/**< @note Required for TLS 1.2 and above */
#  define USE_HMAC_SHA256
#  define USE_SHA384/**< @pre USE_SHA512 */
#  define USE_HMAC_SHA384
#  define USE_SHA512

/**
    @security SHA-1 based hashes are deprecated but enabled by default
    @note ENABLE_SHA1_SIGNED_CERTS can additionally be configured below.
 */
#  define USE_SHA1
#  define USE_HMAC_SHA1

/**
    @security MD5 is considered insecure, but required by TLS < 1.2
    @note ENABLE_MD5_SIGNED_CERTS can additionally be configured below.
 */
#  define USE_MD5
#  define USE_MD5SHA1/* Required for < TLS 1.2 Handshake */
#  define USE_HMAC_MD5

/**
    @security MD2 is considered insecure, but is sometimes used for
    verification of legacy root certificate signatures.
    @note MD2 signature verification also requires
    ENABLE_MD5_SIGNED_CERTS and USE_MD5.
 */
/* #define USE_MD2 */

/* Please enable, unless using no HMAC algorithms. */
#  define USE_HMAC

/******************************************************************************/
/**
    X.509 Certificates/PKI
 */
#  define USE_BASE64_DECODE
#  define USE_X509/**< Enable minimal X.509 support. */
#  define USE_CERT_PARSE/**< Enable TBSCertificate parsing. Usually required. @pre USE_X509 */
#  define USE_FULL_CERT_PARSE/**< @pre USE_CERT_PARSE */
/**< Support extra distinguished name attributes that SHOULD be supported according to RFC 5280. */
/* #define USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
/**< Support extra distinguished name attributes not mentioned in RFC 5280. */
/* #define USE_EXTRA_DN_ATTRIBUTES */
/* #define ENABLE_CA_CERT_HASH  *//**< Used only for TLS trusted CA ind ext. */
/* #define ENABLE_MD5_SIGNED_CERTS  *//** @security Accept MD5 signed certs? */

/**
    @security SHA-1 based signatures are insecure, as SHA-1 can no longer
    be considered collision resistant (https://shattered.it/static/shattered.pdf).
    Enable if compatibility with old certificates is required.
 */
/* #define ENABLE_SHA1_SIGNED_CERTS */

/**< @security Allow parsing of locally trusted v1 root certs? */
/* #define ALLOW_VERSION_1_ROOT_CERT_PARSE */
/**
    When parsing certificates, always also retain the unparsed DER data.
    Enabling this has the same effect as setting the
    CERT_STORE_UNPARSED_BUFFER flag in each psX509ParseCert call.
 */
/* #define ALWAYS_KEEP_CERT_DER */
/**
   Always attempt to match expectedName with the subject CN, even if
   a supported, but non-matching subjectAltName was presented.
   The default behaviour is to check the CN only when no supported SAN
   was presented, in accordance with Section 6.4.4 of RFC 6125.
 */
/* #define ALWAYS_CHECK_SUBJECT_CN_IN_HOSTNAME_VALIDATION */
#  define USE_CRL/***< @pre USE_FULL_CERT_PARSE */
#  ifdef USE_CRL
/**
   Allow CRL authentication to succeed even when signer CA's cert does not
   have the keyUsage extension and thus no cRLSign bit.
   Note that RFC 5280 requires CRL issuer certs to have the keyUsage extension
   and the cRLSign bit.
 */
/* #define ALLOW_CRL_ISSUERS_WITHOUT_KEYUSAGE */
#  endif
/**
   Enable OCSP response and request handling.
*/
/* #define USE_OCSP  *//**< @pre USE_SHA1 */
#  ifdef USE_OCSP
#    define USE_OCSP_RESPONSE
#    define USE_OCSP_REQUEST
#  elif defined(USE_X509) && defined(USE_SHA1)
/**
   Enable parsing and writing of OCSP responses. This is enough
   to support OCSP stapling.
*/
#    define USE_OCSP_RESPONSE /**< @pre USE_SHA1 */
#endif /* USE_OCSP */

/******************************************************************************/
/**
    Various PKCS standards support
 */
#  define USE_PRIVATE_KEY_PARSING
#   define USE_PKCS5/**< v2.0 PBKDF encrypted priv keys. @pre USE_3DES */
/**< Enable PBKDF1 in priv key PEM encryption. @pre USE_PKCS5 and @pre USE_MD5. @security Not recommended. */
#   define USE_PBKDF1
#  define USE_PKCS8/* Alternative private key storage format */
#  define USE_PKCS12/**< @pre USE_PKCS8 */
#  define USE_PKCS1_OAEP/* OAEP padding algorithm */
#  define USE_PKCS1_PSS/* PSS padding algorithm */

#endif    /* _h_PS_CRYPTOCONFIG */

/******************************************************************************/

