/**
 *      @file    matrixsslCheck.h
 *      @version $Format:%h%d$
 *
 *      Configuration validation/sanity checks.
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

#ifndef _h_MATRIXSSLCHECK
# define _h_MATRIXSSLCHECK

# ifdef __cplusplus
extern "C" {
# endif

/*****************************************************************************/
/*
    Start with compile-time checks for the necessary proto and crypto support.
 */
# if !defined(USE_TLS) && defined(DISABLE_SSLV3)
#  error "Must enable a protocol: USE_TLS enabled or DISABLE_SSLV3 disabled"
# endif

# ifdef USE_DTLS
#  ifndef USE_TLS_1_1
#   error "Must enable USE_TLS_1_1 (at a minimum) for DTLS support"
#  endif
#  define DTLS_MAJ_VER        0xFE
#  define DTLS_MIN_VER        0xFF
#  define DTLS_1_2_MIN_VER    0xFD/* DTLS 1.2 */
# endif /* USE_DTLS */

# if defined(USE_TLS_1_1) && !defined(USE_TLS)
#  error "Must define USE_TLS if defining USE_TLS_1_1"
# endif

# ifdef USE_TLS
#  if !defined(USE_TLS_1_2) && defined(DISABLE_TLS_1_0) && defined(DISABLE_TLS_1_1) && defined(DISABLE_SSLV3)
#   error "Bad combination of USE_TLS and DISABLE_TLS"
#  endif
# endif

/*
  Convenience macros for finding out minimum and maximum enabled TLS version.
*/
# if defined(USE_TLS_1_2) && !defined(DISABLE_TLS_1_2)
#  define MAX_ENABLED_TLS_VER TLS_1_2_MIN_VER
# elif defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
#  define MAX_ENABLED_TLS_VER TLS_1_1_MIN_VER
# elif defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
#  define MAX_ENABLED_TLS_VER TLS_MIN_VER
# elif !defined(DISABLE_SSLV3)
#  define MAX_ENABLED_TLS_VER SSL3_MIN_VER
# endif

# if !defined(DISABLE_SSLV3)
#  define MIN_ENABLED_TLS_VER SSL3_MIN_VER
# elif defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
#  define MIN_ENABLED_TLS_VER TLS_MIN_VER
# elif defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
#  define MIN_ENABLED_TLS_VER TLS_1_1_MIN_VER
# elif defined(USE_TLS_1_2) && !defined(DISABLE_TLS_1_2)
#  define MIN_ENABLED_TLS_VER TLS_1_2_MIN_VER
# endif

# ifdef USE_SHARED_SESSION_CACHE
#  ifndef POSIX
#   error "USE_SHARED_SESSION_CACHE only implemented for POSIX platforms."
#  endif
#  ifndef USE_MULTITHREADING
#   error "USE_MULTITHREADING required for USE_SHARED_SESSION_CACHE."
#  endif
# endif

# ifdef USE_EAP_FAST
/******************************************************************************/
#  ifndef USE_SHA1
#   error "Must enable USE_SHA1 in cryptoConfig.h for EAP_FAST"
#  endif
#  if !defined(USE_TLS_RSA_WITH_RC4_128_SHA) || \
    !defined(USE_TLS_RSA_WITH_AES_128_CBC_SHA) || \
    !defined(USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
#   pragma message("WARNING: Not all EAP_FAST required ciphersuites enabled")
#  endif
#  ifndef USE_CLIENT_SIDE_SSL
#   error "EAP_FAST requires CLIENT_SIDE_SSL"
#  endif
#  ifndef USE_STATELESS_SESSION_TICKETS
#   error "EAP_FAST requires STATELESS_SESSION_TICKETS"
#  endif
# endif /* USE_EAP_FAST */

/******************************************************************************/
/*
    SHA1 and MD5 are essential elements for SSL key derivation during protocol
 */
# ifndef USE_MD5SHA1
#  if defined(USE_TLS_1_2) && defined(DISABLE_TLS_1_0) && defined(DISABLE_TLS_1_1) \
    && defined(DISABLE_SSLV3)
#   define USE_ONLY_TLS_1_2
#  else
#   error "Must enable USE_MD5SHA1 in cryptoConfig.h for < TLS 1.2"
#  endif
# endif

# if !defined USE_CLIENT_SIDE_SSL && !defined USE_SERVER_SIDE_SSL
#  error "Must enable either USE_CLIENT_SIDE_SSL or USE_SERVER_SIDE_SSL (or both)"
# endif

# ifdef USE_TLS
#  ifdef USE_HMAC_SHA256   /* TODO */
/*      #error "Must enable USE_HMAC in cryptoConfig.h for TLS protocol support" */
#  endif
# endif

/*
    Handle the various combos of REHANDSHAKES defines
 */
# if defined(ENABLE_INSECURE_REHANDSHAKES) && defined(REQUIRE_SECURE_REHANDSHAKES)
#  error "Can't enable both ENABLE_INSECURE_REHANDSHAKES and REQUIRE_SECURE_REHANDSHAKES"
# endif

# if defined(ENABLE_INSECURE_REHANDSHAKES) || defined(ENABLE_SECURE_REHANDSHAKES)
#  define SSL_REHANDSHAKES_ENABLED
# endif

# if defined(REQUIRE_SECURE_REHANDSHAKES) && !defined(ENABLE_SECURE_REHANDSHAKES)
#  define SSL_REHANDSHAKES_ENABLED
#  define ENABLE_SECURE_REHANDSHAKES
# endif

# ifdef USE_STATELESS_SESSION_TICKETS
#  ifndef USE_HMAC_SHA256
#   error "Must enable USE_HMAC for USE_STATELESS_SESSION_TICKETS"
#  endif
#  ifndef USE_SHA256
#   error "Must enable USE_SHA256 for USE_STATELESS_SESSION_TICKETS"
#  endif
#  ifndef USE_AES
#   error "Must enable USE_AES for USE_STATELESS_SESSION_TICKETS"
#  endif
# endif

/******************************************************************************/
/*
    Test specific crypto features based on which cipher suites are enabled
 */
/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_SSL_RSA_WITH_NULL_MD5
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_NULL_MD5 suite"
#  endif
#  define USE_MD5_MAC
#  define USE_RSA_CIPHER_SUITE
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_SSL_RSA_WITH_NULL_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_NULL_SHA suite"
#  endif
#  define USE_SHA_MAC
#  define USE_RSA_CIPHER_SUITE
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_SSL_RSA_WITH_RC4_128_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_RC4_128_SHA suite"
#  endif
#  ifndef USE_ARC4
#   error "Enable USE_ARC4 in cryptoConfig.h for SSL_RSA_WITH_RC4_128_SHA suite"
#  endif
#  define USE_SHA_MAC
#  define USE_RSA_CIPHER_SUITE
#  define USE_ARC4_CIPHER_SUITE
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_SSL_RSA_WITH_RC4_128_MD5
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_RC4_128_MD5 suite"
#  endif
#  ifndef USE_ARC4
#   error "Enable USE_ARC4 in cryptoConfig.h for SSL_RSA_WITH_RC4_128_MD5 suite"
#  endif
#  define USE_MD5_MAC
#  define USE_RSA_CIPHER_SUITE
#  define USE_ARC4_CIPHER_SUITE
# endif

# ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  ifndef USE_3DES
#   error "Enable USE_3DES in cryptoConfig.h for SSL_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_RSA_CIPHER_SUITE
#  define USE_3DES_CIPHER_SUITE
# endif

# ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_AES_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
# endif

# ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_AES_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
# endif

/******************************************************************************/
/*
    Notes on DHE-related defines
        USE_DHE_CIPHER_SUITE is used for SSL state control for ECC or DH ciphers
        USE_ECC_CIPHER_SUITE is a subset of DHE_CIPHER to determine ECC key
        REQUIRE_DH_PARAMS is a subset of DHE_CIPHER to use 'normal' dh params
 */
# ifdef USE_TLS_1_2
#  ifndef USE_TLS_1_1
#   error "Enable USE_TLS_1_1 in matrixsslConfig.h for TLS_1_2 support"
#  endif
#  ifndef USE_SHA256
#   error "Enable USE_SHA256 in matrixsslConfig.h for TLS_1_2 support"
#  endif

#  ifdef USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
#   ifndef USE_CHACHA20_POLY1305_IETF
#    error "Enable USE_CHACHA20_POLY1305_IETF in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
#   endif
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
#   endif
#   ifndef USE_CHACHA20_POLY1305_IETF
#    error "Enable USE_CHACHA20_POLY1305_IETF in cryptoConfig.h for USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
#   endif
#   define USE_DHE_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
#   endif
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   define USE_SHA_MAC
#   define USE_AES_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA256"
#   endif
#   define USE_SHA_MAC
#   define USE_AES_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   define USE_AES_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   define USE_AES_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_DH
#    error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   define REQUIRE_DH_PARAMS
#   define USE_SHA_MAC
#   define USE_DHE_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
#   endif
#   ifndef USE_DH
#    error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
#   endif
#   define REQUIRE_DH_PARAMS
#   define USE_SHA_MAC
#   define USE_DHE_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
#   endif
#   define USE_SHA_MAC
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
#   endif
#   define USE_SHA_MAC
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
#   endif
#   define USE_SHA_MAC
#   define USE_DH_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
#   endif
#   define USE_SHA_MAC
#   define USE_DH_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
#   endif
#   define USE_DH_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
#   endif
#   define USE_DH_CIPHER_SUITE
#   define USE_ECDSA_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   define USE_SHA_MAC
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   define USE_SHA_MAC
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   define USE_DHE_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
#   endif
#   define USE_DH_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   ifndef USE_AES_GCM
#    error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
#   endif
#   define USE_DH_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   ifndef USE_SHA384
#    error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
#   endif
#   define USE_SHA_MAC
#   define USE_DH_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif

#  ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
#   ifndef USE_ECC
#    error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_RSA
#    error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   ifndef USE_AES
#    error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
#   endif
#   define USE_SHA_MAC
#   define USE_DH_CIPHER_SUITE
#   define USE_ECC_CIPHER_SUITE
#   define USE_RSA_CIPHER_SUITE
#   define USE_AES_CIPHER_SUITE
#  endif
# endif /* USE_TLS_1_2 */

# ifdef USE_TLS_1_1
#  ifndef USE_TLS
#   error "Enable USE_TLS in matrixsslConfig.h for TLS_1_1 support"
#  endif
# endif

# ifndef USE_TLS_1_2
#  if defined(USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) || \
    defined(USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for CHACHA20_POLY1305 cipher suites"
#  endif
#  ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA256"
#  endif
#  ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA256"
#  endif
#  ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
#  endif
#  ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
#  endif
#  ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_128_GCM_SHA256"
#  endif
#  ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
#  endif
#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
#  endif
#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
#  endif
#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
#  endif
#  ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
#  endif
#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
#  endif
#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
#  endif
#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#  endif
#  ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
#  endif
#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
#  endif
#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
#  endif
#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
#  endif
#  ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
#  endif
#  ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
#  endif
#  ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
#  endif
#  ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
#  endif
#  ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
#   error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 "
#  endif
# endif /* ! TLS_1_2 */

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
#  ifndef USE_3DES
#   error "Enable USE_3DES in cryptoConfig.h for SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_ANON_DH_CIPHER_SUITE
#  define USE_DHE_CIPHER_SUITE
#  define USE_3DES_CIPHER_SUITE
#  define USE_SHA_MAC
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_SSL_DH_anon_WITH_RC4_128_MD5
#  ifndef USE_ARC4
#   error "Enable USE_ARC4 in cryptoConfig.h for SSL_DH_anon_WITH_RC4_128_MD5"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for SSL_DH_anon_WITH_RC4_128_MD5"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_ANON_DH_CIPHER_SUITE
#  define USE_DHE_CIPHER_SUITE
#  define USE_ARC4_CIPHER_SUITE
#  define USE_MD5_MAC
# endif

# ifdef USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  ifndef USE_3DES
#   error "Enable USE_3DES in cryptoConfig.h for SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_3DES_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
# endif

# ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
# endif

# ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
# endif

# ifdef USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
#  endif
#  if !defined(USE_TLS) && !defined(USE_DTLS)
#   error "Enable USE_TLS in matrixsslConfig.h for TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_SHA_MAC
#  define USE_ANON_DH_CIPHER_SUITE
#  define USE_DHE_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
#  define USE_PSK_CIPHER_SUITE
#  define USE_DHE_PSK_CIPHER_SUITE
# endif

# ifdef USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
#  endif
#  if !defined(USE_TLS) && !defined(USE_DTLS)
#   error "Enable USE_TLS in matrixsslConfig.h for TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_SHA_MAC
#  define USE_ANON_DH_CIPHER_SUITE
#  define USE_DHE_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
#  define USE_PSK_CIPHER_SUITE
#  define USE_DHE_PSK_CIPHER_SUITE
# endif

# ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA"
#  endif
#  if !defined(USE_TLS) && !defined(USE_DTLS)
#   error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_AES_CIPHER_SUITE
#  define USE_PSK_CIPHER_SUITE
# endif

# ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA"
#  endif
#  if !defined(USE_TLS) && !defined(USE_DTLS)
#   error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_AES_CIPHER_SUITE
#  define USE_PSK_CIPHER_SUITE
# endif

# ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA256
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA256"
#  endif
#  if !defined(USE_TLS) && !defined(USE_DTLS)
#   error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA256"
#  endif
#  ifndef USE_SHA256
#   error "Enable USE_SHA256 in cryptoConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA256"
#  endif
#  define USE_SHA_MAC
#  define USE_AES_CIPHER_SUITE
#  define USE_PSK_CIPHER_SUITE
# endif

# ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA384
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA384"
#  endif
#  if !defined(USE_TLS) && !defined(USE_DTLS)
#   error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA384"
#  endif
#  ifndef USE_SHA384
#   error "Enable USE_SHA384 in cryptoConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA384"
#  endif
#  define USE_SHA_MAC
#  define USE_AES_CIPHER_SUITE
#  define USE_PSK_CIPHER_SUITE
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_TLS_DH_anon_WITH_AES_128_CBC_SHA
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_DH_anon_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for TLS_DH_anon_WITH_AES_128_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_SHA_MAC
#  define USE_ANON_DH_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
#  define USE_DHE_CIPHER_SUITE
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_TLS_DH_anon_WITH_AES_256_CBC_SHA
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_DH_anon_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_DH
#   error "Enable USE_DH in cryptoConfig.h for TLS_DH_anon_WITH_AES_256_CBC_SHA"
#  endif
#  define REQUIRE_DH_PARAMS
#  define USE_SHA_MAC
#  define USE_ANON_DH_CIPHER_SUITE
#  define USE_DHE_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_TLS_RSA_WITH_SEED_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_SEED_CBC_SHA"
#  endif
#  ifndef USE_SEED
#   error "Enable USE_SEED in cryptoConfig.h for TLS_RSA_WITH_SEED_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_RSA_CIPHER_SUITE
#  define USE_SEED_CIPHER_SUITE
# endif

/** @note This cipher is deprecated from matrixsslConfig.h */
# ifdef USE_TLS_RSA_WITH_IDEA_CBC_SHA
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_IDEA_CBC_SHA"
#  endif
#  ifndef USE_IDEA
#   error "Enable USE_IDEA in cryptoConfig.h for TLS_RSA_WITH_IDEA_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_IDEA_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DH_CIPHER_SUITE
#  define USE_ECDSA_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DH_CIPHER_SUITE
#  define USE_ECDSA_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_ECDSA_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_ECDSA_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  ifndef USE_3DES
#   error "Enable USE_3DES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DHE_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
#  define USE_3DES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DH_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

# ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
#  ifndef USE_ECC
#   error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_RSA
#   error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
#  endif
#  define USE_SHA_MAC
#  define USE_DH_CIPHER_SUITE
#  define USE_ECC_CIPHER_SUITE
#  define USE_RSA_CIPHER_SUITE
#  define USE_AES_CIPHER_SUITE
# endif

/******************************************************************************/
/*
    If only PSK suites have been enabled (non-DHE), flip on the USE_ONLY_PSK
    define to create the smallest version of the library. If this is hit, the
    user can disable USE_X509, USE_RSA, USE_ECC, and USE_PRIVATE_KEY_PARSING in
    cryptoConfig.h.
 */
# if !defined(USE_RSA_CIPHER_SUITE) && !defined(USE_DHE_CIPHER_SUITE) && \
    !defined(USE_DH_CIPHER_SUITE)
#  define USE_ONLY_PSK_CIPHER_SUITE
#  ifndef USE_X509
typedef int32 psX509Cert_t;
#  endif
# endif /* !RSA && !DH */

# if !defined(USE_RSA_CIPHER_SUITE) && !defined(USE_DH_CIPHER_SUITE) && \
    defined(USE_DHE_PSK_CIPHER_SUITE)
#  define USE_ONLY_PSK_CIPHER_SUITE
#  ifndef USE_X509
typedef int32 psX509Cert_t;
#  endif
# endif /* DHE_PSK only */

# if !defined(USE_CERT_PARSE) && !defined(USE_ONLY_PSK_CIPHER_SUITE)
#  ifdef USE_CLIENT_SIDE_SSL
#   error "Must enable USE_CERT_PARSE if building client with USE_CLIENT_SIDE_SSL"
#  endif
#  ifdef USE_CLIENT_AUTH
#   error "Must enable USE_CERT_PARSE if client auth (USE_CLIENT_AUTH) is needed"
#  endif
# endif

# if defined(USE_CLIENT_AUTH) || defined(USE_CLIENT_SIDE_SSL)
#  if defined(USE_CERT_PARSE) && !defined(USE_ONLY_PSK_CIPHER_SUITE)
#   define USE_CERT_VALIDATE /* Shorthand. */
#  endif /* USE_CERT_PARSE && USE_ONLY_PSK_CIPHER_SUITE */
# endif /* USE_CLIENT_AUTH || USE_CLIENT_SIDE_SSL */

# if defined(USE_EXT_CERTIFICATE_VERIFY_SIGNING)
#  ifndef USE_CLIENT_AUTH
#   error "Must enable USE_CLIENT_AUTH if USE_EXT_CERTIFICATE_VERIFY_SIGNING is enabled"
#  endif /* USE_CLIENT_AUTH */
#  ifndef USE_CERT_PARSE
#   error "Must enable USE_CERT_PARSE if USE_EXT_CERTIFICATE_VERIFY_SIGNING is enabled"
#  endif /* USE_CERT_PARSE */
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

# ifdef USE_TRUSTED_CA_INDICATION
#  ifndef ENABLE_CA_CERT_HASH
#   error "Define ENABLE_CA_CERT_HASH in cryptoConfig.h for Trusted CA Indication"
#  endif
# endif

# ifdef __cplusplus
}
# endif

#endif /* _h_MATRIXSSLCHECK */

/******************************************************************************/

