/**
 *      @file    layer.h
 *      @version $Format:%h%d$
 *
 *      Header file to determine crypto algorithm provider.
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

#ifndef _h_PS_CRYPTOLAYER
# define _h_PS_CRYPTOLAYER
/**
    Layer implementations of configured crypto APIs.
    First we define MATRIX as the crypto provider for each enabled algorithm
    that was enabled above and then we can override with other providers.
 */
# if (defined(USE_AES_CBC) || defined(USE_AES_GCM) || \
    defined(USE_AES_WRAP) || defined(USE_AES_CMAC) || \
    defined(USE_AES_CTR))
#  define USE_MATRIX_AES_BLOCK
#  define USE_AES_BLOCK
#  define USE_AES
# endif

# define USE_MATRIX_RAW_KEY /* Default, unless changed by lower layers */

# if defined(USE_AES_CBC)
#  define USE_MATRIX_AES_CBC
# endif
# if defined(USE_AES_GCM)
#  define USE_MATRIX_AES_GCM
# endif
# if defined(USE_AES_CMAC)
#  define USE_MATRIX_AES_CMAC
# endif
# if defined(USE_AES_WRAP)
#  define USE_MATRIX_AES_WRAP
# endif
# if defined(USE_AES_CTR)
#  define USE_MATRIX_AES_CTR
# endif

# ifdef USE_CHACHA20_POLY1305
#  ifndef USE_CHACHA20_POLY1305_IETF
#   ifndef NO_CHACHA20_POLY1305_IETF

/* Issue warning if old USE_CHACHA20_POLY1305 is used, and there is
   nothing said about CHACHA20_POLY1305_IETF.
   Old versions of MatrixSSL used USE_CHACHA20_POLY1305 to turn on/off
   ChaCha20Poly1305 non-IETF/IETF. */
#    ifdef WIN32
#     pragma message("Define USE_CHACHA20_POLY1305_IETF instead of USE_CHACHA20_POLY1305.")
#    else
#     warning "Define USE_CHACHA20_POLY1305_IETF instead of USE_CHACHA20_POLY1305."
#    endif

/* Defining USE_CHACHA20_POLY1305_IETF for compatibility, unless
   spefically forbidden using NO_CHACHA20_POLY1305_IETF. */
#    define USE_CHACHA20_POLY1305_IETF
#   endif /* !NO_CHACHA20_POLY1305_IETF */
#  endif /* !USE_CHACHA20_POLY1305_IETF */
# endif /* USE_CHACHA20_POLY1305 */

# ifdef USE_ARC4
#  define USE_MATRIX_ARC4
# endif
# ifdef USE_RC2
#  define USE_MATRIX_RC2
# endif
# ifdef USE_3DES
#  define USE_MATRIX_3DES
# endif
# ifdef USE_SEED
#  define USE_MATRIX_SEED
# endif
# ifdef USE_IDEA
#  define USE_MATRIX_IDEA
# endif

# if defined(USE_SHA256)
#  define USE_MATRIX_SHA256
# endif
# if defined(USE_HMAC_SHA256)
#  define USE_MATRIX_HMAC_SHA256
# endif

# if defined(USE_SHA384)
#  define USE_MATRIX_SHA384
# endif
# if defined(USE_HMAC_SHA384)
#  define USE_MATRIX_HMAC_SHA384
# endif

# if defined(USE_SHA512)
#  define USE_MATRIX_SHA512
# endif

# if defined(USE_SHA1)
#  define USE_MATRIX_SHA1
# endif
# if defined(USE_HMAC_SHA1)
#  define USE_MATRIX_HMAC_SHA1
# endif
# if defined(USE_MD5SHA1)
#  define USE_MATRIX_MD5SHA1
# endif

# if defined(USE_MD5)
#  define USE_MATRIX_MD5
# endif
# if defined(USE_HMAC_MD5)
#  define USE_MATRIX_HMAC_MD5
# endif

# if defined(USE_MD4)
#  define USE_MATRIX_MD4
# endif

# if defined(USE_MD2)
#  define USE_MATRIX_MD2
# endif

# if defined(USE_RSA)
#  define USE_MATRIX_RSA
# endif

# if defined(USE_ECC)
#  define USE_MATRIX_ECC
# endif

# if defined(USE_DH)
#  define USE_MATRIX_DH
# endif

# if defined(USE_PRNG)
#  define USE_MATRIX_PRNG
# endif

# ifdef USE_CHACHA20_POLY1305_IETF
#  define USE_MATRIX_CHACHA20_POLY1305_IETF
# endif /* USE_CHACHA20_POLY1305_IETF */

# ifdef USE_LIBSODIUM_CRYPTO
/******************************************************************************/
/**
    Use libsodium cryptography primitives (link with libsodium.a).
 */
#  ifdef USE_CHACHA20_POLY1305_IETF
#   undef USE_MATRIX_CHACHA20_POLY1305_IETF /* @note, not defined in matrix crypto */
#   define USE_LIBSODIUM_CHACHA20_POLY1305_IETF
#  endif
 
/* libsodium AES-GCM is not automatically enabled.
   libsodium AES-GCM offers only 256-bit AES-GCM, where as TLS uses 128/256.
#  ifdef USE_MATRIX_AES_GCM
#   undef USE_MATRIX_AES_GCM
#   define USE_LIBSODIUM_AES_GCM
#  endif
*/

#  ifdef USE_MATRIX_SHA256
#   undef USE_MATRIX_SHA256
#   define USE_LIBSODIUM_SHA256
#  endif

#  ifdef USE_MATRIX_SHA384
#   undef USE_MATRIX_SHA384
#   define USE_LIBSODIUM_SHA384
#  endif

#  ifdef USE_MATRIX_SHA512
#   undef USE_MATRIX_SHA512
#   define USE_LIBSODIUM_SHA512
#  endif

#  ifdef USE_MATRIX_HMAC_SHA256
#   undef USE_MATRIX_HMAC_SHA256
#   define USE_LIBSODIUM_HMAC_SHA256
#  endif

# endif /* USE_LIBSODIUM_CRYPTO */


/* Common for CL CRYPTO and FIPS CRYPTO */

# ifdef USE_OPENSSL_CRYPTO
/******************************************************************************/
/**
    Use OpenSSL cryptography primitives (link with libcrypto.a).
    This can take advantage of hardware which has a specifically optimized
    libcrypto library, for example Cavium Octeon.
 */
#  ifdef USE_MATRIX_AES_CBC
#   undef USE_MATRIX_AES_CBC
#   define USE_OPENSSL_AES_CBC
#  endif
#  ifdef USE_MATRIX_MD5
#   undef USE_MATRIX_MD5
#   define USE_OPENSSL_MD5
#  endif
#  ifdef USE_MATRIX_SHA1
#   undef USE_MATRIX_SHA1
#   define USE_OPENSSL_SHA1
#  endif
#  ifdef USE_MATRIX_MD5SHA1
#   undef USE_MATRIX_MD5SHA1
#   define USE_OPENSSL_MD5SHA1
#  endif
#  ifdef USE_MATRIX_SHA256
#   undef USE_MATRIX_SHA256
#   define USE_OPENSSL_SHA256
#  endif
#  ifdef USE_MATRIX_SHA384
#   undef USE_MATRIX_SHA384
#   define USE_OPENSSL_SHA384
#  endif
#  ifdef USE_MATRIX_SHA512
#   undef USE_MATRIX_SHA512
#   define USE_OPENSSL_SHA512
#  endif
#  ifdef USE_MATRIX_HMAC_MD5
#   undef USE_MATRIX_HMAC_MD5
#   define USE_OPENSSL_HMAC_MD5
#  endif
#  ifdef USE_MATRIX_HMAC_SHA1
#   undef USE_MATRIX_HMAC_SHA1
#   define USE_OPENSSL_HMAC_SHA1
#  endif
#  ifdef USE_MATRIX_HMAC_SHA256
#   undef USE_MATRIX_HMAC_SHA256
#   define USE_OPENSSL_HMAC_SHA256
#  endif
#  ifdef USE_MATRIX_HMAC_SHA384
#   undef USE_MATRIX_HMAC_SHA384
#   define USE_OPENSSL_HMAC_SHA384
#  endif
#  ifdef USE_MATRIX_RSA
#   undef USE_MATRIX_RSA
#   define USE_OPENSSL_RSA
#  endif
# endif /* USE_OPENSSL_CRYPTO */

# if defined(__AES__) && !defined(USE_FIPS_CRYPTO)
/******************************************************************************/
/**
    This is defined if the -maes compiler flag is used on Intel platforms.
    @see https://en.wikipedia.org/wiki/AES_instruction_set
 */
#  ifdef USE_MATRIX_AES_BLOCK
#   undef USE_MATRIX_AES_BLOCK
#   define USE_AESNI_AES_BLOCK
#  endif
#  ifdef USE_MATRIX_AES_CBC
#   undef USE_MATRIX_AES_CBC
#   define USE_AESNI_AES_CBC
#  endif
#  ifdef USE_MATRIX_AES_GCM
#   undef USE_MATRIX_AES_GCM
#   define USE_AESNI_AES_GCM
#  endif
#  if defined(USE_AESNI_AES_BLOCK) || defined(USE_AESNI_AES_CBC) || \
    defined(USE_AESNI_AES_GCM)
#   define USE_AESNI_CRYPTO
#  endif
# endif /* __AES__ */

/******************************************************************************/
/*
    Enable algorithm optimizations based on the compiler optimization settings.
    GCC compatible compilers will define:
        __OPTIMIZE__ for all -O1 and above (include -Os)
        __OPTIMIZE_SIZE__ in addition to __OPTIMIZE__ for -Os

    Both code size and RAM usage are affected by these defines.

    By default below, these will be enabled on an optimized build that is
        not optimized for size. Eg. for -O[1-3,fast], but not for -Os

    For a specific platform, it is best to tune these by hand to get the
        right balance of speed and size.
 */
# if defined(__OPTIMIZE__)
#  if !defined(__OPTIMIZE_SIZE__)
/*
    Improve block cipher performance, but produce larger code.
    Platforms vary, but ciphers will generally see a 5%-10% performance
        boost at the cost of 10-20 kilobytes (per algorithm).
 */
#   ifdef USE_MATRIX_AES_BLOCK
#    define PS_AES_IMPROVE_PERF_INCREASE_CODESIZE
#   endif
#   ifdef USE_MATRIX_3DES
#    define PS_3DES_IMPROVE_PERF_INCREASE_CODESIZE
#   endif
/*
    Improve hashing performance, but produce larger code.
    Platforms vary, but digests will generally see a 5%-10% performance
        boost at the cost of 1-10 kilobytes (per algorithm).
 */
#   ifdef USE_MATRIX_MD5
#    define PS_MD5_IMPROVE_PERF_INCREASE_CODESIZE
#   endif
#   ifdef USE_MATRIX_SHA1
#    define PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE
#   endif
/*
    Optimize public/private key operations for speed.
    Optimizations for 1024/2048 bit key size multiplication and squaring math.
    The library size can increase significantly if enabled.
 */
#   if defined(USE_MATRIX_RSA) || defined(USE_MATRIX_ECC) || defined(USE_MATRIX_DH)
#    define PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED
#   endif
#   if defined(USE_MATRIX_RSA) || defined(USE_MATRIX_DH)
#    define USE_1024_KEY_SPEED_OPTIMIZATIONS
#    define USE_2048_KEY_SPEED_OPTIMIZATIONS
#   endif

#  else /* OPTIMIZE_SIZE */
/*
    Optimize public/private key operations for smaller ram usage.
    The memory savings for optimizing for ram is around 50%
 */
#   if defined(USE_MATRIX_RSA) || defined(USE_MATRIX_ECC) || defined(USE_MATRIX_DH)
#    define PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#   endif

#  endif /* OPTIMIZE_SIZE */
# endif  /* OPTIMIZE */

#endif   /* _h_PS_CRYPTOLAYER */

/******************************************************************************/

