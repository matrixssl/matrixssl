/**
 *      @file    digest.h
 *      @version $Format:%h%d$
 *
 *      Header for internal symmetric key cryptography support.
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

#ifndef _h_CRYPTO_DIGEST
# define _h_CRYPTO_DIGEST
/******************************************************************************/

# define SHA1_HASH_SIZE      20
# define SHA224_HASH_SIZE    28
# define SHA256_HASH_SIZE    32
# define SHA384_HASH_SIZE    48
# define SHA512_HASH_SIZE    64
# define MD2_HASH_SIZE       16
# define MD5_HASH_SIZE       16

# define SHA1_HASHLEN        20
# define SHA224_HASHLEN      28
# define SHA256_HASHLEN      32
# define SHA384_HASHLEN      48
# define SHA512_HASHLEN      64
# define MD2_HASHLEN         16
# define MD5_HASHLEN         16
# define MD5SHA1_HASHLEN (MD5_HASHLEN + SHA1_HASHLEN)

# if defined(USE_SHA512)
#  define MAX_HASH_SIZE SHA512_HASHLEN
# elif defined(USE_SHA384)
#  define MAX_HASH_SIZE SHA384_HASHLEN
# elif defined(USE_SHA256)
#  define MAX_HASH_SIZE SHA256_HASHLEN
# else
#  define MAX_HASH_SIZE SHA1_HASHLEN
# endif

# define MAX_HASHLEN MAX_HASH_SIZE

# ifdef USE_LIBSODIUM_CRYPTO
#  include "digest_libsodium.h"
# endif
# include "digest_matrix.h"
# ifdef USE_OPENSSL_CRYPTO
#  include "digest_openssl.h"
# endif

/******************************************************************************/

typedef union
{
# ifdef USE_SHA1
    psSha1_t sha1;
# endif
# ifdef USE_MD5SHA1
    psMd5Sha1_t md5sha1;
# endif
# ifdef USE_SHA256
    psSha256_t sha256;
# endif
# ifdef USE_SHA384
    psSha384_t sha384;
# endif
# ifdef USE_SHA512
    psSha512_t sha512;
# endif
# ifdef USE_MD5
    psMd5_t md5;
# endif
# ifdef USE_MD2
    psMd2_t md2;
# endif
# ifdef USE_MD4
    psMd4_t md4;
# endif
} psDigestContext_t;

typedef struct
{
    union
    {
# ifdef USE_HMAC_MD5
        psHmacMd5_t md5;
# endif
# ifdef USE_HMAC_SHA1
        psHmacSha1_t sha1;
# endif
# ifdef USE_HMAC_SHA256
        psHmacSha256_t sha256;
# endif
# ifdef USE_HMAC_SHA384
        psHmacSha384_t sha384;
# endif
    }               u;
    uint8_t type;         /* psCipherType_e */
} psHmac_t;

#endif /* _h_CRYPTO_DIGEST */

/******************************************************************************/

