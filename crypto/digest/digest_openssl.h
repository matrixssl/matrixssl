/**
 *      @file    digest_openssl.h
 *      @version $Format:%h%d$
 *
 *      Header for OpenSSL Crypto Layer.
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

#ifndef _h_OPENSSL_DIGEST
# define _h_OPENSSL_DIGEST

/******************************************************************************/

# if defined(USE_OPENSSL_MD5) || defined(USE_OPENSSL_MD5SHA1)
#  include <openssl/md5.h>
# endif

# if defined(USE_OPENSSL_SHA1) || defined(USE_OPENSSL_SHA256) || \
    defined(USE_OPENSSL_SHA384) || defined(USE_OPENSSL_SHA512)
#  include <openssl/sha.h>
# endif

# ifdef USE_OPENSSL_MD5
typedef MD5_CTX psMd5_t;
# endif

# ifdef USE_OPENSSL_MD5SHA1
typedef struct
{
    MD5_CTX md5;
    SHA_CTX sha1;
} psMd5Sha1_t;
# endif

# ifdef USE_OPENSSL_SHA1
typedef SHA_CTX psSha1_t;
# endif

# ifdef USE_OPENSSL_SHA256
typedef SHA256_CTX psSha256_t;
# endif

# ifdef USE_OPENSSL_SHA384
typedef SHA512_CTX psSha384_t;
# endif

# ifdef USE_OPENSSL_SHA512
typedef SHA512_CTX psSha512_t;
# endif

/******************************************************************************/

# if defined(USE_OPENSSL_HMAC_SHA1) || defined(USE_OPENSSL_HMAC_SHA256) || \
    defined(USE_OPENSSL_HMAC_SHA384) || defined(USE_OPENSSL_HMAC_SHA512)

#  include <openssl/hmac.h>
#  include <openssl/evp.h>

typedef HMAC_CTX psHmacMd5_t;
typedef HMAC_CTX psHmacSha1_t;
typedef HMAC_CTX psHmacSha256_t;
typedef HMAC_CTX psHmacSha384_t;

# endif

/******************************************************************************/

#endif /* _h_OPENSSL_DIGEST */

