/**
 *      @file    digest_sodium.h
 *      @version $Format:%h%d$
 *
 *      Header for libsodium crypto Layer.
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

#ifndef _h_LIBSODIUM_DIGEST
# define _h_LIBSODIUM_DIGEST

/******************************************************************************/


# ifdef USE_LIBSODIUM_SHA256
#  include "sodium/crypto_hash_sha256.h"
typedef crypto_hash_sha256_state psSha256_t;
# endif

# ifdef USE_LIBSODIUM_SHA512
#  include "sodium/crypto_hash_sha512.h"
#  ifdef USE_LIBSODIUM_SHA384
typedef crypto_hash_sha512_state psSha384_t;
#  endif
typedef crypto_hash_sha512_state psSha512_t;
# endif

/******************************************************************************/

# ifdef USE_LIBSODIUM_HMAC_SHA256
#  include "sodium/crypto_auth_hmacsha256.h"
typedef crypto_auth_hmacsha256_state psHmacSha256_t;
# endif

/******************************************************************************/

#endif /* _h_LIBSODIUM_DIGEST */

