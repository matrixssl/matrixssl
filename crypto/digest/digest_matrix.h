/**
 *      @file    digest_matrix.h
 *      @version $Format:%h%d$
 *
 *      Header for internal digest support.
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

#ifndef _h_MATRIX_DIGEST
# define _h_MATRIX_DIGEST

/******************************************************************************/

# ifdef USE_MATRIX_SHA1
typedef struct
{
#  ifdef HAVE_NATIVE_INT64
    uint64 length;
#  else
    uint32 lengthHi;
    uint32 lengthLo;
#  endif /* HAVE_NATIVE_INT64 */
    uint32 state[5], curlen;
    unsigned char buf[64];
} psSha1_t;
# endif

# ifdef USE_MATRIX_SHA256
typedef struct
{
#  ifdef HAVE_NATIVE_INT64
    uint64 length;
#  else
    uint32 lengthHi;
    uint32 lengthLo;
#  endif /* HAVE_NATIVE_INT64 */
    uint32 state[8], curlen;
    unsigned char buf[64];
} psSha256_t;
# endif

# ifdef USE_MATRIX_SHA512
typedef struct
{
    uint64 length, state[8];
    unsigned long curlen;
    unsigned char buf[128];
} psSha512_t;
# endif

# ifdef USE_MATRIX_SHA384
#  ifndef USE_MATRIX_SHA512
#   error "USE_MATRIX_SHA512 must be enabled if USE_MATRIX_SHA384 is enabled"
#  endif
typedef psSha512_t psSha384_t;
# endif

# ifdef USE_MATRIX_MD5
typedef struct
{
#  ifdef HAVE_NATIVE_INT64
    uint64 length;
#  else
    uint32 lengthHi;
    uint32 lengthLo;
#  endif /* HAVE_NATIVE_INT64 */
    uint32 state[4], curlen;
    unsigned char buf[64];
} psMd5_t;
# endif

# ifdef USE_MATRIX_MD5SHA1
typedef struct
{
    psMd5_t md5;
    psSha1_t sha1;
} psMd5Sha1_t;
# endif

# ifdef USE_MATRIX_MD4
typedef struct
{
#  ifdef HAVE_NATIVE_INT64
    uint64 length;
#  else
    uint32 lengthHi;
    uint32 lengthLo;
#  endif /* HAVE_NATIVE_INT64 */
    uint32 state[4], curlen;
    unsigned char buf[64];
} psMd4_t;
# endif

# ifdef USE_MATRIX_MD2
typedef struct
{
    unsigned char chksum[16], X[48], buf[16];
    uint32 curlen;
} psMd2_t;
# endif

/******************************************************************************/

# ifdef USE_MATRIX_HMAC_MD5
typedef struct
{
    unsigned char pad[64];
    psMd5_t md5;
} psHmacMd5_t;
# endif

# ifdef USE_MATRIX_HMAC_SHA1
typedef struct
{
    unsigned char pad[64];
    psSha1_t sha1;
} psHmacSha1_t;
# endif

# ifdef USE_MATRIX_HMAC_SHA256
typedef struct
{
    unsigned char pad[64];
    psSha256_t sha256;
} psHmacSha256_t;
# endif

# ifdef USE_MATRIX_HMAC_SHA384
typedef struct
{
    unsigned char pad[128];
    psSha384_t sha384;
} psHmacSha384_t;
# endif

#endif /* _h_MATRIX_DIGEST */

/******************************************************************************/

