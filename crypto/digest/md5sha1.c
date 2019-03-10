/**
 *      @file    md5sha1.c
 *      @version $Format:%h%d$
 *
 *      Combined MD5+SHA1 hash for SSL 3.0 and TLS 1.0/1.1 handshake hash.
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

#include "../cryptoImpl.h"

#ifdef USE_MATRIX_MD5SHA1

# if !defined(USE_MD5) || !defined(USE_SHA1)
#  error USE_MD5 and USE_SHA1 required
# endif

/******************************************************************************/
/**
    Maintain MD5 and SHA1 hashes of the same data.
    @note This could be done more optimally, give the use of this in TLS.
        Some state is shared between the two contexts, and some paralellism
        could be used in calculation.
 */
int32_t psMd5Sha1Init(psMd5Sha1_t *md)
{
    int32_t rc;

# ifdef CRYPTO_ASSERT
    psAssert(md);
# endif
    if ((rc = psMd5Init(&md->md5)) < 0)
    {
        return rc;
    }
    if ((rc = psSha1Init(&md->sha1)) < 0)
    {
        /* We call Final to clear the state, ignoring the output */
        psMd5Final(&md->md5, NULL);
        return rc;
    }
    return PS_SUCCESS;
}

/**
    Update MD5 and SHA1 hashes of the same data.
 */
void psMd5Sha1Update(psMd5Sha1_t *md, const unsigned char *buf,
    uint32_t len)
{
# ifdef CRYPTO_ASSERT
    psAssert(md && buf);
# endif
    psMd5Update(&md->md5, buf, len);
    psSha1Update(&md->sha1, buf, len);
}

/**
    Finalize output of the combined MD5-SHA1
    The output is 36 bytes, first the 16 bytes MD5 then the 20 bytes SHA1
 */
void psMd5Sha1Final(psMd5Sha1_t *md, unsigned char hash[MD5SHA1_HASHLEN])
{
# ifdef CRYPTO_ASSERT
    psAssert(md && hash);
# endif
    psMd5Final(&md->md5, hash);
    psSha1Final(&md->sha1, hash + MD5_HASHLEN);
}

#endif /* USE_MATRIX_MD5SHA1 */

/******************************************************************************/

