/**
 *      @file    sha256_standalone.h
 *      @version $Format:%h%d$
 *
 *      Header for sha256 standalone use.
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

#ifndef _h_CRYPTO_DIGEST_SHA256_STANDALONE
# define _h_CRYPTO_DIGEST_SHA256_STANDALONE
/******************************************************************************/

#include "osdep-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Compute SHA-256 hash.

    This function computes SHA-256 of contiguous data.
    The function is available prior initialization of CL/FL/SL libraries,
    thus allowing early use of SHA-256 during initialization of the software.

    @param data Data to hash
    @param len  The length of data to hash in bytes.
    @param hash SHA-256 hash digest in binary (32 bytes).
 */
void psSha256Standalone(const void *data,
                        uint32_t len,
                        unsigned char hash[32 /* SHA256_HASHLEN */]);

#ifdef __cplusplus
}
#endif
    
#endif /* _h_CRYPTO_DIGEST_SHA256_STANDALONE */

/******************************************************************************/

