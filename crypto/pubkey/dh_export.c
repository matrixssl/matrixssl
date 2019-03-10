/**
 *      @file    dh_export.c
 *      @version $Format:%h%d$
 *
 *      Diffie-Hellman: Public key export.
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

#include "../cryptoImpl.h"

#if defined USE_MATRIX_DH || defined USE_CL_DH

/******************************************************************************/

/**
    Export a public psDhKey_t struct to a raw binary format.

    @param pool Memory pool
    @param[in] key Pointer to DH key to export
    @param[out] out Pointer to buffer to write raw public DH key
    @param[in,out] outlen On input, the number of bytes available in 'out',
        on successful return, the number of bytes written to 'out'.
    @return < on failure
 */
int32_t psDhExportPubKey(psPool_t *pool, const psDhKey_t *key,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char *c;
    int16_t pad;
    int32_t rc;

    if (*outlen < key->size)
    {
        return PS_ARG_FAIL;
    }
    c = out;
    pad = key->size - pstm_unsigned_bin_size(&key->pub);
    if (pad > 0)
    {
        Memset(c, 0x0, pad);
        c += pad;
    }
    else if (pad < 0)
    {
        return PS_FAIL;
    }
    if ((rc = pstm_to_unsigned_bin(pool, &key->pub, c)) < 0)
    {
        return rc;
    }
    *outlen = key->size;
    return PS_SUCCESS;
}

#endif /* USE_MATRIX_DH || USE_CL_DH */

/******************************************************************************/

