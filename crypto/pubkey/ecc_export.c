/**
 *      @file    ecc_export.c
 *      @version $Format:%h%d$
 *
 *      Functions for exporting ECC public keys over-the-wire using
 *      Matrix Crypto.
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

#ifdef USE_MATRIX_ECC

/******************************************************************************/

# define ECC_BUF_SIZE    256

/******************************************************************************/
/**
   ANSI X9.62 or X9.63 (Sec. 4.3.6) uncompressed export.
   @param[in] pool Memory pool
   @param[in] key Key to export
   @param[out] out [out] destination of export
   @param[in, out] outlen Length of destination and final output size
   @return PS_SUCCESS on success, < 0 on failure
 */
int32_t psEccX963ExportKey(psPool_t *pool, const psEccKey_t *key,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char buf[ECC_BUF_SIZE];
    unsigned long numlen;
    int32_t res;

    numlen = key->curve->size;
    if (*outlen < (1 + 2 * numlen))
    {
        *outlen = 1 + 2 * numlen;
        return PS_LIMIT_FAIL;
    }

    out[0] = (unsigned char) ANSI_UNCOMPRESSED;

    /* pad and store x */
    Memset(buf, 0, sizeof(buf));
    if ((res = pstm_to_unsigned_bin(pool, &key->pubkey.x, buf +
             (numlen - pstm_unsigned_bin_size(&key->pubkey.x)))) != PSTM_OKAY)
    {
        return res;
    }
    Memcpy(out + 1, buf, numlen);

    /* pad and store y */
    Memset(buf, 0, sizeof(buf));
    if ((res = pstm_to_unsigned_bin(pool, &key->pubkey.y, buf +
             (numlen - pstm_unsigned_bin_size(&key->pubkey.y)))) != PSTM_OKAY)
    {
        return res;
    }
    Memcpy(out + 1 + numlen, buf, numlen);

    *outlen = 1 + 2 * numlen;
    return PS_SUCCESS;
}

#endif  /* USE_MATRIX_ECC */

