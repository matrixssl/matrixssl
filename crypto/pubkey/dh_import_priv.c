/**
 *      @file    dh_import_priv.c
 *      @version $Format:%h%d$
 *
 *      Diffie-Hellman: Import private key.
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
    Import a private DH key in raw (wire) format to a psDhKey_t struct.
    This function will not touch public DH key is there is one in the struct.

    This function is intended to support KAT tests for Diffie-Hellman.

    @param pool Memory pool
    @param[in] in Pointer to buffer containing raw public DH key
    @param[in] inlen Length in bytes of 'in'
    @param[out] key Pointer to allocated key to be initialized with raw
        DH value from 'in'.
    @return < on failure
 */
int32_t psDhImportPrivKey(psPool_t *pool,
    const unsigned char *in, psSize_t inlen,
    psDhKey_t *key)
{
    int32_t rc;

    Memset(&key->priv, 0, sizeof(key->priv));
    if ((rc = pstm_init_for_read_unsigned_bin(pool, &key->priv, inlen)) < 0)
    {
        return rc;
    }
    if ((rc = pstm_read_unsigned_bin(&key->priv, in, inlen)) < 0)
    {
        pstm_clear(&key->priv);
        return rc;
    }
    key->type = PS_PRIVKEY;
    return PS_SUCCESS;
}

#endif /* USE_MATRIX_DH || USE_CL_DH */

/******************************************************************************/

