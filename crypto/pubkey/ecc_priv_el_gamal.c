/**
 *      @file    ecc_priv_el_gamal.c
 *      @version $Format:%h%d$
 *
 *      ElGamal decryption using Matrix Crypto.
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

extern psEccPoint_t *eccNewPoint(psPool_t *pool,
        short size);
extern void eccFreePoint(psEccPoint_t *p);
extern int32_t eccMulmod(psPool_t *pool,
        const pstm_int *k,
        const psEccPoint_t *G,
        psEccPoint_t *R,
        pstm_int *modulus,
        uint8_t map,
        pstm_int *tmp_int);

/******************************************************************************/

#endif  /* USE_MATRIX_ECC */

