/**
 *      @file    pstm_str.c
 *      @version $Format:%h%d$
 *
 *      Multiprecision number implementation.
 */
/*
 *      Copyright (c) 2017 INSIDE Secure Corporation
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
#include "pstm.h"
#include "pstm_str.h"

#ifndef NO_PSTM_STR
/* Static storage for pstm_str preallocated values. */
const char *pstm_str_null = "(null)";
const char *pstm_str_memfail = "(memory_error)";

pstm_str pstm_str_from(psPool_t *pool, const pstm_int *a)
{
    static unsigned char hex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    char *b;
    unsigned char *bh;
    int neg;
    uint16_t sz = pstm_unsigned_bin_size(a);
    uint16_t i;
    int32_t err;

    if (a == NULL)
    {
        return PSTM_STR_NULL;
    }
    b = psMalloc(pool, sz * 2 + 4);
    if (!b)
    {
        return PSTM_STR_MEMFAIL;
    }
    neg = a->sign == PSTM_NEG;
    if (neg)
    {
        b[0] = '-';
        b[1] = '0';
        b[2] = sz > 0 ? 'x' : 0;
        bh = (unsigned char *) &b[3];
        bh[sz * 2] = 0;
    }
    else
    {
        b[0] = '0';
        b[1] = sz > 0 ? 'x' : 0;
        bh = (unsigned char *) &b[2];
        bh[sz * 2] = 0;
    }
    err = pstm_to_unsigned_bin(pool, a, bh);
    if (err < 0)
    {
        psFree(b, pool);
        return PSTM_STR_MEMFAIL;
    }
    for (i = sz; i-- > 0; )
    {
        bh[i * 2 + 1] = hex[bh[i] & 15];
        bh[i * 2] = hex[bh[i] / 16];
    }
    return b;
}

void pstm_str_free(psPool_t *pool, pstm_str str)
{
    if (str != PSTM_STR_NULL && str != PSTM_STR_MEMFAIL)
    {
        psFree(str, pool);
    }
}

#endif /* NO_PSTM_STR */

