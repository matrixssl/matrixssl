/**
 *      @file    pstmnt.c
 *      @version $Format:%h%d$
 *
 *      Multiprecision number implementation: constant time montgomery.
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

#ifndef INCLUDE_GUARD_PSTMNT_H
# define INCLUDE_GUARD_PSTMNT_H

# include "../cryptoApi.h"
# include "pstm.h"

/* Before defining pstmnt, ensure pstm has been processed.
   In some configurations the pstm is disabled,
   which also disables pstmnt. */
# ifndef PSTM_AVAILABLE
#  undef USE_CONSTANT_TIME_MODEXP
# endif /* PSTM_AVAILABLE */

# ifdef USE_CONSTANT_TIME_MODEXP

/* pstmnt uses data types subtly different from pstm:
   all limbs specified in the API are always multiples of uint32_t. */
#  define pstmnt_bits uint32_t
#  define pstmnt_word uint32_t
#  define pstmnt_words uint32_t
#  define pstmnt_dword uint64_t
#  define PSTMNT_WORD_BITS 32
#  define PSTMNT_WORD_BYTES 4

/* Inline functions for conversion between types. */

__inline static
const pstmnt_word *pstmnt_const_ptr(const pstm_int *A_const)
{
    return (const pstmnt_word *) A_const->dp;
}

__inline static
pstmnt_word *pstmnt_ptr(pstm_int *A)
{
    return (pstmnt_word *) A->dp;
}

__inline static
pstmnt_words pstmnt_size(const pstm_int *A)
{
    return ((A->used) * DIGIT_BIT) / PSTMNT_WORD_BITS;
}

__inline static
unsigned int pstmnt_size_bytes(const pstm_int *A)
{
    return ((A->used) * DIGIT_BIT) / 8;
}

/* Function attributes. */

#  define PSTMNT_RESTORED /* Parameter is temporary changed during function call,
                             but restored before the function returns. */

/* Function API. */

/* Compute small inverse constant for montgomery operations. */
pstmnt_word pstmnt_neg_small_inv(const pstmnt_word *a_p);

/* Convert values to montgomery format for processing modular exponentiation. */
void
pstmnt_montgomery_input(
    const pstmnt_word Input[] /* NWords */,
    PSTMNT_RESTORED pstmnt_word Prime[] /* NWords */,
    pstmnt_word TempLarge[] /* NWords * 6 */,    /* Note: differs from
                                                    pstmnt_montgomery_input. */
    pstmnt_word Target[] /* NWords */,
    pstmnt_words NWords,
    pstmnt_word PrimeSmallInv);

/* Convert values back from montgomery format. */
void
pstmnt_montgomery_output(
    const pstmnt_word Input[] /* NWords */,
    pstmnt_word Output[] /* NWords */,
    const pstmnt_word Prime[] /* NWords */,
    pstmnt_word TempLarge[] /* NWords * 2 */,
    pstmnt_words NWords,
    pstmnt_word PrimeSmallInv);

/* Compute modular exponentiation with values in montgomery format.
   The modular exponentiation attempts to use constant time amthematical
   operations. */
void
pstmnt_mod_exp_montgomery_skip(
    const pstmnt_word a[],
    const pstmnt_word x[],
    pstmnt_word r[],
    const pstmnt_word start_bit,
    const pstmnt_word bits,
    const pstmnt_word m[],
    pstmnt_word temp[] /* len * 4 */,
    pstmnt_word mp,
    pstmnt_words len);

# endif /* INCLUDE_GUARD_PSTMNT_H */

#endif  /* USE_CONSTANT_TIME_MODEXP */

/* end of file pstmnt.h */
