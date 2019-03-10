/**
 *      @file    pstm_str.h
 *      @version $Format:%h%d$
 *
 *      Multiprecision number implementation: debug output.
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

#include "../cryptoApi.h"
#include "pstm.h"

/* Before defining pstm_str, ensure pstm has been processed.
   In some configurations the pstm is disabled,
   which also disables pstm_str. */
#ifndef PSTM_AVAILABLE
# undef NO_PSTM_STR
# define NO_PSTM_STR
#endif /* PSTM_AVAILABLE */

#ifndef NO_PSTM_STR

/* PSTM String: A string formatted version of number in PSTM.
   PSTM string is (typically) dynamically allocated. */
typedef char *pstm_str;

/* Static PSTM String used when trying to format null pointer. */
# define PSTM_STR_NULL ((char *) pstm_str_null)

/* Static PSTM String used when memory allocation fails. */
# define PSTM_STR_MEMFAIL ((char *) pstm_str_memfail)

extern const char *pstm_str_null;
extern const char *pstm_str_memfail;

/* Construct pstm_str from pstm integer.
   Even if the function fails, the result is printable with %s.
   Failure can be observed by comparing pstm_str against
   PSTM_STR_NULL and PSTM_STR_MEMFAIL. */
pstm_str pstm_str_from(psPool_t *pool, const pstm_int *a);

/* Free pstm_str.
   It is safe to call this function with an errorneous pstm_str, i.e.
   PSTM_STR_NULL or PSTM_STR_MEMFAIL. */
void pstm_str_free(psPool_t *pool, pstm_str str);

#endif /* NO_PSTM_STR */

