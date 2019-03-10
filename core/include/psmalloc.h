/**
 *      @file    psmalloc.h
 *      @version $Format:%h%d$
 *
 *      Header for psMalloc functions.
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

#ifndef _h_PS_MALLOC
# define _h_PS_MALLOC

/******************************************************************************/
/*
 */
# ifdef PS_UNSUPPORTED_OS
#  include "matrixos.h"
# else
/******************************************************************************/
/*
 */

#  define MATRIX_NO_POOL      (void *) 0x0

/* Introduce variables used for memory pooling, so that the compiler does not
   give spurious warnings even when memory pools are not supported by the
   target operating system. */
#  define PS_POOL_USED(poolVar) PS_VARIABLE_SET_BUT_UNUSED(poolVar)

/******************************************************************************/
/*
    Native memory routines
 */
#   include "osdep_stdlib.h"

#   define MAX_MEMORY_USAGE    0
#   define psOpenMalloc()      0
#   define psCloseMalloc()
#   define psDefineHeap(A, B)
#   define psAddPoolCache(A, B)
#   define psMalloc(A, B)      Malloc(B)
#   define psCalloc(A, B, C)   Calloc(B, C)
#   define psMallocNoPool      Malloc
#   define psRealloc(A, B, C)  Realloc(A, B)
#   define psFree(A, B)        Free(A)
#   define psFreeNoPool        Free

#ifndef PS_POOL_T_DEFINED
#define PS_POOL_T_DEFINED
typedef int32 psPool_t;
#endif

/* Functions without pool: Add N to the name, omit pool. */
#  define psCallocN(B, C) psCalloc(MATRIX_NO_POOL, (B), (C))
#  define psZallocN(B)    psCalloc(MATRIX_NO_POOL, (B), 1)
#  define psMallocN(B) psMalloc(MATRIX_NO_POOL, (B))

/* See psUtil.h for psFreeN, psFreeFRR etc. helper functions. */

/******************************************************************************/

# endif /* !PS_UNSUPPORTED_OS */
#endif  /* _h_PS_MALLOC */
/******************************************************************************/

