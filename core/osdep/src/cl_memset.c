/**
 *      @file    cl_memset.c
 *      @version $Format:%h%d$
 *
 *      Secure memset api that will not be optimized out by compiler.
 */
/*
 *      Copyright (c) 2013-2016 INSIDE Secure Corporation
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

#define __STDC_WANT_LIB_EXT1__ 1 /* Request C11 secure memory set API. */
#include "osdep_string.h"

#include "cl_types_base.h"
#include "cl_basic.h"
#include "sl_chacha20poly1305ietf_config.h" /* for HAVE_WEAK_SYMBOLS */
#include "osdep.h"

#ifdef _STDC_LIB_EXT1__

/* The operating environment has memset_s. */

void CL_MemSet(void *s, CL_DataLen_t smax, int c, CL_DataLen_t n)
{
    (void) memset_s(s, (rsize_t) smax, c, (rsize_t) n);
}

#else
/* No support for memset_s() in the operating environment. */

/* Use weak symbol to prevent LTO optimizing memset away. */
# ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
SLSodium_memset_as_a_weak_symbol_to_prevent_lto(void *const  pnt,
                                                unsigned char uch,
                                                const size_t len)
{
    unsigned char *pnt_ = (unsigned char *) pnt;
    size_t         i    = (size_t) 0U;

    while (i < len)
    {
        pnt_[i++] = uch;
    }
}
# endif

void
SLSodium_memset_s_int(void *const pnt, unsigned char uch, const size_t len)
{
# if HAVE_WEAK_SYMBOLS
    SLSodium_memset_as_a_weak_symbol_to_prevent_lto(pnt, uch, len);
# else
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len)
    {
        pnt_[i++] = uch;
    }
# endif
}

void CL_MemSet(void *s, CL_DataLen_t smax, int c, CL_DataLen_t n)
{
    if (n > smax)
    {
        n = smax;
    }
    
    (void) SLSodium_memset_s_int(s, (unsigned char)c, (rsize_t) n);
}

#endif /* _STDC_LIB_EXT1__ */

/******************************************************************************/
