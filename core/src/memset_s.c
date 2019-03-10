/**
 *      @file    memset_s.c
 *      @version $Format:%h%d$
 *
 *      Secure memset api that will not be optimized out by compiler.
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
/**
    Implementation of C11 API for platforms that do not have it.

    In contrast to the Memset(3) function, calls to memset_s() will never be
    "optimised away" by a compiler.  This property is required by the follow-
    ing sentences in section K.3.7.4.1 of ISO/IEC 9899:2011 ("ISO C11"):
        Unlike Memset(), any call to the memset_s() function shall be  evalu-
        ated  strictly  according  to  the  rules  of the abstract machine as
        described in (5.1.2.3).  That is, any call to the memset_s() function
        shall  assume  that the memory indicated by s and n may be accessible
        in the future and thus must contain the values indicated by c.

    On Mac OS X, this api is natively implemented.
    On Windows, this api is mapped to SecureZeroMemory()
 */
#define __STDC_WANT_LIB_EXT1__ 1 /* Request C11 secure memory set API. */
#include "osdep_string.h"
#include "osdep_errno.h"
#include "osdep.h"

/* Only define memset_s if it is not a macro. */
#ifndef memset_s

void
SLSodium_memset_s_int(void *const pnt, unsigned char uch, const size_t len);

/* The operating environment has no memset_s. */
#ifndef _STDC_LIB_EXT1__
errno_t memset_s(void *s, rsize_t smax, int c, rsize_t n)
{
    if (n > smax)
    {
        n = smax;
    }
    
    (void) SLSodium_memset_s_int(s, (unsigned char)c, (rsize_t) n);
    return ((unsigned char volatile *) s)[0];
}
#endif /* _STDC_LIB_EXT1__ */

#endif /* memset_s */

/******************************************************************************/
