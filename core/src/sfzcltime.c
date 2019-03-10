/* sfzcltime.c
 *
 * Time retrieval (time as a counter).
 */

/*****************************************************************************
* Copyright (c) 2006-2017 INSIDE Secure Oy. All Rights Reserved.
*
* The latest version of this code is available at http://www.matrixssl.org
*
* This software is open source; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This General Public License does NOT permit incorporating this software
* into proprietary programs.  If you are unable to comply with the GPL, a
* commercial license for this software may be purchased from INSIDE at
* http://www.insidesecure.com/
*
* This program is distributed in WITHOUT ANY WARRANTY; without even the
* implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#include "sfzclincludes.h"
#include "sfzclgetput.h"
#include "osdep_time.h"

#define SFZCL_DEBUG_MODULE "SfzclTime"

#ifndef SFZCLDIST_FREESTANDING

/* Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
SfzclTime
sfzcl_time(void)
{
    return (SfzclTime) (Time(NULL));
}
#else
/* C99 Freestanding implementation. There is no time() function available.
   The customer needs to implement sfzcl_time() that determines current time
   in platform dependent way. */

/*
   Example:
   SfzclTime
   sfzcl_time (void)
   {
   return (SfzclTime) platform_dependent_get_time();
   }
 */

SfzclTime
sfzcl_time(void)
{
    /* Return static value. (2.4.2011) */
    return 1304432553;
}

#endif                          /* SFZCLDIST_FREESTANDING */

/* end of file sfzcltime.c */
