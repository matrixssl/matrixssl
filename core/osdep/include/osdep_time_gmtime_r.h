/** osdep_time_gmtime_r.h
 *
 * Wrapper for system header osdep_time_gmtime_r.h
 */

/*****************************************************************************
* Copyright (c) 2017-2018 INSIDE Secure Oy. All Rights Reserved.
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

/* This file is extension of osdep_time.h, intended to be used when
   the caller would like to call function gmtime_r().

   This function is unfortunately not available on all operating systems.
*/

#ifndef OSDEP_TIME_GMTIME_R_H_DEFINED
#define OSDEP_TIME_GMTIME_R_H_DEFINED 1

#include "osdep_time.h"

/* On most unix like Unix-like devices gmtime_r() is available.
   Detect its availability by including osdep_unistd.h. */

#if defined __unix__ || defined __unix || (defined (__APPLE__) && defined (__MACH__))
# include "osdep_unistd.h" /* Possibly provides _POSIX_VERSION. */
#endif /* __unix__ */

#if defined _POSIX_VERSION && !defined NO_GMTIME_R
# define USE_GMTIME_R /* On posix systems, we use gmtime_r() */
#endif /* _POSIX_VERSION && !defined NO_GMTIME_R */

#ifdef USE_GMTIME_R

/* Macro that provides Gmtime_r, which is macro wrapper for gmtime_r. */
#ifndef Gmtime_r
#define Gmtime_r gmtime_r
#endif /* Gmtime_r */

#endif

#endif /* OSDEP_TIME_GMTIME_R_H_DEFINED */
