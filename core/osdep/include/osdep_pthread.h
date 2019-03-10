/** osdep_pthread.h
 *
 * Wrapper for system header osdep_pthread.h
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
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

/* This file just includes system header pthread.h.
   In case your system does not include all functions
   pthread_create/pthread_join/pthread_mutex_init/pthread_mutex_lock/pthread_mutex_unlock via that file or
   does not have implementation of pthread.h, please
   customize this place holder header.
*/

#ifndef OSDEP_PTHREAD_H_DEFINED
#define OSDEP_PTHREAD_H_DEFINED 1
#ifdef __ARMCC5
/* pthread.h may use __leaf__ attribute which ARMCC does not recognize. */
#pragma push
#pragma diag_suppress 1207
#endif /* __ARMCC5 */

#include <pthread.h>

#ifdef __ARMCC5
#pragma pop /* restore diagnostics messages settings. */
#endif /* __ARMCC5 */


/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

/* Macro that provides Pthread_create, which is macro wrapper for pthread_create. */
#ifndef Pthread_create
#define Pthread_create pthread_create
#endif /* Pthread_create */

/* Macro that provides Pthread_join, which is macro wrapper for pthread_join. */
#ifndef Pthread_join
#define Pthread_join pthread_join
#endif /* Pthread_join */

/* Macro that provides Pthread_mutex_init, which is macro wrapper for pthread_mutex_init. */
#ifndef Pthread_mutex_init
#define Pthread_mutex_init pthread_mutex_init
#endif /* Pthread_mutex_init */

/* Macro that provides Pthread_mutex_lock, which is macro wrapper for pthread_mutex_lock. */
#ifndef Pthread_mutex_lock
#define Pthread_mutex_lock pthread_mutex_lock
#endif /* Pthread_mutex_lock */

/* Macro that provides Pthread_mutex_unlock, which is macro wrapper for pthread_mutex_unlock. */
#ifndef Pthread_mutex_unlock
#define Pthread_mutex_unlock pthread_mutex_unlock
#endif /* Pthread_mutex_unlock */

#endif /* OSDEP_PTHREAD_H_DEFINED */
