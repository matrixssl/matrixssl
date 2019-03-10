/* cfg_spal.h
 *
 * Description: SPAL configuration constants.
 */

/*****************************************************************************
* Copyright (c) 2007-2016 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef INCLUSION_GUARD_CFG_SPAL_H
#define INCLUSION_GUARD_CFG_SPAL_H

/* These are configuration constants for SPAL.
   The values have been tested with 32-bit and 64-bit Linux environments.
   Depending on target OS values may have to be adjusted. */

#if defined(__x86_64__) || defined(__aarch64__)
/* For 64-bit environments: use wider pthread type. */
# define SPAL_CFG_THREAD_TYPE long int
#endif

#if defined(__x86_64__) || defined(__aarch64__)
/* For 64 bit environments: try doubling the storage size. */
# if defined (__APPLE__)
#  define SPAL_CFG_MUTEX_SIZE 128
# else
#  define SPAL_CFG_MUTEX_SIZE 64
# endif /* APPLE */
# define SPAL_CFG_MUTEX_ALIGN_TYPE long int
#else
# ifdef WIN32
/* This value is needed by the Win32 build */
#  define SPAL_CFG_MUTEX_SIZE 36
# else
/* These value are large enough for encountered 32-bit linux variants. */
#  define SPAL_CFG_MUTEX_SIZE 28
# endif
# define SPAL_CFG_MUTEX_ALIGN_TYPE long int
#endif


#if defined(__x86_64__) || defined(__aarch64__)
/* For 64 bit environments: try doubling the storage size. */
# define SPAL_CFG_SEMAPHORE_SIZE       40
# define SPAL_CFG_SEMAPHORE_ALIGN_TYPE void *
#else
/* These value are large enough for encountered 32-bit linux variants. */
# define SPAL_CFG_SEMAPHORE_SIZE       20
# define SPAL_CFG_SEMAPHORE_ALIGN_TYPE void *
#endif

#endif /* Include Guard */

/* end of file cfg_spal.h */
