/** osdep_malloc.h
 *
 * Wrapper for system header osdep_malloc.h
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

/* This file just includes system header malloc.h.
   In case your system does not include all functions
   malloc/free/calloc/realloc via that file or
   does not have implementation of malloc.h, please
   customize this place holder header.
*/

#ifndef OSDEP_MALLOC_H_DEFINED
#define OSDEP_MALLOC_H_DEFINED 1


#include <malloc.h>

/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

/* Macro that provides Malloc, which is macro wrapper for malloc. */
#ifndef Malloc
#define Malloc malloc
#endif /* Malloc */

/* Macro that provides Free, which is macro wrapper for free. */
#ifndef Free
#define Free free
#endif /* Free */

/* Macro that provides Calloc, which is macro wrapper for calloc. */
#ifndef Calloc
#define Calloc calloc
#endif /* Calloc */

/* Macro that provides Realloc, which is macro wrapper for realloc. */
#ifndef Realloc
#define Realloc realloc
#endif /* Realloc */



#endif /* OSDEP_MALLOC_H_DEFINED */
