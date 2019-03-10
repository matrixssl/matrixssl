/* sfzclincludes.h
 */

/*****************************************************************************
* Copyright (c) 2002-2016 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef SFZCLINCLUDES_H
#define SFZCLINCLUDES_H

#include "cfg_pkcslib.h"
#include "public_defs.h"
#include "c_lib.h"
#include "spal_mutex.h"
#include "spal_memory.h"
#include "spal_semaphore.h"
#include "spal_result.h"
#include "sfzclmalloc.h"
#include "sfzclsnprintf.h"
#include "sfzcltime.h"
#include "sfzclsnprintf.h"

/* The amount of static memory for MP ints. */
#define SFZCL_MP_INTEGER_BIT_SIZE_STATIC 0

#if defined( WIN32)
/* Windows API */
# ifndef SFZCLDIST_FREESTANDING
#  include "osdep_windows.h"
#  include "osdep_winbase.h"
#  include "osdep_fcntl.h"
# endif                         /* !SFZCLDIST_FREESTANDING */

# define SIZEOF_SHORT        2
# define SIZEOF_INT          4
# define SIZEOF_LONG         4  /* WIN64 uses LLP64 convention. */
# define SFZCLUINT64_IS_64BITS
# define SFZCL_C64(x) (x)

#else
/* Other platform. */

# ifndef SFZCLDIST_FREESTANDING
#  include "osdep_stdlib.h"
#  include "osdep_ctype.h"
#  include "osdep_sys_time.h"
#  include "osdep_string.h"
#  include "osdep_stdio.h"
# endif                         /* !SFZCLDIST_FREESTANDING */

# ifndef SIZEOF_SHORT
#  define SIZEOF_SHORT        2
# endif /* SIZEOF_SHORT */
# ifndef SIZEOF_INT
#  define SIZEOF_INT          4
# endif /* SIZEOF_INT */
# ifndef SIZEOF_LONG
#  define SIZEOF_LONG         8
# endif /* SIZEOF_LONG */

#endif                          /* WIN32 */

#define COMPILE_SFZCL_SIZE_GLOBAL_ASSERT(condition)         \
    extern int sfzl_size_global_assert[1 - 2 * (!(condition))]

COMPILE_SFZCL_SIZE_GLOBAL_ASSERT(SIZEOF_SHORT == sizeof(short));
COMPILE_SFZCL_SIZE_GLOBAL_ASSERT(SIZEOF_INT == sizeof(int));
COMPILE_SFZCL_SIZE_GLOBAL_ASSERT(SIZEOF_LONG == sizeof(long));

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

/* Defines related to segmented memory architectures. */
#ifndef NULL_FNPTR
# define NULL_FNPTR  NULL
#else
# define HAVE_SEGMENTED_MEMORY  1
#endif

#ifdef SFZCLDIST_FREESTANDING
/* Provide emulation of is* (ctype.h) operations required by CertLib */

# undef isdigit
# define Isdigit(x) ((x) >= '0' && (x) <= '9')

# undef isalpha
# define Isalpha(x) (((x) | 32) >= 'a' && ((x) | 32) <= 'z')

# undef isxalpha
# define Isxalpha(x) (((x) | 32) >= 'a' && ((x) | 32) <= 'f')

# undef isxdigit
# define Isxdigit(x) (Isdigit(x) || Isxalpha(x))

# undef isspace
# define Isspace(x) ((x) <= 32 && ((x) == 32 || (x) == '\f' || (x) == '\n' || \
                                   (x) == '\r' || (x) == '\t' || (x) == '\v'))

#endif                          /* SFZCLDIST_FREESTANDING */

#endif                          /* SFZCLINCLUDES_H */
