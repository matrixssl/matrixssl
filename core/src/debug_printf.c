/* debug_printf.c
 *
 * Description: Implementation of DEBUG_printf.
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

#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 1 /* Depends on POSIX.1-2001 (file I/O locking) */
#endif /* _POSIX_C_SOURCE */

#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE /* Needs fputc_unlocked  */
#endif /* _DEFAULT_SOURCE */

#include "implementation_defs.h"

#ifdef IMPLDEFS_NEED_DEBUG_PRINTF

#include "osdep_stdarg.h"
#include "osdep_stddef.h"
#include "osdep_stdio.h"
#include "osdep_stdlib.h" /* For strtol. */
#include "osdep_limits.h" /* For strtol. */
#include "coreApi.h"
#include "psprintf.h"

#ifdef DEBUG_CF_USE_STDOUT
# define DEBUG_fd  stdout
#else
# define DEBUG_fd  stderr
#endif

static
void SZ_putc(struct arg *arg)
{
    fputc_unlocked(arg->ch, DEBUG_fd);
}

int DEBUG_printf(const char *format, ...)
{
    struct arg arg;
    va_list ap;

    va_start(ap, format);

    arg.do_putc = &SZ_putc;
    arg.count = 0;
    (void) flockfile(DEBUG_fd);
    (void) psVprintf(&arg, format, ap);

#ifdef DEBUG_CF_USE_FLUSH
    (void) fflush_unlocked(DEBUG_fd);
#endif
    (void) funlockfile(DEBUG_fd);

    va_end(ap);

    return 0;
}

#else /* IMPLDEFS_NEED_DEBUG_PRINTF */

/* DEBUG_printf() has been deprecated. */
extern int DEBUG_printf_not_available;

#endif /* IMPLDEFS_NEED_DEBUG_PRINTF */

/* end of file debug_printf.c */
