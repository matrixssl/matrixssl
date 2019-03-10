/* psprintf.h
 *
 * Description: Interface for formatted printing functions.
 */

/*****************************************************************************
* Copyright (c) 2007-2018 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef INCLUDE_GUARD_PSPRINTF_H
#define INCLUDE_GUARD_PSPRINTF_H 1

#include "coreApi.h"

struct arg
{
    char ch; /* Current character. */
    /* Flags. */
    unsigned char padz;
    unsigned char altform;
    unsigned char upper;
    /* Field formatting. */
    long min;
    long max;
    /* Output count. */
    size_t count;
    /* Formatting control. */
    void (*do_putc)(struct arg *);
    void *context;
    const char *fmt;
};

void psVprintf(struct arg *arg, const char *fmt, va_list va);

#endif /* INCLUDE_GUARD_PSPRINTF_H */

/* end of file psprintf.h */
