/* sfzclsnprintf.h

   Header file for sfzclsnprintf.c
 */

/*****************************************************************************
* Copyright (c) 2006-2016 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef SNPRINTF_H
#define SNPRINTF_H

#include "osdep_stdarg.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Type of functions that implement formatting `external' data types.
   `buf' is the buf where something should be written, `buf_size' the
   maximum number of characters that can be written. `precision' is
   either -1 or a non-negative number supplied by the user; its
   interpretation is chosen by the rendering function. `datum' is the
   actual value to render.

   The functions must return the number of characters written.

   If the renderer would have liked to write more characters than
   there was room in `buf_size', the renderer should return the value
   `buf_size' + 1 (but have written only `buf_size' characters, of
   course).

   As a relaxation, the functions ARE allowed to write the NUL byte at
   buf[buf_size], i.e. at the `buf_size'+1th character. However, this
   is not necessary and doing or doing not has no effect whatsoever.  */
typedef int (*SfzclSnprintfRenderer) (char *buf, int buf_size,
                                      int precision, void *datum);

/* Write formatted text to buffer 'str', using format string 'format'.
   Returns number of characters written, or negative if error
   occurred. Buffer's size is given in 'size'. Format string is
   understood as defined in ANSI C.

   NOTE: This does NOT work identically with BSD's snprintf.

   Integers: Ansi C says that precision specifies the minimun number
   of digits to print. BSD's version however counts the prefixes (+,
   -, ' ', '0x', '0X', octal prefix '0'...) as 'digits'.

   Also, BSD implementation does not permit padding integers to
   specified width with zeros on left (in front of the prefixes), it
   uses spaces instead, even when Ansi C only forbids padding with
   zeros on the right side of numbers.

   This version can also be extended using %@, which takes
   SfzclSnprintfRenderer argument and void *, and calls that
   SfzclSnprintfRenderer function to render the actual data.

   Additionally, some versions consider running out of space an error;
   we do not, and instead return normally; this is consistent with C99
   standard.
 */

int sfzcl_snprintf(char *str, size_t size, const char *format, ...);
int sfzcl_vsnprintf(char *str, size_t size, const char *format, va_list ap);

#ifdef __cplusplus
}
#endif

#endif                          /* SNPRINTF_H */
