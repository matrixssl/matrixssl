/* sfzcldsprintf.h
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

#ifndef SFZCLDSPRINTF_H
#define SFZCLDSPRINTF_H

/* This function is similar to Snprintf (indeed, this function, too,
   uses vsnprintf()); it takes a format argument which specifies the
   subsequent arguments, and writes them to a string using the
   format-string. This function differs from snprintf in that this
   allocates the buffer itself, and returns a pointer to the allocated
   string (in str). This function never fails.  (if there is not
   enough memory, sfzcl_xrealloc() calls sfzcl_fatal())

   The returned string must be freed by the caller. Returns the number
   of characters written.  */
int sfzcl_dsprintf(char **str, const char *format, ...);
int sfzcl_dvsprintf(char **str, const char *format, va_list ap);

#endif                          /* SFZCLDSPRINTF_H */
