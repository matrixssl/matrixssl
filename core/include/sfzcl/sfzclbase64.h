/* sfzclbase64.h

    Functions to convert to and from base64 format.
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

#ifndef SFZCLBASE64_H
#define SFZCLBASE64_H

/** Convert data from base64 format to binary.

    @return
    Returns xmallocated data buffer and length in buf_len.

 */
unsigned char *sfzcl_base64_to_buf(const unsigned char *str, size_t *buf_len);

/** Remove unneeded whitespace (everything that is not in base64!).

    If len is 0, use Strlen(str) to get length of data.

    @return
    Returns new xmallocated string containing the string.

 */
unsigned char *sfzcl_base64_remove_whitespace(const unsigned char *str,
                                              size_t len);

/** Removes headers/footers (and other crud) before and after the
    base64-encoded data.

    Will not modify the contents of str.

    @param str
    Pointer to the string.

    @param len
    The length of the string.

    @param start_ret
    Starting index of the base64 data.

    @param end_ret
    Ending index of the base64 data.

    @return
    Returns TRUE if successful. In case of an error, returns FALSE.

 */
bool sfzcl_base64_remove_headers(const unsigned char *str, size_t len,
                                 size_t *start_ret, size_t *end_ret);

#endif                          /* SFZCLBASE64_H */
