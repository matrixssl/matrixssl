/* sfzclenum.h

   Functions for mapping keywords to numbers and vice versa.
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

#ifndef SFZCLENUM_H
#define SFZCLENUM_H

/* Array of keyword - numeric value pairs.  The array is terminated by
   an entry with NULL name. */
typedef struct
{
    const char *name;
    long code;
} *SfzclKeyword, SfzclKeywordStruct;

/* Finds the name of a keyword corresponding to the numeric value.
   Returns a pointer to a constant name string, or NULL if there is no
   keyword matching the numeric value. */
const char *sfzcl_find_keyword_name(const SfzclKeywordStruct *keywords,
                                    long code);

#endif                          /* SFZCLENUM_H */
