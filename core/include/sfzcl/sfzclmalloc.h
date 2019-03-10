/* sfzclmalloc.h

   Versions of malloc and friends that check their results, and never return
   failure (they call fatal if they encounter an error).

   These functions MUST be multi thread safe, if the system is using threads.
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

#ifndef SFZCLMALLOC_H
#define SFZCLMALLOC_H

#include "public_defs.h"

#ifdef __cplusplus
extern "C"
{
#endif

void *sfzcl_strdup(const void *str);

void *sfzcl_memdup(const void *data, size_t len);

void *sfzcl_realloc(void *ptr, size_t old_size, size_t new_size);

#ifdef __cplusplus
}
#endif

#endif                          /* SFZCLMALLOC_H */
