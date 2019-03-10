/* spal_memory.h
 *
 * Description: Memory management routines
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

#ifndef INCLUDE_GUARD_SPAL_MEMORY_H_
#define INCLUDE_GUARD_SPAL_MEMORY_H_

#include "public_defs.h"

void *
SPAL_Memory_Alloc(
    const size_t Size);


void
SPAL_Memory_Free(
    void * const Memory_p);


void *
SPAL_Memory_Calloc(
    const size_t MemberCount,
    const size_t MemberSize);


void *
SPAL_Memory_ReAlloc(
    void * const Mem_p,
    size_t NewSize);

#endif /* Include guard */

/* end of file spal_memory.h */
