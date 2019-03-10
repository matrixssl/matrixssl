/* sfzclobstack.h
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

/*
   Mallocation to a context, with out possibility to free specific elements.
 */

#ifndef SFZCLOBSTACK_H
#define SFZCLOBSTACK_H

typedef struct SfzclObStackContextRec *SfzclObStackContext;

/** Configuration data structure for the obstack. */
typedef struct SfzclObStackConfRec
{
    size_t prealloc_size; /** Amount of memory is preallocated for the
                             obstack. This is still left allocated for
                             the obstack after clear, i.e after clear
                             this much can always be allocated before
                             failure (note, that alignment might consume
                             some amount here too). The preallocated size
                             is for actual memory allocations, i.e the
                             contexts etc used are not consumed from
                             this. The max_size must be 9 words larger
                             than prealloc_size, otherwise the alloc will
                             fail. Value 0 means no preallocation is
                             done. */
    size_t max_size;      /** Maximum size of the memory used for the
                             whole obstack. This includes all data, i.e
                             also the data header structures, and data
                             not yet returned, but already allocated.
                             When this is used, then allocations start to
                             fail. Note, that even when the first
                             allocation fails, there can still be some
                             empty areas in the obstack, i.e some smaller
                             allocations, can still succeded. Value 0
                             means there is no limit for the memory used.
                           */
} *SfzclObStackConf, SfzclObStackConfStruct;

/** Initialize the mallocation context with given configuration. The
   configuration can be NULL in which case the defaults are used (4000 bytes of
   prealloc, and no max size). The same context can be used for all data of all
   sizes. The data can only be freed by clearing the whole stack. This function
   uses memory efficient algorithm, which tries not to allocate too much data
   (best-fit, fragmentation is not problem here, as single pieces cannot be
   freed from the obstack). This means that allocating 1 byte only takes less
   than 1.005 bytes of data, thus this is optimal for allocating strings etc.

   The obstack can be preallocated to have certain amount of memory in the
   beginning and that memory is never freed by the sfzcl_obstack_clear (i.e if
   the obstack is reused it still contains the same preallocated memory).
   Obstack can also have maximum limit of memory it can consume. This maximum
   limit includes all headers and internal structures, thus the actual amount
   of memory which can be allocated from the obstack can be smaller than the
   maximum limit.

   This function returns NULL if there was an error when allocating the obstack
   (preallocation failed, or the maximum limit didn't allow enough memory for
   the preallocated buffer and headers). */

SfzclObStackContext sfzcl_obstack_create(SfzclObStackConf config);

/** Free all data allocated using this particular context and the context. This
   function makes all allocated space invalid. */

void sfzcl_obstack_destroy(SfzclObStackContext context);

/** Frees all data allocated using this obstack, but keeps the context. This
   effectively clears the obstack. If the obstack had preallocated data, then
   preallocated memory is not freed to the system, but will be returned by the
   first new allocations from the obstack. */

void sfzcl_obstack_clear(SfzclObStackContext context);

/** Allocate byte buffer of length size from the context. If enough
   memory is not available the function will return NULL. */

/** Allocated data is not aligned. */
unsigned char *sfzcl_obstack_alloc_unaligned(SfzclObStackContext context,
                                             size_t size);

/** Allocated data is aligned to 8-byte boundary or if item is less than 8 bytes
   then aligned to 4 (4-7 bytes) or 2 (2-3) byte boundary. This should be
   enough for all datatypes. */
void *sfzcl_obstack_alloc(SfzclObStackContext context, size_t size);

#endif                          /* SFZCLOBSTACK_H */
