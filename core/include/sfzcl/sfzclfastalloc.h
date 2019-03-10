/* sfzclfastalloc.h
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

#ifndef SFZCLFASTALLOC_H_INCLUDED
#define SFZCLFASTALLOC_H_INCLUDED

typedef struct SfzclFastMemoryAllocatorRec *SfzclFastMemoryAllocator;

/** Initialize a new memory allocator for fixed-sized blobs.
   `blob_size' is the size of the blobs. `blob_quant' is the number of
   blobs for which room will be reserved atomically. Both `blob_size'
   and `blob_quant' must be larger than zero. */
SfzclFastMemoryAllocator sfzcl_fastalloc_initialize(int blob_size,
                                                    int blob_quant);

/** Uninitialize a memory allocator. All allocated blobs must have been
   freed, otherwise sfzcl_fatal() may be triggered. */
void sfzcl_fastalloc_uninitialize(SfzclFastMemoryAllocator allocator);

/** Allocate a new blob of the size `blob_size'. The returned data is
   correctly aligned for all kinds of purposes. The data is not
   necessarily initialized.

   This can return NULL if lower-level memory allocation can. */
void *sfzcl_fastalloc_alloc(SfzclFastMemoryAllocator allocator);

/** Free an individual blob. */
void sfzcl_fastalloc_free(SfzclFastMemoryAllocator allocator, void *data);

/** You do not need to access these structures directly but the
   declarations must be public so that the macros above can work. */
typedef struct
{
    void *free_chain;
} SfzclFastallocProtoBlob;

typedef struct sfzcl_fastalloc_blobs
{
    void *blobs;
    struct sfzcl_fastalloc_blobs *next;
} SfzclFastallocBlobs;

struct SfzclFastMemoryAllocatorRec
{
    int total_size;
    int allocated;
    int blob_size;
    int blob_quant;
    SfzclFastallocBlobs *blobs;
    SfzclFastallocProtoBlob *free_chain;
};

#endif /** SFZCLFASTALLOC_H_INCLUDED */
