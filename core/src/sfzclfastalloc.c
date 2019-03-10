/* sfzclfastalloc.c
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

#include "sfzclincludes.h"
#include "sfzclfastalloc.h"
#include "implementation_defs.h"

#define SFZCL_DEBUG_MODULE "SfzclFastalloc"

/* This routine works also when a->free_chain != NULL. This is necessary for
   `sfzcl_fastalloc_reserve'. */
static bool
make_more_blobs(SfzclFastMemoryAllocator a)
{
    SfzclFastallocBlobs *newp;

    newp = SPAL_Memory_Alloc(sizeof(*newp));

    /* Check the return value. */
    if (newp == NULL)
    {
        return FALSE;
    }

    newp->blobs = SPAL_Memory_Alloc(a->blob_quant * a->blob_size);

    /* Check the return value. */
    if (newp->blobs == NULL)
    {
        SPAL_Memory_Free(newp);
        return FALSE;
    }

    newp->next = a->blobs;
    a->blobs = newp;
    a->total_size += a->blob_quant;

    /* Add the new blobs to the chain of free blobs. */
    {
        unsigned char *ptr = newp->blobs;
        unsigned char *end = ptr + a->blob_size * (a->blob_quant - 1);
        int step = a->blob_size;

        while (ptr < end)
        {
            ((SfzclFastallocProtoBlob *) ptr)->free_chain = (ptr + step);
            ptr += step;
        }
        ((SfzclFastallocProtoBlob *) ptr)->free_chain = a->free_chain;
        a->free_chain = newp->blobs;
    }

    return TRUE;
}

static void *
get_blob(SfzclFastMemoryAllocator a)
{
    void *r;

    if (a->free_chain == NULL)
    {
        if (!make_more_blobs(a))
        {
            return NULL;
        }
    }

    r = a->free_chain;
    a->free_chain = a->free_chain->free_chain;
    a->allocated++;
    return r;
}

static void
release_blob(SfzclFastMemoryAllocator a, void *ptr)
{
    ((SfzclFastallocProtoBlob *) ptr)->free_chain = a->free_chain;
    a->free_chain = (SfzclFastallocProtoBlob *) ptr;
    a->allocated--;
    ASSERT(a->allocated >= 0);
}

SfzclFastMemoryAllocator
sfzcl_fastalloc_initialize(int blob_size, int blob_quant)
{
    SfzclFastMemoryAllocator newp;

    ASSERT(blob_size > 0);
    ASSERT(blob_quant > 0);

    /* Ensure correct alignment: round the `blob_size' up to be a
       multiple of sizeof(void *). */
    if (blob_size % sizeof(void *))
    {
        blob_size += sizeof(void *) - (blob_size % sizeof(void *));
    }

    if ((newp = SPAL_Memory_Alloc(sizeof(*newp))) == NULL)
    {
        return NULL;
    }

    newp->blob_size = blob_size;
    newp->blob_quant = blob_quant;
    newp->allocated = 0;
    newp->total_size = 0;
    newp->blobs = NULL;
    newp->free_chain = NULL;
    return newp;
}

void
sfzcl_fastalloc_uninitialize(SfzclFastMemoryAllocator a)
{
    if (a->allocated > 0)
    {
        L_DEBUG(LF_CERTLIB,
            "%d blobs not freed in sfzcl_fastalloc_uninitialize",
            a->allocated);
        return;
    }

    while (a->blobs != NULL)
    {
        SfzclFastallocBlobs *b = a->blobs;
        a->blobs = a->blobs->next;
        SPAL_Memory_Free(b->blobs);
        SPAL_Memory_Free(b);
    }

    SPAL_Memory_Free(a);
}

void *
sfzcl_fastalloc_alloc(SfzclFastMemoryAllocator a)
{
    return get_blob(a);
}

void
sfzcl_fastalloc_free(SfzclFastMemoryAllocator a, void *ptr)
{
    release_blob(a, ptr);
}

/* end of file sfzclfastalloc.c */
