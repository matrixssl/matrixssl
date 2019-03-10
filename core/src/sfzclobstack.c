/* sfzclobstack.c
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
   Memory allocation from a context. These routines allocate data to a
   context, to be freed by one call to sfzcl_obstack_free. There is no
   other way of freeing data, than freeing it all. */

#include "sfzclincludes.h"
#include "sfzclobstack.h"
#include "implementation_defs.h"
#ifdef SFZCL_DEBUG_MALLOC
# ifndef SFZCL_DEBUG_MALLOC_HEAVY
#  define SFZCL_DEBUG_MALLOC_HEAVY
# endif                         /* not SFZCL_DEBUG_MALLOC_HEAVY */
#endif                          /* SFZCL_DEBUG_MALLOC */

#define SFZCL_DEBUG_MODULE "SfzclObstack"

/* The obstack entries in the first list are in the order of space available.
   The first entry has most available space in it. When we allocate something
   from it, it will be moved forward in the list until it reaches its own
   place. */
typedef struct SfzclObStackDataRec
{
    struct SfzclObStackDataRec *next;
    unsigned char *ptr;
    size_t free_bytes;
    size_t alloc_bytes;
} *SfzclObStackData, SfzclObStackDataStruct;

/* Main context for all allocated data through obstack. */

typedef struct SfzclObStackContextRec
{
    SfzclObStackData first;
    size_t current_alloc_size;
    size_t memory_allocated;
    size_t memory_used;
    size_t memory_limit;
    SfzclObStackDataStruct internal_first;
} SfzclObStackContextStruct;

/* Initialize the obstack context. Clear all buckets. */
SfzclObStackContext
sfzcl_obstack_create(SfzclObStackConf config)
{
    SfzclObStackContext created;
    size_t prealloc;

    prealloc = ((config != NULL) ? config->prealloc_size : 4000);
    prealloc += sizeof(SfzclObStackContextStruct);

    if (config != NULL && config->max_size != 0 && prealloc > config->max_size)
    {
        L_DEBUG(LF_CERTLIB,
            "prealloc_size + sizeof(SfzclObStackContextStruct) "
            "is larger than max_size allowed for the object");
        return NULL;
    }
    if ((created = SPAL_Memory_Alloc(prealloc)) != NULL)
    {
        created->current_alloc_size = 4096;
        created->first = &created->internal_first;
        created->first->next = NULL;
        created->first->ptr = (void *) &(created[1]);
        created->first->free_bytes = ((unsigned char *) created + prealloc) -
                                     created->first->ptr;
        created->first->alloc_bytes = created->first->free_bytes;
        created->memory_limit = ((config != NULL) ? config->max_size : 0);
        created->memory_allocated = prealloc;
        created->memory_used = sizeof(SfzclObStackContextStruct);
    }
    return created;
}

void
sfzcl_obstack_clear(SfzclObStackContext context)
{
    SfzclObStackData temp, next;

    temp = context->first;
    while (temp != NULL)
    {
        next = temp->next;
        if (temp != &context->internal_first)
        {
            SPAL_Memory_Free(temp);
        }
        temp = next;
    }
    context->current_alloc_size = 4096;
    context->first = &context->internal_first;
    context->first->next = NULL;
    context->first->ptr = (void *) &(context[1]);
    context->first->free_bytes = context->first->alloc_bytes;
    context->memory_allocated = context->first->free_bytes +
                                sizeof(SfzclObStackContextStruct);
    context->memory_used = sizeof(SfzclObStackContextStruct);
#ifdef SFZCL_DEBUG_MALLOC_HEAVY
    Memset(context->first->ptr, 'F', context->first->free_bytes);
#endif                          /* SFZCL_DEBUG_MALLOC_HEAVY */
}

void
sfzcl_obstack_destroy(SfzclObStackContext context)
{
    sfzcl_obstack_clear(context);

    /* Free the context also. */
    SPAL_Memory_Free(context);
}

static unsigned char *
sfzcl_obstack_internal(SfzclObStackContext context, size_t size, size_t align)
{
    unsigned char *ptr;
    SfzclObStackData data, prev, next;
    size_t alignment;

    if (size == 0)
    {
        L_DEBUG(LF_CERTLIB, "Tried to allocate ZERO bytes");
        return NULL;
    }

    /* Find the item where we can fit the data in. */
    prev = NULL;
    data = NULL;
    next = context->first;
    while (next != NULL)
    {
        /* Compute extra alignment needed */
        alignment = (unsigned long) (next->ptr) & (align - 1);
        if (alignment != 0)
        {
            alignment = align - alignment;
        }
        /* Does not fit, so it must be put to the previous block. */
        if (next->free_bytes < size + alignment)
        {
            break;
        }
        prev = data;
        data = next;
        next = data->next;
    }

    /* Ok, check if we have buffer. */
    if (data == NULL)
    {
        /* Didn't fit to any buffer, allocate new buffer and put in the
           begining of the list. */

        /* If the size we want to allocate is way bigger than the
           current_alloc_size then allocate block for just this entry,
           and do not adjust the current_alloc_size. */
        if (size > context->current_alloc_size * 4)
        {
            size_t len;

            len = size + align - 1;
            if (len % 8 != 0)
            {
                len += (8 - (len % 8));
            }
            if (context->memory_limit != 0 &&
                sizeof(SfzclObStackDataStruct) + len + context->memory_allocated
                > context->memory_limit)
            {
                return NULL;
            }
            data = SPAL_Memory_Alloc(sizeof(SfzclObStackDataStruct) + len);
            if (data == NULL)
            {
                return NULL;
            }
            context->memory_allocated += sizeof(SfzclObStackDataStruct) + len;
            context->memory_used += sizeof(SfzclObStackDataStruct);
            data->next = NULL;
            data->ptr = (void *) &(data[1]);
            data->free_bytes = len;
            data->alloc_bytes = len;
        }
        else
        {
            size_t len;

            len = context->current_alloc_size;
            len += (len >> 1);
            while (size + align > len)
            {
                len += (len >> 1);
            }
            if (context->memory_limit != 0 &&
                sizeof(SfzclObStackDataStruct) + len + context->memory_allocated
                > context->memory_limit)
            {
                if (sizeof(SfzclObStackDataStruct) + size + align +
                    context->memory_allocated > context->memory_limit)
                {
                    return NULL;
                }
                len = size + align;
            }
            data = SPAL_Memory_Alloc(sizeof(SfzclObStackDataStruct) + len);
            if (data == NULL)
            {
                return NULL;
            }
            context->current_alloc_size = len;
            context->memory_allocated += sizeof(SfzclObStackDataStruct) + len;
            context->memory_used += sizeof(SfzclObStackDataStruct);
            data->next = NULL;
            data->ptr = (void *) &(data[1]);
            data->free_bytes = len;
            data->alloc_bytes = len;
        }
        /* Add it to the beginning of the list. */
        data->next = next;
        context->first = data;
    }

    /* Ok, now we have block that can take the current blob to be allocated. */

    /* Adjust the alignment for pointer. */
    alignment = (unsigned long) (data->ptr) & (align - 1);
    if (alignment != 0)
    {
        alignment = align - alignment;
    }
    data->ptr += alignment;
    ASSERT(data->free_bytes >= alignment);
    data->free_bytes -= alignment;
    context->memory_used += alignment;

    /* Allocate object. */
    ptr = data->ptr;
    data->ptr += size;
    ASSERT(data->free_bytes >= size);
    data->free_bytes -= size;
    context->memory_used += size;

    /* Move the object forward. */
    for (next = data;
         next->next != NULL && next->next->free_bytes > data->free_bytes;
         next = next->next)
    {
        ;
    }
    if (data != next)
    {
        /* Remove it from the old place. */
        if (prev == NULL)
        {
            context->first = data->next;
        }
        else
        {
            prev->next = data->next;
        }

        /* Add it after next. */
        data->next = next->next;
        next->next = data;
    }
    for (next = context->first; next->next != NULL; next = next->next)
    {
        ASSERT(next->free_bytes >= next->next->free_bytes);
    }
    return ptr;
}

unsigned char *
sfzcl_obstack_alloc_unaligned(SfzclObStackContext context, size_t size)
{
    return sfzcl_obstack_internal(context, size, 1);
}

void *
sfzcl_obstack_alloc(SfzclObStackContext context, size_t size)
{
    return (void *) sfzcl_obstack_internal(context, size, size >= 8 ? 8 :
        (size >= 4 ? 4 :
         (size >= 2 ? 2 : 1)));
}

/* end of file sfzclobstack.c */
