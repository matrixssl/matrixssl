/* sfzclbuffer.c

   Description:
        Functions for manipulating fifo buffers (that can grow if needed).
        Based on the Tatu Ylonen's implementation from 1995
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
#include "sfzclbuffer.h"
#include "sfzclmalloc.h"
#include "implementation_defs.h"

#define SFZCL_DEBUG_MODULE "SfzclBuffer"

#ifdef DEBUG_HEAVY
/* Provoke errors. */
# define SFZCL_BUFFER_MALLOC_SLOP  1
# define SFZCL_BUFFER_BASE_SIZE    2
#else
# define SFZCL_BUFFER_MALLOC_SLOP  32
# define SFZCL_BUFFER_BASE_SIZE    512
#endif

#define SFZCL_BUFFER_SIZE(x)                              \
    (SFZCL_BUFFER_BASE_SIZE * (x) - SFZCL_BUFFER_MALLOC_SLOP)

static const size_t sfzcl_buffer_size[] = {
    0,
    SFZCL_BUFFER_SIZE(1),
    SFZCL_BUFFER_SIZE(2),
    SFZCL_BUFFER_SIZE(3),
    SFZCL_BUFFER_SIZE(5),
    SFZCL_BUFFER_SIZE(8),
    SFZCL_BUFFER_SIZE(13),
    SFZCL_BUFFER_SIZE(21),
    SFZCL_BUFFER_SIZE(34),
    SFZCL_BUFFER_SIZE(55),
    SFZCL_BUFFER_SIZE(89),
    SFZCL_BUFFER_SIZE(144),
    SFZCL_BUFFER_SIZE(233),
    SFZCL_BUFFER_SIZE(377),
    SFZCL_BUFFER_SIZE(610),
    SFZCL_BUFFER_SIZE(987),
    SFZCL_BUFFER_SIZE(1597),
    SFZCL_BUFFER_SIZE(2584),
    SFZCL_BUFFER_SIZE(4181),
    SFZCL_BUFFER_SIZE(6765),
    SFZCL_BUFFER_SIZE(10946),
    SFZCL_BUFFER_SIZE(17711),
    SFZCL_BUFFER_SIZE(28657),
    SFZCL_BUFFER_SIZE(46368),
    SFZCL_BUFFER_SIZE(75025),
    SFZCL_BUFFER_SIZE(121393),
    SFZCL_BUFFER_SIZE(196418),
    SFZCL_BUFFER_SIZE(317811),
    SFZCL_BUFFER_SIZE(514229),
    SFZCL_BUFFER_SIZE(832040),
    SFZCL_BUFFER_SIZE(1346269),
    SFZCL_BUFFER_SIZE(2178309),
    SFZCL_BUFFER_SIZE(3524578),
    0xFFFFFF00UL,
    0
};

/* Allocates a new buffer. */
SfzclBuffer
sfzcl_buffer_allocate(void)
{
    SfzclBuffer buffer = SPAL_Memory_Alloc(sizeof(*buffer));

    if (buffer)
    {
        sfzcl_buffer_init(buffer);
        buffer->dynamic = TRUE;
    }
    return buffer;
}

/* Zeroes and frees the buffer. */

void
sfzcl_buffer_free(SfzclBuffer buffer)
{
    ASSERT(buffer != NULL);
    ASSERT(buffer->dynamic);

    sfzcl_buffer_uninit(buffer);
    SPAL_Memory_Free(buffer);
}

/* Initializes the buffer structure. */

void
sfzcl_buffer_init(SfzclBuffer buffer)
{
    ASSERT(buffer != NULL);

    buffer->offset = 0;
    buffer->end = 0;
    buffer->dynamic = FALSE;
    buffer->borrowed = FALSE;
    buffer->size_index = 0;
    buffer->alloc = 0;
    buffer->buf = NULL;
}

/* Frees any memory used for the buffer. */

void
sfzcl_buffer_uninit(SfzclBuffer buffer)
{
    ASSERT(buffer != NULL);

    if (buffer->buf && !buffer->borrowed)
    {
        /* memset to clear away all possible sensitive information. */
        c_memset(buffer->buf, 0, buffer->alloc);
        SPAL_Memory_Free(buffer->buf);
    }
}

/* Move the buffer's content to the beginning of the allocated memory,
   realloc it to the current size, and leave the buffer in an uninited
   state. */

unsigned char *
sfzcl_buffer_steal(SfzclBuffer buffer, size_t *len)
{
    unsigned char *buf = buffer->buf, *tmp;

    if (buf != NULL && buffer->offset > 0)
    {
        c_memmove(buf, buf + buffer->offset, buffer->end - buffer->offset);
        buffer->end -= buffer->offset;
    }

    if (!buffer->borrowed)
    {
        if ((tmp = sfzcl_realloc(buf, buffer->alloc, buffer->end)) == NULL)
        {
            SPAL_Memory_Free(buf);
            buffer->buf = NULL;
            if (len != NULL)
            {
                *len = 0;
            }
            return NULL;
        }
        buf = tmp;
    }
    if (len != NULL)
    {
        *len = (buf) ? buffer->end : 0;
    }

    sfzcl_buffer_init(buffer);
    return buf;
}

/* Clears any data from the buffer, making it empty.  This does not actually
   zero the memory. */

void
sfzcl_buffer_clear(SfzclBuffer buffer)
{
    ASSERT(buffer != NULL);

    buffer->offset = 0;
    buffer->end = 0;
}

/* Appends data to the buffer, expanding it if necessary. */

SfzclBufferStatus
sfzcl_buffer_append(SfzclBuffer buffer, const unsigned char *data, size_t len)
{
    unsigned char *cp;
    SfzclBufferStatus status = SFZCL_BUFFER_OK;

    /* argument validation */
    if (data == NULL)
    {
        return SFZCL_BUFFER_ERROR;
    }
    ASSERT(buffer != NULL);

    status = sfzcl_buffer_append_space(buffer, &cp, len);
    if (status == SFZCL_BUFFER_OK && len > 0)
    {
        c_memcpy(cp, data, len);
    }
    return status;
}

/* Appends space to the buffer, expanding the buffer if necessary.
   This does not actually copy the data into the buffer, but instead
   returns a pointer to the allocated region. */

SfzclBufferStatus
sfzcl_buffer_append_space(SfzclBuffer buffer, unsigned char **datap, size_t len)
{
    unsigned char *tmp;
    uint16_t new_size_index;

    ASSERT(buffer != NULL);

    /* Now allocate the buffer space if not done already. */
    if (buffer->buf == NULL)
    {
        ASSERT(!buffer->borrowed);

        if (buffer->alloc == 0)
        {
            buffer->size_index = 1;
            buffer->alloc = sfzcl_buffer_size[buffer->size_index];
        }
        buffer->buf = SPAL_Memory_Alloc(buffer->alloc);
        if (buffer->buf == NULL)
        {
            return SFZCL_BUFFER_ERROR;
        }
    }

    /* If the buffer is empty, start using it from the beginning. */
    if (buffer->offset == buffer->end)
    {
        buffer->offset = 0;
        buffer->end = 0;
    }

restart:
    /* If there is enough space to store all data, store it now. */
    if (buffer->end + len <= buffer->alloc)
    {
        *datap = buffer->buf + buffer->end;
        buffer->end += len;
        return SFZCL_BUFFER_OK;
    }

    /* If the buffer is quite empty, but all data is at the end, move
       the data to the beginning and retry.  Do this also if the buffer
       is borrowed, since we can't realloc it in any case. */
    if (buffer->offset > buffer->alloc / 2
        || (buffer->borrowed && buffer->offset != 0))
    {
        c_memmove(buffer->buf, buffer->buf + buffer->offset,
            buffer->end - buffer->offset);
        buffer->end -= buffer->offset;
        buffer->offset = 0;
        goto restart;
    }

    /* If the buffer is borrowed, then don't proceed, because we can
       increase the buffer size in any case, and hence we have already
       failed. */
    if (buffer->borrowed)
    {
        return SFZCL_BUFFER_ERROR;
    }

    /* Increase the size of the buffer and retry. */
    new_size_index = buffer->size_index + 1;
    while (sfzcl_buffer_size[new_size_index] != 0 &&
           sfzcl_buffer_size[new_size_index] <= buffer->end + len)
    {
        new_size_index++;
    }
    if (sfzcl_buffer_size[new_size_index] == 0)
    {
        return SFZCL_BUFFER_ERROR;
    }

    tmp = sfzcl_realloc(buffer->buf,
        buffer->alloc, sfzcl_buffer_size[new_size_index]);
    if (tmp)
    {
        buffer->buf = tmp;
        buffer->size_index = new_size_index;
        buffer->alloc = sfzcl_buffer_size[new_size_index];
        goto restart;
    }

    /* Realloc failed. */
    return SFZCL_BUFFER_ERROR;
}

/* Appends NUL-terminated C-strings <...> to the buffer.  The argument
   list must be terminated with a NULL pointer. */

SfzclBufferStatus
sfzcl_buffer_append_cstrs(SfzclBuffer buffer, ...)
{
    va_list ap;
    SfzclBufferStatus status = SFZCL_BUFFER_OK;

    va_start(ap, buffer);

    status = sfzcl_buffer_append_cstrs_va(buffer, ap);

    va_end(ap);
    return status;
}

SfzclBufferStatus
sfzcl_buffer_append_cstrs_va(SfzclBuffer buffer, va_list ap)
{
    char *str;
    SfzclBufferStatus status = SFZCL_BUFFER_OK;

    while (status == SFZCL_BUFFER_OK && (str = va_arg(ap, char *)) != NULL)
    {
        status =
            sfzcl_buffer_append(buffer, (unsigned char *) str, c_strlen(str));
    }

    return status;
}

/* Returns the number of bytes of data in the buffer. */

size_t
sfzcl_buffer_len(const SfzclBuffer buffer)
{
    ASSERT(buffer != NULL);
    ASSERT(buffer->offset <= buffer->end);

    return buffer->end - buffer->offset;
}

/* Returns the number of bytes allocated, but not yet in use. */

size_t
sfzcl_buffer_space(const SfzclBuffer buffer)
{
    ASSERT(buffer != NULL);
    ASSERT(buffer->offset <= buffer->end);
    ASSERT(buffer->end <= buffer->alloc);

    return buffer->alloc - buffer->end;
}

/* Consumes the given number of bytes from the beginning of the buffer. */

SfzclBufferStatus
sfzcl_buffer_consume(SfzclBuffer buffer, size_t bytes)
{
    if (bytes > buffer->end - buffer->offset)
    {
        L_DEBUG(LF_CERTLIB,
            "buffer_consume trying to get more bytes than in buffer");
        return SFZCL_BUFFER_ERROR;
    }
    buffer->offset += bytes;
    return SFZCL_BUFFER_OK;
}

/* Consumes the given number of bytes from the end of the buffer. */

SfzclBufferStatus
sfzcl_buffer_consume_end(SfzclBuffer buffer, size_t bytes)
{
    if (bytes > buffer->end - buffer->offset)
    {
        L_DEBUG(LF_CERTLIB,
            "buffer_consume_end trying to get more bytes than in buffer");
        return SFZCL_BUFFER_ERROR;
    }
    buffer->end -= bytes;
    return SFZCL_BUFFER_OK;
}

/* Returns a pointer to the first used byte in the buffer. */

unsigned char *
sfzcl_buffer_ptr(const SfzclBuffer buffer)
{
    ASSERT(buffer != NULL);
    ASSERT(buffer->offset <= buffer->end);

    if (buffer->buf == NULL || sfzcl_buffer_len(buffer) == 0)
    {
        return NULL;
    }

    return buffer->buf + buffer->offset;
}
