/* sfzclbuffer.h

   Description:
        Code for manipulating variable-size buffers where you can
        easily append data and consume it from either end. Routines
        with prefix sfzcl_xbuffer will call sfzcl_fatal (thus not
        returning) if they fail to obtain memory.
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

#ifndef SFZCLBUFFER_H
#define SFZCLBUFFER_H

typedef enum
{
    SFZCL_BUFFER_OK = 0,
    SFZCL_BUFFER_ERROR
} SfzclBufferStatus;

/* This is buffer record. Even if its contents are visible here, one
   should use the function interface to access them. The content is
   visible here only to allow allocation from the stack. */
typedef struct SfzclBufferRec
{
    unsigned char *buf;         /* SfzclBuffer for data. */
    size_t offset;              /* Offset of first byte containing data. */
    size_t end;                 /* Offset of last byte containing data. */
    size_t alloc;               /* Number of bytes allocated for data. */
    /* The `dynamic' flag tells whether or not this struct is allocated
       by a call to `SPAL_Memory_Alloc', in which case `dynamic' is TRUE, or
       whether this struct is allocated from stack, in a global
       variable, or inside another heap-allocated object, in which case
       the `dynamic' flag is FALSE.  It is used as a sanity check. */
    bool dynamic;
    /* The `borrowed' flag is TRUE if and only if the `buf' is memory
       managed by this struct.  This is the default, but it is possible to
       use `sfzcl_buffer_wrap' to wrap a SfzclBuffer around given memory, in
       which case we shall not resize the buf. */
    bool borrowed;
    uint16_t size_index;        /* Index to a table giving the size of the
                                   buffer in bytes. */
} *SfzclBuffer, SfzclBufferStruct;

/* Allocates and initializes a new buffer structure. */

SfzclBuffer sfzcl_buffer_allocate(void);
/* Zeroes and frees any memory used by the buffer and its data structures. */

void sfzcl_buffer_free(SfzclBuffer buffer);

/* Initializes an already allocated buffer structure. */

void sfzcl_buffer_init(SfzclBuffer buffer);

/* Frees any memory used by the buffer, first zeroing the whole area.
   The buffer structure itself is not freed. */

void sfzcl_buffer_uninit(SfzclBuffer buffer);

/* Wrap a given memory area `mem' of length `n_bytes' inside the given
   SfzclBuffer `buf'.  The `buffer' is assumed uninited. */

void sfzcl_buffer_wrap(SfzclBuffer buffer, unsigned char *mem, size_t n_bytes);

/* This function steal the data from buffer to caller. It moves the
   buffer's content to the beginning of the allocated memory, realloc
   it to the current size, and leave the buffer in an uninited
   state. Fill in the returned buffer size into 'len' if it not a NULL
   pointer. */

unsigned char *sfzcl_buffer_steal(SfzclBuffer buffer, size_t *len);

/* Clears any data from the buffer, making it empty.  This does not
   zero the memory.  This does not free the memory used by the buffer. */

void sfzcl_buffer_clear(SfzclBuffer buffer);

/* Appends data to the buffer, expanding it if necessary. */

SfzclBufferStatus sfzcl_buffer_append(SfzclBuffer buffer,
                                      const unsigned char *data, size_t len);
/* Appends space to the buffer, expanding the buffer if necessary.
   This does not actually copy the data into the buffer, but instead
   returns a pointer to the allocated region. */

SfzclBufferStatus sfzcl_buffer_append_space(SfzclBuffer buffer,
                                            unsigned char **datap, size_t len);
/* Appends NUL-terminated C-strings <...> to the buffer.  The argument
   list must be terminated with a NULL pointer. */

SfzclBufferStatus sfzcl_buffer_append_cstrs(SfzclBuffer buffer, ...);
#ifndef SFZCLDIST_SCM_ALIEN_RUN
SfzclBufferStatus sfzcl_buffer_append_cstrs_va(SfzclBuffer buffer, va_list ap);
#endif                          /* SFZCLDIST_SCM_ALIEN_RUN */

/* Returns the number of bytes of data in the buffer. */

size_t sfzcl_buffer_len(const SfzclBuffer buffer);

/* Returns the number of bytes allocated, but not yet in use. */

size_t sfzcl_buffer_space(const SfzclBuffer buffer);

/* Consumes the given number of bytes from the beginning of the buffer. */

SfzclBufferStatus sfzcl_buffer_consume(SfzclBuffer buffer, size_t bytes);

/* Consumes the given number of bytes from the end of the buffer. */

SfzclBufferStatus sfzcl_buffer_consume_end(SfzclBuffer buffer, size_t bytes);

/* Returns a pointer to the first used byte in the buffer. */

unsigned char *sfzcl_buffer_ptr(const SfzclBuffer buffer);

#endif                          /* SFZCLBUFFER_H */
