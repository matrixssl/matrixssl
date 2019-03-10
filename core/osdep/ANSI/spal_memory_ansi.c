/* spal_memory_ansi.c
 *
 * Description: Memory management APIs
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

#include "spal_memory.h"
#include "implementation_defs.h"
#include "c_lib.h"
#include "osdep_stdlib.h"

#ifdef HEAP_MEASUREMENT

# include "sfzutf.h"

/* Define variables for heap measurement. */
bool heap_measurement_started;
size_t current_heap_usage;
size_t measured_heap_usage;

# define HEAP_HDR_SIZE(size) ((size) + sizeof(HeapHdrStruct))
# define HEAP_HDR(ptr)  \
    ((HeapHdr) (((unsigned char *) ptr) - sizeof(HeapHdrStruct)))
# define HEAP_SIGN(hdr) (hdr)->signature = 0xdededede;
# define HEAP_VERIFY(hdr) ((hdr)->signature == 0xdededede)

typedef struct HeapHdrRec
{
    uint32_t signature;
    size_t size;        /* The size of the block. */
    void *self_ptr_for_valgrind;
} *HeapHdr, HeapHdrStruct;

#endif



void *
SPAL_Memory_Alloc(
    const size_t Size)
{
#ifdef HEAP_MEASUREMENT
    HeapHdr hdr;
#endif

    PRECONDITION(Size < 0x80000000);
    PRECONDITION(Size > 0);

#ifdef HEAP_MEASUREMENT
    /* When measuring heap size, mark all blocks with signature. */
    /* If measurement is off treat zero as true size of the block. */

    HEAP_MEASUREMENT_RECORD;
    hdr = Malloc(HEAP_HDR_SIZE(Size));
    if (hdr == NULL)
    {
        return NULL;
    }
    hdr->self_ptr_for_valgrind = hdr;
    hdr->size = (HEAP_MEASUREMENT_ON) ? Size : 0;
    current_heap_usage += (HEAP_MEASUREMENT_ON) ? Size : 0;
    HEAP_SIGN(hdr);
    return (char *) hdr + sizeof(HeapHdrStruct);
#else
    return Malloc(Size);
#endif
}


void
SPAL_Memory_Free(
    void * const Memory_p)
{
#ifdef HEAP_MEASUREMENT
    HeapHdr hdr;
#endif

#ifdef HEAP_MEASUREMENT
/* Note: Signature is checked to make sure memory is allocated by */
/* SPAL_Memory_*. Even when measurement is currently disabled, the */
/* frees of blocks previously allocated while measurement was on */
/* are considered. */

    if (Memory_p != NULL)
    {
        hdr = HEAP_HDR(Memory_p);
        fail_if(!HEAP_VERIFY(hdr),
            "Freeing memory block %p not allocated via SPAL_Memory_*.",
            Memory_p);

        current_heap_usage -= hdr->size;
        Free(hdr);
    }
#else
    Free(Memory_p);
#endif
}


#ifndef IMPLDEFS_CF_DISABLE_PRECONDITION
static inline bool
SPAL_Memory_32Bit_Multiplication_Overflows(
    uint32_t a,
    uint32_t b)
{
    if (a > 0xffff && b > 0xffff)
    {
        return true;
    }

    if (a <= 0xffff && b <= 0xffff)
    {
        return false;
    }

    if (a < b)
    {
        uint32_t Swap = a;
        a = b;
        b = Swap;
    }

    {
        uint32_t Product;

        Product = (a >> 16) * b;

        if (Product > 0xffff)
        {
            return true;
        }

        Product <<= 16;
        if (Product + ((a & 0xffff) * b) < Product)
        {
            return true;
        }
    }

    return false;
}
#endif /* IMPLDEFS_CF_DISABLE_PRECONDITION */

void *
SPAL_Memory_Calloc(
    const size_t MemberCount,
    const size_t MemberSize)
{
#ifdef HEAP_MEASUREMENT
    HeapHdr hdr;
#endif

    PRECONDITION(MemberCount > 0);
    PRECONDITION(MemberSize > 0);

    PRECONDITION(
        SPAL_Memory_32Bit_Multiplication_Overflows(
            MemberCount,
            MemberSize)
        == false);

    PRECONDITION(MemberCount * MemberSize < 0x80000000);
#ifdef HEAP_MEASUREMENT
    HEAP_MEASUREMENT_RECORD;
    hdr =  Malloc(HEAP_HDR_SIZE(MemberCount * MemberSize));
    if (hdr == NULL)
    {
        return NULL;
    }
    current_heap_usage += (HEAP_MEASUREMENT_ON) ? (MemberCount * MemberSize) : 0;
    c_memset(hdr, 0, HEAP_HDR_SIZE(MemberCount * MemberSize));
    HEAP_SIGN(hdr);
    hdr->self_ptr_for_valgrind = hdr;
    hdr->size = (HEAP_MEASUREMENT_ON) ? (MemberCount * MemberSize) : 0;
    return (char *) hdr + sizeof(HeapHdrStruct);
#else
    return Calloc(MemberCount, MemberSize);
#endif
}


void *
SPAL_Memory_ReAlloc(
    void * const Mem_p,
    size_t NewSize)
{
#ifdef HEAP_MEASUREMENT
    HeapHdr hdr;
#endif

    PRECONDITION(Mem_p != NULL);
    PRECONDITION(NewSize < 0x80000000);
    PRECONDITION(NewSize > 0);
#ifdef HEAP_MEASUREMENT
    hdr = HEAP_HDR(Mem_p);

    fail_if(!HEAP_VERIFY(hdr),
        "Realloc memory block %p not allocated via SPAL_Memory_*.",
        Mem_p);

    hdr = Realloc(hdr, HEAP_HDR_SIZE(NewSize));
    if (hdr != NULL)
    {
        /* Adjust book keeping if reallocation succeeded. */
        current_heap_usage -= hdr->size;
        current_heap_usage += (HEAP_MEASUREMENT_ON) ? NewSize : 0;
        HEAP_MEASUREMENT_RECORD;
        hdr->size = (HEAP_MEASUREMENT_ON) ? NewSize :  0;
        hdr->self_ptr_for_valgrind = hdr;
        return (char *) hdr + sizeof(HeapHdrStruct);
    }
    return NULL;
#else
    return Realloc(Mem_p, NewSize);
#endif
}

/* end of file spal_memory_ansi.c */
