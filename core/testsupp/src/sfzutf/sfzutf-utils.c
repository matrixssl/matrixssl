/* sfzutf-utils.c
 *
 * Description: SFZUTF utilities.
 */

/*****************************************************************************
* Copyright (c) 2008-2016 INSIDE Secure Oy. All Rights Reserved.
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

#include "sfzutf_internal.h"
#include "sfzutf-utils.h"

/* Tracking the allocated test resources. */
static
SfzUtfPtrSizeExt *ptrsize_list;

void *
sfzutf_ptrsize_ext_alloc(
    size_t size,
    bool clear,
    SfzUtfUtilsID *purpose,
    SfzUtfEvent livetime)
{
    SfzUtfPtrSizeExt *pe;
    size_t alloc_size = size + sizeof(*pe);
    void *ptr;

    /* Ensure no wraparound. */
    ASSERT(alloc_size > size);

    if (clear == 1)
    {
        pe = SFZUTF_CALLOC(alloc_size, 1);
    }
    else
    {
        pe = SFZUTF_MALLOC(alloc_size);
    }

    if (!pe)
    {
        return NULL;
    }

    ptr = pe + 1;
    if (purpose == NULL)
    {
        purpose = ptr;
    }

    pe->base.ptr = ptr;
    pe->base.size = (uint32_t) size;
    pe->base.len = (uint32_t) size;
    pe->base.format = SFZUTF_PTRSIZE_STRING_MSB_FIRST;
    pe->purpose = purpose;
    pe->livetime = livetime;

    /* Link. */
    pe->next = ptrsize_list;
    ptrsize_list = pe;

    return ptr;
}

static
void sfzutf_ptrsize_ext_free(void *ptr)
{
    SfzUtfPtrSizeExt *pe = ptr;
    SfzUtfPtrSizeExt *pe_prev;

    if (!pe)
    {
        return;
    }
    pe -= 1;

    if (ptrsize_list == pe)
    {
        /* First in list. */
        ptrsize_list = pe->next;
    }
    else
    {
        /* Not first. */
        pe_prev = ptrsize_list;
        ASSERT(pe_prev);
        while (pe_prev->next != pe)
        {
            pe_prev = pe_prev->next;
            ASSERT(pe_prev != NULL);
        }
        /* Got correct entry. */
        pe_prev->next = pe->next;
    }
    /* c_memset(pe, 0xff, pe->size + sizeof(*pe)); */
    SFZUTF_FREE(pe);
}

SfzUtfPtrSizeExt *sfzutf_find_ptrsize_ext_by_address(void *ptr)
{
    SfzUtfPtrSizeExt *pe = ptrsize_list;

    while (pe && pe->base.ptr != ptr)
    {
        pe = pe->next;
    }
    return pe;
}

SfzUtfPtrSizeExt *sfzutf_find_ptrsize_ext_by_purpose(SfzUtfUtilsID *purpose)
{
    SfzUtfPtrSizeExt *pe = ptrsize_list;

    while (pe && pe->purpose != purpose)
    {
        pe = pe->next;
    }
    return pe;
}

SfzUtfPtrSizeExt *sfzutf_find_ptrsize_ext_by_livetime(SfzUtfEvent livetime)
{
    SfzUtfPtrSizeExt *pe = ptrsize_list;

    while (pe && pe->livetime != livetime)
    {
        pe = pe->next;
    }
    return pe;
}

void
sfzutf_utils_event(
    SfzUtfEvent event,
    const char *name,
    const void *struct_ptr)
{
    SfzUtfPtrSizeExt *pe;

    PARAMETER_NOT_USED(name);
    PARAMETER_NOT_USED(struct_ptr);

    do
    {
        pe = sfzutf_find_ptrsize_ext_by_livetime(event);
        if (pe)
        {
            sfzutf_ptrsize_ext_free(pe->base.ptr);
        }
    }
    while (pe != NULL);
}

uint32_t
sfzutf_strlen(
    const char *str)
{
    uint32_t len = 0;
    const char *string_it = str;

    while (*string_it)
    {
        len++;
        string_it++;
    }
    return len;
}

/* Switch ordering of array.
   This implementation works byte at a time. */
static void
endianFlip(
    void *dst,
    uint32_t len)
{
    unsigned char *dst_c = dst;
    unsigned char t;
    uint32_t i;

    for (i = 0; i < len / 2; i++)
    {
        t = dst_c[i];
        dst_c[i] = dst_c[len - i - 1];
        dst_c[len - i - 1] = t;
    }
}

static int
getHexDigit(
    char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }


    if (ch >= 'A' && ch <= 'F')
    {
        return ch - 'A' + 10;
    }

    return -1;
}

static void
putHexDigit(
    char *target,
    unsigned char ch_x)
{
    if (ch_x < 10)
    {
        *target = '0' + ch_x;
    }
    else
    {
        *target = 'a' + (ch_x - 10);
    }
}

SfzUtfPtrSize
sfzutf_ptrsize_from_mem(
    const void *mem,
    uint32_t memlength,
    enum SfzUtfPtrSizeFormat format)
{
    SfzUtfPtrSize new;
    char *ptr;
    const char *str = mem;

    if (format == SFZUTF_PTRSIZE_STRING_TEXT)
    {
        ptr = sfzutf_AssertNotNull(
            sfzutf_ptrsize_ext_alloc(memlength,
                0,
                NULL,
                SFZUTF_EVENT_TEST_END));

        new.ptr = ptr;
        new.size = memlength;
        new.len = memlength;
        new.format = SFZUTF_PTRSIZE_STRING_LSB_FIRST;
        SFZUTF_MEMCPY(ptr, mem, memlength);
        return new;
    }

    fail_if(format != SFZUTF_PTRSIZE_STRING_MSB_FIRST &&
        format != SFZUTF_PTRSIZE_STRING_LSB_FIRST,
        "Unsupported input format.");
    fail_if((memlength & 1) != 0, "Wrong input length.");

    ptr = sfzutf_AssertNotNull(
        sfzutf_ptrsize_ext_alloc(memlength / 2,
            0,
            NULL,
            SFZUTF_EVENT_TEST_END));

    new.ptr = ptr;
    new.size = memlength / 2;
    new.len = memlength / 2;
    new.format = format;

    /* Get string in LSB byte order. */
    while (memlength > 1)
    {
        int h1 = getHexDigit(str[0]);
        int h2 = getHexDigit(str[1]);
        fail_if(h1 < 0 || h2 < 0, "Invalid hex digit.");

        *(ptr++) = (char) ((h1 << 4) | h2);
        str += 2;
        memlength -= 2;
    }

    if (new.format == SFZUTF_PTRSIZE_STRING_MSB_FIRST)
    {
        endianFlip(new.ptr, new.size);
    }

    return new;
}

char *
sfzutf_ptrsize_to_str(
    SfzUtfPtrSize sups)
{
    char *buf;
    unsigned int i;
    int len = sups.len * 2 + 1;
    const unsigned char *data = sups.ptr;

    buf = sfzutf_AssertNotNull(
        sfzutf_ptrsize_ext_alloc(len,
            1,
            NULL,
            SFZUTF_EVENT_TEST_END));
    buf[len - 1] = 0;
    for (i = 0; i < sups.len; i++)
    {
        if (sups.format == SFZUTF_PTRSIZE_STRING_MSB_FIRST)
        {
            putHexDigit(&buf[i * 2], data[sups.len - i - 1] & 0xf);
            putHexDigit(&buf[i * 2 + 1], data[sups.len - i - 1] / 16);
        }
        else
        {
            putHexDigit(&buf[i * 2], data[i] / 16);
            putHexDigit(&buf[i * 2 + 1], data[i] & 0xf);
        }
    } /* for */

    return buf;
}

SfzUtfPtrSize
sfzutf_ptrsize_from_str(
    const char *string,
    enum SfzUtfPtrSizeFormat format)
{
    return sfzutf_ptrsize_from_mem(string, sfzutf_strlen(string), format);
}

void
sfzutf_ptrsize_free(
    SfzUtfPtrSize sups)
{
    sfzutf_ptrsize_ext_free(sups.ptr);
}

SfzUtfPtrSize
sfzutf_ptrsize_blank(
    uint32_t size)
{
    SfzUtfPtrSize new;

    new.ptr = sfzutf_AssertNotNull(
        sfzutf_ptrsize_ext_alloc(size,
            1,
            NULL,
            SFZUTF_EVENT_TEST_END));

    new.size = size;
    new.len = 0;
    new.format = SFZUTF_PTRSIZE_STRING_LSB_FIRST;
    return new;
}

SfzUtfPtrSize
sfzutf_ptrsize_fill_with_ptrsize(
    SfzUtfPtrSize empty_target,
    SfzUtfPtrSize filler)
{
    uint32_t i;
    uint32_t len_mod = filler.len;
    uint8_t *target = empty_target.ptr;
    const uint8_t *source = filler.ptr;

    fail_if(empty_target.len != 0, "Target provided must be empty.");
    fail_if(len_mod == 0, "Empty filler specified.");

    for (i = 0; i < empty_target.size; i++)
    {
        target[i] = source[i % len_mod];
    }

    empty_target.len = empty_target.size;
    return empty_target;
}

int
sfzutf_ptrsize_cmp_ptrsize(
    SfzUtfPtrSize ptrsize_1,
    SfzUtfPtrSize ptrsize_2)
{
    int r;
    uint32_t minsize = ptrsize_1.len < ptrsize_2.len ? ptrsize_1.len : ptrsize_2.len;

    r = SFZUTF_MEMCMP(ptrsize_1.ptr, ptrsize_2.ptr, minsize);

    if (r != 0)
    {
        return r;
    }

    /* Minsize was same, determine return value from lengths. */

    if (ptrsize_1.len < ptrsize_2.len)
    {
        return -1;
    }

    return ptrsize_1.len != ptrsize_2.len;
}

/* end of file sfzutf-utils.c */
