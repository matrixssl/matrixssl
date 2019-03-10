/* sfzutf-utils.h
 *
 * Description: SFZUTF utility routines header.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef INCLUDE_GUARD_SFZUTF_UTILS_H
#define INCLUDE_GUARD_SFZUTF_UTILS_H

#include "public_defs.h"
#include "sfzutf.h"

/* To supplement common need. */
uint32_t sfzutf_strlen(const char *str);

enum SfzUtfPtrSizeFormat
{
    SFZUTF_PTRSIZE_STRING_MSB_FIRST,
    SFZUTF_PTRSIZE_STRING_LSB_FIRST,
    SFZUTF_PTRSIZE_STRING_TEXT,
};

/* Short notations. */
#define SUPS_MSBF SFZUTF_PTRSIZE_STRING_MSB_FIRST
#define SUPS_LSBF SFZUTF_PTRSIZE_STRING_LSB_FIRST
#define SUPS_TEXT SFZUTF_PTRSIZE_STRING_TEXT

typedef struct sfzutf_ptrsize
{
    void *ptr;
    uint32_t size;
    uint32_t len;
    enum SfzUtfPtrSizeFormat format;
} SfzUtfPtrSize;

/* Identifier for ptrsize purpose. */
typedef unsigned short SfzUtfUtilsID;

typedef struct sfzutf_ptrsize_ext
{
    SfzUtfPtrSize base;
    struct sfzutf_ptrsize_ext *next;
    SfzUtfEvent livetime;
    SfzUtfUtilsID *purpose;
    unsigned long long foralignment;
} SfzUtfPtrSizeExt;

SfzUtfPtrSize sfzutf_ptrsize_blank(uint32_t size);
char *sfzutf_ptrsize_to_str(SfzUtfPtrSize sups);
SfzUtfPtrSize sfzutf_ptrsize_from_str(const char *string,
                                      enum SfzUtfPtrSizeFormat format);
SfzUtfPtrSize sfzutf_ptrsize_from_mem(const void *mem,
                                      uint32_t memlength,
                                      enum SfzUtfPtrSizeFormat format);
void sfzutf_ptrsize_free(SfzUtfPtrSize sups);

SfzUtfPtrSize sfzutf_ptrsize_fill_with_ptrsize(SfzUtfPtrSize empty_target,
                                               SfzUtfPtrSize filler);

#define sfzutf_ptrsize_eq_ptrsize(ptrsize_1, ptrsize_2) \
    (sfzutf_ptrsize_cmp_ptrsize(ptrsize_1, ptrsize_2) == 0)

#define sfzutf_ptrsize_eq_str(ptrsize_1, str, format)                  \
    (sfzutf_ptrsize_cmp_str(ptrsize_1, str, format) == 0)

#define sfzutf_ptrsize_eq_mem(ptrsize_1, mem, len, format)             \
    (sfzutf_ptrsize_cmp_mem(ptrsize_1, mem, len, format) == 0)

int sfzutf_ptrsize_cmp_ptrsize(SfzUtfPtrSize ptrsize_1,
                               SfzUtfPtrSize ptrsize_2);

/* SFZUTF ptrsize default livetime is single test.
   This function sets the livetime
   (until end of test, testcase, suite or global). */
void sfzutf_ptrsize_set_livetime(SfzUtfPtrSize ps,
                                 SfzUtfEvent livetime);

/* Extended ptrsize allocator. Avoid using the function directly. */
void *sfzutf_ptrsize_ext_alloc(size_t size,
                               bool clear,
                               SfzUtfUtilsID *purpose,
                               SfzUtfEvent livetime);

/* Entrypoint called by sfzutf core on various events.
   Do not call directly. */
void sfzutf_utils_event(SfzUtfEvent event,
                        const char *name,
                        const void *struct_ptr);

/* Functions for discovering a ptrsize.
   Do not call directly. */
SfzUtfPtrSizeExt *sfzutf_find_ptrsize_ext_by_address(void *memaddress);
SfzUtfPtrSizeExt *sfzutf_find_ptrsize_ext_by_purpose(SfzUtfUtilsID *purpose);
SfzUtfPtrSizeExt *sfzutf_find_ptrsize_ext_by_livetime(SfzUtfEvent livetime);

#define SFZUTF_UTILS_NEED_TEMPORARY(name, scope)                        \
    do {                                                                \
        static SfzUtfUtilsID name ## _id;                                 \
        SfzUtfPtrSizeExt *ex_T = sfzutf_find_ptrsize_ext_by_purpose(   \
            &name ## _id);                                            \
        if (ex_T) { name = ex_T->base.ptr; } else { name = NULL; }              \
        if (name == NULL) { name = sfzutf_ptrsize_ext_alloc(sizeof(*name), \
                                1,            \
                                &name ## _id,   \
                                scope); }       \
        name = sfzutf_AssertNotNull(name);                              \
    } while (0)

/* Same than SFZUTF_NEED_TEMPORARY, but reservation is skipped if space
   is not available. (Need to check pointer for null.) */
#define SFZUTF_UTILS_TEMPORARY_BEGIN(name, scope)                       \
    do {                                                                \
        static SfzUtfUtilsID name ## _id;                                 \
        SfzUtfPtrSizeExt *ex_T = sfzutf_find_ptrsize_ext_by_purpose(   \
            &name ## _id);                                            \
        if (ex_T) { name = ex_T->base.ptr; } else { name = NULL; }              \
        if (name == NULL) { name = sfzutf_ptrsize_ext_alloc(sizeof(*name), \
                                1,            \
                                &name ## _id,   \
                                scope); }       \
        if (!name) { unsupported_quick("Memory Not Available"); break; }

#define SFZUTF_UTILS_TEMPORARY_END \
    } while (0)

#endif /* Include Guard */

/* end of file sfzutf-utils.h */
