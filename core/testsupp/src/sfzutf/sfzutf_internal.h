/* sfzutf_internal.h
 *
 * Description: SFZUTF internally used macros.
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

#ifndef INCLUDE_GUARD_SFZUTF_INTERNAL_H
#define INCLUDE_GUARD_SFZUTF_INTERNAL_H

#include "sfzutf.h"

struct TestNode
{
    struct TestNode *NextNode_p;
    const char *NodeName_p;
};

struct TestList
{
    struct TestNode *NodeList_p;
};

struct Fixture
{
    struct Fixture *NextFixture_p;
    const char *Name_p;
    SFun StartFunc;
    SFun EndFunc;
};

struct Test
{
    struct Test *NextTest_p;
    const char *Name_p;
    TFun TestFunc;
    int Start;
    int EndPlus1;
    bool Enabled;
};

struct TestCase
{
    struct TestCase *NextCase_p;
    const char *Name_p;
    struct Test *TestList_p;
    struct Fixture *FixtureList_p;
    bool Enabled;
};

struct TestSuite
{
    struct TestSuite *NextSuite_p;
    const char *Name_p;
    struct TestCase *TestCaseList_p;
    bool Enabled;
};

typedef enum
{
    SFZUTF_ENABLE_UNDETERMINED,
    SFZUTF_ENABLE_SINGLE,
    SFZUTF_ENABLE_AFTER,
    SFZUTF_ENABLE_ALL
}
SfzUtfEnable_t;

extern struct TestSuite *sfzutf_current_suite;
extern struct TestCase *sfzutf_current_tcase;


/* Define macros to do operations sfzutf.c needs to do.
   The macros may map to IMPLDEFS/SPAL/CLIB or ANSI C facilities, according
   to user choice. */
#ifdef SFZUTF_CONFIG_USE_SPAL

# include "spal_memory.h"
# include "c_lib.h"

# define SFZUTF_ASSERT(x) ASSERT(x)
# define SFZUTF_PANIC(x) PANIC(x)
# define SFZUTF_MALLOC(x) SPAL_Memory_Alloc((x) > 0 ? (x) : 1)
# define SFZUTF_CALLOC(x, y) SPAL_Memory_Calloc(x, y)
# define SFZUTF_FREE(x) SPAL_Memory_Free(x)
# define SFZUTF_MEMCMP(a, b, l) c_memcmp(a, b, l)
# define SFZUTF_MEMCPY(a, b, l) c_memcpy(a, b, l)
uint32_t sfzutf_strlen(const char *str);
# define SFZUTF_STRLEN(s) sfzutf_strlen(s)

#else /* !SFZUTF_CONFIG_USE_SPAL */

/* SFZUTF defaults to use ANSI.
   This makes it easier to debug modules themselves, especially
   SPAL modules. */
# include "osdep_stdlib.h"
# include "osdep_stdio.h"
# include "osdep_string.h"
# include "osdep_assert.h"

uint32_t sfzutf_strlen(const char *str);
# define SFZUTF_STRLEN(s) sfzutf_strlen(s)
# define SFZUTF_ASSERT(x) Assert(x)
# define SFZUTF_PANIC(msg) \
    do { Fprintf(stderr, msg "\n"); exit(1); } while (0)
# define SFZUTF_MALLOC(x) Malloc((x) > 0 ? (x) : 1)
# define SFZUTF_CALLOC(x, y) Calloc(x, y)
# define SFZUTF_FREE(x) Free(x)
# define SFZUTF_MEMCMP(a, b, l) Memcmp(a, b, l)
# define SFZUTF_MEMCPY(a, b, l) Memcpy(a, b, l)

#endif /* SFZUTF_CONFIG_USE_SPAL */

/* Compositions of above, for common string operations. */
#define SFZUTF_STREQ(s1, s2)                             \
    (SFZUTF_STRLEN(s1) == SFZUTF_STRLEN(s2) &&            \
     SFZUTF_MEMCMP((s1), (s2), SFZUTF_STRLEN(s1)) == 0)

#define SFZUTF_STREQ_PREFIX(s1, sp)                      \
    (SFZUTF_STRLEN(s1) >= SFZUTF_STRLEN(sp) &&            \
     SFZUTF_MEMCMP((s1), (sp), SFZUTF_STRLEN(sp)) == 0)

/* Macros for working with string literals.
   Although strings are compared, only memory comparison functionality
   is required. */
#define streq_lit(str, lit_str) SFZUTF_STREQ(str, lit_str)
#define streq_lit_prefix(str, lit_str) SFZUTF_STREQ_PREFIX(str, lit_str)
#define strlen_lit(lit_str) (sizeof(lit_str) - 1)


void
sfzutf_disable_all(
    struct TestSuite *TestSuite_p);

bool
sfzutf_enable_suite(
    struct TestSuite *TestSuite_p,
    const char * const SuiteName_p,
    const char * const TCaseName_p,
    const char * const TestName_p,
    const int * const IterValue_p,
    const SfzUtfEnable_t OrigEnableMode);

int
sfzutf_run_suite(
    struct TestSuite *TestSuite_p);

void
sfzutf_utils_event(
    SfzUtfEvent event,
    const char *name,
    const void *struct_ptr);

#endif /* Include Guard */

/* end of file sfzutf_internal.h */
