/* sfzutf.h
 *
 * Description: SFZUTF header.
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

#ifndef INCLUDE_GUARD_SFZUTF_H
#define INCLUDE_GUARD_SFZUTF_H

#include "implementation_defs.h"

/* Events related to test suite processing. */
typedef enum
{
    SFZUTF_EVENT_BEGIN,
    SFZUTF_EVENT_SUITE_BEGIN,
    SFZUTF_EVENT_TCASE_BEGIN,
    SFZUTF_EVENT_TEST_BEGIN,
    SFZUTF_EVENT_TEST_END,
    SFZUTF_EVENT_TCASE_END,
    SFZUTF_EVENT_SUITE_END,
    SFZUTF_EVENT_END,
} SfzUtfEvent;

/* Not using check from sourceforge => Need to define replacements here. */
typedef void (*TFun)(int _i);
typedef void (*SFun)(void);

/* This is internal macro that implements FAILURE reporting via
   implementation_defs.h */
#ifdef GCOV_PROFILE
void
__gcov_flush(); /* Function to write profiles on disk. */

# define SFZUTF_FAILURE(stub, ...)                                       \
    do { __gcov_flush();                                                \
         L_TESTLOG(LF_FAILURE, __VA_ARGS__);                            \
         DEBUG_abort();                                                 \
    } while (0)

# define SFZUTF_UNSUPPORTED(...)                                         \
    __gcov_flush();                                                     \
    L_TESTLOG(LF_TEST_UNSUPPORTED, "Test unsupported");                 \
    fail(__VA_ARGS__)                                                   \

#else /* !GCOV_PROFILE */
# define SFZUTF_FAILURE(stub, ...)                                       \
    do { L_TESTLOG(LF_FAILURE, __VA_ARGS__);                              \
         DEBUG_abort();                                                   \
    } while (0)

# define SFZUTF_UNSUPPORTED(...)                                         \
    L_TESTLOG(LF_TEST_UNSUPPORTED, "Test unsupported");                 \
    fail(__VA_ARGS__)

#endif /* GCOV_PROFILE */

#define fail_if(expr, ...)                                              \
    do {                                                                  \
        if (expr) {                                                         \
            SFZUTF_FAILURE(1, "Failure '"#expr "' occurred: " __VA_ARGS__);   \
        }                                                                   \
    } while (0)

#define fail_unless(expr, ...)                                          \
    do {                                                                  \
        if (!(expr)) {                                                      \
            SFZUTF_FAILURE(1, "Failure '"#expr "' occurred: " __VA_ARGS__);   \
        }                                                                   \
    } while (0)

#define fail(...) fail_if(1, __VA_ARGS__)

/* Mark test as unsupported if condition is true. */
#define unsupported(...) \
    do {                                                                  \
        SFZUTF_UNSUPPORTED(__VA_ARGS__);                                    \
    } while (0)

#define unsupported_if(expr, ...)                                       \
    do {                                                                  \
        if (expr) {                                                         \
            SFZUTF_UNSUPPORTED(__VA_ARGS__);                                  \
        }                                                                   \
    } while (0)

#define unsupported_unless(expr, ...)                                   \
    do {                                                                  \
        if (!(expr)) {                                                      \
            SFZUTF_UNSUPPORTED(__VA_ARGS__);                                  \
        }                                                                   \
    } while (0)

#define unsupported_quick(...) \
    do {                                                                  \
        L_TESTLOG(LF_TEST_NOTE_UNSUPPORTED, __VA_ARGS__);                   \
        sfzutf_unsupported_quick();                                         \
    } while (0)

/* Test can declare that certain effect happening is to be considered
   successful test, to be able to test error situation handling, even
   for fatal errors. */
#ifdef IMPLDEFS_CF_DISABLE_ASSERT

# define SFZUTF_EXPECT_ASSERT \
    unsupported("Assertions disabled.")

#else /* !IMPLDEFS_CF_DISABLE_ASSERT */

# define SFZUTF_EXPECT_ASSERT \
    L_TESTLOG(LF_TEST_EXPECT_ASSERT, "expected assertion")

#endif /* !IMPLDEFS_CF_DISABLE_ASSERT */

#ifdef IMPLDEFS_CF_DISABLE_PRECONDITION

# define SFZUTF_EXPECT_PRECONDITION \
    unsupported("Preconditions disabled.")

#else /* !IMPLDEFS_CF_DISABLE_PRECONDITION */

# define SFZUTF_EXPECT_PRECONDITION \
    L_TESTLOG(LF_TEST_EXPECT_PRECONDITION, "expected precondition")

#endif /* !IMPLDEFS_CF_DISABLE_PRECONDITION */

/* Provided for completeness. There should be no valid use for this. */
#ifdef IMPLDEFS_CF_DISABLE_POSTCONDITION

# define SFZUTF_EXPECT_POSTCONDITION \
    unsupported("Postconditions disabled.")

#else /* !IMPLDEFS_CF_DISABLE_POSTCONDITION */

# define SFZUTF_EXPECT_POSTCONDITION \
    L_TESTLOG(LF_TEST_EXPECT_POSTCONDITION, "expected postcondition")

#endif /* !IMPLDEFS_CF_DISABLE_POSTCONDITION */

#define START_TEST(name)                                \
    static void name(int _i)                              \
    {                                                     \
        const char *funcname = #name;                       \
        L_TESTLOG(LF_TESTFUNC_INVOKED, "%s:%d", #name, _i); \
        do

#define END_TEST while (0);                                     \
    if (sfzutf_unsupported_quick_process()) {                   \
        L_TESTLOG(LF_TESTFUNC_UNSUPPORTED_QUICK, "%s:%d", funcname, _i); \
    } else {                                                    \
        L_TESTLOG(LF_TESTFUNC_SUCCESS, "%s:%d", funcname, _i); \
    }                                                           \
    }


/* These are like START_TEST, but for fixtures whose are global. */
#define DECLARE_FIXTURE_SETUP(name)     void name(void)
#define START_FIXTURE_SETUP(name)       void name(void)
#define END_FIXTURE_SETUP

#define DECLARE_FIXTURE_TEARDOWN(name)  void name(void)
#define START_FIXTURE_TEARDOWN(name)    void name(void)
#define END_FIXTURE_TEARDOWN

/* Each suite needs to provide this interface */
void build_suite(void);

/* Check allocation was successful. */
void *sfzutf_AssertNotNull(const void *input);

/* Helper for handier suite creation. */
void sfzutf_suite_create(const char *name);
void sfzutf_tcase_create(const char *name);
void sfzutf_tcase_finish(void);

#define sfzutf_test_add(func) sfzutf_test_add_fname(func, ""#func "")
void sfzutf_test_add_fname(TFun TestFunc, const char *TestFuncName);

#define sfzutf_loop_test_add(func, mi, ma) \
    sfzutf_loop_test_add_fname(func, ""#func "", mi, ma)
void sfzutf_loop_test_add_fname(TFun TestFunc,
                                const char *TestFuncName,
                                int mi, int ma);

void sfzutf_tcase_add_fixture(SFun start, SFun end);

void sfzutf_unsupported_quick(void);
bool sfzutf_unsupported_quick_process(void);

void sfzutf_interactive_start(
    int (*getinputfunc)(char * const c_p));


#ifdef STACK_MEASUREMENT
# include "sfzutf-stack.h"
#endif

#ifdef HEAP_MEASUREMENT
# include "sfzutf-heap.h"
#endif

#endif /* Include Guard */

/* end of file sfzutf.h */
