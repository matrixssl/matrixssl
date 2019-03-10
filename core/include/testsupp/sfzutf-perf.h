/* sfzutf-perf.h
 *
 * Description: SFZUTF performance test suite header.
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

#ifndef INCLUDE_GUARD_SFZUTF_PERF_H
#define INCLUDE_GUARD_SFZUTF_PERF_H

/* Include generic parts of SFZ UTF framework. */
#include "sfzutf.h"

/* These values correspond to systems where we use up-to 64 bits per
   recorded time. Test count 10 is often quite good. Need to consider
   making it more configurable. */

#define SFZUTF_PERFTEST_ENTRIES 20
#define SFZUTF_PERFTEST_COUNT 10
#define SFZUTF_PERFTEST_ENTRIES_PER_COUNT 2

/* START_PERF_TEST(name)/END_TEST pair allow defining performance tests. */

void sfzutf_perf_test_begin(const char *funcname,
                            uint32_t repeats,
                            uint32_t perftest_array[SFZUTF_PERFTEST_ENTRIES]);
void sfzutf_perf_test_update(uint32_t perftest_array_ent[
                                 SFZUTF_PERFTEST_ENTRIES_PER_COUNT]);
void sfzutf_perf_test_end(const char *funcname,
                          uint32_t perftest_array[SFZUTF_PERFTEST_ENTRIES]);

#define PERF_INIT                                               \
    sfzutf_perf_test_begin(__func__, perftest_repeats, perftest_array);  \
    do                                                          \
    {                                                           \
        do

#define PERF_TEST_BEGIN(repeats)                                \
    uint32_t perftest_repeats = repeats;                        \
    uint32_t perftest_array[SFZUTF_PERFTEST_ENTRIES];           \
    uint32_t perftest_counter = 0

#define START_PERF_TEST(name, repeats)                          \
    START_TEST(name)                                                \
    {                                                               \
        uint32_t perftest_repeats = repeats;                        \
        uint32_t perftest_array[SFZUTF_PERFTEST_ENTRIES];           \
        uint32_t perftest_counter = 0;

#define PERF_EXIT                                                       \
    while (0);                                                          \
    sfzutf_perf_test_update(&perftest_array[perftest_counter *      \
                                            SFZUTF_PERFTEST_ENTRIES_PER_COUNT]); \
    } while (++perftest_counter < SFZUTF_PERFTEST_COUNT);               \
    sfzutf_perf_test_end(__func__, perftest_array);

#define END_PERF_TEST } \
    END_TEST

#ifdef SFZUTF_USE_PERF_WITH_CHECK
/* Runs performance tests with bit diminished performance but checks
   the results.
   Notice: in this mode these completely match fail*(). */

# define perf_fail_if(expr, ...)                                         \
    do {                                                                  \
        if (expr) {                                                         \
            SFZUTF_FAILURE(1, "Failure '"#expr "' occurred: " __VA_ARGS__);   \
        }                                                                   \
    } while (0)

# define perf_fail_unless(expr, ...)                                     \
    do {                                                                  \
        if (!(expr)) {                                                      \
            SFZUTF_FAILURE(1, "Failure '"#expr "' occurred: " __VA_ARGS__);   \
        }                                                                   \
    } while (0)

# define perf_fail(...) fail_if(1, __VA_ARGS__)

# define perf(...) __VA_ARGS__

#else /* SFZUTF_USE_PERF_WITH_CHECK */
/* Maximum performance, omits all checks. */
# define perf_fail_if(expr, ...) do {} while (0)
# define perf_fail_unless(expr, ...) do {} while (0)
# define perf_fail(...) do {} while (0)
# define perf(...) do {} while (0)

#endif /* SFZUTF_USE_PERF_WITH_CHECK */

#define PERF_REP1(x) x
#define PERF_REP10(x) x; x; x; x; x; x; x; x; x; x
#define PERF_REP10A(x) x; x; x; x; x; x; x; x; x; x
#ifdef __i386__
/* This may be used on all architectures with large caches. */
# define PERF_REP100(x) PERF_REP10A(PERF_REP10(x))
#else /* Assume small caches. */
# define PERF_REP100(x) \
    do { unsigned int perf_looper; \
         for (perf_looper = 0; perf_looper < 10; perf_looper++) \
         { PERF_REP10(x); } \
    } while (0)
#endif /* __i386__ */

/* These macros are always used as pairs.
   The macro to use depends on desired test accuracy and
   speed of test.

   Guidelines: FAST == symmetric cryptographic operation with
                       >= 100 MIPS processor on 256 bytes of data
               NORMAL == same processor but up-to 4096 bytes of data
               SLOW   == asymmetric operation (sign/verify)

   For non-cryptographic operations, more work is needed to apply
   these guidelines, but you can manage it. */

#define PERF_TEST_FAST /* 100 */ 10
#define PERF_TEST_NORMAL 10
#define PERF_TEST_SLOW 1
#define PERF_EXECUTE_TEST_FAST(x) /* PERF_REP100 */ PERF_INIT { PERF_REP10(x); } PERF_EXIT
#define PERF_EXECUTE_TEST_NORMAL(x) PERF_INIT { PERF_REP10(x); } PERF_EXIT
#define PERF_EXECUTE_TEST_SLOW(x) PERF_INIT { PERF_REP1(x); } PERF_EXIT

#endif /* Include Guard */

/* end of file sfzutf-perf.h */
