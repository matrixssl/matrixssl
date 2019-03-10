/* sfzutf-perf.c
 *
 * Description: SFZUTF performance test suite.
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

#include "implementation_defs.h"
#include "sfzutf_internal.h"
#include "sfzutf-perf.h"

#if defined __GNUC__ && (defined __i386__ || defined __x86_64__)

/* Directly access cycle counter. */

void sfzutf_perf_test_update(uint32_t perftest_array_ent[
        SFZUTF_PERFTEST_ENTRIES_PER_COUNT])
{
    /* Read cycle counter and store it to given memory location.
       Uses cpuid to force serialized instruction execution. */
    __asm__ volatile ("subl %%eax, %%eax\n\t"
                      "cpuid\n\t"
                      "rdtsc\n\t"
                      "movl %%eax,(%0)\n\t"
                      "movl %%edx,4(%0)\n\t"
                      "subl %%eax, %%eax\n\t"
                      "cpuid"
                      :
                      : "S" (perftest_array_ent)
                      : "memory", "%eax", "%ebx", "%ecx", "%edx");
}
static uint64_t sfzutf_perf_test_normalize(uint32_t perftest_array_ent[
        SFZUTF_PERFTEST_ENTRIES_PER_COUNT])
{
    /* No normalization, only conversion uin32_t * 2 => uint64_t */
    return *(uint64_t *) perftest_array_ent;
}

static const char sfzutf_perf_units[] = "cycles";

#else
/* Fallback to using gettimeofday */
# include "osdep_sys_time.h"
# include <time.h>

void sfzutf_perf_test_update(uint32_t perftest_array_ent[
        SFZUTF_PERFTEST_ENTRIES_PER_COUNT])
{
    struct timeval target;
    int res;

    res = gettimeofday(&target, NULL);
    (void) res; /* perf_fail_if may expand to nothing. */
    perf_fail_if(res != 0, "gettimeofday() function failed.");

    perftest_array_ent[0] = target.tv_sec;
    perftest_array_ent[1] = target.tv_usec;
}

static uint64_t sfzutf_perf_test_normalize(
    uint32_t perftest_array_ent[SFZUTF_PERFTEST_ENTRIES_PER_COUNT])
{
    /* Values need to be normalized. This normalization procedure produces
       the numbers out as nanoseconds. */

    uint64_t combined_value;

    combined_value = (perftest_array_ent[0] * 1000000000LL) +
                     (perftest_array_ent[1] * 1000);

    return combined_value;
}

static const char sfzutf_perf_units[] = "ns";

#endif /* defined __GNUC__ && (defined __i386__ || defined __x86_64__) */

/* Static variable to remember initialization status of performance test. */
static enum
{
    SFZUTF_PERF_STATE_UNINITIALIZED,
    SFZUTF_PERF_STATE_CALIBRATING,
    SFZUTF_PERF_STATE_INITIALIZED
} sfzutf_perf_state = SFZUTF_PERF_STATE_UNINITIALIZED;

static uint32_t sfzutf_perf_repeats;
static uint64_t sfzutf_perf_calibrate_delta;

/* Builtin "performance test": calibrates with empty loop. */
START_PERF_TEST(sfzutf_perf_calibrate, 1)
{
    PERF_EXECUTE_TEST_SLOW({ /* Do nothing */ });
}
END_PERF_TEST

void sfzutf_perf_test_begin(const char *funcname,
    uint32_t repeats,
    uint32_t perftest_array[SFZUTF_PERFTEST_ENTRIES])
{
    uint32_t i;

    PARAMETER_NOT_USED(funcname);

    if (sfzutf_perf_state == SFZUTF_PERF_STATE_UNINITIALIZED)
    {
        sfzutf_perf_state = SFZUTF_PERF_STATE_CALIBRATING;
        L_TESTLOG(LF_CALIBRATING,
            "Invoking performance measurement calibration");
        sfzutf_perf_calibrate(0);
        sfzutf_perf_state = SFZUTF_PERF_STATE_INITIALIZED;
    }

    /* Store repeat counter. */
    sfzutf_perf_repeats = repeats;

    /* Read timecounter to perftest_array[0-1]:
       side-effect fetch sfzutf_perf_test_update to instruction cache. */
    sfzutf_perf_test_update(perftest_array);

    /* Clear the perftests array (and as important side-effect make sure the
       whole array is in TLB and caches). */
    for (i = 0; i < SFZUTF_PERFTEST_ENTRIES; i++)
    {
        perftest_array[i] = 0;
    }
}

void sfzutf_perf_test_end(const char *funcname,
    uint32_t perftest_array[SFZUTF_PERFTEST_ENTRIES])
{
    uint64_t prev;
    uint64_t delta;
    uint64_t smallest_delta = 0ULL - 1ULL;
    uint32_t i;

    PARAMETER_NOT_USED(funcname);

    /* Logic: find the smallest measurement. (Ie. the one that has no
       context switches or the lest number of them).*/

    prev = sfzutf_perf_test_normalize(perftest_array);
    for (i = 1; i < SFZUTF_PERFTEST_COUNT; i++)
    {
        delta = sfzutf_perf_test_normalize(
            &perftest_array[i * SFZUTF_PERFTEST_ENTRIES_PER_COUNT]) - prev;

        L_TESTLOG(LF_PERF_MEASUREMENT, "%" PRIu64 " %s", delta,
            sfzutf_perf_units);

        if (delta < smallest_delta)
        {
            smallest_delta = delta;
        }

        prev = delta + prev;
    }

    fail_if(smallest_delta < sfzutf_perf_calibrate_delta,
        "Measured performance value is less than calibrated minimum.");

    if (sfzutf_perf_state == SFZUTF_PERF_STATE_CALIBRATING)
    {
        fail_if(sfzutf_perf_repeats != 1,
            "Calibrate always with repeats == 1");

        L_TESTLOG(LF_PERF_ACCEPTED_CALIBRATION,
            "%" PRIu64 ".000 %s", smallest_delta, sfzutf_perf_units);
    }
    else
    {
        /* Check that SFZUTF initialization has been done. */
        ASSERT(sfzutf_perf_state == SFZUTF_PERF_STATE_INITIALIZED);

        /* Decrement calibration result from the smallest delta. */
        smallest_delta -= sfzutf_perf_calibrate_delta;

        /* Choose formatting according to number of repeats.
           This is to avoid floating point mathematics... */
        if (sfzutf_perf_repeats == 1)
        {
            L_TESTLOG(LF_PERF_ACCEPTED_MEASUREMENT,
                "%" PRIu64 ".000 %s", smallest_delta, sfzutf_perf_units);
        }
        else if (sfzutf_perf_repeats == 10)
        {
            L_TESTLOG(LF_PERF_ACCEPTED_MEASUREMENT,
                "%" PRIu64 ".%" PRIu64 "00 %s",
                smallest_delta / 10, smallest_delta % 10, sfzutf_perf_units);
        }
        else if (sfzutf_perf_repeats == 100)
        {
            L_TESTLOG(LF_PERF_ACCEPTED_MEASUREMENT,
                "%" PRIu64 ".%02" PRIu64 "0 %s",
                smallest_delta / 100, smallest_delta % 100,
                sfzutf_perf_units);
        }
        else
        {
            fail("Unsupported value for sfzutf_perf_repeats.");
        }
    }
}

/* end of file sfzutf-perf.c */
