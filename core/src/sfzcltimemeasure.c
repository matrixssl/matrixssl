/* sfzcltimemeasure.c
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

/* Real time measuring, for measuring software performance. */

#include "sfzclincludes.h"
#include "implementation_defs.h"
#include "sfzcltimemeasure.h"

#define SFZCL_DEBUG_MODULE "SfzclTimeMeasure"
/*
 * FOLLOWING SECTION HAS CODE TO EMULATE DIFFERENT TIME MEASUREMENT
 * FUNCTIONS WITH UNIX GETTIMEOFDAY.  THIS IS FOR TESTING ONLY.
 */
/* Define this to test Windows specific code in Unix. */

/* It should work this way everywhere. */
#define SFZCL_UINT64_TO_SFZCL_TIME_T(x) ((SfzclTimeT) (x))

/* Return nonzero, if the first second-nanosecond pair is greater (later)
   than the second one. */
#define SFZCL_TIME_MEASURE_GT(sec1, nsec1, sec2, nsec2) \
    ((sec1) > (sec2)) || (((sec1) == (sec2)) && ((nsec1) > (nsec2)))

/* Return nonzero, if the first second-nanosecond pair is less (earlier)
   than the second one. */
#define SFZCL_TIME_MEASURE_LT(sec1, nsec1, sec2, nsec2) \
    ((sec1) < (sec2)) || (((sec1) == (sec2)) && ((nsec1) < (nsec2)))

/* Return nonzero, if first second-nanosecond pair is equal to
   the second one. */
#define SFZCL_TIME_MEASURE_EQ(sec1, nsec1, sec2, nsec2) \
    (((sec1) == (sec2)) && ((nsec1) == (nsec2)))

/*
 * Init time measure structure to initial
 * nonrunning state with zero cumulated time.
 * This can be used instead of sfzcl_time_measure_allocate,
 * if the timer structure is statically allocated by
 * the application.
 */
void
sfzcl_time_measure_init(SfzclTimeMeasure timer)
{
    if (timer)
    {
        timer->running = FALSE;
        timer->start.seconds = 0;
        timer->start.nanoseconds = 0;
        timer->cumulated.seconds = 0;
        timer->cumulated.nanoseconds = 0;
    }
    return;
}

/*
 * Allocates and returns a new nonrunning timer object.
 */
SfzclTimeMeasure
sfzcl_time_measure_allocate(void)
{
    SfzclTimeMeasure timer =
        SPAL_Memory_Calloc(1, sizeof(struct SfzclTimeMeasureRec));

    if (timer)
    {
        sfzcl_time_measure_init(timer);
    }
    return timer;
}

/*
 * Frees an allocated timer object.
 * Returns the time (in seconds), that timer
 * has been running.
 */
void
sfzcl_time_measure_free(SfzclTimeMeasure timer)
{
    SPAL_Memory_Free(timer);
    return;
}

/*
 * Start the timer.
 */
void
sfzcl_time_measure_start(SfzclTimeMeasure timer)
{
    ASSERT(timer != NULL);
    if (sfzcl_time_measure_running(timer))
    {
        return;
    }
    sfzcl_time_measure_system_time(&(timer->start));
    timer->running = TRUE;
    return;
}

/*
 * Stop the timer.
 */
void
sfzcl_time_measure_stop(SfzclTimeMeasure timer)
{
    struct SfzclTimeValRec stop;

    ASSERT(timer != NULL);
    if (!sfzcl_time_measure_running(timer))
    {
        return;
    }
    sfzcl_time_measure_system_time(&stop);
    sfzcl_time_measure_difference(&stop, &(timer->start), &stop);
    sfzcl_time_measure_add(&(timer->cumulated), &(timer->cumulated), &stop);
    timer->running = FALSE;
    return;
}

/*
 * Return TRUE if timer is running.
 */
bool
sfzcl_time_measure_running(SfzclTimeMeasure timer)
{
    ASSERT(timer != NULL);
    if (timer)
    {
        return timer->running;
    }
    else
    {
        return FALSE;
    }
}

/*
 * Reset the timer to zero.
 * If timer is running before this call, the timer runs
 * also after reset.
 */
void
sfzcl_time_measure_reset(SfzclTimeMeasure timer)
{
    sfzcl_time_measure_set_value(timer, 0, 0);
    return;
}

/*
 * Set the timer to given value in seconds and nanoseconds (10e-9s).
 * If timer is running before this call, the timer runs
 * also after set operation.
 */
void
sfzcl_time_measure_set_value(SfzclTimeMeasure timer,
    uint64_t seconds, uint32_t nanoseconds)
{
    bool restart;

    ASSERT(timer != NULL);
    if (sfzcl_time_measure_running(timer))
    {
        restart = TRUE;
        sfzcl_time_measure_stop(timer);
    }
    else
    {
        restart = FALSE;
    }
    sfzcl_time_measure_init(timer);
    timer->cumulated.seconds = seconds;
    timer->cumulated.nanoseconds = nanoseconds;
    if (restart)
    {
        sfzcl_time_measure_start(timer);
    }
    return;
}

/*
 * Get the cumulated running time of the timer.
 * Timer can be either runnung or stopped.
 */
void
sfzcl_time_measure_get_value(SfzclTimeMeasure timer,
    uint64_t *seconds, uint32_t *nanoseconds)
{
    struct SfzclTimeMeasureRec tmp_timer = *timer;

    sfzcl_time_measure_stop(&tmp_timer);
    if (seconds != NULL)
    {
        *seconds = tmp_timer.cumulated.seconds;
    }
    if (nanoseconds != NULL)
    {
        *nanoseconds = tmp_timer.cumulated.nanoseconds;
    }
    return;
}

/*
 * Get the cumulated running time of the timer in seconds.
 * Be aware that depending on SfzclTimeT, timer can overwrap
 * at some point.
 */
SfzclTimeT
sfzcl_time_measure_get(SfzclTimeMeasure timer, SfzclTimeGranularity granularity)
{
    uint64_t seconds;
    uint32_t nanoseconds;

    sfzcl_time_measure_get_value(timer, &seconds, &nanoseconds);
    switch (granularity)
    {
    case SFZCL_TIME_GRANULARITY_NANOSECOND:
        return ((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds)) *
                (SfzclTimeT) 1000000000) + (((SfzclTimeT) nanoseconds));
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_MICROSECOND:
        return ((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds)) *
                (SfzclTimeT) 1000000) + (((SfzclTimeT) nanoseconds) /
                                         (SfzclTimeT) 1000);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_MILLISECOND:
        return ((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds)) *
                (SfzclTimeT) 1000) + (((SfzclTimeT) nanoseconds) /
                                      (SfzclTimeT) 1000000);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_SECOND:
        return ((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
               (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_MINUTE:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) 60);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_HOUR:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) (60 * 60));
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_DAY:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) (60 * 60 * 24));
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_WEEK:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) (60 * 60 * 24 * 7));
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_MONTH_SIDEREAL:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) 2360592);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_MONTH_SYNODIC:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) 2551443);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_YEAR_ANOMALISTIC:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) 31558433);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_YEAR_TROPICAL:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) 31556926);
    /*NOTREACHED*/         case SFZCL_TIME_GRANULARITY_YEAR_SIDEREAL:
        return (((SFZCL_UINT64_TO_SFZCL_TIME_T(seconds))) +
                (((SfzclTimeT) nanoseconds) / (SfzclTimeT) 1000000000)) /
               ((SfzclTimeT) 31558149);
    /*NOTREACHED*/         default:
        L_DEBUG(LF_CERTLIB, "sfzcl_time_measure_get: Bad granularity.");
        return (SfzclTimeT) 0;
        /*NOTREACHED*/ }
    /*NOTREACHED*/ }

/*
 * Calculate difference between time values beg and end and store result
 * to ret.
 */

void
sfzcl_time_measure_difference(SfzclTimeVal ret, SfzclTimeVal beg,
    SfzclTimeVal end)
{
    ASSERT(beg != NULL);
    ASSERT(end != NULL);
    if (SFZCL_TIME_MEASURE_LT(end->seconds, end->nanoseconds,
            beg->seconds, beg->nanoseconds))
    {
        L_DEBUG(LF_CERTLIB,
            "Negative time difference: beg(%lu %lu) > end(%lu %lu).",
            (unsigned long) beg->seconds, (unsigned long) beg->nanoseconds,
            (unsigned long) end->seconds, (unsigned long) end->nanoseconds);
        if ((end->seconds + 20) < beg->seconds)
        {
            L_DEBUG(LF_CERTLIB,
                "sfzcl_time_measure_difference: Negative difference.");
        }
        if (ret != NULL)
        {
            ret->seconds = 0;
            ret->nanoseconds = 0;
        }
        return;
    }
    if (ret == NULL)
    {
        return;
    }

    if (beg->nanoseconds <= end->nanoseconds)
    {
        ret->seconds = end->seconds - beg->seconds;
        ret->nanoseconds = end->nanoseconds - beg->nanoseconds;
    }
    else
    {
        ret->seconds = end->seconds - beg->seconds - 1;
        ret->nanoseconds = (((uint32_t) 1000000000) +
                            (end->nanoseconds - beg->nanoseconds));
    }
    return;
}

/*
 * Add time values tv1 and tv2 together and store result to
 * ret (if ret != NULL).
 */
void
sfzcl_time_measure_add(SfzclTimeVal ret, SfzclTimeVal tv1, SfzclTimeVal tv2)
{
    ASSERT(tv1 != NULL);
    ASSERT(tv2 != NULL);
    if (ret == NULL)
    {
        return;
    }
    ret->seconds = tv1->seconds + tv2->seconds;
    ret->nanoseconds = tv1->nanoseconds + tv2->nanoseconds;
    if (ret->nanoseconds >= (uint32_t) 1000000000)
    {
        ret->nanoseconds -= (uint32_t) 1000000000;
        ret->seconds++;
    }
    return;
}

/*
 * A function implementing system time queries for different platforms.
 * Be aware that granularity of time measurement may vary on different
 * hardware and operating systems.  Returns FALSE, if system time can't
 * be retrieved (i.e. system call fails).  This function returns time
 * measured from arbitrary moment in the past.  This can be time of
 * last boot or some other random epoch.
 */
bool
sfzcl_time_measure_system_time(SfzclTimeVal timeval)
{

    SfzclTime tv;

    tv = sfzcl_time();
    if (timeval != NULL)
    {
        timeval->seconds = (uint64_t) tv;
        timeval->nanoseconds = (uint32_t) 0;
    }
    return TRUE;

}

/* end of file sfzcltimemeasure.c */
