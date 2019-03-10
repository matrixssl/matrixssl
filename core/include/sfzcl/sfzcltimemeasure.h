/* sfzcltimemeasure.h
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

/*
   Real time measuring.
 */

#ifndef SFZCLTIMEMEASURE_H
#define SFZCLTIMEMEASURE_H

typedef enum
{
    SFZCL_TIME_GRANULARITY_NANOSECOND = 0,   /* 1/1000000000 seconds */
    SFZCL_TIME_GRANULARITY_MICROSECOND,      /*    1/1000000 seconds */
    SFZCL_TIME_GRANULARITY_MILLISECOND,      /*       1/1000 seconds */
    SFZCL_TIME_GRANULARITY_SECOND,           /*            1 second  */
    SFZCL_TIME_GRANULARITY_MINUTE,           /*           60 seconds */
    SFZCL_TIME_GRANULARITY_HOUR,             /*        60x60 seconds */
    SFZCL_TIME_GRANULARITY_DAY,              /*     24x60x60 seconds */
    SFZCL_TIME_GRANULARITY_WEEK,             /*   7x24x60x60 seconds */
    SFZCL_TIME_GRANULARITY_MONTH_SIDEREAL,   /*      2360592 seconds */
    SFZCL_TIME_GRANULARITY_MONTH_SYNODIC,    /*      2551443 seconds */
    SFZCL_TIME_GRANULARITY_YEAR_ANOMALISTIC, /*     31558433 seconds */
    SFZCL_TIME_GRANULARITY_YEAR_TROPICAL,    /*     31556926 seconds */
    SFZCL_TIME_GRANULARITY_YEAR_SIDEREAL     /*     31558149 seconds */
} SfzclTimeGranularity;

#define SFZCL_TIME_GRANULARITY_MONTH SFZCL_TIME_GRANULARITY_MONTH_SIDEREAL
#define SFZCL_TIME_GRANULARITY_YEAR  SFZCL_TIME_GRANULARITY_YEAR_SIDEREAL

struct SfzclTimeValRec
{
    uint64_t seconds;           /* Overlaps in 584 billion years (if really 64 bits) */
    uint32_t nanoseconds;
};

typedef struct SfzclTimeValRec *SfzclTimeVal;

struct SfzclTimeMeasureRec
{
    struct SfzclTimeValRec start;
    struct SfzclTimeValRec cumulated;
    bool running;
};

typedef struct SfzclTimeMeasureRec *SfzclTimeMeasure, SfzclTimeMeasureStruct;

/*
 * SfzclTimeT is a return type for functions returning seconds,
 * milliseconds etc.  In systems that do not support floating
 * point numbers, it is always an integer type.  Otherwise
 * it can be either double precision floating point number or
 * some integer type.
 */

#ifdef VXWORKS
# undef HAVE_DOUBLE_FLOAT
#endif

#ifdef HAVE_DOUBLE_FLOAT
typedef double SfzclTimeT;
#else
typedef int64_t SfzclTimeT;
#endif

/*
 * Maximum value of time stamp.  Time stamps never overwrap.
 * They stop at SFZCL_TIME_STAMP_MAX if maximum value
 * is exceeded.
 */
#define SFZCL_TIME_STAMP_MAX      (~((uint64_t) 0))

/*
 * Can be used to initialize statically allocated timer.
 * No separate `init' or `uninit' is needed, if this
 * method is used.
 *
 * e.g. `static struct SfzclTimeMeasure timer =
 *                                      SFZCL_TIME_MEASURE_INITIALIZER;'
 */
#define SFZCL_TIME_MEASURE_INITIALIZER { { 0, 0 }, { 0, 0 }, FALSE }

/*
 * Init time measure structure to initial
 * nonrunning state with zero cumulated time.
 * This can be used instead of sfzcl_time_measure_allocate,
 * if the timer structure is statically allocated by
 * the application.  In this case, no `uninit' function
 * is needed.  It is also initialize statically allocated
 * timer structure with SFZCL_TIME_MEASURE_INITIALIZER.
 */
void sfzcl_time_measure_init(SfzclTimeMeasure timer);

/*
 * Allocates and returns a new nonrunning timer object.
 */
SfzclTimeMeasure sfzcl_time_measure_allocate(void);

/*
 * Frees an allocated timer object.
 */
void sfzcl_time_measure_free(SfzclTimeMeasure timer);

/*
 * Start the timer.
 */
void sfzcl_time_measure_start(SfzclTimeMeasure timer);

/*
 * Stop the timer.
 */
void sfzcl_time_measure_stop(SfzclTimeMeasure timer);

/*
 * Return TRUE if timer is running.
 */
bool sfzcl_time_measure_running(SfzclTimeMeasure timer);

/*
 * Reset the timer to zero.
 * If timer is running before this call, the timer runs
 * also after reset.
 */
void sfzcl_time_measure_reset(SfzclTimeMeasure timer);

/*
 * Set the timer to given value in seconds and nanoseconds (10e-9s).
 * If timer is running before this call, the timer runs
 * also after set operation.
 */
void sfzcl_time_measure_set_value(SfzclTimeMeasure timer,
                                  uint64_t seconds, uint32_t nanoseconds);

/*
 * Get the cumulated running time of the timer.
 * Timer can be either runnung or stopped.
 */
void sfzcl_time_measure_get_value(SfzclTimeMeasure timer,
                                  uint64_t *seconds, uint32_t *nanoseconds);

/*
 * Return a time stamp from timer.  Values returned by this function
 * never overwrap.  Instead if maximum timer value is exceeded,
 * SFZCL_TIME_STAMP_MAX is always returned.
 */
uint64_t sfzcl_time_measure_stamp(SfzclTimeMeasure timer,
                                  SfzclTimeGranularity granularity);
/*
 * Get the cumulated running time of the timer in seconds.
 * Be aware that depending on SfzclTimeT, timer can overwrap
 * at some point.
 */
SfzclTimeT sfzcl_time_measure_get(SfzclTimeMeasure timer,
                                  SfzclTimeGranularity granularity);

/*
 * Calculate difference between time values beg and end and store
 * result to ret.
 */
void sfzcl_time_measure_difference(SfzclTimeVal ret,
                                   SfzclTimeVal beg, SfzclTimeVal end);

/*
 * Add time values tv1 and tv2 together and store result to ret.
 */
void sfzcl_time_measure_add(SfzclTimeVal ret, SfzclTimeVal tv1,
                            SfzclTimeVal tv2);

/*
 * A function implementing system time queries for different platforms.
 * Be aware that granularity of time measurement may vary on different
 * hardware and operating systems.  Returns FALSE, if system time can't
 * be retrieved (i.e. system call fails).  This function returns time
 * measured from arbitrary moment in the past.  This can be time of
 * last boot or some other random epoch.
 */
bool sfzcl_time_measure_system_time(SfzclTimeVal timeval);

#endif                          /* ! SFZCLTIMEMEASURE_H */
/* eof (sfzcltimemeasure.h) */
