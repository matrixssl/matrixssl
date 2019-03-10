/* sfzclcalendar.c
 *
 * Description: Calendar time retrieval and manipulation.
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

#include "sfzclincludes.h"
#include "sfzclgetput.h"
#include "implementation_defs.h"
#include "osdep_stdio.h"

/* Returns seconds that local timezone is east from the UTC meridian
   and bool which is TRUE if DST is in effect.
   This one is system dependent and yet even vulnerable to Y2K bug.
   Anyway, this is used only to retrieve current timezone.  If
   localtime(3) function freaks out with this call, we return just zero
   and assume that our localtime is UTC. */
static
void sfzcl_get_local_timezone(SfzclTime tv, int32_t *utc_offset, bool *dst);

/* Array that tells how many days each month of the year have.
   Variable monthday[1] has to be fixed to 28 or 29 depending
   on the year we are referring to. */
static const uint8_t monthdays[12] = { 31, 28, 31, 30, 31, 30,
                                       31, 31, 30, 31, 30, 31 };

/* Arrays of weekday and month names.  These are used by
   sfzcl_readable_time_string to generate ctime(3) like
   output string from the SfzclTime value. */
static const char *sfzcl_time_abbr_day[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", NULL
};

static const char *sfzcl_time_abbr_month[] = {
    "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec",
    NULL
};

/* Check if a year is a leap year (i.e. 29 days in February, 366 days in year)
   according to gregorian calendar.
     - Every year divisible by 400 is a leap year.
     - Year divisible by 4 is a leap year, if it is NOT divisible by 100.
     - Otherwise year is not a leap year.
 */
#define SFZCL_IS_LEAP_YEAR(y) ((((y) % 400) == 0) || \
                               ((((y) % 4) == 0) && (((y) % 100) != 0)))

/* Fills the calendar structure according to ``current_time''.  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
void
sfzcl_calendar_time(SfzclTime input_time,
    SfzclCalendarTime calendar_ret, bool local_time)
{
    /*
     * Naive implementation of calendar time.  This implementation
     * ignores timezones and leap seconds but is otherwise
     * (way beyond) Y2K compatible.
     * This implementation follows the Gregorian calendar even before
     * the Gregorian calendar was invented.  This is really not right
     * if we want to present dates before the 17th century.
     */
    int64_t day;
    int64_t sec;

    if (local_time)
    {
        sfzcl_get_local_timezone(input_time,
            &(calendar_ret->utc_offset),
            &(calendar_ret->dst));
        input_time += (SfzclTime) (calendar_ret->utc_offset);
    }
    else
    {
        calendar_ret->utc_offset = 0;
        calendar_ret->dst = FALSE;
    }
    if (input_time >= 0)
    {
        /* Calculate day of the year and second of the day.  Weekday
           calculation is based on the fact that 1.1.1970 (the epoch day)
           was Thursday. */
        day = input_time / 86400;
        sec = input_time % 86400;
        calendar_ret->weekday = (uint8_t) ((day + 4) % 7);
    }
    else
    {
        /* Ensure that we have positive day of the year, second of the
           day and day of the week also if we have negative time value
           measured from the epoch. */
        day = (-(((-input_time) - 1) / 86400)) - 1;
        sec = 86399 - (((-input_time) - 1) % 86400);
        calendar_ret->weekday = (uint8_t) (6 - (((-day) + 2) % 7));
    }
    /* Start calculation from the epoch year.  If we are on the negative side
       or more than 400 years beyond 1970, we adjust the year so that we
       need to iterate only years from the last even 400 years.
       146097 is the number of days in each 400 years in Gregorian era. */
    calendar_ret->year = 1970;
    if (day < 0)
    {
        day = -day;
        calendar_ret->year -= (uint32_t) (((day / 146097) * 400) + 400);
        day = -((day % 146097) - 146097);
    }
    else if (day >= 146097)
    {
        calendar_ret->year += (uint32_t) ((day / 146097) * 400);
        day = day % 146097;
    }
    /* Iterate years until we have number of days that fits in the
       ``current'' year. */
    do
    {
        if (day < (365 + (SFZCL_IS_LEAP_YEAR(calendar_ret->year) ? 1 : 0)))
        {
            break;
        }
        day -= 365 + (SFZCL_IS_LEAP_YEAR(calendar_ret->year) ? 1 : 0);
        calendar_ret->year++;
    }
    while (1);
    /* There is no year 0. */
    if (calendar_ret->year <= 0)
    {
        calendar_ret->year -= 1;
    }
    /* Day of the year we got as a by product of year calculation. */
    calendar_ret->yearday = (uint16_t) day;
    /* Now we can trivially calculate seconds, minutes and hours. */
    calendar_ret->second = (uint8_t) (sec % 60);
    calendar_ret->minute = (uint8_t) ((sec % 3600) / 60);
    calendar_ret->hour = (uint8_t) (sec / 3600);
    /* Now we iterate the month.  Leap years make this a bit bitchy. */
    calendar_ret->month = 0;
    do
    {
        ASSERT(calendar_ret->month < 12);
        if (day < (monthdays[calendar_ret->month] +
                   (((calendar_ret->month == 1) &&
                     (SFZCL_IS_LEAP_YEAR(calendar_ret->year))) ? 1 : 0)))
        {
            break;
        }
        day -= (monthdays[calendar_ret->month] +
                (((calendar_ret->month == 1) &&
                  (SFZCL_IS_LEAP_YEAR(calendar_ret->year))) ? 1 : 0));
        calendar_ret->month++;
    }
    while (1);
    /* Day of the month is a leftover from the month calculation. */
    calendar_ret->monthday = (uint8_t) (day + 1);
    return;
}

int
sfzcl_time_format(unsigned char *buf, int buf_size, SfzclTime input_time)
{
    struct SfzclCalendarTimeRec calendar[1];

    sfzcl_calendar_time(input_time, calendar, FALSE);
    return Snprintf((char *) buf, buf_size, "%04d%02d%02d%02d%02d%02d",
        (int) calendar->year,
        (int) calendar->month + 1,
        (int) calendar->monthday,
        (int) calendar->hour,
        (int) calendar->minute, (int) calendar->second);
}

/* Return time string in RFC-2550 compatible format.  Returned string
   is allocated with sfzcl_xmalloc and has to be freed with sfzcl_xfree by
   the caller.  This implementation is only a subset of RFC-2550 and
   is valid only between years 0-9999.  Fix this before Y10K problem
   is imminent. */
char *
sfzcl_time_string(SfzclTime input_time)
{
    unsigned char temp[100];

    sfzcl_time_format(temp, sizeof(temp), input_time);

    return sfzcl_strdup(temp);
}

char *
sfzcl_readable_time_string(SfzclTime input_time, bool local_time)
{
    struct SfzclCalendarTimeRec calendar[1];
    char zoneid[8];
    char temp[100];

    sfzcl_calendar_time(input_time, calendar, local_time);

    if (calendar->utc_offset == 0)
    {
        zoneid[0] = '\0';
    }
    else if (calendar->utc_offset > 0)
    {
        Snprintf(zoneid, sizeof(zoneid), " +%02d%02d",
                 (int) ((calendar->utc_offset / 3600) % 100),
                 (int) ((calendar->utc_offset / 60) % 60));
    }
    else
    {
        Snprintf(zoneid, sizeof(zoneid), " -%02d%02d",
            (int) (((-calendar->utc_offset) / 3600) % 100),
            (int) (((-calendar->utc_offset) / 60) % 60));
    }

    Snprintf(temp, sizeof(temp), "%s %s %02d %04d %02d:%02d:%02d%s",
        sfzcl_time_abbr_day[calendar->weekday % 7],
        sfzcl_time_abbr_month[calendar->month % 12],
        (int) calendar->monthday,
        (int) calendar->year,
        (int) calendar->hour,
        (int) calendar->minute, (int) calendar->second, zoneid);
    return sfzcl_strdup(temp);
}

/* Returns seconds that local timezone is east from the UTC meridian
   and bool which is TRUE if DST is in effect.
   This one is system dependent and yet even vulnerable to Y2K bug.
   Anyway, this is used only to retrieve current timezone.  If
   localtime(3) function freaks out with this call, we return just zero
   and assume that our localtime is UTC. */
static
void
sfzcl_get_local_timezone(SfzclTime tv, int32_t *utc_offset, bool *dst)
{
#if !defined (USE_SFZCL_INTERNAL_LOCALTIME) && defined (HAVE_LOCALTIME)
    struct tm *tm;
# if defined(_REENTRANT) && defined(__sun__) && defined(__svr4__)
    struct tm tms;
# endif
    time_t t;
    struct SfzclCalendarTimeRec ct[1];

    /* We trust localtime(3) for dst interpretation 1970-2037.
       Before this timeframe, we just check localtime for
       Jan 1 1998, which should work more or less everywhere.
       After 2037 we normalize this date to year 2037 and
       call system localtime(3) for that. */
    if ((tv > ((SfzclTime) 0)) && (tv < ((SfzclTime) 2145916800)))
    {
        t = (time_t) tv;
    }
    else if (tv >= ((SfzclTime) 2145916800))
    {
        sfzcl_calendar_time(tv, ct, FALSE);
        if (SFZCL_IS_LEAP_YEAR(ct->year))
        {
            t = (time_t) 2082758400;    /* 1.1.2036 */
        }
        else
        {
            t = (time_t) 2114380800;    /* 1.1.2037 */
        }
        t += ((((time_t) 86400) * ((time_t) (ct->yearday))) +
              (((time_t) 3600) * ((time_t) (ct->hour))) +
              (((time_t) 60) * ((time_t) (ct->minute))) +
              ((time_t) (ct->second)));
    }
    else
    {
        t = (time_t) 883656061; /* Thu Jan 1 12:01:01 1998 UTC */
    }
# if defined(_REENTRANT) && defined(__sun__) && defined(__svr4__)
    tm = localtime_r(&t, &tms);
# else
#  undef localtime
    tm = localtime(&t);
# endif
# ifdef HAVE_TM_GMTOFF_IN_STRUCT_TM
    if ((tm != NULL) && (tm->tm_gmtoff >= (-50400)) && (tm->tm_gmtoff <= 50400))
    {
        if (utc_offset != NULL)
        {
            *utc_offset = (int32_t) (tm->tm_gmtoff);
        }
    }
    else
    {
        if (utc_offset != NULL)
        {
            *utc_offset = (int32_t) 0;
        }
    }
# else                          /* HAVE_TM_GMTOFF_IN_STRUCT_TM */
#  ifdef HAVE_OLD_TM_GMTOFF_IN_STRUCT_TM
    if ((tm != NULL) &&
        (tm->__tm_gmtoff__ >= (-50400)) && (tm->__tm_gmtoff__ <= 50400))
    {
        if (utc_offset != NULL)
        {
            *utc_offset = (int32_t) (tm->__tm_gmtoff__);
        }
    }
    else
    {
        if (utc_offset != NULL)
        {
            *utc_offset = (int32_t) 0;
        }
    }
#  else                         /* HAVE_OLD_TM_GMTOFF_IN_STRUCT_TM */
#   ifdef HAVE_EXTERNAL_TIMEZONE
    if ((timezone >= (-50400)) && (timezone <= 50400))
    {
        if (utc_offset != NULL)
        {
            *utc_offset = (int32_t) -timezone;
        }
    }
    else
    {
        if (utc_offset != NULL)
        {
            *utc_offset = (int32_t) 0;
        }
    }
#   else                        /* HAVE_EXTERNAL_TIMEZONE */
    if (utc_offset != NULL)
    {
        *utc_offset = (int32_t) 0;
    }
#   endif                       /* HAVE_EXTERNAL_TIMEZONE */
#  endif                        /* HAVE_OLD_TM_GMTOFF_IN_STRUCT_TM */
# endif                         /* HAVE_TM_GMTOFF_IN_STRUCT_TM */
# ifdef HAVE_TM_ISDST_IN_STRUCT_TM
    if (tm != NULL)
    {
        if (dst != NULL)
        {
            *dst = (tm->tm_isdst != 0);
        }
    }
    else
    {
        if (dst != NULL)
        {
            *dst = FALSE;
        }
    }
# else                          /* HAVE_TM_ISDST_IN_STRUCT_TM */
    if (dst != NULL)
    {
        *dst = FALSE;
    }
# endif                         /* HAVE_TM_ISDST_IN_STRUCT_TM */
#else                           /* ! defined (USE_SFZCL_INTERNAL_LOCALTIME) &&
                                   defined (HAVE_LOCALTIME) */

    /* Parameter tv not used if localtime() function is not being used. */
    PARAMETER_NOT_USED(tv);

    if (utc_offset != NULL)
    {
        *utc_offset = (int32_t) 0;
    }
    if (dst != NULL)
    {
        *dst = FALSE;
    }
#endif                          /* ! defined (USE_SFZCL_INTERNAL_LOCALTIME) &&
                                   defined (HAVE_LOCALTIME) */
}

/* Convert SfzclCalendarTime to SfzclTime. If the dst is set to TRUE then
   daylight saving time is assumed to be set, if dst field is set to FALSE
   then it is assumed to be off.

   Weekday and yearday fields are ignored in the conversion, but filled with
   approriate values during the conversion. All other values are normalized to
   their normal range during the conversion.

   If the local_time is set to TRUE then dst and utc_offset values
   are ignored.

   If the time cannot be expressed as SfzclTime this function returns FALSE,
   otherwise returns TRUE. */
bool
sfzcl_make_time(SfzclCalendarTime calendar_time, SfzclTime *time_return,
    bool local_time)
{
    SfzclCalendarTimeStruct test_time;
    SfzclTime estimate;

    /* Normalize values first */
    while (calendar_time->second > 59)
    {
#ifdef DEBUG
        L_DEBUG(LF_CERTLIB, "Seconds too large, adjusting %d",
            calendar_time->second);
#endif
        calendar_time->second -= 60;
        calendar_time->minute++;
    }
    while (calendar_time->minute > 59)
    {
#ifdef DEBUG
        L_DEBUG(LF_CERTLIB, "Minutes too large, adjusting %d",
            calendar_time->minute);
#endif
        calendar_time->minute -= 60;
        calendar_time->hour++;
    }
    while (calendar_time->hour > 23)
    {
#ifdef DEBUG
        L_DEBUG(LF_CERTLIB, "Hours too large, adjusting %d",
            calendar_time->hour);
#endif
        calendar_time->hour -= 24;
        calendar_time->monthday++;
    }
    do
    {
        int days_per_month;

        while (calendar_time->month > 11)
        {
#ifdef DEBUG
            L_DEBUG(LF_CERTLIB, "Month too large, adjusting %d",
                calendar_time->month);
#endif
            calendar_time->month -= 12;
            calendar_time->year++;
        }
        days_per_month = monthdays[calendar_time->month] +
                         ((calendar_time->month == 1 &&
                           SFZCL_IS_LEAP_YEAR(calendar_time->year)) ? 1 : 0);
        if (calendar_time->monthday > days_per_month)
        {
#ifdef DEBUG
            L_DEBUG(LF_CERTLIB, "Month day too large, adjusting %d",
                calendar_time->monthday);
#endif
            calendar_time->monthday -= days_per_month;
            calendar_time->month++;
        }
        else if (calendar_time->monthday == 0)
        {
#ifdef DEBUG
            L_DEBUG(LF_CERTLIB, "Month day zero, adjusting %d",
                calendar_time->monthday);
#endif
            if (calendar_time->month == 0)
            {
                calendar_time->month = 11;
                calendar_time->year--;
            }
            else
            {
                calendar_time->month--;
            }
            calendar_time->monthday = monthdays[calendar_time->month] +
                                      ((calendar_time->month == 1 &&
                                        SFZCL_IS_LEAP_YEAR(calendar_time->year)) ? 1 : 0);
        }
        else
        {
            break;
        }
    }
    while (1);


    /* Calculate estimate */
    estimate = calendar_time->monthday - 1 +
               30 * calendar_time->month +
               365 * (calendar_time->year - 1970) + ((calendar_time->year - 1970) / 4);
    estimate *= 24;
    estimate += calendar_time->hour;
    estimate *= 60;
    estimate += calendar_time->minute;
    estimate *= 60;
    estimate += calendar_time->second;

    do
    {
        /* L_DEBUG(LF_CERTLIB,  "Estimate is %ld", */
        /*                            (unsigned long) estimate); */
        sfzcl_calendar_time(estimate, &test_time, FALSE);
        /* L_DEBUG(LF_CERTLIB, */
        /*           "Compare time is %04d-%02d-%02d %02d:%02d:%02d", */
        /*          test_time.year, test_time.month + 1, test_time.monthday, */
        /*        test_time.hour, test_time.minute, test_time.second); */

        if (test_time.year == calendar_time->year &&
            test_time.month == calendar_time->month &&
            test_time.monthday == calendar_time->monthday &&
            test_time.hour == calendar_time->hour &&
            test_time.minute == calendar_time->minute &&
            test_time.second == calendar_time->second)
        {
            break;
        }
        if (test_time.year == calendar_time->year &&
            test_time.month == calendar_time->month &&
            test_time.monthday == calendar_time->monthday)
        {
            if (test_time.hour != calendar_time->hour)
            {
                estimate += (calendar_time->hour - test_time.hour) * 3600;
            }
            if (test_time.minute != calendar_time->minute)
            {
                estimate += (calendar_time->minute - test_time.minute) * 60;
            }
            if (test_time.hour != calendar_time->hour)
            {
                estimate += (calendar_time->second - test_time.second);
            }
            continue;
        }
        if (test_time.year != calendar_time->year)
        {
            estimate += (calendar_time->year - test_time.year) * 365 * 86400;
            continue;
        }
        if (test_time.month != calendar_time->month)
        {
            estimate += (calendar_time->month - test_time.month) * 28 * 86400;
            continue;
        }
        if (test_time.monthday != calendar_time->monthday)
        {
            estimate += (calendar_time->monthday - test_time.monthday) * 86400;
            continue;
        }
#ifdef DEBUG
        L_DEBUG(LF_CERTLIB, "Internal error in sfzcl_make_time");
#endif
        return FALSE;
    }
    while (1);

    if (local_time)
    {
        estimate += calendar_time->utc_offset;
        if (calendar_time->dst == TRUE)
        {
            estimate += 3600;
        }
    }
    /* L_DEBUG(LF_CERTLIB,  "Result is %ld", (unsigned long) estimate); */
    *time_return = estimate;
    calendar_time->yearday = test_time.yearday;
    calendar_time->weekday = test_time.weekday;
    return TRUE;
}

/* end of file sfzclcalendar.c */
