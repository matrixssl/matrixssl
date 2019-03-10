/**
 *      @file    corelib_date.c
 *      @version $Format:%h%d$
 *
 *      Broken down date support.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#include "osdep_stdio.h"
#include "coreApi.h"
#include "osdep.h"
#include "psUtil.h"
#include "corelib_main.h"
#include "osdep_time.h"
#include "osdep_time_gmtime_r.h"
#include "osdep_strict.h"

/* 32-bit Unix machines may need workaround for Year 2038 (and beyond).
   64-bit Unix machines generally use large enough time_t. */
#if !defined __LP64__ && !defined __ILP64__
# ifndef NO_UNIX_Y2038_WORKAROUND
#  define USE_UNIX_Y2038_WORKAROUND 1
# endif
#endif

/* A wrapper for time(). */
PSPUBLIC psTimeSeconds_t psGetEpochTime()
{
    psTimeSeconds_t t = time(NULL);

    return t;
}

/******************************************************************************/
/*
    Get broken-down time, similar to time returned by gmtime(), but avoiding
    the race condition. The function only applies offset if it does not cause
    overflow.
 */
PSPUBLIC int32 psBrokenDownTimeImportSeconds(psBrokenDownTime_t *t,
                                             psTimeSeconds_t s)
{
    int32 ret = PS_FAILURE;
    struct tm *tm;
    psTimeSeconds_t time = s;

    /* Use Gmtime_r if it exists. */
#ifdef Gmtime_r
    /* Note: This command assumes psBrokenDownTime_t and struct tm use
       exactly the same representation. If you optimize storage space of
       psBrokenDownTime_t, then transfer each field separately. */
    tm = Gmtime_r(&time, t);

    if (tm != NULL)
    {
        ret = PS_SUCCESS;
    }
#else
    /* No Gmtime_r, use gmtime. To prevent multithreading problems,
       use locking. */

    /* Use mutex to lock if multithreading is enabled. */
# ifdef USE_MULTITHREADING
    int32 ret2 = psCoreLibInternalLock();
    if (ret2 < 0)
    {
        return ret2;
    }
# endif
    tm = Gmtime(&time);
    if (tm)
    {
        /* Note: This command assumes psBrokenDownTime_t and struct tm use
           exactly the same representation. If you optimize storage space of
           psBrokenDownTime_t, then transfer each field separately. */
        Memcpy(t, tm, sizeof(*t));
        ret = PS_SUCCESS;
    }
# ifdef USE_MULTITHREADING
    psCoreLibInternalUnlock(ret2);
# endif
#endif

#ifdef USE_UNIX_Y2038_WORKAROUND
    /* Workaround for time_t overflow in 2038 on 32-bit Linux/Unix: */
    if (time < 0 && t->tm_year < 70)
    {
        /* Overflow of dat has occurred. Fix the date, using
           psBrokenDownTimeAdd(). This may possibly result in an estimate
           because the computation here does not know of details like
           leap seconds assigned in future. The result should be precise to
           few seconds. */
        /* Note: Adjustment in three parts, because adjustment is too large
           to be processed at once.
           Note: 0x100000000 == 883612800 * 4 + 760516096. */
        (void) psBrokenDownTimeAdd(t, 883612800 * 2);
        (void) psBrokenDownTimeAdd(t, 883612800 * 2);
        (void) psBrokenDownTimeAdd(t, 760516096);
    }
#endif /* USE_UNIX_Y2038_WORKAROUND */
    return ret;
}

/*
    Get broken-down time, similar to time returned by gmtime(), but avoiding
    the race condition. The function only applies offset if it does not cause
    overflow.
 */
PSPUBLIC int32 psGetBrokenDownGMTime(psBrokenDownTime_t *t, int offset)
{
    int32 ret;
    psTimeSeconds_t current_time;
    psTimeSeconds_t offseted_time;

    current_time = psGetEpochTime();
    if (current_time == ((psTimeSeconds_t) -1))
    {
        return PS_FAILURE;
    }

    /* Handle negative offsets here. */
    offseted_time = ((psTimeSeconds_t) current_time) + offset;
    /* In case of overflow or positive offset, use time without offset. */
    if ((offset < 0 && offseted_time > current_time) || (offset > 0))
    {
        offseted_time = current_time;
    }

    ret = psBrokenDownTimeImportSeconds(t, offseted_time);
    /* Handle positive offsets here. */
    if (ret == PS_SUCCESS && offset > 0)
    {
        ret = psBrokenDownTimeAdd(t, offset);
    }
    return ret;
}

/* Compute number of days in month. */
static int mdays(const psBrokenDownTime_t *t)
{
    static unsigned char days_tab[] = {
        /* Jan */ 31, /* Most Feb */ 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    unsigned char days;

    if (t->tm_mon > 11)
    {
        return -1;
    }
    days = days_tab[t->tm_mon];
    if (days == 28)
    {
        /* Note: This computation does not consider possible corrections once
           every 3200 years. */
        int year = t->tm_year + 1900;
        int is_leap_year = (year % 4) == 0 &&
                           ((year % 100) != 0 || (year % 400) == 0);
        days += is_leap_year;
    }
    return days;
}

/******************************************************************************/
/*
    Compute broken-down time, with specified offset. The initial broken
    down time t must have been previously initialized. This function only
    needs to support positive offset (including 0).
 */
PSPUBLIC int32 psBrokenDownTimeAdd(psBrokenDownTime_t *res, int32 offset)
{
    if (offset < 0)
    {
        return PS_FAILURE;
    }

    /* Quick path for multiples of 28 years. */
    while (offset > 883612800)
    {
        /* Quick addition of exactly 28 years (the cycle of Gregorian calendar,
           7 * 4 * 365.25 * 24 * 60 * 60 seconds). */
        offset -= 883612800;
        res->tm_year += 28;
    }

    if (offset == 0)
    {
        return PS_SUCCESS;
    }

    /* Note: this function is approximate in presence of leap seconds. */
    res->tm_sec += offset;
    if (res->tm_sec >= 60)
    {
        res->tm_min += res->tm_sec / 60;
        res->tm_sec %= 60;
    }
    if (res->tm_min >= 60)
    {
        res->tm_hour += res->tm_min / 60;
        res->tm_min %= 60;
    }
    if (res->tm_hour >= 24)
    {
        res->tm_mday += res->tm_hour / 24;
        res->tm_wday += res->tm_hour / 24;
        res->tm_wday %= 7;
        res->tm_hour %= 24;
    }
    /* Do month days, months & years as a loop. */
    while (res->tm_mday > mdays(res))
    {
        res->tm_mday -= mdays(res);
        res->tm_mon += 1;
        if (res->tm_mon > 11)
        {
            res->tm_mon -= 12;
            res->tm_year++;
        }
        /* Note: tm_yday is not updated. */
        res->tm_hour %= 60;
    }
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Format BrokenDown Time String with 4 digit year.
    The string format will be "YYYYMMDDHHMMSSZ". Z and NIL are included.
 */
PSPUBLIC int32 psBrokenDownTimeStr(const psBrokenDownTime_t *t,
    char (*string)[PS_BROKENDOWN_TIME_STR_LEN])
{
    size_t len = Strftime(*string, PS_BROKENDOWN_TIME_STR_LEN,
        "%Y%m%d%H%M%SZ", t);

    return len == PS_BROKENDOWN_TIME_STR_LEN - 1 ? PS_SUCCESS : PS_FAILURE;
}

/*
    Format BrokenDown Time String with 2 digit year.
    The string format will be "YYMMDDHHMMSSZ". Z and NIL are included.
 */
PSPUBLIC int32 psBrokenDownTimeStrTwoDigitYear(const psBrokenDownTime_t *t,
    char (*string)[PS_BROKENDOWN_TIME_STR_LEN])
{
    size_t len = Strftime(*string, PS_BROKENDOWN_TIME_STR_LEN,
        "%y%m%d%H%M%SZ", t);

    return len == PS_BROKENDOWN_TIME_STR_LEN - 3 ? PS_SUCCESS : PS_FAILURE;
}

/* Helper function to read specified amount of digits.
   The number read shall be within boundaries. On parse errors function returns
   (unsigned) -1, otherwise the parsed number. */
static unsigned parse_digits(
    const unsigned char **c_p,
    unsigned digits, unsigned minimum, unsigned maximum)
{
    const unsigned char *c = *c_p;
    unsigned result = 0;

    while (digits)
    {
        if (*c < '0' || *c > '9')
        {
            return (unsigned) -1;
        }
        result *= 10;
        result += *c - '0';
        c++;
        digits--;
    }

    *c_p = c;

    if (result < minimum || result > maximum)
    {
        return (unsigned) -1;
    }

    return result;
}

/******************************************************************************/
/**
    Verify a string has nearly valid date range format and length,
    and return it in broken-down time format.
 */
static unsigned char parsedate_zulu(const unsigned char *p,
    unsigned int time_len,
    unsigned int year_len,
    psBrokenDownTime_t *target,
    int strict)
{
    unsigned year, month, mday, hour, min, sec;
    const unsigned char *c = p;
    psBrokenDownTime_t check_only;
    psBool_t is_indefinite = PS_FALSE;

    if (!target)
    {
        /* Use check_only as target. */
        target = &check_only;
    }

    /* Zeroize all fields as some systems have extra fields
       in struct tm. */
    Memset(target, 0, sizeof(*target));

    if (year_len == 4)
    {
        /* Format shall be YYYYMMDDHHMMSSZ (according to RFC 5280). */
        if (time_len != 15 && strict)
        {
            return 0;
        }
        /* Flexible: allow Z to be replaced with anything. */
        if (time_len < 14 && !strict)
        {
            return 0;
        }
        /* Allow indefinite date specified by RFC 5280. */
        if (time_len == 15 && !memcmp(c, "99991231235959Z", 15))
        {
            is_indefinite = PS_TRUE;
            year = 9999 - 1900;
            c += year_len;
        }
        else
        {
            year = parse_digits(&c, 4, 1900, 2999);
        }
    }
    else if (year_len == 2)
    {
        /* Format shall be YYMMDDHHMMSSZ (according to RFC 5280). */
        if (time_len != 13 && strict)
        {
            return 0;
        }
        if (time_len < 12 && !strict)
        {
            return 0;
        }
        year = parse_digits(&c, 2, 0, 99);
    }
    else
    {
        return 0;
    }

    if (year == (unsigned) -1)
    {
        return 0;
    }

    month = parse_digits(&c, 2, 1, 12);
    if (month == (unsigned) -1)
    {
        return 0;
    }

    mday = parse_digits(&c, 2, 1, 31);
    if (mday == (unsigned) -1)
    {
        return 0;
    }

    hour = parse_digits(&c, 2, 0, 23);
    if (hour == (unsigned) -1)
    {
        return 0;
    }

    min = parse_digits(&c, 2, 0, 59);
    if (min == (unsigned) -1)
    {
        return 0;
    }

    /* This allows up-to 1 leap second.
       (Note: could check that leap second only occurs at 23:59:60 on
        end of Jun 30 or Dec 31 (such as on 31 Dec 2016 23:59:60), but
       rules for insertion of leap seconds may change. */
    sec = parse_digits(&c, 2, 0, 60);
    if (sec == (unsigned) -1)
    {
        return 0;
    }

    /* Require all times in X.509 materials to be Zulu time, as is correct
       according to RFC 5280. */
    if (strict && *c != 'Z')
    {
        return 0;
    }
    else
    {
        /* Ignore time zone. The time zone shall be Zulu according to RFC 5280,
           for X.509 certificates, CRL, OCSP etc. These times will be matched
           exactly. However, some old systems may use certificates with some
           other time zone. When handling those, the times will not be handled
           exactly, but the inaccuracy will be within a day. */
    }

    if (!is_indefinite)
    {
        /* Convert 2 or 4 digit year to tm format (year after 1900).
           Two digit years are interpreted according to RFC 5280. */
        if (year < 50)
        {
            year += 100;
        }
        else if (year >= 1900)
        {
            year -= 1900;
        }
        else if (year >= 100)
        {
            /* years 100-1900 cannot be represented in psBrokenDownTime_t. */
            return 0;
        }
        else
        {
            /* Two digit year 50-99 is already correct. */
        }
    }

    target->tm_year = (int) year;
    target->tm_mon = (int) month - 1;
    target->tm_mday = (int) mday;
    target->tm_hour = (int) hour;
    target->tm_min = (int) min;
    target->tm_sec = (int) sec;
    /* Note: target->tm_wday and target->tm_yday are not set. */
    if (target->tm_mday > mdays(target))
    {
        /* No such day in this month. */
        Memset(target, 0, sizeof(*target));
        return 0;
    }
    return 1;
}

/******************************************************************************/
/*
    Import BrokenDown Time from String format. Number of digits in year
    can be provided via an option. The string format recommended is
    "YYYYMMDDHHMMSSZ".
    This function only supports Zulu time, any other time zone will be ignored.
 */
PSPUBLIC int32 psBrokenDownTimeImport(
    psBrokenDownTime_t *t,
    const char *string, size_t time_string_len,
    unsigned int opts)
{
    unsigned char res;

    /* Reject very long strings as illegal. */
    if (time_string_len > 255)
    {
        return PS_FAILURE;
    }

    res = parsedate_zulu((const unsigned char *) string,
        (unsigned int) time_string_len,
        (opts & PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR) ?
        2 : 4, t,
        (opts & PS_BROKENDOWN_TIME_IMPORT_STRICT_ZULU));

    return res ? PS_SUCCESS : PS_FAILURE;
}

/******************************************************************************/
/*
    Compute broken-down times, returning <0, 0 or >0 according to t1 being
    smaller, equal or greater than t2.
 */
PSPUBLIC int psBrokenDownTimeCmp(const psBrokenDownTime_t *t1,
    const psBrokenDownTime_t *t2)
{
    char s1[PS_BROKENDOWN_TIME_STR_LEN] = { '!', 0 };
    char s2[PS_BROKENDOWN_TIME_STR_LEN] = { 0 };

    /* The dates are represented using YYYYMMDDHHMMSSZ for comparison.
       I.e. comparison ignores tm_wday, tm_yday, and tm_isdst. */
    (void) psBrokenDownTimeStr(t1, &s1);
    (void) psBrokenDownTimeStr(t2, &s2);
    /* If you wish to debug time comparisons, you can enable next lines. */
    /* _psTraceStr("Comparing t1: %s against ", s1); */
    /* _psTraceStr("t2: %s ", s2); */
    /* _psTraceInt("got: %d\n", Memcmp(s1, s2, sizeof(s1))); */
    return Memcmp(s1, s2, sizeof(s1));
}
