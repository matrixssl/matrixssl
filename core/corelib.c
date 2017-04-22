/**
 *      @file    corelib.c
 *      @version $Format:%h%d$
 *
 *      Open and Close APIs and utilities for Matrix core library.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
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

#include "coreApi.h"
#include "osdep.h"
#include "psUtil.h"

#ifdef USE_MULTITHREADING
/* A mutex for concurrency control of functions implemented in this file.
   Obvious exception are psCoreOpen() and psCoreClose(). */
static psMutex_t corelibMutex;
#endif /* USE_MULTITHREADING */

/******************************************************************************/
/*
    Open (initialize) the Core module
    The config param should always be passed as:
        PSCORE_CONFIG
 */
static char g_config[32] = "N";

/******************************************************************************/
int32 psCoreOpen(const char *config)
{
    if (*g_config == 'Y')
    {
        return PS_CORE_IS_OPEN;
    }
    strncpy(g_config, PSCORE_CONFIG, sizeof(g_config) - 1);
    if (strncmp(g_config, config, strlen(PSCORE_CONFIG)) != 0)
    {
        psErrorStr( "Core config mismatch.\n" \
            "Library: " PSCORE_CONFIG \
            "\nCurrent: %s\n", config);
        return -1;
    }

    if (osdepTimeOpen() < 0)
    {
        psTraceCore("osdepTimeOpen failed\n");
        return PS_FAILURE;
    }
    if (osdepEntropyOpen() < 0)
    {
        psTraceCore("osdepEntropyOpen failed\n");
        osdepTimeClose();
        return PS_FAILURE;
    }

#ifdef USE_MULTITHREADING
    if (osdepMutexOpen() < 0)
    {
        psTraceCore("osdepMutexOpen failed\n");
        osdepEntropyClose();
        osdepTimeClose();
        return PS_FAILURE;
    }
    if (psCreateMutex(&corelibMutex, 0) < 0)
    {
        psTraceCore("psCreateMutex failed\n");
        osdepMutexClose();
        osdepEntropyClose();
        osdepTimeClose();
        return PS_FAILURE;
    }
#endif /* USE_MULTITHREADING */

    return PS_SUCCESS;
}

/******************************************************************************/
void psCoreClose(void)
{
    if (*g_config == 'Y')
    {
        *g_config = 'N';

#ifdef USE_MULTITHREADING
        psDestroyMutex(&corelibMutex);
        osdepMutexClose();
#endif  /* USE_MULTITHREADING */

        osdepEntropyClose();

        osdepTimeClose();
    }
}

/******************************************************************************/
/**
    Constant time memory comparison - like memcmp but w/o data dependent branch.
    @security SECURITY - Should be used when comparing values that use or have
    been derived or have been decrypted/encrypted/signed from secret information.

    @param[in] s1 Pointer to first buffer to compare
    @param[in] s2 Pointer to first buffer to compare
    @param[in] len number of bytes to compare in s1 and s2
    @return 0 on successful match, nonzero on failure.
 */
int32 memcmpct(const void *s1, const void *s2, size_t len)
{
    int xor = 0;

    while (len > 0)
    {
        len--;
        xor |= ((unsigned char *) s1)[len] ^ ((unsigned char *) s2)[len];
    }
    return xor;
}

/******************************************************************************/
/*
    ERROR FUNCTIONS
    Tap into platform trace and break execution if DEBUG compile

    Modules should tie themselves to these low levels
    with compile-time defines
 */
void _psError(const char *msg)
{
    _psTrace(msg);
    _psTrace("\n");
#ifdef HALT_ON_PS_ERROR
    osdepBreak();
#endif
}
void _psErrorInt(const char *msg, int32 val)
{
    _psTraceInt(msg, val);
    _psTrace("\n");
#ifdef HALT_ON_PS_ERROR
    osdepBreak();
#endif
}
void _psErrorStr(const char *msg, const char *val)
{
    _psTraceStr(msg, val);
    _psTrace("\n");
#ifdef HALT_ON_PS_ERROR
    osdepBreak();
#endif
}

/*
    copy 'len' bytes from 'b' to 's', converting all to printable characters
 */
static void mem2str(char *s, const unsigned char *b, uint32 len)
{
    for (; len > 0; len--)
    {
        if (*b > 31 && *b < 127)
        {
            *s = *b;
        }
        else
        {
            *s = '.';
        }
        b++;
        s++;
    }
}

void psTraceBytes(const char *tag, const unsigned char *p, int l)
{
    char s[17];
    int i;

    s[16] = '\0';
    if (tag)
    {
        _psTraceStr("psTraceBytes(%s, ", tag);
        _psTraceInt("%d);", l);
    }
    else
    {
        _psTrace("\"");
    }
    for (i = 0; i < l; i++)
    {
        if (!(i & 0xF))
        {
            if (tag)
            {
                if (i != 0)
                {
                    mem2str(s, p - 16, 16);
                    _psTraceStr("  %s", s);
                }
#ifdef _LP64
                _psTraceInt("\n0x%08x:", (int64) p);
#else
                _psTraceInt("\n0x%04x:", (int32) p);
#endif
            }
            else
            {
                _psTrace("\"\n\"");
            }
        }
        if (tag)
        {
            _psTraceInt("%02x ", *p++);
        }
        else
        {
            _psTraceInt("\\x%02x", *p++);
        }
    }
    if (tag)
    {
        memset(s, 0x0, 16);
        i = l & 0xF;
        mem2str(s, p - i, (unsigned int) i);
        for (; i < 16; i++)
        {
            _psTrace("   ");
        }
        _psTraceStr("  %s", s);
        _psTrace("\n");
    }
    else
    {
        _psTrace("\"\n");
    }
}

/******************************************************************************/
/*
    Creates a simple linked list from a given stream and separator char

    Memory info:
    Callers do not have to free 'items' on function failure.
 */
int32 psParseList(psPool_t *pool, char *list, const char separator,
    psList_t **items)
{
    psList_t *litems, *start, *prev;
    uint32 itemLen, listLen;
    char *tmp;

    *items = NULL;
    prev = NULL;

    listLen = (int32) strlen(list) + 1;
    if (listLen == 1)
    {
        return PS_ARG_FAIL;
    }
    start = litems = psMalloc(pool, sizeof(psList_t));
    if (litems == NULL)
    {
        return PS_MEM_FAIL;
    }
    memset(litems, 0, sizeof(psList_t));

    while (listLen > 0)
    {
        itemLen = 0;
        tmp = list;
        if (litems == NULL)
        {
            litems = psMalloc(pool, sizeof(psList_t));
            if (litems == NULL)
            {
                psFreeList(start, pool);
                return PS_MEM_FAIL;
            }
            memset(litems, 0, sizeof(psList_t));
            prev->next = litems;

        }
        while (*list != separator && *list != '\0')
        {
            itemLen++;
            listLen--;
            list++;
        }
        litems->item = psMalloc(pool, itemLen + 1);
        if (litems->item == NULL)
        {
            psFreeList(start, pool);
            return PS_MEM_FAIL;
        }
        litems->len = itemLen;
        memset(litems->item, 0x0, itemLen + 1);
        memcpy(litems->item, tmp, itemLen);
        list++;
        listLen--;
        prev = litems;
        litems = litems->next;
    }
    *items = start;
    return PS_SUCCESS;
}

void psFreeList(psList_t *list, psPool_t *pool)
{
    psList_t *next, *current;

    if (list == NULL)
    {
        return;
    }
    current = list;
    while (current)
    {
        next = current->next;
        if (current->item)
        {
            psFree(current->item, pool);
        }
        psFree(current, pool);
        current = next;
    }
}

/******************************************************************************/
/*
    Clear the stack deeper than the caller to erase any potential secrets
    or keys.
 */
void psBurnStack(uint32 len)
{
    unsigned char buf[32];

    memset_s(buf, sizeof(buf), 0x0, sizeof(buf));
    if (len > (uint32) sizeof(buf))
    {
        psBurnStack(len - sizeof(buf));
    }
}

/******************************************************************************/
/*
    Free pointed memory and clear the pointer to avoid accidental
    double free.
 */
void psFreeAndClear(void *ptrptr, psPool_t *pool)
{
    void *ptr;

    if (ptrptr != NULL)
    {
        ptr = *(void **) ptrptr;
        psFree(ptr, pool);
        *(void **) ptrptr = NULL;
        PS_PARAMETER_UNUSED(pool); /* Parameter can be unused. */
    }
}

#if defined __unix__ || defined __unix || (defined (__APPLE__) && defined (__MACH__))
# include <unistd.h> /* Possibly provides _POSIX_VERSION. */
/* 32-bit Unix machines may need workaround for Year 2038.
   64-bit Unix machines generally use large enough time_t. */
# if !defined __LP64__ && !defined __ILP64__
#  define USE_UNIX_Y2038_WORKAROUND 1
# endif
#endif /* __unix__ */

#ifdef _POSIX_VERSION
# define USE_GMTIME_R /* On posix systems, we use gmtime_r() */
#endif /* _POSIX_VERSION */

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
    time_t time = s;

#ifdef USE_GMTIME_R
    /* Note: This command assumes psBrokenDownTime_t and struct tm use
       exactly the same representation. If you optimize storage space of
       psBrokenDownTime_t, then transfer each field separately. */
    tm = gmtime_r(&time, t);
    if (tm != NULL)
    {
        ret = PS_SUCCESS;
    }
#else
    /* Use mutex to lock. */
    psLockMutex(&corelibMutex);
    tm = gmtime(&time);
    if (tm)
    {
        /* Note: This command assumes psBrokenDownTime_t and struct tm use
           exactly the same representation. If you optimize storage space of
           psBrokenDownTime_t, then transfer each field separately. */
        memcpy(t, tm, sizeof(*t));
        ret = PS_SUCCESS;
    }
    psUnlockMutex(&corelibMutex);
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
    time_t current_time;
    psTimeSeconds_t offseted_time;

    current_time = time(NULL);
    if (current_time == ((time_t) -1))
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
        /* Jan */ 31,                                                                             /* Most Feb */ 28,31, 30, 31, 30, 31, 31, 30, 31, 30, 31
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
    size_t len = strftime(*string, PS_BROKENDOWN_TIME_STR_LEN,
        "%Y%m%d%H%M%SZ", t);

    return len == PS_BROKENDOWN_TIME_STR_LEN - 1 ? PS_SUCCESS : PS_FAILURE;
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

    if (!target)
    {
        /* Use check_only as target. */
        target = &check_only;
    }

    /* Zeroize all fields as some systems have extra fields
       in struct tm. */
    memset(target, 0, sizeof(*target));

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
        year = parse_digits(&c, 4, 1900, 2999);
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
        memset(target, 0, sizeof(*target));
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
    /* _psTraceInt("got: %d\n", memcmp(s1, s2, sizeof(s1))); */
    return memcmp(s1, s2, sizeof(s1));
}

/******************************************************************************/
/*
    Helper function for String conversion.
 */
PSPUBLIC int32 psToUtf8String(psPool_t *pool,
    const unsigned char *input, size_t input_len,
    psStringType_t input_type,
    unsigned char **output, size_t *output_len,
    int opts)
{
    int32 err;
    psParseBuf_t in;
    psDynBuf_t out;
    size_t ignored_size;
    int clen = 1;

    if ((opts & ~PS_STRING_DUAL_NIL) != 0)
    {
        return PS_UNSUPPORTED_FAIL;
    }

    switch (input_type)
    {
    case PS_STRING_NUMERIC_STRING:
    case PS_STRING_PRINTABLE_STRING:
        /* These are subsets of ASCII. */
        break;
    case PS_STRING_BMP_STRING:
        /* UCS2 characters. */
        clen = 2;
        break;
    default:
        return PS_UNSUPPORTED_FAIL;
    }

    /* Sequence of 16-bit characters has to have even length. */
    if (clen == 2 && (input_len & 1) > 0)
    {
        return PS_FAILURE;
    }

    err = psParseBufFromStaticData(&in, input, input_len);
    if (err != PS_SUCCESS)
    {
        return err;
    }

    /* Create dynamic buffer with initial size estimate being the same
       than input + termination character(s). */
    err = psDynBufInit(pool, &out, input_len + 2) ? PS_SUCCESS : PS_MEM_FAIL;
    if (err != PS_SUCCESS)
    {
        return err;
    }

    if (clen == 1)
    {
        while (psParseCanRead(&in, 1))
        {
            int8_t chr = (int8_t) *in.buf.start;
            if (chr >= 1)
            {
                (void) psDynBufAppendChar(&out, (char) chr);
            }
            else
            {
                /* non-ASCII character (eight bit set) or \0. */
                err = PS_LIMIT_FAIL;
            }
            psParseBufSkipBytes(&in, (unsigned char *) &chr, 1);
        }
    }
    else     /* clen == 2 */
    {
        while (psParseCanRead(&in, 2))
        {
            unsigned char a[2];
            uint16_t chr;
            memcpy(a, in.buf.start, 2);
            chr = a[0];
            chr <<= 8;
            chr |= a[1];
            if (chr != 0 && (chr < 0xd800 || chr > 0xdfff))
            {
                /* ASCII */
                (void) psDynBufAppendUtf8(&out, chr);
            }
            else
            {
                /* surrogate pair or \0. These are invalid code points BMP. */
                err = PS_LIMIT_FAIL;
            }
            psParseBufSkipBytes(&in, a, 2);
        }
    }

    if (output_len == NULL)
    {
        output_len = &ignored_size;
    }

    /* Append terminating \0 or \0\0. */
    psDynBufAppendChar(&out, 0);
    if ((opts & PS_STRING_DUAL_NIL) != 0)
    {
        psDynBufAppendChar(&out, 0);
    }

    if (err == PS_SUCCESS)
    {
        *output = psDynBufDetach(&out, output_len);
        *output_len -= (opts & PS_STRING_DUAL_NIL) ? 2 : 1;
        if (*output == NULL)
        {
            return PS_MEM_FAIL;
        }
    }
    else
    {
        psDynBufUninit(&out);
    }
    return err;
}

/******************************************************************************/
/*
	Support for memory allocation in order to avoid applications that redefine
	malloc/free (see Perl)
*/
void *psMallocNative(size_t size)
{
	return malloc(size);
}

void psFreeNative(void *ptr)
{
	free(ptr);
}
