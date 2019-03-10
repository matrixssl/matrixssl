/* psprintf.c
 *
 * Description: Implementation of printf: for platforms without C99 printf.
 */

/*****************************************************************************
* Copyright (c) 2007-2018 INSIDE Secure Oy. All Rights Reserved.
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

#include "osdep_stdarg.h"
#include "osdep_stddef.h"
#include "osdep_stdio.h"
#include "osdep_stdlib.h" /* For strtol. */
#include "osdep_limits.h" /* For strtol. */
#include "coreApi.h"
#include "psprintf.h"

static const char SZ_nulls[] = "(null)";

static
void SZ_outc(struct arg *arg, int ch)
{
    arg->count++;
    if (arg->upper && (ch >= 'a' && ch <= 'z'))
    {
        arg->ch = ch - 32;
    }
    else
    {
        arg->ch = ch;
    }
    (*arg->do_putc)(arg);
}

static
void SZ_outs(struct arg *arg, const char *ptr)
{
    long slen = 0, min, max;
    unsigned int plen;
    unsigned char left = 0;

    if (!ptr)
    {
        ptr = SZ_nulls;
    }

    /* Check if min is negative (left flag). */
    min = arg->min;
    max = arg->max;
    if (min < 0)
    {
        min = -min; left = 1;
    }

    /* Find length. (equivalent to strnlen). */
    while (*ptr && max)
    {
        max--; ptr++; slen++;
    }
    ptr -= slen;
    if (arg->altform)
    {
        slen++;
    }

    plen = min > slen ? min - slen : 0;
    while (plen && !left && !arg->padz)
    {
        SZ_outc(arg, ' '); plen--;
    }
    if (arg->altform)
    {
        SZ_outc(arg, '0'); slen--;
    }
    if ((*ptr < '0' || *ptr > '9') && slen)
    {
        SZ_outc(arg, *(ptr++)); slen--;
    }
    while (plen && !left && arg->padz)
    {
        SZ_outc(arg, '0'); plen--;
    }
    while (*ptr && slen)
    {
        SZ_outc(arg, *(ptr++)); slen--;
    }
    while (plen)
    {
        SZ_outc(arg, ' '); plen--;
    }
}

static
void SZ_outs_w_ext(struct arg *arg, const char *ptr_c, int m)
{
    const __WCHAR_TYPE__ *ptr_w = (const __WCHAR_TYPE__ *) ptr_c;
    const unsigned int *ptr_i = (const unsigned int *) ptr_c;
    static char out[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    long slen = 0, min, max;
    unsigned int plen;
    unsigned char left = 0;
    int dir = 0;

    if (!ptr_w)
    {
        SZ_outs(arg, SZ_nulls); return;
    }

    /* Check if min is negative (left flag). */
    min = arg->min;
    max = arg->max;
    if (min < 0)
    {
        min = -min; left = 1;
    }

    /* Get length. */
    slen = (long) arg->max;
    max -= arg->max;
    if (m == 4 || m == 5)
    {
        dir = -2; /* backwards. */
        ptr_w += slen - 1;
        ptr_i += slen - 1;
        m -= 2;
    }
    if (m == 2)
    {
        slen *= 8;
    }
    if (m == 3)
    {
        slen *= 9;
        if (slen > 0)
        {
            slen--;
        }
    }
    if (arg->altform)
    {
        slen++;
    }

    plen = min > slen ? min - slen : 0;
    while (plen && !left && !arg->padz)
    {
        SZ_outc(arg, ' '); plen--;
    }
    if (arg->altform)
    {
        SZ_outc(arg, '0'); slen--;
    }
    while (slen)
    {
        if (m == 1)
        {
            __WCHAR_TYPE__ ch = *(ptr_w++);
            ch = ((ch < 32) || (ch > 126)) ? '.' : ch;
            SZ_outc(arg, (char) ch);
            slen--;
        }
        else
        {
            unsigned int uwch;
            uwch = (unsigned int) *(ptr_i++);
            ptr_i += dir;
            SZ_outc(arg, out[(uwch / 0x10000000) & 15]);
            SZ_outc(arg, out[(uwch / 0x1000000) & 15]);
            SZ_outc(arg, out[(uwch / 0x100000) & 15]);
            SZ_outc(arg, out[(uwch / 0x10000) & 15]);
            SZ_outc(arg, out[(uwch / 0x1000) & 15]);
            SZ_outc(arg, out[(uwch / 0x100) & 15]);
            SZ_outc(arg, out[(uwch / 16) & 15]);
            SZ_outc(arg, out[uwch & 15]);
            slen -= 8;
            if (m == 3 && slen > 0)
            {
                SZ_outc(arg, ' ');
                slen--;
            }
        }
    }
    while (plen)
    {
        SZ_outc(arg, ' '); plen--;
    }
}

static
void SZ_outs_ext(struct arg *arg, const char *ptr, int m)
{
    static char out[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    long slen = 0, min, max;
    unsigned int plen;
    unsigned char left = 0;
    int dir = 0;

    if (!ptr)
    {
        SZ_outs(arg, SZ_nulls); return;
    }

    /* Check if min is negative (left flag). */
    min = arg->min;
    max = arg->max;
    if (min < 0)
    {
        min = -min; left = 1;
    }

    /* Get length. */
    slen = (long) arg->max;
    max -= arg->max;
    if (m == 4 || m == 5)
    {
        dir = -2; /* backwards. */
        ptr += slen - 1;
        m -= 2;
    }
    if (m == 2)
    {
        slen *= 2;
    }
    if (m == 3)
    {
        slen *= 3;
        if (slen > 0)
        {
            slen--;
        }
    }
    if (arg->altform)
    {
        slen++;
    }

    plen = min > slen ? min - slen : 0;
    while (plen && !left && !arg->padz)
    {
        SZ_outc(arg, ' '); plen--;
    }
    if (arg->altform)
    {
        SZ_outc(arg, '0'); slen--;
    }
    while (slen)
    {
        if (m == 1)
        {
            char ch = *(ptr++);
            ch = ((ch < 32) || (ch > 126)) ? '.' : ch;
            SZ_outc(arg, ch);
            slen--;
        }
        else
        {
            unsigned char uch;
            uch = (unsigned char) *(ptr++);
            SZ_outc(arg, out[uch / 16]);
            SZ_outc(arg, out[uch & 15]);
            slen -= 2;
            if (m == 3 && slen > 0)
            {
                SZ_outc(arg, ' ');
                slen--;
            }
            ptr += dir;
        }
    }
    while (plen)
    {
        SZ_outc(arg, ' '); plen--;
    }
}

static
void SZ_outs_w(struct arg *arg, const char *ptr_c)
{
    wchar_t *ptr = (wchar_t *) ptr_c;
    long slen = 0, min, max;
    unsigned int plen;
    unsigned char left = 0;

    if (!ptr)
    {
        SZ_outs(arg, SZ_nulls); return;
    }

    /* Check if min is negative (left flag). */
    min = arg->min;
    max = arg->max;
    if (min < 0)
    {
        min = -min; left = 1;
    }

    /* Find length. (equivalent to strnlen). */
    while (*ptr && max)
    {
        max--; ptr++; slen++;
    }
    ptr -= slen;
    if (arg->altform)
    {
        slen++;
    }

    plen = min > slen ? min - slen : 0;
    while (plen && !left && !arg->padz)
    {
        SZ_outc(arg, ' '); plen--;
    }
    if (arg->altform)
    {
        SZ_outc(arg, '0'); slen--;
    }
    if ((*ptr < '0' || *ptr > '9') && slen)
    {
        SZ_outc(arg, (char) *(ptr++)); slen--;
    }
    while (plen && !left && arg->padz)
    {
        SZ_outc(arg, '0'); plen--;
    }
    while (*ptr && slen)
    {
        SZ_outc(arg, *(ptr++)); slen--;
    }
    while (plen)
    {
        SZ_outc(arg, ' '); plen--;
    }
}

void SZ_ulltoa(char *target, unsigned long long val, unsigned int base)
{
    unsigned int idx;
    unsigned long long val_mag = val;
    static char out[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    idx = 0;
    do
    {
        idx++;
        val_mag /= base;
    }
    while (val_mag > 0);

    target[idx] = 0;
    do
    {
        target[--idx] = out[val % base];
        val /= base;
    }
    while (val > 0);
    ASSERT(idx == 0);
}

void psVprintf(struct arg *arg, const char *fmt, va_list va)
{
    unsigned long long val;
    char buf[(sizeof(val) * 8 + 2) / 3 + 2];
    char ch;
    signed char left_right;
    char pad;
    char l;
    signed char arg_size;
    int mode = 0;

    arg->upper = 0;

    if (!fmt)
    {
        fmt = SZ_nulls;
    }
    while (*fmt)
    {
        ch = *fmt;
        fmt++;
        if (ch != '%')
        {
            SZ_outc(arg, ch);
        }
        else
        {
            char *ptr = buf;
            long *fill = (long *) &(arg->min);

            arg->min = 0;
            arg->max = ~0;
            arg->padz = 0;
            arg->altform = 0;
            arg->upper = 0;
            left_right = 1;
            pad = 0;
            l = 0;
            arg_size = 0;

            do
            {
next_ch:
                ch = *(fmt++);
                switch (ch)
                {
                case '-':
                    left_right = -1;
                    goto next_ch;
                case '.': fill = &(arg->max); left_right = 1;
                    goto next_ch;
                case '*': *fill = left_right * va_arg(va, int); goto next_ch;
                case '#':
                    arg->altform = 1;
                    goto next_ch;
                case '0':
                    arg->padz = 1;
                    goto next_ch;
                case '1': case '2': case '3': case '4': case '5':
                case '6': case '7': case '8': case '9':
                {
                    char *newfmt;
                    *fill = left_right * (long) Strtol(fmt - 1, &newfmt, 10);
                    fmt = newfmt;
                    goto next_ch;
                }
                case ' ':
                case '+': pad = ch; goto next_ch;
                case 'h': arg_size--; goto next_ch;
                case 'j': arg_size++; /* assume: long long is intmax_t */
                /* fall-through. */
                case 't':             /* assume: ptrdiff_t same size than size_t. */
                case 'z':             /* assume: size_t same size than long. */
                case 'l': arg_size++; goto next_ch;
                case 'p': arg->altform = 1; l = 16;
                    val = (uintptr_t) va_arg(va, void *);
                    goto print_num;
                case 'X': arg->upper = 1;
                /* fall-through. */
                case 'x': l = 6;
                /* fall-through. */
                case 'u':
                case 'i':
                case 'd': l += 2;
                /* fall-through. */
                case 'o': l += 8;
                /* fall-through. */
                case 'c':
                    /* Promote "long" to "long long" on LP64 architectures. */
                    if (arg_size > 0 && sizeof(long) > sizeof(int))
                    {
                        arg_size++;
                    }
                    if (arg_size >= 2)
                    {
                        val = va_arg(va, unsigned long long);
                    }
                    else
                    {
                        val = va_arg(va, unsigned int);
                    }
                    if (arg_size == -1)
                    {
                        val &= 0xffff;
                    }
                    else if (arg_size == -2)
                    {
                        val &= 0xff;
                    }
                    if (ch == 'c')
                    {
                        goto out_char;
                    }
print_num:
                    if (arg->altform)
                    {
                        if (l == 8)
                        {
                        }
                        else if (l == 16)
                        {
                            buf[0] = 'x'; ptr++;
                        }
                        else
                        {
                            arg->altform = 0;
                        }
                    }
                    if (l == 10 && ch != 'u')
                    {
                        if (arg_size == -1 && val > 0x7fff)
                        {
                            short vals = (short) val; val = (long long) vals;
                        }
                        else if (arg_size == -2 && val > 0x7f)
                        {
                            char valb = (char) val; val = (long long) valb;
                        }
                        else if (((int) val) < 0 && arg_size < 2)
                        {
                            val = (int) val;
                        }
                        if (((int) val) < 0)
                        {
                            buf[0] = '-'; ptr++; val = -val;
                        }
                        else if (pad != 0)
                        {
                            buf[0] = pad; ptr++;
                        }
                    }
                    arg->max = sizeof(buf);
                    SZ_ulltoa(ptr, val, l);
                    ptr = buf;
                    goto out_string;
out_char:
                    /* Support for printing explicit \000 to string. */
                    if ((char) val == 0)
                    {
                        SZ_outc(arg, 0);
                        goto format_done;
                    }
                    buf[0] = (char) val;
                    buf[1] = 0;
                    goto out_string_nullpad;
                case 'S':
                    ptr = va_arg(va, char *);
                    if (mode == 1 || mode == 2 || mode == 3 ||
                        mode == 4 || mode == 5)
                    {
                        if (arg->max == ~0)
                        {
                            goto error_in_args;
                        }

                        SZ_outs_w_ext(arg, ptr, mode);
                        mode = 0;
                        goto format_done;
                    }
                    /* out_wstring_nullpad: */
                    arg->padz = 0;
                    /* out_wstring: */
                    SZ_outs_w(arg, ptr);
                    goto format_done;
                case 's':
                    ptr = va_arg(va, char *);
                    if (mode == 1 || mode == 2 || mode == 3 ||
                        mode == 4 || mode == 5)
                    {
                        if (arg->max == ~0)
                        {
                            goto error_in_args;
                        }

                        SZ_outs_ext(arg, ptr, mode);
                        mode = 0;
                        goto format_done;
                    }
out_string_nullpad:
                    arg->padz = 0;
out_string:
                    SZ_outs(arg, ptr);
                    goto format_done;
                case 'm':
                    /* Mode switch. */
                    mode = arg->min;
                    buf[0] = 0;
                    arg->min = 0;
                    goto format_done;
                case '%':
                    SZ_outc(arg, '%');
                    goto format_done;
                default:
                    /* Default error handling: print formatting code
                       with problems and stop handling. */
error_in_args:
                    arg->upper = 0;
                    SZ_outc(arg, '%');
                    SZ_outc(arg, ch);
                    return; /* Unexpected character, do not continue printing. */
                            /* Note: the behavior is different than usual print */
                            /* The rationale for behavior is: after unexpected */
                            /* character, the amount of arguments read might */
                            /* differ from expectations of the caller and thus */
                            /* it could cause crash. */
                }
            }
            while (1);
format_done:
            arg->upper = 0;
        }
    }
}

static
void SZ_putbuf(struct arg *arg)
{
    (void) psBufAppendChar(arg->context, (char) arg->ch);
}

int psSbufprintf(psBuf_t *buf, const char *format, ...)
{
    struct arg arg;
    va_list ap;

    va_start(ap, format);

    arg.do_putc = &SZ_putbuf;
    arg.count = 0;
    arg.context = buf;
    (void) psVprintf(&arg, format, ap);
    va_end(ap);

    return arg.count < (size_t) INT_MAX ? arg.count : INT_MAX;
}

int psVsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    struct arg arg;
    psBuf_t buf;

    buf.buf = (unsigned char *) str;
    buf.start = buf.buf;
    buf.end = buf.start;
    buf.size = (int32) size;
    if (size != (size_t) buf.size)
    {
        /* Size has been truncated. */
        buf.size = 0x7FFFFFFFL;
    }

    arg.do_putc = &SZ_putbuf;
    arg.count = 0;
    arg.context = &buf;
    (void) psVprintf(&arg, format, ap);

    /* Zero terminate. */
    arg.ch = 0;
    if (arg.count >= size && size >= 1)
    {
        str[size - 1] = 0;
    }
    else if (size >= 1)
    {
        str[arg.count] = 0;
    }

    return arg.count < (size_t) INT_MAX ? arg.count : INT_MAX;
}

int psSnprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int res;

    va_start(ap, format);
    res = psVsnprintf(str, size, format, ap);
    va_end(ap);

    return res;
}

/* end of file debug_printf.c */
