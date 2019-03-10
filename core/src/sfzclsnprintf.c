/* sfzclsnprintf.c

   Implementation of functions sfzcl_snprintf() and sfzcl_vsnprintf()
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

#include "implementation_defs.h"
#include "sfzclincludes.h"
#include "sfzclsnprintf.h"
#include "sfzcldsprintf.h"

#ifndef NO_SFZCL_SNPRINTF

#define HAVE_LONG               /* Added to avoid long long error. */

/* Currently floats are not needed. */
#define CERTLIB_SNPRINTF_NO_FLOAT

#ifdef KERNEL
# ifndef CERTLIB_SNPRINTF_NO_FLOAT
#  define CERTLIB_SNPRINTF_NO_FLOAT /* floats not compatible with kernel */
# endif                             /* CERTLIB_SNPRINTF_NO_FLOAT */
#endif                              /* KERNEL */

#define SFZCL_DEBUG_MODULE "SfzclSPrintf"

#define SFZCL_SNPRINTF_FLAG_MINUS         0x1
#define SFZCL_SNPRINTF_FLAG_PLUS          0x2
#define SFZCL_SNPRINTF_FLAG_SPACE         0x4
#define SFZCL_SNPRINTF_FLAG_HASH          0x8
#define SFZCL_SNPRINTF_FLAG_CONV_TO_SHORT 0x10
#define SFZCL_SNPRINTF_FLAG_LONG_INT      0x20
#define SFZCL_SNPRINTF_FLAG_LONG_LONG_INT 0x40
#define SFZCL_SNPRINTF_FLAG_LONG_DOUBLE   0x80
#define SFZCL_SNPRINTF_FLAG_X_UPCASE      0x100
#define SFZCL_SNPRINTF_FLAG_IS_NEGATIVE   0x200
#define SFZCL_SNPRINTF_FLAG_UNSIGNED      0x400
#define SFZCL_SNPRINTF_FLAG_ZERO_PADDING  0x800

#undef sprintf

#if defined(HAVE_LONG_LONG)
# define LLTYPE        long long
# define ULLTYPE        unsigned long long
#elif defined(HAVE_LONG)
# define LLTYPE        long
# define ULLTYPE       unsigned long
#else
# error "No long long or long defined."
#endif

/* Convert a integer from unsigned long int representation
   to string representation. This will insert prefixes if needed
   (leading zero for octal and 0x or 0X for hexadecimal) and
   will write at most buf_size characters to buffer.
   tmp_buf is used because we want to get correctly truncated
   results.
 */

static int
sfzcl_snprintf_convert_unumber(char *buffer, size_t buf_size, ULLTYPE base,
    const char *digits, ULLTYPE ulong_val,
    int flags, int width, int precision)
{
    size_t tmp_buf_len = 100 + width;
    int len, written = 0;
    char *tmp_buf_ptr, prefix[2];
    char tmp_buf[200];

    if (tmp_buf_len > sizeof(tmp_buf))
    {
        L_DEBUG(LF_CERTLIB, "Trying to print number with width more than %ld",
            (long) (sizeof(tmp_buf) - 100));
        return 0;
    }

    prefix[0] = '\0';
    prefix[1] = '\0';

    /* Make tmp_buf_ptr point just past the last char of buffer */
    tmp_buf_ptr = tmp_buf + tmp_buf_len;

    if (precision < 0)
    {
        precision = 0;
    }

    /* Main conversion loop */
    do
    {
        switch ((uint8_t) base)
        {
        case 2:
            *--tmp_buf_ptr = digits[ulong_val & 0x1];
            ulong_val >>= 1;
            break;
        case 8:
            *--tmp_buf_ptr = digits[ulong_val & 0x7];
            ulong_val >>= 3;
            break;
        case 10:
#if defined(HAVE_LONG_LONG)
            {
                /* Perform division by ten. */
                ULLTYPE a = ulong_val, q = 0, b = 0xA000000000000000ULL;

                while (b >= 10)
                {
                    q <<= 1;
                    if (a >= b)
                    {
                        q++;
                        a -= b;
                    }
                    b >>= 1;
                }

                *--tmp_buf_ptr = digits[a];
                ulong_val = q;
            }
#else
            *--tmp_buf_ptr = digits[ulong_val % 10];
            ulong_val /= 10;
#endif
            break;
        case 16:
            *--tmp_buf_ptr = digits[ulong_val & 0xF];
            ulong_val >>= 4;
            break;
        default:
            ASSERT(0);

        }
        precision--;
    }
    while ((ulong_val != 0 || precision > 0) && tmp_buf_ptr > tmp_buf);

    /* Get the prefix */
    if (!(flags & SFZCL_SNPRINTF_FLAG_IS_NEGATIVE))
    {
        if (base == 16 && (flags & SFZCL_SNPRINTF_FLAG_HASH))
        {
            if (flags & SFZCL_SNPRINTF_FLAG_X_UPCASE)
            {
                prefix[0] = 'X';
                prefix[1] = '0';
            }
            else
            {
                prefix[0] = 'x';
                prefix[1] = '0';
            }
        }

        if (base == 8 && (flags & SFZCL_SNPRINTF_FLAG_HASH))
        {
            prefix[0] = '0';
        }

        if (base == 10
            && !(flags & SFZCL_SNPRINTF_FLAG_UNSIGNED)
            && (flags & SFZCL_SNPRINTF_FLAG_PLUS))
        {
            prefix[0] = '+';
        }
        else
        {
            if (base == 10
                && !(flags & SFZCL_SNPRINTF_FLAG_UNSIGNED)
                && (flags & SFZCL_SNPRINTF_FLAG_SPACE))
            {
                prefix[0] = ' ';
            }
        }
    }
    else
    {
        prefix[0] = '-';
    }

    if ((flags & SFZCL_SNPRINTF_FLAG_MINUS)
        || !(flags & SFZCL_SNPRINTF_FLAG_ZERO_PADDING))
    {
        /* Left-justified */
        if (prefix[0] != '\0' && tmp_buf_ptr > tmp_buf)
        {
            *--tmp_buf_ptr = prefix[0];
            if (prefix[1] != '\0' && tmp_buf_ptr > tmp_buf)
            {
                *--tmp_buf_ptr = prefix[1];
            }
        }
    }
    else
    {
        /* Right-justified */
        if (prefix[1] != '\0' && buf_size - written > 0)
        {
            buffer[written++] = prefix[1];
        }
        if (prefix[0] != '\0' && buf_size - written > 0)
        {
            buffer[written++] = prefix[0];
        }
    }

    len = (tmp_buf + tmp_buf_len) - tmp_buf_ptr;

    /* Now:
       - len is the length of the actual converted number,
       which is pointed to by tmp_buf_ptr.
       - buf_size is how much space we have.
       - width is the minimum width requested by the user.
       The following code writes the number and padding into
       the buffer and returns the number of characters written.
       If the SFZCL_SNPRINTF_FLAG_MINUS is set, the number will be
       left-justified, and if it is not set, the number will be right-justified.
     */

    while (buf_size - written > 0)
    {
        /* Write until the buffer is full. If stuff to write is exhausted
           first, return straight from the loop. */
        if (flags & SFZCL_SNPRINTF_FLAG_MINUS)
        {
            if (written < len)
            {
                buffer[written] = tmp_buf_ptr[written];
            }
            else
            {
                if (written >= width)
                {
                    return written;
                }
                buffer[written] =
                    (flags & SFZCL_SNPRINTF_FLAG_ZERO_PADDING) ? '0' : ' ';
            }
            written++;
        }
        else
        {
            if (width > len && written < width - len)
            {
                buffer[written] =
                    (flags & SFZCL_SNPRINTF_FLAG_ZERO_PADDING) ? '0' : ' ';
            }
            else
            {
                if (width > len)
                {
                    buffer[written] = tmp_buf_ptr[written - (width - len)];
                }
                else
                {
                    buffer[written] = tmp_buf_ptr[written];
                }
            }
            written++;
            if (written >= width && written >= len)
            {
                return written;
            }
        }
    }
    return written + 1;
}

#ifndef CERTLIB_SNPRINTF_NO_FLOAT

static int
sfzcl_snprintf_convert_float(char *buffer, size_t buf_size,
    double dbl_val, int flags, int width,
    int precision, char format_char)
{
    unsigned char print_buf[160], print_buf_len = 0;
    char format_str[80], *format_str_ptr;

    format_str_ptr = format_str;

    if (width > 155)
    {
        width = 155;
    }
    if (precision < 0)
    {
        precision = 6;
    }
    if (precision > 120)
    {
        precision = 120;
    }

    /* Construct the formatting string and let system's sprintf
       do the real work. */

    *format_str_ptr++ = '%';

    if (flags & SFZCL_SNPRINTF_FLAG_MINUS)
    {
        *format_str_ptr++ = '-';
    }
    if (flags & SFZCL_SNPRINTF_FLAG_PLUS)
    {
        *format_str_ptr++ = '+';
    }
    if (flags & SFZCL_SNPRINTF_FLAG_SPACE)
    {
        *format_str_ptr++ = ' ';
    }
    if (flags & SFZCL_SNPRINTF_FLAG_ZERO_PADDING)
    {
        *format_str_ptr++ = '0';
    }
    if (flags & SFZCL_SNPRINTF_FLAG_HASH)
    {
        *format_str_ptr++ = '#';
    }

    Sprintf(format_str_ptr, "%d.%d", width, precision);
    format_str_ptr += c_strlen((char *) format_str_ptr);

    if (flags & SFZCL_SNPRINTF_FLAG_LONG_DOUBLE)
    {
        *format_str_ptr++ = 'L';
    }
    *format_str_ptr++ = format_char;
    *format_str_ptr++ = '\0';

    Sprintf((char *) print_buf, format_str, dbl_val);
    print_buf_len = c_strlen((char *) print_buf);

    if (print_buf_len > buf_size)
    {
        print_buf_len = buf_size + 1;
        c_strncpy(buffer, (char *) print_buf, print_buf_len - 1);
    }
    else
    {
        c_strncpy(buffer, (char *) print_buf, print_buf_len);
    }
    return print_buf_len;
}

#endif                          /* CERTLIB_SNPRINTF_NO_FLOAT */

int
sfzcl_snprintf(char *str, size_t size, const char *format, ...)
{
    int ret;
    va_list ap;

    va_start(ap, format);
    ret = sfzcl_vsnprintf(str, size, format, ap);
    va_end(ap);

    return ret;
}

static void
sfzcl_snprintf_realloc(char **orig_str, size_t *size_ptr, int bytes_to_expand)
{
    char *str;

    str = sfzcl_realloc(*orig_str, *size_ptr, *size_ptr + bytes_to_expand);
    if (str == NULL)
    {
        *size_ptr = ~((size_t) 0);
        SPAL_Memory_Free(*orig_str);
        *orig_str = NULL;
    }
    *orig_str = str;
    *size_ptr += bytes_to_expand;
}

#define SFZCL_SNPRINTF_INCREMENT(ofs)     \
    do                                      \
    {                                       \
        if (ofs)                              \
        {                                   \
            str += ofs;                       \
            left -= ofs;                      \
            ASSERT(left >= 0);            \
        }                                   \
    } while (0)

#define SFZCL_SNPRINTF_RETURN_NOT_NEGATIVE(n)   \
    do {                                            \
        int m_return_value = (n);                     \
        if (m_return_value < 0) { m_return_value = 0; }   \
        return m_return_value;                        \
    } while (0)

#define SFZCL_SNPRINTF_NEED_MORE_SPACE_BASE(ofs, need)     \
    do                                                      \
    {                                                       \
        int shift_ofs = ofs;                                  \
                                                        \
        ASSERT(shift_ofs >= 0);                           \
                                                        \
        SFZCL_SNPRINTF_INCREMENT(shift_ofs);                    \
        if (!allow_realloc)                                   \
        {                                                   \
            if (left >= 0) {                                    \
                *str = 0; }                                       \
            SFZCL_SNPRINTF_RETURN_NOT_NEGATIVE(*size_ptr - 1);  \
        }                                                   \
        pos = str - *str_ptr;                                 \
        sfzcl_snprintf_realloc(str_ptr, size_ptr,               \
            pos + (need));                   \
        if (*str_ptr == NULL) {                                 \
            return -1; }                                          \
        str = *str_ptr + pos;                                 \
        left = *size_ptr - pos - 1;                           \
        SFZCL_SNPRINTF_INCREMENT(-shift_ofs);                   \
    } while (0)

#define SFZCL_SNPRINTF_NEED_MORE_SPACE(ofs)                    \
    SFZCL_SNPRINTF_NEED_MORE_SPACE_BASE(ofs, 200)

#define SFZCL_SNPRINTF_PROCESS(funcall)           \
    do                                              \
    {                                               \
        while (1)                                     \
        {                                           \
            status = funcall;                         \
            if (status != left + 1)                   \
            {                                       \
                SFZCL_SNPRINTF_INCREMENT(status);       \
                break;                                \
            }                                       \
            SFZCL_SNPRINTF_NEED_MORE_SPACE(left);       \
        }                                           \
    } while (0)

int
sfzcl_vsnprintf_internal(char **str_ptr, size_t *size_ptr,
    bool allow_realloc, const char *format, va_list ap)
{
    int status, left, pos;
    const char *format_ptr;
    int flags, precision, i;
    char format_char, *str;
    size_t format_len;
    unsigned long int ulong_val;
    ULLTYPE ulong_long_val = 0;
    LLTYPE long_long_val = 0;
    int *int_ptr;
    const char *str_val;
    int length, value;
    const char *format_start;
    unsigned int width;

#ifndef CERTLIB_SNPRINTF_NO_FLOAT
    double dbl_val;
#endif                          /* CERTLIB_SNPRINTF_NO_FLOAT */

    /* argument validation */
    if (format == NULL)
    {
        return 0;
    }

    left = (int) *size_ptr - 1;
    format_ptr = format;
    str = *str_ptr;
    format_len = c_strlen(format);
    while (format_ptr < format + format_len)
    {
        if (left <= 0)
        {
            SFZCL_SNPRINTF_NEED_MORE_SPACE(0);
        }

        ASSERT(left > 0);

        /* Non-% is trivial to handle; just copy it */
        if (*format_ptr != '%')
        {
            *str++ = *format_ptr++;
            left--;
            continue;
        }

        /* First character is '%'. */
        /* If second character is also %, it turns to % on output. */
        if (format_ptr[1] == '%')
        {
            /* Format `%%' at format string as `%' */
            *str++ = '%';
            left--;
            format_ptr += 2;
            continue;
        }
        format_start = format_ptr;

        /* Other format directive. */

        flags = 0;
        width = 0;
        precision = -1;
        format_char = (char) 0;

        /* Get the flags */
        format_ptr++;
        while (*format_ptr == '-' || *format_ptr == '+' ||
               *format_ptr == ' ' || *format_ptr == '#' || *format_ptr == '0')
        {
            switch (*format_ptr)
            {
            case '-':
                flags |= SFZCL_SNPRINTF_FLAG_MINUS;
                break;
            case '+':
                flags |= SFZCL_SNPRINTF_FLAG_PLUS;
                break;
            case ' ':
                flags |= SFZCL_SNPRINTF_FLAG_SPACE;
                break;
            case '#':
                flags |= SFZCL_SNPRINTF_FLAG_HASH;
                break;
            case '0':
                flags |= SFZCL_SNPRINTF_FLAG_ZERO_PADDING;
                break;
            }
            format_ptr++;
        }

        /* Don't pad left-justified numbers withs zeros */
        if ((flags & SFZCL_SNPRINTF_FLAG_MINUS)
            && (flags & SFZCL_SNPRINTF_FLAG_ZERO_PADDING))
        {
            flags &= ~SFZCL_SNPRINTF_FLAG_ZERO_PADDING;
        }

        /* Is width field present? */
        if (Isdigit(*format_ptr))
        {
            for (value = 0; *format_ptr && Isdigit(*format_ptr); format_ptr++)
            {
                value = 10 * value + *format_ptr - '0';
            }

            width = value;
        }
        else
        {
            if (*format_ptr == '*')
            {
                width = va_arg(ap, int);
                format_ptr++;
            }
        }

        /* Is the precision field present? */
        if (*format_ptr == '.')
        {
            format_ptr++;
            if (Isdigit(*format_ptr))
            {
                for (value = 0;
                     *format_ptr && Isdigit(*format_ptr); format_ptr++)
                {
                    value = 10 * value + *format_ptr - '0';
                }

                precision = value;
            }
            else
            {
                if (*format_ptr == '*')
                {
                    precision = va_arg(ap, int);
                    format_ptr++;
                }
                else
                {
                    precision = 0;
                }
            }
        }

        switch (*format_ptr)
        {
        case 'h':
            flags |= SFZCL_SNPRINTF_FLAG_CONV_TO_SHORT;
            format_ptr++;
            break;
        case 'l':
            if (*(format_ptr + 1) == 'l')
            {
                format_ptr++;
                flags |= SFZCL_SNPRINTF_FLAG_LONG_LONG_INT;
            }
            else
            {
                flags |= SFZCL_SNPRINTF_FLAG_LONG_INT;
            }
            format_ptr++;
            break;
        case 'q':
            flags |= SFZCL_SNPRINTF_FLAG_LONG_LONG_INT;
            format_ptr++;
            break;
        case 'L':
            flags |= SFZCL_SNPRINTF_FLAG_LONG_DOUBLE;
            format_ptr++;
            break;
        default:
            break;
        }

        /* Get and check the formatting character */
        format_char = *format_ptr;
        format_ptr++;
        length = format_ptr - format_start;

        switch (format_char)
        {
        case 'c':
        case 's':
        case 'p':
        case 'n':
        case 'd':
        case 'i':
        case 'o':
        case 'u':
        case 'x':
        case 'X':
        case 'f':
        case 'e':
        case 'E':
        case 'g':
        case 'G':
        case '@':
            if (format_char == 'X')
            {
                flags |= SFZCL_SNPRINTF_FLAG_X_UPCASE;
            }
            if (format_char == 'o')
            {
                flags |= SFZCL_SNPRINTF_FLAG_UNSIGNED;
            }
            status = length;
            break;

        default:
            status = 0;
        }

        if (status == 0)
        {
            /* Invalid format directive. Fail with zero return. */
            *str = '\0';
            return 0;
        }

        /* Print argument according to the directive. */
        switch (format_char)
        {
        case 'i':
        case 'd':
            /* Convert to unsigned long int before
               actual conversion to string */
            if (flags & SFZCL_SNPRINTF_FLAG_LONG_LONG_INT)
            {
                long_long_val = va_arg(ap, LLTYPE);
            }
            else if (flags & SFZCL_SNPRINTF_FLAG_LONG_INT)
            {
                long_long_val = (LLTYPE) va_arg(ap, long int);
            }
            else
            {
                long_long_val = (LLTYPE) va_arg(ap, int);
            }

            if (long_long_val < 0)
            {
                ulong_long_val = (ULLTYPE) -long_long_val;
                flags |= SFZCL_SNPRINTF_FLAG_IS_NEGATIVE;
            }
            else
            {
                ulong_long_val = (ULLTYPE) long_long_val;
            }

            SFZCL_SNPRINTF_PROCESS(sfzcl_snprintf_convert_unumber
                    (str, left, 10, "0123456789", ulong_long_val,
                    flags, width, precision));
            break;

        case 'p':
            ulong_val = (unsigned long int) va_arg(ap, void *);
            SFZCL_SNPRINTF_PROCESS(sfzcl_snprintf_convert_unumber
                    (str, left, 16, "0123456789abcdef",
                    ulong_val, flags, width, precision));
            break;

        case 'x':
        case 'X':

            if (flags & SFZCL_SNPRINTF_FLAG_LONG_LONG_INT)
            {
                ulong_long_val = va_arg(ap, ULLTYPE);
            }
            else if (flags & SFZCL_SNPRINTF_FLAG_LONG_INT)
            {
                ulong_long_val = va_arg(ap, unsigned long int);
            }
            else
            {
                ulong_long_val = (ULLTYPE) va_arg(ap, unsigned int);
            }
            SFZCL_SNPRINTF_PROCESS(sfzcl_snprintf_convert_unumber
                    (str, left, 16,
                    (format_char ==
                     'x') ? "0123456789abcdef" :
                    "0123456789ABCDEF", ulong_long_val, flags,
                    width, precision));
            break;

        case 'o':
            if (flags & SFZCL_SNPRINTF_FLAG_LONG_LONG_INT)
            {
                ulong_long_val = va_arg(ap, ULLTYPE);
            }
            else if (flags & SFZCL_SNPRINTF_FLAG_LONG_INT)
            {
                ulong_long_val = (ULLTYPE) va_arg(ap, unsigned long int);
            }
            else
            {
                ulong_long_val = (ULLTYPE) va_arg(ap, unsigned int);
            }
            SFZCL_SNPRINTF_PROCESS(sfzcl_snprintf_convert_unumber(str,
                    left,
                    8,
                    "01234567",
                    ulong_long_val,
                    flags, width,
                    precision));
            break;

        case 'u':
            if (flags & SFZCL_SNPRINTF_FLAG_LONG_LONG_INT)
            {
                ulong_long_val = va_arg(ap, ULLTYPE);
            }
            else if (flags & SFZCL_SNPRINTF_FLAG_LONG_INT)
            {
                ulong_long_val = (ULLTYPE) va_arg(ap, unsigned long int);
            }
            else
            {
                ulong_long_val = (unsigned long int) va_arg(ap, unsigned int);
            }

            SFZCL_SNPRINTF_PROCESS(sfzcl_snprintf_convert_unumber
                    (str, left, 10, "0123456789", ulong_long_val,
                    flags, width, precision));
            break;

        case 'c':
            if (flags & SFZCL_SNPRINTF_FLAG_LONG_LONG_INT)
            {
                ulong_long_val = va_arg(ap, ULLTYPE);
            }
            else if (flags & SFZCL_SNPRINTF_FLAG_LONG_INT)
            {
                ulong_long_val = (ULLTYPE) va_arg(ap, unsigned long int);
            }
            else
            {
                ulong_long_val = (ULLTYPE) va_arg(ap, unsigned int);
            }
            *str++ = (unsigned char) ulong_long_val;
            left--;
            break;

        case '@':
        {
            SfzclSnprintfRenderer renderer = va_arg(ap, SfzclSnprintfRenderer);
            void *arg = va_arg(ap, void *);
            int return_value;

            while (1)
            {
                return_value = (*renderer)(str, left, precision, arg);

                ASSERT(return_value <= left + 1);

                if (return_value == left + 1)
                {
                    SFZCL_SNPRINTF_NEED_MORE_SPACE(left);
                }
                else
                {
                    break;
                }
            }
            ASSERT(return_value >= 0);
            ASSERT(return_value <= left);

            if (width > (unsigned int) left)
            {
                /* 100 is ad hoc */
                if (allow_realloc)
                {
                    SFZCL_SNPRINTF_NEED_MORE_SPACE_BASE(return_value,
                        width - left + 100);
                }
                else
                {
                    width = left;
                }
            }
            if (width < (unsigned int) return_value)
            {
                width = return_value;
            }
            else if (width > (unsigned int) return_value)
            {
                /* We have room for formatting, if any. */
                if (flags & SFZCL_SNPRINTF_FLAG_MINUS)
                {
                    c_memset(str + return_value, ' ', (width - return_value));
                }
                else
                {
                    c_memmove(str + (width - return_value), str, return_value);
                    c_memset(str, ' ', (width - return_value));
                }
            }
            SFZCL_SNPRINTF_INCREMENT(width);
        }
        break;

        case 's':
        {
            size_t bytes_to_alloc = 0;

            str_val = va_arg(ap, char *);

            if (str_val == NULL)
            {
                str_val = "(null)";
            }

            if (precision == -1)
            {
                precision = c_strlen(str_val);
            }
            else
            {
                /* If a precision is given, no null character needs to be
                   present, unless the array is shorter than the precision. */
                char *end = (char *) (c_memchr(str_val, '\0', precision));
                if (end != NULL)
                {
                    precision = end - str_val;
                }
            }
            if (precision > left)
            {
                /* Either reallocate more space or
                   concatenate the string */
                if (allow_realloc)
                {
                    bytes_to_alloc = precision - left + 16;
                }
                else
                {
                    precision = left;
                }
            }

            if (width > (left + bytes_to_alloc))
            {
                /* The width is specified to be longer than left.
                   Allocate more if allowed. */
                if (allow_realloc)
                {
                    bytes_to_alloc += 16 + width - (left + bytes_to_alloc);
                }
                else
                {
                    width = left;
                }
            }
            if (bytes_to_alloc)
            {
                pos = str - *str_ptr;
                /* Alocate new space for the rest of %s and
                   16 bytes extra. */
                sfzcl_snprintf_realloc(str_ptr, size_ptr, bytes_to_alloc);
                if (*str_ptr == NULL)
                {
                    return -1;
                }
                str = *str_ptr + pos;
                left = *size_ptr - pos - 1;
            }
            if (width < (unsigned int) precision)
            {
                width = precision;
            }
            i = width - precision;

            if (flags & SFZCL_SNPRINTF_FLAG_MINUS)
            {
                c_strncpy(str, str_val, precision);
                c_memset(str + precision,
                    (flags & SFZCL_SNPRINTF_FLAG_ZERO_PADDING) ? '0' : ' ',
                    i);
            }
            else
            {
                c_memset(str,
                    (flags & SFZCL_SNPRINTF_FLAG_ZERO_PADDING) ? '0' :
                    ' ', i);
                c_strncpy(str + i, str_val, precision);
            }
            SFZCL_SNPRINTF_INCREMENT(width);
            break;
        }
        case 'n':
            int_ptr = va_arg(ap, int *);
            *int_ptr = str - *str_ptr;
            break;

#ifndef CERTLIB_SNPRINTF_NO_FLOAT
        case 'f':
        case 'e':
        case 'E':
        case 'g':
        case 'G':
            if (flags & SFZCL_SNPRINTF_FLAG_LONG_DOUBLE)
            {
                dbl_val = (double) va_arg(ap, long double);
            }
            else
            {
                dbl_val = va_arg(ap, double);
            }
            SFZCL_SNPRINTF_PROCESS(sfzcl_snprintf_convert_float(str, left,
                    dbl_val,
                    flags, width,
                    precision,
                    format_char));
            break;
#endif                          /* CERTLIB_SNPRINTF_NO_FLOAT */

        default:
            break;
        }
    }
    if (left == -1 && allow_realloc)
    {
        SFZCL_SNPRINTF_NEED_MORE_SPACE_BASE(0, 1);
    }
    if (left >= 0)
    {
        *str = '\0';
    }
    SFZCL_SNPRINTF_RETURN_NOT_NEGATIVE(*size_ptr - left - 1);
}

int
sfzcl_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    return sfzcl_vsnprintf_internal(&str, &size, FALSE, format, ap);
}

int
sfzcl_dsprintf(char **str, const char *format, ...)
{
    va_list ap;
    int result;

    va_start(ap, format);
    result = sfzcl_dvsprintf(str, format, ap);
    va_end(ap);

    return result;
}

int
sfzcl_dvsprintf(char **str, const char *format, va_list ap)
{
    size_t size;

    PRECONDITION(str != NULL);
    PRECONDITION(format != NULL);
    size = 0;
    *str = NULL;

    return sfzcl_vsnprintf_internal(str, &size, TRUE, format, ap);
}

#else /* NO_SFZCL_SNPRINTF */

extern int sfzcl_snprint_has_been_omitted;

#endif /* NO_SFZCL_SNPRINTF */
