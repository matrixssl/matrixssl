/* sfzclstr.h
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

#ifndef SFZCLSTR_H
#define SFZCLSTR_H

#include "c_lib.h"

/** Policy: SFZCL is not going to support all special character sets or
   country specific ASCII sets. That would be almost impossible. It is
   hoped that the UTF-8 will become de facto standard in near future
   and atleast after 2003 as hoped by PKIX, thus we concentrate our
   support for that set.

   Why UTF-8 is the choice? Mainly because it extends the US-ASCII in
   a transparent way and has the full power of UCS-4 and UCS-2. I
   feel, and probably other too, that having just one common character
   set is best for us all. */

/** Following charsets are only ones supported at the moment. */
typedef enum
{
    /** Given any as argument to conversion function will convert the
       string into smallest charset it fits into. */
    SFZCL_CHARSET_ANY = -1,

    /** The basic charset (a subset of ASCII). Usually printable
       strings are case insensitive. */
    SFZCL_CHARSET_PRINTABLE,

    /** Another relative of ASCII, but instead of letters such as '@'
       there are some like 'A' with acute. Equivalent to ISO 646. */
    SFZCL_CHARSET_VISIBLE,

    /** US ASCII. Handled as a 7 bits of the Unicode standard. */
    SFZCL_CHARSET_US_ASCII,

    /** ISO 8859-1:1987, or ISO latin1. Equivalent to the US ASCII. */
    SFZCL_CHARSET_ISO_8859_1,
    /** ISO 8859-2:1987 character set. */
    SFZCL_CHARSET_ISO_8859_2,
    /** ISO 8859-3:1988 character set. */
    SFZCL_CHARSET_ISO_8859_3,
    /** ISO 8859-4:1988 character set. */
    SFZCL_CHARSET_ISO_8859_4,

    /** ISO-8859-15 character set, a.k.a Latin9, a.k.a Latin0. */
    SFZCL_CHARSET_ISO_8859_15,

    /** T.61/Teletex string. */
    SFZCL_CHARSET_T61,

    /** 16 bit Basic Multilingual Plane (BMP), or UCS-2 as in ISO 10646-1. */
    SFZCL_CHARSET_BMP,

    /** 32 bit Universal Character Set, or UCS-4 as in ISO 10646-1. */
    SFZCL_CHARSET_UNIVERSAL,

    /** UTF-8 encoding format for UCS-2 and UCS-4. */
    SFZCL_CHARSET_UTF8
} SfzclCharset;

/** The size of the 16-bit character set. */
#define SFZCL_CHARSET_BMP_SIZE 65536

/** Our string type. */
typedef struct SfzclStrRec *SfzclStr;

/* Initialization. */

/** This function makes a character string in given `charset', e.g. the
   input data given in octet array `str' whose length is `str_length'
   is converted into the internal presentation which is returned.

   This function keeps the input string untouched.

   The function will return NULL if the given input can not be a
   presenation of string using charset, or if memory allocation for
   the internal presentation fails. */
SfzclStr
sfzcl_str_new(SfzclCharset charset, const void *str, size_t str_length);

/** This function makes a character string in given `charset', e.g. the
   input data given in octet array `str' whose length is `str_length'
   is converted into the internal presentation which is returned.

   This function steals the input string. It must no longer be
   referenced directly by the caller.

   The function will return NULL if the given input can not be a
   presenation of string using charset, or if memory allocation for
   the internal presentation fails. */
SfzclStr
sfzcl_str_make(SfzclCharset charset, unsigned char *str, size_t str_length);

/** Free a string that is no longer used. */
void sfzcl_str_free(SfzclStr str);

/** Get pointer to internal string representation. */
unsigned char *sfzcl_str_get_data(SfzclStr in_str, size_t *out_str_length);

/** This function frees the wrapper data structure only, not the
   underlying string. */
void sfzcl_str_free_wrapper(SfzclStr str);

/* Character set operations. */

/** Convert a string to some particular character set. Usually one
   cannot expect to convert a string into character set with less
   characters.  However, the opposite does work. Returns NULL if
   fails. */
SfzclStr sfzcl_str_charset_convert(SfzclStr str, SfzclCharset charset);

/** Get the charset used for the string internally. */
SfzclCharset sfzcl_str_charset_get(SfzclStr str);

/** Convert a string represented as an array of binary data to
    another array of binary data. */
void *sfzcl_charset_convert_generic(SfzclCharset charset_in,
                                    const void *str_in,
                                    size_t str_in_length,
                                    SfzclCharset charset_out,
                                    size_t *str_out_len);

/* Elementary manipulation. */

/** Duplicate a string. */
SfzclStr sfzcl_str_dup(SfzclStr str);

/** Comparison. */
typedef enum
{
    SFZCL_STR_ORDREL_LT = -1, /** Less than. */
    SFZCL_STR_ORDREL_EQ = 0,  /** Equal. */
    SFZCL_STR_ORDREL_GT = 1,  /** Greater than. */
    SFZCL_STR_ORDREL_IC = 2   /** Incomparable. */
} SfzclStrOrdRel;

/** Comparison of two strings. Returns an element of the type
   SfzclStrOrdRel */
SfzclStrOrdRel sfzcl_str_cmp(SfzclStr op1, SfzclStr op2);

/* Output conversions. */

/** This function returns the string encoded into a byte sequence. */
unsigned char *sfzcl_str_get(SfzclStr str, size_t *str_length);

/** This function returns the string encoded into a byte sequence, and
   transformed by a) taking all the 'unnecessary' whitespace away b)
   making letters lower-case in printable strings. */
unsigned char *sfzcl_str_get_canonical(SfzclStr str, size_t *str_length);

/* Cast functions between unsigned and signed character strings. */

static inline
unsigned char *sfzcl_ustr(char *string)
{
    return (unsigned char *) string;
}

static inline
const unsigned char *sfzcl_custr(const char *string)
{
    return (const unsigned char *) string;
}

static inline
const char *sfzcl_csstr(const unsigned char *string)
{
    return (const char *) string;
}

static inline
char *sfzcl_sstr(unsigned char *string)
{
    return (char *) string;
}

static inline
unsigned char *sfzcl_ustrncpy(unsigned char *s1,
    const unsigned char *s2, size_t n)
{
    return (unsigned char *) c_strncpy((char *) s1,
        (const char *) s2,
        n);
}

static inline
int sfzcl_usstrcmp(const unsigned char *s1,
    const unsigned char *s2)
{
    return c_strcmp((const char *) s1, (const char *) s2);
}

static inline
int sfzcl_usstrncmp(const unsigned char *s1,
    const unsigned char *s2,
    size_t n)
{
    return c_strncmp((const char *) s1, (const char *) s2, n);
}

#endif                          /* SFZCLSTR_H */

/* end of file sfzclstr.h */
