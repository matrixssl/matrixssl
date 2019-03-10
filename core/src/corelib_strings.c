/**
 *      @file    corelib_strings.c
 *      @version $Format:%h%d$
 *
 *      Strings and conversion of strings.
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

#include "osdep_stdio.h"
#include "coreApi.h"
#include "osdep.h"
#include "psUtil.h"
#include "osdep_strict.h"

/*
    copy 'len' bytes from 'b' to 's', converting all to printable characters
 */
void psMem2Str(char *s, const unsigned char *b, uint32 len)
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
    Helper function for String conversion.
 */
static int32 psToUtfXString(psPool_t *pool,
    const unsigned char *input, size_t input_len,
    psStringType_t input_type,
    unsigned char **output, size_t *output_len,
    int oclen, int opts)
{
    int32 err;
    psParseBuf_t in;
    psDynBuf_t out;
    size_t ignored_size;
    int clen = 1;
    unsigned char bytes0[4] = { 0, 0, 0, 0 };
    const unsigned short *map = NULL;
    const unsigned short map_t61[256] =
    {
        /* T.61 maps most of the ASCII as-is. */
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34, 0, 0, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
        80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 0, 93, 0, 95,
        0, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 0, 124,
        0, 0, 127,
        /* Control characters. */
        128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
        142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
        156, 157, 158, 159,
        /* Extended characters */
        160, 161, 162, 163, 36, 165, 166, 167, 168, 0, 0, 171, 0, 0, 0, 0,
        176, 177, 178, 179, 180, 181, 182, 183, 184, 0, 0, 187, 188, 189, 190,
        191,
        0, 0x300, 0x301, 0x302, 0x303, 0x304, 0x306, 0x307, 0x308,
        0, 0x30A, 0x327, 0x332, 0x30B, 0x328, 0x30C,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x2126, 0xC6, 0xD0, 0xAA, 0x126, 0, 0x132, 0x13F, 0x141, 0xD8, 0x152,
        0xBA, 0xDE, 0x166, 0x14A, 0x149, 0x138, 0xE6, 0x111, 0xF0, 0x127,
        0x131, 0x133, 0x140, 0x142, 0xF8, 0x153, 0xDF, 0xFE, 0x167, 0x14B, 0
    };
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
    case PS_STRING_TELETEX_STRING:
        /* Superset of ASCII. */
        map = map_t61;
        break;
    case PS_STRING_UTF8_STRING:
        /* UTF-8 characters. */
        clen = 0;
        break;
    case PS_STRING_UTF16_STRING:
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
    err = psDynBufInit(pool, &out,
                       ((input_len + 2) * oclen)) ? PS_SUCCESS : PS_MEM_FAIL;
    if (err != PS_SUCCESS)
    {
        return err;
    }

    if (clen == 0)
    {
        /* UTF-8: */
        while(psParseBufCanReadUtf8(&in))
        {
            unsigned int chr = psParseBufReadUtf8(&in);
            if (oclen == 1)
            {
                (void) psDynBufAppendUtf8(&out, chr);
            }
            else if (oclen == 2)
            {
                (void) psDynBufAppendUtf16(&out, chr);
            }    
            else /* oclen == 4 */
            {
                (void) psDynBufAppendUtf32(&out, chr);
            }
        }
    }
    else if (clen == 1)
    {
        while (psParseCanRead(&in, 1))
        {
            unsigned short chr = (unsigned short) *in.buf.start;

            if (map)
            {
                chr = map[chr];
            }
            if ((chr >= 1 && chr <= 127) || (map && chr >= 1))
            {
                if (oclen == 1)
                {
                    (void) psDynBufAppendUtf8(&out, chr);
                }
                else
                {
                    if (oclen == 4)
                    {
                        (void) psDynBufAppendUtf16(&out, 0);
                    }
                    (void) psDynBufAppendUtf16(&out, chr);
                }
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
            Memcpy(a, in.buf.start, 2);
            chr = a[0];
            chr <<= 8;
            chr |= a[1];
            if (chr != 0 && (chr < 0xd800 || chr > 0xdfff))
            {
                /* ASCII or other page 0 characters. */
                if (oclen == 1)
                {
                    (void) psDynBufAppendUtf8(&out, chr);
                }
                else if (oclen == 2)
                {
                    (void) psDynBufAppendUtf16(&out, chr);
                }    
                else /* oclen == 4 */
                {
                    (void) psDynBufAppendUtf32(&out, chr);
                }
            }
            else if ((chr >= 0xd800 && chr <= 0xdbff) &&
                     input_type == PS_STRING_UTF16_STRING &&
                     psParseCanRead(&in, 4))
            {
                /* surrogates. */
                unsigned char b[2];
                unsigned int c;
                Memcpy(b, in.buf.start + 2, 2);

                c = (chr & 0x3FF) << 10;
                c |= ((b[0] & 0x3) << 8) | b[1];
                if (b[0] < 0xDC || b[0] > 0xDF)
                {
                    /* Invalid code point third byte needs to be 0xDC..0xDF. */
                    err = PS_LIMIT_FAIL;
                }
                if (oclen == 1)
                {
                    (void) psDynBufAppendUtf8(&out, c + 0x010000);
                }
                else if (oclen == 2)
                {
                    (void) psDynBufAppendUtf16(&out, c + 0x010000);
                }    
                else /* oclen == 4 */
                {
                    (void) psDynBufAppendUtf32(&out, c + 0x010000);
                }
                psParseBufSkipBytes(&in, a, 2);
                Memcpy(a, b, 2);
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

    /* Append terminating \0 or \0\0. x oclen */
    psDynBufAppendOctets(&out, bytes0, oclen);
    if ((opts & PS_STRING_DUAL_NIL) != 0)
    {
        psDynBufAppendOctets(&out, bytes0, oclen);
    }

    if (err == PS_SUCCESS)
    {
        *output = psDynBufDetach(&out, output_len);
        *output_len -= (opts & PS_STRING_DUAL_NIL) ? 2 * oclen : oclen;
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

PSPUBLIC int32 psToUtf8String(psPool_t *pool,
    const unsigned char *input, size_t input_len,
    psStringType_t input_type,
    unsigned char **output, size_t *output_len,
    int opts)
{
    return psToUtfXString(pool, input, input_len, input_type,
                          output, output_len, 1, opts);
}

PSPUBLIC int32 psToUtf16String(psPool_t *pool,
    const unsigned char *input, size_t input_len,
    psStringType_t input_type,
    unsigned char **output, size_t *output_len,
    int opts)
{
    return psToUtfXString(pool, input, input_len, input_type,
                          output, output_len, 2, opts);
}

PSPUBLIC int32 psToUtf32String(psPool_t *pool,
    const unsigned char *input, size_t input_len,
    psStringType_t input_type,
    unsigned char **output, size_t *output_len,
    int opts)
{
    return psToUtfXString(pool, input, input_len, input_type,
                          output, output_len, 4, opts);
}

PSPUBLIC int32 psHexToBinary(unsigned char *hex,
        unsigned char *bin,
        int32 binlen)
{
    unsigned char *end, c, highOrder;

    highOrder = 1;
    for (end = hex + binlen * 2; hex < end; hex++)
    {
        c = *hex;
        if ('0' <= c && c <= '9')
        {
            c -= '0';
        }
        else if ('a' <= c && c <= 'f')
        {
            c -= ('a' - 10);
        }
        else if ('A' <= c && c <= 'F')
        {
            c -= ('A' - 10);
        }
        else
        {
            return PS_FAILURE;
        }
        if (highOrder++ & 0x1)
        {
            *bin = c << 4;
        }
        else
        {
            *bin |= c;
            bin++;
        }
    }
    return binlen * 2;
}

PSPUBLIC int32 psBinaryToHex(unsigned char *bin, int32 binLen, char *hex)
{
    int32 high, low;

    while (binLen > 0)
    {
        high = *bin >> 4;
        hex += Sprintf(hex, "%X", high);
        low = *bin & 0xF;
/*
        This final increment is a bit bad.  The passed in memory must be
        +1 the size so some systems will not complain
 */
        hex += Sprintf(hex, "%X", low);
        bin++;
        binLen--;
    }
    return binLen * 2;
}

int32 psStrCaseCmp(const char *s1, const char *s2)
{
    int ch1;
    int ch2;
    int ch2u;
    int ch_xor;

    /* Special case: NULL pointers as input. Return inequality (-1 or 1). */
    if (s1 == NULL)
    {
        return -1;
    }
    else if (s2 == NULL)
    {
        return 1;
    }

    do
    {
        ch1 = (unsigned char) *s1;
        ch2 = (unsigned char) *s2;
        s1++;
        s2++;
        ch_xor = ch1 ^ ch2;

        switch (ch_xor)
        {
        case 0:
            /* Same character. */
            break;
        case 32:
            /* Possibly same character, but different case. */
            ch2u = ch2 | 32; /* Make ch2 lower case (in case it is letter). */
            if (ch2u >= 'a' && ch2u <= 'z')
            {
                break;
            }
            /* Fall-through. */
        default:
            /* Mismatch. */
            if (ch1 >= 'A' && ch1 <= 'Z')
            {
                ch1 |= 32;
            }
            if (ch2 >= 'A' && ch2 <= 'Z')
            {
                ch2 |= 32;
            }
            return ch1 - ch2;
        }
    } while(ch1);

    return ch2;
}
