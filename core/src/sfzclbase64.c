/* sfzclbase64.c
 *
 * Converting buffers to and from base64.
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
#include "sfzclbase64.h"

/* Convert from buffer of base 256 to base 64. */

static const unsigned char sfzcl_inv_base64[128] =
{
    255, 255, 255,  255,   255,    255,   255,  255,
    255, 255, 255,  255,   255,    255,   255,  255,
    255, 255, 255,  255,   255,    255,   255,  255,
    255, 255, 255,  255,   255,    255,   255,  255,
    255, 255, 255,  255,   255,    255,   255,  255,
    255, 255, 255,  62,    255,    255,   255,  63,
    52,  53,  54,   55,    56,     57,    58,   59,
    60,  61,  255,  255,   255,    255,   255,  255,
    255, 0,   1,    2,     3,      4,     5,    6,
    7,   8,   9,    10,    11,     12,    13,   14,
    15,  16,  17,   18,    19,     20,    21,   22,
    23,  24,  25,   255,   255,    255,   255,  255,
    255, 26,  27,   28,    29,     30,    31,   32,
    33,  34,  35,   36,    37,     38,    39,   40,
    41,  42,  43,   44,    45,     46,    47,   48,
    49,  50,  51,   255,   255,    255,   255,  255,
};

unsigned char *
sfzcl_base64_to_buf(const unsigned char *str, size_t *buf_len)
{
    unsigned char *buf;
    int i, j, len;
    uint32_t limb;

    len = c_strlen((char *) str);
    *buf_len = (len * 6 + 7) / 8;

    if ((buf = SPAL_Memory_Alloc(*buf_len)) == NULL)
    {
        return NULL;
    }

    for (i = 0, j = 0, limb = 0; i + 3 < len; i += 4)
    {
        if (str[i] == '=' || str[i + 1] == '=' ||
            str[i + 2] == '=' || str[i + 3] == '=')
        {
            if (str[i] == '=' || str[i + 1] == '=')
            {
                break;
            }

            if (str[i + 2] == '=')
            {
                limb =
                    ((uint32_t) sfzcl_inv_base64[str[i]] << 6) |
                    ((uint32_t) sfzcl_inv_base64[str[i + 1]]);
                buf[j] = (unsigned char) (limb >> 4) & 0xff;
                j++;
            }
            else
            {
                limb =
                    ((uint32_t) sfzcl_inv_base64[str[i]] << 12) |
                    ((uint32_t) sfzcl_inv_base64[str[i + 1]] << 6) |
                    ((uint32_t) sfzcl_inv_base64[str[i + 2]]);
                buf[j] = (unsigned char) (limb >> 10) & 0xff;
                buf[j + 1] = (unsigned char) (limb >> 2) & 0xff;
                j += 2;
            }
        }
        else
        {
            limb =
                ((uint32_t) sfzcl_inv_base64[str[i]] << 18) |
                ((uint32_t) sfzcl_inv_base64[str[i + 1]] << 12) |
                ((uint32_t) sfzcl_inv_base64[str[i + 2]] << 6) |
                ((uint32_t) sfzcl_inv_base64[str[i + 3]]);

            buf[j] = (unsigned char) (limb >> 16) & 0xff;
            buf[j + 1] = (unsigned char) (limb >> 8) & 0xff;
            buf[j + 2] = (unsigned char) (limb) & 0xff;
            j += 3;
        }
    }

    *buf_len = j;

    return buf;
}

/* Remove unneeded whitespace (everything that is not in base64!).
 * Returns new xmallocated string containing the string. If len is 0
 * use Strlen(str) to get length of data. */

unsigned char *
sfzcl_base64_remove_whitespace(const unsigned char *str, size_t len)
{
    unsigned char *cp;
    size_t i, j;

    if (len == 0)
    {
        len = c_strlen((char *) str);
    }

    if ((cp = SPAL_Memory_Alloc(len + 1)) == NULL)
    {
        return NULL;
    }

    for (i = 0, j = 0; i < len; i++)
    {
        if (!(str[i] & 128))
        {
            if (sfzcl_inv_base64[str[i]] != 255 || str[i] == '=')
            {
                cp[j++] = str[i];
            }
        }
    }

    cp[j] = '\0';

    return cp;
}

/* Remove headers/footers (and other crud) before and after the
 * base64-encoded data.  Pointer to the string is supplied in str and
 * length in len. Stores the starting and ending indexes of the
 * base64-data to start_ret and end_ret and returns TRUE if
 * successful. In case of an error, returns FALSE.  */

bool
sfzcl_base64_remove_headers(const unsigned char *str,
    size_t len, size_t *start_ret, size_t *end_ret)
{
    size_t i, end, start, header, inside, skip, bol;

    /* Remove all before and after headers. */
    for (i = 0, skip = 0, end = 0, start = 0, header = 0, inside = 0, bol = 1;
         i < len; i++)
    {
        switch (str[i])
        {
        case '-':
            if (skip)
            {
                break;
            }

            if (bol)
            {
                if (inside)
                {
                    end = i;
                }
                header = 1;
                inside ^= 1;
                skip = 1;
                bol = 0;
            }
            break;
        case '\n':
        case '\r':
            bol = 1;
            if (header)
            {
                header = 0;
                if (inside)
                {
                    start = i + 1;
                }
            }
            skip = 0;
            break;
        case ' ':
        case '\t':
            break;

        default:
            bol = 0;
            break;
        }
    }

    if (end == 0 && start == 0)
    {
        start = 0;
        end = len;
    }

    if (end == start)
    {
        return FALSE;
    }

    if (end <= start)
    {
        return FALSE;
    }

    *start_ret = start;
    *end_ret = end;

    return TRUE;
}

/* end of file sfzclbase64.c */
