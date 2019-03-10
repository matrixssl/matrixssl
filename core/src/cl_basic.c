/* cl_basic.c
 *
 * Basic utility functions to aid in use of CL/CLS APIs.
 */

/*****************************************************************************
* Copyright (c) 2016 INSIDE Secure Oy. All Rights Reserved.
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

#include "osdep_stddef.h"

#ifndef CLS_MIN
# define CLS_MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* Mark expected execution paths. */
#ifdef __GNUC__
# define CLG_EXPECT(value, usual_value) __builtin_expect(value, (usual_value))
#else /* !__GNUC__ */
# define CLG_EXPECT(value, usual_value) (value)
#endif /* __GNUC__ */

#define CLG_DUFFS_DEVICE8(iter, count, command) \
    do {                                      \
        register long iter = ((count) + 7) / 8; \
        switch (CLG_EXPECT((count) % 8, 0))      \
        {                                     \
        case 0:                               \
            do                                  \
            {                                 \
                command;                        \
            case 7: command;                  \
            case 6: command;                  \
            case 5: command;                  \
            case 4: command;                  \
            case 3: command;                  \
            case 2: command;                  \
            case 1: command;                  \
            }                                 \
            while (--iter > 0);                  \
        }                                     \
    } while (0)

int CL_MemEqual(const void *p1, size_t sz1, const void *p2, size_t sz2)
{
    const unsigned char *p1b = p1;
    const unsigned char *p2b = p2;
    unsigned int xoror = 0;

    /* Check size */
    if (sz1 != sz2)
    {
        return 0;
    }
    if (sz1 == 0)
    {
        return 1;
    }

    /* Attempt to perform data comparison in constant time per data byte. */
    CLG_DUFFS_DEVICE8(FLGCmp_counter, sz1, xoror |= *(p1b++) ^ *(p2b++));

    /* Return 1 if xoror == 0, otherwise return 0.
       Expressed as mathematical expression to try avoid compiler turning
       the expression into conditional branch. */
    return (int) (1 & ((xoror - 1) >> 8));
}

/* Memory comparison with masking for the last byte.
   This function always goes through all bytes (which reduces
   timing side channels). */
static int cl_memcmp_mask(const void *bytes1,
    const void *bytes2,
    size_t sz,
    const unsigned char mask1,
    const unsigned char mask2)
{
    int diff = 0; /* bytes1 < larger, same or larger than bytes2. */
    size_t i = 0;
    const unsigned char *p1 = bytes1;
    const unsigned char *p2 = bytes2;

    if (sz > 0)
    {
        for (i = 0; i < sz - 1; i++)
        {
            diff = diff == 0 ? ((int) p1[i]) - ((int) p2[i]) : diff;
        }

        diff = diff * 256;
        /* diff is now < -256, 0 or > 256. Add effect of last
           byte to diff, which is only meaningful if diff == 0. */
        diff += ((int) p1[i] & mask1) - (int) (p2[i] & mask2);
    }
    return diff;
}

int CL_MemCmp(const void *p1, size_t sz1, const void *p2, size_t sz2)
{
    size_t len = CLS_MIN(sz1, sz2);
    int diff = cl_memcmp_mask(p1, p2, len, 0xFF, 0xFF);

    /* If lengths are different, then consider longer as larger,
       only if the result is 0, for <0 value must remain <0 and
       for >0 value must remain >0. */
    diff *= 2;
    diff += (sz1 < sz2) ? -1 : ((sz1 > sz2) ? 1 : 0);

    return diff;
}

int CL_MemCmpEndMask(const void *p1, size_t sz1, const void *p2, size_t sz2,
    const unsigned char mask1,
    const unsigned char mask2)

{
    size_t len = CLS_MIN(sz1, sz2);
    int diff = cl_memcmp_mask(p1, p2, len, mask1, mask2);

    /* If lengths are different, then consider longer as larger,
       only if the result is 0, for <0 value must remain <0 and
       for >0 value must remain >0. */
    diff *= 2;
    diff += (sz1 < sz2) ? -1 : ((sz1 > sz2) ? 1 : 0);

    return diff;
}

/* end of file cl_basic.c */
