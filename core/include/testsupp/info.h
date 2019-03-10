/* info.h
 *
 * Helper for tests: Get information on platform.
 */

/*****************************************************************************
* Copyright (c) 2018 INSIDE Secure Oy. All Rights Reserved.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef TESTSUPP_INFO_H
#define TESTSUPP_INFO_H 1

#include "osdep_stdlib.h"

static inline int TargetIs64Bit(void)
{
    /* Works for most environments. */
    return sizeof(void *) > 4 || sizeof(long) > 4;
}

static inline int TargetEnableSlowTests(void)
{
    /* Allow tests which can take a long time. */
    return !!Getenv("ENABLE_SLOW_TESTS") ||
    !!Getenv("ENABLE_VERY_SLOW_TESTS");
}

static inline int TargetEnableVerySlowTests(void)
{
    /* Allow tests which can take a very long time. */
    return !!Getenv("ENABLE_VERY_SLOW_TESTS");
}

#endif /* TESTSUPP_INFO_H */
