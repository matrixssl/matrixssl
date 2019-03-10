/*
 * A test case for core API testing.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#define _FILE_OFFSET_BITS 64 /* Allow opening large file. */
#include "coreApi.h"
#include "psUtil.h"
#include "testsupp/testsupp.h"
#include "testsupp/info.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

psPool_t *pool = NULL;

static int can_read(const char *Filename_p)
{
    FILE *f = fopen(Filename_p, "r");
    int success = 0;

    if (f != NULL)
    {
        fclose(f);
        success = 1;
    }
    return success;
}

static size_t sum(const unsigned char *bytes, size_t sz)
{
    size_t sum = 0;
    size_t i;

    for(i = 0; i < sz; i++)
    {
        sum += bytes[i];
    }

    return sum;
}

AUTO_TEST(TEST_psGetFileBuf_empty_file)
{
    const char *file = "/dev/null";
    int32 res;
    unsigned char array[2] = { '?', 0 };
    unsigned char *buf = array;
    psSizeL_t len = 3;

    if (!can_read(file))
    {
        return SKIPPED;
    }

    res = psGetFileBuf(pool, file, &buf, &len);
    FAIL_IF(res != PS_SUCCESS);
    FAIL_IF(buf == NULL);
    FAIL_IF(buf == array);
    FAIL_IF(len != 0);
    FAIL_IF(strlen((const char *) buf) != 0);
    psFree(buf, pool);
    return OK;
}

AUTO_TEST(TEST_psGetFileBuf_endless_file)
{
    const char *file = "/dev/zero";
    int32 res;
    unsigned char array[2] = { '?', 0 };
    unsigned char *buf = array;
    psSizeL_t len = 3;

    if (!can_read(file))
    {
        return SKIPPED;
    }

    res = psGetFileBuf(pool, file, &buf, &len);
    FAIL_IF(res != PS_SUCCESS);
    FAIL_IF(buf == NULL);
    FAIL_IF(buf == array);
    FAIL_IF(len != 0);
    FAIL_IF(strlen((const char *) buf) != 0);
    psFree(buf, pool);
    return OK;
}

AUTO_TEST(TEST_psGetFileBuf_4294967295_bytes_file)
{
#define FILENAME "long_file"
    int32 res;
    unsigned char array[2] = { '?', 0 };
    unsigned char *buf = array;
    psSizeL_t len = 3;

    if (TargetIs64Bit() && !TargetEnableSlowTests())
    {
        /* Reading 4GB file will succeed on most 64-bit platforms but
           take a long time. */
        return SKIPPED;
    }

    FAIL_IF(system("rm " FILENAME) < -1);
    FAIL_IF(system("fallocate -l 4294967295 " FILENAME) < -1);
    if (!can_read(FILENAME))
    {
        FAIL_IF(system("rm " FILENAME) < -1);
        return SKIPPED;
    }

    /* File is too large to fit in memory (on some platforms). */
    /* This test may fail on some operating systems. */
    res = psGetFileBuf(pool, FILENAME, &buf, &len);
    if (res == PS_SUCCESS)
    {
        FAIL_IF(res != PS_SUCCESS);
        FAIL_IF(buf == NULL);
        FAIL_IF(buf == array);
        FAIL_IF(len != 4294967295U);
        FAIL_IF(sum(buf, len) != 0);
        return OK;
    }
    FAIL_IF(res == PS_SUCCESS);
    FAIL_IF(system("rm " FILENAME) < 0);
    return OK;
#undef FILENAME
}

AUTO_TEST(TEST_psGetFileBuf_4294967297_bytes_file)
{
#define FILENAME "long_file"
    int32 res;
    unsigned char array[2] = { '?', 0 };
    unsigned char *buf = array;
    psSizeL_t len = 3;

    if (TargetIs64Bit() && !TargetEnableSlowTests())
    {
        /* Reading 4GB file will succeed on most 64-bit platforms but
           take a long time. */
        return SKIPPED;
    }

    FAIL_IF(system("rm " FILENAME) < -1);
    FAIL_IF(system("fallocate -l 4294967297 " FILENAME) < -1);
    if (!can_read(FILENAME))
    {
        FAIL_IF(system("rm " FILENAME) < -1);
        return SKIPPED;
    }

    /* File is too large to fit in memory. */
    /* This test may fail on some operating systems. */
    res = psGetFileBuf(pool, FILENAME, &buf, &len);
    if (res == PS_SUCCESS)
    {
        FAIL_IF(res != PS_SUCCESS);
        FAIL_IF(buf == NULL);
        FAIL_IF(buf == array);
        FAIL_IF(((uint64_t) len) != 4294967297ULL);
        FAIL_IF(sum(buf, len) != 0);
        return OK;
    }
    FAIL_IF(res == PS_SUCCESS);
    FAIL_IF(system("rm " FILENAME) < 0);
    return OK;
#undef FILENAME
}

TESTSUPP_MAIN();
