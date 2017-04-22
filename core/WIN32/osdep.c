/**
 *      @file    osdep.c
 *      @version $Format:%h%d$
 *
 *      WIN32 platform PScore .
 */
/*
 *      Copyright (c) 2013-2016 INSIDE Secure Corporation
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

#include "../coreApi.h"
#include "../osdep.h"

#ifdef WIN32
# include <wincrypt.h>

/******************************************************************************/
/* TIME */

static LARGE_INTEGER hiresStart;   /* zero-time */
static LARGE_INTEGER hiresFreq;    /* tics per second */

int osdepTimeOpen(void)
{
    if (QueryPerformanceFrequency(&hiresFreq) == PS_FALSE)
    {
        return PS_FAILURE;
    }
    if (QueryPerformanceCounter(&hiresStart) == PS_FALSE)
    {
        return PS_FAILURE;
    }
    return PS_SUCCESS;
}

void osdepTimeClose(void)
{
}

/* PScore Public API implementations */
int32 psGetTime(psTime_t *t, void *userPtr)
{
    psTime_t lt;
    __int64 diff;
    int32 d;

    if (t == NULL)
    {
        QueryPerformanceCounter(&lt);
        diff = lt.QuadPart - hiresStart.QuadPart;
        d = (int32) ((diff * 1000) / hiresFreq.QuadPart);
        return d;
    }

    QueryPerformanceCounter(t);
    diff = t->QuadPart - hiresStart.QuadPart;
    d = (int32) ((diff * 1000) / hiresFreq.QuadPart);
    return d;
}

int32 psDiffMsecs(psTime_t then, psTime_t now, void *userPtr)
{
    __int64 diff;

    diff = now.QuadPart - then.QuadPart;
    return (int32) ((diff * 1000) / hiresFreq.QuadPart);
}

int32 psCompareTime(psTime_t a, psTime_t b, void *userPtr)
{
    if (a.QuadPart <= b.QuadPart)
    {
        return 1;
    }
    return 0;
}

/******************************************************************************/
/* MUTEX */

# ifdef USE_MULTITHREADING

int32_t osdepMutexOpen(void)
{
    return PS_SUCCESS;
}

void osdepMutexClose(void)
{
}

int32_t psCreateMutex(psMutex_t *mutex, uint32_t flags)
{
    if (flags)
    {
        psErrorInt("psCreateMutex unsupported flag %u\n", flags);
        return PS_PLATFORM_FAIL;
    }
    InitializeCriticalSection(mutex);   /* Does not return a value */
    return PS_SUCCESS;
}

void psLockMutex(psMutex_t *mutex)
{
    EnterCriticalSection(mutex);
}

void psUnlockMutex(psMutex_t *mutex)
{
    LeaveCriticalSection(mutex);
}

void psDestroyMutex(psMutex_t *mutex)
{
    DeleteCriticalSection(mutex);
}
# endif /* USE_MULTITHREADING */

/******************************************************************************/
/* ENTROPY */
static HCRYPTPROV hProv;        /* Crypto context for random bytes */

int osdepEntropyOpen(void)
{
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT))
    {
        return PS_FAILURE;
    }
    return PS_SUCCESS;
}

void osdepEntropyClose(void)
{
    CryptReleaseContext(hProv, 0);
}

int32 psGetEntropy(unsigned char *bytes, uint32 size, void *userPtr)
{
    if (CryptGenRandom(hProv, size, bytes))
    {
        return size;
    }
    return PS_FAILURE;
}

/******************************************************************************/
/* TRACE */

int osdepTraceOpen(void)
{
    return PS_SUCCESS;
}

void osdepTraceClose(void)
{
}

void _psTrace(const char *msg)
{
    printf("%s", msg);
}

/* Message should contain one %s, unless value is NULL */
void _psTraceStr(const char *message, const char *value)
{
    if (value)
    {
        printf(message, value);
    }
    else
    {
        printf("%s", message);
    }
}

/* message should contain one %d */
void _psTraceInt(const char *message, int32 value)
{
    printf(message, value);
}

/* message should contain one %p */
void _psTracePtr(const char *message, const void *value)
{
    printf(message, value);
}

/******************************************************************************/
/* DEBUGGING */

# ifdef HALT_ON_PS_ERROR
void osdepBreak(void)
{
    /* System halt on psError (and assert) */
    DebugBreak();
}
# endif /* HALT_ON_PS_ERROR */

/******************************************************************************/
/* FILE SYSTEM */

# ifdef MATRIX_USE_FILE_SYSTEM
/*
    Memory info:
    Caller must free 'buf' parameter on success
    Callers do not need to free buf on function failure
 */
int32 psGetFileBuf(psPool_t *pool, const char *fileName, unsigned char **buf,
    int32 *bufLen)
{
    DWORD dwAttributes;
    HANDLE hFile;
    int32 size;
    DWORD tmp = 0;

    *bufLen = 0;
    *buf = NULL;

    dwAttributes = GetFileAttributesA(fileName);
    if (dwAttributes != 0xFFFFFFFF && dwAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        psTraceStrCore("Unable to find %s\n", (char *) fileName);
        return PS_PLATFORM_FAIL;
    }

    /* Open an existing file read-only (we are not actually creating) */
    if ((hFile = CreateFileA(fileName, GENERIC_READ,
             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
             FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        psTraceStrCore("Unable to open %s\n", (char *) fileName);
        return PS_PLATFORM_FAIL;
    }

    size = GetFileSize(hFile, NULL);

    *buf = psMalloc(pool, size + 1);
    if (*buf == NULL)
    {
        CloseHandle(hFile);
        return PS_MEM_FAIL;
    }
    memset(*buf, 0x0, size + 1);

    while (*bufLen < size)
    {
        if (ReadFile(hFile, *buf + *bufLen,
                (size - *bufLen > 512 ? 512 : size - *bufLen),
                &tmp, NULL) == FALSE)
        {

            psFree(*buf, pool);
            psTraceStrCore("Unable to read %s\n", (char *) fileName);
            CloseHandle(hFile);
            return PS_PLATFORM_FAIL;
        }
        *bufLen += (int32) tmp;
    }

    CloseHandle(hFile);
    return PS_SUCCESS;
}
# endif /* MATRIX_USE_FILE_SYSTEM */

#endif  /* WIN32 */

/******************************************************************************/

