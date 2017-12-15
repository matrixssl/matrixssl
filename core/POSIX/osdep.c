/**
 *      @file    osdep.c
 *      @version $Format:%h%d$
 *
 *      POSIX layer.
 *              Mac OSX 10.5
 *              Linux
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

#include "../coreApi.h"
#include "../osdep.h"

#ifdef POSIX
/******************************************************************************/
/*
    Universal system POSIX headers and then PScore/coreApi.h
    OS-specific header includes should be added to PScore/osdep.h
 */
# include <stdlib.h>   /* abort() */
# include <fcntl.h>    /* open(), O_RDONLY, ect... */
# include <unistd.h>   /* close() */
# include <errno.h>    /* errno */
# include <sys/time.h> /* gettimeofday */

/******************************************************************************/
/*
    TIME FUNCTIONS
 */
# ifndef USE_HIGHRES_TIME
/******************************************************************************/
/*
    Module open and close
 */
int osdepTimeOpen(void)
{
    psTime_t lt;

/*
    Just a check that gettimeofday is functioning
 */
    if (gettimeofday(&lt, NULL) < 0)
    {
        return PS_FAILURE;
    }
    return PS_SUCCESS;
}

void osdepTimeClose(void)
{
}

/*
    PScore Public API implementations

    This function always returns seconds/ticks AND OPTIONALLY populates
    whatever psTime_t happens to be on the given platform.
 */
int32 psGetTime(psTime_t *t, void *userPtr)
{
    psTime_t lt;

    if (t == NULL)
    {
        if (gettimeofday(&lt, NULL) < 0)
        {
            return PS_FAILURE;
        }
        return lt.tv_sec;
    }

    if (gettimeofday(t, NULL) < 0)
    {
        return PS_FAILURE;
    }
    return t->tv_sec;
}

int32 psDiffMsecs(psTime_t then, psTime_t now, void *userPtr)
{
    if (now.tv_usec < then.tv_usec)
    {
        now.tv_sec--;
        now.tv_usec += 1000000; /* borrow 1 second worth of usec */
    }
    return (int32) ((now.tv_sec - then.tv_sec) * 1000) +
           ((now.tv_usec - then.tv_usec) / 1000);
}

int32 psCompareTime(psTime_t a, psTime_t b, void *userPtr)
{
/*
    Time comparison.  1 if 'a' is less than or equal.  0 if 'a' is greater
 */
    if (a.tv_sec < b.tv_sec)
    {
        return 1;
    }
    if (a.tv_sec == b.tv_sec && a.tv_usec <= b.tv_usec)
    {
        return 1;
    }
    return 0;
}

# else /* USE_HIGHRES_TIME */
/******************************************************************************/
#  ifdef __APPLE__
/* MAC OS X */

#   include <mach/mach_time.h>

static mach_timebase_info_data_t hiresFreq;

int osdepTimeOpen(void)
{
    mach_timebase_info(&hiresFreq);
    return PS_SUCCESS;
}

void osdepTimeClose(void)
{
}

int32 psGetTime(psTime_t *t, void *userPtr)
{
    psTime_t lt;

    if (t == NULL)
    {
        t = &lt;
    }
    *t = mach_absolute_time();
    return (int32) ((*t * hiresFreq.numer) / (hiresFreq.denom * 1000000000L));
}

int32 psDiffMsecs(psTime_t then, psTime_t now, void *userPtr)
{
    return (int32) (((now - then) * hiresFreq.numer) / (hiresFreq.denom * 1000000));
}

int64_t psDiffUsecs(psTime_t then, psTime_t now)
{
    return (int64_t) (((now - then) * hiresFreq.numer) / (hiresFreq.denom * 1000));
}

int32 psCompareTime(psTime_t a, psTime_t b, void *userPtr)
{
    return a <= b ? 1 : 0;
}

/******************************************************************************/
#  else /* !APPLE, !tile */
/******************************************************************************/
/* LINUX */
int osdepTimeOpen(void)
{
    return PS_SUCCESS;
}

void osdepTimeClose(void)
{
}

int32 psGetTime(psTime_t *t, void *userPtr)
{
    psTime_t lt;

    if (t == NULL)
    {
        t = &lt;
    }
    clock_gettime(CLOCK_MONOTONIC, t);
    return t->tv_sec;
}

int32 psDiffMsecs(psTime_t then, psTime_t now, void *userPtr)
{
    if (now.tv_nsec < then.tv_nsec)
    {
        now.tv_sec--;
        now.tv_nsec += 1000000000L; /* borrow 1 second worth of nsec */
    }
    return (int32) ((now.tv_sec - then.tv_sec) * 1000) +
           ((now.tv_nsec - then.tv_nsec) / 1000000);
}

int64_t psDiffUsecs(psTime_t then, psTime_t now)
{
    if (now.tv_nsec < then.tv_nsec)
    {
        now.tv_sec--;
        now.tv_nsec += 1000000000L; /* borrow 1 second worth of nsec */
    }
    return (int32) ((now.tv_sec - then.tv_sec) * 1000000) +
           ((now.tv_nsec - then.tv_nsec) / 1000);
}

int32 psCompareTime(psTime_t a, psTime_t b, void *userPtr)
{
    /* Time comparison.  1 if 'a' is less than or equal.  0 if 'a' is greater */
    if (a.tv_sec < b.tv_sec)
    {
        return 1;
    }
    if (a.tv_sec == b.tv_sec && a.tv_nsec <= b.tv_nsec)
    {
        return 1;
    }
    return 0;
}
#  endif /* !APPLE */

# endif  /* USE_HIGHRES_TIME */

/******************************************************************************/

# ifdef USE_MULTITHREADING
/******************************************************************************/
/*
    MUTEX FUNCTIONS
 */
/******************************************************************************/

int32_t osdepMutexOpen(void)
{
    return PS_SUCCESS;
}

void osdepMutexClose(void)
{
}

int32_t psCreateMutex(psMutex_t *mutex, uint32_t flags)
{
    pthread_mutexattr_t attr;
    int rc;

    if (flags & ~PS_SHARED)
    {
        psErrorInt("psCreateMutex unsupported flag %u\n", flags);
        return PS_PLATFORM_FAIL;
    }
    if ((rc = pthread_mutexattr_init(&attr)) < 0)
    {
        psErrorInt("pthread_mutexattr_init failed %d\n", rc);
        return PS_PLATFORM_FAIL;
    }
    if ((flags & PS_SHARED) &&
        (rc = pthread_mutexattr_setpshared(&attr,
             PTHREAD_PROCESS_SHARED)) < 0)
    {
        pthread_mutexattr_destroy(&attr);
        psErrorInt("pthread_mutexattr shared failed %d\n", rc);
        return PS_PLATFORM_FAIL;
    }
    if ((rc = pthread_mutex_init(mutex, &attr)) != 0)
    {
        pthread_mutexattr_destroy(&attr);
        psErrorInt("pthread_mutex_init failed %d\n", rc);
        return PS_PLATFORM_FAIL;
    }
    if (pthread_mutexattr_destroy(&attr) != 0)
    {
        psTraceCore("pthread_mutexattr_destroy failed\n");
    }
    return PS_SUCCESS;
}

void psLockMutex(psMutex_t *mutex)
{
    if (pthread_mutex_lock(mutex) != 0)
    {
        psTraceCore("pthread_mutex_lock failed\n");
        abort(); /* Catastrophic error: mutex does not work correctly. */
    }
}

void psUnlockMutex(psMutex_t *mutex)
{
    if (pthread_mutex_unlock(mutex) != 0)
    {
        psTraceCore("pthread_mutex_unlock failed\n");
        abort(); /* Catastrophic error: mutex does not work correctly. */
    }
}

void psDestroyMutex(psMutex_t *mutex)
{
    pthread_mutex_destroy(mutex);
}
# endif /* USE_MULTITHREADING */
/******************************************************************************/


/******************************************************************************/
/*
    ENTROPY FUNCTIONS
 */
/******************************************************************************/
#  define MAX_RAND_READS      1024

static int32 urandfd = -1;
static int32 randfd = -1;
/*
    Module open and close
 */
int osdepEntropyOpen(void)
{
/*
    Open /dev/random access non-blocking.
 */
    if ((urandfd = open("/dev/urandom", O_RDONLY)) < 0)
    {
        psErrorInt("open of urandom failed %d\n", urandfd);
        return PS_PLATFORM_FAIL;
    }
/*
    For platforms that don't have /dev/random, just assign it to urandom
 */
    if ((randfd = open("/dev/random", O_RDONLY | O_NONBLOCK)) < 0)
    {
        randfd = urandfd;
    }
    return PS_SUCCESS;
}

void osdepEntropyClose(void)
{
    if (randfd != urandfd)
    {
        close(randfd);
    }
    close(urandfd);
}

/*
    PScore Public API implementations
 */
int32 psGetEntropy(unsigned char *bytes, uint32 size, void *userPtr)
{
/*
    Read from /dev/random non-blocking first, then from urandom if it would
    block.  Also, handle file closure case and re-open.
 */
    int32 rc, sanity, retry, readBytes;
    unsigned char *where = bytes;

    sanity = retry = rc = readBytes = 0;

    while (size)
    {
        if ((rc = read(randfd, where, size)) < 0 || sanity > MAX_RAND_READS)
        {
            if (errno == EINTR)
            {
                if (sanity > MAX_RAND_READS)
                {
                    psTraceCore("psGetEntropy failed randfd sanity\n");
                    return PS_PLATFORM_FAIL;
                }
                sanity++;
                continue;
            }
            else if (errno == EAGAIN)
            {
                break;
            }
            else if (errno == EBADF && retry == 0)
            {
                close(randfd);
                if ((randfd = open("/dev/random", O_RDONLY | O_NONBLOCK)) < 0)
                {
                    break;
                }
                retry++;
                continue;
            }
            else
            {
                break;
            }
        }
        readBytes += rc;
        where += rc;
        size -= rc;
    }

    sanity = retry = 0;
    while (size)
    {
        if ((rc = read(urandfd, where, size)) < 0 || sanity > MAX_RAND_READS)
        {
            if (errno == EINTR)
            {
                if (sanity > MAX_RAND_READS)
                {
                    psTraceCore("psGetEntropy failed urandfd sanity\n");
                    return PS_PLATFORM_FAIL;
                }
                sanity++;
                continue;
            }
            else if (errno == EBADF && retry == 0)
            {
                close(urandfd);
                if ((urandfd =
                         open("/dev/urandom", O_RDONLY | O_NONBLOCK)) < 0)
                {
                    psTraceCore("psGetEntropy failed urandom open\n");
                    return PS_PLATFORM_FAIL;
                }
                retry++;
                continue;
            }
            else
            {
                psTraceIntCore("psGetEntropy fail errno %d\n", errno);
                return PS_PLATFORM_FAIL;
            }
        }
        readBytes += rc;
        where += rc;
        size -= rc;
    }
    return readBytes;
}
/******************************************************************************/


/******************************************************************************/
/*
    RAW TRACE FUNCTIONS
 */
/******************************************************************************/

int osdepTraceOpen(void)
{
    return PS_SUCCESS;
}

void osdepTraceClose(void)
{
}

FILE *_psGetTraceFile(void)
{
    static FILE *tracefile = NULL;
#ifdef USE_MULTITHREADING
    static pthread_mutex_t tracefile_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif /* USE_MULTITHREADING */

    if (tracefile == NULL)
    {
        const char *str;

#ifdef USE_MULTITHREADING
        pthread_mutex_lock(&tracefile_mutex);
#endif /* USE_MULTITHREADING */
        
        if (tracefile == NULL)
        {
            str = getenv("PSCORE_DEBUG_FILE");
            if (str != NULL)
            {
                tracefile = fopen(str, "w");
                if (!tracefile)
                {
                    fprintf(
                            stderr,
                            "%s: Unable to open file %s, %s.\n",
                            __func__,
                            str,
                            "producing log to standard output");
                    tracefile = stdout;
                }
            }
            else
            {
                str = getenv("PSCORE_DEBUG_FILE_APPEND");
            }

            if (tracefile == NULL && str != NULL)
            {
                tracefile = fopen(str, "a");
                if (!tracefile)
                {
                    fprintf(
                            stderr,
                            "%s: Unable to open file %s, %s.\n",
                            __func__,
                            str,
                            "producing log to standard output");
                    tracefile = stdout;
                }
            }

            if (tracefile == NULL)
            {
                /* Default: output to standard output. */
                tracefile = stdout;
            }
        }

        if (tracefile)
        {
            setvbuf(tracefile, NULL, _IONBF, 0);
        }

#ifdef USE_MULTITHREADING
        pthread_mutex_unlock(&tracefile_mutex);
#endif /* USE_MULTITHREADING */
    }
    return tracefile;
}

void _psTrace(const char *msg)
{
    FILE *tracefile = _psGetTraceFile();

    if (tracefile)
    {
        fprintf(tracefile, "%s", msg);
    }
}

/* message should contain one %s, unless value is NULL */
void _psTraceStr(const char *message, const char *value)
{
    FILE *tracefile = _psGetTraceFile();
    if (value)
    {
        if (tracefile)
        {
            fprintf(tracefile, message, value);
        }
    }
    else
    {
        if (tracefile)
        {
            fprintf(tracefile, "%s", message);
        }
    }
}

/* message should contain one %d */
void _psTraceInt(const char *message, int32 value)
{
    FILE *tracefile = _psGetTraceFile();

    if (tracefile)
    {
        fprintf(tracefile, message, value);
    }
}

/* message should contain one %p */
void _psTracePtr(const char *message, const void *value)
{
    FILE *tracefile = _psGetTraceFile();

    if (tracefile)
    {
        fprintf(tracefile, message, value);
    }
}

/******************************************************************************/

# ifdef HALT_ON_PS_ERROR
/******************************************************************************/
/*
    POSIX - abort() on psError when HALT_ON_PS_ERROR enabled
 */
void osdepBreak(void)
{
    abort();
}
# endif /* HALT_ON_PS_ERROR */


# ifdef MATRIX_USE_FILE_SYSTEM
/******************************************************************************/
/*
    FILE APIs
 */
/**
    Allocate a buffer and read in a file.
    @note Caller must free 'buf' parameter on success.
    Callers do not need to free buf on function failure.

    Two variants: psGetFileBuf takes in a filename, psGetFileBufFp takes in
    a pointer to an already opened FILE.
 */
int32 psGetFileBufFp(psPool_t *pool, FILE *fp, unsigned char **buf,
    int32 *bufLen)
{
    struct stat f_stat;
    size_t tmp = 0;
    int fno = fileno(fp);

    if (fstat(fno, &f_stat) != 0)
    {
        fclose(fp);
        psTraceIntCore("Unable to stat fp %d\n", fno);
        return PS_PLATFORM_FAIL;
    }
    *buf = psMalloc(pool, (size_t) (f_stat.st_size + 1));
    if (*buf == NULL)
    {
        fclose(fp);
        return PS_MEM_FAIL;
    }
    memset(*buf, 0x0, (size_t) f_stat.st_size + 1);

    while (((tmp = fread(*buf + *bufLen, sizeof(char), 512, fp)) > 0) &&
           (*bufLen < f_stat.st_size))
    {
        *bufLen += (int32) tmp;
    }
    fclose(fp);
    return PS_SUCCESS;
}

int32 psGetFileBuf(psPool_t *pool, const char *fileName, unsigned char **buf,
    int32 *bufLen)
{
    FILE *fp;

    *bufLen = 0;
    *buf = NULL;

    if (fileName == NULL)
    {
        return PS_ARG_FAIL;
    }
    if ((fp = fopen(fileName, "r")) == NULL)
    {
        psTraceStrCore("Unable to open %s\n", (char *) fileName);
        return PS_PLATFORM_FAIL;
    }
    return psGetFileBufFp(pool, fp, buf, bufLen);
}
# endif /* MATRIX_USE_FILE_SYSTEM */
#endif  /* POSIX */
/******************************************************************************/
