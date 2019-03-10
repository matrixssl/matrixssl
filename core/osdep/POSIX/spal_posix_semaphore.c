/*****************************************************************************
* Copyright (c) 2007-2016 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L /* Request IEEE 1003.1-2004 support. */
#endif /* _POSIX_C_SOURCE */

#include "spal_semaphore.h"
#include "implementation_defs.h"

#include "osdep_semaphore.h"
#include "osdep_time.h"
#include "osdep_errno.h"

#define SPAL_MAGIC_SEMAPHORE 0x55555556

struct SPAL_SemaphorePosix
{
    uint32_t Magic;
    sem_t Sem;
};

typedef struct SPAL_SemaphorePosix SPAL_SemaphorePosix_t;

COMPILE_GLOBAL_ASSERT(
    sizeof(SPAL_SemaphorePosix_t) <= sizeof(SPAL_Semaphore_t));

SPAL_Result_t
SPAL_Semaphore_Init(
    SPAL_Semaphore_t * const Semaphore_p,
    const unsigned int InitialCount)
{
    SPAL_SemaphorePosix_t * const Sem_p =
        (SPAL_SemaphorePosix_t *) Semaphore_p;

    int rval;

    PRECONDITION(Semaphore_p != NULL);

    PRECONDITION(InitialCount < 256);

    rval = sem_init(
        &Sem_p->Sem,
        /* pshared: */ 0,
        InitialCount);

    if (rval != 0)
    {
        ASSERT(errno != EINVAL);

        return SPAL_RESULT_NORESOURCE;
    }

    Sem_p->Magic = SPAL_MAGIC_SEMAPHORE;

    return SPAL_SUCCESS;
}

void
SPAL_Semaphore_Wait(
    SPAL_Semaphore_t * const Semaphore_p)
{
    SPAL_SemaphorePosix_t * const Sem_p =
        (SPAL_SemaphorePosix_t *) Semaphore_p;

    int rval;

    PRECONDITION(Semaphore_p != NULL);
    PRECONDITION(Sem_p->Magic == SPAL_MAGIC_SEMAPHORE);

    do
    {
        rval = sem_wait(&Sem_p->Sem);
    }
    while (rval != 0 && errno == EINTR);

    ASSERT(rval == 0);
}


SPAL_Result_t
SPAL_Semaphore_TryWait(
    SPAL_Semaphore_t * const Semaphore_p)
{
    SPAL_SemaphorePosix_t * const Sem_p =
        (SPAL_SemaphorePosix_t *) Semaphore_p;

    int rval;

    PRECONDITION(Semaphore_p != NULL);
    PRECONDITION(Sem_p->Magic == SPAL_MAGIC_SEMAPHORE);

    do
    {
        rval = sem_trywait(&Sem_p->Sem);
    }
    while (rval != 0 && errno == EINTR);

    ASSERT(rval == 0 || errno == EAGAIN);

    if (rval != 0)
    {
        return SPAL_RESULT_LOCKED;
    }

    return SPAL_SUCCESS;
}


SPAL_Result_t
SPAL_Semaphore_TimedWait(
    SPAL_Semaphore_t * const Semaphore_p,
    const unsigned int TimeoutMilliSeconds)
{
    SPAL_SemaphorePosix_t * const Sem_p =
        (SPAL_SemaphorePosix_t *) Semaphore_p;
    struct timespec WaitTime;

    int rval;

    PRECONDITION(Semaphore_p != NULL);
    PRECONDITION(Sem_p->Magic == SPAL_MAGIC_SEMAPHORE);

    rval = clock_gettime(CLOCK_REALTIME, &WaitTime);

    ASSERT(rval == 0);

#define THOUSAND 1000
#define MILLION  1000000
#define BILLION  1000000000
    WaitTime.tv_sec += TimeoutMilliSeconds / THOUSAND;
    WaitTime.tv_nsec += (TimeoutMilliSeconds % THOUSAND) * MILLION;
    if (WaitTime.tv_nsec >= BILLION)
    {
        WaitTime.tv_sec += 1;
        WaitTime.tv_nsec -= BILLION;
    }
#undef BILLION
#undef MILLION
#undef THOUSAND

    do
    {
        rval = sem_timedwait(&Sem_p->Sem, &WaitTime);
    }
    while (rval != 0 && errno == EINTR);

    ASSERT(rval == 0 || errno == ETIMEDOUT);

    if (rval != 0)
    {
        return SPAL_RESULT_TIMEOUT;
    }

    return SPAL_SUCCESS;
}


void
SPAL_Semaphore_Post(
    SPAL_Semaphore_t * const Semaphore_p)
{
    SPAL_SemaphorePosix_t * const Sem_p =
        (SPAL_SemaphorePosix_t *) Semaphore_p;

    int rval;

    PRECONDITION(Semaphore_p != NULL);
    PRECONDITION(Sem_p->Magic == SPAL_MAGIC_SEMAPHORE);

    rval = sem_post(&Sem_p->Sem);

    ASSERT(rval == 0);
}

void
SPAL_Semaphore_Destroy(
    SPAL_Semaphore_t * const Semaphore_p)
{
    SPAL_SemaphorePosix_t * const Sem_p =
        (SPAL_SemaphorePosix_t *) Semaphore_p;

    int rval;

    PRECONDITION(Semaphore_p != NULL);
    PRECONDITION(Sem_p->Magic == SPAL_MAGIC_SEMAPHORE);

    rval = sem_destroy(&Sem_p->Sem);

    ASSERT(rval == 0);
}

/* end of file spal_posix_semaphore.c */
