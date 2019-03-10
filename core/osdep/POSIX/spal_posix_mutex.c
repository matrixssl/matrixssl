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

#include "spal_mutex.h"
#include "implementation_defs.h"

#ifndef CERTLIB_NO_MULTITHREADING
# include "osdep_pthread.h"
#endif /* !CERTLIB_NO_MULTITHREADING */
#include "osdep_stdlib.h"
#include "osdep_errno.h"

#define SPAL_MAGIC_MUTEX 0x55555555

struct SPAL_MutexPosix
{
    uint32_t Magic;
#ifndef CERTLIB_NO_MULTITHREADING
    pthread_mutex_t Mutex;
#endif /* !CERTLIB_NO_MULTITHREADING */
};

typedef struct SPAL_MutexPosix SPAL_MutexPosix_t;

COMPILE_GLOBAL_ASSERT(sizeof(SPAL_MutexPosix_t) <= sizeof(SPAL_Mutex_t));

SPAL_Result_t
SPAL_Mutex_Init(
    SPAL_Mutex_t * const Mutex_p)
{
    SPAL_MutexPosix_t * const m_p = (SPAL_MutexPosix_t *) Mutex_p;

#ifndef CERTLIB_NO_MULTITHREADING
    PRECONDITION(m_p != NULL);

    if (pthread_mutex_init(&m_p->Mutex, NULL) != 0)
    {
        m_p->Magic = 0;

        POSTCONDITION(m_p->Magic != SPAL_MAGIC_MUTEX);

        return SPAL_RESULT_NORESOURCE;
    }

    m_p->Magic = SPAL_MAGIC_MUTEX;

    POSTCONDITION(m_p->Magic == SPAL_MAGIC_MUTEX);
#endif /* !CERTLIB_NO_MULTITHREADING */

    return SPAL_SUCCESS;
}


void
SPAL_Mutex_Lock(
    SPAL_Mutex_t * const Mutex_p)
{
    SPAL_MutexPosix_t * const m_p = (SPAL_MutexPosix_t *) Mutex_p;
    int rval;

#ifndef CERTLIB_NO_MULTITHREADING
    PRECONDITION(m_p != NULL);
    PRECONDITION(m_p->Magic == SPAL_MAGIC_MUTEX);

    rval = pthread_mutex_lock(&m_p->Mutex);

    ASSERT(rval == 0);
#endif /* !CERTLIB_NO_MULTITHREADING */
}


void
SPAL_Mutex_UnLock(
    SPAL_Mutex_t * const Mutex_p)
{
    SPAL_MutexPosix_t * const m_p = (SPAL_MutexPosix_t *) Mutex_p;
    int rval;

#ifndef CERTLIB_NO_MULTITHREADING
    PRECONDITION(m_p != NULL);
    PRECONDITION(m_p->Magic == SPAL_MAGIC_MUTEX);

    rval = pthread_mutex_unlock(&m_p->Mutex);

    ASSERT(rval == 0);
#endif /* !CERTLIB_NO_MULTITHREADING */
}


void
SPAL_Mutex_Destroy(
    SPAL_Mutex_t * const Mutex_p)
{
    SPAL_MutexPosix_t * const m_p = (SPAL_MutexPosix_t *) Mutex_p;
    int rval;

#ifndef CERTLIB_NO_MULTITHREADING
    PRECONDITION(m_p != NULL);
    PRECONDITION(m_p->Magic == SPAL_MAGIC_MUTEX);

    rval = pthread_mutex_destroy(&m_p->Mutex);
    m_p->Magic = 0;

    ASSERT(rval == 0);

    POSTCONDITION(m_p->Magic != SPAL_MAGIC_MUTEX);
#endif /* !CERTLIB_NO_MULTITHREADING */
}


bool
SPAL_Mutex_IsLocked(
    SPAL_Mutex_t * const Mutex_p)
{
    SPAL_MutexPosix_t * const m_p = (SPAL_MutexPosix_t *) Mutex_p;
    int rval;

#ifndef CERTLIB_NO_MULTITHREADING
    PRECONDITION(m_p != NULL);
    PRECONDITION(m_p->Magic == SPAL_MAGIC_MUTEX);

    rval = pthread_mutex_trylock(&m_p->Mutex);

    ASSERT(rval == EBUSY || rval == 0);

    if (rval == EBUSY)
    {
        return true;
    }

    rval = pthread_mutex_unlock(&m_p->Mutex);

    ASSERT(rval == 0);
#endif /* !CERTLIB_NO_MULTITHREADING */

    return false;
}


SPAL_Result_t
SPAL_Mutex_TryLock(
    SPAL_Mutex_t * const Mutex_p)
{
    SPAL_MutexPosix_t * const m_p = (SPAL_MutexPosix_t *) Mutex_p;
    int rval;

#ifndef CERTLIB_NO_MULTITHREADING
    PRECONDITION(m_p != NULL);
    PRECONDITION(m_p->Magic == SPAL_MAGIC_MUTEX);

    rval = pthread_mutex_trylock(&m_p->Mutex);

    ASSERT(rval == EBUSY || rval == 0);

    if (rval == EBUSY)
    {
        return SPAL_RESULT_LOCKED;
    }
#endif /* !CERTLIB_NO_MULTITHREADING */

    return SPAL_SUCCESS;
}

/* end of file spal_posix_mutex.c */
