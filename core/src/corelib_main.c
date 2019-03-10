/**
 *      @file    corelib_main.c
 *      @version $Format:%h%d$
 *
 *      Open and Close APIs.
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

#ifdef USE_MULTITHREADING
/* A mutex for concurrency control of functions implemented in this file.
   Obvious exception are psCoreOpen() and psCoreClose(). */
static psMutex_t corelibMutex;
#endif /* USE_MULTITHREADING */

/******************************************************************************/
/*
    Open (initialize) the Core module
    The config param should always be passed as:
        PSCORE_CONFIG
 */
static char g_config[32] = "N";

/******************************************************************************/
int32 psCoreOpen(const char *config)
{
    if (*g_config == 'Y')
    {
        return PS_CORE_IS_OPEN;
    }
    Strncpy(g_config, PSCORE_CONFIG, sizeof(g_config) - 1);
    if (Strncmp(g_config, config, Strlen(PSCORE_CONFIG)) != 0)
    {
        psErrorStr( "Core config mismatch.\n" \
            "Library: " PSCORE_CONFIG \
            "\nCurrent: %s\n", config);
        return -1;
    }

    if (osdepTimeOpen() < 0)
    {
        psTraceCore("osdepTimeOpen failed\n");
        return PS_FAILURE;
    }
    if (osdepEntropyOpen() < 0)
    {
        psTraceCore("osdepEntropyOpen failed\n");
        osdepTimeClose();
        return PS_FAILURE;
    }

#ifdef USE_MULTITHREADING
    if (osdepMutexOpen() < 0)
    {
        psTraceCore("osdepMutexOpen failed\n");
        osdepEntropyClose();
        osdepTimeClose();
        return PS_FAILURE;
    }
    if (psCreateMutex(&corelibMutex, 0) < 0)
    {
        psTraceCore("psCreateMutex failed\n");
        osdepMutexClose();
        osdepEntropyClose();
        osdepTimeClose();
        return PS_FAILURE;
    }
#endif /* USE_MULTITHREADING */

    return PS_SUCCESS;
}

/******************************************************************************/
void psCoreClose(void)
{
    if (*g_config == 'Y')
    {
        *g_config = 'N';

#ifdef USE_MULTITHREADING
        psDestroyMutex(&corelibMutex);
        osdepMutexClose();
#endif  /* USE_MULTITHREADING */

        osdepEntropyClose();

        osdepTimeClose();
    }
}

#ifdef USE_MULTITHREADING

/* These functions are intended for internal use of corelib. */

/* Acquire lock for performing an operation that does not allow
   multithreading.
   Returns >= 0 for success and negative value otherwise. */
int32 psCoreLibInternalLock(void)
{
    psLockMutex(&corelibMutex);
    return 0;
}

/* Free lock for performing an operation that does not allow
   multithreading. */
void psCoreLibInternalUnlock(int32 lockid)
{
    if (lockid == 0)
    {
        psUnlockMutex(&corelibMutex);
    }
}

#endif /* USE_MULTITHREADING */

/******************************************************************************/
/*
    Clear the stack deeper than the caller to erase any potential secrets
    or keys.
 */
void psBurnStack(uint32 len)
{
    unsigned char buf[32];

    memset_s(buf, sizeof(buf), 0x0, sizeof(buf));
    if (len > (uint32) sizeof(buf))
    {
        psBurnStack(len - sizeof(buf));
    }
}
