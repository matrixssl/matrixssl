/* spal_mutex.h
 *
 * Description: Mutex APIs
 */

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

#ifndef INCLUDE_GUARD_SPAL_MUTEX_H_
#define INCLUDE_GUARD_SPAL_MUTEX_H_

#include "public_defs.h"
#include "spal_result.h"

#include "cfg_spal.h"

struct SPAL_Mutex
{
    union
    {
#ifdef SPAL_CFG_MUTEX_ALIGN_TYPE
        SPAL_CFG_MUTEX_ALIGN_TYPE Alignment;
#endif
        uint8_t Size[SPAL_CFG_MUTEX_SIZE];
    } Union;
};

typedef struct SPAL_Mutex SPAL_Mutex_t;

SPAL_Result_t
SPAL_Mutex_Init(
    SPAL_Mutex_t * const Mutex_p);

void
SPAL_Mutex_Lock(
    SPAL_Mutex_t * const Mutex_p);

void
SPAL_Mutex_UnLock(
    SPAL_Mutex_t * const Mutex_p);

void
SPAL_Mutex_Destroy(
    SPAL_Mutex_t * const Mutex_p);

bool
SPAL_Mutex_IsLocked(
    SPAL_Mutex_t * const Mutex_p);

SPAL_Result_t
SPAL_Mutex_TryLock(
    SPAL_Mutex_t * const Mutex_p);

#endif /* Include guard */

/* end of file spal_mutex.h */
