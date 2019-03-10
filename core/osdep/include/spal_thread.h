/* spal_thread.h
 *
 * Description: Thread APIs
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

#ifndef INCLUDE_GUARD_SPAL_THREAD_H
#define INCLUDE_GUARD_SPAL_THREAD_H

#include "public_defs.h"
#include "spal_result.h"

#include "cfg_spal.h"


#ifdef SPAL_CFG_THREAD_TYPE
typedef SPAL_CFG_THREAD_TYPE SPAL_Thread_t;
#else
typedef uint32_t SPAL_Thread_t;
#endif

SPAL_Thread_t
SPAL_Thread_Self(
    void);


SPAL_Result_t
SPAL_Thread_Create(
    SPAL_Thread_t * const Thread_p,
    const void * const Reserved_p,
    void * (*StartFunction_p)(void * const Param_p),
    void * const ThreadParam_p);


SPAL_Result_t
SPAL_Thread_Detach(
    const SPAL_Thread_t Thread);


SPAL_Result_t
SPAL_Thread_Join(
    const SPAL_Thread_t Thread,
    void ** const Status_p);


void
SPAL_Thread_Exit(
    void * const Status);

#endif /* Include guard */

/* end of file spal_thread.h */
