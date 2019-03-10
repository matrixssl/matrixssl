/* spal_result.h
 *
 * Description: This header spal_result.h defines enumerated type
 *              SPAL_Resul_t, a common return type for SPAL API functions.
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

#ifndef INCLUDE_GUARD_SPAL_RESULT_H_
#define INCLUDE_GUARD_SPAL_RESULT_H_

#include "public_defs.h"

enum SPAL_ResultCodes
{
    SPAL_SUCCESS,
    SPAL_RESULT_NOMEM,
    SPAL_RESULT_NORESOURCE,
    SPAL_RESULT_LOCKED,
    SPAL_RESULT_INVALID,
    SPAL_RESULT_CANCELED,
    SPAL_RESULT_TIMEOUT,
    SPAL_RESULT_NOTFOUND,
    SPAL_RESULT_COUNT
};

typedef enum SPAL_ResultCodes SPAL_Result_t;

#endif /* Include guard */

/* end of file spal_result.h */
