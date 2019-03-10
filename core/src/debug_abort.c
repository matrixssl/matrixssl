/* debug_abort.c
 *
 * Description: Implementation of DEBUG_abort.
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

#include "implementation_defs.h"

#include "osdep_stdlib.h"
#include "osdep_stdio.h"      /* fflush, stderr */


/* This logic is to make it possible to get coverage reports on
   software runs that end-up (intentionally) to abort. */
#ifdef DEBUG_CF_ABORT_WRITE_PROFILE
void __gcov_flush();    /* Function to write profiles on disk. */
# define DEBUG_ABORT_WRITE_PROFILE __gcov_flush()
#else
# define DEBUG_ABORT_WRITE_PROFILE do { /* Not written. */ } while (0)
#endif


void DEBUG_abort(void)
{
#ifdef WIN32
    /* avoid the "report to microsoft?" dialog and the */
    /* "your program seems to have stopped abnormally" message */
    _set_abort_behavior(0, _WRITE_ABORT_MSG + _CALL_REPORTFAULT);
#endif

    /* flush stderr before calling Abort() to make sure
       out is not cut off due to buffering. */
    Fflush(stderr);

    DEBUG_ABORT_WRITE_PROFILE;

    Abort();
}

/* end of file debug_abort.c */
