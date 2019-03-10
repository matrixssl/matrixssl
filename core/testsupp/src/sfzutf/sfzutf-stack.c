/* sfzutf-stack.c
 *
 * Description: SFZUTF stack size calculation.
 */

/*****************************************************************************
* Copyright (c) 2008-2016 INSIDE Secure Oy. All Rights Reserved.
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
#include "sfzutf.h"

#ifdef STACK_MEASUREMENT
/* stack measurement globals. */
const void *initial_stack_pointer;
const void *current_stack_pointer;
size_t measured_stack_usage = 0;

#endif

#ifdef STACK_MEASUREMENT
/* Notice: the following code is GCC specific. */

void __cyg_profile_func_enter(void *, void *)
__attribute__ ((no_instrument_function));
void __cyg_profile_func_exit(void *, void *)
__attribute__ ((no_instrument_function));

void
__cyg_profile_func_enter(void *this, void *callsite)
{
    char a;

    /* Dont do anything if stack measurement is not in start mode. */
    if (!STACK_MEASUREMENT_ON)
    {
        return;
    }
    if (&a < (char *) current_stack_pointer)
    {
        current_stack_pointer = &a;
    }
}

void
__cyg_profile_func_exit(void *this, void *callsite)
{
    char a;

    /* Dont do anything if stack measurement is not in start mode. */
    if (!STACK_MEASUREMENT_ON)
    {
        return;
    }
    if (&a < (char *) current_stack_pointer)
    {
        current_stack_pointer = &a;
    }
}
#endif

/* end of file sfzutf-stack.c */
