/** osdep_setjmp.h
 *
 * Wrapper for system header osdep_setjmp.h
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
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

/* This file just includes system header setjmp.h.
   In case your system does not include all functions
   setjmp/longjmp via that file or
   does not have implementation of setjmp.h, please
   customize this place holder header. 
*/

#ifndef OSDEP_SETJMP_H_DEFINED
#define OSDEP_SETJMP_H_DEFINED 1


#include <setjmp.h>

/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

/* Macro that provides Setjmp, which is macro wrapper for setjmp. */
#ifndef Setjmp
#define Setjmp setjmp
#endif /* Setjmp */

/* Macro that provides Longjmp, which is macro wrapper for longjmp. */
#ifndef Longjmp
#define Longjmp longjmp
#endif /* Longjmp */



#endif /* OSDEP_SETJMP_H_DEFINED */
