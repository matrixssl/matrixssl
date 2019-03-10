/** osdep_strings.h
 *
 * Wrapper for system header osdep_strings.h
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

/* This file just includes system header strings.h.
   In case your system does not include all functions
   ffsll via that file or
   does not have implementation of strings.h, please
   customize this place holder header.
*/

#ifndef OSDEP_STRINGS_H_DEFINED
#define OSDEP_STRINGS_H_DEFINED 1


#include <strings.h>

/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

/* Macro that provides Ffsll, which is macro wrapper for ffsll. */
#ifndef Ffsll
#define Ffsll ffsll
#endif /* Ffsll */

/* Macro that provides Strcasecmp, which is macro wrapper for strcasecmp. */
#ifndef Strcasecmp
#define Strcasecmp strcasecmp
#endif /* Strcasecmp */

#endif /* OSDEP_STRINGS_H_DEFINED */
