/** osdep_ctype.h
 *
 * Wrapper for system header osdep_ctype.h
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

/* This file just includes system header ctype.h.
   In case your system does not include all functions
   tolower/toupper/isdigit/isalpha/isxalpha/isxdigit/isspace via that file or
   does not have implementation of ctype.h, please
   customize this place holder header.
*/

#ifndef OSDEP_CTYPE_H_DEFINED
#define OSDEP_CTYPE_H_DEFINED 1


#include <ctype.h>

/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

/* Macro that provides Tolower, which is macro wrapper for tolower. */
#ifndef Tolower
#define Tolower tolower
#endif /* Tolower */

/* Macro that provides Toupper, which is macro wrapper for toupper. */
#ifndef Toupper
#define Toupper toupper
#endif /* Toupper */

/* Macro that provides Isdigit, which is macro wrapper for isdigit. */
#ifndef Isdigit
#define Isdigit isdigit
#endif /* Isdigit */

/* Macro that provides Isalpha, which is macro wrapper for isalpha. */
#ifndef Isalpha
#define Isalpha isalpha
#endif /* Isalpha */

/* Macro that provides Isxalpha, which is macro wrapper for isxalpha. */
#ifndef Isxalpha
#define Isxalpha isxalpha
#endif /* Isxalpha */

/* Macro that provides Isxdigit, which is macro wrapper for isxdigit. */
#ifndef Isxdigit
#define Isxdigit isxdigit
#endif /* Isxdigit */

/* Macro that provides Isspace, which is macro wrapper for isspace. */
#ifndef Isspace
#define Isspace isspace
#endif /* Isspace */



#endif /* OSDEP_CTYPE_H_DEFINED */
