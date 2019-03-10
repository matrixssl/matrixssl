/** osdep_string.h
 *
 * Wrapper for system header osdep_string.h
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

/* This file just includes system header string.h.
   In case your system does not include all functions
   memcmp/memmove/memcpy/memset/strcmp/strncmp/strcpy/strncpy/strcat/strlen/strstr/strtol/strchr/strtok/memchr via that file or
   does not have implementation of string.h, please
   customize this place holder header.
*/

#ifndef OSDEP_STRING_H_DEFINED
#define OSDEP_STRING_H_DEFINED 1


#include <string.h>

/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

/* Macro that provides Memcmp, which is macro wrapper for memcmp. */
#ifndef Memcmp
#define Memcmp memcmp
#endif /* Memcmp */

/* Macro that provides Memmove, which is macro wrapper for memmove. */
#ifndef Memmove
#define Memmove memmove
#endif /* Memmove */

/* Macro that provides Memcpy, which is macro wrapper for memcpy. */
#ifndef Memcpy
#define Memcpy memcpy
#endif /* Memcpy */

/* Macro that provides Memset, which is macro wrapper for memset. */
#ifndef Memset
#define Memset memset
#endif /* Memset */

/* Macro that provides Strcmp, which is macro wrapper for strcmp. */
#ifndef Strcmp
#define Strcmp strcmp
#endif /* Strcmp */

/* Macro that provides Strncmp, which is macro wrapper for strncmp. */
#ifndef Strncmp
#define Strncmp strncmp
#endif /* Strncmp */

/* Macro that provides Strcpy, which is macro wrapper for strcpy. */
#ifndef Strcpy
#define Strcpy strcpy
#endif /* Strcpy */

/* Macro that provides Strncpy, which is macro wrapper for strncpy. */
#ifndef Strncpy
#define Strncpy strncpy
#endif /* Strncpy */

/* Macro that provides Strcat, which is macro wrapper for strcat. */
#ifndef Strcat
#define Strcat strcat
#endif /* Strcat */

/* Macro that provides Strlen, which is macro wrapper for strlen. */
#ifndef Strlen
#define Strlen strlen
#endif /* Strlen */

/* Macro that provides Strstr, which is macro wrapper for strstr. */
#ifndef Strstr
#define Strstr strstr
#endif /* Strstr */

/* Macro that provides Strtol, which is macro wrapper for strtol. */
#ifndef Strtol
#define Strtol strtol
#endif /* Strtol */

/* Macro that provides Strchr, which is macro wrapper for strchr. */
#ifndef Strchr
#define Strchr strchr
#endif /* Strchr */

/* Macro that provides Strtok, which is macro wrapper for strtok. */
#ifndef Strtok
#define Strtok strtok
#endif /* Strtok */

/* Macro that provides Memchr, which is macro wrapper for memchr. */
#ifndef Memchr
#define Memchr memchr
#endif /* Memchr */



#endif /* OSDEP_STRING_H_DEFINED */
