/** osdep_stdio.h
 *
 * Wrapper for system header osdep_stdio.h
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

/* This file just includes system header stdio.h.
   In case your system does not include all functions
   fopen/ferror/fread/fwrite/fclose/fflush/fprintf/printf/puts/snprintf/sprintf/sscanf via that file or
   does not have implementation of stdio.h, please
   customize this place holder header.
*/

#ifndef OSDEP_STDIO_H_DEFINED
#define OSDEP_STDIO_H_DEFINED 1


#include <stdio.h>

/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

/* Macro that provides Fopen, which is macro wrapper for fopen. */
#ifndef Fopen
#define Fopen fopen
#endif /* Fopen */

/* Macro that provides Ferror, which is macro wrapper for ferror. */
#ifndef Ferror
#define Ferror ferror
#endif /* Ferror */

/* Macro that provides Fread, which is macro wrapper for fread. */
#ifndef Fread
#define Fread fread
#endif /* Fread */

/* Macro that provides Fwrite, which is macro wrapper for fwrite. */
#ifndef Fwrite
#define Fwrite fwrite
#endif /* Fwrite */

/* Macro that provides Fclose, which is macro wrapper for fclose. */
#ifndef Fclose
#define Fclose fclose
#endif /* Fclose */

/* Macro that provides Fflush, which is macro wrapper for fflush. */
#ifndef Fflush
#define Fflush fflush
#endif /* Fflush */

/* Macro that provides Fprintf, which is macro wrapper for fprintf. */
#ifndef Fprintf
#define Fprintf fprintf
#endif /* Fprintf */

/* Macro that provides Printf, which is macro wrapper for printf. */
#ifndef Printf
#define Printf printf
#endif /* Printf */

/* Macro that provides Puts, which is macro wrapper for puts. */
#ifndef Puts
#define Puts puts
#endif /* Puts */

/* Macro that provides Snprintf, which is macro wrapper for snprintf. */
#ifndef Snprintf
#define Snprintf snprintf
#endif /* Snprintf */

/* Macro that provides Sprintf, which is macro wrapper for sprintf. */
#ifndef Sprintf
#define Sprintf sprintf
#endif /* Sprintf */

/* Macro that provides Sscanf, which is macro wrapper for sscanf. */
#ifndef Sscanf
#define Sscanf sscanf
#endif /* Sscanf */



#endif /* OSDEP_STDIO_H_DEFINED */
