/** osdep_strict.h
 *
 * Helper for avoiding extra system dependencies.
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

/* This file tries to prevent accidental use of operating system
   dependent functions. Once this header is included, the references
   to operating system dependent functions must go through osdep_*.h wrappers.
   In case direct reference is made, when this header is included the compiler
   detects the reference and prevent it on compile time.

   The header is only effective when using GNU C compiler, and compiling with
   -DOSDEP_POISON_FUNCTIONS. The header typically is no-op on most other
   compilers.
 */

#ifndef OSDEP_STRICT_H_DEFINED
#define OSDEP_STRICT_H_DEFINED 1

#if defined __GNUC__ && defined OSDEP_POISON_FUNCTIONS
#ifndef __ARMCC5 /* ARMCC is not compatible with #pragma GCC poison. */
#pragma GCC poison malloc
#pragma GCC poison free
#pragma GCC poison calloc
#pragma GCC poison realloc
#pragma GCC poison abort
#pragma GCC poison fopen
#pragma GCC poison fwread
#pragma GCC poison fwrite
#pragma GCC poison fclose
#pragma GCC poison fflush
#pragma GCC poison fprintf
#pragma GCC poison printf
#pragma GCC poison snprintf
#pragma GCC poison sprintf
#pragma GCC poison memcmp
#pragma GCC poison memmove
#pragma GCC poison memcpy
#pragma GCC poison memset
#ifndef strcmp /* Cannot use GCC poison if strcmp is a macro. */
#pragma GCC poison strcmp
#endif
#ifndef strncmp /* Cannot use GCC poison if strncmp is a macro. */
#pragma GCC poison strncmp
#endif
#pragma GCC poison strcpy
#ifndef strncpy /* Cannot use GCC poison if strncmp is a macro. */
#pragma GCC poison strncpy
#endif
#pragma GCC poison strcat
#pragma GCC poison strlen
#pragma GCC poison strstr
#pragma GCC poison strtol
#ifndef strchr /* Cannot use GCC poison if strchr is a macro. */
#pragma GCC poison strchr
#endif
#pragma GCC poison memchr
#pragma GCC poison tolower
#pragma GCC poison toupper
#pragma GCC poison isdigit
#pragma GCC poison isalpha
#pragma GCC poison isxalpha
#pragma GCC poison isxdigit
#pragma GCC poison isspace
#pragma GCC poison select
#endif
#endif /* defined __GNUC__ && defined OSDEP_POISON_FUNCTIONS */

#endif /* OSDEP_STRICT_H_DEFINED */
