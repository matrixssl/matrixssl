__DOC__
/* This file is template for wrapper of system header.
   You can copy the file directly and edit portions marked with __NAME__ or
   apply template via makefile. */
__END__

/** __FILENAME__
 *
 * Wrapper for system header __FILENAME__
 */

#ifdef MATRIX_COMMERCIAL
/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*****************************************************************************/
#else
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
#endif /* MATRIX_COMMERCIAL */

/* This file just includes system header __TOFILE__.
   In case your system does not include all functions
   __FUNCS__ via that file or
   does not have implementation of __TOFILE__, please
   customize this place holder header.
*/

#ifndef __UC_FILENAME___DEFINED
#define __UC_FILENAME___DEFINED 1

__REQUIRES__
#include <__TOFILE__>

/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from C standard
   ISO C99 and other common standards.
   The defines may be overrided from command line. */

__FUNCS_REDIRECT__
"/* Macro that provides \u$_, which is macro wrapper for $_. */
#ifndef \u$_
#define \u$_ $_
#endif /* \u$_ */
"
__END__
__END_REQUIRES__
__DEFINED__
#endif /* __UC_FILENAME___DEFINED */
