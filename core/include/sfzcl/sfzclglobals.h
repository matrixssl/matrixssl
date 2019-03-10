/* sfzclglobals.h
 */

/*****************************************************************************
* Copyright (c) 2006-2016 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef SFZCLGLOBALS_H
#define SFZCLGLOBALS_H

/* To use global variables in code you have to do following:

   old code                     new code

 ** Declaration of global variable **

   extern int foobar;           SFZCL_GLOBAL_DECLARE(int, foobar);
 ********#define foobar SFZCL_GLOBAL_USE(foobar)

 ** Definiation of global variable **
   int foobar;                  SFZCL_GLOBAL_DEFINE(int, foobar);

 ** Initialization of global variable (this must be inside the
 ** init function or similar, all global variables are initialized to
 ** zero at the beginning). If SFZCL_GLOBAL_INIT is not called then
 ** first use of variable might print out warning about use of
 ** uninitialized global variable (if warnings are enabled).
 ** Warning might also be printed out if the SFZCL_GLOBAL_INIT is called
 ** multiple times without calls to sfzcl_global_reset or
 ** sfzcl_global_uninit + init.

   int foobar = 1;              ** this is not allowed

   foobar = 1;                  SFZCL_GLOBAL_INIT(foobar,1);

 ** Using the global variable

   foobar = 1;                  foobar = 1; ** i.e no changes
   foobar = foobar++;           foobar = foobar++;

 */

#define SFZCL_GLOBAL_USE(var) sfzcl_global_ ## var
#define SFZCL_GLOBAL_DECLARE(type, var) extern type sfzcl_global_ ## var
#define SFZCL_GLOBAL_DEFINE(type, var) type sfzcl_global_ ## var
#define SFZCL_GLOBAL_INIT(var, value) (sfzcl_global_ ## var) = (value)

#endif                          /* SFZCLGLOBALS_H */
