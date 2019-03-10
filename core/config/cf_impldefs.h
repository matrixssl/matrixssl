/* cf_impldefs.h
 *
 * Description: Configuration options for Framework/IMPLDEFS implementation
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

#ifndef INCLUDE_GUARD_CF_IMPLDEFS_H
#define INCLUDE_GUARD_CF_IMPLDEFS_H 1

/*
   All L_PRINTFs (ie. all debug/trace and panic messages).
 */
#undef  IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF


/*
   L_DEBUG print outs.
 */
#undef  IMPLDEFS_CF_DISABLE_L_DEBUG

#ifdef CFG_IMPLDEFS_NO_DEBUG
# define IMPLDEFS_CF_DISABLE_L_DEBUG
#endif


/*
   L_TRACE print outs.
 */
#undef  IMPLDEFS_CF_DISABLE_L_TRACE

/*
   ASSERT() macro, i.e. assertion checks.
 */
#undef  IMPLDEFS_CF_DISABLE_ASSERT

#ifdef CFG_IMPLDEFS_NO_DEBUG
# define IMPLDEFS_CF_DISABLE_ASSERT
#endif

/*
   PRECONDITION() macro, ie. function contract input checks.
 */
#undef  IMPLDEFS_CF_DISABLE_PRECONDITION

#ifdef CFG_IMPLDEFS_NO_DEBUG
# define IMPLDEFS_CF_DISABLE_PRECONDITION
#endif

/*
   POSTCONDITION() macro, ie. function contract output checks.
 */
#undef  IMPLDEFS_CF_DISABLE_POSTCONDITION

#ifdef CFG_IMPLDEFS_NO_DEBUG
# define IMPLDEFS_CF_DISABLE_POSTCONDITION
#endif

/**
   All assertion and function contract checks.
   (Ie. ASSERT(), PRECONDITION(), and POSTCONDITION() macros.)
 */
#undef  IMPLDEFS_CF_DISABLE_ASSERTION_CHECK

#ifdef CFG_IMPLDEFS_NO_DEBUG
# define IMPLDEFS_CF_DISABLE_ASSERTION_CHECK
#endif

/** Functionality that is omitted.
    Old sfzcl_snprintf (with renderer support) is no longer used by default. */
#define NO_SFZCL_SNPRINTF 1

/* Support for ISO 8859-2, 8859-3, and 8859-4 character set is omitted.
   For characters beyond ASCII, UTF-8 needs to be used instead. */
/* #define USE_SFZCL_CHARSET_ISO_8859_2_CONVERTER 1 */
/* #define USE_SFZCL_CHARSET_ISO_8859_3_CONVERTER 2 */
/* #define USE_SFZCL_CHARSET_ISO_8859_4_CONVERTER 3 */

#endif /* INCLUDE_GUARD_CF_IMPLDEFS_H */

/* end of file cf_impldefs.h */
