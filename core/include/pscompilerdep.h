/**
 *      @file    pscompilerdep.h
 *      @version $Format:%h%d$
 *
 *      Compiler Pragmas/Diagnostics Capabilities Abstraction.
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#ifndef _h_PS_COMPILERDEP
# define _h_PS_COMPILERDEP

/* Compiler detection. */

/* Detect GCC 4.x series. */
# ifdef __GNUC__
#  if __GNUC__ == 4
#   define __GNUC4__ /* 4.x series GNU C. These default to C89 standard,
                        which has to be considered in some of the code. */
#  endif
/* For all GCC versions, provide version as single number for easier range
   matching. */
#  define __GCC_VERSION ((__GNUC__ * 1000000) |                         \
                         (__GNUC_MINOR__ * 1000) |                      \
                         (__GNUC_PATCHLEVEL__))
# else /* __GNUC__ */
# define __GCC_VERSION 0 /* No GCC. */
# endif

/* Detect ARM DS-5 compiler. */
# ifdef __ARMCC_VERSION
#  if __ARMCC_VERSION < 6000000
#   define __ARMCC5 /* armcc prior 6.0 (not clang-based) */
#   undef inline
#   define inline __inline /* Use compiler specific inline keyword. */
#  endif
# endif /* __ARMCC_VERSION */

/* Mark API function as deprecated. */
#define PSDEPRECATED /* the following function is deprecated. */

/* Control for diagnostics on deprecated functions.
   PSDEPRECATED_START ... PSDEPRECATED_END allows section where
   deprected functions are allowed. */
#ifdef __GNUC__
#if ( __GNUC__ == 4 && __GNUC_MINOR__ >= 8 ) || __GNUC__ >= 5
#define PSDEPRECATED_START /* Omit deprecated warnings */ \
    _Pragma( "GCC diagnostic push" )                      \
    _Pragma( "GCC diagnostic ignored \"-Wdeprecated-declarations\"" )
#define PSDEPRECATED_END /* end section with omitted warnings */ \
    _Pragma( "GCC diagnostic pop" )
#endif
#endif

/* Mark API function as deprecated, and warn when it is used if compiler
   provides the capability. This only happens on GCC 4.8 or later. */
#ifdef PSDEPRECATED_START
#define PSDEPRECATED_WARN __attribute__((__deprecated__))
#else
#define PSDEPRECATED_WARN /* silently ignored on compilers
                             not providing PSDEPRECATED_START.
                             Note: Header will still advice function is
                             deprecated. */
#endif

/* If compiling source files that intentionally use deprecated functions,
   omit warnings. (For instance implementation may use deprecated functions
   internally as components of implementation.) */
#ifdef CONTAINS_DEPRECATED_FUNCTION_CALLS
#undef PSDEPRECATED_WARN
#define PSDEPRECATED_WARN PSDEPRECATED
#endif /* CONTAINS_DEPRECATED_FUNCTION_CALLS */

#ifndef PSDEPRECATED_START
#define PSDEPRECATED_START /* this code may call deprecated functions. */
#define PSDEPRECATED_END /* end of section. */
#endif

#ifdef __GNUC__
/* Mark intentionally unused functions. */
#define PSFUNC_UNUSED __attribute__((__unused__))
#else
/* Mark intentionally unused functions (can used compiler specific
   directive) here. */
#define PSFUNC_UNUSED /* __attribute__((__unused__)) */
#endif


#endif  /* _h_PS_COMPILERDEP */

