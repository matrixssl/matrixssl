/* implementation_defs_log.h
 *
 * Logging services for implementation_defs.h
 */

/*****************************************************************************
* Copyright (c) 2016 INSIDE Secure Oy. All Rights Reserved.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef INCLUDE_GUARD_IMPLEMENTATION_DEFS_LOG_H
#define INCLUDE_GUARD_IMPLEMENTATION_DEFS_LOG_H

#include "osdep_stdio.h"

/* Define L_ENABLE/L_DISABLE/L_DEFAULT_ENABLE/L_DEFAULT_DISABLE macros.
   These are used to define logging settings for LL_* (i.e. per log level)
   and LF_* (i.e. per log type).
 */
#define L_ENABLE ,
#define L_DISABLE , ,
#define L_DEFAULT_ENABLE , , ,
#define L_DEFAULT_DISABLE , , , ,

/* Printing settings per log level.
 */
#ifndef LL_ASSERT_CONTROL
# define LL_ASSERT__CONTROL L_ENABLE
#endif
#ifndef LL_CRIT__CONTROL
# define LL_CRIT__CONTROL L_ENABLE /* Currently not provided by front-end */
#endif
#ifndef LL_INFO__CONTROL
# define LL_INFO__CONTROL L_DISABLE /* Currently not provided by front-end */
#endif
#ifndef LL_DEBUG__CONTROL
# define LL_DEBUG__CONTROL L_DEFAULT_ENABLE
#endif
#ifndef LL_TRACE__CONTROL
# ifdef CFG_IMPLDEFS_ENABLE_TRACE
#  define LL_TRACE__CONTROL L_DEFAULT_ENABLE
# else
#  define LL_TRACE__CONTROL L_DEFAULT_DISABLE
# endif
#endif
#ifndef LL_TESTLOG__CONTROL
# define LL_TESTLOG__CONTROL L_ENABLE
#endif

/* Printing settings per log field.
   These are just examples (LF_DEBUG1 is log field never used).
 */
#define LF_DEBUG1__CONTROL L_ENABLE          /* Enabled, override LL_* settings */
#define LF_DEBUG2__CONTROL L_DISABLE         /* Disabled, override LL_* setting */
/* The following differ in default action: */
#define LF_DEBUG3__CONTROL L_DEFAULT_ENABLE  /* Follow LL_* setting */
#define LF_DEBUG4__CONTROL L_DEFAULT_DISABLE /* Follow LL_* setting */

/* L_CONCAT

   Concatenate parameters.
 */
#define L_CONCAT(a, b) L_CONCAT_(a, b)
#define L_CONCAT_(a, b) a ## b

/* L_PRINTF

   The L_PRINTF macro provides a single point of customization of the
   debug output mechanism. It takes debug level as first argument,
   debug flow as second and the variable argument containing fprintf-style
   format string and it's arguments.

   C99 requires that the ellipsis in macro calls contains at least one
   argument (unlike in function calls). To enable calls to L_PRINTF
   with plain format string, and to be able to concatenate a newline
   to format string, the L_PRINTF_OUTPUT_WRAP macro has to be called
   with single argument that is the list of the format string and rest
   of the parameters within parentheses with an extra argument; an
   empty string constant. This enables further macro layers to break
   format string to a separate argument.

   NOTE: Must not be called directly.
 */
/* Define L_PRINTF functionality, which uses
   L_PRINTF_OUTPUT_WRAP_INVOKE to find handler for output. */
#define L_PRINTF(__level, __flow, ...)          \
    L_PRINTF_OUTPUT_WRAP_INVOKE(__level, __flow)((                      \
                                                     L_STRINGIFY(__level) ", "           \
                                                     L_STRINGIFY(__flow) ", "            \
                                                     __FILELINE__ ": "                   \
                                                     "%s: "                              \
                                                     __VA_ARGS__, ""))

/* L_PRINTF_OUTPUT

   Final macro that calls DEBUG_printf with format string and format
   arguments. There is always as least one argument, the empty string
   added by L_PRINTF, so format can be separated from the ellipsis.

   The function DEBUG_printf, that is used for actual output, is
   declared below in this header.

   NOTE: Must not be called directly.
 */
/* Helper macro, which is invoked with #__VA_ARGS__ if the variable arguments
   are not used */
#define L_PRINTF_NOT_USED(string) /* empty */
/* If output is enabled, this macro will be invoked. */
#define L_PRINTF_OUTPUT(format, ...)                                 \
    (void) Printf(format "%s\n", FUNCTION_NAME, __VA_ARGS__)
#define L_PRINTF_OUTPUT_WRAP(arg) L_PRINTF_OUTPUT arg

/* If output is disabled, this macro will be invoked. */
#define L_PRINTF_IGNORE(format, ...)                                 \
    (void) L_PRINTF_NOT_USED(#__VA_ARGS__) 0
#define L_PRINTF_IGNORE_WRAP(arg) L_PRINTF_IGNORE arg

/* Choose OUTPUT/IGNORE wrap to invoke, according to __level. */
#define L_PRINTF_OUTPUT_WRAP_INVOKE(__level, __flow) \
    L_PRINTF_OUTPUT_WRAP_INVOKE_((L_CONCAT(__level, __CONTROL), \
                                  L_PRINTF_IGNORE_WRAP_INVOKE_DEFAULT(__flow), \
                                  L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT(__flow), \
                                  L_PRINTF_IGNORE_WRAP, \
                                  L_PRINTF_OUTPUT_WRAP, \
                                  L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT(__flow), ))

#define L_PRINTF_OUTPUT_WRAP_INVOKE_(arg) L_PRINTF_OUTPUT_WRAP_INVOKE__ arg
#define L_PRINTF_OUTPUT_WRAP_INVOKE__(ctrl, i1, i2, i3, i4, _d, ...) \
    L_PRINTF_NOT_USED(#__VA_ARGS__) _d
/* Choose OUTPUT/IGNORE wrap to invoke, according to __level,
   defaulting to "output" */
#define L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT(__flow) \
    L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT_((L_CONCAT(__flow, __CONTROL), \
                                          L_PRINTF_IGNORE_WRAP, \
                                          L_PRINTF_OUTPUT_WRAP, \
                                          L_PRINTF_IGNORE_WRAP, \
                                          L_PRINTF_OUTPUT_WRAP, \
                                          L_PRINTF_OUTPUT_WRAP, ))

/* Choose OUTPUT/IGNORE wrap to invoke, according to __level,
   defaulting to "ignore" */
#define L_PRINTF_IGNORE_WRAP_INVOKE_DEFAULT(__flow) \
    L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT_((L_CONCAT(__flow, __CONTROL), \
                                          L_PRINTF_IGNORE_WRAP, \
                                          L_PRINTF_OUTPUT_WRAP, \
                                          L_PRINTF_IGNORE_WRAP, \
                                          L_PRINTF_OUTPUT_WRAP, \
                                          L_PRINTF_IGNORE_WRAP, ))

#define L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT_(arg) \
    L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT__ arg
#define L_PRINTF_OUTPUT_WRAP_INVOKE_DEFAULT__(ctrl, i1, i2, i3, i4, _d, ...) \
    L_PRINTF_NOT_USED(#__VA_ARGS__) _d

#endif /* INCLUDE_GUARD_IMPLEMENTATION_DEFS_LOG_H */

/* end of file implementation_defs_log.h */
