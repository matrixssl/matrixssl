/* implementation_defs.h
 *
 * Description: See below.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

/*
   This header provides implementation definitions required by the
   SafeZone Software Modules. The definitions are used only in the
   implementation code including module internal header and
   implementation files. This header file shall not be included from
   any public header.

   The definitions provided are:

   - possibility to use static inline for function definitions
   - MIN() and MAX() macros
   - BIT_N constants
   - BIT_CLEAR, BIT_SET, BIT_IS_SET macros
   - definition of NULL
   - definition of offsetof
   - macro PARAMETER_NOT_USED
   - Logging macros
   - macro PRECONDITION
   - macro POSTCONDITION
   - macro PANIC

   This particular header should is used for building on basic
   development platforms that are Linux and Win32.
 */

#ifndef INCLUDE_GUARD_IMPLEMENTATION_DEFS_H
#define INCLUDE_GUARD_IMPLEMENTATION_DEFS_H


#include "public_defs.h" /* include public defs for convenience */
#include "cf_impldefs.h" /* include configuration options */

/*
   Enable static inline
 */
#if (defined(WIN32) || defined(__CC_ARM))
# define inline __inline
#endif


/* MIN, MAX

   Evaluate to maximum or minimum of two values.

   NOTE:

   warning for side-effects on the following two macros since the
   arguments are evaluated twice changing this to inline functions is
   problematic because of type incompatibilities
 */
#define MIN(_x, _y) ((_x) < (_y) ? (_x) : (_y))
#define MAX(_x, _y) ((_x) > (_y) ? (_x) : (_y))

/* BIT_n

   Bit positions for 32-bit values.

   using postfix "U" to be compatible with uint32
   ("UL" is not needed and gives lint warning)
 */
#define BIT_0   0x00000001U
#define BIT_1   0x00000002U
#define BIT_2   0x00000004U
#define BIT_3   0x00000008U
#define BIT_4   0x00000010U
#define BIT_5   0x00000020U
#define BIT_6   0x00000040U
#define BIT_7   0x00000080U
#define BIT_8   0x00000100U
#define BIT_9   0x00000200U
#define BIT_10  0x00000400U
#define BIT_11  0x00000800U
#define BIT_12  0x00001000U
#define BIT_13  0x00002000U
#define BIT_14  0x00004000U
#define BIT_15  0x00008000U
#define BIT_16  0x00010000U
#define BIT_17  0x00020000U
#define BIT_18  0x00040000U
#define BIT_19  0x00080000U
#define BIT_20  0x00100000U
#define BIT_21  0x00200000U
#define BIT_22  0x00400000U
#define BIT_23  0x00800000U
#define BIT_24  0x01000000U
#define BIT_25  0x02000000U
#define BIT_26  0x04000000U
#define BIT_27  0x08000000U
#define BIT_28  0x10000000U
#define BIT_29  0x20000000U
#define BIT_30  0x40000000U
#define BIT_31  0x80000000U
#define BIT_ALL 0xffffffffU


/* BIT_CLEAR

   Clear bits enabled __bit in variable __bits.
 */
#define BIT_CLEAR(__bits, __bit) \
    do {                         \
        (__bits) &= ~(__bit);    \
    } while (0)


/* BIT_SET

   Enable bits enabled __bit in variable __bits.
 */
#define BIT_SET(__bits, __bit)   \
    do {                         \
        (__bits) |= (__bit);     \
    } while (0)


/* BIT_IS_SET

   Evaluate to true if one or more bits enabled in __bit are
   enabled in __bits.
 */
#define BIT_IS_SET(__bits, __bit) (((__bits) & (__bit)) != 0)


/* ALIGNED_TO

   Return true if Value is Alignment aligned; false otherwise. That is
   if Value modulo Alignment equals 0.

   NOTE: Only Alignments that are power of 2 are supported. False is
   returned is Alignment is not a power of 2.
 */
#define ALIGNED_TO(Value, Alignment)                                    \
    ((((((Alignment) & (Alignment - 1)) == 0) &&                        \
       ((uintptr_t) (Value) & (Alignment - 1))) == 0) ? true : false)


/* PARAMETER_NOT_USED()

   To mark function input parameters that are purposely not used in
   the function and to prevent compiler warnings on them.
 */
#define PARAMETER_NOT_USED(__identifier)        \
    do { if (__identifier) {} } while (0)


/* IDENTIFIER_NOT_USED()

   To mark function input parameters or local variables that are
   purposely not used in the function and
   to prevent compiler warnings on them.
 */
#define IDENTIFIER_NOT_USED(__identifier)        \
    do { if (__identifier) {} } while (0)


/* NULL
 */
#ifndef NULL
# define NULL 0
#endif


/* offsetof
 */
#ifndef offsetof
# define offsetof(type, member) ((size_t) &(((type *) NULL)->member))
#endif


/* alignmentof
 */
#define alignmentof(type) (offsetof(struct { char x; type y; }, y))
#ifdef WIN32
# pragma warning(disable: 4116)
#endif


/* L_STRINGIFY

   Convert parameter preprocessor token to a string constant.
 */
#define L_STRINGIFY(x) #x


/* L_TOSTRING

   Convert value of parameter preprocessor constant token to a string.
 */
#define L_TOSTRING(x) L_STRINGIFY(x)


/* __FILELINE__

   Macro __FILELINE__ combines __FILE__ and __LINE__ preprocessor
   macros into a single macro with a string value.
   As an example: If __FILE__ would have value "file.c" and
   __LINE__ value 24, the __FILELINE__ would become "file.c:24".

   Some compilers have the full path in __FILE__.
   Some compilers have __MODULE__, which is __FILE__ but without the path.
 */
#undef __FILELINE__
#ifdef __MODULE__
# define __FILELINE__ __MODULE__ ":" L_TOSTRING(__LINE__)
#else
# define __FILELINE__ __FILE__   ":" L_TOSTRING(__LINE__)
#endif

#ifndef IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF
# include "implementation_defs_log.h"
#else /* IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF */
# define L_PRINTF(__level, __flow, ...)      \
    do { /* L_PRINTF disabled */ L_PRINTF_NOT_USED(#__VA_ARGS__) } while (0)
# define L_PRINTF_NOT_USED(string) /* empty */
#endif /* !IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF */

/* FUNCTION_NAME

   Macro that expands a pointer to a constant character string giving
   representing a name of the function in which used.

   C99 standard specifies this as __func__, VC uses __FUNCTION__.

 */
#ifdef WIN32
# define FUNCTION_NAME __FUNCTION__
#else
# define FUNCTION_NAME __func__
#endif

#include "psLog.h" /* SafeZone/Matrix common logging framework */
/* L_DEBUG

   The L_DEBUG macro takes a debug flow as its first argument and the
   variable part is fprintf-style format string and it's parameters.
 */
#define L_DEBUG(__flow, fmt, ...) PS_LOGF_DEBUG_LN(__flow, fmt ,##__VA_ARGS__ )

#include "psLog.h" /* SafeZone/Matrix common logging framework */
/* L_TRACE

   The L_TRACE macro takes a debug flow as its first argument and the
   variable part is fprintf-style format string and it's parameters.
 */
#define L_TRACE(__flow, fmt, ...) PS_LOGF_TRACE_LN(__flow, fmt ,##__VA_ARGS__ )

/* L_TESTLOG

   The L_TESTLOG macro is used internally by unit testing.
   Although L_TESTLOG seems similar to L_DEBUG and L_TRACE,
   it must not be used directly (except from CHECK_* implementation).
   Also, it is typically required that logs printed with this statement
   are immediately printed out where as other logs may be delayed.
 */
#define L_TESTLOG(__event, ...)                    \
    L_PRINTF( LL_TESTLOG, __event, __VA_ARGS__ )

/* ASSERTION_CHECK()

   The ASSERTION_CHECK macro is a helper macro for implementing actual
   assertion macros: ASSERT(), PRECONDITION, and POSTCONDITION.

   The macro check given condition. When condition evaluates to false
   the execution is aborted. By default this is done calling
   DEBUG_abort() function declared below in this header.

   The macro aborts the execution calling. By default this is done calling
   DEBUG_abort() function declared below in this header.

   This macro should not be called directly.
 */
#ifdef IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF
# ifdef __KERNEL__
#  define ASSERTION_CHECK(__flow, __condition, __description)     \
    ({ if (!(__condition)) { BUG(); } })
# else
#  define ASSERTION_CHECK(__flow, __condition, __description)     \
    (void) ((__condition) ? 0 :                                  \
            ( DEBUG_abort(), 0 ) )
# endif /* __KERNEL__ */
#else /* !defined IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF */
# ifdef __KERNEL__
#  define ASSERTION_CHECK(__flow, __condition, __description)              \
    ({ if (!(__condition)) { L_PRINTF(LL_ASSERT, __flow, __description   \
                                 ", function %s: %s", __FUNCTION__, \
                                 #__condition);                     \
                             BUG(); } })
# else
#  define ASSERTION_CHECK(__flow, __condition, __description)     \
    (void) ((__condition) ? 0 :                                 \
            ( L_PRINTF(LL_ASSERT,                              \
                  __flow,                                 \
                  __description ", function %s: %s",      \
                  __FUNCTION__,                           \
                  #__condition),                          \
              DEBUG_abort(),                                   \
              0 ) )
# endif /* __KERNEL__ */
#endif  /* IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF */

#ifdef IMPLDEFS_CF_DISABLE_ASSERTION_CHECK
/* Disable all assertion checks and contract checks. */

# ifndef IMPLDEFS_CF_DISABLE_ASSERT
#  define IMPLDEFS_CF_DISABLE_ASSERT
# endif

# ifndef IMPLDEFS_CF_DISABLE_PRECONDITION
#  define IMPLDEFS_CF_DISABLE_PRECONDITION
# endif

# ifndef IMPLDEFS_CF_DISABLE_POSTCONDITION
#  define IMPLDEFS_CF_DISABLE_POSTCONDITION
# endif
#endif /* IMPLDEFS_CF_DISABLE_ASSERTION_CHECK */


/* ASSERT()

   The ASSERT macro provides a "normal" assert.
 */
#ifndef IMPLDEFS_CF_DISABLE_ASSERT
# define ASSERT(__condition)                     \
    ASSERTION_CHECK(                            \
    LF_ASSERT,                          \
    (__condition),                      \
    "assertion failed")
#else /* IMPLDEFS_CF_DISABLE_ASSERT */
# define ASSERT(__condition)                     \
    (void) ((__condition) ? 0 : 0)
#endif /* !IMPLDEFS_CF_DISABLE_ASSERT */


/* PARAMETER_CHECK

   To validate the parameters passed into a function. This macro,
   if turned on evaluates the given condition and if found to be
   true, makes the calling function return the given second argument.
   This macro should only be called in beginning of functions, after local
   variables and PARAMETER_UNUSED. In the case of void functions, please
   prefer to use PRECONDITION instead.
 */
#ifndef IMPLDEFS_CF_DISABLE_PARAMETER_CHECK
# define PARAMETER_CHECK(__condition, __ret_val)  \
    if ((__condition)) return (__ret_val)
#else /* IMPLDEFS_CF_DISABLE_PARAMETER_CHECK */
# define PARAMETER_CHECK(__condition, __ret_val) \
    do { /* PARAMETER checks disabled. */ } while (0)
#endif /* !IMPLDEFS_CF_DISABLE_PARAMETER_CHECK */

/* PRECONDITION

   To define preconditions of a function. Preconditions are conditions
   that the implementation of the function assumes to hold when the
   function is called. Preconditions are not to be checked by
   production builds and no errors are returned when preconditions do
   not hold. Defining preconditions with this macro documents clearly
   what is assumed to hold and provides a possibility to assert such
   conditions on debug builds.
 */
#ifndef IMPLDEFS_CF_DISABLE_PRECONDITION
# define PRECONDITION(__condition)               \
    ASSERTION_CHECK(                            \
    LF_CONDITION,                       \
    (__condition),                      \
    "precondition failed")
#else /* IMPLDEFS_CF_DISABLE_PRECONDITION */
# define PRECONDITION(__condition) \
    do { /* preconditions disabled. */ } while (0)
#endif /* !IMPLDEFS_CF_DISABLE_PRECONDITION */

/* POSTCONDITION

   To define postconditions of a function. Same rationale as for
   PRECONDITION above.
 */
#ifndef IMPLDEFS_CF_DISABLE_POSTCONDITION
# define POSTCONDITION(__condition)              \
    ASSERTION_CHECK(                            \
    LF_CONDITION,                       \
    (__condition),                      \
    "postcondition failed")
#else /* IMPLDEFS_CF_DISABLE_POSTCONDITION */
# define POSTCONDITION(__condition) \
    do { /* postconditions disabled. */ } while (0)
#endif /* !IMPLDEFS_CF_DISABLE_POSTCONDITION */


/* PANIC()

   Macro to be called from code branches that should never be reached.
   The macro aborts the execution calling. By default this is done calling
   DEBUG_abort() function declared below in this header.
 */
#ifdef IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF
# ifdef __KERNEL__
#  define PANIC(...) BUG()
# else
#  define PANIC(...)                              \
    (void)                                      \
    (DEBUG_abort())
# endif /* __KERNEL__ */
#else /* !defined IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF */
# ifdef __KERNEL__
#  define PANIC(...)                              \
    ({ L_PRINTF(                                \
           LL_ASSERT,                          \
           LF_PANIC,                           \
           "PANIC: " __VA_ARGS__);             \
       BUG(); })
# else
#  define PANIC(...)                              \
    (void)                                      \
    (L_PRINTF(                                  \
         LL_ASSERT,                          \
         LF_PANIC,                           \
         "PANIC: " __VA_ARGS__),             \
     DEBUG_abort())
# endif /* __KERNEL__ */
#endif  /* IMPLDEFS_CF_DISABLE_DEBUG_L_PRINTF */


/* COMPILE_GLOBAL_ASSERT

   Macro to make global scope compile time assertions. The condition
   must be a constant C expression (expression that can be evaluated
   at compile time) evaluating to true when the required condition
   holds and to false otherwise.

   When condition evaluates to true the macro has no effect.

   When condition evaluates to false the compilation fails due to
   declaration of arrays of size -1.
 */
#define COMPILE_GLOBAL_ASSERT(condition)                                \
    extern int global_assert_ ## description[1 - 2 * (!(condition))]


/* COMPILE_STATIC_ASSERT

   Macro to make function scope compile time assertions. The condition
   must be a constant C expression (expression that can be evaluated
   at compile time) evaluating to true when the required condition
   holds and to false otherwise.

   When condition evaluates to true the macro has no effect.

   When condition evaluates to false the compilation fails due to
   declaration of arrays of size -1.
 */
#define COMPILE_STATIC_ASSERT(condition)                                \
    do {                                                                \
        int static_assertion[1 - 2 * (!(condition))] = { 1 }; \
        if (static_assertion[0])                                        \
        { /* Nothing */ }                                               \
    } while (0)


/* UNREACHABLE

   Macro to mark locations that are never reached by code execution.
   This macro can be used by compiler to analyze the source code and
   notice paths that are never taken. Some compilers may use this
   to optimize produced code betetr, other may use it to ensure the
   patchs unreachable are factually unreachable.
 */
#define UNREACHABLE ASSERT(0 /* This code shall never be reached. */)


/* Define C99 fixed with integer print formatting macros for Windows.
   On most GCC platforms include <inttypes.h>
 */

#if defined(WIN32) || defined(__KERNEL__)

# define PRId8  "hhd"
# define PRIi8  "hhi"
# define PRIo8  "hho"
# define PRIu8  "hhu"
# define PRIx8  "hhx"
# define PRIX8  "hhX"

# define PRId16 "hd"
# define PRIi16 "hi"
# define PRIo16 "ho"
# define PRIu16 "hu"
# define PRIx16 "hx"
# define PRIX16 "hX"

# define PRIi32 "i"
# define PRId32 "d"
# define PRIo32 "o"
# define PRIu32 "u"
# define PRIx32 "x"
# define PRIX32 "X"

# define PRIi64 "lli"
# define PRId64 "lld"
# define PRIo64 "llo"
# define PRIu64 "llu"
# define PRIx64 "llx"
# define PRIX64 "llX"

#elif (defined(__GNUC__) || defined(__CC_ARM))
# include "osdep_inttypes.h"
#else
# error Unsupported platform
#endif

/* Definitions of functions defined in DEBUG module.
   Always only use these via L_* macros. */
extern void DEBUG_abort(void);

/* DEBUG_printf has been deprecated.
   Only provide prototype if explictly requested. */
#ifdef IMPLDEFS_NEED_DEBUG_PRINTF
#ifdef __GNUC__
extern int  DEBUG_printf(
    const char *format, ...)
__attribute__ ((format(printf, 1, 2)));
#else
extern int  DEBUG_printf(
    const char *format, ...);
#endif
#endif

/* Make wide character type available.
   Wide characters are actually not supported in debug printing,
   but silently truncated to 8-bit characters. */
#ifndef __WCHAR_TYPE__
# include "osdep_wchar.h"
# ifndef __WCHAR_TYPE__
#  define __WCHAR_TYPE__ wchar_t
# endif /* __WCHAR_TYPE__ */
#endif  /* __WCHAR_TYPE__ */

#endif  /* Include guard */

/* end of file implementation_defs.h */
