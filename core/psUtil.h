/**
 *      @file    psUtil.h
 *      @version $Format:%h%d$
 *
 *      Useful utility macros and functions. These macros and functions
 *  are intended to allow easier use of common idioms and to provide
 *  simple extensions to functions provided by C language standard.
 *
 *  These macros and functions can be used in programs using SafeZone
 *  and MatrixSSL software or related software components.
 */
/*
 *      Copyright (c) 2017 INSIDE Secure Corporation
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

#ifndef _h_PS_UTIL
# define _h_PS_UTIL

/******************************************************************************/
/*
    psCore helper macros: for communicating with compiler
    These macros allow to remove spurious warnings or to compile with C++
    compiler.
 */

/* Produce specified output only on C++ compilers.
   This macro is intended to help with small differences between C and C++. */
# ifdef __cplusplus
#  define PS_CPLUSPLUS_ONLY(text) text
# else
#  define PS_CPLUSPLUS_ONLY(text_ignored) /* nothing */
# endif /* __cplusplus */

/* Additional typecast which is only needed on C++ code. */
# define PS_CPLUSPLUS_CAST(target_type) PS_CPLUSPLUS_ONLY((target_type))

/* Special versions of PS_CPLUSPLUS_ONLY allowing balancing of braces. */
# define PS_CPLUSPLUS_ONLY_FIRST(text, ignored) PS_CPLUSPLUS_ONLY(text)
# define PS_CPLUSPLUS_ONLY_LAST(ignored, text) PS_CPLUSPLUS_ONLY(text)

/* Begin "C" definitions. */
# define PS_EXTERN_C_BEGIN PS_CPLUSPLUS_ONLY_FIRST(extern "C" {, })

/* End "C" definitions. */
# define PS_EXTERN_C_END PS_CPLUSPLUS_ONLY_LAST({, })

/* Select output: C99_or_older_C */
# define PS_C99_OR_OLDER(text_c99, text_pre99) text_pre99
# ifdef __STDC_VERSION__
#  if __STDC_VERSION__ >= 199901L
/* C99 available. */
#   undef PS_C99_OR_OLDER
#   define PS_C99_OR_OLDER(text_c99, text_pre99) text_c99
#  endif /* __STDC_VERSION__ >= 199901L */
# endif  /* __STDC_VERSION__ */

/* Tell compiler a variable is intended that it can be set, but not used.
   (The variable is for debugging, future extension or used in some
   conditionally disabled/unifdeffed branches of execution). */
# define PS_VARIABLE_SET_BUT_UNUSED(x) do { (void) (x); } while (0)

/* Tell compiler a variable is intended that it can be unused.
   This is for compilers which detect variables that are not set.
   (The variable is for debugging, future extension or used in some
   conditionally disabled/unifdeffed branches of execution). */
# define PS_VARIABLE_UNUSED(x) do { (void) (x); } while (0)

/* Tell compiler a function parameter is intended that it can be unused.
   This is for compilers which detect parameters that are not used.
   (The parameter is for debugging, future extension or used in some
   conditionally disabled/unifdeffed branches of execution). */
# define PS_PARAMETER_UNUSED(x) do { (void) (x); } while (0)


/******************************************************************************/
/*
    Generic helper macros.
 */

/* Get smaller of two values. */
# define PS_MIN(m_a, m_b)    (((m_a) < (m_b)) ? (m_a) : (m_b))

/* Get larger of two values. */
# define PS_MAX(m_a, m_b)    (((m_a) > (m_b)) ? (m_a) : (m_b))

/* Provide alias for assertions.
   Note: This macro is also defined in osdep.h.
   The definition in osdep.h is intended for implementation of MatrixSSL
   software components, and the definition here is provided as convenience for
   software using matrixssl. */
# ifndef psAssert
#  include <assert.h>
#  define psAssert(x) assert(x)
# endif /* psAssert already defined */

/* produce debug output: This output is directed to standard output.
   Note: This macro is also defined in osdep.h.
   The definition in osdep.h is intended for implementation of MatrixSSL
   software components, and the definition here is provided as convenience for
   software using matrixssl. */
# ifndef psTrace
#  include <stdio.h>
#  define psPrint(x) printf("%s", (x))
#  define psPrintInt(x, i) printf(x, (i))
#  define psPrintStr(x, s) printf(x, (s))
#  define psPrintPtr(x, p) printf(x, (p))
#  define psTrace(x) printf("%s", (x))
#  define psTraceInt(x, i) printf(x, (i))
#  define psTraceStr(x, s) printf(x, (s))
#  define psTracePtr(x, p) printf(x, (p))
#  define psError(x) fprintf(stderr, "%s", (x))
#  define psErrorInt(x, i) fprintf(stderr, x, (i))
#  define psErrorStr(x, s) fprintf(stderr, (s))
#  define psErrorPtr(x, p) fprintf(stderr, (p))
#  define psPrintf(...) printf(__VA_ARGS__)
#  define psTracef(...) printf(__VA_ARGS__)
#  define psErrorf(...) fprintf(stderr, __VA_ARGS__)
# endif

/* Equivalent to sizeof, but returns result in psSize_t type. */
# define PS_SIZEOF(x) ((psSize_t) sizeof(x))

/* Equivalent to sizeof, but returns result in psSize32_t type. */
# define PS_SIZEOF32(x) ((psSize32_t) sizeof(x))

/******************************************************************************/
/*
    Temporary memory allocation for small and medium sized temporaries.
    These macros allow compile time decision between preferring stack or
    dynamic memory allocation for storage.
 */

/* Allocate array from stack or heap. */
# define PS_TEMP_ARRAYZ(type, ptr_name, constant_length)             \
    PS_TEMP_DEF_ARRAY(type, ptr_name, constant_length) =            \
        PS_TEMP_ALLOC_ARRAYZ(type, ptr_name, constant_length)

/* Check allocation was successful. */
# define PS_TEMP_IS_OK(ptr_name)                 \
    ((ptr_name) != NULL)

/* Free array allocated temporary. */
# define PS_TEMP_FINISH(ptr_name) PS_TEMP_FREE_ARRAYZ(ptr_name)

/* Free array first creating a duplicate (for returning).
   Currently uses statement expressions. */
# define PS_TEMP_RETURN_DUP(ptr_name, dupfunc) /* Defined below. */

/* Zeroize and free array: internals. */
# define PS_TEMP_FREE_ARRAYZ(ptr_name)                         /* see end of this file for definition */
# define PS_TEMP_ALLOC_ARRAYZ(type, ptr_name, constant_length) /* -"- */

/* Temporary allocation internals: */
# define PS_TEMP_DEF_ARRAY(type, ptr_name, constant_length)  \
    type(ptr_name)[constant_length]

/* Allocate specified sized zero initialized item from stack. */
# define PS_TEMP_ALLOC_ARRAYZ_STACK(type, ptr_name, constant_length) \
    PS_C99_OR_OLDER(& ((type [constant_length]) { 0 }), \
    psMemzeroSR(alloca(sizeof(ptr_name)), sizeof(ptr_name)))

# include <stdlib.h>

/* Allocate specified sized zero initialized item dynamically. */
# define PS_TEMP_ALLOC_ARRAYZ_DYNAMIC(type, ptr_name, constant_length) \
    PS_CPLUSPLUS_CAST(type(*)[constant_length]) calloc(sizeof(ptr_name), 1)

/* Allocate specified sized zero initialized item from stack. */
# define PS_TEMP_FREE_ARRAYZ_STACK(ptr_name) \
    psMemzeroS(ptr_name, sizeof(ptr_name))

/* Allocate specified sized zero initialized item from stack. */
# define PS_TEMP_FREE_ARRAYZ_DYNAMIC(ptr_name)       \
    free(psMemzeroSR(ptr_name, sizeof(ptr_name)))

/* Return specified type. */
# define PS_TEMP_RETURN_DUP_STACK(ptr_name, dupfunc) \
    psMemzeroSRR(ptr_name, sizeof(ptr_name), dupfunc(ptr_name))

/* Return specified type. */
# define PS_TEMP_RETURN_DUP_DYNAMIC(ptr_name, dupfunc) \
    psFreeFRR(free, ptr_name, dupfunc(ptr_name))

/******************************************************************************/
/*
    Helper utility functions.
    Beware: Some of these may be implemented via function like macros or
    compiler intrinsics.
 */

PS_EXTERN_C_BEGIN

/* Initialize memory with specified value.
   The effect of the function is never optimized out by the compiler.
   If pointer is NULL, no memory bytes are written.
   Returns the value passed in as input. */
void *psMemsetSR(void *s, int c, psSizeL_t n);

/* Initialize memory with zero value.
   The effect of the function is never optimized out by the compiler.
   If pointer is NULL, no memory is zeroized.
   Returns the value passed in as input. */
void *psMemzeroSR(void *s, psSizeL_t n);

/* Initialize memory with specified value.
   The effect of the function is never optimized out by the compiler.
   If pointer is NULL, no memory bytes are written. */
void psMemsetS(void *s, int c, psSizeL_t n);

/* Initialize memory with zero value.
   The effect of the function is never optimized out by the compiler.
   If pointer is NULL, no memory is zeroized. */
void psMemzeroS(void *s, psSizeL_t n);

/* Initialize memory with specified value.
   The effect of the function is never optimized out by the compiler.
   If pointer is NULL, no memory bytes are written.
   Returns the value passed in as return value input. */
void *psMemsetSRR(void *s, int c, psSizeL_t n, void *ret);

/* Initialize memory with zero value.
   The effect of the function is never optimized out by the compiler.
   If pointer is NULL, no memory is zeroized.
   Returns the value passed in as return value input. */
void *psMemzeroSRR(void *s, psSizeL_t n, void *ret);

/* Free memory using specified free function.
   Then return specified return value. */
void *psFreeFRR(void (*free_func)(void *ptr), void *ptr, void *ret);

/* Allocate copy of specified string (psMalloc). */
char *psStrdupN(const char *string);

/* Free (no pool specified): This must be a real function. */
void psFreeN(void *ptr);

/* These are implemented as macros, to allow compiler intrinsics to be
   used. */
# include <string.h>

/* Simple C string functions.
   Some of the APIs use them via these macros. */
# define psMemcpy memcpy
# define psMemmove memmove
# define psMemset memset
# define psStrcmp strcmp
# define psStrncmp strncmp
# define psStrlen strlen

PS_EXTERN_C_END

/* Include memory allocation capabilities: They are currently separate
   file than psUtil.h. psmalloc.h is included after _h_PS_UTIL to allow
   it to make use of macros defined above. */
# include "psmalloc.h"

#endif /* _h_PS_UTIL */

/* The remaining part is intentionally outside the _h_PS_UTIL.
   It is possible to multiply include the header and change
   PS_TEMP_IS_DYNAMIC between inclusions. */

/* Temporary allocation internals: switch PS_TEMP_IS_DYNAMIC */
#undef PS_TEMP_ALLOC_ARRAYZ
#undef PS_TEMP_FREE_ARRAYZ
#undef PS_TEMP_RETURN_DUP
#ifdef PS_TEMP_IS_DYNAMIC
# define PS_TEMP_ALLOC_ARRAYZ(type, ptr_name, constant_length)   \
    PS_TEMP_ALLOC_ARRAYZ_DYNAMIC(type, ptr_name, constant_length)
# define PS_TEMP_FREE_ARRAYZ(ptr_name)   \
    PS_TEMP_FREE_ARRAYZ_DYNAMIC(ptr_name)
# define PS_TEMP_RETURN_DUP(ptr_name, dupfunc) \
    PS_TEMP_RETURN_DUP_DYNAMIC(ptr_name, dupfunc)
#else
# define PS_TEMP_ALLOC_ARRAYZ(type, ptr_name, constant_length)   \
    PS_TEMP_ALLOC_ARRAYZ_STACK(type, ptr_name, constant_length)
# define PS_TEMP_FREE_ARRAYZ(ptr_name)   \
    PS_TEMP_FREE_ARRAYZ_STACK(ptr_name)
# define PS_TEMP_RETURN_DUP(ptr_name, dupfunc) \
    PS_TEMP_RETURN_DUP_STACK(ptr_name, dupfunc)
#endif /* PS_TEMP_IS_DYNAMIC */

/* end of psUtil.h */
