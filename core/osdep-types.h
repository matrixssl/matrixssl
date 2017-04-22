/**
 *      @file    osdep-types.h
 *      @version $Format:%h%d$
 *
 *      Operating System and Hardware Abstraction Layer: type definitions.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
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

#ifndef _h_PS_PLATFORM_TYPES
# define _h_PS_PLATFORM_TYPES

/******************************************************************************/
/*
    Platform detection based on compiler settings
    @see http://sourceforge.net/p/predef/wiki/Home/
 */
/* Determine the operating system (if any) */
# if defined(__linux__) /* Linux and Android */
#  define POSIX
#  define LINUX
#  define MATRIX_USE_FILE_SYSTEM
# elif defined(__APPLE__) && defined(__MACH__) /* Mac OS X */
#  define POSIX
#  define OSX
#  define HAVE_NATIVE_INT64
#  define MATRIX_USE_FILE_SYSTEM
# elif defined(_WIN32) /* Windows */
#  ifndef WIN32
#   define WIN32
#  endif
#  define HAVE_NATIVE_INT64
#  define MATRIX_USE_FILE_SYSTEM
# endif
/* For others such as FREERTOS, define in build system */

/* Use packed attribute on compilers that support it */
# if defined(__GNUC__) || defined(__clang__)
#  define PACKED __attribute__((__packed__))
# else
#  define PACKED
# endif

/* Determine which assembly language optimizations we can use */
# if defined(__GNUC__) || defined(__clang__) /* Only supporting gcc-like */
#  if defined(__x86_64__)
#   define PSTM_X86_64
#   define PSTM_64BIT /* Supported by architecture */
#  elif defined(__i386__)
#   define PSTM_X86
#  elif defined(__arm__)
#   define PSTM_ARM
/* __aarch64__ / * 64 bit arm * / */
/* __thumb__ / * Thumb mode * / */
#  elif defined(__mips__)
#   if defined(__mips64)
#    define PSTM_64BIT
#   else
#    define PSTM_MIPS /* MIPS assembly supported on 32 bit only */
#   endif
#  elif defined(__aarch64__)
#   define PSTM_64BIT /* Supported by architecture */
#  endif
# endif /* GNUC/CLANG */

/* Try to determine if the compiler/platform supports 64 bit integer ops */
# if !defined(HAVE_NATIVE_INT64) && defined(__SIZEOF_LONG_LONG__)
#  define HAVE_NATIVE_INT64 /* Supported by compiler */
# endif

/* Detect endian based on platform */
# if (defined __LITTLE_ENDIAN__ || defined __i386__ || defined __x86_64__ || \
      defined _M_X64 || defined _M_IX86 || \
      defined __ARMEL__ || defined __MIPSEL__)
#  define __ORDER_LITTLE_ENDIAN__ 1234
#  define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
# elif (defined __BIG_ENDIAN__ || defined __MIPSEB__)
#  define __ORDER_BIG_ENDIAN__ 4321
#  define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__
# endif

# ifdef __BYTE_ORDER__       /* Newer GCC and LLVM */
#  if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#   define ENDIAN_LITTLE
#  else
#   define ENDIAN_BIG
#  endif
#  ifdef PSTM_64BIT
#   define ENDIAN_64BITWORD
#  else
#   define ENDIAN_32BITWORD
#  endif
# else
#  if (defined(_MSC_VER) && defined(WIN32)) || \
    (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || \
    defined(__MINGW32__) || defined(__i386__)))
#   define ENDIAN_LITTLE
#   define ENDIAN_32BITWORD
#  else
#   warning "Cannot determine endianness, using neutral"
#  endif
/* #define ENDIAN_LITTLE */
/* #define ENDIAN_BIG */

/* #define ENDIAN_32BITWORD */
/* #define ENDIAN_64BITWORD */
# endif

# if (defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE)) && \
    !(defined(ENDIAN_32BITWORD) || defined(ENDIAN_64BITWORD))
#  error You must specify a word size as well as endianness
# endif

# if !(defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE))
#  define ENDIAN_NEUTRAL
# endif

/******************************************************************************/
/*
    APIs that must be implemented on every platform
 */

# ifdef WIN32
#  ifdef _LIB   /* Static library */
#   define PSPUBLIC extern
#  else
#   ifdef _USRDLL   /* DLL */
#    define PSPUBLIC extern __declspec(dllexport)
#   else
#    define PSPUBLIC extern __declspec(dllimport)
#   endif
#  endif
# else
#  define PSPUBLIC extern
# endif /* !WIN32 */

/******************************************************************************/
/*
    If the Makefile specifies that MatrixSSL does not currently have
    a layer for the given OS, or the port is to "bare metal" hardware,
    do basic defines here and include externally provided file "matrixos.h".
    In addition, if building for such a platform, a C file defining the above
    functions must be linked with the final executable.
 */
# ifdef PS_UNSUPPORTED_OS
#  include "matrixos.h"
# else

#  ifndef POSIX
#   if defined(LINUX) || defined(OSX)
#    define POSIX
#   endif
#  endif

#  if defined(POSIX) || (defined(WIN32) && _MSC_VER >= 1600 /*MSVC2010*/)
#   if defined(WIN32)
#    include <windows.h>
#    define strcasecmp lstrcmpiA
#    define snprintf _snprintf
#   endif
#   include <stdint.h>
typedef int32_t int32;
typedef uint32_t uint32;
typedef int16_t int16;
typedef uint16_t uint16;
typedef uint8_t uint8;
#   ifdef HAVE_NATIVE_INT64
typedef int64_t int64;
typedef uint64_t uint64;
#   endif
#  elif defined(WIN32)
#   include <windows.h>
#   define strcasecmp lstrcmpiA
#   define snprintf _snprintf
typedef signed long int32;
typedef unsigned long uint32;
typedef signed short int16;
typedef unsigned short uint16;
typedef unsigned char uint8;
typedef signed long int32_t;
typedef unsigned long uint32_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef signed char int8_t;
#   ifdef HAVE_NATIVE_INT64
typedef unsigned long long uint64;
typedef signed long long int64;
typedef unsigned long long uint64_t;
typedef signed long long int64_t;
#   endif
#  elif defined(METAL)
#   include <stdint.h>
typedef int32_t int32;
typedef uint32_t uint32;
typedef int16_t int16;
typedef uint16_t uint16;
typedef uint8_t uint8;
#   ifdef HAVE_NATIVE_INT64
typedef int64_t int64;
typedef uint64_t uint64;
#   endif
#  elif defined (NUCLEUS)
#   include <stdint.h>
typedef int32_t int32;
typedef uint32_t uint32;
typedef int16_t int16;
typedef uint16_t uint16;
typedef uint8_t uint8;
#   ifdef HAVE_NATIVE_INT64
typedef int64_t int64;
typedef uint64_t uint64;
#   endif
#  endif

/******************************************************************************/
/*
    OS-specific psTime_t types

    Make psTime_t an opaque time value.
 */

#  if defined(__x86_64__)
#   define USE_HIGHRES_TIME
#  endif

#  if defined(POSIX)
#   ifndef USE_HIGHRES_TIME
#    include <sys/time.h>
#    include <time.h>
typedef struct timeval psTime_t;
#   else
#    if defined(__APPLE__) || defined(__tile__)
typedef uint64_t psTime_t;
#    else
#     include <time.h>
typedef struct timespec psTime_t;
#    endif
extern int64_t psDiffUsecs(psTime_t then, psTime_t now);
#   endif
#  elif defined(WIN32)
typedef LARGE_INTEGER psTime_t;
#  elif defined(METAL)
typedef unsigned int psTime_t;
#  elif defined(NUCLEUS)
typedef uint64_t psTime_t;
#  elif defined(VXWORKS)
typedef struct
{
    long sec;
    long usec;
} psTime_t;
#  endif

/******************************************************************************/
/*
    Defines of other derived types
 */

/* Size type commonly used by MatrixSSL. This is currently 16-bit to keep
   data structures small. In future the type can be larger. */
typedef uint16_t psSize_t;

/* At least 32-bit size for large inputs.
   On some platforms the type can be larger than 32 bits. */
typedef uint32_t psSize32_t;

/* An alias for largest possible object size on the target.
   Currently the same than size_t. */
typedef size_t psSizeL_t;

/* 16-bit identifier for cipher. This can be used in TLS protocol. */
typedef uint16_t psCipher16_t;

/* 16-bit identifier for curve. This can be used in cryptography protocol. */
typedef uint16_t psCurve16_t;

/* Result code of ps functions returning negative value for error and
   a positive value for success. The purpose of positive values
   returned is documented for each function. */
typedef int32_t psRes32_t;

/* Result code of ps functions returning negative value for error and
   a positive value for success. The positive value is size of operation
   or area returned.
   The full documentation of positive values returned is documented for
   each function. */
typedef int32_t psResSize_t;

/* Result code of ps functions, returning PS_SUCCESS for success and
   a negative value for failure. */
typedef int32_t psRes_t;

/* An integer with boolean value PS_TRUE or PS_FALSE.
   The actual datatype used varies according to platform.
   On C99 or later stdbool.h is used, otherwise integer. */
#  ifdef __STDC_VERSION__
#   if __STDC_VERSION__ >= 199901L
#    include <stdbool.h>
typedef bool psBool_t;
#   else
typedef int psBool_t;
#   endif
#  else
typedef int psBool_t;
#  endif

/******************************************************************************/
/*
    Limitations for the data types.
 */

#  define PS_SIZE_MIN ((psSize_t) 0)
#  define PS_SIZE_MAX (~(psSize_t) 0)
#  define PS_SIZE32_MIN ((psSize32_t) 0)
#  define PS_SIZE32_MAX (~(psSize32_t) 0)
#  define PS_SIZEL_MIN ((psSizeL_t) 0)
#  define PS_SIZEL_MAX (~(psSizeL_t) 0)
#  define PS_RES_OK_MIN ((psRes_t) 0)
#  define PS_RES_OK_MAX ((psRes_t) 0)
#  define PS_RES_SIZE_OK_MIN ((psResSize_t) 0)
#  define PS_RES_SIZE_OK_MAX ((psResSize_t) 0x7FFFFFFFUL)
#  define PS_BOOL_MIN ((psBool_t) PS_FALSE)
#  define PS_BOOL_MAX ((psBool_t) PS_TRUE)

/******************************************************************************/
/*
    Defines to make library multithreading safe
 */
#  ifdef USE_MULTITHREADING

extern int32_t osdepMutexOpen(void);
extern void osdepMutexClose(void);

#   if defined(WIN32)
typedef CRITICAL_SECTION psMutex_t;
#   elif defined(POSIX)
#    include <string.h>
#    include <pthread.h>
typedef pthread_mutex_t psMutex_t;
#   elif defined(VXWORKS)
#    include "semLib.h"
typedef SEM_ID psMutex_t;
#   else
#    error psMutex_t must be defined
#   endif /* OS specific mutex */
#  endif  /* USE_MULTITHREADING */

# endif   /* !PS_UNSUPPORTED_OS */
#endif    /* _h_PS_PLATFORM_TYPES */

