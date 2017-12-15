/**
 *      @file    osdep.h
 *      @version $Format:%h%d$
 *
 *      Operating System and Hardware Abstraction Layer.
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

/* This file depends on osdependent type definitions for osdep-types.h */
#include "osdep-types.h"
#include "psLog.h"

#ifndef _h_PS_PLATFORM
# define _h_PS_PLATFORM

extern int  osdepTraceOpen(void);
extern void osdepTraceClose(void);
extern int  osdepTimeOpen(void);
extern void osdepTimeClose(void);
extern int  osdepEntropyOpen(void);
extern void osdepEntropyClose(void);
# ifdef HALT_ON_PS_ERROR
extern void    osdepBreak(void);
# endif

/* Note: This macro has been deprecated. Macro PS_MIN should be used instead. */
# ifndef min
#  define min(a, b)    (((a) < (b)) ? (a) : (b))
# endif /* min */

# ifdef PS_UNSUPPORTED_OS
/* Unsupported platforms, everything below needs to be defined in
   a platform specific manner. */
# else
/* On supported platforms we can use ANSI C or C99 hosted APIs. */
#  include <stdio.h>

/******************************************************************************/
/*
    Secure memset/memzero
 */
#  if defined(WIN32)
#   undef memset_s
#   define memset_s(A, B, C, D) SecureZeroMemory(A, D)
#  elif defined(OSX)
#   define __STDC_WANT_LIB_EXT1__ 1
#   include <string.h>
#  else
#   include <string.h>
typedef size_t rsize_t;
typedef int errno_t;
extern errno_t memset_s(void *s, rsize_t smax, int c, rsize_t n);
#  endif

#  define memzero_s(S, N) memset_s(S, N, 0x0, N)

/******************************************************************************/
/*
    Hardware Abstraction Layer
 */
/* Hardware Abstraction Layer - define functions in HAL directory */
#  if defined(POSIX) || defined(WIN32) || defined(ECOS) || defined(FREERTOS) || defined(NUCLEUS)
#   define halOpen() 0
#   define halClose()
#   define halAlert()
#  else
extern int     halOpen(void);
extern void    halAlert(void);
extern void    halClose(void);
#  endif /* HAL */

/******************************************************************************/
/*
    Raw trace and error
 */
PSPUBLIC void _psTrace(const char *msg);
PSPUBLIC void _psTraceInt(const char *msg, int32 val);
PSPUBLIC void _psTraceStr(const char *msg, const char *val);
PSPUBLIC void _psTracePtr(const char *message, const void *value);
PSPUBLIC void psTraceBytes(const char *tag, const unsigned char *p, int l);

PSPUBLIC void _psError(const char *msg);
PSPUBLIC void _psErrorInt(const char *msg, int32 val);
PSPUBLIC void _psErrorStr(const char *msg, const char *val);

PSPUBLIC void psMem2Str(char *s, const unsigned char *b, uint32 len);

#  include "psLog.h"

/* Generic trace and debug macros. */
#  ifdef USE_PS_LOGF_COMMON
#   define psTrace(x) PS_LOGF_COMMON(Log_Trace, PS_UNKNOWN, PS_LOGF_FMT, \
                                     PS_LOGF_FILELINE, "%s", x)
#   define psTraceInt(x, i) PS_LOGF_COMMON(Log_Trace, PS_UNKNOWN, PS_LOGF_FMT, \
                                           PS_LOGF_FILELINE, x, i)
#   define psTraceStr(x, s) PS_LOGF_COMMON(Log_Trace, PS_UNKNOWN, PS_LOGF_FMT, \
                                           PS_LOGF_FILELINE, x, s)
#   define psTracePtr(x, p) PS_LOGF_COMMON(Log_Trace, PS_UNKNOWN, PS_LOGF_FMT, \
                                           PS_LOGF_FILELINE, x, p)
#  else
#   define psTrace(x) _psTrace(x)
#   define psTraceInt(x, i) _psTraceInt(x, i)
#   define psTraceStr(x, s) _psTraceStr(x, s)
#   define psTracePtr(x, p) _psTracePtr(x, p)
#  endif
/******************************************************************************/
/*
    Core trace
 */
#  ifdef USE_PS_LOGF_COMMON
#   define psTraceCore(x) PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT, \
                                         PS_LOGF_FILELINE, "%s", x)
#   define psTraceIntCore(x, i) PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT,\
                                               PS_LOGF_FILELINE, x, i)
#   define psTraceStrCore(x, s) PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT,\
                                               PS_LOGF_FILELINE, x, s)
#   define psTracePtrCore(x, p) PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT,\
                                               PS_LOGF_FILELINE, x, p)
#  else
#   ifndef USE_CORE_TRACE
#    define psTraceCore(x)
#    define psTraceStrCore(x, y)
#    define psTraceIntCore(x, y)
#    define psTracePtrCore(x, y)
#   else
#    define psTraceCore(x) _psTrace(x)
#    define psTraceStrCore(x, y) _psTraceStr(x, y)
#    define psTraceIntCore(x, y) _psTraceInt(x, y)
#    define psTracePtrCore(x, y) _psTracePtr(x, y)
#   endif /* USE_CORE_TRACE */
#  endif /* USE_PS_LOGF_COMMON */

/******************************************************************************/
/*
    HALT_ON_PS_ERROR define at compile-time determines whether to halt on
    psAssert and psError calls
 */
#  ifdef USE_PS_LOGF_COMMON
#   ifdef HALT_ON_PS_ERROR
#    define PS_OSDEP_BREAK() osdepBreak()
#   else
#    define PS_OSDEP_BREAK() do { } while(0)
#   endif
extern void osdepBreak(void);
#   ifdef USE_CORE_ASSERT
#    define psAssert(C)  do { if (C) {; } else                          \
        { halAlert(); PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT, PS_LOGF_FILELINE, "%s", #C); PS_OSDEP_BREAK(); } } while(0)
#   else
#    define psAssert(C)  if (C) {; } else do { /* assert ignored. */ } while (0)
#   endif
#  else
#   ifdef USE_CORE_ASSERT
#    define psAssert(C)  if (C) {; } else \
    { halAlert(); _psTraceStr("psAssert %s", __FILE__); _psTraceInt(":%d ", __LINE__); \
      _psError(#C); }
#   else
#    define psAssert(C)  if (C) {; } else do { /* assert ignored. */ } while (0)
#   endif
#  endif

#  ifdef USE_PS_LOGF_COMMON
#   ifdef USE_CORE_ERROR
#    define psError(a) \
    do { halAlert(); PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT, PS_LOGF_FILELINE, "%s", a); PS_OSDEP_BREAK(); } while(0)
#    define psErrorStr(a, s)                                              \
    do { halAlert(); PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT, PS_LOGF_FILELINE, a, s); PS_OSDEP_BREAK(); } while(0)
#    define psErrorInt(a, i)                                              \
    do { halAlert(); PS_LOGF_COMMON(Log_Trace, PS_CORE, PS_LOGF_FMT, PS_LOGF_FILELINE, a, i); PS_OSDEP_BREAK(); } while(0)
#   else
#    define psError(a) do { /* error ignored. */ } while (0)
#    define psErrorStr(a, b) do { /* error ignored. */ } while (0)
#    define psErrorInt(a, b) do { /* error ignored. */ } while (0)
#   endif
#  else
#   ifdef USE_CORE_ERROR
#    define psError(a) \
    halAlert(); _psTraceStr("psError %s", __FILE__); _psTraceInt(":%d ", __LINE__); \
    _psError(a);

#    define psErrorStr(a, b) \
    halAlert(); _psTraceStr("psError %s", __FILE__); _psTraceInt(":%d ", __LINE__); \
    _psErrorStr(a, b)

#    define psErrorInt(a, b) \
    halAlert(); _psTraceStr("psError %s", __FILE__); _psTraceInt(":%d ", __LINE__); \
    _psErrorInt(a, b)
#   else
#    define psError(a) do { /* error ignored. */ } while (0)
#    define psErrorStr(a, b) do { /* error ignored. */ } while (0)
#    define psErrorInt(a, b) do { /* error ignored. */ } while (0)
#   endif
#  endif

/******************************************************************************/
/*
    OS specific file system apis
 */
#  ifdef MATRIX_USE_FILE_SYSTEM
#   ifdef POSIX
#    include <sys/stat.h>
#   endif /* POSIX */
#  endif  /* MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/

# endif /* !PS_UNSUPPORTED_OS */
#endif  /* _h_PS_PLATFORM */

