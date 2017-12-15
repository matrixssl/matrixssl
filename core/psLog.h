/**
 *      @file    psLog.h
 *      @version $Format:%h%d$
 *
 *  Extensible logging facility.
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

#ifndef _h_PS_CORECONFIG
# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <coreConfig.h> /* Must be first included */
# else
#  include "coreConfig.h" /* Must be first included */
# endif
#endif /* _h_PS_CORECONFIG */

#ifndef _h_PS_LOG
# define _h_PS_LOG

# ifndef PS_NO_LOGF
/* Define a common logging framework.
   If you want to use previous MatrixSSL logging facilities only, 
   please add #define PS_NO_LOGF
   to coreConfig.h.
*/
#include "psPrnf.h"

#ifdef __GNUC__
# define PS_LOGF_FORMAT3_4 __attribute__ (( __format__( printf, 3, 4 ) ))
#else
# define PS_LOGF_FORMAT3_4 /* No formatting code. */
#endif
          
#include <stdarg.h> /* Variable length function arguments are used for
                       formatting. */

/* This string is used as token when logging function is called to "probe"
   if specific kind of logging is enabled. */
#define PS_LOGF_FMT_IS_ENABLED "%.0s", ""

/* This is generic log formatting macro.
   The calls to psTrace functions will map to this macro.
   The first and second argument are expressed as plain strings,
   and converted into actual C strings.
Invocation: PS_LOGF_COMMON(Log_Level, CODE_UNIT, PS_LOGF_TYPE, "File:Line: ", \
                           FmtString, Args...) */

/* Note: GCC supports ,## concatenation trick. */
#define PS_LOGF_COMMON(psLogf_ll, psLogf_cu, psLogf_type, psLogf_ctx,   \
                       psLogf_fmt, ...)                                 \
    PS_LOGF_COMMON1(psLogf_ll, psLogf_cu, psLogf_type, psLogf_ctx,      \
                    psLogf_fmt, ( ,##__VA_ARGS__ ))
#define PS_LOGF_COMMON1(psLogf_ll, psLogf_cu, psLogf_type, psLogf_ctx,   \
                       psLogf_fmt, psLogf_args)                         \
PS_LOGF_CONCATENATE(PS_LOGF_COMMON_, psLogf_ll)(PS_LOGF_STRINGIZE(psLogf_ll), PS_LOGF_STRINGIZE(psLogf_cu), PS_LOGF_CONCATENATE(PS_LOGF_FORMAT_LOG_, psLogf_type)(PS_LOGF_STRINGIZE(psLogf_cu), psLogf_ctx, psLogf_fmt, psLogf_args))

/* This is generic log checking macro.
   The calls to psTrace functions will map to this macro.
   The first and second argument are expressed as plain strings.
   The macro will return 1 (true) when log is enabled.
   This macro is intended to allow avoiding complex processing when
   logging is not enabled.
   Invocation: PS_LOGF_IS_ENABLED(Log_Level, CODE_UNIT) */
#define PS_LOGF_IS_ENABLED(psLogf_ll, psLogf_cu) \
    PS_LOGF_CONCATENATE(PS_LOGF_COMMON_IS_ENABLED_, psLogf_ll)(PS_LOGF_STRINGIZE(psLogf_ll), PS_LOGF_STRINGIZE(psLogf_cu))

/* Function called for fatal logs.
   Note: This function is only ever called just before software goes down. */
int psLogfFatal(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Function called for error logs. */
int psLogfError(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Function called for warnings logs. */
int psLogfWarning(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Function called for informational logs. */
int psLogfInfo(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Function called for debugging logs. */
int psLogfDebug(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Function called for verbose debugging logs. */
int psLogfVerbose(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Function called for trace logs. */
int psLogfTrace(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Function called for function trace logs. */
int psLogfCallTrace(const char *level, const char *unit, const char *fmt, ...)
    PS_LOGF_FORMAT3_4;

/* Common function for any logs. */
int psLogVaCommon(const char *level, const char *unit, const char *fmt,
                  va_list args);

/* Common function for flushing any files and any cached information.
   Currently the function will only flush cached information on
   disabled/enabled logs. */
void psLogfFlush(void);

/* Enable logging for select levels or modules. */
void psLogfEnable(const char *module_or_level);
#define PS_LOGF_HAVE_ENABLE 1

/* Disable logging for select levels or modules. */
void psLogfDisable(const char *module_or_level);
#define PS_LOGF_HAVE_DISABLE 1

/* Provide components necessary to embed conditional information and PRNF
   context within log formatting code snipplet. These macros are not safe
   to use for other purposes. */
#ifdef PS_LOGF_WITH_PRNF
#define PS_LOGF_PRNF1 do { if  /* continue with condition */
#define PS_LOGF_PRNF2 { char free_stub[1]; PS_PRNF_CTX; /* continue: printing */
#define PS_LOGF_PRNF3 ; psSnprnf(free_stub, 1, "%s", ""); } } while(0)
#endif

/* Provide Fatal output via psLogfFatal function.
   Note: The software only ever intends to produce fatal output upon shutting
   down. */
#if defined PS_NO_LOGF_FATAL || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_Fatal(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfFatal(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_Fatal(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_Fatal(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_PRNF1 \
    (psLogfFatal(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)) \
    PS_LOGF_PRNF2 \
    (void)psLogfFatal(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_Fatal(psLogf_llstr, psLogf_custr) \
    psLogfFatal(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_Fatal(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfFatal(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_Fatal(psLogf_llstr, psLogf_custr) \
    psLogfFatal(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Provide Error output vis psLogfError function. */
#if defined PS_NO_LOGF_ERROR || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_Error(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfError(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_Error(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_Error(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_PRNF1 \
    (psLogfError(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED))   \
    PS_LOGF_PRNF2 \
    (void)psLogfError(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_Error(psLogf_llstr, psLogf_custr) \
    psLogfError(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_Error(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfError(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_Error(psLogf_llstr, psLogf_custr) \
    psLogfError(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Provide Info output vis psLogfInfo function. */
#if defined PS_NO_LOGF_INFO || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_Info(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfInfo(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_Info(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_Info(psLogf_llstr, psLogf_custr, ...)        \
    PS_LOGF_PRNF1 \
    (psLogfInfo(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)) \
    PS_LOGF_PRNF2 \
    (void)psLogfInfo(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_Info(psLogf_llstr, psLogf_custr) \
    psLogfInfo(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_Info(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfInfo(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_Info(psLogf_llstr, psLogf_custr) \
    psLogfInfo(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Provide Warning output vis psLogfWarning function. */
#if defined PS_NO_LOGF_WARNING || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_Warning(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfWarning(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_Warning(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_Warning(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_PRNF1 \
    (psLogfWarning(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)) \
    PS_LOGF_PRNF2 \
    (void)psLogfWarning(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_Warning(psLogf_llstr, psLogf_custr) \
    psLogfWarning(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_Warning(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfWarning(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_Warning(psLogf_llstr, psLogf_custr) \
    psLogfWarning(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Provide Verbose output vis psLogfVerbose function. */
#if defined PS_NO_LOGF_VERBOSE || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_Verbose(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfVerbose(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_Verbose(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_Verbose(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_PRNF1   \
    (psLogfVerbose(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)) \
    PS_LOGF_PRNF2 \
    (void)psLogfVerbose(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_Verbose(psLogf_llstr, psLogf_custr) \
    psLogfVerbose(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_Verbose(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfVerbose(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_Verbose(psLogf_llstr, psLogf_custr) \
    psLogfVerbose(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Provide Debug output vis psLogfDebug function. */
#if defined PS_NO_LOGF_DEBUG || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_Debug(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfDebug(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_Debug(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_Debug(psLogf_llstr, psLogf_custr, ...)       \
    PS_LOGF_PRNF1                                                       \
    (psLogfDebug(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)) \
    PS_LOGF_PRNF2                                                     \
    (void)psLogfDebug(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_Debug(psLogf_llstr, psLogf_custr) \
    psLogfDebug(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_Debug(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfDebug(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_Debug(psLogf_llstr, psLogf_custr) \
    psLogfDebug(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Provide Trace output vis psLogfTrace function. */
#if defined PS_NO_LOGF_TRACE || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_Trace(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfTrace(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_Trace(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_Trace(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_PRNF1 \
    (psLogfTrace(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED))   \
    PS_LOGF_PRNF2 \
    (void)psLogfTrace(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_Trace(psLogf_llstr, psLogf_custr) \
    psLogfTrace(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_Trace(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfTrace(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_Trace(psLogf_llstr, psLogf_custr) \
    psLogfTrace(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Provide CallTrace output vis psLogfCallTrace function. */
#if defined PS_NO_LOGF_CALL_TRACE || defined PS_NO_LOGF_ANY
#define PS_LOGF_COMMON_Log_CallTrace(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_NO(psLogfCallTrace(psLogf_llstr, psLogf_custr, __VA_ARGS__))
#define PS_LOGF_COMMON_IS_ENABLED_Log_CallTrace(psLogf_llstr, psLogf_custr) 0
#elif defined(PS_LOGF_WITH_PRNF)
#define PS_LOGF_COMMON_Log_CallTrace(psLogf_llstr, psLogf_custr, ...) \
    PS_LOGF_PRNF1 \
    (psLogfCallTrace(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)) \
    PS_LOGF_PRNF2 \
    (void)psLogfCallTrace(psLogf_llstr, psLogf_custr, __VA_ARGS__) \
    PS_LOGF_PRNF3
#define PS_LOGF_COMMON_IS_ENABLED_Log_CallTrace(psLogf_llstr, psLogf_custr) \
    psLogfCallTrace(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#else
#define PS_LOGF_COMMON_Log_CallTrace(psLogf_llstr, psLogf_custr, ...) \
    (void)psLogfCallTrace(psLogf_llstr, psLogf_custr, __VA_ARGS__)
#define PS_LOGF_COMMON_IS_ENABLED_Log_CallTrace(psLogf_llstr, psLogf_custr) \
    psLogfCallTrace(psLogf_llstr, psLogf_custr, PS_LOGF_FMT_IS_ENABLED)
#endif

/* Typedef for log levels. */
typedef enum
{
    PS_LOGF_UNKNOWN, /* For messages of unknown type. */
    PS_LOGF_CALL_TRACE,
    PS_LOGF_TRACE,
    PS_LOGF_VERBOSE,
    PS_LOGF_DEBUG,
    PS_LOGF_INFO,
    PS_LOGF_WARNING,
    PS_LOGF_ERROR,
    PS_LOGF_FATAL
} psLogfLevel_t;

/* Convenience formatting */
#define PS_LOGF_CALL_TRACE(tag, fmt, ...)                               \
    PS_LOGF_COMMON(Log_CallTrace, tag,                                  \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_TRACE(tag, fmt, ...)                                    \
    PS_LOGF_COMMON(Log_Trace, tag,                                      \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_VERBOSE(tag, fmt, ...)                                  \
    PS_LOGF_COMMON(Log_Verbose, tag,                                    \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_DEBUG(tag, fmt, ...)                                    \
    PS_LOGF_COMMON(Log_Debug, tag,                                      \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_INFO(tag, fmt, ...)                                     \
    PS_LOGF_COMMON(Log_Info, tag,                                       \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_WARNING(tag, fmt, ...)                                  \
    PS_LOGF_COMMON(Log_Warning, tag,                                    \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_ERROR(tag, fmt, ...)                                    \
    PS_LOGF_COMMON(Log_Error, tag,                                      \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_FATAL(tag, fmt, ...)                                    \
    PS_LOGF_COMMON(Log_Fatal, tag,                                      \
                   PS_LOGF_FMT,                                         \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )

#define PS_LOGF_CALL_TRACE_LN(tag, fmt, ...)                            \
    PS_LOGF_COMMON(Log_CallTrace, tag,                                  \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_TRACE_LN(tag, fmt, ...)                                 \
    PS_LOGF_COMMON(Log_Trace, tag,                                      \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_VERBOSE_LN(tag, fmt, ...)                               \
    PS_LOGF_COMMON(Log_Verbose, tag,                                    \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_DEBUG_LN(tag, fmt, ...)                                 \
    PS_LOGF_COMMON(Log_Debug, tag,                                      \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_INFO_LN(tag, fmt, ...)                                  \
    PS_LOGF_COMMON(Log_Info, tag,                                       \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_WARNING_LN(tag, fmt, ...)                               \
    PS_LOGF_COMMON(Log_Warning, tag,                                    \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_ERROR_LN(tag, fmt, ...)                                 \
    PS_LOGF_COMMON(Log_Error, tag,                                      \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )
#define PS_LOGF_FATAL_LN(tag, fmt, ...)                                 \
    PS_LOGF_COMMON(Log_Fatal, tag,                                      \
                   PS_LOGF_FMTLN,                                       \
                   PS_LOGF_CTX, fmt ,##__VA_ARGS__ )

/* Common idiom: Don't perform activity.
   This macro provides input for compiler so that it goes through parsing,
   although no code should be generated. */
#define PS_LOGF_NO(...) do { if (0) { (void)__VA_ARGS__; } } while(0)

/* PS_LOGF_NO_PRINT_UNIT can be used to omit unit log from printouts. */
#ifdef PS_NO_LOGF_PRINT_UNIT
#define PS_LOGF_PRINT_UNIT "%.0s"
#else
#define PS_LOGF_PRINT_UNIT "[%s] "
#endif
    
/* Concatenate context information with formatting string.
   This is used to generate format strings for log fields that already include
   line termination. */
#define PS_LOGF_FORMAT_LOG_PS_LOGF_FMT(psLogf_cu, psLogf_ctx, psLogf_fmt, psLogf_args) \
    PS_LOGF_PRINT_UNIT "%s" psLogf_fmt, psLogf_cu, psLogf_ctx PS_LOGF_GET_ARGS psLogf_args

/* Concatenate context information with formatting string.
   This is used to generate format strings for log fields that do not include
   line termination. */
#define PS_LOGF_FORMAT_LOG_PS_LOGF_FMTLN(psLogf_cu, psLogf_ctx, psLogf_fmt, psLogf_args) \
    PS_LOGF_PRINT_UNIT "%s" psLogf_fmt "\n", psLogf_cu, psLogf_ctx PS_LOGF_GET_ARGS psLogf_args

/* Output argument list provided within parenthesis. */
#define PS_LOGF_GET_ARGS(...) __VA_ARGS__

/* Common representation of context: Source code file and line. */
#define PS_LOGF_FILELINE __FILE__ ":" PS_LOGF_STRINGIZE(__LINE__) ": "
#ifdef PS_NO_LOGF_FILELINE
/* Omit file name and line number information.
   This is good for file size and for avoiding leaking details of software
   implementation. */
#define PS_LOGF_CTX ""
#else
/* Provide file name and line number information, which is often useful for
   debugging purposes. */
#define PS_LOGF_CTX PS_LOGF_FILELINE
#endif /* PS_NO_LOGF_FILELINE */

/* Standard C preprocessor stringification idiom. */
#define PS_LOGF_STRINGIZE(psLogf_arg) PS_LOGF_STRINGIZE1(psLogf_arg)
#define PS_LOGF_STRINGIZE1(psLogf_arg) PS_LOGF_STRINGIZE2(psLogf_arg)
#define PS_LOGF_STRINGIZE2(psLogf_arg) #psLogf_arg

/* Standard C preprocessor concatenation idiom. */
#define PS_LOGF_CONCATENATE(psLogf_arg1, psLogf_arg2)   \
    PS_LOGF_CONCATENATE1(psLogf_arg1, psLogf_arg2)
#define PS_LOGF_CONCATENATE1(psLogf_arg1, psLogf_arg2) \
    PS_LOGF_CONCATENATE2(psLogf_arg1, psLogf_arg2)
#define PS_LOGF_CONCATENATE2(psLogf_arg1, psLogf_arg2) psLogf_arg1##psLogf_arg2

typedef int (*psLogfSetHookEnabledCheckFunction_t)
    (const char *level, const char *unit);

/* Set log hook for checking if specific log message is enabled.
   The function must return one of three outputs:
    0 == DISABLED.
    1 == ENABLED.
   -1 == Check enable/disable status from environment variable(s).

   When there is no hook installed, the software will act as if hook
   returned zero.

   This function returns the previous hook or NULL.
*/
psLogfSetHookEnabledCheckFunction_t psLogfSetHookEnabledCheck(
        psLogfSetHookEnabledCheckFunction_t hook);
    
typedef int (*psLogfSetHookPrintfFunction_t)
    (const char *level, const char *unit,
     const char *format_string, va_list va);

/* Set log hook for printf'ng log messages.
   The function normally returns 1 (success).
   However, the function may return 0 as an error if printing does not work.
   If the function returns -1, then default behavior (as if without hook) is
   invoked: 
      - printing to standard output or file.

   When there is no hook installed, the software will use PS_LOG_FILE or
   PS_LOG_FILE_APPEND or standard output (console or shell) as target for
   log messages. This function allows receiving some log messages to e.g.
   system log instead.

   This function returns the previous hook or NULL.
*/
psLogfSetHookPrintfFunction_t psLogfSetHookPrintf(
        psLogfSetHookPrintfFunction_t hook);

/* Convenience macro: Omit unit and file name logging from format string
   provided to psLogfSetHookPrintfFunction_t. */
#define PS_LOGF_RAW_FMT(format_string_arg, vl_arg)                      \
    do                                                                  \
    {                                                                   \
        if ((format_string_arg)[0] == '[' &&                            \
            (format_string_arg)[1] == '%' &&                            \
            (format_string_arg)[2] == 's' &&                            \
            (format_string_arg)[3] == ']' &&                            \
            (format_string_arg)[4] == ' ' &&                            \
            (format_string_arg)[5] == '%' &&                            \
            (format_string_arg)[6] == 's')                              \
        {                                                               \
            (format_string_arg) += 7;                                   \
            (void)va_arg(vl_arg, const char *);                         \
            (void)va_arg(vl_arg, const char *);                         \
        }                                                               \
    } while(0)

# endif /* PS_NO_LOGF */

#endif /* _h_PS_LOG */

/* end of psLog.h */
