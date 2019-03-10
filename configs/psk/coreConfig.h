/**
 *      @file    coreConfig.h
 *      @version $Format:%h%d$
 *
 *      Configuration settings for Matrix core module.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
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

#ifndef _h_PS_CORECONFIG
# define _h_PS_CORECONFIG


/******************************************************************************/
/* Debug and tracing configuration */
/******************************************************************************/

/**
    Select tracing facility.
    Default: Use psLogf, which is used in all of MatrixSSL, CL etc. and
    allows log redirection.

    On the smallest embedded targets platform using PS_NO_LOGF may provide
    footprint benefits but will limit logging capabilities.
 */
 
/* Uncomment to use previous generation logging facility: */
/* #define PS_NO_LOGF */

/* When using psLogf, logging messages by default go to the binary, but
   they are not shown unless enabled by environment variables or
   filter loaded with psLogfSetHookEnabledCheck() function.

   Enable macros below to completely remove specified logging class. */
/* #define PS_NO_LOGF_FATAL */
/* #define PS_NO_LOGF_ERROR */
/* #define PS_NO_LOGF_WARNING */
/* #define PS_NO_LOGF_INFO */
/* #define PS_NO_LOGF_VERBOSE */
/* #define PS_NO_LOGF_DEBUG */
/* #define PS_NO_LOGF_TRACE */
/* #define PS_NO_LOGF_CALL_TRACE */

/* MatrixSSL contains extensive tracing capabilities. The lines below
   disable trace and call trace message levels, unless debug build.
   Omitting the messages will improve performance and create smaller
   executables with a degradation in debugging capabilities. */
#  ifndef DEBUG
#   ifndef PS_NO_LOGF_TRACE
#    define PS_NO_LOGF_TRACE
#   endif
#   ifndef PS_NO_LOGF_CALL_TRACE
#    define PS_NO_LOGF_CALL_TRACE
#   endif
#  endif

/* File and line information consumes some storage and may reveal details on
   structure of software. This information is omitted from production builds,
   but included within "debug build". If you want to include file and line
   information also on production builds, disable the lines below. */
#  ifndef DEBUG
#   ifndef  PS_NO_LOGF_FILELINE
#    define PS_NO_LOGF_FILELINE
#   endif
#  endif

/**
    Enable various levels of trace.
    When these option is turned off, messages are silently
    discarded and their text does not take space in the binary image.
    Note: These are legacy configuration, and it is recommended to use
    PS_NO_LOGF_* above, unless PS_NO_LOGF is set.
 */
/* #define USE_CORE_TRACE */
#  ifndef NO_CORE_ERROR
#   define USE_CORE_ERROR
#  endif
#  ifndef NO_CORE_ASSERT
#   define USE_CORE_ASSERT
#  endif

/******************************************************************************/
/* Other Configurable features */
/******************************************************************************/

/**
    If enabled, calls to the psError set of APIs will perform a platform
    abort on the exeutable to aid in debugging.
 */
#  ifdef DEBUG
/* #define HALT_ON_PS_ERROR  *//* NOT RECOMMENDED FOR PRODUCTION BUILDS */
#  endif

/**
    Include the psCoreOsdepMutex family of APIs

    @note If intending to compile crypto-cl, then this flag should
    always be set.
*/
#  ifndef NO_MULTITHREADING
/* #define USE_MULTITHREADING */
#  endif /* NO_MULTITHREADING */

/**
    Include the psNetwork family of APIs.

    These APIs allow simple high-level socket api.
    The API derive from BSD Sockets, and therefore it can only be used
    on devices which have the prerequisitive APIs.
    MatrixSSL itself can be used also be used without PS networking, but
    many of example programs and MatrixSSLNet are based on PS networking.
 */
#  ifndef NO_PS_NETWORKING
#   define USE_PS_NETWORKING
#  endif /* NO_PS_NETWORKING */

#endif   /* _h_PS_CORECONFIG */

/******************************************************************************/

