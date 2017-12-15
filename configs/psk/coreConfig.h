/**
 *      @file    coreConfig.h
 *      @version $Format:%h%d$
 *
 *      Configuration settings for Matrix core module.
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

#ifndef _h_PS_CORECONFIG
# define _h_PS_CORECONFIG


/******************************************************************************/
/* Configurable features */
/******************************************************************************/
/**
    Enable various levels of trace.
    When these option is turned off, messages are silently
    discarded and their text does not take space in the binary image.
 */
/* #define USE_CORE_TRACE */
#  ifndef NO_CORE_ERROR
#   define USE_CORE_ERROR
#  endif
#  ifndef NO_CORE_ASSERT
#   define USE_CORE_ASSERT
#  endif

/**
    When logging or tracing use psLog.h APIs.

    Generally, using psLog.h allows more control over logging, because
    it is possible to filter log and tracing information more efficiently.
    However, this feature comes with a footprint cost, so the feature can be
    disabled by setting NO_PS_LOGF_COMMON or by commenting out USE_PS_LOGF_COMMON
    below.
 */
#ifdef NO_PS_LOGF_COMMON
#define USE_PS_LOGF_COMMON
#endif /* NO_PS_LOGF_COMMON */

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
    Include the psNetwork family of APIs

    These APIs allow simple high-level socket api.
 */
#  define USE_PS_NETWORKING

#endif   /* _h_PS_CORECONFIG */

/******************************************************************************/

