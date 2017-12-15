/**
 *      @file    ps_chacha20poly1305ietf_config.h
 *      @version $Format:%h%d$
 *
 *      Header for MatrixSSL Chacha20-poly1305: Configuration.
 */
/*
 *      Copyright (c) 2017 INSIDE Secure Corporation
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

#ifndef _h_PS_CHACHA20_POLY1305IETF_CONFIG
# define _h_PS_CHACHA20_POLY1305IETF_CONFIG

/* Provide list of APIs and facilities available on the target platform and
   configure the components for optimal performance on the target. */

/* When porting the module to foreign target, it is possible that some of
   these need to be changed to best adapt for the platform. */

# include "../../cryptoApi.h"

# ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
#  ifdef USE_MULTITHREADING
#   define HAVE_PTHREAD_PRIO_INHERIT 1
#   define HAVE_PTHREAD 1
#   define _POSIX_PTHREAD_SEMANTICS 1
#  endif /* USE_MULTITHREADING */

#  ifndef STDC_HEADERS
#   define STDC_HEADERS
#  endif

#  if defined __linux__ || defined __android__
#   define HAVE_SYS_TYPES_H 1
#   define HAVE_SYS_STAT_H 1
#   define HAVE_SYS_MMAN_H 1
#   define HAVE_DLFCN_H 1
#  endif

#  define HAVE_STDLIB_H 1
#  define HAVE_STRING_H 1
#  define HAVE_MEMORY_H 1
#  define HAVE_STRINGS_H 1
#  define HAVE_INTTYPES_H 1
#  define HAVE_STDINT_H 1
#  define HAVE_UNISTD_H 1

/* X86/X86-64 SIMD instructions: MMX, SSE, and AVX. */
#  if defined __i386__ || defined __x86_64__
#   define HAVE_MMINTRIN_H 1
#   define HAVE_EMMINTRIN_H 1
#   define HAVE_PMMINTRIN_H 1
#   define HAVE_TMMINTRIN_H 1
#   define HAVE_SMMINTRIN_H 1
#   define HAVE_AVXINTRIN_H 1
#   define HAVE_AVX2INTRIN_H 1
#   define HAVE_WMMINTRIN_H 1
#   define HAVE_AVX_ASM 1
#  endif

#  define NATIVE_LITTLE_ENDIAN 1
#  ifdef __x86_64__
#   define HAVE_AMD64_ASM 1
#   define HAVE_TI_MODE 1
#  endif
#  if defined __i386__ || defined __x86_64__
#   define HAVE_CPUID 1
#  endif
#  define HAVE_WEAK_SYMBOLS 1
#  define HAVE_ATOMIC_OPS 1
#  define HAVE_MMAP 1
#  define HAVE_MLOCK 1
#  define HAVE_MADVISE 1
#  define HAVE_NANOSLEEP 1
#  define HAVE_POSIX_MEMALIGN 1
#  define HAVE_GETPID 1

#  define ASM_HIDE_SYMBOL .hidden
#  define CPU_UNALIGNED_ACCESS 1

#  define NO_SODIUM_MEMORY_MANAGEMENT 1 /* Omit memory management functions. */

#  ifdef __android__
#   define HAVE_ANDROID_GETCPUFEATURES
#  endif /* __android__ */

#  ifndef NO_SODIUM_MEMORY_MANAGEMENT
#   define HAVE_MPROTECT 1
#  else
#   undef HAVE_MPROTECT
#  endif


# endif
#endif /* _h_PS_CHACHA20_POLY1305IETF_CONFIG */

