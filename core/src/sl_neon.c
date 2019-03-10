/* sl_neon.c
 *
 * Detect features of the NEON co-processor on ARM devices.
 *
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

/* This is based on neon-simd.cpp: */
// crc-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//
//    This source file uses intrinsics to gain access to ARMv7a and
//    ARMv8a NEON instructions. A separate source file is needed
//    because additional CXXFLAGS are required to enable the
//    appropriate instructions sets in some build configurations.

#include "pscompilerdep.h"

#if defined __ARMCC5 && !defined __TARGET_FEATURE_NEON
/* Set SL_NO_NEON if compiling with ARM DS-5 compiler for processor
   without ARM neon capability. In this case, the test will always return
   false (no NEON detected). */
#define SL_NO_NEON 1
#endif

#if defined(__aarch64__) || defined(__aarch32__) || defined(__arm__)

#define _POSIX_SOURCE 1
#if !defined SL_NO_NEON
#include "osdep_arm_neon.h"
#endif
#include "osdep_setjmp.h"
#include "osdep_stdbool.h"
#include "osdep_stddef.h"
#include "osdep_signal.h"

extern bool SL_CPU_ProbeNEON(void);
extern bool SL_CPU_ProbeCRC32(void);
extern bool SL_CPU_ProbeAES(void);
extern bool SL_CPU_ProbeSHA1(void);
extern bool SL_CPU_ProbeSHA2(void);
extern bool SL_CPU_ProbePMULL(void);

#define NULLPTR NULL

#define EXTERN_C /* C ABI is the default. */

#if !defined SL_NO_NEON
EXTERN_C typedef void (*SigHandler)(int);
EXTERN_C static jmp_buf s_jmpSIGILL;
EXTERN_C static void SigIllHandler(int unused)
{
    (void)unused;
    Longjmp(s_jmpSIGILL, 1);
}

/* Neon instructions are enabled: Can build test code using neon. */
bool SL_CPU_ProbeNEON(void)
{
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and
    // http://stackoverflow.com/q/7721854
    volatile bool result = true;
    volatile sigset_t oldMask;
    volatile SigHandler oldHandler = Signal(SIGILL, SigIllHandler);

    if (oldHandler == SIG_ERR)
    {
        return false;
    }

    if (Sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        return false;
    }

    if (Setjmp(s_jmpSIGILL))
    {
        result = false;
    }
    else
    {
        uint32_t v1[4] = {1,1,1,1};
        uint32x4_t x1 = vld1q_u32(v1);
        uint64_t v2[2] = {1,1};
        uint64x2_t x2 = vld1q_u64(v2);
        
        uint32x4_t x3 = {0,0,0,0};
        x3 = vsetq_lane_u32(vgetq_lane_u32(x1,0),x3,0);
        x3 = vsetq_lane_u32(vgetq_lane_u32(x1,3),x3,3);
        uint64x2_t x4 = {0,0};
        x4 = vsetq_lane_u64(vgetq_lane_u64(x2,0),x4,0);
        x4 = vsetq_lane_u64(vgetq_lane_u64(x2,1),x4,1);
        
        // Hack... GCC optimizes away the code and returns true
        result = !!(vgetq_lane_u32(x3,0) | vgetq_lane_u64(x4,1));
    }

    Sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    Signal(SIGILL, oldHandler);
    return result;
}
#else
/* No support for NEON. */
bool SL_CPU_ProbeNEON(void)
{
    return false;
}
#endif /* !defined SL_NO_NEON */

/* SL_CPU_ProbeAES() is based on CPU_ProbeAES() in rijndael-simd.cpp. */
// rijndael-simd.cpp - written and placed in the public domain by
//                     Jeffrey Walton, Uri Blumenthal and Marcel Raad.
//                     AES-NI code originally written by Wei Dai.

bool SL_CPU_ProbeAES(void)
{
#ifdef __ARM_FEATURE_CRYPTO
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and
    // http://stackoverflow.com/q/7721854
    volatile bool result = true;
    volatile sigset_t oldMask;
    volatile SigHandler oldHandler = Signal(SIGILL, SigIllHandler);

    if (oldHandler == SIG_ERR)
    {
        return false;
    }

    if (Sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        return false;
    }

    if (Setjmp(s_jmpSIGILL))
    {
        result = false;
    }
    else
    {
        uint8x16_t data = vdupq_n_u8(0), key = vdupq_n_u8(0);
        uint8x16_t r1 = vaeseq_u8(data, key);
        uint8x16_t r2 = vaesdq_u8(data, key);
        r1 = vaesmcq_u8(r1);
        r2 = vaesimcq_u8(r2);

        // Hack... GCC optimizes away the code and returns true
        result = !!(vgetq_lane_u8(r1,0) | vgetq_lane_u8(r2,7));
    }

    Sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    Signal(SIGILL, oldHandler);
    return result;
#else
    return false;
#endif
}

/* SL_CPU_ProbePMULL() is based on CPU_ProbePMULL() in rijndael-simd.cpp. */
// gcm-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.

#define VMULL_P64(a1, b1, r1)                                           \
    __asm__("pmull %0.1q, %1.1d, %2.1d" : "=w" (r1) : "w" (a1), "w" (b1))
#define VMULL_HIGH_P64(a2, b2, r2)                                      \
    __asm__("pmull2 %0.1q, %1.2d, %2.2d" : "=w" (r2) : "w" (a2), "w" (b2))

bool SL_CPU_ProbePMULL(void)
{
#ifdef __ARM_FEATURE_CRYPTO
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and
    // http://stackoverflow.com/q/7721854
    volatile bool result = true;

    volatile SigHandler oldHandler = Signal(SIGILL, SigIllHandler);
    if (oldHandler == SIG_ERR)
    {
        return false;
    }

    volatile sigset_t oldMask;
    if (Sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        return false;
    }

    if (Setjmp(s_jmpSIGILL))
    {
        result = false;
    }
    else
    {
        const poly64_t   a1={0x9090909090909090}, b1={0xb0b0b0b0b0b0b0b0};
        const poly8x16_t a2={0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0xa0,0xa0,
                             0xa0,0xa0,0xa0,0xa0,0xa0,0xa0},
                         b2={0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xe0,0xe0,
                             0xe0,0xe0,0xe0,0xe0,0xe0,0xe0};

        poly128_t r1;
        VMULL_P64(a1, b1, r1);
        poly128_t r2;
        VMULL_HIGH_P64((poly64x2_t)(a2), (poly64x2_t)(b2), r2);

        // Linaro is missing vreinterpretq_u64_p128. Also see
        // http://github.com/weidai11/cryptopp/issues/233.
        const uint64x2_t t1 = (uint64x2_t)(r1);  // {bignum,bignum}
        const uint64x2_t t2 = (uint64x2_t)(r2);  // {bignum,bignum}

        result = !!(vgetq_lane_u64(t1,0) == 0x5300530053005300 &&
                    vgetq_lane_u64(t1,1) == 0x5300530053005300 &&
                    vgetq_lane_u64(t2,0) == 0x6c006c006c006c00 &&
                    vgetq_lane_u64(t2,1) == 0x6c006c006c006c00);
    }

    Sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    Signal(SIGILL, oldHandler);
    return result;
#else
    return false;
#endif
}

/* SL_CPU_ProbeSHA1() and SL_CPU_ProbeSHA2() is based on CPU_ProbeSHA1() and
   CPU_ProbeSHA2() in sha-simd.cpp. */
// sha-simd.cpp - written and placed in the public domain by
//                Jeffrey Walton, Uri Blumenthal and Marcel Raad.
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and http://stackoverflow.com/q/7721854
bool SL_CPU_ProbeSHA1(void)
{
#ifdef __ARM_FEATURE_CRYPTO
    volatile bool result = true;

    volatile SigHandler oldHandler = Signal(SIGILL, SigIllHandler);
    if (oldHandler == SIG_ERR)
    {
        return false;
    }

    volatile sigset_t oldMask;
    if (Sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        return false;
    }

    if (Setjmp(s_jmpSIGILL))
    {
        result = false;
    }
    else
    {
        uint32x4_t data1 = {1,2,3,4}, data2 = {5,6,7,8}, data3 = {9,10,11,12};

        uint32x4_t r1 = vsha1cq_u32 (data1, 0, data2);
        uint32x4_t r2 = vsha1mq_u32 (data1, 0, data2);
        uint32x4_t r3 = vsha1pq_u32 (data1, 0, data2);
        uint32x4_t r4 = vsha1su0q_u32 (data1, data2, data3);
        uint32x4_t r5 = vsha1su1q_u32 (data1, data2);

        result = !!(vgetq_lane_u32(r1,0) | vgetq_lane_u32(r2,1) |
                    vgetq_lane_u32(r3,2) | vgetq_lane_u32(r4,3) |
                    vgetq_lane_u32(r5,0));
    }

    Sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    Signal(SIGILL, oldHandler);
    return result;
#else
    return false;
#endif
}

bool SL_CPU_ProbeSHA2(void)
{
#ifdef __ARM_FEATURE_CRYPTO
    // longjmp and clobber warnings. Volatile is required.
    // http://github.com/weidai11/cryptopp/issues/24 and
    // http://stackoverflow.com/q/7721854
    volatile bool result = true;

    volatile SigHandler oldHandler = Signal(SIGILL, SigIllHandler);
    if (oldHandler == SIG_ERR)
    {
        return false;
    }

    volatile sigset_t oldMask;
    if (Sigprocmask(0, NULLPTR, (sigset_t*)&oldMask))
    {
        return false;
    }

    if (Setjmp(s_jmpSIGILL))
    {
        result = false;
    }
    else
    {
        uint32x4_t data1 = {1,2,3,4}, data2 = {5,6,7,8}, data3 = {9,10,11,12};

        uint32x4_t r1 = vsha256hq_u32 (data1, data2, data3);
        uint32x4_t r2 = vsha256h2q_u32 (data1, data2, data3);
        uint32x4_t r3 = vsha256su0q_u32 (data1, data2);
        uint32x4_t r4 = vsha256su1q_u32 (data1, data2, data3);

        result = !!(vgetq_lane_u32(r1,0) | vgetq_lane_u32(r2,1) |
                    vgetq_lane_u32(r3,2) | vgetq_lane_u32(r4,3));
    }

    Sigprocmask(SIG_SETMASK, (sigset_t*)&oldMask, NULLPTR);
    Signal(SIGILL, oldHandler);
    return result;
#else
    return false;
#endif
}

#else
extern int platform_not_arm; /* Not generating any code on non-ARM. */ 
#endif /* __arm__, __aarch32__ or __aarch64__ */
