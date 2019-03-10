/* sl_cpu.c
 *
 * Detect features of the CPU running the software.
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

/* Note this file is loosely based on cpu.cpp.
   cpu.cpp - originally written and placed in the public domain by Wei Dai */

#if defined(__aarch64__) || defined(__aarch32__) || defined(__arm__)

#include "pscompilerdep.h"
#include <osdep_libc-version.h>

// Capability queries, requires Glibc 2.16, http://lwn.net/Articles/519085/
// CRYPTOPP_GLIBC_VERSION not used because config.h is missing <feature.h>
#if (((__GLIBC__ * 100) + __GLIBC_MINOR__) >= 216)
# define CRYPTOPP_GETAUXV_AVAILABLE 1
#endif

#include "osdep_stdbool.h"

#if CRYPTOPP_GETAUXV_AVAILABLE
# include "osdep_sys_auxv.h"
#else
unsigned long int getauxval(unsigned long int) { return 0; }
#endif

#include "osdep_unistd.h"

/* Default cache line size, from */
// config.h - originally written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_L1_CACHE_LINE_SIZE
// This should be a lower bound on the L1 cache line size.
// Also see http://stackoverflow.com/questions/794632/programmatically-get-the-cache-line-size.
# if defined(_M_X64) || defined(__x86_64__) || defined(__arm64__) || defined(__aarch64__) || defined(__powerpc64__) || defined(_ARCH_PPC64)
#  define CRYPTOPP_L1_CACHE_LINE_SIZE 64
# else
// L1 cache line size is 32 on Pentium III and earlier
#  define CRYPTOPP_L1_CACHE_LINE_SIZE 32
# endif
#endif

// *************************** ARM-32, Aarch32 and Aarch64 ***************************

bool SL_ArmDetectionDone;
bool SL_hasNEON, SL_hasPMULL, SL_hasCRC32, SL_hasAES, SL_hasSHA1, SL_hasSHA2;
unsigned int SL_cacheLineSize;

// ARM does not have an unprivliged equivalent to CPUID on IA-32. We have to jump through some
//   hoops to detect features on a wide array of platforms. Our strategy is two part. First,
//   attempt to *Query* the OS for a feature, like using getauxval on Linux. If that fails,
//   then *Probe* the cpu executing an instruction and an observe a SIGILL if unsupported.
// The probes are in source files where compilation options like -march=armv8-a+crc make
//   intrinsics available. They are expensive when compared to a standard OS feature query.
//   Always perform the feature quesry first. For Linux see
//   http://sourceware.org/ml/libc-help/2017-08/msg00012.html
// Avoid probes on Apple platforms because Apple's signal handling for SIGILLs appears broken.
//   We are trying to figure out a way to feature test without probes. Also see
//   http://stackoverflow.com/a/11197770/608639 and
//   http://gist.github.com/erkanyildiz/390a480f27e86f8cd6ba

#ifndef HWCAP_ASIMD
# define HWCAP_ASIMD (1 << 1)
#endif
#ifndef HWCAP_ARM_NEON
# define HWCAP_ARM_NEON 4096
#endif
#ifndef HWCAP_CRC32
# define HWCAP_CRC32 (1 << 7)
#endif
#ifndef HWCAP2_CRC32
# define HWCAP2_CRC32 (1 << 4)
#endif
#ifndef HWCAP_PMULL
# define HWCAP_PMULL (1 << 4)
#endif
#ifndef HWCAP2_PMULL
# define HWCAP2_PMULL (1 << 1)
#endif
#ifndef HWCAP_AES
# define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP2_AES
# define HWCAP2_AES (1 << 0)
#endif
#ifndef HWCAP_SHA1
# define HWCAP_SHA1 (1 << 5)
#endif
#ifndef HWCAP_SHA2
# define HWCAP_SHA2 (1 << 6)
#endif
#ifndef HWCAP2_SHA1
# define HWCAP2_SHA1 (1 << 2)
#endif
#ifndef HWCAP2_SHA2
# define HWCAP2_SHA2 (1 << 3)
#endif

static inline bool CPU_QueryNEON()
{
#if defined(__ANDROID__) && defined(__aarch64__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_ASIMD))
                return true;
#elif defined(__ANDROID__) && defined(__arm__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON))
                return true;
#elif defined(__linux__) && defined(__aarch64__)
        if (getauxval(AT_HWCAP) & HWCAP_ASIMD)
                return true;
#elif defined(__linux__) && defined(__aarch32__)
        if (getauxval(AT_HWCAP2) & HWCAP2_ASIMD)
                return true;
#elif defined(__linux__) && defined(__arm__)
        if (getauxval(AT_HWCAP) & HWCAP_ARM_NEON)
                return true;
#elif defined(__APPLE__) && defined(__aarch64__)
        // Core feature set for Aarch32 and Aarch64.
        return true;
#endif
        return false;
}

static inline bool CPU_QueryCRC32()
{
#if defined(__ANDROID__) && defined(__aarch64__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_CRC32))
                return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_CRC32))
                return true;
#elif defined(__linux__) && defined(__aarch64__)
        if (getauxval(AT_HWCAP) & HWCAP_CRC32)
                return true;
#elif defined(__linux__) && defined(__aarch32__)
        if (getauxval(AT_HWCAP2) & HWCAP2_CRC32)
                return true;
#elif defined(__APPLE__) && defined(__aarch64__)
        // No compiler support. CRC intrinsics result in a failed compiled.
        return false;
#endif
        return false;
}

static inline bool CPU_QueryPMULL()
{
#if defined(__ANDROID__) && defined(__aarch64__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_PMULL))
                return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_PMULL))
                return true;
#elif defined(__linux__) && defined(__aarch64__)
        if (getauxval(AT_HWCAP) & HWCAP_PMULL)
                return true;
#elif defined(__linux__) && defined(__aarch32__)
        if (getauxval(AT_HWCAP2) & HWCAP2_PMULL)
                return true;
#elif defined(__APPLE__) && defined(__aarch64__)
        /* Currently all 64-bit iOS devices support PMULL. */
        return true;
#endif
        return false;
}

static inline bool CPU_QueryAES()
{
#if defined(__ANDROID__) && defined(__aarch64__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES))
                return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES))
                return true;
#elif defined(__linux__) && defined(__aarch64__)
        if (getauxval(AT_HWCAP) & HWCAP_AES)
                return true;
#elif defined(__linux__) && defined(__aarch32__)
        if (getauxval(AT_HWCAP2) & HWCAP2_AES)
                return true;
#elif defined(__APPLE__) && defined(__aarch64__)
        // http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
        struct utsname systemInfo;
        systemInfo.machine[0] = '\0';
        uname(&systemInfo);

        // The machine strings below are known ARM8 devices
        std::string machine(systemInfo.machine);
        if (machine.substr(0, 7) == "iPhone6" || machine.substr(0, 7) == "iPhone7" ||
                machine.substr(0, 7) == "iPhone8" || machine.substr(0, 7) == "iPhone9" ||
                machine.substr(0, 5) == "iPad4" || machine.substr(0, 5) == "iPad5" ||
                machine.substr(0, 5) == "iPad6" || machine.substr(0, 5) == "iPad7")
        {
                return true;
        }
#endif
        return false;
}

static inline bool CPU_QuerySHA1()
{
#if defined(__ANDROID__) && defined(__aarch64__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA1))
                return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA1))
                return true;
#elif defined(__linux__) && defined(__aarch64__)
        if (getauxval(AT_HWCAP) & HWCAP_SHA1)
                return true;
#elif defined(__linux__) && defined(__aarch32__)
        if (getauxval(AT_HWCAP2) & HWCAP2_SHA1)
                return true;
#elif defined(__APPLE__) && defined(__aarch64__)
        // http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
        struct utsname systemInfo;
        systemInfo.machine[0] = '\0';
        uname(&systemInfo);

        // The machine strings below are known ARM8 devices
        std::string machine(systemInfo.machine);
        if (machine.substr(0, 7) == "iPhone6" || machine.substr(0, 7) == "iPhone7" ||
                machine.substr(0, 7) == "iPhone8" || machine.substr(0, 7) == "iPhone9" ||
                machine.substr(0, 5) == "iPad4" || machine.substr(0, 5) == "iPad5" ||
                machine.substr(0, 5) == "iPad6" || machine.substr(0, 5) == "iPad7")
        {
                return true;
        }
#endif
        return false;
}
static inline bool CPU_QuerySHA2()
{
#if defined(__ANDROID__) && defined(__aarch64__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA2))
                return true;
#elif defined(__ANDROID__) && defined(__aarch32__)
        if ((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) &&
                (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA2))
                return true;
#elif defined(__linux__) && defined(__aarch64__)
        if (getauxval(AT_HWCAP) & HWCAP_SHA2)
                return true;
#elif defined(__linux__) && defined(__aarch32__)
        if (getauxval(AT_HWCAP2) & HWCAP2_SHA2)
                return true;
#elif defined(__APPLE__) && defined(__aarch64__)
        // http://stackoverflow.com/questions/45637888/how-to-determine-armv8-features-at-runtime-on-ios
        struct utsname systemInfo;
        systemInfo.machine[0] = '\0';
        uname(&systemInfo);

        // The machine strings below are known ARM8 devices
        std::string machine(systemInfo.machine);
        if (machine.substr(0, 7) == "iPhone6" || machine.substr(0, 7) == "iPhone7" ||
                machine.substr(0, 7) == "iPhone8" || machine.substr(0, 7) == "iPhone9" ||
                machine.substr(0, 5) == "iPad4" || machine.substr(0, 5) == "iPad5" ||
                machine.substr(0, 5) == "iPad6" || machine.substr(0, 5) == "iPad7")
        {
                return true;
        }
#endif
        return false;
}

extern bool SL_CPU_ProbeNEON(void);
extern bool SL_CPU_ProbeCRC32(void);
extern bool SL_CPU_ProbeAES(void);
extern bool SL_CPU_ProbeSHA1(void);
extern bool SL_CPU_ProbeSHA2(void);
extern bool SL_CPU_ProbePMULL(void);

void SL_DetectArmFeatures(void)
{
    // The CPU_ProbeXXX's return false for OSes which
    //   can't tolerate SIGILL-based probes
    SL_hasNEON  = CPU_QueryNEON() || SL_CPU_ProbeNEON();
    SL_hasCRC32 = CPU_QueryCRC32();
    SL_hasPMULL = CPU_QueryPMULL() || SL_CPU_ProbePMULL();
    SL_hasAES  = CPU_QueryAES() || SL_CPU_ProbeAES();
    SL_hasSHA1 = CPU_QuerySHA1() || SL_CPU_ProbeSHA1();
    SL_hasSHA2 = CPU_QuerySHA2() || SL_CPU_ProbeSHA2();

#if defined(__linux__) && defined(_SC_LEVEL1_DCACHE_LINESIZE)
    SL_cacheLineSize = Sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
#endif

    if (!SL_cacheLineSize)
    {
        SL_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;
    }
    
    SL_ArmDetectionDone = true;
}

#else
extern int platform_not_arm; /* Not generating any code on non-ARM. */ 
#endif /* __arm__, __aarch32__ or __aarch64__ */
