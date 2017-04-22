/**
 *      @file    pstmnt.c
 *      @version $Format:%h%d$
 *
 *      Multiprecision number implementation: constant time montgomery.
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

#include "../cryptoImpl.h"
#include "pstmnt.h"

#ifdef USE_CONSTANT_TIME_MODEXP

# include <assert.h>

/* Workarounds for C99 features */
# if __STDC_VERSION__ < 199901L
#  define restrict /* define restrict to nothing if compiler is not sufficiently
                      new to support it. */
# endif

/* Additional internal definitions. */
# define PSTMNT_HOT_FUNCTION /* Function is likely hot spot in computation. */

/* Simple preprocessor macros. */
# define PSTMNT_JOIN_(a, b) a ## b
# define PSTMNT_JOIN(a, b) PSTMNT_JOIN_(a, b)

/* Test condition during compilation. */
# define PSTMNT_COMPILE_ASSERT(pstmnt_condition)                 \
    extern int PSTMNT_JOIN(PSTMNT_COMPILE_ASSERT_at_, __LINE__)  \
    [1 - 2 * (!(pstmnt_condition))]

/* Semantics: variants according to intent. */
# define PSTMNT_ASSERT(x) assert(x)
# define PSTMNT_PRECONDITION(x) assert(x)
# define PSTMNT_POSTCONDITION(x) assert(x)

/* Mark expected execution paths for compiler optimizations. */
# ifndef PSTMNT_EXPECT
#  ifdef __GNUC__
#   define PSTMNT_EXPECT(value, usual_value) __builtin_expect(value, (usual_value))
#  else /* !__GNUC__ */
#   define PSTMNT_EXPECT(value, usual_value) (value)
#  endif /* __GNUC__ */
# endif /* PSTMNT_EXPECT */

/* Rename standard C API function calls.
   (allows easy substitution with alternatives in non-standard C libraries.). */
# ifndef PSTMNT_COPY
#  define PSTMNT_COPY(ptr_d, ptr, sz) memcpy((ptr_d), (ptr), (sz))
# endif /* PSTMNT_COPY */
# ifndef PSTMNT_MOVE
#  define PSTMNT_MOVE(ptr_d, ptr, sz) memmove((ptr_d), (ptr), (sz))
# endif /* PSTMNT_MOVE */
# ifndef PSTMNT_ZEROIZE
#  define PSTMNT_ZEROIZE(ptr, sz) memset((ptr), 0, (sz))
# endif /* PSTMNT_ZEROIZE */

/* Basic mathematics operations - inlined or macro. */
# define PSTMNT_WORD_NEGATE(x) ((~((pstmnt_word) (x))) + 1)
# define PSTMNT_WORD_BITS_M1 31
# define PSTMNT_WORD_HIGH_BIT (1U << (PSTMNT_WORD_BITS_M1))
# define PSTMNT_WORDS_TO_BITS(in) ((in) * 32)
# define pstmnt_is_zero(w, n) (pstmnt_get_num_bits((w), (n)) == 0)
# define pstmnt_is_one(w, n) (pstmnt_get_num_bits((w), (n)) == 1)
# define pstmnt_is_even(w, n) (n == 0 || (w[0] & 1) == 0)
# define pstmnt_is_odd(w, n) (n > 0 && (w[0] & 1) == 1)
# define pstmnt_clear(r_, n_) (void) PSTMNT_ZEROIZE((r_), (n_) * sizeof(pstmnt_word))
# define pstmnt_extend(r, n1, n2) pstmnt_clear((r) + (n1), (n2) - (n1))
# define pstmnt_copy(a, r, n) (void) PSTMNT_COPY((r), (a), (n) * sizeof(pstmnt_word))
# define pstmnt_reduce(a, p, r, t, n) pstmnt_reduce2(a, p, r, NULL, t, n)
# define PSTMNT_UINT32 uint32_t
# define PSTMNT_UINT64 uint64_t

/* Determine platform and configure accordingly. */

# define PSTMNT_NO_KARATSUBA
# if defined(__LP64__) || defined(_LP64)
/* X86 or ARM64: Use 128-bit integers where available. */
#  define PSTMNT_USE_INT128
#  define PSTMNT_USE_INT128
#  define PSTMNT_USE_INT128_SQUARE
#  define PSTMNT_USE_INT128_MULT
#  define PSTMNT_USE_INT128_MONTGOMERY
# endif /* __LP64__ */

# ifdef __i386__
/* Note: on X86 we must enable inline assembly: to make sure the C compiler
   does not use __udivdi3, __umoddi3 functions. */
#  define PSTMNT_USE_X86_ASSEMBLY
# endif /* __i386__ */

# ifdef __thumb2__
/* Optional assembly optimizations for ARMv7 with Thumb-2. */
#  ifndef PSTMNT_OMIT_ASSEMBLY_OPTIMIZATIONS
#   define PSTMNT_USE_THUMB2_ASSEMBLY
#  endif /* PSTMNT_OMIT_ASSEMBLY_OPTIMIZATIONS */
# endif  /* __thumb2__ */

# if __arm__
/* Optional assembly optimizations for ARM
   (note: also Thumb-2, above, may be in effect). */
#  ifndef PSTMNT_OMIT_ASSEMBLY_OPTIMIZATIONS
#   define PSTMNT_USE_ARM_ASSEMBLY
#  endif /* PSTMNT_OMIT_ASSEMBLY_OPTIMIZATIONS */
# endif  /* __arm__ */

/* --- low-level mathematics operations --- */

# ifdef PSTMNT_USE_X86_ASSEMBLY
/* Optimized versions for macros for Intel x86 architecture based
   platforms. (Only for GCC compiler.) */

/* Replace contents of count with number of leading zeros in x.
   Both count and x are 32-bit unsigned values. */
#  define PSTMNT_COUNT_LEADING_ZEROS(count, x)        \
    __asm__("bsrl %1,%0; xorl $31, %0" :            \
    "=r" (count) : "rm" ((pstmnt_word) (x)))

/* Replace contents of count with number of trailing zeros in x.
   Both count and x are 32-bit unsigned values. */
#  define PSTMNT_COUNT_TRAILING_ZEROS(count, x)       \
    __asm__("bsfl %1,%0" :                          \
    "=r" (count) : "rm" ((pstmnt_word) (x)))

#  ifndef PSTMNT_LONG_MUL_GENERIC
/* Multiply a and b, produce result u:v. Where u is 32 high order bits of
   the result and v are the 32 low order bits of the result.
   All parameters are 32-bit unsigned integers. */
#   define PSTMNT_LONG_MUL(u, v, a, b)             \
    __asm__("mull %3"                           \
    : "=a" ((pstmnt_word) v),            \
    "=d" ((pstmnt_word) u)             \
    : "0" ((pstmnt_word) a),             \
    "rm" ((pstmnt_word) b))
#  endif /* PSTMNT_LONG_MUL_GENERIC */

/* {u:v} = {u:v} + c1 + c2
   Add 32-bit values c1 and c2 to 64-bit value represented by {u:v},
   where u has 32 highest bits of the value and v has 32 lowest bits of
   the values.
   All parameters (u, v, c1, c2) are 32-bit integers. */
#  define PSTMNT_LONG_ADD32_32(u, v, c1, c2)                          \
    __asm__("addl %4,%0\nadcl $0,%1\n\taddl %5,%0\n\tadcl $0,%1"    \
    : "=&r" ((pstmnt_word) v),                               \
    "=&r" ((pstmnt_word) u)                                \
    : "0" ((pstmnt_word) v),                                 \
    "1" ((pstmnt_word) u),                                 \
    "rm" ((pstmnt_word) c1),                               \
    "rm" ((pstmnt_word) c2))

/* {u:v} = {u:v} + c1 + c2
   Add 32-bit values c1 and c2 to 64-bit value represented by {u:v},
   where u has 32 highest bits of the value and v has 32 lowest bits of
   the values.
   All parameters (u, v, c1, c2) are 32-bit integers.
   For this function, value c2 is constrained to be either 0 or 1, for
   any other values of c2, result of the function is undefined. */
#  define PSTMNT_LONG_ADD32_1(u, v, c1, c2)                   \
    do { uint32_t c2_shift;                                 \
         __asm__("rcrl $1,%6\n\tadcl %5,%0\n\tadcl $0,%1"    \
             : "=&r" ((pstmnt_word) v),                   \
             "=r" ((pstmnt_word) u),                    \
             "=&r" ((pstmnt_word) c2_shift)             \
             : "0" ((pstmnt_word) v),                     \
             "1" ((pstmnt_word) u),                     \
             "rm" ((pstmnt_word) c1),                   \
             "2" ((pstmnt_word) c2));                   \
    } while (0)

/* {u:v} = {u:v} + c
   Add 32-bit c to 64-bit value represented by {u:v},
   All parameters (u, v, c) are 32-bit integers.
 */
#  define PSTMNT_LONG_ADD32(u, v, c)              \
    __asm__("addl %4,%0\n\tadcl $0,%1"          \
    : "=&r" ((pstmnt_word) v),           \
    "=r" ((pstmnt_word) u)             \
    : "0" ((pstmnt_word) v),             \
    "1" ((pstmnt_word) u),             \
    "rm" ((pstmnt_word) c))

/* Same as PSTMNT_LONG_MUL, but additional parameter with 32-bit value c
   is added to result of the multiplication. */
#  define PSTMNT_LONG_MUL_ADD32(u, v, a, b, c)                            \
    do { PSTMNT_LONG_MUL(u, v, a, b); PSTMNT_LONG_ADD32(u, v, c); } while (0)

/* Divide 64-bit value represented by {d1:d0} with 32-bit value d.
   32-bit result is returned as q, and remainder is returned as r.
   The behavior is undefined if d is not defined or if the result of
   operation does not fit in q. */
#  define PSTMNT_LONG_DIV(q, r, d1, d0, d)        \
    __asm__("divl %4"                           \
    : "=a" ((pstmnt_word) q),            \
    "=d" ((pstmnt_word) r)             \
    : "0"  ((pstmnt_word) d0),           \
    "1"  ((pstmnt_word) d1),           \
    "rm" ((pstmnt_word) d))

# elif defined PSTMNT_USE_ARM_ASSEMBLY
/* Assembly optimizations for ARMv7 with and without Thumb-2. */

/* {u:v} = {u:v} + b*a
   Set 64-bit result of multiplication of 32-bit integers to
   64-bit value represented by {u:v},
   All parameters (u, v, b, a) are 32-bit integers.
 */
#  ifndef PSTMNT_LONG_MUL_GENERIC
#   define PSTMNT_LONG_MUL(u, v, a, b)                                     \
    __asm__("umull %0, %1, %2, %3" : "=r" (v), "=r" (u) : "r" (a), "r" (b))
#  endif /* PSTMNT_LONG_MUL_GENERIC */

/* {u:v} = {u:v} + b*a
   Add 64-bit result of multiplication of 32-bit integers to
   64-bit value represented by {u:v},
   All parameters (u, v, b, a) are 32-bit integers.
 */
#  define PSTMNT_LONG_MULADD(u, v, b, a)          \
    __asm__("umlal %0,%1,%2,%3" :               \
    "=r" (v), "=r" (u) :                \
    "r" (a), "r" (b), "0" (v), "1" (u))

/* {u:v} = u + v + b*a
   Add 64-bit result of multiplication of 32-bit integers to
   32-bit values represented by u and v, return 64-bit result
   in {u:v}.
   All parameters (u, v, b, a) are 32-bit integers.
 */
#  ifdef __ARM_ARCH_7A__
#   define PSTMNT_LONG_MULADD2(u, v, b, a)                 \
    __asm__("umaal %0,%1,%2,%3" :                       \
    "=r" (v), "=r" (u) :                        \
    "r" (a), "r" (b), "0" (v), "1" (u) : "cc")
#  else
/* avoid umaal instruction. */
#   define PSTMNT_LONG_MULADD2(u, v, b, a)             \
    do { PSTMNT_LONG_ADD32_32_TO_33(u, v, u, v);    \
         PSTMNT_LONG_MULADD(u, v, b, a); } while (0)
#  endif

#  ifdef __ARM_ARCH_7A__
/* PSTMNT_LONG_MULADD2 is fast enough to substitute much of usual integer
   addition arithmetics (it can be used as add 3x32 => 64bit result.) */
#   define PSTMNT_LONG_MULADD2_FAST PSTMNT_LONG_MULADD2
#  endif /* __ARM_ARCH_7A__ */

/* {uu} += u_new < u_old
   Handle carries: increment uu if increment of u_old
   to u_new caused overflow.
   All parameters (uu, u_new, u_old) are 32-bit integers.
 */
#  define PSTMNT_LONG_CARRY(uu, u_new, u_old)                             \
    __asm__("cmp %1, %2\n\t"                                            \
    "it lo\n\t"                                                 \
    "addlo %0, %3, #1"                                          \
    : "=&r" (uu) : "r" (u_new), "r" (u_old), "0" (uu) : "cc")

/* {uu:u:v} = {uu:u:v} + b*a
   Add 64-bit result of multiplication of 32-bit integers to
   96-bit value represented by {uu:u:v},
   All parameters (uu, u, v, b, a) are 32-bit integers.
 */
#  define PSTMNT_LONG_MULADD_CARRY(uu, u, v, b, a)    \
    do { unsigned int u_old = (u);                  \
         PSTMNT_LONG_MULADD(u, v, b, a);             \
         PSTMNT_LONG_CARRY(uu, (u), u_old);          \
    } while (0)

/* {u:v} = {u:v} + c1 */
#  define PSTMNT_LONG_ADD32(u, v, c)                  \
    __asm__("adds %0, %0, %3\n\tadc %1, %2, #0" :   \
    "+&r" (v), "=r" (u) :                   \
    "r" (u), "rI" (c) : "cc")

/* {hi:u:v} = {u:v} + {u2:v2} */
#  define PSTMNT_LONG_ADD64_CARRY(hi, u, v, u2, v2)                       \
    __asm__("adds %0, %0, %3\n\tadcs %1, %1, %4\n\tadc %2, %2, #0" :    \
    "+&r" (v), "+&r" (u), "+r" (hi) :                           \
    "r" (v2), "r" (u2) : "cc")


#  ifdef PSTMNT_ARMV7
/* {u:v} = a + b */
#   define PSTMNT_LONG_ADD32_32_TO_33(u, v, a, b)                          \
    __asm__("adds %0, %2, %3\n\tsbc.w %1, %1, %1\n\tadd %1, %1, #1" :   \
    "=&r" (v), "=r" (u) :                                       \
    "r" (a), "r" (b) : "cc")
#  endif /* PSTMNT_ARMV7 */
#  ifndef PSTMNT_LONG_ADD32_32_TO_33
#   define PSTMNT_LONG_ADD32_32_TO_33(u, v, a, b)  \
    do {                                        \
        unsigned int b_in = (b);                \
        v = (a) + b_in;                         \
        u = (v < b_in); /* Check carry. */      \
    } while (0)
#  endif /* PSTMNT_LONG_ADD32_32_TO_33 */

/* {u:v} = {u:v} + c1 + c2.
   All parameters except c2 are 32-bit integers. c2 is either 0 or 1. */
#  define PSTMNT_LONG_ADD32_1(u, v, c1, c2)                   \
    __asm__("cmn %5, #0xffffffff\n\t"                       \
    "adcs %0, %2, %4\n\tadc %1, %3, #0" :           \
    "=&r" (v), "=r" (u) :                           \
    "r" (v), "r" (u), "rI" (c1), "r" (c2) : "cc")

# endif /* Switch: platform specific assembly optimizations. */

# ifdef PSTMNT_LONG_MULADD_GENERIC
/* Provide PSTMNT_LONG_MULADD and others as generic variants.
   This'll make some compilers use paths optimized for fused-multiply-add
   instruction, which often is faster, at least on platforms with many
   registers. */

#  ifndef PSTMNT_LONG_ADD32_32_TO_33
#   define PSTMNT_LONG_ADD32_32_TO_33(u, v, a, b)  \
    do {                                        \
        unsigned int b_in = (b);                \
        v = (a) + b_in;                         \
        u = (v < b_in); /* Check carry. */      \
    } while (0)
#  endif /* PSTMNT_LONG_ADD32_32_TO_33 */

#  ifndef PSTMNT_LONG_LEFT_SHIFT96_1
/* {c,b,a} = {c,b,a} + {c,b,a} */
#   define PSTMNT_LONG_LEFT_SHIFT96_1(c, b, a)     \
    do {                                        \
        c = ((c) << 1) | ((b) >> 31);           \
        b = ((b) << 1) | ((a) >> 31);           \
        a = (a) << 1;                           \
    } while (0)
#  endif /* PSTMNT_LONG_SHIFT96_1 */

#  ifndef PSTMNT_LONG_ADD64
#   define PSTMNT_LONG_ADD64(u, v, b, a)           \
    do {                                        \
        PSTMNT_UINT64 uv;                       \
        PSTMNT_UINT64 ba;                       \
        uv = (((PSTMNT_UINT64) u) << 32) | v;   \
        ba = (((PSTMNT_UINT64) b) << 32) | a;   \
        uv += ba;                               \
        u = (PSTMNT_UINT32) (uv >> 32);         \
        v = (PSTMNT_UINT32) (uv);               \
    } while (0)
#  endif /* PSTMNT_LONG_ADD64 */

#  ifndef PSTMNT_LONG_ADD32
#   define PSTMNT_LONG_ADD32(u, v, a) PSTMNT_LONG_ADD64(u, v, 0, a)
#  endif /* PSTMNT_LONG_ADD32 */

#  ifndef PSTMNT_LONG_ADD64_CARRY
#   define PSTMNT_LONG_ADD64_CARRY(uu, u, v, b, a)     \
    do {                                            \
        PSTMNT_UINT64 uv;                           \
        PSTMNT_UINT64 ba;                           \
        uv = (((PSTMNT_UINT64) u) << 32) | v;       \
        ba = (((PSTMNT_UINT64) b) << 32) | a;       \
        uv += ba;                                   \
        if (uv < ba) { uu++; /* Carry handling. */    \
        } \
        u = (PSTMNT_UINT32) (uv >> 32);             \
        v = (PSTMNT_UINT32) (uv);                   \
    } while (0)
#  endif /* PSTMNT_LONG_ADD64_CARRY */

#  ifndef PSTMNT_LONG_MULADD
#   define PSTMNT_LONG_MULADD(u, v, b, a)          \
    do { unsigned int ut, vt;                   \
         PSTMNT_LONG_MUL(ut, vt, b, a);          \
         PSTMNT_LONG_ADD64(u, v, ut, vt);        \
    } while (0)
#  endif /* PSTMNT_LONG_MULADD */

/* {u:v} = u + v + b*a
   Add 64-bit result of multiplication of 32-bit integers to
   32-bit values represented by u and v, return 64-bit result
   in {u:v}.
   All parameters (u, v, b, a) are 32-bit integers.
 */
#  ifndef PSTMNT_LONG_MULADD2
#   define PSTMNT_LONG_MULADD2(u, v, b, a)         \
    do {                                        \
        pstmnt_dword uv;                        \
        pstmnt_dword ba;                        \
        uv = ((pstmnt_dword) u) + v;            \
        ba = ((pstmnt_dword) b) * a;            \
        uv += ba;                               \
        u = (pstmnt_word) (uv >> 32);           \
        v = (pstmnt_word) (uv);                 \
    } while (0)
#  endif /* PSTMNT_LONG_MULADD2 */

#  ifndef PSTMNT_LONG_MULADD_CARRY
#   define PSTMNT_LONG_MULADD_CARRY(uu, u, v, b, a)    \
    do { pstmnt_word uo = u;                        \
         pstmnt_dword uv;                            \
         pstmnt_dword ba;                            \
         uv = (((pstmnt_dword) u) << 32) | v;        \
         ba = ((pstmnt_dword) b) * a;                \
         uv += ba;                                   \
         u = (pstmnt_word) (uv >> 32);               \
         v = (pstmnt_word) (uv);                     \
         uu += (u < uo); /* Carry handling. */       \
    } while (0)
#  endif /* PSTMNT_LONG_MULADD_CARRY */

# endif /* Switch: platform specific assembly optimizations. */

# ifndef PSTMNT_LONG_ADD64_CARRY
#  define PSTMNT_LONG_ADD64_CARRY(uu, u, v, b, a) \
    do {                                        \
        PSTMNT_UINT64 uv;                       \
        PSTMNT_UINT64 ba;                       \
        uv = (((PSTMNT_UINT64) u) << 32) | v;   \
        ba = (((PSTMNT_UINT64) b) << 32) | a;   \
        uv += ba;                               \
        uu += (uv < ba); /* Carry handling. */  \
        u = (PSTMNT_UINT32) (uv >> 32);         \
        v = (PSTMNT_UINT32) (uv);               \
    } while (0)
# endif /* PSTMNT_LONG_ADD64_CARRY */

# ifndef PSTMNT_LONG_LEFT_SHIFT96_1
/* {c,b,a} = {c,b,a} + {c,b,a} */
#  define PSTMNT_LONG_LEFT_SHIFT96_1(c, b, a)     \
    do {                                        \
        c = ((c) << 1) | ((b) >> 31);           \
        b = ((b) << 1) | ((a) >> 31);           \
        a = (a) << 1;                           \
    } while (0)
# endif /* PSTMNT_LONG_LEFT_SHIFT96_1 */

static
inline
uint32_t
pstmnt_pop_count(uint32_t Value)
{
    /* Reduce bits into counts. */
    Value -= ((Value >> 1) & 0x55555555);
    Value = ((Value >> 2) & 0x33333333) + (Value & 0x33333333);
    Value = ((Value >> 4) + Value); /* Upper nibbles of each byte are
                                       garbage. */
# if defined(__ARM_ARCH_7A__) && defined(PSTMNT_USE_ARM_ASSEMBLY)
    /* Combine results with usad8, use subtraction to ignore
       garbage bits. */
    __asm__("usad8 %0, %1, %2" : "=r" (Value) : "r" (Value),
        "r" (Value & 0xf0f0f0f0));
    return Value;
# else /* Not ARM ARCH 7-A. */
       /* Reduce bits into counts. */
    Value &= 0x0f0f0f0f;
    Value += (Value >> 8);
    Value += (Value >> 16);
    return Value & 0x0000003f;
# endif /* defined(__ARM_ARCH_7A__) && defined(PSTMNT_USE_ARM_ASSEMBLY) */
}

static
inline
uint32_t
pstmnt_ffsV(const uint32_t Value)
{
    /* Get least significant 1 bit (or 0 if Value is zero.) */
    return Value & - Value;
}

# ifdef PSTMNT_USE_GCC_BUILTIN_CTZ
#  ifndef PSTMNT_COUNT_TRAILING_ZEROS
#   define PSTMNT_COUNT_TRAILING_ZEROS(count, x)       \
    count = (uint32_t) __builtin_ctz((uint32_t) x)
#  endif /* PSTMNT_COUNT_TRAILING_ZEROS */
# endif  /* PSTMNT_USE_GCC_BUILTIN_CTZ */

# ifndef PSTMNT_COUNT_TRAILING_ZEROS
static
inline
uint32_t
pstmnt_ffs__minus1(uint32_t Value)
{
    /* OPTN: This algorithm has three SWAR operations, likely it is
       possible to just use two, like PSTMNT_COUNT_LEADING_ZEROS. */
    Value = pstmnt_ffsV(Value);
    /* Decrement 1 from highest bit set to get mask with all bits prior
       the highest valued bit set.
       Note: possible wraparound makes the value 0xFFFFFFFFU. */
    Value--;

    /* Construct mask, starting from the lowest bit. */
    Value |= (Value >> 1);
    Value |= (Value >> 2);
    Value |= (Value >> 4);
    Value |= (Value >> 8);
    Value |= (Value >> 16);

    /* Calculate bits within the mask, return 0 when mask is full of ones. */
    return pstmnt_pop_count(Value) & 31;
}

#  define PSTMNT_COUNT_TRAILING_ZEROS(count, x) count = pstmnt_ffs__minus1(x)
# endif /* !PSTMNT_COUNT_TRAILING_ZEROS */

# ifdef PSTMNT_USE_GCC_BUILTIN_CLZ
#  ifndef PSTMNT_COUNT_LEADING_ZEROS
#   define PSTMNT_COUNT_LEADING_ZEROS(count, x)        \
    count = (uint32_t) __builtin_clz((uint32_t) x)
#  endif /* PSTMNT_COUNT_LEADING_ZEROS */
# endif  /* PSTMNT_USE_GCC_BUILTIN_CLZ */

# ifndef PSTMNT_COUNT_LEADING_ZEROS
static
inline
uint32_t
pstmnt_lzc(uint32_t Value)
{
    /* Create mask with all bits starting from first set bit set. */
    Value |= (Value >> 1);
    Value |= (Value >> 2);
    Value |= (Value >> 4);
    Value |= (Value >> 8);
    Value |= (Value >> 16);

    /* Calculate population count, return 0 when mask is full of ones. */
    return (32 - pstmnt_pop_count(Value)) & 31;
}

#  define PSTMNT_COUNT_LEADING_ZEROS(count, x) count = pstmnt_lzc(x)
# endif /* PSTMNT_COUNT_LEADING_ZEROS */

# ifndef PSTMNT_LONG_MUL
/* Define generic version of PSTMNT_LONG_MUL if no specific
   instruction/instruction sequence is available. */
static
inline
void
pstmnt_parse__uint64(uint64_t InputBits,
    uint32_t * const HighBits_p,
    uint32_t * const LowBits_p)
{
    *HighBits_p = (uint32_t) (InputBits >> 32);
    *LowBits_p = (uint32_t) (InputBits & 0xFFFFFFFFUL);
}

#  define PSTMNT_LONG_MUL(u, v, a, b)                             \
    pstmnt_parse__uint64(((uint64_t) (a)) * (b), (&(u)), (&(v)))
# endif /* !PSTMNT_LONG_MUL */

# ifndef PSTMNT_LONG_DIV
#  ifndef __arm__
/* Use simple inline function for long division. */
static inline
void
pstmnt_long_div(uint32_t *q_p, uint32_t *r_p,
    uint32_t d1, uint32_t d0, uint32_t Divisor)
{
    uint32_t q = (uint32_t) (((((uint64_t) d1) << 32) | d0) / Divisor);
    uint32_t r = (uint32_t) (((((uint64_t) d1) << 32) | d0) % Divisor);

    *q_p = q;
    *r_p = r;
}
#  else
/* On ARM, pstmnt_long_div implemented in fl-deps.c.
   This is because in ARM the CPU instruction does not have neccessary
   division instruction, but long division is processed by the platform ABI. */
void
pstmnt_long_div(uint32_t *q_p, uint32_t *r_p,
                uint32_t d1, uint32_t d0, uint32_t Divisor);
#  endif

#  define PSTMNT_LONG_DIV(q, r, d1, d0, d)        \
    pstmnt_long_div(&(q), &(r), d1, d0, d)
# endif /* !PSTMNT_LONG_DIV */

# ifndef PSTMNT_USE_GCC_BUILTIN_BSWAP32
static
inline
uint32_t
pstmnt_reverse_bytes32(uint32_t Value)
{
    Value = (((Value & 0xff00ff00U) >> 8) | ((Value & 0x00ff00ffU) << 8));
    return (Value >> 16) | (Value << 16);
}
# else
static
inline
uint32_t
pstmnt_reverse_bytes32(uint32_t Value)
{
    return __builtin_bswap32(Value);
}
# endif /* PSTMNT_USE_GCC_BUILTIN_BSWAP32 */

# ifndef PSTMNT_USE_GCC_BUILTIN_BSWAP64
static
inline
uint64_t
pstmnt_reverse_bytes64(uint64_t Value)
{
    Value = (((Value & 0xff00ff00ff00ff00ULL) >> 8) |
             ((Value & 0x00ff00ff00ff00ffULL) << 8));
    Value = (((Value & 0xffff0000ffff0000ULL) >> 16) |
             ((Value & 0x0000ffff0000ffffULL) << 16));
    return (Value >> 32) | (Value << 32);
}
# else
static
inline
uint64_t
pstmnt_reverse_bytes64(uint64_t Value)
{
    return __builtin_bswap64(Value);
}
# endif /* PSTMNT_USE_GCC_BUILTIN_BSWAP64 */

# ifdef PSTMNT_USE_INT128
typedef struct
{
    uint64_t value;
}  __attribute__((__packed__, __aligned__(4))) pstmnt_uint64_aligned4_t;

__extension__ typedef unsigned __int128 pstmntDD_word;

#  ifndef PSTMNT_VERYLONG_MULADD_CARRY
#   define PSTMNT_VERYLONG_MULADD_CARRY(uu, u, v, b, a)    \
    do { pstmnt_dword uo = u;                           \
         pstmntDD_word uv;                               \
         pstmntDD_word ba;                               \
         uv = (((pstmntDD_word) u) << 64) | v;           \
         ba = ((pstmntDD_word) b) * a;                   \
         uv += ba;                                       \
         u = (pstmnt_dword) (uv >> 64);                  \
         v = (pstmnt_dword) (uv);                        \
         uu += (u < uo); /* Carry handling. */           \
    } while (0)
#  endif /* PSTMNT_VERYLONG_MULADD_CARRY */

#  ifndef PSTMNT_VERYLONG_MULADD2
#   define PSTMNT_VERYLONG_MULADD2(u, v, b, a)     \
    do {                                        \
        pstmntDD_word uv;                       \
        pstmntDD_word ba;                       \
        uv = ((pstmntDD_word) u) + v;           \
        ba = ((pstmntDD_word) b) * a;           \
        uv += ba;                               \
        u = (pstmnt_dword) (uv >> 64);          \
        v = (pstmnt_dword) (uv);                \
    } while (0)
#  endif /* PSTMNT_VERYLONG_MULADD2 */

#  ifndef PSTMNT_VERYLONG_ADD128_CARRY
#   define PSTMNT_VERYLONG_ADD128_CARRY(uu, u, v, b, a)    \
    do {                                                \
        pstmntDD_word uv;                               \
        pstmntDD_word ba;                               \
        uv = (((pstmntDD_word) u) << 64) | v;           \
        ba = (((pstmntDD_word) b) << 64) | a;           \
        uv += ba;                                       \
        uu += (uv < ba); /* Carry handling. */          \
        u = (pstmntDD_word) (uv >> 64);                 \
        v = (pstmntDD_word) (uv);                       \
    } while (0)
#  endif /* PSTMNT_VERYLONG_ADD128_CARRY */
# endif  /* PSTMNT_USE_INT128 */

# ifndef PSTMNT_VERYLONG_LEFT_SHIFT192_1
/* {c,b,a} = {c,b,a} + {c,b,a} */
#  define PSTMNT_VERYLONG_LEFT_SHIFT192_1(c, b, a)    \
    do {                                            \
        c = ((c) << 1) | ((b) >> 63);               \
        b = ((b) << 1) | ((a) >> 63);               \
        a = (a) << 1;                               \
    } while (0)
# endif /* PSTMNT_VERYLONG_SHIFT192_1 */

# ifndef __PLATFORM_HAS_SPECIAL_DIV_MOD_U32__
/* Macros for division/modulo. (For the most platforms.) */
#  define PSTMNT_DIV_U32(a, b) ((a) / (b))
#  define PSTMNT_MOD_U32(a, b) ((a) % (b))
# endif /* __PLATFORM_HAS_SPECIAL_DIV_MOD_U32__ */

/* Logic to map square and multiplication functions to implementations.
   Occasionally it is better to invoke pstm_*_comba.
   Occasionally square is not individually defined and it needs to map to
   multiplication.
 */

/* Create "wrapper" pstm_int's for memory arrays.
   These can be used by pstm_*_comba functions but these are not safe for
   all pstm functions. These wrappers shall not be freed or resized. */
# define PSTM_INT_UNSIGNED_MEM(ptr_uint32, sz_digits)        \
    {                                                       \
        (pstm_digit *) (const pstm_digit *) (ptr_uint32),   \
        (psPool_t *) (void *) 1UL,                          \
        (sz_digits),                                        \
        (sz_digits),                                        \
        PSTM_ZPOS                                           \
    }

/* Use pstm_sqr_comba if compiled in and suitable size variant is available. */
__inline static int
pstmnt_square_comba(
    const uint32_t a[],
    uint32_t * restrict r,
    int sz)
{
# ifndef PSTMNT_NO_COMBA
#  if PSTMNT_WORD_BITS == 32
#   if DIGIT_BIT == 64 && defined(USE_1024_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 32)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 16);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 32);
        int32_t res = pstm_sqr_comba(NULL, &a_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#   if DIGIT_BIT == 64 && defined(USE_2048_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 64)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 32);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 64);
        int32_t res = pstm_sqr_comba(NULL, &a_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#   if DIGIT_BIT == 32 && defined(USE_1024_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 16)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 16);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 32);
        int32_t res = pstm_sqr_comba(NULL, &a_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#   if DIGIT_BIT == 32 && defined(USE_2048_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 32)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 32);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 64);
        int32_t res = pstm_sqr_comba(NULL, &a_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#  endif /* PSTMNT_WORD_BITS == 32 */
# endif  /* !PSTMNT_NO_COMBA */
    return 0;
}

__inline static int
pstmnt_mult_comba(
    const uint32_t a[],
    const uint32_t b[],
    uint32_t * restrict r,
    int sz)
{
# ifndef PSTMNT_NO_COMBA
#  if PSTMNT_WORD_BITS == 32
#   if DIGIT_BIT == 64 && defined(USE_1024_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 32)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 16);
        pstm_int b_wrap = PSTM_INT_UNSIGNED_MEM(b, 16);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 32);
        int32_t res = pstm_mul_comba(NULL, &a_wrap, &b_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#   if DIGIT_BIT == 64 && defined(USE_2048_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 64)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 32);
        pstm_int b_wrap = PSTM_INT_UNSIGNED_MEM(b, 32);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 64);
        int32_t res = pstm_mul_comba(NULL, &a_wrap, &b_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#   if DIGIT_BIT == 32 && defined(USE_1024_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 16)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 16);
        pstm_int b_wrap = PSTM_INT_UNSIGNED_MEM(b, 16);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 32);
        int32_t res = pstm_mul_comba(NULL, &a_wrap, &b_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#   if DIGIT_BIT == 32 && defined(USE_2048_KEY_SPEED_OPTIMIZATIONS)
    if (sz == 32)
    {
        pstm_int a_wrap = PSTM_INT_UNSIGNED_MEM(a, 32);
        pstm_int b_wrap = PSTM_INT_UNSIGNED_MEM(b, 32);
        pstm_int r_wrap = PSTM_INT_UNSIGNED_MEM(r, 64);
        int32_t res = pstm_mul_comba(NULL, &a_wrap, &b_wrap, &r_wrap, NULL, 0);
        return res == PSTM_OKAY;
    }
#   endif
#  endif /* PSTMNT_WORD_BITS == 32 */
# endif  /* !PSTMNT_NO_COMBA */
    return 0;
}

void
pstmnt_mult(
    const uint32_t a[],
    const uint32_t b[],
    uint32_t * restrict r,
    int sz);

# if defined(PSTMNT_LONG_MULADD_CARRY) || defined PSTMNT_USE_INT128_SQUARE
/* Use optimized square function */
void
pstmnt_square(
    const uint32_t a[],
    uint32_t * restrict r,
    int sz);
# else
/* Apply the generic pstmnt_mult() function for square. */

void
pstmnt_square(
    const uint32_t a[],
    uint32_t * restrict r,
    int sz)
{
    if (pstmnt_square_comba(a, r, sz))
    {
        return;
    }

    /* No square function, just use multiplier. */
    pstmnt_mult(a, a, r, n);
}
# endif

/* --- actual high level functions --- */

/* pstmnt_neg_small_inv is dependent on bits per word. */
PSTMNT_COMPILE_ASSERT(PSTMNT_WORD_BITS == 32);

/* Return -1 / a (mod 2^PSTMNT_WORD_BITS).
   Note: The function is based on Newton iteration method.
   The inverse only exists if x is odd.
   The function shall not be passed even values as input.
   The function has 4 rounds, test if flu.c ensures 4 rounds
   is enough for all 32-bit values. */
pstmnt_word pstmnt_neg_small_inv(const pstmnt_word *a_p)
{
    pstmnt_word a = *a_p;
    pstmnt_word t, k;
    int countdown = 4;           /* Because of quadratic convergence, the
                                    operation is always finished with up-to 4
                                    steps [assuming pstmnt_word is 32-bit unsigned int].
                                  */

    PSTMNT_ASSERT((a & 1) == 1); /* Ensure value passed in is odd. */

    /* This function uses the Newton's iteration to find
       modular multiplicative inverse of given value in field mod 2^32.
       Such value is needed e.g. in Montgomery Reduction.

       Note on sequence used:
     * Sequence (x_n+1 = x_n*(2 - a*x_n) (mod 2^k))
       converges quadratically, iff a == a^-1 (mod 2).

       It can be shown for this sequence that error converges.

       Using a test in flu.c, it is ensured that the function operates
       correctly for all odd values to converge between 1 and 2^32 - 1.
       ATTN: Ensure the filename is updated if test is moved.

       The reason to use static value 4 is that it makes the function
       performance deterministic: function will execute the same operations
       no matter what odd integer was passed in.
     */
    t = a;
    while (countdown > 0)
    {
        k = 2 - (t * a);
        t *= k;
        countdown--;
    }

    PSTMNT_ASSERT(a * t == 1);    /* Ensure t has been calculated correctly */
    return PSTMNT_WORD_NEGATE(t); /* Return calculated t. */
}

static inline
uint32_t add_carry_nt(uint32_t a, uint32_t b, psBool_t *carry)
{
    /* OPTN: If available, prefer PSTMNT_LONG_ADD32_32, PSTMNT_LONG_ADD32_1 etc. */
    /* over this function. */
    uint32_t res;
    int c = *carry;

    if (c)
    {
        res = a + b + 1;
        *carry = res <= a;
    }
    else
    {
        res = a + b;
        *carry = res < a;
    }
    return res;
}

/*
   Addition of two big numbers. The numbers added shall be the same length.
   If numbers are different length, the smaller number shall be extended
   (pstmnt_extend) prior addition or the result of the addition shall be used as
   carry, for pstmnt_add_1.

   Operation: carry || r<szl> == a<szl> + b<szl>
   The carry is returned from function,
   The result is stored in r<szl> and operands for addition are read from
   a<szl> and b<szl>.

   Note: b<szl> shall not alias r<szl>.
 */
int pstmnt_add(const uint32_t *a, const uint32_t *b, uint32_t *r, int szl)
{
    /* Simple but slow addition function. */
    psBool_t carry = PS_FALSE;

    /* a may be same as r, but b may only be same as r if all
       a, b and r are the same. */
    PSTMNT_PRECONDITION((b != r) || (a == b));
    PSTMNT_PRECONDITION(szl >= 1);
    PSTMNT_PRECONDITION(szl <= 4096 / PSTMNT_WORD_BITS);

# ifdef PSTMNT_LONG_MULADD2_FAST
    /* Use MULADD2 to add two values and carry. */
    {
        uint32_t hi;
        int i;

        if (a != r)
        {
            pstmnt_copy(a, r, szl);
        }

        /* OPTN: Optimize this function even further. */
        /* Duff's device (unrolling, calculate 4 words per loop iteration. */
        {
            register int n = (szl + 3) / 4;
            int szl_mod4 = szl % 4;
            hi = 0;
            i = 0;
            switch (PSTMNT_EXPECT(szl_mod4, 0))
            {
            case 0:
                do
                {
                    PSTMNT_LONG_MULADD2(hi, r[i], b[i], 1); i++;
                case 3: PSTMNT_LONG_MULADD2(hi, r[i], b[i], 1); i++;
                case 2: PSTMNT_LONG_MULADD2(hi, r[i], b[i], 1); i++;
                case 1: PSTMNT_LONG_MULADD2(hi, r[i], b[i], 1); i++;
                }
                while (--n > 0);
            }
        }
        carry = hi;
    }
# elif defined(PSTMNT_LONG_ADD32_1)
    /* PSTMNT_LONG_ADD32_1 available. Use it. */
    {
        int i;
        uint32_t hi1;
        uint32_t hi2;

        if (a != r)
        {
            pstmnt_copy(a, r, szl);
        }

        /* OPTN: Optimize this function even further. */
        /* Duff's device (unrolling, calculate 4 words per loop iteration. */
        {
            register int n = (szl + 3) / 4;
            hi1 = hi2 = 0;
            i = 0;
            switch (szl % 4)
            {
            case 0:
                do
                {
                    hi1 = 0; PSTMNT_LONG_ADD32_1(hi1, r[i], b[i], hi2); i++;
                case 3: hi2 = 0; PSTMNT_LONG_ADD32_1(hi2, r[i], b[i], hi1); i++;
                case 2: hi1 = 0; PSTMNT_LONG_ADD32_1(hi1, r[i], b[i], hi2); i++;
                case 1: hi2 = 0; PSTMNT_LONG_ADD32_1(hi2, r[i], b[i], hi1); i++;
                }
                while (--n > 0);
            }
        }
        carry = hi2;
    }
# else
    while (szl > 0)
    {
        *r = add_carry_nt(*a, *b, &carry);
        a++;
        b++;
        r++;
        szl--;
    }
# endif
    return carry;
}

# ifdef PSTMNT_USE_INT128_MONTGOMERY
pstmnt_dword pstmnt_montgomery_reduce_d(PSTMNT_UINT64 * restrict temp_r,
    pstmnt_word r[] /* n * 2 */,
    const PSTMNT_UINT64 p[] /* n */,
    pstmnt_word mp_,
    pstmnt_words n)
{
    unsigned int i;
    int j;
    pstmnt_dword high_carry;
    pstmnt_dword u, a1, c;
    pstmnt_dword mp;

    /* Construct 64-bit equivalent of 32-bit mp (on extra calculation step). */
    mp = PSTMNT_WORD_NEGATE(mp_);
    mp = mp * (2 - (mp * p[0]));
    mp = ((~((pstmnt_dword) (mp))) + 1);

    if (temp_r + n != (PSTMNT_UINT64 *) r)
    {
        PSTMNT_ZEROIZE(r, n * 8); /* Clear r. */
    }

    for (high_carry = 0, i = 0; i < n; i++)
    {
        pstmnt_dword d;
        pstmnt_dword *array = &temp_r[i];
        d = *array;
        /* Calculate u and process the first 32 bits. */
        u = d * mp;

        /* Perform {c:d} = d + u * p[0] */
        c = 0;
        PSTMNT_VERYLONG_MULADD2(c, d, u, p[0]);
        /* Note: the calculated value for d (which is always 0)
           could be stored to temp_r[i] = d like this.
           However, this is skipped as the cleared portion of temp_r
           is not used after pstmnt_montgomery_reduce. */
        for (j = 1; j < (int) n; j++)
        {
            a1 = array[j];
            PSTMNT_VERYLONG_MULADD2(c, a1, u, p[j]);
            array[j] = a1;
        }

        PSTMNT_VERYLONG_MULADD2(high_carry, c, array[j], 1);
        array[j] = c;
    }

    /* Copy high portion, if required. */
    if (temp_r + n != (PSTMNT_UINT64 *) r)
    {
        /* OPTN: It is may be possible to get rid of this copy operation
           by reorganizing how this function works or is used. */
        PSTMNT_COPY(r, temp_r + n, n * 8);
    }

    return high_carry;
}
# endif /* PSTMNT_USE_INT128_MONTGOMERY */

# ifndef PSTMNT_LONG_MULADD_CARRY
static inline
void
add64_to_96_nt(
    const uint64_t a,
    uint32_t r[3]) PSTMNT_HOT_FUNCTION;

/* If Multiply-add with high carry handling is not available,
   define this helper function. */
static inline
void
add64_to_96_nt(
    const uint64_t a,
    uint32_t r[3])
{
    /* Use PSTMNT_LONG_ADD32 and PSTMNT_LONG_ADD32_1 if available. */
#  if defined(PSTMNT_LONG_ADD32_1) && defined(PSTMNT_LONG_ADD32)
    uint32_t carry;
    PSTMNT_ASSERT(r[2] != 0xffffffff);                      /* detect possible carry loss */
    PSTMNT_ASSERT(a <= (((uint64_t) (0xFFFFFFFFU)) << 32)); /* Check range of
                                                               input values. */

    carry = 0;
    PSTMNT_LONG_ADD32(carry, r[0], (uint32_t) (a & 0xFFFFFFFFU));
    PSTMNT_LONG_ADD32_1(r[2], r[1], (uint32_t) (a >> 32), carry);
#  else
    uint32_t p[2];

    PSTMNT_ASSERT(r[2] != 0xffffffff);                      /* detect possible carry loss */
    PSTMNT_ASSERT(a <= (((uint64_t) (0xFFFFFFFFU)) << 32)); /* Check range of
                                                               input values. */

    p[0] = (uint32_t) a;
    p[1] = (uint32_t) (a >> 32);
    r[2] += pstmnt_add(r, p, r, 2);
#  endif
}
# endif /* PSTMNT_LONG_MULADD_CARRY */

/*
   Optionally add given big number.
   The number is masked with given mask. The mask will be repeated as
   neccessary.
   If add, and, and shift execution times are data-independent, this
   function will provide data independent execution time.

   Operation: carry || r<szl> == r<szl> + (b<szl> & bmask)
   The carry is returned from function,
   The result is stored in r<szl> and operands for addition are read from
   r<szl> and b<szl>.

   Note: b<szl> shall not alias r<szl>.
 */
int pstmnt_add_mask(const uint32_t * restrict b, uint32_t * restrict r, int szl,
    uint32_t bmask)
{
    uint32_t carry = 0;
    int i;

    for (i = 0; i < szl; i++)
    {
        uint64_t sum;
        uint32_t bv = b[i];
        uint32_t rv = r[i];
        sum = rv;
        bv &= bmask;
        sum += bv;
        sum += carry;
        r[i] = sum & (-1U);
        carry = (uint32_t) (sum >> 32);
    }
    return carry;
}

/*
   Optionally subtract given big number.
   The number is masked with given mask. The mask will be repeated as
   neccessary.
   If negate, sub, and, and shift execution times are data-independent, this
   function will provide data independent execution time.

   Operation: carry || r<szl> == r<szl> - (b<szl> & bmask)
   The carry is returned from function,
   The result is stored in r<szl> and operands for addition are read from
   r<szl> and b<szl>.

   Note: b<szl> shall not alias r<szl>.
 */
int pstmnt_sub_mask(const uint32_t * restrict b, uint32_t * restrict r, int szl,
    uint32_t bmask)
{
    uint32_t borrow = 0;
    int i;

    for (i = 0; i < szl; i++)
    {
        uint64_t res;
        uint32_t bv = b[i];
        uint32_t rv = r[i];
        res = rv;
        bv &= bmask;
        res -= bv;
        res -= borrow;
        r[i] = res & (-1U);
        borrow = -(uint32_t) (res >> 32);
    }
    return borrow;
}

/*
   Fix value that is not much higher than p.

   Operation: out<n> == (carry || in<n>) % p<n>

   Note: This operation is used to deal with the last modulo operation, after
   operation that produces result not significantly larger than p<n>, such
   as addition of two numbers smaller than p<n> (mod p<n>).
   The benefit of this operation is that the operation consists of just
   subtract and addition, thus the adjustment is often faster than equivalent
   pstmnt_reduce().
 */
void pstmnt_cmp_sub_mod_carry(pstmnt_word r[], const pstmnt_word p[],
    pstmnt_words n, pstmnt_word carry)
{
    /* Resolve carries by substracting p, as long as required.
       (To be efficient carry needs to be small, usually 0-1.) */

    /* If the carry || r<n> < 3*p<n>, the processing time is data-independent
       assuming pstmnt_sub_nt, pstmnt_add, pstmnt_sub_mask and pstmnt_add_mask
       are. */

    carry -= pstmnt_sub_mask(p, r, n, -(pstmnt_word) 1);
    carry -= pstmnt_sub_mask(p, r, n, -(pstmnt_word) (((int32_t) carry) >= 0));
    carry -= pstmnt_sub_mask(p, r, n, -(pstmnt_word) (((int32_t) carry) >= 0));

    while (((int32_t) carry) >= 0)
    {
        carry -= pstmnt_sub_mask(p, r, n, -(pstmnt_word) 1);
    }

    carry += pstmnt_add_mask(p, r, n, -(pstmnt_word) 1);
}

/*
   Optionally move given big number.
   The number is masked with given mask. The mask will be repeated as
   neccessary.
   If move, and, and shift execution times are data-independent, this
   function will provide data independent execution time.

   Operation: carry || r<szl> == (r<szl> & ~bmask) | (b<szl> & bmask)
 */
void pstmnt_select_mask(const uint32_t * restrict b, uint32_t * restrict r,
    int szl, uint32_t bmask)
{
    int i;
    uint32_t rmask = ~bmask;

    for (i = 0; i < szl; i++)
    {
        uint32_t bv = b[i];
        uint32_t rv = r[i];
        r[i] = (rv & rmask) | (bv & bmask);
    }
}

static inline
uint32_t sub_borrow_nt(uint32_t a, uint32_t b, psBool_t *borrow)
{
    uint32_t res;

    if (*borrow)
    {
        res = a - b - 1;
        *borrow = res >= a;
    }
    else
    {
        res = a - b;
        *borrow = res > a;
    }
    return res;
}

/*
   Subtraction of two big numbers. The number subtracted shall be the same
   length than the number to subtract from.

   Operation: carry || r<szl> == (1 || a<szl>) - b<szl>

   The function returns !carry, and sets r<szl> according to operation above.
   Note: b<szl> shall not alias r<szl>.
 */
int
pstmnt_sub(
    const uint32_t *a,
    const uint32_t *b,
    uint32_t *r,
    int szl)
{
    psBool_t borrow = PS_FALSE;

    /* OPTN: Replace pstmnt_sub implementation with more efficient */
    PSTMNT_PRECONDITION(b != r);
    PSTMNT_PRECONDITION(szl >= 1);
    PSTMNT_PRECONDITION(szl <= 4096 / 32);

    while (szl > 0)
    {
        *r = sub_borrow_nt(*a, *b, &borrow);
        a++;
        b++;
        r++;
        szl--;
    }

    return borrow;
}

# ifdef PSTMNT_USE_INT128_SQUARE
void
pstmnt_square_d(
    const pstmnt_dword a[],
    pstmnt_uint64_aligned4_t * restrict r,
    int sz)
{
    signed int i, j, k;
    pstmnt_dword hi;
    pstmnt_dword lo;
    pstmnt_dword hihi;
    pstmnt_dword hi2;
    pstmnt_dword lo2;

    lo = hi = hihi = 0;

    if (sz == 1)
    {
        PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi, lo, a[0], a[0]);
        r[0].value = lo;
        r[1].value = hi;
        return;
    }

    PSTMNT_PRECONDITION(sz >= 2);
    PSTMNT_PRECONDITION(((pstmnt_uint64_aligned4_t *) a) != r);

    /* Process lower half (j will go from i to 0) */
    for (i = 0; i < sz; i++)
    {
        j = (((i + 1) ^ 1) - 2) / 2;
        hi2 = lo2 = 0;
        /* Note: hihi is already 0. */

        /* Loop for processing things counted twice. */
        for (k = i - j; j >= 0; j--, k++)
        {
            PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi2, lo2, a[j], a[k]);
        }
        /* Double {hihi, hi2, lo2}. */
        PSTMNT_VERYLONG_LEFT_SHIFT192_1(hihi, hi2, lo2);
        /* Add existing {hi, lo} to {hi2, lo2}, get result to {hi, lo} */
        PSTMNT_VERYLONG_ADD128_CARRY(hihi, hi, lo, hi2, lo2);

        /* Even? Add single. */
        if ((i & 1) == 0)
        {
            PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi, lo, a[i / 2], a[i / 2]);
        }
        r[i].value = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }
    /* Process upper half (k goes from i-j to sz) */
    for (; i < sz * 2 - 2; i++)
    {
        j = (i - 1) / 2;
        hi2 = lo2 = 0;

        for (k = i - j; k < sz; j--, k++)
        {
            PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi2, lo2, a[j], a[k]);
        }

        /* Double (Add twice). */
        PSTMNT_VERYLONG_LEFT_SHIFT192_1(hihi, hi2, lo2);
        /* Add existing {hi, lo} to {hi2, lo2}, get result to {hi, lo} */
        PSTMNT_VERYLONG_ADD128_CARRY(hihi, hi, lo, hi2, lo2);

        /* Even? Add single. */
        if ((i & 1) == 0)
        {
            PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi, lo, a[i / 2], a[i / 2]);
        }
        r[i].value = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }

    /* The most significant word (will always give carry == 0) */
    PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi, lo, a[sz - 1], a[sz - 1]);
    r[i].value = lo;
    r[i + 1].value = hi;
}

void
pstmnt_square(
    const uint32_t a[],
    uint32_t * restrict r,
    int sz)
{
    if (pstmnt_square_comba(a, r, sz))
    {
        return;
    }

    if ((sz & 1) == 0 && sz < 4096 / 32)
    {
        pstmnt_dword a_storage[4096 / 64];
        if ((((unsigned long) a) & 0x7) != 0)
        {
            /* Unaligned a. */
            PSTMNT_COPY(a_storage, a, sz * 4);
            a = (pstmnt_word *) a_storage;
        }
        pstmnt_square_d((const pstmnt_dword *) a,
            (pstmnt_uint64_aligned4_t *) r, sz / 2);
        if (a == (pstmnt_word *) a_storage)
        {
            PSTMNT_ZEROIZE(a_storage, sz * 4);
        }
        return;
    }
    /* Fallback if size is not even (rare). */
    pstmnt_mult(a, a, r, sz);
}
# elif defined PSTMNT_LONG_MULADD_CARRY
void
pstmnt_square(
    const uint32_t a[],
    uint32_t * restrict r,
    int sz)
{
    signed int i, j, k;
    pstmnt_word hi;
    pstmnt_word lo;
    pstmnt_word hihi;
    pstmnt_word hi2;
    pstmnt_word lo2;

    PSTMNT_PRECONDITION(sz >= 2);
    PSTMNT_PRECONDITION(a != r);

    if (pstmnt_square_comba(a, r, sz))
    {
        return;
    }

    lo = hi = hihi = 0;

    /* Process lower half (j will go from i to 0) */
    for (i = 0; i < sz; i++)
    {
        j = (((i + 1) ^ 1) - 2) / 2;
        hi2 = lo2 = 0;
        /* Note: hihi is already 0. */

        /* Loop for processing things counted twice. */
        for (k = i - j; j >= 0; j--, k++)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi2, lo2, a[j], a[k]);
        }
        /* Double {hihi, hi2, lo2}. */
        PSTMNT_LONG_LEFT_SHIFT96_1(hihi, hi2, lo2);
        /* Add existing {hi, lo} to {hi2, lo2}, get result to {hi, lo} */
        PSTMNT_LONG_ADD64_CARRY(hihi, hi, lo, hi2, lo2);

        /* Even? Add single. */
        if ((i & 1) == 0)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi, lo, a[i / 2], a[i / 2]);
        }
        r[i] = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }
    /* Process upper half (k goes from i-j to sz) */
    for (; i < sz * 2 - 2; i++)
    {
        j = (i - 1) / 2;
        hi2 = lo2 = 0;

        for (k = i - j; k < sz; j--, k++)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi2, lo2, a[j], a[k]);
        }

        /* Double (Add twice). */
        PSTMNT_LONG_LEFT_SHIFT96_1(hihi, hi2, lo2);
        /* Add existing {hi, lo} to {hi2, lo2}, get result to {hi, lo} */
        PSTMNT_LONG_ADD64_CARRY(hihi, hi, lo, hi2, lo2);

        /* Even? Add single. */
        if ((i & 1) == 0)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi, lo, a[i / 2], a[i / 2]);
        }
        r[i] = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }

    /* Special handling of the most-significant word,
       carry handling is no longer needed. */
    PSTMNT_LONG_MULADD(hi, lo, a[sz - 1], a[sz - 1]);
    r[i] = lo;
    r[i + 1] = hi;
}

#  ifdef PSTMNT_UNROLL2
void
pstmnt_square_unroll2(
    const uint32_t a[],
    uint32_t * restrict r,
    int sz)
{
    signed int i, j, k;
    pstmnt_word hi;
    pstmnt_word lo;
    pstmnt_word hi2;
    pstmnt_word lo2;

    /* The size must be even. */
    PSTMNT_PRECONDITION(sz >= 2 && (sz & 1) == 0);
    PSTMNT_PRECONDITION(a != r);

    /* Initialize {hi,lo} to 0. */
    lo = hi = 0;

    /* Process lower half (j will go from i to 0) */
    for (i = 0; i < sz; i += 2)
    {
        pstmnt_word hihi = 0;
        pstmnt_word hihihi = 0;
        j = (((i + 1) ^ 1) - 2) / 2;
        hi2 = lo2 = 0;
        /* Note: hihi is already 0. */

        /* Loop for processing things counted twice. */
        for (k = i - j; j >= 0; j--, k++)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi2, lo2, a[j], a[k]);
        }
        /* {hihi:hi:lo} = {hi:lo} + {hihi:hi2:lo2} * 2 */
        PSTMNT_LONG_LEFT_SHIFT96_1(hihi, hi2, lo2);
        PSTMNT_LONG_ADD64_CARRY(hihi, hi, lo, hi2, lo2);

        /* Add single. */
        PSTMNT_LONG_MULADD_CARRY(hihi, hi, lo, a[i / 2], a[i / 2]);
        r[i] = lo;

        j = (((i + 1 + 1) ^ 1) - 2) / 2;
        hi2 = lo2 = 0;
        /* Loop for processing things counted twice. */
        for (k = i + 1 - j; j >= 0; j--, k++)
        {
            PSTMNT_LONG_MULADD_CARRY(hihihi, hi2, lo2, a[j], a[k]);
        }
        /* Double {hihi, hi2, lo2}. */
        PSTMNT_LONG_LEFT_SHIFT96_1(hihihi, hi2, lo2);
        /* Add existing {hihi, hi} to {hi2, lo2}, get result to {hihi, hi} */
        PSTMNT_LONG_ADD64_CARRY(hihihi, hihi, hi, hi2, lo2);

        r[i + 1] = hi;
        lo = hihi;
        hi = hihihi;
    }
    /* Process upper half (k goes from i-j to sz) */
    for (; i < sz * 2 - 2; i += 2)
    {
        pstmnt_word hihi = 0;
        pstmnt_word hihihi = 0;

        j = (i - 1) / 2;
        hi2 = lo2 = 0;

        for (k = i - j; k < sz; j--, k++)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi2, lo2, a[j], a[k]);
        }

        /* Double (Add twice). */
        PSTMNT_LONG_LEFT_SHIFT96_1(hihi, hi2, lo2);
        /* Add existing {hi, lo} to {hi2, lo2}, get result to {hi2, lo2} */
        PSTMNT_LONG_ADD64_CARRY(hihi, hi, lo, hi2, lo2);

        /* Even? Add single. */
        PSTMNT_LONG_MULADD_CARRY(hihi, hi, lo, a[i / 2], a[i / 2]);

        r[i] = lo;

        j = (i + 1 - 1) / 2;
        hi2 = lo2 = 0;
        /* Loop for processing things counted twice. */
        for (k = i + 1 - j; k < sz; j--, k++)
        {
            PSTMNT_LONG_MULADD_CARRY(hihihi, hi2, lo2, a[j], a[k]);
        }
        /* Double {hihi, hi2, lo2}. */
        PSTMNT_LONG_LEFT_SHIFT96_1(hihihi, hi2, lo2);
        /* Add existing {hihi, hi} to {hi2, lo2}, get result to {hihi, hi} */
        PSTMNT_LONG_ADD64_CARRY(hihihi, hihi, hi, hi2, lo2);

        r[i + 1] = hi;
        lo = hihi;
        hi = hihihi;
    }

    /* Special handling of the most-significant words,
       carry handling is no longer needed. */
    PSTMNT_LONG_MULADD(hi, lo, a[sz - 1], a[sz - 1]);
    r[i] = lo;
    r[i + 1] = hi;
}
#  endif /* PSTMNT_UNROLL2 */
# endif  /* PSTMNT_LONG_MULADD_CARRY */

# ifdef PSTMNT_USE_INT128_MULT
/*
   Multiplication of two big numbers (of same size).
   This function uses double sized operations (64x64 => 128).

   Operation: r<sz*2> == a<sz> * b<sz>

   Note: a<sz> or b<sz> shall not alias r<sz>.

   This version of multiplication uses
   PSTMNT_VERYLONG_MULADD_CARRY macro (defined in flm_base.h).
   If such macro is not available, alternative path
   below will be used instead.
 */
void
pstmnt_mult_d(
    const pstmnt_dword a[],
    const pstmnt_dword b[],
    pstmnt_uint64_aligned4_t * restrict r,
    int sz)
{
    signed int i, j;
    pstmnt_dword hi;
    pstmnt_dword lo;
    pstmnt_dword hihi;

    PSTMNT_PRECONDITION(sz >= 2);

    lo = hi = hihi = 0;

    /* Process lower half (j will go from i to 0) */
    for (i = 0; i < sz; i++)
    {
        for (j = i; j >= 0; j--)
        {
            PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi, lo, a[j], b[i - j]);
        }
        r[i].value = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }

    /* Process upper half */
    /* Manipulate data pointers to get j count to 0. */
    a += sz; /* a: usable range: -sz .. -1 */
    b -= sz; /* b: usable range: sz .. 2 * sz -1 */
    for (; i < sz * 2 - 1; i++)
    {
        for (j = i - (sz - 1) - sz; j < 0; j++)
        {
            PSTMNT_VERYLONG_MULADD_CARRY(hihi, hi, lo, a[j], b[i - j]);
        }
        r[i].value = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }
    r[i].value = lo;

    /* Produce output. */
    sz *= 2;
}
# endif /* PSTMNT_USE_INT128_MULT */

# ifdef PSTMNT_LONG_MULADD_CARRY
#  ifdef PSTMNT_UNROLL2
void
pstmnt_mult_unroll2(
    const uint32_t a[],
    const uint32_t b[],
    uint32_t * restrict r,
    int sz);
#  endif /* PSTMNT_UNROLL2 */

/*
   Multiplication of two big numbers (of same size).

   Operation: r<sz*2> == a<sz> * b<sz>

   Note: a<sz> or b<sz> shall not alias r<sz>.

   This version of multiplication uses
   PSTMNT_LONG_MULADD_CARRY macro (defined in flm_base.h).
   If such macro is not available, alternative path
   below will be used instead.
 */
void
pstmnt_mult(
    const uint32_t a[],
    const uint32_t b[],
    uint32_t * restrict r,
    int sz)
{
    signed int i, j;
    pstmnt_word hi;
    pstmnt_word lo;
    pstmnt_word hihi;

    PSTMNT_PRECONDITION(sz >= 2);
    PSTMNT_PRECONDITION(a != r);
    PSTMNT_PRECONDITION(b != r);

    if (pstmnt_mult_comba(a, b, r, sz))
    {
        return;
    }

#  ifdef PSTMNT_USE_INT128_MULT
    if ((sz & 1) == 0 && sz >= 4 && sz < 4096 / 32)
    {
        pstmnt_dword a_storage[4096 / 64];
        pstmnt_dword b_storage[4096 / 64];
        if ((((unsigned long) a) & 0x7) != 0)
        {
            /* Unaligned a. */
            PSTMNT_COPY(a_storage, a, sz * 4);
            a = (pstmnt_word *) a_storage;
        }
        if ((((unsigned long) b) & 0x7) != 0)
        {
            /* Unaligned b. */
            PSTMNT_COPY(b_storage, b, sz * 4);
            b = (pstmnt_word *) b_storage;
        }
        pstmnt_mult_d((const pstmnt_dword *) a, (const pstmnt_dword *) b,
            (pstmnt_uint64_aligned4_t *) r, sz / 2);
        if (a == (pstmnt_word *) a_storage)
        {
            PSTMNT_ZEROIZE(a_storage, sz * 4);
        }
        if (b == (pstmnt_word *) b_storage)
        {
            PSTMNT_ZEROIZE(b_storage, sz * 4);
        }
        return;
    }
#  endif /* PSTMNT_USE_INT128_MULT */

    lo = hi = hihi = 0;

    /* Process lower half (j will go from i to 0) */
    for (i = 0; i < sz; i++)
    {
        for (j = i; j >= 0; j--)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi, lo, a[j], b[i - j]);
        }
        r[i] = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }

    /* Process upper half */
    /* Manipulate data pointers to get j count to 0. */
    a += sz; /* a: usable range: -sz .. -1 */
    b -= sz; /* b: usable range: sz .. 2 * sz -1 */
    for (; i < sz * 2 - 1; i++)
    {
        for (j = i - (sz - 1) - sz; j < 0; j++)
        {
            PSTMNT_LONG_MULADD_CARRY(hihi, hi, lo, a[j], b[i - j]);
        }
        r[i] = lo;
        lo = hi;
        hi = hihi;
        hihi = 0;
    }
    r[i] = lo;
}

#  ifdef PSTMNT_UNROLL2
void
pstmnt_mult_unroll2(
    const uint32_t a[],
    const uint32_t b[],
    uint32_t * restrict r,
    int sz)
{
    signed int i, j;
    pstmnt_word hi;
    pstmnt_word lo;
    pstmnt_word hihi;
    pstmnt_word hihi2;
    pstmnt_word hihihi;

    PSTMNT_PRECONDITION(sz >= 2);
    PSTMNT_PRECONDITION(a != r);
    PSTMNT_PRECONDITION(b != r);

#   ifdef PSTMNT_USE_INT128_MULT
    if ((sz & 1) == 0 && sz >= 4 && sz < 4096 / 32)
    {
        pstmnt_dword a_storage[4096 / 64];
        pstmnt_dword b_storage[4096 / 64];
        if ((((unsigned long) a) & 0x7) != 0)
        {
            /* Unaligned a. */
            PSTMNT_COPY(a_storage, a, sz * 4);
            a = (pstmnt_word *) a_storage;
        }
        if ((((unsigned long) b) & 0x7) != 0)
        {
            /* Unaligned b. */
            PSTMNT_COPY(b_storage, b, sz * 4);
            b = (pstmnt_word *) b_storage;
        }
        pstmnt_mult_d((const pstmnt_dword *) a, (const pstmnt_dword *) b,
            (pstmnt_uint64_aligned4_t *) r, sz / 2);
        if (a == (pstmnt_word *) a_storage)
        {
            PSTMNT_ZEROIZE(a_storage, sz * 4);
        }
        if (b == (pstmnt_word *) b_storage)
        {
            PSTMNT_ZEROIZE(b_storage, sz * 4);
        }
        return;
    }
#   endif /* PSTMNT_USE_INT128_MULT */

    lo = hi = hihi = hihi2 = hihihi = 0;

    /* Process lower half (j will go from i to 0) */
    for (i = 0; i < sz; i += 2)
    {
        pstmnt_word bw;
        j = i + 1;
        bw = b[0];
        PSTMNT_LONG_MULADD_CARRY(hihihi, hihi, hi, a[j], bw);
        for (j = i; j >= 0; j--)
        {
            /* Note: bw =  b[i-j] */
            PSTMNT_LONG_MULADD_CARRY(hihi2, hi, lo, a[j], bw);
            bw = b[i + 1 - j];
            PSTMNT_LONG_MULADD_CARRY(hihihi, hihi, hi, a[j], bw);
        }
        PSTMNT_LONG_ADD32(hihihi, hihi, hihi2);
        r[i] = lo;
        r[i + 1] = hi;
        lo = hihi;
        hi = hihihi;
        hihihi = hihi2 = hihi = 0;
    }

    /* Process upper half */
    /* Manipulate data pointers to get j count to 0. */
    a += sz; /* a: usable range: -sz .. -1 */
    b -= sz; /* b: usable range: sz .. 2 * sz -1 */
    for (; i < sz * 2 - 2; i += 2)
    {
        pstmnt_word bw;
        j = i - (sz - 1) - sz;
        bw = b[i - j];
        PSTMNT_LONG_MULADD_CARRY(hihi, hi, lo, a[j], bw);
        j++;
        for (; j < 0; j++)
        {
            /* note: bw = b[i+1-j] */
            PSTMNT_LONG_MULADD_CARRY(hihihi, hihi, hi, a[j], bw);
            bw = b[i - j];
            PSTMNT_LONG_MULADD_CARRY(hihi2, hi, lo, a[j], bw);
        }
        PSTMNT_LONG_ADD32(hihihi, hihi, hihi2);
        r[i] = lo;
        r[i + 1] = hi;
        lo = hihi;
        hi = hihihi;
        hihihi = hihi2 = hihi = 0;
    }
    PSTMNT_LONG_MULADD(hi, lo, a[-1], b[2 * sz - 1]);
    r[i] = (uint32_t) lo;
    r[i + 1] = (uint32_t) hi;
}
#  endif /* PSTMNT_UNROLL2 */
# else /* !PSTMNT_LONG_MULADD_CARRY */
/*
   Multiplication of two big numbers (of same size).

   Operation: r<sz*2> == a<sz> * b<sz>

   Note: a<sz> or b<sz> shall not alias r<sz>.
 */
void
pstmnt_mult(
    const uint32_t a[],
    const uint32_t b[],
    uint32_t * restrict r,
    int sz)
{
    int i, j, k;
    uint64_t res;
    uint32_t p[2];
    uint32_t *target;
    pstmnt_word hi;
    pstmnt_word lo;

    /* OPTN: This function could be significantly further optimized */

    PSTMNT_PRECONDITION(sz >= 2);
    PSTMNT_PRECONDITION(a != r);
    PSTMNT_PRECONDITION(b != r);

    if (pstmnt_mult_comba(a, b, r, sz))
    {
        return;
    }

#  ifdef PSTMNT_USE_INT128_MULT
    if ((sz & 1) == 0 && sz >= 4 && sz < 4096 / 32)
    {
        pstmnt_dword a_storage[4096 / 64];
        pstmnt_dword b_storage[4096 / 64];
        if ((((unsigned long) a) & 0x7) != 0)
        {
            /* Unaligned a. */
            PSTMNT_COPY(a_storage, a, sz * 4);
            a = (pstmnt_word *) a_storage;
        }
        if ((((unsigned long) b) & 0x7) != 0)
        {
            /* Unaligned b. */
            PSTMNT_COPY(b_storage, b, sz * 4);
            b = (pstmnt_word *) b_storage;
        }
        pstmnt_mult_d((const pstmnt_dword *) a, (const pstmnt_dword *) b,
            (pstmnt_uint64_aligned4_t *) r, sz / 2);
        if (a == (pstmnt_word *) a_storage)
        {
            PSTMNT_ZEROIZE(a_storage, sz * 4);
        }
        if (b == (pstmnt_word *) b_storage)
        {
            PSTMNT_ZEROIZE(b_storage, sz * 4);
        }
        return;
    }
#  endif /* PSTMNT_USE_INT128_MULT */

    for (i = 0; i < sz; i++)
    {
        r[i * 2] = 0;
        r[i * 2 + 1] = 0;
    }

    for (i = 0; i < sz * 2 - 2; i++)
    {
        j = i;
        if (j >= sz)
        {
            j = sz - 1;
        }
        target = &r[i];
        for (k = i - j; j >= 0 && k < sz; j--, k++)
        {
            PSTMNT_LONG_MUL(hi, lo, a[j], b[k]);
            res = hi;
            res <<= 32;
            res |= lo;
            add64_to_96_nt(res, target);
        }
    }

    /* Special handling of most-significant words, to prevent
       'add64_to_96_nt' from writing beyond space allotted to 'r'. */
    PSTMNT_LONG_MUL(hi, lo, a[sz - 1], b[sz - 1]);
    p[0] = (uint32_t) lo;
    p[1] = (uint32_t) hi;
    i = pstmnt_add(&(r[sz * 2 - 2]), p, &(r[sz * 2 - 2]), 2);
    PSTMNT_ASSERT(i == 0);
}
# endif /* PSTMNT_LONG_MULADD_CARRY */

# if defined(PSTMNT_LONG_MULADD2)
#  ifdef PSTMNT_UNROLL2
/* Accelerated path using multiply-add instruction. */
void pstmnt_montgomery_reduce_unroll2(pstmnt_word temp_r[] /* n * 2 */,
    pstmnt_word r[] /* n */,
    const pstmnt_word p[] /* n */,
    pstmnt_word mp,
    pstmnt_words n)
{
    unsigned int i;
    unsigned int j;
    pstmnt_word high_carry;
    pstmnt_word u, a1, c;
    pstmnt_word d2, c2, u2;
    pstmnt_word p2, p1;

    if (temp_r + n != r)
    {
        pstmnt_clear(r, n); /* Clear r. */
    }

    for (high_carry = 0, i = 0; i < n; i += 2)
    {
        pstmnt_word d = temp_r[i];
        /* Calculate u and process the first 32 bits. */
        u = d * mp;

        c = 0;
        p1 = p[0]; /* First value of p[x] processing. */
        PSTMNT_LONG_MULADD(c, d, u, p1);
        /* Note: the calculated value for d (which is always 0)
           could be stored to temp_r[i] = d like this.
           However, this is skipped as the cleared portion of temp_r
           is not used after pstmnt_montgomery_reduce. */

        /* Process second value. */
        d2 = temp_r[1 + i];
        p2 = p[1]; /* p2: Stored p value for *2 processing. */
        PSTMNT_LONG_MULADD2(c, d2, u, p2);

        /* Process first value of second processing round. */
        c2 = 0;
        u2 = d2 * mp;
        PSTMNT_LONG_MULADD(c2, d2, u2, p1);
        /* Note: the calculated value for d (which is always 0)
           could be stored to temp_r[1 + i] = d like this.
           However, this is skipped as the cleared portion of temp_r
           is not used after pstmnt_montgomery_reduce. */

        /* Process one words at a time, but process it twice,
           with c and c2. This allows to reduce memory accesses needed. */
        for (j = 2; j < n; j++)
        {
            p1 = p[j]; /* p2 is always 1 words late. */

            a1 = temp_r[j + i];
            PSTMNT_LONG_MULADD2(c, a1, u, p1);
            PSTMNT_LONG_MULADD2(c2, a1, u2, p2);
            temp_r[j + i] = a1;
            p2 = p1;
        }

        /* Process second last word of the round.
           with u: handle high carry,
           with u2: Process just like the other words.
         */
        PSTMNT_LONG_MULADD2(high_carry, c, temp_r[j + i], 1);

        PSTMNT_LONG_MULADD2(c2, c, u2, p2);
        temp_r[j + i] = c;

        /* Process last word. */
        PSTMNT_LONG_MULADD2(high_carry, c2, temp_r[j + i + 1], 1);
        temp_r[j + i + 1] = c2;
    }

    /* Copy high portion, if required. */
    if (temp_r + n != r)
    {
        /* OPTN: It is may be possible to get rid of this copy operation
           by reorganizing how this function works or is used. */
        pstmnt_copy(temp_r + n, r, n);
    }

    pstmnt_cmp_sub_mod_carry(r, p, n, high_carry);
}
#  endif /* PSTMNT_UNROLL2 */

/* Accelerated path using multiply-add instruction. */
void pstmnt_montgomery_reduce(pstmnt_word * restrict temp_r,
    pstmnt_word r[] /* n */,
    const pstmnt_word p[] /* n */,
    pstmnt_word mp,
    pstmnt_words n)
{
    unsigned int i;
    int j;
    pstmnt_word high_carry;
    pstmnt_word u, a1, c;

#  ifdef PSTMNT_USE_INT128_MONTGOMERY
    if ((n & 1) == 0 && n <= 4096 / 32)
    {
        pstmnt_dword temp_r_storage[8192 / 64];
        pstmnt_dword p_storage[4096 / 64];
        if ((((unsigned long) temp_r) & 0x7) != 0)
        {
            /* Unaligned temp_r, copy it to a new temporary buffer. */
            PSTMNT_COPY(temp_r_storage, temp_r, n * 8);
            PSTMNT_ZEROIZE(temp_r, n * 8);
            temp_r = (pstmnt_word *) temp_r_storage;
        }
        if ((((unsigned long) p) & 0x7) != 0)
        {
            /* Unaligned p. */
            PSTMNT_COPY(p_storage, p, n * 4);
            p = (pstmnt_word *) p_storage;
        }
        pstmnt_dword hcd = pstmnt_montgomery_reduce_d((PSTMNT_UINT64 *) temp_r,
            r,
            (const PSTMNT_UINT64 *) p,
            mp, n / 2);
        pstmnt_cmp_sub_mod_carry(r, p, n, (pstmnt_word) hcd);
        if (p == (pstmnt_word *) p_storage)
        {
            PSTMNT_ZEROIZE(p_storage, n * 4);
        }
        if (temp_r == (pstmnt_word *) temp_r_storage)
        {
            PSTMNT_ZEROIZE(temp_r_storage, n * 8);
        }
        return;
    }
#  endif /* PSTMNT_USE_INT128_MONTGOMERY */

    if (temp_r + n != r)
    {
        pstmnt_clear(r, n); /* Clear r. */
    }

    for (high_carry = 0, i = 0; i < n; i++)
    {
        pstmnt_word d;
        pstmnt_word *array = &temp_r[i];
        d = *array;
        /* Calculate u and process the first 32 bits. */
        u = d * mp;

        /* Perform {c:d} = d + u * p[0] */
        c = 0;
        PSTMNT_LONG_MULADD2(c, d, u, p[0]);
        /* Note: the calculated value for d (which is always 0)
           could be stored to temp_r[i] = d like this.
           However, this is skipped as the cleared portion of temp_r
           is not used after pstmnt_montgomery_reduce. */
        for (j = 1; j < (int) n; j++)
        {
            a1 = array[j];
            PSTMNT_LONG_MULADD2(c, a1, u, p[j]);
            array[j] = a1;
        }

        PSTMNT_LONG_MULADD2(high_carry, c, array[j], 1);
        array[j] = c;
    }

    /* Copy high portion, if required. */
    if (temp_r + n != r)
    {
        /* OPTN: It is may be possible to get rid of this copy operation
           by reorganizing how this function works or is used. */
        pstmnt_copy(temp_r + n, r, n);
    }

    pstmnt_cmp_sub_mod_carry(r, p, n, high_carry);
}
# elif defined(PSTMNT_LONG_MULADD) && defined(PSTMNT_LONG_ADD32_32_TO_33)
/* Accelerated path using multiply-add instruction. */
void pstmnt_montgomery_reduce(pstmnt_word * restrict temp_r,
    pstmnt_word r[] /* n */,
    const pstmnt_word p[] /* n */,
    pstmnt_word mp,
    pstmnt_words n)
{
    unsigned int i;
    unsigned int j;
    pstmnt_word high_carry;
    pstmnt_word u, a1, c;

#  ifdef PSTMNT_USE_INT128_MONTGOMERY
    if ((n & 1) == 0 && n <= 4096 / 32)
    {
        pstmnt_dword temp_r_storage[8192 / 64];
        pstmnt_dword p_storage[4096 / 64];
        if ((((unsigned long) temp_r) & 0x7) != 0)
        {
            /* Unaligned temp_r, copy it to a new temporary buffer. */
            PSTMNT_COPY(temp_r_storage, temp_r, n * 8);
            PSTMNT_ZEROIZE(temp_r, n * 8);
            temp_r = (pstmnt_word *) temp_r_storage;
        }
        if ((((unsigned long) p) & 0x7) != 0)
        {
            /* Unaligned p. */
            PSTMNT_COPY(p_storage, p, n * 4);
            p = (pstmnt_word *) p_storage;
        }
        pstmnt_dword hcd = pstmnt_montgomery_reduce_d((PSTMNT_UINT64 *) temp_r,
            r,
            (const PSTMNT_UINT64 *) p,
            mp, n / 2);
        pstmnt_cmp_sub_mod_carry(r, p, n, (pstmnt_word) hcd);
        if (p == (pstmnt_word *) p_storage)
        {
            PSTMNT_ZEROIZE(p_storage, n * 4);
        }
        if (temp_r == (pstmnt_word *) temp_r_storage)
        {
            PSTMNT_ZEROIZE(temp_r_storage, n * 8);
        }
        return;
    }
#  endif /* PSTMNT_USE_INT128_MONTGOMERY */

    if (temp_r + n != r)
    {
        pstmnt_clear(r, n); /* Clear r. */
    }

    for (high_carry = 0, i = 0; i < n; i++)
    {
        pstmnt_word d = temp_r[i];
        /* Calculate u and process the first 32 bits. */
        u = d * mp;

        /* Perform {c:d} = d + u * p[0] */
        c = 0;
        PSTMNT_LONG_MULADD(c, d, u, p[0]);
        /* Note: the calculated value for d (which is always 0)
           could be stored to temp_r[i] = d like this.
           However, this is skipped as the cleared portion of temp_r
           is not used after pstmnt_montgomery_reduce. */
        for (j = 1; j < n; j++)
        {
            PSTMNT_LONG_ADD32_32_TO_33(c, a1, temp_r[j + i], c);
            PSTMNT_LONG_MULADD(c, a1, u, p[j]);
            temp_r[j + i] = a1;
        }

        PSTMNT_LONG_ADD32_32_TO_33(high_carry, c, c, high_carry);
        PSTMNT_LONG_ADD32(high_carry, c, temp_r[j + i]);
        temp_r[j + i] = c;
    }

    /* Copy high portion, if required. */
    if (temp_r + n != r)
    {
        /* OPTN: It is may be possible to get rid of this copy operation
           by reorganizing how this function works or is used. */
        pstmnt_copy(temp_r + n, r, n);
    }

    pstmnt_cmp_sub_mod_carry(r, p, n, high_carry);
}
# else /* Standard path (no multiply-add instruction available). */
/* Compute x*R^-1 (mod M), that is reduce in Montgomery representation.
   This algorithm is basically from HAC.
   Note: the function will work with temp_r. */
/* OPTN: Consider MODP optimizations: pstmnt_neg_small_inv(0xFFFFFFFF) == 1.
   This is used to optimize reduction, for instance with the MODP groups
   used with IKEv2.) */
void pstmnt_montgomery_reduce(pstmnt_word * restrict temp_r,
    pstmnt_word r[] /* n */,
    const pstmnt_word p[] /* n */,
    pstmnt_word mp,
    pstmnt_words n)
{
    unsigned int i;
    unsigned int j;
    pstmnt_word high_carry;
    pstmnt_word t, u, a2, a1, c;

#  ifdef PSTMNT_USE_INT128_MONTGOMERY
    if ((n & 1) == 0 && n <= 4096 / 32)
    {
        pstmnt_dword temp_r_storage[8192 / 64];
        pstmnt_dword p_storage[4096 / 64];
        if ((((unsigned long) temp_r) & 0x7) != 0)
        {
            /* Unaligned temp_r, copy it to a new temporary buffer. */
            PSTMNT_COPY(temp_r_storage, temp_r, n * 8);
            PSTMNT_ZEROIZE(temp_r, n * 8);
            temp_r = (pstmnt_word *) temp_r_storage;
        }
        if ((((unsigned long) p) & 0x7) != 0)
        {
            /* Unaligned p. */
            PSTMNT_COPY(p_storage, p, n * 4);
            p = (pstmnt_word *) p_storage;
        }
        pstmnt_dword hcd = pstmnt_montgomery_reduce_d((PSTMNT_UINT64 *) temp_r,
            r,
            (const PSTMNT_UINT64 *) p,
            mp, n / 2);
        pstmnt_cmp_sub_mod_carry(r, p, n, (pstmnt_word) hcd);
        if (p == (pstmnt_word *) p_storage)
        {
            PSTMNT_ZEROIZE(p_storage, n * 4);
        }
        if (temp_r == (pstmnt_word *) temp_r_storage)
        {
            PSTMNT_ZEROIZE(temp_r_storage, n * 8);
        }
        return;
    }
#  endif /* PSTMNT_USE_INT128_MONTGOMERY */

    if (temp_r + n != r)
    {
        pstmnt_clear(r, n); /* Clear r. */
    }

    for (high_carry = 0, i = 0; i < n; i++)
    {
        /* Calculate u (32 bits precision), for the reduce loop. */
        u = temp_r[i] * mp;
        for (j = 0, c = 0; j < n; j++)
        {
#  ifdef PSTMNT_LONG_MUL_ADD32
            PSTMNT_LONG_MUL_ADD32(a2, a1, u, p[j], c);
#  else
            PSTMNT_LONG_MUL(a2, a1, u, p[j]);

            /* Add the carry. */
            a1 += c;
            if (a1 < c)
            {
                a2++;
            }
#  endif    /* PSTMNT_LONG_MUL_ADD32 */
            c = a2;

#  ifdef PSTMNT_LONG_ADD32
            PSTMNT_LONG_ADD32(c, temp_r[j + i], a1);
#  else
            /* Add to the result. */
            t = temp_r[j + i] + a1;
            if (t < a1)
            {
                c++;
            }
            temp_r[j + i] = t;
#  endif    /* PSTMNT_LONG_MUL_ADD32 */
        }

        c = c + high_carry;
        if (c < high_carry)
        {
            high_carry = 1;
        }
        else
        {
            high_carry = 0;
        }
        t = temp_r[j + i] + c;
        if (t < c)
        {
            high_carry++;
        }
        temp_r[j + i] = t;
    }

    /* Copy high portion, if required. */
    if (temp_r + n != r)
    {
        /* OPTN: It is may be possible to get rid of this copy operation
           by reorganizing how this function works or is used. */
        pstmnt_copy(temp_r + n, r, n);
    }

    pstmnt_cmp_sub_mod_carry(r, p, n, high_carry);
}
# endif /* defined(PSTMNT_LONG_MULADD) && defined(PSTMNT_LONG_ADD32) */

void pstmnt_montgomery_step(const pstmnt_word a[],
    const pstmnt_word b[],
    pstmnt_word r[],
    pstmnt_word temp_r[],
    const pstmnt_word p[],
    pstmnt_word mp,
    pstmnt_words n)
{
    /* Square or Multiplication */
    if (a == b)
    {
# ifdef PSTMNT_UNROLL2
        if ((n & 1) == 0)
        {
            /* pstmnt_square_unroll2 is optimized for multiples of 2 */
            pstmnt_square_unroll2(a, temp_r, n);
        }
        else
# endif /* PSTMNT_UNROLL2 */
        {
            pstmnt_square(a, temp_r, n);
        }
    }
    else
    {
# ifdef PSTMNT_UNROLL2
        if ((n & 1) == 0)
        {
            /* pstmnt_square_unroll2 is optimized for multiples of 2 */
            pstmnt_mult_unroll2(a, b, temp_r, n);
        }
        else
# endif /* PSTMNT_UNROLL2 */
        {
            pstmnt_mult(a, b, temp_r, n);
        }
    }

    /* Reduction. */
# ifdef PSTMNT_UNROLL2
    if ((n & 1) == 0)
    {
        /* pstmnt_square_unroll2 is optimized for multiples of 2 */
        pstmnt_montgomery_reduce_unroll2(temp_r, r, p, mp, n);
    }
    else
# endif /* PSTMNT_UNROLL2 */
    {
        pstmnt_montgomery_reduce(temp_r, r, p, mp, n);
    }
}

void
pstmnt_montgomery_input(
    const pstmnt_word Input[] /* NWords */,
    PSTMNT_RESTORED pstmnt_word Prime[] /* NWords */,
    pstmnt_word TempLarge[] /* NWords * 6 */,
    pstmnt_word Target[] /* NWords */,
    pstmnt_words NWords,
    pstmnt_word PrimeSmallInv
    )
{
    /* Calculate 2R and use ModExp (Montgomery) to get R^2. */
    pstmnt_word NBitsArray[1]; /* single index is sufficient for maximum. */

    NBitsArray[0] = PSTMNT_WORDS_TO_BITS(NWords);

    pstmnt_clear(TempLarge, NWords);
    (void) pstmnt_sub(TempLarge, Prime, TempLarge, NWords); /* R */
    /* 2R */
    pstmnt_cmp_sub_mod_carry(TempLarge,
        Prime,
        NWords,
        pstmnt_add(TempLarge, TempLarge, TempLarge, NWords));

    pstmnt_mod_exp_montgomery_skip(
        TempLarge,
        NBitsArray,
        TempLarge,
        0,
        13,     /* Up-to 4096 supported for number of bits. */
        Prime,
        TempLarge + NWords * 2,
        pstmnt_neg_small_inv(Prime),
        NWords);     /* 2^NBits * R == R^2 */

    /* OPTN: The computed value could be stored for later use.
       The R^2 is the same value always for the same Prime/Modulus. */

    /* Calculate Input * R^2 and then Montgomery reduce to Input * R (mod p) */
    pstmnt_copy(TempLarge, TempLarge + NWords * 2, NWords);
    pstmnt_mult(TempLarge + NWords * 2, Input, TempLarge, NWords);
    pstmnt_montgomery_reduce(TempLarge,
        Target,
        Prime,
        PrimeSmallInv,
        NWords);
}

void
pstmnt_montgomery_output(
    const pstmnt_word Input[] /* NWords */,
    pstmnt_word Output[] /* NWords */,
    const pstmnt_word Prime[] /* NWords */,
    pstmnt_word TempLarge[] /* NWords * 2 */,
    pstmnt_words NWords,
    pstmnt_word PrimeSmallInv
    )
{
    /* Note: pstmnt_montgomery_reduce requires size of temp is NWords * 2. */
    PSTMNT_MOVE(TempLarge, Input, NWords * PSTMNT_WORD_BYTES);
    pstmnt_extend(TempLarge, NWords, NWords * 2);
    pstmnt_montgomery_reduce(TempLarge, Output, Prime, PrimeSmallInv, NWords);
}

# define pstmnt_montgomery_eq(a, b, n)           \
    (!pstmnt_compare(a, b, n))

/* Modular exponentiation with montgomery.
   (a<len>^(x<b:bits>) == r<len> (mod n<len>)*/
# define PSTMNT_MODEXP_FLAGS_SELECT 1
# define PSTMNT_MODEXP_FLAGS_CLEAR 2
void
pstmnt_mod_exp_montgomery_skipF(
    const pstmnt_word a[],
    const pstmnt_word x[],
    pstmnt_word r[],
    const pstmnt_word start_bit,
    const pstmnt_word bits,
    const pstmnt_word m[],
    pstmnt_word temp[] /* len * 4 */,
    pstmnt_word mp,
    pstmnt_words len,
    int moflags)
{
    pstmnt_word i;
    pstmnt_word xw = 0;
    pstmnt_word *temp_w = temp;
    pstmnt_word *temp_w2 = temp + 2 * len;
    pstmnt_word *resultbuf = temp + 3 * len;

    /* Initialize work area (2) with the value to exponentiate. */
    pstmnt_copy(a, temp_w2, len);

    /* Ignore first bits. */
    for (i = 0; i < start_bit; i++)
    {
        if ((i & 31) == 0)
        {
            xw = x[i / 32];
        }
        xw /= 2;
    }

    /* Take first bit. */
    if ((i & 31) == 0)
    {
        xw = x[i / 32];
    }

    if (xw & 1)
    {
        /* Initial value == a - use memmove to allow dst/src overlap. */
        PSTMNT_MOVE(r, a, len * sizeof(pstmnt_word));
    }
    else
    {
        /* Initial value == 2**R mod m. [i.e. 1 in Montgomery format] */
        pstmnt_clear(r, len);
        pstmnt_sub(r, m, r, len);
    }
    xw /= 2;
    i++;

    /* Process bits-start_bit bits. */
    for (; i < bits; i++)
    {
        pstmnt_montgomery_step(temp_w2, temp_w2, temp_w2, temp_w, m, mp, len);

        if ((i & 31) == 0)
        {
            xw = x[i / 32];
        }

        if (moflags & PSTMNT_MODEXP_FLAGS_SELECT)
        {
            pstmnt_montgomery_step(temp_w2, r, resultbuf, temp_w,
                m, mp, len);
            pstmnt_select_mask(resultbuf, r, len,
                -(pstmnt_word) ((xw & 1) == 1));
        }
        else
        {
            if ((xw & 1) == 1)
            {
                pstmnt_montgomery_step(temp_w2, r, r, temp_w, m, mp, len);
            }
        }

        xw /= 2;
    }

    /* Clear temporaries. */
    pstmnt_clear(temp, len * 4);
}

void
pstmnt_mod_exp_montgomery_skip(
    const pstmnt_word a[],
    const pstmnt_word x[],
    pstmnt_word r[],
    const pstmnt_word start_bit,
    const pstmnt_word bits,
    const pstmnt_word m[],
    pstmnt_word temp[] /* len * 4 */,
    pstmnt_word mp,
    pstmnt_words len)
{
    pstmnt_mod_exp_montgomery_skipF(a, x, r, start_bit, bits, m, temp, mp, len,
        PSTMNT_MODEXP_FLAGS_SELECT |
        PSTMNT_MODEXP_FLAGS_CLEAR);
}

#else
extern int constant_time_modexp_code_omitted;

#endif /* USE_CONSTANT_TIME_MODEXP */

/* end of file pstmnt.c */
