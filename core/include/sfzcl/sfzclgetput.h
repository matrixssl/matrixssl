/* sfzclgetput.h

   Macros for storing and retrieving integers in msb first and lsb
   first order.  This interface can also be called from the other
   thread than SFZCL main thread.
 */

/*****************************************************************************
* Copyright (c) 2006-2016 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef SFZCLGETPUT_H
#define SFZCLGETPUT_H

#define SFZCL_GET_8BIT(cp) (*(unsigned char *) (cp))
#define SFZCL_PUT_8BIT(cp, value) (*(unsigned char *) (cp)) = \
    (unsigned char) (value)
#define SFZCL_GET_4BIT_LOW(cp) (*(unsigned char *) (cp) & 0x0f)
#define SFZCL_GET_4BIT_HIGH(cp) ((*(unsigned char *) (cp) >> 4) & 0x0f)
#define SFZCL_PUT_4BIT_LOW(cp, value) (*(unsigned char *) (cp) = \
                                           (unsigned char) ((*(unsigned char *) (cp) & 0xf0) | ((value) & 0x0f)))
#define SFZCL_PUT_4BIT_HIGH(cp, value) (*(unsigned char *) (cp) = \
                                            (unsigned char) ((*(unsigned char *) (cp) & 0x0f) | (((value) & 0x0f) << 4)))

#ifdef SFZCLUINT64_IS_64BITS
# define SFZCL_GET_64BIT(cp) (((uint64_t) SFZCL_GET_32BIT((cp)) << 32) | \
                              ((uint64_t) SFZCL_GET_32BIT((cp) + 4)))
# define SFZCL_PUT_64BIT(cp, value) do { \
        SFZCL_PUT_32BIT((cp), (uint32_t) ((uint64_t) (value) >> 32)); \
        SFZCL_PUT_32BIT((cp) + 4, (uint32_t) (value)); } while (0)
# define SFZCL_GET_64BIT_LSB_FIRST(cp) \
    (((uint64_t) SFZCL_GET_32BIT_LSB_FIRST((cp))) | \
     ((uint64_t) SFZCL_GET_32BIT_LSB_FIRST((cp) + 4) << 32))
# define SFZCL_PUT_64BIT_LSB_FIRST(cp, value) do { \
        SFZCL_PUT_32BIT_LSB_FIRST((cp), (uint32_t) (value)); \
        SFZCL_PUT_32BIT_LSB_FIRST((cp) + 4, \
            (uint32_t) ((uint64_t) (value) >> 32)); \
} while (0)

# define SFZCL_GET_40BIT(cp) (((uint64_t) SFZCL_GET_8BIT((cp)) << 32) | \
                              ((uint64_t) SFZCL_GET_32BIT((cp) + 1)))
# define SFZCL_PUT_40BIT(cp, value) do { \
        SFZCL_PUT_8BIT((cp), (uint32_t) ((uint64_t) (value) >> 32)); \
        SFZCL_PUT_32BIT((cp) + 1, (uint32_t) (value)); } while (0)

# define SFZCL_GET_40BIT_LSB_FIRST(cp) \
    (((uint64_t) SFZCL_GET_32BIT_LSB_FIRST((cp))) | \
     ((uint64_t) SFZCL_GET_8BIT((cp) + 4) << 32))
# define SFZCL_PUT_40BIT_LSB_FIRST(cp, value) do { \
        SFZCL_PUT_32BIT_LSB_FIRST((cp), (uint32_t) (value)); \
        SFZCL_PUT_8BIT((cp) + 4, \
            (uint32_t) ((uint64_t) (value) >> 32)); } while (0)

#else                           /* SFZCLUINT64_IS_64BITS */
# define SFZCL_GET_64BIT(cp) ((uint64_t) SFZCL_GET_32BIT((cp) + 4))
# define SFZCL_PUT_64BIT(cp, value) do { \
        SFZCL_PUT_32BIT((cp), 0L); \
        SFZCL_PUT_32BIT((cp) + 4, (uint32_t) (value)); } while (0)
# define SFZCL_GET_64BIT_LSB_FIRST(cp) ((uint64_t) SFZCL_GET_32BIT((cp)))
# define SFZCL_PUT_64BIT_LSB_FIRST(cp, value) do { \
        SFZCL_PUT_32BIT_LSB_FIRST((cp), (uint32_t) (value)); \
        SFZCL_PUT_32BIT_LSB_FIRST((cp) + 4, 0L); } while (0)

# define SFZCL_GET_40BIT(cp) ((uint64_t) SFZCL_GET_32BIT((cp) + 1))
# define SFZCL_PUT_40BIT(cp, value) do { \
        SFZCL_PUT_8BIT((cp), 0); \
        SFZCL_PUT_32BIT((cp) + 1, (uint32_t) (value)); } while (0)
# define SFZCL_GET_40BIT_LSB_FIRST(cp) \
    ((uint64_t) SFZCL_GET_32BIT_LSB_FIRST((cp)))
# define SFZCL_PUT_40BIT_LSB_FIRST(cp, value) do { \
        SFZCL_PUT_32BIT_LSB_FIRST((cp), (uint32_t) (value)); \
        SFZCL_PUT_8BIT((cp) + 4, 0); } while (0)

#endif                          /* SFZCLUINT64_IS_64BITS */

#define SFZCL_GET_24BIT(cp) \
    ((((unsigned long) ((unsigned char *) (cp))[0]) << 16) | \
     (((unsigned long) ((unsigned char *) (cp))[1]) << 8) | \
     ((unsigned long) ((unsigned char *) (cp))[2]))
#define SFZCL_GET_24BIT_LSB_FIRST(cp) \
    ((((unsigned long) ((unsigned char *) (cp))[2]) << 16) | \
     (((unsigned long) ((unsigned char *) (cp))[1]) << 8) | \
     ((unsigned long) ((unsigned char *) (cp))[0]))
#define SFZCL_PUT_24BIT(cp, value) do { \
        ((unsigned char *) (cp))[0] = (unsigned char) ((value) >> 16); \
        ((unsigned char *) (cp))[1] = (unsigned char) ((value) >> 8); \
        ((unsigned char *) (cp))[2] = (unsigned char) (value); } while (0)
#define SFZCL_PUT_24BIT_LSB_FIRST(cp, value) do { \
        ((unsigned char *) (cp))[2] = (unsigned char) ((value) >> 16); \
        ((unsigned char *) (cp))[1] = (unsigned char) ((value) >> 8); \
        ((unsigned char *) (cp))[0] = (unsigned char) (value); } while (0)

/*------------ macros for storing/extracting msb first words -------------*/

#define SFZCL_GET_32BIT(cp) \
    ((((unsigned long) ((unsigned char *) (cp))[0]) << 24) | \
     (((unsigned long) ((unsigned char *) (cp))[1]) << 16) | \
     (((unsigned long) ((unsigned char *) (cp))[2]) << 8) | \
     ((unsigned long) ((unsigned char *) (cp))[3]))

#define SFZCL_GET_16BIT(cp) \
    ((uint16_t) ((((unsigned long) ((unsigned char *) (cp))[0]) << 8) | \
                 ((unsigned long) ((unsigned char *) (cp))[1])))

#define SFZCL_PUT_32BIT(cp, value) do { \
        ((unsigned char *) (cp))[0] = (unsigned char) ((value) >> 24); \
        ((unsigned char *) (cp))[1] = (unsigned char) ((value) >> 16); \
        ((unsigned char *) (cp))[2] = (unsigned char) ((value) >> 8); \
        ((unsigned char *) (cp))[3] = (unsigned char) (value); } while (0)

#define SFZCL_PUT_16BIT(cp, value) do { \
        ((unsigned char *) (cp))[0] = (unsigned char) ((value) >> 8); \
        ((unsigned char *) (cp))[1] = (unsigned char) (value); } while (0)

/*------------ macros for storing/extracting lsb first words -------------*/

#define SFZCL_GET_32BIT_LSB_FIRST(cp) \
    (((unsigned long) ((unsigned char *) (cp))[0]) | \
     (((unsigned long) ((unsigned char *) (cp))[1]) << 8) | \
     (((unsigned long) ((unsigned char *) (cp))[2]) << 16) | \
     (((unsigned long) ((unsigned char *) (cp))[3]) << 24))

#define SFZCL_GET_16BIT_LSB_FIRST(cp) \
    ((uint16_t) (((unsigned long) ((unsigned char *) (cp))[0]) | \
                 (((unsigned long) ((unsigned char *) (cp))[1]) << 8)))

#define SFZCL_PUT_32BIT_LSB_FIRST(cp, value) do { \
        ((unsigned char *) (cp))[0] = (unsigned char) (value); \
        ((unsigned char *) (cp))[1] = (unsigned char) ((value) >> 8); \
        ((unsigned char *) (cp))[2] = (unsigned char) ((value) >> 16); \
        ((unsigned char *) (cp))[3] = (unsigned char) ((value) >> 24); } while (0)

#define SFZCL_PUT_16BIT_LSB_FIRST(cp, value) do { \
        ((unsigned char *) (cp))[0] = (unsigned char) (value); \
        ((unsigned char *) (cp))[1] = (unsigned char) ((value) >> 8); } while (0)

/* This `|| 1' thing disables the GCC i386 optimizations.  They seem
   to be very mysticly broken so it is better to disable them. */
#if !defined(NO_INLINE_GETPUT) && defined(__i386__) && defined(__GNUC__)

/* Intel i386 processor, using AT&T syntax for gcc compiler. */

# undef SFZCL_GET_32BIT_LSB_FIRST
# undef SFZCL_GET_16BIT_LSB_FIRST
# undef SFZCL_PUT_32BIT_LSB_FIRST
# undef SFZCL_PUT_16BIT_LSB_FIRST
# undef SFZCL_GET_32BIT
# undef SFZCL_PUT_32BIT

/* Lsb first cases could be done efficiently also with just C-definitions
   to just copy values.  i386 has no alignment restrictions. */

# define SFZCL_GET_32BIT_LSB_FIRST(cp) (*(uint32_t *) (cp))
# define SFZCL_GET_16BIT_LSB_FIRST(cp) (*(uint16_t *) (cp))
# define SFZCL_PUT_32BIT_LSB_FIRST(cp, x) (*(uint32_t *) (cp)) = (x)
# define SFZCL_PUT_16BIT_LSB_FIRST(cp, x) (*(uint16_t *) (cp)) = (x)

/* Getting bytes msb first */

# ifdef NO_386_COMPAT
#  define SFZCL_GET_32BIT(cp) \
    ({  \
        uint32_t __v__; \
        __asm__ volatile ("movl (%1), %%ecx; " \
                          "bswap %%ecx;" \
                          : "=c" (__v__) \
                          : "r" (cp) : "cc"); \
        __v__; \
    })
# else
#  define SFZCL_GET_32BIT(cp) \
    ({  \
        uint32_t __v__; \
        __asm__ volatile ("movl (%1), %%ecx; rolw $8, %%cx; " \
                          "roll $16, %%ecx; rolw $8, %%cx;" \
                          : "=c" (__v__) \
                          : "r" (cp) : "cc"); \
        __v__; \
    })

# endif

# define SFZCL_PUT_32BIT(cp, v) \
    __asm__ volatile ("movl %1, %%ecx; rolw $8, %%cx; " \
                      "roll $16, %%ecx; rolw $8, %%cx;" \
                      "movl %%ecx, (%0);" \
                      : : "S" (cp), "a" ((uint32_t) (v)) : "%ecx", "memory", "cc")


#endif                          /* __i386__ */

#endif                          /* GETPUT_H */
