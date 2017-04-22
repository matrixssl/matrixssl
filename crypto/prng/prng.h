/**
 *      @file    prng.h
 *      @version $Format:%h%d$
 *
 *      Pseudorandom Number Generator header.
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

#ifndef _h_PS_PRNG
# define _h_PS_PRNG

# ifdef USE_YARROW
/*
    AES SHA-1 implementation
 */
#  define CTR_COUNTER_LITTLE_ENDIAN    0x0000
#  define CTR_COUNTER_BIG_ENDIAN       0x1000

#  define AESBLOCKSIZE 16

typedef struct
{
#  ifdef USE_SHA256
    unsigned char pool[SHA256_HASH_SIZE]; /* hash of entropy */
#  else
    unsigned char pool[SHA1_HASH_SIZE];   /* hash of entropy */
#  endif
    int32 mode;                           /** The mode (endianess) of the CTR, 0==little, 1==big */
    int32 ctrlen;                         /** counter width */
    int32 padlen;                         /** The padding offset */
    int32 blocklen;                       /** The AESBLOCKSIZE */
    unsigned char ctr[AESBLOCKSIZE];      /** The counter being encrypted */
    unsigned char pad[AESBLOCKSIZE];      /** The actual prn */
    psAesKey_t key;                       /** The scheduled key */
} psYarrow_t;
# endif /* USE_YARROW */

/*
    prng.c wrapper
 */
# define RANDOM_BYTES_BEFORE_ENTROPY 1024 /* add entropy each time # bytes read */
# define RANDOM_ENTROPY_BYTES        8    /* Bytes of entropy from source */

typedef struct
{
# ifdef USE_YARROW
    psYarrow_t yarrow;
# endif
    uint32 bytecount;      /* number of bytes read from this context */
} psRandom_t;

/******************************************************************************/
#endif /* _h_PS_PRNG */

