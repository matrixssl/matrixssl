/**
 *      @file    aes_aesni.h
 *      @version $Format:%h%d$
 *
 *      Header for AES-NI Hardware Crypto Instructions.
 */
/*
 *      Copyright (c) 2014-2017 INSIDE Secure Corporation
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

#include "../cryptoApi.h"

#ifndef _h_AESNI_CRYPTO
# define _h_AESNI_CRYPTO

/******************************************************************************/
/*
    Intel Native Instructions for AES
    http://en.wikipedia.org/wiki/AES_instruction_set
 */

# ifdef USE_AESNI_AES_BLOCK
#  include <stdio.h>
#  include <emmintrin.h>
typedef struct __attribute__((aligned(16)))
{
    __m128i skey[15];       /* Key schedule (encrypt or decrypt) */
    uint16 rounds;          /* Number of rounds */
    uint16 type;            /* Encrypt or Decrypt */
} psAesKey_t;
# endif

# ifdef USE_AESNI_AES_CBC
typedef struct __attribute__((aligned(16)))
{
    psAesKey_t key;
    unsigned char IV[16];
} psAesCbc_t;
# endif

# ifdef USE_AESNI_AES_GCM
#  include <emmintrin.h>
typedef struct __attribute__((aligned(16)))
{
    psAesKey_t key;
    unsigned char IV[16];
    __m128i h_m128i;
    __m128i y_m128i;
    __m128i icb_m128i;
    int cipher_started;
    unsigned int a_len;
    unsigned int c_len;
} psAesGcm_t;
# endif

#endif /* _h_AESNI_CRYPTO */
/******************************************************************************/

