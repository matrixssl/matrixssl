/**
 *      @file    symmetric_libsodium.h
 *      @version $Format:%h%d$
 *
 *      Header for libsodium crypto layer.
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

#ifndef _h_LIBSODIUM_SYMMETRIC
# define _h_LIBSODIUM_SYMMETRIC

# include "../cryptoApi.h"
# include "sodium.h"

/******************************************************************************/

# ifdef USE_LIBSODIUM_AES_GCM
typedef struct __attribute__((aligned(16)))
{
    crypto_aead_aes256gcm_state libSodiumCtx;
    unsigned char IV[AES_BLOCKLEN];
    unsigned char Tag[AES_BLOCKLEN];
    unsigned char Aad[crypto_aead_aes256gcm_ABYTES];   /* TODO change this length */
    uint32_t AadLen;
} psAesGcm_t;
# endif

# ifdef USE_LIBSODIUM_CHACHA20_POLY1305_IETF
typedef struct
{
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char IV[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    unsigned char Tag[crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned char Aad[16];
    uint32_t AadLen;
} psChacha20Poly1305Ietf_t;
# define PS_CHACHA20POLY1305IETF_DEFINED 1
# endif

/******************************************************************************/

#endif /* _h_LIBSODIUM_SYMMETRIC */

