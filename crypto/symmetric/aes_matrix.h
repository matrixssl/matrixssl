/**
 *      @file    aes_matrix.h
 *      @version $Format:%h%d$
 *
 *      Header for internal symmetric key cryptography support.
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

#ifndef _h_AES_MATRIX
# define _h_AES_MATRIX

/******************************************************************************/
/*
    Cipher usage in SSL is that any given key is used only for either encryption
    or decryption, not both. If the same key is to be used for both, two
    key structures must be initialized.
    The first use of the key is what marks the key's usage (for example if
    psAesEncryptBlock() is called on the key first, it can only be used
    in future calls to encrypt.
 */

# ifdef USE_MATRIX_RAW_KEY
typedef struct
{
    uint8_t len;
    unsigned char *key;
} psRawKey_t;
# endif

# ifdef USE_MATRIX_AES_BLOCK
typedef struct
{
    uint32_t skey[64];      /**< Key schedule (either encrypt or decrypt) */
    uint16_t rounds;        /**< Number of rounds */
    uint16_t type;          /**< PS_AES_ENCRYPT or PS_AES_DECRYPT (inverse) key */
} psAesKey_t;
# endif

# ifdef USE_MATRIX_AES_CBC
typedef struct
{
    psAesKey_t key;
    unsigned char IV[AES_BLOCKLEN];
} psAesCbc_t;
# endif

# ifdef USE_MATRIX_AES_GCM
typedef struct
{
    psAesKey_t key;
    unsigned char IV[AES_BLOCKLEN];
    unsigned char EncCtr[AES_BLOCKLEN];
    unsigned char CtrBlock[AES_BLOCKLEN];
    unsigned char gInit[AES_BLOCKLEN];
    uint32_t TagTemp[AES_BLOCKLEN / sizeof(uint32_t)];
    unsigned char Hash_SubKey[AES_BLOCKLEN];
    uint32_t ProcessedBitCount[AES_BLOCKLEN / sizeof(uint32_t)];
    uint32_t InputBufferCount;
    uint32_t OutputBufferCount;
    union
    {
        unsigned char Buffer[128];
        uint32_t BufferAlignment;
    } Input;
} psAesGcm_t;
# endif

/******************************************************************************/

# ifdef USE_MATRIX_3DES

typedef struct
{
    uint32_t ek[3][32];
    uint32_t dk[3][32];
} psDes3Key_t;

typedef struct
{
    psDes3Key_t key;
    unsigned char IV[DES3_BLOCKLEN];
} psDes3_t;

# endif

/******************************************************************************/

# ifdef USE_MATRIX_IDEA

typedef struct
{
    uint16_t key_schedule[52];
} psIdeaKey_t;

typedef struct
{
    psIdeaKey_t key;
    uint32_t IV[2];
    uint32_t inverted;
} psIdea_t;

# endif

/******************************************************************************/

# ifdef USE_MATRIX_SEED

typedef struct
{
    uint32_t K[32];
    uint32_t dK[32];
} psSeedKey_t;

typedef struct
{
    psSeedKey_t key;
    unsigned char IV[SEED_BLOCKLEN];
} psSeed_t;

# endif

/******************************************************************************/

# ifdef USE_MATRIX_ARC4

typedef struct
{
    unsigned char state[256];
    uint32_t byteCount;
    unsigned char x;
    unsigned char y;
} psArc4_t;

# endif

/******************************************************************************/

# ifdef USE_MATRIX_RC2

#  define RC2_BLOCKLEN    8

typedef struct
{
    uint32_t xkey[64];
} psRc2Key_t;

typedef struct
{
    psRc2Key_t key;
    unsigned char IV[RC2_BLOCKLEN];
} psRc2Cbc_t;

# endif

#endif /* _h_AES_MATRIX */

/******************************************************************************/

