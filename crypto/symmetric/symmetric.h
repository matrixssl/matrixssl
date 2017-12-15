/**
 *      @file    symmetric.h
 *      @version $Format:%h%d$
 *
 *      Header for symmetric key API implementations.
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

#ifndef _h_MATRIX_SYMMETRIC
# define _h_MATRIX_SYMMETRIC

/******************************************************************************/
/* Forward declarations */

# define AES_BLOCKLEN    16
# define AES_IVLEN       AES_BLOCKLEN
# define AES128_KEYLEN   16
# define AES192_KEYLEN   24
# define AES256_KEYLEN   32
# define DES3_BLOCKLEN    8
# define DES3_IVLEN      DES3_BLOCKLEN
# define DES3_KEYLEN     24
# define IDEA_BLOCKLEN    8
# define IDEA_IVLEN      IDEA_BLOCKLEN
# define IDEA_KEYLEN     16
# define SEED_BLOCKLEN   16
# define SEED_IVLEN      SEED_BLOCKLEN
# define SEED_KEYLEN     16
# define CHACHA20POLY1305_IETF_IV_FIXED_LENGTH    12
# define CHACHA20POLY1305_IETF  /* Always use IETF mode */

# define MAX_IVLEN       AES_IVLEN
# define MAX_KEYLEN      AES256_KEYLEN
# define AES_MAXKEYLEN   AES256_KEYLEN

/******************************************************************************/
/* Layer includes */

# include "aes_aesni.h"
# include "aes_matrix.h"
# ifdef USE_OPENSSL_CRYPTO
#  include "symmetric_openssl.h"
# endif
# ifdef USE_LIBSODIUM_CRYPTO
#  include "symmetric_libsodium.h"
#  include "../ps_chacha20poly1305ietf.h"
# endif
# ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
#  include "../ps_chacha20poly1305ietf.h"
# endif

/******************************************************************************/
/* Universal types and defines */
typedef union
{
# ifdef USE_AES_GCM
    psAesGcm_t aesgcm;
# endif
# ifdef USE_AES_CBC
    psAesCbc_t aes;
# endif
# ifdef USE_CHACHA20_POLY1305_IETF
    psChacha20Poly1305Ietf_t chacha20poly1305ietf;
# endif
# ifdef USE_MATRIX_RC2
    psRc2Cbc_t rc2;
# endif
# ifdef USE_MATRIX_ARC4
    psArc4_t arc4;
# endif
# if defined USE_MATRIX_3DES || defined USE_CL_3DES
    psDes3_t des3;
# endif
# ifdef USE_MATRIX_IDEA
    psIdea_t idea;
# endif
# ifdef USE_MATRIX_SEED
    psSeed_t seed;
# endif
} psCipherContext_t;

typedef uint32 CL_AnyAsset_t;

typedef struct
{
    uint32 KeyLen;
    struct
    {
        CL_AnyAsset_t Asset_key;
        CL_AnyAsset_t Asset_ke;
        CL_AnyAsset_t Asset_state;
        unsigned char IVend[8];
    } fips;
} psCipherGivContext_t;

#endif /* _h_MATRIX_SYMMETRIC */
/******************************************************************************/

