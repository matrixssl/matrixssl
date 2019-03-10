/**
 *      @file    ps_x25519.h
 *      @version $Format:%h%d$
 *
 *      Header for Matrix X25519 interface.
 */

/*****************************************************************************
* Copyright (c) 2018 INSIDE Secure Oy. All Rights Reserved.
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

/******************************************************************************/

#ifndef _h_PS_X25519
# define _h_PS_X25519

# include "coreApi.h" /* Must be included first */
# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <cryptoConfig.h>   /* Must be included second */
# else
#  include "../cryptoConfig.h"   /* Must be included second */
# endif
# include "osdep-types.h"

/******************************************************************************/

/** Keylength of X25519 private key. */
#define PS_DH_X25519_PRIVATE_KEY_BYTES 32U

/** Keylength of X25519 public key. */
#define PS_DH_X25519_PUBLIC_KEY_BYTES 32U

/** Keylength of X25519 shared secret. */
#define PS_DH_X25519_SHARED_SECRET_BYTES 32U

PSPUBLIC psRes_t psDhX25519GenKey(
        unsigned char priv_key[PS_DH_X25519_PRIVATE_KEY_BYTES],
        unsigned char pub_key[PS_DH_X25519_PUBLIC_KEY_BYTES]);

PSPUBLIC psRes_t psDhX25519GenSharedSecret(
        const unsigned char peer_pub_key[PS_DH_X25519_PUBLIC_KEY_BYTES],
        const unsigned char my_priv_key[PS_DH_X25519_PRIVATE_KEY_BYTES],
        unsigned char secret[PS_DH_X25519_PUBLIC_KEY_BYTES]);

/******************************************************************************/

#endif /* _h_PS_X25519 */


