/**
 *      @file    ps_x25519.c
 *      @version $Format:%h%d$
 *
 *      Implementation for Matrix X25519 interface.
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

#include "ps_x25519.h"
#include "include/sodium/crypto_scalarmult.h"
#include "../cryptoApi.h"

#ifdef USE_MATRIX_X25519

psRes_t psDhX25519GenSharedSecret(
        const unsigned char peer_pub_key[PS_DH_X25519_PUBLIC_KEY_BYTES],
        const unsigned char my_priv_key[PS_DH_X25519_PRIVATE_KEY_BYTES],
        unsigned char secret[PS_DH_X25519_PUBLIC_KEY_BYTES])
{
    int res = psSodium_crypto_scalarmult(secret, my_priv_key, peer_pub_key);
    if (res == 0)
    {
        return PS_SUCCESS;
    }
    return PS_FAILURE;
}

# ifdef USE_PS_CRYPTO_SCALARMULT_BASE
/* Use special function for multiplication with the known base.
   This path enables some optimizations. */
psRes_t psDhX25519GenKey(
        unsigned char priv_key[PS_DH_X25519_PRIVATE_KEY_BYTES],
        unsigned char pub_key[PS_DH_X25519_PUBLIC_KEY_BYTES])
{
    psResSize_t rvs;

    rvs = psGetPrngLocked(priv_key, PS_DH_X25519_PRIVATE_KEY_BYTES, NULL);
    if (rvs == PS_DH_X25519_PRIVATE_KEY_BYTES)
    {
        int res = psSodium_crypto_scalarmult_base(pub_key, priv_key);
        if (res == 0)
        {
            return PS_SUCCESS;
        }
        return PS_FAILURE;
    }
    return rvs < 0 ? (psRes_t) rvs : PS_FAILURE;
}
# else
/* Use the shared secret generation function also for key generation. */
psRes_t psDhX25519GenKey(
        unsigned char priv_key[PS_DH_X25519_PRIVATE_KEY_BYTES],
        unsigned char pub_key[PS_DH_X25519_PUBLIC_KEY_BYTES])
{
    psResSize_t rvs;
    const unsigned char base_point[PS_DH_X25519_PRIVATE_KEY_BYTES] = {
        9, /* 0, ... */
    };

    rvs = psGetPrngLocked(priv_key, PS_DH_X25519_PRIVATE_KEY_BYTES, NULL);
    if (rvs == PS_DH_X25519_PRIVATE_KEY_BYTES)
    {
        return psDhX25519GenSharedSecret(base_point, priv_key, pub_key);
    }
    return rvs < 0 ? (psRes_t) rvs : PS_FAILURE;
}
# endif

#endif /* USE_MATRIX_X25519 */

/******************************************************************************/

