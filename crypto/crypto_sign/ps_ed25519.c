/**
 *      @file    ps_ed25519.c
 *      @version $Format:%h%d$
 *
 *      Implementation for Matrix Ed25519 interface.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
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

#include "ps_ed25519.h"
#include "include/sodium/crypto_sign_ed25519.h"
#include "../cryptoApi.h"

#ifndef DEBUG_ED25519
/* #define DEBUG_ED25519 */
#endif

#ifdef USE_MATRIX_ED25519
int32_t psEd25519Sign(const unsigned char *msg,
        psSizeL_t msgLen,
        unsigned char *sigOut,
        psSizeL_t *sigOutLen,
        const unsigned char privKey[32],
        const unsigned char pubKey[32])
{
    int rc;
    unsigned long long smlen;
    unsigned char sig[64];
    unsigned char privPub[64];

    if (sigOut == NULL || sigOutLen == NULL)
    {
        return PS_ARG_FAIL;
    }

# ifdef DEBUG_ED25519
    psTraceBytes("ed25519 sign msg", msg, msgLen);
    psTraceBytes("ed25519 sign priv key", privKey, 32);
    psTraceBytes("ed25519 sign pub key", pubKey, 32);
# endif

    /* psSodium_crypto_sign_ed25519_detached requires, as an
       optimization, that the public key must be appended to
       the priv key. */
    Memcpy(privPub, privKey, 32);
    Memcpy(privPub + 32, pubKey, 32);

    rc = psSodium_crypto_sign_ed25519_detached(sig,
            &smlen,
            msg,
            (unsigned long long) msgLen,
            privPub);
    Memcpy(sigOut, sig, 64);
    *sigOutLen = smlen;

# ifdef DEBUG_ED25519
    psTraceBytes("ed25519 sign sig", sigOut, *sigOutLen);
    if (rc == PS_SUCCESS)
    {
        rc = psEd25519Verify(sig, msg, msgLen, pubKey);
        if (rc != PS_SUCCESS)
        {
            printf("ec25519 sign unable to verify own sig\n");
            return PS_FAILURE;
        }
    }
# endif

    if (rc == 0)
    {
        return PS_SUCCESS;
    }
    else
    {
        return PS_FAILURE;
    }
}

int32_t psEd25519Verify(const unsigned char sig[64],
        const unsigned char *msg,
        psSizeL_t msgLen,
        const unsigned char pubKey[32])
{
    int rc;

# ifdef DEBUG_ED25519
    psTraceBytes("ed25519 ver msg", msg, msgLen);
    psTraceBytes("ed25519 ver sig", sig, 64);
    psTraceBytes("ed25519 ver pub key", pubKey, 32);
# endif

    rc = psSodium_crypto_sign_ed25519_verify_detached(sig,
            msg,
            (unsigned long long) msgLen,
            pubKey);
    if (rc == 0)
    {
        return PS_SUCCESS;
    }
    else
    {
        return PS_FAILURE;
    }
}
#endif /* USE_MATRIX_ED25519 */
