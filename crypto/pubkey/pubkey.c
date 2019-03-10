/**
 *      @file    pubkey.c
 *      @version $Format:%h%d$
 *
 *      Public and Private key operations shared by crypto implementations.
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

#include "../cryptoImpl.h"

# if defined(USE_RSA) || defined(USE_ECC) || defined(USE_DH) || defined(USE_X25519) || defined(USE_ED25519)

/******************************************************************************/

int32_t psInitPubKey(psPool_t *pool, psPubKey_t *key, uint8_t type)
{
    if (!key)
    {
        return PS_ARG_FAIL;
    }
    switch (type)
    {
# ifdef USE_RSA
    case PS_RSA:
        psRsaInitKey(pool, &key->key.rsa);
        break;
# endif
# ifdef USE_ECC
    case PS_ECC:
        psEccInitKey(pool, &key->key.ecc, NULL);
        break;
# endif
    default:
        break;
    }
    key->pool = pool;
    key->type = type;
    key->keysize = 0;
    return PS_SUCCESS;
}

/******************************************************************************/

void psClearPubKey(psPubKey_t *key)
{
    if (!key)
    {
        return;
    }
    switch (key->type)
    {
# ifdef USE_RSA
    case PS_RSA:
        psRsaClearKey(&key->key.rsa);
        break;
# endif
# ifdef USE_ECC
    case PS_ECC:
        psEccClearKey(&key->key.ecc);
        break;
# endif
# ifdef USE_DH
    case PS_DH:
        psDhClearKey(&key->key.dh);
        break;
# endif
    default:
        break;
    }
    key->pool = NULL;
    key->keysize = 0;
    key->type = 0;
}

int32_t psNewPubKey(psPool_t *pool, uint8_t type, psPubKey_t **key)
{
    int32_t rc;

    if ((*key = psMalloc(pool, sizeof(psPubKey_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }

    if ((rc = psInitPubKey(pool, *key, type)) < 0)
    {
        psFree(*key, pool);
    }
    return rc;
}

void psDeletePubKey(psPubKey_t **key)
{
    psClearPubKey(*key);
    psFree(*key, NULL);
    *key = NULL;
}

/******************************************************************************/

#endif /* USE_RSA || USE_ECC */
