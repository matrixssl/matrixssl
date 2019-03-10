/**
 *      @file    ecc.c
 *      @version $Format:%h%d$
 *
 *      Implements ECC over Z/pZ for curve y^2 = x^3 + ax + b.
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

#ifdef USE_MATRIX_ECC

/******************************************************************************/

/* These internal functions are defined in ecc_math.c */
extern psEccPoint_t *eccNewPoint(psPool_t *pool,
        short size);
extern void eccFreePoint(psEccPoint_t *p);

/*****************************************************************************/
/**
    Initialize an ecc key, and assign the curve, if provided.
    @param[in] pool Memory pool
    @param[out] key Pointer to allocated ECC key to initialize
    @param[in] curve Curve to assign, or NULL.
    @return < 0 on failure, 0 on success.
    @note To allocate and initialize a key, use psEccNewKey().
 */
int32_t psEccInitKey(psPool_t *pool, psEccKey_t *key, const psEccCurve_t *curve)
{
    if (!key)
    {
        return PS_MEM_FAIL;
    }
    Memset(key, 0x0, sizeof(psEccKey_t));
    key->pool = pool;
    key->pubkey.pool = pool;
    key->curve = curve; /* Curve can be NULL */
    /* key->type will be set by one of the key generate/import/read functions */
    return PS_SUCCESS;
}

/**
    Clear an ECC key.
    @param[out] key Pointer to allocated ECC key to clear.
    @note Caller is responsible for freeing memory associated with key structure,
        if appropriate.
 */
void psEccClearKey(psEccKey_t *key)
{
    psAssert(key);
    /* Clear private k separately, since it may not be present */
    pstm_clear(&key->k);
    pstm_clear_multi(
        &key->pubkey.x,
        &key->pubkey.y,
        &key->pubkey.z,
        NULL, NULL, NULL, NULL, NULL);
    key->curve = NULL;
    key->pool = NULL;
    key->pubkey.pool = NULL;
    key->type = 0;
}

/**
    Allocate memory for an ECC key and initialize it.
    @param[in] pool Memory pool
    @param[out] key Pointer to unallocated ECC key to initialize. Will
    point to allocated and initialized key on successful return.
    @param[in] curve Curve to assign, or NULL.
    @return < 0 on failure, 0 on success.
 */
int32_t psEccNewKey(psPool_t *pool, psEccKey_t **key, const psEccCurve_t *curve)
{
    psEccKey_t *k;
    int32_t rc;

    if ((k = psMalloc(pool, sizeof(psEccKey_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }
    k->type = 0;
    if ((rc = psEccInitKey(pool, k, curve)) < 0)
    {
        psFree(k, pool);
        return rc;
    }
    *key = k;
    return PS_SUCCESS;
}

/* 'to' digits will be allocated here */
int32 psEccCopyKey(psEccKey_t *to, psEccKey_t *from)
{
    int32 rc;

    if (to->pool == NULL)
    {
        to->pool = from->pool;
        to->pubkey.pool = from->pubkey.pool;
    }
    else
    {
        to->pubkey.pool = to->pool;
    }
    to->curve = from->curve;
    to->type = from->type;

    /* pubkey */
    if ((rc = pstm_init_copy(to->pool, &to->pubkey.x, &from->pubkey.x, 0))
        != PSTM_OKAY)
    {
        goto error;
    }
    if ((rc = pstm_init_copy(to->pool, &to->pubkey.y, &from->pubkey.y, 0))
        != PSTM_OKAY)
    {
        goto error;
    }
    if ((rc = pstm_init_copy(to->pool, &to->pubkey.z, &from->pubkey.z, 0))
        != PSTM_OKAY)
    {
        goto error;
    }

    /* privkey */
    if (to->type == PS_PRIVKEY)
    {
        if ((rc = pstm_init_copy(to->pool, &to->k, &from->k, 0))
            != PSTM_OKAY)
        {
            goto error;
        }
    }

error:
    if (rc < 0)
    {
        psEccClearKey(from);
    }
    return rc;
}

/**
    Free memory for an ECC key and clear it.
    @param[out] key Pointer to dynamically allocated ECC key to free. Pointer
    will be cleared, freed and set to NULL on return.
 */
void psEccDeleteKey(psEccKey_t **key)
{
    psEccKey_t *k = *key;

    psEccClearKey(k);
    psFree(k, NULL);
    *key = NULL;
}

#endif  /* USE_MATRIX_ECC */

