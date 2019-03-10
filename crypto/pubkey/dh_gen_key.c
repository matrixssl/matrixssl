/**
 *      @file    dh_gen_key.c
 *      @version $Format:%h%d$
 *
 *      Diffie-Hellman: Key generation.
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

#include "../cryptoImpl.h"

#ifdef USE_MATRIX_DH

/******************************************************************************/
/**
    Generate a DH key given the parameters.

 */
int32_t psDhGenKey(psPool_t *pool, psSize_t keysize,
    const unsigned char *pBin, psSize_t pLen,
    const unsigned char *gBin, psSize_t gLen,
    psDhKey_t *key, void *usrData)
{
    int32_t rc;
    pstm_int p, g;

    if (keysize > pLen)
    {
        psTraceCrypto("psDhGenKey: keysize > pLen\n");
        return PS_FAIL;
    }
    switch (pLen)
    {
    case 128:
    case 192:
    case 256:
    case 384:
    case 512:
#ifdef USE_LARGE_DH_GROUPS
    case 768:
    case 1024:
#endif
        break;
    default:
        psTraceCrypto("psDhGenKey: invalid keysize\n");
        return PS_FAIL;
    }
    /* Convert the p and g into ints and make keys */
    if ((rc = pstm_init_for_read_unsigned_bin(pool, &p, pLen)) != PS_SUCCESS)
    {
        return rc;
    }
    if ((rc = pstm_init_for_read_unsigned_bin(pool, &g, gLen)) != PS_SUCCESS)
    {
        pstm_clear(&p);
        return rc;
    }

    if ((rc = pstm_read_unsigned_bin(&p, pBin, pLen)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((rc = pstm_read_unsigned_bin(&g, gBin, gLen)) != PS_SUCCESS)
    {
        goto error;
    }

    PSDEPRECATED_START
    rc = psDhGenKeyInts(pool, keysize, &p, &g, key, usrData);
    PSDEPRECATED_END

error:
    pstm_clear(&p);
    pstm_clear(&g);
    return rc;
}

/******************************************************************************/
/**
    Does the actual key generation given p and g.

 */
# define DH_KEYGEN_SANITY    256
int32_t psDhGenKeyIntsSize(psPool_t *pool, psSize_t keysize,
                           const pstm_int *p, const pstm_int *g,
                           int privsize, psDhKey_t *key, void *usrData)
{
    unsigned char *buf = NULL;
    int32_t err, i;

    if (key == NULL)
    {
        return PS_ARG_FAIL;
    }

    /* Detect parameters with too small g. */
    if (pstm_count_bits(g) < 2)
    {
        return PS_ARG_FAIL;
    }

    if (privsize == 0)
    {
        privsize = keysize;
    }

    key->size = keysize;

    buf = psMalloc(pool, privsize);
    if (buf == NULL)
    {
        psError("malloc error in psDhMakeKey\n");
        return PS_MEM_FAIL;
    }
    if ((err = pstm_init_for_read_unsigned_bin(pool, &key->priv, privsize))
        != PS_SUCCESS)
    {
        goto error;
    }

    for (i = 0; i < DH_KEYGEN_SANITY; i++)
    {
        if ((err = psGetPrngLocked(buf, privsize, usrData)) < 0)
        {
            goto error;
        }
        /* Load the random bytes as the private key */
        if ((err = pstm_read_unsigned_bin(&key->priv, buf, privsize))
            != PS_SUCCESS)
        {
            goto error;
        }
        /* Test (1 < key < p), usually succeeds right away */
        if (pstm_cmp_d(&key->priv, 1) == PSTM_GT &&
            pstm_cmp(&key->priv, p) == PSTM_LT)
        {
            break; /* found one */
        }
    }
    if (i == DH_KEYGEN_SANITY)
    {
        psTraceCrypto("DH private key could not be generated\n");
        err = PS_PLATFORM_FAIL;
        goto error;
    }
    /* Have the private key, now calculate the public part */
    if ((err = pstm_init_size(pool, &key->pub, (p->used * 2) + 1))
        != PS_SUCCESS)
    {
        pstm_clear(&key->priv);
        goto error;
    }
    if ((err = pstm_exptmod(pool, g, &key->priv, p, &key->pub)) !=
        PS_SUCCESS)
    {
        goto error;
    }
    key->type = PS_PRIVKEY;
    err = PS_SUCCESS;
    goto done;
error:
    pstm_clear(&key->priv);
    pstm_clear(&key->pub);
done:
    if (buf)
    {
        memzero_s(buf, privsize);
        psFree(buf, pool);
    }
    return err;
}

int32_t psDhGenKeyInts(psPool_t *pool, psSize_t keysize,
                       const pstm_int *p, const pstm_int *g,
                       psDhKey_t *key, void *usrData)
{
    /* Determine suitable size for Diffie-Hellman private key. */
    int privsize;

    if (keysize >= 160 / 8 && keysize <= 1024 / 8)
    {
        privsize = 160 / 8;
    }
    else if (keysize > 1024 / 8 && keysize <= 2048 / 8)
    {
        privsize = 224 / 8;
    }
    else if (keysize > 2048 / 8 && keysize <= 3072 / 8)
    {
        privsize = 256 / 8;
    }
    else if (keysize > 3072 / 8 && keysize <= 7680 / 8)
    {
        privsize = 384 / 8;
    }
    else if (keysize > 7680 / 8)
    {
        privsize = 512 / 8;
    }
    else
    {
        privsize = keysize; /* Use full key size. */
    }

    return psDhGenKeyIntsSize(pool, keysize, p, g, privsize, key, usrData);
}

int32_t psDhGenKeyParams(psPool_t *pool, const psDhParams_t *params,
                         psDhKey_t *key, void *usrData)
{
    if (params->x_bitlen == 0)
    {
        PSDEPRECATED_START
        return psDhGenKeyInts(pool, params->size, &params->p,
                              &params->g, key, usrData);
        PSDEPRECATED_END
    }
    else
    {
        return psDhGenKeyIntsSize(pool, params->size, &params->p,
                                  &params->g, params->x_bitlen/8, key, usrData);
    }
}

#endif /* USE_MATRIX_DH */

/******************************************************************************/

