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

/* These internal functions are defined in ecc_math.c */
extern int32 eccTestPoint(psPool_t *pool,
        psEccPoint_t *P,
        pstm_int *prime,
        pstm_int *b);

/******************************************************************************/

/**
    ANSI X9.62 or X9.63 (Section 4.3.7) uncompressed import.
    This function imports the public ECC key elements (the x, y and z values).
    If a private 'k' value is defined, the public elements are added to the
        key. Otherwise, only the public elements are loaded and the key
        marked public.
    The format of import is ASN.1, and is used both within certificate
    parsing and when parsing public keys passed on the wire in TLS.

    @param[in] pool Memory pool
    @param[in] in ECC key data in uncompressed form
    @param[in] inlen Length of destination and final output size
    @param[in, out] key Key to import. Private keys types will not be
    initialized, all others will.
    @param[in] curve Curve parameters, may be NULL
    @return PS_SUCCESS on success, < 0 on failure
 */
int32_t psEccX963ImportKey(psPool_t *pool,
    const unsigned char *in, psSize_t inlen,
    psEccKey_t *key, const psEccCurve_t *curve)
{
    int32_t err;
    pstm_int prime, b;

    /* Must be odd and minimal size */
    if (inlen < ((2 * (MIN_ECC_BITS / 8)) + 1) || (inlen & 1) == 0)
    {
        return PS_ARG_FAIL;
    }

    /* The key passed in may be a private key that is already initialized
       and the 'k' parameter set. */
    if (key->type != PS_PRIVKEY)
    {
        if (psEccInitKey(pool, key, curve) < 0)
        {
            return PS_MEM_FAIL;
        }
        key->type = PS_PUBKEY;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &key->pubkey.x,
            (inlen - 1) >> 1) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &key->pubkey.y,
            (inlen - 1) >> 1) < 0)
    {
        pstm_clear(&key->pubkey.x);
        return PS_MEM_FAIL;
    }
    if (pstm_init_size(pool, &key->pubkey.z, 1) < 0)
    {
        pstm_clear(&key->pubkey.x);
        pstm_clear(&key->pubkey.y);
        return PS_MEM_FAIL;
    }

    switch (*in)
    {
    /* Standard, supported format */
    case ANSI_UNCOMPRESSED:
        break;
    /* Unsupported formats */
    case ANSI_COMPRESSED0:
    case ANSI_COMPRESSED1:
    case ANSI_HYBRID0:
    case ANSI_HYBRID1:
    default:
        psTraceCrypto("ERROR: ECC compressed/hybrid formats unsupported\n");
        err = PS_UNSUPPORTED_FAIL;
        goto error;
    }
    if ((err = pstm_read_unsigned_bin(&key->pubkey.x, (unsigned char *) in + 1,
             (inlen - 1) >> 1)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_read_unsigned_bin(&key->pubkey.y,
             (unsigned char *) in + 1 + ((inlen - 1) >> 1),
             (inlen - 1) >> 1)) != PS_SUCCESS)
    {
        goto error;
    }
    pstm_set(&key->pubkey.z, 1);

    /* Validate the point is on the curve */
    if (curve != NULL && curve->isOptimized)
    {
        if ((err = pstm_init_for_read_unsigned_bin(pool, &prime, curve->size)) < 0)
        {
            goto error;
        }
        if ((err = pstm_init_for_read_unsigned_bin(pool, &b, curve->size)) < 0)
        {
            pstm_clear(&prime);
            goto error;
        }
        if ((err = pstm_read_radix(pool, &prime, curve->prime,
                 curve->size * 2, 16)) < 0)
        {
            pstm_clear(&prime);
            pstm_clear(&b);
            goto error;
        }

        if ((err = pstm_read_radix(pool, &b, curve->B, curve->size * 2, 16)) < 0)
        {
            pstm_clear(&prime);
            pstm_clear(&b);
            goto error;
        }
        if ((err = eccTestPoint(pool, &key->pubkey, &prime, &b)) < 0)
        {
            pstm_clear(&prime);
            pstm_clear(&b);
            goto error;
        }
        pstm_clear(&prime);
        pstm_clear(&b);
    }
    else
    {
        psTraceCrypto("WARNING: ECC public key not validated\n");
    }

    return PS_SUCCESS;

error:
    psEccClearKey(key);
    return err;
}

#endif  /* USE_MATRIX_ECC */

