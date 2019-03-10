/**
 *      @file    ecc_gen_shared.c
 *      @version $Format:%h%d$
 *
 *      ECC shared secret generation using Matrix Crypto.
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

#ifdef USE_MATRIX_ECC

/******************************************************************************/

# define ECC_BUF_SIZE    256

/* These internal functions are defined in ecc_math.c */
extern psEccPoint_t *eccNewPoint(psPool_t *pool,
        short size);
extern void eccFreePoint(psEccPoint_t *p);
extern int32_t eccMulmod(psPool_t *pool,
        const pstm_int *k,
        const psEccPoint_t *G,
        psEccPoint_t *R,
        pstm_int *modulus,
        uint8_t map,
        pstm_int *tmp_int);

/******************************************************************************/
/**
    Create an ECC shared secret between two keys.
    @param[in] pool Memory pool
    @param[in] private_key The private ECC key
    @param[in] public_key The public key
    @param[out] out Destination of the shared secret (Conforms to EC-DH from ANSI X9.63)
    @param[in,out] outlen The max size and resulting size of the shared secret
    @param[in,out] usrData Opaque usrData for hardware offload.
    @return PS_SUCCESS if successful
 */
int32_t psEccGenSharedSecret(psPool_t *pool,
    const psEccKey_t *private_key, const psEccKey_t *public_key,
    unsigned char *out, psSize_t *outlen,
    void *usrData)
{
    uint16_t x;
    psEccPoint_t *result;
    pstm_int *A = NULL;
    pstm_int prime;
    int32_t err;

    /* type valid? */
    if (private_key->type != PS_PRIVKEY)
    {
        return PS_ARG_FAIL;
    }
    if (public_key->curve != NULL)
    {
        if (private_key->curve != public_key->curve)
        {
            return PS_ARG_FAIL;
        }
    }

    /* make new point */
    result = eccNewPoint(pool, (private_key->k.used * 2) + 1);
    if (result == NULL)
    {
        return PS_MEM_FAIL;
    }

    if (private_key->curve->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL)
        {
            eccFreePoint(result);
            return PS_MEM_FAIL;
        }

        if (pstm_init_for_read_unsigned_bin(pool, A, private_key->curve->size) < 0)
        {
            psFree(A, pool);
            eccFreePoint(result);
            return PS_MEM_FAIL;
        }

        if ((err = pstm_read_radix(pool, A, private_key->curve->A,
                 private_key->curve->size * 2, 16))
            != PS_SUCCESS)
        {
            pstm_clear(A);
            psFree(A, pool);
            eccFreePoint(result);
            return err;
        }
    }

    if ((err = pstm_init_for_read_unsigned_bin(pool, &prime,
             private_key->curve->size))  != PS_SUCCESS)
    {
        if (A)
        {
            pstm_clear(A);
            psFree(A, pool);
        }
        eccFreePoint(result);
        return err;
    }

    if ((err = pstm_read_radix(pool, &prime, private_key->curve->prime,
             private_key->curve->size * 2, 16)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = eccMulmod(pool, &private_key->k, &public_key->pubkey, result,
             &prime, 1, A)) != PS_SUCCESS)
    {
        goto done;
    }

    x = pstm_unsigned_bin_size(&prime);
    if (*outlen < x)
    {
        *outlen = x;
        err = PS_LIMIT_FAIL;
        goto done;
    }
    Memset(out, 0, x);
    if ((err = pstm_to_unsigned_bin(pool, &result->x,
             out + (x - pstm_unsigned_bin_size(&result->x)))) != PS_SUCCESS)
    {
        goto done;
    }

    err = PS_SUCCESS;
    *outlen = x;
done:
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }
    pstm_clear(&prime);
    eccFreePoint(result);
    return err;
}

#endif  /* USE_MATRIX_ECC */

