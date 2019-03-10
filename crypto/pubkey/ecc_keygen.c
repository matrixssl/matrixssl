/**
 *      @file    ecc_keygen.c
 *      @version $Format:%h%d$
 *
 *      ECC key generation using Matrix Crypto.
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

/*****************************************************************************/
/*
   Generate scalar value between 1 and group order - 1.
   The scalar is returned in a buffer containing the value as
   unsigned char array. The value needs to be freed with psFree().
 */
int32_t psEccGenerateScalar(psPool_t *pool, const psEccCurve_t *curve,
                            void *usrData, unsigned char **buf_p)
{
    int32_t err;
    pstm_int order, rand;
    unsigned char *buf;
    psSize_t keysize, slen;
    uint32_t sanity = 0;

    /* Assumptions: curve is non-null, buf_p is non-null. */
# ifdef CRYPTO_ASSERT
    if (curve == NULL || curve->size < 16 || curve->size > 66 || buf_p == NULL)
    {
        psTraceCrypto("Bad args to psEccGenerateScalar\n");
        return PS_ARG_FAIL;
    }
# endif

    /* Note: this function assumes magnitude of p (keysize) ==
       magnitude of order,
       in other words older curves like secp160r1 cannot be used. */
    keysize = curve->size;
    slen = keysize * 2;

    /* allocate ram */
    buf = psMalloc(pool, keysize);
    if (buf == NULL)
    {
        psError("Memory allocation error in psEccGenKey\n");
        err = PS_MEM_FAIL;
        goto ERR_MEM;
    }

    /* The random number will be smaller than order. */
    if (pstm_init_for_read_unsigned_bin(pool, &order, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BUF;
    }

    if ((err = pstm_read_radix(pool, &order, curve->order, slen, 16))
        != PS_SUCCESS)
    {
        pstm_clear(&order);
        goto ERR_BUF;
    }

    /* make up random string */
RETRY_RAND:
    if (psGetPrngLocked(buf, keysize, usrData) != keysize)
    {
        err = PS_PLATFORM_FAIL;
        pstm_clear(&order);
        goto ERR_BUF;
    }

    if (pstm_init_for_read_unsigned_bin(pool, &rand, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        pstm_clear(&order);
        goto ERR_BUF;
    }

    if (keysize == 66)
    {
        /* Special case for P-521: the uppermost 7 bits should be cleared,
           as the range for the first byte is only 0x00...0x01 rather than
           0x00...0xFF as is common for all the common ECC curves. */
        buf[0] &= 0x01;
    }

    if ((err = pstm_read_unsigned_bin(&rand, buf, keysize)) != PS_SUCCESS)
    {
        pstm_clear(&order);
        pstm_clear(&rand);
        goto ERR_BUF;
    }

    /* Make sure random number is less than "order", but at least 1. */
    if (pstm_cmp_d(&rand, 1) == PSTM_LT ||
        pstm_cmp(&rand, &order) != PSTM_LT)
    {
        pstm_clear(&rand);

        if (sanity++ > 99)
        {
            psTraceCrypto("ECC sanity exceeded. Verify PRNG output.\n");
            err = PS_PLATFORM_FAIL; /* possible problem with prng */
            goto ERR_BUF;
        }
        goto RETRY_RAND;
    }
    pstm_clear(&rand);
    pstm_clear(&order);

ERR_BUF:
    if (err != PS_SUCCESS)
    {
        psFree(buf, pool);
        buf = NULL;
    }
ERR_MEM:
    *buf_p = buf;
    return err;
}

/**
    Initialize an ECC key and generate a public/private keypair for the given
    curve.
    @param pool Memory pool
    @param[out] key Uninitialized ECC key. This API will call psEccInitKey() on this key.
    @param[in] curve ECC named curve to use for key.
    @param[in] usrData User data pointer to pass to hardware implementations that use it.
    @return < 0 on failure.
 */
int32_t psEccGenKey(psPool_t *pool, psEccKey_t *key, const psEccCurve_t *curve,
    void *usrData)
{
    int32_t err;
    psSize_t keysize, slen;
    psEccPoint_t *base;
    pstm_int *A = NULL;
    pstm_int prime;
    unsigned char *buf;

    if (!key || !curve)
    {
        psTraceCrypto("Only named curves supported in psEccGenKey\n");
        return PS_UNSUPPORTED_FAIL;
    }

    base = NULL;
    psEccInitKey(pool, key, curve);
    keysize  = curve->size; /* Note, curve is non-null */
    slen = keysize * 2;

    err = psEccGenerateScalar(pool, curve, usrData, &buf);
    if (err != PS_SUCCESS)
    {
        goto ERR_KEY;
    }        
    if (key->curve->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL)
        {
            err = PS_MEM_FAIL;
            goto ERR_BUF;
        }
        if (pstm_init_for_read_unsigned_bin(pool, A, keysize) < 0)
        {
            err = PS_MEM_FAIL;
            psFree(A, pool);
            goto ERR_BUF;
        }
        if ((err = pstm_read_radix(pool, A, key->curve->A, slen, 16))
            != PS_SUCCESS)
        {
            goto ERR_A;
        }
    }

    if (pstm_init_for_read_unsigned_bin(pool, &prime, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_A;
    }

    base = eccNewPoint(pool, prime.alloc);
    if (base == NULL)
    {
        err = PS_MEM_FAIL;
        goto ERR_PRIME;
    }

    /* read in the specs for this key */
    if ((err = pstm_read_radix(pool, &prime, key->curve->prime, slen, 16))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }
    if ((err = pstm_read_radix(pool, &base->x, key->curve->Gx, slen, 16))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }
    if ((err = pstm_read_radix(pool, &base->y, key->curve->Gy, slen, 16))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }
    pstm_set(&base->z, 1);

    if (pstm_init_for_read_unsigned_bin(pool, &key->k, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if ((err = pstm_read_unsigned_bin(&key->k, buf, keysize))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }

    /* make the public key */
    if (pstm_init_size(pool, &key->pubkey.x, (key->k.used * 2) + 1) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if (pstm_init_size(pool, &key->pubkey.y, (key->k.used * 2) + 1) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if (pstm_init_size(pool, &key->pubkey.z, (key->k.used * 2) + 1) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if ((err = eccMulmod(pool, &key->k, base, &key->pubkey, &prime, 1, A)) !=
        PS_SUCCESS)
    {
        goto ERR_BASE;
    }

    key->type = PS_PRIVKEY;

    /* frees for success */
    eccFreePoint(base);
    pstm_clear(&prime);
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }
    psFree(buf, pool);
    return PS_SUCCESS;

ERR_BASE:
    eccFreePoint(base);
ERR_PRIME:
    pstm_clear(&prime);
ERR_A:
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }
ERR_BUF:
    psFree(buf, pool);
ERR_KEY:
    psEccClearKey(key);
    return err;
}

#endif  /* USE_MATRIX_ECC */

