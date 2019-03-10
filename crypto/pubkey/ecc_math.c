/**
 *      @file    ecc_math.c
 *      @version $Format:%h%d$
 *
 *      Elliptic curve mathematical operations for Matrix Crypto.
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

psEccPoint_t *eccNewPoint(psPool_t *pool,
        short size);
void eccFreePoint(psEccPoint_t *p);
int32_t eccMulmod(psPool_t *pool,
        const pstm_int *k,
        const psEccPoint_t *G,
        psEccPoint_t *R,
        pstm_int *modulus,
        uint8_t map,
        pstm_int *tmp_int);
int32_t eccProjectiveAddPoint(psPool_t *pool,
        const psEccPoint_t *P,
        const psEccPoint_t *Q,
        psEccPoint_t *R,
        const pstm_int *modulus,
        const pstm_digit *mp,
        pstm_int *tmp_int);
int32_t eccMap(psPool_t *pool,
        psEccPoint_t *P,
        const pstm_int *modulus,
        const pstm_digit *mp);

static int32_t eccProjectiveDblPoint(psPool_t *pool,
        const psEccPoint_t *P,
        psEccPoint_t *R,
        const pstm_int *modulus,
        const pstm_digit *mp,
        const pstm_int *A);

/******************************************************************************/

static uint8_t get_digit_count(const pstm_int *a)
{
    return a->used;
}

static pstm_digit get_digit(const pstm_int *a, uint8_t n)
{
    return (n >= a->used) ? (pstm_digit) 0 : a->dp[n];
}

/******************************************************************************/
/**
    Perform a point multiplication
    @param[in] pool Memory pool
    @param[in] k The scalar to multiply by
    @param[in] G The base point
    @param[out] R Destination for kG
    @param modulus The modulus of the field the ECC curve is in
    @param map Boolean whether to map back to affine or not (1==map)
    @param[in,out] tmp_int Temporary scratch big integer (memory optimization)
    @return PS_SUCCESS on success, < 0 on error
 */
/* size of sliding window, don't change this! */
# define ECC_MULMOD_WINSIZE 4

int32_t eccMulmod(psPool_t *pool, const pstm_int *k, const psEccPoint_t *G,
    psEccPoint_t *R, pstm_int *modulus, uint8_t map, pstm_int *tmp_int)
{
    psEccPoint_t *tG, *M[8];      /* @note large on stack */
    int32 i, j, err;
    pstm_int mu;
    pstm_digit mp;
    unsigned long buf;
    int32 first, bitbuf, bitcpy, bitcnt, mode, digidx;

    /* init montgomery reduction */
    if ((err = pstm_montgomery_setup(modulus, &mp)) != PS_SUCCESS)
    {
        return err;
    }
    if ((err = pstm_init_size(pool, &mu, modulus->alloc)) != PS_SUCCESS)
    {
        return err;
    }
    if ((err = pstm_montgomery_calc_normalization(&mu, modulus)) != PS_SUCCESS)
    {
        pstm_clear(&mu);
        return err;
    }

    /* alloc ram for window temps */
    for (i = 0; i < 8; i++)
    {
        M[i] = eccNewPoint(pool, (G->x.used * 2) + 1);
        if (M[i] == NULL)
        {
            for (j = 0; j < i; j++)
            {
                eccFreePoint(M[j]);
            }
            pstm_clear(&mu);
            return PS_MEM_FAIL;
        }
    }

    /* make a copy of G incase R==G */
    tG = eccNewPoint(pool, G->x.alloc);
    if (tG == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* tG = G  and convert to montgomery */
    if (pstm_cmp_d(&mu, 1) == PSTM_EQ)
    {
        if ((err = pstm_copy(&G->x, &tG->x)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_copy(&G->y, &tG->y)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_copy(&G->z, &tG->z)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    else
    {
        if ((err = pstm_mulmod(pool, &G->x, &mu, modulus, &tG->x)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_mulmod(pool, &G->y, &mu, modulus, &tG->y)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_mulmod(pool, &G->z, &mu, modulus, &tG->z)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    pstm_clear(&mu);

    /* calc the M tab, which holds kG for k==8..15 */
    /* M[0] == 8G */
    if ((err = eccProjectiveDblPoint(pool, tG, M[0], modulus, &mp, tmp_int)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = eccProjectiveDblPoint(pool, M[0], M[0], modulus, &mp, tmp_int)) !=
        PS_SUCCESS)
    {
        goto done;
    }
    if ((err = eccProjectiveDblPoint(pool, M[0], M[0], modulus, &mp, tmp_int)) !=
        PS_SUCCESS)
    {
        goto done;
    }

    /* now find (8+k)G for k=1..7 */
    for (j = 9; j < 16; j++)
    {
        if ((err = eccProjectiveAddPoint(pool, M[j - 9], tG, M[j - 8], modulus,
                 &mp, tmp_int)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* setup sliding window */
    mode   = 0;
    bitcnt = 1;
    buf    = 0;
    digidx = get_digit_count(k) - 1;
    bitcpy = bitbuf = 0;
    first  = 1;

    /* perform ops */
    for (;; )
    {
        /* grab next digit as required */
        if (--bitcnt == 0)
        {
            if (digidx == -1)
            {
                break;
            }
            buf = get_digit(k, digidx);
            bitcnt = DIGIT_BIT;
            --digidx;
        }

        /* grab the next msb from the ltiplicand */
        i = (buf >> (DIGIT_BIT - 1)) & 1;
        buf <<= 1;

        /* skip leading zero bits */
        if (mode == 0 && i == 0)
        {
            continue;
        }

        /* if the bit is zero and mode == 1 then we double */
        if (mode == 1 && i == 0)
        {
            if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, tmp_int)) !=
                PS_SUCCESS)
            {
                goto done;
            }
            continue;
        }

        /* else we add it to the window */
        bitbuf |= (i << (ECC_MULMOD_WINSIZE - ++bitcpy));
        mode = 2;

        if (bitcpy == ECC_MULMOD_WINSIZE)
        {
            /* if this is the first window we do a simple copy */
            if (first == 1)
            {
                /* R = kG [k = first window] */
                if ((err = pstm_copy(&M[bitbuf - 8]->x, &R->x)) != PS_SUCCESS)
                {
                    goto done;
                }
                if ((err = pstm_copy(&M[bitbuf - 8]->y, &R->y)) != PS_SUCCESS)
                {
                    goto done;
                }
                if ((err = pstm_copy(&M[bitbuf - 8]->z, &R->z)) != PS_SUCCESS)
                {
                    goto done;
                }
                first = 0;
            }
            else
            {
                /* normal window */
                /* ok window is filled so double as required and add  */
                /* double first */
                for (j = 0; j < ECC_MULMOD_WINSIZE; j++)
                {
                    if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, tmp_int))
                        != PS_SUCCESS)
                    {
                        goto done;
                    }
                }

                /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
                if ((err = eccProjectiveAddPoint(pool, R, M[bitbuf - 8], R,
                         modulus, &mp, tmp_int)) != PS_SUCCESS)
                {
                    goto done;
                }
            }
            /* empty window and reset */
            bitcpy = bitbuf = 0;
            mode = 1;
        }
    }

    /* if bits remain then double/add */
    if (mode == 2 && bitcpy > 0)
    {
        /* double then add */
        for (j = 0; j < bitcpy; j++)
        {
            /* only double if we have had at least one add first */
            if (first == 0)
            {
                if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, tmp_int)) !=
                    PS_SUCCESS)
                {
                    goto done;
                }
            }

            bitbuf <<= 1;
            if ((bitbuf & (1 << ECC_MULMOD_WINSIZE)) != 0)
            {
                if (first == 1)
                {
                    /* first add, so copy */
                    if ((err = pstm_copy(&tG->x, &R->x)) != PS_SUCCESS)
                    {
                        goto done;
                    }
                    if ((err = pstm_copy(&tG->y, &R->y)) != PS_SUCCESS)
                    {
                        goto done;
                    }
                    if ((err = pstm_copy(&tG->z, &R->z)) != PS_SUCCESS)
                    {
                        goto done;
                    }
                    first = 0;
                }
                else
                {
                    /* then add */
                    if ((err = eccProjectiveAddPoint(pool, R, tG, R, modulus,
                             &mp, tmp_int)) !=  PS_SUCCESS)
                    {
                        goto done;
                    }
                }
            }
        }
    }

    /* map R back from projective space */
    if (map)
    {
        err = eccMap(pool, R, modulus, &mp);
    }
    else
    {
        err = PS_SUCCESS;
    }
done:

    pstm_clear(&mu);
    eccFreePoint(tG);
    for (i = 0; i < 8; i++)
    {
        eccFreePoint(M[i]);
    }
    return err;
}

int32 eccTestPoint(psPool_t *pool, psEccPoint_t *P, pstm_int *prime,
    pstm_int *b)
{
    pstm_int t1, t2;
    uint32 paDlen;
    pstm_digit *paD;
    int32 err;

    if ((err = pstm_init(pool, &t1)) < 0)
    {
        return err;
    }
    if ((err = pstm_init(pool, &t2)) < 0)
    {
        pstm_clear(&t1);
        return err;
    }
    /*  Pre-allocated digit. TODO: haven't fully explored max paDlen */
    paDlen = (prime->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        pstm_clear(&t1);
        pstm_clear(&t2);
        return PS_MEM_FAIL;
    }

    /* compute y^2 */
    if ((err = pstm_sqr_comba(pool, &P->y, &t1, paD, paDlen)) < 0)
    {
        goto error;
    }

    /* compute x^3 */
    if ((err = pstm_sqr_comba(pool, &P->x, &t2, paD, paDlen)) < 0)
    {
        goto error;
    }
    if ((err = pstm_mod(pool, &t2, prime, &t2)) < 0)
    {
        goto error;
    }

    if ((err = pstm_mul_comba(pool, &P->x, &t2, &t2, paD, paDlen)) < 0)
    {
        goto error;
    }

    /* compute y^2 - x^3 */
    if ((err = pstm_sub(&t1, &t2, &t1)) < 0)
    {
        goto error;
    }

    /* compute y^2 - x^3 + 3x */
    if ((err = pstm_add(&t1, &P->x, &t1)) < 0)
    {
        goto error;
    }
    if ((err = pstm_add(&t1, &P->x, &t1)) < 0)
    {
        goto error;
    }
    if ((err = pstm_add(&t1, &P->x, &t1)) < 0)
    {
        goto error;
    }
    if ((err = pstm_mod(pool, &t1, prime, &t1)) < 0)
    {
        goto error;
    }
    while (pstm_cmp_d(&t1, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&t1, prime, &t1)) < 0)
        {
            goto error;
        }
    }
    while (pstm_cmp(&t1, prime) != PSTM_LT)
    {
        if ((err = pstm_sub(&t1, prime, &t1)) < 0)
        {
            goto error;
        }
    }

    /* compare to b */
    if (pstm_cmp(&t1, b) != PSTM_EQ)
    {
        psTraceCrypto("Supplied EC public point not on curve\n");
        err = PS_LIMIT_FAIL;
    }
    else
    {
        err = PS_SUCCESS;
    }

error:
    psFree(paD, pool);
    pstm_clear(&t1);
    pstm_clear(&t2);
    return err;
}

/******************************************************************************/
/**
    Add two ECC points
    @param P The point to add
    @param Q The point to add
    @param[out] R The destination of the double
    @param modulus The modulus of the field the ECC curve is in
    @param mp The "b" value from montgomery_setup()
    @return PS_SUCCESS on success
 */
int32_t eccProjectiveAddPoint(psPool_t *pool, const psEccPoint_t *P,
    const psEccPoint_t *Q, psEccPoint_t *R,
    const pstm_int *modulus, const pstm_digit *mp, pstm_int *tmp_int)
{
    pstm_int t1, t2, x, y, z;
    pstm_digit *paD;
    int32 err;
    uint32 paDlen;

    paD = NULL;
    if (pstm_init_size(pool, &t1, P->x.alloc) < 0)
    {
        return PS_MEM_FAIL;
    }
    err = PS_MEM_FAIL;
    if (pstm_init_size(pool, &t2, P->x.alloc) < 0)
    {
        goto ERR_T1;
    }
    if (pstm_init_size(pool, &x, P->x.alloc) < 0)
    {
        goto ERR_T2;
    }
    if (pstm_init_size(pool, &y, P->y.alloc) < 0)
    {
        goto ERR_X;
    }
    if (pstm_init_size(pool, &z, P->z.alloc) < 0)
    {
        goto ERR_Y;
    }

    /* should we dbl instead? */
    if ((err = pstm_sub(modulus, &Q->y, &t1)) != PS_SUCCESS)
    {
        goto done;
    }

    if ((pstm_cmp(&P->x, &Q->x) == PSTM_EQ) &&
        /* (&Q->z != NULL && pstm_cmp(&P->z, &Q->z) == PSTM_EQ) && */
        (pstm_cmp(&P->z, &Q->z) == PSTM_EQ) &&
        (pstm_cmp(&P->y, &Q->y) == PSTM_EQ ||
         pstm_cmp(&P->y, &t1) == PSTM_EQ))
    {
        pstm_clear_multi(&t1, &t2, &x, &y, &z, NULL, NULL, NULL);
        return eccProjectiveDblPoint(pool, P, R, modulus, mp, tmp_int);
    }

    if ((err = pstm_copy(&P->x, &x)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&P->y, &y)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&P->z, &z)) != PS_SUCCESS)
    {
        goto done;
    }

/*
    Pre-allocated digit.  Used for mul, sqr, AND reduce*/
    paDlen = (modulus->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* if Z is one then these are no-operations */
    if (pstm_cmp_d(&Q->z, 1) != PSTM_EQ)
    {
        /* T1 = Z' * Z' */
        if ((err = pstm_sqr_comba(pool, &Q->z, &t1, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* X = X * T1 */
        if ((err = pstm_mul_comba(pool, &t1, &x, &x, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* T1 = Z' * T1 */
        if ((err = pstm_mul_comba(pool, &Q->z, &t1, &t1, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* Y = Y * T1 */
        if ((err = pstm_mul_comba(pool, &t1, &y, &y, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &y, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* T1 = Z*Z */
    if ((err = pstm_sqr_comba(pool, &z, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = X' * T1 */
    if ((err = pstm_mul_comba(pool, &Q->x, &t1, &t2, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T1 = Z * T1 */
    if ((err = pstm_mul_comba(pool, &z, &t1, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T1 = Y' * T1 */
    if ((err = pstm_mul_comba(pool, &Q->y, &t1, &t1, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* Y = Y - T1 */
    if ((err = pstm_sub(&y, &t1, &y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T1 = 2T1 */
    if ((err = pstm_add(&t1, &t1, &t1)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t1, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T1 = Y + T1 */
    if ((err = pstm_add(&t1, &y, &t1)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t1, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* X = X - T2 */
    if ((err = pstm_sub(&x, &t2, &x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&x, modulus, &x)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = 2T2 */
    if ((err = pstm_add(&t2, &t2, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t2, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = X + T2 */
    if ((err = pstm_add(&t2, &x, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t2, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* if Z' != 1 */
    if (pstm_cmp_d(&Q->z, 1) != PSTM_EQ)
    {
        /* Z = Z * Z' */
        if ((err = pstm_mul_comba(pool, &z, &Q->z, &z, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &z, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* Z = Z * X */
    if ((err = pstm_mul_comba(pool, &z, &x, &z, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &z, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* T1 = T1 * X  */
    if ((err = pstm_mul_comba(pool, &t1, &x, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* X = X * X */
    if ((err = pstm_sqr_comba(pool, &x, &x, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = T2 * x */
    if ((err = pstm_mul_comba(pool, &t2, &x, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T1 = T1 * X  */
    if ((err = pstm_mul_comba(pool, &t1, &x, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* X = Y*Y */
    if ((err = pstm_sqr_comba(pool, &y, &x, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* X = X - T2 */
    if ((err = pstm_sub(&x, &t2, &x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&x, modulus, &x)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* T2 = T2 - X */
    if ((err = pstm_sub(&t2, &x, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&t2, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = T2 - X */
    if ((err = pstm_sub(&t2, &x, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&t2, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = T2 * Y */
    if ((err = pstm_mul_comba(pool, &t2, &y, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Y = T2 - T1 */
    if ((err = pstm_sub(&t2, &t1, &y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* Y = Y/2 */
    if (pstm_isodd(&y))
    {
        if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    if ((err = pstm_div_2(&y, &y)) != PS_SUCCESS)
    {
        goto done;
    }

    if ((err = pstm_copy(&x, &R->x)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&y, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&z, &R->z)) != PS_SUCCESS)
    {
        goto done;
    }

    err = PS_SUCCESS;

done:
    pstm_clear(&z);
ERR_Y:
    pstm_clear(&y);
ERR_X:
    pstm_clear(&x);
ERR_T2:
    pstm_clear(&t2);
ERR_T1:
    pstm_clear(&t1);
    if (paD)
    {
        psFree(paD, pool);
    }
    return err;
}


/******************************************************************************/
/**
    Double an ECC point
    @param[in] P The point to double
    @param[out] R The destination of the double
    @param[in] modulus The modulus of the field the ECC curve is in
    @param[in] mp The "b" value from montgomery_setup()
    @param[in] A The "A" of the field the ECC curve is in
    @return PS_SUCCESS on success
 */
static int32_t eccProjectiveDblPoint(psPool_t *pool, const psEccPoint_t *P,
    psEccPoint_t *R, const pstm_int *modulus, const pstm_digit *mp,
    const pstm_int *A)
{
    pstm_int t1, t2;
    pstm_digit *paD;
    uint32 paDlen;
    int32 err, initSize;


    if (P != R)
    {
        if (pstm_copy(&P->x, &R->x) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (pstm_copy(&P->y, &R->y) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (pstm_copy(&P->z, &R->z) < 0)
        {
            return PS_MEM_FAIL;
        }
    }

    initSize = R->x.used;
    if (R->y.used > initSize)
    {
        initSize = R->y.used;
    }
    if (R->z.used > initSize)
    {
        initSize = R->z.used;
    }

    if (pstm_init_size(pool, &t1, (initSize * 2) + 1) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_size(pool, &t2, (initSize * 2) + 1) < 0)
    {
        pstm_clear(&t1);
        return PS_MEM_FAIL;
    }

/*
    Pre-allocated digit.  Used for mul, sqr, AND reduce*/
    paDlen = (modulus->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* t1 = Z * Z */
    if ((err = pstm_sqr_comba(pool, &R->z, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Z = Y * Z */
    if ((err = pstm_mul_comba(pool, &R->z, &R->y, &R->z, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->z, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Z = 2Z */
    if ((err = pstm_add(&R->z, &R->z, &R->z)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&R->z, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&R->z, modulus, &R->z)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* compute into T1  M=3(X+Z^2)(X-Z^2) */
    if (A == NULL)
    {
        /* T2 = X - T1 */
        if ((err = pstm_sub(&R->x, &t1, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp_d(&t2, 0) == PSTM_LT)
        {
            if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
            {
                goto done;
            }
        }
        /* T1 = X + T1 */
        if ((err = pstm_add(&t1, &R->x, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }
        /* T2 = T1 * T2 */
        if ((err = pstm_mul_comba(pool, &t1, &t2, &t2, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* T1 = 2T2 */
        if ((err = pstm_add(&t2, &t2, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }
        /* T1 = T1 + T2 */
        if ((err = pstm_add(&t1, &t2, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }
    }
    else
    {
        /* compute into T1  M=3X^2 + A Z^4 */
        pstm_int t3, t4;

        if (pstm_init_size(pool, &t3, (initSize * 2) + 1) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (pstm_init_size(pool, &t4, (initSize * 2) + 1) < 0)
        {
            pstm_clear(&t3);
            return PS_MEM_FAIL;
        }

        /* T3 = X * X */
        if ((err = pstm_sqr_comba(pool, &R->x, &t3, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t3, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }

        /* T4 = 2T3 */
        if ((err = pstm_add(&t3, &t3, &t4)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t4, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t4, modulus, &t4)) != PS_SUCCESS)
            {
                goto done;
            }
        }

        /* T3 = T3 + T4 */
        if ((err = pstm_add(&t3, &t4, &t3)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t3, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t3, modulus, &t3)) != PS_SUCCESS)
            {
                goto done;
            }
        }

        /* T4 = T1 * T1 */
        if ((err = pstm_sqr_comba(pool, &t1, &t4, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_mod(pool, &t4, modulus, &t4)) != PS_SUCCESS)
        {
            goto done;
        }

        /* T4 = T4 * A */
        if ((err = pstm_mul_comba(pool, &t4, A, &t4, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }

        if ((err = pstm_montgomery_reduce(pool, &t4, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }

        /* T1 = T3 + T4 */
        if ((err = pstm_add(&t3, &t4, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }

        pstm_clear_multi(&t3, &t4, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    /* Y = 2Y */
    if ((err = pstm_add(&R->y, &R->y, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&R->y, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&R->y, modulus, &R->y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* Y = Y * Y */
    if ((err = pstm_sqr_comba(pool, &R->y, &R->y, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = Y * Y */
    if ((err = pstm_sqr_comba(pool, &R->y, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = T2/2 */
    if (pstm_isodd(&t2))
    {
        if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    if ((err = pstm_div_2(&t2, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    /* Y = Y * X */
    if ((err = pstm_mul_comba(pool, &R->y, &R->x, &R->y, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* X  = T1 * T1 */
    if ((err = pstm_sqr_comba(pool, &t1, &R->x, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* X = X - Y */
    if ((err = pstm_sub(&R->x, &R->y, &R->x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->x, modulus, &R->x)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* X = X - Y */
    if ((err = pstm_sub(&R->x, &R->y, &R->x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->x, modulus, &R->x)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* Y = Y - X */
    if ((err = pstm_sub(&R->y, &R->x, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->y, modulus, &R->y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* Y = Y * T1 */
    if ((err = pstm_mul_comba(pool, &R->y, &t1, &R->y, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Y = Y - T2 */
    if ((err = pstm_sub(&R->y, &t2, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->y, modulus, &R->y)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    err = PS_SUCCESS;
done:
    pstm_clear_multi(&t1, &t2, NULL, NULL, NULL, NULL, NULL, NULL);
    if (paD)
    {
        psFree(paD, pool);
    }
    return err;
}

/******************************************************************************/
/**
    Allocate a new ECC point.
    @return A newly allocated point or NULL on error
 */
psEccPoint_t *eccNewPoint(psPool_t *pool, short size)
{
    psEccPoint_t *p = NULL;

    p = psMalloc(pool, sizeof(psEccPoint_t));
    if (p == NULL)
    {
        return NULL;
    }
    p->pool = pool;
    if (size == 0)
    {
        if (pstm_init(pool, &p->x) != PSTM_OKAY)
        {
            goto ERR;
        }
        if (pstm_init(pool, &p->y) != PSTM_OKAY)
        {
            goto ERR_X;
        }
        if (pstm_init(pool, &p->z) != PSTM_OKAY)
        {
            goto ERR_Y;
        }
    }
    else
    {
        if (pstm_init_size(pool, &p->x, size) != PSTM_OKAY)
        {
            goto ERR;
        }
        if (pstm_init_size(pool, &p->y, size) != PSTM_OKAY)
        {
            goto ERR_X;
        }
        if (pstm_init_size(pool, &p->z, size) != PSTM_OKAY)
        {
            goto ERR_Y;
        }
    }
    return p;
ERR_Y:
    pstm_clear(&p->y);
ERR_X:
    pstm_clear(&p->x);
ERR:
    psFree(p, pool);
    return NULL;
}

/**
    Free an ECC point from memory.
    @param p   The point to free
 */
void eccFreePoint(psEccPoint_t *p)
{
    if (p != NULL)
    {
        pstm_clear(&p->x);
        pstm_clear(&p->y);
        pstm_clear(&p->z);
        psFree(p, p->pool);
    }
}

/**
   Map a projective jacbobian point back to affine space
   @param[in,out] P [in/out] The point to map
   @param[in] modulus  The modulus of the field the ECC curve is in
   @param[in] mp       The "b" value from montgomery_setup()
   @return PS_SUCCESS on success
 */
int32_t eccMap(psPool_t *pool, psEccPoint_t *P, const pstm_int *modulus,
    const pstm_digit *mp)
{
    pstm_int t1, t2;
    pstm_digit *paD;
    int32 err;
    uint32 paDlen;

    if (pstm_init_size(pool, &t1, P->x.alloc) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_size(pool, &t2, P->x.alloc) < 0)
    {
        pstm_clear(&t1);
        return PS_MEM_FAIL;
    }

    /* Pre-allocated digit.  Used for mul, sqr, AND reduce */
    paDlen = (modulus->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* first map z back to normal */
    if ((err = pstm_montgomery_reduce(pool, &P->z, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* get 1/z */
    if ((err = pstm_invmod(pool, &P->z, modulus, &t1)) != PS_SUCCESS)
    {
        goto done;
    }

    /* get 1/z^2 and 1/z^3 */
    if ((err = pstm_sqr_comba(pool, &t1, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mod(pool, &t2, modulus, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mul_comba(pool, &t1, &t2, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mod(pool, &t1, modulus, &t1)) != PS_SUCCESS)
    {
        goto done;
    }

    /* multiply against x/y */
    if ((err = pstm_mul_comba(pool, &P->x, &t2, &P->x, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &P->x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mul_comba(pool, &P->y, &t1, &P->y, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &P->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    pstm_set(&P->z, 1);
    err = PS_SUCCESS;
done:
    pstm_clear_multi(&t1, &t2, NULL, NULL, NULL, NULL, NULL, NULL);
    if (paD)
    {
        psFree(paD, pool);
    }
    return err;
}

#endif  /* USE_MATRIX_ECC */

