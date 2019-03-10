/**
 *      @file    ecc_pub.c
 *      @version $Format:%h%d$
 *
 *      ECDSA public key operations for Matrix Crypto.
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
extern int32_t eccProjectiveAddPoint(psPool_t *pool,
        const psEccPoint_t *P,
        const psEccPoint_t *Q,
        psEccPoint_t *R,
        const pstm_int *modulus,
        const pstm_digit *mp,
        pstm_int *tmp_int);
extern int32_t eccMap(psPool_t *pool,
        psEccPoint_t *P,
        const pstm_int *modulus,
        const pstm_digit *mp);

/******************************************************************************/
/**
    Verify an ECDSA signature.

    @param pool Memory pool
    @param[in] key Public key to use for signature validation
    @param[in] buf Data that is signed by private 'key'
    @param[in] buflen Length in bytes of 'buf'
    @param[in] sig Signature of 'buf' by the private key pair of 'key'
    @param[in] siglen Length in bytes of 'sig'
    @param[out] status Result of the signature check. 1 on success, -1 on
        non-matching signature.
    @param usrData Data used by some hardware crypto. Can be NULL.
    @return < 0 on failure. Also 'status'.
 */
int32_t psEccDsaVerify(psPool_t *pool, const psEccKey_t *key,
    const unsigned char *buf, psSize_t buflen,
    const unsigned char *sig, psSize_t siglen,
    int32_t *status, void *usrData)
{
    psEccPoint_t *mG, *mQ;
    pstm_digit mp;
    pstm_int *A = NULL;
    pstm_int v, w, u1, u2, e, p, m, r, s;
    const unsigned char *c, *end;
    int32_t err, radlen;
    psSize_t len;

    /* default to invalid signature */
    *status = -1;

    c = sig;
    end = c + siglen;

    if ((err = getAsnSequence(&c, (uint16_t) (end - c), &len)) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 1\n");
        return err;
    }
    if ((err = pstm_read_asn(pool, &c, (uint16_t) (end - c), &r)) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 2\n");
        return err;
    }
    if ((err = pstm_read_asn(pool, &c, (uint16_t) (end - c), &s)) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 3\n");
        pstm_clear(&r);
        return err;
    }

    /* allocate ints */
    radlen = key->curve->size * 2;
    if (pstm_init_for_read_unsigned_bin(pool, &p, key->curve->size) < 0)
    {
        pstm_clear(&s);
        pstm_clear(&r);
        return PS_MEM_FAIL;
    }
    err = PS_MEM_FAIL;
    if (pstm_init_for_read_unsigned_bin(pool, &m, key->curve->size) < 0)
    {
        goto LBL_P;
    }
    if (pstm_init_size(pool, &v, key->pubkey.x.alloc) < 0)
    {
        goto LBL_M;
    }
    if (pstm_init_size(pool, &w, s.alloc) < 0)
    {
        goto LBL_V;
    }
    /* Shouldn't have signed more data than the key length.  Truncate if so */
    if (buflen > key->curve->size)
    {
        buflen = key->curve->size;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &e, buflen) < 0)
    {
        goto LBL_W;
    }
    if (pstm_init_size(pool, &u1, e.alloc + w.alloc) < 0)
    {
        goto LBL_E;
    }
    if (pstm_init_size(pool, &u2, r.alloc + w.alloc) < 0)
    {
        goto LBL_U1;
    }

    /* allocate points */
    if ((mG = eccNewPoint(pool, key->pubkey.x.alloc * 2)) == NULL)
    {
        goto LBL_U2;
    }
    if ((mQ = eccNewPoint(pool, key->pubkey.x.alloc * 2)) == NULL)
    {
        goto LBL_MG;
    }

    /* get the order */
    if ((err = pstm_read_radix(pool, &p, key->curve->order, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }

    /* get the modulus */
    if ((err = pstm_read_radix(pool, &m, key->curve->prime, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }

    /* check for zero */
    if (pstm_iszero(&r) || pstm_iszero(&s) || pstm_cmp(&r, &p) != PSTM_LT ||
        pstm_cmp(&s, &p) != PSTM_LT)
    {
        err = PS_PARSE_FAIL;
        goto error;
    }

    /* read data */
    if ((err = pstm_read_unsigned_bin(&e, buf, buflen)) != PS_SUCCESS)
    {
        goto error;
    }

    /*  w  = s^-1 mod n */
    if ((err = pstm_invmod(pool, &s, &p, &w)) != PS_SUCCESS)
    {
        goto error;
    }

    /* u1 = ew */
    if ((err = pstm_mulmod(pool, &e, &w, &p, &u1)) != PS_SUCCESS)
    {
        goto error;
    }

    /* u2 = rw */
    if ((err = pstm_mulmod(pool, &r, &w, &p, &u2)) != PS_SUCCESS)
    {
        goto error;
    }

    /* find mG and mQ */
    if ((err = pstm_read_radix(pool, &mG->x, key->curve->Gx, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_read_radix(pool, &mG->y, key->curve->Gy, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }
    pstm_set(&mG->z, 1);

    if ((err = pstm_copy(&key->pubkey.x, &mQ->x)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_copy(&key->pubkey.y, &mQ->y)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_copy(&key->pubkey.z, &mQ->z)) != PS_SUCCESS)
    {
        goto error;
    }

    if (key->curve->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL)
        {
            goto error;
        }

        if (pstm_init_for_read_unsigned_bin(pool, A, key->curve->size) < 0)
        {
            goto error;
        }

        if ((err = pstm_read_radix(pool, A, key->curve->A,
                 key->curve->size * 2, 16))
            != PS_SUCCESS)
        {
            goto error;
        }
    }

    /* compute u1*mG + u2*mQ = mG */
    if ((err = eccMulmod(pool, &u1, mG, mG, &m, 0, A)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = eccMulmod(pool, &u2, mQ, mQ, &m, 0, A)) != PS_SUCCESS)
    {
        goto error;
    }

    /* find the montgomery mp */
    if ((err = pstm_montgomery_setup(&m, &mp)) != PS_SUCCESS)
    {
        goto error;
    }

    /* add them */
    if ((err = eccProjectiveAddPoint(pool, mQ, mG, mG, &m, &mp, A)) != PS_SUCCESS)
    {
        goto error;
    }

    /* reduce */
    if ((err = eccMap(pool, mG, &m, &mp)) != PS_SUCCESS)
    {
        goto error;
    }

    /* v = X_x1 mod n */
    if ((err = pstm_mod(pool, &mG->x, &p, &v)) != PS_SUCCESS)
    {
        goto error;
    }

    /* does v == r */
    if (pstm_cmp(&v, &r) == PSTM_EQ)
    {
        *status = 1;
    }

    /* clear up and return */
    err = PS_SUCCESS;

error:
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }

    eccFreePoint(mQ);
LBL_MG:
    eccFreePoint(mG);
LBL_U2:
    pstm_clear(&u2);
LBL_U1:
    pstm_clear(&u1);
LBL_E:
    pstm_clear(&e);
LBL_W:
    pstm_clear(&w);
LBL_V:
    pstm_clear(&v);
LBL_M:
    pstm_clear(&m);
LBL_P:
    pstm_clear(&p);
    pstm_clear(&s);
    pstm_clear(&r);
    return err;
}

#endif  /* USE_MATRIX_ECC */

