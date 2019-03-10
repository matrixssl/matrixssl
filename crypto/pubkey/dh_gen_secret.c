/**
 *      @file    dh_gen_secret.c
 *      @version $Format:%h%d$
 *
 *      Diffie-Hellman: Secret generation.
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
    Create secret value using DH, such as TLS premaster secret.
    The result out will have any initial zero bytes removed, just like
    TLS 1.0-1.2 is intended to work.

    @param[in] privKey     The private DH key in the pair
    @param[in] pubKey      The public DH key in the pair
    @param[in] pBin        The DH Param Prime value
    @param[in] pBinLen     The length in bytes if 'pBin'
    @param[out] out        Buffer to write the shared secret
    @param[in,out] outlen  On input, the available space in 'out', on
        successful return, the number of bytes written to 'out'.
 */
int32_t psDhGenSharedSecret(psPool_t *pool,
    const psDhKey_t *privKey, const psDhKey_t *pubKey,
    const unsigned char *pBin, psSize_t pBinLen,
    unsigned char *out, psSize_t *outlen, void *usrData)
{
    pstm_int tmp, p;
    uint16_t x;
    int32_t err;

    /* Verify the privKey is a private type. pubKey param can be either */
    if (privKey->type != PS_PRIVKEY)
    {
        psTraceCrypto("Bad private key format for DH premaster\n");
        return PS_ARG_FAIL;
    }

    /* compute y^x mod p */
    if ((err = pstm_init(pool, &tmp)) != PS_SUCCESS)
    {
        return err;
    }
    if ((err = pstm_init_for_read_unsigned_bin(pool, &p, pBinLen)) != PS_SUCCESS)
    {
        return err;
    }

    if ((err = pstm_read_unsigned_bin(&p, pBin, pBinLen)) != PS_SUCCESS)
    {
        goto error;
    }

    /* Check key->pub is within correct range 2 <= pub < p - 1. */
    if (pstm_count_bits(&pubKey->pub) < 2)
    {
        err = PS_FAILURE;
        goto error;
    }
    if ((err = pstm_add_d(pool, &pubKey->pub, 1, &tmp)) != PSTM_OKAY)
    {
        goto error;
    }
    if (pstm_cmp(&p, &tmp) != PSTM_GT)
    {
        err = PS_FAILURE;
        goto error;
    }

    if ((err = pstm_exptmod(pool, &pubKey->pub, &privKey->priv, &p,
             &tmp)) != PS_SUCCESS)
    {
        goto error;
    }

    /* enough space for output? */
    x = (unsigned long) pstm_unsigned_bin_size(&tmp);
    if (*outlen < x)
    {
        psTraceCrypto("Overflow in DH shared secret generation\n");
        err = PS_LIMIT_FAIL;
        goto error;
    }

    /* It is possible to have a key size smaller than we expect */
    *outlen = x;
    if ((err = pstm_to_unsigned_bin(pool, &tmp, out)) < 0)
    {
        goto error;
    }

    err = PS_SUCCESS;
error:
    pstm_clear(&p);
    pstm_clear(&tmp);
    return err;
}

int32_t psDhGenSharedSecretParams(
        psPool_t *pool,
        const psDhKey_t *privKey, const psDhKey_t *pubKey,
        const psDhParams_t *params,
        unsigned char *out, psSize_t *outlen, void *usrData)
{
    unsigned char *bin_p;
    psSize_t bin_p_len;
    int32_t res = PS_MEM_FAIL;

    bin_p = pstm_to_unsigned_bin_alloc(pool, &params->p);
    if (bin_p)
    {
        bin_p_len = pstm_unsigned_bin_size(&params->p);
        res = psDhGenSharedSecret(pool, privKey, pubKey,
                                  bin_p, bin_p_len, out, outlen,
                                  usrData);
        psFree(bin_p, pool);
    }

    return res;
}

#endif /* USE_MATRIX_DH */

/******************************************************************************/

