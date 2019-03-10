/**
 *      @file    dh_params.c
 *      @version $Format:%h%d$
 *
 *      Diffie-Hellman: parameters
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

#if defined USE_MATRIX_DH || defined USE_CL_DH

/******************************************************************************/
/**
    Parse ASN.1 encoded DH parameters.

    DHParameter ::= SEQUENCE {
        prime INTEGER, -- p
        base INTEGER, -- g
        privateValueLength INTEGER OPTIONAL
    }

    @param pool Memory pool
    @param[in] dhBin Pointer to buffer containing ASN.1 format parameters
    @param[in] dhBinLen Length in bytes of 'dhBin'
    @param[in,out] params Allocated parameter structure to receive parsed
        params.
    @return < on error.

 */
int32_t psPkcs3ParseDhParamBin(psPool_t *pool, const unsigned char *dhBin,
    psSize_t dhBinLen, psDhParams_t *params)
{
    const unsigned char *c, *end;
    psSize_t baseLen;

    if (!params || !dhBin)
    {
        return PS_ARG_FAIL;
    }
    end = dhBin + dhBinLen;
    c = dhBin;

    if (getAsnSequence(&c, (uint16_t) (end - c), &baseLen) < 0)
    {
        return PS_PARSE_FAIL;
    }
    /* Parse the DH prime value and validate against minimum length */
    if (pstm_read_asn(pool, &c, (uint16_t) (end - c), &params->p) < 0)
    {
        goto L_ERR;
    }
    params->size = pstm_unsigned_bin_size(&params->p);
    if (params->size < (MIN_DH_BITS / 8))
    {
        psTraceIntCrypto("Unsupported DH prime size %hu\n", params->size);
        goto L_ERR;
    }
    /* The DH base parameter is typically small (usually value 2 or 5),
        so we don't validate against a minimum length */
    if (pstm_read_asn(pool, &c, (uint16_t) (end - c), &params->g) < 0)
    {
        goto L_ERR;
    }
    /* Red recommended length of private key. */
    params->x_bitlen = 0;
    if (end != c)
    {
        /* Read desired length of private key.
           (Note: currently ignored by MatrixSSL). */
        pstm_int bitlen;
        if (pstm_init_size(pool, &bitlen, 1) < 0)
        {
            goto L_ERR;
        }
        if (pstm_read_asn(pool, &c, (uint16_t) (end - c), &bitlen) < 0)
        {
            pstm_clear(&bitlen);
            goto L_ERR;
        }
        while(pstm_cmp_d(&bitlen, params->x_bitlen) == PSTM_GT)
        {
            params->x_bitlen++;
            if (params->x_bitlen > 16384)
            {
                pstm_clear(&bitlen);
                goto L_ERR;
            }
        }
        pstm_clear(&bitlen);
    }
    if (end != c)
    {
        psTraceCrypto("Unsupported DHParameter Format\n");
        goto L_ERR;
    }
    params->pool = pool;
    return PS_SUCCESS;

L_ERR:
    pstm_clear(&params->g);
    pstm_clear(&params->p);
    params->pool = NULL;
    params->size = 0;
    return PS_PARSE_FAIL;
}

/**
    Clear DH params.
    @param[out] params Pointer to allocated DH params to clear.
    @note Caller is responsible for freeing memory associated with 'params',
        if appropriate.
 */
void psPkcs3ClearDhParams(psDhParams_t *params)
{
    if (params == NULL)
    {
        return;
    }
    pstm_clear(&params->g);
    pstm_clear(&params->p);
    params->size = 0;
    params->x_bitlen = 0;
    params->pool = NULL;
}

/**
    Allocate and populate buffers for DH prime and base values.

    @param pool Memory pool
    @param[in] params DH params to export
    @param[out] pp On success, will point to an allocated memory buffer
        containing the DH params prime value.
    @param[out] pLen Pointer to value to receive length of 'pp' in bytes
    @param[out] pg On success, will point to an allocated memory buffer
        containing the DH params generator/base value.
    @param[out] gLen Pointer to value to receive length of 'pg' in bytes
    @return < 0 on failure

    @post On success, the buffers pointed to by 'pp' and 'pg' are allocated
        by this API and must be freed by the caller.
 */
int32_t psDhExportParameters(psPool_t *pool,
    const psDhParams_t *params,
    unsigned char **pp, psSize_t *pLen,
    unsigned char **pg, psSize_t *gLen)
{
    uint16_t pl, gl;
    unsigned char *p, *g;

    pl = pstm_unsigned_bin_size(&params->p);
    gl = pstm_unsigned_bin_size(&params->g);
    if ((p = psMalloc(pool, pl)) == NULL)
    {
        psError("Memory allocation error in psDhExportParameters\n");
        return PS_MEM_FAIL;
    }
    if ((g = psMalloc(pool, gl)) == NULL)
    {
        psError("Memory allocation error in psDhExportParameters\n");
        psFree(p, pool);
        return PS_MEM_FAIL;
    }
    if (pstm_to_unsigned_bin(pool, &params->p, p) < 0 ||
        pstm_to_unsigned_bin(pool, &params->g, g) < 0)
    {

        psFree(p, pool);
        psFree(g, pool);
        return PS_FAIL;
    }
    *pLen = pl;
    *gLen = gl;
    *pp = p;
    *pg = g;
    return PS_SUCCESS;
}

#endif /* USE_MATRIX_DH || USE_CL_DH */

/******************************************************************************/

