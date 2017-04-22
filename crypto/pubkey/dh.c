/**
 *      @file    dh.c
 *      @version $Format:%h%d$
 *
 *      Diffie-Hellman.
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

#ifdef USE_MATRIX_DH

/******************************************************************************/

void psDhClearKey(psDhKey_t *key)
{
    psAssert(key);
    pstm_clear(&key->priv);
    pstm_clear(&key->pub);
    key->type = 0;
}

psSize_t psDhSize(const psDhKey_t *key)
{
    return key->size;
}

/******************************************************************************/
/**
    Parse ASN.1 encoded DH parameters.

    DHParameter ::= SEQUENCE {
        prime INTEGER, -- p
        base INTEGER, -- g
        privateValueLength INTEGER OPTIONAL
    }
    @note privateValueLength field unsupported

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

/******************************************************************************/
/**
    Import a public DH key in raw (wire) format to a psDhKey_t struct.

    @param pool Memory pool
    @param[in] in Pointer to buffer containing raw public DH key
    @param[in] inlen Length in bytes of 'in'
    @param[out] key Pointer to allocated key to be initialized with raw
        DH value from 'in'.
    @return < on failure
 */
int32_t psDhImportPubKey(psPool_t *pool,
    const unsigned char *in, psSize_t inlen,
    psDhKey_t *key)
{
    int32_t rc;

    memset(&key->priv, 0, sizeof(key->priv));
    if ((rc = pstm_init_for_read_unsigned_bin(pool, &key->pub, inlen)) < 0)
    {
        return rc;
    }
    if ((rc = pstm_read_unsigned_bin(&key->pub, in, inlen)) < 0)
    {
        pstm_clear(&key->pub);
        return rc;
    }
    key->size = inlen;
    key->type = PS_PUBKEY;
    return PS_SUCCESS;
}

/**
    Export a public psDhKey_t struct to a raw binary format.

    @param pool Memory pool
    @param[in] key Pointer to DH key to export
    @param[out] out Pointer to buffer to write raw public DH key
    @param[in,out] outlen On input, the number of bytes available in 'out',
        on successful return, the number of bytes written to 'out'.
    @return < on failure
 */
int32_t psDhExportPubKey(psPool_t *pool, const psDhKey_t *key,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char *c;
    int16_t pad;
    int32_t rc;

    if (*outlen < key->size)
    {
        return PS_ARG_FAIL;
    }
    c = out;
    pad = key->size - pstm_unsigned_bin_size(&key->pub);
    if (pad > 0)
    {
        memset(c, 0x0, pad);
        c += pad;
    }
    else if (pad < 0)
    {
        return PS_FAIL;
    }
    if ((rc = pstm_to_unsigned_bin(pool, &key->pub, c)) < 0)
    {
        return rc;
    }
    *outlen = key->size;
    return PS_SUCCESS;
}


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

    rc = psDhGenKeyInts(pool, keysize, &p, &g, key, usrData);

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
int32_t psDhGenKeyInts(psPool_t *pool, psSize_t keysize,
    const pstm_int *p, const pstm_int *g,
    psDhKey_t *key, void *usrData)
{
    unsigned char *buf = NULL;
    int32_t err, i;
    psSize_t privsize;

    if (key == NULL)
    {
        return PS_ARG_FAIL;
    }

    /* Detect parameters with too small g. */
    if (pstm_count_bits(g) < 2)
    {
        return PS_ARG_FAIL;
    }

    privsize = keysize;
# ifndef USE_LARGE_DH_PRIVATE_KEYS
/*
    The mapping between DH prime field size and key size follows
    NIST SP 800-57 Part 1 for the common sizes, and for unusual
    sizes the key size is intentionally rounded up.
    The private key size must never be larger than prime size.
 */
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
    else if (keysize > 7680 / 8 && keysize <= 15360 / 8)
    {
        privsize = 256 / 8;
    }
# endif /* USE_LARGE_DH_PRIVATE_KEYS */

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

/******************************************************************************/
/**
    Create the DH premaster secret.
    @param[in] privKey  The private DH key in the pair
    @param[in] pubKey   The public DH key in the pair
    @param[in] pBin             The DH Param Prime value
    @param[in] pBinLen  The length in bytes if 'pBin'
    @param[out] out             Buffer to write the shared secret
    @param[in,out] outlen       On input, the available space in 'out', on
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
        psTraceCrypto("Overflow in DH premaster generation\n");
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

#endif /* USE_MATRIX_DH */

/******************************************************************************/

