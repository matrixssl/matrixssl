/**
 *      @file    ecc_priv.c
 *      @version $Format:%h%d$
 *
 *      ECDSA private key operations using Matrix Crypto.
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

/* This function uses psEccGenerateScalar in ecc_keygen.c. */
int32_t psEccGenerateScalar(psPool_t *pool, const psEccCurve_t *curve,
                            void *usrData, unsigned char **buf_p);

/**
    Sign a message digest.
    @param pool Memory pool
    @param[in] key Private ECC key
    @param[in] in The data to sign
    @param[in] inlen The length in bytes of 'in'
    @param[out] out The destination for the signature
    @param[in,out] outlen The max size and resulting size of the signature
    @param[in] includeSize Pass 1 to include size prefix in output.
    @param usrData Implementation specific data. Can pass NULL.
    @param[in] blinding Use blinding
    @return PS_SUCCESS if successful

    @note TLS does use the size prefix in output.
 */
int32_t psEccDsaSignCommon(psPool_t *pool, const psEccKey_t *privKey,
                           const unsigned char *buf, psSize_t buflen,
                           unsigned char *sig, psSize_t *siglen,
                           uint8_t includeSize, void *usrData,
                           int blinding)
{
    psEccKey_t pubKey;      /* @note Large on the stack */
    pstm_int r, s;
    pstm_int b, binv;

    pstm_int e, p;
    psSize_t radlen;
    int32_t err = PS_MEM_FAIL;
    psSize_t olen, rLen, sLen;
    uint32_t rflag, sflag, sanity;
    unsigned char *rngbuf;

    rflag = sflag = 0;

    /* is this a private key? */
    if (privKey->type != PS_PRIVKEY)
    {
        return PS_ARG_FAIL;
    }

    /* Can't sign more data than the key length.  Truncate if so */
    if (buflen > privKey->curve->size)
    {
        buflen = privKey->curve->size;
    }


    radlen = privKey->curve->size * 2;
    if (pstm_init_for_read_unsigned_bin(pool, &p, privKey->curve->size) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &e, buflen) < 0)
    {
        goto LBL_P;
    }
    if (pstm_init_size(pool, &r, p.alloc) < 0)
    {
        goto LBL_E;
    }
    if (pstm_init_size(pool, &s, p.alloc) < 0)
    {
        goto LBL_R;
    }

    if (pstm_init_for_read_unsigned_bin(pool, &b, privKey->curve->size) < 0)
    {
        goto LBL_S;
    }
    
    if (pstm_init_size(pool, &binv, privKey->curve->size) < 0)
    {
        goto LBL_B;
    }

    if ((err = pstm_read_radix(pool, &p, privKey->curve->order, radlen,
             16)) != PS_SUCCESS)
    {
        goto errnokey;
    }
    if ((err = pstm_read_unsigned_bin(&e, buf, buflen)) != PS_SUCCESS)
    {
        goto errnokey;
    }

    /* make up a key and export the public copy */
    sanity = 0;
    for (;; )
    {
        if (sanity++ > 99)
        {
            psTraceCrypto("ECC Signature sanity exceeded. Verify PRNG output.\n");
            err = PS_PLATFORM_FAIL; /* possible problem with prng */
            goto errnokey;
        }

        if (blinding)
        {
            /* Generate scalar for blinding.
               Use the same function than for generating private keys.
               The scalar will be in range [1, n-1] which is usable,
               for curves where n < p. */
            err = psEccGenerateScalar(pool, privKey->curve, usrData, &rngbuf);
            if (err != PS_SUCCESS)
            {
                goto errnokey;
            }
            if ((err = pstm_read_unsigned_bin(&b, rngbuf,
                                              privKey->curve->size)) !=
                PS_SUCCESS)
            {
                psFree(rngbuf, pool);
                goto errnokey;
            }
            psFree(rngbuf, pool);
            if ((err = pstm_invmod(pool, &b, &p, &binv)) != PS_SUCCESS)
            {
                goto errnokey; /* b = 1/b */
            }
        }

        if ((err = psEccGenKey(pool, &pubKey, privKey->curve, usrData))
            != PS_SUCCESS)
        {
            goto errnokey;
        }
        /* find r = x1 mod n */
        if ((err = pstm_mod(pool, &pubKey.pubkey.x, &p, &r)) != PS_SUCCESS)
        {
            goto error;
        }

        if (pstm_iszero(&r) == PS_TRUE)
        {
            psEccClearKey(&pubKey);
        }
        else
        {
            /* find s = (e + xr)/k */
            if ((err = pstm_invmod(pool, &pubKey.k, &p, &pubKey.k)) !=
                PS_SUCCESS)
            {
                goto error; /* k = 1/k */
            }
            if (blinding)
            {
                if ((err = pstm_mulmod(pool, &b, &r, &p, &s)) != PS_SUCCESS)
                {
                    goto error; /* s = br */
                }
            }
            else
            {
                /* If not blinding, compute as if binv == b == 1. */
                if ((err = pstm_mod(pool, &r, &p, &s)) != PS_SUCCESS)
                {
                    goto error; /* s = br (b == 1). */
                }
            }

            if (blinding)
            {
                if ((err = pstm_mulmod(pool, &e, &b, &p, &e))
                    != PS_SUCCESS)
                {
                    goto error; /* e = be */
                }
            }
            else
            {
                if ((err = pstm_mod(pool, &e, &p, &e))
                    != PS_SUCCESS)
                {
                    goto error; /* e = be */
                }
            }

            if ((err = pstm_mulmod(pool, &s, &privKey->k, &p, &s))
                != PS_SUCCESS)
            {
                goto error; /* s = bxr */
            }
            if ((err = pstm_add(&e, &s, &s)) != PS_SUCCESS)
            {
                goto error;  /* s = be + bxr */
            }
            if ((err = pstm_mod(pool, &s, &p, &s)) != PS_SUCCESS)
            {
                goto error; /* s = be + bxr */
            }
            if ((err = pstm_mulmod(pool, &s, &pubKey.k, &p, &s))
                != PS_SUCCESS)
            {
                goto error; /* s = (be + bxr)/k */
            }

            if (blinding)
            {
                if ((err = pstm_mulmod(pool, &s, &binv, &p, &s))
                    != PS_SUCCESS)
                {
                    goto error; /* s = (e + xr)/k */
                }
            }
            psEccClearKey(&pubKey);

            rLen = pstm_unsigned_bin_size(&r);
            sLen = pstm_unsigned_bin_size(&s);

            /* Signatures can be smaller than the keysize but keep it sane */
            if (((rLen + 6) >= privKey->curve->size) &&
                ((sLen + 6) >= privKey->curve->size))
            {
                if (pstm_iszero(&s) == PS_FALSE)
                {
                    break;
                }
            }
        }
    }

    /* If r or s has the high bit set, the ASN.1 encoding should include
        a leading 0x0 byte to prevent it from being "negative". */
    /* We check high bit by checking if number of bits is multiple of 8. */
    rflag = (pstm_count_bits(&r) & 7) == 0;
    sflag = (pstm_count_bits(&s) & 7) == 0;
    rLen += rflag;
    sLen += sflag;
    olen = 6 + rLen + sLen;

    /* Handle lengths longer than 128.. but still only handling up to 256 */
    if (olen - 3 >= 128)
    {
        olen++;
    }

    /* TLS uses a two byte length specifier.  Others sometimes do not */
    if (includeSize)
    {
        if (olen + 2 > *siglen)
        {
            err = -1;
            goto errnokey;
        }

        *sig = olen >> 8 & 0xFF; sig++;
        *sig = olen & 0xFF; sig++;
    }
    else
    {
        if (olen > *siglen)
        {
            err = -1;
            goto errnokey;
        }
    }

    *sig = ASN_CONSTRUCTED | ASN_SEQUENCE; sig++;

    if ((olen - 3) >= 128)
    {
        *sig = 0x81; sig++; /* high bit to indicate 'long' and low for byte count */
        *sig = (olen & 0xFF) - 3; sig++;
        *siglen = 1;
    }
    else
    {
        *sig = (olen & 0xFF) - 2; sig++;
        *siglen = 0;
    }
    *sig = ASN_INTEGER; sig++;
    *sig = rLen & 0xFF; sig++;
    if (includeSize)
    {
        *siglen += 6;
    }
    else
    {
        *siglen += 4;
    }
    if (rflag)
    {
        *sig = 0x0; sig++;
    }
    if ((err = pstm_to_unsigned_bin(pool, &r, sig)) != PSTM_OKAY)
    {
        goto errnokey;
    }
    sig += rLen - rflag;  /* Moved forward rflag already */
    *siglen += rLen;
    *sig = ASN_INTEGER; sig++;
    *sig = sLen & 0xFF; sig++;
    if (sflag)
    {
        *sig = 0x0; sig++;
    }
    if ((err = pstm_to_unsigned_bin(pool, &s, sig)) != PSTM_OKAY)
    {
        goto errnokey;
    }
    *siglen += sLen + 2;
    err = PS_SUCCESS;
    goto errnokey;

error:
    psEccClearKey(&pubKey);
errnokey:
    pstm_clear(&binv);
LBL_B:
    pstm_clear(&b);
LBL_S:
    pstm_clear(&s);
LBL_R:
    pstm_clear(&r);
LBL_E:
    pstm_clear(&e);
LBL_P:
    pstm_clear(&p);
    return err;
}

/**
    Sign a message digest.
    @param pool Memory pool
    @param[in] key Private ECC key
    @param[in] in The data to sign
    @param[in] inlen The length in bytes of 'in'
    @param[out] out The destination for the signature
    @param[in,out] outlen The max size and resulting size of the signature
    @param[in] includeSize Pass 1 to include size prefix in output.
    @param usrData Implementation specific data. Can pass NULL.
    @return PS_SUCCESS if successful

    @note TLS does use the size prefix in output.
 */
int32_t psEccDsaSign(psPool_t *pool, const psEccKey_t *privKey,
    const unsigned char *buf, psSize_t buflen,
    unsigned char *sig, psSize_t *siglen,
    uint8_t includeSize, void *usrData)
{
    /* Use ECC blinding.
       Cost of ECC blinding is around 10% signing performance. */
    static int do_blinding = 1;

    return  psEccDsaSignCommon(pool, privKey, buf, buflen, sig, siglen,
                               includeSize, usrData, do_blinding);
}
#endif /* USE_MATRIX_ECC */
