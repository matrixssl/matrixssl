/**
 *      @file    prng.c
 *      @version $Format:%h%d$
 *
 *      Psuedo random number generation.
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

#ifdef USE_MATRIX_PRNG

# ifdef USE_MULTITHREADING
static psMutex_t prngLock;
# endif

static psRandom_t gMatrixPrng;
static short gPrngInit = 0;

/******************************************************************************/
/* One-time global prng lock creation and prng context */
void psOpenPrng(void)
{
# ifdef USE_MULTITHREADING
    psCreateMutex(&prngLock, 0);
# endif
    /* NOTE: if a PRNG is enabled, the low level psGetEntropy call can't
        have a useful userPtr context becuase there will be no session
        context at this early stage */
    psInitPrng(&gMatrixPrng, NULL);
    gPrngInit = 1;
    return;
}

/******************************************************************************/
/* One-time global prng lock destruction */
void psClosePrng(void)
{
# ifdef USE_MULTITHREADING
    psDestroyMutex(&prngLock);
# endif
    return;
}

/******************************************************************************/
/*
    Main PRNG retrieval API for Matrix based apps to lock all PRNG and entropy
    fetches
 */
int32_t psGetPrngLocked(unsigned char *bytes, psSize_t size, void *userPtr)
{
    int32_t rc;

    if (gPrngInit == 0)
    {
        return PS_FAILURE;
    }
# ifdef USE_MULTITHREADING
    psLockMutex(&prngLock);
# endif /* USE_MULTITHREADING */
    rc = psGetPrng(&gMatrixPrng, bytes, size, userPtr);
# ifdef USE_MULTITHREADING
    psUnlockMutex(&prngLock);
# endif /* USE_MULTITHREADING */
    return rc;
}

/******************************************************************************/
/*
    Priority order of PRNG algorithms and then default GetEntropy if none.
    Does an initial entropy source and reseeding
 */
int32_t psInitPrng(psRandom_t *ctx, void *userPtr)
{
# if defined(USE_FORTUNA) || defined(USE_YARROW)
    unsigned char entropyBytes[RANDOM_ENTROPY_BYTES];
    int32 rc;
# endif

    ctx->bytecount = 0;

# if defined(USE_FORTUNA) || defined(USE_YARROW)
    if ((rc = psGetEntropy(entropyBytes, RANDOM_ENTROPY_BYTES, userPtr)) < 0)
    {
        return rc;
    }
# endif

# ifdef USE_YARROW
    if ((rc = psYarrowStart(&ctx->yarrow)) < 0)
    {
        return rc;
    }
    if ((rc = psYarrowAddEntropy(entropyBytes, RANDOM_ENTROPY_BYTES,
             &ctx->yarrow)) < 0)
    {
        return rc;
    }
    if ((rc = psYarrowReseed(&ctx->yarrow)) < 0)
    {
        return rc;
    }
# endif
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Performs the read
 */
static int32_t readRandomData(psRandom_t *ctx, unsigned char *bytes, psSize_t size,
    void *userPtr)
{
#  if defined(USE_FORTUNA) || defined(USE_YARROW)
    unsigned char entropyBytes[RANDOM_ENTROPY_BYTES];
    int32 rc;
#  endif
/*
    Return random data.  The defines above control how often to add
    entropy and reseed the key.
 */
    ctx->bytecount += size;


#  ifdef USE_YARROW
    if (ctx->bytecount >= RANDOM_BYTES_BEFORE_ENTROPY)
    {
        ctx->bytecount = 0;
        if ((rc = psGetEntropy(entropyBytes, RANDOM_ENTROPY_BYTES, userPtr))
            < 0)
        {
            return rc;
        }
        if ((rc = psYarrowAddEntropy(entropyBytes, RANDOM_ENTROPY_BYTES,
                 &ctx->yarrow)) < 0)
        {
            return rc;
        }
        if ((rc = psYarrowReseed(&ctx->yarrow)) < 0)
        {
            return rc;
        }
    }
    return psYarrowRead(bytes, size, &ctx->yarrow);
#  endif
/*
    If no PRNG algorithms defined, default to the low level GetEntropy function
    for all the randomness
 */
    return psGetEntropy(bytes, size, userPtr);
}

/******************************************************************************/
/*
    Allow NULL context if caller is just doing a single read
 */
int32_t psGetPrng(psRandom_t *ctx, unsigned char *bytes, psSize_t size,
    void *userPtr)
{
    psRandom_t lctx;

    if (ctx == NULL)
    {
        psInitPrng(&lctx, userPtr);
        return readRandomData(&lctx, bytes, size, userPtr);
    }
    return readRandomData(ctx, bytes, size, userPtr);
}

#endif /* USE_MATRIX_PRNG */

/******************************************************************************/

