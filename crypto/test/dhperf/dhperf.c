/**
 *      @file    dhperf.c
 *      @version $Format:%h%d$
 *
 *      DH performance testing  .
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
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#include "osdep_stdio.h"
#include "crypto/cryptoImpl.h"

#ifdef USE_DH

/******************************************************************************/

/* OPS TO PERFORM */
# define DO_GEN_INTS
# define DO_GEN_SECRET

/* DH SIZES */
# define DO_1024
# define DO_2048
# define DO_4096

/* NUMBER OF OPERATIONS */
# define ITER 30

# define PS_OH (sizeof(psPool_t) + 1024) /* TODO - remove the 1024 overhead */

/*
    Tuned to smallest K for each key size and optimization setting
 */
# ifdef PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#  define POOL_GEN_SECRET_1024    (3 * 1024) + PS_OH
#  define POOL_GEN_INTS_1024      (3 * 1024) + PS_OH
#  define POOL_MISC_1024          (4 * 1024) + PS_OH
#  define POOL_GEN_SECRET_2048    (5 * 1024) + PS_OH
#  define POOL_GEN_INTS_2048      (5 * 1024) + PS_OH
#  define POOL_MISC_2048          (7 * 1024) + PS_OH
#  define POOL_GEN_SECRET_4096    (8 * 1024) + PS_OH
#  define POOL_GEN_INTS_4096      (8 * 1024) + PS_OH
#  define POOL_MISC_4096          (10 * 1024) + PS_OH

# else /* PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED */

#  define POOL_GEN_SECRET_1024    (6 * 1024) + PS_OH
#  define POOL_GEN_INTS_1024      (6 * 1024) + PS_OH
#  define POOL_MISC_1024          (7 * 1024) + PS_OH
#  define POOL_GEN_SECRET_2048    (11 * 1024) + PS_OH
#  define POOL_GEN_INTS_2048      (11 * 1024) + PS_OH
#  define POOL_MISC_2048          (13 * 1024) + PS_OH
#  define POOL_GEN_SECRET_4096    (20 * 1024) + PS_OH
#  define POOL_GEN_INTS_4096      (20 * 1024) + PS_OH
#  define POOL_MISC_4096          (24 * 1024) + PS_OH
# endif

# ifdef DO_1024
#  include "testkeys/DH/1024_DH_PARAMS.h"
# endif
# ifdef DO_2048
#  include "testkeys/DH/2048_DH_PARAMS.h"
# endif
# ifdef DO_4096
#  include "testkeys/DH/4096_DH_PARAMS.h"
# endif

typedef struct
{
    char *name;
    const unsigned char *key;
    uint32 len;
    int32 iter;
    int32 poolSecret;
    int32 poolInts;
    int32 poolMisc;
} keyList_t;

# ifdef USE_HIGHRES_TIME
#  define psDiffMsecs(A, B, C) psDiffUsecs(A, B)
#  define TIME_UNITS "    %lld usecs"
# else
#  define TIME_UNITS "    %d msecs"
# endif

/*
    Add an iteration count so we don't have to run the large keys so many times
 */
static keyList_t keys[] = {
# ifdef DO_1024
    { "dh1024", DHPARAM1024, DHPARAM1024_SIZE, ITER,
      POOL_GEN_SECRET_1024, POOL_GEN_INTS_1024, POOL_MISC_1024 },
# endif
# ifdef DO_2048
    { "dh2048", DHPARAM2048, DHPARAM2048_SIZE, ITER,
      POOL_GEN_SECRET_2048, POOL_GEN_INTS_2048, POOL_MISC_2048 },
# endif
# ifdef DO_2048
    { "dh4096", DHPARAM4096, DHPARAM4096_SIZE, ITER,
      POOL_GEN_SECRET_4096, POOL_GEN_INTS_4096, POOL_MISC_4096 },
# endif
    { NULL }    /* Terminate the list */
};

/******************************************************************************/
/*
    Main
 */

int main(int argc, char **argv)
{
    psPool_t *pool, *misc;
    psDhParams_t dhParams;
    psDhKey_t dhKeyPriv, dhKeyPub;
    psSize_t pLen, gLen;
    unsigned char *p, *g;
    psTime_t start, end;
    uint16_t iter, i = 0;
    unsigned char out[512];
    psSize_t outLen = sizeof(out);

    pool = misc = NULL;
    if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS)
    {
        _psTrace("Failed to initialize library:  psCryptoOpen failed\n");
        return -1;
    }
    _psTraceStr("STARTING DHPERF\n", NULL);

    while (keys[i].key != NULL)
    {
        _psTraceStr("Test %s...\n", keys[i].name);
        psPkcs3ParseDhParamBin(misc, (unsigned char *) keys[i].key,   keys[i].len,
            &dhParams);

        iter = 0;

# ifdef DO_GEN_INTS
        psGetTime(&start, NULL);
        while (iter < keys[i].iter)
        {
            if (psDhGenKeyParams(pool, &dhParams, &dhKeyPriv, NULL) < 0)
            {
                _psTrace("	FAILED OPERATION\n");
            }

            psDhClearKey(&dhKeyPriv);
            iter++;
        }
        psGetTime(&end, NULL);
        _psTraceInt(TIME_UNITS " genInts\n", psDiffMsecs(start, end, NULL));
# endif /* DO_GEN_INTS */

# ifdef DO_GEN_SECRET
        psDhExportParameters(misc, &dhParams, &p, &pLen, &g, &gLen);
        if (p == NULL || g == NULL)
        {
            _psTrace("	DH parameters could not be used\n");
            Fprintf(stderr, "FAIL: DH parameters did not work.\n");
            exit(1);
        }
        if (psDhGenKeyParams(misc, &dhParams, &dhKeyPriv, NULL) < 0)
        {
            _psTrace("	FAILED OPERATION\n");
        }
        if (psDhGenKeyParams(misc, &dhParams, &dhKeyPub, NULL) < 0)
        {
            _psTrace("	FAILED OPERATION\n");
        }
        iter = 0;
        outLen = sizeof(out);
        psGetTime(&start, NULL);
        while (iter < keys[i].iter)
        {
            if (psDhGenSharedSecretParams(pool, &dhKeyPriv, &dhKeyPub,
                                          &dhParams, out, &outLen, NULL) < 0)
            {
                _psTrace("	FAILED OPERATION\n");
            }

            iter++;
        }
        psGetTime(&end, NULL);
        psDhClearKey(&dhKeyPriv);
        psDhClearKey(&dhKeyPub);
        _psTraceInt(TIME_UNITS " genSecret\n", psDiffMsecs(start, end, NULL));
# endif /* DO_GEN_SECRET */

        psFreeAndClear(&p, misc);
        psFreeAndClear(&g, misc);
        psPkcs3ClearDhParams(&dhParams);
        i++;
    }

# ifdef WIN32
    _psTrace("Press any key to close");
    getchar();
# endif
    _psTraceStr("FINISHED DHPERF\n", NULL);
    psCryptoClose();
    return 0;
}

#else

/* Stub main */
# include "osdep_stdio.h"

int main(int argc, char **argv)
{
    Printf("USE_DH not defined.\n");
    return 0;
}

#endif /* USE_DH */
