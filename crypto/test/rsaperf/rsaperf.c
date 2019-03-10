/**
 *      @file    rsaperf.c
 *      @version $Format:%h%d$
 *
 *      RSA performance testing.
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

#ifndef NEED_PS_TIME_CONCRETE
# define NEED_PS_TIME_CONCRETE
#endif

#include "osdep_stdio.h"
#include "osdep_unistd.h" /* sleep */
#include "crypto/cryptoImpl.h"
#include "osdep-types.h"

#if defined(USE_RSA) && defined(USE_PRIVATE_KEY_PARSING)

typedef void pkaCmdInfo_t;

/* OPERATIONS TO TEST */
# define SIGN_OP    /* Private encrypt operations */
# define VERIFY_OP  /* Public decrypt operations */

# define ENCRYPT_OP /* Public encrypt operations */
# define DECRYPT_OP /* Private decrypt operations */

/* KEY SIZES TO TEST */
# if (MIN_RSA_BITS <= 512)
#  define DO_512
# endif
# if (MIN_RSA_BITS <= 1024)
#  define DO_1024
# endif
# if (MIN_RSA_BITS <= 2048)
#  define DO_2048
# endif
# if (MIN_RSA_BITS <= 4096)
#  define DO_4096
# endif

/* NUMBER OF ENCRYPTION OPERATIONS TO AVERAGE FOR EACH KEY LEN */
# if defined(PSTM_64BIT)
#  define ITER_512    512
#  define ITER_1024   256
#  define ITER_2048   128
#  define ITER_4096   64
# elif defined(PSTM_32BIT)
#  define ITER_512    256
#  define ITER_1024   128
#  define ITER_2048   64
#  define ITER_4096   32
# else
#  define ITER_512    16
#  define ITER_1024   8
#  define ITER_2048   4
#  define ITER_4096   2
# endif

/* Another pass with different keys */
/* #define INCLUDE_SECOND_SET */

# define PS_OH (sizeof(psPool_t))

/*
    Tuned to smallest K for each key size and optimization setting.
    Private key operations take about 1/2 the RAM when optimized for size
 */
# ifdef PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#  define POOL_SIGN_512       (1 * 1024) + PS_OH
#  define POOL_VERIFY_512     (2 * 1024) + PS_OH
#  define POOL_ENCRYPT_512    (2 * 1024) + PS_OH
#  define POOL_DECRYPT_512    (1 * 1024) + PS_OH
#  define POOL_MISC_512       (3 * 1024) + PS_OH

#  define POOL_SIGN_1024      (2 * 1024) + PS_OH
#  define POOL_VERIFY_1024    (3 * 1024) + PS_OH
#  define POOL_ENCRYPT_1024   (3 * 1024) + PS_OH
#  define POOL_DECRYPT_1024   (2 * 1024) + PS_OH
#  define POOL_MISC_1024      (4 * 1024) + PS_OH

#  define POOL_SIGN_2048      (3 * 1024) + PS_OH
#  define POOL_VERIFY_2048    (5 * 1024) + PS_OH
#  define POOL_ENCRYPT_2048   (5 * 1024) + PS_OH
#  define POOL_DECRYPT_2048   (3 * 1024) + PS_OH
#  define POOL_MISC_2048      (7 * 1024) + PS_OH

#  define POOL_SIGN_4096      (6 * 1024) + PS_OH
#  define POOL_VERIFY_4096    (8 * 1024) + PS_OH
#  define POOL_ENCRYPT_4096   (8 * 1024) + PS_OH
#  define POOL_DECRYPT_4096   (6 * 1024) + PS_OH
#  define POOL_MISC_4096      (12 * 1024) + PS_OH

# else /* PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED */

#  define POOL_SIGN_512       (3 * 1024) + PS_OH
#  define POOL_VERIFY_512     (2 * 1024) + PS_OH
#  define POOL_ENCRYPT_512    (2 * 1024) + PS_OH
#  define POOL_DECRYPT_512    (3 * 1024) + PS_OH
#  define POOL_MISC_512       (4 * 1024) + PS_OH

#  define POOL_SIGN_1024      (5 * 1024) + PS_OH
#  define POOL_VERIFY_1024    (3 * 1024) + PS_OH
#  define POOL_ENCRYPT_1024   (3 * 1024) + PS_OH
#  define POOL_DECRYPT_1024   (5 * 1024) + PS_OH
#  define POOL_MISC_1024      (6 * 1024) + PS_OH

#  define POOL_SIGN_2048      (7 * 1024) + PS_OH
#  define POOL_VERIFY_2048    (5 * 1024) + PS_OH
#  define POOL_ENCRYPT_2048   (5 * 1024) + PS_OH
#  define POOL_DECRYPT_2048   (7 * 1024) + PS_OH
#  define POOL_MISC_2048      (9 * 1024) + PS_OH

#  define POOL_SIGN_4096      (13 * 1024) + PS_OH
#  define POOL_VERIFY_4096    ( 8 * 1024) + PS_OH
#  define POOL_ENCRYPT_4096   ( 8 * 1024) + PS_OH
#  define POOL_DECRYPT_4096   (13 * 1024) + PS_OH
#  define POOL_MISC_4096      (16 * 1024) + PS_OH
# endif

# ifdef DO_512
#  include "rsa3e512.h"
#  include "rsa17e512.h"
#  include "rsa257e512.h"
#  include "rsa65537e512.h"
# endif /* DO_512 */

# ifdef DO_1024
#  include "rsa3e1024.h"
#  include "rsa17e1024.h"
#  include "rsa257e1024.h"
#  include "rsa65537e1024.h"
# endif /* DO_1024 */

# ifdef DO_2048
#  include "rsa3e2048.h"
#  include "rsa17e2048.h"
#  include "rsa257e2048.h"
#  include "rsa65537e2048.h"
# endif /* DO_2048 */

# ifdef DO_4096
#  include "rsa3e4096.h"
#  include "rsa17e4096.h"
#  include "rsa257e4096.h"
#  include "rsa65537e4096.h"
# endif /* DO_4096 */

# ifdef INCLUDE_SECOND_SET
#  ifdef DO_512
#   include "rsa3e512_1.h"
#   include "rsa17e512_1.h"
#   include "rsa257e512_1.h"
#   include "rsa65537e512_1.h"
#  endif /* DO_512 */

#  ifdef DO_1024
#   include "rsa3e1024_1.h"
#   include "rsa17e1024_1.h"
#   include "rsa257e1024_1.h"
#   include "rsa65537e1024_1.h"
#  endif /* DO_1024 */

#  ifdef DO_2048
#   include "rsa3e2048_1.h"
#   include "rsa17e2048_1.h"
#   include "rsa257e2048_1.h"
#   include "rsa65537e2048_1.h"
#  endif /* DO_2048 */

#  ifdef DO_4096
#   include "rsa3e4096_1.h"
#   include "rsa17e4096_1.h"
#   include "rsa257e4096_1.h"
#   include "rsa65537e4096_1.h"
#  endif /* DO_4096 */
# endif  /* INCLUDE_SECOND_SET */

typedef struct
{
    char *name;
    const unsigned char *key;
    uint32 len;
    int32 iter;
    int32 poolSign;
    int32 poolVerify;
    int32 poolEncrypt;
    int32 poolDecrypt;
    int32 poolMisc;
} keyList_t;

# ifdef USE_HIGHRES_TIME
#  define psDiffMsecs(A, B, C) (unsigned long long) psDiffUsecs(A, B)
#  define TIME_UNITS "    %lld usecs"
#  define PER_SEC(A) ((A) ? (1000000 / (A)) : 0)
# else
#  define TIME_UNITS "    %d msecs"
#  define PER_SEC(A) ((A) ? (1000 / (A)) : 0)
# endif

/*
    Add an iteration count so we don't have to run the large keys so many times
 */
static keyList_t keys[] = {
# ifdef DO_512
    { "rsa3e512",        rsa3e512,          sizeof(rsa3e512),          ITER_512,          POOL_SIGN_512,
      POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512, POOL_MISC_512 },
    { "rsa17e512",       rsa17e512,         sizeof(rsa17e512),         ITER_512,          POOL_SIGN_512,
      POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512, POOL_MISC_512 },
    { "rsa257e512",      rsa257e512,        sizeof(rsa257e512),        ITER_512,          POOL_SIGN_512,
      POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512, POOL_MISC_512 },
    { "rsa65537e512",    rsa65537e512,      sizeof(rsa65537e512),      ITER_512,
      POOL_SIGN_512, POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512,
      POOL_MISC_512 },
# endif
# ifdef DO_1024
    { "rsa3e1024",       rsa3e1024,         sizeof(rsa3e1024),         ITER_1024,         POOL_SIGN_1024,
      POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
    { "rsa17e1024",      rsa17e1024,        sizeof(rsa17e1024),        ITER_1024,         POOL_SIGN_1024,
      POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
    { "rsa257e1024",     rsa257e1024,       sizeof(rsa257e1024),       ITER_1024,         POOL_SIGN_1024,
      POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
    { "rsa65537e1024",   rsa65537e1024,     sizeof(rsa65537e1024),     ITER_1024,
      POOL_SIGN_1024, POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
# endif
# ifdef DO_2048
    { "rsa3e2048",       rsa3e2048,         sizeof(rsa3e2048),         ITER_2048,         POOL_SIGN_2048,
      POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
    { "rsa17e2048",      rsa17e2048,        sizeof(rsa17e2048),        ITER_2048,         POOL_SIGN_2048,
      POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
    { "rsa257e2048",     rsa257e2048,       sizeof(rsa257e2048),       ITER_2048,         POOL_SIGN_2048,
      POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
    { "rsa65537e2048",   rsa65537e2048,     sizeof(rsa65537e2048),     ITER_2048,
      POOL_SIGN_2048, POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
# endif
# ifdef DO_4096
    { "rsa3e4096",       rsa3e4096,         sizeof(rsa3e4096),         ITER_4096,         POOL_SIGN_4096,
      POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
    { "rsa17e4096",      rsa17e4096,        sizeof(rsa17e4096),        ITER_4096,         POOL_SIGN_4096,
      POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
    { "rsa257e4096",     rsa257e4096,       sizeof(rsa257e4096),       ITER_4096,         POOL_SIGN_4096,
      POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
    { "rsa65537e4096",   rsa65537e4096,     sizeof(rsa65537e4096),     ITER_4096,
      POOL_SIGN_4096, POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
# endif
# ifdef INCLUDE_SECOND_SET
#  ifdef DO_512
    { "rsa3e512_1",      rsa3e5121,         sizeof(rsa3e5121),         ITER_512,          POOL_SIGN_512,
      POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512, POOL_MISC_512 },
    { "rsa17e512_1",     rsa17e5121,        sizeof(rsa17e5121),        ITER_512,          POOL_SIGN_512,
      POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512, POOL_MISC_512 },
    { "rsa257e512_1",    rsa257e5121,       sizeof(rsa257e5121),       ITER_512,          POOL_SIGN_512,
      POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512, POOL_MISC_512 },
    { "rsa65537e512_1",  rsa65537e5121,     sizeof(rsa65537e5121),     ITER_512,
      POOL_SIGN_512, POOL_VERIFY_512, POOL_ENCRYPT_512, POOL_DECRYPT_512,
      POOL_MISC_512 },
#  endif
#  ifdef DO_1024
    { "rsa3e1024_1",     rsa3e10241,        sizeof(rsa3e10241),        ITER_1024,         POOL_SIGN_1024,
      POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
    { "rsa17e1024_1",    rsa17e10241,       sizeof(rsa17e10241),       ITER_1024,
      POOL_SIGN_1024, POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
    { "rsa257e1024_1",   rsa257e10241,      sizeof(rsa257e10241),      ITER_1024,
      POOL_SIGN_1024, POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
    { "rsa65537e1024_1", rsa65537e10241,    sizeof(rsa65537e10241),    ITER_1024,
      POOL_SIGN_1024, POOL_VERIFY_1024, POOL_ENCRYPT_1024, POOL_DECRYPT_1024,
      POOL_MISC_1024 },
#  endif
#  ifdef DO_2048
    { "rsa3e2048_1",     rsa3e20481,        sizeof(rsa3e20481),        ITER_2048,         POOL_SIGN_2048,
      POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
    { "rsa17e2048_1",    rsa17e20481,       sizeof(rsa17e20481),       ITER_2048,
      POOL_SIGN_2048, POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
    { "rsa257e2048_1",   rsa257e20481,      sizeof(rsa257e20481),      ITER_2048,
      POOL_SIGN_2048, POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
    { "rsa65537e2048_1", rsa65537e20481,    sizeof(rsa65537e20481),    ITER_2048,
      POOL_SIGN_2048, POOL_VERIFY_2048, POOL_ENCRYPT_2048, POOL_DECRYPT_2048,
      POOL_MISC_2048 },
#  endif
#  ifdef DO_4096
    { "rsa3e4096_1",     rsa3e40961,        sizeof(rsa3e40961),        ITER_4096,         POOL_SIGN_4096,
      POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
    { "rsa17e4096_1",    rsa17e40961,       sizeof(rsa17e40961),       ITER_4096,
      POOL_SIGN_4096, POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
    { "rsa257e4096_1",   rsa257e40961,      sizeof(rsa257e40961),      ITER_4096,
      POOL_SIGN_4096, POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
    { "rsa65537e4096_1", rsa65537e40961,    sizeof(rsa65537e40961),    ITER_4096,
      POOL_SIGN_4096, POOL_VERIFY_4096, POOL_ENCRYPT_4096, POOL_DECRYPT_4096,
      POOL_MISC_4096 },
#  endif
# endif /* INCLUDE_SECOND_SET */
    { NULL,              NULL,              0 }
};

/******************************************************************************/
/*
    Main
 */

# ifdef STATS
#  include "osdep_fcntl.h"
#  ifdef USE_HIGHRES_TIME
#   define TIME_STRING "\t%lld"
#  else
#   define TIME_STRING "\t%d"
#  endif
# endif

int main(int argc, char **argv)
{
    psPool_t *pool, *misc;
    psRsaKey_t privkey;
    psSize_t keysize;
    unsigned char *in, *out, *savein, *saveout;
    psTime_t start, end;
    uint32 iter, i = 0;
    int32 t;
    pkaCmdInfo_t *pkaInfo;

# ifdef STATS
    FILE *sfd;
# endif

    pool = misc = NULL;
    if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS)
    {
        _psTrace("Failed to initialize library:  psCryptoOpen failed\n");
        return -1;
    }

    pkaInfo = NULL;

    /* Verify time sanity */
    psGetTime(&start, NULL);
    Sleep(1);
    psGetTime(&end, NULL);
    Printf("Time sanity, 1 second = " TIME_UNITS "\n", psDiffMsecs(start, end, NULL));

    _psTraceStr("STARTING RSAPERF\n", NULL);
# ifdef STATS
    if ((sfd = Fopen("perfstat.txt", "w")) == NULL)
    {
        return PS_FAILURE;
    }
#  ifdef USE_HIGHRES_TIME
    Fprintf(sfd, "Key\tSign(usec)\tVerify\tEncrypt\tDecrypt\n");
#  else
    Fprintf(sfd, "Key\tSign(msec)\tVerify\tEncrypt\tDecrypt\n");
#  endif
# endif /* STATS */

    while (keys[i].key != NULL)
    {
        _psTraceStr("Test %s...\n", keys[i].name);
# ifdef STATS
        Fprintf(sfd, "%s", keys[i].name);
# endif
        psRsaInitKey(misc, &privkey);
        if (psRsaParsePkcs1PrivKey(misc, keys[i].key, keys[i].len, &privkey) < 0)
        {
            _psTrace("	FAILED TO PARSE PRIVATE KEY\n");
            continue;
        }
        /* psRsaParsePkcs1PrivKeyOld(misc, keys[i].key, keys[i].len, &privkey); */
        keysize = psRsaSize(&privkey);
        savein = in = psMalloc(misc, keysize);
        psGetEntropy(in, keysize, NULL);
        saveout = out = psMalloc(misc, keysize);

# ifdef SIGN_OP
        iter = 0;
        psGetTime(&start, NULL);
        while (iter < keys[i].iter)
        {
            if (psRsaEncryptPriv(pool, &privkey, in, keysize - 16,
                    out, keysize, pkaInfo) < 0)
            {
                _psTrace("	FAILED SIGNATURE OPERATION\n");
            }
/*
            The idea here is that I wanted the encryption to happen over
            an ever-changing value without adding any timing overhead by
            going out and getting more random data (or whatever).  So just
            passing the output as the basis for the input each time.
 */
            in = out;
/**/
            if (iter % 2)
            {
                out = saveout;
            }
            else
            {
                out = savein;
            }
            iter++;
        }
        psGetTime(&end, NULL);

        _psTraceInt(TIME_UNITS "/sig ",
            t = psDiffMsecs(start, end, NULL) / keys[i].iter);
        _psTraceInt("(%d per sec)\n", PER_SEC(t));

#  ifdef STATS
        Fprintf(sfd, TIME_STRING, t);
#  endif
# endif /* SIGN_OP */

# ifdef VERIFY_OP
        static const unsigned char sigdata[] = "Test message to be signed - at least 28 bytes";
        Memset(in, 0x0, keysize);
        Memcpy(in, sigdata, sizeof(sigdata));
        if (psRsaEncryptPriv(misc, &privkey, in, sizeof(sigdata), out, keysize, pkaInfo) < 0)
        {
            _psTrace("	FAILED VERIFY PREP\n");
        }
        Memset(in, 0x0, keysize);

        psGetTime(&start, NULL);
        /* coverity[swapped_arguments] */
        if (psRsaDecryptPub(pool, &privkey, out, keysize, in, sizeof(sigdata), pkaInfo) < 0)
        {
            _psTrace("	FAILED VERIFY OPERATION\n");
        }
        psGetTime(&end, NULL);
        if (Memcmp(in, sigdata, sizeof(sigdata)) != 0)
        {
            _psTrace("	FAILED VERIFY VERIFY\n");
        }
        _psTraceInt(TIME_UNITS "/verify ", t = psDiffMsecs(start, end, NULL));
        _psTraceInt("(%d per sec)\n", PER_SEC(t));
#  ifdef STATS
        Fprintf(sfd, TIME_STRING, t);
#  endif
# endif /* VERIFY_OP */

# ifdef ENCRYPT_OP
        iter = 0;
        psGetEntropy(in, keysize, NULL);
        psGetTime(&start, NULL);
        while (iter < keys[i].iter)
        {
            if (psRsaEncryptPub(pool, &privkey, in, keysize - 16,
                    out, keysize, pkaInfo) < 0)
            {
                _psTrace("	FAILED ENCRYPT OPERATION\n");
            }
/*
            The idea here is that we wanted the encryption to happen over
            an ever-changing value without adding any timing overhead by
            going out and getting more random data (or whatever).  So just
            passing the output as the basis for the input each time.
 */
            in = out;
/**/
            if (iter % 2)
            {
                out = saveout;
            }
            else
            {
                out = savein;
            }
            iter++;
        }
        psGetTime(&end, NULL);
        _psTraceInt(TIME_UNITS "/encrypt ",
            t = psDiffMsecs(start, end, NULL) / keys[i].iter);
        _psTraceInt("(%d per sec)\n", PER_SEC(t));
#  ifdef STATS
        Fprintf(sfd, TIME_STRING, t);
#  endif
# endif /* ENCRYPT_OP */

# ifdef DECRYPT_OP
/**/
        if (in == out)
        {
            out = saveout;
        }
        Memset(in, 0x0, keysize);
        Memcpy(in, "hello", 5);
        if (psRsaEncryptPub(misc, &privkey, in, 5, out, keysize, pkaInfo) < 0)
        {
            _psTrace("	FAILED VERIFY PREP\n");
        }
        Memset(in, 0x0, keysize);

        psGetTime(&start, NULL);
        /* coverity[swapped_arguments] */
        if (psRsaDecryptPriv(pool, &privkey, out, keysize, in, 5, pkaInfo) < 0)
        {
            _psTrace("	FAILED DECRYPT OPERATION\n");
        }
        psGetTime(&end, NULL);
        if (Memcmp(in, "hello", 5) != 0)
        {
            _psTrace("	FAILED DECRYPT VERIFY\n");
        }
        _psTraceInt(TIME_UNITS "/decrypt ", t = psDiffMsecs(start, end, NULL));
        _psTraceInt("(%d per sec)\n", PER_SEC(t));
#  ifdef STATS
        Fprintf(sfd, TIME_STRING "\n", t);
#  endif
# endif /* DECRYPT_OP */

        psFree(savein, misc);
        psFree(saveout, misc);
        psRsaClearKey(&privkey);
        i++;
    }

# ifdef STATS
    Fclose(sfd);
# endif
# ifdef WIN32
    _psTrace("Press any key to close");
    getchar();
# endif
    _psTraceStr("FINISHED RSAPERF\n", NULL);
    psCryptoClose();
    return 0;
}
#else /* --> !USE_RSA || !USE_PRIVATE_KEY_PARSING*/
int main(int argc, char **argv)
{
# ifndef USE_RSA
    _psTrace("Please enable USE_RSA for this test\n");
# endif /* USE_RSA */
# ifndef USE_PRIVATE_KEY_PARSING
    _psTrace("Please enable USE_PRIVATE_KEY_PARSING for this test\n");
# endif /* USE_PRIVATE_KEY_PARSING */
    return 1;
}
#endif /* USE_RSA && USE_PRIVATE_KEY_PARSING */
