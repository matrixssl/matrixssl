/**
 *      @file    sha256.c
 *      @version $Format:%h%d$
 *
 *      SHA256 hash implementation.
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

#ifdef USE_MATRIX_SHA256

/******************************************************************************/

# ifndef PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE

/* The K array */
static const uint32_t K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};
# endif /* PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE */

/* Various logical functions */
# define Ch(x, y, z)           (z ^ (x & (y ^ z)))
# define Maj(x, y, z)          (((x | y) & z) | (x & y))
# define S(x, n)             ROR((x), (n))
# define R(x, n)             (((x) & 0xFFFFFFFFUL) >> (n))
# define Sigma0(x)           (S(x, 2) ^ S(x, 13) ^ S(x, 22))
# define Sigma1(x)           (S(x, 6) ^ S(x, 11) ^ S(x, 25))
# define Gamma0(x)           (S(x, 7) ^ S(x, 18) ^ R(x, 3))
# define Gamma1(x)           (S(x, 17) ^ S(x, 19) ^ R(x, 10))

/*
    compress 512-bits
 */
# ifdef USE_BURN_STACK
static void _sha256_compress(psSha256_t *sha256, const unsigned char *buf)
# else
static void sha256_compress(psSha256_t *sha256, const unsigned char *buf)
# endif /* CLEAN_STACK */
{

    uint32 S[8], W[64], t0, t1;
#  ifndef PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE
    uint32 t;
#  endif /* PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE */
    int32 i;

    /* copy state into S */
    for (i = 0; i < 8; i++)
    {
        S[i] = sha256->state[i];
    }

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++)
    {
        LOAD32H(W[i], buf + (4 * i));
    }

    /* fill W[16..63] */
    for (i = 16; i < 64; i++)
    {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

    /* Compress */
#  ifndef PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE
#   define RND(a, b, c, d, e, f, g, h, i)                          \
    t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
    t1 = Sigma0(a) + Maj(a, b, c);                      \
    d += t0;                                            \
    h  = t0 + t1;

    for (i = 0; i < 64; ++i)
    {
        RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i);
        t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
        S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
    }
#  else /* PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE */
#   define RND(a, b, c, d, e, f, g, h, i, ki)                       \
    t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];       \
    t1 = Sigma0(a) + Maj(a, b, c);                      \
    d += t0;                                            \
    h  = t0 + t1;

    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 0, 0x428a2f98);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 1, 0x71374491);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 2, 0xb5c0fbcf);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 3, 0xe9b5dba5);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 4, 0x3956c25b);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 5, 0x59f111f1);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 6, 0x923f82a4);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 7, 0xab1c5ed5);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 8, 0xd807aa98);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 9, 0x12835b01);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 10, 0x243185be);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 11, 0x550c7dc3);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 12, 0x72be5d74);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 13, 0x80deb1fe);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 14, 0x9bdc06a7);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 15, 0xc19bf174);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 16, 0xe49b69c1);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 17, 0xefbe4786);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 18, 0x0fc19dc6);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 19, 0x240ca1cc);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 20, 0x2de92c6f);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 21, 0x4a7484aa);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 22, 0x5cb0a9dc);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 23, 0x76f988da);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 24, 0x983e5152);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 25, 0xa831c66d);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 26, 0xb00327c8);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 27, 0xbf597fc7);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 28, 0xc6e00bf3);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 29, 0xd5a79147);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 30, 0x06ca6351);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 31, 0x14292967);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 32, 0x27b70a85);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 33, 0x2e1b2138);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 34, 0x4d2c6dfc);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 35, 0x53380d13);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 36, 0x650a7354);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 37, 0x766a0abb);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 38, 0x81c2c92e);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 39, 0x92722c85);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 40, 0xa2bfe8a1);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 41, 0xa81a664b);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 42, 0xc24b8b70);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 43, 0xc76c51a3);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 44, 0xd192e819);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 45, 0xd6990624);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 46, 0xf40e3585);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 47, 0x106aa070);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 48, 0x19a4c116);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 49, 0x1e376c08);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 50, 0x2748774c);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 51, 0x34b0bcb5);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 52, 0x391c0cb3);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 53, 0x4ed8aa4a);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 54, 0x5b9cca4f);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 55, 0x682e6ff3);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 56, 0x748f82ee);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 57, 0x78a5636f);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 58, 0x84c87814);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 59, 0x8cc70208);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 60, 0x90befffa);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 61, 0xa4506ceb);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 62, 0xbef9a3f7);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 63, 0xc67178f2);

#   undef RND

#  endif /* PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE */

    /* feedback */
    for (i = 0; i < 8; i++)
    {
        sha256->state[i] = sha256->state[i] + S[i];
    }

}

# ifdef USE_BURN_STACK
static void sha256_compress(psSha256_t *sha256, const unsigned char *buf)
{
    _sha256_compress(sha256, buf);
    psBurnStack(sizeof(uint32) * 74);
}
# endif /* USE_BURN_STACK */

/******************************************************************************/

int32_t psSha256Init(psSha256_t *sha256)
{
# ifdef CRYPTO_ASSERT
    psAssert(sha256 != NULL);
# endif
    sha256->curlen = 0;
    sha256->state[0] = 0x6A09E667UL;
    sha256->state[1] = 0xBB67AE85UL;
    sha256->state[2] = 0x3C6EF372UL;
    sha256->state[3] = 0xA54FF53AUL;
    sha256->state[4] = 0x510E527FUL;
    sha256->state[5] = 0x9B05688CUL;
    sha256->state[6] = 0x1F83D9ABUL;
    sha256->state[7] = 0x5BE0CD19UL;
# ifdef HAVE_NATIVE_INT64
    sha256->length = 0;
# else
    sha256->lengthHi = 0;
    sha256->lengthLo = 0;
# endif /* HAVE_NATIVE_INT64 */
    return PS_SUCCESS;
}

/******************************************************************************/

void psSha256Update(psSha256_t *sha256, const unsigned char *buf, uint32_t len)
{
    uint32 n;

# ifdef CRYPTO_ASSERT
    psAssert(sha256 != NULL);
    psAssert(buf != NULL);
# endif

    while (len > 0)
    {
        if (sha256->curlen == 0 && len >= 64)
        {
            sha256_compress(sha256, (unsigned char *) buf);
# ifdef HAVE_NATIVE_INT64
            sha256->length += 512;
# else
            n = (sha256->lengthLo + 512) & 0xFFFFFFFFL;
            if (n < sha256->lengthLo)
            {
                sha256->lengthHi++;
            }
            sha256->lengthLo = n;
# endif     /* HAVE_NATIVE_INT64 */
            buf     += 64;
            len     -= 64;
        }
        else
        {
            n = min(len, (64 - sha256->curlen));
            memcpy(sha256->buf + sha256->curlen, buf, (size_t) n);
            sha256->curlen  += n;
            buf                 += n;
            len                 -= n;

            if (sha256->curlen == 64)
            {
                sha256_compress(sha256, sha256->buf);
# ifdef HAVE_NATIVE_INT64
                sha256->length += 512;
# else
                n = (sha256->lengthLo + 512) & 0xFFFFFFFFL;
                if (n < sha256->lengthLo)
                {
                    sha256->lengthHi++;
                }
                sha256->lengthLo = n;
# endif         /* HAVE_NATIVE_INT64 */
                sha256->curlen  = 0;
            }
        }
    }
    return;
}

/******************************************************************************/

void psSha256Final(psSha256_t *sha256, unsigned char hash[SHA256_HASHLEN])
{
    int32 i;

# ifndef HAVE_NATIVE_INT64
    uint32 n;
# endif

# ifdef CRYPTO_ASSERT
    psAssert(sha256 != NULL);
    psAssert(hash != NULL);
    if (sha256->curlen >= sizeof(sha256->buf))
    {
        psTraceCrypto("psSha256Final error\n");
        return;
    }
# endif

    /* increase the length of the message */
# ifdef HAVE_NATIVE_INT64
    sha256->length += sha256->curlen << 3;
# else
    n = (sha256->lengthLo + (sha256->curlen << 3)) & 0xFFFFFFFFL;
    if (n < sha256->lengthLo)
    {
        sha256->lengthHi++;
    }
    sha256->lengthHi += (sha256->curlen >> 29);
    sha256->lengthLo = n;
# endif /* HAVE_NATIVE_INT64 */

    /* append the '1' bit */
    sha256->buf[sha256->curlen++] = (unsigned char) 0x80;

/*
    if the length is currently above 56 bytes we append zeros then compress.
    Then we can fall back to padding zeros and length encoding like normal.
 */
    if (sha256->curlen > 56)
    {
        while (sha256->curlen < 64)
        {
            sha256->buf[sha256->curlen++] = (unsigned char) 0;
        }
        sha256_compress(sha256, sha256->buf);
        sha256->curlen = 0;
    }
    /* pad upto 56 bytes of zeroes */
    while (sha256->curlen < 56)
    {
        sha256->buf[sha256->curlen++] = (unsigned char) 0;
    }

    /* store length */
# ifdef HAVE_NATIVE_INT64
    STORE64H(sha256->length, sha256->buf + 56);
# else
    STORE32H(sha256->lengthHi, sha256->buf + 56);
    STORE32H(sha256->lengthLo, sha256->buf + 60);
# endif /* HAVE_NATIVE_INT64 */
    sha256_compress(sha256, sha256->buf);

    /* copy output */
    for (i = 0; i < 8; i++)
    {
        STORE32H(sha256->state[i], hash + (4 * i));
    }
    memset(sha256, 0x0, sizeof(psSha256_t));
}

# ifdef USE_SHA224
/******************************************************************************/

void psSha224Init(psSha256_t *sha256)
{
#  ifdef CRYPTO_ASSERT
    psAssert(sha256 != NULL);
#  endif

    sha256->curlen = 0;
#  ifdef HAVE_NATIVE_INT64
    sha256->length = 0;
#  else
    sha256->lengthHi = 0;
    sha256->lengthLo = 0;
#  endif /* HAVE_NATIVE_INT64 */
    sha256->state[0] = 0xc1059ed8UL;
    sha256->state[1] = 0x367cd507UL;
    sha256->state[2] = 0x3070dd17UL;
    sha256->state[3] = 0xf70e5939UL;
    sha256->state[4] = 0xffc00b31UL;
    sha256->state[5] = 0x68581511UL;
    sha256->state[6] = 0x64f98fa7UL;
    sha256->state[7] = 0xbefa4fa4UL;
}

/******************************************************************************/

void psSha224Update(psSha256_t *sha256, const unsigned char *buf, uint32 len)
{
    psSha256Update(sha256, buf, len);
}

/******************************************************************************/

void psSha224Final(psSha256_t *sha256, unsigned char out[SHA224_HASHLEN])
{
    unsigned char buf[SHA224_HASHLEN];

#  ifdef CRYPTO_ASSERT
    psAssert(sha256 != NULL);
    psAssert(out != NULL);
#  endif
    psSha256Final(sha256, buf);
    memcpy(out, buf, SHA224_HASH_SIZE);
#  ifdef USE_BURN_STACK
    psBurnStack(sizeof(buf));
#  endif
}
# endif /* USE_SHA224 */

#endif  /* USE_MATRIX_SHA256 */

/******************************************************************************/

