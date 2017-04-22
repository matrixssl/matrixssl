/**
 *      @file    sha512.c
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

#if defined(USE_MATRIX_SHA384) || defined(USE_MATRIX_SHA512)

# ifndef HAVE_NATIVE_INT64
#  error Must have NATIVE_INT64 support
# endif

/******************************************************************************/

/* the K array */
static const uint64_t K[80] = {
    CONST64(0x428a2f98d728ae22), CONST64(0x7137449123ef65cd),
    CONST64(0xb5c0fbcfec4d3b2f), CONST64(0xe9b5dba58189dbbc),
    CONST64(0x3956c25bf348b538), CONST64(0x59f111f1b605d019),
    CONST64(0x923f82a4af194f9b), CONST64(0xab1c5ed5da6d8118),
    CONST64(0xd807aa98a3030242), CONST64(0x12835b0145706fbe),
    CONST64(0x243185be4ee4b28c), CONST64(0x550c7dc3d5ffb4e2),
    CONST64(0x72be5d74f27b896f), CONST64(0x80deb1fe3b1696b1),
    CONST64(0x9bdc06a725c71235), CONST64(0xc19bf174cf692694),
    CONST64(0xe49b69c19ef14ad2), CONST64(0xefbe4786384f25e3),
    CONST64(0x0fc19dc68b8cd5b5), CONST64(0x240ca1cc77ac9c65),
    CONST64(0x2de92c6f592b0275), CONST64(0x4a7484aa6ea6e483),
    CONST64(0x5cb0a9dcbd41fbd4), CONST64(0x76f988da831153b5),
    CONST64(0x983e5152ee66dfab), CONST64(0xa831c66d2db43210),
    CONST64(0xb00327c898fb213f), CONST64(0xbf597fc7beef0ee4),
    CONST64(0xc6e00bf33da88fc2), CONST64(0xd5a79147930aa725),
    CONST64(0x06ca6351e003826f), CONST64(0x142929670a0e6e70),
    CONST64(0x27b70a8546d22ffc), CONST64(0x2e1b21385c26c926),
    CONST64(0x4d2c6dfc5ac42aed), CONST64(0x53380d139d95b3df),
    CONST64(0x650a73548baf63de), CONST64(0x766a0abb3c77b2a8),
    CONST64(0x81c2c92e47edaee6), CONST64(0x92722c851482353b),
    CONST64(0xa2bfe8a14cf10364), CONST64(0xa81a664bbc423001),
    CONST64(0xc24b8b70d0f89791), CONST64(0xc76c51a30654be30),
    CONST64(0xd192e819d6ef5218), CONST64(0xd69906245565a910),
    CONST64(0xf40e35855771202a), CONST64(0x106aa07032bbd1b8),
    CONST64(0x19a4c116b8d2d0c8), CONST64(0x1e376c085141ab53),
    CONST64(0x2748774cdf8eeb99), CONST64(0x34b0bcb5e19b48a8),
    CONST64(0x391c0cb3c5c95a63), CONST64(0x4ed8aa4ae3418acb),
    CONST64(0x5b9cca4f7763e373), CONST64(0x682e6ff3d6b2b8a3),
    CONST64(0x748f82ee5defb2fc), CONST64(0x78a5636f43172f60),
    CONST64(0x84c87814a1f0ab72), CONST64(0x8cc702081a6439ec),
    CONST64(0x90befffa23631e28), CONST64(0xa4506cebde82bde9),
    CONST64(0xbef9a3f7b2c67915), CONST64(0xc67178f2e372532b),
    CONST64(0xca273eceea26619c), CONST64(0xd186b8c721c0c207),
    CONST64(0xeada7dd6cde0eb1e), CONST64(0xf57d4f7fee6ed178),
    CONST64(0x06f067aa72176fba), CONST64(0x0a637dc5a2c898a6),
    CONST64(0x113f9804bef90dae), CONST64(0x1b710b35131c471b),
    CONST64(0x28db77f523047d84), CONST64(0x32caab7b40c72493),
    CONST64(0x3c9ebe0a15c9bebc), CONST64(0x431d67c49c100d4c),
    CONST64(0x4cc5d4becb3e42b6), CONST64(0x597f299cfc657e2a),
    CONST64(0x5fcb6fab3ad6faec), CONST64(0x6c44198c4a475817)
};

/* Various logical functions */
# define Ch(x, y, z)       (z ^ (x & (y ^ z)))
# define Maj(x, y, z)      (((x | y) & z) | (x & y))
# define S(x, n)         ROR64c(x, n)
# define R(x, n)         (((x) & CONST64(0xFFFFFFFFFFFFFFFF)) >> ((uint64) n))
# define Sigma0(x)       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
# define Sigma1(x)       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
# define Gamma0(x)       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
# define Gamma1(x)       (S(x, 19) ^ S(x, 61) ^ R(x, 6))

/* compress 1024-bits */
# ifdef USE_BURN_STACK
static void _sha512_compress(psSha512_t *sha512, const unsigned char *buf)
# else
static void  sha512_compress(psSha512_t *sha512, const unsigned char *buf)
# endif
{
    uint64 S[8], W[80], t0, t1;
    int i;

    /* copy state into S */
    for (i = 0; i < 8; i++)
    {
        S[i] = sha512->state[i];
    }

    /* copy the state into 1024-bits into W[0..15] */
    for (i = 0; i < 16; i++)
    {
        LOAD64H(W[i], buf + (8 * i));
    }

    /* fill W[16..79] */
    for (i = 16; i < 80; i++)
    {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

    /* Compress */
# ifndef PS_SHA512_IMPROVE_PERF_INCREASE_CODESIZE
    for (i = 0; i < 80; i++)
    {
        t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
        t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + t0;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = t0 + t1;
    }
# else
#  define RND(a, b, c, d, e, f, g, h, i)                    \
    t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
    t1 = Sigma0(a) + Maj(a, b, c);                  \
    d += t0;                                        \
    h  = t0 + t1;

    for (i = 0; i < 80; i += 8)
    {
        RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i + 0);
        RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1);
        RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2);
        RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3);
        RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4);
        RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5);
        RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6);
        RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7);
    }
# endif /* PS_SHA512_IMPROVE_PERF_INCREASE_CODESIZE */

    /* feedback */
    for (i = 0; i < 8; i++)
    {
        sha512->state[i] = sha512->state[i] + S[i];
    }
}

/* compress 1024-bits */
# ifdef USE_BURN_STACK
static void sha512_compress(psSha512_t *sha512, const unsigned char *buf)
{
    _sha512_compress(sha512, buf);
    psBurnStack(sizeof(uint64) * 90 + sizeof(int));
}
# endif

/******************************************************************************/
# ifdef USE_MATRIX_SHA512
/* Other 512 functions are used by 384 */
int32_t psSha512Init(psSha512_t *sha512)
{
#  ifdef CRYPTO_ASSERT
    psAssert(sha512 != NULL);
#  endif
    sha512->curlen = 0;
    sha512->length = 0;
    sha512->state[0] = CONST64(0x6a09e667f3bcc908);
    sha512->state[1] = CONST64(0xbb67ae8584caa73b);
    sha512->state[2] = CONST64(0x3c6ef372fe94f82b);
    sha512->state[3] = CONST64(0xa54ff53a5f1d36f1);
    sha512->state[4] = CONST64(0x510e527fade682d1);
    sha512->state[5] = CONST64(0x9b05688c2b3e6c1f);
    sha512->state[6] = CONST64(0x1f83d9abfb41bd6b);
    sha512->state[7] = CONST64(0x5be0cd19137e2179);
    return PS_SUCCESS;
}
# endif
/******************************************************************************/

# ifdef USE_MATRIX_SHA512
void psSha512Update(psSha512_t *sha512, const unsigned char *buf, uint32_t len)
# else
static void psSha512Update(psSha512_t *sha512, const unsigned char *buf, uint32_t len)
# endif
{
    uint32_t n;

    psAssert(sha512 != NULL);
    psAssert(buf != NULL);

    while (len > 0)
    {
        if (sha512->curlen == 0 && len >= 128)
        {
            sha512_compress(sha512, (unsigned char *) buf);
            sha512->length += 1024;
            buf     += 128;
            len     -= 128;
        }
        else
        {
            n = min(len, (128 - sha512->curlen));
            memcpy(sha512->buf + sha512->curlen, buf, (size_t) n);
            sha512->curlen  += n;
            buf                 += n;
            len                 -= n;

            if (sha512->curlen == 128)
            {
                sha512_compress(sha512, sha512->buf);
                sha512->length += 1024;
                sha512->curlen  = 0;
            }
        }
    }
}

/******************************************************************************/

# ifdef USE_MATRIX_SHA512
void psSha512Final(psSha512_t *sha512, unsigned char out[SHA512_HASHLEN])
# else
static void psSha512Final(psSha512_t *sha512, unsigned char out[SHA512_HASHLEN])
# endif
{
    int i;

# ifdef CRYPTO_ASSERT
    psAssert(sha512  != NULL);
    psAssert(out != NULL);
    if (sha512->curlen >= sizeof(sha512->buf))
    {
        return;
    }
# endif
    /* increase the length of the message */
    sha512->length += sha512->curlen * CONST64(8);

    /* append the '1' bit */
    sha512->buf[sha512->curlen++] = (unsigned char) 0x80;

    /* if the length is currently above 112 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (sha512->curlen > 112)
    {
        while (sha512->curlen < 128)
        {
            sha512->buf[sha512->curlen++] = (unsigned char) 0;
        }
        sha512_compress(sha512, sha512->buf);
        sha512->curlen = 0;
    }

    /* pad upto 120 bytes of zeroes
        @note from 112 to 120 is the 64 MSB of the length.
        We assume that you won't hash > 2^64 bits of data... :-)
     */
    while (sha512->curlen < 120)
    {
        sha512->buf[sha512->curlen++] = (unsigned char) 0;
    }

    /* store length */
    STORE64H(sha512->length, sha512->buf + 120);
    sha512_compress(sha512, sha512->buf);

    /* copy output */
    for (i = 0; i < 8; i++)
    {
        STORE64H(sha512->state[i], out + (8 * i));
    }
# ifdef USE_BURN_STACK
    psBurnStack(sizeof(psSha512_t));
# endif
}

# ifdef USE_MATRIX_SHA384
/******************************************************************************/

int32_t psSha384Init(psSha384_t *sha384)
{
#  ifdef CRYPTO_ASSERT
    psAssert(sha384 != NULL);
#  endif
    sha384->curlen = 0;
    sha384->length = 0;
    sha384->state[0] = CONST64(0xcbbb9d5dc1059ed8);
    sha384->state[1] = CONST64(0x629a292a367cd507);
    sha384->state[2] = CONST64(0x9159015a3070dd17);
    sha384->state[3] = CONST64(0x152fecd8f70e5939);
    sha384->state[4] = CONST64(0x67332667ffc00b31);
    sha384->state[5] = CONST64(0x8eb44a8768581511);
    sha384->state[6] = CONST64(0xdb0c2e0d64f98fa7);
    sha384->state[7] = CONST64(0x47b5481dbefa4fa4);
    return PS_SUCCESS;
}

/******************************************************************************/

void psSha384Update(psSha384_t *sha384, const unsigned char *buf, uint32_t len)
{
    psSha512Update(sha384, buf, len);
}

/******************************************************************************/

void psSha384Final(psSha384_t *sha384, unsigned char out[SHA384_HASHLEN])
{
    unsigned char buf[SHA512_HASHLEN];

#  ifdef CRYPTO_ASSERT
    psAssert(sha384 != NULL);
    psAssert(out != NULL);
    if (sha384->curlen >= sizeof(sha384->buf))
    {
        return;
    }
#  endif
    psSha512Final(sha384, buf);
    memcpy(out, buf, SHA384_HASHLEN);
#  ifdef USE_BURN_STACK
    psBurnStack(sizeof(buf));
#  endif
}

# endif /* USE_MATRIX_SHA384 */

#endif  /* USE_MATRIX_SHA384 || USE_MATRIX_SHA512 */

/******************************************************************************/

