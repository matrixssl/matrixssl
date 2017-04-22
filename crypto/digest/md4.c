/**
 *      @file    md4.c
 *      @version $Format:%h%d$
 *
 *      MD4 hash implementation.
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

#ifdef USE_MATRIX_MD4

/******************************************************************************/

# define S11 3
# define S12 7
# define S13 11
# define S14 19
# define S21 3
# define S22 5
# define S23 9
# define S24 13
# define S31 3
# define S32 9
# define S33 11
# define S34 15

/* F, G and H are basic MD4 functions. */
# define F(x, y, z) (z ^ (x & (y ^ z)))
# define G(x, y, z) ((x & y) | (z & (x | y)))
# define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits. */
# define ROTATE_LEFT(x, n) ROL(x, n)

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */

# define FF(a, b, c, d, x, s) { \
        (a) += F((b), (c), (d)) + (x); \
        (a) = ROTATE_LEFT((a), (s)); \
}
# define GG(a, b, c, d, x, s) { \
        (a) += G((b), (c), (d)) + (x) + 0x5a827999UL; \
        (a) = ROTATE_LEFT((a), (s)); \
}
# define HH(a, b, c, d, x, s) { \
        (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL; \
        (a) = ROTATE_LEFT((a), (s)); \
}

# ifdef USE_BURN_STACK
static int32 _md4_compress(psMd4_t *md, const unsigned char *buf)
# else
static int32  md4_compress(psMd4_t *md, const unsigned char *buf)
# endif
{
    uint32 x[16], a, b, c, d, i;

    /* copy state */
    a = md->state[0];
    b = md->state[1];
    c = md->state[2];
    d = md->state[3];

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++)
    {
        LOAD32L(x[i], buf + (4 * i));
    }

    /* Round 1 */
    FF(a, b, c, d, x[ 0], S11);  /* 1 */
    FF(d, a, b, c, x[ 1], S12);  /* 2 */
    FF(c, d, a, b, x[ 2], S13);  /* 3 */
    FF(b, c, d, a, x[ 3], S14);  /* 4 */
    FF(a, b, c, d, x[ 4], S11);  /* 5 */
    FF(d, a, b, c, x[ 5], S12);  /* 6 */
    FF(c, d, a, b, x[ 6], S13);  /* 7 */
    FF(b, c, d, a, x[ 7], S14);  /* 8 */
    FF(a, b, c, d, x[ 8], S11);  /* 9 */
    FF(d, a, b, c, x[ 9], S12);  /* 10 */
    FF(c, d, a, b, x[10], S13);  /* 11 */
    FF(b, c, d, a, x[11], S14);  /* 12 */
    FF(a, b, c, d, x[12], S11);  /* 13 */
    FF(d, a, b, c, x[13], S12);  /* 14 */
    FF(c, d, a, b, x[14], S13);  /* 15 */
    FF(b, c, d, a, x[15], S14);  /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[ 0], S21);  /* 17 */
    GG(d, a, b, c, x[ 4], S22);  /* 18 */
    GG(c, d, a, b, x[ 8], S23);  /* 19 */
    GG(b, c, d, a, x[12], S24);  /* 20 */
    GG(a, b, c, d, x[ 1], S21);  /* 21 */
    GG(d, a, b, c, x[ 5], S22);  /* 22 */
    GG(c, d, a, b, x[ 9], S23);  /* 23 */
    GG(b, c, d, a, x[13], S24);  /* 24 */
    GG(a, b, c, d, x[ 2], S21);  /* 25 */
    GG(d, a, b, c, x[ 6], S22);  /* 26 */
    GG(c, d, a, b, x[10], S23);  /* 27 */
    GG(b, c, d, a, x[14], S24);  /* 28 */
    GG(a, b, c, d, x[ 3], S21);  /* 29 */
    GG(d, a, b, c, x[ 7], S22);  /* 30 */
    GG(c, d, a, b, x[11], S23);  /* 31 */
    GG(b, c, d, a, x[15], S24);  /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[ 0], S31);  /* 33 */
    HH(d, a, b, c, x[ 8], S32);  /* 34 */
    HH(c, d, a, b, x[ 4], S33);  /* 35 */
    HH(b, c, d, a, x[12], S34);  /* 36 */
    HH(a, b, c, d, x[ 2], S31);  /* 37 */
    HH(d, a, b, c, x[10], S32);  /* 38 */
    HH(c, d, a, b, x[ 6], S33);  /* 39 */
    HH(b, c, d, a, x[14], S34);  /* 40 */
    HH(a, b, c, d, x[ 1], S31);  /* 41 */
    HH(d, a, b, c, x[ 9], S32);  /* 42 */
    HH(c, d, a, b, x[ 5], S33);  /* 43 */
    HH(b, c, d, a, x[13], S34);  /* 44 */
    HH(a, b, c, d, x[ 3], S31);  /* 45 */
    HH(d, a, b, c, x[11], S32);  /* 46 */
    HH(c, d, a, b, x[ 7], S33);  /* 47 */
    HH(b, c, d, a, x[15], S34);  /* 48 */


    /* Update our state */
    md->state[0] = md->state[0] + a;
    md->state[1] = md->state[1] + b;
    md->state[2] = md->state[2] + c;
    md->state[3] = md->state[3] + d;

    return PS_SUCCESS;
}

# ifdef USE_BURN_STACK
static int32 md4_compress(psMd4_t *md, const unsigned char *buf)
{
    int32 err;

    err = _md4_compress(md, buf);
    psBurnStack(sizeof(uint32) * 20 + sizeof(int32));
    return err;
}
# endif

void psMd4Init(psMd4_t *md)
{
# ifdef CRYPTO_ASSERT
    psAssert(md != NULL);
# endif
    md->state[0] = 0x67452301UL;
    md->state[1] = 0xefcdab89UL;
    md->state[2] = 0x98badcfeUL;
    md->state[3] = 0x10325476UL;
    md->curlen  = 0;
# ifdef HAVE_NATIVE_INT64
    md->length  = 0;
# else
    md->lengthHi = 0;
    md->lengthLo = 0;
# endif /* HAVE_NATIVE_INT64 */
}

void psMd4Update(psMd4_t *md, const unsigned char *buf, uint32_t len)
{
    uint32 n;

# ifdef CRYPTO_ASSERT
    psAssert(md != NULL);
    psAssert(buf != NULL);
# endif
    while (len > 0)
    {
        n = min(len, (64 - md->curlen));
        memcpy(md->buf + md->curlen, buf, (size_t) n);
        md->curlen  += n;
        buf             += n;
        len             -= n;

        /* is 64 bytes full?  */
        if (md->curlen == 64)
        {
            md4_compress(md, md->buf);
# ifdef HAVE_NATIVE_INT64
            md->length += 512;
# else
            n = (md->lengthLo + 512) & 0xFFFFFFFFL;
            if (n < md->lengthLo)
            {
                md->lengthHi++;
            }
            md->lengthLo = n;
# endif     /* HAVE_NATIVE_INT64 */
            md->curlen = 0;
        }
    }
}

int32_t psMd4Final(psMd4_t *md, unsigned char *out)
{
    int32 i;

# ifndef HAVE_NATIVE_INT64
    uint32 n;
# endif

# ifdef CRYPTO_ASSERT
    psAssert(md  != NULL);
    psAssert(out != NULL);
    if (md->curlen >= sizeof(md->buf))
    {
        psTraceCrypto("psMd4Final error\n");
        return PS_LIMIT_FAIL;
    }
# endif

    /* increase the length of the message */
# ifdef HAVE_NATIVE_INT64
    md->length += md->curlen << 3;
# else
    n = (md->lengthLo + (md->curlen << 3)) & 0xFFFFFFFFL;
    if (n < md->lengthLo)
    {
        md->lengthHi++;
    }
    md->lengthHi += (md->curlen >> 29);
    md->lengthLo = n;
# endif /* HAVE_NATIVE_INT64 */

    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char) 0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->curlen > 56)
    {
        while (md->curlen < 64)
        {
            md->buf[md->curlen++] = (unsigned char) 0;
        }
        md4_compress(md, md->buf);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56)
    {
        md->buf[md->curlen++] = (unsigned char) 0;
    }

    /* store length */
# ifdef HAVE_NATIVE_INT64
    STORE64L(md->length, md->buf + 56);
# else
    STORE32L(md->lengthLo, md->buf + 56);
    STORE32L(md->lengthHi, md->buf + 60);
# endif /* HAVE_NATIVE_INT64 */
    md4_compress(md, md->buf);

    /* copy output */
    for (i = 0; i < 4; i++)
    {
        STORE32L(md->state[i], out + (4 * i));
    }
    memset(md, 0x0, sizeof(psMd4_t));
    return PS_SUCCESS;
}

#endif /* USE_MATRIX_MD4 */

/******************************************************************************/

