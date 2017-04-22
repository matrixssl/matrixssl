/**
 *      @file    sha1.c
 *      @version $Format:%h%d$
 *
 *      SHA1 hash implementation.
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

#ifdef USE_MATRIX_SHA1

/******************************************************************************/

# define F0(x, y, z)   (z ^ (x & (y ^ z)))
# define F1(x, y, z)   (x ^ y ^ z)
# define F2(x, y, z)   ((x & y) | (z & (x | y)))
# define F3(x, y, z)   (x ^ y ^ z)

# ifdef USE_BURN_STACK
static void _sha1_compress(psSha1_t *sha1)
# else
static void sha1_compress(psSha1_t *sha1)
# endif /* USE_BURN_STACK */
{
    uint32 a, b, c, d, e, W[80], i;

# ifndef PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE
    uint32 t;
# endif

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++)
    {
        LOAD32H(W[i], sha1->buf + (4 * i));
    }

    /* copy state */
    a = sha1->state[0];
    b = sha1->state[1];
    c = sha1->state[2];
    d = sha1->state[3];
    e = sha1->state[4];

    /* expand it */
    for (i = 16; i < 80; i++)
    {
        W[i] = ROL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }

    /* compress round one */
# define FF0(a, b, c, d, e, i) e = (ROL(a, 5) + F0(b, c, d) + e + W[i] + 0x5a827999UL); b = ROL(b, 30);
# define FF1(a, b, c, d, e, i) e = (ROL(a, 5) + F1(b, c, d) + e + W[i] + 0x6ed9eba1UL); b = ROL(b, 30);
# define FF2(a, b, c, d, e, i) e = (ROL(a, 5) + F2(b, c, d) + e + W[i] + 0x8f1bbcdcUL); b = ROL(b, 30);
# define FF3(a, b, c, d, e, i) e = (ROL(a, 5) + F3(b, c, d) + e + W[i] + 0xca62c1d6UL); b = ROL(b, 30);

# ifndef PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE
    for (i = 0; i < 20; )
    {
        FF0(a, b, c, d, e, i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 40; )
    {
        FF1(a, b, c, d, e, i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 60; )
    {
        FF2(a, b, c, d, e, i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 80; )
    {
        FF3(a, b, c, d, e, i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }
# else /* PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE */
    for (i = 0; i < 20; )
    {
        FF0(a, b, c, d, e, i++);
        FF0(e, a, b, c, d, i++);
        FF0(d, e, a, b, c, i++);
        FF0(c, d, e, a, b, i++);
        FF0(b, c, d, e, a, i++);
    }

    /* round two */
    for (; i < 40; )
    {
        FF1(a, b, c, d, e, i++);
        FF1(e, a, b, c, d, i++);
        FF1(d, e, a, b, c, i++);
        FF1(c, d, e, a, b, i++);
        FF1(b, c, d, e, a, i++);
    }

    /* round three */
    for (; i < 60; )
    {
        FF2(a, b, c, d, e, i++);
        FF2(e, a, b, c, d, i++);
        FF2(d, e, a, b, c, i++);
        FF2(c, d, e, a, b, i++);
        FF2(b, c, d, e, a, i++);
    }

    /* round four */
    for (; i < 80; )
    {
        FF3(a, b, c, d, e, i++);
        FF3(e, a, b, c, d, i++);
        FF3(d, e, a, b, c, i++);
        FF3(c, d, e, a, b, i++);
        FF3(b, c, d, e, a, i++);
    }
# endif /* PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE */

# undef FF0
# undef FF1
# undef FF2
# undef FF3

    /* store */
    sha1->state[0] = sha1->state[0] + a;
    sha1->state[1] = sha1->state[1] + b;
    sha1->state[2] = sha1->state[2] + c;
    sha1->state[3] = sha1->state[3] + d;
    sha1->state[4] = sha1->state[4] + e;
}

# ifdef USE_BURN_STACK
static void sha1_compress(psSha1_t *sha1)
{
    _sha1_compress(sha1);
    psBurnStack(sizeof(uint32) * 87);
}
# endif /* USE_BURN_STACK */

/******************************************************************************/

int32_t psSha1Init(psSha1_t *sha1)
{
# ifdef CRYPTO_ASSERT
    psAssert(sha1 != NULL);
# endif
    sha1->state[0] = 0x67452301UL;
    sha1->state[1] = 0xefcdab89UL;
    sha1->state[2] = 0x98badcfeUL;
    sha1->state[3] = 0x10325476UL;
    sha1->state[4] = 0xc3d2e1f0UL;
    sha1->curlen = 0;
# ifdef HAVE_NATIVE_INT64
    sha1->length = 0;
# else
    sha1->lengthHi = 0;
    sha1->lengthLo = 0;
# endif /* HAVE_NATIVE_INT64 */
    return PS_SUCCESS;
}

void psSha1Update(psSha1_t *sha1, const unsigned char *buf, uint32_t len)
{
    uint32_t n;

# ifdef CRYPTO_ASSERT
    psAssert(sha1 != NULL);
    psAssert(buf != NULL);
# endif
    while (len > 0)
    {
        n = min(len, (64 - sha1->curlen));
        memcpy(sha1->buf + sha1->curlen, buf, (size_t) n);
        sha1->curlen    += n;
        buf             += n;
        len             -= n;

        /* is 64 bytes full? */
        if (sha1->curlen == 64)
        {
            sha1_compress(sha1);
# ifdef HAVE_NATIVE_INT64
            sha1->length += 512;
# else
            n = (sha1->lengthLo + 512) & 0xFFFFFFFFL;
            if (n < sha1->lengthLo)
            {
                sha1->lengthHi++;
            }
            sha1->lengthLo = n;
# endif     /* HAVE_NATIVE_INT64 */
            sha1->curlen = 0;
        }
    }
}

/******************************************************************************/

void psSha1Final(psSha1_t *sha1, unsigned char hash[SHA1_HASHLEN])
{
    int32 i;

# ifndef HAVE_NATIVE_INT64
    uint32 n;
# endif
# ifdef CRYPTO_ASSERT
    psAssert(sha1 != NULL);
    if (sha1->curlen >= sizeof(sha1->buf) || hash == NULL)
    {
        psTraceCrypto("psSha1Final error\n");
        return;
    }
# endif
    /* increase the length of the message */
# ifdef HAVE_NATIVE_INT64
    sha1->length += sha1->curlen << 3;
# else
    n = (sha1->lengthLo + (sha1->curlen << 3)) & 0xFFFFFFFFL;
    if (n < sha1->lengthLo)
    {
        sha1->lengthHi++;
    }
    sha1->lengthHi += (sha1->curlen >> 29);
    sha1->lengthLo = n;
# endif /* HAVE_NATIVE_INT64 */

    /* append the '1' bit */
    sha1->buf[sha1->curlen++] = (unsigned char) 0x80;

    /*
       if the length is currently above 56 bytes we append zeros then compress.
       Then we can fall back to padding zeros and length encoding like normal.
     */
    if (sha1->curlen > 56)
    {
        while (sha1->curlen < 64)
        {
            sha1->buf[sha1->curlen++] = (unsigned char) 0;
        }
        sha1_compress(sha1);
        sha1->curlen = 0;
    }
    /* pad upto 56 bytes of zeroes */
    while (sha1->curlen < 56)
    {
        sha1->buf[sha1->curlen++] = (unsigned char) 0;
    }
    /* store length */
# ifdef HAVE_NATIVE_INT64
    STORE64H(sha1->length, sha1->buf + 56);
# else
    STORE32H(sha1->lengthHi, sha1->buf + 56);
    STORE32H(sha1->lengthLo, sha1->buf + 60);
# endif /* HAVE_NATIVE_INT64 */
    sha1_compress(sha1);

    /* copy output */
    for (i = 0; i < 5; i++)
    {
        STORE32H(sha1->state[i], hash + (4 * i));
    }
    memset(sha1, 0x0, sizeof(psSha1_t));
}

#endif /* USE_MATRIX_SHA1 */

/******************************************************************************/

