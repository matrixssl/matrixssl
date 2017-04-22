/**
 *      @file    idea.c
 *      @version $Format:%h%d$
 *
 *      IDEA-CBC. This code is based on Xuejia Lai: On the Design and Security of.
 *      Block Ciphers, ETH Series in Information Processing, vol. 1,
 *      Hartung-Gorre Verlag, Konstanz, Switzerland, 1992.  Another source
 *      was Bruce Schneier: Applied Cryptography, John Wiley & Sons, 1994
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
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

#ifdef USE_MATRIX_IDEA

/******************************************************************************/

# define LOAD16H(x, y) { \
        x = ((uint16) ((y)[0] & 255) << 8) | ((uint16) ((y)[1] & 255)); \
}

/* Performs the "multiplication" operation of IDEA: returns a*b mod 65537,
   where a and b are first converted to 65536 if they are zero, and result
   65536 is converted to zero.  Both inputs should be less than 65536.
   Only the lower 16 bits of result are significant; other bits are garbage.
 */

static __inline uint32 idea_mulop(uint32 a, uint32 b)
{
    uint32 ab = a * b;

    if (ab != 0)
    {
        uint32 lo = ab & 0xffff;
        uint32 hi = (ab >> 16) & 0xffff;
        return (lo - hi) + (lo < hi);
    }
    if (a == 0)
    {
        return 1 - b;
    }
    return 1 - a;
}

/* Computes the multiplicative inverse of a modulo 65537. The algorithm
   used is the Euclid's. */

static __inline uint32 idea_mulinv(uint32 a)
{
    long n1, n2, q, r, b1, b2, t;

    if (a == 0)
    {
        return 0;
    }

    n1 = 65537; n2 = (long) a; b2 = 1; b1 = 0;
    do
    {
        r = n1 % n2;
        q = (n1 - r) / n2;
        if (r == 0)
        {
            if (b2 < 0)
            {
                b2 += 65537;
            }
        }
        else
        {
            n1 = n2;
            n2 = r;
            t = b2;
            b2 = b1 - q * b2;
            b1 = t;
        }
    }
    while (r != 0);

    return (uint32) b2;
}

static void idea_transform(uint32 l, uint32 r, uint32 *output,
    int for_encryption, psIdeaKey_t *c)
{
    unsigned int round;
    uint16 *keys;
    uint32 t1, t2, x1, x2, x3, x4;

    keys = c->key_schedule;
    x1 = l >> 16;
    x2 = l;
    x3 = r >> 16;
    x4 = r;
    for (round = 0; round < 8; round++)
    {
        x1 = idea_mulop(x1 & 0xffff, keys[0]);
        x3 = x3 + keys[2];
        x4 = idea_mulop(x4 & 0xffff, keys[3]);
        x2 = x2 + keys[1];
        t1 = x1 ^ x3;
        t2 = x2 ^ x4;
        t1 = idea_mulop(t1 & 0xffff, keys[4]);
        t2 = t1 + t2;
        t2 = idea_mulop(t2 & 0xffff, keys[5]);
        t1 = t1 + t2;
        x1 = x1 ^ t2;
        x4 = x4 ^ t1;
        t1 = t1 ^ x2;
        x2 = t2 ^ x3;
        x3 = t1;
        keys += 6;
    }
    x1 = idea_mulop(x1 & 0xffff, keys[0]);
    x3 = (x2 + keys[2]) & 0xffff;
    x2 = t1 + keys[1]; /* t1 == old x3 */
    x4 = idea_mulop(x4 & 0xffff, keys[3]);
    output[0] = (x1 << 16) | (x2 & 0xffff);
    output[1] = (x3 << 16) | (x4 & 0xffff);
}

static int32_t psIdeaInitKey(const unsigned char key[IDEA_KEYLEN],
    psIdeaKey_t *skey)
{
    int i;
    uint16 *keys;

    /* Get pointer to the keys. */
    keys = skey->key_schedule;

    /* Keys for the first round are taken from the user-supplied key. */
    for (i = 0; i < 8; i++)
    {
        LOAD16H(keys[i], key + 2 * i);
    }

    /*  Each round uses the key of the previous key, rotated to the left by 25
        bits.  The last four keys (output transform) are the first four keys
        from what would be the ninth round. */
    for (i = 8; i < 52; i++)
    {
        if ((i & 7) == 0)
        {
            keys += 8;
        }
        keys[i & 7] = ((keys[((i + 1) & 7) - 8] << 9) |
                       (keys[((i + 2) & 7) - 8] >> 7)) & 0xffff;
    }

    return 0;
}

/******************************************************************************/
/* Sets idea key and IV for CBC crypto */
int32_t psIdeaInit(psIdea_t *idea, const unsigned char IV[IDEA_IVLEN],
    const unsigned char key[IDEA_KEYLEN])
{
    int32_t err;

    if (IV == NULL || key == NULL || idea == NULL)
    {
        psTraceCrypto("psIdeaInit arg fail\n");
        return PS_ARG_FAIL;
    }
    memset(idea, 0x0, sizeof(psIdea_t));
    /* setup cipher */
    if ((err = psIdeaInitKey(key, &idea->key))
        != PS_SUCCESS)
    {
        return err;
    }
    /* copy IV */
    LOAD32H(idea->IV[0], IV);
    LOAD32H(idea->IV[1], IV + 4);
    return PS_SUCCESS;

}

/******************************************************************************/

void psIdeaDecrypt(psIdea_t *idea, const unsigned char *ct,
    unsigned char *pt, uint32_t len)
{
    psIdeaKey_t *key;
    uint16 *keys;
    uint16 temp[52];
    uint32 tmp[2];
    uint32 l, r, iv[2], processed;
    int i;


    key = &idea->key;
    processed = len;
    iv[0] = idea->IV[0];
    iv[1] = idea->IV[1];

    /* Our mechanism doesn't distinguish encrypt from decrypt at the init
        stage so we wait until decrypt is called to invert the first time */
    if (idea->inverted == 0)
    {
        keys = key->key_schedule;

# define MULINV(x, y) temp[x] = idea_mulinv(keys[y])
# define ADDINV(x, y) temp[x] = (65536 - keys[y]) & 0xFFFF;
# define STRAIG(x, y) temp[x] = keys[y]

        MULINV(0, 48);
        ADDINV(1, 49);
        ADDINV(2, 50);
        MULINV(3, 51);

        STRAIG(4, 46);
        STRAIG(5, 47);

        for (i = 6; i < 48; i += 6)
        {
            MULINV(i, 48 - i);
            ADDINV(i + 1, 48 - i + 2);
            ADDINV(i + 2, 48 - i + 1);
            MULINV(i + 3, 48 - i + 3);
            STRAIG(i + 4, 42 - i + 4);
            STRAIG(i + 5, 42 - i + 5);
        }

        MULINV(48, 0);
        ADDINV(49, 1);
        ADDINV(50, 2);
        MULINV(51, 3);

# undef MULINV
# undef ADDINV
# undef STRAIG

        /* Copy the new key to replace the original and replace the
            temporal data with zeros. */

        memcpy(key->key_schedule, temp, sizeof(uint16) * 52);
        memset(temp, 0, sizeof(uint16) * 52);
        idea->inverted = 1;
    }

    while (processed)
    {
        LOAD32H(l, ct);
        LOAD32H(r, ct + 4);

        idea_transform(l, r, tmp, 0, &idea->key);

        tmp[0] ^= iv[0];
        tmp[1] ^= iv[1];

        STORE32H(tmp[0], pt);
        pt += 4;
        STORE32H(tmp[1], pt);
        pt += 4;

        iv[0] = l;
        iv[1] = r;

        ct += 8;
        processed -= 8;
    }
    idea->IV[0] = iv[0];
    idea->IV[1] = iv[1];
}

/******************************************************************************/

void psIdeaEncrypt(psIdea_t *idea, const unsigned char *pt,
    unsigned char *ct, uint32_t len)
{
    uint32 l, r, iv[2], processed;

    processed = len;
    iv[0] = idea->IV[0];
    iv[1] = idea->IV[1];

    while (processed)
    {
        LOAD32H(l, pt);
        l = l ^ iv[0];

        LOAD32H(r, pt + 4);
        r = r ^ iv[1];

        idea_transform(l, r, iv, 1, &idea->key);

        STORE32H(iv[0], ct);
        ct += 4;
        STORE32H(iv[1], ct);
        ct += 4;

        pt += 8;
        processed -= 8;
    }

    idea->IV[0] = iv[0];
    idea->IV[1] = iv[1];
}

/******************************************************************************/

void psIdeaClear(psIdea_t *idea)
{
    memzero_s(idea, sizeof(psIdea_t));
}

#endif /* USE_MATRIX_IDEA */

/******************************************************************************/

