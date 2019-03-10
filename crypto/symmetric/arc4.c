/**
 *      @file    arc4.c
 *      @version $Format:%h%d$
 *
 *      ARC4 stream cipher implementation.
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

#ifdef USE_MATRIX_ARC4

/******************************************************************************/
/*
    SECURITY
    Some accounts, such as O'Reilly's Secure Programming Cookbook say that no
    more than 2^30 bytes should be processed without rekeying, so we
    enforce that limit here.  FYI, this is equal to 1GB of data transferred.
 */
# define ARC4_MAX_BYTES  0x40000000

/******************************************************************************/
/*

 */
int32_t psArc4Init(psArc4_t *arc4, const unsigned char *key, uint8_t keylen)
{
    unsigned char index1, index2, tmp, *state;
    short counter;

    arc4->byteCount = 0;
    state = &arc4->state[0];

    for (counter = 0; counter < 256; counter++)
    {
        state[counter] = (unsigned char) counter;
    }
    arc4->x = 0;
    arc4->y = 0;
    index1 = 0;
    index2 = 0;

    for (counter = 0; counter < 256; counter++)
    {
        index2 = (key[index1] + state[counter] + index2) & 0xff;

        tmp = state[counter];
        state[counter] = state[index2];
        state[index2] = tmp;

        index1 = (index1 + 1) % keylen;
    }
    return PS_SUCCESS;
}

/******************************************************************************/

void psArc4(psArc4_t *arc4, const unsigned char *in,
    unsigned char *out, uint32_t len)
{
    unsigned char x, y, *state, xorIndex, tmp;
    uint32_t counter;

    arc4->byteCount += len;
    if (arc4->byteCount > ARC4_MAX_BYTES)
    {
        psTraceCrypto("ARC4 byteCount overrun\n");
        psAssert(arc4->byteCount <= ARC4_MAX_BYTES);
        memzero_s(arc4, sizeof(psArc4_t));
        return;
    }

    x = arc4->x;
    y = arc4->y;
    state = &arc4->state[0];
    for (counter = 0; counter < len; counter++)
    {
        x = (x + 1) & 0xff;
        y = (state[x] + y) & 0xff;

        tmp = state[x];
        state[x] = state[y];
        state[y] = tmp;

        xorIndex = (state[x] + state[y]) & 0xff;

        tmp = in[counter];
        tmp ^= state[xorIndex];
        out[counter] = tmp;
    }
    arc4->x = x;
    arc4->y = y;
}

void psArc4Clear(psArc4_t *arc4)
{
    memzero_s(arc4, sizeof(psArc4_t));
}

#endif /* USE_MATRIX_ARC4 */

/******************************************************************************/

