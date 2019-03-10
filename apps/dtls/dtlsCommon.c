/**
 *      @file    dtlsCommon.c
 *      @version $Format:%h%d$
 */
/*
 *      Copyright (c) 2014-2017 INSIDE Secure Corporation
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

#include "dtlsCommon.h"
/* Currently this example uses _psTrace for tracing, so osdep.h is needed: */
#include "core/osdep.h"
#include "core/psUtil.h"

#ifdef USE_DTLS

# ifdef DTLS_PACKET_LOSS_TEST
static int num_dropped = 0;
# endif /* DTLS_PACKET_LOSS_TEST */

/******************************************************************************/
/*
    Set up a PRNG context for dropping random packets
 */
void udpInitProxy(void)
{
    /* This function is no longer needed, since we are
       using psGetPrngLocked instead of psGetPrng. */
}

/******************************************************************************/
/*
    Wrapper around sendto to easily plug in and out the dropped packet tests
 */
int32 udpSend(SOCKET s, unsigned char *buf, int len,
    const struct sockaddr *to, int tolen, int flags,
    int packet_loss_prob, int *drop_rehandshake_cipher_spec)
{
    int32 sent;

# ifdef DTLS_PACKET_LOSS_TEST
#  ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
    if (drop_rehandshake_cipher_spec != NULL
        && *drop_rehandshake_cipher_spec == 1)
    {
        /* Test dropping a CIPHER_SPEC_CHANGE containing the new cipher spec
           during a re-handshake. */
        if (buf[12] == 0x40 ||
            buf[12] == 0x26     /* Quick hack: use record length to find our re-handshake
                                   CIPHER_SPEC_CHANGE. Note: this trick will probably
                                   only work in our current test scenario and may stop
                                   working if e.g. the ciphers used in the test
                                   are changed. */
            )
        {
            *drop_rehandshake_cipher_spec = 0;
            psTraceIntDtls("Didn't send (CHANGE_CIPHER_SPEC flight): %d\n", len);
            ++num_dropped;
        }
        else
        {
            if ((sent = sendto(s, buf, len, 0, to, tolen)) < 0)
            {
                return -1;
            }
            psTraceIntDtls("Sent %d bytes\n", sent);
        }
    }
    else
    {
#  endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
         /* Test random packet loss. */
    uint32 randInt;
    (void) psGetPrngLocked((unsigned char *) &randInt,
        sizeof(uint32), NULL);

    if ((packet_loss_prob == 0) || (randInt % packet_loss_prob))
    {
        if ((sent = sendto(s, buf, len, 0, to, tolen)) < 0)
        {
            return -1;
        }
        psTraceIntDtls("Sent %d bytes\n", sent);
    }
    else
    {
        /* flags is used here as the current timeout value.  if it's too high
           we've already skipped a few sends so let's not timeout */
        if (flags >= 16)
        {
            if ((sent = sendto(s, buf, len, 0, to, tolen)) < 0)
            {
                return -1;
            }
            psTraceIntDtls("Sent %d bytes\n", sent);
        }
        else
        {
            psTraceIntDtls("Didn't send: %d\n", len);
            ++num_dropped;
        }
    }
#  ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
}
#  endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
# else
    if ((sent = (int32) sendto(s, buf, len, 0, to, tolen)) < 0)
    {
        return -1;
    }
    psTraceIntDtls("Sent %d bytes\n", sent);
# endif /* DTLS_PACKET_LOSS_TEST */
# ifdef DTLS_PACKET_LOSS_TEST
    psTraceIntDtls("%d packets dropped so far\n",
        num_dropped);
# endif /* DTLS_PACKET_LOSS_TEST */
    return len;
}

#endif /* USE_DTLS */
