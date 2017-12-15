/**
 *      @file    dtlsCommon.h
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

#ifndef _h_DTLSCOMMON
# define _h_DTLSCOMMON

# include "matrixssl/matrixsslApi.h"

# ifdef USE_DTLS

#  include <stdlib.h>
#  include <string.h>
#  include <stdio.h>
#  include <fcntl.h>        /* Defines FD_CLOEXEC, etc. */
#  include <errno.h>        /* Defines EWOULDBLOCK, etc. */

#  ifdef POSIX
#   define USE_GETOPT_LONG
#   ifdef USE_GETOPT_LONG
#    include <getopt.h>
#   endif
#   include <unistd.h>
#   include <netdb.h>      /* Defines AF_INET, etc. */
#   include <sys/socket.h> /* sockaddr */
#   include <arpa/inet.h>  /* inet_addr */
#  endif /* POSIX */

#  ifdef WIN32
#   include <WinSock2.h>
#   include <WS2tcpip.h>

#   define SIGPIPE         SIGABRT
#   define close           closesocket
#   define MSG_DONTWAIT    0
#  endif /* WIN32 */

#  ifdef __cplusplus
extern "C" {
#  endif

#  ifndef SOCKET
typedef int SOCKET;
#  endif

/*
    Timeout and debug settings
 */
#  define MIN_WAIT_SECS   1  /* SHOULD be 1.  Also the default */
#  define MAX_WAIT_SECS   32 /* SHOULD be 2^x as time is doubled on timeout */

/*
    Enable to intentially not send some datagrams for testing purposes
 */
#  ifndef DTLS_PACKET_LOSS_TEST
/* #define DTLS_PACKET_LOSS_TEST */
#  endif /* DTLS_PACKET_LOSS_TEST */

/*
   Enable a test where the client tries to change the cipher spec during
   a re-handshake and the resulting CHANGE_CIPHER_SPEC message is lost.
   Requires #define DTLS_PACKET_LOST_TEST.
 */
#  ifdef DTLS_PACKET_LOSS_TEST
#   ifndef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
/* #define DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
#   endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
#  endif  /* DTLS_PACKET_LOSS_TEST */

#  define DTLS_FATAL  -1


#  ifdef WIN32
#   define SOCKET_ERRNO    WSAGetLastError()
#  else
#   define SOCKET_ERRNO    errno
#  endif

#  ifndef INVALID_SOCKET
#   define INVALID_SOCKET  -1
#  endif

extern void udpInitProxy(void);
extern int32 udpSend(SOCKET s, unsigned char *buf, int len,
                     const struct sockaddr *to, int tolen, int flags,
                     int packet_loss_prob, int *drop_rehandshake_cipher_spec);

#  ifdef __cplusplus
}
#  endif

# endif /* USE_DTLS */
#endif  /* _h_DTLSCOMMON */

/******************************************************************************/
