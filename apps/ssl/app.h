/**
 *      @file    app.h
 *      @version $Format:%h%d$
 *
 *      Header for MatrixSSL example sockets client and server applications.
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

#ifndef _h_MATRIXSSLAPP
# define _h_MATRIXSSLAPP

# ifdef __cplusplus
extern "C" {
# endif
/******************************************************************************/

# include "core/coreApi.h"
# include "matrixssl/matrixsslApi.h"

# include <errno.h>         /* Defines EWOULDBLOCK, etc. */
# include <fcntl.h>         /* Defines FD_CLOEXEC, etc. */
# include <stdlib.h>        /* Defines malloc, exit, etc. */

# ifdef POSIX
#  include <netdb.h>        /* Defines AF_INET, etc. */
#  include <unistd.h>       /* Defines close() */
#  include <netinet/tcp.h>  /* Defines TCP_NODELAY, etc. */
#  include <arpa/inet.h>    /* inet_addr */
# endif

# ifdef WIN32
#  define SIGPIPE         SIGABRT
#  define snprintf        _snprintf
#  define close           closesocket
#  define MSG_DONTWAIT    0
#  ifndef EWOULDBLOCK
#   define EWOULDBLOCK     WSAEWOULDBLOCK
#  endif
#  ifndef EINPROGRESS
#   define EINPROGRESS     WSAEINPROGRESS
#  endif
# endif /* WIN32 */

/******************************************************************************/
/*
     Platform independent socket defines for convenience
 */
# ifndef INVALID_SOCKET
#  define INVALID_SOCKET (-1)
typedef int32 SOCKET;
# endif

# ifdef WIN32
#  define SOCKET_ERRNO   WSAGetLastError()
# else
#  define SOCKET_ERRNO   errno
# endif

/******************************************************************************/
/*
    Configuration Options
 */
# define HTTPS_PORT      4433   /* Port to run the server/client on */

/******************************************************************************/
/*
    Protocol specific defines
 */
/* Maximum size of parseable http element. In this case, a HTTP header line. */
# define HTTPS_BUFFER_MAX 256

/* Return codes from http parsing routine */
# define HTTPS_COMPLETE  1               /* Full request/response parsed */
# define HTTPS_PARTIAL   0               /* Only a partial request/response was received */
# define HTTPS_ERROR     MATRIXSSL_ERROR /* Invalid/unsupported HTTP syntax */

typedef struct
{
    DLListEntry List;
    ssl_t *ssl;
    SOCKET fd;
    psTime_t time;              /* Last time there was activity */
    uint32 timeout;             /* in milliseconds*/
    uint32 flags;
    unsigned char *parsebuf;    /* Partial data */
    uint32 parsebuflen;
    uint32 bytes_received;
    uint32 bytes_requested;
    uint32 bytes_sent;
    psPool_t *bufPool;          /* Mem pool to allocate inbuf and outbuf */
} httpConn_t;

extern int32 httpBasicParse(httpConn_t *cp, unsigned char *buf, uint32 len,
                            int32 trace);

/******************************************************************************/

# ifdef __cplusplus
}
# endif

#endif /* _h_MATRIXSSLAPP */

/******************************************************************************/
