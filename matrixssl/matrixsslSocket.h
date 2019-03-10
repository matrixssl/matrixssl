/* matrixsslSocket.h
 *
 * Build psSocket_t based on matrixsslNet.
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
*
* The latest version of this code is available at http://www.matrixssl.org
*
* This software is open source; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This General Public License does NOT permit incorporating this software
* into proprietary programs.  If you are unable to comply with the GPL, a
* commercial license for this software may be purchased from INSIDE at
* http://www.insidesecure.com/
*
* This program is distributed in WITHOUT ANY WARRANTY; without even the
* implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef INCLUDE_GUARD_MATRIXSSLSOCKET_H
#define INCLUDE_GUARD_MATRIXSSLSOCKET_H

/* This code is extension on core.h's USE_PS_NETWORKING */
#include "coreApi.h"

#ifdef USE_PS_NETWORKING

/* Obtain TLS socket internally using MatrixSSL. */
const psSocketFunctions_t *psGetSocketFunctionsTLS(void);

struct psSocketTls
{
    /* Configuration items for TLS Socket. */
    const char *capath;
    int tls_version;
    int ciphers;
    const psCipher16_t *cipherlist;
    /* Internal use only */
    int nested_call;
    int handshaked;
    matrixSslInteract_t msi;
    int32 (*ssl_socket_cert_auth)(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
};

/* Set certificate callback for psSockets of TLS type. */
void setSocketTlsCertAuthCb(
        psSocket_t *sock,
        int32 (*ssl_cert_auth_cb)(ssl_t *ssl, psX509Cert_t *cert, int32 alert));

#endif /* USE_PS_NETWORKING */

#endif /* INCLUDE_GUARD_MATRIXSSLSOCKET_H */

/* end of file matrixsslSocket.h */
