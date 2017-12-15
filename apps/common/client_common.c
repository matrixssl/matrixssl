/**
 *      @file    client_common.c
 *      @version $Format:%h%d$
 *
 *      MatrixSSL client common code.
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

#include "client_common.h"

int g_enable_ext_cv_sig_op = 0;

/* Default RSA key length */
int g_key_len = 2048;

/* Append data of size datasize to buf of bufsize
   Bufused must be the number of bytes used of buf and is updated at return
   Returns 0 if failed, 1 otherwise.
 */
int appendCACert(unsigned char *buf, const size_t bufsize, size_t *bufused,
                 const unsigned char *data, const size_t datasize)
{
    if (datasize > bufsize - *bufused ) {
        return 0; /* Does not fit into the buffer */
    }

    memcpy(buf + *bufused, data, datasize);
    *bufused += datasize;
    return 1;
}

/* Append str to strbuf, adding separator between the strings
   Returns 0 if failed, 1 otherwise.
 */
int appendCAFilename(char *strbuf, const size_t strbufsize, const char *str)
{
    static const char *sep = ";";
    const size_t strbuflen = strlen(strbuf);
    const size_t strseplen = (strbuflen == 0 ? 0 : strlen(sep));
    const size_t bufUnused = strbufsize - strbuflen - 1;
    const size_t len = strlen(str);

    if (len == 0) {
        return 1;
    }

    if (len + strseplen > bufUnused) {
        return 0; /* Does not fit into the buffer */
    }

    if (strseplen) {
        strncat(strbuf, sep, bufUnused - len);
    }

    strncat(strbuf, str, bufUnused - strseplen);
    return 1;
}
