/**
 *      @file    pem_decode_file.c
 *      @version $Format:%h%d$
 *
 *      Functions for PEM file decoding. For in-memory decoding, see
 *      pem_decode_mem.c
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
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

# if defined(USE_PEM_DECODE) && defined(MATRIX_USE_FILE_SYSTEM)

int32_t psPemFileToDer(psPool_t *pool,
        const char *fileName,
        const char *password,
        psPemType_t expectedPemType,
        unsigned char **derOut,
        psSizeL_t *derOutLen)
{
    unsigned char *pemBuf;
    psSizeL_t pemBufLen;
    psRes_t rc;

    if (fileName == NULL)
    {
        psTraceCrypto("psPemFileToDer: no fileName passed in\n");
        return PS_ARG_FAIL;
    }

    rc = psGetFileBuf(pool,
            fileName,
            &pemBuf,
            &pemBufLen);
    if (rc < PS_SUCCESS)
    {
        psTraceCrypto("psPemFileToDer: psGetFileBuf failed\n");
        return rc;
    }
    if (!psPemCheckOk(pemBuf,
                    pemBufLen,
                    expectedPemType,
                    NULL,
                    NULL,
                    NULL))
    {
        psTraceCrypto("psPemFileToDer: file not in expected PEM format\n");
        return PS_FAILURE;
    }
    rc = psPemDecode(pool,
            pemBuf,
            pemBufLen,
            password,
            derOut,
            derOutLen);
    psFree(pemBuf, pool);
    return rc;
}
# endif /* USE_PEM_DECODE && MATRIX_USE_FILE_SYSTEM */
