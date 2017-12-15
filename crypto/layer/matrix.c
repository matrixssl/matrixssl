/**
 *      @file    matrix.c
 *      @version $Format:%h%d$
 *
 *      Matrix Crypto Initialization and utility layer.
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

/******************************************************************************/
/**
    Open (initialize) the Crypto module.

    The config param should always be passed as:
        PSCRYPTO_CONFIG
 */
static char g_config[32] = "N";

int32_t psCryptoOpen(const char *config)
{
    uint32_t clen;
    
    if (*g_config == 'Y')
    {
        return PS_SUCCESS; /* Function has been called previously */
    }

    /* 'config' is cryptoconfig + coreconfig */
    clen = strlen(PSCRYPTO_CONFIG) - strlen(PSCORE_CONFIG);
    if (strncmp(PSCRYPTO_CONFIG, config, clen) != 0)
    {
        psErrorStr( "Crypto config mismatch.\n" \
            "Library: " PSCRYPTO_CONFIG \
            "\nCurrent: %s\n", config);
        return PS_FAILURE;
    }
    if (psCoreOpen(config + clen) < 0)
    {
        psError("pscore open failure\n");
        return PS_FAILURE;
    }

#ifdef USE_FLPS_BINDING
    flps_binding();
    /* Check if FIPS Library Open failed. */
    if ((int)CLS_LibStatus(flps_getCLS()) < 0)
    {
        return PS_SELFTEST_FAILED;
    }
#endif /* USE_FLPS_BINDING */
#ifdef USE_LIBSODIUM_CRYPTO
    if (sodium_init() == -1)
    {
        return PS_FAILURE;
    }
#endif /* USE_LIBSODIUM_CRYPTO */
#ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
    /* Pick chacha20-poly1305 implementation. */
    {
        psChacha20Poly1305Ietf_t tmp;
        (void) psChacha20Poly1305IetfInit(
                &tmp,
                (const unsigned char *)g_config /* at least 32 bytes */);
    }
#endif

    psOpenPrng();
#ifdef USE_CRL
    psCrlOpen();
#endif
    /* Everything successful, store configuration. */
    strncpy(g_config, PSCRYPTO_CONFIG, sizeof(g_config) - 1);

    return PS_SUCCESS;
}

void psCryptoClose(void)
{
    if (*g_config == 'Y')
    {
        *g_config = 'N';
        psClosePrng();
        psCoreClose();
#ifdef USE_CRL
        psCrlClose();
#endif
    }
}

/******************************************************************************/
