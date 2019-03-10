/**
 *      @file    ecc_curve_config.c
 *      @version $Format:%h%d$
 *
 *      Functions for ECC curve configuration, e.g. default curve
 *      specification. Implementations may be different for FIPS and
 *      non-FIPS modes or for different crypto libraries.
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

#ifdef USE_MATRIX_ECC

int32_t getEccParamById(psCurve16_t curveId, const psEccCurve_t **curve)
{
    int i = 0;

    /* A curveId of zero is asking for a default curve */
    if (curveId == 0)
    {
        *curve = &eccCurves[0];
        return 0;
    }

    *curve = NULL;
    while (eccCurves[i].size > 0)
    {
        if (curveId == eccCurves[i].curveId)
        {
            *curve = &eccCurves[i];
            return 0;
        }
        i++;
    }
    return PS_FAIL;
}

/**
    User set list of curves they want to support.
    This method will put the largest bit strength first in the list.
    @param[in] curves Flags indicating which curves to use.
 */
void userSuppliedEccList(unsigned char *curveList, uint8_t *len, uint32_t curves)
{
    const psEccCurve_t *curve;
    uint8_t listLen = 0;

# ifdef USE_SECP521R1
    if (curves & IS_SECP521R1)
    {
        if (getEccParamById(IANA_SECP521R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_BRAIN512R1
    if (curves & IS_BRAIN512R1)
    {
        if (getEccParamById(IANA_BRAIN512R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_SECP384R1
    if (curves & IS_SECP384R1)
    {
        if (getEccParamById(IANA_SECP384R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_BRAIN384R1
    if (curves & IS_BRAIN384R1)
    {
        if (getEccParamById(IANA_BRAIN384R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_SECP256R1
    if (curves & IS_SECP256R1)
    {
        if (getEccParamById(IANA_SECP256R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_BRAIN256R1
    if (curves & IS_BRAIN256R1)
    {
        if (getEccParamById(IANA_BRAIN256R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_SECP224R1
    if (curves & IS_SECP224R1)
    {
        if (getEccParamById(IANA_SECP224R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_BRAIN224R1
    if (curves & IS_BRAIN224R1)
    {
        if (getEccParamById(IANA_BRAIN224R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif
# ifdef USE_SECP192R1
    if (curves & IS_SECP192R1)
    {
        if (getEccParamById(IANA_SECP192R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
# endif

    *len = listLen;
}

uint32_t compiledInEcFlags(void)
{
    uint32_t ecFlags = 0;

# ifdef USE_SECP192R1
    ecFlags |= IS_SECP192R1;
# endif
# ifdef USE_SECP224R1
    ecFlags |= IS_SECP224R1;
# endif
# ifdef USE_SECP256R1
    ecFlags |= IS_SECP256R1;
# endif
# ifdef USE_SECP384R1
    ecFlags |= IS_SECP384R1;
# endif
# ifdef USE_SECP521R1
    ecFlags |= IS_SECP521R1;
# endif
# ifdef USE_BRAIN224R1
    ecFlags |= IS_BRAIN224R1;
# endif
# ifdef USE_BRAIN256R1
    ecFlags |= IS_BRAIN256R1;
# endif
# ifdef USE_BRAIN384R1
    ecFlags |= IS_BRAIN384R1;
# endif
# ifdef USE_BRAIN512R1
    ecFlags |= IS_BRAIN512R1;
# endif

    return ecFlags;
}

#endif  /* USE_MATRIX_ECC */

