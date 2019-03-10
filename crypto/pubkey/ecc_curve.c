/**
 *      @file    ecc_curve.c
 *      @version $Format:%h%d$
 *
 *      ECC curve data getter functions.
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

# ifdef USE_ECC

/******************************************************************************/

/**
    ECC key size in bytes.
    @return Public key size in bytes if key->type is public, otherwise private size.
    @note ECC public keys are twice as many bytes as private keys.
 */
uint8_t psEccSize(const psEccKey_t *key)
{
    if (key && key->curve)
    {
        return key->curve->size * 2;
    }
    return 0;
}

int32_t getEccParamByOid(uint32_t oid, const psEccCurve_t **curve)
{
    int i = 0;

    *curve = NULL;
    while (eccCurves[i].size > 0)
    {
        if (oid == eccCurves[i].OIDsum)
        {
            *curve = &eccCurves[i];
            return 0;
        }
        i++;
    }
    return PS_FAIL;
}

int32_t getEccParamByName(const char *curveName,
    const psEccCurve_t **curve)
{
    int i = 0;

    *curve = NULL;
    while (eccCurves[i].size > 0)
    {
        if (Strcmp(curveName, eccCurves[i].name) == 0)
        {
            *curve = &eccCurves[i];
            return 0;
        }
        i++;
    }
    return PS_FAIL;
}

/**
    Return a list of all supported curves.
    This method will put the largest bit strength first in the list, because
    of their order in the eccCurves[] array.
 */
void psGetEccCurveIdList(unsigned char *curveList, uint8_t *len)
{
    psSize_t listLen = 0, i = 0;

    while (eccCurves[i].size > 0)
    {
        if (listLen < (*len - 2))
        {
            curveList[listLen++] = (eccCurves[i].curveId & 0xFF00) >> 8;
            curveList[listLen++] = eccCurves[i].curveId & 0xFF;
        }
        i++;
    }
    *len = listLen;
}

#endif  /* USE_ECC */

