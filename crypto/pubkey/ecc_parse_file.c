/**
 *      @file    ecc_parse_file.c
 *      @version $Format:%h%d$
 *
 *      Functions for parsing ECC keys from file.
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

/******************************************************************************/

#ifdef USE_ECC
# if defined(MATRIX_USE_FILE_SYSTEM) && defined(USE_PRIVATE_KEY_PARSING)
/******************************************************************************/
/*
    ECPrivateKey{CURVES:IOSet} ::= SEQUENCE {
        version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        privateKey OCTET STRING,
        parameters [0] Parameters{{IOSet}} OPTIONAL,
        publicKey [1] BIT STRING OPTIONAL
    }

 */
int32_t psEccParsePrivFile(psPool_t *pool, const char *fileName,
    const char *password, psEccKey_t *key)
{
    unsigned char *DERout;
    int32_t rc;
    psSize_t DERlen;

#  ifdef USE_PKCS8
    psPubKey_t pubkey;
#  endif

    if ((rc = psPkcs1DecodePrivFile(pool, fileName, password, &DERout, &DERlen)) < 0)
    {
        return rc;
    }

    if ((rc = psEccParsePrivKey(pool, DERout, DERlen, key, NULL)) < 0)
    {
#  ifdef USE_PKCS8
        /* This logic works for processing PKCS#8 files because the above file
            and bin decodes will always leave the unprocessed buffer intact and
            the password protection is done in the internal ASN.1 encoding */
        if ((rc = psPkcs8ParsePrivBin(pool, DERout, DERlen, (char *) password,
                 &pubkey)) < 0)
        {
            psFree(DERout, pool);
            return rc;
        }
        psEccInitKey(pool, key, key->curve);
        rc = psEccCopyKey(key, &pubkey.key.ecc);
        psClearPubKey(&pubkey);
#  else
        psFree(DERout, pool);
        return rc;
#  endif
    }
    psFree(DERout, pool);
    return PS_SUCCESS;
}

# ifdef USE_ED25519
int32_t psEd25519ParsePrivFile(psPool_t *pool,
        const char *fileName,
        const char *password,
        psCurve25519Key_t *key)
{
    int32_t rc;
    unsigned char *keyDer;
    psSize_t keyDerLen;

    if ((rc = psPkcs1DecodePrivFile(pool,
                            fileName,
                            password,
                            &keyDer,
                            &keyDerLen)) < 0)
    {
        psTraceIntCrypto("Could not parse Ed25519 PEM file: %d\n", rc);
        return rc;
    }

    rc = psEd25519ParsePrivKey(pool,
            keyDer,
            keyDerLen,
            key);
    if (rc < 0)
    {
        psFree(keyDer, pool);
        psTraceIntCrypto("psEd25519ParsePrivKey failed: %d\n", rc);
        return rc;
    }

    psFree(keyDer, pool);

    return PS_SUCCESS;
}
# endif /* USE_ED25519 */
# endif /* MATRIX_USE_FILE_SYSTEM && USE_PRIVATE_KEY_PARSING */
#endif /* USE_ECC */

