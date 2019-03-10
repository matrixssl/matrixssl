/**
 *      @file    rsa_parse_file.c
 *      @version $Format:%h%d$
 *
 *      Functions for parsing RSA keys from file.
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

#  ifdef MATRIX_USE_FILE_SYSTEM

#   ifdef USE_RSA
int32_t psPkcs1ParsePubFile(psPool_t *pool, const char *fileName,
        psRsaKey_t *key)
{
#   ifdef USE_PEM_DECODE
    unsigned char *DERout;
    unsigned char sha1KeyHash[SHA1_HASH_SIZE];
    const unsigned char *p, *end;
    int32_t rc, oi;
    psSizeL_t DERlen;
    const unsigned char *publicKey;

    rc = psPemFileToDer(pool,
            fileName, NULL,
            PEM_TYPE_KEY, &DERout, &DERlen);
    if (rc < PS_SUCCESS)
    {
        return rc;
    }
    p = DERout;
    end = p + DERlen;

    rc = psParseSubjectPublicKeyInfo(pool,
            DERout,
            DERlen,
            &oi,
            NULL, NULL,
            &publicKey);
    if (rc != PS_SUCCESS)
    {
        psTraceCrypto("Couldn't parse PKCS#1 RSA public key file\n");
        goto pubKeyFail;
    }

    if (oi != OID_RSA_KEY_ALG)
    {
        psTraceCrypto("psPkcs1ParsePubFile: not an RSA key\n");
        goto pubKeyFail;
    }

    rc = psRsaParseAsnPubKey(pool,
            &publicKey,
            (int32) (end - publicKey),
            key,
            sha1KeyHash);
    if (rc < 0)
    {
        psTraceCrypto("Couldn't parse PKCS#1 RSA public key file\n");
        goto pubKeyFail;
    }

    psFree(DERout, pool);
    return PS_SUCCESS;

pubKeyFail:
    psFree(DERout, pool);
    return PS_PARSE_FAIL;
#   else
    return PS_UNSUPPORTED_FAIL;
#   endif
}

#  ifdef USE_PRIVATE_KEY_PARSING

/******************************************************************************/
/**
    Parse a PEM format private key file.

    @pre File must be a PEM format RSA keys.
    @return < 0 on error
 */
int32_t psPkcs1ParsePrivFile(psPool_t *pool, const char *fileName,
    const char *password, psRsaKey_t *key)
{
    unsigned char *DERout;
    int32_t rc;
    psSize_t DERlen;

#   ifdef USE_PKCS8
    psPubKey_t pubkey;
#   endif

    rc = psPkcs1DecodePrivFile(pool, fileName, password, &DERout, &DERlen);
    if (rc < PS_SUCCESS)
    {
        return rc;
    }

    rc = psRsaParsePkcs1PrivKey(pool, DERout, DERlen, key);
    if (rc < 0)
    {
#   ifdef USE_PKCS8
        /* This logic works for processing PKCS#8 files because the above file
            and bin decodes will always leave the unprocessed buffer intact and
            the password protection is done in the internal ASN.1 encoding */
        rc = psPkcs8ParsePrivBin(pool,
                DERout,
                DERlen,
                (char *) password,
                &pubkey);
        if (rc < 0)
        {
            psFree(DERout, pool);
            return rc;
        }
        rc = psRsaCopyKey(key, &pubkey.key.rsa);
        psClearPubKey(&pubkey);
#   else
        psFree(DERout, pool);
        return rc;
#   endif
    }

    psFree(DERout, pool);
    return rc;
}
#  endif /* USE_RSA */

#  endif  /* USE_PRIVATE_KEY_PARSING */
# endif /* MATRIX_USE_FILE_SYSTEM */
