/**
 *      @file    digest_info.c
 *      @version $Format:%h%d$
 *
 *      Static DigestInfo prefixes and querying functions for PKCS #1.5.
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
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

#include "../cryptoImpl.h"

# ifdef USE_RSA

/*
  ASN.1 DER encoded DigestInfos.
  In RSA signature verification, the prefix of the RSA-decrypted message
  should be compared against one of these. The correct one can be fetched
  with psGetDigestInfoPrefix, which takes in as arguments the sig alg ID
  and the length of the decrypted message. Each DigestInfo has two variants:
  one with optional NULL parameters in the AlgorithmIdentifier, the other
  without.
*/

#  ifdef USE_MD2
static const unsigned char PKCS1Dig_MD2[] =
{
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10
};
static const unsigned char PKCS1Dig_MD2_ALT[] =
{
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x02, 0x02, 0x04, 0x10
};
#  endif /* USE_MD2 */

#  ifdef USE_MD5
static const unsigned char PKCS1Dig_MD5[] =
{
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const unsigned char PKCS1Dig_MD5_ALT[] =
{
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x02, 0x05, 0x04, 0x10
};
#  endif /* USE_MD5 */

#  ifdef USE_SHA1
static const unsigned char PKCS1Dig_SHA1[] =
{
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
    0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static const unsigned char PKCS1Dig_SHA1_ALT[] =
{
    0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03,
    0x02, 0x1a, 0x04, 0x14
};
#  endif /* USE_SHA1 */

#ifdef USE_SHA224
static const unsigned char PKCS1Dig_SHA224[] =
{
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};
static const unsigned char PKCS1Dig_SHA224_ALT[] =
{
    0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x04, 0x1c
};
#  endif /* USE_SHA224 */

#  ifdef USE_SHA256
static const unsigned char PKCS1Dig_SHA256[] =
{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const unsigned char PKCS1Dig_SHA256_ALT[] =
{
    0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20
};
#  endif /* USE_SHA256 */

#  ifdef USE_SHA384
static const unsigned char PKCS1Dig_SHA384[] =
{
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const unsigned char PKCS1Dig_SHA384_ALT[] =
{
    0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30
};
#  endif /* USE_SHA384 */

#  ifdef USE_SHA512
static const unsigned char PKCS1Dig_SHA512[] =
{
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};
static const unsigned char PKCS1Dig_SHA512_ALT[] =
{
    0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40
};
#  endif /* USE_SHA512 */

const
unsigned char *psGetDigestInfoPrefix(int32_t len,
    int32_t sigAlg)
{
    switch (sigAlg)
    {
#  ifdef USE_MD2
    case OID_MD2_RSA_SIG:
        if (len == sizeof(PKCS1Dig_MD2) + MD2_HASH_SIZE)
        {
            return PKCS1Dig_MD2;
        }
        else if (len == sizeof(PKCS1Dig_MD2_ALT) + MD2_HASH_SIZE)
        {
            return PKCS1Dig_MD2_ALT;
        }
        break;
#  endif /* USE_MD2 */
#  ifdef USE_MD5
    case OID_MD5_RSA_SIG:
        if (len == sizeof(PKCS1Dig_MD5) + MD5_HASH_SIZE)
        {
            return PKCS1Dig_MD5;
        }
        else if (len == sizeof(PKCS1Dig_MD5_ALT) + MD5_HASH_SIZE)
        {
            return PKCS1Dig_MD5_ALT;
        }
        break;
#  endif /* USE_MD5 */
#  ifdef USE_SHA1
    case OID_SHA1_RSA_SIG:
        if (len == sizeof(PKCS1Dig_SHA1) + SHA1_HASH_SIZE)
        {
            return PKCS1Dig_SHA1;
        }
        else if (len == sizeof(PKCS1Dig_SHA1_ALT) + SHA1_HASH_SIZE)
        {
            return PKCS1Dig_SHA1_ALT;
        }
        break;
#  endif /* USE_SHA1 */
#  ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
        if (len == sizeof(PKCS1Dig_SHA224) + SHA224_HASH_SIZE)
        {
            return PKCS1Dig_SHA224;
        }
        else if (len == sizeof(PKCS1Dig_SHA224_ALT) + SHA224_HASH_SIZE)
        {
            return PKCS1Dig_SHA224_ALT;
        }
        break;
#  endif /* USE_SHA224 */
#  ifdef USE_SHA256
    case OID_SHA256_RSA_SIG:
        if (len == sizeof(PKCS1Dig_SHA256) + SHA256_HASH_SIZE)
        {
            return PKCS1Dig_SHA256;
        }
        else if (len == sizeof(PKCS1Dig_SHA256_ALT) + SHA256_HASH_SIZE)
        {
            return PKCS1Dig_SHA256_ALT;
        }
        break;
#  endif /* USE_SHA256 */
#  ifdef USE_SHA384
    case OID_SHA384_RSA_SIG:
        if (len == sizeof(PKCS1Dig_SHA384) + SHA384_HASH_SIZE)
        {
            return PKCS1Dig_SHA384;
        }
        else if (len == sizeof(PKCS1Dig_SHA384_ALT) + SHA384_HASH_SIZE)
        {
            return PKCS1Dig_SHA384_ALT;
        }
        break;
#  endif /* USE_SHA384 */
#  ifdef USE_SHA512
    case OID_SHA512_RSA_SIG:
        if (len == sizeof(PKCS1Dig_SHA512) + SHA512_HASH_SIZE)
        {
            return PKCS1Dig_SHA512;
        }
        else if (len == sizeof(PKCS1Dig_SHA512_ALT) + SHA512_HASH_SIZE)
        {
            return PKCS1Dig_SHA512_ALT;
        }
        break;
#  endif /* USE_SHA512 */
    default:
        psTraceCrypto("Unsupported RSA signature algorithm\n");
        return NULL;
    }

    return NULL;
}

# endif /* USE_RSA */
