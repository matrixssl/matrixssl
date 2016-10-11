/**
 *	@file    pubkey.c
 *	@version $Format:%h%d$
 *
 *	Public and Private key operations shared by crypto implementations.
 */
/*
 *	Copyright (c) 2013-2016 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software
 *	into proprietary programs.  If you are unable to comply with the GPL, a
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/
 *
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *	See the GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "../cryptoApi.h"

#if defined(USE_RSA) || defined(USE_ECC)

/******************************************************************************/

int32_t psInitPubKey(psPool_t *pool, psPubKey_t *key, uint8_t type)
{
	if (!key) {
		return PS_ARG_FAIL;
	}
	switch (type) {
#ifdef USE_RSA
	case PS_RSA:
		psRsaInitKey(pool, &key->key.rsa);
		break;
#endif
#ifdef USE_ECC
	case PS_ECC:
		psEccInitKey(pool, &key->key.ecc, NULL);
		break;
#endif
	default:
		break;
	}
	key->pool = pool;
	key->type = type;
	key->keysize = 0;
	return PS_SUCCESS;
}

/******************************************************************************/

void psClearPubKey(psPubKey_t *key)
{
	if (!key) {
		return;
	}
	switch (key->type) {
#ifdef USE_RSA
	case PS_RSA:
		psRsaClearKey(&key->key.rsa);
		break;
#endif
#ifdef USE_ECC
	case PS_ECC:
		psEccClearKey(&key->key.ecc);
		break;
#endif
	default:
		break;
	}
	key->pool = NULL;
	key->keysize = 0;
	key->type = 0;
}

int32_t psNewPubKey(psPool_t *pool, uint8_t type, psPubKey_t **key)
{
	int32_t rc;
	if ((*key = psMalloc(pool, sizeof(psPubKey_t))) == NULL) {
		return PS_MEM_FAIL;
	}
	
	if ((rc = psInitPubKey(pool, *key, type)) < 0) {
		psFree(*key, pool);
	}
	return rc;
}

void psDeletePubKey(psPubKey_t **key)
{
	psClearPubKey(*key);
	psFree(*key, NULL);
	*key = NULL;
}

#ifdef MATRIX_USE_FILE_SYSTEM
#if defined(USE_ECC) && defined(USE_RSA)
/* Trial and error private key parse for when ECC or RSA is unknown.

	pemOrDer should be 1 if PEM
	
	Return codes:
		1 RSA key
		2 ECC key
		-1 error
*/
int32_t psParseUnknownPrivKey(psPool_t *pool, int pemOrDer, char *keyfile,
		char *password, psPubKey_t *privkey)
{
	psRsaKey_t		*rsakey;
	psEccKey_t		*ecckey;
	int				keytype = 1;
	unsigned char	*keyBuf;
	int32			keyBufLen;
	
	privkey->keysize = 0;
	rsakey = &privkey->key.rsa;
	ecckey = &privkey->key.ecc;
	if (pemOrDer == 1) {
		/* PEM file. */
		if (pkcs1ParsePrivFile(pool, keyfile, password, rsakey)
				< PS_SUCCESS) {
			/* psEccParsePrivFile will also try pkcs8ParsePrivBin. */
			if (psEccParsePrivFile(pool, keyfile, password, ecckey)
					< PS_SUCCESS) {
				psTraceStrCrypto("Unable to parse private key file %s\n",
					keyfile);
				return -1;
			}
			keytype = 2;
		} else {
			keytype = 1;
		}
	} else {
		/* DER file. */
		if (psGetFileBuf(pool, keyfile, &keyBuf, &keyBufLen) < PS_SUCCESS) {
			psTraceStrCrypto("Unable to open private key file %s\n", keyfile);
			return -1;
		}
		/* A raw RSAPrivateKey? */
		if (psRsaParsePkcs1PrivKey(pool, keyBuf, keyBufLen, rsakey)
				< PS_SUCCESS) {
			/* A raw ECPrivateKey? */
			if (psEccParsePrivKey(pool, keyBuf, keyBufLen, ecckey, NULL)
					< PS_SUCCESS) {
#ifdef USE_PKCS8
				/* A PKCS #8 PrivateKeyInfo containing an ECPrivateKey? */
				if (pkcs8ParsePrivBin(pool, keyBuf, keyBufLen, password,
									  privkey)) {
#endif /* USE_PKCS8 */
					/* Nothing worked. */
					psTraceCrypto("Unable to parse private key. " \
								  "Supported formats are RSAPrivateKey, " \
								  "ECPrivateKey and PKCS #8.\n");
					psFree(keyBuf, pool);
					return -1;
				}
#ifdef USE_PKCS8
				if (privkey->type == PS_RSA)
					keytype = 1;
				else if (privkey->type == PS_ECC)
					keytype = 2;
				goto parsed;
#endif /* USE_PKCS8 */
			}
			keytype = 2;
		} else {
			keytype = 1;
		}
parsed:
		psFree(keyBuf, pool);
	}

	if (keytype == 1) {
		privkey->type = PS_RSA;
		privkey->keysize = psRsaSize(&privkey->key.rsa);
	} else {
		privkey->type = PS_ECC;
		privkey->keysize = psEccSize(&privkey->key.ecc);
	}
	privkey->pool = pool;
	return keytype;
}
#endif /* USE_ECC && USE_RSA */
#endif /* MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/

#endif /* USE_RSA || USE_ECC */

