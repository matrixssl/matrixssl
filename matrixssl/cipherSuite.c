/**
 *	@file    cipherSuite.c
 *	@version $Format:%h%d$
 *
 *	Wrappers for the various cipher suites..
 *	Enable specific suites at compile time in matrixsslConfig.h
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

#include "matrixsslApi.h"

/******************************************************************************/
/*	Symmetric cipher initializtion wrappers for cipher suites */
/******************************************************************************/
/*
	SSL_NULL_WITH_NULL_NULL cipher functions
	Used in handshaking before SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC message
*/
static int32 csNullInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	return 0;
}

/******************************************************************************/
#if defined(USE_ARC4) && defined(USE_ARC4_CIPHER_SUITE)
/******************************************************************************/
static int32 csArc4Init(sslSec_t *sec, int32 type, uint32 keysize)
{
	if (type == INIT_ENCRYPT_CIPHER) {
		psArc4Init(&(sec->encryptCtx.arc4), sec->writeKey, keysize);
	} else {
		psArc4Init(&(sec->decryptCtx.arc4), sec->readKey, keysize);
	}
	return PS_SUCCESS;
}
int32 csArc4Encrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t		*lssl = ssl;
	psArc4_t	*ctx = &lssl->sec.encryptCtx.arc4;

	psArc4(ctx, pt, ct, len);
	return len;
}
int32 csArc4Decrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t		*lssl = ssl;
	psArc4_t	*ctx = &lssl->sec.decryptCtx.arc4;

	psArc4(ctx, ct, pt, len);
	return len;
}

#endif /* USE_ARC4_CIPHER_SUITE */
/******************************************************************************/

/******************************************************************************/
#if defined(USE_3DES) && defined (USE_3DES_CIPHER_SUITE)
/******************************************************************************/
static int32 csDes3Init(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;

	psAssert(keysize == DES3_KEYLEN);

	if (type == INIT_ENCRYPT_CIPHER) {
		if ((err = psDes3Init(&(sec->encryptCtx.des3), sec->writeIV, sec->writeKey)) < 0) {
			return err;
		}
	} else {
		if ((err = psDes3Init(&(sec->decryptCtx.des3), sec->readIV, sec->readKey)) < 0) {
			return err;
		}
	}
	return PS_SUCCESS;
}

int32 csDes3Encrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t			*lssl = ssl;
	psDes3_t	*ctx = &lssl->sec.encryptCtx.des3;

	psDes3Encrypt(ctx, pt, ct, len);
	return len;
}

int32 csDes3Decrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t	*lssl = ssl;
	psDes3_t	*ctx = &lssl->sec.decryptCtx.des3;

	psDes3Decrypt(ctx, ct, pt, len);
	return len;
}

#endif /* USE_3DES_CIPHER_SUITE */
/******************************************************************************/

#ifdef USE_AES_CIPHER_SUITE
#ifdef USE_TLS_1_2
#ifdef USE_AES_GCM
int32 csAesGcmInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;

	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&sec->encryptCtx.aesgcm, 0, sizeof(psAesGcm_t));
		if ((err = psAesInitGCM(&sec->encryptCtx.aesgcm, sec->writeKey,
				keysize)) < 0) {
			return err;
		}
	} else {
		memset(&sec->decryptCtx.aesgcm, 0, sizeof(psAesGcm_t));
		if ((err = psAesInitGCM(&sec->decryptCtx.aesgcm, sec->readKey,
				keysize)) < 0) {
			return err;
		}
	}
	return 0;
}

int32 csAesGcmEncrypt(void *ssl, unsigned char *pt,
			unsigned char *ct, uint32 len)
{
	ssl_t				*lssl = ssl;
	psAesGcm_t			*ctx;
	unsigned char		nonce[12];
	unsigned char		aad[TLS_GCM_AAD_LEN];
	int32				i, ptLen, seqNotDone;

	if (len == 0) {
		return PS_SUCCESS;
	}

	if (len < 16 + 1) {
		return PS_LIMIT_FAIL;
	}
	ptLen = len - TLS_GCM_TAG_LEN;

	ctx = &lssl->sec.encryptCtx.aesgcm;

	memcpy(nonce, lssl->sec.writeIV, 4);

	seqNotDone = 1;
	/* Each value of the nonce_explicit MUST be distinct for each distinct
		invocation of the GCM encrypt function for any fixed key.  Failure to
		meet this uniqueness requirement can significantly degrade security.
		The nonce_explicit MAY be the 64-bit sequence number. */
#ifdef USE_DTLS
	if (lssl->flags & SSL_FLAGS_DTLS) {
		memcpy(nonce + 4, lssl->epoch, 2);
		memcpy(nonce + 4 + 2, lssl->rsn, 6);
		/* In the case of DTLS the counter is formed from the concatenation of
			the 16-bit epoch with the 48-bit sequence number.*/
		memcpy(aad, lssl->epoch, 2);
		memcpy(aad + 2, lssl->rsn, 6);
		seqNotDone = 0;
	}
#endif

	if (seqNotDone) {
		memcpy(nonce + 4, lssl->sec.seq, TLS_EXPLICIT_NONCE_LEN);
		memcpy(aad, lssl->sec.seq, 8);
	}
	aad[8] = lssl->outRecType;
	aad[9] = lssl->majVer;
	aad[10] = lssl->minVer;
	aad[11] = ptLen >> 8 & 0xFF;
	aad[12] = ptLen & 0xFF;

	psAesReadyGCM(ctx, nonce, aad, TLS_GCM_AAD_LEN);
	psAesEncryptGCM(ctx, pt, ct, ptLen);
	psAesGetGCMTag(ctx, 16, ct + ptLen);

#ifdef USE_DTLS
	if (lssl->flags & SSL_FLAGS_DTLS) {
		return len;
	}
#endif

	/* Normally HMAC would increment the sequence */
	for (i = 7; i >= 0; i--) {
		lssl->sec.seq[i]++;
		if (lssl->sec.seq[i] != 0) {
			break;
		}
	}
	return len;
}

int32 csAesGcmDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t				*lssl = ssl;
	psAesGcm_t			*ctx;
	int32				i, ctLen, bytes, seqNotDone;
	unsigned char		nonce[12];
	unsigned char		aad[TLS_GCM_AAD_LEN];

	ctx = &lssl->sec.decryptCtx.aesgcm;

	seqNotDone = 1;
	memcpy(nonce, lssl->sec.readIV, 4);
	memcpy(nonce + 4, ct, TLS_EXPLICIT_NONCE_LEN);
	ct += TLS_EXPLICIT_NONCE_LEN;
	len -= TLS_EXPLICIT_NONCE_LEN;

#ifdef USE_DTLS
	if (lssl->flags & SSL_FLAGS_DTLS) {
		/* In the case of DTLS the counter is formed from the concatenation of
			the 16-bit epoch with the 48-bit sequence number.  */
		memcpy(aad, lssl->rec.epoch, 2);
		memcpy(aad + 2, lssl->rec.rsn, 6);
		seqNotDone = 0;
	}
#endif

	if (seqNotDone) {
		memcpy(aad, lssl->sec.remSeq, 8);
	}
	ctLen = len - TLS_GCM_TAG_LEN;
	aad[8] = lssl->rec.type;
	aad[9] = lssl->majVer;
	aad[10] = lssl->minVer;
	aad[11] = ctLen >> 8 & 0xFF;
	aad[12] = ctLen & 0xFF;

	psAesReadyGCM(ctx, nonce, aad, TLS_GCM_AAD_LEN);

	if ((bytes = psAesDecryptGCM(ctx, ct, len, pt, len - TLS_GCM_TAG_LEN)) < 0){
		return -1;
	}
	for (i = 7; i >= 0; i--) {
		lssl->sec.remSeq[i]++;
		if (lssl->sec.remSeq[i] != 0) {
			break;
		}
	}
	return bytes;
}
#endif /* USE_AES_GCM */
#endif /* USE_TLS_1_2 */

#ifdef USE_AES_CBC
/******************************************************************************/
int32 csAesInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;

	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&(sec->encryptCtx), 0, sizeof(psAesCbc_t));
		if ((err = psAesInitCBC(&sec->encryptCtx.aes, sec->writeIV, sec->writeKey,
							 keysize, PS_AES_ENCRYPT)) < 0) {
			return err;
		}
	} else { /* Init for decrypt */
		memset(&(sec->decryptCtx), 0, sizeof(psAesCbc_t));
		if ((err = psAesInitCBC(&sec->decryptCtx.aes, sec->readIV, sec->readKey,
							 keysize, PS_AES_DECRYPT)) < 0) {
			return err;
		}
	}
	return PS_SUCCESS;
}

int32 csAesEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t		*lssl = ssl;
	psAesCbc_t	*ctx = &lssl->sec.encryptCtx.aes;

	psAesEncryptCBC(ctx, pt, ct, len);
	return len;
}

int32 csAesDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t		*lssl = ssl;
	psAesCbc_t	*ctx = &lssl->sec.decryptCtx.aes;
	psAesDecryptCBC(ctx, ct, pt, len);
	return len;
}
#endif /*USE_AES_CBC */
#endif /* USE_AES_CIPHER_SUITE */

/******************************************************************************/

//#define DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
#ifdef USE_CHACHA20_POLY1305_CIPHER_SUITE
int32 csChacha20Poly1305Init(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;

	if (type == INIT_ENCRYPT_CIPHER) {
#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
		psTraceInfo("Entering csChacha20Poly1305Init encrypt\n");
		psTraceBytes("sec->writeKey", sec->writeKey, keysize);
#endif
		memset(&sec->encryptCtx.chacha20poly1305, 0, sizeof(psChacha20Poly1305_t));
		if ((err = psChacha20Poly1305Init(&sec->encryptCtx.chacha20poly1305, sec->writeKey,
				keysize)) < 0) {
			return err;
		}
	} else {
#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
		psTraceInfo("Entering csChacha20Poly1305Init decrypt\n");
		psTraceBytes("sec->readKey", sec->readKey, keysize);
#endif
		memset(&sec->decryptCtx.chacha20poly1305, 0, sizeof(psChacha20Poly1305_t));
		if ((err = psChacha20Poly1305Init(&sec->decryptCtx.chacha20poly1305, sec->readKey,
				keysize)) < 0) {
			return err;
		}
	}
	return 0;
}

int32 csChacha20Poly1305Encrypt(void *ssl, unsigned char *pt,
	unsigned char *ct, uint32 len)
{
	ssl_t				*lssl = ssl;
	psChacha20Poly1305_t	*ctx;
	unsigned char		nonce[TLS_AEAD_NONCE_MAXLEN];
	unsigned char		aad[TLS_CHACHA20_POLY1305_AAD_LEN];
	int32				i, ptLen;

	if (len == 0) {
		return PS_SUCCESS;
	}
	if (len < 16 + 1) {
		return PS_LIMIT_FAIL;
	}
	ptLen = len - TLS_CHACHA20_POLY1305_TAG_LEN;
	ctx = &lssl->sec.encryptCtx.chacha20poly1305;

	memset(nonce, 0, TLS_AEAD_NONCE_MAXLEN);
	memset(aad, 0, TLS_CHACHA20_POLY1305_AAD_LEN);

#ifdef CHACHA20POLY1305_IETF
#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
	psTraceInfo("Entering csChacha20Poly1305Encrypt IETF\n");
#endif
	if (sizeof(lssl->sec.writeIV) < CHACHA20POLY1305_IV_FIXED_LENGTH) return PS_LIMIT_FAIL;
	if (sizeof(nonce) < CHACHA20POLY1305_IV_FIXED_LENGTH) return PS_LIMIT_FAIL;

	// The nonce is built according to: https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305
	
	memcpy(nonce + (CHACHA20POLY1305_IV_FIXED_LENGTH-TLS_AEAD_SEQNB_LEN), lssl->sec.seq, TLS_AEAD_SEQNB_LEN);

	for (i = 0; i < CHACHA20POLY1305_IV_FIXED_LENGTH; i++) {
		nonce[i] ^= lssl->sec.writeIV[i];
	}
#else
#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
	psTraceInfo("Entering csChacha20Poly1305Encrypt\n");
#endif

/*
	The nonce is just the sequence number, as explained in
	https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-5 AEAD construction
*/
	memcpy(nonce, lssl->sec.seq, TLS_AEAD_SEQNB_LEN);
#endif
	//--- Fill Additional data ---//
	memcpy(aad, lssl->sec.seq, TLS_AEAD_SEQNB_LEN);
	i = TLS_AEAD_SEQNB_LEN;

	aad[i++] = lssl->outRecType;
	aad[i++] = lssl->majVer;
	aad[i++] = lssl->minVer;
	aad[i++] = ptLen >> 8 & 0xFF;
	aad[i++] = ptLen & 0xFF;

#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE	
	psTraceBytes("nonce", nonce, CHACHA20POLY1305_IV_FIXED_LENGTH);
	psTraceBytes("aad", aad, TLS_CHACHA20_POLY1305_AAD_LEN);
	psTraceBytes("pt", pt, ptLen);
#endif

	/* Perform encryption and authentication tag computation */
	psChacha20Poly1305Ready(ctx, nonce, aad, TLS_CHACHA20_POLY1305_AAD_LEN);
	psChacha20Poly1305Encrypt(ctx, pt, ct, ptLen);
	psChacha20Poly1305GetTag(ctx,TLS_CHACHA20_POLY1305_TAG_LEN, ct + ptLen);

#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
	psTraceBytes("ct", ct, ptLen);
	psTraceBytes("tag", ct+ptLen, TLS_CHACHA20_POLY1305_TAG_LEN);
#endif

	/* Normally HMAC would increment the sequence */
	for (i = (TLS_AEAD_SEQNB_LEN - 1); i >= 0; i--) {
		lssl->sec.seq[i]++;
		if (lssl->sec.seq[i] != 0) {
			break;
		}
	}
	return len;
}

int32 csChacha20Poly1305Decrypt(void *ssl, unsigned char *ct,
	unsigned char *pt, uint32 len)
{
	ssl_t				*lssl = ssl;
	psChacha20Poly1305_t			*ctx;
	int32				i, ctLen, bytes;

	unsigned char		nonce[TLS_AEAD_NONCE_MAXLEN];
	unsigned char		aad[TLS_CHACHA20_POLY1305_AAD_LEN];

	ctx = &lssl->sec.decryptCtx.chacha20poly1305;

	memset(nonce, 0, TLS_AEAD_NONCE_MAXLEN);
	memset(aad, 0, TLS_CHACHA20_POLY1305_AAD_LEN);
	
#ifdef CHACHA20POLY1305_IETF
	// Check https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-06

#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE	
	psTraceInfo("Entering csChacha20Poly1305Decrypt IETF\n");
#endif
	
	if (sizeof(lssl->sec.readIV) < CHACHA20POLY1305_IV_FIXED_LENGTH) return PS_LIMIT_FAIL;
	if (sizeof(nonce) < CHACHA20POLY1305_IV_FIXED_LENGTH) return PS_LIMIT_FAIL;

	// The nonce is built according to: https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305

	memcpy(nonce + (CHACHA20POLY1305_IV_FIXED_LENGTH-TLS_AEAD_SEQNB_LEN), lssl->sec.remSeq, TLS_AEAD_SEQNB_LEN);

	for (i = 0; i < CHACHA20POLY1305_IV_FIXED_LENGTH; i++) {
		nonce[i] ^= lssl->sec.readIV[i];
	}

#else
#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
	psTraceInfo("Entering csChacha20Poly1305Decrypt\n");
#endif
	memcpy(nonce, lssl->sec.remSeq, TLS_AEAD_SEQNB_LEN);
#endif

	//--- Fill Additional data ---//
	memcpy(aad, lssl->sec.remSeq, TLS_AEAD_SEQNB_LEN);
	i = TLS_AEAD_SEQNB_LEN;

	// Update length of encrypted data: we have to remove tag's length
	if (len < TLS_CHACHA20_POLY1305_TAG_LEN) {
		return PS_LIMIT_FAIL;
	}
	ctLen = len - TLS_CHACHA20_POLY1305_TAG_LEN;

	aad[i++] = lssl->rec.type;
	aad[i++] = lssl->majVer;
	aad[i++] = lssl->minVer;
	aad[i++] = ctLen >> 8 & 0xFF;
	aad[i++] = ctLen & 0xFF;

#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
	psTraceBytes("nonce", nonce, CHACHA20POLY1305_IV_FIXED_LENGTH);
	psTraceBytes("aad", aad, TLS_CHACHA20_POLY1305_AAD_LEN);
	psTraceBytes("ct", ct, ctLen);
	psTraceBytes("tag", ct+ctLen, TLS_CHACHA20_POLY1305_TAG_LEN);
#endif

	//--- Check authentication tag and decrypt data ---//
	psChacha20Poly1305Ready(ctx, nonce, aad, TLS_CHACHA20_POLY1305_AAD_LEN);

	if ((bytes = psChacha20Poly1305Decrypt(ctx, ct, len, pt, ctLen)) < 0){
#ifdef DEBUG_CHACHA20_POLY1305_CIPHER_SUITE
		psTraceInfo("Decrypt NOK\n");
#endif
		return -1;
	}
	
	for (i = (TLS_AEAD_SEQNB_LEN - 1); i >= 0; i--) {
		lssl->sec.remSeq[i]++;
		if (lssl->sec.remSeq[i] != 0) {
			break;
		}
	}

	return bytes;
}
#endif /* USE_CHACHA20_POLY1305_CIPHER_SUITE */

/******************************************************************************/

#if defined(USE_IDEA) && defined(USE_IDEA_CIPHER_SUITE)
int32 csIdeaInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;

	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&(sec->encryptCtx), 0, sizeof(psCipherContext_t));
		if ((err = psIdeaInit(&(sec->encryptCtx.idea), sec->writeIV, sec->writeKey)) < 0) {
			return err;
		}
	} else { /* Init for decrypt */
		memset(&(sec->decryptCtx), 0, sizeof(psCipherContext_t));
		if ((err = psIdeaInit(&(sec->decryptCtx.idea), sec->readIV, sec->readKey)) < 0) {
			return err;
		}
	}
	return PS_SUCCESS;
}

int32 csIdeaEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t		*lssl = ssl;
	psIdea_t	*ctx = &lssl->sec.encryptCtx.idea;

	psIdeaEncrypt(ctx, pt, ct, len);
	return len;
}

int32 csIdeaDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t		*lssl = ssl;
	psIdea_t	*ctx = &lssl->sec.encryptCtx.idea;

	psIdeaDecrypt(ctx, ct, pt, len);
	return len;
}
#endif /* USE_IDEA_CIPHER_SUITE */

/******************************************************************************/
#if defined(USE_SEED) && defined(USE_SEED_CIPHER_SUITE)
/******************************************************************************/
static int32 csSeedInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;

	psAssert(keysize == SEED_KEYLEN);

	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&(sec->encryptCtx), 0, sizeof(psSeed_t));
		if ((err = psSeedInit(&(sec->encryptCtx.seed), sec->writeIV, sec->writeKey)) < 0) {
			return err;
		}
	} else {
		memset(&(sec->decryptCtx), 0, sizeof(psSeed_t));
		if ((err = psSeedInit(&(sec->decryptCtx.seed), sec->readIV, sec->readKey)) < 0) {
			return err;
		}
	}
	return 0;
}
int32 csSeedEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t		*lssl = ssl;
	psSeed_t	*ctx = &lssl->sec.encryptCtx.seed;

	psSeedEncrypt(ctx, pt, ct, len);
	return len;
}

int32 csSeedDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t		*lssl = ssl;
	psSeed_t	*ctx = &lssl->sec.encryptCtx.seed;

	psSeedDecrypt(ctx, ct, pt, len);
	return len;
}

#endif /* USE_SEED_CIPHER_SUITE */
/******************************************************************************/


/******************************************************************************/
/*	Null cipher crypto */
/******************************************************************************/
static int32 csNullEncrypt(void *ctx, unsigned char *in,
						 unsigned char *out, uint32 len)
{
	if (out != in) {
		memcpy(out, in, len);
	}
	return len;
}

static int32 csNullDecrypt(void *ctx, unsigned char *in,
						 unsigned char *out, uint32 len)
{
	if (out != in) {
		memmove(out, in, len);
	}
	return len;
}

/******************************************************************************/
/*	HMAC wrappers for cipher suites */
/******************************************************************************/
static int32 csNullGenerateMac(void *ssl, unsigned char type,
						unsigned char *data, uint32 len, unsigned char *mac)
{
	return 0;
}

static int32 csNullVerifyMac(void *ssl, unsigned char type,
						unsigned char *data, uint32 len, unsigned char *mac)
{
	return 0;
}

#ifdef USE_SHA_MAC
/******************************************************************************/
static int32 csShaGenerateMac(void *sslv, unsigned char type,
					unsigned char *data, uint32 len, unsigned char *macOut)
{
	ssl_t	*ssl = (ssl_t*)sslv;
	unsigned char	mac[MAX_HASH_SIZE];

#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
#ifdef USE_SHA256
		if (ssl->nativeEnMacSize == SHA256_HASH_SIZE ||
				ssl->nativeEnMacSize == SHA384_HASH_SIZE) {
			tlsHMACSha2(ssl, HMAC_CREATE, type, data, len, mac,
				ssl->nativeEnMacSize);
		} else {
#endif
#ifdef USE_SHA1
			tlsHMACSha1(ssl, HMAC_CREATE, type, data, len, mac);
#endif
#ifdef USE_SHA256
		}
#endif
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		ssl3HMACSha1(ssl->sec.writeMAC, ssl->sec.seq, type, data,
				len, mac);
#else
		return PS_ARG_FAIL;
#endif /* DISABLE_SSLV3 */
#ifdef USE_TLS
	}
#endif /* USE_TLS */

	memcpy(macOut, mac, ssl->enMacSize);
	return ssl->enMacSize;
}

static int32 csShaVerifyMac(void *sslv, unsigned char type,
					unsigned char *data, uint32 len, unsigned char *mac)
{
	unsigned char	buf[MAX_HASH_SIZE];
	ssl_t	*ssl = (ssl_t*)sslv;

	if (ssl->flags & SSL_FLAGS_TLS) {
		switch (ssl->nativeDeMacSize) {
#ifdef USE_SHA256
		case SHA256_HASH_SIZE:
		case SHA384_HASH_SIZE:
			tlsHMACSha2(ssl, HMAC_VERIFY, type, data, len, buf,
				ssl->nativeDeMacSize);
			break;
#endif
#ifdef USE_SHA1
		case SHA1_HASH_SIZE:
			tlsHMACSha1(ssl, HMAC_VERIFY, type, data, len, buf);
			break;
#endif
		default:
			memzero_s(buf, ssl->nativeDeMacSize); /* Will fail below */
			break;
		}
	} else {
#ifndef DISABLE_SSLV3
		ssl3HMACSha1(ssl->sec.readMAC, ssl->sec.remSeq, type, data, len, buf);
#else
		memzero_s(buf, SHA1_HASH_SIZE); /* Will fail below */
#endif /* DISABLE_SSLV3 */
	}
	if (memcmpct(buf, mac, ssl->deMacSize) == 0) {
		return PS_SUCCESS;
	}
	return PS_FAILURE;
}
#endif /* USE_SHA_MAC */
/******************************************************************************/

/******************************************************************************/
#if defined(USE_MD5) && defined(USE_MD5_MAC)
/******************************************************************************/
static int32 csMd5GenerateMac(void *sslv, unsigned char type,
					unsigned char *data, uint32 len, unsigned char *macOut)
{
	unsigned char	mac[MD5_HASH_SIZE];
	ssl_t	*ssl = (ssl_t*)sslv;
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		tlsHMACMd5(ssl, HMAC_CREATE, type, data, len, mac);
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		ssl3HMACMd5(ssl->sec.writeMAC, ssl->sec.seq, type, data,
						   len, mac);
#else
		return PS_ARG_FAIL;
#endif /* DISABLE_SSLV3 */
#ifdef USE_TLS
	}
#endif /* USE_TLS */
	memcpy(macOut, mac, ssl->enMacSize);
	return ssl->enMacSize;
}

static int32 csMd5VerifyMac(void *sslv, unsigned char type, unsigned char *data,
					uint32 len, unsigned char *mac)
{
	unsigned char	buf[MD5_HASH_SIZE];
	ssl_t	*ssl = (ssl_t*)sslv;

#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		tlsHMACMd5(ssl, HMAC_VERIFY, type, data, len, buf);
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		ssl3HMACMd5(ssl->sec.readMAC, ssl->sec.remSeq, type, data, len, buf);
#endif /* DISABLE_SSLV3 */
#ifdef USE_TLS
	}
#endif /* USE_TLS */
	if (memcmpct(buf, mac, ssl->deMacSize) == 0) {
		return PS_SUCCESS;
	}
	return PS_FAILURE;
}
#endif /* USE_MD5_MAC */

/******************************************************************************/

/* Set of bits corresponding to supported cipher ordinal. If set, it is
	globally disabled */
static uint32_t	disabledCipherFlags[8] = { 0 };	/* Supports up to 256 ciphers */

const static sslCipherSpec_t	supportedCiphers[] = {
/*
	New ciphers should be added here, similar to the ones below

	Ciphers are listed in order of greater security at top... this generally
	means the slower ones are on top as well.

	256 ciphers max.

	The ordering of the ciphers is grouped and sub-grouped by the following:
	1. Non-deprecated
	 2. Ephemeral
	  3. Authentication Method (PKI > PSK > anon)
	   4. Hash Strength (SHA384 > SHA256 > SHA > MD5)
	    5. Cipher Strength (AES256 > AES128 > 3DES > ARC4 > SEED > IDEA > NULL)
	     6. PKI Key Exchange (DHE > ECDHE > ECDH > RSA > PSK)
	      7. Cipher Mode (GCM > CBC)
	       8. PKI Authentication Method (ECDSA > RSA > PSK)
*/

/* Ephemeral ciphersuites */
#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,	/* ident */
		CS_ECDHE_ECDSA,							/* type */
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3, /* flags */
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,	/* init */
		csAesGcmEncrypt,	/* encrypt */
		csAesGcmDecrypt,	/* decrypt */
		NULL,	/* generateMac */
		NULL},	/* verifyMac */
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		32,			/* keySize */
		CHACHA20POLY1305_IV_FIXED_LENGTH, /* ivSize */
		0,			/* blocksize */
		csChacha20Poly1305Init,
		csChacha20Poly1305Encrypt,
		csChacha20Poly1305Decrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		32,			/* keySize */
		CHACHA20POLY1305_IV_FIXED_LENGTH,	/* ivSize */
		0,			/* blocksize */
		csChacha20Poly1305Init,
		csChacha20Poly1305Encrypt,
		csChacha20Poly1305Decrypt,
		NULL,
		NULL },
#endif /* USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	{SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
		CS_DHE_RSA,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt,
		csDes3Decrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt,
		csDes3Decrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
	{TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
		CS_DHE_PSK,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
	{TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
		CS_DHE_PSK,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA */

/* Non-ephemeral ciphersuites */

#ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
	{TLS_RSA_WITH_AES_256_GCM_SHA384,
		CS_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
	{TLS_RSA_WITH_AES_256_CBC_SHA256,
		CS_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
	{TLS_RSA_WITH_AES_128_GCM_SHA256,
		CS_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt,
		csAesGcmDecrypt,
		NULL,
		NULL},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
	{TLS_RSA_WITH_AES_128_CBC_SHA256,
		CS_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
	{TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA
	{TLS_RSA_WITH_AES_256_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
	{TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
	{TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA
	{TLS_RSA_WITH_AES_128_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
	{TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
	{SSL_RSA_WITH_3DES_EDE_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt,
		csDes3Decrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA384
	{TLS_PSK_WITH_AES_256_CBC_SHA384,
		CS_PSK,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA256
	{TLS_PSK_WITH_AES_128_CBC_SHA256,
		CS_PSK,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA
	{TLS_PSK_WITH_AES_256_CBC_SHA,
		CS_PSK,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA
	{TLS_PSK_WITH_AES_128_CBC_SHA,
		CS_PSK,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_128_CBC_SHA */

/* @security Deprecated weak ciphers */

#ifdef USE_SSL_RSA_WITH_RC4_128_SHA
	{SSL_RSA_WITH_RC4_128_SHA,
		CS_RSA,
		CRYPTO_FLAGS_ARC4 | CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		0,			/* ivSize */
		1,			/* blocksize */
		csArc4Init,
		csArc4Encrypt,
		csArc4Decrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_RC4_128_SHA */

#ifdef USE_TLS_RSA_WITH_SEED_CBC_SHA
	{TLS_RSA_WITH_SEED_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csSeedInit,
		csSeedEncrypt,
		csSeedDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_SEED_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_IDEA_CBC_SHA
	{TLS_RSA_WITH_IDEA_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_IDEA | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csIdeaInit,
		csIdeaEncrypt,
		csIdeaDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_IDEA_CBC_SHA */

#ifdef USE_SSL_RSA_WITH_RC4_128_MD5
	{SSL_RSA_WITH_RC4_128_MD5,
		CS_RSA,
		CRYPTO_FLAGS_ARC4 | CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_MD5,
		16,			/* macSize */
		16,			/* keySize */
		0,			/* ivSize */
		1,			/* blocksize */
		csArc4Init,
		csArc4Encrypt,
		csArc4Decrypt,
		csMd5GenerateMac,
		csMd5VerifyMac},
#endif /* USE_SSL_RSA_WITH_RC4_128_MD5 */

/* @security Deprecated unencrypted ciphers */

#ifdef USE_SSL_RSA_WITH_NULL_SHA
	{SSL_RSA_WITH_NULL_SHA,
		CS_RSA,
		CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		0,			/* keySize */
		0,			/* ivSize */
		0,			/* blocksize */
		csNullInit,
		csNullEncrypt,
		csNullDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_NULL_SHA */

#ifdef USE_SSL_RSA_WITH_NULL_MD5
	{SSL_RSA_WITH_NULL_MD5,
		CS_RSA,
		CRYPTO_FLAGS_MD5,
		16,			/* macSize */
		0,			/* keySize */
		0,			/* ivSize */
		0,			/* blocksize */
		csNullInit,
		csNullEncrypt,
		csNullDecrypt,
		csMd5GenerateMac,
		csMd5VerifyMac},
#endif /* USE_SSL_RSA_WITH_NULL_MD5 */

/* @security Deprecated unauthenticated ciphers */

#ifdef USE_TLS_DH_anon_WITH_AES_256_CBC_SHA
	{TLS_DH_anon_WITH_AES_256_CBC_SHA,
		CS_DH_ANON,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DH_anon_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DH_anon_WITH_AES_128_CBC_SHA
	{TLS_DH_anon_WITH_AES_128_CBC_SHA,
		CS_DH_ANON,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt,
		csAesDecrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_TLS_DH_anon_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
	{SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,
		CS_DH_ANON,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt,
		csDes3Decrypt,
		csShaGenerateMac,
		csShaVerifyMac},
#endif /* USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_SSL_DH_anon_WITH_RC4_128_MD5
	{SSL_DH_anon_WITH_RC4_128_MD5,
		CS_DH_ANON,
		CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_MD5,
		16,			/* macSize */
		16,			/* keySize */
		0,			/* ivSize */
		1,			/* blocksize */
		csArc4Init,
		csArc4Encrypt,
		csArc4Decrypt,
		csMd5GenerateMac,
		csMd5VerifyMac},
#endif /* USE_SSL_DH_anon_WITH_RC4_128_MD5 */

/*
	The NULL Cipher suite must exist and be the last in this list
*/
	{SSL_NULL_WITH_NULL_NULL,
		CS_NULL,
		0,
		0,
		0,
		0,
		0,
		csNullInit,
		csNullEncrypt,
		csNullDecrypt,
		csNullGenerateMac,
		csNullVerifyMac}
};

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
	Disable and re-enable ciphers suites on a global or per-session level.
	This is only a server-side feature because the client is always able to
	nominate the specific cipher it wishes to use.  Servers may want to disable
	specific ciphers for a given session (or globally without having to
	rebuild the library).

	This function must be called immediately after matrixSslNewServerSession

	If ssl is NULL, the setting will be global.  If a cipher is globally
	disabled, the per-session setting will be ignored.

	flags:
		PS_TRUE to reenable (always enabled by default if compiled in)
		PS_FALSE to disable cipher suite
*/
int32_t matrixSslSetCipherSuiteEnabledStatus(ssl_t *ssl, uint16_t cipherId,
			uint32_t flags)
{
	uint8_t		i, j;

	if (ssl && !(ssl->flags & SSL_FLAGS_SERVER)) {
		return PS_UNSUPPORTED_FAIL;
	}
	if (flags != PS_TRUE && flags != PS_FALSE) {
		return PS_ARG_FAIL;
	}
	for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++) {
		if (supportedCiphers[i].ident == cipherId) {
			if (ssl == NULL) {
/*
				Global status of cipher suite.  Disabled status takes
				precident over session setting
*/
				if (flags == PS_TRUE) {
					/* Unset the disabled bit */
					disabledCipherFlags[i >> 5] &= ~(1 << (i & 31));
				} else {
					/* Set the disabled bit */
					disabledCipherFlags[i >> 5] |= 1 << (i & 31);
				}
				return PS_SUCCESS;
			} else {
				/* Status of this suite for a specific session */
				for (j = 0; j < SSL_MAX_DISABLED_CIPHERS; j++) {
					if (flags == PS_FALSE) {
						/* Find first empty spot to add disabled cipher */
						if (ssl->disabledCiphers[j] == 0x0 ||
								ssl->disabledCiphers[j] == cipherId) {
							ssl->disabledCiphers[j] = cipherId;
							return PS_SUCCESS;
						}
					} else {
						if (ssl->disabledCiphers[j] == cipherId) {
							ssl->disabledCiphers[j] = 0x0;
							return PS_SUCCESS;
						}
					}
				}
				if (flags == PS_FALSE) {
					return PS_LIMIT_FAIL; /* No empty spot in disabledCiphers */
				} else {
					/* Tried to re-enabled a cipher that wasn't disabled */
					return PS_SUCCESS;
				}
			}
		}
	}
	return PS_FAILURE; /* Cipher not found */
}
/* 
	Convert the cipher suite "type" into what public key signature algorithm is
	required. Return values are from the sigAlgorithm of psX509_t:
	
	RSA_TYPE_SIG (User must also test for RSAPSS_TYPE_SIG!!)
	ECDSA_TYPE_SIG
	
	CS_NULL (0) if no public key signatures needed (PSK and DH_anon)
		
	The dhParamsRequired return paramater must hold whether standard DH
	is used in the suite.  The caller will have to load some during
	the callback if so
	
	The ecKeyExchange is to identify RSA signatures but EC key exchange
*/

static uint16 getKeyTypeFromCipherType(uint16 type, uint16 *dhParamsRequired,
			uint16 *ecKeyExchange)
{
	*dhParamsRequired = *ecKeyExchange = 0;
	switch (type) {
		case CS_RSA:
			return RSA_TYPE_SIG;
			
		case CS_DHE_RSA:
			*dhParamsRequired = 1;
			return RSA_TYPE_SIG;
			
		case CS_DH_ANON:
		case CS_DHE_PSK:
			*dhParamsRequired = 1;
			return CS_NULL;
			
		case CS_ECDHE_ECDSA:
		case CS_ECDH_ECDSA:
			return ECDSA_TYPE_SIG;
			
		case CS_ECDHE_RSA:
		case CS_ECDH_RSA:
			*ecKeyExchange = 1;
			return RSA_TYPE_SIG;
			
		default: /* CS_NULL or CS_PSK type */
			return CS_NULL; /* a cipher suite with no pub key or DH */
	}
}
#endif /* USE_SERVER_SIDE_SSL */

#ifdef VALIDATE_KEY_MATERIAL
#define KEY_ALG_ANY		1
#define KEY_ALG_FIRST	2
/*
	anyOrFirst is basically a determination of whether we are looking through
	a collection of CA files for an algorithm (ANY) or a cert chain where
	we really only care about the child most cert because that is the one
	that ultimately determines the authentication algorithm (FIRST)
*/
static int32 haveCorrectKeyAlg(psX509Cert_t *cert, int32 keyAlg, int anyOrFirst)
{
	while (cert) {
		if (cert->pubKeyAlgorithm == keyAlg) {
			return PS_SUCCESS;
		}
		if (anyOrFirst == KEY_ALG_FIRST) {
			return PS_FAILURE;
		}
		cert = cert->next;
	}
	return PS_FAILURE;
}

#ifdef USE_SERVER_SIDE_SSL
/* If using TLS 1.2 we need to test agains the sigHashAlg and eccParams */
static int32_t validateKeyForExtensions(ssl_t *ssl, const sslCipherSpec_t *spec,
								sslKeys_t *givenKey)
{
#ifdef USE_TLS_1_2
	psX509Cert_t	*crt;
#endif

	/* Can immediately weed out PSK suites and anon suites that don't use
		sigHashAlg or EC curves */
	if (spec->type == CS_PSK || spec->type == CS_DHE_PSK ||
			spec->type == CS_DH_ANON) {
		return PS_SUCCESS;
	}
	
#ifdef USE_TLS_1_2
	/* hash and sig alg is a TLS 1.2 only extension */
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
	
		/* Walk through each cert and confirm the client will be able to
			deal with them based on the algorithms provided in the extension */
		crt = givenKey->cert;
		while (crt) {
	
#ifdef USE_DHE_CIPHER_SUITE
			/* Have to look out for the case where the public key alg doesn't
				match the sig algorithm.  This is only a concern for DHE based
				suites where we'll be sending a signature in the
				SeverKeyExchange message */
			if (spec->type == CS_DHE_RSA || spec->type == CS_ECDHE_RSA ||
					spec->type == CS_ECDHE_ECDSA) {
				if (crt->pubKeyAlgorithm == OID_RSA_KEY_ALG) {
					if (
#ifdef USE_SHA1
							!(ssl->hashSigAlg & HASH_SIG_SHA1_RSA_MASK) &&
#endif
#ifdef USE_SHA384
							!(ssl->hashSigAlg & HASH_SIG_SHA384_RSA_MASK) &&
#endif
#ifdef USE_SHA512
							!(ssl->hashSigAlg & HASH_SIG_SHA512_RSA_MASK) &&
#endif
							!(ssl->hashSigAlg & HASH_SIG_SHA256_RSA_MASK)) {
						return PS_UNSUPPORTED_FAIL;
					}
				}
#ifdef USE_ECC
				if (crt->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
					if (
#ifdef USE_SHA1
							!(ssl->hashSigAlg & HASH_SIG_SHA1_ECDSA_MASK) &&
#endif
#ifdef USE_SHA384
							!(ssl->hashSigAlg & HASH_SIG_SHA384_ECDSA_MASK) &&
#endif
#ifdef USE_SHA512
							!(ssl->hashSigAlg & HASH_SIG_SHA512_ECDSA_MASK) &&
#endif
							!(ssl->hashSigAlg & HASH_SIG_SHA256_ECDSA_MASK)) {
						return PS_UNSUPPORTED_FAIL;
					}
				}
#endif /* USE_ECC */
			}
#endif /* USE_DHE_CIPHER_SUITE */

		/* Now look for the specific pubkey/hash combo is supported */
			switch (crt->sigAlgorithm) {
#ifdef USE_RSA_CIPHER_SUITE
			case OID_SHA256_RSA_SIG:
				if (!(ssl->hashSigAlg & HASH_SIG_SHA256_RSA_MASK)) {
					return PS_UNSUPPORTED_FAIL;
				}
				break;
#ifdef USE_SHA1
			case OID_SHA1_RSA_SIG:
				if (!(ssl->hashSigAlg & HASH_SIG_SHA1_RSA_MASK)) {
					return PS_UNSUPPORTED_FAIL;
				}
				break;
#endif
#ifdef USE_SHA384
			case OID_SHA384_RSA_SIG:
				if (!(ssl->hashSigAlg & HASH_SIG_SHA384_RSA_MASK)) {
					return PS_UNSUPPORTED_FAIL;
				}
				break;
#endif
#endif /* USE_RSA_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE
			case OID_SHA256_ECDSA_SIG:
				if (!(ssl->hashSigAlg & HASH_SIG_SHA256_ECDSA_MASK)) {
					return PS_UNSUPPORTED_FAIL;
				}
				break;
#ifdef USE_SHA1
			case OID_SHA1_ECDSA_SIG:
				if (!(ssl->hashSigAlg & HASH_SIG_SHA1_ECDSA_MASK)) {
					return PS_UNSUPPORTED_FAIL;
				}
				break;
#endif
#ifdef USE_SHA384
			case OID_SHA384_ECDSA_SIG:
				if (!(ssl->hashSigAlg & HASH_SIG_SHA384_ECDSA_MASK)) {
					return PS_UNSUPPORTED_FAIL;
				}
				break;
#endif
#endif /* USE_ECC */
			default:
				psTraceInfo("Don't share ANY sig/hash algorithms with peer\n");
				return PS_UNSUPPORTED_FAIL;
			}
			
#ifdef USE_ECC
			/* EC suites have the added check of specific curves.  Just
				checking DH suites because the curve comes from the cert.
				ECDHE suites negotiate key exchange curve elsewhere */
			if (spec->type == CS_ECDH_ECDSA || spec->type == CS_ECDH_RSA) {
				if (ssl->ecInfo.ecFlags) {
					/* Do negotiated curves work with our signatures */
					if (psTestUserEcID(crt->publicKey.key.ecc.curve->curveId,
							ssl->ecInfo.ecFlags) < 0) {
						return PS_UNSUPPORTED_FAIL;
					}
				} else {
					psTraceInfo("Don't share ANY EC curves with peer\n");
					return PS_UNSUPPORTED_FAIL;
				}
			}
#endif
			crt = crt->next;
		}
	}


#endif /* USE_TLS_1_2 */

	/* Must be good */
	return PS_SUCCESS;
}

/*
	This is the signature algorithm that the client will be using to encrypt
	the key material based on what the cipher suite says it should be.
	Only looking at child most cert
*/
static int32 haveCorrectSigAlg(psX509Cert_t *cert, int32 sigType)
{
	if (sigType == RSA_TYPE_SIG) {
		if (cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
				cert->sigAlgorithm == OID_SHA256_RSA_SIG ||
				cert->sigAlgorithm == OID_SHA384_RSA_SIG ||
				cert->sigAlgorithm == OID_SHA512_RSA_SIG ||
				cert->sigAlgorithm == OID_MD5_RSA_SIG ||
				cert->sigAlgorithm == OID_MD2_RSA_SIG ||
				cert->sigAlgorithm == OID_RSASSA_PSS) {
			return PS_SUCCESS;
		}
	} else if (sigType == ECDSA_TYPE_SIG) {
		if (cert->sigAlgorithm == OID_SHA1_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA224_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA256_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA384_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA512_ECDSA_SIG) {
			return PS_SUCCESS;
		}
	}

	return PS_FAILURE;
}
#endif /* USE_SERVER_SIDE_SSL */

/******************************************************************************/
/*
	Don't report a matching cipher suite if the user hasn't loaded the
	proper public key material to support it.  We do not check the client
	auth side of the algorithms because that authentication mechanism is
	negotiated within the handshake itself

	The annoying #ifdef USE_SERVER_SIDE and CLIENT_SIDE are because the
	structure members only exist one one side or the other and so are used
	for compiling.  You can't actually get into the wrong area of the
	SSL_FLAGS_SERVER test so no #else cases should be needed
 */
int32_t haveKeyMaterial(const ssl_t *ssl, int32 cipherType, short reallyTest)
{

#ifdef USE_SERVER_SIDE_SSL
	/* If the user has a ServerNameIndication callback registered we're
		going to skip the first test because they may not have loaded the
		final key material yet */
	if (ssl->sni_cb && reallyTest == 0) {
		return PS_SUCCESS;
	}
#endif

#ifndef USE_ONLY_PSK_CIPHER_SUITE

	/*	To start, capture all the cipherTypes where servers must have an
		identity and clients have a CA so we don't repeat them everywhere */
	if (cipherType == CS_RSA || cipherType == CS_DHE_RSA ||
			cipherType == CS_ECDHE_RSA || cipherType == CS_ECDH_RSA ||
			cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL
			if (ssl->keys == NULL || ssl->keys->cert == NULL) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (ssl->keys == NULL || ssl->keys->CAcerts == NULL) {
				return PS_FAILURE;
			}
#endif
		}
	}

	/*	Standard RSA ciphers types - auth and exchange */
	if (cipherType == CS_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_RSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, RSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL
		} else { /* Client */

			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}
	}

#ifdef USE_DHE_CIPHER_SUITE
/*
	DHE_RSA ciphers types
*/
	if (cipherType == CS_DHE_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef REQUIRE_DH_PARAMS
			if (ssl->keys->dhParams.size == 0) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_SERVER_SIDE_SSL
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_RSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}
	}

#ifdef REQUIRE_DH_PARAMS
/*
	Anon DH ciphers don't need much
*/
	if (cipherType == CS_DH_ANON) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->keys == NULL || ssl->keys->dhParams.size == 0) {
				return PS_FAILURE;
			}
		}
	}
#endif

#ifdef USE_PSK_CIPHER_SUITE
	if (cipherType == CS_DHE_PSK) {
#ifdef REQUIRE_DH_PARAMS
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->keys == NULL || ssl->keys->dhParams.size == 0) {
				return PS_FAILURE;
			}
		}
#endif
		/* Only using these for clients at the moment */
		if (!(ssl->flags & SSL_FLAGS_SERVER)) {
			if (ssl->keys == NULL || ssl->keys->pskKeys == NULL) {
				return PS_FAILURE;
			}
		}
	}
#endif	/* USE_PSK_CIPHER_SUITE */
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE /* key exchange */
/*
	ECDHE_RSA ciphers use RSA keys
*/
	if (cipherType == CS_ECDHE_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_RSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, RSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}
	}

/*
	ECDH_RSA ciphers use ECDSA key exhange and RSA auth.
*/
	if (cipherType == CS_ECDH_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_ECDSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, RSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}
	}


/*
	ECDHE_ECDSA and ECDH_ECDSA ciphers must have ECDSA keys
*/
	if (cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_ECDSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, ECDSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_ECDSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}
	}
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* USE_ONLY_PSK_CIPHER_SUITE	*/

#ifdef USE_PSK_CIPHER_SUITE
	if (cipherType == CS_PSK) {
		if (ssl->keys == NULL || ssl->keys->pskKeys == NULL) {
			return PS_FAILURE;
		}
	}
#endif	/* USE_PSK_CIPHER_SUITE */

	return PS_SUCCESS;
}
#endif /* VALIDATE_KEY_MATERIAL */


#ifdef USE_SERVER_SIDE_SSL

#ifdef USE_SERVER_PREFERRED_CIPHERS

/*	quick sort support for sorting descendingly the client's supported
	supported cipher list
*/
void quick_sort_desc(uint32 *v, int l, int r) {
	int i = l, j = r;
	int tmp;
	int p = v[(l + r) / 2];

	while (i <= j) {
		while (v[i] > p)
			i++;
		while (v[j] < p)
			j--;

		if (i <= j) {
			tmp = v[i];
			v[i] = v[j];
			v[j] = tmp;
			i++;
			j--;
		}
	};

	if (l < j)
		quick_sort_desc(v, l, j);
	if (i < r)
		quick_sort_desc(v, i, r);
}

#endif /* USE_SERVER_PREFERRED_CIPHERS */

/*	0 return is a key was found
	<0 is no luck
*/
int32 chooseCipherSuite(ssl_t *ssl, unsigned char *listStart, int32 listLen)
{
	const sslCipherSpec_t	*spec;
	unsigned char			*c = listStart;
	unsigned char			*end;
	uint16					ecKeyExchange;
	uint32					cipher;
	sslPubkeyId_t			wantKey;
	sslKeys_t				*givenKey = NULL;

#ifdef USE_SERVER_PREFERRED_CIPHERS

#define MAX_CIPHERS 256

	unsigned char			*cc = listStart;
	unsigned char			*ec = listStart + listLen;
	uint32					ciphers[MAX_CIPHERS];
	int						ciphersLen = 0, cn = 0, i = 0;

	while ((cc < ec) && (cn < MAX_CIPHERS)) {
		if (ssl->rec.majVer > SSL2_MAJ_VER) {
			ciphers[cn] = *cc << 8; cc++;
			ciphers[cn] += *cc; cc++;
		} else {
			/* Deal with an SSLv2 hello message.  Ciphers are 3 bytes long */
			ciphers[cn] = *cc << 16; cc++;
			ciphers[cn] += *cc << 8; cc++;
			ciphers[cn] += *cc; cc++;
		}

		psTraceIntInfo("Cipher index %d ", cn);
		psTraceIntInfo("is %d\n", ciphers[cn]);

		cn++;
	}

	if (cn > 1) quick_sort_desc(ciphers, 0, cn - 1);

	while (i < cn) {
		cipher = ciphers[i++];

#else

	end = c + listLen;
	while (c < end) {
		
		if (ssl->rec.majVer > SSL2_MAJ_VER) {
			cipher = *c << 8; c++;
			cipher += *c; c++;
		} else {
			/* Deal with an SSLv2 hello message.  Ciphers are 3 bytes long */
			cipher = *c << 16; c++;
			cipher += *c << 8; c++;
			cipher += *c; c++;
		}

#endif /*USE_SERVER_PREFERRED_CIPHERS*/

		psTraceIntInfo("Testing cipher %d\n", cipher);
		/* Checks if this cipher suite compiled into the library.
			ALSO, in the cases of static server keys (ssl->keys not NULL)
			the haveKeyMaterial	function will be run */
		if ((spec = sslGetCipherSpec(ssl, cipher)) == NULL) {
			psTraceIntInfo("Cipher %d not compiled in the library\n", cipher);
			continue;
		}

		psTraceIntInfo("Cipher %d found in the library. Testing keys...\n", cipher);
		
		if (ssl->keys == NULL) {
			psTraceInfo("NULL keys\n");

			/* Populate the sslPubkeyId_t struct to pass to user callback */
			wantKey.keyType = getKeyTypeFromCipherType(spec->type,
				&wantKey.dhParamsRequired, &ecKeyExchange);
			/* If this is a ECDHE_RSA or ECDH_RSA suite, there are going to
				need to be some indications for that */
			psTraceInfo("ecKeyExchange must be incorporated into the user callback.\n");
		
			/* If this a pure PSK cipher with no DH then we assign that suite
				immediately and never invoke the user callback.  This server has
				already indicated its willingness to use PSK if compiled in and
				the client has sent the suites in priority order so we use it */
			if (wantKey.keyType == CS_NULL && wantKey.dhParamsRequired == 0) {
				ssl->cipher = spec;
				return PS_SUCCESS;
			}
		
			/* ssl->expectedName is populated with the optional
				SNI extension value.  
				
				In this flexible server case, the SNI callback function is
				NOT USED.
				*/
			wantKey.serverName = ssl->expectedName;
#ifdef USE_TLS_1_2
			wantKey.hashAlg = ssl->hashSigAlg;
#else
			wantKey.hashAlg = 0;
#endif
#ifdef USE_ECC_CIPHER_SUITE
			/* At this point ssl->ecInfo.ecFlags carries the shared curves */
			wantKey.curveFlags = ssl->ecInfo.ecFlags;
#else
			wantKey.curveFlags = 0;
#endif
		
#ifndef USE_ONLY_PSK_CIPHER_SUITE	
			/* Invoke the user's callback */
			givenKey = (ssl->sec.pubkeyCb)(ssl, &wantKey);
#endif
			
			if (givenKey == NULL) {
				/* User didn't have a match.  Keep looking through suites */
				continue;
			}
			
#ifdef VALIDATE_KEY_MATERIAL
			/* We want to double check this.  Temporarily assign their keys as
				ssl->keys for haveKeyMaterial to find */
			ssl->keys = givenKey;
			if (haveKeyMaterial(ssl, spec->type, 1) < 0) {
				ssl->keys = NULL;
				/* We're still looping through cipher suites above so this
					isn't really fatal.  It just means the user gave us keys
					that don't match the suite we wanted */
				psTraceInfo("WARNING: server didn't load proper keys for ");
				psTraceIntInfo("cipher suite %d during pubkey callback\n",
					spec->ident);
				continue;
			}
			/* Reset.  One final test below before we can set ssl->keys */
			ssl->keys = NULL;
#endif
		} else {
			if (ssl->expectedName) {
				/* The SNI callback is no longer invoked in the middle of the
					parse.  Now is the time to call it for pre-loaded keys */
				if (matrixServerSetKeysSNI(ssl, ssl->expectedName,
						strlen(ssl->expectedName)) < 0) {
					psTraceInfo("Server didn't load SNI keys\n");
					ssl->err = SSL_ALERT_UNRECOGNIZED_NAME;
					return MATRIXSSL_ERROR;
				}
			}
			/* This is here becuase it still could be useful to support the
				old mechanism where the server just loads the single known
				ID key at new session and never looks back */
			givenKey = ssl->keys;
		}
		
#ifdef VALIDATE_KEY_MATERIAL
		/* Validate key for any sigHashAlg and eccParam hello extensions */
		if (validateKeyForExtensions(ssl, spec, givenKey) < 0){
			givenKey = NULL;
		} else {
#endif
			ssl->cipher = spec;
			ssl->keys = givenKey;
			return PS_SUCCESS;
#ifdef VALIDATE_KEY_MATERIAL
		}
#endif
	}
	
	psAssert(givenKey == NULL);
	return PS_UNSUPPORTED_FAIL; /* Server can't match anything */
}
#endif /* USE_SERVER_SIDE */


#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_ECC_CIPHER_SUITE
/*
	See if any of the EC suites are supported.  Needed by client very early on
	to know whether or not to add the EC client hello extensions
*/
int32_t eccSuitesSupported(const ssl_t *ssl,
				const uint16_t cipherSpecs[], uint8_t cipherSpecLen)
{
	int32	i = 0;

	if (cipherSpecLen == 0) {
		if (sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA) ||
#ifdef USE_TLS_1_2
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) ||
#endif
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA)) {
			return 1;
		}
	} else {
		while (i < cipherSpecLen) {
			if (cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_CBC_SHA ||
#ifdef USE_TLS_1_2
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
#endif
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_CBC_SHA) {
				return 1;
			}
			i++;
		}
	}
	return 0;
}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_CLIENT_SIDE_SSL
/* Test if agreed upon cipher suite authentication is being adhered to */
int32 csCheckCertAgainstCipherSuite(int32 pubKey, int32 cipherType)
{
	if (pubKey == PS_RSA) {
		if (cipherType == CS_DHE_RSA || cipherType == CS_RSA ||
				cipherType == CS_ECDHE_RSA) {
			return 1;
		}
	}
	if (pubKey == PS_ECC) {
		if (cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA ||
				cipherType == CS_ECDH_RSA) {
			return 1;
		}

	}
	return 0; /* no match */
}
#endif /* USE_CLIENT_SIDE_SSL */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/
/**
	Lookup the given cipher spec ID.
	@param[in] id The official ciphersuite id to find.
	@return A pointer to the cipher suite structure, if configured in build.
		If not defined, return NULL.
*/
const sslCipherSpec_t *sslGetDefinedCipherSpec(uint16_t id)
{
	uint8_t		i;

	for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++) {
		if (supportedCiphers[i].ident == id) {
			return &supportedCiphers[i];
		}
	}
	return NULL;
}

/******************************************************************************/
/**
	Lookup and validate the given cipher spec ID.
	Return a pointer to the structure if found and meeting constraints in 'ssl'.
	This is used when negotiating security, to find out what suites we support.
	@param[in] id The official ciphersuite id to find.
	@return A pointer to the cipher suite structure, if configured in build
		and appropriate for the constraints in 'ssl'.
		If not defined or apprppriate, return NULL.
*/
const sslCipherSpec_t *sslGetCipherSpec(const ssl_t *ssl, uint16_t id)
{
	uint8_t		i;
#ifdef USE_SERVER_SIDE_SSL
	uint8_t		j;
#endif /* USE_SERVER_SIDE_SSL */

	i = 0;
	do {
		if (supportedCiphers[i].ident != id) {
			continue;
		}
		/* Double check we support the requsted hash algorithm */
#ifndef USE_MD5
		if (supportedCiphers[i].flags & CRYPTO_FLAGS_MD5) {
			return NULL;
		}
#endif
#ifndef USE_SHA1
		if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA1) {
			return NULL;
		}
#endif
#if !defined(USE_SHA256) && !defined(USE_SHA384)
		if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
			return NULL;
		}
#endif
		/* Double check we support the requsted weak cipher algorithm */
#ifndef USE_ARC4
		if (supportedCiphers[i].flags &
			(CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD)) {
			return NULL;
		}
#endif
#ifndef USE_3DES
		if (supportedCiphers[i].flags & CRYPTO_FLAGS_3DES) {
			return NULL;
		}
#endif
#ifdef USE_SERVER_SIDE_SSL
		/* Globally disabled? */
		if (disabledCipherFlags[i >> 5] & (1 << (i & 31))) {
			psTraceIntInfo("Matched cipher suite %d but disabled by user\n",
				id);
			return NULL;
		}
		/* Disabled for session? */
		if (id != 0) { /* Disable NULL_WITH_NULL_NULL not possible */
			for (j = 0; j < SSL_MAX_DISABLED_CIPHERS; j++) {
				if (ssl->disabledCiphers[j] == id) {
					psTraceIntInfo("Matched cipher suite %d but disabled by user\n",
						id);
					return NULL;
				}
			}
		}
#endif /* USE_SERVER_SIDE_SSL */
#ifdef USE_TLS_1_2
		/* Unusable because protocol doesn't allow? */
#ifdef USE_DTLS
		if (ssl->majVer == DTLS_MAJ_VER &&
				ssl->minVer != DTLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				psTraceIntInfo(
					"Matched cipher suite %d but only allowed in DTLS 1.2\n", id);
				return NULL;
			}
		}
		if (!(ssl->flags & SSL_FLAGS_DTLS)) {
#endif
		if (ssl->minVer < TLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				psTraceIntInfo(
					"Matched cipher suite %d but only allowed in TLS 1.2\n", id);
				return NULL;
			}
		}
		if (ssl->minVer == TLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_MD5) {
				psTraceIntInfo("Not allowing MD5 suite %d in TLS 1.2\n",
					id);
				return NULL;
			}
		}
#ifdef USE_DTLS
		}
#endif
#endif /* TLS_1_2 */

		/** Check restrictions by HTTP2 (set by ALPN extension).
			This should filter out all ciphersuites specified in:
				https://tools.ietf.org/html/rfc7540#appendix-A
		"Note: This list was assembled from the set of registered TLS
		cipher suites at the time of writing.  This list includes those
		cipher suites that do not offer an ephemeral key exchange and
		those that are based on the TLS null, stream, or block cipher type
		(as defined in Section 6.2.3 of [TLS12]).  Additional cipher
		suites with these properties could be defined; these would not be
		explicitly prohibited."
		*/
		if (ssl->flags & SSL_FLAGS_HTTP2) {
			/** Only allow AEAD ciphers. */
			if (!(supportedCiphers[i].flags & CRYPTO_FLAGS_GCM) &&
				!(supportedCiphers[i].flags & CRYPTO_FLAGS_CHACHA)) {

				return NULL;
			}
			/** Only allow ephemeral key exchange. */
			switch (supportedCiphers[i].type) {
			case CS_DHE_RSA:
			case CS_ECDHE_ECDSA:
			case CS_ECDHE_RSA:
				break;
			default:
				return NULL;
			}
		}

		/*	The suite is available.  Want to reject if current key material
			does not support? */
#ifdef VALIDATE_KEY_MATERIAL
		if (ssl->keys != NULL) {
			if (haveKeyMaterial(ssl, supportedCiphers[i].type, 0)
					== PS_SUCCESS) {
				return &supportedCiphers[i];
			}
			psTraceIntInfo("Matched cipher suite %d but no supporting keys\n",
				id);
		} else {
			return &supportedCiphers[i];
		}
#else
		return &supportedCiphers[i];
#endif /* VALIDATE_KEY_MATERIAL */
	} while (supportedCiphers[i++].ident != SSL_NULL_WITH_NULL_NULL) ;

	return NULL;
}


/******************************************************************************/
/*
	Write out a list of the supported cipher suites to the caller's buffer
	First 2 bytes are the number of cipher suite bytes, the remaining bytes are
	the cipher suites, as two byte, network byte order values.
*/
int32_t sslGetCipherSpecList(ssl_t *ssl, unsigned char *c, int32 len,
		int32 addScsv)
{
	unsigned char	*end, *p;
	unsigned short	i;
	int32			ignored;

	if (len < 4) {
		return -1;
	}
	end = c + len;
	p = c; c += 2;

	ignored = 0;
	for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++) {
		if (end - c < 2) {
			return PS_MEM_FAIL;
		}
#ifdef USE_TLS_1_2
		/* The SHA-2 based cipher suites are TLS 1.2 only so don't send
			those if the user has requested a lower protocol in
			NewClientSession */
#ifdef USE_DTLS
		if (ssl->majVer == DTLS_MAJ_VER && ssl->minVer != DTLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				ignored += 2;
				continue;
			}
		}
		if (!(ssl->flags & SSL_FLAGS_DTLS)) {
#endif
		if (ssl->minVer != TLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				ignored += 2;
				continue;
			}
		}
#ifdef USE_DTLS
		}
#endif
#endif	/* TLS_1_2 */
#ifdef VALIDATE_KEY_MATERIAL
		if (haveKeyMaterial(ssl, supportedCiphers[i].type, 0) != PS_SUCCESS) {
			ignored += 2;
			continue;
		}
#endif
		*c = (unsigned char)((supportedCiphers[i].ident & 0xFF00) >> 8); c++;
		*c = (unsigned char)(supportedCiphers[i].ident & 0xFF); c++;
	}
	i *= 2;
	i -= (unsigned short)ignored;
#ifdef ENABLE_SECURE_REHANDSHAKES
	if (addScsv == 1) {
#ifdef USE_CLIENT_SIDE_SSL
		ssl->extFlags.req_renegotiation_info = 1;
#endif
		if (end - c < 2) {
			return PS_MEM_FAIL;
		}
		*c = ((TLS_EMPTY_RENEGOTIATION_INFO_SCSV & 0xFF00) >> 8); c++;
		*c = TLS_EMPTY_RENEGOTIATION_INFO_SCSV  & 0xFF; c++;
		i += 2;
	}
#endif

#ifdef USE_CLIENT_SIDE_SSL
	/* This flag is set in EncodeClientHello based on sslSessOpts_t.fallbackScsv */
	if (ssl->extFlags.req_fallback_scsv) {
		/** Add the fallback signalling ciphersuite.
		@see https://tools.ietf.org/html/rfc7507 */
		if (end - c < 2) {
			return PS_MEM_FAIL;
		}
		*c = (TLS_FALLBACK_SCSV >> 8) & 0xFF; c++;
		*c = TLS_FALLBACK_SCSV & 0xFF; c++;
		i += 2;
	}
#endif	

	*p = (unsigned char)(i >> 8); p++;
	*p = (unsigned char)(i & 0xFF);
	return i + 2;
}

/******************************************************************************/
/*
	Return the length of the cipher spec list, including initial length bytes,
	(minus any suites that we don't have the key material to support)
*/
int32_t sslGetCipherSpecListLen(const ssl_t *ssl)
{
	int32	i, ignored;

	ignored = 0;
	for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++) {
#ifdef USE_TLS_1_2
		/* The SHA-2 based cipher suites are TLS 1.2 only so don't send
			those if the user has requested a lower protocol in
			NewClientSession */
#ifdef USE_DTLS
		if (ssl->majVer == DTLS_MAJ_VER && ssl->minVer != DTLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				ignored += 2;
				continue;
			}
		}
		if (!(ssl->flags & SSL_FLAGS_DTLS)) {
#endif
		if (ssl->minVer != TLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				ignored += 2;
				continue;
			}
		}
#ifdef USE_DTLS
		}
#endif
#endif	/* USE_TLS_1_2 */
#ifdef VALIDATE_KEY_MATERIAL
		if (haveKeyMaterial(ssl, supportedCiphers[i].type, 0) != PS_SUCCESS) {
			ignored += 2;
		}
#endif
	}
	return (i * 2) + 2 - ignored;
}

/******************************************************************************/
/*
	Flag the session based on the agreed upon cipher suite
	NOTE: sslResetContext will have cleared these flags for re-handshakes
*/
void matrixSslSetKexFlags(ssl_t *ssl)
{

#ifdef USE_DHE_CIPHER_SUITE
/*
	Flag the specific DH ciphers so the correct key exchange
	mechanisms can be used.  And because DH changes the handshake
	messages as well.
*/
	if (ssl->cipher->type == CS_DHE_RSA) {
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_DHE_WITH_RSA;
	}

#ifdef USE_PSK_CIPHER_SUITE
/*
	Set the PSK flags and DH kex.
	NOTE:  Although this isn't technically a DH_anon cipher, the handshake
	message order for DHE_PSK are identical and we can nicely piggy back
	on the handshake logic that already exists.
*/
	if (ssl->cipher->type == CS_DHE_PSK) {
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_ANON_CIPHER;
		ssl->flags |= SSL_FLAGS_PSK_CIPHER;
#ifdef USE_CLIENT_AUTH
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				psTraceInfo("No client auth TLS mode for DHE_PSK ciphers");
				psTraceInfo(". Disabling CLIENT_AUTH.\n");
				ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
			}
		}
#endif /* USE_CLIENT_AUTH */
	}
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->cipher->type == CS_ECDHE_RSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_DHE_WITH_RSA;
	}
	if (ssl->cipher->type == CS_ECDHE_ECDSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_DHE_WITH_DSA;
	}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_ANON_DH_CIPHER_SUITE
	if (ssl->cipher->type == CS_DH_ANON) {
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_ANON_CIPHER;
		ssl->sec.anon = 1;
	}
#endif /* USE_ANON_DH_CIPHER_SUITE */
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->cipher->type == CS_ECDH_ECDSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
	}
	if (ssl->cipher->type == CS_ECDH_RSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
	}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
	if (ssl->cipher->type == CS_PSK) {
		ssl->flags |= SSL_FLAGS_PSK_CIPHER;
#ifdef USE_CLIENT_AUTH
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				psTraceInfo("No client auth TLS mode for basic PSK ciphers");
				psTraceInfo(". Disabling CLIENT_AUTH.\n");
				ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
			}
		}
#endif /* USE_CLIENT_AUTH */
	}
#endif /* USE_PSK_CIPHER_SUITE	*/

	return;
}
/******************************************************************************/

