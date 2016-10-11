/**
 *	@file    sslEncode.c
 *	@version $Format:%h%d$
 *
 *	Secure Sockets Layer protocol message encoding portion of MatrixSSL.
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

#ifndef USE_ONLY_PSK_CIPHER_SUITE
static int32 writeCertificate(ssl_t *ssl, sslBuf_t *out, int32 notEmpty);
#if defined(USE_OCSP) && defined(USE_SERVER_SIDE_SSL)
static int32 writeCertificateStatus(ssl_t *ssl, sslBuf_t *out);
#endif
#endif
static int32 writeChangeCipherSpec(ssl_t *ssl, sslBuf_t *out);
static int32 writeFinished(ssl_t *ssl, sslBuf_t *out);
static int32 writeAlert(ssl_t *ssl, unsigned char level,
				unsigned char description, sslBuf_t *out, uint32 *requiredLen);
static int32_t writeRecordHeader(ssl_t *ssl, uint8_t type, uint8_t hsType,
				uint16_t *messageSize, uint8_t *padLen,
				unsigned char **encryptStart,
				const unsigned char *end, unsigned char **c);
#ifdef USE_DTLS
#ifdef USE_SERVER_SIDE_SSL
static int32 writeHelloVerifyRequest(ssl_t *ssl, sslBuf_t *out);
#endif
#endif /* USE_DTLS */

static int32 encryptRecord(ssl_t *ssl, int32 type, int32 hsMsgType,
				int32 messageSize,	int32 padLen, unsigned char *pt,
				sslBuf_t *out, unsigned char **c);

#ifdef USE_CLIENT_SIDE_SSL
static int32 writeClientKeyExchange(ssl_t *ssl, sslBuf_t *out);
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
static int32 writeCertificateRequest(ssl_t *ssl, sslBuf_t *out, int32 certLen,
				int32 certCount);
static int32 writeMultiRecordCertRequest(ssl_t *ssl, sslBuf_t *out,
				int32 certLen, int32 certCount, int32 sigHashLen);
#endif
#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
static int32 writeCertificateVerify(ssl_t *ssl, sslBuf_t *out);
static int32 nowDoCvPka(ssl_t *ssl, psBuf_t *out);
#endif
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_SERVER_SIDE_SSL
static int32 writeServerHello(ssl_t *ssl, sslBuf_t *out);
static int32 writeServerHelloDone(ssl_t *ssl, sslBuf_t *out);
#ifdef USE_PSK_CIPHER_SUITE
static int32 writePskServerKeyExchange(ssl_t *ssl, sslBuf_t *out);
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
static int32 writeServerKeyExchange(ssl_t *ssl, sslBuf_t *out, uint32 pLen,
					unsigned char *p, uint32 gLen, unsigned char *g);
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_STATELESS_SESSION_TICKETS /* Already inside a USE_SERVER_SIDE block */
static int32 writeNewSessionTicket(ssl_t *ssl, sslBuf_t *out);
#endif
#endif /* USE_SERVER_SIDE_SSL */

static int32 secureWriteAdditions(ssl_t *ssl, int32 numRecs);
static int32 encryptFlight(ssl_t *ssl, unsigned char **end);

#ifdef USE_ZLIB_COMPRESSION
#define MAX_ZLIB_COMPRESSED_OH	128 /* Only FINISHED message supported */
#endif
/******************************************************************************/
/*
	This works for both in-situ and external buf

	buf		in	Start of allocated buffer (header bytes beyond are overwritten)
			out	Start of encrypted data on function success

	size	in	Total size of the allocated buffer

	ptBuf	in	Pointer to front of the plain text data to be encrypted

	len		in	Length of incoming plain text
			out	Length of encypted text on function success
			out	Length of required 'size' on SSL_FULL
*/
int32 matrixSslEncode(ssl_t *ssl, unsigned char *buf, uint32 size,
		unsigned char *ptBuf, uint32 *len)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize;
	int32_t			rc;
	psBuf_t			tmpout;

	/* If we've had a protocol error, don't allow further use of the session
		Also, don't allow a application data record to be encoded unless the
		handshake is complete.
	*/
	if (ssl->flags & SSL_FLAGS_ERROR || ssl->hsState != SSL_HS_DONE ||
			ssl->flags & SSL_FLAGS_CLOSED) {
		psTraceInfo("Bad SSL state for matrixSslEncode call attempt: ");
		psTraceIntInfo(" flags %d,", ssl->flags);
		psTraceIntInfo(" state %d\n", ssl->hsState);
		return MATRIXSSL_ERROR;
	}

	c = buf;
	end = buf + size;

#ifdef USE_BEAST_WORKAROUND
	if (ssl->bFlags & BFLAG_STOP_BEAST) {
		messageSize = ssl->recordHeadLen + 1; /* single byte is the fix */
		if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
				&messageSize, &padLen, &encryptStart, end, &c)) < 0) {
			if (rc == SSL_FULL) {
				*len = messageSize;
			}
			return rc;
		}
		psAssert(encryptStart == buf + ssl->recordHeadLen);
		c += 1;
		*len -= 1;

		tmpout.buf = tmpout.start = tmpout.end = buf;
		tmpout.size = size;
		if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
				messageSize, padLen, ptBuf, &tmpout, &c)) < 0) {
			return rc;
		}
		ptBuf += 1;
		tmpout.end = tmpout.end + (c - buf);

	}
#endif
/*
	writeRecordHeader will determine SSL_FULL cases.  The expected
	messageSize to writeRecored header is the plain text length plus the
	record header length
 */
	messageSize = ssl->recordHeadLen + *len;

	if (messageSize > SSL_MAX_BUF_SIZE) {
		psTraceIntInfo("Message too large for matrixSslEncode: %d\n",
			messageSize);
		return PS_MEM_FAIL;
	}
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
			&messageSize, &padLen, &encryptStart, end, &c)) < 0) {
		if (rc == SSL_FULL) {
			*len = messageSize;
		}
		return rc;
	}

	c += *len;
#ifdef USE_BEAST_WORKAROUND
	if (ssl->bFlags & BFLAG_STOP_BEAST) {
		/* The tmpout buf already contains the single byte record and has
			updated pointers for current location.  Disable at this time */
		ssl->bFlags &= ~BFLAG_STOP_BEAST;
	} else {
		tmpout.buf = tmpout.start = tmpout.end = buf;
		tmpout.size = size;
	}
#else
	tmpout.buf = tmpout.start = tmpout.end = buf;
	tmpout.size = size;
#endif

	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
			messageSize, padLen, ptBuf, &tmpout, &c)) < 0) {
		return rc;
	}
	*len = (int32)(c - buf);

#ifdef SSL_REHANDSHAKES_ENABLED
	ssl->rehandshakeBytes += *len;
	if (ssl->rehandshakeBytes >= BYTES_BEFORE_RH_CREDIT) {
		if (ssl->rehandshakeCount < 0x8000) {
			/* Don't increment if disabled (-1) */
			if (ssl->rehandshakeCount >= 0) {
				ssl->rehandshakeCount++;
			}
		}
		ssl->rehandshakeBytes = 0;
	}
#endif /* SSL_REHANDSHAKES_ENABLED */
	return *len;
}

/******************************************************************************/
/*
	A helper function for matrixSslGetWritebuf to determine the correct
	destination size before allocating an output buffer.
 */
int32 matrixSslGetEncodedSize(ssl_t *ssl, uint32 len)
{
	len += ssl->recordHeadLen;
	if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
		len += ssl->enMacSize;
#ifdef USE_TLS_1_1
/*
		If a block cipher is being used TLS 1.1 requires the use
		of an explicit IV.  This is an extra random block of data
		prepended to the plaintext before encryption.  Account for
		that extra length here.
*/
		if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
				(ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
			len += ssl->enBlockSize;
		}
		if (ssl->flags & SSL_FLAGS_AEAD_W) {
			len += AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl);
		}
#endif /* USE_TLS_1_1 */

#ifdef USE_BEAST_WORKAROUND
		if (ssl->bFlags & BFLAG_STOP_BEAST) {
			/* Original message less one */
			len += psPadLenPwr2(len - 1 - ssl->recordHeadLen, ssl->enBlockSize);
			/* The single byte record overhead */
			len += ssl->recordHeadLen + ssl->enMacSize;
			len += psPadLenPwr2(1 + ssl->enMacSize, ssl->enBlockSize);
		} else {
			len += psPadLenPwr2(len - ssl->recordHeadLen, ssl->enBlockSize);
		}
#else
		len += psPadLenPwr2(len - ssl->recordHeadLen, ssl->enBlockSize);
#endif
	}
	return len;
}

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/* Second parameter includes handshake header length */
static int32 addCertFragOverhead(ssl_t *ssl, int32 totalCertLen)
{
	int32 oh = 0;

	/* For each additional record, we'll need a record header and
		secureWriteAdditions.  Borrowing ssl->fragIndex and ssl->fragTotal */
	ssl->fragTotal = totalCertLen;
	ssl->fragIndex = 0;
	while (ssl->fragTotal > 0) {
		if (ssl->fragIndex == 0) {
			/* First one is accounted for below as normal */
			ssl->fragTotal -= ssl->maxPtFrag;
			ssl->fragIndex++;
		} else {
			/* Remember this stage is simply for SSL_FULL test
			  so just incr totalCertLen to add overhead */
			oh += secureWriteAdditions(ssl, 1);
			oh += ssl->recordHeadLen;
			if (ssl->fragTotal > (uint32)ssl->maxPtFrag) {
				ssl->fragTotal -= ssl->maxPtFrag;
			} else {
				ssl->fragTotal = 0;
			}
		}
	}
	return oh;
}
#endif /* SERVER || CLIENT_AUTH */
#endif /* ! ONLY_PSK */

#ifdef USE_ECC
/* ECDSA signature is two DER INTEGER values.  Either integer could result
	in the high bit being set which is interpreted as a negative number
	unless proceeded by a 0x0 byte.  MatrixSSL predicts one of the two will
	be negative when creating the empty buffer spot where the signature
	will be written.  If this guess isn't correct, this function is called
	to correct the buffer size */
static int accountForEcdsaSizeChange(ssl_t *ssl, pkaAfter_t *pka, int real,
				unsigned char *sig, psBuf_t *out, int hsMsg)
{
	flightEncode_t	*flightMsg;
	unsigned char	*whereToMoveFrom, *whereToMoveTo, *msgLenLoc;
	int				howMuchToMove, howFarToMove, msgLen, addOrSub;
	int				sigSizeChange, newPadLen;
	
	if (real > pka->user) {
		/* ECDSA SIGNATURE IS LONGER THAN DEFAULT */
		addOrSub = 1;
		/* Push outbuf backwards */
		sigSizeChange = real - pka->user;
	} else {
		/* ECDSA SIGNATURE IS SHORTER THAN DEFAULT */
		addOrSub = 0;
		/* Pull outbuf forward */
		sigSizeChange = pka->user - real;
	}
#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		/* Needed somewhere to store the size change for DTLS retransmits */
		ssl->ecdsaSizeChange = real - pka->user;
	}
#endif
	if (sigSizeChange > 12) {
		/* Sanity */
		psTraceIntInfo("ECDSA sig length change too big: %d\n", sigSizeChange);
		return MATRIXSSL_ERROR;
	}
	/* Get the flightEncode for this message early because the
		distance to shift things could depend on the padding bytes in
		addition to the basic ECDSA mismatch if we are rehandshaking */
	flightMsg = ssl->flightEncode;
	while (flightMsg != NULL &&	flightMsg->hsMsg != hsMsg) {
		flightMsg = flightMsg->next;
	}
	if (flightMsg == NULL) {
		return MATRIXSSL_ERROR;
	}
	
	if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) && (ssl->enBlockSize > 1)) {
		/* rehandshaking with block cipher */
		msgLen = (flightMsg->messageSize - ssl->recordHeadLen) -
			flightMsg->padLen;
		if (addOrSub) {
			msgLen += sigSizeChange;
		} else {
			msgLen -= sigSizeChange;
		}
		newPadLen = psPadLenPwr2(msgLen, ssl->enBlockSize);
		flightMsg->padLen = newPadLen;
		msgLen += newPadLen + ssl->recordHeadLen;

		if (flightMsg->messageSize >= msgLen) {
			howFarToMove = flightMsg->messageSize - msgLen;
		} else {
			howFarToMove = msgLen - flightMsg->messageSize;
		}
	} else {
		howFarToMove = sigSizeChange;
	}
			
	howMuchToMove = out->end - (pka->outbuf + pka->user);
	whereToMoveFrom	= pka->outbuf + pka->user;
			
	if (addOrSub) {
		whereToMoveTo = whereToMoveFrom + howFarToMove;
		/* enough room to push into? Extra two bytes should already
			have been accounted for but this is still nice for sanity */
		if (((out->start + out->size) - out->end) < howFarToMove) {
			return MATRIXSSL_ERROR;
		}
	} else {
		whereToMoveTo = whereToMoveFrom - howFarToMove;
	}
	memmove(whereToMoveTo, whereToMoveFrom, howMuchToMove);
	if (addOrSub) {
		out->end += howFarToMove;
		flightMsg->len += sigSizeChange;
		flightMsg->messageSize += howFarToMove;
	} else {
		out->end -= howFarToMove;
		flightMsg->len -= sigSizeChange;
		flightMsg->messageSize -= howFarToMove;
	}
	/* Now put in ECDSA sig */
	memcpy(pka->outbuf, sig, real);
			
	/* Now update the record message length - We can use the
		flightEncode entry to help us find the handshake header
		start. The record header len is only 2 bytes behind here...
		subtract nonce for AEAD */
	msgLenLoc = flightMsg->start - 2;
	msgLen = flightMsg->messageSize - ssl->recordHeadLen;

	if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			(ssl->flags & SSL_FLAGS_AEAD_W)) {
		msgLenLoc -= AEAD_NONCE_LEN(ssl);
	}
	
	msgLenLoc[0] = msgLen >> 8;
	msgLenLoc[1] = msgLen;
			
	/* Now update the handshake header length with same techique. */
	msgLenLoc = flightMsg->start + 1; /* Skip hsType byte */
	msgLen = flightMsg->len - ssl->hshakeHeadLen;
#ifdef USE_TLS_1_1
	/* Account for explicit IV in TLS_1_1 and above. */
	if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
		(ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
		msgLen -= ssl->enBlockSize;
		msgLenLoc += ssl->enBlockSize;
	}
#endif

#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		/* Will also be a fragment length to update in handshake header.
			Only supporting	if there is no fragmentation here.  The magic
			5 is skipping over the 3 byte length iteself, 2 byte sequence
			and 3 byte offset */
		if (memcmp(msgLenLoc, msgLenLoc + 8, 3) != 0) {
			psTraceInfo("ERROR: ECDSA SKE DTLS fragmentation unsupported\n");
			return MATRIXSSL_ERROR;
		}
	}
#endif

	msgLenLoc[0] = msgLen >> 16;
	msgLenLoc[1] = msgLen >> 8;
	msgLenLoc[2] = msgLen;
	
#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		/* Update the fragLen as well.  Sanity test was performed above */
		msgLenLoc[8] = msgLen >> 16;
		msgLenLoc[9] = msgLen >> 8;
		msgLenLoc[10] = msgLen;
	}
#endif

	/* All messages that follow in the flight have to be updated now */
	flightMsg = flightMsg->next;
	while (flightMsg != NULL) {
		if (addOrSub) {
			flightMsg->start += howFarToMove;
			if (flightMsg->seqDelay) {
				flightMsg->seqDelay += howFarToMove;
			}
		} else {
			flightMsg->start -= howFarToMove;
			if (flightMsg->seqDelay) {
				flightMsg->seqDelay -= howFarToMove;
			}
		}
		if (flightMsg->hsMsg == SSL_HS_FINISHED) {
			/* The finished message has set aside a pointer as well */
			if (addOrSub) {
				ssl->delayHsHash += howFarToMove;
			} else {
				ssl->delayHsHash -= howFarToMove;
			}
		}
		flightMsg = flightMsg->next;
	}
	return PS_SUCCESS;
}
#endif /* USE_ECC */


#ifdef USE_SERVER_SIDE_SSL
/* The ServerKeyExchange delayed PKA op */
static int32 nowDoSkePka(ssl_t *ssl, psBuf_t *out)
{
	int32_t		rc = PS_SUCCESS;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	pkaAfter_t	*pka;
#if defined(USE_ECC_CIPHER_SUITE) || defined(USE_RSA_CIPHER_SUITE)
	psPool_t	*pkiPool = NULL;
#endif /* USE_ECC_CIPHER_SUITE || USE_RSA_CIPHER_SUITE */

#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		if (ssl->retransmit) {
			/* Was already copied out in writeServerKeyExchange */
			/* Would not expect to see this because pkaAfter.type should
				never be set */
			return PS_SUCCESS;
		}
	}
#endif /* USE_DTLS */

	/* Always first one.  clearPkaAfter will move 1 to 0 if needed */
	pka = &ssl->pkaAfter[0];

#ifdef USE_RSA_CIPHER_SUITE
	if (pka->type == PKA_AFTER_RSA_SIG_GEN_ELEMENT ||
			pka->type == PKA_AFTER_RSA_SIG_GEN) {

#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			if ((rc = privRsaEncryptSignedElement(pkiPool,
					&ssl->keys->privKey.key.rsa,
					pka->inbuf, pka->inlen, pka->outbuf,
					ssl->keys->privKey.keysize, pka->data)) < 0) { 
				if (rc != PS_PENDING) {
					psTraceIntInfo("Unable to sign SKE digital element %d\n",
						rc);
					return MATRIXSSL_ERROR;
				}
				/* If the result is going directly inline to the output
					buffer we unflag 'type' so this function isn't called
					again on the way back around. Also, we can safely
					free inbuf because it has been copied out */
				psFree(pka->inbuf, ssl->hsPool); pka->inbuf = NULL;
				pka->type = 0;
				return PS_PENDING;
			}
		} else {
			if ((rc = psRsaEncryptPriv(pkiPool, &ssl->keys->privKey.key.rsa, pka->inbuf,
					pka->inlen, pka->outbuf, ssl->keys->privKey.keysize,
					pka->data)) < 0) {
				if (rc != PS_PENDING) {
					psTraceInfo("Unable to sign SERVER_KEY_EXCHANGE message\n");
					return MATRIXSSL_ERROR;
				}
				/* If the result is going directly inline to the output
					buffer we unflag 'type' so this function isn't called
					again on the way back around. Also, we can safely free
					inbuf becuase it has been copied out */
				psFree(pka->inbuf, ssl->hsPool); pka->inbuf = NULL;
				pka->type = 0;
				return PS_PENDING;
			}
		}
#else /* !USE_TLS_1_2 */
		if ((rc = psRsaEncryptPriv(pkiPool, &ssl->keys->privKey.key.rsa, pka->inbuf,
				pka->inlen, pka->outbuf, ssl->keys->privKey.keysize,
				pka->data)) < 0) {
			if (rc != PS_PENDING) {
				psTraceInfo("Unable to sign SERVER_KEY_EXCHANGE message\n");
				return MATRIXSSL_ERROR;
			}
			/* If the result is going directly inline to the output
				buffer we unflag 'type' so this function isn't called
				again on the way back around */
			psFree(pka->inbuf, ssl->hsPool); pka->inbuf = NULL;
			pka->type = 0;
			return PS_PENDING;
		}
#endif /* USE_TLS_1_2 */


#ifdef USE_DTLS
		if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 0)) {
			/* Using existing ckeMsg and ckeSize that clients are using but
				this should be totally fine on the server side because it is
				freed at FINISHED parse */
			ssl->ckeSize = ssl->keys->privKey.keysize;
			if ((ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize)) == NULL) {
				psTraceInfo("Memory allocation error ckeMsg\n");
				return PS_MEM_FAIL;
			}
			memcpy(ssl->ckeMsg, pka->outbuf, ssl->ckeSize);
		}
#endif /* USE_DTLS */

		clearPkaAfter(ssl); /* Blocking success case */
	}
#endif /* USE_RSA_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (pka->type == PKA_AFTER_ECDSA_SIG_GEN) {

		int32_t		err;
		uint16_t	len;
		/* New temp location for ECDSA sig which can be one len byte different
			than what we originally calculated (pka->user is holding) */
		unsigned char	*tmpEcdsa;

		/* Only need to allocate 1 larger because 1 has already been added
			at creation */
		if ((tmpEcdsa = psMalloc(ssl->hsPool, pka->user + 1)) == NULL) {
			return PS_MEM_FAIL;
		}

		len = pka->user + 1;

#ifdef USE_DTLS
		ssl->ecdsaSizeChange = 0;
#endif
		if ((err = psEccDsaSign(pkiPool, &ssl->keys->privKey.key.ecc,
				pka->inbuf, pka->inlen, tmpEcdsa, &len, 1, pka->data)) != 0) {
			/* DO NOT close pool (unless failed).  It is kept around in
				pkaCmdInfo for result until finished and is closed there */
			if (err != PS_PENDING) {
				psFree(tmpEcdsa, ssl->hsPool);
				return MATRIXSSL_ERROR;
			}

			/* ASYNC: tmpEcdsa is not saved as output location so correct to 
				free here */
			psFree(tmpEcdsa, ssl->hsPool);
			return PS_PENDING;
		}
		if (len != pka->user) {
			/* Confirmed ECDSA is not default size */
			if (accountForEcdsaSizeChange(ssl, pka, len, tmpEcdsa, out,
					SSL_HS_SERVER_KEY_EXCHANGE)	< 0) {
				clearPkaAfter(ssl);
				psFree(tmpEcdsa, ssl->hsPool);
				return MATRIXSSL_ERROR;
			}
		} else {
			memcpy(pka->outbuf, tmpEcdsa, pka->user);
		}
		psFree(tmpEcdsa, ssl->hsPool);

#ifdef USE_DTLS
		if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 0)) {
			/* ECC signatures have random bytes so need to save aside for
				retransmit cases. Using existing ckeMsg and ckeSize that
				clients are using but this should be totally fine on the
				server side because it is freed at FINISHED parse */
			ssl->ckeSize = len;
			if ((ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize)) == NULL) {
				psTraceInfo("Memory allocation error ckeMsg\n");
				return PS_MEM_FAIL;
			}
			memcpy(ssl->ckeMsg, pka->outbuf, ssl->ckeSize);
		}
#endif /* USE_DTLS */

		clearPkaAfter(ssl);
	}
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
	return rc;
}
#endif /* USE_SERVER_SIDE_SSL */


#ifdef USE_CLIENT_SIDE_SSL

/*********/
/* A test feature to allow clients to reuse the CKE RSA encryption output
	for each connection to remove the CPU overhead of pubkey operation when
	testing against high performance servers. The same premaster must be
	used each time as well though. */
//#define REUSE_CKE 
#ifdef REUSE_CKE
#pragma message("!! DO NOT USE REUSE_CKE IN PRODUCTION !!")
static char	g_reusePremaster[SSL_HS_RSA_PREMASTER_SIZE] = { 0 };
static int16  g_reusePreLen = 0;
static char g_reuseRSAEncrypt[512] = { 0 };	/* Encrypted pre-master */
static int16  g_reuseRSALen = 0;
static psRsaKey_t g_reuseRSAKey;
#endif
/*********/

/* The ClientKeyExchange delayed PKA ops */
static int32 nowDoCkePka(ssl_t *ssl)
{
	int32		rc = PS_FAIL;
	pkaAfter_t	*pka;
#ifdef REQUIRE_DH_PARAMS
	uint8_t		cleared = 0;
#endif

#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		if (ssl->retransmit) {
			/* Was already copied out in writeClientKeyExchange */
			/* In fact, would not expect to hit this because pkaAfter.type
				should never be set to re-enter this routine */
			psAssert(0);
			return PS_SUCCESS;
		}
	}
#endif /* USE_DTLS */

	/* Always the first one.  clearPkaAfter will move 1 to 0 if needed */
	pka = &ssl->pkaAfter[0];

	/* The flags logic is used for the cipher type and then the pkaAfter.type
		value is validated */
#ifdef USE_DHE_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {

	#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			/* ECDHE suite */
			psAssert(pka->outbuf == ssl->sec.premaster);
			if (pka->type == PKA_AFTER_ECDH_SECRET_GEN) {
				if ((rc = psEccGenSharedSecret(ssl->sec.eccDhKeyPool,
						ssl->sec.eccKeyPriv, ssl->sec.eccKeyPub,
						ssl->sec.premaster, &ssl->sec.premasterSize,
						pka->data)) < 0) {
					if (rc != PS_PENDING) {
						psFree(ssl->sec.premaster, ssl->hsPool);
						ssl->sec.premaster = NULL;
						return MATRIXSSL_ERROR;
					}
					pka->type = PKA_AFTER_ECDH_SECRET_GEN_DONE; /* Bypass next*/
					return rc;
				}
			}
			clearPkaAfter(ssl);
			psEccDeleteKey(&ssl->sec.eccKeyPub);
			psEccDeleteKey(&ssl->sec.eccKeyPriv);
		} else {
	#endif /* USE_ECC_CIPHER_SUITE */
	
		#ifdef REQUIRE_DH_PARAMS
		
			psAssert(pka->outbuf == ssl->sec.premaster);
			psAssert(pka->type == PKA_AFTER_DH_KEY_GEN);

			if ((rc = psDhGenSharedSecret(ssl->sec.dhKeyPool,
					ssl->sec.dhKeyPriv,	ssl->sec.dhKeyPub,	ssl->sec.dhP,
					ssl->sec.dhPLen, ssl->sec.premaster,
					&ssl->sec.premasterSize, pka->data)) < 0) {

				if (rc != PS_PENDING) {
					return MATRIXSSL_ERROR;
				}
				return rc;
			}

		#ifdef USE_PSK_CIPHER_SUITE
			/* DHE PSK ciphers make dual use of the pkaAfter storage */
			if (!(ssl->flags & SSL_FLAGS_PSK_CIPHER)) {
				if (cleared == 0) {
					clearPkaAfter(ssl); cleared = 1;
				}
			}
		#else
			if (cleared == 0) {
				clearPkaAfter(ssl); cleared = 1;
			}
		#endif

			psFree(ssl->sec.dhP, ssl->hsPool);
			ssl->sec.dhP = NULL; ssl->sec.dhPLen = 0;
			psDhClearKey(ssl->sec.dhKeyPub);
			psFree(ssl->sec.dhKeyPub, ssl->hsPool);
			ssl->sec.dhKeyPub = NULL;
			psDhClearKey(ssl->sec.dhKeyPriv);
			psFree(ssl->sec.dhKeyPriv, ssl->sec.dhKeyPool);
			ssl->sec.dhKeyPriv = NULL;

		#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {

				unsigned char	*pskKey;
				uint8_t			pskIdLen;

			/* RFC4279: The premaster secret is formed as follows.
			First, perform the Diffie-Hellman computation in the same way
			as for other Diffie-Hellman-based ciphersuites.  Let Z be the
			value produced by this computation.  Concatenate a uint16
			containing the length of Z (in octets), Z itself, a uint16
			containing the length of the PSK (in octets), and the PSK itself.

				The pskId is held in the pkaAfter inbuf */
				matrixSslPskGetKey(ssl, pka->inbuf, pka->inlen, &pskKey,
					&pskIdLen);
				if (pskKey == NULL) {
					psFree(ssl->sec.premaster, ssl->hsPool);
					ssl->sec.premaster = NULL;
					return MATRIXSSL_ERROR;
				}
				/* Need to prepend a uint16 length to the premaster key. */
				memmove(&ssl->sec.premaster[2], ssl->sec.premaster,
					ssl->sec.premasterSize);
				ssl->sec.premaster[0] = (ssl->sec.premasterSize & 0xFF00) >> 8;
				ssl->sec.premaster[1] = (ssl->sec.premasterSize & 0xFF);
				/*	Next, uint16 length of PSK and key itself */
				ssl->sec.premaster[ssl->sec.premasterSize + 2] =
					(pskIdLen & 0xFF00) >> 8;
				ssl->sec.premaster[ssl->sec.premasterSize + 3] =
					(pskIdLen & 0xFF);
				memcpy(&ssl->sec.premaster[ssl->sec.premasterSize + 4], pskKey,
					pskIdLen);
				/*	Lastly, adjust the premasterSize */
				ssl->sec.premasterSize += pskIdLen + 4;
			}
			if (cleared == 0) {
				clearPkaAfter(ssl); cleared = 1; /* Standard and PSK DHE */
			}
		#else
			if (cleared == 0) {
				clearPkaAfter(ssl); cleared = 1; /* Standard DHE, PSK disabled*/
			}
		#endif /* PSK */

		#endif /* REQUIRE_DH_PARAMS	*/

	#ifdef USE_ECC_CIPHER_SUITE
		}
	#endif /* USE_ECC_CIPHER_SUITE */

	} else {
#endif /* USE_DHE_CIPHER_SUITE */

		/* Else case for non-DHE, which still could mean ECDH static or
			standard RSA */
	#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->cipher->type == CS_ECDH_ECDSA ||
				ssl->cipher->type == CS_ECDH_RSA) {

			/* This case is unique becuase it has two PKA ops for a single CKE
				message.  The key generation is done and then secret is
				generated.  The 'type' will change after the first one */
			
			if (pka->type == PKA_AFTER_ECDH_KEY_GEN) {
				if (psEccNewKey(pka->pool, &ssl->sec.eccKeyPriv, 
						ssl->sec.cert->publicKey.key.ecc.curve) < 0) {
					return PS_MEM_FAIL;
				}
				if ((rc = matrixSslGenEphemeralEcKey(ssl->keys,
						ssl->sec.eccKeyPriv,
						ssl->sec.cert->publicKey.key.ecc.curve,
						pka->data)) < 0) {

					if (rc == PS_PENDING) {
						return rc;
					}
					psEccDeleteKey(&ssl->sec.eccKeyPriv);
					psTraceInfo("GenEphemeralEcc failed\n");
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					return MATRIXSSL_ERROR;
				}

				/* key len must be valid */
				if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv,
						pka->outbuf, &pka->user) < 0) {
					psTraceInfo("psEccX963ExportKey in CKE failed\n");
					return MATRIXSSL_ERROR;
				}
				/* Does written len equal stated len? */
				psAssert(pka->user == (int32)*(pka->outbuf - 1));

			#ifdef USE_DTLS
				/* Save aside for retransmits */
				if (ssl->flags & SSL_FLAGS_DTLS) {
					ssl->ckeSize = pka->user + 1; /* The size is wrote first */
					ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize);
					if (ssl->ckeMsg == NULL) {
						return SSL_MEM_ERROR;
					}
					ssl->ckeMsg[0] = pka->user & 0xFF;
					memcpy(ssl->ckeMsg + 1, pka->outbuf, ssl->ckeSize - 1);
				}
			#endif /* USE_DTLS */

				/* NOTE: Do not clearPkaAfter.  We will just use the current
					context since there is no special state data required
					for this next EccGenSharedSecret call.  We don't clear
					because the certificateVerify info might be	sitting in the
					second pkaAfter slot */
				/* Set for the next operation now using same pkaAfter slot */
				pka->type = PKA_AFTER_ECDH_SECRET_GEN;
			}

			/* Second PKA operation */
			if (pka->type == PKA_AFTER_ECDH_SECRET_GEN) {

				if ((rc = psEccGenSharedSecret(pka->pool,
						ssl->sec.eccKeyPriv, &ssl->sec.cert->publicKey.key.ecc,
						ssl->sec.premaster,	&ssl->sec.premasterSize,
						pka->data)) < 0) {
					if (rc == PS_PENDING) {
						pka->type = PKA_AFTER_ECDH_SECRET_GEN_DONE; /* Bypass */
						return rc;
					}
					psFree(ssl->sec.premaster, ssl->hsPool);
					ssl->sec.premaster = NULL;
					return MATRIXSSL_ERROR;
				}
			}
			/* Successfully completed both PKA operations and key write */
			psEccDeleteKey(&ssl->sec.eccKeyPriv);
			clearPkaAfter(ssl);

		} else {
	#endif /* USE_ECC_CIPHER_SUITE */

	#ifdef USE_RSA_CIPHER_SUITE
			/* Standard RSA suite entry point */
			psAssert(pka->type == PKA_AFTER_RSA_ENCRYPT);

		#ifdef REUSE_CKE
			if (g_reusePreLen) {
				if (psRsaCmpPubKey(&g_reuseRSAKey, &ssl->sec.cert->publicKey.key.rsa) == 0) {
					memcpy(ssl->sec.premaster, g_reusePremaster, g_reusePreLen);
					memcpy(pka->outbuf, g_reuseRSAEncrypt, g_reuseRSALen);
				} else {
					memzero_s(g_reusePremaster, g_reusePreLen);
					g_reusePreLen = 0;
					memzero_s(g_reuseRSAEncrypt, g_reuseRSALen);
					g_reuseRSALen = 0;
					psRsaClearKey(&g_reuseRSAKey);
				}
			} else {
		#endif
			/* pkaAfter.user is buffer len */
			if ((rc = psRsaEncryptPub(pka->pool,
					&ssl->sec.cert->publicKey.key.rsa,
					ssl->sec.premaster,	ssl->sec.premasterSize, pka->outbuf,
					pka->user, pka->data)) < 0) {
				if (rc == PS_PENDING) {
					/* For these ClientKeyExchange paths, we do want to come
						back through nowDoCkePka for a double pass so each
						case can manage its own pkaAfter and to make sure
						psX509FreeCert and sslCreateKeys() are hit below. */
					return rc;
				}
				psTraceIntInfo("psRsaEncryptPub in CKE failed %d\n", rc);
				return MATRIXSSL_ERROR;
			}
		#ifdef REUSE_CKE
			}
			if (g_reusePreLen == 0) {
				printf("REUSE_CKE ENABLED!! NOT FOR PRODUCTION USE\n");
				g_reusePreLen = ssl->sec.premasterSize; 
				g_reuseRSALen = psRsaSize(&ssl->sec.cert->publicKey.key.rsa);
				memcpy(g_reusePremaster, ssl->sec.premaster,  g_reusePreLen);
				memcpy(g_reuseRSAEncrypt, pka->outbuf, g_reuseRSALen);	
				/* TODO this key is allocated once and leaked */
				if (psRsaCopyKey(&g_reuseRSAKey, &ssl->sec.cert->publicKey.key.rsa) < 0) {
					return MATRIXSSL_ERROR;
				}
			}
		#endif
			/* RSA closed the pool on second pass */
			/* CHANGE NOTE: This comment looks specific to async and this
				pool is not being closed in clearPkaAfter if set to NULL here
				on the normal case.  So commenting this line out for now */
			//pka->pool = NULL;
		#ifdef USE_DTLS
			/* This was first pass for DH ckex so set it aside */

			if (ssl->flags & SSL_FLAGS_DTLS) {

				ssl->ckeMsg = psMalloc(ssl->hsPool, pka->user);
				if (ssl->ckeMsg == NULL) {
					return SSL_MEM_ERROR;
				}
				ssl->ckeSize = pka->user;
				memcpy(ssl->ckeMsg, pka->outbuf, pka->user);
			}
		#endif /* USE_DTLS */
			clearPkaAfter(ssl);
#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for writeClientKeyExchange.  ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA_CIPHER_SUITE */


	#ifdef USE_ECC_CIPHER_SUITE
		}
	#endif /* USE_ECC_CIPHER_SUITE */
	
#ifdef USE_DHE_CIPHER_SUITE
	}
#endif /* USE_DHE_CIPHER_SUITE */

/*
	Now that we've got the premaster secret, derive the various symmetric
	keys using it and the client and server random values.
	
	However, if extended_master_secret is being used we must delay the
	master secret creation until the CKE handshake message has been added
	to the rolling handshake hash.  Key generation will be done in encryptRecord
*/
	if (ssl->extFlags.extended_master_secret == 0) {
		if ((rc = sslCreateKeys(ssl)) < 0) {
			return rc;
		}
	}

#ifdef USE_DTLS
	/* Can't free cert in DTLS in case of retransmit */
	if (ssl->flags & SSL_FLAGS_DTLS) {
		return rc;
	}
#endif

#ifndef USE_ONLY_PSK_CIPHER_SUITE
	/* This used to be freed in writeFinished but had to stay around longer
		for key material in PKA after ops */
	if (ssl->sec.cert) {
		psX509FreeCert(ssl->sec.cert);
		ssl->sec.cert = NULL;
	}
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

	return rc;
}
#endif /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/
/*
	We indicate to the caller through return codes in sslDecode when we need
	to write internal data to the remote host.  The caller will call this
	function to generate a message appropriate to our state.
*/
int32 sslEncodeResponse(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen)
{
	int32			messageSize = 0;
	int32			rc = MATRIXSSL_ERROR;
	uint32			alertReqLen;
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	int32			i;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	psX509Cert_t	*cert;
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_SERVER_SIDE_SSL */

#if defined(USE_SERVER_SIDE_SSL)
	int32			extSize;
	int32			stotalCertLen;
#endif

#ifdef USE_CLIENT_SIDE_SSL
	int32			ckeSize;
#ifdef USE_CLIENT_AUTH
	int32			ctotalCertLen;
#endif
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
	psX509Cert_t	*CAcert;
	int32			certCount = 0, certReqLen = 0, CAcertLen = 0;
#endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_DHE_CIPHER_SUITE)
	int32			srvKeyExLen;
#endif /* USE_SERVER_SIDE_SSL && USE_DHE_CIPHER_SUITE */

#ifdef USE_DTLS
	sslSessOpts_t	options;
	memset(&options, 0x0, sizeof(sslSessOpts_t));
#endif

/*
	We may be trying to encode an alert response if there is an error marked
	on the connection.
*/
	if (ssl->err != SSL_ALERT_NONE) {
		rc = writeAlert(ssl, SSL_ALERT_LEVEL_FATAL, (unsigned char)ssl->err,
			out, requiredLen);
		if (rc == MATRIXSSL_ERROR) {
			/* We'll be returning an error code from this call so the typical
				alert SEND_RESPONSE handler will not be hit to set this error
				flag for us.  We do it ourself to prevent further session use
				and the result of this error will be that the connection is
				silently closed rather than this alert making it out */
			ssl->flags |= SSL_FLAGS_ERROR;
		}
#ifdef USE_SERVER_SIDE_SSL
/*
		Writing a fatal alert on this session.  Let's remove this client from
		the session table as a precaution.  Additionally, if this alert is
		happening mid-handshake the master secret might not even be valid
*/
		if (ssl->flags & SSL_FLAGS_SERVER) {
			matrixClearSession(ssl, 1);
		}
#endif /* USE_SERVER_SIDE_SSL */
		return rc;
	}

#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		/*	This function takes care of writing out entire flights so we know
			to capture the current MSN and Epoch as the resends so that a
			resend of this flight will contain the identical MSN and Epoch
			for each resent message. */
		ssl->resendMsn = ssl->msn;
		ssl->resendEpoch[0] = ssl->epoch[0];
		ssl->resendEpoch[1] = ssl->epoch[1];
	}
#endif /* USE_DTLS */

/*
	We encode a set of response messages based on our current state
	We have to pre-verify the size of the outgoing buffer against
	all the messages to make the routine transactional.  If the first
	write succeeds and the second fails because of size, we cannot
	rollback the state of the cipher and MAC.
*/
	switch (ssl->hsState) {
/*
	If we're waiting for the ClientKeyExchange message, then we need to
	send the messages that would prompt that result on the client
*/
#ifdef USE_SERVER_SIDE_SSL
	case SSL_HS_CLIENT_KEY_EXCHANGE:
#ifdef USE_CLIENT_AUTH
/*
		This message is also suitable for the client authentication case
		where the server is in the CERTIFICATE state.
*/
	case SSL_HS_CERTIFICATE:
/*
		Account for the certificateRequest message if client auth is on.
		First two bytes are the certificate_types member (rsa_sign (1) and
		ecdsa_sign (64) are supported).  Remainder of length is the
		list of BER encoded distinguished names this server is
		willing to accept children certificates of.  If there
		are no valid CAs to work with, client auth can't be done.
*/
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
			CAcert = ssl->keys->CAcerts;
			certCount = certReqLen = CAcertLen = 0;
#ifdef USE_TLS_1_2
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				/* TLS 1.2 has a SigAndHashAlgorithm member in certRequest */
				certReqLen += 2;
#ifdef USE_ECC
#ifdef USE_SHA384
				certReqLen += 6;
#else
				certReqLen += 4;
#endif	/* USE_SHA */
#endif /* USE_ECC */
#ifdef USE_RSA
#ifdef USE_SHA384
				certReqLen += 6;
#else
				certReqLen += 4;
#endif	/* USE_SHA */
#endif /* USE_RSA */
			}
#endif /* USE_TLS_1_2 */

			if (CAcert) {
				certReqLen += 4 + ssl->recordHeadLen + ssl->hshakeHeadLen;
#ifdef USE_ECC
				certReqLen += 1; /* Add on ECDSA_SIGN support */
#endif /* USE_ECC */
				while (CAcert) {
					certReqLen += 2; /* 2 bytes for specifying each cert len */
					CAcertLen += CAcert->subject.dnencLen;
					CAcert = CAcert->next;
					certCount++;
				}
#ifdef USE_DTLS
				//if (ssl->flags & SSL_FLAGS_DTLS) {
				//	if (certReqLen + CAcertLen > ssl->pmtu) {
				//		/* Decrease the CA count or contact support if a
				//			needed requirement */
				//		psTraceDtls("ERROR: No fragmentation support for ");
				//		psTraceDtls("CERTIFICATE_REQUEST message/n");
				//		return MATRIXSSL_ERROR;
				//	}
				//}
#endif
			} else {
#ifdef SERVER_CAN_SEND_EMPTY_CERT_REQUEST
				certReqLen += 4 + ssl->recordHeadLen + ssl->hshakeHeadLen;
#ifdef USE_ECC
				certReqLen += 1; /* Add on ECDSA_SIGN support */
#endif /* USE_ECC */
#else
				psTraceInfo("No server CAs loaded for client authentication\n");
				return MATRIXSSL_ERROR;
#endif
			}
		}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_CLIENT_AUTH */

#ifdef USE_DHE_CIPHER_SUITE
		srvKeyExLen = 0;
		if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifdef USE_ECC_CIPHER_SUITE
			if (!(ssl->flags & SSL_FLAGS_ECC_CIPHER)) {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
/*
			Extract p and g parameters from key to session context.  Going
			to send these in the SERVER_KEY_EXCHANGE message.  This is
			wrapped in a test of whether or not the values have already
			been extracted because an SSL_FULL scenario below will cause
			this code to be executed again with a larger buffer.
*/
			if (ssl->sec.dhPLen == 0 && ssl->sec.dhP == NULL) {
				if (psDhExportParameters(ssl->hsPool, &ssl->keys->dhParams,
						&ssl->sec.dhP, &ssl->sec.dhPLen,
						&ssl->sec.dhG, &ssl->sec.dhGLen) < 0) {
					return MATRIXSSL_ERROR;
				}
			}
#endif
#ifdef USE_ECC_CIPHER_SUITE
			}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_ANON_DH_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
/*
				If we are an anonymous cipher, we don't send the certificate.
				The messages are simply SERVER_HELLO, SERVER_KEY_EXCHANGE,
				and SERVER_HELLO_DONE
*/
				stotalCertLen = 0;

				srvKeyExLen = ssl->sec.dhPLen + 2 + ssl->sec.dhGLen + 2 +
					ssl->sec.dhKeyPriv->size + 2;

#ifdef USE_PSK_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
 *					struct {
 *						select (KeyExchangeAlgorithm) {
 *							case diffie_hellman_psk:  * NEW *
 *							opaque psk_identity_hint<0..2^16-1>;
 *							ServerDHParams params;
 *						};
 *					} ServerKeyExchange;
 */
 					if (SSL_PSK_MAX_HINT_SIZE > 0) {
						srvKeyExLen += SSL_PSK_MAX_HINT_SIZE + 2;
 					}
				}
#endif /* USE_PSK_CIPHER_SUITE */

				messageSize =
					3 * ssl->recordHeadLen +
					3 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE +  /* server hello */
					srvKeyExLen; /* server key exchange */

				messageSize += secureWriteAdditions(ssl, 3);
			} else {
#endif /* USE_ANON_DH_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
					if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA) {
/*
						 Magic 7: 1byte ECCurveType named, 2bytes NamedCurve id
						 1 byte pub key len, 2 byte privkeysize len,
						 1 byte 0x04 inside the eccKey itself
*/
						srvKeyExLen = (ssl->sec.eccKeyPriv->curve->size * 2) + 7 +
							ssl->keys->privKey.keysize;
					} else if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
						/* ExportKey plus signature */
						srvKeyExLen = (ssl->sec.eccKeyPriv->curve->size * 2) + 7 +
							6 + /* 6 = 2 ASN_SEQ, 4 ASN_BIG */
							ssl->keys->privKey.keysize;
						if (ssl->keys->privKey.keysize >= 128) {
							srvKeyExLen += 1; /* Extra len byte in ASN.1 sig */
						}
						/* NEGATIVE ECDSA - For purposes of SSL_FULL we
							add 2 extra bytes to account for the two possible
							0x0	bytes in signature */
						srvKeyExLen += 2;
					}
#ifdef USE_TLS_1_2
					if (ssl->flags & SSL_FLAGS_TLS_1_2) {
						srvKeyExLen += 2; /* hashSigAlg */
					}
#endif /* USE_TLS_1_2 */
				} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
/*
				The AUTH versions of the DHE cipher suites include a
				signature value in the SERVER_KEY_EXCHANGE message.
				Account for that length here.  Also, the CERTIFICATE
				message is sent in this flight as well for normal
				authentication.
*/
				srvKeyExLen = ssl->sec.dhPLen + 2 + ssl->sec.dhGLen + 2 +
					ssl->sec.dhKeyPriv->size + 2 +
					ssl->keys->privKey.keysize + 2;
#ifdef USE_TLS_1_2
				if (ssl->flags & SSL_FLAGS_TLS_1_2) {
					srvKeyExLen += 2; /* hashSigAlg */
				}
#endif /* USE_TLS_1_2 */

#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */
				stotalCertLen = i = 0;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
				cert = ssl->keys->cert;
				for (i = 0; cert != NULL; i++) {
					stotalCertLen += cert->binLen;
					cert = cert->next;
				}
				/* Are we going to have to fragment the CERTIFICATE message? */
				if ((stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen) >
						ssl->maxPtFrag) {
					stotalCertLen += addCertFragOverhead(ssl,
						stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen);
				}
#endif /* USE_ONLY_PSK_CIPHER_SUITE  */
				messageSize =
					4 * ssl->recordHeadLen +
					4 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE +  /* server hello */
					srvKeyExLen + /* server key exchange */
					3 + (i * 3) + stotalCertLen; /* certificate */
#ifdef USE_CLIENT_AUTH
#ifndef USE_ONLY_PSK_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
					/* Are we going to have to fragment the
						CERTIFICATE_REQUEST message? */
					if (certReqLen + CAcertLen > ssl->maxPtFrag) {
						certReqLen += addCertFragOverhead(ssl,
							certReqLen + CAcertLen);
					}
					/* Account for the CertificateRequest message */
					messageSize += certReqLen + CAcertLen;
					messageSize += secureWriteAdditions(ssl, 1);
				}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_CLIENT_AUTH */
				messageSize += secureWriteAdditions(ssl, 4);
#ifdef USE_ANON_DH_CIPHER_SUITE
			}
#endif /* USE_ANON_DH_CIPHER_SUITE */
		} else {
#endif /* USE_DHE_CIPHER_SUITE */
/*
			This is the entry point for a server encoding the first flight
			of a non-DH, non-client-auth handshake.
*/
			stotalCertLen = 0;
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
				Omit the CERTIFICATE message but (possibly) including the
				SERVER_KEY_EXCHANGE.
*/
				messageSize =
					2 * ssl->recordHeadLen +
					2 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE;  /* server hello */
				if (SSL_PSK_MAX_HINT_SIZE > 0) {
					messageSize += 2 + SSL_PSK_MAX_HINT_SIZE +  /* SKE */
						ssl->recordHeadLen + ssl->hshakeHeadLen;
				} else {
/*
					Assuming 3 messages below when only two are going to exist
*/
					messageSize -= secureWriteAdditions(ssl, 1);
				}
			} else {
#endif
#ifndef USE_ONLY_PSK_CIPHER_SUITE
				cert = ssl->keys->cert;
				for (i = 0; cert != NULL; i++) {
					psAssert(cert->unparsedBin != NULL);
					stotalCertLen += cert->binLen;
					cert = cert->next;
				}
				/* Are we going to have to fragment the CERTIFICATE message? */
				if ((stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen) >
						ssl->maxPtFrag) {
					stotalCertLen += addCertFragOverhead(ssl,
						stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen);
				}
				messageSize =
					3 * ssl->recordHeadLen +
					3 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE +  /* server hello */
					3 + (i * 3) + stotalCertLen; /* certificate */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
			}
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_CLIENT_AUTH
#ifndef USE_ONLY_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				/* Are we going to have to fragment the	CERTIFICATE_REQUEST
					message? This is the SSL fragment level */
				if (certReqLen + CAcertLen > ssl->maxPtFrag) {
					certReqLen += addCertFragOverhead(ssl,
						certReqLen + CAcertLen);
				}
				messageSize += certReqLen + CAcertLen; /* certificate request */
				messageSize += secureWriteAdditions(ssl, 1);
#ifdef USE_DTLS
				if (ssl->flags & SSL_FLAGS_DTLS) {
					/*	DTLS pmtu CERTIFICATE_REQUEST */
					messageSize += (MAX_FRAGMENTS - 1) *
						(ssl->recordHeadLen + ssl->hshakeHeadLen);
					if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
						messageSize += secureWriteAdditions(ssl,
						MAX_FRAGMENTS - 1);
					}
				}
#endif /* USE_DTLS */
			}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_CLIENT_AUTH */

			messageSize += secureWriteAdditions(ssl, 3);

#ifdef USE_DHE_CIPHER_SUITE
		}
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
/*
			If DTLS, make sure the max fragment overhead is accounted for
			on any flight containing the CERTIFICATE message.  If
			SSL_FULL is hit mid-flight creation, the updates that happen
			on the handshake hash on that first pass will really mess us up
*/
			messageSize += (MAX_FRAGMENTS - 1) *
				(ssl->recordHeadLen + ssl->hshakeHeadLen);
			if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
				messageSize += secureWriteAdditions(ssl, MAX_FRAGMENTS - 1);
			}
		}
#endif /* USE_DTLS */

/*
		Add extensions
*/
		extSize = 0; /* Two byte total length for all extensions */
		if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN) {
			extSize = 2;
			messageSize += 5; /* 2 type, 2 length, 1 value */
		}

		if (ssl->extFlags.truncated_hmac) {
			extSize = 2;
			messageSize += 4; /* 2 type, 2 length, 0 value */
		}

		if (ssl->extFlags.extended_master_secret) {
			extSize = 2;
			messageSize += 4; /* 2 type, 2 length, 0 value */
		}
		
#ifdef USE_OCSP
		/* If we are sending the OCSP status_request extension, we are also
			sending the CERTIFICATE_STATUS handshake message */
		if (ssl->extFlags.status_request) {
			extSize = 2;
			messageSize += 4; /* 2 type, 2 length, 0 value */
			
			/* And the handshake message oh.  1 type, 3 len, x OCSPResponse 
				The status_request flag will only have been set if a 
				ssl->keys->OCSPResponseBuf was present during extension parse */
			messageSize += ssl->hshakeHeadLen + ssl->recordHeadLen + 4 +
				ssl->keys->OCSPResponseBufLen;
			messageSize += secureWriteAdditions(ssl, 1);
		}
#endif

#ifdef USE_SCT
		if (ssl->extFlags.signed_certificate_timestamp) {
			extSize = 2;
			messageSize += 2 + 2 + 2 + ssl->keys->SCTResponseBufLen; /* 2 type, 2 length, data */
		}
#endif
		
#ifdef USE_STATELESS_SESSION_TICKETS
		if (ssl->sid &&
				ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT) {
			extSize = 2;
			messageSize += 4; /* 2 type, 2 length, 0 value */
		}
#endif
		if (ssl->extFlags.sni) {
			extSize = 2;
			messageSize += 4;
		}

#ifdef USE_ALPN
		if (ssl->alpnLen) {
			extSize = 2;
			messageSize += 6 + 1 + ssl->alpnLen; /* 6 type/len + 1 len + data */
		}
#endif

#ifdef ENABLE_SECURE_REHANDSHAKES
/*
		The RenegotiationInfo extension lengths are well known
*/
		if (ssl->secureRenegotiationFlag == PS_TRUE &&
				ssl->myVerifyDataLen == 0) {
			extSize = 2;
			messageSize += 5; /* ff 01 00 01 00 */
		} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
				ssl->myVerifyDataLen > 0) {
			extSize = 2;
			messageSize += 5 + ssl->myVerifyDataLen +
				ssl->peerVerifyDataLen; /* 2 for total len, 5 for type+len */
		}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
/*
	Server Hello ECC extension
*/
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			extSize = 2;
			/* EXT_ELLIPTIC_POINTS - hardcoded to 'uncompressed' support */
			messageSize += 6; /* 00 0B 00 02 01 00 */
		}
#endif /* USE_ECC_CIPHER_SUITE */
/*
		Done with extensions.  If had some, add the two byte total length
*/
		messageSize += extSize;

		if ((out->buf + out->size) - out->end < messageSize) {
			*requiredLen = messageSize;
			return SSL_FULL;
		}
/*
		Message size complete.  Begin the flight write
*/
		rc = writeServerHello(ssl, out);

#ifdef USE_DHE_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA ||
					ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
				if (rc == MATRIXSSL_SUCCESS) {
					rc = writeCertificate(ssl, out, 1);
				}
#ifdef USE_OCSP
				if (rc == MATRIXSSL_SUCCESS) {
					rc = writeCertificateStatus(ssl, out);
				}
#endif
			}
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
			if (rc == MATRIXSSL_SUCCESS) {
#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
					rc = writeServerKeyExchange(ssl, out, 0, NULL, 0, NULL);
				} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
				rc = writeServerKeyExchange(ssl, out, ssl->sec.dhPLen,
					ssl->sec.dhP, ssl->sec.dhGLen, ssl->sec.dhG);
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */
			}
		} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
				if (rc == MATRIXSSL_SUCCESS) {
					rc = writePskServerKeyExchange(ssl, out);
				}
			} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
				if (rc == MATRIXSSL_SUCCESS) {
					rc = writeCertificate(ssl, out, 1);
				}
#ifdef USE_OCSP
				if (rc == MATRIXSSL_SUCCESS) {
					rc = writeCertificateStatus(ssl, out);
				}
#endif
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
			}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
		}
#endif /* USE_DHE_CIPHER_SUITE */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_CLIENT_AUTH
		if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeCertificateRequest(ssl, out, CAcertLen, certCount);
			}
		}
#endif /* USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

		if (rc == MATRIXSSL_SUCCESS) {
			rc = writeServerHelloDone(ssl, out);
		}
		if (rc == SSL_FULL) {
			psTraceInfo("Bad flight messageSize calculation");
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			out->end = out->start;
			alertReqLen = out->size;
			/* Going recursive */
			return sslEncodeResponse(ssl, out, &alertReqLen);
		}
		break;

#ifdef USE_DTLS
/*
	Got a cookie-less CLIENT_HELLO, need a HELLO_VERIFY_REQUEST message
*/
	case SSL_HS_CLIENT_HELLO:
		messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
			DTLS_COOKIE_SIZE + 3;
		messageSize += secureWriteAdditions(ssl, 1);

		if ((out->buf + out->size) - out->end < messageSize) {
			*requiredLen = messageSize;
			return SSL_FULL;
		}
		rc = writeHelloVerifyRequest(ssl, out);
		break;
#endif /* USE_DTLS */
#endif /* USE_SERVER_SIDE_SSL */

/*
	If we're not waiting for any message from client, then we need to
	send our finished message
*/
	case SSL_HS_DONE:
		messageSize = 2 * ssl->recordHeadLen +
			ssl->hshakeHeadLen +
			1 + /* change cipher spec */
			MD5_HASH_SIZE + SHA1_HASH_SIZE; /* finished */
/*
		Account for possible overhead in CCS message with secureWriteAdditions
		then always account for the encryption overhead on FINISHED message.
		Correct to use ssl->cipher values for mac and block since those will
		be the ones used when encrypting FINISHED
*/
		messageSize += secureWriteAdditions(ssl, 1);
		messageSize += ssl->cipher->macSize + ssl->cipher->blockSize;

#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->sid &&
				  (ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT)) {
				messageSize += ssl->recordHeadLen +
					ssl->hshakeHeadLen + matrixSessionTicketLen() + 6;
			}
		}
#endif

#ifdef USE_TLS
/*
		Account for the smaller finished message size for TLS.
*/
		if (ssl->flags & SSL_FLAGS_TLS) {
			messageSize += TLS_HS_FINISHED_SIZE -
				(MD5_HASH_SIZE + SHA1_HASH_SIZE);
		}
#endif /* USE_TLS */
#ifdef USE_TLS_1_1
/*
		Adds explict IV overhead to the FINISHED message
*/
		if (ssl->flags & SSL_FLAGS_TLS_1_1) {
			if (ssl->flags & SSL_FLAGS_AEAD_W) {
				/* The magic 1 back into messageSize is because the
					macSize + blockSize above ends up subtracting one on AEAD */
				messageSize += AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl) + 1;
			} else {
				messageSize += ssl->cipher->blockSize;
			}
		}
#endif /* USE_TLS_1_1 */

#ifdef USE_ZLIB_COMPRESSION
		/* Lastly, add the zlib overhead for the FINISHED message */
		if (ssl->compression) {
			messageSize += MAX_ZLIB_COMPRESSED_OH;
		}
#endif
		if ((out->buf + out->size) - out->end < messageSize) {
			*requiredLen = messageSize;
			return SSL_FULL;
		}
		rc = MATRIXSSL_SUCCESS;

#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->sid &&
				  (ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT)) {
				rc = writeNewSessionTicket(ssl, out);
			}
		}
#endif
		if (rc == MATRIXSSL_SUCCESS) {
			rc = writeChangeCipherSpec(ssl, out);
		}
		if (rc == MATRIXSSL_SUCCESS) {
			rc = writeFinished(ssl, out);
		}

		if (rc == SSL_FULL) {
			psTraceInfo("Bad flight messageSize calculation");
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			out->end = out->start;
			alertReqLen = out->size;
			/* Going recursive */
			return sslEncodeResponse(ssl, out, &alertReqLen);
		}
		break;
/*
	If we're expecting a Finished message, as a server we're doing
	session resumption.  As a client, we're completing a normal
	handshake
*/
	case SSL_HS_FINISHED:
#ifdef USE_SERVER_SIDE_SSL
		if (ssl->flags & SSL_FLAGS_SERVER) {
			messageSize =
				3 * ssl->recordHeadLen +
				2 * ssl->hshakeHeadLen +
				38 + SSL_MAX_SESSION_ID_SIZE + /* server hello */
				1 + /* change cipher spec */
				MD5_HASH_SIZE + SHA1_HASH_SIZE; /* finished */
/*
			Account for possible overhead with secureWriteAdditions
			then always account for the encrypted FINISHED message.  Correct
			to use the ssl->cipher values for mac and block since those will
			always be the values used to encrypt the FINISHED message
*/
			messageSize += secureWriteAdditions(ssl, 2);
			messageSize += ssl->cipher->macSize + ssl->cipher->blockSize;
#ifdef ENABLE_SECURE_REHANDSHAKES
/*
			The RenegotiationInfo extension lengths are well known
*/
			if (ssl->secureRenegotiationFlag == PS_TRUE &&
					ssl->myVerifyDataLen == 0) {
				messageSize += 7; /* 00 05 ff 01 00 01 00 */
			} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
					ssl->myVerifyDataLen > 0) {
				messageSize += 2 + 5 + ssl->myVerifyDataLen +
					ssl->peerVerifyDataLen; /* 2 for tot len, 5 for type+len */
			}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
#ifndef ENABLE_SECURE_REHANDSHAKES
				messageSize += 2; /* ext 2 byte len has not been included */
#endif /* ENABLE_SECURE_REHANDSHAKES */
				/* EXT_ELLIPTIC_POINTS - hardcoded to 'uncompressed' support */
				messageSize += 6; /* 00 0B 00 02 01 00 */
			}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_TLS
/*
			Account for the smaller finished message size for TLS.
			The MD5+SHA1 is SSLv3.  TLS is 12 bytes.
*/
			if (ssl->flags & SSL_FLAGS_TLS) {
				messageSize += TLS_HS_FINISHED_SIZE -
					(MD5_HASH_SIZE + SHA1_HASH_SIZE);
			}
#endif /* USE_TLS */
#ifdef USE_TLS_1_1
/*
			Adds explict IV overhead to the FINISHED message.  Always added
			because FINISHED is never accounted for in secureWriteAdditions
*/
			if (ssl->flags & SSL_FLAGS_TLS_1_1) {
				if (ssl->cipher->flags &
					(CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM)) {
					/* The magic 1 back into messageSize is because the
						blockSize -1 above ends up subtracting one on AEAD */
					messageSize += AEAD_TAG_LEN(ssl) + TLS_EXPLICIT_NONCE_LEN + 1;
				} else if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA) {
					messageSize += AEAD_TAG_LEN(ssl) + 1;
				} else {
					messageSize += ssl->cipher->blockSize; /* explicitIV */
				}
			}
#endif /* USE_TLS_1_1 */

#ifdef USE_ZLIB_COMPRESSION
			/* Lastly, add the zlib overhead for the FINISHED message */
			if (ssl->compression) {
				messageSize += MAX_ZLIB_COMPRESSED_OH;
			}
#endif
			if ((out->buf + out->size) - out->end < messageSize) {
				*requiredLen = messageSize;
				return SSL_FULL;
			}
			rc = writeServerHello(ssl, out);
			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeChangeCipherSpec(ssl, out);
			}
			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeFinished(ssl, out);
			}
		}
#endif /* USE_SERVER_SIDE_SSL */
#ifdef USE_CLIENT_SIDE_SSL
/*
		Encode entry point for client side final flight encodes.
		First task here is to find out size of ClientKeyExchange message
*/
		if (!(ssl->flags & SSL_FLAGS_SERVER)) {
			ckeSize = 0;
#ifdef USE_DHE_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifdef USE_DTLS
				if (ssl->flags & SSL_FLAGS_DTLS && ssl->retransmit == 1) {
					ckeSize = ssl->ckeSize; /* Keys have been freed */
				} else {
#endif /* USE_DTLS */
#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
					ckeSize = (ssl->sec.eccKeyPriv->curve->size * 2) + 2;
				} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
				ckeSize = ssl->sec.dhKeyPriv->size;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_DTLS
				}
#endif /* USE_DTLS */
#ifdef USE_PSK_CIPHER_SUITE
/*
				This is the DHE_PSK suite case.
				PSK suites add the key identity with uint16 size
*/
				if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
					ckeSize += SSL_PSK_MAX_ID_SIZE + 2;
				}
#endif /* USE_PSK_CIPHER_SUITE */
			} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
				This is the basic PSK case
				PSK suites add the key identity with uint16 size
*/
				if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
					ckeSize += SSL_PSK_MAX_ID_SIZE + 2;
				} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_ECC_CIPHER_SUITE
					if (ssl->cipher->type == CS_ECDH_ECDSA ||
							ssl->cipher->type == CS_ECDH_RSA) {
						ckeSize = (ssl->sec.cert->publicKey.key.ecc.curve->size
							* 2) + 2;
					} else {
#endif /* USE_ECC_CIPHER_SUITE */
/*
					Normal RSA auth cipher suite case
*/
					if (ssl->sec.cert == NULL) {
						ssl->flags |= SSL_FLAGS_ERROR;
						return MATRIXSSL_ERROR;
					}
					ckeSize = ssl->sec.cert->publicKey.keysize;

#ifdef USE_ECC_CIPHER_SUITE
					}
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
				}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
			}
#endif /* USE_DHE_CIPHER_SUITE */

			messageSize = 0;

			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
/*
			Client authentication requires the client to send a CERTIFICATE
			and CERTIFICATE_VERIFY message.  Account for the length.  It
			is possible the client didn't have a match for the requested cert.
			Send an empty certificate message in that case (or alert for SSLv3)
*/
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_CLIENT_AUTH
				if (ssl->sec.certMatch > 0) {
/*
					Account for the certificate and certificateVerify messages
*/
					cert = ssl->keys->cert;
					ctotalCertLen = 0;
					for (i = 0; cert != NULL; i++) {
						ctotalCertLen += cert->binLen;
						cert = cert->next;
					}
					/* Are we going to have to fragment the CERT message? */
					if ((ctotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen) >
							ssl->maxPtFrag) {
						ctotalCertLen += addCertFragOverhead(ssl,
							ctotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen);
					}
					messageSize += (2 * ssl->recordHeadLen) + 3 + (i * 3) +
						(2 * ssl->hshakeHeadLen) + ctotalCertLen +
						2 +	ssl->keys->privKey.keysize;

#ifdef USE_ECC
					/* Overhead ASN.1 in psEccSignHash */
					if (ssl->keys->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
						/* NEGATIVE ECDSA - For purposes of SSL_FULL we
							add 2 extra bytes to account for the two 0x0
							bytes in signature */
						messageSize += 6 + 2;
						if (ssl->keys->privKey.keysize >= 128) {
							messageSize += 1; /* Extra len byte in ASN.1 sig */
						}
					}
#endif /* USE_ECC */
				} else {
#endif /* USE_CLIENT_AUTH */
/*
					SSLv3 sends a no_certificate warning alert for no match
*/
					if (ssl->majVer == SSL3_MAJ_VER
							&& ssl->minVer == SSL3_MIN_VER) {
						messageSize += 2 + ssl->recordHeadLen;
					} else {
/*
						TLS just sends an empty certificate message
*/
						messageSize += 3 + ssl->recordHeadLen +
							ssl->hshakeHeadLen;
					}
#ifdef USE_CLIENT_AUTH
				}
#endif /* USE_CLIENT_AUTH */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
			}
/*
			Account for the header and message size for all records.  The
			finished message will always be encrypted, so account for one
			largest possible MAC size and block size.  The finished message is
			not accounted for in the writeSecureAddition calls below since it
			is accounted for here.
*/
			messageSize +=
				3 * ssl->recordHeadLen +
				2 * ssl->hshakeHeadLen + /* change cipher has no hsHead */
				ckeSize + /* client key exchange */
				1 + /* change cipher spec */
				MD5_HASH_SIZE + SHA1_HASH_SIZE + /* SSLv3 finished payload */
				ssl->cipher->macSize +
				ssl->cipher->blockSize; /* finished overhead */
#ifdef USE_TLS
/*
			Must add the 2 bytes key size length to the client key exchange
			message. Also, at this time we can account for the smaller finished
			message size for TLS.  The MD5+SHA1 is SSLv3.  TLS is 12 bytes.
*/
			if (ssl->flags & SSL_FLAGS_TLS) {
				messageSize += 2 - MD5_HASH_SIZE - SHA1_HASH_SIZE +
					TLS_HS_FINISHED_SIZE;
			}
#endif /* USE_TLS */
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
/*
				Secure write for ClientKeyExchange, ChangeCipherSpec,
				Certificate, and CertificateVerify.  Don't account for
				Certificate and/or CertificateVerify message if no auth cert.
				This will also cover the NO_CERTIFICATE alert sent in
				replacement of the NULL certificate message in SSLv3.
*/
				if (ssl->sec.certMatch > 0) {
#ifdef USE_TLS_1_2
					if (ssl->flags & SSL_FLAGS_TLS_1_2) {
						messageSize += 2; /* hashSigAlg in CertificateVerify */
					}
#endif
					messageSize += secureWriteAdditions(ssl, 4);
				} else {
					messageSize += secureWriteAdditions(ssl, 3);
				}
			} else {
				messageSize += secureWriteAdditions(ssl, 2);
			}

#ifdef USE_DTLS
			if (ssl->flags & SSL_FLAGS_DTLS) {
/*
				 If DTLS, make sure the max fragment overhead is accounted for
				 on any flight containing the CERTIFICATE message.  If
				 SSL_FULL is hit mid-flight creation, the updates that happen
				 on the handshake hash on that first pass will really mess us up
*/
				messageSize += (MAX_FRAGMENTS - 1) *
					(ssl->recordHeadLen + ssl->hshakeHeadLen);
				if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
					messageSize += secureWriteAdditions(ssl, MAX_FRAGMENTS - 1);
				}
			}
#endif /* USE_DTLS */
#ifdef USE_TLS_1_1
/*
			Adds explict IV overhead to the FINISHED message.  Always added
			because FINISHED is never accounted for in secureWriteAdditions
*/
			if (ssl->flags & SSL_FLAGS_TLS_1_1) {
				if (ssl->cipher->flags &
					(CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM)) {
					/* The magic 1 back into messageSize is because the
					 blockSize -1 above ends up subtracting one on AEAD */
					messageSize += AEAD_TAG_LEN(ssl) + TLS_EXPLICIT_NONCE_LEN + 1;
				} else if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA) {
					messageSize += AEAD_TAG_LEN(ssl) + 1;
				} else {
					messageSize += ssl->cipher->blockSize; /* explicitIV */
				}
			}
#endif /* USE_TLS_1_1 */
#ifdef USE_ZLIB_COMPRESSION
			/* Lastly, add the zlib overhead for the FINISHED message */
			if (ssl->compression) {
				messageSize += MAX_ZLIB_COMPRESSED_OH;
			}
#endif
/*
			The actual buffer size test to hold this flight
*/
			if ((out->buf + out->size) - out->end < messageSize) {
				*requiredLen = messageSize;
				return SSL_FULL;
			}
			rc = MATRIXSSL_SUCCESS;

#ifndef USE_ONLY_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
/*
				The TLS RFC is fairly clear that an empty certificate message
				be sent if there is no certificate match.  SSLv3 tends to lean
				toward a NO_CERTIFIATE warning alert message
*/
				if (ssl->sec.certMatch == 0 && ssl->majVer == SSL3_MAJ_VER
							&& ssl->minVer == SSL3_MIN_VER) {
					rc = writeAlert(ssl, SSL_ALERT_LEVEL_WARNING,
						SSL_ALERT_NO_CERTIFICATE, out, requiredLen);
				} else {
					rc = writeCertificate(ssl, out, ssl->sec.certMatch);
				}
			}
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeClientKeyExchange(ssl, out);
			}
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_CLIENT_AUTH
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				if (rc == MATRIXSSL_SUCCESS && ssl->sec.certMatch > 0) {
					rc = writeCertificateVerify(ssl, out);
				}
			}
#endif /* USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeChangeCipherSpec(ssl, out);
			}
			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeFinished(ssl, out);
			}
		}
#endif /* USE_CLIENT_SIDE_SSL */
		if (rc == SSL_FULL) {
			psTraceInfo("Bad flight messageSize calculation");
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			out->end = out->start;
			alertReqLen = out->size;
			/* Going recursive */
			return sslEncodeResponse(ssl, out, &alertReqLen);
		}
		break;
#ifdef USE_DTLS
/*
	If we a client being invoked from here in the HS_SERVER_HELLO state,
	we are being asked for a CLIENT_HELLO with a cookie.  It's already
	been parsed out of the server HELLO_VERIFY_REQUEST message, so
	we can simply call matrixSslEncodeClientHello again and essentially
	start over again.
*/
	case SSL_HS_SERVER_HELLO:
		rc = matrixSslEncodeClientHello(ssl, out, ssl->cipherSpec,
			ssl->cipherSpecLen,	requiredLen, NULL, &options);
		break;
#endif /* USE_DTLS */
	}

	if (rc < MATRIXSSL_SUCCESS && rc != SSL_FULL) {
	/* Indication one of the message creations failed and setting the flag to
		prevent other API calls from working.  We want to send a fatal
		internal error alert in this case.  Make sure to write to front of
		buffer since we	can't trust the data in there due to the creation
		failure. */
		psTraceIntInfo("ERROR: Handshake flight creation failed %d\n", rc);
		if (rc == PS_UNSUPPORTED_FAIL) {
			/* Single out this particular error as a handshake failure
				because there are combinations of cipher negotiations where
				we don't know until handshake creation that we can't support.
				For example, the server key material test will be bypassed
				if an SNI callback is registered.  We won't know until SKE
				creation that we can't support the requested cipher.  This is
				a user error so don't report an INTERNAL_ERROR */
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
		} else {
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
		}
		out->end = out->start;
		alertReqLen = out->size;
		/* Going recursive */
		return sslEncodeResponse(ssl, out, &alertReqLen);
	}

#ifdef USE_SERVER_SIDE_SSL
	/* Post-flight write PKA operation.  Support is for the signature
		generation during ServerKeyExchange write.  */
	if (ssl->flags & SSL_FLAGS_SERVER) {
		if (ssl->pkaAfter[0].type > 0) {
			if ((rc = nowDoSkePka(ssl, out)) < 0) {
				return rc;
			}
		}
	}
#endif

#ifdef USE_CLIENT_SIDE_SSL
	/* Post-flight write PKA operation.  Support is for the operations during
		ClientKeyExchange write.  */
	if (!(ssl->flags & SSL_FLAGS_SERVER)) {
		if (ssl->pkaAfter[0].type > 0) {
			if ((rc = nowDoCkePka(ssl)) < 0) {
				return rc;
			}
		}
	}
#endif

	/* Encrypt Flight */
	if (ssl->flightEncode) {
		if ((rc = encryptFlight(ssl, &out->end)) < 0) {
			return rc;
		}
	}

	return rc;
}

void clearFlightList(ssl_t *ssl)
{
	flightEncode_t *msg, *next;

	msg = ssl->flightEncode;
	while (msg) {
		next = msg->next;
		psFree(msg, ssl->flightPool);
		msg = next;
	}
	ssl->flightEncode = NULL;
}

static int32 encryptFlight(ssl_t *ssl, unsigned char **end)
{
	flightEncode_t *msg, *remove;
	sslBuf_t		out;
#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
	sslBuf_t		cvFlight;
#endif
	unsigned char	*c, *origEnd;
	int32			rc;

	/* NEGATIVE ECDSA - save the end of the flight buffer */
	origEnd = *end;
	
	msg = ssl->flightEncode;
	while (msg) {
		c = msg->start + msg->len;
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
			if (msg->hsMsg == SSL_HS_FINISHED) {
				/*	Epoch is incremented and the sequence numbers are reset for
					this message */
				incrTwoByte(ssl, ssl->epoch, 1);
				zeroSixByte(ssl->rsn);
			}
			psTraceIntDtls("RSN %d, ", ssl->rsn[5]);
			psTraceIntDtls("MSN %d, ", ssl->msn);
			psTraceIntDtls("Epoch %d\n", ssl->epoch[1]);
			*msg->seqDelay = ssl->epoch[0]; msg->seqDelay++;
			*msg->seqDelay = ssl->epoch[1]; msg->seqDelay++;
			*msg->seqDelay = ssl->rsn[0]; msg->seqDelay++;
			*msg->seqDelay = ssl->rsn[1]; msg->seqDelay++;
			*msg->seqDelay = ssl->rsn[2]; msg->seqDelay++;
			*msg->seqDelay = ssl->rsn[3]; msg->seqDelay++;
			*msg->seqDelay = ssl->rsn[4]; msg->seqDelay++;
			*msg->seqDelay = ssl->rsn[5]; msg->seqDelay++;
			msg->seqDelay++;
			msg->seqDelay++; /* Last two incremements skipped recLen */
		}
#endif
		if (msg->hsMsg == SSL_HS_FINISHED) {
			/* If it was just a ChangeCipherSpec message that was encoded we can
				activate the write cipher */
			if ((rc = sslActivateWriteCipher(ssl)) < 0) {
				psTraceInfo("Error Activating Write Cipher\n");
				clearFlightList(ssl);
				return rc;
			}

			/* The finished message had to hold off snapshoting the handshake
				hash because those updates are done in the encryptRecord call
				below for each message.  THAT was done because of a possible
				delay in a PKA op */
			rc = sslSnapshotHSHash(ssl, ssl->delayHsHash,
				ssl->flags & SSL_FLAGS_SERVER);
			if (rc <= 0) {
				psTraceIntInfo("Error snapshotting HS hash flight %d\n", rc);
				clearFlightList(ssl);
				return rc;
			}

#ifdef ENABLE_SECURE_REHANDSHAKES
			/* The rehandshake verify data is the previous handshake msg hash */
#ifdef USE_DTLS
			if (ssl->flags & SSL_FLAGS_DTLS) {
				if (ssl->myVerifyDataLen > 0) {
					memcpy(ssl->omyVerifyData, ssl->myVerifyData,
						ssl->myVerifyDataLen);
					ssl->omyVerifyDataLen = ssl->myVerifyDataLen;
				}
			}
#endif /* USE_DTLS */
			memcpy(ssl->myVerifyData, ssl->delayHsHash, rc);
			ssl->myVerifyDataLen = rc;
#endif /* ENABLE_SECURE_REHANDSHAKES */
		}

		if (ssl->flags & SSL_FLAGS_NONCE_W) {
			out.start = out.buf = out.end = msg->start - ssl->recordHeadLen -
				TLS_EXPLICIT_NONCE_LEN;
#ifdef USE_DTLS
			if (ssl->flags & SSL_FLAGS_DTLS) {
				/* nonce */
				*msg->seqDelay = ssl->epoch[0]; msg->seqDelay++;
				*msg->seqDelay = ssl->epoch[1]; msg->seqDelay++;
				*msg->seqDelay = ssl->rsn[0]; msg->seqDelay++;
				*msg->seqDelay = ssl->rsn[1]; msg->seqDelay++;
				*msg->seqDelay = ssl->rsn[2]; msg->seqDelay++;
				*msg->seqDelay = ssl->rsn[3]; msg->seqDelay++;
				*msg->seqDelay = ssl->rsn[4]; msg->seqDelay++;
				*msg->seqDelay = ssl->rsn[5]; msg->seqDelay++;
			} else {
#endif
			*msg->seqDelay = ssl->sec.seq[0]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[1]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[2]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[3]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[4]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[5]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[6]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[7];
#ifdef USE_DTLS
			}
#endif
		} else {
			out.start = out.buf = out.end = msg->start - ssl->recordHeadLen;
		}

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
		if (msg->hsMsg == SSL_HS_CERTIFICATE_VERIFY) {
			/* This delayed PKA op has to be done mid flight encode because
				the contents of the signature is the hash of the handshake
				messages.  This can theoretically return PENDING too */
			/* NEGATIVE ECDSA - Need psBuf_t to work in */
			cvFlight.start = cvFlight.buf = out.start;
			cvFlight.end = origEnd;
			cvFlight.size = ssl->insize - (cvFlight.end - cvFlight.buf);
			nowDoCvPka(ssl, &cvFlight);
			/* NEGATIVE ECDSA - account for message may have changed size */
			c = msg->start + msg->len;
			if (ssl->flags & SSL_FLAGS_AEAD_W) {
				out.start = out.buf = out.end =
					(msg->start - ssl->recordHeadLen) - AEAD_NONCE_LEN(ssl);
			} else {
				out.start = out.buf = out.end = msg->start - ssl->recordHeadLen;
			}
		}
#endif /* Client */
#endif /* !PSK_ONLY */

#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS && msg->fragCount > 0) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
			rc = dtlsEncryptFragRecord(ssl, msg, &out, &c);
#endif /* SERVER || CLIENT_AUTH */
#endif /* PSK_ONLY */
		} else {
			rc = encryptRecord(ssl, msg->type, msg->hsMsg, msg->messageSize,
				msg->padLen, msg->start, &out, &c);
		}
#else
		rc = encryptRecord(ssl, msg->type, msg->hsMsg, msg->messageSize, msg->padLen,
			msg->start, &out, &c);
#endif /* DTLS */

		*end = c;
		if (rc == PS_PENDING) {
			/* Eat this message from flight encode, moving next to the front */
			/* Save how far along we are to be picked up next time */
			*end = msg->start + msg->messageSize - ssl->recordHeadLen;
			if (ssl->flags & SSL_FLAGS_AEAD_W) {
				*end -= AEAD_NONCE_LEN(ssl);
			}
			ssl->flightEncode = msg->next;
			psFree(msg, ssl->flightPool);
			return rc;
		}
		if (rc < 0) {
			psTraceIntInfo("Error encrypting record from flight %d\n", rc);
			clearFlightList(ssl);
			return rc;
		}
		remove = msg;
		ssl->flightEncode = msg = msg->next;
		psFree(remove, ssl->flightPool);
	}
	clearFlightList(ssl);
	return PS_SUCCESS;
}

/* One message flight requires 2 PKA "after" operations so need to store both */
pkaAfter_t	*getPkaAfter(ssl_t *ssl)
{
	if (ssl->pkaAfter[0].type == 0) {
		return &ssl->pkaAfter[0];
	} else if (ssl->pkaAfter[1].type == 0) {
		return &ssl->pkaAfter[1];
	} else {
		return NULL;
	}
}

void freePkaAfter(ssl_t *ssl)
{
	/* Just call clear twice */
	clearPkaAfter(ssl);
	clearPkaAfter(ssl);
}


/* Clear pkaAfter[0] and move pkaAfter[1] to [0].  Will be zeroed if no [1] */
void clearPkaAfter(ssl_t *ssl)
{
	if (ssl->pkaAfter[0].inbuf) {
		/* If it was a TMP_PKI pool with PENDING, it will have been saved
			aside in the pkaAfter.pool.  Otherwise, it's in handshake pool */
		if (ssl->pkaAfter[0].pool) {
			psFree(ssl->pkaAfter[0].inbuf, ssl->pkaAfter[0].pool);
		} else {
			psFree(ssl->pkaAfter[0].inbuf, ssl->hsPool);
		}
		ssl->pkaAfter[0].inbuf = NULL;
	}
	if (ssl->pkaAfter[0].pool) {
	}
	ssl->pkaAfter[0].type = 0;
	ssl->pkaAfter[0].outbuf = NULL;
	ssl->pkaAfter[0].data = NULL;
	ssl->pkaAfter[0].inlen = 0;
	ssl->pkaAfter[0].user = 0;

	if (ssl->pkaAfter[1].type != 0) {
		ssl->pkaAfter[0].type = ssl->pkaAfter[1].type;
		ssl->pkaAfter[0].outbuf = ssl->pkaAfter[1].outbuf;
		ssl->pkaAfter[0].data = ssl->pkaAfter[1].data;
		ssl->pkaAfter[0].inlen = ssl->pkaAfter[1].inlen;
		ssl->pkaAfter[0].user = ssl->pkaAfter[1].user;

		ssl->pkaAfter[1].type = 0;
		ssl->pkaAfter[1].outbuf = NULL;
		ssl->pkaAfter[1].data = NULL;
		ssl->pkaAfter[1].inlen = 0;
		ssl->pkaAfter[1].user = 0;
	}
}

/******************************************************************************/
/*
	Message size must account for any additional length a secure-write
	would add to the message.  It would be too late to check length in
	the writeRecordHeader() call since some of the handshake hashing could
	have already taken place and we can't rewind those hashes.
*/
static int32 secureWriteAdditions(ssl_t *ssl, int32 numRecs)
{
	int32 add = 0;
/*
	There is a slim chance for a false FULL message due to the fact that
	the maximum padding is being calculated rather than the actual number.
	Caller must simply grow buffer and try again.  Not subtracting 1 for
	the padding overhead to support NULL ciphers that will have 0 enBlockSize
*/
	if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
		add += (numRecs * ssl->enMacSize) + /* handshake msg hash */
			(numRecs * (ssl->enBlockSize)); /* padding */
#ifdef USE_TLS_1_1
/*
		 Checks here for TLS1.1 with block cipher for explict IV additions.
 */
		if ((ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
			add += (numRecs * ssl->enBlockSize); /* explicitIV */
		}
#endif /* USE_TLS_1_1 */
		if (ssl->flags & SSL_FLAGS_AEAD_W) {
			add += (numRecs * (AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl)));
		}
	}
	return add;
}

/******************************************************************************/
/*
	Write out a closure alert message (the only user initiated alert message)
	The user would call this when about to initate a socket close
	NOTICE: This is the internal function, there is a similarly named public
		API called matrixSslEncodeClosureAlert
*/
int32 sslEncodeClosureAlert(ssl_t *ssl, sslBuf_t *out, uint32 *reqLen)
{
/*
	If we've had a protocol error, don't allow further use of the session
*/
	if (ssl->flags & SSL_FLAGS_ERROR) {
		return MATRIXSSL_ERROR;
	}
	return writeAlert(ssl, SSL_ALERT_LEVEL_WARNING, SSL_ALERT_CLOSE_NOTIFY,
		out, reqLen);
}

/******************************************************************************/
/*
	Generic record header construction for alerts, handshake messages, and
	change cipher spec.  Determines message length for encryption and
	writes out to buffer up to the real message data.

	The FINISHED message is given special treatment here to move through the
	encrypted stages because the postponed flight encoding mechanism will
	not have moved to the SECURE_WRITE state until the CHANGE_CIPHER_SPEC
	has been encoded.  This means we have to look at the hsType and the
	ssl->cipher profile to see what is needed.

	Incoming messageSize is the plaintext message length plus the header
	lengths.
*/
static int32_t writeRecordHeader(ssl_t *ssl, uint8_t type, uint8_t hsType,
				uint16_t *messageSize, uint8_t *padLen,
				unsigned char **encryptStart, const unsigned char *end,
				unsigned char **c)
{
	int32	messageData, msn;

	messageData = *messageSize - ssl->recordHeadLen;
	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
		 messageData -= ssl->hshakeHeadLen;
	}
	if (type == SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG) {
		 messageData -= ssl->hshakeHeadLen;
		 *messageSize = ssl->maxPtFrag + ssl->recordHeadLen;
		 type = SSL_RECORD_TYPE_HANDSHAKE;
	}

#ifdef USE_TLS_1_1
/*
	If a block cipher is being used TLS 1.1 requires the use
	of an explicit IV.  This is an extra random block of data
	prepended to the plaintext before encryption.  Account for
	that extra length here. */
	if (hsType == SSL_HS_FINISHED && (ssl->flags & SSL_FLAGS_TLS_1_1)) {
		if (ssl->cipher->blockSize > 1) {
			*messageSize += ssl->cipher->blockSize;
		}
	} else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			(ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->enBlockSize > 1)) {
		*messageSize += ssl->enBlockSize;
	}
#endif /* USE_TLS_1_1 */

	/* This is to catch the FINISHED write for the postponed encode */
	if (hsType == SSL_HS_FINISHED) {
		if (ssl->cipher->flags & 
			(CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM)) {
			*messageSize += AEAD_TAG_LEN(ssl) + TLS_EXPLICIT_NONCE_LEN;
		} else if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA) {
			*messageSize += AEAD_TAG_LEN(ssl);
		}
	} else if (ssl->flags & SSL_FLAGS_AEAD_W) {
		*messageSize += (AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl));
	}
/*
	If this session is already in a secure-write state, determine padding.
	Again, the FINISHED message is explicitly checked due to the delay
	of the ActivateWriteCipher for flight encodings.  In this case, cipher
	sizes are taken from ssl->cipher rather than the active values
*/
	*padLen = 0;
	if (hsType == SSL_HS_FINISHED) {
		if (ssl->cipher->macSize > 0) {
			if (ssl->extFlags.truncated_hmac) {
				*messageSize += 10;
			} else {
				*messageSize += ssl->cipher->macSize;
			}
		}
		*padLen = psPadLenPwr2(*messageSize - ssl->recordHeadLen,
			ssl->cipher->blockSize);
		*messageSize += *padLen;
	} else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			!(ssl->flags & SSL_FLAGS_AEAD_W)) {
		*messageSize += ssl->enMacSize;
		*padLen = psPadLenPwr2(*messageSize - ssl->recordHeadLen,
			ssl->enBlockSize);
		*messageSize += *padLen;
	}

	if (end - *c < *messageSize) {
/*
		Callers other than sslEncodeResponse do not necessarily check for
		FULL before calling.  We do it here for them.
*/
		return SSL_FULL;
	}

#ifdef USE_DTLS
/*
	This routine does not deal with DTLS fragmented messages, but it was
	necessary to call for all the length computations to happen in here.
*/
	if (ssl->flags & SSL_FLAGS_DTLS) {
		if (*messageSize > ssl->pmtu) {
			psTraceIntDtls("Datagram size %d ", ssl->pmtu);
			psTraceIntDtls("too small for message: %d\n", *messageSize);
			return DTLS_MUST_FRAG;
		}
	}
#endif /* USE_DTLS */

	*c += psWriteRecordInfo(ssl, (unsigned char)type,
		*messageSize - ssl->recordHeadLen, *c, hsType);

/*
	All data written after this point is to be encrypted (if secure-write)
*/
	*encryptStart = *c;
	msn = 0;

#ifdef USE_TLS_1_1
/*
	Explicit IV notes taken from TLS 1.1 ietf draft.

	Generate a cryptographically strong random number R of
	length CipherSpec.block_length and prepend it to the plaintext
	prior to encryption. In this case either:

	The CBC residue from the previous record may be used
	as the mask. This preserves maximum code compatibility
	with TLS 1.0 and SSL 3. It also has the advantage that
	it does not require the ability to quickly reset the IV,
	which is known to be a problem on some systems.

	The data (R || data) is fed into the encryption process.
	The first cipher block containing E(mask XOR R) is placed
	in the IV field. The first block of content contains
	E(IV XOR data)
*/

	if (hsType == SSL_HS_FINISHED) {
		if ((ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->cipher->blockSize > 1)) {
			if (matrixCryptoGetPrngData(*c, ssl->cipher->blockSize,
					ssl->userPtr) < 0) {
				psTraceInfo("WARNING: matrixCryptoGetPrngData failed\n");
			}
			*c += ssl->cipher->blockSize;
		}
	} else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			(ssl->flags & SSL_FLAGS_TLS_1_1) &&
			(ssl->enBlockSize > 1)) {
		if (matrixCryptoGetPrngData(*c, ssl->enBlockSize, ssl->userPtr) < 0) {
			psTraceInfo("WARNING: matrixCryptoGetPrngData failed\n");
		}
		*c += ssl->enBlockSize;
	}
#endif /* USE_TLS_1_1 */

/*
	Handshake records have another header layer to write here
*/
	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
/*
			A message sequence number is unique for each handshake message. It
			is not incremented on a resend; that is the record sequence number.
*/
			msn = ssl->msn;
			ssl->msn++;
			/* These aren't useful anymore because of the seqDelay mechanism */
			//psTraceIntDtls("RSN %d, ", ssl->rsn[5]);
			//psTraceIntDtls("MSN %d, ", msn);
			//psTraceIntDtls("Epoch %d\n", ssl->epoch[1]);
		}
#endif /* USE_DTLS */
		*c += psWriteHandshakeHeader(ssl, (unsigned char)hsType, messageData,
			msn, 0, messageData, *c);
	}

	return PS_SUCCESS;
}


#ifdef USE_ZLIB_COMPRESSION
static int32 encryptCompressedRecord(ssl_t *ssl, int32 type, int32 messageSize,
						   unsigned char *pt, sslBuf_t *out, unsigned char **c)
{
	unsigned char	*encryptStart, *dataToMacAndEncrypt;
	int32			rc, ptLen, divLen, modLen, dataToMacAndEncryptLen;
	int32			zret, ztmp;
	int32			padLen;


	encryptStart = out->end + ssl->recordHeadLen;
	if (ssl->flags & SSL_FLAGS_AEAD_W) {
		encryptStart += AEAD_NONCE_LEN(ssl); /* Move past the plaintext nonce */
		ssl->outRecType = (unsigned char) type;
	}
	ptLen = *c - encryptStart;

#ifdef USE_TLS_1_1
	if ((ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
		/* Do not compress IV */
		if (type == SSL_RECORD_TYPE_APPLICATION_DATA) {
			/* FUTURE: Application data is passed in with real pt from user but
				with the length of the explict IV added already. Can just
				encrypt IV in-siture now since the rest of the encypts will be
				coming from zlibBuffer */
			rc = ssl->encrypt(ssl, encryptStart, encryptStart,
				ssl->enBlockSize);
			if (rc < 0) {
				psTraceIntInfo("Error encrypting IV: %d\n", rc);
				return MATRIXSSL_ERROR;
			}
			ptLen -= ssl->enBlockSize;
			encryptStart += ssl->enBlockSize;
		}  else {
			/* Handshake messages have been passed in with plaintext that
				begins with the explicit IV and size included.  Can just
				encrypt IV in-situ now since the rest of the encypts will be
				coming from zlibBuffer */
			rc = ssl->encrypt(ssl, pt, pt, ssl->enBlockSize);
			if (rc < 0) {
				psTraceIntInfo("Error encrypting IV: %d\n", rc);
				return MATRIXSSL_ERROR;
			}
			pt += ssl->enBlockSize;
			ptLen -= ssl->enBlockSize;
			encryptStart += ssl->enBlockSize;
		}
	}
#endif

	/* Compression is done only on the data itself so the prior work that
		was just put into message size calcuations and padding length will
		need to be done again after deflate */
	ssl->zlibBuffer = psMalloc(ssl->bufferPool, ptLen + MAX_ZLIB_COMPRESSED_OH);
	memset(ssl->zlibBuffer, 0, ptLen + MAX_ZLIB_COMPRESSED_OH);
	if (ssl->zlibBuffer == NULL) {
		psTraceInfo("Error allocating compression buffer\n");
		return MATRIXSSL_ERROR;
	}
	dataToMacAndEncrypt = ssl->zlibBuffer;
	dataToMacAndEncryptLen = ssl->deflate.total_out; /* tmp for later */
	/* psTraceBytes("pre deflate", pt, ptLen); */
	ssl->deflate.avail_out = ptLen + MAX_ZLIB_COMPRESSED_OH;
	ssl->deflate.next_out = dataToMacAndEncrypt;
	ssl->deflate.avail_in = ztmp = ptLen;
	ssl->deflate.next_in = pt;

	/* FUTURE: Deflate would need to be in a smarter loop if large amounts
		of data are ever passed through here */
	if ((zret = deflate(&ssl->deflate, Z_SYNC_FLUSH)) != Z_OK) {
		psTraceIntInfo("ZLIB deflate error %d\n", zret);
		psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
		return MATRIXSSL_ERROR;
	}
	if (ssl->deflate.avail_in != 0) {
		psTraceIntInfo("ZLIB didn't deflate %d bytes in single pass\n", ptLen);
		psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
		deflateEnd(&ssl->deflate);
		return MATRIXSSL_ERROR;
	}

	dataToMacAndEncryptLen = ssl->deflate.total_out - dataToMacAndEncryptLen;
	/* psTraceBytes("post deflate", dataToMacAndEncrypt,
		dataToMacAndEncryptLen); */
	if (dataToMacAndEncryptLen > ztmp) {
		/* Case where compression grew the data.  Push out end */
		*c += dataToMacAndEncryptLen - ztmp;
	} else {
		/* Compression did good job to shrink. Pull back in */
		*c -= ztmp - dataToMacAndEncryptLen;
	}

	/* Can now calculate new padding length */
	padLen = psPadLenPwr2(dataToMacAndEncryptLen + ssl->enMacSize,
		ssl->enBlockSize);

	/* Now see how this has changed the data lengths */
	ztmp = dataToMacAndEncryptLen + ssl->recordHeadLen + ssl->enMacSize +padLen;

#ifdef USE_TLS_1_1
	if ((ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
		ztmp += ssl->enBlockSize;
	}
#endif

	if (ssl->flags & SSL_FLAGS_AEAD_W) {
		psAssert(padLen == 0);
		/* This += works fine because padLen will be zero because enBlockSize
			and enMacSize are 0 */
		ztmp += AEAD_TAG_LEN(ssl) + AEAD_NONCE_LEN(ssl);

	}

	/* Possible the length hasn't changed if compression didn't do much */
	if (messageSize != ztmp) {
		messageSize = ztmp;
		ztmp -= ssl->recordHeadLen;
		out->end[3] = (ztmp & 0xFF00) >> 8;
		out->end[4] = ztmp & 0xFF;
	}

	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
		sslUpdateHSHash(ssl, pt, ptLen);
	}

	if (ssl->generateMac) {
		*c += ssl->generateMac(ssl, (unsigned char)type,
			dataToMacAndEncrypt, dataToMacAndEncryptLen, *c);
	}

	*c += sslWritePad(*c, (unsigned char)padLen);

	if (ssl->flags & SSL_FLAGS_AEAD_W) {
		*c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
									tag has not yet been accounted for */
	}

	/* Will always be non-insitu since the compressed data is in zlibBuffer.
		Requres two encrypts, one for plaintext and one for the
		any < blockSize remainder of the plaintext and the mac and pad	*/
	if (ssl->cipher->blockSize > 1) {
		divLen = dataToMacAndEncryptLen & ~(ssl->cipher->blockSize - 1);
		modLen = dataToMacAndEncryptLen & (ssl->cipher->blockSize - 1);
	} else {
		if (ssl->flags & SSL_FLAGS_AEAD_W) {
			divLen = dataToMacAndEncryptLen + AEAD_TAG_LEN(ssl);
			modLen = 0;
		} else {
			divLen = dataToMacAndEncryptLen;
			modLen = 0;
		}
	}
	if (divLen > 0) {
		rc = ssl->encrypt(ssl, dataToMacAndEncrypt, encryptStart,
			divLen);
		if (rc < 0) {
			psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
			deflateEnd(&ssl->deflate);
			psTraceIntInfo("Error encrypting 2: %d\n", rc);
			return MATRIXSSL_ERROR;
		}
	}
	if (modLen > 0) {
		memcpy(encryptStart + divLen, dataToMacAndEncrypt + divLen,
			modLen);
	}
	rc = ssl->encrypt(ssl, encryptStart + divLen,
		encryptStart + divLen, modLen + ssl->enMacSize + padLen);

	if (rc < 0 || (*c - out->end != messageSize)) {
		psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
		deflateEnd(&ssl->deflate);
		psTraceIntInfo("Error encrypting 3: %d\n", rc);
		return MATRIXSSL_ERROR;
	}
	psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
	/* Will not need the context any longer since FINISHED is the only
		supported message */
	deflateEnd(&ssl->deflate);

#ifdef USE_DTLS
/*
	Waited to increment record sequence number until completely finished
	with the encoding because the HMAC in DTLS uses the rsn of current record
*/
	if (ssl->flags & SSL_FLAGS_DTLS) {
		dtlsIncrRsn(ssl);
	}
#endif /* USE_DTLS */

	return MATRIXSSL_SUCCESS;
}
#endif /* USE_ZLIB_COMPRESSION */


/******************************************************************************/
/*
	Flights are encypted after they are fully written so this function
	just moves the buffer forward to account for the encryption overhead that
	will be filled in later
*/
static int32 postponeEncryptRecord(ssl_t *ssl, int32 type, int32 hsMsg,
				int32 messageSize, int32 padLen, unsigned char *pt,
				sslBuf_t *out, unsigned char **c)
{
	flightEncode_t	*flight, *prev;
	unsigned char	*encryptStart;
	int32			ptLen;

	if ((flight = psMalloc(ssl->flightPool, sizeof(flightEncode_t))) == NULL) {
		return PS_MEM_FAIL;
	}
	memset(flight, 0x0, sizeof(flightEncode_t));
	if (ssl->flightEncode == NULL) {
		ssl->flightEncode = flight;
	} else {
		prev = ssl->flightEncode;
		while (prev->next) {
			prev = prev->next;
		}
		prev->next = flight;
	}
	encryptStart = out->end + ssl->recordHeadLen;

	if (hsMsg == SSL_HS_FINISHED) {
		if (ssl->cipher->flags & (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM)) {
			encryptStart += TLS_EXPLICIT_NONCE_LEN;
		}
	} else if (ssl->flags & SSL_FLAGS_AEAD_W) {
		encryptStart += AEAD_NONCE_LEN(ssl); /* Move past the plaintext nonce */
	}

	ptLen = (int32)(*c - encryptStart);

	flight->start = pt;
	flight->len = ptLen;
	flight->type = type;
	flight->padLen = padLen;
	flight->messageSize = messageSize;
	flight->hsMsg = hsMsg;
	flight->seqDelay = ssl->seqDelay;

	if (hsMsg == SSL_HS_FINISHED) {
		if (!(ssl->cipher->flags &
				(CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_CCM))) {
			if (ssl->extFlags.truncated_hmac) {
				*c += 10;
			} else {
				*c += ssl->cipher->macSize;
			}
		} else {
			*c += ssl->cipher->macSize;
		}
	} else {
		*c += ssl->enMacSize;
	}
	*c += padLen;

	if (hsMsg == SSL_HS_FINISHED) {
		if (ssl->cipher->flags &
			(CRYPTO_FLAGS_GCM| CRYPTO_FLAGS_CHACHA | CRYPTO_FLAGS_CCM)) {
			*c += AEAD_TAG_LEN(ssl);
		}
	} else if (ssl->flags & SSL_FLAGS_AEAD_W) {
		*c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
									tag has not yet been accounted for */
	}

#ifdef USE_TLS_1_1
#endif /* USE_TLS_1_1 */

	if (*c - out->end != messageSize) {
		psTraceIntInfo("postponeEncryptRecord length test failed: wanted %d ",
			messageSize);
		psTraceIntInfo("but generated %d\n", (int32)(*c - out->end));
		return MATRIXSSL_ERROR;
	}
	return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
	Encrypt the message using the current cipher.  This call is used in
	conjunction with the writeRecordHeader() function above to finish writing
	an SSL record.  Updates handshake hash if necessary, generates message
	MAC, writes the padding, and does the encryption.

	messageSize is the final size, with header, mac and padding of the output
	messageSize - 5 = ssl.recLen
	*c - encryptStart = plaintext length
*/
static int32 encryptRecord(ssl_t *ssl, int32 type, int32 hsMsgType,
							int32 messageSize, int32 padLen, unsigned char *pt,
							sslBuf_t *out, unsigned char **c)
{
	unsigned char	*encryptStart;
	int32			rc, ptLen, divLen, modLen;

#ifdef USE_ZLIB_COMPRESSION
	/* In the current implementation, MatrixSSL will only internally handle
		the compression and decompression of the FINISHED message.  Application
		data will be compressed and decompressed by the caller.
		Re-handshakes are not supported and this would have been caught
		earlier in the state machine so if the record type is HANDSHAKE we
		can be sure this is the FINISHED message

		This should allow compatibility with SSL implementations that support
		ZLIB compression */
	if (ssl->flags & SSL_FLAGS_WRITE_SECURE && ssl->compression &&
			type == SSL_RECORD_TYPE_HANDSHAKE) {
		return encryptCompressedRecord(ssl, type, messageSize, pt, out, c);
	}
#endif

	encryptStart = out->end + ssl->recordHeadLen;

	if (ssl->flags & SSL_FLAGS_AEAD_W) {
		encryptStart += AEAD_NONCE_LEN(ssl); /* Move past the plaintext nonce */
		ssl->outRecType = (unsigned char) type;
	}

	ptLen = (int32)(*c - encryptStart);
#ifdef USE_TLS
#ifdef USE_TLS_1_1
	if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			(ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
/*
		Don't add the random bytes into the hash of the message.  Makes
		things very easy on the other side to simply discard the randoms
*/
		if (type == SSL_RECORD_TYPE_HANDSHAKE) {
			sslUpdateHSHash(ssl, pt + ssl->enBlockSize,
				ptLen - ssl->enBlockSize);
			if (hsMsgType == SSL_HS_CLIENT_KEY_EXCHANGE &&
					ssl->extFlags.extended_master_secret == 1) {
				if (tlsExtendedDeriveKeys(ssl) < 0) {
					return MATRIXSSL_ERROR;
				}
			}
		}
		if (type == SSL_RECORD_TYPE_APPLICATION_DATA) {
			/* Application data is passed in with real pt from user but
				with the length of the explict IV added already */
			*c += ssl->generateMac(ssl, (unsigned char)type,
				pt, ptLen - ssl->enBlockSize, *c);
			/* While we are in here, let's see if this is an in-situ case */
			if (encryptStart + ssl->enBlockSize == pt) {
				pt = encryptStart;
			} else {
				/* Not in-situ.  Encrypt the explict IV now */
				if ((rc = ssl->encrypt(ssl, encryptStart,
						encryptStart, ssl->enBlockSize)) < 0) {
					psTraceIntInfo("Error encrypting explicit IV: %d\n", rc);
					return MATRIXSSL_ERROR;
				}
				encryptStart += ssl->enBlockSize;
				ptLen -= ssl->enBlockSize;
			}
		} else {
			/* Handshake messages have been passed in with plaintext that
				begins with the explicit IV and size included */
			*c += ssl->generateMac(ssl, (unsigned char)type,
				pt + ssl->enBlockSize, ptLen - ssl->enBlockSize, *c);
		}
	} else {
#endif /* USE_TLS_1_1 */
		if (type == SSL_RECORD_TYPE_HANDSHAKE) {
			if ((rc = sslUpdateHSHash(ssl, pt, ptLen)) < 0) {
				return rc;
			}
			/* Explicit state test for peforming the extended master secret
				calculation.  The sslUpdateHsHash immediately above has just
				ran the ClientKeyExchange message through the hash so now
				we can snapshot and create the key block */
			if (hsMsgType == SSL_HS_CLIENT_KEY_EXCHANGE &&
					ssl->extFlags.extended_master_secret == 1) {
				if (tlsExtendedDeriveKeys(ssl) < 0) {
					return MATRIXSSL_ERROR;
				}
			}
		}
		if (ssl->generateMac) {
			*c += ssl->generateMac(ssl, (unsigned char)type, pt, ptLen, *c);
		}
#ifdef USE_TLS_1_1
	}
#endif /* USE_TLS_1_1 */
#else /* USE_TLS */
	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
		sslUpdateHSHash(ssl, pt, ptLen);
	}
	*c += ssl->generateMac(ssl, (unsigned char)type, pt,
		ptLen, *c);
#endif /* USE_TLS */

	*c += sslWritePad(*c, (unsigned char)padLen);

	if (ssl->flags & SSL_FLAGS_AEAD_W) {
		*c += AEAD_TAG_LEN(ssl); /* c is tracking end of record here and the
									tag has not yet been accounted for */
	}

	if (pt == encryptStart) {
		/* In-situ encode */
		if ((rc = ssl->encrypt(ssl, pt, encryptStart,
				(uint32)(*c - encryptStart))) < 0 ||
				*c - out->end != messageSize) {
			psTraceIntInfo("Error encrypting 1: %d\n", rc);
			psTraceIntInfo("messageSize is %d\n", messageSize);
			psTraceIntInfo("pointer diff %d\n", *c - out->end);
			psTraceIntInfo("cipher suite %d\n", ssl->cipher->ident);
			return MATRIXSSL_ERROR;
		}
	} else {
		/*
			Non-insitu requres two encrypts, one for plaintext and one for the
			any < blockSize remainder of the plaintext and the mac and pad
		*/
		if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
			if (ssl->cipher->blockSize > 1) {
				divLen = ptLen & ~(ssl->cipher->blockSize - 1);
				modLen = ptLen & (ssl->cipher->blockSize - 1);
			} else {
				if (ssl->flags & SSL_FLAGS_AEAD_W) {
					divLen = ptLen + AEAD_TAG_LEN(ssl);
					modLen = 0;
				} else {
					divLen = ptLen;
					modLen = 0;
				}
			}
			if (divLen > 0) {
				rc = ssl->encrypt(ssl, pt, encryptStart, divLen);
				if (rc < 0) {
					psTraceIntInfo("Error encrypting 2: %d\n", rc);
					return MATRIXSSL_ERROR;
				}
			}
			if (modLen > 0) {
				memcpy(encryptStart + divLen, pt + divLen, modLen);
			}
			rc = ssl->encrypt(ssl, encryptStart + divLen,
				encryptStart + divLen, modLen + ssl->enMacSize + padLen);
		} else {
			rc = ssl->encrypt(ssl, pt, encryptStart,
				(uint32)(*c - encryptStart));
		}
		if (rc < 0 || (*c - out->end != messageSize)) {
			psTraceIntInfo("Error encrypting 3: %d\n", rc);
			return MATRIXSSL_ERROR;
		}
	}
#ifdef USE_DTLS
/*
	Waited to increment record sequence number until completely finished
	with the encoding because the HMAC in DTLS uses the rsn of current record
*/
	if (ssl->flags & SSL_FLAGS_DTLS) {
		dtlsIncrRsn(ssl);
	}
#endif /* USE_DTLS */

	if (*c - out->end != messageSize) {
		psTraceInfo("encryptRecord length sanity test failed\n");
		return MATRIXSSL_ERROR;
	}
	return MATRIXSSL_SUCCESS;
}

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
	Write out the ServerHello message
*/
static int32 writeServerHello(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint16_t		messageSize;
	uint8_t			padLen;
	int32			t, rc, extLen = 0;

	psTraceHs("<<< Server creating SERVER_HELLO message\n");
	c = out->end;
	end = out->buf + out->size;
/*
	Calculate the size of the message up front, and verify we have room
	We assume there will be a sessionId in the message, and make adjustments
	below if there is no sessionId.
*/
	messageSize =
		ssl->recordHeadLen +
		ssl->hshakeHeadLen +
		38 + SSL_MAX_SESSION_ID_SIZE;

#ifdef ENABLE_SECURE_REHANDSHAKES
#ifdef USE_DTLS
/*
	Can run into a problem if doing a new resumed handshake because the flight
	is SERVER_HELLO, CCS, and FINISHED which will populate myVerifyData
	which will confuse the resend logic here that we are doing a rehandshake.
	If peerVerifyData isn't available and we're doing a retransmit we know
	this is the problematic case so forget we have a myVerifyData
*/
	if (ssl->flags & SSL_FLAGS_DTLS) {
		if ((ssl->secureRenegotiationFlag == PS_TRUE) && (ssl->retransmit == 1)
				&& (ssl->myVerifyDataLen > 0) && (ssl->peerVerifyDataLen == 0))
		{
			ssl->myVerifyDataLen = 0;
		}
	}
#endif
/*
	The RenegotiationInfo extension lengths are well known
*/
	if (ssl->secureRenegotiationFlag == PS_TRUE && ssl->myVerifyDataLen == 0) {
		extLen = 7; /* 00 05 ff 01 00 01 00 */
	} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
			ssl->myVerifyDataLen > 0) {
		extLen = 2 + 5 + ssl->myVerifyDataLen + ssl->peerVerifyDataLen;
	}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
		if (extLen == 0) {
			extLen = 2; /* if first extension, add two byte total len */
		}
		/* EXT_ELLIPTIC_POINTS - hardcoded to 'uncompressed' support */
		extLen += 6; /* 00 0B 00 02 01 00 */
	}
#endif /* USE_ECC_CIPHER_SUITE */

	if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 5;
	}

	if (ssl->extFlags.truncated_hmac) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}
	
	if (ssl->extFlags.extended_master_secret) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}

#ifdef USE_STATELESS_SESSION_TICKETS
	if (ssl->sid &&	ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}
#endif

	if (ssl->extFlags.sni) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}
#ifdef USE_OCSP
	if (ssl->extFlags.status_request) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}
#endif

#ifdef USE_SCT
	if (ssl->extFlags.signed_certificate_timestamp) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 2 + 2 + 2 + ssl->keys->SCTResponseBufLen; /* 2 type, 2 len, data */
	}
#endif

#ifdef USE_ALPN
	if (ssl->alpnLen) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 6 + 1 + ssl->alpnLen; /* 6 type/len + 1 len + data */
	}
#endif

	messageSize += extLen;
	t = 1;
#ifdef USE_DTLS
	if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 1)) {
/*
		All retransmits must generate identical handshake messages as the
		original.  This is to ensure both sides are running the same material
		through the handshake hash
*/
		t = 0;
	}
#endif /* USE_DTLS */

	if (t) {
	/**	@security RFC says to set the first 4 bytes to time, but best common practice is
		to use full 32 bytes of random. This is forward looking to TLS 1.3, and also works
		better for embedded platforms and FIPS secret key material.
		@see https://www.ietf.org/mail-archive/web/tls/current/msg09861.html */
#ifdef SEND_HELLO_RANDOM_TIME
		/* First 4 bytes of the serverRandom are the unix time to prevent replay
			attacks, the rest are random */
		t = psGetTime(NULL, ssl->userPtr);
		ssl->sec.serverRandom[0] = (unsigned char)((t & 0xFF000000) >> 24);
		ssl->sec.serverRandom[1] = (unsigned char)((t & 0xFF0000) >> 16);
		ssl->sec.serverRandom[2] = (unsigned char)((t & 0xFF00) >> 8);
		ssl->sec.serverRandom[3] = (unsigned char)(t & 0xFF);
		if (matrixCryptoGetPrngData(ssl->sec.serverRandom + 4,
				SSL_HS_RANDOM_SIZE - 4, ssl->userPtr) < 0) {
			return MATRIXSSL_ERROR;
		}
#else
		if (matrixCryptoGetPrngData(ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE , ssl->userPtr) < 0) {
			return MATRIXSSL_ERROR;
		}
#endif
	}

/*
	We register session here because at this point the serverRandom value is
	populated.  If we are able to register the session, the sessionID and
	sessionIdLen fields will be non-NULL, otherwise the session couldn't
	be registered.
*/
	if (!(ssl->flags & SSL_FLAGS_RESUMED)) {
		matrixRegisterSession(ssl);
	}
	messageSize -= (SSL_MAX_SESSION_ID_SIZE - ssl->sessionIdLen);

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO, &messageSize, &padLen, &encryptStart,
			end, &c)) < 0) {
		return rc;
	}
/*
	First two fields in the ServerHello message are the major and minor
	SSL protocol versions we agree to talk with
*/
	*c = ssl->majVer; c++;
	*c = ssl->minVer; c++;

/*
	The next 32 bytes are the server's random value, to be combined with
	the client random and premaster for key generation later
*/
	memcpy(c, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
	c += SSL_HS_RANDOM_SIZE;
/*
	The next data is a single byte containing the session ID length,
	and up to 32 bytes containing the session id.
	First register the session, which will give us a session id and length
	if not all session slots in the table are used
*/
	*c = (unsigned char)ssl->sessionIdLen; c++;
	if (ssl->sessionIdLen > 0) {
		memcpy(c, ssl->sessionId, ssl->sessionIdLen);
		c += ssl->sessionIdLen;
	}
/*
	Two byte cipher suite we've chosen based on the list sent by the client
	and what we support.
	One byte compression method (always zero)
*/
	*c = (ssl->cipher->ident & 0xFF00) >> 8; c++;
	*c = ssl->cipher->ident & 0xFF; c++;
#ifdef USE_ZLIB_COMPRESSION
	if (ssl->compression) {
		*c = 1; c++;
	} else {
		*c = 0; c++;
	}
#else
	*c = 0; c++;
#endif

	if (extLen != 0) {
		extLen -= 2; /* Don't add self to total extension len */
		*c = (extLen & 0xFF00) >> 8; c++;
		*c = extLen & 0xFF; c++;

		if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN) {
			*c = 0x0; c++;
			*c = 0x1; c++;
			*c = 0x0; c++;
			*c = 0x1; c++;

			if (ssl->maxPtFrag == 0x200) {
				*c = 0x1; c++;
			}
			if (ssl->maxPtFrag == 0x400) {
				*c = 0x2; c++;
			}
			if (ssl->maxPtFrag == 0x800) {
				*c = 0x3; c++;
			}
			if (ssl->maxPtFrag == 0x1000) {
				*c = 0x4; c++;
			}
		}
		if (ssl->extFlags.truncated_hmac) {
			*c = (EXT_TRUNCATED_HMAC & 0xFF00) >> 8; c++;
			*c = EXT_TRUNCATED_HMAC & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}
		if (ssl->extFlags.extended_master_secret) {
			*c = (EXT_EXTENDED_MASTER_SECRET & 0xFF00) >> 8; c++;
			*c = EXT_EXTENDED_MASTER_SECRET & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}

#ifdef USE_STATELESS_SESSION_TICKETS
		if (ssl->sid &&
				ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT) {
			/* This empty extension is ALWAYS an indication to the client that
				a NewSessionTicket handshake message will be sent */
			*c = (EXT_SESSION_TICKET & 0xFF00) >> 8; c++;
			*c = EXT_SESSION_TICKET & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}
#endif

		if (ssl->extFlags.sni) {
			*c = (EXT_SNI & 0xFF00) >> 8; c++;
			*c = EXT_SNI & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}
#ifdef USE_OCSP
		if (ssl->extFlags.status_request) {
			*c = (EXT_STATUS_REQUEST & 0xFF00) >> 8; c++;
			*c = EXT_STATUS_REQUEST & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}
#endif

#ifdef USE_SCT
		if (ssl->extFlags.signed_certificate_timestamp) {
			*c = (EXT_SIGNED_CERTIFICATE_TIMESTAMP & 0xFF00) >> 8; c++;
			*c = EXT_SIGNED_CERTIFICATE_TIMESTAMP & 0xFF; c++;
			*c = ((ssl->keys->SCTResponseBufLen + 2) & 0xFF00) >> 8; c++;
			*c = (ssl->keys->SCTResponseBufLen + 2) & 0xFF; c++;
			*c = (ssl->keys->SCTResponseBufLen & 0xFF00) >> 8; c++;
			*c = ssl->keys->SCTResponseBufLen & 0xFF; c++;
			memcpy(c, ssl->keys->SCTResponseBuf, ssl->keys->SCTResponseBufLen);
			c += ssl->keys->SCTResponseBufLen;
		}
#endif

#ifdef USE_ALPN
		if (ssl->alpnLen) {
			*c = (EXT_ALPN & 0xFF00) >> 8; c++;
			*c = EXT_ALPN & 0xFF; c++;
			/* Total ext len can be hardcoded +3 because only one proto reply */
			*c = ((ssl->alpnLen + 3) & 0xFF00) >> 8; c++;
			*c = (ssl->alpnLen + 3) & 0xFF; c++;
			/* Can only ever be a reply of one proto so explict len +1 works */
			*c = ((ssl->alpnLen + 1) & 0xFF00) >> 8; c++;
			*c = (ssl->alpnLen + 1) & 0xFF; c++;
			*c = ssl->alpnLen; c++;
			memcpy(c, ssl->alpn, ssl->alpnLen);
			c += ssl->alpnLen;
			psFree(ssl->alpn, ssl->sPool); ssl->alpn = NULL; /* app must store if needed */
			ssl->alpnLen = 0;
		}
#endif

#ifdef ENABLE_SECURE_REHANDSHAKES
		if (ssl->secureRenegotiationFlag == PS_TRUE) {
			/* RenegotiationInfo*/
			*c = (EXT_RENEGOTIATION_INFO & 0xFF00) >> 8; c++;
			*c = EXT_RENEGOTIATION_INFO & 0xFF; c++;
			if (ssl->myVerifyDataLen == 0) {
				*c = 0; c++;
				*c = 1; c++;
				*c = 0; c++;
			} else {
				*c =((ssl->myVerifyDataLen+ssl->peerVerifyDataLen+1)&0xFF00)>>8;
				c++;
				*c = (ssl->myVerifyDataLen + ssl->peerVerifyDataLen + 1) & 0xFF;
				c++;
				*c = (ssl->myVerifyDataLen + ssl->peerVerifyDataLen) & 0xFF;c++;
				memcpy(c, ssl->peerVerifyData, ssl->peerVerifyDataLen);
				c += ssl->peerVerifyDataLen;
				memcpy(c, ssl->myVerifyData, ssl->myVerifyDataLen);
				c += ssl->myVerifyDataLen;
			}
		}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			*c = (EXT_ELLIPTIC_POINTS & 0xFF00) >> 8; c++;
			*c = EXT_ELLIPTIC_POINTS & 0xFF; c++;
			*c = 0x00; c++;
			*c = 0x02; c++;
			*c = 0x01; c++;
			*c = 0x00; c++;
		}
#endif /* USE_ECC_CIPHER_SUITE */
	}

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO, messageSize, padLen, encryptStart, out, &c))
			< 0) {
		return rc;
	}
/*
	If we're resuming a session, we now have the clientRandom, master and
	serverRandom, so we can derive keys which we'll be using shortly.
*/
	if (ssl->flags & SSL_FLAGS_RESUMED) {
		if ((rc = sslCreateKeys(ssl)) < 0) {
			return rc;
		}
	}
	out->end = c;

#ifdef USE_MATRIXSSL_STATS
	matrixsslUpdateStat(ssl, SH_SENT_STAT, 1);
#endif
	return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
	ServerHelloDone message is a blank handshake message
*/
static int32 writeServerHelloDone(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize;
	int32_t			rc;

	psTraceHs("<<< Server creating SERVER_HELLO_DONE message\n");
	c = out->end;
	end = out->buf + out->size;
	messageSize =
		ssl->recordHeadLen +
		ssl->hshakeHeadLen;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO_DONE, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		return rc;
	}

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO_DONE, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#ifdef USE_PSK_CIPHER_SUITE
/******************************************************************************/
/*
	The PSK cipher version of ServerKeyExchange.  Was able to single this
	message out with a dedicated write simply due to the flight
	logic of DH ciphers.  The ClientKeyExchange message for PSK was rolled
	into the generic function, for example.
*/
static int32 writePskServerKeyExchange(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	unsigned char	*hint;
	uint16_t		messageSize;
	uint8_t			padLen, hintLen;
	int32_t			rc;

	psTraceHs("<<< Server creating SERVER_KEY_EXCHANGE message\n");
#ifdef USE_DHE_CIPHER_SUITE
/*
	This test prevents a second ServerKeyExchange from being written if a
	PSK_DHE cipher was choosen.  This is an ugly side-effect of the many
	combinations of cipher suites being supported in the 'flight' based
	state machine model
*/
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
		return MATRIXSSL_SUCCESS;
	}
#endif /* USE_DHE_CIPHER_SUITE */

	if (matrixPskGetHint(ssl, &hint, &hintLen) < 0) {
		return MATRIXSSL_ERROR;
	}
	if (hint == NULL || hintLen == 0) {
		return MATRIXSSL_SUCCESS;
	}

	c = out->end;
	end = out->buf + out->size;

	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + hintLen + 2;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		return rc;
	}

	*c = (hintLen & 0xFF00) >> 8; c++;
	*c = (hintLen & 0xFF); c++;
	memcpy(c, hint, hintLen);
	c += hintLen;

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, messageSize, padLen, encryptStart,
			out, &c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_STATELESS_SESSION_TICKETS /* Already inside a USE_SERVER_SIDE block */
static int32 writeNewSessionTicket(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char		*c, *end, *encryptStart;
	uint8_t				padLen;
	uint16_t			messageSize;
	int32_t				rc;

	psTraceHs("<<< Server creating NEW_SESSION_TICKET message\n");
	c = out->end;
	end = out->buf + out->size;

	/* magic 6 is 4 bytes lifetime hint and 2 bytes len */
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		matrixSessionTicketLen() + 6;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_NEW_SESSION_TICKET, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		return rc;
	}

	rc = (int32)(end - c);
	if (matrixCreateSessionTicket(ssl, c, &rc) < 0) {
		psTraceInfo("Error generating session ticket\n");
		return MATRIXSSL_ERROR;
	}
	c += rc;

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_NEW_SESSION_TICKET, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	
	ssl->sid->sessionTicketState = SESS_TICKET_STATE_USING_TICKET;

	return PS_SUCCESS;
}
#endif /* USE_STATELESS_SESSION_TICKETS */

#ifdef USE_DHE_CIPHER_SUITE /* Already inside a USE_SERVER_SIDE block */
/******************************************************************************/
/*
	Write out the ServerKeyExchange message.
*/
static int32 writeServerKeyExchange(ssl_t *ssl, sslBuf_t *out, uint32 pLen,
					unsigned char *p, uint32 gLen, unsigned char *g)
{
	unsigned char		*c, *end, *encryptStart;
	uint8_t				padLen;
	uint16_t			messageSize = 0;
	int32_t				rc;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	uint16_t			hashSize;
	unsigned char		*hsMsgHash, *sigStart;
	psDigestContext_t	digestCtx;
	pkaAfter_t			*pkaAfter;
	void				*pkiData = ssl->userPtr;
#endif

#if defined(USE_PSK_CIPHER_SUITE) && defined(USE_ANON_DH_CIPHER_SUITE)
	unsigned char	*hint;
	uint8_t			hintLen;
#endif /* USE_PSK_CIPHER_SUITE && USE_ANON_DH_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE
	uint16_t		eccPubKeyLen;
#endif /* USE_ECC_CIPHER_SUITE */

	psTraceHs("<<< Server creating SERVER_KEY_EXCHANGE message\n");
	c = out->end;
	end = out->buf + out->size;

/*
	Calculate the size of the message up front, and verify we have room
*/
#ifdef USE_ANON_DH_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
		messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
			6 + pLen + gLen + ssl->sec.dhKeyPriv->size;
	#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			messageSize -= 2; /* hashSigAlg not going to be needed */
		}
	#endif

	#ifdef USE_PSK_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			if (matrixPskGetHint(ssl, &hint, &hintLen) < 0) {
				return MATRIXSSL_ERROR;
			}
/*
 * 			RFC4279: In the absence of an application profile specification
 * 			specifying otherwise, servers SHOULD NOT provide an identity hint
 * 			and clients MUST ignore the identity hint field.  Applications that
 * 			do use this field MUST specify its contents, how the value is
 * 			chosen by the TLS server, and what the TLS client is expected to do
 * 			with the value.
 *			@note Unlike pure PSK cipher which will omit the ServerKeyExchange
 *			message if the hint is NULL, the DHE_PSK exchange simply puts
 *			two zero bytes in this case, since the message must still be sent
 *			to exchange the DHE public key.
 */
 			messageSize += 2; /* length of hint (even if zero) */
 			if (hintLen != 0 && hint != NULL) {
				messageSize += hintLen;
 			}
		}
	#endif /* USE_PSK_CIPHER_SUITE */
	} else {
#endif /* USE_ANON_DH_CIPHER_SUITE */
	#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			/* ExportKey portion */
			eccPubKeyLen = (ssl->sec.eccKeyPriv->curve->size * 2) + 1;

			if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA) {
				messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
					eccPubKeyLen + 4 + ssl->keys->privKey.keysize + 2;
			} else if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
				messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + 6 +
					eccPubKeyLen;
				/* NEGATIVE ECDSA - Adding ONE spot for a 0x0 byte in the
					ECDSA signature.  This will allow us to be right ~50% of
					the time and not require any manual manipulation
					
					However, if this is a 521 curve there is no chance
					the final byte could be negative if the full 66
					bytes are needed because there can only be a single
					low bit for that sig size.  So subtract that byte
					back out to stay around the 50% no-move goal */
				if (ssl->keys->privKey.keysize != 132) {
					messageSize += 1;
				}
				messageSize += ssl->keys->privKey.keysize;
				/* Signature portion */
				messageSize += 6; /* 6 = 2 ASN_SEQ, 4 ASN_BIG */
				/* BIG EC KEY.  The sig is 2 bytes len, 1 byte SEQ,
					1 byte length (+1 OPTIONAL byte if length is >=128),
					1 byte INT, 1 byte rLen, r, 1 byte INT, 1 byte sLen, s.
					So the +4 here are the 2 INT and 2 rLen/sLen bytes on
					top of the keysize */
				if (ssl->keys->privKey.keysize + 4 >= 128) {
					messageSize++; /* Extra byte for 'long' asn.1 encode */
				}
#ifdef USE_DTLS
				if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 1)) {
					/* We already know if this signature got resized */
					messageSize += ssl->ecdsaSizeChange;
				}
#endif
			}
		} else {
	#endif /* USE_ECC_CIPHER_SUITE */
	#ifdef REQUIRE_DH_PARAMS
		messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
			8 + pLen + gLen + ssl->sec.dhKeyPriv->size +
			ssl->keys->privKey.keysize;
	#endif /* REQUIRE_DH_PARAMS */
	#ifdef USE_ECC_CIPHER_SUITE
		}
	#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_ANON_DH_CIPHER_SUITE
	}
#endif /* USE_ANON_DH_CIPHER_SUITE */

	if (messageSize == 0) {
		/* This api was called without DHE, PSK and ECC enabled */
		return MATRIXSSL_ERROR;
	}
#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		messageSize += 2; /* hashSigAlg */
	}
#endif
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		return rc;
	}
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	sigStart = c;
#endif

#if defined(USE_PSK_CIPHER_SUITE) && defined(USE_ANON_DH_CIPHER_SUITE)
	/* PSK suites have a leading PSK identity hint (may be zero length) */
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
		*c = (hintLen & 0xFF00) >> 8; c++;
		*c = (hintLen & 0xFF); c++;
 		if (hintLen != 0 && hint != NULL) {
			memcpy(c, hint, hintLen);
			c += hintLen;
		}
	}
#endif /* USE_PSK_CIPHER_SUITE && USE_ANON_DH_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
/*
		1 byte - ECCurveType (NamedCurve enum is 3)
		 2 byte - NamedCurve id
*/
		*c = 3; c++; /* NamedCurve enum */
		*c = (ssl->sec.eccKeyPriv->curve->curveId & 0xFF00) >> 8; c++;
		*c = (ssl->sec.eccKeyPriv->curve->curveId & 0xFF); c++;
		*c = eccPubKeyLen & 0xFF; c++;
		if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv, c,
				&eccPubKeyLen) != 0) {
			return MATRIXSSL_ERROR;
		}
		c += eccPubKeyLen;

	} else {
#endif
#ifdef REQUIRE_DH_PARAMS
/*
		The message itself;
			2 bytes p len, p, 2 bytes g len, g, 2 bytes pubKeyLen, pubKey

		Size tests have all ready been taken care of a level up from this
*/
		*c = (pLen & 0xFF00) >> 8; c++;
		*c = pLen & 0xFF; c++;
		memcpy(c, p, pLen);
		c += pLen;
		*c = (gLen & 0xFF00) >> 8; c++;
		*c = gLen & 0xFF; c++;
		memcpy(c, g, gLen);
		c += gLen;
		*c = (ssl->sec.dhKeyPriv->size & 0xFF00) >> 8; c++;
		*c = ssl->sec.dhKeyPriv->size & 0xFF; c++;
		{
		uint16_t	dhLen = end - c;
		if (psDhExportPubKey(ssl->hsPool, ssl->sec.dhKeyPriv, c, &dhLen) < 0) {
			return MATRIXSSL_ERROR;
		}
		psAssert(dhLen == ssl->sec.dhKeyPriv->size);
		}
		c += ssl->sec.dhKeyPriv->size;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
	}
#endif /* USE_ECC_CIPHER_SUITE */

	/*  RFC 5246 - 7.4.3.  Server Key Exchange Message
		In addition, the hash and signature algorithms MUST be compatible
		with the key in the server's end-entity certificate.  RSA keys MAY be
		used with any permitted hash algorithm, subject to restrictions in
		the certificate, if any. */

#ifdef USE_RSA_CIPHER_SUITE
/*
	RSA authentication requires an additional signature portion to the message
*/
	if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		/* Saved aside for pkaAfter_t */
		if ((hsMsgHash = psMalloc(ssl->hsPool, SHA384_HASH_SIZE)) == NULL) {
			return PS_MEM_FAIL;
		}
#endif
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/* Using the algorithm from the certificate */
			if (ssl->keys->cert->sigAlgorithm == OID_SHA256_RSA_SIG) {
				hashSize = SHA256_HASH_SIZE;
				psSha256Init(&digestCtx.sha256);
				psSha256Update(&digestCtx.sha256, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha256Update(&digestCtx.sha256, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha256Update(&digestCtx.sha256, sigStart,
					(uint32)(c - sigStart));
				psSha256Final(&digestCtx.sha256, hsMsgHash);
				*c++ = 0x4;
				*c++ = 0x1;
#ifdef USE_SHA384
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA384_RSA_SIG) {
				hashSize = SHA384_HASH_SIZE;
				psSha384Init(&digestCtx.sha384);
				psSha384Update(&digestCtx.sha384, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha384Update(&digestCtx.sha384, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha384Update(&digestCtx.sha384, sigStart,
					(uint32)(c - sigStart));
				psSha384Final(&digestCtx.sha384, hsMsgHash);
				*c++ = 0x5;
				*c++ = 0x1;
#endif /* USE_SHA384 */
			/* If MD5, just send a SHA1.  Don't want to contribute to any
				longevity of MD5 */
#ifdef USE_SHA1
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_MD5_RSA_SIG) {
				hashSize = SHA1_HASH_SIZE;
				psSha1Init(&digestCtx.sha1);
				psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx.sha1, sigStart, (uint32)(c - sigStart));
				psSha1Final(&digestCtx.sha1, hsMsgHash);
				*c++ = 0x2;
				*c++ = 0x1;
#endif				
			} else {
				psTraceIntInfo("Unavailable sigAlgorithm for SKE write: %d\n",
					ssl->keys->cert->sigAlgorithm);
				psFree(hsMsgHash, ssl->hsPool);
				return PS_UNSUPPORTED_FAIL;
			}
		} else {
#if defined(USE_SHA1) && defined(USE_MD5)
			hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
			psMd5Init(&digestCtx.md5);
			psMd5Update(&digestCtx.md5, ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE);
			psMd5Update(&digestCtx.md5, ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE);
			psMd5Update(&digestCtx.md5, sigStart, (uint32)(c - sigStart));
			psMd5Final(&digestCtx.md5, hsMsgHash);

			psSha1Init(&digestCtx.sha1);
			psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx.sha1, sigStart, (uint32)(c - sigStart));
			psSha1Final(&digestCtx.sha1, hsMsgHash + MD5_HASH_SIZE);
#else
			psTraceIntInfo("Unavailable sigAlgorithm for SKE write: %d\n",
				ssl->keys->cert->sigAlgorithm);
			psFree(hsMsgHash, ssl->hsPool);
			return PS_UNSUPPORTED_FAIL;
#endif
		}
#else /* USE_TLS_1_2 */
		hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
		psMd5Init(&digestCtx.md5);
		psMd5Update(&digestCtx.md5, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
		psMd5Update(&digestCtx.md5, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
		psMd5Update(&digestCtx.md5, sigStart, (uint32)(c - sigStart));
		psMd5Final(&digestCtx.md5, hsMsgHash);

		psSha1Init(&digestCtx.sha1);
		psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx.sha1, sigStart, (uint32)(c - sigStart));
		psSha1Final(&digestCtx.sha1, hsMsgHash + MD5_HASH_SIZE);
#endif /* USE_TLS_1_2 */

		*c = (ssl->keys->privKey.keysize & 0xFF00) >> 8; c++;
		*c = ssl->keys->privKey.keysize & 0xFF; c++;

#ifdef USE_DTLS
		if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 1)) {
			/* It is not optimal to have run through the above digest updates
				again on a retransmit just to free the hash here but the
				saved message is ONLY the signature portion done in nowDoSke
				so the few hashSigAlg bytes and keysize done above during the
				hash are important to rewrite */
			psFree(hsMsgHash, ssl->hsPool);
			memcpy(c, ssl->ckeMsg, ssl->ckeSize);
			c += ssl->ckeSize;
		} else { /* closed below */
#endif /* USE_DTLS */
		pkaAfter = getPkaAfter(ssl);
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			pkaAfter->type = PKA_AFTER_RSA_SIG_GEN_ELEMENT;
		} else {
			pkaAfter->type = PKA_AFTER_RSA_SIG_GEN;
		}
#else /* !USE_TLS_1_2 */
		pkaAfter->type = PKA_AFTER_RSA_SIG_GEN;
#endif /* USE_TLS_1_2 */

		pkaAfter->inbuf = hsMsgHash;
		pkaAfter->outbuf = c;
		pkaAfter->data = pkiData;
		pkaAfter->inlen = hashSize;
		c += ssl->keys->privKey.keysize;
#ifdef USE_DTLS
		}
#endif /* USE_DTLS */
	}
#endif /* USE_RSA_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		/* Saved aside for pkaAfter_t */
		if ((hsMsgHash = psMalloc(ssl->hsPool, SHA384_HASH_SIZE)) == NULL) {
			return PS_MEM_FAIL;
		}
#endif
#ifdef USE_TLS_1_2
		if ((ssl->flags & SSL_FLAGS_TLS_1_2) &&
				(ssl->keys->cert->sigAlgorithm == OID_SHA256_ECDSA_SIG)) {
			hashSize = SHA256_HASH_SIZE;
			psSha256Init(&digestCtx.sha256);
			psSha256Update(&digestCtx.sha256, ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE);
			psSha256Update(&digestCtx.sha256, ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE);
			psSha256Update(&digestCtx.sha256, sigStart, (int32)(c - sigStart));
			psSha256Final(&digestCtx.sha256, hsMsgHash);
			*c++ = 0x4; /* SHA256 */
			*c++ = 0x3; /* ECDSA */
#ifdef USE_SHA384
		} else if ((ssl->flags & SSL_FLAGS_TLS_1_2) &&
				(ssl->keys->cert->sigAlgorithm == OID_SHA384_ECDSA_SIG)) {
			hashSize = SHA384_HASH_SIZE;
			psSha384Init(&digestCtx.sha384);
			psSha384Update(&digestCtx.sha384, ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE);
			psSha384Update(&digestCtx.sha384, ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE);
			psSha384Update(&digestCtx.sha384, sigStart, (int32)(c - sigStart));
			psSha384Final(&digestCtx.sha384, hsMsgHash);
			*c++ = 0x5; /* SHA384 */
			*c++ = 0x3; /* ECDSA */
#endif
#ifdef USE_SHA1
		} else if (ssl->minVer < TLS_1_2_MIN_VER ||
#ifdef USE_DTLS
					/* DTLS 1.0 is same at TLS 1.1 */
					ssl->minVer == DTLS_MIN_VER ||
#endif
					((ssl->flags & SSL_FLAGS_TLS_1_2) &&
					(ssl->keys->cert->sigAlgorithm == OID_SHA1_ECDSA_SIG))) {
			hashSize = SHA1_HASH_SIZE;
			psSha1Init(&digestCtx.sha1);
			psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx.sha1, sigStart, (int32)(c - sigStart));
			psSha1Final(&digestCtx.sha1, hsMsgHash);
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x3; /* ECDSA */
			}
#endif
		} else {
			psFree(hsMsgHash, ssl->hsPool);
			return PS_UNSUPPORTED_FAIL;
		}
#else
		hashSize = SHA1_HASH_SIZE;
		psSha1Init(&digestCtx.sha1);
		psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom,
			SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom,
			SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx.sha1, sigStart, (int32)(c - sigStart));
		psSha1Final(&digestCtx.sha1, hsMsgHash);
#endif

#ifdef USE_DTLS
		if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 1)) {
			/* It is not optimal to have run through the above digest updates
				again on a retransmit just to free the hash here but the
				saved message is ONLY the signature portion done in nowDoSke
				so the few hashSigAlg bytes and keysize done above during the
				hash are important to rewrite */
			psFree(hsMsgHash, ssl->hsPool);
			memcpy(c, ssl->ckeMsg, ssl->ckeSize);
			c += ssl->ckeSize;
		} else { /* closed below */
#endif /* USE_DTLS */

		if ((pkaAfter = getPkaAfter(ssl)) == NULL) {
			psTraceInfo("getPkaAfter error\n");
			return PS_PLATFORM_FAIL;
		}
		pkaAfter->inbuf = hsMsgHash;
		pkaAfter->outbuf = c;
		pkaAfter->data = pkiData;
		pkaAfter->inlen = hashSize;
		pkaAfter->type = PKA_AFTER_ECDSA_SIG_GEN;
		rc = ssl->keys->privKey.keysize + 8;
		/* NEGATIVE ECDSA - Adding spot for ONE 0x0 byte in ECDSA so we'll
			be right 50% of the time... 521 curve doesn't need */
		if (ssl->keys->privKey.keysize != 132) {
			rc += 1;
		}
		/* Above we added in the 8 bytes of overhead (2 sigLen, 1 SEQ,
			1 len (possibly 2!), 1 INT, 1 rLen, 1 INT, 1 sLen) and now
			subtract the first 3 bytes to see if the 1 len needs to be 2 */
		if (rc - 3 >= 128) {
			rc++;
		}
		pkaAfter->user = rc; /* outlen for later */
		c += rc;
#ifdef USE_DTLS
		}
#endif /* USE_DTLS */
	}
#endif /* USE_ECC_CIPHER_SUITE */

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_DHE_CIPHER_SUITE */

/******************************************************************************/
/*
	Server initiated rehandshake public API call.
*/
int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out,
								  uint32 *requiredLen)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize;
	int32_t			rc;

	*requiredLen = 0;
	psTraceHs("<<< Server creating HELLO_REQUEST message\n");
	if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED) {
		psTraceInfo("SSL flag error in matrixSslEncodeHelloRequest\n");
		return MATRIXSSL_ERROR;
	}
	if (!(ssl->flags & SSL_FLAGS_SERVER) || (ssl->hsState != SSL_HS_DONE)) {
		psTraceInfo("SSL state error in matrixSslEncodeHelloRequest\n");
		return MATRIXSSL_ERROR;
	}

	c = out->end;
	end = out->buf + out->size;
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen;
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_HELLO_REQUEST, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}

	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE, 0, messageSize,
			padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;

	return MATRIXSSL_SUCCESS;
}
#else /* USE_SERVER_SIDE_SSL */
int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out,
								  uint32 *requiredLen)
{
		psTraceInfo("Library not built with USE_SERVER_SIDE_SSL\n");
		return PS_UNSUPPORTED_FAIL;
}
#endif /* USE_SERVER_SIDE_SSL */


#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/*
	A fragmented write of the CERTIFICATE handhshake message.  This is the
	only handshake message that supports fragmentation because it is the only
	message where the 512byte plaintext max of the max_fragment extension can
	be exceeded.
*/
static int32 writeMultiRecordCertificate(ssl_t *ssl, sslBuf_t *out,
				int32 notEmpty, int32 totalClen, int32 lsize)
{
	psX509Cert_t	*cert, *future;
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize;
	uint32_t		certLen;
	int32_t			rc;
	int32			midWrite, midSizeWrite, countDown, firstOne = 1;

	c = out->end;
	end = out->buf + out->size;

	midSizeWrite = midWrite = certLen = 0;
	cert = NULL;

	while (totalClen > 0) {
		if (firstOne) {
			firstOne = 0;
			countDown = ssl->maxPtFrag;
			messageSize = totalClen + lsize + ssl->recordHeadLen + ssl->hshakeHeadLen;
			if ((rc = writeRecordHeader(ssl,
					SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG, SSL_HS_CERTIFICATE,
					&messageSize, &padLen, &encryptStart, end, &c)) < 0) {
				return rc;
			}
			/*	Write out the certs	*/
			*c = (unsigned char)(((totalClen + (lsize - 3)) & 0xFF0000) >> 16);
			c++;
			*c = ((totalClen + (lsize - 3)) & 0xFF00) >> 8; c++;
			*c = ((totalClen + (lsize - 3)) & 0xFF); c++;
			countDown -= ssl->hshakeHeadLen + 3;

			if (notEmpty) {
				cert = ssl->keys->cert;
				while (cert) {
					psAssert(cert->unparsedBin != NULL);
					certLen = cert->binLen;
					midWrite = 0;
					if (certLen > 0) {
						if (countDown <= 3) {
							/* Fragment falls right on cert len write.  Has
								to be at least one byte or countDown would have
								been 0 and got us out of here already*/
							*c = (unsigned char)((certLen & 0xFF0000) >> 16);
							c++; countDown--;
							midSizeWrite = 2;
							if (countDown != 0) {
								*c = (certLen & 0xFF00) >> 8; c++; countDown--;
								midSizeWrite = 1;
								if (countDown != 0) {
									*c = (certLen & 0xFF); c++; countDown--;
									midSizeWrite = 0;
								}
							}
							break;
						} else {
							*c = (unsigned char)((certLen & 0xFF0000) >> 16);
							c++;
							*c = (certLen & 0xFF00) >> 8; c++;
							*c = (certLen & 0xFF); c++;
							countDown -= 3;
						}
						midWrite = min(certLen, countDown);
						memcpy(c, cert->unparsedBin, midWrite);
						certLen -= midWrite;
						c += midWrite;
						totalClen -= midWrite;
						countDown -= midWrite;
						if (countDown == 0) {
							break;
						}
					}
					cert = cert->next;
				}
			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
					&c)) < 0) {
				return rc;
			}
			out->end = c;
		} else {
			/* Not-first fragments */
			if (!cert) {
				return PS_FAIL;
			}
			if (midSizeWrite > 0) {
				messageSize = midSizeWrite;
			} else {
				messageSize = 0;
			}
			if ((certLen + messageSize) > ssl->maxPtFrag) {
				messageSize += ssl->maxPtFrag;
			} else {
				messageSize += certLen;
				if (cert->next != NULL) {
					future = cert->next;
					while (future != NULL) {
						if (messageSize + future->binLen + 3 >
								(uint32)ssl->maxPtFrag) {
							messageSize = ssl->maxPtFrag;
							future = NULL;
						} else {
							messageSize += 3 + future->binLen;
							future = future->next;
						}

					}
				}
			}

			countDown = messageSize;
			messageSize += ssl->recordHeadLen;
			/* Second, etc... */
			if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE_FRAG,
					SSL_HS_CERTIFICATE, &messageSize, &padLen, &encryptStart,
					end, &c)) < 0) {
				return rc;
			}

			if (midSizeWrite > 0) {
				if (midSizeWrite == 2) {
					*c = (certLen & 0xFF00) >> 8; c++;
					*c = (certLen & 0xFF); c++;
					countDown -= 2;
				} else {
					*c = (certLen & 0xFF); c++;
					countDown -= 1;
				}
				midSizeWrite = 0;
			}

			if (countDown < certLen) {
				memcpy(c, cert->unparsedBin + midWrite, countDown);
				certLen -= countDown;
				c += countDown;
				totalClen -= countDown;
				midWrite += countDown;
				countDown = 0;
			} else {
				memcpy(c, cert->unparsedBin + midWrite, certLen);
				c += certLen;
				totalClen -= certLen;
				countDown -= certLen;
				certLen -= certLen;
			}

			while (countDown > 0) {
				cert = cert->next;
				if (!cert) {
					return PS_FAIL;
				}
				certLen = cert->binLen;
				midWrite = 0;
				if (countDown <= 3) {
					/* Fragment falls right on cert len write */
					*c = (unsigned char)((certLen & 0xFF0000) >> 16);
					c++; countDown--;
					midSizeWrite = 2;
					if (countDown != 0) {
						*c = (certLen & 0xFF00) >> 8; c++; countDown--;
						midSizeWrite = 1;
						if (countDown != 0) {
							*c = (certLen & 0xFF); c++; countDown--;
							midSizeWrite = 0;
						}
					}
					break;
				} else {
					*c = (unsigned char)((certLen & 0xFF0000) >> 16);
					c++;
					*c = (certLen & 0xFF00) >> 8; c++;
					*c = (certLen & 0xFF); c++;
					countDown -= 3;
				}
				midWrite = min(certLen, countDown);
				memcpy(c, cert->unparsedBin, midWrite);
				certLen -= midWrite;
				c += midWrite;
				totalClen -= midWrite;
				countDown -= midWrite;
				if (countDown == 0) {
					break;
				}

			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
					&c)) < 0) {
				return rc;
			}
			out->end = c;
		}
	}

	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */


#if defined(USE_OCSP) && defined(USE_SERVER_SIDE_SSL)
static int32 writeCertificateStatus(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	int32			rc;
	uint16_t		messageSize, ocspLen;


	/* Easier to exclude this message internally rather than futher muddy the
		numerous #ifdef and ssl_t tests in the caller */
	if (ssl->extFlags.status_request == 0) {
		return MATRIXSSL_SUCCESS;
	}

	psTraceHs("<<< Server creating CERTIFICATE_STATUS  message\n");

	c = out->end;
	end = out->buf + out->size;
	
	ocspLen = ssl->keys->OCSPResponseBufLen;
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + 4 + ocspLen;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_STATUS, &messageSize, &padLen, &encryptStart,
			end, &c)) < 0) {
		return rc;
	}
	/*  struct {
          CertificateStatusType status_type;
          select (status_type) {
              case ocsp: OCSPResponse;
          } response;
      } CertificateStatus; */
	*c = 0x1; c++;
	*c = (unsigned char)((ocspLen & 0xFF0000) >> 16); c++;
	*c = (ocspLen & 0xFF00) >> 8; c++;
	*c = (ocspLen & 0xFF); c++;
	memcpy(c, ssl->keys->OCSPResponseBuf, ocspLen);
	c += ocspLen;
	
	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_STATUS, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;

}
#endif /* OCSP && SERVER_SIDE_SSL */

/******************************************************************************/
/*
	Write a Certificate message.
	The encoding of the message is as follows:
		3 byte length of certificate data (network byte order)
		If there is no certificate,
			3 bytes of 0
		If there is one certificate,
			3 byte length of certificate + 3
			3 byte length of certificate
			certificate data
		For more than one certificate:
			3 byte length of all certificate data
			3 byte length of first certificate
			first certificate data
			3 byte length of second certificate
			second certificate data
	Certificate data is the base64 section of an X.509 certificate file
	in PEM format decoded to binary.  No additional interpretation is required.
*/
static int32 writeCertificate(ssl_t *ssl, sslBuf_t *out, int32 notEmpty)
{
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	psX509Cert_t	*cert;
	uint32			certLen;
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	int32			totalCertLen, lsize, i, rc;
	uint16_t		messageSize;

	psTraceStrHs("<<< %s creating CERTIFICATE  message\n",
		(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");

#ifdef USE_PSK_CIPHER_SUITE
/*
	Easier to exclude this message internally rather than futher muddy the
	numerous #ifdef and ssl->flags tests for DH, CLIENT_AUTH, and PSK states.
	A PSK or DHE_PSK cipher will never send this message
*/
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
		return MATRIXSSL_SUCCESS;
	}
#endif /* USE_PSK_CIPHER_SUITE */

	c = out->end;
	end = out->buf + out->size;

/*
	Determine total length of certs
*/
	totalCertLen = i = 0;
	if (notEmpty) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		cert = ssl->keys->cert;
		for (; cert != NULL; i++) {
			psAssert(cert->unparsedBin != NULL);
			totalCertLen += cert->binLen;
			cert = cert->next;
		}
#else
		return PS_DISABLED_FEATURE_FAIL;
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
	}

/*
	Account for the 3 bytes of certChain len for each cert and get messageSize
*/
	lsize = 3 + (i * 3);

	/* TODO DTLS: Make sure this maxPtFrag is consistent with the fragment
		extension and is not interfering with DTLS notions of fragmentation */
	if ((totalCertLen + lsize + ssl->hshakeHeadLen) > ssl->maxPtFrag) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		return writeMultiRecordCertificate(ssl, out, notEmpty,
				totalCertLen, lsize);
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
	} else {
		messageSize =
			ssl->recordHeadLen +
			ssl->hshakeHeadLen +
			lsize + totalCertLen;

		if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
				SSL_HS_CERTIFICATE, &messageSize, &padLen, &encryptStart,
				end, &c)) < 0) {
#ifdef USE_DTLS
			if (ssl->flags & SSL_FLAGS_DTLS) {
/*
				Is this the fragment case?
*/
				if (rc == DTLS_MUST_FRAG) {
					rc = dtlsWriteCertificate(ssl, totalCertLen, lsize, c);
					if (rc < 0) {
						return rc;
					}
					c += rc;
					out->end = c;
					return MATRIXSSL_SUCCESS;
				}
			}
#endif /* USE_DTLS */
			return rc;
		}

/*
		Write out the certs
*/
		*c = (unsigned char)(((totalCertLen + (lsize - 3)) & 0xFF0000) >> 16);
		c++;
		*c = ((totalCertLen + (lsize - 3)) & 0xFF00) >> 8; c++;
		*c = ((totalCertLen + (lsize - 3)) & 0xFF); c++;

#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (notEmpty) {
			cert = ssl->keys->cert;
			while (cert) {
				psAssert(cert->unparsedBin != NULL);
				certLen = cert->binLen;
				if (certLen > 0) {
					*c = (unsigned char)((certLen & 0xFF0000) >> 16); c++;
					*c = (certLen & 0xFF00) >> 8; c++;
					*c = (certLen & 0xFF); c++;
					memcpy(c, cert->unparsedBin, certLen);
					c += certLen;
				}
				cert = cert->next;
			}
		}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

		if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
				SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
				&c)) < 0) {
			return rc;
		}
		out->end = c;
	}
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/
/*
	Write the ChangeCipherSpec message.  It has its own message type
	and contains just one byte of value one.  It is not a handshake
	message, so it isn't included in the handshake hash.
*/
static int32_t writeChangeCipherSpec(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize;
	int32_t			rc;

	psTraceStrHs("<<< %s creating CHANGE_CIPHER_SPEC message\n",
		(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");

	c = out->end;
	end = out->buf + out->size;
	messageSize = ssl->recordHeadLen + 1;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC, 0,
			&messageSize, &padLen, &encryptStart, end, &c)) < 0) {
		return rc;
	}
	*c = 1; c++;

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC,
			0, messageSize, padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;

	return MATRIXSSL_SUCCESS;
}

static int32 postponeSnapshotHSHash(ssl_t *ssl, unsigned char *c, int32 sender)
{
	ssl->delayHsHash = c;
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		return TLS_HS_FINISHED_SIZE;
	} else {
#endif /* USE_TLS */
		return MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS
	}
#endif /* USE_TLS */

}

/******************************************************************************/
/*
	Write the Finished message
	The message contains the 36 bytes, the 16 byte MD5 and 20 byte SHA1 hash
	of all the handshake messages so far (excluding this one!)
*/
static int32 writeFinished(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize, verifyLen;
	int32_t			rc;

	psTraceStrHs("<<< %s creating FINISHED message\n",
		(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");

	c = out->end;
	end = out->buf + out->size;

	verifyLen = MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		verifyLen = TLS_HS_FINISHED_SIZE;
	}
#endif /* USE_TLS */
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + verifyLen;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE, SSL_HS_FINISHED,
			&messageSize, &padLen, &encryptStart, end, &c)) < 0) {
		return rc;
	}
/*
	Output the hash of messages we've been collecting so far into the buffer
*/
	c += postponeSnapshotHSHash(ssl, c, ssl->flags & SSL_FLAGS_SERVER);

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_FINISHED, messageSize, padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;


#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
/*
		Can't free the sec.cert buffer or close the handshake pool if
		using DTLS as we may be coming back around through this flight on
		a retransmit.  These frees are only taken care of once DTLS is
		positive the handshake has completed.
*/
		return MATRIXSSL_SUCCESS;
	}
#endif /* USE_DTLS */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	/* In client cases, there will be an outstanding PKA operation that
		could require the key from the cert so we can't free it yet */
	if (ssl->pkaAfter[0].type == 0) {
		if (ssl->sec.cert) {
			psX509FreeCert(ssl->sec.cert);
			ssl->sec.cert = NULL;
		}
	}
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
	return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
	Write an Alert message
	The message contains two bytes: AlertLevel and AlertDescription
*/
static int32 writeAlert(ssl_t *ssl, unsigned char level,
						unsigned char description, sslBuf_t *out,
						uint32 *requiredLen)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize;
	int32_t		rc;

#ifdef USE_SSL_HANDSHAKE_MSG_TRACE
	if (ssl->flags & SSL_FLAGS_SERVER) {
		psTraceHs("<<< Server");
	} else {
		psTraceHs("<<< Client");
	}
	if (description == SSL_ALERT_CLOSE_NOTIFY) {
		psTraceHs(" creating ALERT (CLOSE_NOTIFY) message\n");
	} else {
		psTraceHs(" creating ALERT message\n");
	}
#endif
	psTraceIntInfo("Creating alert %d\n", description);
	c = out->end;
	end = out->buf + out->size;
	messageSize = 2 + ssl->recordHeadLen;

	/* Force the alert to WARNING if the spec says the alert MUST be that */
	if (description == (unsigned char)SSL_ALERT_NO_RENEGOTIATION) {
		level = (unsigned char)SSL_ALERT_LEVEL_WARNING;
		ssl->err = SSL_ALERT_NONE;
	}

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_ALERT, 0, &messageSize,
			&padLen, &encryptStart, end, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}
	*c = level; c++;
	*c = description; c++;

	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_ALERT, 0, messageSize,
			padLen, encryptStart, out, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}
	out->end = c;
#ifdef USE_MATRIXSSL_STATS
	matrixsslUpdateStat(ssl, ALERT_SENT_STAT, (int32)(description));
#endif
	return MATRIXSSL_SUCCESS;
}

#ifdef USE_CLIENT_SIDE_SSL
#ifdef USE_TRUSTED_CA_INDICATION
static int32_t trustedCAindicationExtLen(psX509Cert_t *certs)
{
	psX509Cert_t	*next;
	int32_t			len;
	
	len = 0;
	/* Using the cert_sha1_hash identifier_type */
	next = certs;
	while (next) {
		len += 21;  /* 1 id_type, 20 hash */
		next = next->next;
	}
	return len;
}

static void writeTrustedCAindication(psX509Cert_t *certs, unsigned char **pp)
{
	psX509Cert_t	*next;
	int32_t			len;
	unsigned char	*p = *pp;
	
	len = trustedCAindicationExtLen(certs);
	*p = (len & 0xFF00) >> 8; p++;
	*p = len & 0xFF; p++;
	
	next = certs;
	while (next) {
		*p = 0x3; p++; /* cert_sha1_hash */
		memcpy(p, next->sha1CertHash, 20);
		p += 20;
		next = next->next;
	}
	psAssert((p - *pp) == (len + 2));
	*pp = p;
}
#endif /* USE_TRUSTED_CA_INDICATION */

/******************************************************************************/
/*
	Write out the ClientHello message to a buffer
*/
int32_t matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
		const uint16_t cipherSpecs[], uint8_t cipherSpecLen,
		uint32 *requiredLen, tlsExtension_t *userExt, sslSessOpts_t *options)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	int32			rc, t;
	uint16_t		messageSize, cipherLen, cookieLen, addRenegotiationScsv;
	tlsExtension_t	*ext;
	uint32			extLen;
	const sslCipherSpec_t	*cipherDetails;
	short			i, useTicket;
#ifdef USE_TLS_1_2
	uint16_t		sigHashLen, sigHashFlags;
	unsigned char	sigHash[18];	/* 2b len + 2b * 8 sig hash combos */
#endif
#ifdef USE_ECC_CIPHER_SUITE
	unsigned char	eccCurveList[32];
	uint8_t			curveListLen;
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_DTLS
	unsigned char	*extStart = NULL;
	int				cipherCount;
#endif

	psTraceHs("<<< Client creating CLIENT_HELLO  message\n");
	*requiredLen = 0;
	if (out == NULL || out->buf == NULL || ssl == NULL || options == NULL) {
		return PS_ARG_FAIL;
	}
	if (cipherSpecLen > 0 && (cipherSpecs == NULL || cipherSpecs[0] == 0)) {
		return PS_ARG_FAIL;
	}
	if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED) {
		psTraceInfo("SSL flag error in matrixSslEncodeClientHello\n");
		return MATRIXSSL_ERROR;
	}
	if (ssl->flags & SSL_FLAGS_SERVER || (ssl->hsState != SSL_HS_SERVER_HELLO &&
			ssl->hsState != SSL_HS_DONE &&
			ssl->hsState != SSL_HS_HELLO_REQUEST )) {
		psTraceInfo("SSL state error in matrixSslEncodeClientHello\n");
		return MATRIXSSL_ERROR;
	}

	sslInitHSHash(ssl);

	cookieLen = 0;
#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		/* TODO DTLS make sure a block cipher suite is being used */
		if (ssl->haveCookie) {
			cookieLen = ssl->cookieLen + 1; /* account for length byte */
		} else {
			cookieLen = 1; /* Always send the length (0) even if no cookie */
		}
		/* save for next time called for VERIFY_REQUEST response */
		ssl->cipherSpecLen = min(8, cipherSpecLen); /* 8 is arbitrary limit */
		for (cipherCount = 0; cipherCount < ssl->cipherSpecLen; cipherCount++) {
			ssl->cipherSpec[cipherCount] = cipherSpecs[cipherCount];
		}
	}
#endif
	/* If no resumption, clear the RESUMED flag in case the caller is
		attempting to bypass matrixSslEncodeRehandshake. */
	if (ssl->sessionIdLen <= 0) {
		ssl->flags &= ~SSL_FLAGS_RESUMED;
	}

	if (cipherSpecLen == 0 || cipherSpecs == NULL || cipherSpecs[0] == 0) {
		if ((cipherLen = sslGetCipherSpecListLen(ssl)) == 2) {
			psTraceInfo("No cipher suites enabled (or no key material)\n");
			return MATRIXSSL_ERROR;
		}
	} else {
		/* If ciphers are specified it is two bytes length and two bytes data */
		cipherLen = 2;
		for (i = 0; i < cipherSpecLen; i++) {
			if ((cipherDetails = sslGetCipherSpec(ssl, cipherSpecs[i]))
					== NULL) {
				psTraceIntInfo("Cipher suite not supported: %d\n",
					cipherSpecs[i]);
				return PS_UNSUPPORTED_FAIL;
			}
			cipherLen += 2;
		}
	}

	addRenegotiationScsv = 0;
#ifdef ENABLE_SECURE_REHANDSHAKES
	/* Initial CLIENT_HELLO will use the SCSV mechanism for greatest compat */
	if (ssl->myVerifyDataLen == 0) {
		cipherLen += 2; /* signalling cipher id 0x00FF */
		addRenegotiationScsv = 1;
	}
#endif
	if (options->fallbackScsv) {
		if (ssl->minVer == TLS_HIGHEST_MINOR) {
			/** If a client sets ClientHello.client_version to its highest
			supported protocol version, it MUST NOT include TLS_FALLBACK_SCSV.
			@see https://tools.ietf.org/html/rfc7507#section-4 */
			psTraceInfo("Cannot set fallbackScsv if using maximum supported TLS version.\n");
			return MATRIXSSL_ERROR;
		}
		if (ssl->sessionIdLen > 0) {
			/** when a client intends to resume a session and sets ClientHello.client_version
			to the protocol version negotiated for that session, it MUST NOT include
			TLS_FALLBACK_SCSV.
			@see https://tools.ietf.org/html/rfc7507#section-4 */
			psTraceInfo("Cannot set fallbackScsv if attempting to resume a connection.\n");
			return MATRIXSSL_ERROR;
		}
		cipherLen += 2; /* signalling cipher id 0x5600 */
		ssl->extFlags.req_fallback_scsv = 1;
	} else {
		/** If a client sends a ClientHello.client_version containing a lower
		value than the latest (highest-valued) version supported by the
		client, it SHOULD include the TLS_FALLBACK_SCSV.
		@see https://tools.ietf.org/html/rfc7507#section-4
		We warn because this is a SHOULD not a MUST.
		@security The only reason (outside testing) that we should propose a TLS version
		lower than what we support is if we had already tried to negotiate the highest
		version but the server did not support it. In that case, the fallbackScsv
		option should have been specified to mitigate version rollback attacks.
		*/
		if (ssl->minVer < TLS_HIGHEST_MINOR) {
			psTraceInfo("Warning, if this is a fallback connection, set fallbackScsv?\n");
		}
	}

	/* Calculate the size of the message up front, and write header */
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		5 + SSL_HS_RANDOM_SIZE + ssl->sessionIdLen + cipherLen + cookieLen;

#ifdef USE_ZLIB_COMPRESSION
	messageSize += 1;
#endif

	/* Extension lengths */
	extLen = 0;

	/* Max Fragment extension request */
	ssl->maxPtFrag = SSL_MAX_PLAINTEXT_LEN;
	if (ssl->minVer > 0 && (options->maxFragLen > 0) &&
			(options->maxFragLen < SSL_MAX_PLAINTEXT_LEN)) {
		if (options->maxFragLen == 0x200 ||
				options->maxFragLen == 0x400 ||
				options->maxFragLen == 0x800 ||
				options->maxFragLen == 0x1000) {
			extLen = 2 + 5; /* 2 for total ext len + 5 for ourselves */
			ssl->maxPtFrag = options->maxFragLen;
			/* Also indicate that we're requesting a different plaintext size */
			ssl->maxPtFrag |= 0x10000;
		} else {
			psTraceInfo("Unsupported maxFragLen value to session options\n");
			return PS_ARG_FAIL;
		}
	}

	if (options->truncHmac) {
		if (extLen == 0) {
			extLen = 2; /* First extension found so total len */
		}
		extLen += 4; /* empty "extension_data" */
	}
	
	if (options->extendedMasterSecret >= 0) {
		if (extLen == 0) {
			extLen = 2; /* First extension found so total len */
		}
		extLen += 4; /* empty extension */
	}

#ifdef USE_TRUSTED_CA_INDICATION
	if (options->trustedCAindication) {
		if (extLen == 0) {
			extLen = 2; /* First extension found so total len */
		}
		/* Magic 4 is extension id and length as usual */
		extLen += trustedCAindicationExtLen(ssl->keys->CAcerts) + 4;
	}
#endif

#ifdef ENABLE_SECURE_REHANDSHAKES
	/* Subsequent CLIENT_HELLOs must use a populated RenegotiationInfo extension */
	if (ssl->myVerifyDataLen != 0) {
		if (extLen == 0) {
			extLen = 2; /* First extension found so total len */
		}
		extLen += ssl->myVerifyDataLen + 5; /* 5 type/len/len */
	}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
	curveListLen = 0;
	if (eccSuitesSupported(ssl, cipherSpecs, cipherSpecLen)) {
		/*	Getting the curve list from crypto directly */
		curveListLen = sizeof(eccCurveList);
		if (options->ecFlags) {
			userSuppliedEccList(eccCurveList, &curveListLen, options->ecFlags);
		} else {
			/* Use all that are enabled */
			psGetEccCurveIdList(eccCurveList, &curveListLen);
		}
		if (curveListLen > 0) {
			if (extLen == 0) {
				extLen = 2; /* First extension found so total len */
			}
			/* EXT_ELLIPTIC_CURVE */
			extLen += curveListLen + 6; /* 2 id, 2 for ext len, 2 len */
			/* EXT_ELLIPTIC_POINTS - hardcoded to 'uncompressed' support */
			extLen += 6; /* 00 0B 00 02 01 00 */
		}
	}
#endif /* USE_ECC_CIPHER_SUITE */

	useTicket = 0;
#ifdef USE_STATELESS_SESSION_TICKETS
	if (options && options->ticketResumption == 1) {
		useTicket = 1;
	}
	if (useTicket && ssl->sid) {
		if (extLen == 0) {
			extLen = 2;  /* First extension found so total len */
		}
		extLen += 4; /* 2 type, 2 length */
		if (ssl->sid->sessionTicketLen > 0 &&
				ssl->sid->sessionTicketState == SESS_TICKET_STATE_USING_TICKET) {
			extLen += ssl->sid->sessionTicketLen;
		}
	}
#endif

#ifdef USE_OCSP
	if (options && options->OCSPstapling == 1) {
		if (extLen == 0) {
			extLen = 2;  /* First extension found so total len */
		}
		/* Currently only supporting an empty status_request extension */
		extLen += 9;
	}
#endif
	
#ifdef USE_TLS_1_2
	/*
		TLS 1.2 clients must add the SignatureAndHashAlgorithm extension,
		(although not sending them implies SHA-1, and it's unused for
		non-certificate based ciphers like PSK).
		Sending all the algorithms that are enabled at compile time.
		Always sends SHA256 since it must be enabled for TLS 1.2

		enum {
		  none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
		  sha512(6), (255)
		} HashAlgorithm;
		enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SigAlgorithm;
	*/

#define ADD_SIG_HASH(A,B) \
{\
	sigHashFlags |= HASH_SIG_MASK(A,B);\
	sigHash[sigHashLen] = A; \
	sigHash[sigHashLen + 1] = B; \
	sigHashLen += 2; \
}
	sigHashFlags = 0;
	sigHashLen = 2;		/* Length of buffer, Start with 2b len */

#ifdef USE_ECC
	/* Always support SHA256 */
	ADD_SIG_HASH(HASH_SIG_SHA256, HASH_SIG_ECDSA);

#ifdef USE_SHA512
	ADD_SIG_HASH(HASH_SIG_SHA512, HASH_SIG_ECDSA);
#endif
#ifdef USE_SHA384
	ADD_SIG_HASH(HASH_SIG_SHA384, HASH_SIG_ECDSA);
#endif
#ifdef USE_SHA1
	ADD_SIG_HASH(HASH_SIG_SHA1, HASH_SIG_ECDSA);
#endif
#endif /* USE_ECC */

#ifdef USE_RSA
	/* Always support SHA256 */
	ADD_SIG_HASH(HASH_SIG_SHA256, HASH_SIG_RSA);

#ifdef USE_SHA512
	ADD_SIG_HASH(HASH_SIG_SHA512, HASH_SIG_RSA);
#endif
#ifdef USE_SHA384
	ADD_SIG_HASH(HASH_SIG_SHA384, HASH_SIG_RSA);
#endif
#ifdef USE_SHA1
	ADD_SIG_HASH(HASH_SIG_SHA1, HASH_SIG_RSA);
#endif
#endif /* USE_RSA */

#ifdef USE_ONLY_PSK_CIPHER_SUITE
	/* Have to  pass something */
	ADD_SIG_HASH(HASH_SIG_SHA1, HASH_SIG_RSA);
#endif

#undef ADD_SIG_HASH

	/* First two bytes is the byte count of remaining data */
	/* Note that in PSK mode, there will be no supported sig alg hashes */
	sigHash[0] = 0x0;
	sigHash[1] = sigHashLen - 2;	/* 2 b len*/

	if (extLen == 0) {
		extLen = 2;  /* First extension found so total len */
	}
	extLen += 2 + 2 + sigHashLen; /* 2 ext type, 2 ext length */
	
	/* On the client side, the value is set to the algorithms offered */
	ssl->hashSigAlg = sigHashFlags;

#endif /* USE_TLS_1_2 */

	/* Add any user-provided extensions */
	ext = userExt;
	if (ext && extLen == 0) {
		extLen = 2; /* Start with the initial len */
	}
	while (ext) {
		extLen += ext->extLen + 4; /* +4 for type and length of each */
		ext = ext->next;
	}

#ifdef USE_DTLS
	if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->helloExtLen > 0)) {
		/* Override all the extension calculations and just grab what was
			sent the first time.  Can't rebuild because there is no good line
			between the extensions we add and the extensions the user adds and
			no user extensions will have been passed in here on a retransmit */
		extLen = ssl->helloExtLen;
	}
#endif
	messageSize += extLen;

	c = out->end;
	end = out->buf + out->size;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CLIENT_HELLO, &messageSize, &padLen, &encryptStart,
			end, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}

	t = 1;
#ifdef USE_DTLS
/*
	Test if this is DTLS response to the HelloVerify server message.
	If so, we use the exact same one (+cookie) as before to prove to the
	server we are legit.  The only thing that should change in this message
	is the client random so we make sure to use the original one

	  struct {
		ProtocolVersion client_version;
		Random random;
		SessionID session_id;
		opaque cookie<0..32>;                             // New field
		CipherSuite cipher_suites<2..2^16-1>;
		CompressionMethod compression_methods<1..2^8-1>;
	  } ClientHello;
*/
	if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->haveCookie)) {
		t = 0;
	}
	/* Also test for retransmit */
	if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 1)) {
		t = 0;
	}
#endif

	if (t) {
	/**	@security RFC says to set the first 4 bytes to time, but best common practice is
		to use full 32 bytes of random. This is forward looking to TLS 1.3, and also works
		better for embedded platforms and FIPS secret key material.
		@see https://www.ietf.org/mail-archive/web/tls/current/msg09861.html */
#ifdef SEND_HELLO_RANDOM_TIME
		/*	First 4 bytes of the serverRandom are the unix time to prevent
			replay attacks, the rest are random */
		t = psGetTime(NULL, ssl->userPtr);
		ssl->sec.clientRandom[0] = (unsigned char)((t & 0xFF000000) >> 24);
		ssl->sec.clientRandom[1] = (unsigned char)((t & 0xFF0000) >> 16);
		ssl->sec.clientRandom[2] = (unsigned char)((t & 0xFF00) >> 8);
		ssl->sec.clientRandom[3] = (unsigned char)(t & 0xFF);
		if ((rc = matrixCryptoGetPrngData(ssl->sec.clientRandom + 4,
				SSL_HS_RANDOM_SIZE - 4, ssl->userPtr)) < PS_SUCCESS) {
			return rc;
		}
#else
		if ((rc = matrixCryptoGetPrngData(ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE, ssl->userPtr)) < PS_SUCCESS) {
			return rc;
		}
#endif
	}
/*
	First two fields in the ClientHello message are the maximum major
	and minor SSL protocol versions we support.
*/
	*c = ssl->majVer; c++;
	*c = ssl->minVer; c++;

/*
	The next 32 bytes are the server's random value, to be combined with
	the client random and premaster for key generation later
*/
	memcpy(c, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
	c += SSL_HS_RANDOM_SIZE;
/*
	The next data is a single byte containing the session ID length,
	and up to 32 bytes containing the session id.
	If we are asking to resume a session, then the sessionId would have
	been set at session creation time.
*/
	*c = (unsigned char)ssl->sessionIdLen; c++;
	if (ssl->sessionIdLen > 0) {
		memcpy(c, ssl->sessionId, ssl->sessionIdLen);
		c += ssl->sessionIdLen;
#ifdef USE_MATRIXSSL_STATS
		matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
	}
#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		if (ssl->haveCookie) {
			*c = (unsigned char)ssl->cookieLen; c++;
			memcpy(c, ssl->cookie, ssl->cookieLen);
			c += ssl->cookieLen;
		} else {
			/*	This condition is an empty cookie client hello.  Still must
				send a zero length specifier. */
			*c = 0; c++;
		}
	}
#endif
/*
	Write out the length and ciphers we support
	Client can request a single specific cipher in the cipherSpec param
*/
	if (cipherSpecLen == 0 || cipherSpecs == NULL || cipherSpecs[0] == 0) {
		if ((rc = sslGetCipherSpecList(ssl, c, (int32)(end - c), addRenegotiationScsv)) < 0){
			return SSL_FULL;
		}
		c += rc;
	} else {
		if ((int32)(end - c) < cipherLen) {
			return SSL_FULL;
		}
		cipherLen -= 2; /* don't include yourself */
		*c = (cipherLen & 0xFF00) >> 8; c++;
		*c = cipherLen & 0xFF; c++;
		/* Safe to include all cipher suites in the list because they were
			checked above */
		for (i = 0; i < cipherSpecLen; i++) {
			*c = (cipherSpecs[i] & 0xFF00) >> 8; c++;
			*c = cipherSpecs[i] & 0xFF; c++;
		}
#ifdef ENABLE_SECURE_REHANDSHAKES
		if (addRenegotiationScsv == 1) {
			ssl->extFlags.req_renegotiation_info = 1;
			*c = ((TLS_EMPTY_RENEGOTIATION_INFO_SCSV & 0xFF00) >> 8); c++;
			*c = TLS_EMPTY_RENEGOTIATION_INFO_SCSV  & 0xFF; c++;
		}
#endif
	    if (ssl->extFlags.req_fallback_scsv) {
			*c = (TLS_FALLBACK_SCSV >> 8) & 0xFF; c++;
			*c = TLS_FALLBACK_SCSV & 0xFF; c++;
		}
	}
/*
	Compression.  Length byte and 0 for 'none' and possibly 1 for zlib
*/
#ifdef USE_ZLIB_COMPRESSION
	*c = 2; c++;
	*c = 0; c++;
	*c = 1; c++;
#else
	*c = 1; c++;
	*c = 0; c++;
#endif

#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		/* Need to save aside (or recall) extensions because the resend
			path doesn't go	back to the user to rebuild them. */
		extStart = c;
	}
#endif
/*
	Extensions
*/
	if (extLen > 0) {
		extLen -= 2; /* Don't include yourself in the length */
		*c = (extLen & 0xFF00) >> 8; c++; /* Total list length */
		*c = extLen & 0xFF; c++;

		/*	User-provided extensions.  Do them first in case something
			like a ServerNameIndication is here that will influence a
			later extension such as the sigHashAlgs */
		if (userExt) {
			ext = userExt;
			while (ext) {
				switch (ext->extType) {
				case EXT_SNI:
					ssl->extFlags.req_sni = 1;
					break;
				case EXT_ALPN:
					ssl->extFlags.req_alpn = 1;
#ifdef USE_ALPN
					if (ssl->extCb == NULL) {
						psTraceInfo("WARNING: Providing ALPN extension without "
							"registering extension callback to receive server reply\n");
					}
#endif
					break;
				default:
					break;
				}
				*c = (ext->extType & 0xFF00) >> 8; c++;
				*c = ext->extType & 0xFF; c++;

				*c = (ext->extLen & 0xFF00) >> 8; c++;
				*c = ext->extLen & 0xFF; c++;
				if (ext->extLen == 1 && ext->extData == NULL) {
					memset(c, 0x0, 1);
				} else {
					memcpy(c, ext->extData, ext->extLen);
				}
				c += ext->extLen;
				ext = ext->next;
			}
		}

		/* Max fragment extension */
		if (ssl->maxPtFrag & 0x10000) {
			ssl->extFlags.req_max_fragment_len= 1;
			*c = 0x00; c++;
			*c = 0x01; c++;
			*c = 0x00; c++;
			*c = 0x01; c++;
			if (options->maxFragLen == 0x200) {
				*c = 0x01; c++;
			} else if (options->maxFragLen == 0x400) {
				*c = 0x02; c++;
			} else if (options->maxFragLen == 0x800) {
				*c = 0x03; c++;
			} else if (options->maxFragLen == 0x1000) {
				*c = 0x04; c++;
			}
		}
#ifdef ENABLE_SECURE_REHANDSHAKES
/*
		Populated RenegotiationInfo extension
*/
		if (ssl->myVerifyDataLen > 0) {
			ssl->extFlags.req_renegotiation_info = 1;
			*c = (EXT_RENEGOTIATION_INFO & 0xFF00) >> 8; c++;
			*c = EXT_RENEGOTIATION_INFO & 0xFF; c++;
			*c = ((ssl->myVerifyDataLen + 1) & 0xFF00) >> 8; c++;
			*c = (ssl->myVerifyDataLen + 1) & 0xFF; c++;
			*c = ssl->myVerifyDataLen & 0xFF; c++;
			memcpy(c, ssl->myVerifyData, ssl->myVerifyDataLen);
			c += ssl->myVerifyDataLen;
		}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
		if (curveListLen > 0) {
			ssl->extFlags.req_elliptic_curve = 1;
			*c = (EXT_ELLIPTIC_CURVE & 0xFF00) >> 8; c++;
			*c = EXT_ELLIPTIC_CURVE & 0xFF; c++;
			*c = ((curveListLen + 2) & 0xFF00) >> 8; c++;
			*c = (curveListLen + 2) & 0xFF; c++;
			*c = 0; c++;	/* High byte always zero */
			*c = curveListLen & 0xFF; c++;
			memcpy(c, eccCurveList, curveListLen);
			c += curveListLen;

			ssl->extFlags.req_elliptic_points = 1;
			*c = (EXT_ELLIPTIC_POINTS & 0xFF00) >> 8; c++;
			*c = EXT_ELLIPTIC_POINTS & 0xFF; c++;
			*c = 0x00; c++;
			*c = 0x02; c++;
			*c = 0x01; c++;
			*c = 0x00; c++;
		}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_TLS_1_2
		/* Will always exist in some form if TLS 1.2 is enabled */
		ssl->extFlags.req_signature_algorithms = 1;
		*c = (EXT_SIGNATURE_ALGORITHMS & 0xFF00) >> 8; c++;
		*c = EXT_SIGNATURE_ALGORITHMS & 0xFF; c++;
		*c = (sigHashLen & 0xFF00) >> 8; c++;
		*c = sigHashLen & 0xFF; c++;
		memcpy(c, sigHash, sigHashLen);
		c += sigHashLen;
#endif

#ifdef USE_STATELESS_SESSION_TICKETS
		/* If ticket exists and is marked "USING" then it can be used */
		if (useTicket && ssl->sid) {
			if (ssl->sid->sessionTicketLen == 0 ||
				ssl->sid->sessionTicketState != SESS_TICKET_STATE_USING_TICKET) {

				ssl->extFlags.req_session_ticket = 1;
				*c = (EXT_SESSION_TICKET & 0xFF00) >> 8; c++;
				*c = EXT_SESSION_TICKET & 0xFF; c++;
				*c = 0x00; c++;
				*c = 0x00; c++;
				ssl->sid->sessionTicketState = SESS_TICKET_STATE_SENT_EMPTY;
			} else {
				ssl->extFlags.req_session_ticket = 1;
				*c = (EXT_SESSION_TICKET & 0xFF00) >> 8; c++;
				*c = EXT_SESSION_TICKET & 0xFF; c++;
				*c = (ssl->sid->sessionTicketLen & 0xFF00) >> 8; c++;
				*c = ssl->sid->sessionTicketLen & 0xFF; c++;
				memcpy(c, ssl->sid->sessionTicket, ssl->sid->sessionTicketLen);
				c += ssl->sid->sessionTicketLen;
				ssl->sid->sessionTicketState = SESS_TICKET_STATE_SENT_TICKET;
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
			}
		}
#endif /* USE_STATELESS_SESSION_TICKETS	*/

#ifdef USE_OCSP
		if (options->OCSPstapling) {
			ssl->extFlags.req_status_request = 1;
			*c = (EXT_STATUS_REQUEST & 0xFF00) >> 8; c++;
			*c = EXT_STATUS_REQUEST & 0xFF; c++;
			*c = 0x00; c++;
			*c = 0x05; c++;
			*c = 0x01; c++;
			*c = 0x00; c++;
			*c = 0x00; c++;
			*c = 0x00; c++;
			*c = 0x00; c++;
		}
#endif

#ifdef USE_TRUSTED_CA_INDICATION
		if (options->trustedCAindication) {
			*c = (EXT_TRUSTED_CA_KEYS & 0xFF00) >> 8; c++;
			*c = EXT_TRUSTED_CA_KEYS & 0xFF; c++;
			writeTrustedCAindication(ssl->keys->CAcerts, &c);
		}
#endif
		if (options->truncHmac) {
			ssl->extFlags.req_truncated_hmac = 1;
			*c = (EXT_TRUNCATED_HMAC & 0xFF00) >> 8; c++;
			*c = EXT_TRUNCATED_HMAC & 0xFF; c++;
			*c = 0x00; c++;
			*c = 0x00; c++;
		}
		
		if (options->extendedMasterSecret >= 0) {
			if (options->extendedMasterSecret > 0) {
				/* User is REQUIRING the server to support it */
				ssl->extFlags.require_extended_master_secret = 1;
			}
			ssl->extFlags.req_extended_master_secret = 1;
			*c = (EXT_EXTENDED_MASTER_SECRET & 0xFF00) >> 8; c++;
			*c = EXT_EXTENDED_MASTER_SECRET & 0xFF; c++;
			*c = 0x00; c++;
			*c = 0x00; c++;
		}

	}

#ifdef USE_DTLS
	if ((ssl->flags & SSL_FLAGS_DTLS) && (extLen > 0)) {
		if (ssl->helloExtLen == 0) {
			ssl->helloExtLen = (int32)(c - extStart);
			ssl->helloExt = psMalloc(ssl->hsPool, ssl->helloExtLen);
			if (ssl->helloExt == NULL) {
				return SSL_MEM_ERROR;
			}
			memcpy(ssl->helloExt, extStart, ssl->helloExtLen);
		} else {
			/* Forget the extensions we wrote above and use the saved ones */
			c = extStart;
			memcpy(c, ssl->helloExt, ssl->helloExtLen);
			c+= ssl->helloExtLen;
		}
	}
#endif /* USE_DTLS */

	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE, 0, messageSize,
			padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;

/*
	Could be a rehandshake so clean	up old context if necessary.
	Always explicitly set state to beginning.
*/
	if (ssl->hsState == SSL_HS_DONE) {
		sslResetContext(ssl);
	}

/*
	Could be a rehandshake on a previous connection that used client auth.
	Reset our local client auth state as the server is always the one
	responsible for initiating it.
*/
	ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
	ssl->hsState = SSL_HS_SERVER_HELLO;

#ifdef USE_MATRIXSSL_STATS
	matrixsslUpdateStat(ssl, CH_SENT_STAT, 1);
#endif
	return MATRIXSSL_SUCCESS;
	
}

/******************************************************************************/
/*
	Write a ClientKeyExchange message.
*/
static int32 writeClientKeyExchange(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		keyLen, messageSize, explicitLen;
	int32_t			rc;
	pkaAfter_t		*pkaAfter;
#ifdef USE_PSK_CIPHER_SUITE
	unsigned char	*pskId, *pskKey;
	uint8_t			pskIdLen;
#endif /* USE_PSK_CIPHER_SUITE */
	void			*pkiData = ssl->userPtr;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_ECC_CIPHER_SUITE) || defined(USE_RSA_CIPHER_SUITE)
	psPool_t		*pkiPool = NULL;
#endif /* USE_ECC_CIPHER_SUITE || USE_RSA_CIPHER_SUITE */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

	psTraceHs("<<< Client creating CLIENT_KEY_EXCHANGE message\n");

	c = out->end;
	end = out->buf + out->size;
	messageSize = keyLen = 0;

	if ((pkaAfter = getPkaAfter(ssl)) == NULL) {
		return PS_PLATFORM_FAIL;
	}

#ifdef USE_PSK_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
		/* Get the key id to send in the clientKeyExchange message.  */
		if (matrixSslPskGetKeyId(ssl, &pskId, &pskIdLen,
				ssl->sec.hint, ssl->sec.hintLen) < 0) {
			psFree(ssl->sec.hint, ssl->hsPool); ssl->sec.hint = NULL;
			return MATRIXSSL_ERROR;
		}
#ifdef USE_DTLS
		/* Need to save for retransmit? */
		if (!(ssl->flags & SSL_FLAGS_DTLS)) {
			psFree(ssl->sec.hint, ssl->hsPool); ssl->sec.hint = NULL;
		}
#else
		psFree(ssl->sec.hint, ssl->hsPool); ssl->sec.hint = NULL;
#endif

	}
#endif /* USE_PSK_CIPHER_SUITE */

/*
	Determine messageSize for the record header
*/
#ifdef USE_DHE_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS && ssl->retransmit == 1) {
			keyLen = ssl->ckeSize;
		} else {
#endif
#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			keyLen = (ssl->sec.eccKeyPriv->curve->size * 2) + 2;
		} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
			keyLen += ssl->sec.dhKeyPriv->size;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
		}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_DTLS
		}
#endif
#ifdef USE_PSK_CIPHER_SUITE
/*
		Leave keyLen as the native DH or RSA key to keep the write
		logic untouched below.  Just directly increment the messageSize
		for the PSK id information
*/
		/* DHE_PSK suites */
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			messageSize += pskIdLen + 2;
		}
#endif /* USE_PSK_CIPHER_SUITE */
	} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
		/* basic PSK suites */
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			messageSize += pskIdLen; /* don't need the +2 */
		} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->cipher->type == CS_ECDH_ECDSA ||
				ssl->cipher->type == CS_ECDH_RSA) {
			keyLen = (ssl->sec.cert->publicKey.key.ecc.curve->size * 2) + 2;
		} else {
#endif /* USE_ECC_CIPHER_SUITE */
			/* Standard RSA auth suites */
			keyLen = ssl->sec.cert->publicKey.keysize;
#ifdef USE_ECC_CIPHER_SUITE
		}
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* !USE_PSK_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
		}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
	}
#endif /* USE_DHE_CIPHER_SUITE */

	messageSize += ssl->recordHeadLen + ssl->hshakeHeadLen + keyLen;
	explicitLen = 0;
#ifdef USE_TLS
	/*	Must always add the key size length to the message */
	if (ssl->flags & SSL_FLAGS_TLS) {
		messageSize += 2;
		explicitLen = 1;
	}
#endif /* USE_TLS */

#ifdef USE_DHE_CIPHER_SUITE
	/*	DHE must include the explicit key size regardless of protocol */
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
		if (explicitLen == 0) {
			messageSize += 2;
			explicitLen = 1;
		}
	}
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
	/* Standard PSK suite in SSLv3 will not have accounted for +2 yet */
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
		if (explicitLen == 0) {
			messageSize += 2;
			explicitLen = 1;
		}
	}
#endif

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
		if (explicitLen == 1) {
			messageSize -= 2; /* For some reason, ECC CKE doesn't use 2 len */
			explicitLen = 0;
		}
	}
#endif /* USE_ECC_CIPHER_SUITE */

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CLIENT_KEY_EXCHANGE, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		return rc;
	}

/*
	ClientKeyExchange message contains the encrypted premaster secret.
	The base premaster is the original SSL protocol version we asked for
	followed by 46 bytes of random data.
	These 48 bytes are padded to the current RSA key length and encrypted
	with the RSA key.
*/
	if (explicitLen == 1) {
#ifdef USE_PSK_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			*c = (pskIdLen & 0xFF00) >> 8; c++;
			*c = (pskIdLen & 0xFF); c++;
/*
			The cke message begins with the ID of the desired key
*/
			memcpy(c, pskId, pskIdLen);
			c += pskIdLen;
		}
#endif /* USE_PSK_CIPHER_SUITE */
/*
		Add the two bytes of key length
*/
		if (keyLen > 0) {
			*c = (keyLen & 0xFF00) >> 8; c++;
			*c = (keyLen & 0xFF); c++;
		}
	}

#ifdef USE_DTLS
	if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 1)) {
/*
		 Retransmit case.  Must use the cached encrypted msg from
		 the first flight to keep handshake hash same
*/
		memcpy(c, ssl->ckeMsg, ssl->ckeSize);
		c += ssl->ckeSize;
	} else {
#endif /* USE_DTLS */

#ifdef USE_DHE_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
		/* For DHE, the clientKeyExchange message is simply the public
			key for this client.  No public/private encryption here
			because there is no authentication (so not necessary or
			meaningful to activate public cipher). Just check ECDHE or DHE */
#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			keyLen--;
			*c = keyLen & 0xFF; c++;
			if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv, c,
					&keyLen) < 0) {
				return MATRIXSSL_ERROR;
			}
			psAssert(keyLen == (uint32)*(c - 1));
#ifdef USE_DTLS
			if (ssl->flags & SSL_FLAGS_DTLS) {
				/* Set aside retransmit for this case here since there is
					nothing happening in nowDoCke related to the handshake
					message output */
				ssl->ckeSize = keyLen + 1;
				ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize);
				if (ssl->ckeMsg == NULL) {
					return SSL_MEM_ERROR;
				}
				memcpy(ssl->ckeMsg, c - 1, ssl->ckeSize);
			}
#endif
			c += keyLen;
/*
			Generate premaster and free ECC key material
*/
			ssl->sec.premasterSize = ssl->sec.eccKeyPriv->curve->size;
			ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}

			/* Schedule EC secret generation */
			pkaAfter->type = PKA_AFTER_ECDH_SECRET_GEN;
			pkaAfter->inbuf = NULL;
			pkaAfter->inlen = 0;
			pkaAfter->outbuf = ssl->sec.premaster;
			pkaAfter->data = pkiData;

		} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
		{
			uint16_t	dhLen = end - c;
			/* Write out the public key part of our private key */
			if (psDhExportPubKey(ssl->hsPool, ssl->sec.dhKeyPriv, c, &dhLen) < 0) {
				return MATRIXSSL_ERROR;
			}
			psAssert(dhLen == keyLen);
		}
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
			/* Set aside retransmit for this case here since there is
				nothing happening in nowDoCke related to the handshake
				message output */
			ssl->ckeSize = keyLen;
			ssl->ckeMsg = psMalloc(ssl->hsPool, ssl->ckeSize);
			if (ssl->ckeMsg == NULL) {
				return SSL_MEM_ERROR;
			}
			memcpy(ssl->ckeMsg, c, ssl->ckeSize);
		}
#endif
		c += keyLen;

		/* Schedule DH secret gen.*/
		pkaAfter->type = PKA_AFTER_DH_KEY_GEN;
		pkaAfter->inbuf = NULL;
		pkaAfter->inlen = 0;
#ifdef USE_PSK_CIPHER_SUITE
		/*  Borrowing the inbuf and inlen params to hold pskId information */
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			pkaAfter->inlen = pskIdLen;
			if ((pkaAfter->inbuf = psMalloc(ssl->hsPool, pskIdLen)) == NULL) {
				return PS_MEM_FAIL;
			}
			memcpy(pkaAfter->inbuf, pskId, pskIdLen);
		}
#endif
		pkaAfter->outbuf = ssl->sec.premaster;
		pkaAfter->user = ssl->sec.premasterSize;
		pkaAfter->data = pkiData;

#endif /* REQUIRE_DH_PARAMS	*/
#ifdef USE_ECC_CIPHER_SUITE
		}
#endif /* USE_ECC_CIPHER_SUITE */

	} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
		Create the premaster for basic PSK suites
*/
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
			RFC4279: The premaster secret is formed as follows: if the PSK is
			N octets long, concatenate a uint16 with the value N, N zero octets,
			a second uint16 with the value N, and the PSK itself.
			@note pskIdLen will contain the length of pskKey after this call.
*/
			matrixSslPskGetKey(ssl, pskId, pskIdLen, &pskKey, &pskIdLen);
			if (pskKey == NULL) {
				return MATRIXSSL_ERROR;
			}
			ssl->sec.premasterSize = (pskIdLen * 2) + 4;
			ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}
			memset(ssl->sec.premaster, 0, ssl->sec.premasterSize);
			ssl->sec.premaster[0] = (pskIdLen & 0xFF00) >> 8;
			ssl->sec.premaster[1] = (pskIdLen & 0xFF);
			/* memset to 0 handled middle portion */
			ssl->sec.premaster[2 + pskIdLen] = (pskIdLen & 0xFF00) >> 8;
			ssl->sec.premaster[3 + pskIdLen] = (pskIdLen & 0xFF);
			memcpy(&ssl->sec.premaster[4 + pskIdLen], pskKey, pskIdLen);
			/*	Now that we've got the premaster secret, derive the various
				symmetrics.  Correct this is only a PSK requirement here because
				there is no pkaAfter to call it later

				However, if extended_master_secret is being used we must delay
				the master secret creation until the CKE handshake message has
				been added to the rolling handshake hash.  Key generation will
				be done in encryptRecord */
			if (ssl->extFlags.extended_master_secret == 0) {
				if ((rc = sslCreateKeys(ssl)) < 0) {
					return rc;
				}
			}

		} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
			/* Non-DHE cases below */
#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->cipher->type == CS_ECDH_ECDSA ||
					ssl->cipher->type == CS_ECDH_RSA) {

				/* Write key len */
				keyLen--;
				*c = keyLen & 0xFF; c++;

				/* Tricky case where a key generation, public key write, and
					then secret generation are needed.  Schedule the key gen.
					The combination of the cipher suite type and the pkaAfter
					type will be used to locate this case */
				pkaAfter->type = PKA_AFTER_ECDH_KEY_GEN;
				pkaAfter->outbuf = c; /* Where the public key will be written */
				pkaAfter->pool = pkiPool;
				pkaAfter->data = pkiData;
				pkaAfter->user = keyLen;

				c += keyLen;

				/*	Allocate premaster and free ECC key material */

				ssl->sec.premasterSize =
					ssl->sec.cert->publicKey.key.ecc.curve->size;
				ssl->sec.premaster = psMalloc(ssl->hsPool,
					ssl->sec.premasterSize);
				if (ssl->sec.premaster == NULL) {
					return SSL_MEM_ERROR;
				}

			} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_RSA_CIPHER_SUITE
/*
			Standard RSA suite
*/
			ssl->sec.premasterSize = SSL_HS_RSA_PREMASTER_SIZE;
			ssl->sec.premaster = psMalloc(ssl->hsPool,
									SSL_HS_RSA_PREMASTER_SIZE);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}

			ssl->sec.premaster[0] = ssl->reqMajVer;
			ssl->sec.premaster[1] = ssl->reqMinVer;
			if (matrixCryptoGetPrngData(ssl->sec.premaster + 2,
					SSL_HS_RSA_PREMASTER_SIZE - 2, ssl->userPtr) < 0) {
				return MATRIXSSL_ERROR;
			}

			/* Shedule RSA encryption.  Put tmp pool under control of After */
			pkaAfter->type = PKA_AFTER_RSA_ENCRYPT;
			pkaAfter->outbuf = c;
			pkaAfter->data = pkiData;
			pkaAfter->pool = pkiPool;
			pkaAfter->user = keyLen; /* Available space */

			c += keyLen;
#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for writeClientKeyExchange.  ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA_CIPHER_SUITE */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
			}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
		}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
	}
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_DTLS
	}
#endif /* USE_DTLS */

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CLIENT_KEY_EXCHANGE, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}

	out->end = c;
	return MATRIXSSL_SUCCESS;
}

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_CLIENT_AUTH
/******************************************************************************/
/*	Postponed CERTIFICATE_VERIFY PKA operation */
static int32 nowDoCvPka(ssl_t *ssl, psBuf_t *out)
{
	pkaAfter_t		*pka;
	unsigned char	msgHash[SHA512_HASH_SIZE];
#ifdef USE_DTLS
	int32			saveSize;
#endif /* USE_DTLS */
	psPool_t	*pkiPool = NULL;

	pka = &ssl->pkaAfter[0];

#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		if (ssl->retransmit) {
			/* This call is not gated on pkaAfter.type so we test for
				retransmits manaully.  The retransmit will have already been
				written in writeCertifiateVerify if true */
			return PS_SUCCESS;
		}
	}
#endif /* USE_DTLS */

	/* Does a smart default hash automatically for us */
	if (sslSnapshotHSHash(ssl, msgHash, -1) <= 0) {
		psTraceInfo("Internal error: handshake hash failed\n");
		return MATRIXSSL_ERROR;
	}

#ifdef USE_ECC
	if (pka->type == PKA_AFTER_ECDSA_SIG_GEN) {
		/* NEGATIVE ECDSA - New temp location for ECDSA sig which can be
			two bytes larger MAX than what we originally calculated
			(pka->user is holding). */
		unsigned char	*tmpEcdsa;
		uint16_t		len;
		
		/* Only need to allocate 1 larger because 1 has already been added */
		if ((tmpEcdsa = psMalloc(ssl->hsPool, pka->user + 1)) == NULL) {
			return PS_MEM_FAIL;
		}

#ifdef USE_TLS_1_2
		/* Tweak if needed */
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			switch(pka->inlen) {
#ifdef USE_SHA1
			case SHA1_HASH_SIZE:
				sslSha1SnapshotHSHash(ssl, msgHash);
				break;
#endif
#ifdef USE_SHA384
			case SHA384_HASH_SIZE:
				sslSha384SnapshotHSHash(ssl, msgHash);
				break;
#endif
#ifdef USE_SHA512
			case SHA512_HASH_SIZE:
				sslSha512SnapshotHSHash(ssl, msgHash);
				break;
#endif
			default:
				break;
			}
#ifdef USE_DTLS
			ssl->ecdsaSizeChange = 0;
#endif
			/* NEGATIVE ECDSA - 5th output param is now tmp instead of
				pka->outbuf.  Length of outbuf is increased by 1 */
			len = pka->user + 1;
			if (psEccDsaSign(pkiPool, &ssl->keys->privKey.key.ecc,
					msgHash, pka->inlen, tmpEcdsa, &len, 1, pka->data) != 0) {
				psFree(tmpEcdsa, ssl->hsPool);
				return MATRIXSSL_ERROR;
			}
		} else {
#ifdef USE_DTLS
			ssl->ecdsaSizeChange = 0;
#endif
			len = pka->user + 1;
			if (psEccDsaSign(pkiPool, &ssl->keys->privKey.key.ecc,
					msgHash + MD5_HASH_SIZE, SHA1_HASH_SIZE,
					tmpEcdsa, &len, 1, pka->data) != 0) {
				psFree(tmpEcdsa, ssl->hsPool);
				return MATRIXSSL_ERROR;
			}
		}
#else /* USE_TLS_1_2 */
		
		len = pka->user + 1;
#ifdef USE_DTLS
		ssl->ecdsaSizeChange = 0;
#endif
		/* The ECDSA signature is always done over a SHA1 hash so we need
			to skip over the first 16 bytes of MD5 that the SSL hash stores */
		if (psEccDsaSign(pkiPool, &ssl->keys->privKey.key.ecc,
				msgHash + MD5_HASH_SIZE, SHA1_HASH_SIZE,
				tmpEcdsa, &len, 1, pka->data) != 0) {
			psFree(tmpEcdsa, ssl->hsPool);
			return MATRIXSSL_ERROR;
		}
#endif /* USE_TLS_1_2 */

		if (len != pka->user) {
			/* int accountForEcdsaSizeChange(ssl_t *ssl, pkaAfter_t *pka, int real,
				unsigned char *sig, psBuf_t *out); */
			if (accountForEcdsaSizeChange(ssl, pka, len, tmpEcdsa, out,
					SSL_HS_CERTIFICATE_VERIFY) < 0) {
				clearPkaAfter(ssl);
				psFree(tmpEcdsa, ssl->hsPool);
				return MATRIXSSL_ERROR;
			}
		} else {
			memcpy(pka->outbuf, tmpEcdsa, pka->user);
		}
		psFree(tmpEcdsa, ssl->hsPool);
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
			saveSize = len;

			ssl->certVerifyMsgLen = saveSize;
			ssl->certVerifyMsg = psMalloc(ssl->hsPool, saveSize);
			if (ssl->certVerifyMsg == NULL) {
				return SSL_MEM_ERROR;
			}
			memcpy(ssl->certVerifyMsg, pka->outbuf, saveSize);
		}
#endif /* USE_DTLS */
		clearPkaAfter(ssl);

	} else {
#endif /* USE_ECC */

#ifdef USE_RSA
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/*	RFC:  "The hash and signature algorithms used in the
				signature MUST be one of those present in the
				supported_signature_algorithms field of the
				CertificateRequest message.  In addition, the hash and
				signature algorithms MUST be compatible with the key in the
				client's end-entity certificate.

				We've done the above tests in the parse of the
				CertificateRequest message and wouldn't be here if our
				certs didn't match the sigAlgs.  However, we do have
				to test for both sig algorithm types here to find the
				hash strength because the sig alg might not match the
				pubkey alg.  This was also already confirmed in
				CertRequest parse so wouldn't be here if not allowed */
			if (pka->inlen == SHA1_HASH_SIZE) {
				sslSha1SnapshotHSHash(ssl, msgHash);
			} else if (pka->inlen == SHA256_HASH_SIZE) {
#ifdef USE_SHA384
			} else if (pka->inlen == SHA384_HASH_SIZE) {
				sslSha384SnapshotHSHash(ssl, msgHash);
#endif /* USE_SHA384 */
#ifdef USE_SHA512
			} else if (pka->inlen == SHA512_HASH_SIZE) {
				sslSha512SnapshotHSHash(ssl, msgHash);
#endif /* USE_SHA512 */
			}

			/* The signed element is not the straight hash */
			if (privRsaEncryptSignedElement(pkiPool, &ssl->keys->privKey.key.rsa,
					msgHash, pka->inlen, pka->outbuf,
					ssl->keys->privKey.keysize, pka->data) < 0) {
				return MATRIXSSL_ERROR;
			}
		} else {
			if (psRsaEncryptPriv(pkiPool, &ssl->keys->privKey.key.rsa, msgHash,
					pka->inlen, pka->outbuf, ssl->keys->privKey.keysize,
					pka->data) < 0) {
				return MATRIXSSL_ERROR;

			}
		}
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
			saveSize = ssl->keys->privKey.keysize;

			ssl->certVerifyMsgLen = saveSize;
			ssl->certVerifyMsg = psMalloc(ssl->hsPool, saveSize);
			if (ssl->certVerifyMsg == NULL) {
				return SSL_MEM_ERROR;
			}
			memcpy(ssl->certVerifyMsg, pka->outbuf, saveSize);
		}
#endif /* USE_DTLS */
		clearPkaAfter(ssl);
		
#else /* ! USE_TLS_1_2 */
		if (psRsaEncryptPriv(pkiPool, &ssl->keys->privKey.key.rsa, msgHash,
				pka->inlen, pka->outbuf, ssl->keys->privKey.keysize,
				pka->data) < 0) {
			return MATRIXSSL_ERROR;
		}
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
			saveSize = ssl->keys->privKey.keysize;

			ssl->certVerifyMsgLen = saveSize;
			ssl->certVerifyMsg = psMalloc(ssl->hsPool, saveSize);
			if (ssl->certVerifyMsg == NULL) {
				return SSL_MEM_ERROR;
			}
			memcpy(ssl->certVerifyMsg, pka->outbuf, saveSize);
		}
#endif /* USE_DTLS */
		clearPkaAfter(ssl);
#endif /* USE_TLS_1_2 */


#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for writeCertificateVerify.  ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA */
#ifdef USE_ECC
	} /* Closing type test */
#endif /* USE_ECC */

	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Write the CertificateVerify message (client auth only)
	The message contains the signed hash of the handshake messages.

	The PKA operation is delayed
*/
static int32 writeCertificateVerify(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize, hashSize;
	int32_t			rc;
	pkaAfter_t		*pkaAfter;
	void			*pkiData = ssl->userPtr;

	psTraceHs("<<< Client creating CERTIFICATE_VERIFY  message\n");
	c = out->end;
	end = out->buf + out->size;

	if ((pkaAfter = getPkaAfter(ssl)) == NULL) {
		psTraceInfo("getPkaAfter error for certVerify\n");
		return MATRIXSSL_ERROR;
	}

	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		2 + ssl->keys->privKey.keysize;

#ifdef USE_ECC
	/* Additional ASN.1 overhead from psEccSignHash */
	if (ssl->keys->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
		messageSize += 6;
		/* NEGATIVE ECDSA - Adding ONE spot for a 0x0 byte in the
			ECDSA signature.  This will allow us to be right ~50% of
			the time and not require any manual manipulation
			
			However, if this is a 521 curve there is no chance
			the final byte could be negative if the full 66
			bytes are needed because there can only be a single
			low bit for that sig size.  So subtract that byte
			back out to stay around the 50% no-move goal */
		if (ssl->keys->privKey.keysize != 132) {
			messageSize += 1;
		}
		/* BIG EC KEY.  The sig is 2 bytes len, 1 byte SEQ,
			1 byte length (+1 OPTIONAL byte if length is >=128),
			1 byte INT, 1 byte rLen, r, 1 byte INT, 1 byte sLen, s.
			So the +4 here are the 2 INT and 2 rLen/sLen bytes on
			top of the keysize */
		if (ssl->keys->privKey.keysize + 4 >= 128) {
			messageSize++; /* Extra byte for 'long' asn.1 encode */
		}
#ifdef USE_DTLS
		if ((ssl->flags & SSL_FLAGS_DTLS) && (ssl->retransmit == 1)) {
			/* We already know if this signature got resized */
			messageSize += ssl->ecdsaSizeChange;
		}
#endif
	}
#endif /* USE_ECC */

#ifdef USE_TLS_1_2
/*	RFC: "This is the concatenation of all the
	Handshake structures (as defined in Section 7.4) exchanged thus
	far.  Note that this requires both sides to either buffer the
	messages or compute running hashes for all potential hash
	algorithms up to the time of the CertificateVerify computation.
	Servers can minimize this computation cost by offering a
	restricted set of digest algorithms in the CertificateRequest
	message."

	We're certainly not	going to buffer the messages so the
	handshake hash update and snapshot functions have to keep the
	running total.  Not a huge deal for the updating but
	the current snapshot framework didn't support this so there
	are one-off algorithm specific snapshots where needed. */
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		messageSize += 2; /* hashSigAlg */
	}
#endif
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_VERIFY, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		return rc;
	}

/*
	Correct to be looking at the child-most cert here because that is the
	one associated with the private key.
*/
#ifdef USE_ECC
	if (ssl->keys->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
		hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/*	RFC:  "The hash and signature algorithms used in the
				signature MUST be one of those present in the
				supported_signature_algorithms field of the
				CertificateRequest message.  In addition, the hash and
				signature algorithms MUST be compatible with the key in the
				client's end-entity certificate."

				We've done the above tests in the parse of the
				CertificateRequest message and wouldn't be here if our
				certs didn't match the sigAlgs.  However, we do have
				to test for both sig algorithm types here to find the
				hash strength because the sig alg might not match the
				pubkey alg.  This was also already confirmed in
				CertRequest parse so wouldn't be here if not allowed */
			if ((ssl->keys->cert->sigAlgorithm == OID_SHA1_ECDSA_SIG) ||
					(ssl->keys->cert->sigAlgorithm == OID_SHA1_RSA_SIG)) {
				*c = 0x2; c++; /* SHA1 */
				*c = 0x3; c++; /* ECDSA */
				hashSize = SHA1_HASH_SIZE;
			} else if ((ssl->keys->cert->sigAlgorithm ==
					OID_SHA256_ECDSA_SIG) || (ssl->keys->cert->sigAlgorithm
					== OID_SHA256_RSA_SIG)) {
				*c = 0x4; c++; /* SHA256 */
				*c = 0x3; c++; /* ECDSA */
				hashSize = SHA256_HASH_SIZE;
#ifdef USE_SHA384
			} else if ((ssl->keys->cert->sigAlgorithm ==
					OID_SHA384_ECDSA_SIG) || (ssl->keys->cert->sigAlgorithm
					== OID_SHA384_RSA_SIG)) {
				*c = 0x5; c++; /* SHA384 */
				*c = 0x3; c++; /* ECDSA */
				hashSize = SHA384_HASH_SIZE;
#endif
#ifdef USE_SHA512
			} else if ((ssl->keys->cert->sigAlgorithm ==
					OID_SHA512_ECDSA_SIG) || (ssl->keys->cert->sigAlgorithm
					== OID_SHA512_RSA_SIG)) {
				*c = 0x6; c++; /* SHA512 */
				*c = 0x3; c++; /* ECDSA */
				hashSize = SHA512_HASH_SIZE;
#endif
			} else {
				psTraceInfo("Need more hash support for certVerify\n");
				return MATRIXSSL_ERROR;
			}
		}
#endif /* USE_TLS_1_2 */


#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS && ssl->retransmit) {
			memcpy(c, ssl->certVerifyMsg, ssl->certVerifyMsgLen);
			c += ssl->certVerifyMsgLen;
		} else {
#endif

		pkaAfter->inlen = hashSize;
		pkaAfter->type = PKA_AFTER_ECDSA_SIG_GEN;
		pkaAfter->data = pkiData;
		pkaAfter->outbuf = c;
		rc = ssl->keys->privKey.keysize + 8;
		/* NEGATIVE ECDSA - Adding spot for ONE 0x0 byte in ECDSA so we'll
			be right 50% of the time.  521 curve doesn't need */
		if (ssl->keys->privKey.keysize != 132) {
			rc += 1;
		}
		/* Above we added in the 8 bytes of overhead (2 sigLen, 1 SEQ,
			1 len (possibly 2!), 1 INT, 1 rLen, 1 INT, 1 sLen) and now
			subtract the first 3 bytes to see if the 1 len needs to be 2 */
		if (rc - 3 >= 128) {
			rc++;
		}
		pkaAfter->user = rc;
		c += rc;
#ifdef USE_DTLS
		}
#endif
	} else {
#endif /* USE_ECC */

#ifdef USE_RSA
		hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/*	RFC:  "The hash and signature algorithms used in the
				signature MUST be one of those present in the
				supported_signature_algorithms field of the
				CertificateRequest message.  In addition, the hash and
				signature algorithms MUST be compatible with the key in the
				client's end-entity certificate.

				We've done the above tests in the parse of the
				CertificateRequest message and wouldn't be here if our
				certs didn't match the sigAlgs.  However, we do have
				to test for both sig algorithm types here to find the
				hash strength because the sig alg might not match the
				pubkey alg.  This was also already confirmed in
				CertRequest parse so wouldn't be here if not allowed */
			if (ssl->keys->cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_MD5_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_SHA1_ECDSA_SIG) {
				*c = 0x2; c++; /* SHA1 */
				*c = 0x1; c++; /* RSA */
				hashSize = SHA1_HASH_SIZE;
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA256_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_SHA256_ECDSA_SIG) {
				*c = 0x4; c++; /* SHA256 */
				*c = 0x1; c++; /* RSA */
				/* Normal handshake hash uses SHA256 and has been done above */
				hashSize = SHA256_HASH_SIZE;
#ifdef USE_SHA384
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA384_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_SHA384_ECDSA_SIG) {
				*c = 0x5; c++; /* SHA384 */
				*c = 0x1; c++; /* RSA */
				hashSize = SHA384_HASH_SIZE;
#endif /* USE_SHA384 */
#ifdef USE_SHA512
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA512_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_SHA512_ECDSA_SIG) {
				*c = 0x6; c++; /* SHA512 */
				*c = 0x1; c++; /* RSA */
				hashSize = SHA512_HASH_SIZE;
#endif /* USE_SHA512 */
#ifdef USE_PKCS1_PSS
			} else if (ssl->keys->cert->sigAlgorithm == OID_RSASSA_PSS) {
				if (ssl->keys->cert->pssHash == PKCS1_SHA1_ID ||
						ssl->keys->cert->pssHash == PKCS1_MD5_ID) {
					*c = 0x2; c++;
					hashSize = SHA1_HASH_SIZE;
				} else if (ssl->keys->cert->pssHash == PKCS1_SHA256_ID) {
					*c = 0x4; c++;
					hashSize = SHA256_HASH_SIZE;
#ifdef USE_SHA384
				} else if (ssl->keys->cert->pssHash == PKCS1_SHA384_ID) {
					*c = 0x5; c++;
					hashSize = SHA384_HASH_SIZE;
#endif
#ifdef USE_SHA512
				} else if (ssl->keys->cert->pssHash == PKCS1_SHA512_ID) {
					*c = 0x6; c++;
					hashSize = SHA512_HASH_SIZE;
#endif
				} else {
					psTraceInfo("Need additional hash support for certVerify\n");
					return MATRIXSSL_ERROR;
				}
				*c = 0x1; c++; /* RSA */
#endif
			} else {
				psTraceInfo("Need additional hash support for certVerify\n");
				return MATRIXSSL_ERROR;
			}

			pkaAfter->type = PKA_AFTER_RSA_SIG_GEN_ELEMENT; /* this one */
		} else {
			pkaAfter->type = PKA_AFTER_RSA_SIG_GEN;
		}
#else /* ! USE_TLS_1_2 */
		pkaAfter->type = PKA_AFTER_RSA_SIG_GEN;
#endif /* USE_TLS_1_2 */

		*c = (ssl->keys->privKey.keysize & 0xFF00) >> 8; c++;
		*c = (ssl->keys->privKey.keysize & 0xFF); c++;

#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS && ssl->retransmit) {
			pkaAfter->type = 0; /* reset so AFTER logic doesn't trigger */
			memcpy(c, ssl->certVerifyMsg, ssl->certVerifyMsgLen);
			c += ssl->certVerifyMsgLen;
		} else {
#endif
		pkaAfter->data = pkiData;
		pkaAfter->inlen = hashSize;
		pkaAfter->outbuf = c;
		c += ssl->keys->privKey.keysize;
#ifdef USE_DTLS
		}
#endif

#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for writeCertificateVerify.  ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA */
#ifdef USE_ECC
	} /* Closing sigAlgorithm test */
#endif /* USE_ECC */

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_VERIFY, messageSize,	padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#else /* USE_CLIENT_SIDE_SSL */
/******************************************************************************/
/*
	Stub out this function rather than ifdef it out in the public header
*/
int32_t matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
				const uint16_t cipherSpec[], uint8_t cipherSpecLen,
				uint32 *requiredLen, tlsExtension_t *userExt,
				sslSessOpts_t *options)
{
	psTraceInfo("Library not built with USE_CLIENT_SIDE_SSL\n");
	return PS_UNSUPPORTED_FAIL;
}
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
/******************************************************************************/
/*
	Write the CertificateRequest message (client auth only)
	The message contains the list of CAs the server is willing to accept
	children certificates of from the client.
*/
static int32 writeCertificateRequest(ssl_t *ssl, sslBuf_t *out, int32 certLen,
								   int32 certCount)
{
	unsigned char	*c, *end, *encryptStart;
	psX509Cert_t	*cert;
	uint8_t			padLen;
	uint16_t		messageSize, sigHashLen = 0;
	int32_t			rc;

	psTraceHs("<<< Server creating CERTIFICATE_REQUEST message\n");
	c = out->end;
	end = out->buf + out->size;

	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		4 + (certCount * 2) + certLen;
#ifdef USE_ECC
	messageSize += 1; /* Adding ECDSA_SIGN type */
#endif /* USE_ECC */

#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/* TLS 1.2 has a SignatureAndHashAlgorithm type after CertType */
		sigHashLen = 2;
#ifdef USE_ECC
#ifdef USE_SHA384
		sigHashLen += 6;
#else
		sigHashLen += 4;
#endif	/* USE_SHA */
#endif /* USE_ECC */
#ifdef USE_RSA
#ifdef USE_SHA384
		sigHashLen += 6;
#else
		sigHashLen += 4;
#endif	/* USE_SHA */
#endif /* USE_RSA */
		messageSize += sigHashLen;
	}
#endif /* TLS_1_2 */

	if ((messageSize - ssl->recordHeadLen) > ssl->maxPtFrag) {
		return writeMultiRecordCertRequest(ssl, out, certLen, certCount,
			sigHashLen);
	}

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
#ifdef USE_DTLS
			if (ssl->flags & SSL_FLAGS_DTLS) {
/*
				Is this the fragment case?
*/
				if (rc == DTLS_MUST_FRAG) {
					rc = dtlsWriteCertificateRequest(ssl->hsPool, ssl,
						certLen, certCount, sigHashLen, c);
					if (rc < 0) {
						return rc;
					}
					c += rc;
					out->end = c;
					return MATRIXSSL_SUCCESS;
				}
			}
#endif /* USE_DTLS */
		return rc;
	}

#ifdef USE_ECC
	*c++ = 2;
	*c++ = ECDSA_SIGN;
#else
	*c++ = 1;
#endif
	*c++ = RSA_SIGN;
#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		/* RFC: "The interaction of the certificate_types and
		supported_signature_algorithms fields is somewhat complicated.
		certificate_types has been present in TLS since SSLv3, but was
		somewhat underspecified.  Much of its functionality is superseded
		by supported_signature_algorithms."

		The spec says the cert must support the hash/sig algorithm but
		it's a bit confusing what this means for the hash portion.
		Just going to use SHA1, SHA256, and SHA384 support.

		We're just sending the raw list of all sig algorithms that are
		compiled into the library.  It might be smart to look through the
		individual CA files here only send the pub key operations that
		they use but the CA info is sent explicitly anyway so the client
		can confirm they have a proper match.

		If a new algorithm is added here it will require additions to
		messageSize	directly above in this function and in the flight
		calculation in sslEncodeResponse */
		*c++ = 0x0;
		*c++ = sigHashLen - 2;
#ifdef USE_ECC
#ifdef USE_SHA384
		*c++ = 0x5; /* SHA384 */
		*c++ = 0x3; /* ECDSA */
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x3; /* ECDSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x3; /* ECDSA */
#else
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x3; /* ECDSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x3; /* ECDSA */
#endif
#endif

#ifdef USE_RSA
#ifdef USE_SHA384
		*c++ = 0x5; /* SHA384 */
		*c++ = 0x1; /* RSA */
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x1; /* RSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x1; /* RSA */
#else
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x1; /* RSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x1; /* RSA */
#endif
#endif /* USE_RSA */
	}
#endif /* TLS_1_2 */

	cert = ssl->keys->CAcerts;
	if (cert) {
		*c = ((certLen + (certCount * 2))& 0xFF00) >> 8; c++;
		*c = (certLen + (certCount * 2)) & 0xFF; c++;
		while (cert) {
			if (cert->subject.dnenc == NULL) {
				return PS_FAIL;
			}
			*c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
			*c = cert->subject.dnencLen & 0xFF; c++;
			memcpy(c, cert->subject.dnenc, cert->subject.dnencLen);
			c += cert->subject.dnencLen;
			cert = cert->next;
		}
	} else {
		*c++ = 0; /* Cert len */
		*c++ = 0;
	}
	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}



static int32 writeMultiRecordCertRequest(ssl_t *ssl, sslBuf_t *out,
				int32 certLen, int32 certCount, int32 sigHashLen)
{
	psX509Cert_t	*cert, *future;
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize, dnencLen = 0;
	int32			midWrite, midSizeWrite, countDown, firstOne = 1;
	int32_t			rc;

	c = out->end;
	end = out->buf + out->size;

	midSizeWrite = midWrite = 0;

	while (certLen > 0) {
		if (firstOne){
			firstOne = 0;
			countDown = ssl->maxPtFrag;
			messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
				4 + (certCount * 2) + certLen + sigHashLen;
#ifdef USE_ECC
			messageSize += 1; /* Adding ECDSA_SIGN type */
#endif /* USE_ECC */
			if ((rc = writeRecordHeader(ssl,
					SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG,
					SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
					&encryptStart, end, &c)) < 0) {
				return rc;
			}
#ifdef USE_ECC
			*c++ = 2;
			*c++ = ECDSA_SIGN;
			countDown -= 2;
#else
			*c++ = 1;
			countDown--;
#endif
			*c++ = RSA_SIGN;
			countDown--;
#ifdef USE_TLS_1_2
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				*c++ = 0x0;
				*c++ = sigHashLen - 2;
#ifdef USE_ECC
#ifdef USE_SHA384
				*c++ = 0x5; /* SHA384 */
				*c++ = 0x3; /* ECDSA */
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x3; /* ECDSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x3; /* ECDSA */
#else
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x3; /* ECDSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x3; /* ECDSA */
#endif
#endif

#ifdef USE_RSA
#ifdef USE_SHA384
				*c++ = 0x5; /* SHA384 */
				*c++ = 0x1; /* RSA */
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x1; /* RSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x1; /* RSA */
#else
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x1; /* RSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x1; /* RSA */
#endif
#endif /* USE_RSA */
				countDown -= sigHashLen;
			}
#endif /* TLS_1_2 */
			cert = ssl->keys->CAcerts;
			*c = ((certLen + (certCount * 2))& 0xFF00) >> 8; c++;
			*c = (certLen + (certCount * 2)) & 0xFF; c++;
			countDown -= ssl->hshakeHeadLen + 2;
			while (cert) {
				if (cert->subject.dnenc == NULL) {
					return PS_FAIL;
				}
				midWrite = 0;
				dnencLen = cert->subject.dnencLen;
				if (dnencLen > 0) {
					if (countDown < 2) {
						/* Fragment falls right on dn len write.  Has
							to be at least one byte or countDown would have
							been 0 and got us out of here already*/
						*c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
						midSizeWrite = 1;
						break;
					} else {
						*c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
						*c = cert->subject.dnencLen & 0xFF; c++;
						countDown -= 2;
					}
					midWrite = min(dnencLen, countDown);
					memcpy(c, cert->subject.dnenc, midWrite);
					dnencLen -= midWrite;
					c += midWrite;
					certLen -= midWrite;
					countDown -= midWrite;
					if (countDown == 0) {
						break;
					}
				}
				cert = cert->next;
			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen,
					encryptStart, out, &c)) < 0) {
				return rc;
			}
			out->end = c;
		} else {
			if (cert == NULL || cert->subject.dnenc == NULL) {
				return PS_FAIL;
			}
			/*	Not-first fragments */
			if (midSizeWrite > 0) {
				messageSize = midSizeWrite;
			} else {
				messageSize = 0;
			}
			if ((certLen + messageSize) > ssl->maxPtFrag) {
				messageSize += ssl->maxPtFrag;
			} else {
				messageSize += dnencLen;
				if (cert->next != NULL) {
					future = cert->next;
					while (future != NULL) {
						if (messageSize + future->subject.dnencLen + 2 >
								(uint32)ssl->maxPtFrag) {
							messageSize = ssl->maxPtFrag;
							future = NULL;
						} else {
							messageSize += 2 + future->subject.dnencLen;
							future = future->next;
						}

					}
				}
			}
			countDown = messageSize;
			messageSize += ssl->recordHeadLen;
			/* Second, etc... */
			if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE_FRAG,
					SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
					&encryptStart, end, &c)) < 0) {
				return rc;
			}
			if (midSizeWrite > 0) {
				*c = (dnencLen & 0xFF); c++;
				countDown -= 1;
			}
			midSizeWrite = 0;
			if (countDown < dnencLen) {
				memcpy(c, cert->subject.dnenc + midWrite, countDown);
				dnencLen -= countDown;
				c += countDown;
				certLen -= countDown;
				midWrite += countDown;
				countDown = 0;
			} else {
				memcpy(c, cert->subject.dnenc + midWrite, dnencLen);
				c += dnencLen;
				certLen -= dnencLen;
				countDown -= dnencLen;
				dnencLen -= dnencLen;
			}
			while (countDown > 0) {
				cert = cert->next;
				if (cert == NULL || cert->subject.dnenc == NULL) {
					return PS_FAIL;
				}
				dnencLen =  cert->subject.dnencLen;
				midWrite = 0;
				if (countDown < 2) {
					/* Fragment falls right on cert len write */
					*c = (unsigned char)((dnencLen & 0xFF00) >> 8);
					c++; countDown--;
					midSizeWrite = 1;
					break;
				} else {
					*c = (unsigned char)((dnencLen & 0xFF00) >> 8); c++;
					*c = (dnencLen & 0xFF); c++;
					countDown -= 2;
				}
				midWrite = min(dnencLen, countDown);
				memcpy(c, cert->subject.dnenc, midWrite);
				dnencLen -= midWrite;
				c += midWrite;
				certLen -= midWrite;
				countDown -= midWrite;
				if (countDown == 0) {
					break;
				}
			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen,
					encryptStart, out, &c)) < 0) {
				return rc;
			}
			out->end = c;

		}

	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_SERVER_SIDE && USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_DTLS
#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
	DTLS specific handshake message to verify client existence
*/
static int32 writeHelloVerifyRequest(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	uint8_t			padLen;
	uint16_t		messageSize;
	int32_t			rc;

	psTraceHs("<<< Server creating HELLO_VERIFY_REQUEST message\n");
	c = out->end;
	end = out->buf + out->size;
/*
	The magic 3 bytes consist of the 2 byte TLS version and the 1 byte length
*/
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		DTLS_COOKIE_SIZE + 3;

/*
	Always have to reset msn to zero because we don't know if this is a
	resend to a cookie-less CLIENT_HELLO that never receieved our verify
	request
*/
	ssl->msn = 0;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_HELLO_VERIFY_REQUEST, &messageSize, &padLen,
			&encryptStart, end, &c)) < 0) {
		return rc;
	}

/*
	Message content is version, cookie length, and cookie itself
*/
	*c++ = ssl->rec.majVer;
	*c++ = ssl->rec.minVer;
	*c++ = DTLS_COOKIE_SIZE;
	memcpy(c, ssl->srvCookie, DTLS_COOKIE_SIZE);
	c += DTLS_COOKIE_SIZE;

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_HELLO_VERIFY_REQUEST, messageSize, padLen, encryptStart,
			out, &c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_SERVER_SIDE_SSL */
#endif /* USE_DTLS */

/******************************************************************************/
/*
	Write out a SSLv3 record header.
	Assumes 'c' points to a buffer of at least SSL3_HEADER_LEN bytes
		1 byte type (SSL_RECORD_TYPE_*)
		1 byte major version
		1 byte minor version
		2 bytes length (network byte order)
	Returns the number of bytes written
*/
int32 psWriteRecordInfo(ssl_t *ssl, unsigned char type, int32 len,
							   unsigned char *c, int32 hsType)
{
	int32	explicitNonce = 0;

	if (type == SSL_RECORD_TYPE_HANDSHAKE_FRAG) {
		type = SSL_RECORD_TYPE_HANDSHAKE;
	}
	*c = type; c++;
	*c = ssl->majVer; c++;
	*c = ssl->minVer; c++;
#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		ssl->seqDelay = c;
		*c = ssl->epoch[0]; c++;
		*c = ssl->epoch[1]; c++;
		*c = ssl->rsn[0]; c++;
		*c = ssl->rsn[1]; c++;
		*c = ssl->rsn[2]; c++;
		*c = ssl->rsn[3]; c++;
		*c = ssl->rsn[4]; c++;
		*c = ssl->rsn[5]; c++;
	}
#endif /* USE_DTLS */
	*c = (len & 0xFF00) >> 8; c++;
	*c = (len & 0xFF);

	if (hsType == SSL_HS_FINISHED) {
		if (ssl->cipher->flags & (CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_CCM)) {
			explicitNonce++;
		}
	} else if (ssl->flags & SSL_FLAGS_NONCE_W) {
		explicitNonce++;
	}
	if (explicitNonce) {
#ifdef USE_DTLS
		if (ssl->flags & SSL_FLAGS_DTLS) {
			c++;
			*c = ssl->epoch[0]; c++;
			*c = ssl->epoch[1]; c++;
			*c = ssl->rsn[0]; c++;
			*c = ssl->rsn[1]; c++;
			*c = ssl->rsn[2]; c++;
			*c = ssl->rsn[3]; c++;
			*c = ssl->rsn[4]; c++;
			*c = ssl->rsn[5]; c++;
		} else {
#endif /* USE_DTLS */
		c++;
		ssl->seqDelay = c; /* not being incremented in postpone mechanism */
		*c = ssl->sec.seq[0]; c++;
		*c = ssl->sec.seq[1]; c++;
		*c = ssl->sec.seq[2]; c++;
		*c = ssl->sec.seq[3]; c++;
		*c = ssl->sec.seq[4]; c++;
		*c = ssl->sec.seq[5]; c++;
		*c = ssl->sec.seq[6]; c++;
		*c = ssl->sec.seq[7];
#ifdef USE_DTLS
		}
#endif
		return ssl->recordHeadLen + TLS_EXPLICIT_NONCE_LEN;
	}

	return ssl->recordHeadLen;
}

/******************************************************************************/
/*
	Write out an ssl handshake message header.
	Assumes 'c' points to a buffer of at least ssl->hshakeHeadLen bytes
		1 byte type (SSL_HS_*)
		3 bytes length (network byte order)
	Returns the number of bytes written
*/
int32 psWriteHandshakeHeader(ssl_t *ssl, unsigned char type, int32 len,
								int32 seq, int32 fragOffset, int32 fragLen,
								unsigned char *c)
{
	*c = type; c++;
	*c = (unsigned char)((len & 0xFF0000) >> 16); c++;
	*c = (len & 0xFF00) >> 8; c++;
#ifdef USE_DTLS
	if (ssl->flags & SSL_FLAGS_DTLS) {
		*c = (len & 0xFF); c++;
		*c = (seq & 0xFF00) >> 8; c++;
		*c = (seq & 0xFF); c++;
		*c = (unsigned char)((fragOffset & 0xFF0000) >> 16); c++;
		*c = (fragOffset & 0xFF00) >> 8; c++;
		*c = (fragOffset & 0xFF); c++;
		*c = (unsigned char)((fragLen & 0xFF0000) >> 16); c++;
		*c = (fragLen & 0xFF00) >> 8; c++;
		*c = (fragLen & 0xFF);
	} else {
		*c = (len & 0xFF);
	}
#else
	*c = (len & 0xFF);
#endif /* USE_DTLS */

	ssl->encState = type;
	return ssl->hshakeHeadLen;
}

/******************************************************************************/
/*
	Write pad bytes and pad length per the TLS spec.  Most block cipher
	padding fills each byte with the number of padding bytes, but SSL/TLS
	pretends one of these bytes is a pad length, and the remaining bytes are
	filled with that length.  The end result is that the padding is identical
	to standard padding except the values are one less. For SSLv3 we are not
	required to have any specific pad values, but they don't hurt.

	PadLen	Result
	0
	1		00
	2		01 01
	3		02 02 02
	4		03 03 03 03
	5		04 04 04 04 04
	6		05 05 05 05 05 05
	7		06 06 06 06 06 06 06
	8		07 07 07 07 07 07 07 07
	9		08 08 08 08 08 08 08 08 08
	...
	15		...

	We calculate the length of padding required for a record using
	psPadLenPwr2()
*/
int32 sslWritePad(unsigned char *p, unsigned char padLen)
{
	unsigned char c = padLen;

	while (c > 0) {
		*p++ = padLen - 1;
		c--;
	}
	return padLen;
}

/******************************************************************************/

