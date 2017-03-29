/**
 *	@file    extDecode.c
 *	@version $Format:%h%d$
 *
 *	CLIENT_HELLO and SERVER_HELLO extension parsing
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

#ifdef USE_SERVER_SIDE_SSL
static int ClientHelloExt(ssl_t *ssl, unsigned short extType,
						  unsigned short extLen, const unsigned char *c);
#endif
#ifdef USE_CLIENT_SIDE_SSL
static int ServerHelloExt(ssl_t *ssl, unsigned short extType,
						  unsigned short extLen, const unsigned char *c);
#endif
#ifdef USE_ALPN
static int dealWithAlpnExt(ssl_t *ssl, const unsigned char *c,
						   unsigned short extLen);
#endif

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
	Parse the ClientHello extension list.
*/
int32 parseClientHelloExtensions(ssl_t *ssl, unsigned char **cp, unsigned short len)
{
	unsigned short	extLen, extType;
	unsigned char	*c, *end;
	int				rc;
#ifdef ENABLE_SECURE_REHANDSHAKES
	unsigned short	renegotiationExtSent = 0;
#endif

	c = *cp;
	end = c + len;
	
	/* Clear extFlags in case of rehandshakes */
	ssl->extFlags.truncated_hmac = 0;
	ssl->extFlags.sni = 0;
	ssl->extFlags.session_id = 0;
	ssl->extFlags.session_ticket = 0;
	ssl->extFlags.extended_master_secret = 0;
	ssl->extFlags.status_request = 0;
	
	/*	There could be extension data to parse here:
		Two byte length and extension info.
		http://www.faqs.org/rfcs/rfc3546.html

		NOTE:  This c != end test is only safe because ClientHello is the
		only record/message in the flight of supported handshake protocols.	*/
	if (c != end) {
		if (end - c < 2) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid extension header len\n");
			return MATRIXSSL_ERROR;
		}
		extLen = *c << 8; c++; /* Total length of list, in bytes */
		extLen += *c; c++;
		/* extLen must be minimum 2 b type 2 b len and 0 b value */
		if ((uint32)(end - c) < extLen || extLen < 4) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid extension header len\n");
			return MATRIXSSL_ERROR;
		}

#ifdef USE_TLS_1_2
		ssl->hashSigAlg = 0;
#endif
		while (c != end) {
			extType = *c << 8; c++; /* Individual hello ext */
			extType += *c; c++;
			if (end - c < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid extension header len\n");
				return MATRIXSSL_ERROR;
			}
			extLen = *c << 8; c++; /* length of one extension */
			extLen += *c; c++;
			/* Minimum extension value len is 0 bytes */
			if ((uint32)(end - c) < extLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid extension header len\n");
				return MATRIXSSL_ERROR;
			}
#ifdef ENABLE_SECURE_REHANDSHAKES
			if (extType == EXT_RENEGOTIATION_INFO) {
				renegotiationExtSent = 1;
			}
#endif
			/* Parse incoming client extensions we support. */
			if ((rc = ClientHelloExt(ssl, extType, extLen, c)) < 0) {
				/* On error, ssl->error will have been set */
				return rc;
			}
			c += extLen;
		}
	}
	
	/* Handle the extensions that were missing or not what we wanted */
	if (ssl->extFlags.require_extended_master_secret == 1 &&
			ssl->extFlags.extended_master_secret == 0) {
		psTraceInfo("Client doesn't support extended master secret\n");
		ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
		return MATRIXSSL_ERROR;
	}
	
#if defined(USE_TLS_1_2) && defined(USE_CERT_PARSE)
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		if (!ssl->hashSigAlg) {
#ifdef USE_SHA1
			/* Client didn't send the extension at all. Unfortunately, spec says we
				have to assume SHA1 in this case, even though both peers are 
				already calculating a SHA256 based handshake hash. */
#ifdef USE_RSA_CIPHER_SUITE
			ssl->hashSigAlg |= HASH_SIG_SHA1_RSA_MASK;
#endif
#ifdef USE_ECC_CIPHER_SUITE
			ssl->hashSigAlg |= HASH_SIG_SHA1_ECDSA_MASK;
#endif
#else
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				psTraceInfo("Client didn't provide hashSigAlg and sha1 not supported\n");
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				return MATRIXSSL_ERROR;
			}
#endif /* USE_SHA1 */
		}
	}
#endif /* USE_TLS_1_2 */

#ifdef USE_STATELESS_SESSION_TICKETS
	/* If session ID was sent that we didn't like AND no ticket was sent
		then we can forget we ever received a sessionID now */
	if (ssl->extFlags.session_id == 1) {
		memset(ssl->sessionId, 0, SSL_MAX_SESSION_ID_SIZE);
		ssl->sessionIdLen = 0;
	}
	ssl->extFlags.session_id = 0;
	ssl->extFlags.session_ticket = 0;
#endif

#ifdef ENABLE_SECURE_REHANDSHAKES
	if (!renegotiationExtSent) {
#ifdef REQUIRE_SECURE_REHANDSHAKES
		/*	Check if SCSV was sent instead */
		if (ssl->secureRenegotiationFlag == PS_FALSE &&
				ssl->myVerifyDataLen == 0) {
			psTraceInfo("Client doesn't support renegotiation hello\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
#endif /* REQUIRE_SECURE_REHANDSHAKES */
		if (ssl->secureRenegotiationFlag == PS_TRUE &&
				ssl->myVerifyDataLen > 0) {
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			psTraceInfo("Cln missing renegotiationInfo on re-hndshk\n");
			return MATRIXSSL_ERROR;
		}
#ifndef ENABLE_INSECURE_REHANDSHAKES
		if (ssl->secureRenegotiationFlag == PS_FALSE &&
				ssl->myVerifyDataLen > 0) {
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			psTraceInfo("Cln attempting insecure handshake\n");
			return MATRIXSSL_ERROR;
		}
#endif /* !ENABLE_INSECURE_REHANDSHAKES */
	}
#endif /* ENABLE_SECURE_REHANDSHAKES */

	*cp = c;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Parse a single client extension
*/
static int ClientHelloExt(ssl_t *ssl, unsigned short extType, unsigned short extLen,
					 const unsigned char *c)
{
	int				i;
#ifdef USE_ECC_CIPHER_SUITE
	unsigned short	dataLen, curveId;
	uint32			ecFlags;
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_TLS_1_2
	unsigned short	tmpLen;
#endif

	switch (extType) {

	/**************************************************************************/

	case EXT_TRUNCATED_HMAC:
		if (extLen != 0) {
			psTraceInfo("Bad truncated HMAC extension\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		/* User could have disabled for this session */
		if (!ssl->extFlags.deny_truncated_hmac) {
			ssl->extFlags.truncated_hmac = 1;
		}
		break;
		
	case EXT_EXTENDED_MASTER_SECRET:
		if (extLen != 0) {
			psTraceInfo("Bad extended master secret extension\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		/* TODO: User can disable? */
		ssl->extFlags.extended_master_secret = 1;
		break;

	/**************************************************************************/

	case EXT_MAX_FRAGMENT_LEN:
		if (extLen != 1) {
			psTraceInfo("Invalid frag len ext len\n");
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		/* User could have disabled for this session using
			the session options */
		if (!ssl->extFlags.deny_max_fragment_len) {
			if (*c == 0x1) {
				ssl->maxPtFrag = 0x200;
			} else if (*c == 0x2) {
				ssl->maxPtFrag = 0x400;
			} else if (*c == 0x3) {
				ssl->maxPtFrag = 0x800;
			} else if (*c == 0x4) {
				ssl->maxPtFrag = 0x1000;
			} else {
				psTraceInfo("Client sent bad frag len value\n");
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				return MATRIXSSL_ERROR;
			}
		}
		break;

	/**************************************************************************/

	case EXT_SNI:
		/* Must hold (2 b len + 1 b zero) + 2 b len */
		if (extLen < 5) {
			psTraceInfo("Invalid server name ext len\n");
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		/* Two length bytes.  May seem odd to ignore but
			the inner length is repeated right below after
			the expected 0x0 bytes */
		i = *c << 8; c++;
		i += *c; c++;
		if (*c++ != 0x0) {
			psTraceInfo("Expected host_name in SNI ext\n");
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		(void)i; /* TODO - validate against length determined below */
		extLen -= 3;
		i = *c << 8; c++;
		i += *c; c++;
		extLen -= 2;	/* Length check covered above */
		/* Arbitrary length cap between 1 and min(extlen,255) */
		if ((int32)extLen < i || i > 255 || i <= 0) {
			psTraceInfo("Invalid host name ext len\n");
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		if (ssl->expectedName) {
			psFree(ssl->expectedName, ssl->sPool);
		}
		if ((ssl->expectedName = psMalloc(ssl->sPool, i + 1)) == NULL) {
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		memcpy(ssl->expectedName, c, i);
		ssl->expectedName[i] = '\0';
		break;

#ifdef USE_ALPN
	/**************************************************************************/

	case EXT_ALPN:
		/* Must hold 2 b len 1 b zero 2 b len */
		if (extLen < 2) {
			psTraceInfo("Invalid ALPN ext len\n");
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		/* Skip extension if server didn't register callback */
		if (ssl->srv_alpn_cb) {
			int		rc;
			if ((rc = dealWithAlpnExt(ssl, c, extLen)) < 0) {
				if (rc == PS_PROTOCOL_FAIL) {
					/* This is a user space rejection */
					psTraceInfo("User rejects ALPN ext\n");
					ssl->err = SSL_ALERT_NO_APP_PROTOCOL;
					return MATRIXSSL_ERROR;
				}
				psTraceInfo("Invalid ALPN ext\n");
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				return MATRIXSSL_ERROR;
			}
		}
		break;
#endif 

#ifdef ENABLE_SECURE_REHANDSHAKES
	/**************************************************************************/

	case EXT_RENEGOTIATION_INFO:
		if (ssl->secureRenegotiationFlag == PS_FALSE &&
				ssl->myVerifyDataLen == 0) {
			if (extLen == 1 && *c == '\0') {
				ssl->secureRenegotiationFlag = PS_TRUE;
			} else {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("Cln sent bad renegotiationInfo\n");
				return MATRIXSSL_ERROR;
			}
		} else if ((extLen == ssl->peerVerifyDataLen + 1) &&
				(ssl->secureRenegotiationFlag == PS_TRUE)) {
			if (*c != ssl->peerVerifyDataLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid renegotiation encoding\n");
				return MATRIXSSL_ERROR;
			}
			if (memcmpct(c + 1, ssl->peerVerifyData,
					ssl->peerVerifyDataLen) != 0) {
				psTraceInfo("Cli verify renegotiation fail\n");
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				return MATRIXSSL_ERROR;
			}
		} else {
			psTraceInfo("Bad state/len of renegotiation ext\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		break;
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_TLS_1_2
	/**************************************************************************/

	case EXT_SIGNATURE_ALGORITHMS:
		/* This extension is responsible for telling the server which
			sig algorithms it accepts so here we are saving them
			aside for when user chooses identity certificate.
			https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 */
		
		/* Minimum length of 2 b type, 2 b alg */
		/* Arbitrary Max of 16 suites */
		if (extLen > (2 + 32) || extLen < 4 || (extLen & 1)) {
			psTraceInfo("Malformed sig_alg len\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		
		tmpLen = *c << 8; c++;
		tmpLen |= *c; c++;
		extLen -= 2;

		if ((uint32)tmpLen > extLen || tmpLen < 2 || (tmpLen & 1)) {
			psTraceInfo("Malformed sig_alg extension\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		/* list of 2 byte pairs in a hash/sig format that
			need to be searched to find match with server
			cert sigAlgorithm
			Test if client will be able to accept our sigs
			based on what our idenity certificate is */
		while (tmpLen >= 2 && extLen >= 2) {
			ssl->hashSigAlg |= HASH_SIG_MASK(c[0], c[1]);
			c += 2;
			tmpLen -= 2;
			extLen -= 2;
		}
		break;
#endif /* USE_TLS_1_2 */

#ifdef USE_STATELESS_SESSION_TICKETS
	/**************************************************************************/

	case EXT_SESSION_TICKET:
		/* Have a handy place to store this info.  Tickets are
			the	only way a server will make use of 'sid'.
			Could already exist if rehandshake case here */
		if (ssl->sid == NULL) {
			/* Server just needs a spot to manage the state
				of the negotiation.  Uses the sessionTicketState
				of this structure */
			ssl->sid = psMalloc(ssl->sPool, sizeof(sslSessionId_t));
			if (ssl->sid == NULL) {
				ssl->err = SSL_ALERT_INTERNAL_ERROR;
				return MATRIXSSL_ERROR;
			}
			memset(ssl->sid, 0x0, sizeof(sslSessionId_t));
			ssl->sid->pool = ssl->sPool;
		}
		if (extLen > 0) { /* received a ticket */
			ssl->extFlags.session_ticket = 1;

			if (matrixUnlockSessionTicket(ssl, (unsigned char*)c, extLen) ==
					PS_SUCCESS) {
				/* Understood the token */
				ssl->flags |= SSL_FLAGS_RESUMED;
				ssl->sid->sessionTicketState = SESS_TICKET_STATE_USING_TICKET;
				memcpy(ssl->sec.masterSecret, ssl->sid->masterSecret,
					SSL_HS_MASTER_SIZE);
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
			} else {
				/* If client sent a sessionId in the hello,
					we can ignore that here now */
				if (ssl->sessionIdLen > 0) {
					memset(ssl->sessionId, 0, SSL_MAX_SESSION_ID_SIZE);
					ssl->sessionIdLen = 0;
				}
				/* Issue another one if we have any keys */
				if (ssl->keys && ssl->keys->sessTickets) {
					ssl->sid->sessionTicketState = SESS_TICKET_STATE_RECVD_EXT;
				} else {
					ssl->sid->sessionTicketState = SESS_TICKET_STATE_INIT;
				}
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
#endif				
			}
		} else {
			/* Request for session ticket.  Can we honor? */
			if (ssl->keys && ssl->keys->sessTickets) {
				ssl->sid->sessionTicketState = SESS_TICKET_STATE_RECVD_EXT;
			} else {
				ssl->sid->sessionTicketState = SESS_TICKET_STATE_INIT;
			}
		}
		break;
#endif /* USE_STATELESS_SESSION_TICKETS */

#ifdef USE_ECC_CIPHER_SUITE
	/**************************************************************************/

	case EXT_ELLIPTIC_CURVE:
		/* Minimum is 2 b dataLen and 2 b cipher */
		if (extLen < 4) {
			psTraceInfo("Invalid ECC Curve len\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		dataLen = *c << 8; c++;
		dataLen += *c; c++;
		extLen -= 2;
		if (dataLen > extLen || dataLen < 2 || (dataLen & 1)) {
			psTraceInfo("Malformed ECC Curve extension\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		/* Matching EC curve logic */
		ecFlags = IS_RECVD_EXT; /* Flag if we got it */
		ssl->ecInfo.ecCurveId = 0;
		while (dataLen >= 2 && extLen >= 2) {
			curveId = *c << 8; c++;
			curveId += *c; c++;
			dataLen -= 2;
			extLen -= 2;
/*
			Find the curves that are in common between client and server.
			ssl->ecInfo.ecFlags defaults to all curves compiled into the library.
*/
			if (psTestUserEcID(curveId, ssl->ecInfo.ecFlags) == 0) {
/*
				Client sends curves in priority order, so choose the first
				one we have in common. If ECDHE, it will be used after 
				this CLIENT_HELLO parse as the ephemeral key gen curve.
				If ECDH, it will be used to find a matching cert, and for
				key exchange.
*/
				if (ecFlags == IS_RECVD_EXT) {
					ssl->ecInfo.ecCurveId = curveId;
				}
				ecFlags |= curveIdToFlag(curveId);
			}
		}
		ssl->ecInfo.ecFlags = ecFlags;
		break;

	/**************************************************************************/

	case EXT_ELLIPTIC_POINTS:
		if (extLen < 1) {
			psTraceInfo("Invaid ECC Points len\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		dataLen = *c; c++; /* single byte data len */
		extLen -= 1;
		if (dataLen > extLen || dataLen < 1) {
			psTraceInfo("Malformed ECC Points extension\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		/*	One of them has to be a zero (uncompressed) and that
			is all we are looking for at the moment */
		if (memchr(c, '\0', dataLen) == NULL) {
			psTraceInfo("ECC Uncommpressed Points missing\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
		break;
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_OCSP
	case EXT_STATUS_REQUEST:
		/*  Validation of minimum size and status_type of 1 (ocsp) */
		if (extLen < 5 || *c != 0x1) {
			psTraceIntInfo("Bad cert_status_request extension: %d\n", extType);
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		c++; extLen--; /* checked status type above */
		/* Skipping the ResponderIDs */
		dataLen = *c << 8; c++; extLen--;
		dataLen += *c; c++; extLen--;
		if (dataLen + 2 > extLen) {
			psTraceIntInfo("Bad cert_status_request extension: \n", extType);
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		c += dataLen;
		/* Skipping the Extensions */
		dataLen = *c << 8; c++; extLen--;
		dataLen += *c; c++; extLen--;
		if (dataLen > extLen) {
			psTraceIntInfo("Bad cert_status_request extension: \n", extType);
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			return MATRIXSSL_ERROR;
		}
		c += dataLen;
		/* Currently, the OCSPResponse must be loaded into the key material
			so we check if that exists to determine if we will reply with
			the extension and CERTIFICATE_STATUS handshake message */
		if (ssl->keys->OCSPResponseBufLen > 0 &&
				ssl->keys->OCSPResponseBuf != NULL) {
			ssl->extFlags.status_request = 1;
		} else {
			psTraceInfo("Client requesting OCSP but we have no response\n");
		}
		
		break;
#endif


	/**************************************************************************/

	default:
		psTraceIntInfo("Ignoring unknown extension: %d\n", extType);
		break;
	}
	return PS_SUCCESS;
}

#ifdef USE_ALPN
	/**************************************************************************/
/*
	Parse Application Layer Protocol extension and invoke callback.  No need
	to advance any buffer pointers, caller is managing.
*/
static int dealWithAlpnExt(ssl_t *ssl, const unsigned char *c, unsigned short extLen)
{
	int32			totLen, i, userChoice;
	unsigned char	*end;
	char			*proto[MAX_PROTO_EXT];
	int32			protoLen[MAX_PROTO_EXT];

	end = (unsigned char*)c + extLen;

	totLen	= *c << 8; c++;
	totLen += *c; c++;
	if (totLen != extLen - 2) {
		return PS_PARSE_FAIL;
	}

	for (i = 0; totLen > 0; i++) {
		if (i + 1 > MAX_PROTO_EXT) {
			i--;
			break;
		}
		protoLen[i] = *c; c++; totLen--;
		if (protoLen[i] > totLen) {
			while (i > 0) {
				psFree(proto[i - 1], ssl->sPool);
				i--;
			}
			return PS_PARSE_FAIL;
		}
		if ((proto[i] = psMalloc(ssl->sPool, protoLen[i])) == NULL) {
			while (i > 0) {
				psFree(proto[i - 1], ssl->sPool);
				i--;
			}
			return PS_MEM_FAIL;
		}
		memcpy(proto[i], c, protoLen[i]);
		totLen -= protoLen[i];
		c += protoLen[i];
	}

	/* see if they touch it.  Using a value outside the range to gauge */
	userChoice = MAX_PROTO_EXT;

	/* Already tested if callback exists */
	(*ssl->srv_alpn_cb)((void*)ssl, (short)i, proto, protoLen, &userChoice);

	if (userChoice == MAX_PROTO_EXT) {
		/* User chose to completely ignore. No reply extension will be sent */
		while (i > 0) {
			psFree(proto[i - 1], ssl->sPool);
			i--;
		}
		return PS_SUCCESS;
	}
	if (userChoice >= i) {
		/* User chose something completely unreasonable */
		while (i > 0) {
			psFree(proto[i - 1], ssl->sPool);
			i--;
		}
		return PS_LIMIT_FAIL;
	}

	if (userChoice < 0) {
		/* They actually rejected these completely.  Returning the
			no-application-protocol alert per the spec */
		while (i > 0) {
			psFree(proto[i - 1], ssl->sPool);
			i--;
		}
		return PS_PROTOCOL_FAIL;
	}

	/* Allocated to session pool so fine to point to it and just skip
		freeing it while cleaning up here */
	ssl->alpn = proto[userChoice];
	ssl->alpnLen = protoLen[userChoice];

	while (i > 0) {
		if (i - 1 != userChoice) {
			psFree(proto[i - 1], ssl->sPool);
		}
		i--;
	}

	/** HTTP2 places some constraints on TLS configuration, so flag
		that here for checking later (in choosing cipher suite, etc).
		@see https://tools.ietf.org/html/rfc7540#section-9.2
	*/
	if ((ssl->alpnLen == 2) && memcmp(ssl->alpn, "h2", 2) = 0) {
		ssl->flags |= SSL_FLAGS_HTTP2;
	}

	return PS_SUCCESS;
}
#endif /* USE_ALPN */

#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
	Parse the ServerHello extension list.
*/
int32 parseServerHelloExtensions(ssl_t *ssl, int32 hsLen,
							unsigned char *extData,	unsigned char **cp,
							unsigned short len)
{
	unsigned short	extLen, extType;
	int32			rc;
	unsigned char	*c, *end;
#ifdef ENABLE_SECURE_REHANDSHAKES
	unsigned short renegotiationExtSent = 0;
#endif

	rc = PS_SUCCESS;
	c = *cp;
	end = c + len;
	
	if (end - c < 2) {
		ssl->err = SSL_ALERT_DECODE_ERROR;
		psTraceInfo("Invalid extension header len\n");
		return MATRIXSSL_ERROR;
	}
	extLen = *c << 8; c++; /* Total length of list */
	extLen += *c; c++;
	if ((uint32)(end - c) < extLen) {
		ssl->err = SSL_ALERT_DECODE_ERROR;
		psTraceInfo("Invalid extension header len\n");
		return MATRIXSSL_ERROR;
	}
	while ((int32)hsLen > (c - extData)) {
		extType = *c << 8; c++; /* Individual hello ext */
		extType += *c; c++;
		if (end - c < 2) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid extension header len\n");
			return MATRIXSSL_ERROR;
		}
		extLen = *c << 8; c++; /* Length of individual extension */
		extLen += *c; c++;
		if ((uint32)(end - c) < extLen) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid extension header len\n");
			return MATRIXSSL_ERROR;
		}
#ifdef ENABLE_SECURE_REHANDSHAKES
		if (extType == EXT_RENEGOTIATION_INFO) {
			renegotiationExtSent = 1;
		}
#endif
		if ((rc = ServerHelloExt(ssl, extType, extLen, c)) < 0) {
			/* On error, ssl->error will have been set */
			return rc;
		}
		c += extLen;
	}

	/* Enforce the rules for extensions that require the server to send
		something back to us */
		
	if (ssl->extFlags.req_extended_master_secret == 1) {
		/* The req_extended_master_secret is reset to 0 when the server sends
			one so this case means the server doesn't support it */
		if (ssl->extFlags.require_extended_master_secret == 1) {
			psTraceInfo("Server doesn't support extended master secret\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
	}

#ifdef USE_OCSP_MUST_STAPLE
	if (ssl->extFlags.req_status_request == 1) {
		if (ssl->extFlags.status_request == 0) {
			psTraceInfo("Server doesn't support OCSP stapling\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
	}
#endif

#ifdef ENABLE_SECURE_REHANDSHAKES
	if (!renegotiationExtSent) {
#ifdef REQUIRE_SECURE_REHANDSHAKES
		/*	Check if SCSV was sent instead */
		if (ssl->secureRenegotiationFlag == PS_FALSE &&
				ssl->myVerifyDataLen == 0) {
			psTraceInfo("Server doesn't support renegotiation hello\n");
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			return MATRIXSSL_ERROR;
		}
#endif /* REQUIRE_SECURE_REHANDSHAKES */
		if (ssl->secureRenegotiationFlag == PS_TRUE &&
				ssl->myVerifyDataLen > 0) {
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			psTraceInfo("Server missing renegotiationInfo on re-hndshk\n");
			return MATRIXSSL_ERROR;
		}
#ifndef ENABLE_INSECURE_REHANDSHAKES
		if (ssl->secureRenegotiationFlag == PS_FALSE &&
				ssl->myVerifyDataLen > 0) {
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			psTraceInfo("Server attempting insecure handshake\n");
			return MATRIXSSL_ERROR;
		}
#endif /* !ENABLE_INSECURE_REHANDSHAKES */
	}
#endif /* ENABLE_SECURE_REHANDSHAKES */

	*cp = c;
	return rc;
}

/******************************************************************************/
/*
	Parse the ServerHello extension list.
*/
static int ServerHelloExt(ssl_t *ssl, unsigned short extType, unsigned short extLen,
						  const unsigned char *c)
{
	int		rc;

	/*	Verify the server only responds with an extension the client requested.
		Zero the value once seen so that it will catch the error if sent twice */
	rc = -1;
	switch (extType) {

	/**************************************************************************/

	case EXT_SNI:
		if (ssl->extFlags.req_sni) {
			ssl->extFlags.req_sni = 0;
			if (ssl->extCb) {
				rc = (*ssl->extCb)(ssl, extType, extLen, (void *)c);
			} else {
				rc = 0;
			}
		}
		break;

	/**************************************************************************/

	case EXT_MAX_FRAGMENT_LEN:
		if (ssl->extFlags.req_max_fragment_len) {
			ssl->extFlags.req_max_fragment_len = 0;
			rc = 0;
		}
		if (!(ssl->maxPtFrag & 0x10000)) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Server sent unexpected MAX_FRAG ext\n");
			return MATRIXSSL_ERROR;
		}
		if (extLen != 1) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Server sent bad MAX_FRAG ext\n");
			return MATRIXSSL_ERROR;
		}
		/* Confirm it's the same size we requested and strip
			off 0x10000 from maxPtrFrag */
		if (*c == 0x01 &&
				(ssl->maxPtFrag & 0x200)) {
			ssl->maxPtFrag = 0x200;
		} else if (*c == 0x02 &&
				(ssl->maxPtFrag & 0x400)) {
			ssl->maxPtFrag = 0x400;
		} else if (*c == 0x03 &&
				(ssl->maxPtFrag & 0x800)) {
			ssl->maxPtFrag = 0x800;
		} else if (*c == 0x04 &&
				(ssl->maxPtFrag & 0x1000)) {
			ssl->maxPtFrag = 0x1000;
		} else {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Server sent mismatched MAX_FRAG ext\n");
			return MATRIXSSL_ERROR;
		}
		c++; extLen--;
		break;

	/**************************************************************************/

	case EXT_TRUNCATED_HMAC:
		if (ssl->extFlags.req_truncated_hmac) {
			ssl->extFlags.req_truncated_hmac = 0;
			rc = 0;
		}
		if (extLen != 0) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Server sent bad truncated hmac ext\n");
			return MATRIXSSL_ERROR;
		}
		ssl->extFlags.truncated_hmac = 1;
		break;
		
	case EXT_EXTENDED_MASTER_SECRET:
		if (ssl->extFlags.req_extended_master_secret) {
			ssl->extFlags.req_extended_master_secret = 0;
			rc = 0;
		}
		if (extLen != 0) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Server sent bad extended master secret ext\n");
			return MATRIXSSL_ERROR;
		}
		ssl->extFlags.extended_master_secret = 1;
		break;

#ifdef USE_ECC_CIPHER_SUITE
	/**************************************************************************/

	case EXT_ELLIPTIC_CURVE:
		/* @note we do not allow EXT_ELLIPTIC_CURVE from server */
		break;

	/**************************************************************************/

	case EXT_ELLIPTIC_POINTS:
		if (ssl->extFlags.req_elliptic_points) {
			ssl->extFlags.req_elliptic_points = 0;
			rc = 0;
		}
		if (*c++ != (extLen - 1)) {
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			psTraceInfo("Server sent bad ECPointFormatList\n");
			return MATRIXSSL_ERROR;
		}
		extLen--; /* TODO: check that one of these bytes is 0
								(uncompressed point support) */
		break;
#endif /* USE_ECC_CIPHER_SUITE */

	/**************************************************************************/

	case EXT_SIGNATURE_ALGORITHMS:
		/* @note we do not allow EXT_SIGNATURE_ALGORITHMS from server */
		break;

	/**************************************************************************/

	case EXT_ALPN:
		if (ssl->extFlags.req_alpn) {
			ssl->extFlags.req_alpn = 0;
			if (ssl->extCb) {
				rc = (*ssl->extCb)(ssl, extType, extLen, (void *)c);
			} else {
				rc = 0;
			}
		}
		break;

#ifdef USE_STATELESS_SESSION_TICKETS
	/**************************************************************************/

	case EXT_SESSION_TICKET:
		if (ssl->extFlags.req_session_ticket) {
			ssl->extFlags.req_session_ticket = 0;
			rc = 0;
		}
		if (ssl->sid && ssl->sid->sessionTicketState ==
					SESS_TICKET_STATE_SENT_EMPTY) {
			ssl->sid->sessionTicketState =
				SESS_TICKET_STATE_RECVD_EXT; /* expecting ticket */
		} else if (ssl->sid && ssl->sid->sessionTicketState ==
					SESS_TICKET_STATE_SENT_TICKET) {
			ssl->sid->sessionTicketState =
				SESS_TICKET_STATE_RECVD_EXT; /* expecting ticket */
		} else {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Server sent unexpected SESSION_TICKET\n");
			return MATRIXSSL_ERROR;
		}
		break;
#endif /* USE_STATELESS_SESSION_TICKETS */

#ifdef ENABLE_SECURE_REHANDSHAKES
	/**************************************************************************/

	case EXT_RENEGOTIATION_INFO:
		if (ssl->extFlags.req_renegotiation_info) {
			ssl->extFlags.req_renegotiation_info = 0;
			rc = 0;
		}
		if (ssl->secureRenegotiationFlag == PS_FALSE &&
				ssl->myVerifyDataLen == 0) {
			if (extLen == 1 && *c == '\0') {
				ssl->secureRenegotiationFlag = PS_TRUE;
			} else {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("Server sent bad renegotiationInfo\n");
				return MATRIXSSL_ERROR;
			}
		} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
				extLen == ((ssl->myVerifyDataLen * 2) + 1)) {
			c++; extLen--;
			if (memcmpct(c, ssl->myVerifyData,
					ssl->myVerifyDataLen) != 0) {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("Srv had bad my renegotiationInfo\n");
				return MATRIXSSL_ERROR;
			}
			if (memcmpct(c + ssl->myVerifyDataLen,ssl->peerVerifyData,
					ssl->peerVerifyDataLen) != 0) {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("Srv had bad peer renegotiationInfo\n");
				return MATRIXSSL_ERROR;
			}
		} else {
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			psTraceInfo("Server sent bad renegotiationInfo\n");
			return MATRIXSSL_ERROR;
		}
		break;
#endif /* ENABLE_SECURE_REHANDSHAKES */

	case EXT_STATUS_REQUEST:
		if (ssl->extFlags.req_status_request) {
			/* Weed out the unsolicited status_request */
			ssl->extFlags.status_request = 1;
			rc = 0;
		}
		break;
		
		
	/**************************************************************************/

	default:
		/* We don't recognize the extension, maybe the callback will */
		if (ssl->extCb) {
			rc = (*ssl->extCb)(ssl, extType, extLen, (void *)c);
		}
		break;
	}

	if (rc < 0) {
		if (ssl->minVer >= TLS_1_2_MIN_VER) {
			/* This alert was added only in 1.2 */
			ssl->err = SSL_ALERT_UNSUPPORTED_EXTENSION;
		} else {
			/* Use a generic alert for older versions */
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
		}
		psTraceIntInfo("Server sent unsolicited or duplicate ext %d\n",
			extType);
		return MATRIXSSL_ERROR;
	}
	return rc;
}
#endif

	/**************************************************************************/

