/**
 *	@file    matrixssllib.h
 *	@version $Format:%h%d$
 *
 *	Internal header file used for the MatrixSSL implementation..
 *	Only modifiers of the library should be intersted in this file
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

#ifndef _h_MATRIXSSLLIB
#define _h_MATRIXSSLLIB

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/**
	Additional 'hidden' TLS configuration here for deprecated support.
	@security These options allow enabling/disabling features that have been
	found to generally considered weak and should not be changed except for
	compatibility with older software that cannot be changed.
	@security The default value for strongest security is indicated for each
	option.
*/
/** Deprecated cipher suites. */
#ifndef USE_DTLS
//#define USE_SSL_RSA_WITH_RC4_128_MD5 /**< @security OFF */
//#define USE_SSL_RSA_WITH_RC4_128_SHA /**< @security OFF */
//#define USE_TLS_RSA_WITH_SEED_CBC_SHA /**< @security OFF */
//#define USE_TLS_RSA_WITH_IDEA_CBC_SHA /**< @security OFF */
#endif

/** Anonymous, non authenticated ciphers. */
//#define USE_TLS_DH_anon_WITH_AES_128_CBC_SHA /**< @security OFF */
//#define USE_TLS_DH_anon_WITH_AES_256_CBC_SHA /**< @security OFF */
//#define USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA /**< @security OFF */
#ifndef USE_DTLS
//#define USE_SSL_DH_anon_WITH_RC4_128_MD5 /**< @security OFF */
#endif

/** Authenticated but not encrypted ciphers. */
//#define USE_SSL_RSA_WITH_NULL_SHA /**< @security OFF */
//#define USE_SSL_RSA_WITH_NULL_MD5 /**< @security OFF */

/**
	False Start support for Chrome browser.
	@see http://tools.ietf.org/html/draft-bmoeller-tls-falsestart-00

	@note April 2012: Google has announced this feature will be removed in
	version 20 of their browser due to industry compatibility issues.

	@note November 2016: An official IETF draft is in process for this
	functionality to become standardized.
	@see https://datatracker.ietf.org/doc/draft-ietf-tls-falsestart/
*/
//#define ENABLE_FALSE_START /**< @security OFF */

/**
	zlib compression support.
	@security The CRIME attack on HTTPS has shown that compression at the
	TLS layer can introduce vulnerabilities in higher level protocols. It is
	recommended to NOT use compression features at the TLS level.
*/
//#define USE_ZLIB_COMPRESSION /**< @security OFF NIST_SHOULD_NOT */

/******************************************************************************/
/**
	Rehandshaking support.
	In late 2009 An "authentication gap" exploit was discovered in the
	SSL re-handshaking protocol.  The fix to the exploit was introduced
	in RFC 5746 and is referred to here	as SECURE_REHANDSHAKES.

	ENABLE_SECURE_REHANDSHAKES implements RFC 5746 and will securely
	renegotiate with any implementations that support it.  It is
	recommended to leave this disabled unless there is a specific requirement
	to support it.

	By enabling REQUIRE_SECURE_REHANDSHAKES, the library will test that each
	communicating peer that is attempting to connect has implemented
	RFC 5746 and will terminate handshakes with any that have not.

	If working with SSL peers that have not implemented RFC 5746 and
	rehandshakes are required, you may enable ENABLE_INSECURE_REHANDSHAKES
	but it is NOT RECOMMENDED

	It is a conflict to enable both ENABLE_INSECURE_REHANDSHAKES and
	REQUIRE_SECURE_REHANDSHAKES and a compile error will occur

	To completely disable rehandshaking comment out all three of these defines

	@security Disabling handshaking altogether is the most secure. If it must
	be enabled, only secure rehandshakes should be allowed. Other modes below
	are provided only for compatibility with old TLS/SSL libraries.
*/
#ifdef USE_REHANDSHAKING
//#define ENABLE_SECURE_REHANDSHAKES /**< @security OFF NIST_SHALL */
#define REQUIRE_SECURE_REHANDSHAKES /**< @security ON NIST_SHALL */
//#define ENABLE_INSECURE_REHANDSHAKES /** @security OFF NIST_SHALL_NOT */
#endif

/******************************************************************************/
/**
	Beast Mode.
	In Sept. 2011 security researchers demonstrated how a previously known
	CBC encryption weakness could be used to decrypt HTTP data over SSL.
	The attack was named BEAST (Browser Exploit Against SSL/TLS).

	This issue only affects TLS 1.0 (and SSL) and only if the cipher suite
	is using a symmetric CBC block cipher.  Enable USE_TLS_1_1 above to
	completely negate this workaround if TLS 1.1 is also supported by peers.

	As with previous SSL vulnerabilities, the attack is generally considered
	a very low risk for individual browsers as it requires the attacker
	to have control over the network to become a MITM.  They will also have
	to have knowledge of the first couple blocks of underlying plaintext
	in order to mount the attack.

	A zero length record proceeding a data record has been a known fix to this
	problem for years and MatrixSSL has always supported the handling of empty
	records. So alternatively, an implementation could always encode a zero
	length record before each record encode. Some old SSL implementations do
	not handle decoding zero length records, however.

	This BEAST fix is on the client side and moves the implementation down to
	the SSL library level so users do not need to manually send zero length
	records. This fix uses the same IV obfuscation logic as a zero length
	record by breaking up each application data record in two. Because some
	implementations don't handle zero-length records, the the first record
	is the first byte of the plaintext message, and the second record
	contains the remainder of the message.

	This fix is based on the workaround implemented in Google Chrome:
	http://src.chromium.org/viewvc/chrome?view=rev&revision=97269

	This workaround adds approximagely 53 bytes to the encoded length of each
	SSL3.0 or TLS1.0 record that is encoded, due to the additional header,
	padding and MAC of the second record.

	@security This mode should always be enabled unless explicit compatibility
	with old TLS 1.0 and SSL 3.0 libraries is required.
*/
#define USE_BEAST_WORKAROUND /**< @security ON */

/******************************************************************************/
/**
	Enable certificate chain message "stream" parsing.  This allows single
	certificates to be parsed on-the-fly without having to wait for the entire
	certificate chain to be recieved in the buffer.  This is a memory saving
	feature for the application buffer but will add a small amount of code
	size for the parsing and structure overhead.

	This feature will only save memory if the CERTIFICATE message is the
	only message in the record, and multiple certs are present in the chain.

	@note This features is deprecated and should be enabled only if
	processing long certificate chains with very low memory.
*/
//#define USE_CERT_CHAIN_PARSING /**< @note Setting does not affect security */

/******************************************************************************/
/**
	Experimental support for process-shared server session cache.
	This allows forked copies of a process to use the same session cache.
	@pre Supported for POSIX environments only currently.
*/
//#define USE_SHARED_SESSION_CACHE /**< @note Experimental */

/******************************************************************************/
/**
	- USE_TLS versions must 'stack' for compiling purposes
		- must enable TLS if enabling TLS 1.1
		- must enable TLS 1.1 if enabling TLS 1.2
	- Use the DISABLE_TLS_ defines to disallow specific protocols at runtime
		that have been enabled via USE_TLS_.
	- There is no DISABLE_TLS_ for the latest version of the protocol.  If
		you don't want to use that version disable the USE_TLS_ define instead
	The USE_TLS_1_x_AND_ABOVE simplifies this configuration.
	@security To enable SSL3.0, see below.
*/
#define USE_TLS			/**< DO NOT DISABLE @security NIST_MAY */
#define USE_TLS_1_1		/**< DO NOT DISABLE @security NIST_SHALL */
#define USE_TLS_1_2		/**< DO NOT DISABLE @security NIST_SHOULD */
#define DISABLE_SSLV3	/**< DO NOT DISABLE, undef below if required
						@security NIST_SHALL_NOT */

#if defined USE_TLS_1_2_AND_ABOVE
 #define DISABLE_TLS_1_1
 #define DISABLE_TLS_1_0
#elif defined USE_TLS_1_1_AND_ABOVE
 #define DISABLE_TLS_1_0
#elif defined USE_TLS_1_0_AND_ABOVE
 /** @security undef DISABLE_SSLV3 here if required */
#else
 #error Must define USE_TLS_1_x_AND_ABOVE
#endif

#ifdef USE_DTLS
/******************************************************************************/
 /** DTLS definitions */
 #define DTLS_COOKIE_SIZE	16
#endif /* USE_DTLS */

/******************************************************************************/
/**
	Include matrixssl external crypto provider layer headers.
*/

#ifdef USE_ZLIB_COMPRESSION
 #include "zlib.h"
#endif

#if defined(USE_AES_GCM) || defined(USE_AES_CCM) || defined(USE_CHACHA20_POLY1305)
 #define USE_AEAD_CIPHER
#endif

/* PKCS11 is set in crypto. Use all modes of it if enabled */
#define USE_NATIVE_TLS_ALGS
#define USE_NATIVE_TLS_HS_HASH
#define USE_NATIVE_SYMMETRIC

/******************************************************************************/
/**
	Do sanity checks on configuration.
*/
#include "matrixsslCheck.h"

/******************************************************************************/
/*
	Leave this enabled for run-time check of sslKeys_t content when a cipher
	suite is matched.  Disable only if you need to manage key material yourself.
	Always conditional on whether certificate parsing is enabled because it
	looks at members that only exist if certificates have been parsed
*/
#ifdef USE_CERT_PARSE
#define VALIDATE_KEY_MATERIAL
#endif /* USE_CERT_PARSE */

/******************************************************************************/
/**
	SSL protocol and MatrixSSL defines.
	@see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
*/

/*
	Maximum SSL record size, per specification
*/
#define     SSL_MAX_PLAINTEXT_LEN		0x4000  /* 16KB */
#define     SSL_MAX_RECORD_LEN			SSL_MAX_PLAINTEXT_LEN + 2048
#define     SSL_MAX_BUF_SIZE			SSL_MAX_RECORD_LEN + 0x5
#define		SSL_MAX_DISABLED_CIPHERS	8
/*
	Maximum buffer sizes for static SSL array types
*/
#define SSL_MAX_MAC_SIZE		48 /* SHA384 */
#define SSL_MAX_IV_SIZE			16
#define SSL_MAX_BLOCK_SIZE		16
#define SSL_MAX_SYM_KEY_SIZE	32

/*
	Negative return codes must be between -50 and -69 in the MatrixSSL module
*/
#define     SSL_FULL            -50  /* must call sslRead before decoding */
#define     SSL_PARTIAL         -51 /* more data reqired to parse full msg */
#define     SSL_SEND_RESPONSE   -52  /* decode produced output data */
#define     SSL_PROCESS_DATA    -53  /* succesfully decoded application data */
#define     SSL_ALERT           -54  /* we've decoded an alert */
#define     SSL_FILE_NOT_FOUND  -55  /* File not found */
#define     SSL_MEM_ERROR       PS_MEM_FAIL  /* Memory allocation failure */
#ifdef USE_DTLS
#define     DTLS_MUST_FRAG      -60 /* Message must be fragmented */
#define		DTLS_RETRANSMIT		-61 /* Received a duplicate hs msg from peer */
#endif /* USE_DTLS */

/*
	Magic numbers for handshake header lengths
*/
#define SSL2_HEADER_LEN				2
#define SSL3_HEADER_LEN				5
#define SSL3_HANDSHAKE_HEADER_LEN	4
#ifdef USE_DTLS
 #define DTLS_HEADER_ADD_LEN		8
#endif

#define TLS_CHACHA20_POLY1305_AAD_LEN	13
#define TLS_GCM_AAD_LEN					13
#define TLS_AEAD_SEQNB_LEN				8

#define TLS_GCM_TAG_LEN					16
#define TLS_CHACHA20_POLY1305_TAG_LEN	16
#define TLS_CCM_TAG_LEN					16
#define TLS_CCM8_TAG_LEN				8

#define TLS_AEAD_NONCE_MAXLEN			12 /* Maximum length for an AEAD's nonce */
#define TLS_EXPLICIT_NONCE_LEN			8
#define TLS_CHACHA20_POLY1305_NONCE_LEN	0

#define AEAD_NONCE_LEN(SSL) ((SSL->flags & SSL_FLAGS_NONCE_W) ? TLS_EXPLICIT_NONCE_LEN : 0)
#define AEAD_TAG_LEN(SSL) ((SSL->cipher->flags & CRYPTO_FLAGS_CCM8) ? 8 : 16)

/*
	matrixSslSetSessionOption defines
*/
#define	SSL_OPTION_FULL_HANDSHAKE			1
#ifdef USE_CLIENT_AUTH
#define	SSL_OPTION_DISABLE_CLIENT_AUTH		2
#define	SSL_OPTION_ENABLE_CLIENT_AUTH		3
#endif /* USE_CLIENT_AUTH */
#define SSL_OPTION_DISABLE_REHANDSHAKES		4
#define SSL_OPTION_REENABLE_REHANDSHAKES	5

/*
	SSL Alert levels and descriptions
	This implementation treats all alerts that are not related to
	certificate validation as fatal
*/
#define SSL_ALERT_LEVEL_WARNING             1
#define SSL_ALERT_LEVEL_FATAL               2

#define SSL_ALERT_CLOSE_NOTIFY              0
#define SSL_ALERT_UNEXPECTED_MESSAGE        10
#define SSL_ALERT_BAD_RECORD_MAC            20
#define SSL_ALERT_DECRYPTION_FAILED			21 /* Do not use, per RFC 5246 */
#define SSL_ALERT_RECORD_OVERFLOW			22
#define SSL_ALERT_DECOMPRESSION_FAILURE     30
#define SSL_ALERT_HANDSHAKE_FAILURE         40
#define SSL_ALERT_NO_CERTIFICATE            41
#define SSL_ALERT_BAD_CERTIFICATE           42
#define SSL_ALERT_UNSUPPORTED_CERTIFICATE   43
#define SSL_ALERT_CERTIFICATE_REVOKED       44
#define SSL_ALERT_CERTIFICATE_EXPIRED       45
#define SSL_ALERT_CERTIFICATE_UNKNOWN       46
#define SSL_ALERT_ILLEGAL_PARAMETER         47
#define SSL_ALERT_UNKNOWN_CA				48
#define SSL_ALERT_ACCESS_DENIED				49
#define SSL_ALERT_DECODE_ERROR				50
#define SSL_ALERT_DECRYPT_ERROR				51
#define SSL_ALERT_PROTOCOL_VERSION			70
#define SSL_ALERT_INSUFFICIENT_SECURITY		71
#define SSL_ALERT_INTERNAL_ERROR			80
#define SSL_ALERT_INAPPROPRIATE_FALLBACK	86
#define SSL_ALERT_NO_RENEGOTIATION			100
#define SSL_ALERT_UNSUPPORTED_EXTENSION		110
#define SSL_ALERT_UNRECOGNIZED_NAME			112
#define SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE	113
#define SSL_ALERT_UNKNOWN_PSK_IDENTITY		115
#define SSL_ALERT_NO_APP_PROTOCOL			120

/*
	Use as return code in user validation callback to allow
	anonymous connections to proceed.
	MUST NOT OVERLAP WITH ANY OF THE ALERT CODES ABOVE
*/
#define SSL_ALLOW_ANON_CONNECTION           254

/* Internal values for ssl_t.flags  */
#define	SSL_FLAGS_SERVER		(1<< 0)
#define	SSL_FLAGS_READ_SECURE	(1<< 1)
#define	SSL_FLAGS_WRITE_SECURE	(1<< 2)
#define SSL_FLAGS_RESUMED		(1<< 3)
#define SSL_FLAGS_CLOSED		(1<< 4)
#define SSL_FLAGS_NEED_ENCODE	(1<< 5)
#define SSL_FLAGS_ERROR			(1<< 6)
#define SSL_FLAGS_CLIENT_AUTH	(1<< 7)
#define SSL_FLAGS_ANON_CIPHER	(1<< 8)
#define SSL_FLAGS_FALSE_START	(1<< 9)
#define SSL_FLAGS_SSLV3			(1<<10)
#define SSL_FLAGS_TLS			(1<<11)
#define SSL_FLAGS_TLS_1_0		SSL_FLAGS_TLS	/* For naming consistency */
#define SSL_FLAGS_TLS_1_1		(1<<12)
#define SSL_FLAGS_TLS_1_2		(1<<13)
#define SSL_FLAGS_DTLS			(1<<14)
#define SSL_FLAGS_DHE_WITH_RSA	(1<<15)
#define SSL_FLAGS_DHE_WITH_DSA	(1<<16)
#define SSL_FLAGS_DHE_KEY_EXCH	(1<<17)
#define SSL_FLAGS_PSK_CIPHER	(1<<18)
#define SSL_FLAGS_ECC_CIPHER	(1<<19)
#define SSL_FLAGS_AEAD_W		(1<<20)
#define SSL_FLAGS_AEAD_R		(1<<21)
#define SSL_FLAGS_NONCE_W		(1<<22)
#define SSL_FLAGS_NONCE_R		(1<<23)
#define SSL_FLAGS_HTTP2			(1<<24)

#define SSL_FLAGS_INTERCEPTOR	(1<<30)
#define SSL_FLAGS_EAP_FAST		(1<<31)

/* Internal flags for ssl_t.hwflags */
#define SSL_HWFLAGS_HW					(1<<0) /* Use HW for decode/encode */
#define SSL_HWFLAGS_HW_SW				(1<<1) /* Use HW & SW in parallel (debug) */
#define SSL_HWFLAGS_NONBLOCK			(1<<2) /* Use async HW for decode/encode */
#define SSL_HWFLAGS_PENDING_R			(1<<3) /* Non-blocking app record read */
#define SSL_HWFLAGS_PENDING_W			(1<<4) /* Non-blocking app record write */
#define SSL_HWFLAGS_PENDING_FLIGHT_W	(1<<5) /* mid encryptFlight (hshake) */
#define SSL_HWFLAGS_PENDING_PKA_R		(1<<6) /* Non-blocking public key op */
#define SSL_HWFLAGS_PENDING_PKA_W		(1<<7) /* Non-blocking public key op */
#define SSL_HWFLAGS_EAGAIN				(1<<8) /* Not submitted.  Skip hsHash */
#define SSL_HWFLAGS_HW_BAD				(1<<9) /* Bad hardware result,go software */

/* Buffer flags (ssl->bFlags) */
#define BFLAG_CLOSE_AFTER_SENT	(1<<0)
#define BFLAG_HS_COMPLETE		(1<<1)
#define BFLAG_STOP_BEAST		(1<<2)

/*
	Number of bytes server must send before creating a re-handshake credit
*/
#define DEFAULT_RH_CREDITS		1 /* Allow for one rehandshake by default */
#define	BYTES_BEFORE_RH_CREDIT	20 * 1024 * 1024

#ifdef USE_ECC
/* EC flags for sslSessOpts_t */
#define SSL_OPT_SECP192R1	IS_SECP192R1
#define SSL_OPT_SECP224R1	IS_SECP224R1
#define SSL_OPT_SECP256R1	IS_SECP256R1
#define SSL_OPT_SECP384R1	IS_SECP384R1
#define SSL_OPT_SECP521R1	IS_SECP521R1
/* WARNING: Public points on Brainpool curves are not validated */
#define SSL_OPT_BRAIN224R1	IS_BRAIN224R1
#define SSL_OPT_BRAIN256R1	IS_BRAIN256R1
#define SSL_OPT_BRAIN384R1	IS_BRAIN384R1
#define SSL_OPT_BRAIN512R1	IS_BRAIN512R1
#endif

/* Cipher types (internal for CipherSpec_t.type) */
enum PACKED {
	CS_NULL = 0,
	CS_RSA,
	CS_DHE_RSA,
	CS_DH_ANON,
	CS_DHE_PSK,
	CS_PSK,
	CS_ECDHE_ECDSA,
	CS_ECDHE_RSA,
	CS_ECDH_ECDSA,
	CS_ECDH_RSA
};

/*
	These are defines rather than enums because we want to store them as char,
	not int32 (enum size)
*/
#define SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC		(uint8_t)20
#define SSL_RECORD_TYPE_ALERT					(uint8_t)21
#define SSL_RECORD_TYPE_HANDSHAKE				(uint8_t)22
#define SSL_RECORD_TYPE_APPLICATION_DATA		(uint8_t)23
#define SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG	(uint8_t)90 /* internal */
#define SSL_RECORD_TYPE_HANDSHAKE_FRAG			(uint8_t)91 /* non-standard types */

#define SSL_HS_HELLO_REQUEST		(uint8_t)0
#define SSL_HS_CLIENT_HELLO			(uint8_t)1
#define SSL_HS_SERVER_HELLO			(uint8_t)2
#define SSL_HS_HELLO_VERIFY_REQUEST	(uint8_t)3
#define SSL_HS_NEW_SESSION_TICKET	(uint8_t)4
#define SSL_HS_CERTIFICATE			(uint8_t)11
#define SSL_HS_SERVER_KEY_EXCHANGE	(uint8_t)12
#define SSL_HS_CERTIFICATE_REQUEST	(uint8_t)13
#define SSL_HS_SERVER_HELLO_DONE	(uint8_t)14
#define SSL_HS_CERTIFICATE_VERIFY	(uint8_t)15
#define SSL_HS_CLIENT_KEY_EXCHANGE	(uint8_t)16
#define SSL_HS_FINISHED				(uint8_t)20
#define SSL_HS_CERTIFICATE_STATUS	(uint8_t)22
#define SSL_HS_ALERT				(uint8_t)252	/* ChangeCipherSuite (internal) */
#define SSL_HS_CCC					(uint8_t)253	/* ChangeCipherSuite (internal) */
#define SSL_HS_NONE					(uint8_t)254	/* No recorded state (internal) */
#define SSL_HS_DONE					(uint8_t)255	/* Handshake complete (internal) */

#define	INIT_ENCRYPT_CIPHER		0
#define INIT_DECRYPT_CIPHER		1

#define HMAC_CREATE	1
#define HMAC_VERIFY 2

#ifdef USE_TLS_1_2
/**
enum {
	none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), (255)
} HashAlgorithm;
enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SigAlgorithm;
*/
enum PACKED {
	HASH_SIG_MD5 = 1,
	HASH_SIG_SHA1,
	HASH_SIG_SHA256 = 4,
	HASH_SIG_SHA384,
	HASH_SIG_SHA512
};

enum PACKED {
	HASH_SIG_RSA = 1,
	HASH_SIG_ECDSA = 3 /* This 3 is correct for hashSigAlg */
};

/* Internal flag format for algorithms */
enum PACKED {
	/* For RSA we set a bit in the low byte */
	HASH_SIG_MD5_RSA_MASK = 1 << HASH_SIG_MD5,
	HASH_SIG_SHA1_RSA_MASK = 1 << HASH_SIG_SHA1,
	HASH_SIG_SHA256_RSA_MASK = 1 << HASH_SIG_SHA256,
	HASH_SIG_SHA384_RSA_MASK = 1 << HASH_SIG_SHA384,
	HASH_SIG_SHA512_RSA_MASK = 1 << HASH_SIG_SHA512,
	/* For ECDSA we set a bit in the high byte */
	HASH_SIG_SHA1_ECDSA_MASK = 0x100 << HASH_SIG_SHA1,
	HASH_SIG_SHA256_ECDSA_MASK = 0x100 << HASH_SIG_SHA256,
	HASH_SIG_SHA384_ECDSA_MASK = 0x100 << HASH_SIG_SHA384,
	HASH_SIG_SHA512_ECDSA_MASK = 0x100 << HASH_SIG_SHA512,
};

/** Return a unique flag for the given HASH_SIG_ALG. */
static __inline uint16_t HASH_SIG_MASK(uint8_t hash, uint8_t sig)
{
	//TODO - do better validation on hash and sig
	hash = 1 << (hash & 0x7);
	return (sig == HASH_SIG_RSA ? hash : ((uint16_t)hash << 8));
}
#endif /* USE_TLS_1_2 */

/* Additional ssl alert value, indicating no error has ocurred.  */
#define SSL_ALERT_NONE				255	/* No error */

/* SSL/TLS protocol message sizes */
#define SSL_HS_RANDOM_SIZE			32
#define SSL_HS_RSA_PREMASTER_SIZE	48
#ifdef USE_TLS
#define TLS_HS_FINISHED_SIZE	12
#endif /* USE_TLS */

/* Major and minor (not minimum!) version numbers for TLS */
#define SSL2_MAJ_VER		2

#define SSL3_MAJ_VER		3
#define SSL3_MIN_VER		0

#define TLS_MAJ_VER			SSL3_MAJ_VER
#define TLS_MIN_VER			1
#define TLS_1_0_MIN_VER		TLS_MIN_VER
#define TLS_1_1_MIN_VER		2
#define TLS_1_2_MIN_VER		3

/* Based on settings, define the highest TLS version available */
#if defined(USE_TLS_1_2) && !defined(DISABLE_TLS_1_2)
 #define TLS_HIGHEST_MINOR	TLS_1_2_MIN_VER
#elif defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
 #define TLS_HIGHEST_MINOR	TLS_1_1_MIN_VER
#elif defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
 #define TLS_HIGHEST_MINOR	TLS_1_0_MIN_VER
#elif !defined(DISABLE_SSLV3)
 #define TLS_HIGHEST_MINOR	SSL3_MIN_VER
#else
 #error Unexpected TLS Version
#endif

/* Cipher suite specification IDs, in numerical order. */
#define SSL_NULL_WITH_NULL_NULL					0x0000
#define SSL_RSA_WITH_NULL_MD5					0x0001
#define SSL_RSA_WITH_NULL_SHA					0x0002
#define SSL_RSA_WITH_RC4_128_MD5				0x0004
#define SSL_RSA_WITH_RC4_128_SHA				0x0005
#define TLS_RSA_WITH_IDEA_CBC_SHA				0x0007
#define SSL_RSA_WITH_3DES_EDE_CBC_SHA			0x000A	/* 10 */
#define	SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA		0x0016	/* 22 */
#define SSL_DH_anon_WITH_RC4_128_MD5			0x0018	/* 24 */
#define SSL_DH_anon_WITH_3DES_EDE_CBC_SHA		0x001B	/* 27 */
#define TLS_RSA_WITH_AES_128_CBC_SHA			0x002F	/* 47 */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA		0x0033	/* 51 */
#define	TLS_DH_anon_WITH_AES_128_CBC_SHA		0x0034	/* 52 */
#define TLS_RSA_WITH_AES_256_CBC_SHA			0x0035	/* 53 */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA		0x0039	/* 57 */
#define	TLS_DH_anon_WITH_AES_256_CBC_SHA		0x003A	/* 58 */
#define TLS_RSA_WITH_AES_128_CBC_SHA256			0x003C	/* 60 */
#define TLS_RSA_WITH_AES_256_CBC_SHA256			0x003D	/* 61 */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256		0x0067	/* 103 */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256		0x006B	/* 107 */
#define TLS_RSA_WITH_SEED_CBC_SHA				0x0096	/* 150 */
#define TLS_PSK_WITH_AES_128_CBC_SHA			0x008C	/* 140 */
#define TLS_PSK_WITH_AES_128_CBC_SHA256			0x00AE	/* 174 */
#define TLS_PSK_WITH_AES_256_CBC_SHA384			0x00AF	/* 175 */
#define TLS_PSK_WITH_AES_256_CBC_SHA			0x008D	/* 141 */
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA		0x0090	/* 144 */
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA		0x0091	/* 145 */
#define TLS_RSA_WITH_AES_128_GCM_SHA256			0x009C	/* 156 */
#define TLS_RSA_WITH_AES_256_GCM_SHA384			0x009D	/* 157 */

#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV		0x00FF	/**< @see RFC 5746 */
#define TLS_FALLBACK_SCSV						0x5600	/**< @see RFC 7507 */

#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA		0xC004	/* 49156 */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA		0xC005	/* 49157 */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	0xC009	/* 49161 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	0xC00A  /* 49162 */
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA		0xC012	/* 49170 */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA		0xC013	/* 49171 */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA		0xC014	/* 49172 */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA		0xC00E	/* 49166 */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA		0xC00F	/* 49167 */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC023	/* 49187 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xC024	/* 49188 */
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  0xC025	/* 49189 */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  0xC026	/* 49190 */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	0xC027	/* 49191 */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	0xC028	/* 49192 */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256	0xC029	/* 49193 */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384	0xC02A	/* 49194 */
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B	/* 49195 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C	/* 49196 */
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256	0xC02D	/* 49197 */
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384	0xC02E	/* 49198 */
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	0xC02F	/* 49199 */
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	0xC030	/* 49200 */
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256	0xC031	/* 49201 */
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384	0xC032	/* 49202 */
#ifdef CHACHA20POLY1305_IETF
/* Defined in https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256		0xCCA8 /* 52392 */
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256	0xCCA9	/* 52393 */
#else
/* Defined in https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 	0xCC13 /* 52243 */
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256	0xCC14	/* 52244 */
#endif

/*
	Supported HELLO extensions
	Extension status stored by bitfield in ssl_t.extFlags
	@see https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
*/
#define EXT_SNI								 0
#define EXT_MAX_FRAGMENT_LEN				 1
#define EXT_TRUSTED_CA_KEYS					 3
#define EXT_TRUNCATED_HMAC					 4
#define EXT_STATUS_REQUEST					 5	/* OCSP */
#define EXT_ELLIPTIC_CURVE					10	/* Client-send only */
#define EXT_ELLIPTIC_POINTS					11
#define EXT_SIGNATURE_ALGORITHMS			13
#define EXT_ALPN							16
#define EXT_SIGNED_CERTIFICATE_TIMESTAMP	18  /* SCT */
#define EXT_EXTENDED_MASTER_SECRET			23
#define EXT_SESSION_TICKET					35
#define EXT_RENEGOTIATION_INFO				0xFF01

/* How large the ALPN extension arrary is.  Number of protos client can talk */
#define MAX_PROTO_EXT					8

/*
	Maximum key block size for any defined cipher
	This must be validated if new ciphers are added
	Value is largest total among all cipher suites for
		2*macSize + 2*keySize + 2*ivSize
	Rounded up to nearest PRF block length. We aren't really
		rounding, but just adding another block length for simplicity.
*/
#ifdef USE_TLS_1_2
#define SSL_MAX_KEY_BLOCK_SIZE		((2 * 48) + (2 * 32) + (2 * 16) + \
										SHA256_HASH_SIZE)
#else
#define SSL_MAX_KEY_BLOCK_SIZE		((2 * 48) + (2 * 32) + (2 * 16) + \
										SHA1_HASH_SIZE)
#endif

/*
	Master secret is 48 bytes, sessionId is 32 bytes max
*/
#define		SSL_HS_MASTER_SIZE		48
#define		SSL_MAX_SESSION_ID_SIZE	32

/*
	TLS implementations supporting these ciphersuites MUST support
	arbitrary PSK identities up to 128 octets in length, and arbitrary
	PSKs up to 64 octets in length.  Supporting longer identities and
	keys is RECOMMENDED.
*/
#define SSL_PSK_MAX_KEY_SIZE	64 /* Must be < 256 due to 'idLen' */
#define SSL_PSK_MAX_ID_SIZE		128 /* Must be < 256 due to 'idLen' */
#define SSL_PSK_MAX_HINT_SIZE	32 /* ServerKeyExchange hint is non-standard */

#ifdef USE_DTLS
#define	MAX_FRAGMENTS	8
#define PS_MIN_PMTU		256

typedef struct {
	int32	offset;
	int32	fragLen;
	char	*hsHeader;
} dtlsFragHdr_t;

#ifndef USE_DTLS_DEBUG_TRACE
#define psTraceDtls(x)
#define psTraceIntDtls(x, y)
#define psTraceStrDtls(x, y)
#else
#define psTraceDtls(x) _psTrace(x)
#define psTraceIntDtls(x, y) _psTraceInt(x, y)
#define psTraceStrDtls(x, y) _psTraceStr(x, y)
#endif /* USE_DTLS_DEBUG_TRACE */

#endif /* USE_DTLS */


#ifndef USE_SSL_HANDSHAKE_MSG_TRACE
#define psTraceHs(x)
#define psTraceStrHs(x, y)
#else
#define psTraceHs(x) _psTrace(x)
#define psTraceStrHs(x, y) _psTraceStr(x, y)
#endif /* USE_SSL_HANDSHAKE_MSG_TRACE */

#ifndef USE_SSL_INFORMATIONAL_TRACE
#define psTraceInfo(x)
#define psTraceStrInfo(x, y)
#define psTraceIntInfo(x, y)
#else
#define psTraceInfo(x) _psTrace(x)
#define psTraceStrInfo(x, y) _psTraceStr(x, y)
#define psTraceIntInfo(x, y) _psTraceInt(x, y)
#endif /* USE_SSL_INFORMATIONAL_TRACE */

/******************************************************************************/

struct ssl;

typedef psBuf_t	sslBuf_t;

/******************************************************************************/

#ifdef USE_PSK_CIPHER_SUITE
typedef struct psPsk {
	unsigned char	*pskKey;
	uint8_t			pskLen;
	unsigned char	*pskId;
	uint8_t			pskIdLen;
	struct psPsk	*next;
} psPsk_t;
#endif /* USE_PSK_CIPHER_SUITE */

typedef	int32_t (*pskCb_t)(struct ssl *ssl,
				const unsigned char pskId[SSL_PSK_MAX_ID_SIZE], uint8_t pskIdLen,
				unsigned char *psk[SSL_PSK_MAX_KEY_SIZE], uint8_t *pskLen);

#if defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS)
typedef int32 (*sslSessTicketCb_t)(void *keys, unsigned char[16], short);

typedef struct sessTicketKey {
	unsigned char			name[16];
	unsigned char			symkey[32];
	unsigned char			hashkey[32];
	short					nameLen, symkeyLen, hashkeyLen, inUse;
	struct sessTicketKey	*next;
} psSessionTicketKeys_t;
#endif

/******************************************************************************/
/*
	TLS authentication keys structures
*/
#if defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
#define ECC_EPHEMERAL_CACHE_SECONDS	(2 * 60 * 60) /**< Max lifetime in sec */
#ifdef NO_ECC_EPHEMERAL_CACHE
#define ECC_EPHEMERAL_CACHE_USAGE	0       /**< Cache not used */
#else
#define ECC_EPHEMERAL_CACHE_USAGE	1000	/**< Maximum use count of key */
#endif
typedef struct {
#ifdef USE_MULTITHREADING
	psMutex_t		lock;
#endif
#ifdef USE_ECC
	psEccKey_t		eccPrivKey; /**< Cached ephemeral key */
	psEccKey_t		eccPubKey; /**< Cached remote ephemeral pub key */
	psTime_t		eccPrivKeyTime;	/**< Time key was generated */
	uint16_t		eccPrivKeyUse;	/**< Use count */
	uint16_t		eccPubKeyCurveId;	/**< Curve the point is on */
	unsigned char	eccPubKeyRaw[132];	/**< Max size of secp521r1 */
#endif
#ifdef REQUIRE_DH_PARAMS
#endif
} ephemeralKeyCache_t;
#endif /* defined(USE_ECC) || defined(REQUIRE_DH_PARAMS) */

typedef struct {
	psPool_t		*pool;
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	//TODO - verify that the public part of the privKey is equal to the pubkey
	//in the cert
	psPubKey_t		privKey;
	psX509Cert_t	*cert;
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	psX509Cert_t	*CAcerts;
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#ifdef REQUIRE_DH_PARAMS
	psDhParams_t	dhParams;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_PSK_CIPHER_SUITE
	psPsk_t			*pskKeys;
#endif /* USE_PSK_CIPHER_SUITE */
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS)
	psSessionTicketKeys_t	*sessTickets;
	sslSessTicketCb_t		ticket_cb;
#endif
#if defined(USE_OCSP) && defined(USE_SERVER_SIDE_SSL)
	unsigned char	*OCSPResponseBuf;
	uint16_t		OCSPResponseBufLen;
#endif
#if defined(USE_SCT) && defined(USE_SERVER_SIDE_SSL)
	unsigned char	*SCTResponseBuf;
	uint16_t		SCTResponseBufLen;
#endif
	void			*poolUserPtr; /* Data that will be given to psOpenPool
									for any operations involving these keys */
#if defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
	ephemeralKeyCache_t	cache;
#endif
} sslKeys_t;

/******************************************************************************/
/* Type to pass optional features to NewSession calls */
typedef struct {
	short		ticketResumption; /* Client: 1 to use.  Server N/A */
	short		maxFragLen; /* Client: 512 etc..  Server: -1 to disable */
	short		truncHmac; /* Client: 1 to use.  Server: -1 to disable */
	short		extendedMasterSecret; /* On by default.  -1 to disable */
	short		trustedCAindication; /* Client: 1 to use */
	short		fallbackScsv; /* Client: 1 to use */
#ifdef USE_OCSP
	short		OCSPstapling; /* Client: 1 to send status_request */
#endif	
#ifdef USE_ECC
	int32		ecFlags; /* Elliptic curve set (SSL_OPT_SECP192R1 etc.) */
#endif
	int32		versionFlag; /* The SSL_FLAGS_TLS_ version (+ DTLS flag here) */
	void		*userPtr; /* Initial value of ssl->userPtr during NewSession */
	void		*memAllocPtr; /* Will be passed to psOpenPool for each call
								related to this session */
	psPool_t	*bufferPool; /* Optional mem pool for inbuf and outbuf */
} sslSessOpts_t;

typedef struct {
    unsigned short  keyType;
    unsigned short	hashAlg;
	unsigned short	curveFlags;
	unsigned short	dhParamsRequired;
	char			*serverName;
} sslPubkeyId_t;

typedef sslKeys_t *(*pubkeyCb_t)(struct ssl *ssl, const sslPubkeyId_t *keyId);
typedef int32_t (*sslExtCb_t)(struct ssl *ssl, uint16_t extType, uint8_t extLen,
				void *e);
typedef int32_t (*sslCertCb_t)(struct ssl *ssl, psX509Cert_t *cert, int32_t alert);

#ifdef USE_OCSP
typedef int32_t (*ocspCb_t)(struct ssl *ssl, mOCSPResponse_t *response,
		psX509Cert_t *cert, int32_t status);
#endif

/******************************************************************************/
/*
	SSL record and session structures
*/
typedef struct {
	unsigned short	len;
	unsigned char	majVer;
	unsigned char	minVer;
#ifdef USE_DTLS
	unsigned char	epoch[2];	/* incoming epoch number */
	unsigned char	rsn[6];		/* incoming record sequence number */
#endif /* USE_DTLS */
#ifdef USE_CERT_CHAIN_PARSING
	unsigned short	hsBytesHashed;
	unsigned short	hsBytesParsed;
	unsigned short	trueLen;
	unsigned char	partial;
	unsigned char	certPad;
#endif
	unsigned char	type;
	unsigned char	pad[3];		/* Padding for 64 bit compat */
} sslRec_t;

typedef struct {
	unsigned char	clientRandom[SSL_HS_RANDOM_SIZE];	/* From ClientHello */
	unsigned char	serverRandom[SSL_HS_RANDOM_SIZE];	/* From ServerHello */
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
	unsigned char	*premaster;							/* variable size */
	uint16_t		premasterSize;

	unsigned char	keyBlock[SSL_MAX_KEY_BLOCK_SIZE];	/* Storage for 'ptr' */
	unsigned char	*wMACptr;
	unsigned char	*rMACptr;
	unsigned char	*wKeyptr;
	unsigned char	*rKeyptr;

	/*	All maximum sizes for current cipher suites */
	unsigned char	writeMAC[SSL_MAX_MAC_SIZE];
	unsigned char	readMAC[SSL_MAX_MAC_SIZE];
	unsigned char	writeKey[SSL_MAX_SYM_KEY_SIZE];
	unsigned char	readKey[SSL_MAX_SYM_KEY_SIZE];
	unsigned char	*wIVptr;
	unsigned char	*rIVptr;
	unsigned char	writeIV[SSL_MAX_IV_SIZE];
	unsigned char	readIV[SSL_MAX_IV_SIZE];

	unsigned char	seq[8];
	unsigned char	remSeq[8];

	pskCb_t			pskCb;

#ifndef USE_ONLY_PSK_CIPHER_SUITE
	pubkeyCb_t		pubkeyCb;
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	psX509Cert_t	*cert;
	sslCertCb_t		validateCert;
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_CLIENT_SIDE_SSL
	int32				certMatch;
#endif /* USE_CLIENT_SIDE_SSL */

	psCipherContext_t	encryptCtx;
	psCipherContext_t	decryptCtx;

#ifndef USE_ONLY_TLS_1_2
	psMd5Sha1_t			msgHashMd5Sha1;
#endif

#ifdef USE_TLS_1_2
	psSha256_t			msgHashSha256;

#ifdef USE_SHA1
	psSha1_t			msgHashSha1;
#endif
#ifdef USE_SHA384
	psSha384_t			msgHashSha384;
#endif
#ifdef USE_SHA512
	psSha512_t			msgHashSha512;
#endif
#endif /* USE_TLS_1_2 */

#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
	unsigned char		sha1Snapshot[SHA1_HASH_SIZE];
	unsigned char		sha384Snapshot[SHA384_HASH_SIZE]; /* HW crypto uses
															outside TLS 1.2 */
	unsigned char		sha512Snapshot[SHA512_HASH_SIZE];
#endif

#if defined(USE_PSK_CIPHER_SUITE) && defined(USE_CLIENT_SIDE_SSL)
	unsigned char		*hint;
	uint8_t				hintLen;
#endif /* USE_PSK_CIPHER_SUITE && USE_CLIENT_SIDE_SSL */

#ifdef REQUIRE_DH_PARAMS
	unsigned char		*dhP;			/* prime/modulus */
	unsigned char		*dhG;			/* base/generator */
	uint16_t			dhPLen;
	uint16_t			dhGLen;
	psDhKey_t			*dhKeyPub;		/* remote key */
	psDhKey_t			*dhKeyPriv;		/* local key */
	psPool_t			*dhKeyPool;		/* handshake-scope pool for clients */
#endif

#ifdef USE_ECC_CIPHER_SUITE
	psEccKey_t			*eccKeyPriv; /* local key */
	psEccKey_t			*eccKeyPub; /* remote key */
	psPool_t			*eccDhKeyPool; /* handshake-scope pool for clients */
#endif

	int32				anon;
} sslSec_t;

typedef struct {
	uint16_t		ident;	/* Official cipher ID */
	uint16_t		type;	/* Key exchange method */
	uint32_t		flags;	/* from CRYPTO_FLAGS_* */
	uint8_t 		macSize;
	uint8_t			keySize;
	uint8_t			ivSize;
	uint8_t			blockSize;
	/* Init function */
	int32 (*init)(sslSec_t *sec, int32 type, uint32 keysize);
	/* Cipher functions */
	int32 (*encrypt)(void *ssl, unsigned char *in,
		unsigned char *out, uint32 len);
	int32 (*decrypt)(void *ssl, unsigned char *in,
		unsigned char *out, uint32 len);
	int32 (*generateMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);
	int32 (*verifyMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);
} sslCipherSpec_t;


#ifdef USE_STATELESS_SESSION_TICKETS
enum sessionTicketState_e {
	SESS_TICKET_STATE_INIT = 0,
	SESS_TICKET_STATE_SENT_EMPTY,
	SESS_TICKET_STATE_SENT_TICKET,
	SESS_TICKET_STATE_RECVD_EXT,
	SESS_TICKET_STATE_IN_LIMBO,
	SESS_TICKET_STATE_USING_TICKET
};
#endif

/* Used by user code to store cached session info after the ssl_t is closed */
typedef struct {
	psPool_t		*pool;
	unsigned char	id[SSL_MAX_SESSION_ID_SIZE];
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
	uint32			cipherId;
#ifdef USE_STATELESS_SESSION_TICKETS
	unsigned char	*sessionTicket;		/* Duplicated into 'pool' */
	uint16			sessionTicketState;	/* Not an enum to ensure 2 bytes */
	uint16			sessionTicketLen;	/* Max 32767 */
	uint32			sessionTicketLifetimeHint;
#endif
} sslSessionId_t;

/* Used internally by the session cache table to store session parameters */
typedef struct {
	unsigned char	id[SSL_MAX_SESSION_ID_SIZE];
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
	const sslCipherSpec_t	*cipher;
	unsigned char	majVer;
	unsigned char	minVer;
	short			extendedMasterSecret; /* was the extension used? */
	psTime_t		startTime;
	int32			inUse;
	DLListEntry		chronList;
} sslSessionEntry_t;

/* Used by user code to define custom hello extensions */
typedef struct tlsHelloExt {
	psPool_t			*pool;
	int32				extType;
	uint32				extLen;
	unsigned char		*extData;
	struct tlsHelloExt	*next;
} tlsExtension_t;

/* Hold the info needed to perform a public key operation for flight writes
	until the very end.  This is an architectural change that was added to aid
	the	integration of non-blocking hardware acceleration */
enum {
	PKA_AFTER_RSA_SIG_GEN_ELEMENT = 1,
	PKA_AFTER_RSA_SIG_GEN,
	PKA_AFTER_ECDSA_SIG_GEN,
	PKA_AFTER_RSA_ENCRYPT, /* standard RSA CKE operation */
	PKA_AFTER_ECDH_KEY_GEN, /* ECDH CKE operation. makeKey */
	PKA_AFTER_ECDH_SECRET_GEN, /* GenSecret */
	PKA_AFTER_ECDH_SECRET_GEN_DONE, /* Control for single-pass op */
	PKA_AFTER_DH_KEY_GEN /* DH CKE operation */
};

typedef struct {
	unsigned char	*inbuf; /* allocated to handshake pool */
	unsigned char	*outbuf;
	void			*data; /* hw pkiData */
	uint16_t		inlen;
	uint16_t		type; /* one of PKA_AFTER_* */
	uint16_t		user; /* user size */
	psPool_t		*pool;
} pkaAfter_t;

typedef struct nextMsgInFlight {
	unsigned char	*start;
	unsigned char	*seqDelay;
	int32			len;
	int32			type;
	int32			messageSize;
	int32			padLen;
	int32			hsMsg;
#ifdef USE_DTLS
	int32			fragCount;
#endif
	struct nextMsgInFlight	*next;
} flightEncode_t;

struct ssl {
	sslRec_t		rec;			/* Current SSL record information*/

	sslSec_t		sec;			/* Security structure */

	sslKeys_t		*keys;			/* SSL public and private keys */

	pkaAfter_t		pkaAfter[2];	/* Cli-side cli-auth = two PKA in flight */
	flightEncode_t	*flightEncode;
	unsigned char	*delayHsHash;
	unsigned char	*seqDelay;	/* tmp until flightEncode_t is built */

	psPool_t		*bufferPool; /* If user passed options.bufferPool to
									NewSession, this is inbuf and outbuf pool */
	psPool_t		*sPool;			/* SSL session pool */
	psPool_t		*hsPool;		/* Full session handshake pool */
	psPool_t		*flightPool;	/* Small but handy */

	unsigned char	sessionIdLen;
	unsigned char	sessionId[SSL_MAX_SESSION_ID_SIZE];
	sslSessionId_t	*sid;
	char			*expectedName;	/* Clients: The expected cert subject name
											passed to NewClient Session 
									   Servers: Holds SNI value */
#ifdef USE_SERVER_SIDE_SSL
	uint16			disabledCiphers[SSL_MAX_DISABLED_CIPHERS];
	void			(*sni_cb)(void *ssl, char *hostname, int32 hostnameLen,
						sslKeys_t **newKeys);
#ifdef USE_ALPN
	void			(*srv_alpn_cb)(void *ssl, short protoCount,
						char *proto[MAX_PROTO_EXT],
						int32 protoLen[MAX_PROTO_EXT], int32 *index);
	char			*alpn; /* proto user has agreed to use */
	int32			alpnLen;
#endif /* USE_ALPN */
#endif /* USE_SERVER_SIDE_SSL */
#ifdef USE_CLIENT_SIDE_SSL
	/* Just to handle corner case of app data tacked on HELLO_REQUEST */
	int32			anonBk;
	int32			flagsBk;
	uint32			bFlagsBk;
#endif /* USE_CLIENT_SIDE_SSL */

	unsigned char	*inbuf;
	unsigned char	*outbuf;
	int32			inlen;		/* Bytes unprocessed in inbuf */
	int32			outlen;		/* Bytes unsent in outbuf */
	int32			insize;		/* Total allocated size of inbuf */
	int32			outsize;	/* Total allocated size of outbuf */
	uint32			bFlags;		/* Buffer related flags */

	int32			maxPtFrag;	/* 16K by default - SSL_MAX_PLAINTEXT_LEN */
	unsigned char	*fragMessage; /* holds the constructed fragmented message */
	uint32			fragIndex;	/* How much data has been written to msg */
	uint32			fragTotal;	/* Total length of fragmented message */

	/* Pointer to the negotiated cipher information */
	const sslCipherSpec_t	*cipher;

	/* 	Symmetric cipher callbacks

		We duplicate these here from 'cipher' because we need to set the
		various callbacks at different times in the handshake protocol
		Also, there are 64 bit alignment issues in using the function pointers
		within 'cipher' directly
	*/
	int32 (*encrypt)(void *ctx, unsigned char *in,
		unsigned char *out, uint32 len);
	int32 (*decrypt)(void *ctx, unsigned char *in,
		unsigned char *out, uint32 len);
	/* Message Authentication Codes */
	int32 (*generateMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);
	int32 (*verifyMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);

	/* Current encryption/decryption parameters */
	unsigned char	enMacSize;
	unsigned char	nativeEnMacSize; /* truncated hmac support */
	unsigned char	enIvSize;
	unsigned char	enBlockSize;
	unsigned char	deMacSize;
	unsigned char	nativeDeMacSize; /* truncated hmac support */
	unsigned char	deIvSize;
	unsigned char	deBlockSize;

	uint32_t		flags;			/* SSL_FLAGS_ */
	int32_t			err;			/* SSL errno of last api call */
	int32_t			ignoredMessageCount;

	uint8_t			hsState;		/* Next expected SSL_HS_ message type */
	uint8_t			decState;		/* Most recent encoded SSL_HS_ message */
	uint8_t			encState;		/* Most recent decoded SSL_HS_ message */
	uint8_t			reqMajVer;
	uint8_t			reqMinVer;
	uint8_t			majVer;
	uint8_t			minVer;
	uint8_t			outRecType;

#ifdef ENABLE_SECURE_REHANDSHAKES
	unsigned char	myVerifyData[SHA384_HASH_SIZE]; /*SSLv3 max*/
	unsigned char	peerVerifyData[SHA384_HASH_SIZE];
	uint32			myVerifyDataLen;
	uint32			peerVerifyDataLen;
	int32			secureRenegotiationFlag;
#endif /* ENABLE_SECURE_REHANDSHAKES */
#ifdef SSL_REHANDSHAKES_ENABLED
	int32			rehandshakeCount; /* Make this an internal define of 1 */
	int32			rehandshakeBytes; /* Make this an internal define of 10MB */
#endif /* SSL_REHANDSHAKES_ENABLED */

	sslExtCb_t		extCb;
#ifdef USE_ECC
	struct {
		uint32		ecFlags:24;
		uint32		ecCurveId:8;
	} ecInfo;
#endif
#ifdef USE_TLS_1_2
	uint16_t		hashSigAlg;
#endif

#ifdef USE_DTLS
#ifdef USE_SERVER_SIDE_SSL
	unsigned char	srvCookie[DTLS_COOKIE_SIZE]; /* server can avoid allocs */
#endif
#ifdef USE_CLIENT_SIDE_SSL
	unsigned char	*cookie;	/* hello_verify_request cookie */
	int32			cookieLen;	/* cookie length */
	int32			haveCookie;	/* boolean for cookie existence */
#endif
	unsigned char	*helloExt;	/* need to save the original client hello ext */
	int32			helloExtLen;
	unsigned char	hsSnapshot[SHA512_HASH_SIZE]; /*SSLv3 max*/
	int32			hsSnapshotLen;
	uint16_t		cipherSpec[8]; /* also needed for the cookie client hello */
	uint8_t			cipherSpecLen;
	unsigned char	epoch[2];	/* Current epoch number to send with msg */
	unsigned char	resendEpoch[2];	/* Starting epoch to use for resends */
	unsigned char	expectedEpoch[2];	/* Expected incoming epoch */
	unsigned char	largestEpoch[2]; /* FINISH resends need to incr epoch */
	unsigned char	rsn[6];			/* Last Record Sequence Number sent */
	unsigned char	largestRsn[6];	/* Needed for resends of CCS flight */
	unsigned char	lastRsn[6];	/* Last RSN received (for replay detection) */
	unsigned long	dtlsBitmap; /* Record replay helper */
	int32			parsedCCS;	/* Set between CCS parse and FINISHED parse */
	int32			msn;		/* Current Message Sequence Number to send */
	int32			resendMsn;	/* Starting MSN to use for resends */
	int32			lastMsn;	/* Last MSN successfully parsed from peer */
	int32			pmtu;		/* path maximum trasmission unit */
	int32			retransmit; /* Flag to know not to update handshake hash */
	uint16			flightDone; /* BOOL to flag when entire hs flight sent */
	uint16			appDataExch; /* BOOL to flag if in application data mode */
	int32			fragMsn;	/* fragment MSN */
	dtlsFragHdr_t	fragHeaders[MAX_FRAGMENTS]; /* header storage for hash */
	int32 (*oencrypt)(void *ctx, unsigned char *in,
					 unsigned char *out, uint32 len);
	int32 (*ogenerateMac)(void *ssl, unsigned char type, unsigned char *data,
						 uint32 len, unsigned char *mac);
	unsigned char	oenMacSize;
	unsigned char	oenNativeHmacSize;
	unsigned char	oenIvSize;
	unsigned char	oenBlockSize;
	unsigned char	owriteIV[16]; /* GCM uses this in the nonce */
	unsigned char	owriteMAC[SSL_MAX_MAC_SIZE];
	psCipherContext_t	oencryptCtx;
#ifdef ENABLE_SECURE_REHANDSHAKES
	unsigned char	omyVerifyData[SHA384_HASH_SIZE];
	uint32			omyVerifyDataLen;
#endif /* ENABLE_SECURE_REHANDSHAKES */
	uint32			ckeSize;
	unsigned char	*ckeMsg;
	unsigned char	*certVerifyMsg;
	int32			certVerifyMsgLen;
	int				ecdsaSizeChange; /* retransmits for ECDSA sig */
#endif /* USE_DTLS */

#ifdef USE_ZLIB_COMPRESSION
	int32			compression;
	z_stream		inflate;
	z_stream		deflate;
	unsigned char	*zlibBuffer; /* scratch pad for inflate/deflate data */
#endif

	struct {
#ifdef USE_CLIENT_SIDE_SSL
		/* Did the client request the extension? */
		uint32		req_sni: 1;
		uint32		req_max_fragment_len: 1;
		uint32		req_truncated_hmac: 1;
		uint32		req_extended_master_secret: 1;
		uint32		req_elliptic_curve: 1;
		uint32		req_elliptic_points: 1;
		uint32		req_signature_algorithms: 1;
		uint32		req_alpn: 1;
		uint32		req_session_ticket: 1;
		uint32		req_renegotiation_info: 1;
		uint32		req_fallback_scsv: 1;
		uint32		req_status_request: 1;
#endif
#ifdef USE_SERVER_SIDE_SSL
		/* Whether the server will deny the extension */
		uint32		deny_truncated_hmac: 1;
		uint32		deny_max_fragment_len: 1;
		uint32		deny_session_ticket: 1;
#endif
		/* Set if the extension was negotiated successfully */
		uint32		sni: 1;
		uint32		truncated_hmac: 1;
		uint32		extended_master_secret: 1;
		uint32		session_id: 1;
		uint32		session_ticket: 1;
		uint32		status_request: 1;	/* received EXT_STATUS_REQUEST */
		uint32		status_request_v2: 1;	/* received EXT_STATUS_REQUEST_V2 */
		uint32		signed_certificate_timestamp: 1; /* received EXT_SIGNED_CERTIFICATE_TIMESTAMP */
		uint32		require_extended_master_secret: 1; /* peer may require */
	} extFlags;	/**< Extension flags */

#ifdef USE_MATRIX_OPENSSL_LAYER
	int (*verify_callback)(int alert, psX509Cert_t *data);
#endif
	int32			recordHeadLen;
	int32			hshakeHeadLen;
#ifdef USE_MATRIXSSL_STATS
	void (*statCb)(void *ssl, void *stats_ptr, int32 type, int32 value);
	void *statsPtr;
#endif
	void *memAllocPtr; /* Will be passed to psOpenPool for each call
							related to this session */
	void *userPtr;
};

typedef struct ssl ssl_t;

/******************************************************************************/
/*
	Former public APIS in 1.x and 2.x. Now deprecated in 3.x
	These functions are still heavily used internally, just no longer publically
	supported.
 */
extern int32 matrixSslDecode(ssl_t *ssl, unsigned char **buf, uint32 *len,
						uint32 size, uint32 *remaining, uint32 *requiredLen,
						int32 *error, unsigned char *alertLevel,
						unsigned char *alertDescription);
extern int32 matrixSslEncode(ssl_t *ssl, unsigned char *buf, uint32 size,
						unsigned char *ptBuf, uint32 *len);
extern int32	matrixSslGetEncodedSize(ssl_t *ssl, uint32 len);
extern void		matrixSslSetCertValidator(ssl_t *ssl, sslCertCb_t certValidator);
extern int32	matrixSslNewSession(ssl_t **ssl, const sslKeys_t *keys,
					sslSessionId_t *session, sslSessOpts_t *options);
extern void		matrixSslSetSessionOption(ssl_t *ssl, int32 option,	void *arg);
extern int32_t	matrixSslHandshakeIsComplete(const ssl_t *ssl);

/* This used to be prefixed with 'matrix' */
extern int32	sslEncodeClosureAlert(ssl_t *ssl, sslBuf_t *out,
									  uint32 *reqLen);

extern int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out,
				uint32 *reqLen);
extern int32_t matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
				const uint16_t cipherSpec[], uint8_t cipherSpecLen,
				uint32 *requiredLen, tlsExtension_t *userExt,
				sslSessOpts_t *options);

#ifdef USE_CLIENT_SIDE_SSL
extern int32	matrixSslGetSessionId(ssl_t *ssl, sslSessionId_t *sessionId);
#endif /* USE_CLIENT_SIDE_SSL */

#ifdef USE_SSL_INFORMATIONAL_TRACE
extern void matrixSslPrintHSDetails(ssl_t *ssl);
#endif /* USE_SSL_INFORMATIONAL_TRACE */

#ifdef SSL_REHANDSHAKES_ENABLED
PSPUBLIC int32 matrixSslGetRehandshakeCredits(ssl_t *ssl);
PSPUBLIC void matrixSslAddRehandshakeCredits(ssl_t *ssl, int32 credits);
#endif

#ifdef USE_ZLIB_COMPRESSION
PSPUBLIC int32 matrixSslIsSessionCompressionOn(ssl_t *ssl);
#endif

/******************************************************************************/
/*
	MatrixSSL internal cert functions
*/

#ifndef USE_ONLY_PSK_CIPHER_SUITE
extern int32 matrixValidateCerts(psPool_t *pool, psX509Cert_t *subjectCerts,
				psX509Cert_t *issuerCerts, char *expectedName,
				psX509Cert_t **foundIssuer, void *pkiData, void *userPoolPtr);
extern int32 matrixUserCertValidator(ssl_t *ssl, int32 alert,
				 psX509Cert_t *subjectCert, sslCertCb_t certCb);
#endif /* USE_ONLY_PSK_CIPHER_SUITE */


/******************************************************************************/
/*
	handshakeDecode.c and extensionDecode.c
*/
#ifdef USE_SERVER_SIDE_SSL
extern int32 parseClientHello(ssl_t *ssl, unsigned char **cp,
				unsigned char *end);
extern int32 parseClientHelloExtensions(ssl_t *ssl, unsigned char **cp,
				unsigned short len);
extern int32 parseClientKeyExchange(ssl_t *ssl, int32 hsLen, unsigned char **cp,
				unsigned char *end);
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_CLIENT_AUTH
extern int32 parseCertificateVerify(ssl_t *ssl,
				unsigned char hsMsgHash[SHA512_HASH_SIZE], unsigned char **cp,
				unsigned char *end);
#endif /* USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_CLIENT_SIDE_SSL
extern int32 parseServerHello(ssl_t *ssl, int32 hsLen, unsigned char **cp,
				unsigned char *end);
extern int32 parseServerHelloExtensions(ssl_t *ssl, int32 hsLen,
				unsigned char *extData,	unsigned char **cp,
				unsigned short len);
extern int32 parseServerHelloDone(ssl_t *ssl, int32 hsLen, unsigned char **cp,
				unsigned char *end);
extern int32 parseServerKeyExchange(ssl_t *ssl,
				unsigned char hsMsgHash[SHA512_HASH_SIZE],
				unsigned char **cp,	unsigned char *end);
#ifdef USE_OCSP
extern int32 parseCertificateStatus(ssl_t *ssl, int32 hsLen, unsigned char **cp,
				unsigned char *end);
#endif
#ifndef USE_ONLY_PSK_CIPHER_SUITE
extern int32 parseCertificateRequest(ssl_t *ssl, int32 hsLen,
				unsigned char **cp,	unsigned char *end);
#endif
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
extern int32 parseCertificate(ssl_t *ssl, unsigned char **cp,
				unsigned char *end);
#endif
#endif

extern int32 parseFinished(ssl_t *ssl, int32 hsLen,
				unsigned char hsMsgHash[SHA384_HASH_SIZE], unsigned char **cp,
				unsigned char *end);

/******************************************************************************/
/*
	sslEncode.c and sslDecode.c
*/
extern int32 psWriteRecordInfo(ssl_t *ssl, unsigned char type, int32 len,
							 unsigned char *c, int32 hsType);
extern int32 psWriteHandshakeHeader(ssl_t *ssl, unsigned char type, int32 len,
								int32 seq, int32 fragOffset, int32 fragLen,
								unsigned char *c);
extern int32 sslEncodeResponse(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen);
extern int32 sslActivateReadCipher(ssl_t *ssl);
extern int32 sslActivateWriteCipher(ssl_t *ssl);
extern int32_t sslUpdateHSHash(ssl_t *ssl, const unsigned char *in, uint16_t len);
extern int32 sslInitHSHash(ssl_t *ssl);
extern int32 sslSnapshotHSHash(ssl_t *ssl, unsigned char *out, int32 senderFlag);
extern int32 sslWritePad(unsigned char *p, unsigned char padLen);
extern int32 sslCreateKeys(ssl_t *ssl);
extern void sslResetContext(ssl_t *ssl);
extern void clearPkaAfter(ssl_t *ssl);
extern pkaAfter_t *getPkaAfter(ssl_t *ssl);
extern void freePkaAfter(ssl_t *ssl);
extern void clearFlightList(ssl_t *ssl);

#ifdef USE_SERVER_SIDE_SSL
extern int32 matrixRegisterSession(ssl_t *ssl);
extern int32 matrixResumeSession(ssl_t *ssl);
extern int32 matrixClearSession(ssl_t *ssl, int32 remove);
extern int32 matrixUpdateSession(ssl_t *ssl);
extern int32 matrixServerSetKeysSNI(ssl_t *ssl, char *host, int32 hostLen);

#ifdef USE_STATELESS_SESSION_TICKETS
extern int32 matrixSessionTicketLen(void);
extern int32 matrixCreateSessionTicket(ssl_t *ssl, unsigned char *out,
				int32 *outLen);
extern int32 matrixUnlockSessionTicket(ssl_t *ssl, unsigned char *in,
				int32 inLen);
extern int32 matrixSessionTicketLen(void);
#endif
#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_DTLS
extern int32 dtlsChkReplayWindow(ssl_t *ssl, unsigned char *seq64);
extern int32 dtlsWriteCertificate(ssl_t *ssl, int32 certLen,
								  int32 lsize, unsigned char *c);
extern int32 dtlsWriteCertificateRequest(psPool_t *pool, ssl_t *ssl, int32 certLen,
						   int32 certCount, int32 sigHashLen, unsigned char *c);
extern int32 dtlsComputeCookie(ssl_t *ssl, unsigned char *helloBytes,
							   int32 helloLen);
extern void dtlsInitFrag(ssl_t *ssl);
extern int32 dtlsSeenFrag(ssl_t *ssl, int32 fragOffset, int32 *hdrIndex);
extern int32 dtlsHsHashFragMsg(ssl_t *ssl);
extern int32 dtlsCompareEpoch(unsigned char *incoming, unsigned char *expected);
extern void incrTwoByte(ssl_t *ssl, unsigned char *c, int sending);
extern void zeroTwoByte(unsigned char *c);
extern void dtlsIncrRsn(ssl_t *ssl);
extern void zeroSixByte(unsigned char *c);
extern int32 dtlsGenCookieSecret(void);
extern int32 dtlsEncryptFragRecord(ssl_t *ssl, flightEncode_t *msg,
				sslBuf_t *out, unsigned char **c);
#endif /* USE_DTLS */

/*
	cipherSuite.c
*/
extern int32 chooseCipherSuite(ssl_t *ssl, unsigned char *listStart,
				int32 listLen);
extern const sslCipherSpec_t *sslGetDefinedCipherSpec(uint16_t id);
extern const sslCipherSpec_t *sslGetCipherSpec(const ssl_t *ssl, uint16_t id);
extern int32_t sslGetCipherSpecListLen(const ssl_t *ssl);
extern int32_t sslGetCipherSpecList(ssl_t *ssl, unsigned char *c, int32 len,
				int32 addScsv);
extern int32_t haveKeyMaterial(const ssl_t *ssl, int32 cipherType, short reallyTest);
#ifdef USE_CLIENT_SIDE_SSL
int32 csCheckCertAgainstCipherSuite(int32 sigAlg, int32 cipherType);
#endif
extern void matrixSslSetKexFlags(ssl_t *ssl);

#ifndef DISABLE_SSLV3
/******************************************************************************/
/*
	sslv3.c
*/
extern int32_t sslGenerateFinishedHash(psMd5Sha1_t *md,
				const unsigned char *masterSecret,
				unsigned char *out, int32 senderFlag);

extern int32_t sslDeriveKeys(ssl_t *ssl);

#ifdef USE_SHA_MAC
extern int32 ssl3HMACSha1(unsigned char *key, unsigned char *seq,
						unsigned char type, unsigned char *data, uint32 len,
						unsigned char *mac);
#endif /* USE_SHA_MAC */

#ifdef USE_MD5_MAC
extern int32 ssl3HMACMd5(unsigned char *key, unsigned char *seq,
						unsigned char type, unsigned char *data, uint32 len,
						unsigned char *mac);
#endif /* USE_MD5_MAC */
#endif /* DISABLE_SSLV3 */

#ifdef USE_TLS
/******************************************************************************/
/*
	tls.c
*/
extern int32 tlsDeriveKeys(ssl_t *ssl);
extern int32 tlsExtendedDeriveKeys(ssl_t *ssl);
extern int32 tlsHMACSha1(ssl_t *ssl, int32 mode, unsigned char type,
						unsigned char *data, uint32 len, unsigned char *mac);

extern int32 tlsHMACMd5(ssl_t *ssl, int32 mode, unsigned char type,
						unsigned char *data, uint32 len, unsigned char *mac);
#ifdef  USE_SHA256
extern int32 tlsHMACSha2(ssl_t *ssl, int32 mode, unsigned char type,
						unsigned char *data, uint32 len, unsigned char *mac,
						int32 hashSize);
#endif

/******************************************************************************/

#ifdef USE_TLS_1_2
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
extern int32 sslSha1RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#ifdef USE_SHA384
extern int32 sslSha384RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#endif
#ifdef USE_SHA512
extern int32 sslSha512RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#endif
#endif
#ifdef USE_CLIENT_SIDE_SSL
extern void sslSha1SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#ifdef USE_SHA384
extern void sslSha384SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#endif
#ifdef USE_SHA512
extern void sslSha512SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#endif
#endif
#endif /* USE_TLS_1_2 */

extern int32_t extMasterSecretSnapshotHSHash(ssl_t *ssl, unsigned char *out,
				uint32 *outLen);

/******************************************************************************/
/*
	prf.c
*/
extern int32_t prf(const unsigned char *sec, uint16_t secLen,
				const unsigned char *seed, uint16_t seedLen,
				unsigned char *out, uint16_t outLen);
#ifdef USE_TLS_1_2
extern int32_t prf2(const unsigned char *sec, uint16_t secLen,
				const unsigned char *seed, uint16_t seedLen,
				unsigned char *out, uint16_t outLen, uint32_t flags);
#endif /* USE_TLS_1_2 */
#endif /* USE_TLS */

#ifdef USE_AES_CIPHER_SUITE
extern int32 csAesInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csAesEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csAesDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#ifdef USE_AES_GCM
extern int32 csAesGcmInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csAesGcmEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csAesGcmDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif
#endif /* USE_AES_CIPHER_SUITE */
#ifdef USE_3DES_CIPHER_SUITE
extern int32 csDes3Encrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csDes3Decrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif /* USE_3DES_CIPHER_SUITE */
#ifdef USE_ARC4_CIPHER_SUITE
extern int32 csArc4Encrypt(void *ssl, unsigned char *pt,unsigned char *ct,
					uint32 len);
extern int32 csArc4Decrypt(void *ssl, unsigned char *pt,unsigned char *ct,
					uint32 len);
#endif /* USE_ARC4_CIPHER_SUITE */
#ifdef USE_SEED_CIPHER_SUITE
extern int32 csSeedEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csSeedDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif /* USE_SEED_CIPHER_SUITE */

#ifdef USE_IDEA_CIPHER_SUITE
extern int32 csIdeaInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csIdeaEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csIdeaDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif /* USE_IDEA_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE

extern int32_t matrixSslPskGetKey(ssl_t *ssl, 
				const unsigned char id[SSL_PSK_MAX_ID_SIZE], uint8_t idLen,
				unsigned char *key[SSL_PSK_MAX_KEY_SIZE], uint8_t *keyLen);
extern int32_t matrixSslPskGetKeyId(ssl_t *ssl,
				unsigned char *id[SSL_PSK_MAX_ID_SIZE], uint8_t *idLen,
				const unsigned char hint[SSL_PSK_MAX_HINT_SIZE], uint8_t hintLen);
extern int32_t matrixPskGetHint(ssl_t *ssl,
				unsigned char *hint[SSL_PSK_MAX_HINT_SIZE], uint8_t *hintLen);
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_ECC
extern int32 psTestUserEcID(int32 id, int32 ecFlags);
extern int32 curveIdToFlag(int32 id);
#endif

#ifdef USE_ECC_CIPHER_SUITE
extern int32_t eccSuitesSupported(const ssl_t *ssl,
		const uint16_t cipherSpecs[], uint8_t cipherSpecLen);
#endif /* USE_ECC_CIPHER_SUITE */

/******************************************************************************/
/* Deprected defines for compatibility */
#define CH_RECV_STAT			1
#define CH_SENT_STAT			2
#define SH_RECV_STAT			3
#define SH_SENT_STAT			4
#define ALERT_SENT_STAT			5
#define RESUMPTIONS_STAT		6
#define FAILED_RESUMPTIONS_STAT	7
#define APP_DATA_RECV_STAT		8
#define APP_DATA_SENT_STAT		9

#ifdef USE_MATRIXSSL_STATS
extern void matrixsslUpdateStat(ssl_t *ssl, int32_t type, int32_t value);
#else
static __inline
void matrixsslUpdateStat(ssl_t *ssl, int32_t type, int32_t value)
{
}
#endif /* USE_MATRIXSSL_STATS */

#ifdef __cplusplus
}
#endif

#endif /* _h_MATRIXSSLLIB */

/******************************************************************************/

