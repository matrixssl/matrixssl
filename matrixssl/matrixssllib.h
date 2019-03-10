/**
 *      @file    matrixssllib.h
 *      @version $Format:%h%d$
 *
 *      Internal header file used for the MatrixSSL implementation..
 *      Only modifiers of the library should be intersted in this file
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

#ifndef _h_MATRIXSSLLIB
# define _h_MATRIXSSLLIB

# ifdef __cplusplus
extern "C" {
# endif

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
# ifndef USE_DTLS
/* #define USE_SSL_RSA_WITH_RC4_128_MD5 / **< @security OFF * / */
/* #define USE_SSL_RSA_WITH_RC4_128_SHA / **< @security OFF * / */
/* #define USE_TLS_RSA_WITH_SEED_CBC_SHA / **< @security OFF * / */
/* #define USE_TLS_RSA_WITH_IDEA_CBC_SHA / **< @security OFF * / */
# endif

/** Anonymous, non authenticated ciphers. */
/* #define USE_TLS_DH_anon_WITH_AES_128_CBC_SHA / **< @security OFF * / */
/* #define USE_TLS_DH_anon_WITH_AES_256_CBC_SHA / **< @security OFF * / */
/* #define USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA / **< @security OFF * / */
# ifndef USE_DTLS
/* #define USE_SSL_DH_anon_WITH_RC4_128_MD5 / **< @security OFF * / */
# endif

/** Authenticated but not encrypted ciphers. */
/* #define USE_SSL_RSA_WITH_NULL_SHA / **< @security OFF * / */
/* #define USE_SSL_RSA_WITH_NULL_MD5 / **< @security OFF * / */

/**
    False Start support for Chrome and Firefox browsers.
    @see https://tools.ietf.org/html/rfc7918

    Some versions of Firefox browser and Chrome browser include support for
    False Start. This flag will enable server side support on MatrixSSL
    operating as server for client using false start feature.

    @note April 2012: Google has announced this feature will be removed in
    version 20 of their browser due to industry compatibility issues.
    However because there are other browsers using the feature, this feature
    is often recommendable to enable for maximal browser compatibility.
 */
#ifdef USE_SERVER_SIDE_FALSE_START_SUPPORT
#define ENABLE_FALSE_START
#endif /* USE_SERRVER_SIDE_FALSE_START_SUPPORT */

/**
    zlib compression support.
    @security The CRIME attack on HTTPS has shown that compression at the
    TLS layer can introduce vulnerabilities in higher level protocols. It is
    recommended to NOT use compression features at the TLS level.
 */
/* #define USE_ZLIB_COMPRESSION / **< @security OFF NIST_SHOULD_NOT * / */

/******************************************************************************/
/**
    Rehandshaking support.
    In late 2009 An "authentication gap" exploit was discovered in the
    SSL re-handshaking protocol.  The fix to the exploit was introduced
    in RFC 5746 and is referred to here as SECURE_REHANDSHAKES.

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
# ifdef USE_REHANDSHAKING
/* #define ENABLE_SECURE_REHANDSHAKES / **< @security OFF NIST_SHALL * / */
#  define REQUIRE_SECURE_REHANDSHAKES /**< @security ON NIST_SHALL */
/* #define ENABLE_INSECURE_REHANDSHAKES / ** @security OFF NIST_SHALL_NOT * / */
# endif

# if defined(ENABLE_INSECURE_REHANDSHAKES) || defined(ENABLE_SECURE_REHANDSHAKES)
#  define SSL_REHANDSHAKES_ENABLED
# endif

# if defined(REQUIRE_SECURE_REHANDSHAKES) && !defined(ENABLE_SECURE_REHANDSHAKES)
#  define SSL_REHANDSHAKES_ENABLED
#  define ENABLE_SECURE_REHANDSHAKES
# endif


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
# define USE_BEAST_WORKAROUND /**< @security ON */

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
/* #define USE_CERT_CHAIN_PARSING / **< @note Setting does not affect security * / */

/******************************************************************************/
/**
    Experimental support for process-shared server session cache.
    This allows forked copies of a process to use the same session cache.
    @pre Supported for POSIX environments only currently.
 */
/* #define USE_SHARED_SESSION_CACHE / **< @note Experimental * / */

/******************************************************************************/

# ifdef USE_DTLS
/******************************************************************************/
/** DTLS definitions */
#  define DTLS_COOKIE_SIZE   16
# endif /* USE_DTLS */

/******************************************************************************/
/**
    Include matrixssl external crypto provider layer headers.
 */

# ifdef USE_ZLIB_COMPRESSION
#  include "zlib.h"
# endif

# if defined(USE_AES_GCM) || defined(USE_AES_CCM) || defined(USE_CHACHA20_POLY1305_IETF)
#  define USE_AEAD_CIPHER
# endif

/* PKCS11 is set in crypto. Use all modes of it if enabled */
#  define USE_NATIVE_TLS_ALGS
#  define USE_NATIVE_TLS_HS_HASH
#  define USE_NATIVE_SYMMETRIC

/******************************************************************************/

/******************************************************************************/
/*
    Leave this enabled for run-time check of sslKeys_t content when a cipher
    suite is matched.  Disable only if you need to manage key material yourself.
    Always conditional on whether certificate parsing is enabled because it
    looks at members that only exist if certificates have been parsed
 */
# ifdef USE_CERT_PARSE
#   define VALIDATE_KEY_MATERIAL
# endif /* USE_CERT_PARSE */

/******************************************************************************/

/*
    Magic numbers for handshake header lengths
 */
# define SSL2_HEADER_LEN             2
# define SSL3_HEADER_LEN             5
# define TLS_REC_HDR_LEN             5
# define DTLS_REC_HDR_LEN            13
# define SSL3_HANDSHAKE_HEADER_LEN   4
# define TLS_HS_HDR_LEN              4
# ifdef USE_DTLS
#  define DTLS_HEADER_ADD_LEN        8
# endif
# define DTLS_HEADER_LEN             13

# define TLS_CHACHA20_POLY1305_IETF_AAD_LEN   13
# define TLS_GCM_AAD_LEN                 13
# define TLS_AEAD_SEQNB_LEN              8

# define TLS_GCM_TAG_LEN                 16
# define TLS_CHACHA20_POLY1305_IETF_TAG_LEN   16
# define TLS_CCM_TAG_LEN                 16
# define TLS_CCM8_TAG_LEN                8

# define TLS_AEAD_NONCE_MAXLEN           12/* Maximum length for an AEAD's nonce */
# define TLS_EXPLICIT_NONCE_LEN          8
# define TLS_CHACHA20_POLY1305_IETF_NONCE_LEN 0

# define AEAD_NONCE_LEN(SSL) ((SSL->flags & SSL_FLAGS_NONCE_W) ? TLS_EXPLICIT_NONCE_LEN : 0)
# define AEAD_TAG_LEN(SSL) ((SSL->cipher->flags & CRYPTO_FLAGS_CCM8) ? 8 : 16)

/*
    matrixSslSetSessionOption defines
 */
# define SSL_OPTION_FULL_HANDSHAKE           1
# ifdef USE_CLIENT_AUTH
#  define SSL_OPTION_DISABLE_CLIENT_AUTH      2
#  define SSL_OPTION_ENABLE_CLIENT_AUTH       3
# endif /* USE_CLIENT_AUTH */
# define SSL_OPTION_DISABLE_REHANDSHAKES     4
# define SSL_OPTION_REENABLE_REHANDSHAKES    5

/*
    Use as return code in user validation callback to allow
    anonymous connections to proceed.
    MUST NOT OVERLAP WITH ANY OF THE ALERT CODES ABOVE
 */
# define SSL_ALLOW_ANON_CONNECTION           254

/* Internal values for ssl_t.flags  */
# define SSL_FLAGS_SERVER        (1U << 0)
# define SSL_FLAGS_READ_SECURE   (1U << 1)
# define SSL_FLAGS_WRITE_SECURE  (1U << 2)
# define SSL_FLAGS_RESUMED       (1U << 3)
# define SSL_FLAGS_CLOSED        (1U << 4)
# define SSL_FLAGS_NEED_ENCODE   (1U << 5)
# define SSL_FLAGS_ERROR         (1U << 6)
# define SSL_FLAGS_CLIENT_AUTH   (1U << 7)
# define SSL_FLAGS_ANON_CIPHER   (1U << 8)
# define SSL_FLAGS_FALSE_START   (1U << 9)
# define SSL_FLAGS_SSLV3         (1U << 10)
# define SSL_FLAGS_TLS           (1U << 11)
# define SSL_FLAGS_TLS_1_0       SSL_FLAGS_TLS  /* For naming consistency */
# define SSL_FLAGS_TLS_1_1       (1U << 12)
# define SSL_FLAGS_TLS_1_2       (1U << 13)
# define SSL_FLAGS_DTLS          (1U << 14)
# define SSL_FLAGS_DHE_WITH_RSA  (1U << 15)
# define SSL_FLAGS_DHE_WITH_DSA  (1U << 16)
# define SSL_FLAGS_DHE_KEY_EXCH  (1U << 17)
# define SSL_FLAGS_PSK_CIPHER    (1U << 18)
# define SSL_FLAGS_ECC_CIPHER    (1U << 19)
# define SSL_FLAGS_AEAD_W        (1U << 20)
# define SSL_FLAGS_AEAD_R        (1U << 21)
# define SSL_FLAGS_NONCE_W       (1U << 22)
# define SSL_FLAGS_NONCE_R       (1U << 23)
# define SSL_FLAGS_HTTP2         (1U << 24)
# define SSL_FLAGS_TLS_1_3       (1U << 25)
# define SSL_FLAGS_TLS_1_3_DRAFT_22 (1U << 26)
# define SSL_FLAGS_TLS_1_3_DRAFT_23 (1U << 27)
# define SSL_FLAGS_TLS_1_3_DRAFT_24 (1U << 28)
# define SSL_FLAGS_TLS_1_3_DRAFT_26 (1U << 29)
# define SSL_FLAGS_TLS_1_3_DRAFT_28 (1U << 30)
# define SSL_FLAGS_TLS_1_3_NEGOTIATED (1U << 31)
/*
  The following conflict with TLS 1.3 flags, but interceptor
  and EAP_FAST are not allowed with USE_TLS_1_3.
# ifdef TODO*/
# define SSL_FLAGS_INTERCEPTOR   (1U << 26)
# define SSL_FLAGS_EAP_FAST      (1U << 27)

# define IS_SERVER(SSL) ((SSL->flags & SSL_FLAGS_SERVER) ? PS_TRUE : PS_FALSE)
# define IS_CLIENT(SSL) !IS_SERVER(SSL)

# include "matrixssllib_version.h"
# include "matrixssllib_secconfig.h"

#  define ENCRYPTING_RECORDS(SSL) ((SSL->flags & SSL_FLAGS_WRITE_SECURE) ? PS_TRUE : PS_FALSE)
#  define DECRYPTING_RECORDS(SSL) ((SSL->flags & SSL_FLAGS_READ_SECURE) ? PS_TRUE : PS_FALSE)
#  define RESUMED_HANDSHAKE(SSL) isResumedHandshake(SSL)
#  ifdef USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
#   define DECRYPTING_WITH_CHACHA20(SSL) ((SSL->activeReadCipher != NULL && \
                    (SSL->activeReadCipher->flags & CRYPTO_FLAGS_CHACHA)) ? PS_TRUE : PS_FALSE)
#  else
#   define DECRYPTING_WITH_CHACHA20(SSL) PS_TRUE
#  endif

/* Internal flags for ssl_t.hwflags */
# define SSL_HWFLAGS_HW                  (1 << 0) /* Use HW for decode/encode */
# define SSL_HWFLAGS_HW_SW               (1 << 1) /* Use HW & SW in parallel (debug) */
# define SSL_HWFLAGS_NONBLOCK            (1 << 2) /* Use async HW for decode/encode */
# define SSL_HWFLAGS_PENDING_R           (1 << 3) /* Non-blocking app record read */
# define SSL_HWFLAGS_PENDING_W           (1 << 4) /* Non-blocking app record write */
# define SSL_HWFLAGS_PENDING_FLIGHT_W    (1 << 5) /* mid encryptFlight (hshake) */
# define SSL_HWFLAGS_PENDING_PKA_R       (1 << 6) /* Non-blocking public key op */
# define SSL_HWFLAGS_PENDING_PKA_W       (1 << 7) /* Non-blocking public key op */
# define SSL_HWFLAGS_EAGAIN              (1 << 8) /* Not submitted.  Skip hsHash */
# define SSL_HWFLAGS_HW_BAD              (1 << 9) /* Bad hardware result,go software */

/* Buffer flags (ssl->bFlags) */
# define BFLAG_CLOSE_AFTER_SENT  (1 << 0)
# define BFLAG_HS_COMPLETE       (1 << 1)
# define BFLAG_STOP_BEAST        (1 << 2)
# define BFLAG_KEEP_PEER_CERTS    (1 << 3) /* Keep peer cert chain. */
# define BFLAG_KEEP_PEER_CERT_DER (1 << 4) /* Keep raw DER of peer certs. */


/*
    Number of bytes server must send before creating a re-handshake credit
 */
# define DEFAULT_RH_CREDITS      1/* Allow for one rehandshake by default */
# define BYTES_BEFORE_RH_CREDIT  20 * 1024 * 1024

# ifdef USE_ECC
/* EC flags for sslSessOpts_t */
#  define SSL_OPT_SECP192R1   IS_SECP192R1
#  define SSL_OPT_SECP224R1   IS_SECP224R1
#  define SSL_OPT_SECP256R1   IS_SECP256R1
#  define SSL_OPT_SECP384R1   IS_SECP384R1
#  define SSL_OPT_SECP521R1   IS_SECP521R1
/* WARNING: Public points on Brainpool curves are not validated */
#  define SSL_OPT_BRAIN224R1  IS_BRAIN224R1
#  define SSL_OPT_BRAIN256R1  IS_BRAIN256R1
#  define SSL_OPT_BRAIN384R1  IS_BRAIN384R1
#  define SSL_OPT_BRAIN512R1  IS_BRAIN512R1
# endif

/* Cipher types (internal for CipherSpec_t.type) */
enum PACKED
{
    CS_NULL = 0,
    CS_RSA,
    CS_DHE_RSA,
    CS_DH_ANON,
    CS_DHE_PSK,
    CS_PSK,
    CS_ECDHE_ECDSA,
    CS_ECDHE_RSA,
    CS_ECDH_ECDSA,
    CS_ECDH_RSA,
    CS_TLS13 /* TLS 1.3 suites only specify the symmetric and hash algs. */
};

/*
    These are defines rather than enums because we want to store them as char,
    not int32 (enum size)
 */
# define SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC      (uint8_t) 20
# define SSL_RECORD_TYPE_ALERT                   (uint8_t) 21
# define SSL_RECORD_TYPE_HANDSHAKE               (uint8_t) 22
# define SSL_RECORD_TYPE_APPLICATION_DATA        (uint8_t) 23
# define SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG    (uint8_t) 90  /* internal */
# define SSL_RECORD_TYPE_HANDSHAKE_FRAG          (uint8_t) 91  /* non-standard types */

# define SSL_HS_HELLO_REQUEST        (uint8_t) 0
# define SSL_HS_CLIENT_HELLO         (uint8_t) 1
# define SSL_HS_SERVER_HELLO         (uint8_t) 2
# define SSL_HS_HELLO_VERIFY_REQUEST (uint8_t) 3
# define SSL_HS_NEW_SESSION_TICKET   (uint8_t) 4
# define SSL_HS_EOED                 (uint8_t) 5
# define SSL_HS_ENCRYPTED_EXTENSION  (uint8_t) 8
# define SSL_HS_CERTIFICATE          (uint8_t) 11
# define SSL_HS_SERVER_KEY_EXCHANGE  (uint8_t) 12
# define SSL_HS_CERTIFICATE_REQUEST  (uint8_t) 13
# define SSL_HS_SERVER_HELLO_DONE    (uint8_t) 14
# define SSL_HS_CERTIFICATE_VERIFY   (uint8_t) 15
# define SSL_HS_CLIENT_KEY_EXCHANGE  (uint8_t) 16
# define SSL_HS_FINISHED             (uint8_t) 20
# define SSL_HS_CERTIFICATE_STATUS   (uint8_t) 22

/* TLS 1.3 states. Names are from appendix A. */
# define SSL_HS_TLS_1_3_START         (uint8_t) 23
# define SSL_HS_TLS_1_3_RECVD_CH      (uint8_t) 24
# define SSL_HS_TLS_1_3_NEGOTIATED    (uint8_t) 25
# define SSL_HS_TLS_1_3_WAIT_FLIGHT_2 (uint8_t) 26
# define SSL_HS_TLS_1_3_WAIT_EOED     (uint8_t) 27
# define SSL_HS_TLS_1_3_WAIT_CERT     (uint8_t) 28
# define SSL_HS_TLS_1_3_WAIT_CV       (uint8_t) 29
# define SSL_HS_TLS_1_3_WAIT_FINISHED (uint8_t) 30
# define SSL_HS_TLS_1_3_SEND_NST      (uint8_t) 31

/* TLS 1.3 client-specific states. */
# define SSL_HS_TLS_1_3_WAIT_SH       (uint8_t) 32
# define SSL_HS_TLS_1_3_WAIT_EE       (uint8_t) 33
# define SSL_HS_TLS_1_3_WAIT_CERT_CR  (uint8_t) 34
# define SSL_HS_TLS_1_3_SEND_FINISHED (uint8_t) 35

# define SSL_HS_ALERT                (uint8_t) 252  /* ChangeCipherSuite (internal) */
# define SSL_HS_CCC                  (uint8_t) 253  /* ChangeCipherSuite (internal) */
# define SSL_HS_NONE                 (uint8_t) 254  /* No recorded state (internal) */
# define SSL_HS_DONE                 (uint8_t) 255  /* Handshake complete (internal) */

/*
  Note that the numbering does not match the TLS 1.3 PskKeyExchangeMode
  definition, where psk_ke = 0. This is because we wish to reserve 0 for
  "none" (i.e. non-PSK mode).

  For reference:
  enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
*/
typedef enum psk_key_exchange_mode
{
    psk_keyex_mode_none = 0,
    psk_keyex_mode_psk_ke = 1,
    psk_keyex_mode_psk_dhe_ke = 2
} psk_key_exchange_mode_e;

# ifdef USE_TLS_1_3

/* Last 8 bytes of server_random used for TLS 1.3 downgrade protection
   (4.1.3 in RFC 8446) */
#define TLS13_DOWNGRADE_PROT_TLS12          "\x44\x4f\x57\x4e\x47\x52\x44\x01"
#define TLS13_DOWNGRADE_PROT_TLS11_OR_BELOW "\x44\x4f\x57\x4e\x47\x52\x44\x00"

typedef struct
{
    uint32_t generateEarlySecretDone : 1;
    uint32_t deriveHandshakeTrafficSecretsDone : 1;
    uint32_t deriveHandshakeKeysDone : 1;
    uint32_t deriveAppTrafficSecretsDone : 1;
    uint32_t deriveEarlyDataKeysDone : 1;
    uint32_t deriveAppKeysDone : 1;
    uint32_t deriveServerFinishedKeyDone : 1;
    uint32_t deriveClientFinishedKeyDone : 1;
    uint32_t generateRandomDone : 1;
    uint32_t snapshotCHtoSHDone : 1;
    uint32_t generateEcdheKeyDone : 1;
    uint32_t generateVerifyDataDone : 1;
    uint32_t generateCvSigDone : 1;
} tls13_flight_state_t;
# endif

# define INIT_ENCRYPT_CIPHER     0
# define INIT_DECRYPT_CIPHER     1

# define HMAC_CREATE 1
# define HMAC_VERIFY 2

# ifdef USE_TLS_1_2
/**
   enum {
    none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), (255)
   } HashAlgorithm;
   enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SigAlgorithm;
 */
enum PACKED
{
    HASH_SIG_MD5 = 1,
    HASH_SIG_SHA1,
    HASH_SIG_SHA256 = 4,
    HASH_SIG_SHA384,
    HASH_SIG_SHA512
};

enum PACKED
{
    HASH_SIG_RSA = 1,
    HASH_SIG_ECDSA = 3 /* This 3 is correct for hashSigAlg */
};

/* Internal flag format for algorithms */
enum PACKED
{
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
static inline uint16_t HASH_SIG_MASK(uint8_t hash, uint8_t sig)
{
    /* TODO - do better validation on hash and sig */
    hash = 1 << (hash & 0x7);
    return sig == HASH_SIG_RSA ? hash : ((uint16_t) hash << 8);
}
# endif /* USE_TLS_1_2 */

/* Additional ssl alert value, indicating no error has ocurred.  */
# define SSL_ALERT_NONE              255/* No error */

/* SSL/TLS protocol message sizes */
# define SSL_HS_RANDOM_SIZE          32
# define SSL_HS_RSA_PREMASTER_SIZE   48
# ifdef USE_TLS
#  define TLS_HS_FINISHED_SIZE    12
# endif /* USE_TLS */

/* Major and minor (not minimum!) version numbers for TLS */
# define SSL2_MAJ_VER        2

# define SSL3_MAJ_VER        3
# define SSL3_MIN_VER        0

# define TLS_MAJ_VER         SSL3_MAJ_VER
# define TLS_MIN_VER         1
# define TLS_1_0_MIN_VER     TLS_MIN_VER
# define TLS_1_1_MIN_VER     2
# define TLS_1_2_MIN_VER     3
# define TLS_1_3_MIN_VER     4

# define TLS_1_3_VER 0x0304
# define TLS_1_3_DRAFT_MAJ_VER 0x7f /* Only used in supported_versions ext. */
# define TLS_1_3_DRAFT_22_MIN_VER 0x16 /* Draft 22 */
# define TLS_1_3_DRAFT_22_VER 0x7f16
# define TLS_1_3_DRAFT_23_MIN_VER 0x17 /* Draft 23 */
# define TLS_1_3_DRAFT_23_VER 0x7f17
# define TLS_1_3_DRAFT_24_MIN_VER 0x18 /* Draft 24 */
# define TLS_1_3_DRAFT_24_VER 0x7f18
# define TLS_1_3_DRAFT_26_MIN_VER 0x1a /* Draft 26 */
# define TLS_1_3_DRAFT_26_VER 0x7f1a
# define TLS_1_3_DRAFT_28_MIN_VER 0x1c /* Draft 28 */
# define TLS_1_3_DRAFT_28_VER 0x7f1c
 /* By default, use the RFC instead of draft spec. */
# ifndef TLS_1_3_DRAFT_MIN_VER
#  define TLS_1_3_DRAFT_MIN_VER TLS_1_3_MIN_VER
# endif
# ifndef TLS_1_3_DEFAULT_DRAFT_MIN_VER
#  define TLS_1_3_DEFAULT_DRAFT_MIN_VER TLS_1_3_MIN_VER /* Use RFC version by default*/
# endif

/* Based on settings, define the highest TLS version available */
# if defined(USE_TLS_1_2) && !defined(DISABLE_TLS_1_2)
#  define TLS_HIGHEST_MINOR  TLS_1_2_MIN_VER
# elif defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
#  define TLS_HIGHEST_MINOR  TLS_1_1_MIN_VER
# elif defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
#  define TLS_HIGHEST_MINOR  TLS_1_0_MIN_VER
# elif !defined(DISABLE_SSLV3)
#  define TLS_HIGHEST_MINOR  SSL3_MIN_VER
# else
#  error Unexpected TLS Version
# endif

/* Cipher suite specification IDs, in numerical order. */
# define SSL_NULL_WITH_NULL_NULL                 0x0000
# define SSL_RSA_WITH_NULL_MD5                   0x0001
# define SSL_RSA_WITH_NULL_SHA                   0x0002
# define SSL_RSA_WITH_RC4_128_MD5                0x0004
# define SSL_RSA_WITH_RC4_128_SHA                0x0005
# define TLS_RSA_WITH_IDEA_CBC_SHA               0x0007
# define SSL_RSA_WITH_3DES_EDE_CBC_SHA           0x000A /* 10 */
# define SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA       0x0016 /* 22 */
# define SSL_DH_anon_WITH_RC4_128_MD5            0x0018 /* 24 */
# define SSL_DH_anon_WITH_3DES_EDE_CBC_SHA       0x001B /* 27 */
# define TLS_RSA_WITH_AES_128_CBC_SHA            0x002F /* 47 */
# define TLS_DHE_RSA_WITH_AES_128_CBC_SHA        0x0033 /* 51 */
# define TLS_DH_anon_WITH_AES_128_CBC_SHA        0x0034 /* 52 */
# define TLS_RSA_WITH_AES_256_CBC_SHA            0x0035 /* 53 */
# define TLS_DHE_RSA_WITH_AES_256_CBC_SHA        0x0039 /* 57 */
# define TLS_DH_anon_WITH_AES_256_CBC_SHA        0x003A /* 58 */
# define TLS_RSA_WITH_AES_128_CBC_SHA256         0x003C /* 60 */
# define TLS_RSA_WITH_AES_256_CBC_SHA256         0x003D /* 61 */
# define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256     0x0067 /* 103 */
# define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256     0x006B /* 107 */
# define TLS_RSA_WITH_SEED_CBC_SHA               0x0096 /* 150 */
# define TLS_PSK_WITH_AES_128_CBC_SHA            0x008C /* 140 */
# define TLS_PSK_WITH_AES_128_CBC_SHA256         0x00AE /* 174 */
# define TLS_PSK_WITH_AES_256_CBC_SHA384         0x00AF /* 175 */
# define TLS_PSK_WITH_AES_256_CBC_SHA            0x008D /* 141 */
# define TLS_DHE_PSK_WITH_AES_128_CBC_SHA        0x0090 /* 144 */
# define TLS_DHE_PSK_WITH_AES_256_CBC_SHA        0x0091 /* 145 */
# define TLS_RSA_WITH_AES_128_GCM_SHA256         0x009C /* 156 */
# define TLS_RSA_WITH_AES_256_GCM_SHA384         0x009D /* 157 */
# define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     0x009F /* 159 */

# define TLS_EMPTY_RENEGOTIATION_INFO_SCSV       0x00FF /**< @see RFC 5746 */
# define TLS_FALLBACK_SCSV                       0x5600 /**< @see RFC 7507 */

# define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA     0xC004 /* 49156 */
# define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA     0xC005 /* 49157 */
# define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    0xC009 /* 49161 */
# define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    0xC00A /* 49162 */
# define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     0xC012 /* 49170 */
# define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      0xC013 /* 49171 */
# define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      0xC014 /* 49172 */
# define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA       0xC00E /* 49166 */
# define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA       0xC00F /* 49167 */
# define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC023 /* 49187 */
# define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xC024 /* 49188 */
# define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  0xC025 /* 49189 */
# define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  0xC026 /* 49190 */
# define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   0xC027 /* 49191 */
# define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   0xC028 /* 49192 */
# define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256    0xC029 /* 49193 */
# define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384    0xC02A /* 49194 */
# define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B /* 49195 */
# define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C /* 49196 */
# define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256  0xC02D /* 49197 */
# define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384  0xC02E /* 49198 */
# define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F /* 49199 */
# define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xC030 /* 49200 */
# define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256    0xC031 /* 49201 */
# define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384    0xC032 /* 49202 */
/* Defined in https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */
#  define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xCCA8 /* 52392 */
#  define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA9 /* 52393 */
/* TLS 1.3 ciphersuites. */
#  define TLS_AES_128_GCM_SHA256                 0x1301 /* 4865 */
#  define TLS_AES_256_GCM_SHA384                 0x1302 /* 4866 */
#  define TLS_CHACHA20_POLY1305_SHA256           0x1303 /* 4867 */
#  define TLS_AES_128_CCM_SHA_256                0x1304 /* 4868 */
#  define TLS_AES_128_CCM_8_SHA256               0x1305 /* 4869 */


/*
    Supported HELLO extensions
    Extension status stored by bitfield in ssl_t.extFlags
    @see https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
 */
# define EXT_SNI                              0
# define EXT_SERVER_NAME                      0 /* SNI renamed in TLS 1.3 */
# define EXT_MAX_FRAGMENT_LEN                 1
# define EXT_TRUSTED_CA_KEYS                  3
# define EXT_TRUNCATED_HMAC                   4
# define EXT_STATUS_REQUEST                   5 /* OCSP */
# define EXT_ELLIPTIC_CURVE                  10 /* Client-send only */
# define EXT_SUPPORTED_GROUPS                10 /* ELLIPTIC_CURVE renamed in 1.3 */
# define EXT_ELLIPTIC_POINTS                 11
# define EXT_SIGNATURE_ALGORITHMS            13
# define EXT_ALPN                            16
# define EXT_SIGNED_CERTIFICATE_TIMESTAMP    18
# define EXT_EXTENDED_MASTER_SECRET          23
# define EXT_SESSION_TICKET                  35
# define EXT_KEY_SHARE_PRE_DRAFT_23          40 /* Up to 1.3 draft 22 */
# define EXT_PRE_SHARED_KEY                  41
# define EXT_EARLY_DATA                      42
# define EXT_SUPPORTED_VERSIONS              43
# define EXT_COOKIE                          44
# define EXT_PSK_KEY_EXCHANGE_MODES          45
# define EXT_CERTIFICATE_AUTHORITIES         47
# define EXT_OID_FILTERS                     48
# define EXT_POST_HANDSHAKE_AUTH             49
# define EXT_SIGNATURE_ALGORITHMS_CERT       50
# define EXT_KEY_SHARE                       51 /* Since 1.3 draft 23. */
# define EXT_RENEGOTIATION_INFO              0xFF01

/* How large the ALPN extension arrary is.  Number of protos client can talk */
# define MAX_PROTO_EXT                   8

/*
    Maximum key block size for any defined cipher
    This must be validated if new ciphers are added
    Value is largest total among all cipher suites for
        2*macSize + 2*keySize + 2*ivSize
    Rounded up to nearest PRF block length. We aren't really
        rounding, but just adding another block length for simplicity.
 */
# ifdef USE_TLS_1_2
#  define SSL_MAX_KEY_BLOCK_SIZE      ((2 * 48) + (2 * 32) + (2 * 16) + \
                                       SHA256_HASH_SIZE)
# else
#  define SSL_MAX_KEY_BLOCK_SIZE      ((2 * 48) + (2 * 32) + (2 * 16) + \
                                       SHA1_HASH_SIZE)
# endif
# ifdef USE_EAP_FAST
#  define EAP_FAST_SESSION_KEY_SEED_LEN   40
#  define EAP_FAST_PAC_KEY_LEN            32
#  undef SSL_MAX_KEY_BLOCK_SIZE
#  define SSL_MAX_KEY_BLOCK_SIZE      ((2 * 48) + (2 * 32) + (2 * 16) + \
                                       SHA256_HASH_SIZE + \
                                       EAP_FAST_SESSION_KEY_SEED_LEN)
# endif

/*
    Master secret is 48 bytes, sessionId is 32 bytes max
 */
# define     SSL_HS_MASTER_SIZE      48
# define     SSL_MAX_SESSION_ID_SIZE 32

# ifdef USE_DTLS
#  define MAX_FRAGMENTS   16
#  define PS_MIN_PMTU     256

typedef struct
{
    int32 offset;
    int32 fragLen;
    char *hsHeader;
} dtlsFragHdr_t;
# endif /* USE_DTLS */

/******************************************************************************/

struct ssl;

typedef psBuf_t sslBuf_t;

/** Type of the expectedName parameter (expected peer identity)
    that is passed to matrixValidateCerts or matrixSslNewClientSession.
    These can be used to specify the field in the peer certificate
    against which expectedName is to be matched. */
typedef enum
{
    NAME_TYPE_ANY = 0,        /* Default. Checked against everything listed below.
                                 This option exists for compatibility with earlier
                                 versions, where no attempt was made to distinguish
                                 between different types of expectedNames.
                                 New applications should prefer to pick one of the
                                 more specific types below. */
    NAME_TYPE_HOSTNAME,       /* Checked against the dNSName field and the
                                 subject commonName. This is the default. */
    NAME_TYPE_CN,             /* Checked against the subject commonName.
                                 Note that by default, the subject commonName will only
                                 be checked when there are no supported fields
                                 in the SAN. The flag
                                 VCERTS_MFLAG_ALWAYS_CHECK_SUBJECT_CN can be used
                                 to force a commonName check. */
    NAME_TYPE_SAN_DNS,        /* Checked against the dNSName field. */
    NAME_TYPE_SAN_EMAIL,      /* Checked against the rfc822Name field. */
    NAME_TYPE_SAN_IP_ADDRESS, /* Checked against the iPAddress field. */
} expectedNameType_t;

/** This struct can be used to pass additional options
    to matrixValidateCertsExt */
typedef struct
{
    expectedNameType_t nameType; /* Type of expectedName. */
    uint64_t flags; /* General flags for controling the validation
                       prodecure. The allowed flags have the
                       VCERTS_FLAG_ prefix. */
    uint32_t mFlags; /* Flags for controlling how expectedName should
                        be matched. The allowed flags have the
                        USE VCERTS_MFLAG prefix. */
    int32_t max_verify_depth; /* Maximum allowed depth for the peer's
                                 cert chain. 0 : unrestricted,
                                 1: only a single (self-signed) cert allowed,
                                 2: peer cert + 1 root CA
                                 3: peer cert + 1 CA + 1 root CA, etc. */
} matrixValidateCertsOptions_t;

/* flags for matrixValidateCertsOptions_t: */
/**
   Validate the expectedName argument against a subset of the
   GeneralName rules for DNS, Email and IP types _before_ trying
   to find for expectedName in the cert. Note that this is only
   applicable if expectedName is a GeneralName, i.e. when using
   any of the VCERTS_MFLAG_SAN flags.
 */
# define VCERTS_FLAG_VALIDATE_EXPECTED_GENERAL_NAME 0x01

/**
   Skip the expectedName matching. This is useful e.g. when
   matrixValidateCerts is called by the TLS server to validate
   a client certificate. The client name is usually not known
   in this case.
 */
# define VCERTS_FLAG_SKIP_EXPECTED_NAME_VALIDATION 0x02

/**
   Enable matrixValidateCertsExt to perform an independent validation
   of the certificate date ranges. Dates of the subject cert chain
   and the found issuer cert are validated against the current
   system time.

   By default, MatrixSSL only checks the certificate date validity
   during certificate parsing, setting the PS_CERT_AUTH_FAIL_DATE_FLAG
   flag in cert->authFailFlags when date validation fails. This flag
   will be noticed by matrixValidateCertsExt (but only for subject
   certs, not the found issuer cert). In some applications, the delay
   between parsing and the actual chain validation can be long. In such
   situations, it is useful to re-perform the date validation
   in matrixValidateCertsExt.
*/
#  define VCERTS_FLAG_REVALIDATE_DATES 0x04

/* mFlags for matrixValidateCertsOptions_t: */
/**
   If expectedName is a hostname, always attempt to match it
   with the subject CN, even if a supported, but non-matching
   subjectAltName was presented.
   Without this flag, the CN is checked only when no supported SAN
   was presented. This default behaviour is in accordance with
   Section 6.4.4 of RFC 6125, and this flag overrides it.
 */
# define VCERTS_MFLAG_ALWAYS_CHECK_SUBJECT_CN 0x01

/**
   Use case-insensitive match for the the whole email address
   in the rfc822Name field of the SAN. Without this flag,
   case-sensitive matching is used for the local-part and
   case-insensitive matching for the host-part, in accordance
   with RFC 5280.
   This flag requires VCERTS_MFLAG_SAN_MATCH_RFC822NAME.
 */
# define VCERTS_MFLAG_SAN_EMAIL_CASE_INSENSITIVE_LOCAL_PART 0x02

/******************************************************************************/

# ifdef USE_PSK_CIPHER_SUITE
typedef struct psPsk
{
    unsigned char *pskKey;
    uint8_t pskLen;
    unsigned char *pskId;
    uint8_t pskIdLen;
    struct psPsk *next;
} psPsk_t;
# endif /* USE_PSK_CIPHER_SUITE */

# ifdef USE_TLS_1_3
/* TLS 1.3 session parameters associated with a PSK. */
struct psTls13SessionParams
{
    unsigned char *sni;
    psSize_t sniLen;
    unsigned char *alpn;
    psSize_t alpnLen;
    unsigned char majVer;
    unsigned char minVer;
    uint16_t cipherId;
    psTime_t timestamp;
    uint32_t ticketAgeAdd;
    uint32_t ticketLifetime;
    uint32_t maxEarlyData;
};

#  define TLS_1_3_TICKET_LIFETIME 360 /* Seconds */
/* The time window in which server's and client's calculated
   ticket ages must be in order for the early data to be
   accepted. TLS1.3 spec chapter 8 suggests that in the
   Internet applications this should be around 10 seconds
   but in applications where the round trip time (RTT) is more
   predicatble it could be less */
#  define TLS_1_3_EARLY_DATA_TICKET_AGE_WINDOW 10000 /* Milliseconds */

struct psTls13Psk
{
    unsigned char *pskKey;
    psSize_t pskLen;
    unsigned char *pskId;
    psSize_t pskIdLen;
    psBool_t isResumptionPsk;
    psTls13SessionParams_t *params;
    struct psTls13Psk *next;
};

# endif /* USE_TLS_1_3 */

# if defined(USE_TLS_1_3_RESUMPTION) || (defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS))
typedef int32 (*sslSessTicketCb_t)(void *keys, unsigned char[16], short);

typedef struct sessTicketKey
{
    unsigned char name[16];
    unsigned char symkey[32];
    unsigned char hashkey[32];
    short nameLen, symkeyLen, hashkeyLen, inUse;
    struct sessTicketKey *next;
} psSessionTicketKeys_t;
# endif

/******************************************************************************/
/*
    TLS authentication keys structures
 */
# if defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
#  define ECC_EPHEMERAL_CACHE_SECONDS (2 * 60 * 60) /**< Max lifetime in sec */
#  ifdef NO_ECC_EPHEMERAL_CACHE
#   define ECC_EPHEMERAL_CACHE_USAGE   0            /**< Cache not used */
#  else
#   define ECC_EPHEMERAL_CACHE_USAGE   1000         /**< Maximum use count of key */
#  endif
typedef struct
{
#  ifdef USE_MULTITHREADING
    psMutex_t lock;
#  endif
#  ifdef USE_ECC
    psEccKey_t eccPrivKey;           /**< Cached ephemeral key */
    psEccKey_t eccPubKey;            /**< Cached remote ephemeral pub key */
    psTime_t eccPrivKeyTime;         /**< Time key was generated */
    uint16_t eccPrivKeyUse;          /**< Use count */
    uint16_t eccPubKeyCurveId;       /**< Curve the point is on */
    unsigned char eccPubKeyRaw[132]; /**< Max size of secp521r1 */
#  endif
#  ifdef REQUIRE_DH_PARAMS
#  endif
} ephemeralKeyCache_t;
# endif /* defined(USE_ECC) || defined(REQUIRE_DH_PARAMS) */


#ifdef USE_IDENTITY_CERTIFICATES
/* Public key mechanism based identity for the TLS party.

   Each client may have zero, or more identifying keypairs to choose from. If
   the server requires client authentication, the keypair whose certificate
   was issued by one of the accepted issuers (from the CERTIFICATE_REQUEST
   payload) is used. In case of multiple matches, the key pair added first
   will take precedence.

   If none of the keys match, again, the first added key pair is used.

   See function 'matrixSslNewSession' for initiating client connection.
   See function o
 */
typedef struct sslIdentity
{
    /* Keypair and corresponding certificate (chain) for this identity. */
    psPubKey_t privKey;
    psX509Cert_t *cert;

    /* Next identity for the party. */
    struct sslIdentity *next;
} sslIdentity_t;
#endif /* USE_IDENTITY_CERTIFICATES */

struct sslKeys
{
    psPool_t *pool;
# ifdef USE_IDENTITY_CERTIFICATES
    /* The known public key based identities for the party. One of these gets
       select as pkIdentityChosen based on locally, and remotely supported
       algorithms, and reveived certificate request payloads. */
    sslIdentity_t *identity;
# endif

# if defined(USE_IDENTITY_CERTIFICATES) || defined(USE_CA_CERTIFICATES)
    /* For a client this is the set of trust anchors used to authenticate the
       server, and for the server side this is set of trusted client
       certificate issuers. */
    psX509Cert_t *CAcerts;
# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
# ifdef REQUIRE_DH_PARAMS
    psDhParams_t dhParams;
# endif /* REQUIRE_DH_PARAMS */
# ifdef USE_PSK_CIPHER_SUITE
    psPsk_t *pskKeys;
# ifdef USE_TLS_1_3
    psTls13Psk_t *tls13PskKeys;
# endif
# endif /* USE_PSK_CIPHER_SUITE */
# if defined(USE_TLS_1_3_RESUMPTION) || (defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS))
    psSessionTicketKeys_t *sessTickets;
    sslSessTicketCb_t ticket_cb;
# endif
# if defined(USE_OCSP_RESPONSE) && defined(USE_SERVER_SIDE_SSL)
    unsigned char *OCSPResponseBuf;
    psSize_t OCSPResponseBufLen;
# endif
    void *poolUserPtr;              /* Data that will be given to psOpenPool
                                       for any operations involving these keys */
# if defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
    ephemeralKeyCache_t cache;
# endif
};

/******************************************************************************/
/* Type to pass optional features to NewSession calls */
struct sslSessOpts
{
    short ticketResumption;     /* Client: 1 to use.  Server N/A */
    short maxFragLen;           /* Client: 512 etc..  Server: -1 to disable */
    short truncHmac;            /* Client: 1 to use.  Server: -1 to disable */
    short extendedMasterSecret; /* On by default.  -1 to disable */
    short trustedCAindication;  /* Client: 1 to use */
    short fallbackScsv;         /* Client: 1 to use */
# if defined(USE_OCSP_RESPONSE) || defined(USE_OCSP_REQUEST)
    short OCSPstapling;         /* Client: 1 to send status_request */
# endif
# ifdef USE_ECC
    int32 ecFlags;       /* Elliptic curve set (SSL_OPT_SECP192R1 etc.) */
# endif
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    int32 useExtCvSigOp;                            /* Client: sign the handshake messages hash in
                                                       CertificateVerify externally. */
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
    int32 versionFlag;                              /* The SSL_FLAGS_TLS_ version (+ DTLS flag here) */
    uint32_t supportedVersions[TLS_MAX_SUPPORTED_VERSIONS]; /* Priority list of supported protocol versions*/
    psSize_t supportedVersionsLen;
# ifdef USE_TLS_1_3
    uint16_t tls13SupportedSigAlgsCert[TLS_MAX_SIGNATURE_ALGORITHMS];
    psSize_t tls13SupportedSigAlgsCertLen;
    psSize_t tls13SessionMaxEarlyData;            /* For server this defines what is the max early
                                                       data value for the new session tickets. Not used
                                                       for clients. */
# endif
    void *userPtr;                                  /* Initial value of ssl->userPtr during NewSession */
    void *memAllocPtr;                              /* Will be passed to psOpenPool for each call
                                                       related to this session */
    psPool_t *bufferPool;                           /* Optional mem pool for inbuf and outbuf */
    int32 keep_peer_cert_der;                       /* Keep raw DER of peer certs */
    int32 keep_peer_certs;                          /* Keep peer cert chain until the session
                                                       is deleted  */
    matrixValidateCertsOptions_t validateCertsOpts; /* Certificate validation
                                                       options. */
    void *userDataPtr; /* Initial value of ssl->userDataPtr during NewSession. */
    uint16_t tls13SupportedGroups[TLS_1_3_MAX_GROUPS];
    psSize_t tls13SupportedGroupsLen;
    psSize_t tls13NumClientHelloKeyShares;
    uint16_t supportedSigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS];
    psSize_t supportedSigAlgsLen;
    psSizeL_t tls13PadLen;
    psSizeL_t tls13BlockSize;
    psBool_t tls13CiphersuitesEnabledClient;
    /* Minimum DH modulus size the client is willing to accept
       from the server in ServerKeyExchange. This setting
       affects client-side handshake behaviour only. Server-side
       DH parameters are determined during key loading.
       The global compile-time setting MIN_DH_BITS is the minimum
       size of DH parameters MatrixSSL is allowed to load. */
    psSize_t minDhBits;
};

/******************************************************************************/
/*
    SSL record and session structures
 */
typedef struct
{
    unsigned short len;
    unsigned char majVer;
    unsigned char minVer;
# ifdef USE_DTLS
    unsigned char epoch[2];     /* incoming epoch number */
    unsigned char rsn[6];       /* incoming record sequence number */
# endif /* USE_DTLS */
# ifdef USE_CERT_CHAIN_PARSING
    unsigned short hsBytesHashed;
    unsigned short hsBytesParsed;
    unsigned short trueLen;
    unsigned char partial;
    unsigned char certPad;
# endif
    unsigned char type;
    unsigned char pad[3];       /* Padding for 64 bit compat */
} sslRec_t;

typedef struct
{
    unsigned char clientRandom[SSL_HS_RANDOM_SIZE];     /* From ClientHello */
    unsigned char serverRandom[SSL_HS_RANDOM_SIZE];     /* From ServerHello */
    unsigned char masterSecret[SSL_HS_MASTER_SIZE];
    unsigned char *premaster;                             /* variable size */
    psSize_t premasterSize;

    unsigned char keyBlock[SSL_MAX_KEY_BLOCK_SIZE];     /* Storage for 'ptr' */

# ifdef USE_TLS_1_3
    unsigned char tls13EarlySecret[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13ExtBinderSecret[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13EarlyTrafficSecretClient[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13HandshakeSecret[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13HsTrafficSecretClient[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13HsTrafficSecretServer[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13MasterSecret[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13AppTrafficSecretClient[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13AppTrafficSecretServer[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13ResumptionMasterSecret[MAX_TLS_1_3_HASH_SIZE];

    unsigned char tls13HsWriteKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char tls13HsWriteIv[SSL_MAX_IV_SIZE];
    unsigned char tls13HsReadKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char tls13HsReadIv[SSL_MAX_IV_SIZE];
    unsigned char tls13EarlyDataKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char tls13EarlyDataIv[SSL_MAX_IV_SIZE];
    unsigned char tls13AppWriteKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char tls13AppWriteIv[SSL_MAX_IV_SIZE];
    unsigned char tls13AppReadKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char tls13AppReadIv[SSL_MAX_IV_SIZE];

    unsigned char tls13WriteKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char tls13WriteIv[SSL_MAX_IV_SIZE];
    unsigned char tls13ReadKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char tls13ReadIv[SSL_MAX_IV_SIZE];

    unsigned char tls13TrHashSnapshot[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13TrHashSnapshotCH[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13TrHashSnapshotCHSha384[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13TrHashSnapshotCH1[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13TrHashSnapshotCHtoSH[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13TrHashSnapshotCHWithoutBinders[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13ExtBinderKey[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13FinishedKey[MAX_TLS_1_3_HASH_SIZE];
    unsigned char tls13VerifyData[MAX_TLS_1_3_HASH_SIZE];

    unsigned char *tls13CvSig;
    psSize_t tls13CvSigLen;
    uint16_t tls13CvSigAlg;
    uint16_t tls13PeerCvSigAlg;

    unsigned char *tls13CookieFromServer;
    psSize_t tls13CookieFromServerLen;
    psBool_t tls13ClientCookieOk;

    short tls13ExtendedMasterSecretOpt;

    psTls13Psk_t *tls13SessionPskList;
    psTls13Psk_t *tls13ChosenPsk;
    uint16_t tls13SelectedIdentityIndex;
    psBool_t tls13UsingPsk;
    psSize_t tls13BindersLen;
    const unsigned char *tls13CHStart;
    psSizeL_t tls13CHLen;
    psk_key_exchange_mode_e tls13ClientPskModes[2];
    psSize_t tls13ClientPskModesLen;
    psk_key_exchange_mode_e tls13ChosenPskMode;

    tls13_flight_state_t tls13KsState;
    psSha256_t tls13msgHashSha256;
    psSha384_t tls13msgHashSha384;
# endif /* USE_TLS_1_3 */

# ifdef USE_NATIVE_TLS_ALGS
    unsigned char *wMACptr;
    unsigned char *rMACptr;
    unsigned char *wKeyptr;
    unsigned char *rKeyptr;

    /*  All maximum sizes for current cipher suites */
    unsigned char writeMAC[SSL_MAX_MAC_SIZE];
    unsigned char readMAC[SSL_MAX_MAC_SIZE];
    unsigned char writeKey[SSL_MAX_SYM_KEY_SIZE];
    unsigned char readKey[SSL_MAX_SYM_KEY_SIZE];
# endif
    unsigned char *wIVptr;
    unsigned char *rIVptr;
    unsigned char writeIV[SSL_MAX_IV_SIZE];
    unsigned char readIV[SSL_MAX_IV_SIZE];
# ifdef USE_EAP_FAST
    unsigned char *eap_fast_session_key_seed;
# endif

    unsigned char seq[8];
    unsigned char remSeq[8];

# ifdef USE_SERVER_SIDE_SSL
    pskCb_t pskCb;
    pubkeyCb_t pubkeyCb;
# endif

    sslKeySelectInfo_t keySelect;

# ifndef USE_ONLY_PSK_CIPHER_SUITE
    sslIdentityCb_t identityCb;
#  if defined(USE_IDENTITY_CERTIFICATES) || defined(USE_CERT_VALIDATE)
    psX509Cert_t *cert;
    sslCertCb_t validateCert;
#  endif /* USE_IDENTITY_CERTIFICATES */
# endif  /* USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_CLIENT_SIDE_SSL
    int32 certMatch;
# endif /* USE_CLIENT_SIDE_SSL */

# ifdef USE_NATIVE_SYMMETRIC
    psCipherContext_t encryptCtx;
    psCipherContext_t decryptCtx;
# endif

# ifdef USE_NATIVE_TLS_HS_HASH
#  ifndef USE_ONLY_TLS_1_2
    psMd5Sha1_t msgHashMd5Sha1;
#  endif
# endif

# ifdef USE_TLS_1_2
#  ifdef USE_NATIVE_TLS_HS_HASH
    psSha256_t msgHashSha256;

#   ifdef USE_SHA1
    psSha1_t msgHashSha1;
#   endif
#   ifdef USE_SHA384
    psSha384_t msgHashSha384;
#   endif
#   ifdef USE_SHA512
    psSha512_t msgHashSha512;
#   endif
#  endif
# endif  /* USE_TLS_1_2 */

# if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
    unsigned char sha1Snapshot[SHA1_HASH_SIZE];
    unsigned char sha384Snapshot[SHA384_HASH_SIZE];       /* HW crypto uses
                                                             outside TLS 1.2 */
    unsigned char sha512Snapshot[SHA512_HASH_SIZE];
# endif

# if defined(USE_PSK_CIPHER_SUITE) && defined(USE_CLIENT_SIDE_SSL)
    unsigned char *hint;
    uint8_t hintLen;
# endif /* USE_PSK_CIPHER_SUITE && USE_CLIENT_SIDE_SSL */

# ifdef REQUIRE_DH_PARAMS
    unsigned char *dhP;                   /* prime/modulus */
    unsigned char *dhG;                   /* base/generator */
    psSize_t dhPLen;
    psSize_t dhGLen;
    psDhKey_t *dhKeyPub;                  /* remote key */
    psDhKey_t *dhKeyPriv;                 /* local key */
    psPool_t *dhKeyPool;                  /* handshake-scope pool for clients */
# endif

# ifdef USE_ECC_CIPHER_SUITE
    psEccKey_t *eccKeyPriv;           /* local key */
    psEccKey_t *eccKeyPub;            /* remote key */
    psPool_t *eccDhKeyPool;           /* handshake-scope pool for clients */
    unsigned char *x25519KeyPub;
# endif
# ifdef USE_TLS_1_3
    psPubKey_t *tls13KeyAgreeKeys[TLS_1_3_MAX_GROUPS];
# endif
    int32 anon;
} sslSec_t;

typedef struct
{
    uint16_t ident;         /* Official cipher ID */
    uint16_t type;          /* Key exchange method */
    uint32_t flags;         /* from CRYPTO_FLAGS_* */
    uint8_t macSize;
    uint8_t keySize;
    uint8_t ivSize;
    uint8_t blockSize;
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


# ifdef USE_STATELESS_SESSION_TICKETS
enum sessionTicketState_e
{
    SESS_TICKET_STATE_INIT = 0,
#  ifdef USE_EAP_FAST
    SESS_TICKET_STATE_EAP_FAST, /* Initialized with pre-provisioned key */
#  endif
    SESS_TICKET_STATE_SENT_EMPTY,
    SESS_TICKET_STATE_SENT_TICKET,
    SESS_TICKET_STATE_RECVD_EXT,
    SESS_TICKET_STATE_IN_LIMBO,
    SESS_TICKET_STATE_USING_TICKET
};
# endif

/* Used by user code to store cached session info after the ssl_t is closed */
struct sslSessionId
{
    psPool_t *pool;
    unsigned char id[SSL_MAX_SESSION_ID_SIZE];
    unsigned char masterSecret[SSL_HS_MASTER_SIZE];
    uint32 cipherId;
# ifdef USE_STATELESS_SESSION_TICKETS
    unsigned char *sessionTicket;       /* Duplicated into 'pool' */
    uint16 sessionTicketState;          /* Not an enum to ensure 2 bytes */
    psSize_t sessionTicketLen;          /* Max 32767 */
    uint32 sessionTicketLifetimeHint;
# endif
# ifdef USE_TLS_1_3
    psTls13Psk_t *psk;
# endif
};

/* Used internally by the session cache table to store session parameters */
typedef struct
{
    unsigned char id[SSL_MAX_SESSION_ID_SIZE];
    unsigned char masterSecret[SSL_HS_MASTER_SIZE];
    const sslCipherSpec_t *cipher;
    unsigned char majVer;
    unsigned char minVer;
    short extendedMasterSecret;           /* was the extension used? */
    psTime_t startTime;
    int32 inUse;
    DLListEntry chronList;
} sslSessionEntry_t;

/* Used by user code to define custom hello extensions */
typedef struct tlsHelloExt
{
    psPool_t *pool;
    int32 extType;
    uint32 extLen;
    unsigned char *extData;
    struct tlsHelloExt *next;
} tlsExtension_t;

/* Hold the info needed to perform a public key operation for flight writes
    until the very end.  This is an architectural change that was added to aid
    the integration of non-blocking hardware acceleration */
enum
{
    PKA_AFTER_RSA_SIG_GEN_ELEMENT = 1,
    PKA_AFTER_RSA_SIG_GEN,
    PKA_AFTER_ECDSA_SIG_GEN,
    PKA_AFTER_RSA_ENCRYPT,          /* standard RSA CKE operation */
    PKA_AFTER_ECDH_KEY_GEN,         /* ECDH CKE operation. makeKey */
    PKA_AFTER_ECDH_SECRET_GEN,      /* GenSecret */
    PKA_AFTER_ECDH_SECRET_GEN_DONE, /* Control for single-pass op */
    PKA_AFTER_DH_KEY_GEN            /* DH CKE operation */
};

typedef struct
{
    unsigned char *inbuf; /* allocated to handshake pool */
    unsigned char *outbuf;
    void *data;           /* hw pkiData */
    psSize_t inlen;
    uint16_t type;        /* one of PKA_AFTER_* */
    uint16_t user;        /* user size */
    psPool_t *pool;
} pkaAfter_t;

typedef struct nextMsgInFlight
{
    unsigned char *start;
# ifdef USE_TLS_1_3
    unsigned char *recStart;
    psBool_t alreadyHashed;
# endif
    unsigned char *seqDelay;
    int32 len;
    int32 type;
    int32 messageSize;
    int32 padLen;
    int32 hsMsg;
    psSize_t fragId; /* How manyeth fragment is this for hsMsg (0 - n) */
# ifdef USE_DTLS
    int32 fragCount;
# endif
    struct nextMsgInFlight *next;
} flightEncode_t;


struct ssl
{
    sslRec_t rec;                   /* Current SSL record information*/

    sslSec_t sec;                   /* Security structure */

    sslKeys_t *keys;                /* SSL public and private - keys confiured. */
# ifdef USE_IDENTITY_CERTIFICATES
    sslIdentity_t *chosenIdentity;  /* Keys chosen for authentication */
# endif
    pkaAfter_t pkaAfter[2];         /* Cli-side cli-auth = two PKA in flight */
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    uint8_t extCvSigOpInUse;
    uint8_t extCvSigOpPending;
    unsigned char *extCvHash;
    size_t extCvHashLen;
    unsigned char *extCvSig;
    size_t extCvSigLen;
    int32_t extCvSigAlg;
    unsigned char *extCvOrigFlightEnd;
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
/*
  Note: these flags, stored in ssl->extClientCertKeyStateFlags,
  define the state of the "external client cert loading
  feature". These are mutually exclusive, except
  for GOT_CERTIFICATE_REQUEST and GOT_SERVER_HELLO_DONE.
  This is because we try to prepare for the case where
  these HS messages are decoded in different calls to
  matrixSslReceivedData.
*/
#define EXT_CLIENT_CERT_KEY_STATE_INIT 0
#define EXT_CLIENT_CERT_KEY_STATE_GOT_CERTIFICATE_REQUEST 1
#define EXT_CLIENT_CERT_KEY_STATE_GOT_SERVER_HELLO_DONE 2
#define EXT_CLIENT_CERT_KEY_STATE_WAIT_FOR_CERT_KEY_UPDATE 4
#define EXT_CLIENT_CERT_KEY_STATE_GOT_CERT_KEY_UPDATE 8
    uint32_t extClientCertKeyStateFlags; /* Flags: EXT_CLIENT_CERT_KEY_* */

# endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
    flightEncode_t *flightEncode;
    unsigned char *delayHsHash;
    unsigned char *seqDelay;      /* tmp until flightEncode_t is built */

    psPool_t *bufferPool;         /* If user passed options.bufferPool to
                                     NewSession, this is inbuf and outbuf pool */
    psPool_t *sPool;              /* SSL session pool */
    psPool_t *hsPool;             /* Full session handshake pool */
    psPool_t *flightPool;         /* Small but handy */

    unsigned char sessionIdLen;
    unsigned char sessionId[SSL_MAX_SESSION_ID_SIZE];
    sslSessionId_t *sid;
    char *expectedName;               /* Clients: The expected cert subject name
                                              passed to NewClient Session
                                         Servers: Holds SNI value */
    tlsExtension_t *userExt; /* User provided extensions from session options.
                                Stored here for reuse in renegotiations and in
                                responses to TLS 1.3 HRRs. */
# ifdef USE_SERVER_SIDE_SSL
    uint16 disabledCiphers[SSL_MAX_DISABLED_CIPHERS];
    sniCb_t sni_cb;
#  ifdef USE_ALPN
    void (*srv_alpn_cb)(void *ssl, short protoCount,
        char *proto[MAX_PROTO_EXT],
        int32 protoLen[MAX_PROTO_EXT], int32 *index);
    char *alpn;              /* proto user has agreed to use */
    int32 alpnLen;
#  endif /* USE_ALPN */
# endif /* USE_SERVER_SIDE_SSL */
# ifdef USE_CLIENT_SIDE_SSL
    /* Just to handle corner case of app data tacked on HELLO_REQUEST */
    int32 anonBk;
    int32 flagsBk;
    uint32 bFlagsBk;

    sslExtCb_t extCb;
# endif /* USE_CLIENT_SIDE_SSL */

# if defined(USE_HARDWARE_CRYPTO_RECORD) || defined (USE_HARDWARE_CRYPTO_PKA) || defined(USE_EXT_CERTIFICATE_VERIFY_SIGNING)
    uint32 hwflags;             /* SSL_HWFLAGS_ */
# endif

    unsigned char *inbuf;
    unsigned char *outbuf;
    int32 inlen;                /* Bytes unprocessed in inbuf */
    int32 outlen;               /* Bytes unsent in outbuf */
    int32 insize;               /* Total allocated size of inbuf */
    int32 outsize;              /* Total allocated size of outbuf */
    uint32 bFlags;              /* Buffer related flags */

    int32 maxPtFrag;            /* 16K by default - SSL_MAX_PLAINTEXT_LEN */
    unsigned char *fragMessage; /* holds the constructed fragmented message */
    uint32 fragIndex;           /* How much data has been written to msg */
    uint32 fragTotal;           /* Total length of fragmented message */

    /* Pointer to the negotiated ciphersuite. Note that this cipher
       may not have been activated yet. */
    const sslCipherSpec_t *cipher;

    /* Pointer to the currently active read and write ciphers.
       Currently only used with ChaCha20 suites. */
# ifdef USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    const sslCipherSpec_t *activeReadCipher;
    const sslCipherSpec_t *activeWriteCipher;
# endif

    /*  Symmetric cipher callbacks

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
    unsigned char enMacSize;
    unsigned char nativeEnMacSize;   /* truncated hmac support */
    unsigned char enIvSize;
    unsigned char enBlockSize;
    unsigned char deMacSize;
    unsigned char nativeDeMacSize;   /* truncated hmac support */
    unsigned char deIvSize;
    unsigned char deBlockSize;

    uint32_t flags;                 /* SSL_FLAGS_ */
    int32_t err;                    /* SSL errno of last api call */
    int32_t ignoredMessageCount;

    uint8_t hsState;                /* Next expected SSL_HS_ message type */
    uint8_t decState;               /* Most recent encoded SSL_HS_ message */
    uint8_t encState;               /* Most recent decoded SSL_HS_ message */

# ifdef USE_SEC_CONFIG
    psCipher16_t *supportedCiphers;
    psSize_t supportedCiphersLen;
    psPreDefinedSecProfile_t secProfile;
    psSecConfig_t secConfig;
    securityCb_t secCb;
    uint32_t ecFlagsOverride;
# endif /* USE_SEC_CONFIG */
# ifdef USE_SSL_INFORMATIONAL_TRACE
    /* Store information about the peer public key, to be printed
       in matrixSslPrintHSDetails. */
    uint8_t peerAuthKeyType;
    uint8_t peerKeyExKeyType;
    psSize_t peerAuthKeyNBits;
    psSize_t peerKeyExKeyNBits;
# endif

    /* List of TLS spec versions supported by us. Both compile-time and
       run-time configuration affect these. */
    psProtocolVersion_t supportedVersions; /* TLS versions we support. */
    psProtocolVersion_t supportedVersionsPeer; /* TLS versions the peer supports. */
    psProtocolVersion_t ourHelloVersion; /* Version we encoded in ClientHello. */
    psProtocolVersion_t peerHelloVersion; /* legacy_version from peer's hello msg. */
    psProtocolVersion_t activeVersion; /* TLS spec version we are following.
                                          If v_tls_negotiated flag is set,
                                          this version has been succesfully
                                          negotiated with the peer. */
    /* Priority-ordering information for supported versions.*/
    psProtocolVersion_t supportedVersionsPriority[TLS_MAX_SUPPORTED_VERSIONS];
    psProtocolVersion_t supportedVersionsPriorityLen;
#ifdef USE_TLS_1_3
    psProtocolVersion_t peerSupportedVersionsPriority[TLS_MAX_SUPPORTED_VERSIONS];
    psSize_t peerSupportedVersionsPriorityLen;
    psBool_t tls13IncorrectDheKeyShare;
    psBool_t gotTls13CiphersuiteInCH; /* Does CH contain any 1.3 suites? */
    uint16_t tls13SupportedSigAlgsCert[TLS_MAX_SIGNATURE_ALGORITHMS];
    psSize_t tls13SupportedSigAlgsCertLen;
    uint16_t tls13SupportedGroups[TLS_1_3_MAX_GROUPS];
    psSize_t tls13SupportedGroupsLen;
    uint16_t tls13PeerSupportedGroups[TLS_1_3_MAX_GROUPS];
    psSize_t tls13PeerSupportedGroupsLen;
    uint16_t tls13PeerKeyShareGroups[TLS_1_3_MAX_GROUPS];
    psSize_t tls13PeerKeyShareGroupsLen;
    psSize_t tls13NumClientHelloKeyShares;
    uint16_t tls13NegotiatedGroup;
    uint16_t tls13HelloRetryRequestGroup;
    psSizeL_t tls13NextMsgRequiredLen;
     /* Client's enabled cipher suites from the API */
    psCipher16_t *tls13ClientCipherSuites;
    uint8_t tls13ClientCipherSuitesLen;
    psBool_t tls13CiphersuitesEnabledClient;
    unsigned char *tls13CertRequestContext;
    psSize_t tls13CertRequestContextLen;
    psBool_t tls13GotCertificateRequest;
    psBool_t tls13SentEmptyCertificate;
    psBool_t tls13ClientEarlyDataEnabled;
    psBool_t tls13ServerEarlyDataEnabled;
    psSize_t tls13SessionMaxEarlyData;
    psSize_t tls13ReceivedEarlyDataLen;
    uint32_t tls13EarlyDataStatus;
    psSizeL_t tls13PadLen;
    psSizeL_t tls13BlockSize;
#endif
    /* This is shared between all TLS versions. */
    uint16_t supportedSigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS];
    psSize_t supportedSigAlgsLen;
    uint8_t outRecType;
    psSize_t outRecLen;

# ifdef USE_DH
    psSize_t minDhBits;
# endif

# ifdef ENABLE_SECURE_REHANDSHAKES
    unsigned char myVerifyData[SHA384_HASH_SIZE];   /*SSLv3 max*/
    unsigned char peerVerifyData[SHA384_HASH_SIZE];
    uint32 myVerifyDataLen;
    uint32 peerVerifyDataLen;
    int32 secureRenegotiationFlag;
    psBool_t secureRenegotiationInProgress;
# endif /* ENABLE_SECURE_REHANDSHAKES */
# ifdef SSL_REHANDSHAKES_ENABLED
    int32 rehandshakeCount;           /* Make this an internal define of 1 */
    int32 rehandshakeBytes;           /* Make this an internal define of 10MB */
# endif /* SSL_REHANDSHAKES_ENABLED */

# ifdef USE_ECC
    struct
    {
        uint32 ecFlags : 24;
        uint32 ecCurveId : 8;
    } ecInfo;
# endif
# ifdef USE_TLS_1_2
    uint16_t hashSigAlg;
    uint16_t serverSigAlgs;
# endif /* USE_TLS_1_2 */

# ifdef USE_DTLS
#  ifdef USE_SERVER_SIDE_SSL
    unsigned char srvCookie[DTLS_COOKIE_SIZE];   /* server can avoid allocs */
#  endif
#  ifdef USE_CLIENT_SIDE_SSL
    unsigned char *cookie;                      /* hello_verify_request cookie */
    int32 cookieLen;                            /* cookie length */
    int32 haveCookie;                           /* boolean for cookie existence */
#  endif
    unsigned char *helloExt;                    /* need to save the original client hello ext */
    int32 helloExtLen;
    unsigned char hsSnapshot[SHA512_HASH_SIZE]; /*SSLv3 max*/
    int32 hsSnapshotLen;
    psCipher16_t cipherSpec[8];                 /* also needed for the cookie client hello */
    uint8_t cipherSpecLen;
    unsigned char epoch[2];                     /* Current epoch number to send with msg */
    unsigned char resendEpoch[2];               /* Starting epoch to use for resends */
    unsigned char expectedEpoch[2];             /* Expected incoming epoch */
    unsigned char largestEpoch[2];              /* FINISH resends need to incr epoch */
    unsigned char rsn[6];                       /* Last Record Sequence Number sent */
    unsigned char largestRsn[6];                /* Needed for resends of CCS flight */
    unsigned char lastRsn[6];                   /* Last RSN received (for replay detection) */
    unsigned long dtlsBitmap;                   /* Record replay helper */
    int32 parsedCCS;                            /* Set between CCS parse and FINISHED parse */
    int32 msn;                                  /* Current Message Sequence Number to send */
    int32 resendMsn;                            /* Starting MSN to use for resends */
    int32 lastMsn;                              /* Last MSN successfully parsed from peer */
    int32 pmtu;                                 /* path maximum trasmission unit */
    int32 retransmit;                           /* Flag to know not to update handshake hash */
    uint16 flightDone;                          /* BOOL to flag when entire hs flight sent */
    uint16 appDataExch;                         /* BOOL to flag if in application data mode */
    int32 fragMsn;                              /* fragment MSN */
    dtlsFragHdr_t fragHeaders[MAX_FRAGMENTS];   /* header storage for hash */
    int32 (*oencrypt)(void *ctx, unsigned char *in,
                      unsigned char *out, uint32 len);
    int32 (*ogenerateMac)(void *ssl, unsigned char type, unsigned char *data,
                          uint32 len, unsigned char *mac);
    unsigned char oenMacSize;
    unsigned char oenNativeHmacSize;
    unsigned char oenIvSize;
    unsigned char oenBlockSize;
    unsigned char owriteIV[16];   /* GCM uses this in the nonce */
#  ifdef USE_NATIVE_TLS_ALGS
    unsigned char owriteMAC[SSL_MAX_MAC_SIZE];
    psCipherContext_t oencryptCtx;
#  endif
#  ifdef ENABLE_SECURE_REHANDSHAKES
    unsigned char omyVerifyData[SHA384_HASH_SIZE];
    uint32 omyVerifyDataLen;
#  endif /* ENABLE_SECURE_REHANDSHAKES */
    uint32 ckeSize;
    unsigned char *ckeMsg;
    unsigned char *certVerifyMsg;
    int32 certVerifyMsgLen;
    int ecdsaSizeChange;             /* retransmits for ECDSA sig */
# endif /* USE_DTLS */

# ifdef USE_ZLIB_COMPRESSION
    int32 compression;
    z_stream inflate;
    z_stream deflate;
    unsigned char *zlibBuffer;     /* scratch pad for inflate/deflate data */
# endif

    struct
    {
# ifdef USE_CLIENT_SIDE_SSL
        /* Did the client request the extension? */
        uint32 req_sni : 1;
        uint32 req_max_fragment_len : 1;
        uint32 req_truncated_hmac : 1;
        uint32 req_extended_master_secret : 1;
        uint32 req_elliptic_curve : 1;
        uint32 req_elliptic_points : 1;
        uint32 req_signature_algorithms : 1;
        uint32 req_alpn : 1;
        uint32 req_session_ticket : 1;
        uint32 req_renegotiation_info : 1;
        uint32 req_fallback_scsv : 1;
        uint32 req_status_request : 1;
# endif
# ifdef USE_SERVER_SIDE_SSL
        /* Whether the server will deny the extension */
        uint32 deny_truncated_hmac : 1;
        uint32 deny_max_fragment_len : 1;
        uint32 deny_session_ticket : 1;
        /* Whether the server received this extension. */
        uint32 got_psk_key_exchange_modes : 1;
        uint32 got_cookie : 1;
        uint32 got_elliptic_points : 1;
# endif
        uint32 got_supported_versions : 1; /* server only; but 1bit only */
        uint32 got_key_share : 1;          /* server only; but 1bit only */
        uint32 got_pre_shared_key : 1;     /* server only; but 1bit only */

        uint32 got_early_data : 1;
        /* Set if the extension was negotiated successfully */
        uint32 sni : 1;
        uint32 truncated_hmac : 1;
        uint32 extended_master_secret : 1;
        uint32 session_id : 1;
        uint32 session_ticket : 1;
        uint32 status_request : 1;                 /* received EXT_STATUS_REQUEST */
        uint32 status_request_v2 : 1;              /* received EXT_STATUS_REQUEST_V2 */
        uint32 require_extended_master_secret : 1; /* peer may require */
        /* For renegotiations. */
        uint32 sni_in_last_client_hello : 1;
# ifdef USE_EAP_FAST
        uint32 eap_fast_master_secret : 1;         /* Using eap_fast key derivation */
# endif
    } extFlags;                            /**< Extension flags */

# ifdef USE_MATRIX_OPENSSL_LAYER
    int (*verify_callback)(int alert, psX509Cert_t *data);
# endif
    int32 recordHeadLen;
    int32 hshakeHeadLen;
# ifdef USE_MATRIXSSL_STATS
    void (*statCb)(void *ssl, void *stats_ptr, int32 type, int32 value);
    void *statsPtr;
# endif
    matrixValidateCertsOptions_t validateCertsOpts;
    void *memAllocPtr;   /* Will be passed to psOpenPool for each call
                              related to this session */
    void *userPtr;
    void *userDataPtr;
};

typedef struct ssl ssl_t;

# ifdef USE_TLS_1_3
/** SHA-256 of "HelloRetryRequest": */
static const unsigned char sha256OfHelloRetryRequest[] =
{
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
  0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
  0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

#endif /* USE_TLS_1_3 */
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
extern int32    matrixSslGetEncodedSize(ssl_t *ssl, uint32 len);
extern void     matrixSslSetCertValidator(ssl_t *ssl, sslCertCb_t certValidator);
extern int32    matrixSslNewSession(ssl_t **ssl, const sslKeys_t *keys,
                                    sslSessionId_t *session, sslSessOpts_t *options);
extern void     matrixSslSetSessionOption(ssl_t *ssl, int32 option, void *arg);
extern int32_t  matrixSslHandshakeIsComplete(const ssl_t *ssl);
extern psBool_t matrixSslRehandshaking(const ssl_t *ssl);

/* This used to be prefixed with 'matrix' */
extern int32    sslEncodeClosureAlert(ssl_t *ssl, sslBuf_t *out,
                                      uint32 *reqLen);

extern int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out,
                                         uint32 *reqLen);
extern int32_t matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
                                          const psCipher16_t cipherSpec[], uint8_t cipherSpecLen,
                                          uint32 *requiredLen, tlsExtension_t *userExt,
                                          sslSessOpts_t *options);

# ifdef USE_CLIENT_SIDE_SSL
extern int32 matrixSslGetSessionId(ssl_t *ssl, sslSessionId_t *sessionId);
extern void psCopyHelloExtension(tlsExtension_t *destination,
        const tlsExtension_t *source);
extern void psAddUserExtToSession(ssl_t *ssl,
        const tlsExtension_t *ext);
# endif /* USE_CLIENT_SIDE_SSL */

# ifdef USE_SSL_INFORMATIONAL_TRACE
extern void matrixSslPrintHSDetails(ssl_t *ssl);
# endif /* USE_SSL_INFORMATIONAL_TRACE */

# ifdef SSL_REHANDSHAKES_ENABLED
PSPUBLIC int32 matrixSslGetRehandshakeCredits(ssl_t *ssl);
PSPUBLIC void matrixSslAddRehandshakeCredits(ssl_t *ssl, int32 credits);
# endif

# ifdef USE_ZLIB_COMPRESSION
PSPUBLIC int32 matrixSslIsSessionCompressionOn(ssl_t *ssl);
# endif

# ifdef USE_TLS_1_3
static inline
psBool_t tls13IsResumedHandshake(ssl_t *ssl)
{
    if (ssl->sec.tls13UsingPsk &&
            ssl->sec.tls13ChosenPsk &&
            ssl->sec.tls13ChosenPsk->isResumptionPsk)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}
# endif /* USE_TLS_1_3 */

static inline
psBool_t isResumedHandshake(ssl_t *ssl)
{
# ifdef USE_TLS_1_3
    if (NGTD_VER(ssl, v_tls_1_3_any))
    {
        return tls13IsResumedHandshake(ssl);
    }
# endif
    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

/******************************************************************************/
/*
    MatrixSSL internal cert functions
 */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
extern int32 matrixValidateCerts(psPool_t *pool, psX509Cert_t *subjectCerts,
                                 psX509Cert_t *issuerCerts, char *expectedName,
                                 psX509Cert_t **foundIssuer, void *pkiData, void *userPoolPtr);
extern int32 matrixValidateCertsExt(psPool_t *pool, psX509Cert_t *subjectCerts,
                                    psX509Cert_t *issuerCerts, char *expectedName,
                                    psX509Cert_t **foundIssuer, void *pkiData, void *userPoolPtr,
                                    const matrixValidateCertsOptions_t *options);
extern int32 matrixUserCertValidator(ssl_t *ssl, int32 alert,
                                     psX509Cert_t *subjectCert, sslCertCb_t certCb);
# endif /* USE_ONLY_PSK_CIPHER_SUITE */


/******************************************************************************/
/*
    handshakeDecode.c and extensionDecode.c
 */
# ifdef USE_SERVER_SIDE_SSL
extern int32 parseClientHello(ssl_t *ssl, unsigned char **cp,
                              unsigned char *end);
extern int32 parseClientHelloExtensions(ssl_t *ssl, unsigned char **cp,
                                        unsigned short len);
extern int32 parseClientKeyExchange(ssl_t *ssl, int32 hsLen, unsigned char **cp,
                                    unsigned char *end);
extern int32 checkClientHelloVersion(ssl_t *ssl);
extern int32 checkSupportedVersions(ssl_t *ssl);
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
#   ifdef USE_CLIENT_AUTH
extern int32 parseCertificateVerify(ssl_t * ssl,
                                    unsigned char hsMsgHash[SHA512_HASH_SIZE], unsigned char **cp,
                                    unsigned char *end);
#   endif /* USE_CLIENT_AUTH */
#  endif  /* !USE_ONLY_PSK_CIPHER_SUITE */
# endif   /* USE_SERVER_SIDE_SSL */

# ifdef USE_CLIENT_SIDE_SSL
extern int32 parseServerHello(ssl_t *ssl, int32 hsLen, unsigned char **cp,
                              unsigned char *end);
extern int32 parseServerHelloExtensions(ssl_t *ssl, int32 hsLen,
                                        unsigned char *extData, unsigned char **cp,
                                        unsigned short len);
extern int32 parseServerHelloDone(ssl_t *ssl, int32 hsLen, unsigned char **cp,
                                  unsigned char *end);
extern int32 parseServerKeyExchange(ssl_t * ssl,
                                    unsigned char hsMsgHash[SHA512_HASH_SIZE],
                                    unsigned char **cp, unsigned char *end);

extern int32_t checkServerHelloVersion(ssl_t *ssl);
# ifdef USE_TLS_1_3
extern int32_t performTls13DowngradeCheck(ssl_t *ssl);
# endif

#  ifdef USE_OCSP_RESPONSE
extern int32 parseCertificateStatus(ssl_t *ssl, int32 hsLen, unsigned char **cp,
                                    unsigned char *end);
#  endif /* USE_OCSP_RESPONSE */
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
extern int32 parseCertificateRequest(ssl_t *ssl, int32 hsLen,
                                     unsigned char **cp, unsigned char *end);
#  endif
# endif /* USE_CLIENT_SIDE_SSL */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
extern int32 parseCertificate(ssl_t *ssl, unsigned char **cp,
                              unsigned char *end);
#  endif
# endif

extern int32 parseFinished(ssl_t * ssl, int32 hsLen,
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
extern int32_t sslUpdateHSHash(ssl_t *ssl, const unsigned char *in, psSize_t len);
extern int32 sslInitHSHash(ssl_t *ssl);
extern int32 sslSnapshotHSHash(ssl_t *ssl, unsigned char *out, int32 senderFlag);
extern int32_t findFromUint16Array(const uint16_t *a,
        psSize_t aLen,
        const uint16_t b);
extern psBool_t anyTls13VersionSupported(ssl_t *ssl);
extern psBool_t anyNonTls13VersionSupported(ssl_t *ssl);
extern psBool_t peerOnlySupportsTls13(ssl_t *ssl);
extern psBool_t weOnlySupportTls13(ssl_t *ssl);
extern uint16_t tlsMinVerToOfficialVer(int32_t minVer);

# ifdef USE_CERT_PARSE
#  if defined(USE_TLS_1_3) || (defined(MATRIX_USE_FILE_SYSTEM) && defined(USE_PKCS12))
extern void matrixSslReorderCertChain(psX509Cert_t *a_cert);
#  endif
# endif

# ifndef USE_ONLY_PSK_CIPHER_SUITE
extern int32_t tlsVerify(ssl_t *ssl,
        const unsigned char *tbs,
        psSizeL_t tbsLen,
        const unsigned char *c,
        const unsigned char *end,
        psPubKey_t *pubKey,
        psVerifyOptions_t *opts);
extern psRes_t tlsPrepareSkeSignature(ssl_t *ssl,
        int32_t skeSigAlg,
        unsigned char *tbsStart,
        unsigned char *c);
extern psRes_t tlsMakeSkeSignature(ssl_t *ssl,
        pkaAfter_t *pka,
        psBuf_t *out);
extern int32_t chooseSkeSigAlg(ssl_t *ssl,
        sslIdentity_t *id);
extern int accountForEcdsaSizeChange(ssl_t *ssl,
        pkaAfter_t *pka,
        int real,
        unsigned char *sig,
        psBuf_t *out,
        int hsMsg);
# endif /* USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_TLS_1_3
/* Parsing. */
extern int32 matrixSslDecodeTls13(ssl_t *ssl,
        unsigned char **in,
        uint32 *len,
        uint32 size,
        uint32 *remaining,
        uint32 *requiredLen,
        int32 *error,
        unsigned char *alertLevel,
        unsigned char *alertDescription);
extern int32_t tls13ParseEncryptedExtensions(ssl_t *ssl,
        psParseBuf_t *pb);
extern int32_t tls13ParseServerHelloExtensions(ssl_t *ssl,
        psParseBuf_t *pb);
extern int32_t tls13ParsePreSharedKey(ssl_t *ssl,
        psParseBuf_t *pb);
extern int32_t tls13ParsePskKeyExchangeModes(ssl_t *ssl,
        psParseBuf_t *pb);
extern int32_t tls13ParseCookie(ssl_t *ssl,
        psParseBuf_t *pb);
extern int32_t tls13ParseSignatureAlgorithms(ssl_t *ssl,
        const unsigned char **c,
        psSize_t len,
        psBool_t isCert);
extern psSize_t tls13ParseSupportedVersions(ssl_t *ssl,
        const unsigned char **c,
        psSize_t len);
extern psBool_t tls13ExtensionAllowedInMessage(ssl_t *ssl,
        uint16_t extType,
        unsigned char hsMsgType);
extern int32_t tls13ParseEarlyData(ssl_t *ssl,
        psParseBuf_t *pb,
        uint32_t *maxEarlyData);
extern int32_t tls13ParseStatusRequest(ssl_t *ssl,
        psParseBuf_t *extBuf);
extern int32_t tls13ParseExtensions(ssl_t *ssl,
        psParseBuf_t *pb,
        unsigned char hsMsgType);

/* Encoding. */
extern int32 tls13WriteClientHello(ssl_t *ssl,
        sslBuf_t *out,
        const psCipher16_t cipherSpec[],
        uint8_t cipherSpecLen,
        uint32 *requiredLen,
        tlsExtension_t *userExt,
        sslSessOpts_t *options);
extern int32 tls13WriteServerHelloExtensions(ssl_t *ssl,
        psDynBuf_t *extBuf,
        psBool_t isHelloRetryRequest);
extern int32_t tls13WriteClientHelloExtensions(ssl_t *ssl,
        psDynBuf_t *extBuf,
        tlsExtension_t *userExt,
        sslSessOpts_t *options);
extern int32_t tls13WriteHsRecordHeader(ssl_t *ssl,
        uint8_t protocol,
        uint8_t handshakeMessageType,
        unsigned char *data,
        psSize_t dataLen,
        psSize_t padLen,
        psBool_t toBeEncrypted,
        unsigned char **c,
        const unsigned char *end,
        unsigned char **encryptStart,
        unsigned char **encryptEnd);
extern psSizeL_t tls13GetPadLen(ssl_t *ssl,
        psSizeL_t len);
extern int32_t tls13EncodeAppData(ssl_t *ssl,
        unsigned char *buf,
        uint32_t size,
        unsigned char *ptBuf,
        uint32_t *len);
extern psSizeL_t tls13GetPaddedLength(ssl_t *ssl,
        psSizeL_t len);
extern int32_t tls13EncodeAlert(ssl_t *ssl,
        unsigned char type,
        sslBuf_t *out,
        uint32_t *requiredLen);
extern psSizeL_t tls13EstimateNextFlightSize(ssl_t *ssl);
extern int32_t tls13WriteEarlyData(ssl_t *ssl,
        psDynBuf_t *extBuf,
        const uint32_t maxEarlyData);
extern int32_t tls13WriteSigAlgs(ssl_t *ssl,
        psDynBuf_t *extBuf,
        const uint16_t sigAlgs[],
        const psSize_t sigAlgsLen,
        const uint8_t extensionType);
extern int32_t tls13WriteCertificateAuthorities(ssl_t *ssl,
        psDynBuf_t *extBuf);
extern psRes_t tls13ParseCertificateAuthorities(ssl_t *ssl,
       const unsigned char **start, psSizeL_t len);

extern int32_t tls13WriteOCSPStatusRequest(ssl_t *ssl,
        psDynBuf_t *extBuf);

/* Transcript-Hash. */
extern int32_t tls13TranscriptHashInit(ssl_t *ssl);
extern int32_t tls13TranscriptHashReinit(ssl_t *ssl);
extern int32_t tls13TranscriptHashUpdate(ssl_t *ssl,
        const unsigned char *in,
        psSize_t len);
extern int32_t tls13TranscriptHashFinish(ssl_t *ssl,
        unsigned char *out);
extern int32_t tls13TranscriptHashSnapshot(ssl_t *ssl,
        unsigned char *out);

/* Signatures. */
extern psBool_t tls13IsRsaSigAlg(uint16_t alg);
extern psBool_t tls13IsEcdsaSigAlg(uint16_t alg);
extern psBool_t tls13IsInsecureSigAlg(uint16_t alg);
extern psBool_t tls13RequiresPreHash(uint16_t alg);
extern uint16_t tls13ChooseSigAlg(ssl_t *ssl,
        const uint16_t *peerSigAlgs,
        psSize_t peerSigAlgsLen);
extern int32_t tls13Sign(psPool_t *pool,
        psPubKey_t *privKey,
        uint16_t sigAlg,
        const unsigned char trHash[MAX_TLS_1_3_HASH_SIZE],
        psSize_t trHashLen,
        const char *contextString,
        psSize_t contextStringLen,
        unsigned char **out,
        psSize_t *outLen);
extern int32_t tls13Verify(psPool_t *pool,
        psPubKey_t *pubKey,
        uint16_t sigAlg,
        unsigned char *signature,
        psSize_t signatureLen,
        const unsigned char trHash[MAX_TLS_1_3_HASH_SIZE],
        psSize_t trHashLen,
        const char *contextString,
        psSize_t contextStringLen);

/* Key schedule. */
extern int32_t tls13DeriveSecret(ssl_t *ssl,
        int32_t hmacAlg,
        const unsigned char *inSecret,
        psSize_t inSecretLen,
        const char *label,
        psSize_t labelLen,
        const unsigned char *trHash,
        psSize_t trHashLen,
        unsigned char outSecret[MAX_TLS_1_3_HASH_SIZE]);
extern int32_t tls13GenerateEarlySecret(ssl_t *ssl,
        psTls13Psk_t *psk);
extern int32_t tls13DeriveEarlySecrets(ssl_t *ssl,
        psTls13Psk_t *psk);
extern int32_t tls13DeriveEarlyDataSecret(ssl_t *ssl,
        psTls13Psk_t *psk);
extern int32_t tls13DeriveEarlyDataKeys(ssl_t *ssl);
extern int32_t tls13ActivateEarlyDataWriteKeys(ssl_t *ssl);
extern int32_t tls13ActivateEarlyDataReadKeys(ssl_t *ssl);
extern int32_t tls13DeriveBinderKey(ssl_t *ssl,
        int32_t hmacAlg,
        unsigned char *binderSecret,
        psSize_t binderSecretLen,
        unsigned char *binderKeyOut,
        psSize_t *binderKeyOutLen);
extern int32_t tls13DeriveHandshakeTrafficSecrets(ssl_t *ssl);
extern int32_t tls13DeriveHandshakeKeys(ssl_t *ssl);
extern int32_t tls13DeriveFinishedKey(ssl_t *ssl,
        psBool_t wantServerKey);
extern int32_t tls13ActivateHsWriteKeys(ssl_t *ssl);
extern int32_t tls13ActivateHsReadKeys(ssl_t *ssl);
extern int32_t tls13DeriveAppTrafficSecrets(ssl_t *ssl);
extern int32_t tls13DeriveAppKeys(ssl_t *ssl);
extern int32_t tls13DeriveResumptionMasterSecret(ssl_t *ssl);
extern int32_t tls13ActivateAppWriteKeys(ssl_t *ssl);
extern int32_t tls13ActivateAppReadKeys(ssl_t *ssl);
extern int32_t tls13TranscriptHashSnapshotAlg(ssl_t *ssl,
        int32_t alg,
        unsigned char *out);

/* Cipher suites. */
extern int32_t tls13GetCipherHmacAlg(ssl_t *ssl);
extern psResSize_t tls13GetCipherHashSize(ssl_t *ssl);
extern int32_t tls13CipherIdToHmacAlg(uint32_t cipherId);
extern psBool_t isTls13Ciphersuite(uint16_t suite);

/* PSK. */
extern int32_t tls13FindSessionPsk(ssl_t *ssl,
        const unsigned char *id,
        psSize_t idLen,
        psTls13Psk_t **pskOut);
extern psTls13Psk_t *tls13NewPsk(const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        psBool_t isResumptionPsk,
        const psTls13SessionParams_t *params);
extern int32_t matrixSslTls13PskGetKey(ssl_t *ssl,
        const unsigned char *id,
        psSize_t idLen,
        unsigned char **key,
        psSize_t *keyLen,
        psTls13SessionParams_t **params);
extern int32_t matrixSslLoadTls13Psk(sslKeys_t *keys,
        const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        const psTls13SessionParams_t *params);
extern int32_t tls13LoadSessionPsks(ssl_t *ssl);
extern int32_t tls13AddSessionPsk(ssl_t *ssl,
        const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        psBool_t isResumptionPsk,
        const psTls13SessionParams_t *params);
extern int32_t tls13FillInPskBinders(ssl_t *ssl,
        unsigned char *bindersStart);
extern int32_t tls13GetPskHmacAlg(psTls13Psk_t *psk);
extern psSize_t tls13GetPskHashLen(psTls13Psk_t *psk);
extern void tls13FreePsk(psTls13Psk_t *psk,
        psPool_t *pool);

/* Resumption. */
extern int32_t tls13DeriveResumptionPsk(ssl_t *ssl,
        int32_t hmacAlg,
        unsigned char *nonce,
        psSize_t nonceLen,
        unsigned char *pskOut,
        psSize_t pskOutLen);
extern int32_t tls13ExportState(ssl_t *ssl,
        psTls13Psk_t *psk,
        unsigned char **out,
        psSizeL_t *outLen);
extern int32_t tls13ImportState(ssl_t *ssl,
        const unsigned char *in,
        psSizeL_t inLen,
        psTls13Psk_t **pskOut);
extern int32_t tls13NewTicket(ssl_t *ssl,
        int32_t hmacAlg,
        uint32_t lifetime,
        uint32_t ageAdd,
        unsigned char *nonce,
        psSize_t nonceLen,
        unsigned char **ticketOut,
        psSizeL_t *ticketOutLen);
# if defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS)
extern int32_t tls13DecryptTicket(ssl_t *ssl,
        psSessionTicketKeys_t *key,
        const unsigned char *ticket,
        psSizeL_t ticketLen,
        psTls13Psk_t **pskOut);
# endif
extern int32_t tls13StorePsk(ssl_t *ssl,
        const unsigned char *psk,
        psSize_t pskLen,
        const unsigned char *pskId,
        psSize_t pskIdLen,
        psBool_t isResumptionPsk,
        const psTls13SessionParams_t *params);
extern int32_t tls13ValidateSessionParams(ssl_t *ssl,
        psTls13SessionParams_t *params);

/* Negotiation. */
#ifdef USE_IDENTITY_CERTIFICATES
extern int32_t tls13TryNegotiateParams(ssl_t *ssl,
        const sslCipherSpec_t *spec,
        sslIdentity_t *givenKey);
# endif

extern uint16_t tls13NegotiateGroup(ssl_t *ssl,
        uint16_t *peerList,
        psSize_t peerListLen);
extern int32_t tls13ServerChooseHelloRetryRequestGroup(ssl_t *ssl,
        uint16_t *chosenGroup);
extern psBool_t tls13WeSupportGroup(ssl_t *ssl,
        uint16_t namedGroup);
extern psBool_t tls13PeerSupportsGroup(ssl_t *ssl,
        uint16_t namedGroup);
extern uint16_t tls13GetNextBestGroup(ssl_t *ssl,
        uint16_t alreadyTriedGroup);
extern int32_t tls13AddPeerSupportedGroup(ssl_t *ssl,
        uint16_t namedGroup);
extern int32_t tls13AddPeerKeyShareGroup(ssl_t *ssl,
        uint16_t namedGroup);
extern int32_t tls13IntersectionPrioritySelect(const psProtocolVersion_t *a,
        psSize_t aLen,
        const psProtocolVersion_t *b,
        psSize_t bLen,
        const psProtocolVersion_t *f,
        psSize_t fLen,
        psProtocolVersion_t *selectedElement);
extern int32_t tls13IntersectionPrioritySelectU16(const uint16_t *a,
        psSize_t aLen,
        const uint16_t *b,
        psSize_t bLen,
        const uint16_t *f,
        psSize_t fLen,
        uint16_t *selectedElement);
extern void tls13ClearHsState(ssl_t *ssl);

/* Authentication. */
extern int32_t tls13ValidateCertChain(ssl_t *ssl);
extern int32_t tls13HandleUserCertCbResult(ssl_t *ssl, int32 cbRc);

/* Key agreement. */
extern int32_t tls13ImportPublicValue(ssl_t *ssl,
        const unsigned char *keyExchangeData,
        psSize_t keyExchangeDataLen,
        uint16_t namedGroup);
extern int32_t tls13ExportPublicValue(ssl_t *ssl,
        uint16_t namedGroup,
        psPubKey_t *key,
        unsigned char **out,
        psSize_t *outLen);
# ifdef USE_ECC
extern int32_t tls13GenerateEcdheKey(ssl_t *ssl,
        psEccKey_t *key,
        uint16_t namedGroup);
# endif
extern int32_t tls13GenerateEphemeralKeys(ssl_t *ssl);
extern psPubKey_t *tls13GetGroupKey(ssl_t *ssl,
        uint16_t namedGroup);
extern int32_t tls13GenSharedSecret(ssl_t *ssl,
        unsigned char **out,
        psSize_t *outLen);

/* Record encryption. */
extern int32 csAesGcmInitTls13(sslSec_t *sec,
        int32 type,
        uint32 keysize);
extern int32 csAesGcmEncryptTls13(void *ssl,
        unsigned char *pt,
        unsigned char *ct,
        uint32 ptLen);
extern int32 csAesGcmDecryptTls13(void *ssl,
        unsigned char *ct,
        unsigned char *pt,
        uint32 len);
extern int32 csChacha20Poly1305IetfEncryptTls13(void *ssl,
        unsigned char *pt,
        unsigned char *ct,
        uint32 len);
extern int32 csChacha20Poly1305IetfDecryptTls13(void *ssl,
        unsigned char *ct,
        unsigned char *pt,
        uint32 len);

/* Misc. */
extern void tls13ClearPeerSupportedGroupList(ssl_t *ssl);

# endif /* USE_TLS_1_3 */
extern int32 sslWritePad(unsigned char *p, unsigned char padLen);
extern int32 sslCreateKeys(ssl_t *ssl);
extern void sslResetContext(ssl_t *ssl);
extern void clearPkaAfter(ssl_t *ssl);
extern pkaAfter_t *getPkaAfter(ssl_t *ssl);
extern void freePkaAfter(ssl_t *ssl);
extern void clearFlightList(ssl_t *ssl);

# ifdef USE_SERVER_SIDE_SSL
extern int32 matrixRegisterSession(ssl_t *ssl);
extern int32 matrixResumeSession(ssl_t *ssl);
extern int32 matrixClearSession(ssl_t *ssl, int32 remove);
extern int32 matrixUpdateSession(ssl_t *ssl);
extern int32 matrixServerSetKeysSNI(ssl_t *ssl, char *host, int32 hostLen);
extern sslKeys_t *matrixServerGetKeysSNI(ssl_t *ssl, char *host, int32 hostLen);

#  ifdef USE_STATELESS_SESSION_TICKETS
extern int32 matrixSessionTicketLen(void);
extern int32 matrixCreateSessionTicket(ssl_t *ssl, unsigned char *out,
                                       int32 *outLen);
extern int32 matrixUnlockSessionTicket(ssl_t *ssl, unsigned char *in,
                                       int32 inLen);
extern int32 matrixSessionTicketLen(void);
#  endif
# endif /* USE_SERVER_SIDE_SSL */

# ifdef USE_DTLS
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
# endif /* USE_DTLS */

/*
    cipherSuite.c
 */
extern psRes_t chooseCipherSuite(ssl_t *ssl, unsigned char *listStart,
        int32 listLen);
extern const sslCipherSpec_t *sslGetDefinedCipherSpec(uint16_t id);
extern const sslCipherSpec_t *sslGetCipherSpec(const ssl_t *ssl, uint16_t id);
extern int32_t sslGetCipherSpecListLen(const ssl_t *ssl);
extern int32_t sslGetCipherSpecList(ssl_t *ssl, unsigned char *c, int32 len,
                                    int32 addScsv);
extern int32_t haveKeyMaterial(const ssl_t *ssl,
                               const sslCipherSpec_t *cipher,
                               short reallyTest);
extern psBool_t isAlpnSuite(const sslCipherSpec_t *suite);
# ifdef USE_CLIENT_SIDE_SSL
int32 csCheckCertAgainstCipherSuite(int32 sigAlg, int32 cipherType);
# endif
extern void matrixSslSetKexFlags(ssl_t *ssl);

# ifndef DISABLE_SSLV3
/******************************************************************************/
/*
    sslv3.c
 */
extern int32_t sslGenerateFinishedHash(psMd5Sha1_t *md,
                                       const unsigned char *masterSecret,
                                       unsigned char *out, int32 senderFlag);

extern int32_t sslDeriveKeys(ssl_t *ssl);

#  ifdef USE_SHA_MAC
extern int32 ssl3HMACSha1(unsigned char *key, unsigned char *seq,
                          unsigned char type, unsigned char *data, uint32 len,
                          unsigned char *mac);
#  endif /* USE_SHA_MAC */

#  ifdef USE_MD5_MAC
extern int32 ssl3HMACMd5(unsigned char *key, unsigned char *seq,
                         unsigned char type, unsigned char *data, uint32 len,
                         unsigned char *mac);
#  endif /* USE_MD5_MAC */
# endif  /* DISABLE_SSLV3 */

# ifdef USE_TLS
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
#  ifdef  USE_SHA256
extern int32 tlsHMACSha2(ssl_t *ssl, int32 mode, unsigned char type,
                         unsigned char *data, uint32 len, unsigned char *mac,
                         int32 hashSize);
#  endif

/******************************************************************************/

#  ifdef USE_TLS_1_2
#   if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
extern int32 sslSha1RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#    ifdef USE_SHA384
extern int32 sslSha384RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#    endif
#    ifdef USE_SHA512
extern int32 sslSha512RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#    endif
#   endif
#   ifdef USE_CLIENT_SIDE_SSL
extern void sslSha1SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#    ifdef USE_SHA384
extern void sslSha384SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#    endif
#    ifdef USE_SHA512
extern void sslSha512SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#    endif
#   endif
#  endif /* USE_TLS_1_2 */

extern int32_t extMasterSecretSnapshotHSHash(ssl_t *ssl, unsigned char *out,
                                             uint32 *outLen);

/******************************************************************************/
/*
    prf.c
 */
#  if defined(USE_NATIVE_TLS_ALGS) || defined(USE_NATIVE_TLS_HS_HASH)
extern int32_t prf(const unsigned char *sec, psSize_t secLen,
                   const unsigned char *seed, psSize_t seedLen,
                   unsigned char *out, psSize_t outLen);
#   ifdef USE_TLS_1_2
extern int32_t prf2(const unsigned char *sec, psSize_t secLen,
                    const unsigned char *seed, psSize_t seedLen,
                    unsigned char *out, psSize_t outLen, uint32_t flags);
#   endif /* USE_TLS_1_2 */
#  endif  /* USE_NATIVE_TLS_ALGS || USE_NATIVE_TLS_HS_HASH */
# endif   /* USE_TLS */

# ifdef USE_AES_CIPHER_SUITE
extern int32 csAesInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csAesEncrypt(void *ssl, unsigned char *pt,
                          unsigned char *ct, uint32 len);
extern int32 csAesDecrypt(void *ssl, unsigned char *ct,
                          unsigned char *pt, uint32 len);
#  ifdef USE_AES_GCM
extern int32 csAesGcmInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csAesGcmEncrypt(void *ssl, unsigned char *pt,
                             unsigned char *ct, uint32 len);
extern int32 csAesGcmDecrypt(void *ssl, unsigned char *ct,
                             unsigned char *pt, uint32 len);
#  endif
# endif /* USE_AES_CIPHER_SUITE */
# ifdef USE_3DES_CIPHER_SUITE
extern int32 csDes3Encrypt(void *ssl, unsigned char *pt,
                           unsigned char *ct, uint32 len);
extern int32 csDes3Decrypt(void *ssl, unsigned char *ct,
                           unsigned char *pt, uint32 len);
# endif /* USE_3DES_CIPHER_SUITE */
# ifdef USE_ARC4_CIPHER_SUITE
extern int32 csArc4Encrypt(void *ssl, unsigned char *pt, unsigned char *ct,
                           uint32 len);
extern int32 csArc4Decrypt(void *ssl, unsigned char *pt, unsigned char *ct,
                           uint32 len);
# endif /* USE_ARC4_CIPHER_SUITE */
# ifdef USE_SEED_CIPHER_SUITE
extern int32 csSeedEncrypt(void *ssl, unsigned char *pt,
                           unsigned char *ct, uint32 len);
extern int32 csSeedDecrypt(void *ssl, unsigned char *ct,
                           unsigned char *pt, uint32 len);
# endif /* USE_SEED_CIPHER_SUITE */

# ifdef USE_IDEA_CIPHER_SUITE
extern int32 csIdeaInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csIdeaEncrypt(void *ssl, unsigned char *pt,
                           unsigned char *ct, uint32 len);
extern int32 csIdeaDecrypt(void *ssl, unsigned char *ct,
                           unsigned char *pt, uint32 len);
# endif /* USE_IDEA_CIPHER_SUITE */

# ifdef USE_PSK_CIPHER_SUITE

extern int32_t matrixSslPskGetKey(ssl_t * ssl,
                                  const unsigned char id[SSL_PSK_MAX_ID_SIZE], uint8_t idLen,
                                  unsigned char *key[SSL_PSK_MAX_KEY_SIZE], uint8_t * keyLen);
extern int32_t matrixSslPskGetKeyId(ssl_t * ssl,
                                    unsigned char *id[SSL_PSK_MAX_ID_SIZE], uint8_t * idLen,
                                    const unsigned char hint[SSL_PSK_MAX_HINT_SIZE], uint8_t hintLen);
extern int32_t matrixPskGetHint(ssl_t * ssl,
                                unsigned char *hint[SSL_PSK_MAX_HINT_SIZE], uint8_t * hintLen);
# endif /* USE_PSK_CIPHER_SUITE */

# ifdef USE_ECC
extern int32 psTestUserEc(int32 ecFlags, const sslKeys_t *keys);
extern int32 psTestUserEcID(int32 id, int32 ecFlags);
#  ifdef USE_TLS_1_3
extern int32 psTestUserEcIDTls13(int32 id, int32 ecFlags);
#  endif
extern int32 curveIdToFlag(int32 id);
# endif

# ifdef USE_ECC_CIPHER_SUITE
extern int32_t eccSuitesSupported(const ssl_t *ssl,
                                  const psCipher16_t cipherSpecs[], uint8_t cipherSpecLen);
# endif /* USE_ECC_CIPHER_SUITE */

# ifdef USE_EAP_FAST
/******************************************************************************/
extern void matrixSslSetSessionIdEapFast(sslSessionId_t *sess,
                                         const unsigned char *pac_key, psSize_t pac_key_len,
                                         const unsigned char *pac_opaque, psSize_t pac_opaque_len);

extern int32_t matrixSslGetEapFastSKS(const ssl_t * ssl,
                                      unsigned char session_key_seed[EAP_FAST_SESSION_KEY_SEED_LEN]);

extern int32_t tprf(const unsigned char *key, psSize_t keyLen,
                    const unsigned char seed, psSize_t seedLen,
                    unsigned char out[SSL_HS_MASTER_SIZE]);
# endif

/******************************************************************************/
/* Deprected defines for compatibility */
# define CH_RECV_STAT            1
# define CH_SENT_STAT            2
# define SH_RECV_STAT            3
# define SH_SENT_STAT            4
# define ALERT_SENT_STAT         5
# define RESUMPTIONS_STAT        6
# define FAILED_RESUMPTIONS_STAT 7
# define APP_DATA_RECV_STAT      8
# define APP_DATA_SENT_STAT      9

# ifdef USE_MATRIXSSL_STATS
extern void matrixsslUpdateStat(ssl_t *ssl, int32_t type, int32_t value);
# else
#  ifdef __GNUC__
static inline
void matrixsslUpdateStat(ssl_t *ssl __attribute__((__unused__)),
    int32_t type __attribute__((__unused__)),
    int32_t value __attribute__((__unused__)))
{
}
#  else
static inline
void matrixsslUpdateStat(ssl_t *ssl, int32_t type, int32_t value)
{
}
#  endif
# endif /* USE_MATRIXSSL_STATS */

/** TLS-level debug print functions.

    To save footprint, the functions should only be called via the
    psTrace* macros. For more information, see the comments
    in tlsTrace.c.

    Compile-time configuration:

    USE_SSL_HANDSHAKE_MSG_TRACE
    - Enables psTraceErrr
    - Enables "server/client creating/parsing extension/hs msg"

    USE_SSL_INFORMATIONAL_TRACE
    - Enables psTraceInfo
    - Enables psTracePrint* functions for printing more complex
      elements such as cipher lists, etc.
*/

/**  Pre-defined indent levels to use with psTracePrint*, etc. */
#  define INDENT_CONN_ESTABLISHED 0
#  define INDENT_NEGOTIATED_PARAM 0
#  define INDENT_ERROR 0
#  define INDENT_WARNING 0
#  define INDENT_HS_MSG 5
#  define INDENT_EXTENSION 6

/** Simple message logging macros.
    psTraceErrr - Error messages relating to errors that result in alerts.
    psTraceInfo - Informational messages and warnings.
*/
# ifdef USE_DTLS
#   ifndef USE_DTLS_DEBUG_TRACE
#    define psTraceDtls(x)
#    define psTraceIntDtls(x, y)
#    define psTraceStrDtls(x, y)
#   else
#    include "osdep.h"
#    define psTraceDtls(x) tlsTrace(x)
#    define psTraceIntDtls(x, y) tlsTraceInt(x, y)
#    define psTraceStrDtls(x, y) tlsTraceStr(x, y)
#   endif /* USE_DTLS_DEBUG_TRACE */
# endif  /* USE_DTLS */

#  ifndef USE_SSL_HANDSHAKE_MSG_TRACE
#   define psTraceErrr(x) /* Same macro name length as psTraceInfo. */
#   define psTraceError(x)
#   define psTraceErrrIndent(x, y)
#  else
#   define psTraceErrr(x) tlsTraceError(__FILE__, __LINE__, x)
#   define psTraceError(x) tlsTraceError(__FILE__, __LINE__, x)
#   define psTraceErrorIndent(x, y) tlsTraceErrorIndent(x, __FILE__, __LINE__, y)
#  endif

#  ifndef USE_SSL_INFORMATIONAL_TRACE
#   define psTraceInfo(x)
#   define psTraceStrInfo(x, y)
#   define psTraceIntInfo(x, y)
#  else
#   include "osdep.h"
#   define psTraceInfo(x) tlsTrace(x)
#   define psTraceStrInfo(x, y) tlsTraceStr(x, y)
#   define psTraceIntInfo(x, y) tlsTraceInt(x, y)
#  endif /* USE_SSL_INFORMATIONAL_TRACE */

# ifdef USE_SSL_HANDSHAKE_MSG_TRACE
void tlsTrace(const char *str);
void tlsTraceInt(const char *str, int32_t value);
void tlsTraceStr(const char *str, const char *str2);
void tlsTraceIndent(psSize_t indentLevel, const char *str);
void tlsTraceErrorIndent(psSize_t indentLevel,
        const char *srcFile,
        int srcLine,
        const char *errorMsg);
void tlsTraceError(const char *srcFile,
        int srcLine,
        const char *errorMsg);
void psPrintHsMsgType(int32_t type, psBool_t addNewline);
void psPrintAlertEncodeInfo(ssl_t *ssl, unsigned char alertType);
void psPrintAlertReceiveInfo(ssl_t *ssl, unsigned char alertType);
void psPrintHsMessageCreate(ssl_t *ssl, unsigned char hsMsgType);
void psPrintHsMessageParse(ssl_t *ssl, unsigned char hsMsgType);
void psPrintChangeCipherSpecParse(ssl_t *ssl);
void psPrintChangeCipherSpecCreate(ssl_t *ssl);
void psPrintExtensionParse(ssl_t *ssl, uint16_t extType);
void psPrintExtensionCreate(ssl_t *ssl, uint16_t extType);
#  define psTraceIndent(indentLevel, str) \
    tlsTraceIndent(indentLevel, str)
#  define psTracePrintHsMsgType(type, addNewline) \
    psPrintHsMsgType(type, addNewline)
#  define psTracePrintAlertEncodeInfo(ssl, alertType) \
    psPrintAlertEncodeInfo(ssl, alertType)
#  define psTracePrintAlertReceiveInfo(ssl, alertType) \
    psPrintAlertReceiveInfo(ssl, alertType)
#  define psTracePrintHsMessageCreate(ssl, hsMsgType) \
    psPrintHsMessageCreate(ssl, hsMsgType)
#  define psTracePrintHsMessageParse(ssl, hsMsgType) \
    psPrintHsMessageParse(ssl, hsMsgType)
#  define psTracePrintChangeCipherSpecParse(ssl) \
    psPrintChangeCipherSpecParse(ssl)
#  define psTracePrintChangeCipherSpecCreate(ssl) \
    psPrintChangeCipherSpecCreate(ssl)
#  define psTracePrintExtensionParse(ssl, extType) \
    psPrintExtensionParse(ssl, extType)
#  define psTracePrintExtensionCreate(ssl, extType) \
    psPrintExtensionCreate(ssl, extType)
#  define psTracePrintExtensionType(ssl, type, addNewline) \
    psPrintExtensionType(ssl, type, addNewline)
# else  /* No USE_SSL_HANDSHAKE_MSG_TRACE --> no code */
#  define tlsTraceIndent(indentLevel, str)
#  define psTraceIndent(indentLevel, str)
#  define psTracePrintHsMsgType(type, addNewline)
#  define psTracePrintAlertEncodeInfo(ssl, alertType)
#  define psTracePrintAlertReceiveInfo(ssl, alertType)
#  define psTracePrintHsMessageCreate(ssl, hsMsgType)
#  define psTracePrintHsMessageParse(ssl, hsMsgType)
#  define psTracePrintChangeCipherSpecParse(ssl)
#  define psTracePrintChangeCipherSpecCreate(ssl)
#  define psTracePrintExtensionParse(ssl, extType)
#  define psTracePrintExtensionCreate(ssl, extType)
#  define psTracePrintExtensionType(ssl, type, addNewline)
# endif /* USE_SSL_HANDSHAKE_MSG_TRACE */

# ifdef USE_SSL_INFORMATIONAL_TRACE
void psPrintHex(psSize_t indentLevel,
        const char *where,
        unsigned char *bytes,
        psSizeL_t numBytes,
        psBool_t addNewline);
void psPrintCiphersuiteName(psSize_t indentLevel,
        const char *where,
        uint16_t cipherId,
        psBool_t addNewline);
void psPrintEncodedCipherList(psSize_t indentLevel,
        const char *where,
        const unsigned char *cipherList,
        psSize_t cipherListLen,
        psBool_t addNewline);
void psPrintCipherList(psSize_t indentLevel,
        const char *where,
        const psCipher16_t *cipherList,
        psSize_t numCiphers,
        psBool_t addNewline);
void psPrintSigAlgs(psSize_t indentLevel,
        const char *where,
        uint16_t sigAlgs,
        psBool_t addNewline);
void psPrintTls13SigAlg(psSize_t indentLevel,
        const char *where,
        uint16_t alg,
        psBool_t addNewline);
void psPrintTls13SigAlgList(psSize_t indentLevel,
        const char *where,
        uint16_t *algs,
        psSize_t numAlgs,
        psBool_t addNewline);
void psPrintProtocolVersionNew(psSize_t indentLevel,
        const char *where,
        psProtocolVersion_t ver,
        psBool_t addNewline);
void psPrintProtocolVersion(psSize_t indentLevel,
        const char *where,
        unsigned char majVer,
        unsigned char minVer,
        psBool_t addNewline);
void psPrintNegotiatedProtocolVersion(psSize_t indentLevel,
        const char *where,
        ssl_t *ssl,
        psBool_t addNewline);
void psPrintVersionsList(psSize_t indentLevel,
        const char *where,
        psProtocolVersion_t *list,
        psSize_t listLen,
        psBool_t addNewline);
void psPrintSupportedVersionsList(psSize_t indentLevel,
        const char *where,
        ssl_t *ssl,
        psBool_t peer,
        psBool_t addNewline);
void psPrintTls13NamedGroup(psSize_t indentLevel,
        const char *where,
        uint16_t namedGroup,
        psBool_t addNewline);
void psPrintTls13NamedGroupList(psSize_t indentLevel,
        const char *where,
        const unsigned char *list,
        psSize_t listLen,
        ssl_t *ssl,
        psBool_t addNewline);
void psPrintServerName(psSize_t indentLevel,
        const char *where,
        const char *serverName,
        psBool_t addNewline);
void psPrintTlsKeys(const char *where,
        ssl_t *ssl,
        psBool_t addNewline);
void psPrintSslFlags(uint32_t flags);
void psPrintCurrentFlight(ssl_t *ssl);
void psPrintExtensionType(ssl_t *ssl,
        uint16_t extType,
        psBool_t addNewline);
void psPrintRecordType(unsigned char type,
        psBool_t isInnerType,
        psBool_t addNewline);
void psPrintRecordHeader(sslRec_t *rec, psBool_t addNewline);
void psPrintHandshakeHeader(unsigned char type,
        uint32_t len,
        psBool_t addNewline);
void psPrintHsState(uint8_t type, psBool_t addNewline);
void psPrintCertSubject(psSize_t indentLevel,
        ssl_t *ssl,
        psX509Cert_t *cert,
        psSize_t indexInChain);
void psPrintPskKeyExchangeMode(psSize_t indentLevel,
        const char *where,
        psk_key_exchange_mode_e mode,
        psBool_t addNewLine);
void psPrintTranscriptHashUpdate(ssl_t *ssl,
        unsigned char *in,
        psSizeL_t inLen,
        int32_t hashAlg);
#  define psTracePrintHex(indentLevel, where, bytes, numBytes, addNewline) \
    psPrintHex(indentLevel, where, bytes, numBytes, addNewline)
#  define psTracePrintCiphersuiteName(indentLevel, where, cipher, addNewline) \
    psPrintCiphersuiteName(indentLevel, where, cipher, addNewline)
#  define psTracePrintEncodedCipherList(indentLevel, where, cipherList, cipherListLen, addNewline) \
    psPrintEncodedCipherList(indentLevel, where, cipherList, cipherListLen, addNewline)
#  define psTracePrintCipherList(indentLevel, where, cipherList, numCiphers, addNewline) \
    psPrintCipherList(indentLevel, where, cipherList, numCiphers, addNewline)
#  define psTracePrintSigAlgs(indentLevel, sigAlgs, where, addNewline) \
    psPrintSigAlgs(indentLevel, sigAlgs, where, addNewline)
#  define psTracePrintPubKeyTypeAndSize(ssl, key) \
    psPrintPubKeyTypeAndSize(ssl, key)
#  define psTracePrintTls13SigAlg(indentLevel, where, alg, addNewline)   \
    psPrintTls13SigAlg(indentLevel, where, alg, addNewline)
#  define psTracePrintTls13SigAlgList(indentLevel, where, algs, numAlgs, addNewline) \
    psPrintTls13SigAlgList(indentLevel, where, algs, numAlgs, addNewline)
#  define psTracePrintProtocolVersion(indentLevel, where, majVer, minVer, addNewline) \
    psPrintProtocolVersion(indentLevel, where, majVer, minVer, addNewline)
#  define psTracePrintProtocolVersionNew(indentLevel, where, ver, addNewline) \
    psPrintProtocolVersionNew(indentLevel, where, ver, addNewline)
#  define psTracePrintNegotiatedProtocolVersion(indentLevel, where, ssl, addNewline) \
    psPrintNegotiatedProtocolVersion(indentLevel, where, ssl, addNewline)
#  define psTracePrintVersionsList(indentLevel, where, list, listLen, addNewline) \
    psPrintVersionsList(indentLevel, where, list, listLen, addNewline)
#  define psTracePrintSupportedVersionsList(indentLevel, where, ssl, peer, addNewline) \
    psPrintSupportedVersionsList(indentLevel, where, ssl, peer, addNewline)
#  define psTracePrintTls13NamedGroup(indentLevel, where, curveId, addNewline) \
    psPrintTls13NamedGroup(indentLevel, where, curveId, addNewline)
#  define psTracePrintTls13NamedGroupList(indentLevel, where, list, listLen, ssl, addNewline) \
    psPrintTls13NamedGroupList(indentLevel, where, list, listLen, ssl, addNewline)
#  define psTracePrintServerName(indentLevel, where, serverName, addNewline) \
    psPrintServerName(indentLevel, where, serverName, addNewline)
#  define psTracePrintTlsKeys(where, ssl, addNewline) \
    psPrintTlsKeys(where, ssl, addNewline)
#  define psTracePrintSslFlags(ssl) \
    psPrintSslFlags(ssl)
#  define psTracePrintRecordType(type, isInnerType, addNewline)  \
    psPrintRecordType(type, isInnerType, addNewline)
#  define psTracePrintCurrentFlight(ssl) \
    psPrintCurrentFlight(ssl)
#  define psTracePrintRecordHeader(rec, addNewline)     \
    psPrintRecordHeader(rec, addNewline)
#  define psTracePrintHandshakeHeader(type, len, addNewline) \
    psPrintHandshakeHeader(type, len, addNewline)
#  define psTracePrintHsState(state, addNewline)           \
    psPrintHsState(state, addNewline)
#  define psTracePrintCertSubject(indentLevel, ssl, cert, indexInChain)  \
    psPrintCertSubject(indentLevel, ssl, cert, indexInChain)
#  define psTracePrintPskKeyExchangeMode(indentLevel, where, mode, addNewLine) \
    psPrintPskKeyExchangeMode(indentLevel, where, mode, addNewLine)
#  define psTracePrintTranscriptHashUpdate(ssl, in, inLen, hashAlg) \
    psPrintTranscriptHashUpdate(ssl, in, inLen, hashAlg)
# else /* Do not produce code without USE_SSL_INFORMATIONAL_TRACE. */
#  define psTracePrintHex(indentLevel, where, bytes, numBytes, addNewline)
#  define psTracePrintCiphersuiteName(indentLevel, where, cipher, addNewline)
#  define psTracePrintEncodedCipherList(indentLevel, where, cipherList, cipherListLen, addNewline)
#  define psTracePrintCipherList(indentLevel, where, cipherList, numCiphers, addNewline)
#  define psTracePrintSigAlgs(indentlevel, sigAlgs, where, addNewLine)
#  define psTracePrintPubKeyTypeAndSize(ssl, key)
#  define psTracePrintTls13SigAlg(indentLevel, where, sigAlg, addNewline)
#  define psTracePrintTls13SigAlgList(indentLevel, where, algs, numAlg, addNewline)
#  define psTracePrintProtocolVersion(indentLevel, where, majVer, minVer, addNewline)
#  define psTracePrintProtocolVersionNew(indentLevel, where, ver, addNewline)
#  define psTracePrintNegotiatedProtocolVersion(indentLevel, where, ssl, addNewline)
#  define psTracePrintVersionsList(indentLevel, where, list, listLen, addNewline)
#  define psTracePrintVersionsList32(indentLevel, where, list, listLen, addNewline)
#  define psTracePrintSupportedVersionsList(indentLevel, where, ssl, peer, addNewline)
#  define psTracePrintTls13NamedGroup(indentLevel, where, curveId, addNewline)
#  define psTracePrintTls13NamedGroupList(indentLevel, where, list, listLen, ssl, addNewline)
#  define psTracePrintServerName(indentLevel, where, serverName, addNewline)
#  define psTracePrintTlsKeys(where, ssl, addNewline)
#  define psTracePrintSslFlags(ssl)
#  define psTracePrintRecordType(type, isInnerType, addNewline)
#  define psTracePrintCurrentFlight(ssl)
#  define psTracePrintRecordHeader(rec, addNewline)
#  define psTracePrintHandshakeHeader(type, len, addNewline)
#  define psTracePrintHsState(state, addNewline)
#  define psTracePrintCertSubject(indentLevel, ssl, cert, indexInChain)
#  define psTracePrintPskKeyExchangeMode(indentLevel, where, mode, addNewLine)
#  define psTracePrintTranscriptHashUpdate(ssl, in, inLen, hashAlg)
# endif /* USE_SSL_INFORMATIONAL_TRACE */

# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
psBool_t weSupportSigAlg(int32_t sigAlg,
        int32_t pubKeyAlgorithm);
psBool_t peerSupportsSigAlg(int32_t sigAlg,
        uint16_t peerSigAlgs);
psBool_t canUseSigAlg(int32_t sigAlg,
        int32_t pubKeyAlgorithm,
        uint16_t peerSigAlgs);
int32_t upgradeSigAlg(int32_t sigAlg, int32_t pubKeyAlgorithm);
int32_t chooseSigAlgInt(int32_t certSigAlg,
        psSize_t keySize,
        int32_t pubKeyAlgorithm,
        uint16_t peerSigAlgs);
int32_t chooseSigAlg(psX509Cert_t *cert,
        psPubKey_t *privKey,
        uint16_t peerSigAlgs);
int32_t getSignatureAndHashAlgorithmEncoding(uint16_t sigAlgOid,
        unsigned char *b1,
        unsigned char *b2,
        uint16_t *hashSize);
# endif

# ifdef USE_CLIENT_SIDE_SSL
int32_t matrixSslChooseClientKeys(ssl_t *ssl, sslKeySelectInfo_t *keySelect);
# endif


# ifdef __cplusplus
}
# endif

#endif /* _h_MATRIXSSLLIB */

/******************************************************************************/
