/**
 *      @file    matrixsslApi.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      Implementations interacting with the matrixssl library should
 *      only use the APIs and definitions used in this file.
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

#ifndef _h_MATRIXSSL
# define _h_MATRIXSSL

# ifdef __cplusplus
extern "C" {
# endif

# include "coreApi.h"     /* cryptoApi.h and matrixsslApi.h depend on this */
# include "../crypto/cryptoApi.h" /* matrixsslApi.h depend on cryptoApi.h. */

# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <matrixsslConfig.h> /* Get matrixssl configuration from -I dir. */
# else
#  include "matrixsslConfig.h" /* Get local matrixssl configuration file. */
# endif


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
# define USE_TLS        /**< DO NOT DISABLE @security NIST_MAY */
# define USE_TLS_1_1    /**< DO NOT DISABLE @security NIST_SHALL */
# define USE_TLS_1_2    /**< DO NOT DISABLE @security NIST_SHOULD */
# define DISABLE_SSLV3  /**< DO NOT DISABLE, undef below if required
                           @security NIST_SHALL_NOT */

# ifndef NO_TLS_1_2_TOGGLE
#  define USE_TLS_1_2_TOGGLE /**< Allow disabling TLS 1.2 dynamically. */
# endif
# ifndef NO_TLS_1_1_TOGGLE
#  define USE_TLS_1_1_TOGGLE /**< Allow disabling TLS 1.1 dynamically. */
# endif
 # ifndef NO_TLS_1_0_TOGGLE
#  define USE_TLS_1_0_TOGGLE /**< Allow disabling TLS 1.0 dynamically. */
# endif

/* This looks a bit clumsy, because TLS 1.3 code still requires a separate
   define (USE_TLS_1_3) to enable. */
#  if defined USE_TLS_1_2_AND_ABOVE
#   define USE_TLS_1_3
#   define USE_TLS_1_2
#   define DISABLE_TLS_1_1
#   define DISABLE_TLS_1_0
#  elif defined USE_TLS_1_1_AND_ABOVE
#   define USE_TLS_1_3
#   define USE_TLS_1_2
#   define DISABLE_TLS_1_0
#  elif defined USE_TLS_1_0_AND_ABOVE
#   define USE_TLS_1_3
#   define USE_TLS_1_2
#   define USE_TLS_1_1
/** @security undef DISABLE_SSLV3 here if required */
#  else
#   error Must define USE_TLS_1_x_AND_ABOVE
#  endif

/* Type used for storing protocol versions. */
typedef uint32_t psProtocolVersion_t;

# if defined(USE_TLS_1_3) && defined(DISABLE_TLS_1_3)
#  undef USE_TLS_1_3
#  undef USE_TLS_AES_128_GCM_SHA256
#  undef USE_TLS_AES_256_GCM_SHA384
#  undef USE_TLS_CHACHA20_POLY1305_SHA256
# endif

/**
    Do sanity checks on configuration.
 */
# include "matrixsslCheck.h"




# include "version.h"

# ifdef USE_MATRIX_OPENSSL_LAYER
#  include "opensslApi.h"
# endif
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
#  include "psExt.h"
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

/******************************************************************************/
/*
    Public return codes
 */
# define MATRIXSSL_SUCCESS           PS_SUCCESS       /* Generic success */
# define MATRIXSSL_ERROR             PS_PROTOCOL_FAIL /* Generic SSL error */
# define MATRIXSSL_REQUEST_SEND      1                /* API produced data to be sent */
# define MATRIXSSL_REQUEST_RECV      2                /* API requres more data to continue */
# define MATRIXSSL_REQUEST_CLOSE     3                /* API indicates clean close is req'd */
# define MATRIXSSL_APP_DATA          4                /* App data is avail. to caller */
# define MATRIXSSL_HANDSHAKE_COMPLETE    5            /* Handshake completed */
# define MATRIXSSL_RECEIVED_ALERT    6                /* An alert was received */
# define MATRIXSSL_APP_DATA_COMPRESSED   7            /* App data must be inflated */

/* Early_data return codes */
# ifdef USE_TLS_1_3
#  define MATRIXSSL_EARLY_DATA_ACCEPTED 8
#  define MATRIXSSL_EARLY_DATA_REJECTED 9
#  define MATRIXSSL_EARLY_DATA_SENT 10
#  define MATRIXSSL_EARLY_DATA_NOT_SENT 11

# endif
/******************************************************************************/
/*
    Build the configuration string with the relevant build options for
    runtime validation of compile-time configuration.
 */
#  define HW_CONFIG_STR "N"

# define MATRIXSSL_CONFIG \
    "Y" \
    HW_CONFIG_STR \
    PSCRYPTO_CONFIG


/* Maximum number of simultaneous TLS versions supported */
# define TLS_MAX_SUPPORTED_VERSIONS 16
/* TLS 1.3: maximum number of algorithms in signature_algorithms extension. */
# define TLS_MAX_SIGNATURE_ALGORITHMS 32
/* TLS 1.3: maximum number of cipher suites to support in clientHello */
# define TLS_1_3_MAX_CIPHER_SUITES 8
/* TLS 1.3: maximum number of groups. */
# define TLS_1_3_MAX_GROUPS 32

/*
    TLS implementations supporting these ciphersuites MUST support
    arbitrary PSK identities up to 128 octets in length, and arbitrary
    PSKs up to 64 octets in length.  Supporting longer identities and
    keys is RECOMMENDED.
 */
# define SSL_PSK_MAX_KEY_SIZE    64  /* Must be < 256 due to 'idLen' */
# define SSL_PSK_MAX_ID_SIZE     128 /* Must be < 256 due to 'idLen' */
# define SSL_PSK_MAX_HINT_SIZE   32  /* ServerKeyExchange hint is non-standard */



/*
    SSL Alert levels and descriptions
    This implementation treats all alerts that are not related to
    certificate validation as fatal
 */
# define SSL_ALERT_LEVEL_WARNING             1
# define SSL_ALERT_LEVEL_FATAL               2

# define SSL_ALERT_CLOSE_NOTIFY              0
# define SSL_ALERT_UNEXPECTED_MESSAGE        10
# define SSL_ALERT_BAD_RECORD_MAC            20
# define SSL_ALERT_DECRYPTION_FAILED         21/* Do not use, per RFC 5246 */
# define SSL_ALERT_RECORD_OVERFLOW           22
# define SSL_ALERT_DECOMPRESSION_FAILURE     30
# define SSL_ALERT_HANDSHAKE_FAILURE         40
# define SSL_ALERT_NO_CERTIFICATE            41
# define SSL_ALERT_BAD_CERTIFICATE           42
# define SSL_ALERT_UNSUPPORTED_CERTIFICATE   43
# define SSL_ALERT_CERTIFICATE_REVOKED       44
# define SSL_ALERT_CERTIFICATE_EXPIRED       45
# define SSL_ALERT_CERTIFICATE_UNKNOWN       46
# define SSL_ALERT_ILLEGAL_PARAMETER         47
# define SSL_ALERT_UNKNOWN_CA                48
# define SSL_ALERT_ACCESS_DENIED             49
# define SSL_ALERT_DECODE_ERROR              50
# define SSL_ALERT_DECRYPT_ERROR             51
# define SSL_ALERT_PROTOCOL_VERSION          70
# define SSL_ALERT_INSUFFICIENT_SECURITY     71
# define SSL_ALERT_INTERNAL_ERROR            80
# define SSL_ALERT_INAPPROPRIATE_FALLBACK    86
# define SSL_ALERT_NO_RENEGOTIATION          100
# define SSL_ALERT_UNSUPPORTED_EXTENSION     110
# define SSL_ALERT_UNRECOGNIZED_NAME         112
# define SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE   113
# define SSL_ALERT_UNKNOWN_PSK_IDENTITY      115
# define SSL_ALERT_NO_APP_PROTOCOL           120

/**
    SSL protocol and MatrixSSL defines.
    @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */

/*
    Maximum SSL/TLS record size, per specification
 */
# define     SSL_MAX_PLAINTEXT_LEN       0x4000 /* 16KB */
# define     SSL_MAX_RECORD_LEN          SSL_MAX_PLAINTEXT_LEN + 2048
# define     SSL_MAX_BUF_SIZE            0xffff /* 65536. This must be
                                                   enough for entire
                                                   outgoing flight */
# define     SSL_MAX_DISABLED_CIPHERS    32

/*
  From section 5.2. of the TLS 1.3 spec.
  Assuming a fullsize TLSPlaintext.fragment, TLSInnerPlaintext adds
  1 type octet and TLSCiphertext adds at most 255 AEAD overhead.
*/
# define     TLS_1_3_MAX_PLAINTEXT_FRAGMENT_LEN  16384 /* 2^14 */
# define     TLS_1_3_MAX_INNER_PLAINTEXT_LEN     16385 /* 2^14 + 1 */
# define     TLS_1_3_MAX_CIPHERTEXT_LEN          16640 /* 2^14 + 1 + 255 */

/*
    Maximum buffer sizes for static SSL array types
 */
# define SSL_MAX_MAC_SIZE        48/* SHA384 */
# define SSL_MAX_IV_SIZE         16
# define SSL_MAX_BLOCK_SIZE      16
# define SSL_MAX_SYM_KEY_SIZE    32
# define MAX_TLS_1_3_HASH_SIZE   SHA384_HASHLEN

/*
    Negative return codes must be between -50 and -69 in the MatrixSSL module
 */
# define     SSL_FULL            -50         /* must call sslRead before decoding */
# define     SSL_PARTIAL         -51         /* more data reqired to parse full msg */
# define     SSL_SEND_RESPONSE   -52         /* decode produced output data */
# define     SSL_PROCESS_DATA    -53         /* succesfully decoded application data */
# define     SSL_ALERT           -54         /* we've decoded an alert */
# define     SSL_FILE_NOT_FOUND  -55         /* File not found */
# define     SSL_MEM_ERROR       PS_MEM_FAIL /* Memory allocation failure */
# ifdef USE_DTLS
#  define     DTLS_MUST_FRAG      -60        /* Message must be fragmented */
#  define     DTLS_RETRANSMIT     -61        /* Received a duplicate hs msg from peer */
# endif /* USE_DTLS */
# define     SSL_ENCODE_RESPONSE  -62        /* Need to encode a response. */
# define     SSL_NO_TLS_1_3       -63  /* We advertised TLS 1.3, but server
                                          chose TLS <1.3. */

/* Forward declarations for certain public API opaque data types. */
typedef struct ssl ssl_t;
typedef struct sslKeys sslKeys_t;
typedef struct sslKeySelectInfo sslKeySelectInfo_t;
typedef struct sslSessOpts sslSessOpts_t;
typedef struct sslSessionId sslSessionId_t;
typedef struct tlsHelloExt tlsExtension_t;

#  ifdef USE_TLS_1_3
typedef struct psTls13SessionParams psTls13SessionParams_t;
typedef struct psTls13Psk psTls13Psk_t;
#  endif  /* USE_TLS_1_3 */

/******************************************************************************/
/*
 *      Library init and close
 */
# define matrixSslOpen() matrixSslOpenWithConfig(MATRIXSSL_CONFIG)
PSPUBLIC int32  matrixSslOpenWithConfig(const char *config);
PSPUBLIC void   matrixSslClose(void);

/******************************************************************************/
/*
 *      Certificate and key material loading
 */
PSPUBLIC int32  matrixSslNewKeys(sslKeys_t **keys, void *poolUserPtr);
PSPUBLIC void   matrixSslDeleteKeys(sslKeys_t *keys);

#define LOAD_KEYS_OPT_ALLOW_OUT_OF_DATE_CERT_PARSE (1 << 0)
typedef struct {
    uint32_t flags; /* LOAD_KEYS_OPT_* */
    int32_t key_type;
} matrixSslLoadKeysOpts_t;

# if defined(USE_RSA) || defined(USE_ECC)

/* These functions load key and certificate data into a keychain 'keys'.
   Calls to function must specify a key/cert pair, and/or a CA certificate.
   These functions can be called more than once to input multiple identity
   keys to be used for TLS client authentication (in case of a client with
   more than one identity known at the time a connection is established. */
int32_t matrixSslLoadKeys(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile,
        matrixSslLoadKeysOpts_t *opts);
int32_t matrixSslLoadKeysMem(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        matrixSslLoadKeysOpts_t *opts);
# endif /* USE_RSA || USE_ECC */
# ifdef USE_RSA
PSPUBLIC int32  matrixSslLoadRsaKeysExt(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *trustedCAFile,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32  matrixSslLoadRsaKeys(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *trustedCAFile);
PSPUBLIC int32  matrixSslLoadRsaKeysMemExt(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *trustedCABuf,
        int32 trustedCALen,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32  matrixSslLoadRsaKeysMem(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *trustedCABuf,
        int32 trustedCALen);
# endif /* USE_RSA */

PSPUBLIC int32  matrixSslLoadPkcs12(sslKeys_t *keys,
        const unsigned char *p12File,
        const unsigned char *importPass,
        int32 ipasslen,
        const unsigned char *macPass,
        int32 mpasslen,
        int32 flags);
PSPUBLIC int32  matrixSslLoadPkcs12Mem(sslKeys_t *keys,
        const unsigned char *p12Buf,
        int32 p12Len,
        const unsigned char *importPass,
        int32 ipasslen,
        const unsigned char *macPass,
        int32 mpasslen,
        int32 flags);

# ifdef USE_OCSP_RESPONSE
typedef int32_t (*ocspCb_t)(struct ssl *ssl, psOcspResponse_t *response,
                            psX509Cert_t *cert, int32_t status);
#ifdef USE_SERVER_SIDE_SSL
PSPUBLIC int32_t matrixSslLoadOCSPResponse(sslKeys_t *keys,
        const unsigned char *OCSPResponseBuf,
        psSize_t OCSPResponseBufLen);
#endif /* USE_SERVER_SIDE_SSL */
# endif /* USE_OCSP_RESPONSE */


/******************************************************************************/
/*
 *      Essential public APIs
 */
PSPUBLIC int32  matrixSslGetReadbuf(ssl_t *ssl, unsigned char **buf);
PSPUBLIC int32  matrixSslGetReadbufOfSize(ssl_t *ssl, int32 size,
                                          unsigned char **buf);
PSPUBLIC int32  matrixSslGetOutdata(ssl_t *ssl, unsigned char **buf);
PSPUBLIC int32  matrixSslGetWritebuf(ssl_t *ssl, unsigned char **buf,
                                     uint32 reqLen);
PSPUBLIC int32  matrixSslEncodeWritebuf(ssl_t *ssl, uint32 len);
PSPUBLIC int32  matrixSslEncodeToOutdata(ssl_t *ssl, unsigned char *buf,
                                         uint32 len);
PSPUBLIC int32 matrixSslEncodeToUserBuf(ssl_t *ssl, unsigned char *ptBuf,
                                        uint32 ptLen, unsigned char *ctBuf, uint32 *ctLen);
PSPUBLIC int32  matrixSslSentData(ssl_t *ssl, uint32 bytes);
PSPUBLIC int32  matrixSslReceivedData(ssl_t *ssl, uint32 bytes,
                                      unsigned char **ptbuf, uint32 *ptlen);
PSPUBLIC int32  matrixSslProcessedData(ssl_t *ssl,
                                       unsigned char **ptbuf, uint32 *ptlen);
PSPUBLIC int32  matrixSslEncodeClosureAlert(ssl_t *ssl);
PSPUBLIC void   matrixSslDeleteSession(ssl_t *ssl);

PSPUBLIC psBool_t matrixSslTlsVersionRangeSupported(psProtocolVersion_t low,
        psProtocolVersion_t high);
PSPUBLIC int32_t matrixSslSessOptsSetKeyExGroups(sslSessOpts_t *options,
        uint16_t *namedGroups,
        psSize_t namedGroupsLen,
        psSize_t numClientHelloKeyShares);
PSPUBLIC int32_t matrixSslSessOptsSetSigAlgs(sslSessOpts_t *options,
        uint16_t *sigAlgs,
        psSize_t sigAlgsLen);
PSPUBLIC int32_t matrixSslSessOptsSetSigAlgsCert(sslSessOpts_t *options,
        uint16_t *sigAlgs,
        psSize_t sigAlgsLen);
PSPUBLIC int32_t matrixSslSessOptsSetMinDhBits(sslSessOpts_t *options,
        psSize_t minDhBits);
# ifdef USE_TLS_1_3
PSPUBLIC int32_t matrixSslGetEarlyDataStatus(ssl_t *ssl);
PSPUBLIC int32_t matrixSslGetMaxEarlyData(ssl_t *ssl);
PSPUBLIC int32_t matrixSslSetTls13BlockPadding(ssl_t *ssl,
        psSizeL_t blockSize);
# endif

/* Callback function of this type is called from the matrix library after it
   has performed certificate path construction/validation for the certificate
   presented by the peer (either the web server cert, or the client
   certificate. This function can accept or reject the tls connection on its
   discretion.

   Allowed return values:
   * PS_SUCCCESS:
     connection is OK - returning this will clear any pending from
     potentially failed certificate validation.
   * SSL_ALLOW_ANON_CONNECTION:
     connection is accepted, but is later considered as anonymous
   * >0 TLS alert to send to the peer (one of SSL_ALERT_ codes)
   * <0 Internal error; sending SSL_ALERT_INTERNAL_ERROR to peer. */
typedef int32_t (*sslCertCb_t)(struct ssl *ssl, psX509Cert_t *cert, int32_t alert);

/** Structure for passing client-side key and cert selection requirements
    to the sslIdentityCb_t type callback function. The structure is filled
    with information from the server's CertificateRequest message.
*/
struct sslKeySelectInfo
{
    /* Number of End Entity certificate supplying certificate authorities
       accepted by the peer. Both arrays caNames, and caNameLens have this
       many elements. */
    psSize_t nCas;

# if defined(USE_IDENTITY_CERTIFICATES)
    /* Array of certificate authority names, binary DER encoding, as received
       from the peer. Each element caNames[N] is a binary string whose lenght
       is caNameLens[N] octets.

       These names can be memcmp()'d with values available from the
       certificate subject/issuer names. */
    const unsigned char **caNames;
    psSize_t *caNameLens;
# endif

    /* Supported signature algorithm masks for transport and
       certificate chains (latter for TLS1.3) */
    uint32_t peerSigAlgMask;
    uint32_t peerCertSigAlgMask;

    /* Algorithms supported by peer for session signature. The values are one
       of SignatureAndHashAlgorithm for TLS12, and one of SignatureScheme
       values for TLS13 The selected identity key needs to be usable for
       producing authentication signature with this identified algoritm
       combination. */
    psSize_t peerSigAlgsLen;
    uint16_t peerSigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS];

#ifdef USE_TLS_1_3
    /* Algorithms supported by peer for certificate chains. If the session is
       not TLS13 (or beyond), number of algorithms is always 0. */
    psSize_t peerCertSigAlgsLen;
    uint16_t peerCertSigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS];
#endif /* USE_TLS_1_3 */
};


/* Callback function with signature of sslIdentityCb will be caled from the
   matrix library to obtain key material for TLS client authentication. The
   'ssl' identifies the handshake to authenticate, and 'keySpec' identifies
   the key (type, certificate issuer) accepted by the peer.

   If this callback is set, it will be exclusively used for arranging
   keys used for client authentication, regardless if identities
   (keys) were provided when calling matrixSslNewClientSession().

   The callback shall use function matrixSslSetClientIdentity() to
   select the keys.

   The callback must return 0 on success and < 0 on failure (when key
   or cert could not be loaded).
*/
typedef int32_t (*sslIdentityCb_t)(struct ssl *ssl,
                                const sslKeySelectInfo_t *keySpec);



/* Callback function of this type is called from the matrix library to report
   each received TLS Hello Extension for the application */
typedef int32_t (*sslExtCb_t)(struct ssl *ssl, uint16_t extType, uint8_t extLen,
                              void *e);

#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
    Client side APIs
 */


/* Session ID management */
PSPUBLIC int32 matrixSslNewSessionId(sslSessionId_t **sid, void *poolUserPtr);
PSPUBLIC void  matrixSslClearSessionId(sslSessionId_t *sid);
PSPUBLIC void  matrixSslDeleteSessionId(sslSessionId_t *sid);

/* Create new client session into 'ssl'.  'keys' is cryptographic key
   material, and certificates required for TLS client authentication, and TLS
   server authentication. */
PSPUBLIC int32_t matrixSslNewClientSession(ssl_t **ssl,
                                           const sslKeys_t *keys,
                                           sslSessionId_t *sid,
                                           const psCipher16_t cipherSpec[], uint8_t cSpecLen,
                                           sslCertCb_t certCb,
                                           const char *expectedName, tlsExtension_t *extensions,
                                           sslExtCb_t extCb,
                                           sslSessOpts_t *options);
/* Register a callback function called to select the client identity to be
   used for TLS client authentication of a session. If the 'identityCb' has
   been set, the identities provided via 'keys' argument for
   matrixSslNewClientSession are not used. See documentation of
   'sslIdentityCb_t' type for details. The implementation of sslIdentityCb
   shall use function matrixSslSetClientIdentity() to take the keys into
   use.

   @param[in] ssl pointer to the session
   @param[in] identityCb callback function for identity selection
*/
PSPUBLIC void matrixSslRegisterClientIdentityCallback(ssl_t *ssl,
                                                      sslIdentityCb_t identityCb);

/* Use the 'keys' as a key-pair and certificate for the client identity for
   the TLS session. The matrix library will take a reference to the keys, and
   thus the keys need to remain valid until end of the session, and the
   application will need to delete the keys explicitly. See: matrixSslNewKeys,
   matrixSslLoadKeys, matrixSslDeleteKeys.

   This function MUST be called to select the keys. The keys may also be
   updated into original keys given to matrixSslNewClientSession(), but
   regarless, those must be indicated using this function.

   The identity keys set shall only have one key-pair set. If there are
   multiple keys, this function will return false and has no effect. In
   success, the function returns true.

   @param[in] ssl pointer to the session
   @param[in] keys selected for client authentication (may be NULL).
*/
PSPUBLIC psBool_t matrixSslSetClientIdentity(ssl_t *ssl,
                                             const sslKeys_t *keys);

/* Hello extension support.  RFC 3546 */
PSPUBLIC int32  matrixSslNewHelloExtension(tlsExtension_t **extension,
                                           void *poolUserPtr);
PSPUBLIC int32  matrixSslLoadHelloExtension(tlsExtension_t *extension,
                                            unsigned char *extData, uint32 length,
                                            uint32 extType);
PSPUBLIC void   matrixSslDeleteHelloExtension(tlsExtension_t *extension);
PSPUBLIC int32  matrixSslCreateSNIext(psPool_t *pool, unsigned char *host,
                                      int32 hostLen, unsigned char **extOut, int32 *extLen);
PSPUBLIC int32_t matrixSslSessOptsSetClientTlsVersionRange(sslSessOpts_t *options,
        psProtocolVersion_t low,
        psProtocolVersion_t high);
PSPUBLIC int32_t matrixSslSessOptsSetClientTlsVersions(sslSessOpts_t *options,
        const psProtocolVersion_t versions[],
        int32_t versionsLen);

#  ifdef USE_ALPN
PSPUBLIC int32 matrixSslCreateALPNext(psPool_t *pool, int32 protoCount,
                                      unsigned char *proto[], int32 protoLen[],
                                      unsigned char **extOut, int32 *extLen);
#  endif
#  ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
/** Enable external signing for the CertificateVerify message.

    This function is used to turn on the USE_EXT_CERTIFICATE_SIGNING feature
    for a given SSL session struct. After the feature has been turned on,
    MatrixSSL will delegate computation of the CertificateVerify message
    to the caller.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_SUCCESS Operation was successfull.
 */
PSPUBLIC int32_t matrixSslEnableExtCvSignature(ssl_t *ssl);

/** Disable external signing for the CertificateVerify message.

    This function is used to turn off the USE_EXT_CERTIFICATE_SIGNING feature
    for a given SSL session struct. After the feature has been turned off,
    MatrixSSL will again compute the CertificateVerify signature internally.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_SUCCESS Operation was successfull.
 */
PSPUBLIC int32_t matrixSslDisableExtCvSignature(ssl_t *ssl);

/** Check whether an external signature for the CertificateVerify
    message is needed.

    When the SSL state machine is in the pending state
    (matrixSslReceivedData has returned PS_PENDING), this function can
    be used to check whether the pending operation is the signing
    of the handshake_messages hash for the CertificateVerify handshake
    message, using the client's private key.

    If this function returns PS_TRUE, the handshake_messages hash
    should be fetched with matrixSslGetHSMessagesHash, signed with the
    client's private key and copied to MatrixSSL using
    matrixSslSetCvSignature.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_TRUE The SSL state machine is waiting for the CertificateVerify signature.
    @retval ::PS_FALSE The SSL state machine is not in the pending state or the pending operation is not the CertificateVerify signature.
 */
PSPUBLIC int32_t matrixSslNeedCvSignature(ssl_t *ssl);

/** Fetch the handshake_messages hash.

    This function will fetch the hash of all handshake messages seen
    so far until the CertificateVerify message. The signature of this
    hash is to be included in the CertificateVerify.

    This function will return the raw digest; it will not return a DigestInfo structure.

    @param[in] ssl Pointer to the SSL session struct.
    @param[in,out] hash Pointer to a buffer where the handshake_messages hash will be copied.
    @param[in,out] hash_len (In:) length of the hash buffer, (Out:) length of the handshake_messages hash.
    @retval ::PS_SUCCESS The operation was successfull.
    @retval ::PS_OUTPUT_LENGTH The output buffer is too small. The function should be called again with a larger output buffer.
    @retval ::PS_FAILURE The SSL state machine is in incorrect state.
 */
PSPUBLIC int32_t matrixSslGetHSMessagesHash(ssl_t *ssl,
        unsigned char *hash,
        size_t *hash_len);

/** Get the signature algorithm (RSA or ECDSA) to be used for signing the handshake_messages hash.

    This convenience function can be used to query which signature algorithm (RSA or ECDSA)
    should be used for signing the handshake_messages hash. The algorithm type will be the same
    as in the client certificate. Calling this function is not strictly necessary, since the
    client will know the algorithm to use, but is included as a convenience.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_RSA The required signature algorithm is RSA.
    @retval ::PS_ECC The required signature algorithm is ECDSA.
    @retval ::PS_FAILURE The SSL state machine is in incorrect state.
 */
PSPUBLIC int32_t matrixSslGetCvSignatureAlg(ssl_t *ssl);

/*
   Return size of the public key in the client certificate. This can be used
   as an estimate of private key / signature size when using external
   Cv signature generation.

   Note: This function is intentionally undocumented.

   There should be no need to call this, since the client program should know
   the size of the private key it is using. Useful for testing, however.
 */
PSPUBLIC int32_t matrixSslGetPubKeySize(ssl_t *ssl);

/** Assign the signature of the handshake_messages hash to the CertificateVerify message.

    When RSA is used as the signature algorithm, the signature scheme
    to use depends on the TLS protocol version. For TLS 1.2 (RFC
    5246), the RSA signature scheme must be RSASSA-PKCS1-v1_5 (RFC
    3447). For TLS <1.2 (RFC 4346), PKCS #1 RSA Encryption with block
    type 1 encoding must be used. Note that the RSASSA-PKCS1-v1_5
    scheme requires the hash value to be wrapped within a DigestInfo
    structure and the signature is computed over the DigestInfo. To
    determine which TLS version has been negotiated for the current
    handshake, hash length returned by matrixSslGetHSMessagesHash can
    be used: hash length 36 indicates TLS <1.2, other hash lengths
    indicate TLS 1.2.

    When ECDSA is used as the signature algorithm, the signature must
    be computed according to ANS X9.62 / RFC 4492.

    @param[in] ssl Pointer to the SSL session struct.
    @param[in] sig The signature of the handshake_messages hash.
    @param[in] sig_len The length of the signature.

    @retval ::PS_SUCCESS The operation was successfull.
    @retval ::PS_FAILURE The SSL state machine is in incorrect state.
    @retval ::PS_MEM_FAIL Out of memory.
 */
PSPUBLIC int32_t matrixSslSetCvSignature(ssl_t *ssl,
        const unsigned char *sig,
        const size_t sig_len);
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

#ifdef USE_EXT_CLIENT_CERT_KEY_LOADING

/** Returns PS_TRUE when the client program should load a new client cert. */
PSPUBLIC psBool_t matrixSslNeedClientCert(ssl_t *ssl);

/** Returns PS_TRUE when the client program should load a new priv key. */
PSPUBLIC psBool_t matrixSslNeedClientPrivKey(ssl_t *ssl);

/** Returns the certificate/keypair selectors (the server's acceptable
    certificate issuers and key types).

    The function shall only be called in case matrixSslNeedClientCert() has
    returned true.

    There are two alternative methods for selecting the key to use; the
    original way of modifying the 'keys' given as argument to
    matrixSslNewClientSession(), followed by a call to
    matrixSslClientCertUpdated(), or by issuing a call to
    matrixSslSetClientIdentity() with a new key chain to use

    @param[in] ssl pointer to the session
    @retval sslKeySelectInfo_t structure describing the required key.
*/
PSPUBLIC const sslKeySelectInfo_t *matrixSslGetClientKeySelectInfo(ssl_t *ssl);

/** Client program acknowledges the client key change by calling these after
    updating ssl->keys. */
PSPUBLIC psBool_t matrixSslClientCertUpdated(ssl_t *ssl);
PSPUBLIC psBool_t matrixSslClientPrivKeyUpdated(ssl_t *ssl);
#endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */

# endif  /* USE_CLIENT_SIDE_SSL */
/******************************************************************************/

# ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    Server side APIs
 */
PSPUBLIC int32_t matrixSslNewServerSession(ssl_t **ssl,
                                           const sslKeys_t *keys,
                                           sslCertCb_t certCb,
                                           sslSessOpts_t *options);


/* sslPubkeyId_t structure is given as a key selector to pubkeyCB_t type
   function used for selecting the identity key pair for the SSL server. */
typedef struct
{
    unsigned short keyType;
    unsigned short hashAlg;
    unsigned short curveFlags;
    unsigned short dhParamsRequired;
    /* Name of the (virtual)server the peer connected to. The pubkeyCb should
       return a certificate having this name as its subject name CN, or as a
       subjectAltName. */
    char *serverName;
} sslPubkeyId_t;

/* A callback function of type pubkeyCb_t is called from the library on the
   TLS server side to retrieve a keypair to use for server authentication for
   the connection described by 'ssl' using algoritms specified by 'keyId'.

   This callback is not called, if the server side session was created using
   matrixSslNewServerSession() and the server identity keys were already
   provided during that call.

   This callback may be called multiple times with different 'keyId' (key
   types in particular) for each 'ssl' connection. The callback is not called
   for the same session after it has returned non-null value (found usable
   keypair).

   The function shall return a sslKeys_t instance, or a NULL pointer in case
   suitable keys are not found. */
typedef sslKeys_t *(*pubkeyCb_t)(struct ssl *ssl, const sslPubkeyId_t *keyId);

/* A callback function of the pskCb_t is called from the library to retrieve
   shared secret corresponding to the pskId from the application key
   storage. The application returns returns PS_SUCCESS and fills in the key
   into psk, and key length into pskLen if the key corresponding to the given
   pskId is found. If key is not found, a negative error code shall be
   returned resulting into aborted handshake. */
typedef int32_t (*pskCb_t)(struct ssl *ssl,
        const unsigned char pskId[SSL_PSK_MAX_ID_SIZE],
        uint8_t pskIdLen,
        unsigned char *psk[SSL_PSK_MAX_KEY_SIZE],
        uint8_t *pskLen);

PSPUBLIC int32_t matrixSslNewServer(ssl_t **ssl,
                                    pubkeyCb_t pubkeyCb,
                                    pskCb_t pskCb,
                                    sslCertCb_t certCb,
                                    sslSessOpts_t *options);
PSPUBLIC int32 matrixSslSetCipherSuiteEnabledStatus(ssl_t *ssl,
        psCipher16_t cipherId,
        uint32 status);

# ifdef USE_SEC_CONFIG
/** Security operation IDs. */
typedef enum
{
  secop_undefined = 0,
  secop_symmetric_encrypt,
  secop_hmac,
  secop_hash_for_sig,
  secop_rsa_encrypt,
  secop_rsa_decrypt,
  secop_rsa_sign,
  secop_rsa_verify,
  secop_rsa_load_key,
  secop_ecdsa_sign,
  secop_ecdsa_verify,
  secop_ecdsa_load_key,
  secop_dh_import_pub,
  secop_ecdh_import_pub,
  secop_proto_version_check,
  secop_sigalg_check,
  secop_cipher_check
} psSecOperation_t;
/** Security callback.
    This function will be called by MatrixSSL or Matrix Crypto to query
    the permissibility of an operation. */
typedef psRes_t (*securityCb_t)(
        void *ctx, /* Pointer to either ssl_t or crypto_t */
        psSecOperation_t op, /* Crypto/TLS op code, e.g. CRYPTO_OP_RSA_PKCS1_5_SIGN. */
        psSizeL_t nbits, /* Bits to use in the operation (key size or similar.) */
        void *extraData); /* Extra decision-making info; format depends on op. */
/** Set the security callback to use in TLS connections using ssl_t. */
void matrixSslRegisterSecurityCallback(
        ssl_t *ssl,
        securityCb_t cb);
/** Pre-defined security profiles. */
typedef enum
{
    secprofile_default = 0,
    secprofile_wpa3_1_0_enterprise_192 = 1
} psPreDefinedSecProfile_t;
/** Assign one of the pre-defined security profiles to ssl struct. */
PSPUBLIC int32_t matrixSslSetSecurityProfile(
        ssl_t *ssl,
        psPreDefinedSecProfile_t profile);
# endif /* USE_SEC_CONFIG */

PSPUBLIC int32_t matrixSslSessOptsSetServerTlsVersionRange(
        sslSessOpts_t *options,
        psProtocolVersion_t low,
        psProtocolVersion_t high);
PSPUBLIC int32_t matrixSslSessOptsSetServerTlsVersions(
        sslSessOpts_t *options,
        const psProtocolVersion_t versions[],
        int32_t versionsLen);

/* Callback function of this type is called from the matrix library on the
   server side to retrieve server Identity Keys corresponding to the virtual
   hostname received from the TLS ServerNameIndication. The callback shall
   fill into newKeys the key material to use. The provided key material, if
   any, shall be allocated using matrixSslNewKeys(), and the matrix library
   will take care of freeing the keys when they are no longer needed.

   Note, that if both sniCb and pubkeyCb have been set, and sniCb provides key
   material, the pubkeyCb will not be called. */

typedef void (*sniCb_t)(void *ssl,
                        char *hostname, int32 hostnameLen,
                        sslKeys_t **newKeys);


PSPUBLIC void matrixSslRegisterSNICallback(ssl_t *ssl, sniCb_t sni_cb);

#  ifdef USE_ALPN
PSPUBLIC void matrixSslRegisterALPNCallback(ssl_t *ssl,
                                            void (*srv_alpn_cb)(void *ssl, short protoCount,
                                                char *proto[MAX_PROTO_EXT], int32 protoLen[MAX_PROTO_EXT],
                                                int32 *index));
#  endif

#  ifdef USE_STATELESS_SESSION_TICKETS
PSPUBLIC void matrixSslSetSessionTicketCallback(sslKeys_t *keys,
                                                int32 (*ticket_cb)(void *, unsigned char[16], short));
PSPUBLIC int32 matrixSslLoadSessionTicketKeys(sslKeys_t *keys,
                                              const unsigned char name[16], const unsigned char *symkey,
                                              short symkeyLen, const unsigned char *hashkey, short hashkeyLen);
PSPUBLIC int32 matrixSslDeleteSessionTicketKey(sslKeys_t * keys,
                                               unsigned char name[16]);
#  endif
# endif /* USE_SERVER_SIDE_SSL */


/******************************************************************************/
/*
    Advanced feature public APIS
 */
PSPUBLIC void matrixSslGetAnonStatus(ssl_t *ssl, int32 *anonArg);
PSPUBLIC int32_t matrixSslEncodeRehandshake(ssl_t *ssl, sslKeys_t *keys,
                                            sslCertCb_t certCb,
                                            uint32_t sessionOption,
                                            const psCipher16_t cipherSpec[], uint8_t cSpecLen);
PSPUBLIC int32 matrixSslDisableRehandshakes(ssl_t *ssl);
PSPUBLIC int32 matrixSslReEnableRehandshakes(ssl_t *ssl);



# ifdef USE_DTLS
/******************************************************************************/
/*
    DTLS
 */
PSPUBLIC int32  matrixDtlsSentData(ssl_t *ssl, uint32 bytes);
PSPUBLIC int32  matrixDtlsGetOutdata(ssl_t *ssl, unsigned char **buf);
PSPUBLIC int32  matrixDtlsSetPmtu(int32 pmtu);
PSPUBLIC int32  matrixDtlsGetPmtu(void);
# endif /* USE_DTLS */
/******************************************************************************/

# ifdef REQUIRE_DH_PARAMS
/******************************************************************************/
/*
    Diffie-Helloman
 */
PSPUBLIC int32 matrixSslLoadDhParams(sslKeys_t *keys, const char *paramFile);
PSPUBLIC int32 matrixSslLoadDhParamsMem(sslKeys_t *keys,
                                        const unsigned char *dhBin, int32 dhBinLen);
# endif /* REQUIRE_DH_PARAMS */
/******************************************************************************/

# ifdef USE_PSK_CIPHER_SUITE
/******************************************************************************/
/*
    Pre-shared Keys
 */
PSPUBLIC int32_t matrixSslLoadPsk(sslKeys_t *keys,
        const unsigned char key[SSL_PSK_MAX_KEY_SIZE],
        uint8_t keyLen,
        const unsigned char id[SSL_PSK_MAX_ID_SIZE],
        uint8_t idLen);
#  ifdef USE_TLS_1_3
PSPUBLIC int32_t matrixSslLoadTls13Psk(sslKeys_t *keys,
        const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        const psTls13SessionParams_t *params);
#  endif /* USE_TLS_1_3 */
# endif /* USE_PSK_CIPHER_SUITE */
/******************************************************************************/

# ifdef USE_ECC
/******************************************************************************/
/*
    Elliptic Curve Suites
 */
PSPUBLIC int32 matrixSslLoadEcKeys(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile);
PSPUBLIC int32 matrixSslLoadEcKeysExt(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32 matrixSslLoadEcKeysMemExt(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32 matrixSslLoadEcKeysMem(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen);
# ifdef USE_ECC
PSPUBLIC int32_t matrixSslGenEphemeralEcKey(sslKeys_t *keys,
        psEccKey_t *ecc,
        const psEccCurve_t *curve,
        void *hwCtx);
# endif
# endif /* USE_ECC */

/******************************************************************************/

# ifdef USE_MATRIXSSL_STATS

enum
{
    STAT_CH_RECV = 1,        /**< Count of ClientHellos recvd */
    STAT_CH_SENT,            /**< Count of ClientHellos sent */
    STAT_SH_RECV,            /**< Count of ServerHellos recvd */
    STAT_SH_SENT,            /**< Count of ServerHellos sent */
    STAT_ALERT_SENT,         /**< Count of Alerts sent */
    STAT_RESUMPTIONS,        /**< Count of Resumptions */
    STAT_FAILED_RESUMPTIONS, /**< Count of attempted but rejected resumptions */
    STAT_APP_DATA_RECV,      /**< Bytes of encoded appdata received (incl hdr/mac) */
    STAT_APP_DATA_SENT,      /**< Bytes of encoded appdata sent (incl hdr/mac) */
    STAT_PT_DATA_RECV,       /**< Bytes of plaintext appdata received */
};

PSPUBLIC void matrixSslRegisterStatCallback(ssl_t *ssl,
                                            void (*stat_cb)(void *ssl, void *stat_ptr, int32 type, int32 value),
                                            void *stats);

# endif

# ifdef __cplusplus
}
# endif

/******************************************************************************/

/* The internal header still needs to be included for compatibility, as some
   "applications" access internal data types directly. */
# include "matrixssllib.h"

#endif /* _h_MATRIXSSL */

/******************************************************************************/
