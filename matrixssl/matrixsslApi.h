/**
 *      @file    matrixsslApi.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      Implementations interacting with the matrixssl library should
 *      only use the APIs and definitions used in this file.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
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

# include "../core/coreApi.h"     /* cryptoApi.h and matrixsslApi.h depend on this */
# include "../crypto/cryptoApi.h" /* matrixsslApi.h depend on cryptoApi.h. */

# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <matrixsslConfig.h> /* Get matrixssl configuration from -I dir. */
# else
#  include "matrixsslConfig.h" /* Get local matrixssl configuration file. */
# endif
# include "matrixssllib.h"
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
# ifdef USE_RSA
PSPUBLIC int32  matrixSslLoadRsaKeys(sslKeys_t *keys, const char *certFile,
                                     const char *privFile, const char *privPass,
                                     const char *trustedCAFile);

PSPUBLIC int32  matrixSslLoadRsaKeysMem(sslKeys_t *keys,
                                        const unsigned char *certBuf, int32 certLen,
                                        const unsigned char *privBuf, int32 privLen,
                                        const unsigned char *trustedCABuf, int32 trustedCALen);
# endif /* USE_RSA */
PSPUBLIC int32  matrixSslLoadPkcs12(sslKeys_t *keys,
                                    const unsigned char *p12File,
                                    const unsigned char *importPass, int32 ipasslen,
                                    const unsigned char *macPass, int32 mpasslen,
                                    int32 flags);
# if defined(USE_OCSP) && defined(USE_SERVER_SIDE_SSL)
PSPUBLIC int32_t matrixSslLoadOCSPResponse(sslKeys_t *keys,
                                           const unsigned char *OCSPResponseBuf,
                                           psSize_t OCSPResponseBufLen);
# endif
#if defined(USE_SCT) && defined(USE_SERVER_SIDE_SSL)
PSPUBLIC int32_t matrixSslLoadSCTResponse(sslKeys_t *keys,
						const unsigned char *SCTResponseBuf,
						uint16_t SCTResponseBufLen);
#endif
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

/******************************************************************************/
/*
    Advanced feature public APIS
 */
PSPUBLIC void matrixSslGetAnonStatus(ssl_t *ssl, int32 *anonArg);
PSPUBLIC int32_t matrixSslEncodeRehandshake(ssl_t *ssl, sslKeys_t *keys,
                                            int32 (*certCb)(ssl_t *ssl, psX509Cert_t *cert, int32 alert),
                                            uint32_t sessionOption,
                                            const psCipher16_t cipherSpec[], uint8_t cSpecLen);
PSPUBLIC int32 matrixSslDisableRehandshakes(ssl_t *ssl);
PSPUBLIC int32 matrixSslReEnableRehandshakes(ssl_t *ssl);

# ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
    Client side APIs
 */
PSPUBLIC int32 matrixSslNewSessionId(sslSessionId_t **sid, void *poolUserPtr);
PSPUBLIC void matrixSslClearSessionId(sslSessionId_t *sess);
PSPUBLIC void matrixSslDeleteSessionId(sslSessionId_t *sid);
PSPUBLIC int32_t matrixSslNewClientSession(ssl_t **ssl, const sslKeys_t *keys,
                                           sslSessionId_t *sid,
                                           const psCipher16_t cipherSpec[], uint8_t cSpecLen,
                                           sslCertCb_t certCb,
                                           const char *expectedName, tlsExtension_t *extensions,
                                           sslExtCb_t extCb,
                                           sslSessOpts_t *options);
/* Hello extension support.  RFC 3546 */
PSPUBLIC int32  matrixSslNewHelloExtension(tlsExtension_t **extension,
                                           void *poolUserPtr);
PSPUBLIC int32  matrixSslLoadHelloExtension(tlsExtension_t *extension,
                                            unsigned char *extData, uint32 length, uint32 extType);
PSPUBLIC void   matrixSslDeleteHelloExtension(tlsExtension_t *extension);
PSPUBLIC int32  matrixSslCreateSNIext(psPool_t *pool, unsigned char *host,
                                      int32 hostLen, unsigned char **extOut, int32 *extLen);
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
PSPUBLIC int32_t matrixSslGetHSMessagesHash(ssl_t *ssl, unsigned char *hash, size_t *hash_len);

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
PSPUBLIC int32_t matrixSslSetCvSignature(ssl_t *ssl, const unsigned char *sig, const size_t sig_len);
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
# endif  /* USE_CLIENT_SIDE_SSL */
/******************************************************************************/

# ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    Server side APIs
 */
PSPUBLIC int32_t matrixSslNewServerSession(ssl_t **ssl, const sslKeys_t *keys,
                                           sslCertCb_t certCb, sslSessOpts_t *options);
PSPUBLIC int32_t matrixSslNewServer(ssl_t **ssl,
                                    pubkeyCb_t pubkeyCb, pskCb_t pskCb, sslCertCb_t certCb,
                                    sslSessOpts_t *options);
PSPUBLIC int32 matrixSslSetCipherSuiteEnabledStatus(ssl_t *ssl, psCipher16_t cipherId,
                                                    uint32 status);
PSPUBLIC void matrixSslRegisterSNICallback(ssl_t *ssl,
                                           void (*sni_cb)(void *ssl, char *hostname, int32 hostnameLen,
                                               sslKeys_t **newKeys));

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
                                  const unsigned char key[SSL_PSK_MAX_KEY_SIZE], uint8_t keyLen,
                                  const unsigned char id[SSL_PSK_MAX_ID_SIZE], uint8_t idLen);
# endif /* USE_PSK_CIPHER_SUITE */
/******************************************************************************/

# ifdef USE_ECC
/******************************************************************************/
/*
    Elliptic Curve Suites
 */
PSPUBLIC int32 matrixSslLoadEcKeys(sslKeys_t *keys, const char *certFile,
                                   const char *privFile, const char *privPass, const char *CAfile);
PSPUBLIC int32 matrixSslLoadEcKeysMem(sslKeys_t *keys,
                                      const unsigned char *certBuf, int32 certLen,
                                      const unsigned char *privBuf, int32 privLen,
                                      const unsigned char *CAbuf, int32 CAlen);
PSPUBLIC int32_t matrixSslGenEphemeralEcKey(sslKeys_t *keys,
                                            psEccKey_t *ecc, const psEccCurve_t *curve, void *hwCtx);
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
/******************************************************************************/

# ifdef __cplusplus
}
# endif

#endif /* _h_MATRIXSSL */

/******************************************************************************/

