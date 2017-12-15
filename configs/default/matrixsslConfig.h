/**
 *      @file    matrixsslConfig.h
 *      @version $Format:%h%d$
 *
 *      Configuration settings for building the MatrixSSL library.
 *      This configuration is intended to be used in FIPS Mode of operation.
 *      The configuration aims to be compatible with NIST SP 800-52 Rev 1 and
 *      to enable the most commonly used cipher suites.
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

#ifndef _h_MATRIXSSLCONFIG
# define _h_MATRIXSSLCONFIG

#  ifdef __cplusplus
extern "C" {
#  endif

/**
    NIST SP 800-52 Rev 1 Conformance.
    Guidelines for the Selection, Configuration, and Use of Transport Layer
    Security (TLS) Implementations
    The key words "shall", "shall not", "should", "should not" and "may"
    are used as references to the NIST SP 800-52 Rev 1. Algorithms marked as
    "shall" must not be disabled unless NIST SP 800-52 Rev 1 compatibility
    is not relevant.
    @see http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r1.pdf
 */

/******************************************************************************/
/**
    Show which SSL messages are created and parsed
 */
/* #define USE_SSL_HANDSHAKE_MSG_TRACE */

/**
    Informational trace that could help pinpoint problems with SSL connections
 */
/* #define USE_SSL_INFORMATIONAL_TRACE */
/* #define USE_DTLS_DEBUG_TRACE */

/******************************************************************************/
/**
    Recommended cipher suites.
    Define the following to enable various cipher suites
    At least one of these must be defined.  If multiple are defined,
    the handshake negotiation will determine which is best for the connection.
    @note Ephemeral ciphersuites offer perfect forward security (PFS)
    at the cost of a slower TLS handshake.
 */

/** Ephemeral ECC DH keys, ECC DSA certificates */
#   define USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA/**< @security NIST_SHOULD */
#   define USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA/**< @security NIST_MAY */
/* TLS 1.2 ciphers */
#   define USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256/**< @security NIST_SHOULD */
#   define USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384/**< @security NIST_MAY */
#   define USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256/**< @security NIST_SHOULD */
#   define USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384/**< @security NIST_SHOULD */
/** CHACHA20-POLY1305 cipher suites according to RFC 7905. */
/* #define USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */

/** Ephemeral ECC DH keys, RSA certificates */
#   define USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA/**< @security NIST_SHOULD */
#   define USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
/* TLS 1.2 ciphers */
#   define USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256/**< @security NIST_SHOULD */
#   define USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384/**< @security NIST_MAY */
#   define USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256/**< @security NIST_SHOULD */
#   define USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384/**< @security NIST_SHOULD */
/** CHACHA20-POLY1305 cipher suites according to RFC 7905. */
/* #define USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */

/** Ephemeral Diffie-Hellman ciphersuites, with RSA certificates */
/* #define USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
/* #define USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
/* TLS 1.2 ciphers */
/* #define USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
/* #define USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

/** Non-Ephemeral RSA keys/certificates */
#   define USE_TLS_RSA_WITH_AES_128_CBC_SHA/**< @security NIST_SHALL */
#   define USE_TLS_RSA_WITH_AES_256_CBC_SHA/**< @security NIST_SHOULD */
/* TLS 1.2 ciphers */
#   define USE_TLS_RSA_WITH_AES_128_CBC_SHA256/**< @security NIST_MAY */
#   define USE_TLS_RSA_WITH_AES_256_CBC_SHA256/**< @security NIST_MAY */
#   define USE_TLS_RSA_WITH_AES_128_GCM_SHA256/**< @security NIST_SHALL */
#   define USE_TLS_RSA_WITH_AES_256_GCM_SHA384/**< @security NIST_SHOULD */

/******************************************************************************/
/**
    These cipher suites are secure, but not widely deployed.
 */

/** Ephemeral Diffie-Hellman ciphersuites, with RSA certificates */
/* #define USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA */

/** Ephemeral Diffie-Hellman ciphersuites, with PSK authentication */
/* #define USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA  *//**< @security NIST_SHOULD_NOT */
/* #define USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA  *//**< @security NIST_SHOULD_NOT */

/** Ephemeral ECC DH keys, RSA certificates */
/* #define USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA  *//**< @security NIST_SHOULD */

/** Pre-Shared Key Ciphers.
    NIST SP 800-52 Rev 1 recommends against using PSK unless neccessary
    See NIST SP 800-52 Rev 1 Appendix C */
#   define USE_TLS_PSK_WITH_AES_128_CBC_SHA/**< @security NIST_SHOULD_NOT */
#   define USE_TLS_PSK_WITH_AES_256_CBC_SHA/**< @security NIST_SHOULD_NOT */
/* TLS 1.2 ciphers */
#   define USE_TLS_PSK_WITH_AES_128_CBC_SHA256/**< @security NIST_SHOULD_NOT */
#   define USE_TLS_PSK_WITH_AES_256_CBC_SHA384/**< @security NIST_SHOULD_NOT */

/** Non-Ephemeral ECC DH keys, ECC DSA certificates */
#   define USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA/**< @security NIST_MAY */
#   define USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA/**< @security NIST_MAY */
/* TLS 1.2 ciphers */
#   define USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256/**< @security NIST_MAY */
#   define USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384/**< @security NIST_MAY */
#   define USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256/**< @security NIST_MAY */
#   define USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384/**< @security NIST_MAY */

/** Non-Ephemeral ECC DH keys, RSA certificates */
#   define USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
#   define USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
/* TLS 1.2 ciphers */
#   define USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
#   define USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
#   define USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
#   define USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384

/** Non-Ephemeral RSA keys/certificates */
/* #define USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA  *//**< @security NIST_SHALL */

/** @note Some of (non-mandatory) cipher suites mentioned in NIST SP 800-52
    Rev 1 are not supported by the MatrixSSL / MatrixDTLS.
    ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (NIST SP 800-52 Rev 1 "should")
    is rarely used cipher suite and is not supported.
    Also (NIST SP 800-52 Rev 1 "may") TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_DSS_WITH_* and TLS_RSA_WITH_AES_*_CCM cipher suites cannot be
    enabled as they are not supported. */

/******************************************************************************/
/**
    Ephemeral key cache support.
    If not using cache, new key exchange keys are created for each TLS session.
    If using cache, keys are generated initially, and re-used in each
    subsequent TLS connection within a given time frame and usage count.
    @see ECC_EPHEMERAL_CACHE_SECONDS and ECC_EPHEMERAL_CACHE_USAGE

    @security Do not cache Ephemeral ECC keys as it is against some standards,
    including NIST SP 800-56A, when in FIPS 140-2 mode of operation.
 */
/* #define NO_ECC_EPHEMERAL_CACHE  *//**< @security NIST_SHALL */

/******************************************************************************/
/**
    Configure Support for TLS protocol versions.
    Define one of:
        USE_TLS_1_2_AND_ABOVE
        USE_TLS_1_1_AND_ABOVE
        USE_TLS_1_0_AND_ABOVE
    @note There is no option for enabling SSL3.0 at this level
 */
#   define USE_TLS_1_1_AND_ABOVE/**< @security default 1_1_AND_ABOVE */
/* #define USE_TLS_1_2_AND_ABOVE  *//**< @security better than 1_1_AND_ABOVE if no backwards compatiblity concerns */
/* #define USE_TLS_1_0_AND_ABOVE  *//**< @security no longer recommended. */

/******************************************************************************/
/**
    Datagram TLS support.
    Enables DTLS in addition to TLS.
    @pre TLS_1_1
 */
#   define USE_DTLS

/******************************************************************************/
/**
    Compile time support for server or client side SSL
 */
#   define USE_CLIENT_SIDE_SSL
#   define USE_SERVER_SIDE_SSL

/******************************************************************************/
/**
    Allow the server to parse SSL 2.0 ClientHello messages even when the
    server does not actually support SSL 2.0. As per RFC 5246, E.2:

    "... even TLS servers that do not support SSL 2.0 MAY accept version
    2.0 CLIENT-HELLO messages."

    This option is for compatibility with clients that support
    SSL 2.0 but are ready to negotiate a higher version such as TLS 1.0.
    Note that enabling this option will only allow parsing of the SSL 2.0
    ClientHellos; it will not enable support for the SSL 2.0 protocol.
    Only 32-byte challenges in the SSL 2.0 ClientHello are supported.
*/
#   ifdef USE_SERVER_SIDE_SSL
/* #define ALLOW_SSLV2_CLIENT_HELLO_PARSE */
#   endif

/******************************************************************************/
/**
    Client certificate authentication
 */
#   define USE_CLIENT_AUTH

#   ifdef USE_CLIENT_AUTH
/**
    Enable the handshake_messages signature in the CertificateVerify
    protocol message to be signed using an external module.
 */
/* #define USE_EXT_CERTIFICATE_VERIFY_SIGNING */
#    ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
/**
    Compile an example external module that allows the
    USE_EXT_CERTIFICATE_VERIFY_SIGNING feature to be tested using the example
    client program and sslTest.
 */
/* #define USE_EXT_EXAMPLE_MODULE */
#    endif

/**
   Enable loading of a new client certificate and private key
   in response to a CertificateRequest message from a server. This feature
   allows the client program to e.g. select a client certificate
   whose issuer is included in the server's list of trusted CAs
   that was received in the CertificateRequest message.
*/
/* #define USE_EXT_CLIENT_CERT_KEY_LOADING */
#   endif /* USE_CLIENT_AUTH */

/**
    Enable if the server should send an empty CertificateRequest message if
    no CA files have been loaded
 */
/* #define SERVER_CAN_SEND_EMPTY_CERT_REQUEST */

/**
    Enabling this define will allow the server to "downgrade" a client auth
    handshake to a standard handshake if the client replies to a
    CERTIFICATE_REQUEST with an empty CERTIFICATE message.  The user callback
    will be called with a NULL cert in this case and the user can determine if
    the handshake should continue in a non-client auth state.
 */
/* #define SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG */

/******************************************************************************/
/**
    Allow partial parsing of CA certificate bundles. By default, loading of
    CA files via matrixSslLoadRsaKeys, etc. will fail if the bundle contains
    a certificate not supported by MatrixSSL's current configuration. When
    this define is enabled, the parsing of some CA certificates is allowed fail.
    When parsing of a CA cert fails, a dummy psX509Cert_t with will be added
    to the CAcerts list. Consult the parseStatus members for details on why
    the parsing of a specific certificate failed.
 */
/* #define ALLOW_CA_BUNDLE_PARTIAL_PARSE */

/******************************************************************************/
/**
    Enable the Application Layer Protocol Negotiation extension.
    Servers and Clients will still have to use the required public API to
    set protocols and register application callbacks to negotiate the
    protocol that will be tunneled over TLS.
    @see ALPN section in the developer's guide for information.
 */
/* #define USE_ALPN */

/******************************************************************************/
/**
    Enable the Trusted CA Indication CLIENT_HELLO extension.  Will send the
    sha1 hash of each CA file to the server for help in server selection.
    This extra level of define is to help isolate the SHA1 requirement
 */
/* #define USE_TRUSTED_CA_INDICATION  *//**< @security NIST_SHOULD */

/******************************************************************************/
/**
    A client side configuration that requires a server to provide an OCSP
    response if the client uses the certitificate status request extension.
    The "must staple" terminology is typically associated with certificates
    at the X.509 layer but it is a good description of what is being required
    of the server at the TLS level.
    @pre USE_OCSP_RESPONSE must be enabled at the crypto level and the client
    application must use the OCSPstapling session option at run time for this
    setting to have any effect
 */
#   ifdef USE_OCSP_RESPONSE
#    define USE_OCSP_MUST_STAPLE /**< @security NIST_SHALL */
#   endif

/******************************************************************************/
/**
    Rehandshaking support.

    Enabling USE_REHANDSHAKING will allow secure-rehandshakes using the
    protocol defined in RFC 5748 which fixed a critical exploit in
    the standard TLS specification.

    @security Looking towards TLS 1.3, which removes re-handshaking, this
    feature is disabled by default.
 */
/* #define USE_REHANDSHAKING */

/******************************************************************************//**
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
#   define USE_SERVER_SIDE_FALSE_START_SUPPORT

/******************************************************************************/
/**
    If SERVER you may define the number of sessions to cache and how
    long a session will remain valid in the cache from first access.
    Session caching enables very fast "session resumption handshakes".

    SSL_SESSION_TABLE_SIZE minimum value is 1
    SSL_SESSION_ENTRY_LIFE is in milliseconds, minimum 0

    @note Session caching can be disabled by setting SSL_SESSION_ENTRY_LIFE to 0
    however, this will also immediately expire SESSION_TICKETS below.
 */
#   ifdef USE_SERVER_SIDE_SSL
#    define SSL_SESSION_TABLE_SIZE 32
#    define SSL_SESSION_ENTRY_LIFE (86400 * 1000)/* one day, in milliseconds */
#   endif

/******************************************************************************/
/**
    Use RFC 5077 session resumption mechanism. The SSL_SESSION_ENTRY_LIFE
    define applies to this method as well as the standard method. The
    SSL_SESSION_TICKET_LIST_LEN is the max size of the server key list.
 */
#   define USE_STATELESS_SESSION_TICKETS
#   define SSL_SESSION_TICKET_LIST_LEN 32

/******************************************************************************/
/**
    The initial buffer sizes for send and receive buffers in each ssl_t session.
    Buffers are internally grown if more incoming or outgoing data storage is
    needed, up to a maximum of SSL_MAX_BUF_SIZE. Once the memory used by the
    buffer again drops below SSL_DEFAULT_X_BUF_SIZE, the buffer will be reduced
    to this size. Most standard SSL handshakes require on the order of 1024 B.

    SSL_DEFAULT_x_BUF_SIZE      value in bytes, maximum SSL_MAX_BUF_SIZE
 */
#   ifndef USE_DTLS
#     define SSL_DEFAULT_IN_BUF_SIZE     1500        /* Base recv buf size, bytes */
#     define SSL_DEFAULT_OUT_BUF_SIZE    1500        /* Base send buf size, bytes */
#   else
/******************************************************************************/
/**
    The Path Maximum Transmission Unit is the largest datagram that can be
    sent or recieved.  It is beyond the scope of DTLS to negotiate this value
    so make sure both sides have agreed on this value.  This is an enforced
    limitation in MatrixDTLS so connections will not succeed if a peer has a
    PTMU set larger than this value.
 */
#    define DTLS_PMTU  1500                       /* 1500 Default/Maximum datagram len */
#    define SSL_DEFAULT_IN_BUF_SIZE     DTLS_PMTU /* See PMTU comments above */
#    define SSL_DEFAULT_OUT_BUF_SIZE    DTLS_PMTU /* See PMTU comments above */

/* #define DTLS_SEND_RECORDS_INDIVIDUALLY  *//* Max one record per datagram */
#   endif

#  ifdef __cplusplus
}
#  endif

#endif  /* _h_MATRIXCONFIG */
/******************************************************************************/

