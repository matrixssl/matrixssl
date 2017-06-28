/**
 *      @file    client.c
 *      @version $Format:%h%d$
 *
 *      Simple MatrixSSL blocking client example.
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

#include <stddef.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "app.h"
#ifndef WIN32
# include <unistd.h>
#else
# include "XGetopt.h"
#endif
#include "matrixssl/matrixsslApi.h"
/* Currently this example uses _psTrace for tracing, so osdep.h is needed: */
#include "core/osdep.h"
#include "core/psUtil.h"

#ifdef USE_CLIENT_SIDE_SSL

# ifndef MATRIX_TESTING_ENVIRONMENT /* Omit the message when testing. */
#  ifdef WIN32
#   pragma message("DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS.")
#  else
#   warning "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#  endif
# endif

/*
    If supporting client authentication, pick ONE identity to auto select a
    certificate and private key that support desired algorithms.
 */
/* #define ID_RSA */ /* RSA Certificate and Key */
/* #define ID_ECDH_ECDSA */ /* EC Certificate and Key */
/* #define ID_ECDH_RSA */ /* EC Key with RSA signed certificate */

# if !defined(ID_RSA) && !defined(ID_ECDH_ECDSA) && !defined(ID_ECDH_RSA)
/* Choose a default identity based on which algorithms are supported. */
#  ifdef USE_RSA_CIPHER_SUITE
#   define ID_RSA
#  else
#   ifdef USE_ECC_CIPHER_SUITE
#    define ID_ECDH_ECDSA
#   else
#    ifndef USE_PSK_CIPHER_SUITE
#     error "Please enable either RSA or ECC for client when not using PSK"
#    endif /* !USE_PSK_CIPHER_SUITE */
#   endif  /* USE_ECC_CIPHER_SUITE */
#  endif   /* USE_RSA_CIPHER_SUITE */
# endif    /* !ID_RSA && !ID_ECDH_ECDSA && !ID_ECDH_RSA */

# define USE_HEADER_KEYS
# define ALLOW_ANON_CONNECTIONS  0
# define CRL_MAX_LENGTH 1048576 /* Maximum length for CRL: 1 megabyte. */

/*      If the algorithm type is supported, load a CA for it */
# ifdef USE_ECC_CIPHER_SUITE

/*
  If ALLOW_CA_BUNDLE_PARTIAL_PARSE is defined, we can simply try to load
  all EC CA certs, even if we are not able to parse all of them.
*/
# ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS.pem";
#   endif /* USE_HEADER_KEYS */
# else /* !(ALLOW_CA_BUNDLE_PARTIAL_PARSE) */
/*
  If ALLOW_CA_BUNDLE_PARTIAL_PARSE is not defined, we need the following,
  ugly code to load only those CA bundles, where each cert is supported
  by the present configuration.
*/
#  if defined(USE_SECP192R1) && defined(USE_SECP224R1) && defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* USE_SECP192R1 && USE_SECP224R1 && USE_SECP521R1 */

#  if !defined(USE_SECP192R1) && defined(USE_SECP224R1) && defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS_EXCEPT_P192.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* !USE_SECP192R1 && USE_SECP224R1 && USE_SECP521R1 */

#  if defined(USE_SECP192R1) && !defined(USE_SECP224R1) && defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P224.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS_EXCEPT_P224.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* USE_SECP192R1 && !USE_SECP224R1 && USE_SECP521R1 */

#  if defined(USE_SECP192R1) && defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P521.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS_EXCEPT_P521.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#  if !defined(USE_SECP192R1) && !defined(USE_SECP224R1) && defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192_AND_P224.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS_EXCEPT_P192_AND_P224.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* !USE_SECP192R1 && !USE_SECP224R1 && USE_SECP521R1 */

#  if !defined(USE_SECP192R1) && defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192_AND_P521.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS_EXCEPT_P192_AND_P521.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* !USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#  if defined(USE_SECP192R1) && !defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P224_AND_P521.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS_EXCEPT_P224_AND_P521.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#  if !defined(USE_SECP192R1) && !defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192_P224_AND_P521.h"
#   else
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS_EXCEPT_P192_P224_AND_P521.pem";
#   endif /* USE_HEADER_KEYS */
#  endif  /* !USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */

#  ifndef USE_HEADER_KEYS
/*
   Pointer to filename. We shall increment this when we need to
   skip over the ../../ prefix.
 */
static char *pEcCAFile = ecCAFile;
#  endif /* !USE_HEADER_KEYS */

# endif  /* USE_ECC_CIPHER_SUITE */

# ifdef USE_HEADER_KEYS
/* CAs */
#  ifdef USE_RSA_CIPHER_SUITE
#   include "testkeys/RSA/ALL_RSA_CAS.h"
#   ifdef USE_ECC_CIPHER_SUITE
#    include "testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.h"
#   endif
#  endif

/* Identity Certs and Keys for use with Client Authentication */
#  ifdef ID_RSA
#   define EXAMPLE_RSA_KEYS
#   include "testkeys/RSA/1024_RSA.h"
#   include "testkeys/RSA/1024_RSA_KEY.h"
#   include "testkeys/RSA/2048_RSA.h"
#   include "testkeys/RSA/2048_RSA_KEY.h"
#   include "testkeys/RSA/3072_RSA.h"
#   include "testkeys/RSA/3072_RSA_KEY.h"
#   include "testkeys/RSA/4096_RSA.h"
#   include "testkeys/RSA/4096_RSA_KEY.h"
#  endif

#  ifdef ID_ECDH_ECDSA
#   define EXAMPLE_EC_KEYS
#   include "testkeys/EC/384_EC.h"
#   include "testkeys/EC/384_EC_KEY.h"
#  endif

#  ifdef ID_ECDH_RSA
#   define EXAMPLE_ECDH_RSA_KEYS
#   include "testkeys/ECDH_RSA/521_ECDH-RSA.h"
#   include "testkeys/ECDH_RSA/521_ECDH-RSA_KEY.h"
#  endif

/* File-based keys */
# else /* USE_HEADER_KEYS */
/* CAs */
#  ifdef USE_RSA_CIPHER_SUITE
static char rsaCAFile[] = "../../testkeys/RSA/ALL_RSA_CAS.pem";
static char *pRsaCAFile = rsaCAFile;
#   ifdef USE_ECC_CIPHER_SUITE
static char ecdhRsaCAFile[] = "../../testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.pem";
static char *pEcdhRsaCAFile = ecdhRsaCAFile;
#   endif
#  endif

/* Identity Certs and Keys for use with Client Authentication */
#  ifdef ID_RSA
#   define EXAMPLE_RSA_KEYS
static char rsaCertFile[] = "../../testkeys/RSA/2048_RSA.pem";
static char rsaPrivkeyFile[] = "../../testkeys/RSA/2048_RSA_KEY.pem";
static char *pRsaCertFile = rsaCertFile;
static char *pRsaPrivkeyFile = rsaPrivkeyFile;
#  endif

#  ifdef ID_ECDH_ECDSA
#   define EXAMPLE_EC_KEYS
static char ecCertFile[] = "../../testkeys/EC/384_EC.pem";
static char ecPrivkeyFile[] = "../../testkeys/EC/384_EC_KEY.pem";
static char *pEcCertFile = ecCertFile;
static char *pEcPrivkeyFile = ecPrivkeyFile;
#  endif

#  ifdef ID_ECDH_RSA
#   define EXAMPLE_ECDH_RSA_KEYS
static char ecdhRsaCertFile[] = "../../testkeys/ECDH_RSA/521_ECDH-RSA.pem";
static char ecdhRsaPrivkeyFile[] = "../../testkeys/ECDH_RSA/521_ECDH-RSA_KEY.pem";
static char *pEcdhRsaCertFile = ecdhRsaCertFile;
static char *pEcdhRsaPrivkeyFile = ecdhRsaPrivkeyFile;
#  endif

/* #define REHANDSHAKE_TEST */
#  ifdef REHANDSHAKE_TEST
static int g_rehandshakeFlag = 0;
#  endif

static char *g_ca_file;
# endif /* USE_HEADER_KEYS */

/*
   No file-based keys for PSK.
   Include psk.h even when USE_HEADER_KEYS is not defined.
 */
# ifdef USE_PSK_CIPHER_SUITE
/* Defines PSK_HEADER_TABLE and PSK_HEADER_TABLE_COUNT */
#  include "../../testkeys/PSK/psk.h"
# endif

/********************************** Globals ***********************************/
static unsigned char g_httpRequestHdr[] = "GET %s HTTP/1.0\r\n"
                                          "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
                                          "Accept: */*\r\n"
                                          "Content-Length: 0\r\n"
                                          "\r\n";

static const char g_strver[][8] =
{ "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2" };

static unsigned char g_matrixShutdownServer[] = "MATRIX_SHUTDOWN";

extern int opterr;
static char g_ip[16];
static char g_path[256];
static int g_port, g_new, g_resumed, g_ciphers, g_version, g_closeServer;
static int g_key_len, g_disableCertNameChk;
static int g_max_verify_depth;
static uint16_t g_cipher[16];
static int g_trace;
static int g_keepalive;

static uint32_t g_bytes_requested;
static uint8_t g_send_closure_alert;

struct g_sslstats
{
    int rbytes;         /* Bytes read */
    int64 hstime;
    int64 datatime;
};

# ifndef USE_HEADER_KEYS
/*
   Are we in MatrixSSL root dir? If yes, we shall to skip
   the "../.." prefix in the key and cert filenames.
 */
static int g_at_matrixssl_root = 0;
# endif /* USE_HEADER_KEYS */

static int g_enable_ext_cv_sig_op = 0;

/********************************** Defines ***********************************/

/****************************** Local Functions *******************************/

static int32 httpWriteRequest(ssl_t *ssl);
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
static SOCKET lsocketConnect(char *ip, int32 port, int32 *err);
static void closeConn(ssl_t *ssl, SOCKET fd);
static int32_t extensionCb(ssl_t *ssl,
                           uint16_t extType, uint8_t extLen, void *e);

# ifdef USE_CRL
static int32 fetchCRL(psPool_t *pool, char *url, uint32_t urlLen,
                      unsigned char **crlBuf, uint32_t *crlBufLen);
static int32_t fetchParseAndAuthCRLfromCert(psPool_t *pool, psX509Cert_t *cert,
                                            psX509Cert_t *potentialIssuers);

/* Enable the example on how to fetch CRLs mid-handshake.  If disabled, the
    example will show how to halt the handshake to go out and fetch and retry
    the connection (command line option -n must be specified for multiple
    connection attempts) */
/* #define MIDHANDSHAKE_CRL_FETCH */

#  ifndef MIDHANDSHAKE_CRL_FETCH
/* In the example where we stop the handhsake to go fetch the CRL files, we
    need storage to hold the CRL URL distribution points since those are
    coming from the server cert chain which we do not keep around */
#   define CRL_MAX_SERVER_CERT_CHAIN 3
#   define CRL_MAX_URL_LEN     256
static unsigned char g_crlDistURLs[CRL_MAX_SERVER_CERT_CHAIN][CRL_MAX_URL_LEN];

static int32_t fetchParseAndAuthCRLfromUrl(psPool_t *pool, unsigned char *url,
                                           uint32_t urlLen, psX509Cert_t *potentialIssuers);
static void fetchSavedCRL(psX509Cert_t *potentialIssuers);
#  endif
# endif /* USE_CRL */

# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

/******************************************************************************/
/*
    Make a secure HTTP request to a defined IP and port
    Connection is made in blocking socket mode
    The connection is considered successful if the SSL/TLS session is
    negotiated successfully, a request is sent, and a HTTP response is received.
 */

static int g_alreadyopen = 0;

static int32 httpsClientConnection(sslKeys_t *keys, sslSessionId_t *sid,
    struct g_sslstats *stats)
{
    tlsExtension_t *extension;
    int32 rc, transferred, len, sessionFlag, extLen;
    ssl_t *ssl;
    unsigned char *buf, *ext;
    httpConn_t cp;
    SOCKET fd;
    psTime_t t1, t2;
    sslSessOpts_t options;

# ifdef USE_ALPN
    unsigned char *alpn[MAX_PROTO_EXT];
    int32 alpnLen[MAX_PROTO_EXT];
# endif

    memset(&cp, 0x0, sizeof(httpConn_t));
    if (g_alreadyopen == 0)
    {
        fd = lsocketConnect(g_ip, g_port, &rc);
        if (g_keepalive == 1)
        {
            g_alreadyopen = fd;
        }
    }
    else
    {
        fd = g_alreadyopen;
        rc = PS_SUCCESS;
    }
    if (fd == INVALID_SOCKET || rc != PS_SUCCESS)
    {
        return PS_PLATFORM_FAIL;
    }

# ifdef SSL_FLAGS_SSLV3
    /* Corresponds to version 3.g_version */
    switch (g_version)
    {
    case 0:
        sessionFlag = SSL_FLAGS_SSLV3;
        break;
    case 1:
        sessionFlag = SSL_FLAGS_TLS_1_0;
        break;
    case 2:
        sessionFlag = SSL_FLAGS_TLS_1_1;
        break;
    case 3:
        sessionFlag = SSL_FLAGS_TLS_1_2;
        break;
    default:
        sessionFlag = SSL_FLAGS_TLS_1_0;
        break;
    }
# else
    /* MatrixSSL <= 3.4.2 don't support setting version on request */
    sessionFlag = 0;
# endif

    memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = sessionFlag;
    options.userPtr = keys;
    /* options.maxFragLen = 512; */
    /* options.truncHmac = PS_TRUE; */
    /* options.ticketResumption = PS_TRUE; */
    /* options.ecFlags |= SSL_OPT_SECP521R1; */
    /* options.ecFlags |= SSL_OPT_SECP384R1; */
    /* options.ecFlags |= SSL_OPT_SECP256R1; */
    /* options.ecFlags |= SSL_OPT_SECP224R1; */
    /* options.ecFlags |= SSL_OPT_SECP192R1; */
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
# ifdef TEST_KEEP_PEER_CERTS
    options.keep_peer_certs = 1;
    options.keep_peer_cert_der = 1;
# endif
    if (g_max_verify_depth != 0)
        options.validateCertsOpts.max_verify_depth = g_max_verify_depth;

    /*
      Do not allow the server to pick different version than what
      we select here. Break the connection attempt with a protocol_version
      alert if ServerHello.server_version < ClientHello.client_version.
    */
    options.clientRejectVersionDowngrade = 1;

    matrixSslNewHelloExtension(&extension, NULL);
    matrixSslCreateSNIext(NULL, (unsigned char *) g_ip, (uint32) strlen(g_ip),
        &ext, &extLen);
    matrixSslLoadHelloExtension(extension, ext, extLen, EXT_SNI);
    psFree(ext, NULL);

# ifdef USE_ALPN
    /* Application Layer Protocol Negotiation */
    alpn[0] = psMalloc(NULL, strlen("http/1.0"));
    memcpy(alpn[0], "http/1.0", strlen("http/1.0"));
    alpnLen[0] = strlen("http/1.0");

    alpn[1] = psMalloc(NULL, strlen("http/1.1"));
    memcpy(alpn[1], "http/1.1", strlen("http/1.1"));
    alpnLen[1] = strlen("http/1.1");

    matrixSslCreateALPNext(NULL, 2, alpn, alpnLen, &ext, &extLen);
    matrixSslLoadHelloExtension(extension, ext, extLen, EXT_ALPN);
    psFree(alpn[0], NULL);
    psFree(alpn[1], NULL);
# endif

    /* We are passing the IP address of the server as the expected name */
    /* To skip certificate subject name tests, pass NULL instead of g_ip */
    if (g_disableCertNameChk == 0)
    {
        rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
            certCb, g_ip, extension, extensionCb, &options);


    }
    else
    {
        rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
            certCb, NULL, extension, extensionCb, &options);
    }

    matrixSslDeleteHelloExtension(extension);
    if (rc != MATRIXSSL_REQUEST_SEND)
    {
        _psTraceInt("New Client Session Failed: %d.  Exiting\n", rc);
        close(fd);
        return PS_ARG_FAIL;
    }
WRITE_MORE:
    while ((len = matrixSslGetOutdata(ssl, &buf)) > 0)
    {
        if (g_trace)
        {
            psTraceBytes("SEND", buf, len);
        }
        transferred = send(fd, buf, len, 0);
        if (transferred <= 0)
        {
            printf("Error sending\n");
            goto L_CLOSE_ERR;
        }
        else
        {
            /* Indicate that we've written > 0 bytes of data */
            if ((rc = matrixSslSentData(ssl, transferred)) < 0)
            {
                goto L_CLOSE_ERR;
            }
            if (rc == MATRIXSSL_REQUEST_CLOSE)
            {
                closeConn(ssl, fd);
                return MATRIXSSL_SUCCESS;
            }
            if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
            {
                /* If we sent the Finished SSL message, initiate the HTTP req */
                /* (This occurs on a resumption handshake) */
                if ((rc = httpWriteRequest(ssl)) < 0)
                {
                    goto L_CLOSE_ERR;
                }
                if (rc == MATRIXSSL_REQUEST_SEND)
                {
                    /* We have a HTTP request to send */
                    goto WRITE_MORE;
                }
                closeConn(ssl, fd);
                return MATRIXSSL_SUCCESS;
            }
            /* MATRIXSSL_REQUEST_SEND is handled by loop logic */
        }
    }

READ_MORE:
    if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0)
    {
        goto L_CLOSE_ERR;
    }
    if ((transferred = recv(fd, buf, len, 0)) < 0)
    {
        goto L_CLOSE_ERR;
    }
    if (g_trace)
    {
        psTraceBytes("RECV", buf, transferred);
    }
    /*  If EOF, remote socket closed. But we haven't received the HTTP response
        so we consider it an error in the case of an HTTP client */
    if (transferred == 0)
    {
        goto L_CLOSE_ERR;
    }
    psGetTime(&t1, NULL);
    if ((rc = matrixSslReceivedData(ssl, (int32) transferred, &buf,
             (uint32 *) &len)) < 0)
    {
        psGetTime(&t2, NULL);
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
        if (ssl->hsState == SSL_HS_DONE)
        {
# ifdef USE_HIGHRES_TIME
            stats->datatime += psDiffUsecs(t1, t2);
# else
            stats->datatime += psDiffMsecs(t1, t2, NULL);
# endif
        }
        else
        {
# ifdef USE_HIGHRES_TIME
            stats->hstime += psDiffUsecs(t1, t2);
# else
            stats->hstime += psDiffMsecs(t1, t2, NULL);
# endif
        }
        goto L_CLOSE_ERR;
    }
    psGetTime(&t2, NULL);
    if (ssl->hsState == SSL_HS_DONE)
    {
# ifdef USE_HIGHRES_TIME
        stats->datatime += psDiffUsecs(t1, t2);
# else
        stats->datatime += psDiffMsecs(t1, t2, NULL);
# endif
    }
    else
    {
# ifdef USE_HIGHRES_TIME
        stats->hstime += psDiffUsecs(t1, t2);
# else
        stats->hstime += psDiffMsecs(t1, t2, NULL);
# endif
    }

PROCESS_MORE:
    switch (rc)
    {
    case MATRIXSSL_HANDSHAKE_COMPLETE:
# ifdef REHANDSHAKE_TEST
/*
            Test rehandshake capabilities of server.  A full re-handshake
            is first tested.  After that, a session resmption rehandshake
            is attempted. In that case, this client will be last to
            send handshake data and MATRIXSSL_HANDSHAKE_COMPLETE will hit on
            the WRITE_MORE handler and httpWriteRequest will occur there.

            NOTE: If the server doesn't support session resumption it is
            possible to fall into an endless rehandshake loop
 */
        if (g_rehandshakeFlag == 0)
        {
            /* Full rehandshake */
            if (matrixSslEncodeRehandshake(ssl, NULL, NULL,
                    SSL_OPTION_FULL_HANDSHAKE, g_cipher, g_ciphers) < 0)
            {
                goto L_CLOSE_ERR;
            }
            g_rehandshakeFlag = 1;
        }
        else if (g_rehandshakeFlag == 1)
        {
            /* Resumed rehandshake */
            if (matrixSslEncodeRehandshake(ssl, NULL, NULL, 0,
                    g_cipher, g_ciphers) < 0)
            {
                goto L_CLOSE_ERR;
            }
            g_rehandshakeFlag = 2;
        }
        else
        {
            if ((rc = httpWriteRequest(ssl)) < 0)
            {
                goto L_CLOSE_ERR;
            }
            if (rc != MATRIXSSL_REQUEST_SEND)
            {
                closeConn(ssl, fd);
                return MATRIXSSL_SUCCESS;
            }
        }
        goto WRITE_MORE;
# else
        /* We got the Finished SSL message, initiate the HTTP req */
        if ((rc = httpWriteRequest(ssl)) < 0)
        {
            goto L_CLOSE_ERR;
        }
        if (rc == MATRIXSSL_REQUEST_SEND)
        {
            /* We have a HTTP request to send */
            goto WRITE_MORE;
        }
#  ifdef TEST_KEEP_PEER_CERTS
        if (ssl->sec.cert == NULL)
        {
            printf("Error: peer cert not kept\n");
            return MATRIXSSL_ERROR;
        }
        else
        {
            printf("OK: peer cert still available\n");
        }
        if (ssl->sec.cert->unparsedBin == NULL ||
            ssl->sec.cert->binLen <= 0)
        {
            printf("Error: peer cert DER not kept\n");
            return MATRIXSSL_ERROR;
        }
        else
        {
            printf("OK: peer cert DER still available\n");
        }
#  endif
        closeConn(ssl, fd);
        return MATRIXSSL_SUCCESS;
# endif
    case MATRIXSSL_APP_DATA:
    case MATRIXSSL_APP_DATA_COMPRESSED:
        if (g_trace)
        {
            psTraceBytes("Decrypted app data", buf, len);
        }
        if (cp.flags != HTTPS_COMPLETE)
        {
            rc = httpBasicParse(&cp, buf, len, g_trace);
            if (rc < 0)
            {
                closeConn(ssl, fd);
                if (cp.parsebuf)
                {
                    free(cp.parsebuf);
                }
                cp.parsebuf = NULL;
                cp.parsebuflen = 0;
                return MATRIXSSL_ERROR;
            }
            if (rc == HTTPS_COMPLETE)
            {
                cp.flags = HTTPS_COMPLETE;
            }
        }
        cp.bytes_received += len;
        stats->rbytes += len;
        if (g_trace)
        {
            psTraceBytes("HTTP DATA", buf, len);
        }
        rc = matrixSslProcessedData(ssl, &buf, (uint32 *) &len);
        if (rc < 0)
        {
            goto L_CLOSE_ERR;
        }
        if (g_bytes_requested > 0)
        {
            if (cp.bytes_received >= g_bytes_requested)
            {
                /* We've received all that was requested, so close */
                closeConn(ssl, fd);
                if (cp.parsebuf)
                {
                    free(cp.parsebuf);
                }
                cp.parsebuf = NULL;
                cp.parsebuflen = 0;
                return MATRIXSSL_SUCCESS;
            }
            if (rc == 0)
            {
                /* We processed a partial HTTP message */
                goto READ_MORE;
            }
        }
        goto PROCESS_MORE;
    case MATRIXSSL_REQUEST_SEND:
        goto WRITE_MORE;
    case MATRIXSSL_REQUEST_RECV:
        goto READ_MORE;
    case MATRIXSSL_RECEIVED_ALERT:
        /* The first byte of the buffer is the level */
        /* The second byte is the description */
        if (*buf == SSL_ALERT_LEVEL_FATAL)
        {
            psTraceIntInfo("Fatal alert: %d, closing connection.\n",
                *(buf + 1));
            goto L_CLOSE_ERR;
        }
        /* Closure alert is normal (and best) way to close */
        if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY)
        {
            closeConn(ssl, fd);
            if (cp.parsebuf)
            {
                free(cp.parsebuf);
            }
            cp.parsebuf = NULL;
            cp.parsebuflen = 0;
            return MATRIXSSL_SUCCESS;
        }
        psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
        if ((rc = matrixSslProcessedData(ssl, &buf, (uint32 *) &len)) == 0)
        {
            /* No more data in buffer. Might as well read for more. */
            goto READ_MORE;
        }
        goto PROCESS_MORE;
    default:
        /* If rc <= 0 we fall here */
        goto L_CLOSE_ERR;
    }

L_CLOSE_ERR:
    if (cp.flags != HTTPS_COMPLETE)
    {
        _psTrace("FAIL: No HTTP Response\n");
    }
    else
    {
/*
        printf("Received %d bytes %d usecs, state %d\n",
            stats->rbytes, (int)stats->hstime, (int)stats->datatime,
            ssl->hsState);
 */
    }
    matrixSslDeleteSession(ssl);
    if (g_keepalive == 0)
    {
        close(fd);
    }
    if (cp.parsebuf)
    {
        free(cp.parsebuf);
    }
    cp.parsebuf = NULL;
    cp.parsebuflen = 0;
    return rc;
}

/******************************************************************************/
/*
    Create an HTTP request and encode it to the SSL buffer
 */
static int32 httpWriteRequest(ssl_t *ssl)
{
    unsigned char *buf;
    int32 available, requested;

    /* If we don't have a path defined and are sending zero bytes, skip http */
    if (g_bytes_requested == 0 && *g_path == '\0')
    {
        return PS_SUCCESS;
    }

    if (g_closeServer)
    {
        /* A value of 0 to the 'new' connections is the key to sending the
            server a shutdown message */
        requested = strlen((char *) g_matrixShutdownServer) + 1;
        if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (available < requested)
        {
            return PS_FAILURE;
        }
        memset(buf, 0x0, requested); /* So strlen will work below */
        strncpy((char *) buf, (char *) g_matrixShutdownServer,
            (uint32) strlen((char *) g_matrixShutdownServer));
        if (matrixSslEncodeWritebuf(ssl, (uint32) strlen((char *) buf)) < 0)
        {
            return PS_MEM_FAIL;
        }
        return MATRIXSSL_REQUEST_SEND;
    }

    requested = strlen((char *) g_httpRequestHdr) + strlen(g_path) + 1;
    if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0)
    {
        return PS_MEM_FAIL;
    }
    requested = min(requested, available);
    snprintf((char *) buf, requested, (char *) g_httpRequestHdr, g_path);


    if (g_trace)
    {
        _psTraceStr("SEND: [%s]\n", (char *) buf);
    }
    if (matrixSslEncodeWritebuf(ssl, strlen((char *) buf)) < 0)
    {
        return PS_MEM_FAIL;
    }
    return MATRIXSSL_REQUEST_SEND;
}

# ifdef ID_RSA
#  ifdef USE_HEADER_KEYS
static int32 loadRsaKeys(uint32 key_len, sslKeys_t *keys,
    unsigned char *CAstream, int32 CAstreamLen)
{
    int32 rc;
    const unsigned char *key_buf = NULL;
    const unsigned char *cert_buf = NULL;
    int32 key_buf_len = 0;
    int32 cert_buf_len = 0;

    if (key_len == 1024)
    {
        _psTrace("Using 1024 bit RSA private key\n");
        cert_buf = RSA1024;
        cert_buf_len = sizeof(RSA1024);
        key_buf = RSA1024KEY;
        key_buf_len = sizeof(RSA1024KEY);
    }
    else if (key_len == 2048)
    {
        _psTrace("Using 2048 bit RSA private key\n");
        cert_buf = RSA2048;
        cert_buf_len = sizeof(RSA2048);
        key_buf = RSA2048KEY;
        key_buf_len = sizeof(RSA2048KEY);
    }
    else if (key_len == 3072)
    {
        _psTrace("Using 3072 bit RSA private key\n");
        cert_buf = RSA3072;
        cert_buf_len = sizeof(RSA3072);
        key_buf = RSA3072KEY;
        key_buf_len = sizeof(RSA3072KEY);
    }
    else if (key_len == 4096)
    {
        _psTrace("Using 4096 bit RSA private key\n");
        cert_buf = RSA4096;
        cert_buf_len = sizeof(RSA4096);
        key_buf = RSA4096KEY;
        key_buf_len = sizeof(RSA4096KEY);
    }
    else
    {
        _psTraceInt("Unsupported RSA private key size: %u\n", key_len);
        return PS_FAILURE;
    }

    if (g_enable_ext_cv_sig_op)
    {
        key_buf = NULL;
        key_buf_len = 0;
    }

    rc = matrixSslLoadRsaKeysMem(keys, cert_buf, cert_buf_len,
        key_buf, key_buf_len, CAstream, CAstreamLen);

    if (rc < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        if (CAstream)
        {
            psFree(CAstream, NULL);
        }
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

    return rc;
}
#  endif /* USE_HEADER_KEYS */
# endif  /* ID_RSA */

static void usage(void)
{
    printf(
        "\nusage: client { options }\n"
        "\n"
        "Options can be one or more of the following:\n"
        "\n"
        "-a                      - Disable sending closure alerts\n"
        "-b <numBytesPerRequest> - Client request size\n"
        "                          Generates an HTTPS request after TLS negotiation\n"
        "                          Uses URL path of '/bytes?<numBytesPerRequest>'\n"
        "                          Mutually exclusive with '-u' flag\n"
        "-c <cipherList>         - Comma separated list of ciphers numbers\n"
        "                        - Example cipher numbers:\n"
        "                        - '53' TLS_RSA_WITH_AES_256_CBC_SHA\n"
        "                        - '47' TLS_RSA_WITH_AES_128_CBC_SHA\n"
        "                        - '10' SSL_RSA_WITH_3DES_EDE_CBC_SHA\n"
        "                        - '5'  SSL_RSA_WITH_RC4_128_SHA\n"
        "                        - '4'  SSL_RSA_WITH_RC4_128_MD5\n"
        "-d                      - Disable server certicate name/addr chk\n"
        "-h                      - Help, print usage and exit\n"
        "-k <keyLen>             - RSA keyLen\n"
        "                        - Must be one of 1024, 2048 or 4096\n"
        "-K                      - Keepalive (Re-use socket after TLS session close)\n"
        "-n <numNewSessions>     - Num of new (full handshake) sessions\n"
        "                        - Default 1\n"
        "-p <serverPortNum>      - Port number for SSL/TLS server\n"
        "                        - Default 4433 (HTTPS is 443)\n"
        "-r <numResumedSessions> - Num of resumed SSL/TLS sesssions\n"
        "                        - Default 0\n"
        "-s <serverIpAddress>    - IP address of server machine/interface\n"
        "                        - Default 127.0.0.1 (localhost)\n"
        "-u <url path>           - URL path, eg. '/index.html'\n"
        "                          Generates an HTTPS request after TLS negotiation\n"
        "                          Mutually exclusive with '-b' flag\n"
        "-V <tlsVersion>         - SSL/TLS version to use\n"
        "                        - '0' SSL 3.0\n"
        "                        - '1' TLS 1.0\n"
        "                        - '2' TLS 1.1\n"
        "                        - '3' TLS 1.2 (default)\n"
        "\n");
}

/* Returns number of cipher numbers found, or -1 if an error. */
# include <ctype.h>
static int32_t parse_cipher_list(char *cipherListString,
    psCipher16_t cipher_array[], uint8_t size_of_cipher_array)
{
    uint32 numCiphers, cipher;
    char *endPtr;

    /* Convert the cipherListString into an array of cipher numbers. */
    numCiphers = 0;
    while (cipherListString != NULL)
    {
        cipher = strtol(cipherListString, &endPtr, 10);
        if (endPtr == cipherListString)
        {
            printf("The remaining cipherList has no cipher numbers - '%s'\n",
                cipherListString);
            return -1;
        }
        else if (size_of_cipher_array <= numCiphers)
        {
            printf("Too many cipher numbers supplied.  limit is %d\n",
                size_of_cipher_array);
            return -1;
        }
        cipher_array[numCiphers++] = cipher;
        while (*endPtr != '\0' && !isdigit(*endPtr))
        {
            endPtr++;
        }
        cipherListString = endPtr;
        if (*endPtr == '\0')
        {
            break;
        }
    }

    return numCiphers;
}

/* Return 0 on good set of cmd options, return -1 if a bad cmd option is
   encountered OR a request for help is seen (i.e. '-h' option). */
static int32 process_cmd_options(int32 argc, char **argv)
{
    int optionChar, key_len, version, numCiphers;
    char *cipherListString;

    /* Set some default options: */
    memset(g_cipher, 0, sizeof(g_cipher));
    memset(g_ip,     0, sizeof(g_ip));
    memset(g_path,   0, sizeof(g_path));

    strcpy(g_ip,          "127.0.0.1");
    g_bytes_requested    = 0;
    g_send_closure_alert = 1;
    g_ciphers            = 0;
    g_cipher[0]          = 0;
    g_disableCertNameChk = 0;
    g_key_len            = 1024;
    g_new                = 1;
    g_port               = 4433;
    g_resumed            = 0;
    g_version            = 3;
    g_keepalive          = 0;

    opterr = 0;
    while ((optionChar = getopt(argc, argv, "ab:C:c:de:hk:Km:n:p:r:s:u:V:")) != -1)
    {
        switch (optionChar)
        {
        case 'h':
            return -1;


        case 'a':
            g_send_closure_alert = 0;
            break;

        case 'b':
            if (*g_path)
            {
                printf("-b and -u options cannot both be provided\n");
                return -1;
            }
            g_bytes_requested = atoi(optarg);
            snprintf(g_path, sizeof(g_path), "/bytes?%u", g_bytes_requested);
            break;

        case 'C':
#ifdef USE_HEADER_KEYS
            printf("USE_HEADER_KEYS not compatible with CA file option\n");
#else
            g_ca_file = optarg;
            printf("Using CA file: %s\n", g_ca_file);
#endif
            break;

        case 'c':
            /* Convert the cipherListString into an array of cipher numbers. */
            cipherListString = optarg;
            numCiphers = parse_cipher_list(cipherListString, g_cipher, 16);
            if (numCiphers <= 0)
            {
                return -1;
            }
            g_ciphers = numCiphers;
            break;

        case 'd':
            g_disableCertNameChk = 1;
            break;

        case 'e':
            printf("-e option only supported when USE_EXT_CERTIFICATE_VERIFY_SIGNING " \
                "and USE_EXT_EXAMPLE_MODULE are defined\n");
            return -1;
            break;

        case 'k':
            key_len = atoi(optarg);
            if ((key_len != 1024) && (key_len != 2048)
                    && (key_len != 3072) && (key_len != 4096))
            {
                printf("-k option must be followed by a key_len whose value "
                    " must be 1024, 2048, 3072 or 4096\n");
                return -1;
            }
            g_key_len = key_len;
            break;

        case 'K':
            g_keepalive = 1;
            break;

        case 'm':
            g_max_verify_depth = atoi(optarg);
            break;

        case 'n':
            g_new = atoi(optarg);
            break;

        case 'p':
            g_port = atoi(optarg);
            break;

        case 'r':
            g_resumed = atoi(optarg);
            break;

        case 's':
            strncpy(g_ip, optarg, 15);
            break;

        case 'u':
            if (*g_path)
            {
                printf("-b and -u options cannot both be provided\n");
                return -1;
            }
            strncpy(g_path, optarg, sizeof(g_path) - 1);
            g_bytes_requested = 0;
            break;

        case 'V':
            version = atoi(optarg);
            if (version < 0 || version > 3)
            {
                printf("Invalid version: %d\n", version);
                return -1;
            }
            g_version = version;
            break;
        }
    }

    return 0;
}

/******************************************************************************/
/*
    Main routine. Initialize SSL keys and structures, and make two SSL
    connections, the first with a blank session Id, and the second with
    a session ID populated during the first connection to do a much faster
    session resumption connection the second time.
 */
int32 main(int32 argc, char **argv)
{
    int32 rc, CAstreamLen, i, exit_code;
    sslKeys_t *keys;
    sslSessionId_t *sid = NULL;
    struct g_sslstats stats;
    unsigned char *CAstream;
# if defined(USE_HEADER_KEYS) && !defined(ID_RSA)
    const unsigned char *key_buf;
    int32 key_buf_len;
# endif /* USE_HEADER_KEYS && !ID_RSA */
# ifndef USE_HEADER_KEYS
    unsigned char *tmp_buf;
    int32 tmp_buf_len;
    char *pCA;
# endif /* USE_HEADER_KEYS */
# ifdef WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(1, 1), &wsaData);
# endif

    exit_code = 0;

    if ((rc = matrixSslOpen()) < 0)
    {
        _psTrace("MatrixSSL library init failure.  Exiting\n");
        return EXIT_FAILURE;
    }

    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        _psTrace("MatrixSSL library key init failure.  Exiting\n");
        return EXIT_FAILURE;
    }

    if (0 != process_cmd_options(argc, argv))
    {
        usage();
        return 0;
    }

    if (g_new <= 1 && g_resumed <= 1)
    {
        g_trace = 1;
    }
    else
    {
        g_trace = 0;
    }

    if (g_bytes_requested == 0 && *g_path == '\0')
    {
        printf("client %s:%d "
            "new:%d resumed:%d keylen:%d nciphers:%d version:%s\n",
            g_ip, g_port, g_new, g_resumed, g_key_len,
            g_ciphers, g_strver[g_version]);
    }
    else
    {
        printf("client https://%s:%d%s "
            "new:%d resumed:%d keylen:%d nciphers:%d version:%s\n",
            g_ip, g_port, g_path, g_new, g_resumed, g_key_len,
            g_ciphers, g_strver[g_version]);
    }

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  ifdef USE_HEADER_KEYS
/*
    In-memory based keys
    Build the CA list first for potential client auth usage
 */
    CAstreamLen = 0;
#   ifdef USE_RSA_CIPHER_SUITE
    CAstreamLen += sizeof(RSACAS);
#    ifdef USE_ECC_CIPHER_SUITE
    CAstreamLen += sizeof(ECDHRSACAS);
#    endif
#   endif
#   ifdef USE_ECC_CIPHER_SUITE
    CAstreamLen += sizeof(ECCAS);
#   endif
#   if defined(USE_RSA_CIPHER_SUITE) || defined(USE_ECC_CIPHER_SUITE)
    CAstream = psMalloc(NULL, CAstreamLen);
#   else
    CAstream = NULL;
#   endif

    CAstreamLen = 0;
#   ifdef USE_RSA_CIPHER_SUITE
    memcpy(CAstream, RSACAS, sizeof(RSACAS));
    CAstreamLen += sizeof(RSACAS);
#    ifdef USE_ECC_CIPHER_SUITE
    memcpy(CAstream + CAstreamLen, ECDHRSACAS, sizeof(ECDHRSACAS));
    CAstreamLen += sizeof(ECDHRSACAS);
#    endif
#   endif
#   ifdef USE_ECC_CIPHER_SUITE
    memcpy(CAstream + CAstreamLen, ECCAS, sizeof(ECCAS));
    CAstreamLen += sizeof(ECCAS);
#   endif


#   ifdef ID_RSA
    rc = loadRsaKeys(g_key_len, keys, CAstream, CAstreamLen);
    if (rc < 0)
    {
        return EXIT_FAILURE;
    }
#   endif

#   ifdef ID_ECDH_RSA
    if (g_enable_ext_cv_sig_op)
    {
        key_buf = NULL;
        key_buf_len = 0;
    }
    else
    {
        key_buf = ECDHRSA521KEY;
        key_buf_len = sizeof(ECDHRSA521KEY);
    }

    if ((rc = matrixSslLoadEcKeysMem(keys, ECDHRSA521, sizeof(ECDHRSA521),
             key_buf, key_buf_len, (unsigned char *) CAstream,
             CAstreamLen)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        if (CAstream)
        {
            psFree(CAstream, NULL);
        }
        matrixSslDeleteKeys(keys);
        matrixSslClose();
        return EXIT_FAILURE;
    }
#   endif

#   ifdef ID_ECDH_ECDSA
    if (g_enable_ext_cv_sig_op)
    {
        key_buf = NULL;
        key_buf_len = 0;
    }
    else
    {
        key_buf = EC384KEY;
        key_buf_len = sizeof(EC384KEY);
    }

    if ((rc = matrixSslLoadEcKeysMem(keys, EC384, sizeof(EC384),
             key_buf, key_buf_len, (unsigned char *) CAstream,
             CAstreamLen)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        if (CAstream)
        {
            psFree(CAstream, NULL);
        }
        matrixSslDeleteKeys(keys);
        matrixSslClose();
        return EXIT_FAILURE;
    }
#   endif

    if (CAstream)
    {
        psFree(CAstream, NULL);
    }

#  else
/*
    File based keys
 */
    rc = psGetFileBuf(NULL, "testkeys/RSA/2048_RSA.pem", &tmp_buf, &tmp_buf_len);
    if (rc >= 0)
    {
        g_at_matrixssl_root = 1;
    }
    else
    {
        g_at_matrixssl_root = 0;
    }
    psFree(tmp_buf, NULL);

    CAstreamLen = 0;
#   ifdef USE_RSA_CIPHER_SUITE
    if (g_at_matrixssl_root)
    {
        pRsaCAFile += 6;
    }
    CAstreamLen += (int32) strlen(pRsaCAFile) + 1;
#    ifdef USE_ECC_CIPHER_SUITE
    if (g_at_matrixssl_root)
    {
        pEcdhRsaCAFile += 6;
    }
    CAstreamLen += (int32) strlen(pEcdhRsaCAFile) + 1;
#    endif
#   endif
#   ifdef USE_ECC_CIPHER_SUITE
    if (g_at_matrixssl_root)
    {
        pEcCAFile += 6;
    }
    CAstreamLen += (int32) strlen(pEcCAFile) + 1;
#   endif
    if (CAstreamLen > 0)
    {
        CAstream = psMalloc(NULL, CAstreamLen);
        memset(CAstream, 0x0, CAstreamLen);
    }
    else
    {
        CAstream = NULL;
    }

    CAstreamLen = 0;
#   ifdef USE_RSA_CIPHER_SUITE
    memcpy(CAstream, pRsaCAFile, strlen(pRsaCAFile));
    CAstreamLen += strlen(pRsaCAFile);
#    ifdef USE_ECC_CIPHER_SUITE
    memcpy(CAstream + CAstreamLen, ";", 1); CAstreamLen++;
    memcpy(CAstream + CAstreamLen, pEcdhRsaCAFile,  strlen(pEcdhRsaCAFile));
    CAstreamLen += strlen(pEcdhRsaCAFile);
#    endif
#   endif
#   ifdef USE_ECC_CIPHER_SUITE
    if (CAstreamLen > 0)
    {
        memcpy(CAstream + CAstreamLen, ";", 1); CAstreamLen++;
    }
    memcpy(CAstream + CAstreamLen, pEcCAFile,  strlen(pEcCAFile));
#   endif

/* Load Identity */
#   ifdef EXAMPLE_RSA_KEYS
    if (g_at_matrixssl_root)
    {
        pRsaCertFile += 6;
        pRsaPrivkeyFile += 6;
    }
    if (g_enable_ext_cv_sig_op)
    {
        pRsaPrivkeyFile = NULL;
    }
    if (g_ca_file != NULL)
        pCA = g_ca_file;
    else
        pCA = (char*)CAstream;

    if ((rc = matrixSslLoadRsaKeys(keys, pRsaCertFile, pRsaPrivkeyFile,
                            NULL, pCA) < 0))
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        if (CAstream)
        {
            psFree(CAstream, NULL);
        }
        matrixSslDeleteKeys(keys);
        matrixSslClose();
        return EXIT_FAILURE;
    }
#   endif /* EXAMPLE_RSA_KEYS */

#   ifdef EXAMPLE_ECDH_RSA_KEYS
    if (g_at_matrixssl_root)
    {
        pEcdhRsaCertFile += 6;
        pEcdhRsaPrivkeyFile += 6;
    }

    if (g_enable_ext_cv_sig_op)
    {
        pEcdhRsaPrivkeyFile = NULL;
    }

    if (g_ca_file != NULL)
        pCA = g_ca_file;
    else
        pCA = (char*)CAstream;

    if ((rc = matrixSslLoadEcKeys(keys, pEcdhRsaCertFile, pEcdhRsaPrivkeyFile,
             NULL, pCA)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        if (CAstream)
        {
            psFree(CAstream, NULL);
        }
        matrixSslDeleteKeys(keys);
        matrixSslClose();
        return EXIT_FAILURE;
    }
#   endif /* EXAMPLE_ECDH_RSA_KEYS */

#   ifdef EXAMPLE_EC_KEYS
    if (g_at_matrixssl_root)
    {
        pEcCertFile += 6;
        pEcPrivkeyFile += 6;
    }

    if (g_enable_ext_cv_sig_op)
    {
        pEcPrivkeyFile = NULL;
    }

    if ((rc = matrixSslLoadEcKeys(keys, pEcCertFile, pEcPrivkeyFile, NULL,
             (char *) CAstream)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        if (CAstream)
        {
            psFree(CAstream, NULL);
        }
        matrixSslDeleteKeys(keys);
        matrixSslClose();
        return EXIT_FAILURE;
    }
#   endif /* EXAMPLE_EC_KEYS */

    if (CAstream)
    {
        psFree(CAstream, NULL);
    }
#  endif /* USE_HEADER_KEYS */
# endif  /* USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_PSK_CIPHER_SUITE
    for (rc = 0; rc < PSK_HEADER_TABLE_COUNT; rc++)
    {
        matrixSslLoadPsk(keys,
            PSK_HEADER_TABLE[rc].key, sizeof(PSK_HEADER_TABLE[rc].key),
            PSK_HEADER_TABLE[rc].id, sizeof(PSK_HEADER_TABLE[rc].id));
    }
# endif /* USE_PSK_CIPHER_SUITE */

# ifdef USE_CRL
    /* One initialization step that can be taken is to run through the CA
        files and see if any CRL URL distribution points are present.
        Fetch the CRL and load into the cache if found */
    fetchParseAndAuthCRLfromCert(NULL, keys->CAcerts, keys->CAcerts);
# endif

    memset(&stats, 0x0, sizeof(struct g_sslstats));
    printf("=== %d new connections ===\n", g_new);

    if (g_new == 0)
    {
        /* Special case where client is being used to remotely shut down
            the server for automated tests */
        g_closeServer = 1;
        g_bytes_requested = 0; /* Disable data exchange in this case */
        g_new = 1;
    }

    for (i = 0; i < g_new; i++)
    {
        matrixSslNewSessionId(&sid, NULL);
# ifdef USE_CRL
#  ifndef MIDHANDSHAKE_CRL_FETCH
        /* This is part of the example for an application that has chosen to
            fail a handshake if the CRL was not available during the first
            attempted connection.  In this case, the CRL URL distribution points
            have been saved aside in g_crlDistURLs and now we will go out and
            fetch those CRLs and load them into the library cache so they
            will be available on this next connection attempt. */
        if (g_crlDistURLs[0][0] == 'h')   /* assumption is "http" */
        {
            fetchSavedCRL(keys->CAcerts);
        }
#  endif
# endif
        rc = httpsClientConnection(keys, sid, &stats);
        if (rc < 0)
        {
            printf("F %d/%d\n", i, g_new);
            exit_code = EXIT_FAILURE;
            goto out;
        }
        else
        {
            printf("N"); fflush(stdout);
        }
        /* Leave the final sessionID for resumed connections */
        if (i + 1 < g_new)
        {
            matrixSslDeleteSessionId(sid);
        }
    }
    printf("\n");
    if (g_bytes_requested > 0)
    {
        psAssert(g_bytes_requested * g_new == stats.rbytes);
    }
    printf("%d bytes received\n", stats.rbytes);
# ifdef USE_HIGHRES_TIME
    printf("%d usec (%d avg usec/conn SSL handshake overhead)\n",
        (int) stats.hstime, (int) (stats.hstime / g_new));
    printf("%d usec (%d avg usec/conn SSL data overhead)\n",
        (int) stats.datatime, (int) (stats.datatime / g_new));
# else
    printf("%d msec (%d avg msec/conn SSL handshake overhead)\n",
        (int) stats.hstime, (int) (stats.hstime / g_new));
    printf("%d msec (%d avg msec/conn SSL data overhead)\n",
        (int) stats.datatime, (int) (stats.datatime / g_new));
# endif

    memset(&stats, 0x0, sizeof(struct g_sslstats));
    printf("=== %d resumed connections ===\n", g_resumed);
    for (i = 0; i < g_resumed; i++)
    {
        rc = httpsClientConnection(keys, sid, &stats);
        if (rc < 0)
        {
            printf("f %d/%d\n", i, g_resumed);
            exit_code = EXIT_FAILURE;
            goto out;
        }
        else
        {
            printf("R"); fflush(stdout);
        }
    }
    if (g_keepalive)
    {
        printf("Closing socket\n");
        close(g_keepalive);
        g_keepalive = 0;
    }
    if (g_resumed)
    {
        if (g_bytes_requested > 0)
        {
            psAssert(g_bytes_requested * g_resumed == stats.rbytes);
        }
        printf("\n%d bytes received\n", stats.rbytes);
# ifdef USE_HIGHRES_TIME
        printf("%d usec (%d avg usec/conn SSL handshake overhead)\n",
            (int) stats.hstime, (int) (stats.hstime / g_resumed));
        printf("%d usec (%d avg usec/conn SSL data overhead)\n",
            (int) stats.datatime, (int) (stats.datatime / g_resumed));
# else
        printf("%d msec (%d avg msec/conn SSL handshake overhead)\n",
            (int) stats.hstime, (int) (stats.hstime / g_resumed));
        printf("%d msec (%d avg msec/conn SSL data overhead)\n",
            (int) stats.datatime, (int) (stats.datatime / g_resumed));
# endif
    }

out:
    matrixSslDeleteSessionId(sid);

    matrixSslDeleteKeys(keys);
    matrixSslClose();

    if (rc == MATRIXSSL_SUCCESS)
    {
        printf("TLS handshake complete.\n");
    }

# ifdef WIN32
    _psTrace("Press any key to close");
    getchar();
# endif
    return exit_code;
}

/******************************************************************************/
/*
    Close a socket and free associated SSL context and buffers
    An attempt is made to send a closure alert
 */
static void closeConn(ssl_t *ssl, SOCKET fd)
{
    unsigned char *buf;
    int32 len, rc;

    if (g_send_closure_alert)
    {
# if 1
        /* Set the socket to non-blocking to flush remaining data */
#  ifdef POSIX
        rc = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        psAssert(rc >= 0);
#  endif
#  ifdef WIN32
        len = 1;    /* 1 for non-block, 0 for block */
        rc = ioctlsocket(fd, FIONBIO, &len);
        psAssert(rc);
#  endif
        /* Quick attempt to send a closure alert, don't worry about failure */
        if (matrixSslEncodeClosureAlert(ssl) >= 0)
        {
            if ((len = matrixSslGetOutdata(ssl, &buf)) > 0)
            {
                if ((len = send(fd, buf, len, MSG_DONTWAIT)) > 0)
                {
                    matrixSslSentData(ssl, len);
                }
            }
        }
# endif
    }
    matrixSslDeleteSession(ssl);

    if (fd != INVALID_SOCKET && g_keepalive == 0)
    {
        /* printf("Closing socket from closeConn\n"); */
        close(fd);
    }
}

static int32_t extensionCb(ssl_t *ssl,
    uint16_t extType, uint8_t extLen, void *e)
{
    unsigned char *c;
    short len;
    char proto[128];

    c = (unsigned char *) e;

    if (extType == EXT_ALPN)
    {
        memset(proto, 0x0, 128);
        /* two byte proto list len, one byte proto len, then proto */
        c += 2; /* Skip proto list len */
        len = *c; c++;
        memcpy(proto, c, len);
        printf("Server agreed to use %s\n", proto);
    }
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Example callback to show possiblie outcomes of certificate validation.
    If this callback is not registered in matrixSslNewClientSession
    the connection will be accepted or closed based on the alert value.
 */
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
# ifndef USE_ONLY_PSK_CIPHER_SUITE
    psX509Cert_t *next;

    /* An immediate SSL_ALERT_UNKNOWN_CA alert means we could not find the
        CA to authenticate the server's certificate */
    if (alert == SSL_ALERT_UNKNOWN_CA)
    {
        /*
          SSL_ALERT_UNKNOWN_CA can also result from breach of the
          max_verify_depth limit we specified in the session options.
        */
        if (g_max_verify_depth > 0) {
            for (next = cert; next != NULL; next = next->next)
            {
                if ((next->authStatus & PS_CERT_AUTH_FAIL_PATH_LEN) &&
                        (next->authFailFlags &
                                PS_CERT_AUTH_FAIL_VERIFY_DEPTH_FLAG))
                {
                    _psTrace("Maximum cert chain verify depth exceeded\n");
                    return SSL_ALERT_UNKNOWN_CA;
                }
            }
        }
        /* Example to allow anonymous connections based on a define */
        else if (ALLOW_ANON_CONNECTIONS)
        {
            if (g_trace)
            {
                _psTraceStr("Allowing anonymous connection for: %s.\n",
                    cert->subject.commonName);
            }
            return SSL_ALLOW_ANON_CONNECTION;
        }
        _psTrace("ERROR: No matching CA found.  Terminating connection\n");
    }

    /*  Check for "major" authentication problems within the server certificate
        chain.

        The "alert" is the translation of the very first authentication problem
        found.  So if we are dealing with a certificate chain we should walk to
        the parent-most cert to confirm there are no authentication problems
        that indicate the chain itself did not validate or this client did
        not find a CA to authenticate the server.

        Some certificate callback implemenations might choose to ignore some
        alerts that are considered minor to the use case, so this is an example
        of how to make sure a minor alert (such as expired date) is not
        overriding a more serious authentication problem
     */
    for (next = cert; next != NULL; next = next->next)
    {
        if (next->authStatus == PS_CERT_AUTH_FAIL_SIG)
        {
            _psTrace("Public key signature failure in server cert chain\n");
            /* This should result in a BAD_CERTIFICATE alert */
            alert = SSL_ALERT_BAD_CERTIFICATE;
            break;
        }
        if (next->authStatus == PS_CERT_AUTH_FAIL_DN)
        {
            /* A CA file was never located to support this chain */
            _psTrace("No CA file was found to support server's certificate\n");
            /* This should result in a SSL_ALERT_UNKNOWN_CA alert */
            alert = SSL_ALERT_UNKNOWN_CA;
            break;
        }
        if (next->authStatus == PS_CERT_AUTH_FAIL_AUTHKEY)
        {
            /* Subject and Issuer Key Id extension  */
            _psTrace("Subject and Issuer Key Id mismatch error\n");
            /* This should be a BAD_CERTIFICATE alert */
            alert = SSL_ALERT_BAD_CERTIFICATE;
            break;
        }
    }

    /*
        If the expectedName passed to matrixSslNewClientSession does not
        match any of the server subject name or subjAltNames, we will have
        the alert below.
        For security, the expected name (typically a domain name) _must_
        match one of the certificate subject names, or the connection
        should not continue.
        The default MatrixSSL certificates use localhost and 127.0.0.1 as
        the subjects, so unless the server IP matches one of those, this
        alert will happen.
        To temporarily disable the subject name validation, NULL can be passed
        as expectedName to matrixNewClientSession.
     */
    if (alert == SSL_ALERT_CERTIFICATE_UNKNOWN)
    {
        _psTraceStr("ERROR: %s not found in cert subject names\n",
            ssl->expectedName);
    }

    if (alert == SSL_ALERT_CERTIFICATE_EXPIRED)
    {
#  ifdef POSIX
        _psTrace("ERROR: A cert did not fall within the notBefore/notAfter window\n");
#  else
        _psTrace("WARNING: Certificate date window validation not implemented\n");
        alert = 0;
#  endif
    }

    if (alert == SSL_ALERT_ILLEGAL_PARAMETER)
    {
        _psTrace("ERROR: Found correct CA but X.509 extension details are wrong\n");
    }

    /* Key usage related problems on chain */
    for (next = cert; next != NULL; next = next->next)
    {
        if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION)
        {
            if (next->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG)
            {
                _psTrace("CA keyUsage extension doesn't allow cert signing\n");
            }
            if (next->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG)
            {
                _psTrace("Cert extendedKeyUsage extension doesn't allow TLS\n");
            }
        }
    }

    if (alert == SSL_ALERT_BAD_CERTIFICATE)
    {
        /* Should never let a connection happen if this is set.  There was
            either a problem in the presented chain or in the final CA test */
        _psTrace("ERROR: Problem in certificate validation.  Exiting.\n");
    }


#  ifdef USE_CRL
    /* Examples on how to look at the CRL status for the cert chain and fetch
        CRLs if they have not been loaded */
    {
        psX509Crl_t *expired;
#   ifdef MIDHANDSHAKE_CRL_FETCH
        /* Will pause this handshake to go out and fetch a CRL via HTTP GET,
            re-check for revocation and continue on if it all checks out */
        int retryOnce = 0;
RETRY_CRL_TEST_ONCE:
#   else
        /* Perhaps the more standard way is to stop the handshake if the CRLs have
            not been fetched.  Go fetch them and retry the SSL connection from
            scratch.  The connection reattempt will only occur if the -n command
            line option has been set to something greater than 1 */
        int count = 0;
        uint32_t urlLen;
        unsigned char *url;
#   endif

        /* Loop to look at the CRL status of each cert in the chain */
        for (next = cert; next != NULL; next = next->next)
        {
            switch (next->revokedStatus)
            {
            case CRL_CHECK_CRL_EXPIRED:
                _psTrace("Have CRL but it is expired.  Fetching new one\n");
                /* Remove the CRL from the table */
                expired = psCRL_GetCRLForCert(next);
                if (expired)
                {
                    psAssert(expired->expired);
                    psCRL_Delete(expired);
                }
                else
                {
                    _psTrace("Unexpected combo of expired but no CRL found\n");
                }
            /* MOVING INTO CRL_CHECK_EXPECTED ON PURPOSE TO REFETCH */
            case CRL_CHECK_EXPECTED:
                /* There was a CRL distribution point in this cert but we didn't
                    have the CRL to test against */
#   ifdef MIDHANDSHAKE_CRL_FETCH
                /* It is an application choice to go out and fetch CRLs in the
                    middle of the handshake like this.  It's probably not advised
                    to do this but here is an example if you'd like to do so */
                /* Only attempt this once so we don't get stuck in a loop */
                if (retryOnce)
                {
                    _psTrace("Cert was not able to be tested against a CRL\n");
                    alert = SSL_ALERT_CERTIFICATE_UNKNOWN;
                    break;
                }
                _psTrace("Cert expects CRL.  Mid-handshake attempt being made\n");
                /* This fetchParseAndAuthCRLfromCert will work on "next" as a chain
                    so it is correct that the server cert will look for the first
                    instance of CHECK_EXPECTED and pass that as the start of
                    chain to work upon */
                fetchParseAndAuthCRLfromCert(NULL, next, ssl->keys->CAcerts);
                /* If all went well, every cert in the server chain will have an
                    updated status */
                retryOnce++;
                goto RETRY_CRL_TEST_ONCE;
#   else        /* MIDHANSHAKE_CRL_FETCH */

                /* if (next->extensions.ak.keyId) { */
                /*      psTraceBytes("cert ak", next->extensions.ak.keyId, 20); */
                /* } */
                _psTrace("Cert expects CRL. Failing handshake to go fetch it\n");
                /* A more typical case if CRL testing is expected to be done is
                    to halt the handshake now, go out and fetch the CRLs and
                    try the connection again */
                /* Not clear which alert should be associated with this
                    application level decision.  Let's call it UNKNOWN */
                alert = SSL_ALERT_CERTIFICATE_UNKNOWN;

                /* Save aside the CRL URL distribution points to fetch after
                    control is given back when this handshake is done. Correct
                    to pick up from the current cert and work up as far as
                    possible */
                if (count < CRL_MAX_SERVER_CERT_CHAIN)
                {
                    memset(g_crlDistURLs[count], 0, CRL_MAX_URL_LEN);
                    psX509GetCRLdistURL(next, (char **) &url, &urlLen);
                    if (urlLen > CRL_MAX_URL_LEN)
                    {
                        _psTraceInt("CLR URL distribution point longer than %d\n",
                            CRL_MAX_URL_LEN);
                    }
                    else
                    {
                        memcpy(g_crlDistURLs[count], url, urlLen);
                        count++;
                    }
                }
                else
                {
                    _psTraceInt("Server cert chain was longer than %d\n",
                        CRL_MAX_SERVER_CERT_CHAIN);
                }

                break;

#   endif       /* MIDHANDSHAKE_CRL_FETCH */
                break;

            case CRL_CHECK_NOT_EXPECTED:
                _psTrace("Cert didn't specify a CRL distribution point\n");
                break;
            case CRL_CHECK_PASSED_AND_AUTHENTICATED:
                _psTrace("Cert passed CRL test and CRL was authenticated\n");
                break;
            case CRL_CHECK_PASSED_BUT_NOT_AUTHENTICATED:
                _psTrace("Cert passed CRL test but CRL was not authenticated\n");
                break;
            case CRL_CHECK_REVOKED_AND_AUTHENTICATED:
                _psTrace("Cert was revoked by an authenticated CRL\n");
                alert = SSL_ALERT_CERTIFICATE_REVOKED;
                break;
            case CRL_CHECK_REVOKED_BUT_NOT_AUTHENTICATED:
                _psTrace("Cert was revoked but the CRL wasn't authenticated\n");
                alert = SSL_ALERT_CERTIFICATE_REVOKED;
                break;
            default:
                break;
            }
        }
    } /* End CRL local code block */
#  endif

    if (g_trace && alert == 0 && cert)
    {
        _psTraceStr("SUCCESS: Validated cert for: %s.\n", cert->subject.commonName);
    }

# endif /* !USE_ONLY_PSK_CIPHER_SUITE */
    return alert;
} /* end certificate callback */


/******************************************************************************/
# ifdef USE_CRL

#  ifndef MIDHANDSHAKE_CRL_FETCH
/* Part of example for halting handshake because no CRL was available.  Now
    we have closed that handshake and are fetching the CRLs that were set
    aside during the certificate callback.  We use our list of CA files as
    potential issuers here so we can attempt a round of CRL authentications.
    This authentication round will save time during the next handshake */
static void fetchSavedCRL(psX509Cert_t *potentialIssuers)
{
    int i;

    /* Test for 'h' is assuming URL to begin with "http" */
    for (i = 0; i < CRL_MAX_SERVER_CERT_CHAIN && g_crlDistURLs[i][0] == 'h';
         i++)
    {
        fetchParseAndAuthCRLfromUrl(NULL, g_crlDistURLs[i],
            strlen((char *) g_crlDistURLs[i]), potentialIssuers);
        memset(g_crlDistURLs[i], 0, CRL_MAX_URL_LEN);
    }
}

/* Fetch a CRL give an URL.  Once you have it, check to see if it can be
    authenticated by any of the "potentialIssuers"

    Regardless of authentication status, add any CRL that is found
    to the global cache for     access inside the library during internal
    authentications */
static int32_t fetchParseAndAuthCRLfromUrl(psPool_t *pool, unsigned char *url,
    uint32_t urlLen, psX509Cert_t *potentialIssuers)
{
    unsigned char *crlBuf;
    uint32_t crlBufLen;
    psX509Crl_t *crl;
    psX509Cert_t *ic;

    /* url need not be freed.  It points into cert structure */
    if (fetchCRL(NULL, (char *) url, urlLen, &crlBuf, &crlBufLen) < 0)
    {
        _psTrace("Unable to fetch CRL\n");
        return -1;
    }
    /* Convert the CRL stream into our structure */
    if (psX509ParseCRL(pool, &crl, crlBuf, crlBufLen) < 0)
    {
        _psTrace("Unable to parse CRL\n");
        psFree(crlBuf, pool);
        return -1;
    }
    psFree(crlBuf, pool);

    /* Adding the CRL to the global cache.  This local crl is now the
        same memory as the entry in the global cache and is managed
        there.  Freeing will now be     done with psCRL_DeleteAll at
        application closure */
    psCRL_Update(crl, 1); /* The 1 will delete old CRLs */

    /* Important to separate the concept of the CRL authentication
        from the cert authentication.  Here, we run through the
        list of potential issuers the caller thinks could work */
    for (ic = potentialIssuers; ic != NULL; ic = ic->next)
    {
        if (psX509AuthenticateCRL(ic, crl, NULL) >= 0)
        {
            _psTrace("NOTE: Able to authenticate CRL\n");
            break; /* Stop looking */
        }
    }
    return PS_SUCCESS;
}
#  endif /* ifndef MIDHANDSHAKE_CRL_FETCH */


/* Take the CRL Distribution URL from the "cert" (may be a chain) and go fetch
    the CRL.  Once you have it, check to see if it can be authenticated by any
    of the "potentialIssuers" OR by the "cert" chain itself.

    Regardless of authentication status, add any CRL that is found
    to the global cache for     access inside the library during internal
    authentications */
static int32_t fetchParseAndAuthCRLfromCert(psPool_t *pool, psX509Cert_t *cert,
    psX509Cert_t *potentialIssuers)
{
    char *url;
    unsigned char *crlBuf;
    uint32_t urlLen, crlBufLen;
    psX509Crl_t *crl;
    psX509Cert_t *sc, *ic;
    int32 numLoaded = 0;

    sc = cert;
    while (sc)
    {
        if (psX509GetCRLdistURL(sc, &url, &urlLen) > 0)
        {
            /* url need not be freed.  It points into cert structure */
            if (fetchCRL(NULL, url, urlLen, &crlBuf, &crlBufLen) < 0)
            {
                _psTrace("Unable to fetch CRL\n");
                sc = sc->next;
                continue;
            }
            /* Convert the CRL stream into our structure */
            if (psX509ParseCRL(pool, &crl, crlBuf, crlBufLen) < 0)
            {
                _psTrace("Unable to parse CRL\n");
                psFree(crlBuf, pool);
                sc = sc->next;
                continue;
            }
            psFree(crlBuf, pool);

            /* Adding the CRL to the global cache.  This local crl is now the
                same memory as the entry in the global cache and is managed
                there.  Freeing will now be     done with psCRL_DeleteAll at
                application closure */
            psCRL_Update(crl, 1); /* The 1 will delete old CRLs */
            ++numLoaded;

            /* Important to separate the concept of the CRL authentication
                from the cert authentication.  Here, we run through the
                list of potential issuers the caller thinks could work */
            for (ic = potentialIssuers; ic != NULL; ic = ic->next)
            {
                if (psX509AuthenticateCRL(ic, crl, NULL) >= 0)
                {
                    _psTrace("NOTE: Able to authenticate CRL\n");
                    break; /* Stop looking */
                }
            }
            if (crl->authenticated == 0)
            {
                /* If none of our potential issuers were able to authenticate,
                    let's just run through our own "cert" chain as well.
                    The reason we are doing this is to allow this function
                    to handle cases where the "cert" is part of a server
                    cert chain where the issuer is included as part of that
                    CERTIFICATE message.  That is what we are testing here.
                    The potentialIssuers will typically be the loaded CA
                    files and that will catch the cases where the parent-most
                    certificate of the server chain will need to be
                    authenticated */
                for (ic = cert; ic != NULL; ic = ic->next)
                {
                    if (psX509AuthenticateCRL(ic, crl, NULL) >= 0)
                    {
                        _psTrace("NOTE: Able to authenticate CRL\n");
                        break; /* Stop looking */
                    }
                }
            }

            /* Regardless of whether or not we could authenticate the CRL,
                run the function that recalculates the revokedStatus of
                the certificate itself.  REQUIRES g_CRL */
            psCRL_determineRevokedStatus(sc);
        }
        sc = sc->next;
    }
    _psTraceInt("CRLs loaded: %d\n", numLoaded);
    return PS_SUCCESS;
}

/**
    Return the number of bytes difference between 'end' and 'start'.
    @param[in] end A pointer to valid memory, greater or equal to 'start'
    @param[in] start A pointer to valid memory, less than or equal to 'start'
    @param sanity The maximum expected difference in bytes
    @return Number of bytes that 'end' is greater than 'start'. Range is 0 <= return <= sanity.
        If end < start, 0 is returned. If 'end' - 'start' > 'sanity', 'sanity' is returned.
 */
__inline static size_t ptrdiff_safe(const void *end, const void *start, size_t sanity)
{
    ptrdiff_t d;

    if (end < start)
    {
        return 0;
    }
    d = end - start;
    if (d > sanity)
    {
        return sanity;
    }
    return (size_t) d;
}

/**
    Example function to retrieve a CRL using HTTP GET over POSIX sockets.
    @security This API does not fully validate all input. It should only be used to fetch
    a CRL froa trusted source with validly generated CRL data. The HTTP response of the
    trusted server should also be tested, as the HTTP parsing in this API is not flexible.
    @param [out] crlBuf is allocated by this routine and must be freed via psFree
    @return < 0 Error loading CRL. 0 on Success
 */
int32 fetchCRL(psPool_t *pool, char *url, uint32_t urlLen,
    unsigned char **crlBuf, uint32_t *crlBufLen)
{
    static unsigned char crl_getHdr[] = "GET ";

#  define GET_OH_LEN      4
    static unsigned char crl_httpHdr[] = " HTTP/1.0\r\n";
#  define HTTP_OH_LEN     11
    static unsigned char crl_hostHdr[] = "Host: ";
#  define HOST_OH_LEN     6
    static unsigned char crl_acceptHdr[] = "\r\nAccept: */*\r\n\r\n";
#  define ACCEPT_OH_LEN   17
#  define HOST_ADDR_LEN   64    /* max to hold 'www.something.com' */
#  define GET_REQ_LEN     128   /* max to hold http GET request */
#  define HTTP_REPLY_CHUNK_SIZE   2048

    SOCKET fd;
    struct hostent *ip;
    struct in_addr intaddr;
    char *pageStart, *replyPtr, *ipAddr;
    char hostAddr[HOST_ADDR_LEN], getReq[GET_REQ_LEN];
    int hostAddrLen, getReqLen, pageLen;
    ssize_t transferred;
    int32_t grown = 0;
    int32_t sawOK, sawContentLength, err, httpUriLen, port, offset;
    unsigned char crlChunk[HTTP_REPLY_CHUNK_SIZE + 1];
    unsigned char *crlBin;     /* allocated */
    uint32_t crlBinLen;

    /* Is URI in expected URL form? */
    if (strstr(url, "http://") == NULL)
    {
        if (strstr(url, "https://") == NULL)
        {
            _psTraceStr("fetchCRL: Unsupported CRL URI: %s\n", url);
            return -1;
        }
        httpUriLen = 8;
        port = 80; /* No example yet of using SSL to fetch CRL */
    }
    else
    {
        httpUriLen = 7;
        port = 80;
    }

    /* Parsing host and page and setting up IP address and GET request */
    if ((pageStart = strchr(url + httpUriLen, '/')) == NULL)
    {
        _psTrace("fetchCRL: No host/page divider found\n");
        return -1;
    }
    if ((hostAddrLen = (int) (pageStart - url) - httpUriLen) > HOST_ADDR_LEN)
    {
        _psTrace("fetchCRL: HOST_ADDR_LEN needs to be increased\n");
        return -1; /* ipAddr too small to hold */
    }

    memset(hostAddr, 0, HOST_ADDR_LEN);
    memcpy(hostAddr, url + httpUriLen, hostAddrLen);
    if ((ip = gethostbyname(hostAddr)) == NULL)
    {
        _psTrace("fetchCRL: gethostbyname failed\n");
        return -1;
    }

    memcpy((char *) &intaddr, (char *) ip->h_addr_list[0],
        (size_t) ip->h_length);
    if ((ipAddr = inet_ntoa(intaddr)) == NULL)
    {
        _psTrace("fetchCRL: inet_ntoa failed\n");
        return -1;
    }

    pageLen = (urlLen - hostAddrLen - httpUriLen);
    getReqLen = pageLen + hostAddrLen + GET_OH_LEN + HTTP_OH_LEN +
                HOST_OH_LEN + ACCEPT_OH_LEN;
    if (getReqLen > GET_REQ_LEN)
    {
        _psTrace("fetchCRL: GET_REQ_LEN needs to be increased\n");
        return -1;
    }

    /* Build the request: */
    /*  */
    /*  GET /page.crl HTTP/1.0 */
    /*  Host: www.host.com */
    /*  Accept: * / * */
    /*  */
    memset(getReq, 0, GET_REQ_LEN);
    memcpy(getReq, crl_getHdr, GET_OH_LEN);
    offset = GET_OH_LEN;
    memcpy(getReq + offset, pageStart, pageLen);
    offset += pageLen;
    memcpy(getReq + offset, crl_httpHdr, HTTP_OH_LEN);
    offset += HTTP_OH_LEN;
    memcpy(getReq + offset, crl_hostHdr, HOST_OH_LEN);
    offset += HOST_OH_LEN;
    memcpy(getReq + offset, hostAddr, hostAddrLen);
    offset += hostAddrLen;
    memcpy(getReq + offset, crl_acceptHdr, ACCEPT_OH_LEN);

    /* Connect and send */
    fd = lsocketConnect(ipAddr, port, &err);
    if (fd == INVALID_SOCKET || err != PS_SUCCESS)
    {
        _psTraceInt("fetchCRL: socketConnect failed: %d\n", err);
        return PS_PLATFORM_FAIL;
    }

    /* Send request and receive response */
    offset = 0;
    while (getReqLen)
    {
        if ((transferred = send(fd, getReq + offset, getReqLen, 0)) < 0)
        {
            _psTraceInt("fetchCRL: socket send failed: %d\n", errno);
            close(fd);
            return PS_PLATFORM_FAIL;
        }
        getReqLen -= transferred;
        offset += transferred;
    }

    /* Get a chunk at a time so we can peek at the size on the first chunk
        and allocate the correct CRL size */
    crlBin = NULL;
    crlBinLen = 0;
    *crlBuf = NULL;
    *crlBufLen = 0;
    sawOK = sawContentLength = 0;

    /* This recv loop is not 100%.  The parse is looking for a few specific
        strings in the HTTP header to get initial status, content length,
        and \r\n\r\n for beginning of CRL data. If a recv happens to fall right
        on the boundary of any of these patterns, the behavior is undefined.
        There are some asserts sprinked around to notify if this happens.
        It SHOULD be sufficient to keep a decent size HTTP_REPLY_CHUNK_SIZE
        that you can be pretty sure will hold the entire HTTP header but
        the "recv" call itself is also a factor in how many bytes will be
        recevied in the first call */
    while ((transferred = recv(fd, crlChunk, HTTP_REPLY_CHUNK_SIZE, 0)) > 0)
    {
        crlChunk[transferred] = 0; /* Ensure zero termination for strstr(). */
        if (crlBin == NULL)
        {
            /* Still getting the details of the HTTP response */
            /* Did we get an OK response? */
            if (sawOK == 0)
            {
                if (strstr((const char *) crlChunk, "200 OK") == NULL)
                {
                    /* First chunk. Should be plenty large enough to hold */
                    _psTrace("fetchCRL: server reply was not '200 OK'\n");
                    close(fd);
                    return -1;
                }
                sawOK++;
            }
            /* Length parse */
            if (sawContentLength == 0)
            {
                if ((replyPtr = strstr((const char *) crlChunk,
                         "Content-Length: ")) == NULL)
                {

                    /* Apparently Content-Length is not always going to be
                        there.  See if we have the end of the header instead */
                    if ((replyPtr = strstr((const char *) crlChunk, "\r\n\r\n"))
                        == NULL)
                    {
                        continue; /* saw neither. keep trying */
                    }
                    /* Saw \r\n\r\n but no Content-Length: can't allocate full
                        CRL buffer at once so work in chunks */
                    crlBinLen = HTTP_REPLY_CHUNK_SIZE;
                }
                else
                {
                    /* Got the Content-Length: as expected */
                    sawContentLength++;

                    /* Possible cut off right at Content-Length here which
                        would be a pain.  This assert is seeing if there are
                        at least 8 more bytes in the chunk to read the
                        integer out of.  If you hit this, some partial
                        parsing will need to be instrumented... or change
                        the chunk size if this is truly a chunk boundary */
                    psAssert((replyPtr + 16) <
                        (char *) &(crlChunk[HTTP_REPLY_CHUNK_SIZE - 24]));


                    /* Magic 16 is length of "Content-Length: " */
                    crlBinLen = (int) atoi(replyPtr + 16);
                }
            }


            /* Data begins after CRLF CRLF */
            if ((replyPtr = strstr((const char *) crlChunk, "\r\n\r\n"))
                == NULL)
            {
                continue;
            }
            /* Possible cut off right at data start here which
                would be a pain.  This assert is seeing if there are
                4 more bytes in the chunk to advance past.  If you hit this,
                some partial parsing will need to be instrumented... or change
                the chunk size if this is truly a chunk boundary */
            psAssert((replyPtr + 4) < (char *) &(crlChunk[HTTP_REPLY_CHUNK_SIZE]));
            replyPtr += 4; /* Move past that "\r\n\r\n" to get to start */

            /* Check buffer length appears acceptable */
            if (crlBinLen < 1 || crlBinLen > CRL_MAX_LENGTH)
            {
                _psTrace("fetchCRL: Unacceptable size for CRL\n");
                /* Note: If this fails you may need to check CRL_MAX_LENGTH,
                   as you possibly need to allow larger CRL. */
                close(fd);
                return -1;
            }

            /* Allocate the CRL buffer. Will be full size if sawContentLength */
            if ((crlBin = psMalloc(pool, crlBinLen)) == NULL)
            {
                _psTrace("fetchCRL: Memory allocation error for CRL buffer\n");
                close(fd);
                return -1;
            }

            /* So how much do we actually have to copy our of first chunk? */
            transferred -= ptrdiff_safe(replyPtr, crlChunk, HTTP_REPLY_CHUNK_SIZE);

            if (sawContentLength)
            {
                /* Will march crlBin forward so just assign output crlBuf now */
                *crlBuf = crlBin;
                *crlBufLen = crlBinLen;
                memcpy(crlBin, replyPtr, transferred);
                crlBin += transferred;
                psAssert((crlBin - *crlBuf) <= crlBinLen);
            }
            else
            {
                grown = 1;
                /* Keep track of index to monitor size */
                crlBinLen = transferred;
                memcpy(crlBin, replyPtr, transferred);
            }
        }
        else
        {
            /* subsequent recv calls */
            if (sawContentLength)
            {
                memcpy(crlBin, crlChunk, transferred);
                crlBin += transferred;
                psAssert((crlBin - *crlBuf) <= crlBinLen);
            }
            else
            {
                if (transferred + crlBinLen > (HTTP_REPLY_CHUNK_SIZE * grown))
                {
                    /* not enough room.  psRealloc */
                    grown++;
                    crlBin = psRealloc(crlBin, HTTP_REPLY_CHUNK_SIZE * grown,
                        pool);
                }
                memcpy(crlBin + crlBinLen, crlChunk, transferred);
                crlBinLen += transferred;
            }
        }
    }
    close(fd);
    if (sawContentLength == 0)
    {
        /* These have been changing as we grow */
        *crlBuf = crlBin;
        *crlBufLen = crlBinLen;
    }
    else
    {
        psAssert(crlBinLen == (crlBin - *crlBuf));
    }

    return 0;

}
# endif /* USE_CRL */


/******************************************************************************/
/*
    Open an outgoing blocking socket connection to a remote ip and port.
    Caller should always check *err value, even if a valid socket is returned
 */
static SOCKET lsocketConnect(char *ip, int32 port, int32 *err)
{
    struct sockaddr_in addr;
    SOCKET fd;
    int32 rc;

    /* By default, this will produce a blocking socket */
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        perror("socket()");
        _psTrace("Error creating socket\n");
        *err = SOCKET_ERRNO;
        return INVALID_SOCKET;
    }
# ifdef POSIX
    rc = fcntl(fd, F_SETFD, FD_CLOEXEC);
    psAssert(rc >= 0);
# endif
# if 0
    {
        struct linger lin;
        rc = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &rc, sizeof(rc));
        rc = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &rc, sizeof(rc));
        lin.l_onoff = 0;
        lin.l_linger = 0; /* Seconds */
        setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &lin, sizeof(struct linger));
    }
    {
        uint32 len;
        getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rc, &len);
        printf("SO_RCVBUF: %d\n", rc);
    }
# endif
# ifdef POSIX
/*      rc = 1; */
/*      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&rc, sizeof(rc)); */
/*      fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); */
# elif defined(WIN32)
/*      rc = 1;     / * 1 for non-block, 0 for block * / */
/*      ioctlsocket(fd, FIONBIO, &rc); */
# endif
# ifdef __APPLE__ /* MAC OS X */
    rc = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *) &rc, sizeof(rc));
# endif
    memset((char *) &addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short) port);
    addr.sin_addr.s_addr = inet_addr(ip);
    rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0)
    {
        close(fd);
        perror("connect()");
        *err = SOCKET_ERRNO;
    }
    else
    {
        *err = 0;
    }
    return fd;
}
#else

/******************************************************************************/
/*
    Stub main for compiling without client enabled
 */
int32 main(int32 argc, char **argv)
{
    printf("USE_CLIENT_SIDE_SSL must be enabled in matrixsslConfig.h at build" \
        " time to run this application\n");
    return EXIT_FAILURE;
}
#endif /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/

