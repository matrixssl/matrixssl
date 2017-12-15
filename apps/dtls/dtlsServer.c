/**
 *      @file    dtlsServer.c
 *      @version $Format:%h%d$
 *
 *      Sample DTLS server.
 *      Supports multiple simultaneous clients and non-blocking sockets
 */
/*
 *      Copyright (c) 2014-2017 INSIDE Secure Corporation
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

#include <signal.h>         /* Defines SIGTERM, etc. */
#ifdef OSX
# include <sys/select.h>    /* Defines fd_set, etc. */
# define MSG_NOSIGNAL 0
#endif

#include "dtlsCommon.h"
/* Currently this example uses _psTrace for tracing, so osdep.h is needed: */
#include "core/osdep.h"
#include "core/psUtil.h"

#ifdef USE_DTLS

# include "../../crypto/cryptoApi.h"

/* #define USE_CERT_VALIDATOR */

static int packet_loss_prob = 0; /* Reciprocal of packet loss probability
                                    (i.e. P(packet loss) = 1/x).
                                    Default value is 0 (no packet loss). */
/*
    Client management
 */
# define MAX_CLIENTS 16

typedef struct
{
    psTime_t lastRecvTime;
    uint32 timeout;              /* in seconds */
    uint32 connStatus;
    SOCKET fd;
    struct sockaddr_in addr;
    ssl_t *ssl;
} serverDtls_t;

static serverDtls_t *clientTable;
static psSize_t tableSize;

# define RESUMED_HANDSHAKE_COMPLETE 1

/* Static Prototypes */
static int32 initClientList(uint16 maxPeers);
static int32 handleResends(SOCKET sock);
static serverDtls_t *findClient(struct sockaddr_in addr);
static serverDtls_t *registerClient(struct sockaddr_in addr, SOCKET sock,
                                    ssl_t *ssl);
static void clearClient(serverDtls_t *dtls);
static void closeClientList();
static SOCKET newUdpSocket(char *ip, short port, int *err);
static int sigsetup(void);
static void sigsegv_handler(int);
static void sigintterm_handler(int);
static void usage(void);
static int32 process_cmd_options(int32 argc, char **argv);

# ifdef USE_DTLS_DEBUG_TRACE
static unsigned char *getaddrstring(struct sockaddr *addr, int withport);
# endif

# ifndef MATRIX_TESTING_ENVIRONMENT /* Omit the message when testing. */
#  ifdef WIN32
#   pragma message("DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS.")
#  else
#   warning "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#  endif
# endif

/*      Pick ONE cipher suite type you want to use to auto select a certificate
    and private key identity that support those algorithms.

    In general, it works the other way: a server would obtain an identity
    certificate and private key and then only enable cipher suites that the
    material supports.
 */
/* #define ID_RSA / * Standard RSA suites.  RSA Key Exchange and Authentication * / */
/* #define ID_DHE_RSA / * Diffie-Hellman key exchange.  RSA Authentication * / */
/* #define ID_DH_ANON / * Diffie-Hellman key exchange.  No auth * / */
/* #define ID_DHE_PSK / * Diffie-Hellman key exchange.  Pre-Shared Key Auth * / */
/* #define ID_PSK / * Basic Pre-Shared Key suites * / */
/* #define ID_ECDH_ECDSA / * Elliptic Curve Key Exchange and Authentication * / */
/* #define ID_ECDHE_ECDSA / * Same as above with ephemeral Key Exchange * / */
/* #define ID_ECDHE_RSA / * Ephemeral EC Key Exchange, RSA Authentication * / */
/* #define ID_ECDH_RSA / * EC Key Exchange, RSA Authentication * / */

# ifdef ID_RSA
#  ifndef USE_RSA
#   error USE_RSA shall be defined for ID_RSA
#  endif /* USE_RSA */
# endif  /* ID_RSA */

# ifdef ID_DHE_RSA
#  if !defined(USE_DH) || !defined(USE_RSA)
#   error USE_DH and USE_RSA shall be defined for ID_DHE_RSA
#  endif /* USE_DH || USE_RSA */
# endif  /* ID_DHE_RSA */

# if defined(ID_DH_ANON) || defined(ID_DHE_PSK)
#  ifndef USE_DH
#   error USE_DH shall be defined for ID_DH_ANON and ID_DHE_PSK
#  endif /* USE_DH */
# endif  /* ID_DH_ANON */

# if defined(ID_ECDH_ECDSA) || defined(ID_ECDHE_ECDSA)
#  ifndef USE_ECC
#   error USE_ECC shall be defined for ID_ECDH_ECDSA and ID_ECDHE_ECDSA
#  endif /* USE_ECC */
# endif  /* ID_ECDH_ECDSA || ID_ECDHE_ECDSA */

# if defined(ID_ECDHE_RSA) || defined(ID_ECDH_RSA)
#  if !defined(USE_ECC) || !defined(USE_RSA)
#   error USE_ECC and USE_RSA shall be defined for ID_ECDHE_RSA and ID_ECDH_RSA
#  endif /* USE_ECC || USE_RSA */
# endif  /* ID_ECDHE_RSA || ID_ECDH_RSA */


# define ALLOW_ANON_CONNECTIONS  1
# define USE_HEADER_KEYS


/*      The keys that are loaded are compatible with the MatrixSSL sample client.
    The CA files loaded assume the same authentication mechanism as the
    cipher suite
 */
# ifdef USE_HEADER_KEYS
/* Identity Key and Cert */
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


#  if defined(ID_DHE_RSA) || defined(ID_ECDHE_RSA)
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

#  if defined(ID_ECDHE_ECDSA) || defined(ID_ECDH_ECDSA)
#   define EXAMPLE_EC_KEYS
#   include "testkeys/EC/192_EC.h"
#   include "testkeys/EC/192_EC_KEY.h"
#   include "testkeys/EC/224_EC.h"
#   include "testkeys/EC/224_EC_KEY.h"
#   include "testkeys/EC/256_EC.h"
#   include "testkeys/EC/256_EC_KEY.h"
#   include "testkeys/EC/384_EC.h"
#   include "testkeys/EC/384_EC_KEY.h"
#   include "testkeys/EC/521_EC.h"
#   include "testkeys/EC/521_EC_KEY.h"
#  endif

#  ifdef ID_ECDH_RSA
#   define EXAMPLE_ECDH_RSA_KEYS
#   include "testkeys/ECDH_RSA/256_ECDH-RSA.h"
#   include "testkeys/ECDH_RSA/256_ECDH-RSA_KEY.h"
#   include "testkeys/ECDH_RSA/521_ECDH-RSA.h"
#   include "testkeys/ECDH_RSA/521_ECDH-RSA_KEY.h"
#  endif

#  ifdef REQUIRE_DH_PARAMS
#   include "testkeys/DH/2048_DH_PARAMS.h"
#  endif


/*      CA files for client auth are selected more generously.  If the algorithm
    type is supported, we'll load it */
#  ifdef USE_RSA
#   include "testkeys/RSA/ALL_RSA_CAS.h"
#   ifdef USE_ECC
#    include "testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.h"
#   endif /* USE_ECC */
#  endif  /* USE_RSA */
#  ifdef USE_ECC

#   if defined(USE_SECP192R1) && defined(USE_SECP224R1) && defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS.h"
#   endif /* USE_SECP192R1 && USE_SECP224R1 && USE_SECP521R1 */

#   if !defined(USE_SECP192R1) && defined(USE_SECP224R1) && defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192.h"
#   endif /* !USE_SECP192R1 && USE_SECP224R1 && USE_SECP521R1 */

#   if defined(USE_SECP192R1) && !defined(USE_SECP224R1) && defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P224.h"
#   endif /* USE_SECP192R1 && !USE_SECP224R1 && USE_SECP521R1 */

#   if defined(USE_SECP192R1) && defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P521.h"
#   endif /* USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#   if !defined(USE_SECP192R1) && !defined(USE_SECP224R1) && defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192_AND_P224.h"
#   endif /* !USE_SECP192R1 && !USE_SECP224R1 && USE_SECP521R1 */

#   if !defined(USE_SECP192R1) && defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192_AND_P521.h"
#   endif /* !USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#   if defined(USE_SECP192R1) && !defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P224_AND_P521.h"
#   endif /* USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#   if !defined(USE_SECP192R1) && !defined(USE_SECP224R1) && !defined(USE_SECP521R1)
#    include "testkeys/EC/ALL_EC_CAS_EXCEPT_P192_P224_AND_P521.h"
#   endif /* !USE_SECP192R1 && USE_SECP224R1 && !USE_SECP521R1 */

#  endif  /* USE_ECC */


/* File-based keys */
# else
#  ifdef ID_RSA
#   define EXAMPLE_RSA_KEYS
static char rsaCertFile[] = "testkeys/RSA/2048_RSA.pem";
static char rsaPrivkeyFile[] = "testkeys/RSA/2048_RSA_KEY.pem";
#  endif


#  if defined(ID_DHE_RSA) || defined(ID_ECDHE_RSA)
#   define EXAMPLE_RSA_KEYS
static char rsaCertFile[] = "testkeys/RSA/2048_RSA.pem";
static char rsaPrivkeyFile[] = "testkeys/RSA/2048_RSA_KEY.pem";
#  endif

#  if defined(ID_ECDHE_ECDSA) || defined(ID_ECDH_ECDSA)
#   define EXAMPLE_EC_KEYS
static char ecCertFile[] = "testkeys/EC/256_EC.pem";
static char ecPrivkeyFile[] = "testkeys/EC/256_EC_KEY.pem";
#  endif

#  ifdef ID_ECDH_RSA
#   define EXAMPLE_ECDH_RSA_KEYS
static char ecdhRsaCertFile[] = "testkeys/ECDH_RSA/256_ECDH-RSA.pem";
static char ecdhRsaPrivkeyFile[] = "testkeys/ECDH_RSA/256_ECDH-RSA_KEY.pem";
#  endif

#  ifdef REQUIRE_DH_PARAMS
static char dhParamFile[] = "testkeys/DH/2048_DH_PARAMS.pem";
#  endif


/*      CA files for client auth are selected more generously.  If the algorithm
    type is supported, we'll load it */
#  ifdef USE_RSA
static char rsaCAFile[] = "testkeys/RSA/ALL_RSA_CAS.pem";
static char rsaCA3072File[] = "testkeys/RSA/3072_RSA_CA.pem";
#   ifdef USE_ECC
static char ecdhRsaCAFile[] = "testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.pem";
#   endif /* USE_ECC */
#  endif  /* USE_RSA */
#  ifdef USE_ECC

#   if defined(USE_SECP192R1) && defined(USE_SECP521R1)
static char ecCAFile[] = "testkeys/EC/ALL_EC_CAS.pem";
#   endif /* USE_SECP192R1 && USE_SECP521R1 */

#   if !defined(USE_SECP192R1) && defined(USE_SECP521R1)
static char ecCAFile[] = "testkeys/EC/ALL_EC_CAS_EXCEPT_P192.pem";
#   endif /* USE_SECP192R1 && USE_SECP521R1 */

#   if defined(USE_SECP192R1) && !defined(USE_SECP521R1)
static char ecCAFile[] = "testkeys/EC/ALL_EC_CAS_EXCEPT_P521.pem";
#   endif /* USE_SECP192R1 && USE_SECP521R1 */

#   if !defined(USE_SECP192R1) && !defined(USE_SECP521R1)
static char ecCAFile[] = "testkeys/EC/ALL_EC_CAS_EXCEPT_P192_AND_P521.pem";
#   endif /* USE_SECP192R1 && USE_SECP521R1 */

#  endif  /* USE_ECC */

# endif   /* USE_FILE_KEYS */


# ifdef USE_PSK_CIPHER_SUITE
#  include "testkeys/PSK/psk.h"
# endif /* PSK */



static int exitFlag;

static uint32_t g_rsaKeySize;
static uint32_t g_eccKeySize;
static uint32_t g_ecdhKeySize;
static int g_port;

# ifdef USE_CERT_VALIDATOR
/******************************************************************************/
/*
   Stub for a user-level certificate validator.  Just using
   the default validation value here.
 */
static int32 certValidator(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
    /* Example to allow anonymous connections based on a define */
    if (alert > 0)
    {
        if (ALLOW_ANON_CONNECTIONS)
        {
            /* Could be NULL if SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG */
            if (cert)
            {
                _psTraceStr("Allowing anonymous connection for: %s.\n",
                    cert->subject.commonName);
            }
            else
            {
                _psTrace("Client didn't send certificate. Reverting to standard handshake due to SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG\n");
            }
            return SSL_ALLOW_ANON_CONNECTION;
        }
        _psTrace("Certificate callback returning fatal alert\n");
        return alert;
    }
    _psTraceStr("Validated cert for: %s.\n", cert->subject.commonName);
    return 0;
}
# else
/* No certificate validator is needed */
#  define certValidator NULL
# endif /* USE_CERT_VALIDATOR */

static void usage(void)
{
    printf("\nusage: dltsServer { option }\n"
        "\n"
        "where option can be one of the following:\n"
        "\n"
        "-h                      - Print usage and exit\n"
        "-r <keyLen>             - RSA keyLen (1024|2048|3072|4096)\n"
        "-e <keyLen>             - ECC keyLen (192|224|256|384|521)"
        "-d <keyLen>             - ECDH_RSA keyLen (256|521)\n"
# ifdef DTLS_PACKET_LOSS_TEST
        "-l <value>              - Reciprocal of packet loss probability\n"
        "                          (for packet loss simulation tests)\n"
# endif /* DTLS_PACKET_LOSS_TEST */
        "-p <value>              - Port number to use\n"
        );
}

/* Return 0 on good set of cmd options, return -1 if a bad cmd option is
   encountered OR a request for help is seen (i.e. '-h' option). */
static int32 process_cmd_options(int32 argc, char **argv)
{
    int32 optionChar;

    /* Set some default options: */
    g_rsaKeySize = 2048;
    g_eccKeySize = g_ecdhKeySize = 256;

    opterr = 0;
    while ((optionChar = getopt(argc, argv, "hr:e:d:l:p:")) != -1)
    {
        switch (optionChar)
        {
        case '?':
            return -1;

        case 'h':
            break;

        case 'r':
            g_rsaKeySize = atoi(optarg);
            if ((g_rsaKeySize != 1024) && (g_rsaKeySize != 2048)
                && (g_rsaKeySize != 3072) && (g_rsaKeySize != 4096))
            {
                printf("invalid -r option\n");
                return -1;
            }
            break;

        case 'e':
            g_eccKeySize = atoi(optarg);
            if ((g_eccKeySize != 192) && (g_eccKeySize != 224)
                && (g_eccKeySize != 256) && (g_eccKeySize != 384)
                && (g_eccKeySize != 521))
            {
                printf("invalid -e option\n");
                return -1;
            }
            break;

        case 'd':
            g_ecdhKeySize = atoi(optarg);
            if ((g_ecdhKeySize != 256) && (g_ecdhKeySize != 521))
            {
                printf("invalid -d option\n");
                return -1;
            }
            break;

# ifdef DTLS_PACKET_LOSS_TEST
        case 'l':
            packet_loss_prob = atoi(optarg);
            if (packet_loss_prob < 0)
            {
                printf("invalid -l option\n");
                return -1;
            }
            if (packet_loss_prob > 0)
            {
                printf("Server simulating packet loss with probability 1/%d\n",
                    packet_loss_prob);
            }
            break;
# endif     /* DTLS_PACKET_LOSS_TEST */
        case 'p':
            g_port = atoi(optarg);
            if (g_port < 0)
            {
                printf("invalid -p option\n");
                return -1;
            }
        }
    }

    return 0;
}

/******************************************************************************/
/*
    Main
 */
int main(int argc, char **argv)
{
    struct sockaddr_in inaddr;
    socklen_t inaddrlen;
    struct timeval timeout;
    ssl_t *ssl;
    serverDtls_t *dtlsCtx;
    SOCKET sock;
    fd_set readfd;
    unsigned char *sslBuf, *recvfromBuf, *CAstream;

# ifdef USE_DTLS_DEBUG_TRACE
    unsigned char *addrstr;
# endif
# if !defined(ID_PSK) && !defined(ID_DHE_PSK)
    unsigned char *keyValue, *certValue;
    int32 keyLen, certLen;
# endif
    sslKeys_t *keys;
    int32 freeBufLen, rc, val, recvLen, err, CAstreamLen;
    int32 sslBufLen, rcr, rcs, sendLen, recvfromBufLen;
    sslSessOpts_t options;

# ifdef WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(1, 1), &wsaData);
# endif

    rc = 0;
    ssl = NULL;
    dtlsCtx = NULL;
    CAstream = NULL;
    sock = INVALID_SOCKET;

    if (0 != process_cmd_options(argc, argv))
    {
        usage();
        return 0;
    }
    if (sigsetup() < 0)
    {
        _psTrace("Init error creating signal handlers\n");
        return DTLS_FATAL;
    }
    if (matrixSslOpen() < 0)
    {
        _psTrace("Init error opening MatrixDTLS library\n");
        return DTLS_FATAL;
    }
    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        _psTrace("Init error allocating key structure\n");
        matrixSslClose();
        return DTLS_FATAL;
    }
    if ((rc = initClientList(MAX_CLIENTS)) < 0)
    {
        _psTrace("Init error opening client list\n");
        goto MATRIX_EXIT;
    }

# ifdef USE_HEADER_KEYS
/*
    In-memory based keys
    Build the CA list first for potential client auth usage
 */
    CAstreamLen = 0;
#  ifdef USE_RSA
    CAstreamLen += sizeof(RSACAS);
#   ifdef USE_ECC
    CAstreamLen += sizeof(ECDHRSACAS);
#   endif
#  endif
#  ifdef USE_ECC
    CAstreamLen += sizeof(ECCAS);
#  endif
    CAstream = psMalloc(NULL, CAstreamLen);

    CAstreamLen = 0;
#  ifdef USE_RSA
    memcpy(CAstream, RSACAS, sizeof(RSACAS));
    CAstreamLen += sizeof(RSACAS);
#   ifdef USE_ECC
    memcpy(CAstream + CAstreamLen, ECDHRSACAS, sizeof(ECDHRSACAS));
    CAstreamLen += sizeof(ECDHRSACAS);
#   endif
#  endif
#  ifdef USE_ECC
    memcpy(CAstream + CAstreamLen, ECCAS, sizeof(ECCAS));
    CAstreamLen += sizeof(ECCAS);
#  endif

#  ifdef EXAMPLE_RSA_KEYS
    switch (g_rsaKeySize)
    {
    case 1024:
        certValue = (unsigned char *) RSA1024;
        certLen = sizeof(RSA1024);
        keyValue = (unsigned char *) RSA1024KEY;
        keyLen = sizeof(RSA1024KEY);
        break;
    case 2048:
        certValue = (unsigned char *) RSA2048;
        certLen = sizeof(RSA2048);
        keyValue = (unsigned char *) RSA2048KEY;
        keyLen = sizeof(RSA2048KEY);
        break;
    case 3072:
        certValue = (unsigned char *) RSA3072;
        certLen = sizeof(RSA3072);
        keyValue = (unsigned char *) RSA3072KEY;
        keyLen = sizeof(RSA3072KEY);
        break;
    case 4096:
        certValue = (unsigned char *) RSA4096;
        certLen = sizeof(RSA4096);
        keyValue = (unsigned char *) RSA4096KEY;
        keyLen = sizeof(RSA4096KEY);
        break;
    default:
        _psTraceInt("Invalid RSA key length (%d)\n", g_rsaKeySize);
        goto CLIENT_EXIT;
    }

    if ((rc = matrixSslLoadRsaKeysMem(keys, (const unsigned char *) certValue,
             certLen, (const unsigned char *) keyValue, keyLen, CAstream,
             CAstreamLen)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        goto CLIENT_EXIT;
    }
#  endif


#  ifdef EXAMPLE_ECDH_RSA_KEYS
    switch (g_ecdhKeySize)
    {
    case 256:
        certValue = (unsigned char *) ECDHRSA256;
        certLen = sizeof(ECDHRSA256);
        keyValue = (unsigned char *) ECDHRSA256KEY;
        keyLen = sizeof(ECDHRSA256KEY);
        break;
    case 521:
        certValue = (unsigned char *) ECDHRSA521;
        certLen = sizeof(ECDHRSA521);
        keyValue = (unsigned char *) ECDHRSA521KEY;
        keyLen = sizeof(ECDHRSA521KEY);
        break;
    default:
        _psTraceInt("Invalid ECDH_RSA key length (%d)\n", g_ecdhKeySize);
        goto CLIENT_EXIT;
    }

    if ((rc = matrixSslLoadEcKeysMem(keys, (const unsigned char *) certValue,
             certLen, (const unsigned char *) keyValue, keyLen, CAstream,
             CAstreamLen)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        goto CLIENT_EXIT;
    }
#  endif

#  ifdef EXAMPLE_EC_KEYS
    switch (g_eccKeySize)
    {
    case 192:
        certValue = (unsigned char *) EC192;
        certLen = sizeof(EC192);
        keyValue = (unsigned char *) EC192KEY;
        keyLen = sizeof(EC192KEY);
        break;
    case 224:
        certValue = (unsigned char *) EC224;
        certLen = sizeof(EC224);
        keyValue = (unsigned char *) EC224KEY;
        keyLen = sizeof(EC224KEY);
        break;
    case 256:
        certValue = (unsigned char *) EC256;
        certLen = sizeof(EC256);
        keyValue = (unsigned char *) EC256KEY;
        keyLen = sizeof(EC256KEY);
        break;
    case 384:
        certValue = (unsigned char *) EC384;
        certLen = sizeof(EC384);
        keyValue = (unsigned char *) EC384KEY;
        keyLen = sizeof(EC384KEY);
        break;
    case 521:
        certValue = (unsigned char *) EC521;
        certLen = sizeof(EC521);
        keyValue = (unsigned char *) EC521KEY;
        keyLen = sizeof(EC521KEY);
        break;
    default:
        _psTraceInt("Invalid ECC key length (%d)\n", g_eccKeySize);
        goto CLIENT_EXIT;
    }

    if ((rc = matrixSslLoadEcKeysMem(keys, certValue, certLen,
             keyValue, keyLen, CAstream, CAstreamLen)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        goto CLIENT_EXIT;
    }
#  endif

#  ifdef REQUIRE_DH_PARAMS
    if (matrixSslLoadDhParamsMem(keys, DHPARAM2048, DHPARAM2048_SIZE) < 0)
    {
        _psTrace("Unable to load DH parameters\n");
    }
#  endif /* DH_PARAMS */

# else /* USE_HEADER_KEYS */
/*
    File based keys
    Build the CA list first for potential client auth usage
 */
    CAstreamLen = 0;
#  ifdef USE_RSA
    if (g_rsaKeySize == 3072)
    {
        CAstreamLen += (int32) strlen(rsaCA3072File) + 1;
    }
    else
    {
        CAstreamLen += (int32) strlen(rsaCAFile) + 1;
    }
#   ifdef USE_ECC
    CAstreamLen += (int32) strlen(ecdhRsaCAFile) + 1;
#   endif
#  endif
#  ifdef USE_ECC
    CAstreamLen += (int32) strlen(ecCAFile) + 1;
#  endif
    CAstream = psMalloc(NULL, CAstreamLen);
    memset(CAstream, 0x0, CAstreamLen);

    CAstreamLen = 0;
#  ifdef USE_RSA
    if (g_rsaKeySize == 3072)
    {
        memcpy(CAstream, rsaCA3072File, strlen(rsaCA3072File));
        CAstreamLen += strlen(rsaCA3072File);
    }
    else
    {
        memcpy(CAstream, rsaCAFile, strlen(rsaCAFile));
        CAstreamLen += strlen(rsaCAFile);
    }
#   ifdef USE_ECC
    memcpy(CAstream + CAstreamLen, ";", 1); CAstreamLen++;
    memcpy(CAstream + CAstreamLen, ecdhRsaCAFile,  strlen(ecdhRsaCAFile));
    CAstreamLen += strlen(ecdhRsaCAFile);
#   endif
#  endif
#  ifdef USE_ECC
    if (CAstreamLen > 0)
    {
        memcpy(CAstream + CAstreamLen, ";", 1); CAstreamLen++;
    }
    memcpy(CAstream + CAstreamLen, ecCAFile,  strlen(ecCAFile));
#  endif

/* Load Identiy */
#  ifdef EXAMPLE_RSA_KEYS
    if ((rc = matrixSslLoadRsaKeys(keys, rsaCertFile, rsaPrivkeyFile, NULL,
             (char *) CAstream)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        goto CLIENT_EXIT;
    }
#  endif

#  ifdef EXAMPLE_ECDH_RSA_KEYS
    if ((rc = matrixSslLoadEcKeys(keys, ecdhRsaCertFile, ecdhRsaPrivkeyFile,
             NULL, (char *) CAstream)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        goto CLIENT_EXIT;
    }
#  endif

#  ifdef EXAMPLE_EC_KEYS
    if ((rc = matrixSslLoadEcKeys(keys, ecCertFile, ecPrivkeyFile, NULL,
             (char *) CAstream)) < 0)
    {
        _psTrace("No certificate material loaded.  Exiting\n");
        goto CLIENT_EXIT;
    }
#  endif

#  ifdef REQUIRE_DH_PARAMS
    if (matrixSslLoadDhParams(keys, dhParamFile) < 0)
    {
        _psTrace("Unable to load DH parameters\n");
    }
#  endif

# endif /* USE_HEADER_KEYS */

    psFree(CAstream, NULL);
    CAstream = NULL;

# ifdef USE_PSK_CIPHER_SUITE
    /* The first ID is considered as null-terminiated string for
       compatibility with OpenSSL's s_client default client identity
       "Client_identity" */

    matrixSslLoadPsk(keys,
        PSK_HEADER_TABLE[0].key,
        sizeof(PSK_HEADER_TABLE[0].key),
        PSK_HEADER_TABLE[0].id,
        strlen((const char *) PSK_HEADER_TABLE[0].id));

    for (rc = 1; rc < PSK_HEADER_TABLE_COUNT; rc++)
    {
        matrixSslLoadPsk(keys,
            PSK_HEADER_TABLE[rc].key,
            sizeof(PSK_HEADER_TABLE[rc].key),
            PSK_HEADER_TABLE[rc].id,
            sizeof(PSK_HEADER_TABLE[rc].id));
    }
# endif /* PSK */

    recvfromBufLen = matrixDtlsGetPmtu();
    if ((recvfromBuf = psMalloc(MATRIX_NO_POOL, recvfromBufLen)) == NULL)
    {
        rc = PS_MEM_FAIL;
        _psTrace("Init error allocating receive buffer\n");
        goto CLIENT_EXIT;
    }

    if ((sock = newUdpSocket(NULL, g_port, &err)) == INVALID_SOCKET)
    {
        _psTrace("Error creating UDP socket\n");
        goto DTLS_EXIT;
    }
    _psTraceInt("DTLS server running on port %d\n", g_port);

    /* Server loop */
    for (exitFlag = 0; exitFlag == 0; )
    {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        FD_ZERO(&readfd);
        FD_SET(sock, &readfd);
/*
        Always just wait a second for any incoming data.  The primary loop
        mechanism reads data from one source and replies with handshake data
        if needed (that reply may be a resend if reading a repeat message).
        Individual client timeouts are then handled
 */
        val = select(sock + 1, &readfd, NULL, NULL, &timeout);

        if (val > 0 && FD_ISSET(sock, &readfd))
        {
            psTraceIntDtls("Select woke %d\n", val);
            /* recvfrom data must always go into generic buffer becuase we
               don't yet know who it is from */
            inaddrlen = sizeof(struct sockaddr_in);
            if ((recvLen = (int32) recvfrom(sock, recvfromBuf, recvfromBufLen, 0,
                     (struct sockaddr *) &inaddr, &inaddrlen)) < 0)
            {
# ifdef WIN32
                if (SOCKET_ERRNO != EWOULDBLOCK &&
                    SOCKET_ERRNO != WSAECONNRESET)
                {
# else
                if (SOCKET_ERRNO != EWOULDBLOCK)
                {
# endif
                    _psTraceInt("recvfrom error %d.  Exiting\n", SOCKET_ERRNO);
                    goto DTLS_EXIT;
                }
                continue;
            }
# ifdef USE_DTLS_DEBUG_TRACE
            /* nice for debugging */
            {
                const char *addrstr;
                addrstr = getaddrstring((struct sockaddr *) &inaddr, 1);
                psTraceIntDtls("Read %d bytes ", recvLen);
                _psTraceStr("from %s\n", (char *) addrstr);
                psFree(addrstr, NULL);
            }
# endif

            /* Locate the SSL context of this receive and create a new session
               if not found */
            if ((dtlsCtx = findClient(inaddr)) == NULL)
            {
                memset(&options, 0x0, sizeof(sslSessOpts_t));
                options.versionFlag = SSL_FLAGS_DTLS;
                options.truncHmac = -1;

                if (matrixSslNewServerSession(&ssl, keys,
                        certValidator, &options) < 0)
                {
                    rc = DTLS_FATAL; goto DTLS_EXIT;
                }
                if ((dtlsCtx = registerClient(inaddr, sock, ssl)) == NULL)
                {
                    /* Client list is full.  Just have to ignore */
                    matrixSslDeleteSession(ssl);
                    continue;
                }
            }

            ssl = dtlsCtx->ssl;
            /*  Move socket data into internal buffer */
            freeBufLen = matrixSslGetReadbuf(ssl, &sslBuf);
            psAssert(freeBufLen >= recvLen);
            psAssert(freeBufLen == matrixDtlsGetPmtu());
            memcpy(sslBuf, recvfromBuf, recvLen);

            /*  Notify SSL state machine that we've received more data into the
               ssl buffer retreived with matrixSslGetReadbuf. */
            if ((rcr = matrixSslReceivedData(ssl, recvLen, &sslBuf,
                     (uint32 *) &freeBufLen)) < 0)
            {
                clearClient(dtlsCtx);
                continue;   /* Next connection */
            }
            /* Update last activity time and reset timeout*/
            psGetTime(&dtlsCtx->lastRecvTime, NULL);
            dtlsCtx->timeout = MIN_WAIT_SECS;

PROCESS_MORE_FROM_BUFFER:
            /* Process any incoming plaintext application data */
            switch (rcr)
            {
            case MATRIXSSL_HANDSHAKE_COMPLETE:
                /* This is a resumed handshake case which means we are
                   the last to receive handshake flights and we know the
                   handshake is complete.  However, the internal workings
                   will not flag us officially complete until we receive
                   application data from the peer so we need a local flag
                   to handle this case so we are not resending our final
                   flight */
                dtlsCtx->connStatus = RESUMED_HANDSHAKE_COMPLETE;
                psTraceDtls("Got HANDSHAKE_COMPLETE out of ReceivedData\n");
                break;
            case MATRIXSSL_APP_DATA:
                /* Now safe to clear the connStatus flag that was keeping
                   track of the state between receiving the final flight of
                   a resumed handshake and receiving application data.  The
                   reciept of app data has now internally disabled flight
                   resends */
                dtlsCtx->connStatus = 0;
                _psTrace("Client connected.  Received...\n");
                _psTraceStr("%s\n", (char *) sslBuf);
                break;
            case MATRIXSSL_REQUEST_SEND:
                /* Still handshaking with this particular client */
                while ((sslBufLen = matrixDtlsGetOutdata(ssl,
                            &sslBuf)) > 0)
                {
                    if ((sendLen = udpSend(dtlsCtx->fd, sslBuf, sslBufLen,
                             (struct sockaddr *) &inaddr,
                             sizeof(struct sockaddr_in),
                             dtlsCtx->timeout,
                             packet_loss_prob,
                             NULL)) < 0)
                    {
                        psTraceDtls("udpSend error.  Ignoring\n");
                    }
                    /* Always indicate the entire datagram was sent as
                       there is no way for DTLS to handle partial records.
                       Resends and timeouts will handle any problems */
                    rcs = matrixDtlsSentData(ssl, sslBufLen);

                    if (rcs == MATRIXSSL_REQUEST_CLOSE)
                    {
                        psTraceDtls("Got REQUEST_CLOSE out of SentData\n");
                        clearClient(dtlsCtx);
                        break;
                    }
                    if (rcs == MATRIXSSL_HANDSHAKE_COMPLETE)
                    {
                        /* This is the standard handshake case */
                        _psTrace("Got HANDSHAKE_COMPLETE from SentData\n");
                        break;
                    }
                    /* SSL_REQUEST_SEND is handled by loop logic */
                }
                break;
            case MATRIXSSL_REQUEST_RECV:
                psTraceDtls("Got REQUEST_RECV from ReceivedData\n");
                break;
            case MATRIXSSL_RECEIVED_ALERT:
                /* The first byte of the buffer is the level */
                /* The second byte is the description */
                if (*sslBuf == SSL_ALERT_LEVEL_FATAL)
                {
                    psTraceIntDtls("Fatal alert: %d, closing connection.\n",
                        *(sslBuf + 1));
                    clearClient(dtlsCtx);
                    continue;     /* Next connection */
                }
                /* Closure alert is normal (and best) way to close */
                if (*(sslBuf + 1) == SSL_ALERT_CLOSE_NOTIFY)
                {
                    clearClient(dtlsCtx);
                    continue;     /* Next connection */
                }
                psTraceIntDtls("Warning alert: %d\n", *(sslBuf + 1));
                if ((rcr = matrixSslProcessedData(ssl, &sslBuf,
                         (uint32 *) &freeBufLen)) == 0)
                {
                    continue;
                }
                goto PROCESS_MORE_FROM_BUFFER;

            default:
                continue;     /* Next connection */
            }
        }
        else if (val < 0)
        {
            if (SOCKET_ERRNO != EINTR)
            {
                psTraceIntDtls("unhandled error %d from select", SOCKET_ERRNO);
            }
        }
/*
        Have either timed out waiting for a read or have processed a single
        recv.  Now check to see if any timeout resends are required
 */
        rc = handleResends(sock);
    }   /* Main Select Loop */


DTLS_EXIT:
    psFree(recvfromBuf, NULL);
CLIENT_EXIT:
    if (CAstream)
    {
        psFree(CAstream, NULL);
    }
    closeClientList();
MATRIX_EXIT:
    matrixSslDeleteKeys(keys);
    matrixSslClose();
    if (sock != INVALID_SOCKET)
    {
        close(sock);
    }
    return rc;
}

/******************************************************************************/
/*
    Work through client list and resend handshake flight if haven't heard
    from them in a while
 */
static int32 handleResends(SOCKET sock)
{
    serverDtls_t *dtlsCtx;
    ssl_t *ssl;
    psTime_t now;
    unsigned char *sslBuf;
    int16_t i;
    int32_t sendLen, sslBufLen, rc;
    uint32_t timeout, clientCount;

    clientCount = 0; /* return code is number of active clients or < 0 on error */
    psGetTime(&now, NULL);
    for (i = 0; i < tableSize; i++)
    {
        dtlsCtx = &clientTable[i];
        if (dtlsCtx->ssl != NULL)
        {
            clientCount++;
            timeout = psDiffMsecs(dtlsCtx->lastRecvTime, now, NULL) / 1000;
            /* Haven't heard from this client in a while.  Might need resend */
            if (timeout > dtlsCtx->timeout)
            {
                /* if timeout is too great. clear conn */
                if (dtlsCtx->timeout >= MAX_WAIT_SECS)
                {
                    clearClient(dtlsCtx);
                    clientCount--;
                    break;
                }
                /* Increase the timeout for next pass */
                dtlsCtx->timeout *= 2;

                /* If we are in a RESUMED_HANDSHAKE_COMPLETE state that means
                   we are positive the handshake is complete so we don't want to
                   resend no matter what.  This is an interim state before the
                   internal mechaism sees an application data record and flags
                   us as complete officially */
                if (dtlsCtx->connStatus == RESUMED_HANDSHAKE_COMPLETE)
                {
                    psTraceDtls("Connected but awaiting data\n");
                    continue;
                }
                ssl = dtlsCtx->ssl;
                while ((sslBufLen = matrixDtlsGetOutdata(ssl,
                            &sslBuf)) > 0)
                {
                    if ((sendLen = udpSend(dtlsCtx->fd, sslBuf, sslBufLen,
                             (struct sockaddr *) &dtlsCtx->addr,
                             sizeof(struct sockaddr_in),
                             dtlsCtx->timeout / 2,
                             packet_loss_prob,
                             NULL)) < 0)
                    {
                        psTraceDtls("udpSend error.  Ignoring\n");
                    }
                    /* Always indicate the entire datagram was sent as
                       there is no way for DTLS to handle partial records.
                       Resends and timeouts will handle any problems */
                    if ((rc = matrixDtlsSentData(ssl, sslBufLen)) < 0)
                    {
                        psTraceDtls("internal error\n");
                        clearClient(dtlsCtx);
                        clientCount--;
                        break;
                    }
                    if (rc == MATRIXSSL_REQUEST_CLOSE)
                    {
                        psTraceDtls("Got REQUEST_CLOSE out of SentData\n");
                        clearClient(dtlsCtx);
                        clientCount--;
                        break;
                    }
                    if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
                    {
                        /* This is the standard handshake case */
                        psTraceDtls("Got HANDSHAKE_COMPLETE out of SentData\n");
                        break;
                    }
                    /* SSL_REQUEST_SEND is handled by loop logic */
                }

            }
        }
    }
    return clientCount;
}

/******************************************************************************/
/*
    Make sure the socket is not inherited by exec'd processes
    Set the REUSE flag to minimize the number of sockets in TIME_WAIT
    Then we set REUSEADDR, NODELAY and NONBLOCK on the socket
 */
static int32_t setSocketOptions(SOCKET fd)
{
    int32 rc;

# ifdef POSIX
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
# endif
    rc = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &rc, sizeof(rc)) < 0)
    {
        return PS_PLATFORM_FAIL;
    }
    return PS_SUCCESS;
}


static SOCKET newUdpSocket(char *ip, short port, int *err)
{
    struct sockaddr_in addr = { 0 };
    SOCKET fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        _psTraceInt("Error creating socket %d\n", SOCKET_ERRNO);
        *err = SOCKET_ERRNO;
        return INVALID_SOCKET;
    }

    if (setSocketOptions(fd) < 0)
    {
        *err = SOCKET_ERRNO;
        close(fd);
        return INVALID_SOCKET;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (ip == NULL)
    {
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        {
            _psTrace("Can't bind socket. Port in use or permission problem\n");
            *err = SOCKET_ERRNO;
            close(fd);
            return INVALID_SOCKET;
        }
    }
    return fd;
}

/* catch any segvs */
static void sigsegv_handler(int arg)
{
    _psTrace("Aiee, segfault! You should probably report "
        "this as a bug to the developer\n");
    exit(EXIT_FAILURE);
}

/* catch ctrl-c or sigterm */
static void sigintterm_handler(int arg)
{
    exitFlag = 1;   /* Rudimentary exit flagging */
}

static int sigsetup(void)
{
    /* set up cleanup handler */
    if (signal(SIGINT, sigintterm_handler) == SIG_ERR ||
# ifndef DEBUG_VALGRIND
        signal(SIGTERM, sigintterm_handler) == SIG_ERR ||
# endif
        signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        return -1;
    }
    if (signal(SIGSEGV, sigsegv_handler) == SIG_ERR)
    {
        return -1;
    }

    return 0;
}

# ifdef USE_DTLS_DEBUG_TRACE
/******************************************************************************/
/* Return a string representation of the socket address passed. The return
 * value is allocated with malloc() */
static unsigned char *getaddrstring(struct sockaddr *addr,
    int withport)
{

    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    char *retstring = NULL;
    int ret;
    unsigned int len;

    len = sizeof(struct sockaddr_storage);
    /* Some platforms such as Solaris 8 require that len is the length
     * of the specific structure. Some older linux systems (glibc 2.1.3
     * such as debian potato) have sockaddr_storage.__ss_family instead
     * but we'll ignore them */
#  ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY
    if (addr->ss_family == AF_INET)
    {
        len = sizeof(struct sockaddr_in);
    }
#   ifdef AF_INET6
    if (addr->ss_family == AF_INET6)
    {
        len = sizeof(struct sockaddr_in6);
    }
#   endif
#  endif

    ret = getnameinfo((struct sockaddr *) addr, len, hbuf, sizeof(hbuf),
        sbuf, sizeof(sbuf), NI_NUMERICSERV | NI_NUMERICHOST);

    if (ret != 0)
    {
        /* This is a fairly bad failure - it'll fallback to IP if it
         * just can't resolve */
        _psTrace("failed lookup for getaddrstring");
        strcpy(hbuf, "UNKNOWN");
        strcpy(sbuf, "?");
    }

    if (withport)
    {
        len = strlen(hbuf) + 2 + strlen(sbuf);
        retstring = (char *) psMalloc(MATRIX_NO_POOL, len);
        snprintf(retstring, len, "%s:%s", hbuf, sbuf);
    }
    else
    {
        retstring = strdup(hbuf);
    }

    return (unsigned char *) retstring;
}
# endif /* USE_DTLS_DEBUG_TRACE */

/******************************************************************************/
/*
    Client management
 */
/******************************************************************************/
static int32 initClientList(uint16 maxPeers)
{
    clientTable = psCalloc(NULL, maxPeers, sizeof(serverDtls_t));
    if (clientTable == NULL)
    {
        return PS_MEM_FAIL;
    }
    tableSize = maxPeers;

    udpInitProxy();
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Associates a new sockaddr with an existing ssl context and returns context
 */
serverDtls_t *registerClient(struct sockaddr_in addr, SOCKET sock,
    ssl_t *ssl)
{
    int16 i;
    serverDtls_t *dtlsCtx;

    for (i = 0; i < tableSize && clientTable[i].ssl != NULL &&
         (clientTable[i].addr.sin_addr.s_addr != addr.sin_addr.s_addr ||
          clientTable[i].addr.sin_port != addr.sin_port); i++)
    {
        ;
    }
    if (i >= tableSize)
    {
        /* no available slots */
        return NULL;
    }

    dtlsCtx = &clientTable[i];

    dtlsCtx->addr = addr;
    dtlsCtx->fd = sock;
    dtlsCtx->timeout = MIN_WAIT_SECS;
    dtlsCtx->connStatus = 0;
    psGetTime(&dtlsCtx->lastRecvTime, NULL);
    dtlsCtx->ssl = ssl;
    return dtlsCtx;
}

static void clearClient(serverDtls_t *dtls)
{
    ssl_t *ssl;
    unsigned char *buf;
    int32 len;

    ssl = dtls->ssl;

    /* Quick attempt to send a closure alert, don't worry about failure */
    if (matrixSslEncodeClosureAlert(ssl) >= 0)
    {
        if ((len = matrixDtlsGetOutdata(ssl, &buf)) > 0)
        {
            if (sendto(dtls->fd, buf, len, 0, (struct sockaddr *) &dtls->addr,
                    sizeof(struct sockaddr_in)) >= 0)
            {
                matrixDtlsSentData(ssl, len);
            }
        }
    }
    matrixSslDeleteSession(ssl);

/*
    Free up the entry in the client table
 */
    dtls->ssl = NULL;
    dtls->connStatus = 0;
    dtls->fd = 0;
    memset(&dtls->addr, 0x0, sizeof(struct sockaddr_in));
    return;
}

/******************************************************************************/
/*
    Return the ssl_t given the sockaddr or NULL if doesn't exist
 */
serverDtls_t *findClient(struct sockaddr_in addr)
{
    int i;

    for (i = 0; i < tableSize; i++)
    {
        if (clientTable[i].ssl != NULL)
        {
            if (clientTable[i].addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
                clientTable[i].addr.sin_port == addr.sin_port)
            {
                return &clientTable[i];
            }
        }
    }
    return NULL;
}

static void closeClientList()
{
    int i;

    /* Free any leftover clients */
    for (i = 0; i < tableSize && clientTable[i].ssl != NULL; i++)
    {
        matrixSslDeleteSession(clientTable[i].ssl);
    }
    psFree(clientTable, NULL);
    tableSize = 0;
}

#else

/******************************************************************************/
/*
    Stub main for compiling without dtls enabled
 */
int32 main(int32 argc, char **argv)
{
    printf("USE_DTLS must be enabled in " \
        "matrixsslConfig.h at build time to run this application\n");
    return -1;
}
#endif /* USE_DTLS */

/******************************************************************************/
