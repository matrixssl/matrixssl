/**
 *      @file    sslTest_nonfips.c
 *      @version $Format:%h%d$
 *
 *      Self-test of the MatrixSSL handshake protocol and encrypted data exchange..
 *      Each enabled cipher suite is run through all configured SSL handshake paths
 *      This version of the test is for native crypto library.
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
/******************************************************************************/

#include "matrixssl/matrixsslApi.h"
#include "core/psUtil.h"
#include <stdio.h>

#ifdef USE_PSK_CIPHER_SUITE
# include "testkeys/PSK/psk.h"
#endif /* USE_PSK_CIPHER_SUITE */

/*
    This test application can also run in a mode that measures the time of
    SSL connections.  If USE_HIGHRES time is disabled the granularity is
    milliseconds so most non-embedded platforms will report 0 msecs/conn for
    most stats.

    Standard handshakes and client-auth handshakes are timed
    for each enabled cipher suite. The other handshake types will still run
    but will not be timed
 */
/* #define ENABLE_PERF_TIMING */

#if !defined(POSIX) && !defined(WIN32)
# define EMBEDDED
#endif

#ifndef EMBEDDED
# define DELIM "\t"
# if defined(__x86_64__) && defined(ENABLE_PERF_TIMING)
#  define CONN_ITER         10 /* number of connections per type of hs */
# elif defined(__arm__) && defined(ENABLE_PERF_TIMING)
#  define CONN_ITER         2  /* number of connections per type of hs */
# else
#  define CONN_ITER         1  /* number of connections per type of hs */
# endif
#else
# define DELIM ","
# define CONN_ITER          1 /* number of connections per type of hs */
#endif

#define CLI_APP_DATA        128
#define SVR_APP_DATA        2048

#define THROUGHPUT_NREC     100
#define THROUGHPUT_RECSIZE  SSL_MAX_PLAINTEXT_LEN

#define BYTES_PER_MB 1048576
#ifdef ENABLE_PERF_TIMING
# define testTrace(x)
# ifdef USE_HIGHRES_TIME
#  define psDiffMsecs(A, B, C) psDiffUsecs(A, B)
#  define TIME_UNITS "usecs/connection\n"
#  define TIME_SCALE 1000000
# else /* !USE_HIGHRES_TIME */
#  define TIME_UNITS "msecs/connection\n"
#  define TIME_SCALE 1000
# endif /* USE_HIGHRES_TIME */
#else /* !ENABLE_PERF_TIMING */
# define testTrace(x) testPrint(x)
#endif /* ENABLE_PERF_TIMING */
#define CPS(A) ((A) != 0 ? (TIME_SCALE / (A)) : 0)
#define MBS(A) ((A) != 0 ? (uint32_t) (((uint64_t) THROUGHPUT_NREC * THROUGHPUT_RECSIZE * TIME_SCALE / BYTES_PER_MB) / (A)) : 0)

/* Test will produce output via standard output by default.
   Override these macros if required on your platform (such as if
   standard C header stdio.h is not available). */
#include <stdio.h>
#define testPrint(x) printf(x)
#define testPrintInt(x, i) printf(x, i)
#define testPrintStr(x, s) printf(x, s)

#ifdef USE_MATRIXSSL_STATS
static void statCback(void *ssl, void *stat_ptr, int32 type, int32 value);
#endif

/* #define TEST_RESUMPTIONS_WITH_SESSION_TICKETS */
#define ABORT_IMMEDIATELY_ON_ERROR /* Useful for debugging multi-threaded runs. */

/******************************************************************************/
/*
    Must define in matrixConfig.h:
        USE_SERVER_SIDE_SSL
        USE_CLIENT_SIDE_SSL
    Optional:
        USE_CLIENT_AUTH
        USE_SECURE_REHANDSHAKES
 */
#if !defined(USE_SERVER_SIDE_SSL) || !defined(USE_CLIENT_SIDE_SSL)
# warning "Must enable both USE_SERVER_SIDE_SSL and USE_CLIENT_SIDE_SSL to run"

# include <stdio.h>
int main(void)
{
    printf("Must enable both USE_SERVER_SIDE_SSL and USE_CLIENT_SIDE_SSL to run\n");
    return 1;
}

#else

# ifdef USE_ONLY_PSK_CIPHER_SUITE
#  ifdef USE_CLIENT_AUTH
#   error "Disable client auth if using only PSK ciphers"
#  endif
# endif

typedef struct
{
    ssl_t *ssl;
    sslKeys_t *keys;
# ifdef ENABLE_PERF_TIMING
    uint32 hsTime;
    uint32 appTime;
# endif
} sslConn_t;

enum
{
    TLS_TEST_SKIP = 1,
    TLS_TEST_PASS,
    TLS_TEST_FAIL,
};

enum
{
    STANDARD_HANDSHAKE,
    RE_HANDSHAKE_TEST_CLIENT_INITIATED,
    RESUMED_HANDSHAKE_TEST_NEW_CONNECTION,
    RE_HANDSHAKE_TEST_SERVER_INITIATED,
    RESUMED_RE_HANDSHAKE_TEST_CLIENT_INITIATED,
    SECOND_PASS_RESUMED_RE_HANDSHAKE_TEST,
    RESUMED_RE_HANDSHAKE_TEST_SERVER_INITIATED,
    UPGRADE_CERT_CALLBACK_RE_HANDSHAKE,
    UPGRADE_KEYS_RE_HANDSHAKE,
    CHANGE_CIPHER_SUITE_RE_HANDSHAKE_TEST,
    STANDARD_CLIENT_AUTH_HANDSHAKE,
    RESUMED_CLIENT_AUTH_HANDSHAKE,
    REHANDSHAKE_ADDING_CLIENT_AUTHENTICATION_TEST
};

typedef struct
{
    uint32_t c_hs;
    uint32_t s_hs;
    uint32_t c_rhs;
    uint32_t s_rhs;
    uint32_t c_resume;
    uint32_t s_resume;
    uint32_t c_cauth;
    uint32_t s_cauth;
    uint32_t c_app;
    uint32_t s_app;
    psSize_t keysize;   /* Pubkey size for key exchange */
    psSize_t authsize;  /* Pubkey size for auth */
    uint8_t cid;        /* Array index of testCipherSpec_t */
    uint8_t ver;        /* TLS version */
} testResult_t;

# ifdef ENABLE_PERF_TIMING
static testResult_t g_results[4 * 3 * 48];  /* 4 versions, 3 keysizes, 48 ciphers */
# endif

typedef struct
{
    const char name[64];
    uint16_t id;
} testCipherSpec_t;

# ifndef USE_ONLY_PSK_CIPHER_SUITE
static sslSessionId_t *clientSessionId;
# endif

/******************************************************************************/
/*
    Key loading.  The header files are a bit easier to work with because
    it is better to get a compile error that a header isn't found rather
    than a run-time error that a .pem file isn't found
 */
# define USE_HEADER_KEYS /* comment out this line to test with .pem files */

# if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
#  ifdef USE_RSA
static char svrKeyFile[] = "../../testkeys/RSA/1024_RSA_KEY.pem";
static char svrCertFile[] = "../../testkeys/RSA/1024_RSA.pem";
static char svrCAfile[] = "../../testkeys/RSA/1024_RSA_CA.pem";
static char clnCAfile[] = "../../testkeys/RSA/2048_RSA_CA.pem";
static char clnKeyFile[] = "../../testkeys/RSA/2048_RSA_KEY.pem";
static char clnCertFile[] = "../../testkeys/RSA/2048_RSA.pem";
#  endif /* USE_RSA */
#  ifdef USE_ECC
static char svrEcKeyFile[] = "../../testkeys/EC/192_EC_KEY.pem";
static char svrEcCertFile[] = "../../testkeys/EC/192_EC.pem";
static char svrEcCAfile[] = "../../testkeys/EC/192_EC_CA.pem";
static char clnEcKeyFile[] = "../../testkeys/EC/224_EC_KEY.pem";
static char clnEcCertFile[] = "../../testkeys/EC/224_EC.pem";
static char clnEcCAfile[] = "../../testkeys/EC/224_EC_CA.pem";
/* ECDH_RSA certs */
static char svrEcRsaKeyFile[] = "../../testkeys/ECDH_RSA/192_ECDH-RSA_KEY.pem";
static char svrEcRsaCertFile[] = "../../testkeys/ECDH_RSA/192_ECDH-RSA.pem";
static char svrEcRsaCAfile[] = "../../testkeys/ECDH_RSA/1024_ECDH-RSA_CA.pem";
static char clnEcRsaKeyFile[] = "../../testkeys/ECDH_RSA/256_ECDH-RSA_KEY.pem";
static char clnEcRsaCertFile[] = "../../testkeys/ECDH_RSA/256_ECDH-RSA.pem";
static char clnEcRsaCAfile[] = "../../testkeys/ECDH_RSA/2048_ECDH-RSA_CA.pem";
#  endif /* USE_ECC */
#  ifdef REQUIRE_DH_PARAMS
static char dhParamFile[] = "../../testkeys/DH/1024_DH_PARAMS.pem";
#  endif /* REQUIRE_DH_PARAMS */
# endif  /* MATRIX_USE_FILE_SYSTEM && !USE_HEADER_KEYS */

# ifdef USE_HEADER_KEYS

#  ifdef USE_RSA
#   include "testkeys/RSA/1024_RSA_KEY.h"
#   include "testkeys/RSA/1024_RSA.h"
#   include "testkeys/RSA/1024_RSA_CA.h"
#   include "testkeys/RSA/2048_RSA_KEY.h"
#   include "testkeys/RSA/2048_RSA.h"
#   include "testkeys/RSA/2048_RSA_CA.h"
#   include "testkeys/RSA/4096_RSA_KEY.h"
#   include "testkeys/RSA/4096_RSA.h"
#   include "testkeys/RSA/4096_RSA_CA.h"
static const unsigned char *RSAKEY, *RSACERT, *RSACA;
static uint32_t RSAKEY_SIZE, RSA_SIZE, RSACA_SIZE;
#  endif /* USE_RSA */

#  ifdef USE_ECC
#   include "testkeys/EC/192_EC_KEY.h"
#   include "testkeys/EC/192_EC.h"
#   include "testkeys/EC/192_EC_CA.h"
#   include "testkeys/EC/224_EC_KEY.h"
#   include "testkeys/EC/224_EC.h"
#   include "testkeys/EC/224_EC_CA.h"
#   include "testkeys/EC/256_EC_KEY.h"
#   include "testkeys/EC/256_EC.h"
#   include "testkeys/EC/256_EC_CA.h"
#   include "testkeys/EC/384_EC_KEY.h"
#   include "testkeys/EC/384_EC.h"
#   include "testkeys/EC/384_EC_CA.h"
#   include "testkeys/EC/521_EC_KEY.h"
#   include "testkeys/EC/521_EC.h"
#   include "testkeys/EC/521_EC_CA.h"
static const unsigned char *ECCKEY, *ECC, *ECCCA;
static uint32_t ECCKEY_SIZE, ECC_SIZE, ECCCA_SIZE;

#   include "testkeys/ECDH_RSA/256_ECDH-RSA_KEY.h"
#   include "testkeys/ECDH_RSA/256_ECDH-RSA.h"
#   include "testkeys/ECDH_RSA/1024_ECDH-RSA_CA.h"
#   include "testkeys/ECDH_RSA/521_ECDH-RSA_KEY.h"
#   include "testkeys/ECDH_RSA/521_ECDH-RSA.h"
#   include "testkeys/ECDH_RSA/2048_ECDH-RSA_CA.h"
static uint32_t ECDHRSA_SIZE;
#  endif /* USE_ECC */

#  ifdef REQUIRE_DH_PARAMS
#   include "testkeys/DH/1024_DH_PARAMS.h"
#   include "testkeys/DH/2048_DH_PARAMS.h"
#   include "testkeys/DH/4096_DH_PARAMS.h"
static const unsigned char *DHPARAM;
static uint32_t DH_SIZE;
#  endif /* REQUIRE_DH_PARAMS */

# endif  /* USE_HEADER_KEYS */

/******************************************************************************/

int sslTest(void);

static void freeSessionAndConnection(sslConn_t *cpp);

static int32 initializeServer(sslConn_t *svrConn, psCipher16_t cipher);
static int32 initializeClient(sslConn_t *clnConn, psCipher16_t cipher,
                              sslSessionId_t *sid);

static int32 initializeHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
                                 psCipher16_t cipherSuite,
                                 sslSessionId_t *sid);

# ifndef USE_ONLY_PSK_CIPHER_SUITE
static int32 initializeResumedHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
                                        psCipher16_t cipherSuite);
# endif /* USE_ONLY_PSK_CIPHER_SUITE */

# ifdef SSL_REHANDSHAKES_ENABLED
static int32 initializeReHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
                                   psCipher16_t cipherSuite);

static int32 initializeResumedReHandshake(sslConn_t *clnConn,
                                          sslConn_t *svrConn, psCipher16_t cipherSuite);
static int32 initializeServerInitiatedReHandshake(sslConn_t *clnConn,
                                                  sslConn_t *svrConn, psCipher16_t cipherSuite);
static int32 initializeServerInitiatedResumedReHandshake(sslConn_t *clnConn,
                                                         sslConn_t *svrConn, psCipher16_t cipherSuite);
static int32 initializeUpgradeCertCbackReHandshake(sslConn_t *clnConn,
                                                   sslConn_t *svrConn, psCipher16_t cipherSuite);
static int32 initializeUpgradeKeysReHandshake(sslConn_t *clnConn,
                                              sslConn_t *svrConn, psCipher16_t cipherSuite);
static int32 initializeChangeCipherReHandshake(sslConn_t *clnConn,
                                               sslConn_t *svrConn, psCipher16_t cipherSuite);
#  ifdef USE_CLIENT_AUTH
static int32 initializeReHandshakeClientAuth(sslConn_t *clnConn,
                                             sslConn_t *svrConn, psCipher16_t cipherSuite);
#  endif /* USE_CLIENT_AUTH */
# endif  /* SSL_REHANDSHAKES_ENABLED */

# ifdef USE_CLIENT_AUTH
static int32 initializeClientAuthHandshake(sslConn_t *clnConn,
                                           sslConn_t *svrConn, psCipher16_t cipherSuite,
                                           sslSessionId_t *sid);
# endif /* USE_CLIENT_AUTH */

static int32 performHandshake(sslConn_t *sendingSide, sslConn_t *receivingSide);
static int32 exchangeAppData(sslConn_t *sendingSide, sslConn_t *receivingSide, uint32_t bytes);
# ifdef ENABLE_PERF_TIMING
static int32_t throughputTest(sslConn_t *s, sslConn_t *r, uint16_t nrec, psSize_t reclen);
static void print_throughput(void);
# endif

/*
    Client-authentication.  Callback that is registered to receive client
    certificate information for custom validation
 */
static int32 clnCertChecker(ssl_t *ssl, psX509Cert_t *cert, int32 alert);

# ifdef SSL_REHANDSHAKES_ENABLED
static int32 clnCertCheckerUpdate(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
# endif

# ifdef USE_CLIENT_AUTH
static int32 svrCertChecker(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
# endif /* USE_CLIENT_AUTH */

# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif   /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

/******************************************************************************/

static uint32_t g_versionFlag = 0;

/* Protocol versions to test for each suite */
const static uint32_t g_versions[] = {
# if defined(USE_TLS_1_2)
    SSL_FLAGS_TLS_1_2,
# endif
# if defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
    SSL_FLAGS_TLS_1_1,
# endif
# if defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
    SSL_FLAGS_TLS_1_0,
# endif
# if !defined(DISABLE_SSLV3)
    SSL_FLAGS_SSLV3,
# endif
# if defined(USE_DTLS) && defined(USE_TLS_1_2)
    SSL_FLAGS_TLS_1_2 | SSL_FLAGS_DTLS,
# endif
# if defined(USE_DTLS) && defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
    SSL_FLAGS_TLS_1_1 | SSL_FLAGS_DTLS,
# endif
    0   /* 0 Must be last to terminate list */
};

# ifdef ENABLE_PERF_TIMING
const static char *g_version_str[] = {
#  if defined(USE_TLS_1_2)
    "TLS 1.2",
#  endif
#  if defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
    "TLS 1.1",
#  endif
#  if defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
    "TLS 1.0",
#  endif
#  if !defined(DISABLE_SSLV3)
    "SSL 3.0",
#  endif
#  if defined(USE_TLS) && defined(USE_TLS_1_2)
    "DTLS 1.2",
#  endif
#  if defined(USE_DTLS) && defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
    "DTLS 1.0", /* There is no DTLS 1.1 */
#  endif
    0           /* 0 Must be last to terminate list */
};
# endif

/* Ciphersuites to test */

# define CS(A) { #A, A }

const static testCipherSpec_t ciphers[] = {

/* RSA */
# ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA
    CS(TLS_RSA_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA
    CS(TLS_RSA_WITH_AES_256_CBC_SHA),
# endif

# ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
    CS(TLS_RSA_WITH_AES_128_CBC_SHA256),
# endif

# ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
    CS(TLS_RSA_WITH_AES_256_CBC_SHA256),
# endif

# ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
    CS(TLS_RSA_WITH_AES_128_GCM_SHA256),
# endif

# ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
    CS(TLS_RSA_WITH_AES_256_GCM_SHA384),
# endif

# ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    CS(SSL_RSA_WITH_3DES_EDE_CBC_SHA),
# endif

/* ECDHE-ECDSA */

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    CS(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    CS(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    CS(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    CS(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    CS(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    CS(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
# endif

# ifdef USE_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    CS(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
# endif

/* ECDH-ECDSA */

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    CS(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256),
# endif

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    CS(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384),
# endif

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    CS(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256),
# endif

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    CS(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384),
# endif

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    CS(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    CS(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA),
# endif

/* ECDHE-RSA */

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    CS(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    CS(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    CS(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    CS(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    CS(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    CS(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    CS(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
# endif

# ifdef USE_TLS_ECDHE_RSA_WITH_3DES_EDE_SHA
    CS(TLS_ECDHE_RSA_WITH_3DES_EDE_SHA),
# endif

/* ECDH-RSA */

# ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    CS(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256),
# endif

# ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    CS(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384),
# endif

# ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    CS(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256),
# endif

# ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    CS(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384),
# endif

# ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    CS(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    CS(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA),
# endif

/* DHE-RSA */

# ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    CS(TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    CS(TLS_DHE_RSA_WITH_AES_256_CBC_SHA),
# endif

# ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    CS(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256),
# endif

# ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    CS(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256),
# endif

# ifdef USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    CS(SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA),
# endif

/* PSK */

# ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA
    CS(TLS_PSK_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA
    CS(TLS_PSK_WITH_AES_256_CBC_SHA),
# endif

# ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA256
    CS(TLS_PSK_WITH_AES_128_CBC_SHA256),
# endif

# ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA384
    CS(TLS_PSK_WITH_AES_256_CBC_SHA384),
# endif

/* DHE-PSK */

# ifdef USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    CS(TLS_DHE_PSK_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
    CS(TLS_DHE_PSK_WITH_AES_256_CBC_SHA),
# endif

/* Deprecated / Weak ciphers */

# ifdef USE_SSL_RSA_WITH_RC4_128_SHA
    CS(SSL_RSA_WITH_RC4_128_SHA),
# endif

# ifdef USE_SSL_RSA_WITH_RC4_128_MD5
    CS(SSL_RSA_WITH_RC4_128_MD5),
# endif

# ifdef USE_TLS_RSA_WITH_SEED_CBC_SHA
    CS(TLS_RSA_WITH_SEED_CBC_SHA),
# endif

# ifdef USE_TLS_RSA_WITH_IDEA_CBC_SHA
    CS(TLS_RSA_WITH_IDEA_CBC_SHA),
# endif

/* DH-anon */

# ifdef USE_TLS_DH_anon_WITH_AES_128_CBC_SHA
    CS(TLS_DH_anon_WITH_AES_128_CBC_SHA),
# endif

# ifdef USE_TLS_DH_anon_WITH_AES_256_CBC_SHA
    CS(TLS_DH_anon_WITH_AES_256_CBC_SHA),
# endif

# ifdef USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
    CS(SSL_DH_anon_WITH_3DES_EDE_CBC_SHA),
# endif

# ifdef USE_SSL_DH_anon_WITH_RC4_128_MD5
    CS(SSL_DH_anon_WITH_RC4_128_MD5),
# endif

/* RSA-NULL */

# ifdef USE_SSL_RSA_WITH_NULL_SHA
    CS(SSL_RSA_WITH_NULL_SHA),
# endif

# ifdef USE_SSL_RSA_WITH_NULL_MD5
    CS(SSL_RSA_WITH_NULL_MD5),
# endif

    { "NULL", 0 } /* must be last */
};

# ifdef SSL_REHANDSHAKES_ENABLED
static const char *cipher_name(uint16_t cid)
{
    int id;

    for (id = 0; ciphers[id].id > 0; id++)
    {
        if (ciphers[id].id == cid)
        {
            break;
        }
    }
    return ciphers[id].name;
}
# endif /* !SSL_REHANDSHAKES_ENABLED */

/******************************************************************************/
/*
    This test application will exercise the SSL/TLS handshake and app
    data exchange for every eligible cipher.
 */

# ifndef EMBEDDED
int main(int argc, char **argv)
{
    return sslTest();
}
# endif

int sslTest(void)
{
    sslConn_t *svrConn, *clnConn;
    const sslCipherSpec_t *spec;
    uint8_t id, v;
    psSize_t keysize = 0, authsize = 0;

# ifdef ENABLE_PERF_TIMING
    int32 perfIter;
    uint32 clnTime, svrTime;
    testResult_t *result = g_results;
# endif /* ENABLE_PERF_TIMING */
    int32 rc = PS_SUCCESS;

    if (matrixSslOpen() < 0)
    {
        fprintf(stderr, "matrixSslOpen failed, exiting...\n");
        return EXIT_FAILURE;
    }

    svrConn = psMalloc(MATRIX_NO_POOL, sizeof(sslConn_t));
    clnConn = psMalloc(MATRIX_NO_POOL, sizeof(sslConn_t));
    memset(svrConn, 0, sizeof(sslConn_t));
    memset(clnConn, 0, sizeof(sslConn_t));

# ifdef USE_RSA
    RSA_SIZE = 0;
# endif
# ifdef USE_ECC
    ECC_SIZE = ECDHRSA_SIZE = 0;
# endif
# ifdef REQUIRE_DH_PARAMS
    DH_SIZE = 0;
# endif
    for (id = 0; ciphers[id].id > 0; id++)
    {

        if ((spec = sslGetDefinedCipherSpec(ciphers[id].id)) == NULL)
        {
            testPrint("		FAILED: cipher spec lookup\n");
            goto LBL_FREE;
        }
        keysize = authsize = 0;
# ifdef USE_RSA
L_NEXT_RSA:
        if (spec->type == CS_RSA)
        {
            switch (RSA_SIZE)
            {
            case 0:
                RSAKEY = RSA1024KEY; RSAKEY_SIZE = RSA1024KEY_SIZE;
                RSACERT = RSA1024; RSA_SIZE = RSA1024_SIZE;
                RSACA = RSA1024CA; RSACA_SIZE = RSA1024CA_SIZE;
                keysize = authsize = 1024;
                break;
            case RSA1024_SIZE:
                RSAKEY = RSA2048KEY; RSAKEY_SIZE = RSA2048KEY_SIZE;
                RSACERT = RSA2048; RSA_SIZE = RSA2048_SIZE;
                RSACA = RSA2048CA; RSACA_SIZE = RSA2048CA_SIZE;
                keysize = authsize = 2048;
                break;
            case RSA2048_SIZE:
#  ifndef EMBEDDED
                RSAKEY = RSA4096KEY; RSAKEY_SIZE = RSA4096KEY_SIZE;
                RSACERT = RSA4096; RSA_SIZE = RSA4096_SIZE;
                RSACA = RSA4096CA; RSACA_SIZE = RSA4096CA_SIZE;
                keysize = authsize = 4096;
                break;
            case RSA4096_SIZE:
#  endif
                RSA_SIZE = 0;
                break;
            }
            if (RSA_SIZE == 0)
            {
                continue;   /* Next cipher suite */
            }
        }
        /* For other ciphersuites that use RSA for auth only, default to 1024 */
        if (spec->type == CS_DHE_RSA ||
            spec->type == CS_ECDH_RSA || spec->type == CS_ECDHE_RSA)
        {
            RSAKEY = RSA1024KEY; RSAKEY_SIZE = RSA1024KEY_SIZE;
            RSACERT = RSA1024; RSA_SIZE = RSA1024_SIZE;
            RSACA = RSA1024CA; RSACA_SIZE = RSA1024CA_SIZE;
            authsize = 1024;
#  ifdef USE_ECC
            ECCKEY = EC256KEY; ECCKEY_SIZE = EC256KEY_SIZE;
            ECC = EC256; ECC_SIZE = EC256_SIZE;
            ECCCA = EC256CA; ECCCA_SIZE = EC256CA_SIZE;
            keysize = 256;
#  endif
        }
# endif /* USE_RSA */

# ifdef USE_ECC
L_NEXT_ECC:
        if (spec->type == CS_ECDH_ECDSA || spec->type == CS_ECDHE_ECDSA)
        {
            switch (ECC_SIZE)
            {
            case 0:
                ECCKEY = EC192KEY; ECCKEY_SIZE = EC192KEY_SIZE;
                ECC = EC192; ECC_SIZE = EC192_SIZE;
                ECCCA = EC192CA; ECCCA_SIZE = EC192CA_SIZE;
                keysize = authsize = 192;
                break;
            case EC192_SIZE:
                ECCKEY = EC224KEY; ECCKEY_SIZE = EC224KEY_SIZE;
                ECC = EC224; ECC_SIZE = EC224_SIZE;
                ECCCA = EC224CA; ECCCA_SIZE = EC224CA_SIZE;
                keysize = authsize = 224;
                break;
            case EC224_SIZE:
                ECCKEY = EC256KEY; ECCKEY_SIZE = EC256KEY_SIZE;
                ECC = EC256; ECC_SIZE = EC256_SIZE;
                ECCCA = EC256CA; ECCCA_SIZE = EC256CA_SIZE;
                keysize = authsize = 256;
                break;
            case EC256_SIZE:
#  ifndef EMBEDDED
                ECCKEY = EC384KEY; ECCKEY_SIZE = EC384KEY_SIZE;
                ECC = EC384; ECC_SIZE = EC384_SIZE;
                ECCCA = EC384CA; ECCCA_SIZE = EC384CA_SIZE;
                keysize = authsize = 384;
                break;
            case EC384_SIZE:
                ECCKEY = EC521KEY; ECCKEY_SIZE = EC521KEY_SIZE;
                ECC = EC521; ECC_SIZE = EC521_SIZE;
                ECCCA = EC521CA; ECCCA_SIZE = EC521CA_SIZE;
                keysize = authsize = 521;
                break;
            case EC521_SIZE:
#  endif
                ECC_SIZE = 0;
                break;
            }
            if (ECC_SIZE == 0)
            {
                continue;   /* Next cipher suite */
            }
        }
# endif /* USE_ECC */

# ifdef REQUIRE_DH_PARAMS
L_NEXT_DH:
        if (spec->type == CS_DHE_RSA || spec->type == CS_DHE_PSK
            || spec->type == CS_DH_ANON)
        {
            switch (DH_SIZE)
            {
            case 0:
                DHPARAM = DHPARAM1024; DH_SIZE = DHPARAM1024_SIZE;
                keysize = 1024;
                break;
            case DHPARAM1024_SIZE:
                DHPARAM = DHPARAM2048; DH_SIZE = DHPARAM2048_SIZE;
                keysize = 2048;
                break;
            case DHPARAM2048_SIZE:
#  ifndef EMBEDDED
                DHPARAM = DHPARAM4096; DH_SIZE = DHPARAM4096_SIZE;
                keysize = 4096;
                break;
            case DHPARAM4096_SIZE:
#  endif
                DH_SIZE = 0;
                break;
            }
            if (DH_SIZE == 0)
            {
                continue;   /* Next cipher suite */
            }
        }
# endif
# ifdef USE_PSK_CIPHER_SUITE
        if (spec->type == CS_PSK)
        {
            keysize = authsize = sizeof(PSK_HEADER_TABLE[0].key) * 8;
        }
        if (spec->type == CS_DHE_PSK)
        {
            authsize = sizeof(PSK_HEADER_TABLE[0].key) * 8;
        }
# endif

        /* Loop through each defined version (note: not indented) */
        for (v = 0; g_versions[v] != 0; v++)
        {

            g_versionFlag = g_versions[v];

# ifdef ENABLE_PERF_TIMING
            result->keysize = keysize;
            result->authsize = authsize;
# endif
            /* Some ciphers are not supported in some versions of TLS */
            if (spec->flags & (CRYPTO_FLAGS_SHA2 | CRYPTO_FLAGS_SHA3))
            {
                if (!(g_versionFlag & SSL_FLAGS_TLS_1_2))
                {
                    testPrintStr("Skipping %s < TLS 1.2\n\n", (char *) ciphers[id].name);
                    continue;
                }
            }
            else if (spec->flags & CRYPTO_FLAGS_MD5)
            {
                if (g_versionFlag & SSL_FLAGS_TLS_1_2)
                {
                    testPrintStr("Skipping %s TLS 1.2\n\n", (char *) ciphers[id].name);
                    continue;
                }
            }
# ifdef USE_LIBSODIUM_AES_GCM
            /* Libsodium supports only aes256-gcm, not 128 */
            if ((spec->flags & CRYPTO_FLAGS_AES) && (spec->flags & CRYPTO_FLAGS_GCM))
            {
                testPrintStr("Skipping %s libsodium\n\n", (char *) ciphers[id].name);
                continue;
            }
# endif
# ifndef USE_ONLY_PSK_CIPHER_SUITE
            matrixSslNewSessionId(&clientSessionId, NULL);
# endif
            switch (g_versions[v])
            {
            case SSL_FLAGS_SSLV3:
                testPrintStr("Testing %s SSL 3.0 ", (char *) ciphers[id].name);
                break;
            case SSL_FLAGS_TLS_1_0:
                testPrintStr("Testing %s TLS 1.0 ", (char *) ciphers[id].name);
                break;
            case SSL_FLAGS_TLS_1_1:
                testPrintStr("Testing %s TLS 1.1 ", (char *) ciphers[id].name);
                break;
            case SSL_FLAGS_TLS_1_2:
                testPrintStr("Testing %s TLS 1.2 ", (char *) ciphers[id].name);
                break;
            case SSL_FLAGS_TLS_1_1 | SSL_FLAGS_DTLS:
                testPrintStr("Testing %s DTLS 1.0 ", (char *) ciphers[id].name);
                break;
            case SSL_FLAGS_TLS_1_2 | SSL_FLAGS_DTLS:
                testPrintStr("Testing %s DTLS 1.2 ", (char *) ciphers[id].name);
                break;
            }
            testPrintInt("KeySize %hu ", keysize);
            testPrintInt("AuthSize %hu\n", authsize);

            /* Standard Handshake */
            testPrint("	Standard handshake test\n");
# ifdef ENABLE_PERF_TIMING
/*
        Each matrixSsl call in the handshake is wrapped by a timer.  Data
        exchange is NOT included in the timer
 */
            result->cid = id;
            result->ver = v;
            clnTime = svrTime = 0;
            testPrintInt("		%d connections\n", (int32) CONN_ITER);
            for (perfIter = 0; perfIter < CONN_ITER; perfIter++)
            {
# endif     /* ENABLE_PERF_TIMING */
# ifndef USE_ONLY_PSK_CIPHER_SUITE
            if (initializeHandshake(clnConn, svrConn, ciphers[id].id, clientSessionId) < 0)
            {
# else
            if (initializeHandshake(clnConn, svrConn, ciphers[id].id, NULL) < 0)
            {
# endif
                testPrint("		FAILED: initializing Standard handshake\n");
                goto LBL_FREE;
            }
# ifdef USE_MATRIXSSL_STATS
            matrixSslRegisterStatCallback(clnConn->ssl, statCback, NULL);
            matrixSslRegisterStatCallback(svrConn->ssl, statCback, NULL);
# endif
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("		FAILED: Standard handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Standard handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
# ifdef ENABLE_PERF_TIMING
                if (throughputTest(clnConn, svrConn, THROUGHPUT_NREC, THROUGHPUT_RECSIZE) < 0)
                {
                    testPrint(" but FAILED throughputTest\n");
                    goto LBL_FREE;
                }
                result->c_app = clnConn->appTime;
                result->s_app = svrConn->appTime;
# endif
            }

# ifdef ENABLE_PERF_TIMING
            clnTime += clnConn->hsTime;
            svrTime += svrConn->hsTime;
            /* Have to reset conn for full handshake... except last time through */
            if (perfIter + 1 != CONN_ITER)
            {
                matrixSslDeleteSession(clnConn->ssl);
                matrixSslDeleteSession(svrConn->ssl);
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
                matrixSslClearSessionId(clientSessionId);
#  endif
            }
        } /* iteration loop close */
        result->c_hs = clnTime / CONN_ITER;
        result->s_hs = svrTime / CONN_ITER;
        testPrintInt("		CLIENT:	%d "TIME_UNITS, (int32) clnTime / CONN_ITER);
        testPrintInt("		SERVER:	%d "TIME_UNITS, (int32) svrTime / CONN_ITER);
        testPrint("\n");
# endif     /* ENABLE_PERF_TIMING */

# if defined(SSL_REHANDSHAKES_ENABLED) && !defined(USE_ZLIB_COMPRESSION)
            /* Re-Handshake (full handshake over existing connection) */
            testTrace("	Re-handshake test (client-initiated)\n");
            if (initializeReHandshake(clnConn, svrConn, ciphers[id].id) < 0)
            {
                testPrint("		FAILED: initializing Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("		FAILED: Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Re-handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }
# else
            testPrint("	Re-handshake tests are disabled (ENABLE_SECURE_REHANDSHAKES)\n");
# endif

# ifndef USE_ONLY_PSK_CIPHER_SUITE
            /* Resumed handshake (fast handshake over new connection) */
            testTrace("	Resumed handshake test (new connection)\n");
            if (initializeResumedHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("		FAILED: initializing Resumed handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("		FAILED: Resumed handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Resumed handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }
# else
            testPrint("	Session resumption tests are disabled (USE_ONLY_PSK_CIPHER_SUITE)\n");
# endif

# if defined(SSL_REHANDSHAKES_ENABLED) && !defined(USE_ZLIB_COMPRESSION)
/*
         Re-handshake initiated by server (full handshake over existing conn)
         Cipher Suite negotiations can get a little fuzzy on the server
         initiated rehandshakes based on what is enabled in matrixsslConfig.h
         because the client will send the entire cipher suite list.  In theory,
         the server could disable specific suites to force desired ones but
         we're not doing that here so the cipher suite might be changing
         underneath us now.
 */
            testTrace("	Re-handshake test (server initiated)\n");
            if (initializeServerInitiatedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("		FAILED: initializing Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(svrConn, clnConn) < 0)
            {
                testPrint("		FAILED: Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                if (ciphers[id].id != clnConn->ssl->cipher->ident)
                {
                    testPrintStr("		(new cipher %s)\n",
                        cipher_name(clnConn->ssl->cipher->ident));
                }
                testTrace("		PASSED: Re-handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }

            /* Testing 6 more re-handshake paths.  Add some credits */
            matrixSslAddRehandshakeCredits(svrConn->ssl, 6);
            matrixSslAddRehandshakeCredits(clnConn->ssl, 6);
/*
        Resumed re-handshake (fast handshake over existing connection)
        If the above handshake test did change cipher suites this next test
        will not take a resumption path because the client is specifying the
        specific cipher which will not match the current.  So, we'll run this
        test twice to make sure we reset the cipher on the first one and are
        sure to hit the resumed re-handshake test on the second.
 */
            testTrace("	Resumed Re-handshake test (client initiated)\n");
            if (initializeResumedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("		FAILED: initializing Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("		FAILED: Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Resumed Re-handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }
            testTrace("	Second Pass Resumed Re-handshake test\n");
            if (initializeResumedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("		FAILED: initializing Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("		FAILED: Second Pass Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Second Pass Resumed Re-handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }

            /* Resumed re-handshake initiated by server (fast handshake over conn) */
            testTrace("	Resumed Re-handshake test (server initiated)\n");
            if (initializeServerInitiatedResumedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("		FAILED: initializing Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(svrConn, clnConn) < 0)
            {
                testPrint("		FAILED: Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Resumed Re-handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }

            /* Re-handshaking with "upgraded" parameters */
            testTrace("	Change cert callback Re-handshake test\n");
            if (initializeUpgradeCertCbackReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("		FAILED: init upgrade certCback Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("		FAILED: Upgrade cert callback Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Upgrade cert callback Re-handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }

            /* Upgraded keys */
            testTrace("	Change keys Re-handshake test\n");
            if (initializeUpgradeKeysReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("		FAILED: init upgrade keys Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("		FAILED: Upgrade keys Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("		PASSED: Upgrade keys Re-handshake");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange application data\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("\n");
                }
            }
/*
        Change cipher spec test.  Changing to a hardcoded RSA suite so this
        will not work on suites that don't have RSA material loaded
 */
            if (spec->type == CS_RSA || spec->type == CS_DHE_RSA ||
                spec->type == CS_ECDH_RSA || spec->type == CS_ECDHE_RSA)
            {
                testTrace("	Change cipher suite Re-handshake test\n");
                if (initializeChangeCipherReHandshake(clnConn, svrConn,
                        ciphers[id].id) < 0)
                {
                    testPrint("		FAILED: init change cipher Re-handshake\n");
                    goto LBL_FREE;
                }
                if (performHandshake(clnConn, svrConn) < 0)
                {
                    testPrint("		FAILED: Change cipher suite Re-handshake\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("		PASSED: Change cipher suite Re-handshake");
                    if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                        exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                    {
                        testPrint(" but FAILED to exchange application data\n");
                        goto LBL_FREE;
                    }
                    else
                    {
                        testTrace("\n");
                    }
                }
            }
# endif     /* !SSL_REHANDSHAKES_ENABLED */

# ifdef USE_CLIENT_AUTH
            /* Client Authentication handshakes */
            if (spec->type != CS_PSK && spec->type != CS_DHE_PSK)
            {
                testPrint("	Standard Client Authentication test\n");
#  ifdef ENABLE_PERF_TIMING
                clnTime = svrTime = 0;
                testPrintInt("		%d connections\n", (int32) CONN_ITER);
                for (perfIter = 0; perfIter < CONN_ITER; perfIter++)
                {
#  endif        /* ENABLE_PERF_TIMING */
                matrixSslClearSessionId(clientSessionId);
                if (initializeClientAuthHandshake(clnConn, svrConn,
                        ciphers[id].id, clientSessionId) < 0)
                {
                    testPrint("		FAILED: initializing Standard Client Auth handshake\n");
                    goto LBL_FREE;
                }
                if (performHandshake(clnConn, svrConn) < 0)
                {
                    testPrint("		FAILED: Standard Client Auth handshake\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("		PASSED: Standard Client Auth handshake");
                    if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                        exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                    {
                        testPrint(" but FAILED to exchange application data\n");
                        goto LBL_FREE;
                    }
                    else
                    {
                        testTrace("\n");
                    }
                }
#  ifdef ENABLE_PERF_TIMING
                clnTime += clnConn->hsTime;
                svrTime += svrConn->hsTime;
            } /* iteration loop */
            result->c_cauth = clnTime / CONN_ITER;
            result->s_cauth = svrTime / CONN_ITER;
            testPrintInt("		CLIENT:	%d "TIME_UNITS, (int32) clnTime / CONN_ITER);
            testPrintInt("		SERVER:	%d "TIME_UNITS, (int32) svrTime / CONN_ITER);
            testPrint("\n==========\n");
#  endif        /* ENABLE_PERF_TIMING */


                testTrace("	Resumed client authentication test\n");
                if (initializeResumedHandshake(clnConn, svrConn, ciphers[id].id) < 0)
                {
                    testPrint("		FAILED: initializing resumed Client Auth handshake\n");
                    goto LBL_FREE;
                }
                if (performHandshake(clnConn, svrConn) < 0)
                {
                    testPrint("		FAILED: Resumed Client Auth handshake\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("		PASSED: Resumed Client Auth handshake");
                    if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                        exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                    {
                        testPrint(" but FAILED to exchange application data\n");
                        goto LBL_FREE;
                    }
                    else
                    {
                        testTrace("\n");
                    }
                }
#  if defined(SSL_REHANDSHAKES_ENABLED) && !defined(USE_ZLIB_COMPRESSION)
                testTrace("	Rehandshake adding client authentication test\n");
                if (initializeReHandshakeClientAuth(clnConn, svrConn,
                        ciphers[id].id) < 0)
                {
                    testPrint("		FAILED: initializing reshandshke Client Auth handshake\n");
                    goto LBL_FREE;
                }
                /* Must be server initiatated if client auth is being turned on */
                if (performHandshake(svrConn, clnConn) < 0)
                {
                    testPrint("		FAILED: Rehandshake Client Auth handshake\n");
                    goto LBL_FREE;
                }
                else
                {
                    if (ciphers[id].id != clnConn->ssl->cipher->ident)
                    {
                        testPrintStr("		(new cipher %s)\n",
                            cipher_name(clnConn->ssl->cipher->ident));
                    }
                    testTrace("		PASSED: Rehandshake Client Auth handshake");
                    if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                        exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                    {
                        testPrint(" but FAILED to exchange application data\n");
                        goto LBL_FREE;
                    }
                    else
                    {
                        testTrace("\n");
                    }
                }
#  endif /* SSL_REHANDSHAKES_ENABLED */
            }
# endif  /* USE_CLIENT_AUTH */

            freeSessionAndConnection(svrConn);
            freeSessionAndConnection(clnConn);
# ifndef USE_ONLY_PSK_CIPHER_SUITE
            matrixSslDeleteSessionId(clientSessionId);
# endif
# ifdef ENABLE_PERF_TIMING
            result++;
# endif

            continue; /* Next version */

LBL_FREE:
            testPrint("EXITING ON ERROR\n");
            rc = PS_FAILURE;
# ifdef ABORT_IMMEDIATELY_ON_ERROR
            abort();
# endif     /* ABORT_IMMEDIATELY_ON_ERROR */
            freeSessionAndConnection(svrConn);
            freeSessionAndConnection(clnConn);
# ifndef USE_ONLY_PSK_CIPHER_SUITE
            matrixSslDeleteSessionId(clientSessionId);
# endif
            break;

        } /* End version loop (unindented) */
# ifdef USE_RSA
        if (spec && spec->type == CS_RSA)
        {
            goto L_NEXT_RSA;
        }
# endif
# ifdef USE_ECC
        if (spec && (spec->type == CS_ECDH_ECDSA || spec->type == CS_ECDHE_ECDSA))
        {
            goto L_NEXT_ECC;
        }
# endif
# ifdef REQUIRE_DH_PARAMS
        if (spec && (spec->type == CS_DHE_RSA || spec->type == CS_DHE_PSK))
        {
            goto L_NEXT_DH;
        }
# endif

    } /* End cipher suite loop */

# ifdef ENABLE_PERF_TIMING
    printf("Ciphersuite" DELIM "Keysize" DELIM "Authsize" DELIM
        "Version" DELIM "CliHS" DELIM "SvrHs" DELIM "CliAHS" DELIM "SvrAHS" DELIM
        "MiBs" "\n");
    do
    {
        result--;
        printf("%s" DELIM "%hu" DELIM "%hu" DELIM
            "%s" DELIM "%u" DELIM "%u" DELIM "%u" DELIM "%u" DELIM
            "%u" "\n",
            ciphers[result->cid].name,
            result->keysize,
            result->authsize,
            g_version_str[result->ver],
            CPS(result->c_hs), CPS(result->s_hs),
            CPS(result->c_cauth), CPS(result->s_cauth),
            MBS(result->c_app)
            );
    }
    while (result != g_results);
    print_throughput();
# endif

    psFree(svrConn, NULL);
    psFree(clnConn, NULL);
    matrixSslClose();

# ifdef WIN32
    testPrint("Press any key to close");
    getchar();
# endif

    if (rc == PS_SUCCESS)
    {
        testPrint("OK\n");
        return 0;
    }
    else
    {
        return EXIT_FAILURE;
    }
}

static int32 initializeHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
    psCipher16_t cipherSuite, sslSessionId_t *sid)
{
    int32 rc;

    if ((rc = initializeServer(svrConn, cipherSuite)) < 0)
    {
        return rc;
    }
    return initializeClient(clnConn, cipherSuite, sid);

}

# ifdef SSL_REHANDSHAKES_ENABLED
static int32 initializeReHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
    psCipher16_t cipherSuite)
{
    return matrixSslEncodeRehandshake(clnConn->ssl, NULL, NULL,
        SSL_OPTION_FULL_HANDSHAKE, &cipherSuite, 1);
}

static int32 initializeServerInitiatedReHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite)
{
    return matrixSslEncodeRehandshake(svrConn->ssl, NULL, NULL,
        SSL_OPTION_FULL_HANDSHAKE, &cipherSuite, 1);
}

static int32 initializeServerInitiatedResumedReHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite)
{
    return matrixSslEncodeRehandshake(svrConn->ssl, NULL, NULL, 0, &cipherSuite,
        1);

}

static int32 initializeResumedReHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite)
{
    return matrixSslEncodeRehandshake(clnConn->ssl, NULL, NULL, 0, &cipherSuite,
        1);
}

static int32 initializeUpgradeCertCbackReHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite)
{
    return matrixSslEncodeRehandshake(clnConn->ssl, NULL, clnCertCheckerUpdate,
        0, &cipherSuite, 1);
}

static int32 initializeUpgradeKeysReHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite)
{
/*
    Not really changing the keys but this still tests that passing a
    valid arg will force a full handshake
 */
    return matrixSslEncodeRehandshake(clnConn->ssl, clnConn->ssl->keys, NULL,
        0, &cipherSuite, 1);
}

static int32 initializeChangeCipherReHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite)
{
/*
    Just picking the most common suite
 */
#  ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    uint16_t suite;
    suite = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
    return matrixSslEncodeRehandshake(clnConn->ssl, NULL, NULL,
        0, &suite, 1);
#  else
    return matrixSslEncodeRehandshake(clnConn->ssl, NULL, NULL, 0, 0, 0);
#  endif
}

#  ifdef USE_CLIENT_AUTH
static int32 initializeReHandshakeClientAuth(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite)
{
    return matrixSslEncodeRehandshake(svrConn->ssl, NULL, svrCertChecker, 0,
        &cipherSuite, 1);
}
#  endif /* USE_CLIENT_AUTH */
# endif  /* SSL_REHANDSHAKES_ENABLED */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
static int32 initializeResumedHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
    psCipher16_t cipherSuite)
{
    sslSessionId_t *sessionId;
    sslSessOpts_t options;

#  ifdef ENABLE_PERF_TIMING
    psTime_t start, end;
#  endif /* ENABLE_PERF_TIMING */

    sessionId = clnConn->ssl->sid;

    memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = g_versionFlag;
#  ifdef USE_ECC_CIPHER_SUITE
    options.ecFlags = clnConn->ssl->ecInfo.ecFlags;
#  endif
#  ifdef TEST_RESUMPTIONS_WITH_SESSION_TICKETS
    options.ticketResumption = 1;
#  endif

    matrixSslDeleteSession(clnConn->ssl);

#  ifdef ENABLE_PERF_TIMING
    clnConn->hsTime = 0;
    psGetTime(&start, NULL);
#  endif /* ENABLE_PERF_TIMING */
#  ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    options.useExtCvSigOp = 1;
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
    if (matrixSslNewClientSession(&clnConn->ssl, clnConn->keys, sessionId,
            &cipherSuite, 1, clnCertChecker, "localhost", NULL, NULL,
            &options)
        < 0)
    {
        return PS_FAILURE;
    }
#  ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    clnConn->hsTime += psDiffMsecs(start, end, NULL);
#  endif /* ENABLE_PERF_TIMING */

    matrixSslDeleteSession(svrConn->ssl);
#  ifdef ENABLE_PERF_TIMING
    svrConn->hsTime = 0;
    psGetTime(&start, NULL);
#  endif /* ENABLE_PERF_TIMING */
#  ifdef USE_SERVER_SIDE_SSL
    if (matrixSslNewServerSession(&svrConn->ssl, svrConn->keys, NULL,
            &options) < 0)
    {
        return PS_FAILURE;
    }
#  endif
#  ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    svrConn->hsTime += psDiffMsecs(start, end, NULL);
#  endif /* ENABLE_PERF_TIMING */
    return PS_SUCCESS;
}
# endif /* USE_ONLY_PSK_CIPHER_SUITE */

# ifdef USE_CLIENT_AUTH
static int32 initializeClientAuthHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite, sslSessionId_t *sid)
{
    sslSessOpts_t options;

#  ifdef ENABLE_PERF_TIMING
    psTime_t start, end;
#  endif /* ENABLE_PERF_TIMING */

    memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = g_versionFlag;
#  ifdef USE_ECC_CIPHER_SUITE
    options.ecFlags = clnConn->ssl->ecInfo.ecFlags;
#  endif
#  ifdef TEST_RESUMPTIONS_WITH_SESSION_TICKETS
    options.ticketResumption = 1;
#  endif

    matrixSslDeleteSession(clnConn->ssl);

#  ifdef ENABLE_PERF_TIMING
    clnConn->hsTime = 0;
    psGetTime(&start, NULL);
#  endif /* ENABLE_PERF_TIMING */
#  ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    options.useExtCvSigOp = 1;
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
    if (matrixSslNewClientSession(&clnConn->ssl, clnConn->keys, sid,
            &cipherSuite, 1, clnCertChecker, "localhost", NULL, NULL,
            &options) < 0)
    {
        return PS_FAILURE;
    }
#  ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    clnConn->hsTime += psDiffMsecs(start, end, NULL);
#  endif /* ENABLE_PERF_TIMING */

    matrixSslDeleteSession(svrConn->ssl);
#  ifdef ENABLE_PERF_TIMING
    svrConn->hsTime = 0;
    psGetTime(&start, NULL);
#  endif /* ENABLE_PERF_TIMING */
#  ifdef USE_SERVER_SIDE_SSL
    if (matrixSslNewServerSession(&svrConn->ssl, svrConn->keys, svrCertChecker,
            &options) < 0)
    {
        return PS_FAILURE;
    }
#  endif
#  ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    svrConn->hsTime += psDiffMsecs(start, end, NULL);
#  endif /* ENABLE_PERF_TIMING */
    return PS_SUCCESS;
}
# endif /* USE_CLIENT_AUTH */

/*
    Recursive handshake
 */
static int32 performHandshake(sslConn_t *sendingSide, sslConn_t *receivingSide)
{
    unsigned char *inbuf, *outbuf, *plaintextBuf;
    int32 inbufLen, outbufLen, rc, dataSent;
    uint32 ptLen;

# ifdef ENABLE_PERF_TIMING
    psTime_t start, end;
# endif /* ENABLE_PERF_TIMING */

/*
    Sending side will have outdata ready
 */
# ifdef ENABLE_PERF_TIMING
    psGetTime(&start, NULL);
# endif /* ENABLE_PERF_TIMING */
# ifdef USE_DTLS
    if (sendingSide->ssl->flags & SSL_FLAGS_DTLS)
    {
        outbufLen = matrixDtlsGetOutdata(sendingSide->ssl, &outbuf);
    }
    else
    {
        outbufLen = matrixSslGetOutdata(sendingSide->ssl, &outbuf);
    }
# else
    outbufLen = matrixSslGetOutdata(sendingSide->ssl, &outbuf);
# endif
# ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    sendingSide->hsTime += psDiffMsecs(start, end, NULL);
# endif /* ENABLE_PERF_TIMING */

/*
    Receiving side must ask for storage space to receive data into
 */
# ifdef ENABLE_PERF_TIMING
    psGetTime(&start, NULL);
# endif /* ENABLE_PERF_TIMING */
    inbufLen = matrixSslGetReadbuf(receivingSide->ssl, &inbuf);
# ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    receivingSide->hsTime += psDiffMsecs(start, end, NULL);
# endif /* ENABLE_PERF_TIMING */

/*
    The indata is the outdata from the sending side.  copy it over
 */
    if (outbufLen <= 0 || inbufLen <= 0)
    {
        return PS_FAILURE;
    }
    dataSent = PS_MIN(outbufLen, inbufLen);
    memcpy(inbuf, outbuf, dataSent);

/*
    Now update the sending side that data has been "sent"
 */
# ifdef ENABLE_PERF_TIMING
    psGetTime(&start, NULL);
# endif /* ENABLE_PERF_TIMING */
# ifdef USE_DTLS
    if (sendingSide->ssl->flags & SSL_FLAGS_DTLS)
    {
        matrixDtlsSentData(sendingSide->ssl, dataSent);
    }
    else
    {
        matrixSslSentData(sendingSide->ssl, dataSent);
    }
# else
    matrixSslSentData(sendingSide->ssl, dataSent);
# endif
# ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    sendingSide->hsTime += psDiffMsecs(start, end, NULL);
# endif /* ENABLE_PERF_TIMING */

/*
    Received data
 */
# ifdef ENABLE_PERF_TIMING
    psGetTime(&start, NULL);
# endif /* ENABLE_PERF_TIMING */
    rc = matrixSslReceivedData(receivingSide->ssl, dataSent, &plaintextBuf,
        &ptLen);
# ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    receivingSide->hsTime += psDiffMsecs(start, end, NULL);
# endif /* ENABLE_PERF_TIMING */

# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
    if (rc == MATRIXSSL_REQUEST_SEND)
    {
/*
        Success case.  Switch roles and continue
 */
        return performHandshake(receivingSide, sendingSide);

    }
    else if (rc == MATRIXSSL_REQUEST_RECV)
    {
/*
        This pass didn't take care of it all.  Don't switch roles and
        try again
 */
        return performHandshake(sendingSide, receivingSide);

    }
    else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
    {
        return PS_SUCCESS;

    }
    else if (rc == MATRIXSSL_RECEIVED_ALERT)
    {
/*
        Just continue if warning level alert
 */
        if (plaintextBuf[0] == SSL_ALERT_LEVEL_WARNING)
        {
            if (matrixSslProcessedData(receivingSide->ssl, &plaintextBuf,
                    &ptLen) != 0)
            {
                return PS_FAILURE;
            }
            return performHandshake(sendingSide, receivingSide);
        }
        else
        {
            return PS_FAILURE;
        }

    }
    else
    {
        printf("Unexpected error in performHandshake: %d\n", rc);
        return PS_FAILURE;
    }
    return PS_FAILURE; /* can't get here */
}

# ifdef ENABLE_PERF_TIMING
static void ciphername(uint32_t flags, char s[32])
{
    s[0] = '\0';
    if (flags & CRYPTO_FLAGS_AES)
    {
        strcat(s, "AES");
    }
    else if (flags & CRYPTO_FLAGS_AES256)
    {
        strcat(s, "AES256");
    }
    else if (flags & CRYPTO_FLAGS_3DES)
    {
        strcat(s, "3DES");
    }
    else if (flags & CRYPTO_FLAGS_ARC4)
    {
        strcat(s, "RC4");
    }
    else if (flags & CRYPTO_FLAGS_SEED)
    {
        strcat(s, "SEED");
    }
    else if (flags & CRYPTO_FLAGS_IDEA)
    {
        strcat(s, "IDEA");
    }
    if (flags & CRYPTO_FLAGS_GCM)
    {
        strcat(s, "_GCM");
    }
    else if (flags & CRYPTO_FLAGS_SHA1)
    {
        strcat(s, "_SHA");
    }
    else if (flags & CRYPTO_FLAGS_SHA2)
    {
        strcat(s, "_SHA256");
    }
    else if (flags & CRYPTO_FLAGS_SHA3)
    {
        strcat(s, "_SHA384");
    }
    else if (flags & CRYPTO_FLAGS_MD5)
    {
        strcat(s, "_MD5");
    }
}

static uint32_t g_ttest[64];
static uint32_t g_ttest_val[64];
static uint16_t g_ttest_count = 0;

static void print_throughput(void)
{
    char name[32];
    int i;

    printf("Cipher" DELIM "MiB/s\n");
    for (i = 0; i < g_ttest_count; i++)
    {
        ciphername(g_ttest[i], name);
        printf("%s" DELIM "%u\n", name, MBS(g_ttest_val[i]));
    }
}

static int32_t throughputTest(sslConn_t *s, sslConn_t *r, uint16_t nrec, psSize_t reclen)
{
    uint32_t i, len, flags;
    int32_t rc, buflen;
    unsigned char *rb, *wb, *pt;
    char name[32];

    psTime_t start, end;

#  ifndef USE_HIGHRES_TIME
    psTime_t tstart;
#  endif

#  ifdef USE_DTLS
    if (s->ssl->flags & SSL_FLAGS_DTLS)
    {
        return PS_SUCCESS;
    }
#  endif
    flags = s->ssl->cipher->flags;
    for (i = 0; i < g_ttest_count; i++)
    {
        if (g_ttest[i] == flags)
        {
            s->appTime = r->appTime = g_ttest_val[i];
            return PS_SUCCESS;
        }
    }
    s->appTime = r->appTime = 0;
    ciphername(flags, name);
    printf("%s throughput test for %hu byte records (%u bytes total)\n",
        name, reclen, nrec * reclen);

#  ifndef USE_HIGHRES_TIME
    psGetTime(&tstart, NULL);
#  endif
    for (i = 0; i < nrec; i++)
    {
        buflen = matrixSslGetWritebuf(s->ssl, &wb, reclen);
        if (buflen < reclen)
        {
            return PS_FAIL;
        }
        psGetTime(&start, NULL);
        buflen = matrixSslEncodeWritebuf(s->ssl, reclen);
        if (buflen < 0)
        {
            return buflen;
        }
#  ifdef USE_DTLS
        if (flags & SSL_FLAGS_DTLS)
        {
            buflen = matrixDtlsGetOutdata(s->ssl, &wb);
        }
        else
        {
            buflen = matrixSslGetOutdata(s->ssl, &wb);
        }
#  else
        buflen = matrixSslGetOutdata(s->ssl, &wb);
#  endif
        psGetTime(&end, NULL);
        s->appTime += psDiffMsecs(start, end, NULL);

        len = matrixSslGetReadbufOfSize(r->ssl, buflen, &rb);
        if (buflen <= 0 || len < buflen)
        {
            return PS_FAIL;
        }
        memcpy(rb, wb, buflen);

        psGetTime(&start, NULL);
#  ifdef USE_DTLS
        if (flags & SSL_FLAGS_DTLS)
        {
            rc = matrixDtlsSentData(s->ssl, buflen);
        }
        else
        {
            rc = matrixSslSentData(s->ssl, buflen);
        }
#  else
        rc = matrixSslSentData(s->ssl, buflen);
#  endif
        psGetTime(&end, NULL);
        s->appTime += psDiffMsecs(start, end, NULL);
        if (rc < 0)
        {
            return rc;
        }
        psGetTime(&start, NULL);
        rc = matrixSslReceivedData(r->ssl, buflen, &pt, &len);
        if (rc != MATRIXSSL_APP_DATA)
        {
            return rc;
        }
        /* This is a loop, since with BEAST mode, 2 records may result from one encode */
        while (rc == MATRIXSSL_APP_DATA)
        {
            rc = matrixSslProcessedData(r->ssl, &pt, &len);
        }
        psGetTime(&end, NULL);
        r->appTime += psDiffMsecs(start, end, NULL);
        if (rc != 0)
        {
            return PS_FAIL;
        }
    }
#  ifndef USE_HIGHRES_TIME
    s->appTime = psDiffMsecs(tstart, end, NULL) / 2;
    r->appTime = s->appTime;
#  endif
    printf("  throughput send %u MiB/s\n", MBS(s->appTime));
    printf("  throughput recv %u MiB/s\n", MBS(r->appTime));
    g_ttest[g_ttest_count] = flags;
    g_ttest_val[g_ttest_count] = s->appTime;
    g_ttest_count++;
    return PS_SUCCESS;
}
# endif

/*
    If bytes == 0, does not exchange data.
    return 0 on successful encryption/decryption communication
    return -1 on failed comm
 */
static int32 exchangeAppData(sslConn_t *sendingSide, sslConn_t *receivingSide, uint32_t bytes)
{
    int32 writeBufLen, inBufLen, dataSent, rc, sentRc;
    uint32 ptLen, requestedLen, copyLen, halfReqLen;
    unsigned char *writeBuf, *inBuf, *plaintextBuf;
    unsigned char copyByte;

    if (bytes == 0)
    {
        return PS_SUCCESS;
    }
    requestedLen = bytes;
    copyByte = 0x1;
/*
    Split the data into two records sends.  Exercises the API a bit more
    having the extra buffer management for multiple records
 */
    while (requestedLen > 1)
    {
        copyByte++;
        halfReqLen = requestedLen / 2;
        writeBufLen = matrixSslGetWritebuf(sendingSide->ssl, &writeBuf, halfReqLen);
        if (writeBufLen <= 0)
        {
            return PS_FAILURE;
        }
        copyLen = PS_MIN(halfReqLen, (uint32) writeBufLen);
        /* memset(writeBuf, copyByte, copyLen); */
        requestedLen -= copyLen;
        /* psTraceBytes("sending", writeBuf, copyLen); */

        writeBufLen = matrixSslEncodeWritebuf(sendingSide->ssl, copyLen);
        if (writeBufLen < 0)
        {
            return PS_FAILURE;
        }
        copyByte++;
        writeBufLen = matrixSslGetWritebuf(sendingSide->ssl, &writeBuf,
            halfReqLen);
        if (writeBufLen <= 0)
        {
            return PS_FAILURE;
        }
        copyLen = PS_MIN(halfReqLen, (uint32) writeBufLen);
        /* memset(writeBuf, copyByte, copyLen); */
        requestedLen -= copyLen;
        /* psTraceBytes("sending", writeBuf, copyLen); */

        writeBufLen = matrixSslEncodeWritebuf(sendingSide->ssl, copyLen);
        if (writeBufLen < 0)
        {
            return PS_FAILURE;
        }
    }

SEND_MORE:
# ifdef USE_DTLS
    if (sendingSide->ssl->flags & SSL_FLAGS_DTLS)
    {
        writeBufLen = matrixDtlsGetOutdata(sendingSide->ssl, &writeBuf);
    }
    else
    {
        writeBufLen = matrixSslGetOutdata(sendingSide->ssl, &writeBuf);
    }
# else
    writeBufLen = matrixSslGetOutdata(sendingSide->ssl, &writeBuf);
# endif

/*
    Receiving side must ask for storage space to receive data into.

    A good optimization of the buffer management can be seen here if a
    second pass was required:  the inBufLen should exactly match the
    writeBufLen because when matrixSslReceivedData was called below the
    record length was parsed off and the buffer was reallocated to the
    exact necessary length
 */
    inBufLen = matrixSslGetReadbuf(receivingSide->ssl, &inBuf);

    if (writeBufLen <= 0 || inBufLen <= 0)
    {
        return PS_FAILURE;
    }
    dataSent = PS_MIN(writeBufLen, inBufLen);
    memcpy(inBuf, writeBuf, dataSent);

    /* Now update the sending side that data has been "sent" */
# ifdef USE_DTLS
    if (sendingSide->ssl->flags & SSL_FLAGS_DTLS)
    {
        sentRc = matrixDtlsSentData(sendingSide->ssl, dataSent);
    }
    else
    {
        sentRc = matrixSslSentData(sendingSide->ssl, dataSent);
    }
# else
    sentRc = matrixSslSentData(sendingSide->ssl, dataSent);
# endif

    /* Received data */
    rc = matrixSslReceivedData(receivingSide->ssl, dataSent, &plaintextBuf,
        &ptLen);

    if (rc == MATRIXSSL_REQUEST_RECV)
    {
        goto SEND_MORE;
    }
    else if (rc == MATRIXSSL_APP_DATA || rc == MATRIXSSL_APP_DATA_COMPRESSED)
    {
        while (rc == MATRIXSSL_APP_DATA || rc == MATRIXSSL_APP_DATA_COMPRESSED)
        {
            /* psTraceBytes("received", plaintextBuf, ptLen); */
            if ((rc = matrixSslProcessedData(receivingSide->ssl, &plaintextBuf,
                     &ptLen)) != 0)
            {
                if (rc == MATRIXSSL_APP_DATA ||
                    rc == MATRIXSSL_APP_DATA_COMPRESSED)
                {
                    continue;
                }
                else if (rc == MATRIXSSL_REQUEST_RECV)
                {
                    goto SEND_MORE;
                }
                else
                {
                    return PS_FAILURE;
                }
            }
        }
        if (sentRc == MATRIXSSL_REQUEST_SEND)
        {
            goto SEND_MORE;
        }
    }
    else
    {
        printf("Unexpected error in exchangeAppData: %d\n", rc);
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}


static int32 initializeServer(sslConn_t *conn, psCipher16_t cipherSuite)
{
    sslKeys_t *keys = NULL;
    ssl_t *ssl = NULL;

# ifdef ENABLE_PERF_TIMING
    psTime_t start, end;
# endif /* ENABLE_PERF_TIMING */
    sslSessOpts_t options;
    const sslCipherSpec_t *spec;

    memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = g_versionFlag;

    if (conn->keys == NULL)
    {
        if ((spec = sslGetDefinedCipherSpec(cipherSuite)) == NULL)
        {
            return PS_FAIL;
        }
        if (matrixSslNewKeys(&keys, NULL) < PS_SUCCESS)
        {
            return PS_MEM_FAIL;
        }
        conn->keys = keys;


# ifdef USE_ECC
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (spec->type == CS_ECDH_ECDSA || spec->type == CS_ECDHE_ECDSA)
        {
#   if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
            if (matrixSslLoadEcKeys(keys, svrEcCertFile, svrEcKeyFile, NULL,
                    clnEcCAfile) < 0)
            {
                return PS_FAILURE;
            }
#   endif   /* MATRIX_USE_FILE_SYSTEM && !USE_HEADER_KEYS */

#   ifdef USE_HEADER_KEYS
            if (matrixSslLoadEcKeysMem(keys, ECC, ECC_SIZE,
                    ECCKEY, ECCKEY_SIZE,
                    ECCCA, ECCCA_SIZE) < 0)
            {
                return PS_FAILURE;
            }
#   endif   /* USE_HEADER_KEYS */
        }

        /* ECDH_RSA suites have a different cert pair */
        if (spec->type == CS_ECDH_RSA)
        {
#   if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
            if (matrixSslLoadEcKeys(keys, svrEcRsaCertFile, svrEcRsaKeyFile,
                    NULL, clnEcRsaCAfile) < 0)
            {
                return PS_FAILURE;
            }
#   endif   /* MATRIX_USE_FILE_SYSTEM && !USE_HEADER_KEYS */

#   ifdef USE_HEADER_KEYS
            if (matrixSslLoadEcKeysMem(keys, ECDHRSA256, sizeof(ECDHRSA256),
                    ECDHRSA256KEY, sizeof(ECDHRSA256KEY),
                    ECDHRSA2048CA, sizeof(ECDHRSA2048CA)) < 0)
            {
                return PS_FAILURE;
            }
#   endif /* USE_HEADER_KEYS */
        }
#  endif  /* !USE_ONLY_PSK_CIPHER_SUITE */
# endif   /* USE_ECC */


# ifdef USE_RSA
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (spec->type == CS_RSA || spec->type == CS_DHE_RSA ||
            spec->type == CS_ECDHE_RSA)
        {
#   if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
            if (matrixSslLoadRsaKeys(keys, svrCertFile, svrKeyFile, NULL,
                    clnCAfile) < 0)
            {
                return PS_FAILURE;
            }
#   endif   /* MATRIX_USE_FILE_SYSTEM && !USE_HEADER_KEYS */

#   ifdef USE_HEADER_KEYS
            if (matrixSslLoadRsaKeysMem(keys, (unsigned char *) RSACERT, RSA_SIZE,
                    (unsigned char *) RSAKEY, RSAKEY_SIZE,
                    (unsigned char *) RSACA, RSACA_SIZE) < 0)
            {
                return PS_FAILURE;
            }
#   endif /* USE_HEADER_KEYS */
        }
#  endif  /* !USE_ONLY_PSK_CIPHER_SUITE */
# endif   /* USE_RSA */

# ifdef REQUIRE_DH_PARAMS
        if (spec->type == CS_DHE_RSA || spec->type == CS_DH_ANON ||
            spec->type == CS_DHE_PSK)
        {
#  if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
            matrixSslLoadDhParams(keys, dhParamFile);
#  endif
#  ifdef USE_HEADER_KEYS
            matrixSslLoadDhParamsMem(keys, DHPARAM, DH_SIZE);
#  endif
        }
# endif /* REQUIRE_DH_PARAMS */

# ifdef USE_PSK_CIPHER_SUITE
        if (spec->type == CS_PSK || spec->type == CS_DHE_PSK)
        {
            int rc;
            for (rc = 0; rc < PSK_HEADER_TABLE_COUNT; rc++)
            {
                matrixSslLoadPsk(keys,
                    PSK_HEADER_TABLE[rc].key, sizeof(PSK_HEADER_TABLE[rc].key),
                    PSK_HEADER_TABLE[rc].id, sizeof(PSK_HEADER_TABLE[rc].id));
            }
        }
# endif /* USE_PSK_CIPHER_SUITE */
    }
# ifdef ENABLE_PERF_TIMING
    conn->hsTime = 0;
    psGetTime(&start, NULL);
# endif /* ENABLE_PERF_TIMING */
/*
    Create a new SSL session for the new socket and register the
    user certificate validator. No client auth first time through
 */
# ifdef USE_SERVER_SIDE_SSL
    if (matrixSslNewServerSession(&ssl, conn->keys, NULL, &options) < 0)
    {
        return PS_FAILURE;
    }
# endif

# ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    conn->hsTime += psDiffMsecs(start, end, NULL);
# endif /* ENABLE_PERF_TIMING */
    conn->ssl = ssl;

    return PS_SUCCESS;
}


static int32 initializeClient(sslConn_t *conn, psCipher16_t cipherSuite,
    sslSessionId_t *sid)
{
    ssl_t *ssl;
    sslKeys_t *keys;

# ifdef ENABLE_PERF_TIMING
    psTime_t start, end;
# endif /* ENABLE_PERF_TIMING */
    sslSessOpts_t options;
    const sslCipherSpec_t *spec;

    memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = g_versionFlag;
# ifdef TEST_RESUMPTIONS_WITH_SESSION_TICKETS
    options.ticketResumption = 1;
# endif

    if (conn->keys == NULL)
    {
        if ((spec = sslGetDefinedCipherSpec(cipherSuite)) == NULL)
        {
            return PS_FAIL;
        }
        if (matrixSslNewKeys(&keys, NULL) < PS_SUCCESS)
        {
            return PS_MEM_FAIL;
        }
        conn->keys = keys;

# ifdef USE_ECC_CIPHER_SUITE
        if (spec->type == CS_ECDHE_ECDSA || spec->type == CS_ECDHE_RSA)
        {
            /* For ephemeral ECC keys, define the ephemeral size here,
               otherwise it will default to the largest. We choose the size
               based on the size set for the ECDSA key (even in RSA case). */
            switch (ECC_SIZE)
            {
            case EC192_SIZE:
                options.ecFlags = SSL_OPT_SECP192R1;
                break;
            case EC224_SIZE:
                options.ecFlags = SSL_OPT_SECP224R1;
                break;
            case EC256_SIZE:
                options.ecFlags = SSL_OPT_SECP256R1;
                break;
            case EC384_SIZE:
                options.ecFlags = SSL_OPT_SECP384R1;
                break;
            case EC521_SIZE:
                options.ecFlags = SSL_OPT_SECP521R1;
                break;
            }
        }
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (spec->type == CS_ECDH_ECDSA || spec->type == CS_ECDHE_ECDSA)
        {
#   if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
            if (matrixSslLoadEcKeys(keys, clnEcCertFile, clnEcKeyFile, NULL,
                    svrEcCAfile) < 0)
            {
                return PS_FAILURE;
            }
#   endif   /* MATRIX_USE_FILE_SYSTEM && !USE_HEADER_KEYS */

#   ifdef USE_HEADER_KEYS
            if (matrixSslLoadEcKeysMem(keys, ECC, ECC_SIZE,
                    ECCKEY, ECCKEY_SIZE,
                    ECCCA, ECCCA_SIZE) < 0)
            {
                return PS_FAILURE;
            }
#   endif   /* USE_HEADER_KEYS */
        }

#   ifdef USE_RSA
        /* ECDH_RSA suites have different cert pair. */
        if (spec->type == CS_ECDH_RSA)
        {
#    if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
            if (matrixSslLoadEcKeys(keys, clnEcRsaCertFile, clnEcRsaKeyFile,
                    NULL, svrEcRsaCAfile) < 0)
            {
                return PS_FAILURE;
            }
#    endif  /* MATRIX_USE_FILE_SYSTEM && !USE_HEADER_KEYS */

#    ifdef USE_HEADER_KEYS
            if (matrixSslLoadEcKeysMem(keys, ECDHRSA521, sizeof(ECDHRSA521),
                    ECDHRSA521KEY, sizeof(ECDHRSA521KEY),
                    ECDHRSA1024CA, sizeof(ECDHRSA1024CA)) < 0)
            {
                return PS_FAILURE;
            }
#    endif /* USE_HEADER_KEYS */
        }
#   endif  /* USE_RSA */
#  endif   /* USE_ONLY_PSK_CIPHER_SUITE */
# endif    /* USE_ECC */

# ifdef USE_RSA
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (spec->type == CS_RSA || spec->type == CS_DHE_RSA ||
            spec->type == CS_ECDHE_RSA)
        {
#   if defined(MATRIX_USE_FILE_SYSTEM) && !defined(USE_HEADER_KEYS)
            if (matrixSslLoadRsaKeys(keys, clnCertFile, clnKeyFile, NULL,
                    svrCAfile) < 0)
            {
                return PS_FAILURE;
            }
#   endif   /* MATRIX_USE_FILE_SYSTEM && !USE_HEADER_KEYS */

#   ifdef USE_HEADER_KEYS
            if (matrixSslLoadRsaKeysMem(keys, RSACERT, RSA_SIZE,
                    RSAKEY, RSAKEY_SIZE, (unsigned char *) RSACA,
                    RSACA_SIZE) < 0)
            {
                return PS_FAILURE;
            }
#   endif /* USE_HEADER_KEYS */
        }
#  endif  /* USE_ONLY_PSK_CIPHER_SUITE  */
# endif   /* USE_RSA */

# ifdef USE_PSK_CIPHER_SUITE
        if (spec->type == CS_PSK || spec->type == CS_DHE_PSK)
        {
            matrixSslLoadPsk(keys,
                PSK_HEADER_TABLE[0].key, sizeof(PSK_HEADER_TABLE[0].key),
                PSK_HEADER_TABLE[0].id, sizeof(PSK_HEADER_TABLE[0].id));
        }
# endif /* USE_PSK_CIPHER_SUITE */
    }

    conn->ssl = NULL;
# ifdef ENABLE_PERF_TIMING
    conn->hsTime = 0;
    psGetTime(&start, NULL);
# endif /* ENABLE_PERF_TIMING */
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    options.useExtCvSigOp = 1;
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

    if (matrixSslNewClientSession(&ssl, conn->keys, sid, &cipherSuite,
            1, clnCertChecker, "localhost", NULL, NULL, &options) < 0)
    {
        return PS_FAILURE;
    }

# ifdef ENABLE_PERF_TIMING
    psGetTime(&end, NULL);
    conn->hsTime += psDiffMsecs(start, end, NULL);
# endif /* ENABLE_PERF_TIMING */

    conn->ssl = ssl;

    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Delete session and connection
 */
static void freeSessionAndConnection(sslConn_t *conn)
{
    if (conn->ssl != NULL)
    {
        matrixSslDeleteSession(conn->ssl);
    }
    matrixSslDeleteKeys(conn->keys);
    conn->ssl = NULL;
    conn->keys = NULL;
}

/* Ignoring the CERTIFICATE_EXPIRED alert in the test because it will
    always fail on Windows because there is no implementation for that */
static int32_t clnCertChecker(ssl_t *ssl, psX509Cert_t *cert, int32_t alert)
{
    if (alert == SSL_ALERT_CERTIFICATE_EXPIRED)
    {
        return 0;
    }
    return alert;
}

# ifdef SSL_REHANDSHAKES_ENABLED
static int32 clnCertCheckerUpdate(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
    if (alert == SSL_ALERT_CERTIFICATE_EXPIRED)
    {
        return 0;
    }
    return alert;
}
# endif /* SSL_REHANDSHAKES_ENABLED */

# ifdef USE_CLIENT_AUTH
static int32 svrCertChecker(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
    if (alert == SSL_ALERT_CERTIFICATE_EXPIRED)
    {
        return 0;
    }
    return alert;
}
# endif /* USE_CLIENT_AUTH */


# ifdef USE_MATRIXSSL_STATS
static void statCback(void *ssl, void *stat_ptr, int32 type, int32 value)
{
    /* printf("Got stat event %d with value %d\n", type, value); */
}
# endif
/******************************************************************************/

#endif /* !defined(USE_SERVER_SIDE_SSL) || !defined(USE_CLIENT_SIDE_SSL) */
