/**
 *      @file    sslTest.c
 *      @version $Format:%h%d$
 *
 *      Self-test program that runs Matrix server against Matrix client.
 *      Tests various handshake types and exchange of application data.
 *      Iterates over all supported protocol versions and ciphersuites.
 */
/*
 *      Copyright (c) 2014-2018 INSIDE Secure Corporation
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
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#include "matrixssl/matrixsslApi.h"
#include "psUtil.h"
#include "psStat.h"
#include "osdep_stdio.h"

# ifdef USE_MULTITHREADING
#  include "osdep_pthread.h"
# endif /* USE_MULTITHREADING */

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

#define CLI_APP_BIG_DATA        131072
#define SVR_APP_BIG_DATA        131072

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
#include "osdep_stdio.h"
#define testPrint(x) Printf(x)
#define testPrintInt(x, i) Printf(x, i)
#define testPrintStr(x, s) Printf(x, s)

#ifdef USE_MATRIXSSL_STATS
static void statCback(void *ssl, void *stat_ptr, int32 type, int32 value);
#endif

/* #define TEST_RESUMPTIONS_WITH_SESSION_TICKETS */
#define ABORT_IMMEDIATELY_ON_ERROR /* Useful for debugging multi-threaded runs. */

# ifdef USE_MULTITHREADING
#  define __THREAD  __thread
# else
#  define __THREAD
# endif

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

# include "osdep_stdio.h"
int main(void)
{
    Printf("Must enable both USE_SERVER_SIDE_SSL and USE_CLIENT_SIDE_SSL to run\n");
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
static __THREAD testResult_t g_results[4 * 3 * 48];  /* 4 versions, 3 keysizes,
                                                        48 ciphers */
# endif

typedef struct
{
    const char name[64];
    uint16_t id;
} testCipherSpec_t;

# ifdef USE_TLS_1_3
typedef struct
{
    unsigned char* data;
    uint32 len;
} earlyDataInfo_t;

static __THREAD earlyDataInfo_t g_earlyDataInfo[64];
static __THREAD uint32 g_senderEarlyDataIndex;
static __THREAD uint32 g_receiverEarlyDataIndex;
static __THREAD uint32 g_expectedEarlyDataReceives;

static int32 tls13SendEarlyData(sslConn_t *conn, uint32 writeLen);
static void tls13ResetEarlyData();
# endif /* USE_TLS_1_3 */

/******************************************************************************/
/*
    Key loading.  The header files are a bit easier to work with because
    it is better to get a compile error that a header isn't found rather
    than a run-time error that a .pem file isn't found
 */
#  ifndef USE_FILE_SYSTEM_KEYS
#   define USE_HEADER_KEYS /* comment out this line to test with .pem files */
#  endif

#  ifndef USE_HEADER_KEYS
#   define USE_FILE_SYSTEM_KEYS /* Just in case the above USE_HEADER_KEYS
                                   was commented out. */
#  endif

#  if !defined(MATRIX_USE_FILE_SYSTEM) && defined USE_FILE_SYSTEM_KEYS
#   error "USE_FILE_SYSTEM_KEYS requires MATRIX_USE_FILE_SYSTEM."
#  endif

#  ifdef USE_FILE_SYSTEM_KEYS
#   ifdef USE_RSA
#    ifdef USE_CL_RSA
static char svrKeyFile[] = "../../testkeys/RSA/3072_RSA_KEY.pem";
static char svrCertFile[] = "../../testkeys/RSA/3072_RSA.pem";
static char svrCAfile[] = "../../testkeys/RSA/3072_RSA_CA.pem";
#    else
static char svrKeyFile[] = "../../testkeys/RSA/1024_RSA_KEY.pem";
static char svrCertFile[] = "../../testkeys/RSA/1024_RSA.pem";
static char svrCAfile[] = "../../testkeys/RSA/1024_RSA_CA.pem";
#    endif /* USE_CL_RSA */
static char clnCAfile[] = "../../testkeys/RSA/2048_RSA_CA.pem";
static char clnKeyFile[] = "../../testkeys/RSA/2048_RSA_KEY.pem";
static char clnCertFile[] = "../../testkeys/RSA/2048_RSA.pem";
#   endif /* USE_RSA */
#   ifdef USE_ECC
static char svrEcKeyFile[] = "../../testkeys/EC/192_EC_KEY.pem";
static char svrEcCertFile[] = "../../testkeys/EC/192_EC.pem";
static char svrEcCAfile[] = "../../testkeys/EC/192_EC_CA.pem";
static char clnEcKeyFile[] = "../../testkeys/EC/224_EC_KEY.pem";
static char clnEcCertFile[] = "../../testkeys/EC/224_EC.pem";
static char clnEcCAfile[] = "../../testkeys/EC/224_EC_CA.pem";
/* ECDH_RSA certs */
static char svrEcRsaKeyFile[] = "../../testkeys/ECDH_RSA/256_ECDH-RSA_KEY.pem";
static char svrEcRsaCertFile[] = "../../testkeys/ECDH_RSA/256_ECDH-RSA.pem";
static char svrEcRsaCAfile[] = "../../testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.pem";
static char clnEcRsaKeyFile[] = "../../testkeys/ECDH_RSA/521_ECDH-RSA_KEY.pem";
static char clnEcRsaCertFile[] = "../../testkeys/ECDH_RSA/521_ECDH-RSA.pem";
static char clnEcRsaCAfile[] = "../../testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.pem";
#   endif /* USE_ECC */
#   ifdef REQUIRE_DH_PARAMS
static char dhParamFile[] = "../../testkeys/DH/3072_DH_PARAMS.pem";
#   endif /* REQUIRE_DH_PARAMS */
#  endif  /* USE_FILE_SYSTEM_KEYS */

#  ifdef USE_RSA
#   include "testkeys/RSA/1024_RSA_KEY.h"
#   include "testkeys/RSA/1024_RSA.h"
#   include "testkeys/RSA/1024_RSA_CA.h"
#   include "testkeys/RSA/2048_RSA_KEY.h"
#   include "testkeys/RSA/2048_RSA.h"
#   include "testkeys/RSA/2048_RSA_CA.h"
#   include "testkeys/RSA/3072_RSA_KEY.h"
#   include "testkeys/RSA/3072_RSA.h"
#   include "testkeys/RSA/3072_RSA_CA.h"
#   include "testkeys/RSA/4096_RSA_KEY.h"
#   include "testkeys/RSA/4096_RSA.h"
#   include "testkeys/RSA/4096_RSA_CA.h"
static __THREAD const unsigned char *RSAKEY, *RSACERT, *RSACA;
static __THREAD uint32_t RSAKEY_SIZE, RSA_SIZE, RSACA_SIZE;
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
static __THREAD const unsigned char *ECCKEY, *ECC, *ECCCA;
static __THREAD uint32_t ECCKEY_SIZE, ECC_SIZE, ECCCA_SIZE;

#   include "testkeys/ECDH_RSA/256_ECDH-RSA_KEY.h"
#   include "testkeys/ECDH_RSA/256_ECDH-RSA.h"
#   include "testkeys/ECDH_RSA/1024_ECDH-RSA_CA.h"
#   include "testkeys/ECDH_RSA/2048_ECDH-RSA_CA.h"

#   include "testkeys/ECDH_RSA/521_ECDH-RSA_KEY.h"
#   include "testkeys/ECDH_RSA/521_ECDH-RSA.h"
#   include "testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.h"
#  endif /* USE_ECC */

#  ifdef REQUIRE_DH_PARAMS
#   include "testkeys/DH/1024_DH_PARAMS.h"
#   include "testkeys/DH/1536_DH_PARAMS.h"
#   include "testkeys/DH/2048_DH_PARAMS.h"
#   include "testkeys/DH/3072_DH_PARAMS.h"
#   include "testkeys/DH/4096_DH_PARAMS.h"
#   ifdef USE_LARGE_DH_GROUPS
#    include "testkeys/DH/ffdhe6144_DH_PARAMS.h"
#    include "testkeys/DH/ffdhe8192_DH_PARAMS.h"
#   endif
static __THREAD const unsigned char *DHPARAM;
static __THREAD uint32_t DH_SIZE;
#  endif /* REQUIRE_DH_PARAMS */

#  ifdef USE_TLS_1_3
#   include "testkeys/PSK/tls13_psk.h"
#  endif /* USE_TLS_1_3 */

/******************************************************************************/

int sslTest(void);
int tls13sslTest(void);

static void freeSessionAndConnection(sslConn_t *cpp);

static int32 initializeServer(sslConn_t *svrConn, psCipher16_t cipher);
static int32 initializeClient(sslConn_t *clnConn, psCipher16_t cipher,
                              sslSessionId_t *sid);

static int32 initializeHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
                                 psCipher16_t cipherSuite,
                                 sslSessionId_t *sid);
# ifdef USE_TLS_1_3
static int32 tls13InitializeServer(sslConn_t *svrConn, psCipher16_t cipher, uint32 algorithm);
static int32 tls13InitializeClient(sslConn_t *clnConn, psCipher16_t cipher, uint32 algorithm,
                              sslSessionId_t *sid);

static int32 tls13InitializeHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
                                 psCipher16_t cipherSuite, uint32 algorithm,
                                 sslSessionId_t *sid);
# endif
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
                                               sslConn_t *svrConn, psCipher16_t cipherSuite,
                                               uint16_t type);
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
# ifdef USE_TLS_1_3
static int32 tls13PerformHandshake(sslConn_t *sendingSide, sslConn_t *receivingSide);
# endif
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

enum {
    TLS13_RSA = 1,
    TLS13_ECC,
    TLS13_PSK
   };
static __THREAD uint32_t g_versionFlag = 0;

/* Protocol versions to test for each suite */
const static __THREAD uint32_t g_versions[] = {
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
const static __THREAD char *g_version_str[] = {
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

const static __THREAD testCipherSpec_t ciphers[] = {
/* TLS1.3 */
#ifdef USE_TLS_AES_128_GCM_SHA256
    CS(TLS_AES_128_GCM_SHA256),
#endif
#ifdef USE_TLS_AES_256_GCM_SHA384
    CS(TLS_AES_256_GCM_SHA384),
#endif
#ifdef USE_TLS_CHACHA20_POLY1305_SHA256
    CS(TLS_CHACHA20_POLY1305_SHA256),
#endif

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

# ifdef USE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    CS(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
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

#   define FLPS_SSL_TEST_MAX_THREADS 1000

int parse_args(int argc, char **argv, int *num_threads_p)
{
    int rc = 0;

    /* Parse --threads and --help options, otherwise fail. */
    if (argc == 2 && !Strcmp(argv[1], "--help"))
    {
        rc = 256;
    }
    else if (argc == 3 && !Strcmp(argv[1], "--threads"))
    {
        rc = 0;
        *num_threads_p = atoi(argv[2]);
    }
    else if (argc == 2)
    {
        rc = 0;
        *num_threads_p = atoi(argv[1]);
    }
    else if (argc > 1)
    {
        rc = 1;
    }

    if (rc == 0 && *num_threads_p == 0)
    {
        rc = 1;
    }

    /* On failure or --help, show usage. */
    if (rc != 0)
    {
        if (rc != 256)
        {
            Fprintf(stderr, "Invalid options.\n");
        }
        Fprintf(stderr,
            "Usage: %s [--help | [--threads] num_threads]\n",
            argv[0]);
        return rc;
    }
    return 0;
}

/******************************************************************************/
/*
    This test application will exercise the SSL/TLS handshake and app
    data exchange for every eligible cipher.
 */

/* Invoke a single instance of sslTest. */
int invokeSslTest(void)
{
# if defined(USE_TLS_1_3)
    if (Getenv("TEST_TLS13_ONLY"))
    {
        return tls13sslTest();
    }
    return sslTest() || tls13sslTest();
# else
    return sslTest();
# endif
}

/* pthreads wrapper for invokeSslTest. */
void *sslTestPt(void *mustBeNull)
{
    /* Adapt sslTest() API for pthreads. */
    if (mustBeNull == NULL)
    {
        return (void *) (unsigned long) invokeSslTest();
    }

    return NULL;
}

#   define FLPS_SSL_TEST_MAX_THREADS 1000

int main(int argc, char **argv)
{
    int rc, num_threads = 0;
#   ifdef USE_MULTITHREADING
    int i;
    pthread_t thread[FLPS_SSL_TEST_MAX_THREADS];
#   endif

    if (argc == 1)
    {
        /* Standard operation. */
        Puts("Single-threaded test");
        num_threads = 1;
    }
    else
    {
        /* Parse arguments (currently the number of threads). */
        rc = parse_args(argc, argv, &num_threads);
        if (rc != 0)
        {
            return rc & 255;
        }
    }

    if (num_threads > (SSL_SESSION_TABLE_SIZE / 2))
    {
        Fprintf(stderr, "Error: trying to use %d threads with a session table " \
                "size %u.\n SSL_SESSION_TABLE_SIZE should be defined to be at " \
                "least 2 x the number of threads.\n",
                num_threads, SSL_SESSION_TABLE_SIZE);
        return PS_FAILURE;
    }

    if (matrixSslOpen() < 0)
    {
        Fprintf(stderr, "matrixSslOpen failed, exiting...\n");
        return EXIT_FAILURE;
    }

    if (num_threads > 1)
    {
        /* Multi-threaded test. */
#   ifndef USE_MULTITHREADING
        Fprintf(stderr,
            "ERROR: Multithreading is not enabled.\n"
            "For a multithreaded test, enable "
            "USE_MULTITHREADING in core/coreConfig.h and recompile.\n");
        exit(EXIT_FAILURE);
#   else /* USE_MULTITHREADING */
        for (i = 0; i < num_threads; i++)
        {
            rc = Pthread_create(&thread[i], NULL,
                sslTestPt, NULL);
            if (rc)
            {
                Printf("pthread_create failed : %d\n", rc);
                exit(EXIT_FAILURE);
            }
        }
        for (i = 0; i < num_threads; i++)
        {
            Printf("Waiting for thread %d to finish\n", i);
            Pthread_join(thread[i], NULL);
        }
#   endif /* USE_MULTITHREADING */
    }
    else
    {
        /* Single-threaded test. */
        rc = invokeSslTest();
        if (rc == PS_SUCCESS )
        {
        }
        goto out;
    }

out:
    matrixSslClose();
    Printf("Tested with %d threads\n", num_threads);

    if (rc == PS_SUCCESS)
    {
        return 0;
    }
    else
    {
        return EXIT_FAILURE;
    }
}

psBool_t testCiphersuite(const testCipherSpec_t *spec)
{

    /* No run-time restrictions unless USE_CIPHER_LIST is given. */
    if (!Getenv("USE_CIPHER_LIST"))
    {
        return PS_TRUE;
    }

    if (Getenv(spec->name))
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

psBool_t testProtocolVersion(uint32_t version)
{
    /* No run-time restrictions unless USE_VERION_LIST is given. */
    if (!Getenv("USE_VERSION_LIST"))
    {
        return PS_TRUE;
    }

    if (version == SSL_FLAGS_SSLV3)
    {
        if (Getenv("SSL_3_0"))
        {
            return PS_TRUE;
        }
    }
    if (version == SSL_FLAGS_TLS_1_0)
    {
        if (Getenv("TLS_1_0"))
        {
            return PS_TRUE;
        }
    }
    if (version == SSL_FLAGS_TLS_1_1)
    {
        if (Getenv("TLS_1_1"))
        {
            return PS_TRUE;
        }
    }
    if (version == SSL_FLAGS_TLS_1_2)
    {
        if (Getenv("TLS_1_2"))
        {
            return PS_TRUE;
        }
    }
    if (version == SSL_FLAGS_TLS_1_3)
    {
        if (Getenv("TLS_1_3"))
        {
            return PS_TRUE;
        }
    }
    if (version == (SSL_FLAGS_TLS_1_2 | SSL_FLAGS_DTLS))
    {
        if (Getenv("DTLS_1_2"))
        {
            return PS_TRUE;
        }
    }
    if (version == (SSL_FLAGS_TLS_1_1 | SSL_FLAGS_DTLS))
    {
        if (Getenv("DTLS_1_0"))
        {
            return PS_TRUE;
        }
    }
    return PS_FALSE;
}

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

# ifndef USE_ONLY_PSK_CIPHER_SUITE
    sslSessionId_t *clientSessionId;
# endif

    svrConn = psMalloc(MATRIX_NO_POOL, sizeof(sslConn_t));
    clnConn = psMalloc(MATRIX_NO_POOL, sizeof(sslConn_t));
    Memset(svrConn, 0, sizeof(sslConn_t));
    Memset(clnConn, 0, sizeof(sslConn_t));

# ifdef USE_RSA
    RSA_SIZE = 0;
# endif
# ifdef USE_ECC
    ECC_SIZE = 0;
# endif
#  ifdef REQUIRE_DH_PARAMS
    DH_SIZE = 0;
#  endif  /* REQUIRE_DH_PARAMS */

    for (id = 0; ciphers[id].id > 0; id++)
    {
        if ((spec = sslGetDefinedCipherSpec(ciphers[id].id)) == NULL)
        {
            testPrint("         FAILED: cipher spec lookup\n");
            goto LBL_FREE;
        }
        if (spec->type == CS_TLS13)
        {
            /* TLS1.3 is tested in separate function */
            continue;
        }
        if (!testCiphersuite(&ciphers[id]))
        {
            continue;
        }
        keysize = authsize = 0;
# ifdef USE_RSA
L_NEXT_RSA:
        if (spec->type == CS_RSA)
        {
            switch (RSA_SIZE)
            {
            case 0:
#   ifndef USE_CL_RSA
                RSAKEY = RSA1024KEY; RSAKEY_SIZE = RSA1024KEY_SIZE;
                RSACERT = RSA1024; RSA_SIZE = RSA1024_SIZE;
                RSACA = RSA1024CA; RSACA_SIZE = RSA1024CA_SIZE;
                keysize = authsize = 1024;
#   else
                RSAKEY = RSA2048KEY; RSAKEY_SIZE = RSA2048KEY_SIZE;
                RSACERT = RSA2048; RSA_SIZE = RSA2048_SIZE;
                RSACA = RSA2048CA; RSACA_SIZE = RSA2048CA_SIZE;
                keysize = authsize = 2048;
#   endif       /* USE_CL_RSA */
                break;
            case RSA1024_SIZE:
                RSAKEY = RSA2048KEY; RSAKEY_SIZE = RSA2048KEY_SIZE;
                RSACERT = RSA2048; RSA_SIZE = RSA2048_SIZE;
                RSACA = RSA2048CA; RSACA_SIZE = RSA2048CA_SIZE;
                keysize = authsize = 2048;
                break;
            case RSA2048_SIZE:
                RSAKEY = RSA3072KEY; RSAKEY_SIZE = RSA3072KEY_SIZE;
                RSACERT = RSA3072; RSA_SIZE = RSA3072_SIZE;
                RSACA = RSA3072CA; RSACA_SIZE = RSA3072CA_SIZE;
                keysize = authsize = 3072;
                break;
            case RSA3072_SIZE:
#   if !defined(EMBEDDED) && !defined(USE_CL_CRYPTO)
                RSAKEY = RSA4096KEY; RSAKEY_SIZE = RSA4096KEY_SIZE;
                RSACERT = RSA4096; RSA_SIZE = RSA4096_SIZE;
                RSACA = RSA4096CA; RSACA_SIZE = RSA4096CA_SIZE;
                keysize = authsize = 4096;
                break;
#   endif
            case RSA4096_SIZE:
                RSA_SIZE = 0;
                break;
            }
            if (RSA_SIZE == 0)
            {
                continue;   /* Next cipher suite */
            }
        }
        /* For other ciphersuites that use RSA for auth only, default to 2048 */
        if (spec->type == CS_DHE_RSA ||
            spec->type == CS_ECDH_RSA || spec->type == CS_ECDHE_RSA)
        {
#   ifndef USE_CL_RSA
            RSAKEY = RSA1024KEY; RSAKEY_SIZE = RSA1024KEY_SIZE;
            RSACERT = RSA1024; RSA_SIZE = RSA1024_SIZE;
            RSACA = RSA1024CA; RSACA_SIZE = RSA1024CA_SIZE;
            authsize = 1024;
#   else
            RSAKEY = RSA2048KEY; RSAKEY_SIZE = RSA2048KEY_SIZE;
            RSACERT = RSA2048; RSA_SIZE = RSA2048_SIZE;
            RSACA = RSA2048CA; RSACA_SIZE = RSA2048CA_SIZE;
            authsize = 2048;
#   endif   /* USE_CL_RSA */
#   ifdef USE_ECC
            ECCKEY = EC256KEY; ECCKEY_SIZE = EC256KEY_SIZE;
            ECC = EC256; ECC_SIZE = EC256_SIZE;
            ECCCA = EC256CA; ECCCA_SIZE = EC256CA_SIZE;
            keysize = 256;
#   endif
        }
# endif /* USE_RSA */

# ifdef USE_ECC
L_NEXT_ECC:
        if (spec->type == CS_ECDH_ECDSA || spec->type == CS_ECDHE_ECDSA)
        {
            switch (ECC_SIZE)
            {
            case 0:
#   ifdef USE_SECP192R1
                ECCKEY = EC192KEY; ECCKEY_SIZE = EC192KEY_SIZE;
                ECC = EC192; ECC_SIZE = EC192_SIZE;
                ECCCA = EC192CA; ECCCA_SIZE = EC192CA_SIZE;
                keysize = authsize = 192;
                break;
#   else
#    ifdef USE_SECP224R1
                /* P-192 skipped. */
                ECCKEY = EC224KEY; ECCKEY_SIZE = EC224KEY_SIZE;
                ECC = EC224; ECC_SIZE = EC224_SIZE;
                ECCCA = EC224CA; ECCCA_SIZE = EC224CA_SIZE;
                keysize = authsize = 224;
                break;
#    else
                /* P-192 and P-224 skipped. */
                ECCKEY = EC256KEY; ECCKEY_SIZE = EC256KEY_SIZE;
                ECC = EC256; ECC_SIZE = EC256_SIZE;
                ECCCA = EC256CA; ECCCA_SIZE = EC256CA_SIZE;
                keysize = authsize = 256;
                break;
#    endif /* USE_SECP224R1 */
#   endif  /* USE_SECP192R1 */
            case EC192_SIZE:
#   ifdef USE_SECP224R1
                ECCKEY = EC224KEY; ECCKEY_SIZE = EC224KEY_SIZE;
                ECC = EC224; ECC_SIZE = EC224_SIZE;
                ECCCA = EC224CA; ECCCA_SIZE = EC224CA_SIZE;
                keysize = authsize = 224;
                break;
#   else
                /* P-224 skipped. */
                ECCKEY = EC256KEY; ECCKEY_SIZE = EC256KEY_SIZE;
                ECC = EC256; ECC_SIZE = EC256_SIZE;
                ECCCA = EC256CA; ECCCA_SIZE = EC256CA_SIZE;
                keysize = authsize = 256;
                break;
#   endif       /* USE_SECP224R1 */
            case EC224_SIZE:
                ECCKEY = EC256KEY; ECCKEY_SIZE = EC256KEY_SIZE;
                ECC = EC256; ECC_SIZE = EC256_SIZE;
                ECCCA = EC256CA; ECCCA_SIZE = EC256CA_SIZE;
                keysize = authsize = 256;
                break;
            case EC256_SIZE:
#   ifndef EMBEDDED
                ECCKEY = EC384KEY; ECCKEY_SIZE = EC384KEY_SIZE;
                ECC = EC384; ECC_SIZE = EC384_SIZE;
                ECCCA = EC384CA; ECCCA_SIZE = EC384CA_SIZE;
                keysize = authsize = 384;
                break;
            case EC384_SIZE:
#    ifdef USE_SECP521R1
                ECCKEY = EC521KEY; ECCKEY_SIZE = EC521KEY_SIZE;
                ECC = EC521; ECC_SIZE = EC521_SIZE;
                ECCCA = EC521CA; ECCCA_SIZE = EC521CA_SIZE;
                keysize = authsize = 521;
                break;
#    else
                /* P-521 skipped. */
                ECC_SIZE = 0;
#    endif /* USE_SECP521R1 */
            case EC521_SIZE:
#   endif  /* !EMBEDDED */
                ECC_SIZE = 0;
                break;
            }
            if (ECC_SIZE == 0)
            {
                continue;   /* Next cipher suite */
            }
        }
# endif /* USE_ECC */

#  ifdef REQUIRE_DH_PARAMS
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
                DHPARAM = DHPARAM3072; DH_SIZE = DHPARAM3072_SIZE;
                keysize = 3072;
                break;
            case DHPARAM3072_SIZE:
#   if !defined(EMBEDDED) || defined(USE_LARGE_DH_GROUPS)
                DHPARAM = DHPARAM4096; DH_SIZE = DHPARAM4096_SIZE;
                keysize = 4096;
                break;
#   if defined(USE_LARGE_DH_GROUPS)
            case DHPARAM4096_SIZE:
                DHPARAM = ffdhe6144_DH_PARAMS;
                DH_SIZE = ffdhe6144_DH_PARAMS_SIZE;
                keysize = 6144;
                break;
            case ffdhe6144_DH_PARAMS_SIZE:
                DHPARAM = ffdhe8192_DH_PARAMS;
                DH_SIZE = ffdhe8192_DH_PARAMS_SIZE;
                keysize = 8192;
                break;
            case ffdhe8192_DH_PARAMS_SIZE:
#   else
            case DHPARAM4096_SIZE:
#   endif
#   endif       /* !EMBEDDED || USE_LARGE_DH_GROUPS */
                DH_SIZE = 0;
                break;
            }
            if (DH_SIZE == 0)
            {
                continue; /* Next ciphersuite */
            }
        }
#  endif /* REQUIRE_DH_PARAMS */

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
            if (g_versionFlag & SSL_FLAGS_DTLS)
            {
#  ifdef REQUIRE_DH_PARAMS
                if (DH_SIZE > DHPARAM4096_SIZE)
                {
                    testPrintStr("Skipping %s with DTLS\n\n", "large DH groups");
                    continue;
                }
#  endif /* REQUIRE_DH_PARAMS */
            }
# ifdef USE_LIBSODIUM_AES_GCM
            /* Libsodium supports only aes256-gcm, not 128 */
            if ((spec->flags & CRYPTO_FLAGS_AES) && (spec->flags & CRYPTO_FLAGS_GCM))
            {
                testPrintStr("Skipping %s libsodium\n\n", (char *) ciphers[id].name);
                continue;
            }
# endif
            if (!testProtocolVersion(g_versions[v]))
            {
                continue;
            }
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
            testPrint(" Standard handshake test\n");
# ifdef ENABLE_PERF_TIMING
/*
        Each matrixSsl call in the handshake is wrapped by a timer.  Data
        exchange is NOT included in the timer
 */
            result->cid = id;
            result->ver = v;
            clnTime = svrTime = 0;
            testPrintInt("              %d connections\n", (int32) CONN_ITER);
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
                testPrint("             FAILED: initializing Standard handshake\n");
                goto LBL_FREE;
            }
# ifdef USE_MATRIXSSL_STATS
            matrixSslRegisterStatCallback(clnConn->ssl, statCback, NULL);
            matrixSslRegisterStatCallback(svrConn->ssl, statCback, NULL);
# endif
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Standard handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Standard handshake");
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
                if (exchangeAppData(clnConn, svrConn, CLI_APP_BIG_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_BIG_DATA) < 0)
                {
                    testPrint(" but FAILED to exchange big application data\n");
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
        testPrintInt("          CLIENT: %d "TIME_UNITS, (int32) clnTime / CONN_ITER);
        testPrintInt("          SERVER: %d "TIME_UNITS, (int32) svrTime / CONN_ITER);
        testPrint("\n");
# endif     /* ENABLE_PERF_TIMING */

# if defined(SSL_REHANDSHAKES_ENABLED) && !defined(USE_ZLIB_COMPRESSION)
#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
        if (NGTD_VER(clnConn->ssl, v_dtls_any) &&
                clnConn->ssl->cipher->flags & CRYPTO_FLAGS_GCM &&
                spec->flags & CRYPTO_FLAGS_GCM)
            {
                testPrint("  Re-handshakes with a GCM-to-GCM change are disabled\n");
                goto skip_client_initiated_rehandshake;
            }
#   endif   /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */
            /* Re-Handshake (full handshake over existing connection) */
            testTrace(" Re-handshake test (client-initiated)\n");
            if (initializeReHandshake(clnConn, svrConn, ciphers[id].id) < 0)
            {
                testPrint("             FAILED: initializing Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Re-handshake");
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
#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
skip_client_initiated_rehandshake:
#   endif   /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */
# else
            testPrint(" Re-handshake tests are disabled (ENABLE_SECURE_REHANDSHAKES)\n");
# endif

# ifndef USE_ONLY_PSK_CIPHER_SUITE
            /* Resumed handshake (fast handshake over new connection) */
            testTrace(" Resumed handshake test (new connection)\n");
            if (initializeResumedHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("             FAILED: initializing Resumed handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Resumed handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Resumed handshake");
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
            testPrint(" Session resumption tests are disabled (USE_ONLY_PSK_CIPHER_SUITE)\n");
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
            testTrace(" Re-handshake test (server initiated)\n");
            if (initializeServerInitiatedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("             FAILED: initializing Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(svrConn, clnConn) < 0)
            {
                testPrint("             FAILED: Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                if (ciphers[id].id != clnConn->ssl->cipher->ident)
                {
                    testPrintStr("              (new cipher %s)\n",
                        cipher_name(clnConn->ssl->cipher->ident));
                }
                testTrace("             PASSED: Re-handshake");
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
            testTrace(" Resumed Re-handshake test (client initiated)\n");
#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
            if (NGTD_VER(clnConn->ssl, v_dtls_any) &&
                clnConn->ssl->cipher->flags & CRYPTO_FLAGS_GCM &&
                spec->flags & CRYPTO_FLAGS_GCM)
            {
                goto skip_client_initiated_resumed_rehandshake;
            }
#   endif   /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */
            if (initializeResumedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("             FAILED: initializing Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Resumed Re-handshake");
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
            testTrace(" Second Pass Resumed Re-handshake test\n");
            if (initializeResumedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("             FAILED: initializing Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Second Pass Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Second Pass Resumed Re-handshake");
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

#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
skip_client_initiated_resumed_rehandshake:
#   endif   /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */

            /* Resumed re-handshake initiated by server (fast handshake over conn) */
            testTrace(" Resumed Re-handshake test (server initiated)\n");
            if (initializeServerInitiatedResumedReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("             FAILED: initializing Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(svrConn, clnConn) < 0)
            {
                testPrint("             FAILED: Resumed Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Resumed Re-handshake");
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
            testTrace(" Change cert callback Re-handshake test\n");
#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
            if (NGTD_VER(clnConn->ssl, v_dtls_any) &&
                clnConn->ssl->cipher->flags & CRYPTO_FLAGS_GCM &&
                spec->flags & CRYPTO_FLAGS_GCM)
            {
                goto skip_client_upgrade_parameters_rehandshake;
            }
#   endif   /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */
            if (initializeUpgradeCertCbackReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("             FAILED: init upgrade certCback Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Upgrade cert callback Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Upgrade cert callback Re-handshake");
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
            testTrace(" Change keys Re-handshake test\n");
            if (initializeUpgradeKeysReHandshake(clnConn, svrConn,
                    ciphers[id].id) < 0)
            {
                testPrint("             FAILED: init upgrade keys Re-handshake\n");
                goto LBL_FREE;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Upgrade keys Re-handshake\n");
                goto LBL_FREE;
            }
            else
            {
                testTrace("             PASSED: Upgrade keys Re-handshake");
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
#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
skip_client_upgrade_parameters_rehandshake:
#   endif   /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */

/*
        Change cipher spec test.  Changing to a hardcoded RSA suite so this
        will not work on suites that don't have RSA material loaded
 */
            if (spec->type == CS_RSA || spec->type == CS_DHE_RSA ||
                spec->type == CS_ECDH_RSA || spec->type == CS_ECDHE_RSA)
            {
                testTrace("     Change cipher suite Re-handshake test\n");
#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
                if (NGTD_VER(clnConn->ssl, v_dtls_any) &&
                    clnConn->ssl->cipher->flags & CRYPTO_FLAGS_GCM &&
                    spec->flags & CRYPTO_FLAGS_GCM)
                {
                    goto skip_client_change_cipher_spec_rehandshake;
                }
#   endif       /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */
                if (initializeChangeCipherReHandshake(clnConn, svrConn,
                                                      ciphers[id].id, spec->type) < 0)
                {
                    testPrint("         FAILED: init change cipher Re-handshake\n");
                    goto LBL_FREE;
                }
                if (performHandshake(clnConn, svrConn) < 0)
                {
                    testPrint("         FAILED: Change cipher suite Re-handshake\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("         PASSED: Change cipher suite Re-handshake");
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
#   ifdef DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM
skip_client_change_cipher_spec_rehandshake:
#   endif /* DISABLE_DTLS_CLIENT_CHANGE_CIPHER_FROM_GCM_TO_GCM */
# endif     /* !SSL_REHANDSHAKES_ENABLED */

# ifdef USE_CLIENT_AUTH
            /* Client Authentication handshakes */
            if (spec->type != CS_PSK && spec->type != CS_DHE_PSK)
            {
                testPrint("     Standard Client Authentication test\n");
#  ifdef ENABLE_PERF_TIMING
                clnTime = svrTime = 0;
                testPrintInt("          %d connections\n", (int32) CONN_ITER);
                for (perfIter = 0; perfIter < CONN_ITER; perfIter++)
                {
#  endif        /* ENABLE_PERF_TIMING */
                    matrixSslClearSessionId(clientSessionId);
                    if (initializeClientAuthHandshake(clnConn, svrConn,
                                    ciphers[id].id, clientSessionId) < 0)
                    {
                        testPrint("         FAILED: initializing Standard Client Auth handshake\n");
                        goto LBL_FREE;
                    }
                    if (performHandshake(clnConn, svrConn) < 0)
                    {
                        testPrint("         FAILED: Standard Client Auth handshake\n");
                        goto LBL_FREE;
                    }
                    else
                    {
                        testTrace("         PASSED: Standard Client Auth handshake");
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
            testPrintInt("              CLIENT: %d "TIME_UNITS, (int32) clnTime / CONN_ITER);
            testPrintInt("              SERVER: %d "TIME_UNITS, (int32) svrTime / CONN_ITER);
            testPrint("\n==========\n");
#  endif        /* ENABLE_PERF_TIMING */


                testTrace("     Resumed client authentication test\n");
                if (initializeResumedHandshake(clnConn, svrConn, ciphers[id].id) < 0)
                {
                    testPrint("         FAILED: initializing resumed Client Auth handshake\n");
                    goto LBL_FREE;
                }
                if (performHandshake(clnConn, svrConn) < 0)
                {
                    testPrint("         FAILED: Resumed Client Auth handshake\n");
                    goto LBL_FREE;
                }
                else
                {
                    testTrace("         PASSED: Resumed Client Auth handshake");
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
                testTrace("     Rehandshake adding client authentication test\n");
                if (initializeReHandshakeClientAuth(clnConn, svrConn,
                        ciphers[id].id) < 0)
                {
                    testPrint("         FAILED: initializing reshandshke Client Auth handshake\n");
                    goto LBL_FREE;
                }
                /* Must be server initiatated if client auth is being turned on */
                if (performHandshake(svrConn, clnConn) < 0)
                {
                    testPrint("         FAILED: Rehandshake Client Auth handshake\n");
                    goto LBL_FREE;
                }
                else
                {
                    if (ciphers[id].id != clnConn->ssl->cipher->ident)
                    {
                        testPrintStr("          (new cipher %s)\n",
                            cipher_name(clnConn->ssl->cipher->ident));
                    }
                    testTrace("         PASSED: Rehandshake Client Auth handshake");
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
#  ifdef ABORT_IMMEDIATELY_ON_ERROR
            Abort();
#  endif

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
    Printf("Ciphersuite" DELIM "Keysize" DELIM "Authsize" DELIM
        "Version" DELIM "CliHS" DELIM "SvrHs" DELIM "CliAHS" DELIM "SvrAHS" DELIM
        "MiBs" "\n");
    do
    {
        result--;
        Printf("%s" DELIM "%hu" DELIM "%hu" DELIM
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
                                               sslConn_t *svrConn, psCipher16_t cipherSuite,
                                               uint16_t type)
{
/*
    Picking the most common suites using two different public key
    apgorithm types individually
    - OID_RSA_KEY_ALG (645)
    - OID_ECDSA_KEY_ALG (518)
 */
    uint16_t suites[2];
    uint32_t ecdh_flag, rsa_flag;
    uint8_t cipherLen = 0;
    int32_t rc;

    ecdh_flag = rsa_flag = 0;

#   ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    suites[cipherLen++] = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
    rsa_flag = 1;
#   else
#   endif /* USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA */

#   ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    suites[cipherLen++] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
    ecdh_flag = 1;
#   else
#   endif /* USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */

    if ((type == CS_ECDH_RSA && ecdh_flag)
        || (type != CS_ECDH_RSA && rsa_flag))
    {
        rc = matrixSslEncodeRehandshake(clnConn->ssl, NULL, NULL, 0, suites,
            cipherLen);
    }
    else
    {
        /* No suitable ciphersuite for re-handshake */
        /* Force a full handshake */
        rc = matrixSslEncodeRehandshake(clnConn->ssl, NULL, NULL, 0, 0, 0);
    }
    return rc;
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
    int32_t rc;
#  ifdef ENABLE_PERF_TIMING
    psTime_t start, end;
#  endif /* ENABLE_PERF_TIMING */

    sessionId = clnConn->ssl->sid;

    Memset(&options, 0x0, sizeof(sslSessOpts_t));
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
    rc = matrixSslNewClientSession(&clnConn->ssl,
            clnConn->keys,
            sessionId,
            &cipherSuite,
            1,
            clnCertChecker,
            "localhost",
            NULL,
            NULL,
            &options);
    if (rc < 0)
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
    rc = matrixSslNewServerSession(&svrConn->ssl,
            svrConn->keys,
            NULL,
            &options);
    if (rc < 0)
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

static int32_t identityCb(ssl_t *ssl, const sslKeySelectInfo_t *keySpec)
{
#ifdef USE_CLIENT_AUTH
    psAssert(ssl->keys->identity == NULL);

    /* Fill in the identities and set keys  */
    ssl->keys->identity = ssl->userDataPtr;
    (void) matrixSslSetClientIdentity(ssl, ssl->keys);
#endif

    return PS_SUCCESS;
}

static int32 initializeClientAuthHandshake(sslConn_t *clnConn,
    sslConn_t *svrConn, psCipher16_t cipherSuite, sslSessionId_t *sid)
{
    sslSessOpts_t options;
    sslKeys_t *keys = clnConn->keys;

#  ifdef ENABLE_PERF_TIMING
    psTime_t start, end;
#  endif /* ENABLE_PERF_TIMING */

    Memset(&options, 0x0, sizeof(sslSessOpts_t));
    /* Set fragment size to minimum to test also fragmentation */
    if (g_versionFlag & SSL_FLAGS_TLS_1_3)
    {
        options.maxFragLen = 512;
        if (Getenv("TLS13_BLOCK_SIZE"))
        {
            options.tls13BlockSize = Strtol(Getenv("TLS13_BLOCK_SIZE"),
                    NULL, 10);
        }
        else if (Getenv("TLS13_PAD_LEN"))
        {
            options.tls13PadLen = Strtol(Getenv("TLS13_PAD_LEN"),
                    NULL, 10);
        }
    }
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

    if (cipherSuite == 47)
    {
        options.userDataPtr = keys->identity;
        keys->identity = NULL;
    }
    if (matrixSslNewClientSession(&clnConn->ssl, keys, sid,
            &cipherSuite, 1, clnCertChecker, "localhost", NULL, NULL,
            &options) < 0)
    {
        return PS_FAILURE;
    }

    if (cipherSuite == 47)
    {
        /* exercise both callback and 'keys' argument - see above */
        matrixSslRegisterClientIdentityCallback(clnConn->ssl, identityCb);
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
    if (NGTD_VER(sendingSide->ssl, v_dtls_any))
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
    Memcpy(inbuf, outbuf, dataSent);

/*
    Now update the sending side that data has been "sent"
 */
# ifdef ENABLE_PERF_TIMING
    psGetTime(&start, NULL);
# endif /* ENABLE_PERF_TIMING */
# ifdef USE_DTLS
    if (NGTD_VER(sendingSide->ssl, v_dtls_any))
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

# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
    if (rc == PS_PENDING && matrixSslNeedClientCert(receivingSide->ssl))
    {
        /* Well... we already have the keys read in */
        (void)matrixSslClientCertUpdated(receivingSide->ssl);
        /* Retry now that we have the cert and the priv key. */
        rc = matrixSslReceivedData(receivingSide->ssl,
                                   dataSent,
                                   &plaintextBuf, &ptLen);
    }
# endif

# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
    if (rc == PS_PENDING && matrixSslNeedClientCert(receivingSide->ssl))
    {
        /* We have already loaded a client cert we can use in this test,
           so do nothing. */
        rc = matrixSslClientCertUpdated(receivingSide->ssl);
        psAssert(rc == PS_TRUE);
        rc = matrixSslReceivedData(receivingSide->ssl, dataSent, &plaintextBuf,
            &ptLen);
    }
# endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
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

    Printf("Unexpected error in performHandshake: %d\n", rc);
    return PS_FAILURE;
}


# ifdef ENABLE_PERF_TIMING
static void ciphername(uint32_t flags, char s[32])
{
    s[0] = '\0';
    if (flags & CRYPTO_FLAGS_AES)
    {
        Strcat(s, "AES");
    }
    else if (flags & CRYPTO_FLAGS_AES256)
    {
        Strcat(s, "AES256");
    }
    else if (flags & CRYPTO_FLAGS_3DES)
    {
        Strcat(s, "3DES");
    }
    else if (flags & CRYPTO_FLAGS_ARC4)
    {
        Strcat(s, "RC4");
    }
    else if (flags & CRYPTO_FLAGS_SEED)
    {
        Strcat(s, "SEED");
    }
    else if (flags & CRYPTO_FLAGS_IDEA)
    {
        Strcat(s, "IDEA");
    }
    if (flags & CRYPTO_FLAGS_GCM)
    {
        Strcat(s, "_GCM");
    }
    else if (flags & CRYPTO_FLAGS_SHA1)
    {
        Strcat(s, "_SHA");
    }
    else if (flags & CRYPTO_FLAGS_SHA2)
    {
        Strcat(s, "_SHA256");
    }
    else if (flags & CRYPTO_FLAGS_SHA3)
    {
        Strcat(s, "_SHA384");
    }
    else if (flags & CRYPTO_FLAGS_MD5)
    {
        Strcat(s, "_MD5");
    }
}

static __THREAD uint32_t g_ttest[64];
static __THREAD uint32_t g_ttest_val[64];
static __THREAD uint16_t g_ttest_count = 0;

static void print_throughput(void)
{
    char name[32];
    int i;

    Printf("Cipher" DELIM "MiB/s\n");
    for (i = 0; i < g_ttest_count; i++)
    {
        ciphername(g_ttest[i], name);
        Printf("%s" DELIM "%u\n", name, MBS(g_ttest_val[i]));
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
    if (NGTD_VER(s->ssl, v_dtls_any))
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
    Printf("%s throughput test for %hu byte records (%u bytes total)\n",
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
        Memcpy(rb, wb, buflen);

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
    Printf("  throughput send %u MiB/s\n", MBS(s->appTime));
    Printf("  throughput recv %u MiB/s\n", MBS(r->appTime));
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
static int32 exchangeAppData(sslConn_t *sendingSide,
        sslConn_t *receivingSide,
        uint32_t bytes)
{
    int32 writeBufLen, inBufLen, dataSent, rc, sentRc;
    uint32 ptLen, requestedLen, copyLen, halfReqLen;
    unsigned char *writeBuf, *inBuf, *plaintextBuf;
    unsigned char copyByte;
    unsigned char* sentData[256];
    uint32_t sentDataLen[256];
    unsigned char *pOrigPt;
    uint32 numSends = 0;
    uint32 numRecvs = 0;
    uint32 i;
    int32 finalRc = PS_FAILURE;
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

        /* First part. */
        writeBufLen = matrixSslGetWritebuf(sendingSide->ssl, &writeBuf, halfReqLen);
        if (writeBufLen <= 0)
        {
            goto exit;
        }

        copyLen = PS_MIN(halfReqLen, (uint32) writeBufLen);

        /* Send a block of data and save the pointer so that
           data can be verified after receive */
        sentData[numSends] = psMalloc(NULL, copyLen);
# ifdef USE_DETERMINISTIC_APP_DATA_EXCHANGE
        Memset(sentData[numSends], copyByte, copyLen);
# else
        psGetPrng(NULL, sentData[numSends], copyLen, NULL);
# endif
        Memcpy(writeBuf, sentData[numSends], copyLen);
        sentDataLen[numSends] = copyLen;
        requestedLen -= copyLen;
        /* psTraceBytes("sending part 1/2", writeBuf, copyLen); */

        writeBufLen = matrixSslEncodeWritebuf(sendingSide->ssl, copyLen);
        if (writeBufLen < 0)
        {
            goto exit;
        }

        numSends++;
        copyByte++;

        /* Second part. */
        writeBufLen = matrixSslGetWritebuf(sendingSide->ssl, &writeBuf,
            halfReqLen);
        if (writeBufLen <= 0)
        {
            goto exit;
        }

        copyLen = PS_MIN(halfReqLen, (uint32) writeBufLen);
        sentData[numSends] = psMalloc(NULL, copyLen);
# ifdef USE_DETERMINISTIC_APP_DATA_EXCHANGE
        Memset(sentData[numSends], copyByte, copyLen);
# else
        psGetPrng(NULL, sentData[numSends], copyLen, NULL);
# endif
        Memcpy(writeBuf, sentData[numSends], copyLen);
        sentDataLen[numSends] = copyLen;

        requestedLen -= copyLen;
        /* psTraceBytes("sending part 2/2", writeBuf, copyLen); */

        writeBufLen = matrixSslEncodeWritebuf(sendingSide->ssl, copyLen);
        if (writeBufLen < 0)
        {
            goto exit;
        }

        numSends++;
    } /* End of send loop */

    pOrigPt = sentData[0];

SEND_MORE:
# ifdef USE_DTLS
    if (NGTD_VER(sendingSide->ssl, v_dtls_any))
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
        goto exit;
    }
    dataSent = PS_MIN(writeBufLen, inBufLen);
    Memcpy(inBuf, writeBuf, dataSent);

    /* Now update the sending side that data has been "sent" */
# ifdef USE_DTLS
    if (NGTD_VER(sendingSide->ssl, v_dtls_any))
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
            if (Memcmp(pOrigPt, plaintextBuf, ptLen))
            {
                psStatCompByteSeqResult_t compRes;

                Printf("Sent and received data didn't match for data block %d!\n",
                        numRecvs+1);
                compRes = psStatCompByteSeq(pOrigPt, "original",
                        plaintextBuf, "decrypted",
                        ptLen);
                psStatPrintCompByteSeqResult(compRes, NULL);
                goto exit;
            }
            if (ptLen == sentDataLen[numRecvs])
            {
                /* Decrypted the entire remaining record. Move on to next one. */
                numRecvs++;
                pOrigPt = sentData[numRecvs];
            }
            else
            {
                /* Decrypted a partial record. Update comparison pointer and
                   remaining len. Partial records can occur e.g. when the
                   BEAST workaround, involving using the 1/n-1 split of each
                   record, is used in TLS 1.0. */
                pOrigPt += ptLen;
                sentDataLen[numRecvs] -= ptLen;
            }
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
                    goto exit;
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
        Printf("Unexpected error in exchangeAppData: %d\n", rc);
        goto exit;
    }
    finalRc = PS_SUCCESS;
exit:
    for (i = 0; i < numSends; i++)
    {
        psFree(sentData[i], NULL);
    }
    return finalRc;
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

    Memset(&options, 0x0, sizeof(sslSessOpts_t));
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
        if (spec->type == CS_ECDH_ECDSA
                || spec->type == CS_ECDHE_ECDSA)
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
                    ECDHRSACAS, sizeof(ECDHRSACAS)) < 0)
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
    Memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = g_versionFlag;
    /* options.maxFragLen = 512; */
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
        if (spec->type == CS_ECDHE_ECDSA
                || spec->type == CS_ECDHE_RSA)
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
        if (spec->type == CS_ECDH_ECDSA
                || spec->type == CS_ECDHE_ECDSA)
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
            if (matrixSslLoadEcKeysMem(keys, ECDHRSA256, sizeof(ECDHRSA256),
                    ECDHRSA256KEY, sizeof(ECDHRSA256KEY),
                    ECDHRSACAS, sizeof(ECDHRSACAS)) < 0)
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
#ifdef USE_ECC
            /* load multiple client keys */
            if (matrixSslLoadEcKeysMem(keys,
                                       EC256, EC256_SIZE,
                                       EC256KEY, EC256KEY_SIZE,
                                       (unsigned char *) NULL, 0) < 0)
            {
                return PS_FAILURE;
            }
#endif
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
    TLS1.3 specific parts
 */
#ifdef USE_TLS_1_3

int tls13sslTest(void)
{
    sslConn_t *svrConn, *clnConn;
    const sslCipherSpec_t *spec;
    uint8_t id, algorithmIdx;
    uint32 algorithm;
    psSize_t keysize = 0, authsize = 0;
    int32 rc = PS_SUCCESS;
    sslSessionId_t *clientSessionId;

    g_versionFlag = SSL_FLAGS_TLS_1_3;

    svrConn = psMalloc(MATRIX_NO_POOL, sizeof(sslConn_t));
    clnConn = psMalloc(MATRIX_NO_POOL, sizeof(sslConn_t));
    Memset(svrConn, 0, sizeof(sslConn_t));
    Memset(clnConn, 0, sizeof(sslConn_t));
    /* ECC test data */
    ECCKEY = EC256KEY; ECCKEY_SIZE = EC256KEY_SIZE;
    ECC = EC256; ECC_SIZE = EC256_SIZE;
    ECCCA = EC256CA; ECCCA_SIZE = EC256CA_SIZE;
    keysize = authsize = 256;
    /* RSA test data */
    RSAKEY = RSA2048KEY; RSAKEY_SIZE = RSA2048KEY_SIZE;
    RSACERT = RSA2048; RSA_SIZE = RSA2048_SIZE;
    RSACA = RSA2048CA; RSACA_SIZE = RSA2048CA_SIZE;

    for (id = 0; ciphers[id].id > 0; id++)
    {
        if ((spec = sslGetDefinedCipherSpec(ciphers[id].id)) == NULL)
        {
            testPrint("         FAILED: cipher spec lookup\n");
            goto error;
        }
        if (spec->type != CS_TLS13)
        {
            continue;
        }
        if (!testCiphersuite(&ciphers[id]))
        {
            continue;
        }
        if (!testProtocolVersion(SSL_FLAGS_TLS_1_3))
        {
            continue;
        }
        keysize = authsize = 0;
        for (algorithmIdx = 0; algorithmIdx < 3; algorithmIdx++)
        {
            switch (algorithmIdx)
            {
            case 0:
                keysize = authsize = 2048;
                algorithm = TLS13_RSA;
                break;
            case 1:
                keysize = authsize = 256;
                algorithm = TLS13_ECC;
                break;
            case 2:
                algorithm = TLS13_PSK;
                break;
            }
            matrixSslNewSessionId(&clientSessionId, NULL);
            testPrintStr("Testing %s TLS 1.3 ", (char *) ciphers[id].name);
            if (algorithm != TLS13_PSK)
            {
                testPrintInt("KeySize %hu ", keysize);
                testPrintInt("AuthSize %hu\n", authsize);
            }
            else
            {
                testPrint("PSK");
            }

            /*** Standard Handshake ***/
            testPrint(" Standard handshake test\n");

            if (tls13InitializeHandshake(clnConn, svrConn, ciphers[id].id, algorithm,
                                         clientSessionId) < 0)
            {
                testPrint("             FAILED: initializing Standard handshake\n");
                goto error;
            }
            if (tls13PerformHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Standard handshake\n");
                goto error;
            }
            else
            {
                testTrace("             PASSED: Standard handshake\n");

                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint("          ... but FAILED to exchange application data\n");
                    goto error;
                }
                if (exchangeAppData(clnConn, svrConn, CLI_APP_BIG_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_BIG_DATA) < 0)
                {
                    testPrint("          ... but FAILED to exchange big application data\n");
                    goto error;
                }
                else
                {
                    testTrace("\n");
                }
            }

#   ifdef USE_TLS_1_3_RESUMPTION

            freeSessionAndConnection(clnConn);
            /* Delete server session, but retain session ticket keys. */
            matrixSslDeleteSession(svrConn->ssl);

            /*** Resumed Handshake: client connects using clientSessionId
                 struct filled in the previous handshake. ***/
            if (tls13InitializeHandshake(clnConn, svrConn, ciphers[id].id,
                            algorithm, clientSessionId) < 0)
            {
                testPrint("             FAILED: initializing client for Resumed " \
                        "handshake\n");
                goto error;
            }
            if (tls13PerformHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Resumed handshake\n");
                goto error;
            }
            else
            {
                if (RESUMED_HANDSHAKE(svrConn->ssl))
                {
                    testTrace("         PASSED: Resumed handshake\n");
                }
                else
                {
                    testTrace("     FAILED: Resumed handshake\n");
                    testTrace("     (handshake passed, but failed to resume)\n");
                    goto error;
                }
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                        exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint("     ... but FAILED to exchange application data\n");
                    goto error;
                }
                if (exchangeAppData(clnConn, svrConn, CLI_APP_BIG_DATA) < 0 ||
                        exchangeAppData(svrConn, clnConn, SVR_APP_BIG_DATA) < 0)
                {
                    testPrint("          ... but FAILED to exchange big application data\n");
                    goto error;
                }
                else
                {
                    testTrace("\n");
                }
            }
#   endif /* USE_TLS_1_3_RESUMPTION */

             /*** Client Authentication Handshake ***/

#   ifdef USE_CLIENT_AUTH
            testPrint(" Standard Client Authentication test\n");

            matrixSslClearSessionId(clientSessionId);
            if (initializeClientAuthHandshake(clnConn, svrConn,
                    ciphers[id].id, clientSessionId) < 0)
            {
                testPrint("             FAILED: initializing Standard Client Auth handshake\n");
                goto error;
            }
            if (performHandshake(clnConn, svrConn) < 0)
            {
                testPrint("             FAILED: Standard Client Auth handshake\n");
                goto error;
            }
            else
            {
                testTrace("             PASSED: Standard Client Auth handshake\n");
                if (exchangeAppData(clnConn, svrConn, CLI_APP_DATA) < 0 ||
                    exchangeAppData(svrConn, clnConn, SVR_APP_DATA) < 0)
                {
                    testPrint("         ... but FAILED to exchange application data\n");
                    goto error;
                }
                else
                {
                    testTrace("\n");
                }
            }
#endif
            tls13ResetEarlyData();
            freeSessionAndConnection(svrConn);
            freeSessionAndConnection(clnConn);
            matrixSslDeleteSessionId(clientSessionId);
        }
    }
    goto success;
error:
    testPrint("EXITING ON ERROR\n");
    rc = PS_FAILURE;
# ifdef ABORT_IMMEDIATELY_ON_ERROR
    Abort();
# endif     /* ABORT_IMMEDIATELY_ON_ERROR */

success:
    psFree(svrConn, NULL);
    psFree(clnConn, NULL);

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

static int32 tls13InitializeServer(sslConn_t *conn, psCipher16_t cipherSuite, uint32 algorithm)
{
    sslKeys_t *keys = NULL;
    ssl_t *ssl = NULL;
    sslSessOpts_t options;
    const sslCipherSpec_t *spec;
# ifdef USE_STATELESS_SESSION_TICKETS
    unsigned char sessTicketSymKey[32] = { 0 };
    unsigned char sessTicketMacKey[32] = { 0 };
    unsigned char sessTicketName[16];
# endif

    Memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = g_versionFlag;
    options.tls13SessionMaxEarlyData = 16384;
    if (Getenv("TLS13_BLOCK_SIZE"))
    {
        options.tls13BlockSize = Strtol(Getenv("TLS13_BLOCK_SIZE"),
                NULL, 10);
    }
    else if (Getenv("TLS13_PAD_LEN"))
    {
        options.tls13PadLen = Strtol(Getenv("TLS13_PAD_LEN"),
                NULL, 10);
    }

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
        if (algorithm == TLS13_ECC)
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
#  endif
# endif

# ifdef USE_RSA
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (algorithm == TLS13_RSA)
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

# ifdef USE_PSK_CIPHER_SUITE
        if (algorithm == TLS13_PSK)
        {
            const unsigned char *psk;
            uint32 pskLen;
            psTls13SessionParams_t session;

            switch (cipherSuite)
            {
            case TLS_AES_256_GCM_SHA384:
                psk = g_tls13_test_psk_384;
                pskLen = 48;
                break;
            default:
                psk = g_tls13_test_psk_256;
                pskLen = 32;
            }

            Memset(&session, 0x0, sizeof(psTls13SessionParams_t));

            /* Enable early data both globally and for the PSK */
            session.maxEarlyData = 16384;

            if (matrixSslLoadTls13Psk(keys,
                    psk,
                    pskLen,
                    g_tls13_test_psk_id,
                    sizeof(g_tls13_test_psk_id),
                    &session) < 0)
            {
                return PS_FAILURE;
            }
        }
# endif /* USE_PSK_CIPHER_SUITE */
    }

#  ifdef USE_STATELESS_SESSION_TICKETS
    if (psGetPrngLocked(sessTicketSymKey, sizeof(sessTicketSymKey), NULL) < 0
        || psGetPrngLocked(sessTicketMacKey, sizeof(sessTicketMacKey), NULL) < 0
        || psGetPrngLocked(sessTicketName, sizeof(sessTicketName), NULL) < 0)
    {
        psTrace("Error generating session ticket encryption key\n");
        return PS_FAILURE;
    }
    if (matrixSslLoadSessionTicketKeys(conn->keys, sessTicketName,
            sessTicketSymKey, sizeof(sessTicketSymKey),
            sessTicketMacKey, sizeof(sessTicketMacKey)) < 0)
    {
        psTrace("Error loading session ticket encryption key\n");
        return PS_FAILURE;
    }
#  endif

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

    conn->ssl = ssl;
    return PS_SUCCESS;
}


static int32 tls13InitializeClient(sslConn_t *conn, psCipher16_t cipherSuite,
    uint32 algorithm, sslSessionId_t *sid)
{
    ssl_t *ssl;
    sslKeys_t *keys;
    sslSessOpts_t options;
    const sslCipherSpec_t *spec;

    Memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = g_versionFlag;
    if (Getenv("TLS13_BLOCK_SIZE"))
    {
        options.tls13BlockSize = Strtol(Getenv("TLS13_BLOCK_SIZE"),
                NULL, 10);
    }
    else if (Getenv("TLS13_PAD_LEN"))
    {
        options.tls13PadLen = Strtol(Getenv("TLS13_PAD_LEN"),
                NULL, 10);
    }

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
        if (algorithm == TLS13_ECC)
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
        if (algorithm == TLS13_ECC)
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
#  endif   /* USE_ONLY_PSK_CIPHER_SUITE */
# endif    /* USE_ECC */

# ifdef USE_RSA
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (algorithm == TLS13_RSA)
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
        if (algorithm == TLS13_PSK)
        {
            const unsigned char *psk;
            uint32 pskLen;
            psTls13SessionParams_t session;

            switch (cipherSuite)
            {
            case TLS_AES_256_GCM_SHA384:
                psk = g_tls13_test_psk_384;
                pskLen = 48;
                break;
            default:
                psk = g_tls13_test_psk_256;
                pskLen = 32;
            }

            Memset(&session, 0x0, sizeof(psTls13SessionParams_t));

            /* Enable early data both globally and for the PSK */
            session.maxEarlyData = 16384;
            session.cipherId = spec->ident;
            if (matrixSslLoadTls13Psk(keys,
                    psk,
                    pskLen,
                    g_tls13_test_psk_id,
                    sizeof(g_tls13_test_psk_id),
                    &session) < 0)
            {
                return PS_FAILURE;
            }
        }
# endif /* USE_PSK_CIPHER_SUITE */
    }

    conn->ssl = NULL;
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    options.useExtCvSigOp = 1;
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

    if (matrixSslNewClientSession(&ssl, conn->keys, sid, &cipherSuite,
            1, clnCertChecker, "localhost", NULL, NULL, &options) < 0)
    {
        return PS_FAILURE;
    }
    conn->ssl = ssl;

    /* If PSK is in use send early data */
    if (algorithm == TLS13_PSK)
    {
        tls13ResetEarlyData();
        /* This could be done smarter (randomize?) but for now just send some different
           size records */
        if (tls13SendEarlyData(conn, 64) < 0)
        {
            return PS_FAILURE;
        }
        if (tls13SendEarlyData(conn, 2000) < 0)
        {
            return PS_FAILURE;
        }
        if (tls13SendEarlyData(conn, 1) < 0)
        {
            return PS_FAILURE;
        }
        if (tls13SendEarlyData(conn, 300) < 0)
        {
            return PS_FAILURE;
        }
        if (tls13SendEarlyData(conn, 4000) < 0)
        {
            return PS_FAILURE;
        }
        if (tls13SendEarlyData(conn, 64) < 0)
        {
            return PS_FAILURE;
        }
        if (tls13SendEarlyData(conn, 4) < 0)
        {
            return PS_FAILURE;
        }
        if (tls13SendEarlyData(conn, 4) < 0)
        {
            return PS_FAILURE;
        }
        /* This code tries sending early data when using both pre-configured PSK or
           resumed session. Expect that early data is received successfully only
           for the resumed sessions because Matrix server should ignore early data
           with pre-configured PSK */
        if (sid == NULL || sid->psk == NULL)
        {
            g_expectedEarlyDataReceives = 0;
        }
    }
    return PS_SUCCESS;
}

static int32 tls13InitializeHandshake(sslConn_t *clnConn, sslConn_t *svrConn,
    psCipher16_t cipherSuite, uint32 algorithm, sslSessionId_t *sid)
{
    int32 rc;

    if ((rc = tls13InitializeServer(svrConn, cipherSuite, algorithm)) < 0)
    {
        return rc;
    }
    return tls13InitializeClient(clnConn, cipherSuite, algorithm, sid);
}
static int32 tls13PerformHandshake(sslConn_t *sendingSide, sslConn_t *receivingSide)
{
    unsigned char *inbuf, *outbuf, *plaintextBuf;
    int32 inbufLen, outbufLen, rc, dataSent;
    uint32 ptLen;

/*
    Sending side will have outdata ready
 */

    outbufLen = matrixSslGetOutdata(sendingSide->ssl, &outbuf);

/*
    Receiving side must ask for storage space to receive data into
 */
    inbufLen = matrixSslGetReadbuf(receivingSide->ssl, &inbuf);
/*
    The indata is the outdata from the sending side.  copy it over
 */
    if (outbufLen <= 0 || inbufLen <= 0)
    {
        return PS_FAILURE;
    }
    dataSent = PS_MIN(outbufLen, inbufLen);
    Memcpy(inbuf, outbuf, dataSent);

/*
    Now update the sending side that data has been "sent"
 */
    matrixSslSentData(sendingSide->ssl, dataSent);

/*
    Received data
*/
    rc = matrixSslReceivedData(receivingSide->ssl, dataSent, &plaintextBuf,
        &ptLen);
CHECK_RC:
   if (rc == MATRIXSSL_REQUEST_SEND)
    {
/*
        Success case.  Switch roles and continue
 */
        return tls13PerformHandshake(receivingSide, sendingSide);

    }
    else if (rc == MATRIXSSL_REQUEST_RECV)
    {
/*
        This pass didn't take care of it all.  Don't switch roles and
        try again
 */
        return tls13PerformHandshake(sendingSide, receivingSide);

    }
    else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
    {
        if (g_receiverEarlyDataIndex != g_expectedEarlyDataReceives)
        {
            testPrintInt("Server expected %d records of early data ", g_expectedEarlyDataReceives);
            testPrintInt("but got %d.\n", g_receiverEarlyDataIndex);
            return PS_FAILURE;
        }
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
            return tls13PerformHandshake(sendingSide, receivingSide);
        }
        else
        {
            return PS_FAILURE;
        }

    }
    else if (rc == MATRIXSSL_APP_DATA)
    {
        /* This is the server that is receiving the early data */
        if (matrixSslGetEarlyDataStatus(receivingSide->ssl) != MATRIXSSL_EARLY_DATA_ACCEPTED)
        {
            return PS_FAILURE;
        }
        /* Check that the received early data matches sent */
        testPrintInt("Server received %d bytes early data\n", ptLen);
        if (g_earlyDataInfo[g_receiverEarlyDataIndex].len != ptLen)
        {
            Printf("Sent and received early data lengths didn't match!\n");
            return PS_FAILURE;
        }
        if (Memcmp(g_earlyDataInfo[g_receiverEarlyDataIndex].data, plaintextBuf, ptLen))
        {
            Printf("Sent and received early data didn't match!\n");
            return PS_FAILURE;
        }
        g_receiverEarlyDataIndex++;
        rc = matrixSslProcessedData(receivingSide->ssl, &plaintextBuf, &ptLen);
        goto CHECK_RC;
    }
    else
    {
        Printf("Unexpected error in performHandshake: %d\n", rc);
        return PS_FAILURE;
    }
    return PS_FAILURE; /* can't get here */
}

static void tls13ResetEarlyData()
{
    int32 i;
    for (i = 0; i < g_senderEarlyDataIndex; i++)
    {
        psFree(g_earlyDataInfo[i].data, NULL);
    }
    g_senderEarlyDataIndex = 0;
    g_receiverEarlyDataIndex = 0;
    g_expectedEarlyDataReceives = 0;
}

static int32 tls13SendEarlyData(sslConn_t *conn, uint32 writeLen)
{
    int32 writeBufLen, copyLen;
    unsigned char *writeBuf;
    if (matrixSslGetMaxEarlyData(conn->ssl) == 0)
    {
        return PS_FAILURE;
    }
    while (writeLen > 0)
    {
        writeBufLen = matrixSslGetWritebuf(conn->ssl, &writeBuf,
            writeLen);
        if (writeBufLen <= 0)
        {
            return PS_FAILURE;
        }
        copyLen = PS_MIN(writeLen, (uint32) writeBufLen);
        g_earlyDataInfo[g_senderEarlyDataIndex].data = psMalloc(NULL, copyLen);
        g_earlyDataInfo[g_senderEarlyDataIndex].len = copyLen;
        psGetPrng(NULL, g_earlyDataInfo[g_senderEarlyDataIndex].data, copyLen, NULL);
        Memcpy(writeBuf, g_earlyDataInfo[g_senderEarlyDataIndex].data, copyLen);
        g_senderEarlyDataIndex++;
        /*psTraceBytes("sending", writeBuf, copyLen);*/
        writeBufLen = matrixSslEncodeWritebuf(conn->ssl, copyLen);
        if (writeBufLen < 0)
        {
            return PS_FAILURE;
        }
        writeLen -= copyLen;
        g_expectedEarlyDataReceives++;
    }
    return PS_SUCCESS;
}

#endif

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
    /* Printf("Got stat event %d with value %d\n", type, value); */
}
# endif
/******************************************************************************/

#endif /* !defined(USE_SERVER_SIDE_SSL) || !defined(USE_CLIENT_SIDE_SSL) */
