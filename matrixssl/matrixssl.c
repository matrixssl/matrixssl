/**
 *      @file    matrixssl.c
 *      @version $Format:%h%d$
 *
 *      The session and authentication management portions of the MatrixSSL library.
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
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE
#endif

#include "osdep_stdio.h"
#include "matrixsslImpl.h"
/******************************************************************************/

static const char copyright[] =
    "Copyright Inside Secure Corporation. All rights reserved.";

#ifdef USE_SERVER_SIDE_SSL

# ifndef SSL_SESSION_TICKET_LIST_LEN
#  define SSL_SESSION_TICKET_LIST_LEN     32
# endif /* SSL_SESSION_TICKET_LIST_LEN */

/*
    Static session table for session cache and lock for multithreaded env
 */
#  ifdef USE_MULTITHREADING
static psMutex_t g_sessionTableLock;
#   ifdef USE_STATELESS_SESSION_TICKETS
static psMutex_t g_sessTicketLock;
#   endif
#  endif

#  ifdef USE_SHARED_SESSION_CACHE
#   include "osdep_sys_mman.h"
#   include "osdep_fcntl.h"
static sslSessionEntry_t *g_sessionTable;
#  else
static sslSessionEntry_t g_sessionTable[SSL_SESSION_TABLE_SIZE];
#  endif

static DLListEntry g_sessionChronList;
static void initSessionEntryChronList(void);

#endif  /* USE_SERVER_SIDE_SSL */

#ifdef USE_TLS_1_3
static int32 initSupportedGroups(ssl_t *ssl, sslSessOpts_t *options);
#endif
static int32 initSignatureAlgorithms(ssl_t *ssl, sslSessOpts_t *options);

extern int32 getDefaultSigAlgs(ssl_t *ssl);
extern psBool_t psIsSigAlgSupported(uint16_t sigAlg);
#ifdef USE_TLS_1_3
extern int32 tls13GetDefaultSigAlgsCert(ssl_t *ssl);
extern int32 tls13GetDefaultGroups(ssl_t *ssl);
#endif

extern int32 initSupportedVersions(ssl_t *ssl, sslSessOpts_t *options);

/******************************************************************************/
/*
    Open and close the SSL module.  These routines are called once in the
    lifetime of the application and initialize and clean up the library
    respectively.
    The config param should always be passed as:
        MATRIXSSL_CONFIG
 */
static char g_config[32] = "N";

int32_t matrixSslOpenWithConfig(const char *config)
{
    unsigned long clen;
#ifdef USE_SERVER_SIDE_SSL
    uint32_t shared;
    int32_t rc;
#endif

    (void) copyright;      /* Prevent compiler warning. */
    if (*g_config == 'Y')
    {
        return PS_SUCCESS; /* Function has been called previously */
    }
    /* config parameter is matrixconfig + cryptoconfig + coreconfig */
    Strncpy(g_config, MATRIXSSL_CONFIG, sizeof(g_config) - 1);
    clen = Strlen(MATRIXSSL_CONFIG) - Strlen(PSCRYPTO_CONFIG);
    if (Strncmp(g_config, config, clen) != 0)
    {
        psErrorStr( "MatrixSSL config mismatch.\n" \
            "Library: " MATRIXSSL_CONFIG \
            "\nCurrent: %s\n", config);
        return PS_FAIL;
    }
    if (psCryptoOpen(config + clen) < 0)
    {
        psError("pscrypto open failure\n");
        return PS_FAIL;
    }

# ifdef USE_SERVER_SIDE_SSL
#  ifdef USE_SHARED_SESSION_CACHE
    g_sessionTable = (sslSessionEntry_t *) mmap(NULL,
        sizeof(sslSessionEntry_t) * SSL_SESSION_TABLE_SIZE,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_sessionTable == MAP_FAILED)
    {
        psError("error creating shared memory\n");
        return PS_PLATFORM_FAIL;
    }
    psTraceStrInfo("Shared sessionTable = %p\n", g_sessionTable);
    shared = PS_SHARED;
#  else
    shared = 0;
    /* To prevent warning if multithreading support is disabled. */
    PS_VARIABLE_SET_BUT_UNUSED(shared);
#  endif
    Memset(g_sessionTable, 0x0,
        sizeof(sslSessionEntry_t) * SSL_SESSION_TABLE_SIZE);
    initSessionEntryChronList();

    if ((rc = psCreateMutex(&g_sessionTableLock, shared)) < 0)
    {
        return rc;
    }
#  ifdef USE_STATELESS_SESSION_TICKETS
    if ((rc = psCreateMutex(&g_sessTicketLock, shared)) < 0)
    {
        return rc;
    }
#  endif /* USE_STATELESS_SESSION_TICKETS */
# endif  /* USE_SERVER_SIDE_SSL */

#ifdef USE_DTLS
# ifdef USE_SERVER_SIDE_SSL
    if ((rc = dtlsGenCookieSecret()) < 0)
    {
        return rc;
    }
# endif
    matrixDtlsSetPmtu(-1);
#endif /* USE_DTLS */

    return PS_SUCCESS;
}

/*
    matrixSslClose
 */
void matrixSslClose(void)
{
# ifdef USE_SERVER_SIDE_SSL
    int i;

    psLockMutex(&g_sessionTableLock);
    for (i = 0; i < SSL_SESSION_TABLE_SIZE; i++)
    {
        if (g_sessionTable[i].inUse > 1)
        {
            psTraceInfo("Warning: closing while session still in use\n");
        }
    }
    Memset(g_sessionTable, 0x0,
        sizeof(sslSessionEntry_t) * SSL_SESSION_TABLE_SIZE);
    psUnlockMutex(&g_sessionTableLock);
    psDestroyMutex(&g_sessionTableLock);
#  ifdef USE_SHARED_SESSION_CACHE
    if (munmap(g_sessionTable,
            sizeof(sslSessionEntry_t) * SSL_SESSION_TABLE_SIZE) != 0)
    {
        psTraceInfo("Warning: munmap call failed.\n");
    }
#  endif
# endif /* USE_SERVER_SIDE_SSL */
    psCryptoClose();
    *g_config = 'N';
}

# ifdef USE_TLS_1_3
/** Set the (EC)DHE groups to support for key exchange.

    The groups should be given in priority order. Initial ClientHello
    key shares will be generated for the top [numClientHelloKeyShares]
    entries.

    Allowed group IDs are:
    namedgroup_secp256r1
    namedgroup_secp384r1
    namedgroup_secp521r1
    namedgroup_x25519
    namedgroup_ffdhe2048
    namedgroup_ffdhe3072
    namedgroup_ffdhe4096
*/
int32_t matrixSslSessOptsSetKeyExGroups(sslSessOpts_t *options,
    uint16_t *namedGroups,
    psSize_t namedGroupsLen,
    psSize_t numClientHelloKeyShares)
{
    psSize_t i;

    if (namedGroupsLen == 0)
    {
        return PS_ARG_FAIL;
    }
    if (numClientHelloKeyShares > namedGroupsLen)
    {
        return PS_ARG_FAIL;
    }

    /* Set the groups to support. */
    for (i = 0; i < namedGroupsLen; i++)
    {
        if (i >= TLS_1_3_MAX_GROUPS || namedGroups[i] == 0)
        {
            return PS_ARG_FAIL;
        }
        if (!psIsGroupSupported(namedGroups[i]))
        {
            psTracePrintTls13NamedGroup(0,
                    "matrixSslSessOptsSetKeyExGroups: unsupported group",
                    namedGroups[i],
                    PS_TRUE);
            return PS_ARG_FAIL;
        }
        options->tls13SupportedGroups[i] = namedGroups[i];
    }
    options->tls13SupportedGroupsLen = namedGroupsLen;

    /* Set number of key shares to generate. */
    if (numClientHelloKeyShares == 0)
    {
        options->tls13NumClientHelloKeyShares = 1;
    }
    else
    {
        options->tls13NumClientHelloKeyShares = numClientHelloKeyShares;
    }

    return MATRIXSSL_SUCCESS;
}

/** In TLS1.3 sets the allowed signature_algoritms to be used by the client or server
    in the certificates. Used in the signature_algorithms_cert extension */
int32_t matrixSslSessOptsSetSigAlgsCert(sslSessOpts_t *options,
        uint16_t *sigAlgs,
        psSize_t sigAlgsLen)
{
    psSize_t i;

    if (sigAlgsLen == 0 || sigAlgs == NULL || options == NULL)
    {
        return PS_ARG_FAIL;
    }

    /* Set the signature_algorithms to support. */
    for (i = 0; i < sigAlgsLen; i++)
    {
        if (i >= TLS_MAX_SIGNATURE_ALGORITHMS || sigAlgs[i] == 0)
        {
            return PS_ARG_FAIL;
        }
        if (!psIsSigAlgSupported(sigAlgs[i]))
        {
            psTraceIntInfo("matrixSslSessOptsSetSigAlgsCert: " \
                    "unsupported sig_alg: %hu\n", sigAlgs[i]);
            return PS_ARG_FAIL;
        }
        options->tls13SupportedSigAlgsCert[i] = sigAlgs[i];
    }
    options->tls13SupportedSigAlgsCertLen = sigAlgsLen;
    return MATRIXSSL_SUCCESS;
}

/* In TLS1.3 either the client or server can call this to retrieve
   early_data status during or after the handshake */
int32_t matrixSslGetEarlyDataStatus(ssl_t *ssl)
{
    if (ssl == NULL)
    {
        return PS_ARG_FAIL;
    }

    return ssl->tls13EarlyDataStatus;
}

/* Returns the maximum early data amount that can be sent (client)
   or received (server) */
int32_t matrixSslGetMaxEarlyData(ssl_t *ssl)
{
    if (ssl == NULL)
    {
        return PS_ARG_FAIL;
    }

    if (IS_SERVER(ssl))
    {
        /* For server this is not really relevant but return the global
           maximum */
        return ssl->tls13SessionMaxEarlyData;
    }
    else
    {
        /* For client return the maxEarlyData from the first PSK in the
           session list because that is the one to use for early data */
        if (ssl->sec.tls13SessionPskList != NULL &&
            ssl->sec.tls13SessionPskList->params != NULL)
        {
            return ssl->sec.tls13SessionPskList->params->maxEarlyData;
        }
        else
        {
            return 0;
        }
    }
}
# endif /* USE_TLS_1_3 */

/** Sets the allowed signature_algoritms to be used by the client or server.
    In TLS1.2 this means both the certificate signature and CertificateVerify.
    In TLS1.3 this means just the CertificateVerify as the certificate
    signatures are handled using matrixSslSessOptsSetSigAlgsCert. */
int32_t matrixSslSessOptsSetSigAlgs(sslSessOpts_t *options,
        uint16_t *sigAlgs,
        psSize_t sigAlgsLen)
{
    psSize_t i;

    if (sigAlgsLen == 0 || sigAlgs == NULL || options == NULL)
    {
        return PS_ARG_FAIL;
    }

    /* Set the signature_algorithms to support. */
    for (i = 0; i < sigAlgsLen; i++)
    {
        if (i >= TLS_MAX_SIGNATURE_ALGORITHMS || sigAlgs[i] == 0)
        {
            return PS_ARG_FAIL;
        }
        if (!psIsSigAlgSupported(sigAlgs[i]))
        {
            psTraceIntInfo("matrixSslSessOptsSetSigAlgs: " \
                    "unsupported sig_alg: %hu\n", sigAlgs[i]);
            return PS_ARG_FAIL;
        }
        options->supportedSigAlgs[i] = sigAlgs[i];
    }
    options->supportedSigAlgsLen = sigAlgsLen;
    return MATRIXSSL_SUCCESS;
}

int32_t matrixSslSessOptsSetMinDhBits(sslSessOpts_t *options,
        psSize_t minDhBits)
{
# ifdef USE_DH
    if (options == NULL)
    {
        return PS_ARG_FAIL;
    }
    options->minDhBits = minDhBits;
    return MATRIXSSL_SUCCESS;
# else
    psTraceErrr("USE_DH needed for matrixSslSessOptsSetMinDHBits\n");
    return PS_UNSUPPORTED_FAIL;
# endif
}

/******************************************************************************/
/*
    New SSL protocol context
    This structure is associated with a single SSL connection.  Each socket
    using SSL should be associated with a new SSL context.

    certBuf and privKey ARE NOT duplicated within the server context, in order
    to minimize memory usage with multiple simultaneous requests.  They must
    not be deleted by caller until all server contexts using them are deleted.
 */
int32 matrixSslNewSession(ssl_t **ssl, const sslKeys_t *keys,
    sslSessionId_t *session, sslSessOpts_t *options)
{
    psPool_t *pool = NULL;
    ssl_t *lssl;
    int32_t flags, rc;
#ifdef USE_STATELESS_SESSION_TICKETS
    uint32_t i;
#endif

    /* SERVER_SIDE and CLIENT_AUTH and others will have been added to
        versionFlag by callers */
    flags = options->versionFlag;

/*
    First API level chance to make sure a user is not attempting to use
    client or server support that was not built into this library compile
 */
#ifndef USE_SERVER_SIDE_SSL
    if (flags & SSL_FLAGS_SERVER)
    {
        psTraceErrr("SSL_FLAGS_SERVER passed to matrixSslNewSession but MatrixSSL lib was not compiled with server support\n");
        return PS_ARG_FAIL;
    }
#endif

#ifndef USE_CLIENT_SIDE_SSL
    if (!(flags & SSL_FLAGS_SERVER))
    {
        psTraceErrr("SSL_FLAGS_SERVER was not passed to matrixSslNewSession but MatrixSSL was not compiled with client support\n");
        return PS_ARG_FAIL;
    }
#endif

#ifndef USE_CLIENT_AUTH
    if (flags & SSL_FLAGS_CLIENT_AUTH)
    {
        psTraceErrr("SSL_FLAGS_CLIENT_AUTH passed to matrixSslNewSession but MatrixSSL was not compiled with USE_CLIENT_AUTH enabled\n");
        return PS_ARG_FAIL;
    }
#endif

    if (flags & SSL_FLAGS_SERVER)
    {
# ifndef USE_PSK_CIPHER_SUITE
        if (keys == NULL)
        {
            psTraceErrr("NULL keys parameter passed to matrixSslNewSession\n");
            return PS_ARG_FAIL;
        }
# endif /* USE_PSK_CIPHER_SUITE */
        if (session != NULL)
        {
            psTraceInfo("Ignoring session parameter to matrixSslNewSession\n");
        }
    }

# ifndef USE_TLS_1_3
    if (flags & SSL_FLAGS_INTERCEPTOR)
    {
        psTraceErrr("SSL_FLAGS_INTERCEPTOR not supported\n");
        return PS_ARG_FAIL;
    }
# endif

    lssl = psMalloc(pool, sizeof(ssl_t));
    if (lssl == NULL)
    {
        psTraceErrr("Out of memory for ssl_t in matrixSslNewSession\n");
        return PS_MEM_FAIL;
    }
    Memset(lssl, 0x0, sizeof(ssl_t));
    lssl->memAllocPtr = options->memAllocPtr;

# ifdef USE_SEC_CONFIG
#  ifdef DEFAULT_SEC_CONFIG
    rc = matrixSslSetSecurityProfile(lssl, DEFAULT_SEC_CONFIG);
    if (rc < 0)
    {
        return rc;
    }
    {
        sslIdentity_t *key = keys->identity;
        psSizeL_t nBits;
        uint8_t type;
        psSecOperation_t op;

        /* Check whether the loaded keys fulfill the security requirements. */
        while (key != NULL)
        {
            type = key->privKey.type;
            if (type == PS_RSA)
            {
                nBits = key->privKey.keysize * 8;
                op = secop_rsa_load_key;
            }
            else if (type == PS_ECC)
            {
                nBits = key->privKey.key.ecc.curve->size * 8;
                op = secop_ecdsa_load_key;

            }
            rc = matrixSslCallSecurityCallback(lssl, op, nBits, NULL);
            if (rc < 0)
            {
                return rc;
            }
            key = key->next;
        }
    }
#  endif
# endif

#ifdef USE_X509
    if (options->keep_peer_cert_der)
    {
        lssl->bFlags |= BFLAG_KEEP_PEER_CERT_DER;
    }
    if (options->keep_peer_certs)
    {
        lssl->bFlags |= BFLAG_KEEP_PEER_CERTS;
    }
#endif

    if (options->validateCertsOpts.max_verify_depth >= 0)
    {
        lssl->validateCertsOpts.max_verify_depth =
            options->validateCertsOpts.max_verify_depth;
    }

    if (options->userDataPtr != NULL)
    {
        lssl->userDataPtr = options->userDataPtr;
    }

#ifdef USE_ECC
    /* If user specified EC curves they support, let's check that against
        the key material they provided so there are no conflicts.  Don't
        need to test against default compiled-in curves because the keys
        would not have loaded at all */
    if (options->ecFlags)
    {
        if (psTestUserEc(options->ecFlags, keys) < 0)
        {
            psTraceIntInfo("ERROR: Only EC 0x%x specified in options.ecFlags ",
                options->ecFlags);
            psTraceInfo("but other curves were found in key material\n");
            psFree(lssl, pool);
            return PS_ARG_FAIL;
        }
        lssl->ecInfo.ecFlags = options->ecFlags;
    }
    else
    {
        lssl->ecInfo.ecFlags = compiledInEcFlags();
    }
#endif

/*
    Data buffers
 */
    lssl->bufferPool = options->bufferPool;
    lssl->outsize = SSL_DEFAULT_OUT_BUF_SIZE;
#ifdef USE_DTLS
    if (flags & SSL_FLAGS_DTLS)
    {
        lssl->outsize = matrixDtlsGetPmtu();
    }
#endif /* USE_DTLS */

    /* Standard software implementation */
    lssl->outbuf = psMalloc(lssl->bufferPool, lssl->outsize);

    if (lssl->outbuf == NULL)
    {
        psTraceErrr("Buffer pool is too small\n");
        psFree(lssl, pool);
        return PS_MEM_FAIL;
    }
    lssl->insize = SSL_DEFAULT_IN_BUF_SIZE;
#ifdef USE_DTLS
    if (flags & SSL_FLAGS_DTLS)
    {
        lssl->insize = matrixDtlsGetPmtu();
    }
#endif /* USE_DTLS */
    lssl->inbuf = psMalloc(lssl->bufferPool, lssl->insize);
    if (lssl->inbuf == NULL)
    {
        psTraceErrr("Buffer pool is too small\n");
        psFree(lssl->outbuf, lssl->bufferPool);
        psFree(lssl, pool);
        return PS_MEM_FAIL;
    }

    lssl->sPool = pool;
    lssl->keys = (sslKeys_t *) keys;
    if ((lssl->cipher = sslGetCipherSpec(lssl, SSL_NULL_WITH_NULL_NULL)) == NULL)
    {
        psFree(lssl->outbuf, lssl->bufferPool);
        psFree(lssl, pool);
        return PS_MEM_FAIL;
    }
    sslActivateReadCipher(lssl);
    sslActivateWriteCipher(lssl);

    lssl->recordHeadLen = SSL3_HEADER_LEN;
    lssl->hshakeHeadLen = SSL3_HANDSHAKE_HEADER_LEN;

#ifdef SSL_REHANDSHAKES_ENABLED
    lssl->rehandshakeCount = DEFAULT_RH_CREDITS;
#endif /* SSL_REHANDSHAKES_ENABLED */

#ifdef USE_DTLS
    if (flags & SSL_FLAGS_DTLS)
    {
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
        if (options->useExtCvSigOp)
        {
            psTraceErrr("Error: External CertificateVerify signing ");
            psTraceErrr("not supported with the DTLS protocol\n");
            return PS_ARG_FAIL;
        }
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
        lssl->flags |= SSL_FLAGS_DTLS;
        lssl->recordHeadLen += DTLS_HEADER_ADD_LEN;
        lssl->hshakeHeadLen += DTLS_HEADER_ADD_LEN;
        lssl->pmtu = matrixDtlsGetPmtu();
# ifdef USE_CLIENT_SIDE_SSL
        lssl->haveCookie = 0;
# endif
        lssl->flightDone = 0;
        lssl->appDataExch = 0;
        lssl->lastMsn = -1;
        dtlsInitFrag(lssl);
    }
#endif /* USE_DTLS */

    if (flags & SSL_FLAGS_SERVER)
    {
        lssl->flags |= SSL_FLAGS_SERVER;
        /*
          Client auth can only be requested by server, not set by client
        */
        if (flags & SSL_FLAGS_CLIENT_AUTH)
        {
            lssl->flags |= SSL_FLAGS_CLIENT_AUTH;
        }
        lssl->hsState = SSL_HS_CLIENT_HELLO;
    }
    else /* Client. */
    {
        lssl->hsState = SSL_HS_SERVER_HELLO;
        if (session != NULL && session->cipherId != SSL_NULL_WITH_NULL_NULL)
        {
            /* Use the cipher specified in the session ID struct. */
            lssl->cipher = sslGetCipherSpec(lssl, session->cipherId);
            if (lssl->cipher == NULL)
            {
                psTraceInfo("Invalid session id to matrixSslNewSession\n");
            }
            else
            {
                Memcpy(lssl->sec.masterSecret, session->masterSecret,
                    SSL_HS_MASTER_SIZE);
                lssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;
                Memcpy(lssl->sessionId, session->id, SSL_MAX_SESSION_ID_SIZE);
#ifdef USE_STATELESS_SESSION_TICKETS
                /* Possible no sessionId here at all if tickets used instead.
                    Will know if all 0s */
                lssl->sessionIdLen = 0;
                for (i = 0; i < SSL_MAX_SESSION_ID_SIZE; i++)
                {
                    if (session->id[i] != 0x0)
                    {
                        lssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;
                        break;
                    }
                }
#endif
            }
        }
        lssl->sid = session;
    }

# ifdef USE_TLS_1_3
    if (options->tls13CiphersuitesEnabledClient)
    {
        lssl->tls13CiphersuitesEnabledClient = PS_TRUE;
    }
# endif
    rc = initSupportedVersions(lssl, options);
    if (rc < 0)
    {
        matrixSslDeleteSession(lssl);
        return PS_FAILURE;
    }
#ifdef USE_TLS_1_3
    rc = initSupportedGroups(lssl, options);
    if (rc < 0)
    {
        matrixSslDeleteSession(lssl);
        return PS_FAILURE;
    }
    rc = tls13LoadSessionPsks(lssl);
    if (rc < 0)
    {
        matrixSslDeleteSession(lssl);
        return PS_FAILURE;
    }
    lssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_NOT_SENT;
    lssl->tls13PadLen = options->tls13PadLen;
    lssl->tls13BlockSize = options->tls13BlockSize;
#endif
    rc = initSignatureAlgorithms(lssl, options);
    if (rc < 0)
    {
        matrixSslDeleteSession(lssl);
        return PS_FAILURE;
    }
#ifdef USE_DH
    if (options->minDhBits != 0)
    {
        lssl->minDhBits = options->minDhBits;
    }
    else
    {
        lssl->minDhBits = MIN_DH_BITS;
    }
#endif

    /* Clear these to minimize damage on a protocol parsing bug */
    Memset(lssl->inbuf, 0x0, lssl->insize);
    Memset(lssl->outbuf, 0x0, lssl->outsize);
    lssl->err = SSL_ALERT_NONE;
    lssl->encState = SSL_HS_NONE;
    lssl->decState = SSL_HS_NONE;
    *ssl = lssl;
    return PS_SUCCESS;
}

#ifdef USE_TLS_1_3
/* Copy the supplied supportedGroups to ssl struct. Use defaults if nothing supplied */
static int32 initSupportedGroups(ssl_t *ssl, sslSessOpts_t *options)
{
    psSize_t j;
    int32 rc;
    for (j = 0; j < options->tls13SupportedGroupsLen; j++)
    {
        ssl->tls13SupportedGroups[j] = options->tls13SupportedGroups[j];
    }
    ssl->tls13SupportedGroupsLen = options->tls13SupportedGroupsLen;

    if (ssl->tls13SupportedGroups[0] == 0)
    {
        /* User did not specify any groups --> add default groups. */
        rc = tls13GetDefaultGroups(ssl);
        if (rc < 0)
        {
            matrixSslDeleteSession(ssl);
            return PS_FAILURE;
        }
    }
    else
    {
        ssl->tls13NumClientHelloKeyShares
            = options->tls13NumClientHelloKeyShares;
    }
    return MATRIXSSL_SUCCESS;
}
#endif

static int32 initSignatureAlgorithms(ssl_t *ssl, sslSessOpts_t *options)
{
    psSize_t j;
    int32 rc;
#ifdef USE_TLS_1_3
    /* Signature algorithm configuration for certs */
    for (j = 0; j < options->tls13SupportedSigAlgsCertLen; j++)
    {
        ssl->tls13SupportedSigAlgsCert[j] = options->tls13SupportedSigAlgsCert[j];
    }
    ssl->tls13SupportedSigAlgsCertLen = options->tls13SupportedSigAlgsCertLen;

    if (ssl->tls13SupportedSigAlgsCertLen == 0)
    {
        /* User did not specify any sig_alg_certs --> add defaults */
        rc = tls13GetDefaultSigAlgsCert(ssl);
        if (rc < 0)
        {
            return PS_FAILURE;
        }
    }
# endif
    /* Signature algorithm configuration for CertificateVerify */
    for (j = 0; j < options->supportedSigAlgsLen; j++)
    {
        ssl->supportedSigAlgs[j] = options->supportedSigAlgs[j];
    }
    ssl->supportedSigAlgsLen = options->supportedSigAlgsLen;
    if (ssl->supportedSigAlgsLen == 0)
    {
        /* User did not specify any sig_algs --> add defaults */
        rc = getDefaultSigAlgs(ssl);
        if (rc < 0)
        {
            return PS_FAILURE;
        }
    }
    return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
    Delete an SSL session.  Some information on the session may stay around
    in the session resumption cache.
    SECURITY - We memset relevant values to zero before freeing to reduce
    the risk of our keys floating around in memory after we're done.
 */
void matrixSslDeleteSession(ssl_t *ssl)
{

    if (ssl == NULL)
    {
        return;
    }

    ssl->flags |= SSL_FLAGS_CLOSED;

    /* Synchronize all digests, in case some of them have been updated, but
       not finished. */
#ifdef  USE_TLS_1_2
    psSha256Sync(NULL, 1);
#else /* !USE_TLS_1_2 */
    psSha1Sync(NULL, 1);
#endif /* USE_TLS_1_2 */

/*
    If we have a sessionId, for servers we need to clear the inUse flag in
    the session cache so the ID can be replaced if needed.  In the client case
    the caller should have called matrixSslGetSessionId already to copy the
    master secret and sessionId, so free it now.

    In all cases except a successful updateSession call on the server, the
    master secret must be freed.
 */
#ifdef USE_SERVER_SIDE_SSL
    if (ssl->sessionIdLen > 0 && (ssl->flags & SSL_FLAGS_SERVER))
    {
        matrixUpdateSession(ssl);
    }
# ifdef USE_STATELESS_SESSION_TICKETS
    if ((ssl->flags & SSL_FLAGS_SERVER) && ssl->sid)
    {
        psFree(ssl->sid, ssl->sPool);
        ssl->sid = NULL;
    }
# endif
#endif /* USE_SERVER_SIDE_SSL */

    ssl->sessionIdLen = 0;

    if (ssl->expectedName)
    {
        psFree(ssl->expectedName, ssl->sPool);
    }
#ifdef USE_CLIENT_SIDE_SSL
    if (ssl->userExt)
    {
        matrixSslDeleteHelloExtension(ssl->userExt);
    }
#endif

#if defined(USE_IDENTITY_CERTIFICATES)
    psFree(ssl->sec.keySelect.caNames, ssl->sPool);
    psFree(ssl->sec.keySelect.caNameLens, ssl->sPool);
# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (ssl->sec.cert)
    {
        psX509FreeCert(ssl->sec.cert);
        ssl->sec.cert = NULL;
    }

# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_TLS_1_3
    {
        psSize_t i;
# ifndef USE_ONLY_PSK_CIPHER_SUITE
        for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
        {
            if (ssl->sec.tls13KeyAgreeKeys[i] != NULL)
            {
                psDeletePubKey(&ssl->sec.tls13KeyAgreeKeys[i]);
            }
        }
        if (ssl->tls13CertRequestContext)
        {
            psFree(ssl->tls13CertRequestContext, ssl->hsPool);
            ssl->tls13CertRequestContext = NULL;
        }
# endif
        tls13FreePsk(ssl->sec.tls13SessionPskList, ssl->hsPool);
        if (ssl->sec.tls13CookieFromServer)
        {
            psFree(ssl->sec.tls13CookieFromServer, ssl->hsPool);
        }

        psFree(ssl->tls13ClientCipherSuites, ssl->hsPool);
    }
#endif
#ifdef REQUIRE_DH_PARAMS
    if (ssl->sec.dhP)
    {
        psFree(ssl->sec.dhP, ssl->hsPool); ssl->sec.dhP = NULL;
    }
    if (ssl->sec.dhG)
    {
        psFree(ssl->sec.dhG, ssl->hsPool); ssl->sec.dhG = NULL;
    }
    if (ssl->sec.dhKeyPub)
    {
        psDhClearKey(ssl->sec.dhKeyPub);
        psFree(ssl->sec.dhKeyPub, ssl->hsPool);
        ssl->sec.dhKeyPub = NULL;
    }
    if (ssl->sec.dhKeyPriv)
    {
        psDhClearKey(ssl->sec.dhKeyPriv);
        psFree(ssl->sec.dhKeyPriv, ssl->hsPool);
        ssl->sec.dhKeyPriv = NULL;
    }
#endif /* REQUIRE_DH_PARAMS     */

#ifdef USE_ECC_CIPHER_SUITE
    if (ssl->sec.eccKeyPub)
    {
        psEccDeleteKey(&ssl->sec.eccKeyPub);
    }
    if (ssl->sec.eccKeyPriv)
    {
        psEccDeleteKey(&ssl->sec.eccKeyPriv);
    }
#  ifdef USE_X25519
    if (ssl->sec.x25519KeyPub)
    {
        psFree(ssl->sec.x25519KeyPub, ssl->hsPool);
    }
#  endif
#endif /* USE_ECC_CIPHER_SUITE */

/*
    Premaster could also be allocated if this DeleteSession is the result
    of a failed handshake.  This test is fine since all frees will NULL pointer
 */
    if (ssl->sec.premaster)
    {
        psFree(ssl->sec.premaster, ssl->hsPool);
    }
    if (ssl->fragMessage)
    {
        psFree(ssl->fragMessage, ssl->hsPool);
    }

#ifdef USE_DTLS
# ifdef USE_CLIENT_SIDE_SSL
    if (ssl->cookie)
    {
        psFree(ssl->cookie, ssl->hsPool);
    }
# endif
    if (ssl->helloExt)
    {
        psFree(ssl->helloExt, ssl->hsPool);
    }
    dtlsInitFrag(ssl);
    if (ssl->ckeMsg)
    {
        psFree(ssl->ckeMsg, ssl->hsPool);
    }
    if (ssl->certVerifyMsg)
    {
        psFree(ssl->certVerifyMsg, ssl->hsPool);
    }
# if defined(USE_PSK_CIPHER_SUITE) && defined(USE_CLIENT_SIDE_SSL)
    if (ssl->sec.hint)
    {
        psFree(ssl->sec.hint, ssl->hsPool);
    }
# endif
#endif /* USE_DTLS */

/*
    Free the data buffers, clear any remaining user data
 */
    Memset(ssl->inbuf, 0x0, ssl->insize);
    Memset(ssl->outbuf, 0x0, ssl->outsize);
    psFree(ssl->outbuf, ssl->bufferPool);
    psFree(ssl->inbuf, ssl->bufferPool);

    freePkaAfter(ssl);
    clearFlightList(ssl);

#ifdef USE_ALPN
    if (ssl->alpn)
    {
        psFree(ssl->alpn, ssl->sPool); ssl->alpn = NULL;
    }
#endif

/*
    The cipher and mac contexts are inline in the ssl structure, so
    clearing the structure clears those states as well.
 */
    Memset(ssl, 0x0, sizeof(ssl_t));
    psFree(ssl, pool);
}

/******************************************************************************/
/*
    Generic session option control for changing already connected sessions.
    (ie. rehandshake control).  arg param is future for options that may
    require a value.
 */
void matrixSslSetSessionOption(ssl_t *ssl, int32 option, void *arg)
{
    if (option == SSL_OPTION_FULL_HANDSHAKE)
    {
#ifdef USE_SERVER_SIDE_SSL
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            matrixClearSession(ssl, 1);
        }
#endif  /* USE_SERVER_SIDE_SSL */
        ssl->sessionIdLen = 0;
        Memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
    }

#ifdef SSL_REHANDSHAKES_ENABLED
    if (option == SSL_OPTION_DISABLE_REHANDSHAKES)
    {
        ssl->rehandshakeCount = -1;
    }
    /* Get one credit if re-enabling */
    if (option == SSL_OPTION_REENABLE_REHANDSHAKES)
    {
        ssl->rehandshakeCount = 1;
    }
#endif

#if defined(USE_CLIENT_AUTH) && defined(USE_SERVER_SIDE_SSL)
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        if (option == SSL_OPTION_DISABLE_CLIENT_AUTH)
        {
            ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
        }
        else if (option == SSL_OPTION_ENABLE_CLIENT_AUTH)
        {
            ssl->flags |= SSL_FLAGS_CLIENT_AUTH;
            matrixClearSession(ssl, 1);
        }
    }
#endif /* USE_CLIENT_AUTH && USE_SERVER_SIDE_SSL */
}

/******************************************************************************/
/*
    Will be true if the cipher suite is an 'anon' variety OR if the
    user certificate callback returned SSL_ALLOW_ANON_CONNECTION
 */
void matrixSslGetAnonStatus(ssl_t *ssl, int32 *certArg)
{
    *certArg = ssl->sec.anon;
}

/******************************************************************************/
/**
    @return PS_TRUE if we've completed the SSL handshake. PS_FALSE otherwise.
 */
int32_t matrixSslHandshakeIsComplete(const ssl_t *ssl)
{
    return (ssl->hsState == SSL_HS_DONE) ? PS_TRUE : PS_FALSE;
}

# ifdef ENABLE_SECURE_REHANDSHAKES
/**
   Return PS_TRUE when a secure renegotiation is in progress.
   return PS_FALSE otherwise.

   Return PS_TRUE when we have written a non-empty renegotiation_info
   extension into our ClientHello or ServerHello. This can happen
   only when empty renegotiation_infos or the
   TLS_EMPTY_RENEGOTIATION_INFO_SCSV ciphersuites were exchanged
   during the initial handshake, indicating that both sides support
   secure renegotiation.

   The situation where we, as the client, have parsed HelloRequest,
   but have not sent our renegotiating ClientHello yet, should not
   happen, because matrixSslDecode will call matrixSslEncodeClientHello
   directly after parsing a HelloRequest. Thus, it should not be
   possible that this function will be called between HelloRequest
   parsing and ClientHello sending (in which case it would incorrectly
   return PS_FALSE).

#ifdef TODO
   Check the reset logic for ssl->secureRenegotiationInProgress.
   Currently we set it to PS_FALSE after sending or receiving the
   final handshake message.
#endif

   @return PS_TRUE when a secure renegotiation is in progress.
   @return PS_FALSE when no secure renegotiation is in progress.
*/
psBool_t matrixSslRehandshaking(const ssl_t *ssl)
{
# ifdef USE_TLS_1_3
    if (NGTD_VER(ssl, v_tls_1_3_any))
    {
        /* TLS 1.3 does not allow re-handshakes. */
        return PS_FALSE;
    }
# endif
    if (ssl->flags & SSL_FLAGS_ERROR)
    {
        /* Fatal alerts mean the handshake is over. */
        return PS_FALSE;
    }
    else
    {
        return ssl->secureRenegotiationInProgress;
    }
}
# endif /* ENABLE_SECURE_REHANDSHAKES */

#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/******************************************************************************/
/*
    Set a custom callback to receive the certificate being presented to the
    session to perform custom authentication if needed

    NOTE: Must define either USE_CLIENT_SIDE_SSL or USE_CLIENT_AUTH
    in matrixConfig.h
 */
void matrixSslSetCertValidator(ssl_t *ssl, sslCertCb_t certValidator)
{
    if ((ssl != NULL) && (certValidator != NULL))
    {
# ifndef USE_ONLY_PSK_CIPHER_SUITE
        ssl->sec.validateCert = certValidator;
# endif /* !USE_ONLY_PSK_CIPHER_SUITE */
    }
}
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */

# ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    Initialize the session table.
 */
static void initSessionEntryChronList(void)
{
    uint32 i;

    DLListInit(&g_sessionChronList);
    /* Assign every session table entry with their ID from the start */
    for (i = 0; i < SSL_SESSION_TABLE_SIZE; i++)
    {
        DLListInsertTail(&g_sessionChronList, &g_sessionTable[i].chronList);
        g_sessionTable[i].id[0] = (unsigned char) (i & 0xFF);
        g_sessionTable[i].id[1] = (unsigned char) ((i & 0xFF00) >> 8);
        g_sessionTable[i].id[2] = (unsigned char) ((i & 0xFF0000) >> 16);
        g_sessionTable[i].id[3] = (unsigned char) ((i & 0xFF000000) >> 24);
    }
}

/******************************************************************************/
/*
    Register a session in the session resumption cache.  If successful (rc >=0),
    the ssl sessionId and sessionIdLength fields will be non-NULL upon
    return.
 */
int32 matrixRegisterSession(ssl_t *ssl)
{
    uint32 i;
    sslSessionEntry_t *sess;
    DLListEntry *pList;
    unsigned char *id;

    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
        return PS_FAILURE;
    }

#   ifdef USE_STATELESS_SESSION_TICKETS
    /* Tickets override the other resumption mechanism */
    if (ssl->sid &&
        (ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT))
    {
        /* Have recieved new ticket usage request by client */
        return PS_SUCCESS;
    }
#   endif

#   ifdef USE_DTLS
/*
     Don't reassign a new sessionId if we already have one or we blow the
     handshake hash
 */
    if (ACTV_VER(ssl, v_dtls_any) && ssl->sessionIdLen > 0)
    {
        /* This is a retransmit case  */
        return PS_SUCCESS;
    }
#   endif

/*
    Iterate the session table, looking for an empty entry (cipher null), or
    the oldest entry that is not in use
 */
    psLockMutex(&g_sessionTableLock);

    if (DLListIsEmpty(&g_sessionChronList))
    {
        /* All in use */
        psUnlockMutex(&g_sessionTableLock);
        return PS_LIMIT_FAIL;

    }
    /* GetHead Detaches */
    pList = DLListGetHead(&g_sessionChronList);
    sess = DLListGetContainer(pList, sslSessionEntry_t, chronList);
    id = sess->id;
    i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
    if (i >= SSL_SESSION_TABLE_SIZE)
    {
        psUnlockMutex(&g_sessionTableLock);
        return PS_LIMIT_FAIL;
    }

/*
    Register the incoming masterSecret and cipher, which could still be null,
    depending on when we're called.
 */
    Memcpy(g_sessionTable[i].masterSecret, ssl->sec.masterSecret,
        SSL_HS_MASTER_SIZE);
    g_sessionTable[i].cipher = ssl->cipher;
    g_sessionTable[i].inUse += 1;
/*
    The sessionId is the current serverRandom value, with the first 4 bytes
    replaced with the current cache index value for quick lookup later.
    FUTURE SECURITY - Should generate more random bytes here for the session
    id.  We re-use the server random as the ID, which is OK, since it is
    sent plaintext on the network, but an attacker listening to a resumed
    connection will also be able to determine part of the original server
    random used to generate the master key, even if he had not seen it
    initially.
 */
    Memcpy(g_sessionTable[i].id + 4, ssl->sec.serverRandom,
        min(SSL_HS_RANDOM_SIZE, SSL_MAX_SESSION_ID_SIZE) - 4);
    ssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;

    Memcpy(ssl->sessionId, g_sessionTable[i].id, SSL_MAX_SESSION_ID_SIZE);
/*
    startTime is used to check expiry of the entry

    The versions are stored, because a cached session must be reused
    with same SSL version.
 */
    psGetTime(&g_sessionTable[i].startTime, ssl->userPtr);
    g_sessionTable[i].majVer = psEncodeVersionMaj(GET_NGTD_VER(ssl));
    g_sessionTable[i].minVer = psEncodeVersionMin(GET_NGTD_VER(ssl));

    g_sessionTable[i].extendedMasterSecret = ssl->extFlags.extended_master_secret;

    psUnlockMutex(&g_sessionTableLock);
    return i;
}

/******************************************************************************/
/*
    Decrement inUse to keep the reference count meaningful
 */
int32 matrixClearSession(ssl_t *ssl, int32 remove)
{
    unsigned char *id;
    uint32 i;

    if (ssl->sessionIdLen <= 0)
    {
        return PS_ARG_FAIL;
    }
    id = ssl->sessionId;

    i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
    if (i >= SSL_SESSION_TABLE_SIZE)
    {
        return PS_LIMIT_FAIL;
    }
    psLockMutex(&g_sessionTableLock);
    g_sessionTable[i].inUse -= 1;
    if (g_sessionTable[i].inUse == 0)
    {
        DLListInsertTail(&g_sessionChronList, &g_sessionTable[i].chronList);
    }

/*
    If this is a full removal, actually delete the entry.  Also need to
    clear any RESUME flag on the ssl connection so a new session
    will be correctly registered.
 */
    if (remove)
    {
        Memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
        ssl->sessionIdLen = 0;
        ssl->flags &= ~SSL_FLAGS_RESUMED;
        /* Always preserve the id for chronList */
        Memset(g_sessionTable[i].id + 4, 0x0, SSL_MAX_SESSION_ID_SIZE - 4);
        Memset(g_sessionTable[i].masterSecret, 0x0, SSL_HS_MASTER_SIZE);
        g_sessionTable[i].extendedMasterSecret = 0;
        g_sessionTable[i].cipher = NULL;
    }
    psUnlockMutex(&g_sessionTableLock);
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Look up a session ID in the cache.  If found, set the ssl masterSecret
    and cipher to the pre-negotiated values
 */
int32 matrixResumeSession(ssl_t *ssl)
{
    psTime_t accessTime;
    unsigned char *id;
    uint32 i;

    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
        return PS_ARG_FAIL;
    }
    if (ssl->sessionIdLen <= 0)
    {
        return PS_ARG_FAIL;
    }
    id = ssl->sessionId;

    i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
    psLockMutex(&g_sessionTableLock);
    if (i >= SSL_SESSION_TABLE_SIZE || g_sessionTable[i].cipher == NULL)
    {
        psUnlockMutex(&g_sessionTableLock);
        return PS_LIMIT_FAIL;
    }
/*
    Id looks valid.  Update the access time for expiration check.
    Expiration is done on daily basis (86400 seconds)
 */
    psGetTime(&accessTime, ssl->userPtr);
    if ((Memcmp(g_sessionTable[i].id, id,
             (uint32) min(ssl->sessionIdLen, SSL_MAX_SESSION_ID_SIZE)) != 0) ||
        (psDiffMsecs(g_sessionTable[i].startTime,   accessTime, ssl->userPtr) >
                SSL_SESSION_ENTRY_LIFE) || (g_sessionTable[i].majVer != psEncodeVersionMaj(GET_NGTD_VER(ssl)))
            || (g_sessionTable[i].minVer != psEncodeVersionMin(GET_NGTD_VER(ssl))))
    {
        psUnlockMutex(&g_sessionTableLock);
        return PS_FAILURE;
    }

    /* Enforce the RFC 7627 rules for resumpion and extended master secret.
        Essentially, a resumption must use (or not use) the extended master
        secret extension in step with the orginal connection */
    if (g_sessionTable[i].extendedMasterSecret == 0 &&
        ssl->extFlags.extended_master_secret == 1)
    {
        psUnlockMutex(&g_sessionTableLock);
        return PS_FAILURE;
    }
    if (g_sessionTable[i].extendedMasterSecret == 1 &&
        ssl->extFlags.extended_master_secret == 0)
    {
        psUnlockMutex(&g_sessionTableLock);
        return PS_FAILURE;
    }

    /* Looks good */
    Memcpy(ssl->sec.masterSecret, g_sessionTable[i].masterSecret,
        SSL_HS_MASTER_SIZE);
    ssl->cipher = g_sessionTable[i].cipher;
    g_sessionTable[i].inUse += 1;
    if (g_sessionTable[i].inUse == 1)
    {
        DLListRemove(&g_sessionTable[i].chronList);
    }
    psUnlockMutex(&g_sessionTableLock);

    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Update session information in the cache.
    This is called when we've determined the master secret and when we're
    closing the connection to update various values in the cache.
 */
int32 matrixUpdateSession(ssl_t *ssl)
{
    unsigned char *id;
    uint32 i;

    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
        return PS_ARG_FAIL;
    }
    if (ssl->sessionIdLen == 0)
    {
        /* No table entry.  matrixRegisterSession was full of inUse entries */
        return PS_LIMIT_FAIL;
    }
    id = ssl->sessionId;
    i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
    if (i >= SSL_SESSION_TABLE_SIZE)
    {
        return PS_LIMIT_FAIL;
    }
/*
    If there is an error on the session, invalidate for any future use
 */
    psLockMutex(&g_sessionTableLock);
    g_sessionTable[i].inUse += ssl->flags & SSL_FLAGS_CLOSED ? -1 : 0;
    if (g_sessionTable[i].inUse == 0)
    {
        /* End of the line */
        DLListInsertTail(&g_sessionChronList, &g_sessionTable[i].chronList);
    }
    if (ssl->flags & SSL_FLAGS_ERROR)
    {
        Memset(g_sessionTable[i].masterSecret, 0x0, SSL_HS_MASTER_SIZE);
        g_sessionTable[i].cipher = NULL;
        psUnlockMutex(&g_sessionTableLock);
        return PS_FAILURE;
    }
    Memcpy(g_sessionTable[i].masterSecret, ssl->sec.masterSecret,
        SSL_HS_MASTER_SIZE);
    g_sessionTable[i].cipher = ssl->cipher;
    psUnlockMutex(&g_sessionTableLock);
    return PS_SUCCESS;
}


#  ifdef USE_STATELESS_SESSION_TICKETS
/* This implementation supports AES-128/256_CBC and HMAC-SHA1/256 */

/******************************************************************************/
/*
    Remove a named key from the list.

    NOTE: If this list can get very large the faster DLList API should be
    used instead of this single linked list.
 */
int32 matrixSslDeleteSessionTicketKey(sslKeys_t *keys, unsigned char name[16])
{
    psSessionTicketKeys_t *lkey, *prev;

    psLockMutex(&g_sessTicketLock);
    lkey = keys->sessTickets;
    prev = NULL;
    while (lkey)
    {
        if (lkey->inUse == 0 && (Memcmp(lkey->name, name, 16) == 0))
        {
            if (prev == NULL)
            {
                /* removing the first in the list */
                if (lkey->next == NULL)
                {
                    /* no more list == no more session ticket support */
                    psFree(lkey, keys->pool);
                    keys->sessTickets = NULL;
                    psUnlockMutex(&g_sessTicketLock);
                    return PS_SUCCESS;
                }
                /* first in list but not alone */
                keys->sessTickets = lkey->next;
                psFree(lkey, keys->pool);
                psUnlockMutex(&g_sessTicketLock);
                return PS_SUCCESS;
            }
            /* Middle of list.  Join previous with our next */
            prev->next = lkey->next;
            psFree(lkey, keys->pool);
            psUnlockMutex(&g_sessTicketLock);
            return PS_SUCCESS;
        }
        prev = lkey;
        lkey = lkey->next;
    }
    psUnlockMutex(&g_sessTicketLock);
    return PS_FAILURE; /* not found */

}

/******************************************************************************/
/*
    This will be called on ticket decryption if the named key is not
    in the current local list
 */
void matrixSslSetSessionTicketCallback(sslKeys_t *keys,
    int32 (*ticket_cb)(void *, unsigned char[16], short))
{
    keys->ticket_cb = ticket_cb;
}

/******************************************************************************/
/*
    The first in the list will be the one used for all newly issued tickets
 */
int32 matrixSslLoadSessionTicketKeys(sslKeys_t *keys,
    const unsigned char name[16], const unsigned char *symkey,
    short symkeyLen, const unsigned char *hashkey, short hashkeyLen)
{
    psSessionTicketKeys_t *keylist, *prev;
    int32 i = 0;

    /* AES-128 or AES-256 */
    if (symkeyLen != 16 && symkeyLen != 32)
    {
        return PS_LIMIT_FAIL;
    }
    /* SHA256 only */
    if (hashkeyLen != 32)
    {
        return PS_LIMIT_FAIL;
    }

    psLockMutex(&g_sessTicketLock);
    if (keys->sessTickets == NULL)
    {
        /* first one */
        keys->sessTickets = psMalloc(keys->pool, sizeof(psSessionTicketKeys_t));
        if (keys->sessTickets == NULL)
        {
            psUnlockMutex(&g_sessTicketLock);
            return PS_MEM_FAIL;
        }
        keylist = keys->sessTickets;
    }
    else
    {
        /* append */
        keylist = keys->sessTickets;
        while (keylist)
        {
            prev = keylist;
            keylist = keylist->next;
            i++;
        }
        if (i > SSL_SESSION_TICKET_LIST_LEN)
        {
            psTraceErrr("Session ticket list > SSL_SESSION_TICKET_LIST_LEN\n");
            psUnlockMutex(&g_sessTicketLock);
            return PS_LIMIT_FAIL;
        }
        keylist = psMalloc(keys->pool, sizeof(psSessionTicketKeys_t));
        if (keylist == NULL)
        {
            psUnlockMutex(&g_sessTicketLock);
            return PS_MEM_FAIL;
        }
        prev->next = keylist;
    }

    Memset(keylist, 0x0, sizeof(psSessionTicketKeys_t));
    keylist->hashkeyLen = hashkeyLen;
    keylist->symkeyLen = symkeyLen;
    Memcpy(keylist->name, name, 16);
    Memcpy(keylist->hashkey, hashkey, hashkeyLen);
    Memcpy(keylist->symkey, symkey, symkeyLen);
    psUnlockMutex(&g_sessTicketLock);
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Size of encrypted session ticket using 16-byte block cipher and SHA-256
 */
int32 matrixSessionTicketLen(void)
{
    int32 len = 0;

    /* Master secret, 2 version, 2 cipher suite, 4 timestamp,
        1 extended master secret flag are encypted */
    len += SSL_HS_MASTER_SIZE + 2 + 2 + 4 + 1;
    len += psPadLenPwr2(len, 16);
    /* Name, IV and MAC plaintext */
    len += 16 + 16 + SHA256_HASH_SIZE;
    return len;
}

/******************************************************************************/
/* Plaintext Format:
    4 bytes lifetime hint
    2 bytes length of following:
        16 bytes name
        16 bytes IV
        <encrypt>
        2 bytes protocol version
        2 bytes cipher suite
        1 byte extended master secret flag
        48 bytes master secret
        4 bytes timestamp
        <padding /encrypt>
        32 byte HMAC starting at 'name'
 */
int32 matrixCreateSessionTicket(ssl_t *ssl, unsigned char *out, int32 *outLen)
{
    int32 len, ticketLen, pad, rc;
    uint32 timeSecs;
    psTime_t t;
    psAesCbc_t ctx;

#   ifdef USE_HMAC_SHA256
    psHmacSha256_t dgst;
#   else
    psHmacSha1_t dgst;
#   endif
    psSessionTicketKeys_t *keys;
    unsigned char *enc, *c = out;
    unsigned char randno[AES_IVLEN];

    ticketLen = matrixSessionTicketLen();
    if ((ticketLen + 6) > *outLen)
    {
        return PS_LIMIT_FAIL;
    }

    /* Lifetime hint taken from define in matrixsslConfig.h */
    timeSecs = SSL_SESSION_ENTRY_LIFE / 1000; /* it's in milliseconds */
    *c = (unsigned char) ((timeSecs & 0xFF000000) >> 24); c++;
    *c = (unsigned char) ((timeSecs & 0xFF0000) >> 16); c++;
    *c = (unsigned char) ((timeSecs & 0xFF00) >> 8); c++;
    *c = (unsigned char) (timeSecs & 0xFF); c++;

    /* Len of ticket */
    *c = (ticketLen & 0xFF00) >> 8; c++;
    *c = ticketLen & 0xFF; c++;

    /* Do the heavier CPU stuff outside lock */
    timeSecs = psGetTime(&t, ssl->userPtr);

    if (psGetPrngLocked(randno, AES_IVLEN, ssl->userPtr) < 0)
    {
        psTraceInfo("WARNING: psGetPrngLocked failed\n");
    }

    psLockMutex(&g_sessTicketLock);
    /* Ticket itself */
    keys = ssl->keys->sessTickets;
    /* name */
    Memcpy(c, keys->name, 16);
    c += 16;
    Memcpy(c, randno, AES_IVLEN);
    c += AES_IVLEN;
    enc = c; /* encrypt start */
    *c = psEncodeVersionMaj(GET_NGTD_VER(ssl)); c++;
    *c = psEncodeVersionMin(GET_NGTD_VER(ssl)); c++;
    *c = (ssl->cipher->ident & 0xFF00) >> 8; c++;
    *c = ssl->cipher->ident & 0xFF; c++;
    /* Need to track if original handshake used extended master secret */
    *c = ssl->extFlags.extended_master_secret; c++;

    Memcpy(c, ssl->sec.masterSecret, SSL_HS_MASTER_SIZE);
    c += SSL_HS_MASTER_SIZE;

    *c = (unsigned char) ((timeSecs & 0xFF000000) >> 24); c++;
    *c = (unsigned char) ((timeSecs & 0xFF0000) >> 16); c++;
    *c = (unsigned char) ((timeSecs & 0xFF00) >> 8); c++;
    *c = (unsigned char) (timeSecs & 0xFF); c++;

    /* 4 time stamp, 2 version, 2 cipher, 1 extended master secret */
    len = SSL_HS_MASTER_SIZE + 4 + 2 + 2 + 1;

    pad = psPadLenPwr2(len, AES_BLOCKLEN);
    c += sslWritePad(c, (unsigned char) pad); len += pad;
    /* out + 6 + 16 (name) is pointing at IV */
    if ((rc = psAesInitCBC(&ctx, out + 6 + 16, keys->symkey, keys->symkeyLen, PS_AES_ENCRYPT)) < 0)
    {
        goto ERR_LOCKED;
    }
    psAesEncryptCBC(&ctx, enc, enc, len);
    psAesClearCBC(&ctx);

    /* HMAC starting from the Name */
#   ifdef USE_HMAC_SHA256
    if ((rc = psHmacSha256Init(&dgst, keys->hashkey, keys->hashkeyLen)) < 0)
    {
        goto ERR_LOCKED;
    }
    psHmacSha256Update(&dgst, out + 6, len + 16 + 16);
    psHmacSha256Final(&dgst, c);
    *outLen = len + SHA256_HASHLEN + 16 + 16 + 6;
#   else
    if ((rc = psHmacSha1Init(&dgst, keys->hashkey, keys->hashkeyLen)) < 0)
    {
        goto ERR_LOCKED;
    }
    psHmacSha1Update(&dgst, out + 6, len + 16 + 16);
    psHmacSha1Final(&dgst, c);
    *outLen = len + SHA1_HASHLEN + 16 + 16 + 6;
#   endif
    rc = PS_SUCCESS;
ERR_LOCKED:
    memzero_s(randno, sizeof(randno));
    psUnlockMutex(&g_sessTicketLock);
    return rc;
}

/******************************************************************************/
/*
    @pre Must be called with g_sessTicketLock locked. Returns in all cases
    with g_sessTicketLock locked.
 */
static int32 getTicketKeys(ssl_t *ssl, unsigned char *c,
    psSessionTicketKeys_t **keys)
{
    psSessionTicketKeys_t *lkey;
    unsigned char name[16];
    int32_t rc;
    short cachedTicket = 0;

    /* First 16 bytes are the key name */
    Memcpy(name, c, 16);
    *keys = NULL;
    /* check our cached list beginning with our own encryption key */
    lkey = ssl->keys->sessTickets;
    while (lkey)
    {
        if (Memcmp(lkey->name, name, 16) == 0)
        {
            lkey->inUse = 1;
            *keys = lkey;
            /* Have the key. Invoke callback with SUCCESS */
            if (ssl->keys->ticket_cb)
            {
                cachedTicket++;
                break;
            }
            else
            {
                return PS_SUCCESS;
            }
        }
        lkey = lkey->next;
    }
    /* didn't find it.  Ask user */
    if (ssl->keys->ticket_cb)
    {
        /* Unlock. Cback will likely call matrixSslLoadSessionTicketKeys */
        psUnlockMutex(&g_sessTicketLock);
        rc = ssl->keys->ticket_cb((struct sslKeys_t *) ssl->keys, name, cachedTicket);
        psLockMutex(&g_sessTicketLock);
        if (rc < 0)
        {
            if (lkey)
            {
                /* inUse could be set in the odd case where we
                   found the cached key but the user didn't want to use it. */
                lkey->inUse = 0;
            }
            return PS_FAILURE; /* user couldn't find it either */
        }
        /* found it */
        if (cachedTicket == 0)
        {
            /* it's been found and added at end of list.  confirm this */
            lkey = ssl->keys->sessTickets;
            if (lkey == NULL)
            {
                return PS_FAILURE; /* user claims they added, but empty */
            }
            while (lkey->next)
            {
                lkey = lkey->next;
            }
            if (Memcmp(lkey->name, c, 16) != 0)
            {
                return PS_FAILURE; /* user claims to have added, but... */
            }
            lkey->inUse = 1;
            *keys = lkey;
        }
        return PS_SUCCESS;
    }
    return PS_FAILURE; /* not in list and no callback registered */
}

/******************************************************************************/

int32 matrixUnlockSessionTicket(ssl_t *ssl, unsigned char *in, int32 inLen)
{
    unsigned char *c, *enc;
    unsigned char name[16];
    psSessionTicketKeys_t *keys;

#   ifdef USE_HMAC_SHA256
    psHmacSha256_t dgst;
#    define L_HASHLEN   SHA256_HASHLEN
#   else
    psHmacSha1_t dgst;
#    define L_HASHLEN   SHA1_HASHLEN
#   endif
    unsigned char hash[L_HASHLEN];
    psAesCbc_t ctx;
    int32 len;
    psTime_t t;
    uint32 majVer, minVer, cipherSuite, time, now;

    /* Validate that the incoming ticket is the length we expect */
    if (inLen != matrixSessionTicketLen())
    {
        return PS_FAILURE;
    }
    c = in;
    len = inLen;
    psLockMutex(&g_sessTicketLock);
    if (getTicketKeys(ssl, c, &keys) < 0)
    {
        psUnlockMutex(&g_sessTicketLock);
        psTraceErrr("No key found for session ticket\n");
        return PS_FAILURE;
    }

    /* Mac is over the name, IV and encrypted data */
#   ifdef USE_HMAC_SHA256
    psHmacSha256Init(&dgst, keys->hashkey, keys->hashkeyLen);
    psHmacSha256Update(&dgst, c, len - L_HASHLEN);
    psHmacSha256Final(&dgst, hash);
#   else
    psHmacSha1Init(&dgst, keys->hashkey, keys->hashkeyLen);
    psHmacSha1Update(&dgst, c, len - L_HASHLEN);
    psHmacSha1Final(&dgst, hash);
#   endif

    Memcpy(name, c, 16);
    c += 16;

    /* out is pointing at IV */
    psAesInitCBC(&ctx, c, keys->symkey, keys->symkeyLen, PS_AES_DECRYPT);
    psAesDecryptCBC(&ctx, c + 16, c + 16, len - 16 - 16 - L_HASHLEN);
    psAesClearCBC(&ctx);
    keys->inUse = 0;
    psUnlockMutex(&g_sessTicketLock);

    /* decrypted marker */
    enc = c + 16;

    c += (len - 16 - L_HASHLEN); /* already moved past name */

    if (Memcmp(hash, c, L_HASHLEN) != 0)
    {
        psTraceErrr("HMAC check failure on session ticket\n");
        return PS_FAILURE;
    }
#   undef L_HASHLEN

    majVer = *enc; enc++;
    minVer = *enc; enc++;

    /* Match protocol version */
    if (majVer != psEncodeVersionMaj(GET_NGTD_VER(ssl))
            || minVer != psEncodeVersionMin(GET_NGTD_VER(ssl)))
    {
        psTraceErrr("Protocol check failure on session ticket\n");
        return PS_FAILURE;
    }

    cipherSuite = *enc << 8; enc++;
    cipherSuite += *enc; enc++;

    /* Force cipher suite */
    if ((ssl->cipher = sslGetCipherSpec(ssl, cipherSuite)) == NULL)
    {
        psTraceErrr("Cipher suite check failure on session ticket\n");
        return PS_FAILURE;
    }

    /* Did the initial connection use extended master secret? */
    /* First round of "require" testing can be done here.  If server is
        set to require extended master secret and this ticket DOES NOT have it
        then we can stop resumption right now */
    if (*enc == 0x0 && ssl->extFlags.require_extended_master_secret == 1)
    {
        psTraceErrr("Ticket and master secret derivation methods differ\n");
        return PS_FAILURE;
    }
    ssl->extFlags.require_extended_master_secret = *enc; enc++;

    /* Set aside masterSecret */
    Memcpy(ssl->sid->masterSecret, enc, SSL_HS_MASTER_SIZE);
    enc += SSL_HS_MASTER_SIZE;

    /* Check lifetime */
    time = *enc << 24; enc++;
    time += *enc << 16; enc++;
    time += *enc << 8; enc++;
    time += *enc; enc++;

    now = psGetTime(&t, ssl->userPtr);

    if ((now - time) > (SSL_SESSION_ENTRY_LIFE / 1000))
    {
        /* Expired session ticket.  New one will be issued */
        psTraceErrr("Session ticket was expired\n");
        return PS_FAILURE;
    }
    ssl->sid->cipherId = cipherSuite;

    return PS_SUCCESS;
}
#  endif /* USE_STATELESS_SESSION_TICKETS */
# endif  /* USE_SERVER_SIDE_SSL */

#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
    Get session information from the ssl structure and populate the given
    session structure.  Session will contain a copy of the relevant session
    information, suitable for creating a new, resumed session.

    NOTE: Must define USE_CLIENT_SIDE_SSL in matrixConfig.h

    sslSessionId_t myClientSession;

    ...&myClientSession
 */
int32 matrixSslGetSessionId(ssl_t *ssl, sslSessionId_t *session)
{

    if (ssl == NULL || ssl->flags & SSL_FLAGS_SERVER || session == NULL)
    {
        return PS_ARG_FAIL;
    }

# ifdef USE_TLS_1_3
    if (USING_TLS_1_3(ssl))
    {
        return PS_SUCCESS;
    }
# endif

    if (ssl->cipher != NULL && ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL &&
        ssl->sessionIdLen == SSL_MAX_SESSION_ID_SIZE)
    {

# ifdef USE_STATELESS_SESSION_TICKETS
        /* There is only one sessionId_t structure for any given session and
            it is possible a re-handshake on a session ticket connection will
            agree on using standard resumption and so the old master secret
            for the session ticket will be overwritten.  Check for this case
            here and do not update our session if a ticket is in use */
        if (session->sessionTicket != NULL && session->sessionTicketLen > 0)
        {
            return PS_SUCCESS;
        }
# endif
        session->cipherId = ssl->cipher->ident;
        Memcpy(session->id, ssl->sessionId, ssl->sessionIdLen);
        Memcpy(session->masterSecret, ssl->sec.masterSecret,
            SSL_HS_MASTER_SIZE);
        return PS_SUCCESS;
    }
# ifdef USE_STATELESS_SESSION_TICKETS
    if (ssl->cipher != NULL && ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL &&
        session->sessionTicket != NULL && session->sessionTicketLen > 0)
    {
        session->cipherId = ssl->cipher->ident;
        Memcpy(session->masterSecret, ssl->sec.masterSecret,
            SSL_HS_MASTER_SIZE);
        return PS_SUCCESS;
    }
# endif

    return PS_FAILURE;
}

# ifdef USE_ALPN
/******************************************************************************/

int32 matrixSslCreateALPNext(psPool_t *pool, int32 protoCount,
    unsigned char *proto[MAX_PROTO_EXT], int32 protoLen[MAX_PROTO_EXT],
    unsigned char **extOut, int32 *extLen)
{
    int32 i, len;
    unsigned char *c;

    if (protoCount > MAX_PROTO_EXT)
    {
        psTraceIntInfo("Must increase MAX_PROTO_EXT to %d\n", protoCount);
        return PS_ARG_FAIL;
    }
    len = 2; /* overall len is 2 bytes */
    for (i = 0; i < protoCount; i++)
    {
        if (protoLen[i] <= 0 || protoLen[i] > 255)
        {
            return PS_ARG_FAIL;
        }
        len += protoLen[i] + 1; /* each string has 1 byte len */
    }
    if ((c = psMalloc(pool, len)) == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(c, 0, len);
    *extOut = c;
    *extLen = len;

    *c = ((len - 2) & 0xFF00) >> 8; c++; /* don't include ourself */
    *c = (len - 2) & 0xFF; c++;
    for (i = 0; i < protoCount; i++)
    {
        *c = protoLen[i]; c++;
        Memcpy(c, proto[i], protoLen[i]);
        c += protoLen[i];
    }
    return PS_SUCCESS;
}
# endif

/******************************************************************************/

int32 matrixSslCreateSNIext(psPool_t *pool, unsigned char *host, int32 hostLen,
    unsigned char **extOut, int32 *extLen)
{
    unsigned char *c;

    *extLen = hostLen + 5;
    if ((c = psMalloc(pool, *extLen)) == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(c, 0, *extLen);
    *extOut = c;

    *c = ((hostLen + 3) & 0xFF00) >> 8; c++;
    *c = (hostLen + 3) & 0xFF; c++;
    c++; /* host_name enum */
    *c = (hostLen & 0xFF00) >> 8; c++;
    *c = hostLen  & 0xFF; c++;
    Memcpy(c, host, hostLen);
    return PS_SUCCESS;
}
#endif /* USE_CLIENT_SIDE_SSL */

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    If client sent a ServerNameIndication extension, see if we have those
    keys to load
 */
sslKeys_t *matrixServerGetKeysSNI(ssl_t *ssl, char *host, int32 hostLen)
{
    sslKeys_t *keys = NULL;

    if (ssl->sni_cb)
    {
        ssl->extFlags.sni = 1; /* extension was actually handled */
        (ssl->sni_cb)((void *) ssl, host, hostLen, &keys);
    }
    return keys;
}

int32 matrixServerSetKeysSNI(ssl_t *ssl, char *host, int32 hostLen)
{
    sslKeys_t *keys;

    keys = matrixServerGetKeysSNI(ssl, host, hostLen);
    if (ssl->extFlags.sni)
    {
        if (keys == NULL)
        {
            return PS_UNSUPPORTED_FAIL; /* callback didn't provide keys */
        }
        else
        {
            ssl->keys = keys;
        }
    }
    return PS_SUCCESS;
}
#endif /* USE_SERVER_SIDE_SSL */

/******************************************************************************/
/*
    Rehandshake. Free any allocated sec members that will be repopulated
 */
void sslResetContext(ssl_t *ssl)
{
#ifdef USE_X509
    int32_t bFlagsToKeep = 0;

    /* Most bFlags are cleared below. However, some options we wish
       to retain for the rehandshake. */
    if (ssl->bFlags & BFLAG_KEEP_PEER_CERTS)
    {
        bFlagsToKeep |= BFLAG_KEEP_PEER_CERTS;
    }
    if (ssl->bFlags & BFLAG_KEEP_PEER_CERT_DER)
    {
        bFlagsToKeep |= BFLAG_KEEP_PEER_CERT_DER;
    }
#endif
#ifdef USE_CLIENT_SIDE_SSL
    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
        ssl->anonBk = ssl->sec.anon;
        ssl->flagsBk = ssl->flags;
        ssl->bFlagsBk = ssl->bFlags;
    }
#endif
    ssl->sec.anon = 0;
#ifdef USE_SERVER_SIDE_SSL
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        matrixClearSession(ssl, 0);
    }
#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_DHE_CIPHER_SUITE
    ssl->flags &= ~SSL_FLAGS_DHE_KEY_EXCH;
    ssl->flags &= ~SSL_FLAGS_DHE_WITH_RSA;
# ifdef USE_ANON_DH_CIPHER_SUITE
    ssl->flags &= ~SSL_FLAGS_ANON_CIPHER;
# endif /* USE_ANON_DH_CIPHER_SUITE */
# ifdef USE_ECC_CIPHER_SUITE
    ssl->flags &= ~SSL_FLAGS_ECC_CIPHER;
    ssl->flags &= ~SSL_FLAGS_DHE_WITH_RSA;
    ssl->flags &= ~SSL_FLAGS_DHE_WITH_DSA;
# endif /* USE_ECC_CIPHER_SUITE */
#endif  /* USE_DHE_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
    ssl->flags &= ~SSL_FLAGS_PSK_CIPHER;
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_DTLS
/*
    This flag is used in conjuction with flightDone in the buffer
    management API set to determine whether we are still in a handshake
    state for attempting flight resends. If we are resetting context we
    know a handshake phase is starting up again
 */
    if (ACTV_VER(ssl, v_dtls_any))
    {
        ssl->appDataExch = 0;
    }
#endif
    ssl->bFlags = 0;  /* Reset buffer control */

#ifdef USE_X509
    ssl->bFlags |= bFlagsToKeep;
#endif
}

#ifdef USE_CERT_VALIDATE
static int wildcardMatch(char *wild, char *s)
{
    char *c, *e;

    c = wild;
    if (*c == '*')
    {
        c++;
        /* TODO - this is actually a parse error */
        if (*c != '.')
        {
            return -1;
        }
        if (Strchr(s, '@'))
        {
            return -1;
        }
        if ((e = Strchr(s, '.')) == NULL)
        {
            return -1;
        }
        if (strcasecmp(c, e) == 0)
        {
            return 0;
        }
    }
    else if (*c == '.')
    {
        /* TODO - this is actually a parse error */
        return -1;
    }
    else if (strcasecmp(c, s) == 0)
    {
        return 0;
    }
    return -1;
}

static int matchEmail(char *email, int32 emailLen,
    char *expectedEmail,
    int32 caseSensitiveLocalPart)
{
    int32_t at_i;

    if (Strlen(expectedEmail) != emailLen)
    {
        return 0;
    }

    if (caseSensitiveLocalPart)
    {
        /* Look for "@". The address has been checked
           during parsing, se we know it exists. */
        for (at_i = 0; at_i < emailLen; at_i++)
        {
            if (email[at_i] == '@')
            {
                break;
            }
        }
        /* Case-sensitive match for the local part,
           case-insensitive for the host part. */
        if (((Strncmp(email,
                  expectedEmail, at_i)) == 0) &&
            (strcasecmp(email + at_i,
                 expectedEmail + at_i) == 0))
        {
            return 1;
        }
    }
    else
    {
        /* Case-insensitive match for everything. */
        if (strcasecmp(email, expectedEmail) == 0)
        {
            return 1;
        }
    }

    return 0;
}

static
int32_t checkPathLenConstraint(psX509Cert_t *ic,
        psX509Cert_t *sc,
        int32_t pathLen)
{
    if (ic->extensions.bc.pathLenConstraint >= 0)
    {
        /*
          Make sure the pathLen is not exceeded.  If the sc and ic
          are the same CA at this point, this means the peer
          included the root CA in the chain it sent.  It's not good
          practice to do this but implementations seem to allow it.
          Subtract one from pathLen in this case since one got
          added when it was truly just self-authenticating.
        */
        if (sc->sigHashLen == ic->sigHashLen &&
                memcmpct(sc->sigHash, ic->sigHash, sc->sigHashLen) == 0)
        {
            if (pathLen > 0)
            {
                pathLen--;
            }
        }
        if (ic->extensions.bc.pathLenConstraint < pathLen)
        {
            psTraceErrr("Authentication failed due to X.509 pathLen\n");
            sc->authStatus = PS_CERT_AUTH_FAIL_PATH_LEN;
            return PS_CERT_AUTH_FAIL_PATH_LEN;
        }
    }

    return PS_SUCCESS;
}

/******************************************************************************/
/*
   Wrapper for matrixValidateCertsExt taking in no extra options, using
   default options instead.
 */
int32 matrixValidateCerts(psPool_t *pool, psX509Cert_t *subjectCerts,
    psX509Cert_t *issuerCerts, char *expectedName,
    psX509Cert_t **foundIssuer, void *hwCtx,
    void *poolUserPtr)
{
    matrixValidateCertsOptions_t options;

    Memset(&options, 0, sizeof(matrixValidateCertsOptions_t));

    /*
       By default, earlier versions of matrixValidateCerts checked
       expectedName against all supported fields in the SAN and the CN.
       For now, retain this behaviour for backwards compatibility.
     */
    options.nameType = NAME_TYPE_ANY;

# ifdef ALWAYS_CHECK_SUBJECT_CN_IN_HOSTNAME_VALIDATION
    /*
       In earlier versions, this feature was always enabled.
     */
    options.mFlags |= VCERTS_MFLAG_ALWAYS_CHECK_SUBJECT_CN;
# endif /* ALWAYS_CHECK_SUBJECT_CN_IN_HOSTNAME_VALIDATION */

    /*
       In earlier versions, this feature was always enabled.
     */
    /* options.mFlags |= VCERTS_MFLAG_SAN_EMAIL_CASE_INSENSITIVE_LOCAL_PART; */

    return matrixValidateCertsExt(pool, subjectCerts, issuerCerts, expectedName,
        foundIssuer, hwCtx, poolUserPtr, &options);
}

/*
    Subject certs is the leaf first chain of certs from the peer
    Issuer certs is a flat list of trusted CAs loaded by LoadKeys
 */
int32 matrixValidateCertsExt(psPool_t *pool, psX509Cert_t *subjectCerts,
    psX509Cert_t *issuerCerts, char *expectedName,
    psX509Cert_t **foundIssuer, void *hwCtx,
    void *poolUserPtr,
    const matrixValidateCertsOptions_t *opts)
{

    psX509Cert_t *ic, *sc;
    x509GeneralName_t *n;
    x509v3extensions_t *ext;
    char ip[16];
    int32 rc, foundSupportedSAN, pathLen = 0;

    /*
       Check for illegal option combinations.
     */
    if (opts->mFlags & VCERTS_MFLAG_ALWAYS_CHECK_SUBJECT_CN)
    {
        if (opts->nameType != NAME_TYPE_ANY &&
            opts->nameType != NAME_TYPE_HOSTNAME &&
            opts->nameType != NAME_TYPE_CN)
        {
            return PS_ARG_FAIL;
        }
    }

    if (opts->flags & VCERTS_FLAG_VALIDATE_EXPECTED_GENERAL_NAME)
    {
        /*
           Validate expectedName.
         */
        if (expectedName)
        {
            if (psX509ValidateGeneralName(expectedName) < 0)
            {
                psTraceErrr("expectedName is not a valid GeneralName\n");
                return PS_ARG_FAIL;
            }
        }
    }

    *foundIssuer = NULL;

    if (opts->flags & VCERTS_FLAG_REVALIDATE_DATES)
    {
        sc = subjectCerts;
        while(sc)
        {
            rc = validateDateRange(sc);
            if (rc < 0)
            {
                psTraceCrypto("Could not parse certificate date\n");
                return PS_PARSE_FAIL;
            }
            if (sc->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG)
            {
                psTraceCrypto("Certificate date validation failed\n");
                sc->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
                return PS_CERT_AUTH_FAIL_EXTENSION;
            }
            sc = sc->next;
        }
    }

/*
    Case #1 is no issuing cert.  Going to want to check that the final
    subject cert presented is a SelfSigned CA
 */
    if (issuerCerts == NULL)
    {
        return psX509AuthenticateCert(pool, subjectCerts, NULL, foundIssuer,
            hwCtx, poolUserPtr);
    }
/*
    Case #2 is an issuing cert AND possibly a chain of subjectCerts.
 */
    sc = subjectCerts;
    if ((ic = sc->next) != NULL)
    {
/*
         We do have a chain. Authenticate the chain before even looking
         to our issuer CAs.
 */
        while (ic->next != NULL)
        {
            if ((rc = psX509AuthenticateCert(pool, sc, ic, foundIssuer, hwCtx,
                     poolUserPtr)) < PS_SUCCESS)
            {
                return rc;
            }

            rc = checkPathLenConstraint(ic, sc, pathLen);
            if (rc < 0)
            {
                return rc;
            }
            pathLen++;

            sc = sc->next;
            ic = sc->next;
        }
/*
        Test using the parent-most in chain as the subject
 */
        if ((rc = psX509AuthenticateCert(pool, sc, ic, foundIssuer, hwCtx,
                 poolUserPtr)) < PS_SUCCESS)
        {
            return rc;
        }

        rc = checkPathLenConstraint(ic, sc, pathLen);
        if (rc < 0)
        {
                return rc;
        }
        pathLen++;
/*
        Lastly, set subject to the final cert for the real issuer test below
 */
        sc = sc->next;
    }
/*
     Now loop through the issuer certs and see if we can authenticate this chain

     If subject cert was a chain, that has already been authenticated above so
     we only need to pass in the single parent-most cert to be tested against
 */
    *foundIssuer = NULL;
    ic = issuerCerts;
    while (ic != NULL)
    {
        sc->authStatus = PS_FALSE;
        if ((rc = psX509AuthenticateCert(pool, sc, ic, foundIssuer, hwCtx,
                 poolUserPtr)) == PS_SUCCESS)
        {
            rc = checkPathLenConstraint(ic, sc, pathLen);
            if (rc < 0)
            {
                return rc;
            }

            if (opts->flags & VCERTS_FLAG_REVALIDATE_DATES)
            {
                /* Re-validate the date of the issuer cert also. */
                rc = validateDateRange(ic);
                if (rc < 0)
                {
                    psTraceCrypto("Could not parse certificate date\n");
                    return PS_PARSE_FAIL;
                }
                if (ic->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG)
                {
                    psTraceCrypto("Issuer cert out of date\n");
                    sc->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
                    return PS_CERT_AUTH_FAIL_EXTENSION;
                }
            }

            /* Validate extensions of leaf certificate */
            ext = &subjectCerts->extensions;

            /* Validate extended key usage */
            if (ext->critFlags & EXT_CRIT_FLAG(OID_ENUM(id_ce_extKeyUsage)))
            {
                if (!(ext->ekuFlags & (EXT_KEY_USAGE_TLS_SERVER_AUTH |
                                       EXT_KEY_USAGE_TLS_CLIENT_AUTH)))
                {
                    _psTrace("End-entity certificate not for TLS usage!\n");
                    subjectCerts->authFailFlags |= PS_CERT_AUTH_FAIL_EKU_FLAG;
                    rc = subjectCerts->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
                }
            }

            /* Check the subject/altSubject. Should match requested domain */
            if (expectedName == NULL ||
                (opts->flags & VCERTS_FLAG_SKIP_EXPECTED_NAME_VALIDATION))
            {
                return rc;
            }
            foundSupportedSAN = 0;
            for (n = ext->san; n != NULL; n = n->next)
            {
                switch (n->id)
                {
                case GN_DNS:
                    foundSupportedSAN = 1;
                    if (opts->nameType == NAME_TYPE_ANY ||
                        opts->nameType == NAME_TYPE_HOSTNAME ||
                        opts->nameType == NAME_TYPE_SAN_DNS)
                    {
                        if (wildcardMatch((char *) n->data, expectedName) == 0)
                        {
                            return rc;
                        }
                    }
                    break;
                case GN_EMAIL:
                    foundSupportedSAN = 1;
                    if (opts->nameType == NAME_TYPE_ANY ||
                        opts->nameType == NAME_TYPE_SAN_EMAIL)
                    {
                        if (opts->mFlags &
                            VCERTS_MFLAG_SAN_EMAIL_CASE_INSENSITIVE_LOCAL_PART)
                        {
                            if (matchEmail((char *) n->data, n->dataLen,
                                    expectedName, 0))
                            {
                                return rc;
                            }
                        }
                        else
                        {
                            if (matchEmail((char *) n->data, n->dataLen,
                                    expectedName, 1))
                            {
                                return rc;
                            }
                        }
                    }
                    break;
                case GN_IP:
                    foundSupportedSAN = 1;
                    if (opts->nameType == NAME_TYPE_ANY ||
                        opts->nameType == NAME_TYPE_SAN_IP_ADDRESS)
                    {
                        Snprintf(ip, 15, "%u.%u.%u.%u",
                            (unsigned char) (n->data[0]),
                            (unsigned char ) (n->data[1]),
                            (unsigned char ) (n->data[2]),
                            (unsigned char ) (n->data[3]));
                        ip[15] = '\0';
                        if (Strcmp(ip, expectedName) == 0)
                        {
                            return rc;
                        }
                    }
                    break;
                case GN_OTHER:
                case GN_X400:
                case GN_DIR:
                case GN_EDI:
                case GN_URI:
                case GN_REGID:
                    /* No support for these currently. */
                    break;
                }
            }

            /*
               Now check the subject CN, if necessary.

               RFC 6125, Section 6.4.4:
               "a client MUST NOT seek a match for a reference identifier
               of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
               URI-ID, or any application-specific identifier types supported
               by the client."
             */

# ifdef ALWAYS_CHECK_SUBJECT_CN_IN_HOSTNAME_VALIDATION
            if (wildcardMatch(subjectCerts->subject.commonName,
                    expectedName) == 0)
            {
                return rc;
            }
# else
            if (opts->nameType == NAME_TYPE_ANY ||
                opts->nameType == NAME_TYPE_CN ||
                opts->nameType == NAME_TYPE_HOSTNAME)
            {
                if (!foundSupportedSAN ||
                    (opts->mFlags & VCERTS_MFLAG_ALWAYS_CHECK_SUBJECT_CN))
                {
                    if (wildcardMatch(subjectCerts->subject.commonName,
                            expectedName) == 0)
                    {
                        return rc;
                    }
                }
            }
# endif     /* ALWAYS_CHECK_SUBJECT_CN_IN_HOSTNAME_VALIDATION */

            psTraceErrr("Authentication failed: no matching subject\n");
            subjectCerts->authFailFlags |= PS_CERT_AUTH_FAIL_SUBJECT_FLAG;
            rc = subjectCerts->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
            return rc;
        }
        else if (rc == PS_MEM_FAIL)
        {
/*
            OK to fail on the authentication because there may be a list here
            but MEM failures prevent us from continuing at all.
 */
            return rc;
        }
        ic = ic->next;
    }
/*
    Success would have returned if it happen
 */
    return PS_CERT_AUTH_FAIL;
}

/******************************************************************************/
/*
    Calls a user defined callback to allow for manual validation of the
    certificate.
 */
int32 matrixUserCertValidator(ssl_t *ssl, int32 alert,
    psX509Cert_t *subjectCert, sslCertCb_t certValidator)
{
    int32 status;

/*
    If there is no callback, return PS_SUCCESS because there has already been
    a test for the case where the certificate did NOT PASS pubkey test
    and a callback does not exist to manually handle.

    It is highly recommended that the user manually verify, but the cert
    material has internally authenticated and the user has implied that
    is sufficient enough.
 */
    if (certValidator == NULL)
    {
        psTraceInfo("Internal cert auth passed. No user callback registered\n");
        return PS_SUCCESS;
    }

/*
    Finally, let the user know what the alert status is and
    give them the cert material to access.  Any non-zero value in alert
    indicates there is a pending fatal alert.

    The user can look at authStatus members if they want to examine the cert
    that did not pass.
 */
    if (alert == SSL_ALERT_NONE)
    {
        status = 0;
    }
    else
    {
        status = alert;
    }

/*
    The user callback
 */
    return certValidator(ssl, subjectCert, status);
}
#endif /* USE_CERT_VALIDATE */

/******************************************************************************/
#ifdef USE_MATRIXSSL_STATS
void matrixSslRegisterStatCallback(ssl_t *ssl, void (*stat_cb)(void *ssl,
        void *stats_ptr, int32 type, int32 value), void *stats_ptr)
{
    ssl->statCb = stat_cb;
    ssl->statsPtr = stats_ptr;
}

void matrixsslUpdateStat(ssl_t *ssl, int32 type, int32 value)
{
    if (ssl->statCb)
    {
        (ssl->statCb)(ssl, ssl->statsPtr, type, value);
    }
}

#endif /* USE_MATRIXSSL_STATS */
/******************************************************************************/
