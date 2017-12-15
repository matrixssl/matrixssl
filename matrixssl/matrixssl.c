/**
 *      @file    matrixssl.c
 *      @version $Format:%h%d$
 *
 *      The session and authentication management portions of the MatrixSSL library.
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

#include "matrixsslImpl.h"
/******************************************************************************/

static const char copyright[] =
    "Copyright Inside Secure Corporation. All rights reserved.";

#if defined(USE_RSA) || defined(USE_ECC)
# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
static int32 verifyReadKeys(psPool_t *pool, sslKeys_t *keys, void *poolUserPtr);
# endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
#endif  /* USE_RSA || USE_ECC */

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
#   include <sys/mman.h>
#   include <fcntl.h>
static sslSessionEntry_t *g_sessionTable;
#  else
static sslSessionEntry_t g_sessionTable[SSL_SESSION_TABLE_SIZE];
#  endif

static DLListEntry g_sessionChronList;
static void initSessionEntryChronList(void);

#endif  /* USE_SERVER_SIDE_SSL */

#if defined(USE_RSA) || defined(USE_ECC)
# ifdef MATRIX_USE_FILE_SYSTEM
static int32 matrixSslLoadKeyMaterial(sslKeys_t *keys, const char *certFile,
                                      const char *privFile, const char *privPass, const char *CAfile,
                                      int32 privKeyType);
# endif
static int32 matrixSslLoadKeyMaterialMem(sslKeys_t *keys,
                                         const unsigned char *certBuf, int32 certLen,
                                         const unsigned char *privBuf,
                                         int32 privLen, const unsigned char *CAbuf, int32 CAlen,
                                         int32 privKeyType);
#endif /* USE_RSA || USE_ECC */

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
    uint32_t shared;
    int32_t rc;

    (void) copyright;      /* Prevent compiler warning. */
    if (*g_config == 'Y')
    {
        return PS_SUCCESS; /* Function has been called previously */
    }
    /* config parameter is matrixconfig + cryptoconfig + coreconfig */
    strncpy(g_config, MATRIXSSL_CONFIG, sizeof(g_config) - 1);
    clen = strlen(MATRIXSSL_CONFIG) - strlen(PSCRYPTO_CONFIG);
    if (strncmp(g_config, config, clen) != 0)
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
    memset(g_sessionTable, 0x0,
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
    memset(g_sessionTable, 0x0,
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

/******************************************************************************/
/*
    Must call to allocate the key structure now.  After which, LoadRsaKeys,
    LoadDhParams and/or LoadPskKey can be called

    Memory info:
    Caller must free keys with matrixSslDeleteKeys on function success
    Caller does not need to free keys on function failure
 */
int32_t matrixSslNewKeys(sslKeys_t **keys, void *memAllocUserPtr)
{
    psPool_t *pool = NULL;
    sslKeys_t *lkeys;

#if  defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
    int32_t rc;
#endif

    lkeys = psMalloc(pool, sizeof(sslKeys_t));
    if (lkeys == NULL)
    {
        return PS_MEM_FAIL;
    }
    memset(lkeys, 0x0, sizeof(sslKeys_t));
    lkeys->pool = pool;
    lkeys->poolUserPtr = memAllocUserPtr;

#if  defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
    rc = psCreateMutex(&lkeys->cache.lock, 0);
    if (rc < 0)
    {
        psFree(lkeys, pool);
        return rc;
    }
#endif
    *keys = lkeys;
    return PS_SUCCESS;
}

#ifdef USE_ECC
/* User is specifying EC curves that are supported so check that against the
    keys they are supporting */
int32 psTestUserEcID(int32 id, int32 ecFlags)
{
    if (id == 19)
    {
        if (!(ecFlags & IS_SECP192R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 21)
    {
        if (!(ecFlags & IS_SECP224R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 23)
    {
        if (!(ecFlags & IS_SECP256R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 24)
    {
        if (!(ecFlags & IS_SECP384R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 25)
    {
        if (!(ecFlags & IS_SECP521R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 255)
    {
        if (!(ecFlags & IS_BRAIN224R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 26)
    {
        if (!(ecFlags & IS_BRAIN256R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 27)
    {
        if (!(ecFlags & IS_BRAIN384R1))
        {
            return PS_FAILURE;
        }
    }
    else if (id == 28)
    {
        if (!(ecFlags & IS_BRAIN512R1))
        {
            return PS_FAILURE;
        }
    }
    else
    {
        return PS_UNSUPPORTED_FAIL;
    }
    return PS_SUCCESS;
}

int32 curveIdToFlag(int32 id)
{
    if (id == 19)
    {
        return IS_SECP192R1;
    }
    else if (id == 21)
    {
        return IS_SECP224R1;
    }
    else if (id == 23)
    {
        return IS_SECP256R1;
    }
    else if (id == 24)
    {
        return IS_SECP384R1;
    }
    else if (id == 25)
    {
        return IS_SECP521R1;
    }
    else if (id == 255)
    {
        return IS_BRAIN224R1;
    }
    else if (id == 26)
    {
        return IS_BRAIN256R1;
    }
    else if (id == 27)
    {
        return IS_BRAIN384R1;
    }
    else if (id == 28)
    {
        return IS_BRAIN512R1;
    }
    return 0;
}

static int32 testUserEc(int32 ecFlags, const sslKeys_t *keys)
{
    const psEccKey_t *eccKey;

# ifdef USE_CERT_PARSE
    psX509Cert_t *cert;
# endif /* USE_CERT_PARSE */

# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (keys->privKey.type == PS_ECC)
    {
        eccKey = &keys->privKey.key.ecc;
        if (psTestUserEcID(eccKey->curve->curveId, ecFlags) < 0)
        {
            return PS_FAILURE;
        }
    }

#  ifdef USE_CERT_PARSE
    cert = keys->cert;
    while (cert)
    {
        if (cert->publicKey.type == PS_ECC)
        {
            eccKey = &cert->publicKey.key.ecc;
            if (psTestUserEcID(eccKey->curve->curveId, ecFlags) < 0)
            {
                return PS_FAILURE;
            }
        }
        cert = cert->next;
    }
#  endif /* USE_CERT_PARSE */
# endif  /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    cert = keys->CAcerts;
    while (cert)
    {
        if (cert->publicKey.type == PS_ECC)
        {
            eccKey = &cert->publicKey.key.ecc;
            if (psTestUserEcID(eccKey->curve->curveId, ecFlags) < 0)
            {
                return PS_FAILURE;
            }
        }
        cert = cert->next;
    }
# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */

    return PS_SUCCESS;
}
#endif /* USE_ECC */


#ifdef MATRIX_USE_FILE_SYSTEM
# ifdef USE_PKCS12

#  ifdef USE_CERT_PARSE
/* Have seen cases where the PKCS#12 files are not in a child-to-parent order */
static void ReorderCertChain(psX509Cert_t *a_cert)
{
    psX509Cert_t *prevCert = NULL;
    psX509Cert_t *nextCert = NULL;
    psX509Cert_t *currCert = a_cert;

    while (currCert)
    {
        nextCert = currCert->next;
        while (nextCert && memcmp(currCert->issuer.hash, nextCert->subject.hash,
                   SHA1_HASH_SIZE) != 0)
        {
            prevCert = nextCert;
            nextCert = nextCert->next;

            if (nextCert && memcmp(currCert->issuer.hash,
                    nextCert->subject.hash, SHA1_HASH_SIZE) == 0)
            {
                prevCert->next = nextCert->next;
                nextCert->next = currCert->next;
                currCert->next = nextCert;
                break;
            }
        }
        currCert = currCert->next;
    }
}
#  endif /* USE_CERT_PARSE */

/******************************************************************************/
/*
    File should be a binary .p12 or .pfx
 */
int32 matrixSslLoadPkcs12(sslKeys_t *keys, const unsigned char *certFile,
    const unsigned char *importPass, int32 ipasslen,
    const unsigned char *macPass, int32 mpasslen, int32 flags)
{
    unsigned char *mPass;
    psPool_t *pool;
    int32 rc;

    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }
    pool = keys->pool;
    PS_POOL_USED(pool);

    if (macPass == NULL)
    {
        mPass = (unsigned char *) importPass;
        mpasslen = ipasslen;
    }
    else
    {
        mPass = (unsigned char *) macPass;
    }

    if ((rc = psPkcs12Parse(pool, &keys->cert, &keys->privKey, certFile, flags,
             (unsigned char *) importPass, ipasslen, mPass, mpasslen)) < 0)
    {
        if (keys->cert)
        {
            psX509FreeCert(keys->cert);
            keys->cert = NULL;
        }
        psClearPubKey(&keys->privKey);
        return rc;
    }
#  ifdef USE_CERT_PARSE
    ReorderCertChain(keys->cert);
#  endif /* USE_CERT_PARSE */
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (verifyReadKeys(pool, keys, keys->poolUserPtr) < PS_SUCCESS)
    {
        psTraceInfo("PKCS#12 parse success but material didn't validate\n");
        psX509FreeCert(keys->cert);
        psClearPubKey(&keys->privKey);
        keys->cert = NULL;
        return PS_CERT_AUTH_FAIL;
    }
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
    return PS_SUCCESS;
}
# endif /* USE_PKCS12 */

/******************************************************************************/

# ifdef USE_RSA
int32 matrixSslLoadRsaKeys(sslKeys_t *keys, const char *certFile,
    const char *privFile, const char *privPass, const char *CAfile)
{
    return matrixSslLoadKeyMaterial(keys, certFile, privFile, privPass, CAfile,
        PS_RSA);

}
# endif /* USE_RSA */

/******************************************************************************/

# ifdef USE_ECC

/******************************************************************************/

int32 matrixSslLoadEcKeys(sslKeys_t *keys, const char *certFile,
    const char *privFile, const char *privPass, const char *CAfile)
{
    return matrixSslLoadKeyMaterial(keys, certFile, privFile, privPass, CAfile,
        PS_ECC);

}
# endif /* USE_ECC */

# if defined(USE_RSA) || defined(USE_ECC)
int32_t matrixSslLoadKeysMem(sslKeys_t *keys,
        const unsigned char *certBuf, int32 certLen,
        const unsigned char *privBuf, int32 privLen,
        const unsigned char *CAbuf, int32 CAlen,
        matrixSslLoadKeysOpts_t *opts)
{
    psPubKey_t tmp_privkey;
    int32_t keytype = 0;

    if (opts)
        keytype = opts->key_type;

    if (privBuf == NULL)
        keytype = 1;

    if (privBuf != NULL && keytype == 0)
    {
        /*
          Caller did not tell us the type of privkey to expect, so try
          to find it out.*/
        memset(&tmp_privkey, 0, sizeof(psPubKey_t));
        keytype = psParseUnknownPrivKeyMem(NULL,
                (unsigned char*)privBuf, privLen,
                NULL, &tmp_privkey);
        if (keytype < 0)
        {
            psTraceInfo("Could not load private key from file\n");
            return keytype;
        }
        psClearPubKey(&tmp_privkey);
    }

    switch (keytype)
    {
    case 1: /* RSA */
        return matrixSslLoadKeyMaterialMem(keys, certBuf, certLen,
                privBuf, privLen, CAbuf, CAlen, PS_RSA);
        break;
    case 2: /* ECC */
        return matrixSslLoadKeyMaterialMem(keys, certBuf, certLen,
                privBuf, privLen, CAbuf, CAlen, PS_ECC);
        break;
    }

    return PS_FAILURE;
}

int32_t matrixSslLoadKeys(sslKeys_t *keys, const char *certFile,
        const char *privFile, const char *privPass, const char *CAfile,
        matrixSslLoadKeysOpts_t *opts)
{
    psPubKey_t tmp_privkey;
    int32_t keytype = 0;

    if (opts)
        keytype = opts->key_type;

    if (privFile == NULL)
        keytype = 1;

    if (keytype == 0)
    {
        /*
          Caller did not tell us the type of privkey to expect, so try
          to find it out.*/
        memset(&tmp_privkey, 0, sizeof(psPubKey_t));
        keytype = psParseUnknownPrivKey(NULL, 1, privFile, privPass,
                &tmp_privkey);
        if (keytype < 0)
        {
            psTraceInfo("Could not load private key from file\n");
            return keytype;
        }
        psClearPubKey(&tmp_privkey);
    }

    switch (keytype)
    {
    case 1: /* RSA */
        return matrixSslLoadKeyMaterial(keys, certFile, privFile, privPass,
                CAfile, PS_RSA);
        break;
    case 2: /* ECC */
        return matrixSslLoadKeyMaterial(keys, certFile, privFile, privPass,
                CAfile, PS_ECC);
        break;
    }

    return PS_FAILURE;
}

static int32 matrixSslLoadKeyMaterial(sslKeys_t *keys, const char *certFile,
    const char *privFile, const char *privPass, const char *CAfile,
    int32 privKeyType)
{
    psPool_t *pool;
    int32 err, flags;

    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }
    pool = keys->pool;

/*
    Setting flags to store raw ASN.1 stream for SSL CERTIFICATE message use
 */
    flags = CERT_STORE_UNPARSED_BUFFER;

#  ifdef USE_CLIENT_AUTH
/*
     If the CERTIFICATE_REQUEST message will possibly be needed we must
     save aside the Distiguished Name portion of the certs for that message.
 */
    flags |= CERT_STORE_DN_BUFFER;
#  endif /* USE_CLIENT_AUTH */

    if (certFile)
    {
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        if (keys->cert != NULL)
        {
            return PS_UNSUPPORTED_FAIL;
        }
        if ((err = psX509ParseCertFile(pool, (char *) certFile,
                 &keys->cert, flags)) < 0)
        {
            return err;
        }
#   ifdef USE_CERT_PARSE
        if (keys->cert->authFailFlags)
        {
            psAssert(keys->cert->authFailFlags == PS_CERT_AUTH_FAIL_DATE_FLAG);
            psTraceStrInfo("Certificate out-of-date: %s\n", (char *)certFile);
#    ifdef POSIX /* TODO - implement date check on WIN32, etc. */
            psX509FreeCert(keys->cert);
            keys->cert = NULL;
            return PS_CERT_AUTH_FAIL_EXTENSION;
#    endif /* POSIX */
        }
#   endif  /* USE_CERT_PARSE */
#  else
        psTraceStrInfo("Ignoring %s certFile in matrixSslReadKeys\n",
            (char *) certFile);
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
    }
/*
    Parse the private key file
 */
    if (privFile)
    {
#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        /* See if private key already exists */
        if (keys->privKey.keysize > 0)
        {
            if (keys->cert)
            {
                psX509FreeCert(keys->cert);
                keys->cert = NULL;
                return PS_UNSUPPORTED_FAIL;
            }
        }
#   ifdef USE_RSA
        if (privKeyType == PS_RSA)
        {
            psInitPubKey(pool, &keys->privKey, PS_RSA);
            if ((err = psPkcs1ParsePrivFile(pool, (char *) privFile,
                     (char *) privPass, &keys->privKey.key.rsa)) < 0)
            {
                if (keys->cert)
                {
                    psX509FreeCert(keys->cert);
                    keys->cert = NULL;
                }
                return err;
            }
            keys->privKey.keysize = psRsaSize(&keys->privKey.key.rsa);
        }
#   endif /* USE_RSA */
#   ifdef USE_ECC
        if (privKeyType == PS_ECC)
        {
            psInitPubKey(pool, &keys->privKey, PS_ECC);
            if ((err = psEccParsePrivFile(pool, (char *) privFile,
                     (char *) privPass, &keys->privKey.key.ecc)) < 0)
            {
                if (keys->cert)
                {
                    psX509FreeCert(keys->cert);
                    keys->cert = NULL;
                }
                return err;
            }
            keys->privKey.keysize = psEccSize(&keys->privKey.key.ecc);
        }
#   endif /* USE_ECC */
#  else
        psTraceStrInfo("Ignoring %s privFile in matrixSslReadKeys\n",
            (char *) privFile);
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
    }

#  if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (verifyReadKeys(pool, keys, keys->poolUserPtr) < PS_SUCCESS)
    {
        psTraceInfo("Cert parse success but material didn't validate\n");
        psX509FreeCert(keys->cert);
        psClearPubKey(&keys->privKey);
        keys->cert = NULL;
        return PS_CERT_AUTH_FAIL;
    }
#  endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

    /* Not necessary to store binary representations of CA certs */
    flags &= ~CERT_STORE_UNPARSED_BUFFER;

    if (CAfile)
    {
#  if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        if (keys->CAcerts != NULL)
        {
            return PS_UNSUPPORTED_FAIL;
        }
#ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
        flags |= CERT_ALLOW_BUNDLE_PARTIAL_PARSE;
#endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
        err = psX509ParseCertFile(pool, (char *) CAfile, &keys->CAcerts, flags);
        if (err >= 0)
        {
#ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
            if (err == 0)
            {
                psTraceInfo("Failed to load any CA certs.\n");
                err = PS_PARSE_FAIL;
                goto ca_load_failed;
            }
            else
            {
                psTraceIntInfo("Loaded %d CA certs\n", err);
            }
#endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
            if (keys->CAcerts->authFailFlags)
            {
                /* This should be the only no err, FailFlags case currently */
                psAssert(keys->CAcerts->authFailFlags ==
                    PS_CERT_AUTH_FAIL_DATE_FLAG);
                psTraceStrInfo("Certificate out-of-date: %s\n", (char *)CAfile);
#   ifdef POSIX /* TODO - implement date check on WIN32, etc. */
                psX509FreeCert(keys->CAcerts);
                keys->CAcerts = NULL;
                err = PS_CERT_AUTH_FAIL_EXTENSION;
#   endif
            }
        }

#ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
ca_load_failed:
#endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */

        if (err < 0)
        {
#   if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
            if (keys->cert)
            {
                psX509FreeCert(keys->cert);
                keys->cert = NULL;
            }
            psClearPubKey(&keys->privKey);
#   endif   /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
            return err;
        }
#  else
        psTraceStrInfo("Ignoring %s CAfile in matrixSslReadKeys\n", (char *) CAfile);
#  endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
    }

    return PS_SUCCESS;
}

# endif /* USE_RSA || USE_ECC */
#endif  /* MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/
/*
    Memory buffer versions of ReadKeys

    This function supports cert chains and multiple CAs.  Just need to
    string them together and let psX509ParseCert handle it
 */
#ifdef USE_RSA
int32 matrixSslLoadRsaKeysMem(sslKeys_t *keys, const unsigned char *certBuf,
    int32 certLen, const unsigned char *privBuf, int32 privLen,
    const unsigned char *CAbuf, int32 CAlen)
{
    return matrixSslLoadKeyMaterialMem(keys, certBuf, certLen, privBuf, privLen,
        CAbuf, CAlen, PS_RSA);

}
#endif /* USE_RSA */

#ifdef USE_ECC
int32 matrixSslLoadEcKeysMem(sslKeys_t *keys, const unsigned char *certBuf,
    int32 certLen, const unsigned char *privBuf, int32 privLen,
    const unsigned char *CAbuf, int32 CAlen)
{
    return matrixSslLoadKeyMaterialMem(keys, certBuf, certLen, privBuf, privLen,
        CAbuf, CAlen, PS_ECC);

}
/**
    Generate and cache an ephemeral ECC key for later use in ECDHE key exchange.
    @param[out] keys Keys structure to hold ephemeral keys
    @param[in] curve ECC curve to generate key on, or NULL to generate for all
        supported curves.
    @param[in] hwCtx Context for hardware crypto.
 */
int32_t matrixSslGenEphemeralEcKey(sslKeys_t *keys, psEccKey_t *ecc,
    const psEccCurve_t *curve, void *hwCtx)
{
# if ECC_EPHEMERAL_CACHE_USAGE > 0
    psTime_t t;
# endif
    int32_t rc;

    psAssert(keys && curve);
# if ECC_EPHEMERAL_CACHE_USAGE > 0
    psGetTime(&t, keys->poolUserPtr);
    psLockMutex(&keys->cache.lock);
    if (keys->cache.eccPrivKey.curve != curve)
    {
        psTraceStrInfo("Generating ephemeral %s key (new curve)\n",
            curve->name);
        goto L_REGEN;
    }
    if (keys->cache.eccPrivKeyUse > ECC_EPHEMERAL_CACHE_USAGE)
    {
        psTraceStrInfo("Generating ephemeral %s key (usage exceeded)\n",
            curve->name);
        goto L_REGEN;
    }
    if (psDiffMsecs(keys->cache.eccPrivKeyTime, t, keys->poolUserPtr) >
        (1000 * ECC_EPHEMERAL_CACHE_SECONDS))
    {
        psTraceStrInfo("Generating ephemeral %s key (time exceeded)\n",
            curve->name);
        goto L_REGEN;
    }
    keys->cache.eccPrivKeyUse++;
    rc = PS_SUCCESS;
    if (ecc)
    {
        rc = psEccCopyKey(ecc, &keys->cache.eccPrivKey);
    }
    psUnlockMutex(&keys->cache.lock);
    return rc;
L_REGEN:
    if (keys->cache.eccPrivKeyUse)
    {
        /* We use eccPrivKeyUse == 0 as a flag to note the key not allocated */
        psEccClearKey(&keys->cache.eccPrivKey);
        keys->cache.eccPrivKeyUse = 0;
    }
    rc = psEccGenKey(keys->pool, &keys->cache.eccPrivKey, curve, hwCtx);
    if (rc < 0)
    {
        psUnlockMutex(&keys->cache.lock);
        return rc;
    }
    keys->cache.eccPrivKeyTime = t;
    keys->cache.eccPrivKeyUse = 1;
    rc = PS_SUCCESS;
    if (ecc)
    {
        rc = psEccCopyKey(ecc, &keys->cache.eccPrivKey);
    }
    psUnlockMutex(&keys->cache.lock);
    return rc;
# else
    /* Not using ephemeral caching. */
    if (ecc)
    {
        rc = psEccGenKey(keys->pool, ecc, curve, hwCtx);
        return rc;
    }
    rc = PS_SUCCESS;
    return rc;
# endif /* ECC_EPHEMERAL_CACHE_USAGE > 0 */
}

#endif  /* USE_ECC */

#if defined(USE_RSA) || defined(USE_ECC)
static int32 matrixSslLoadKeyMaterialMem(sslKeys_t *keys,
    const unsigned char *certBuf, int32 certLen,
    const unsigned char *privBuf,
    int32 privLen, const unsigned char *CAbuf, int32 CAlen,
    int32 privKeyType)
{
    psPool_t *pool;
    int32 err, flags = 0;

    if (certBuf == NULL && privBuf == NULL && CAbuf == NULL)
    {
        return PS_ARG_FAIL;
    }

    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }
    pool = keys->pool;

/*
    Setting flags to store raw ASN.1 stream for SSL CERTIFICATE message use
 */
    flags = CERT_STORE_UNPARSED_BUFFER;

# ifdef USE_CLIENT_AUTH
/*
    Setting flag to store raw ASN.1 DN stream for CERTIFICATE_REQUEST
 */
    flags |= CERT_STORE_DN_BUFFER;
# endif /* USE_CLIENT_AUTH */

    if (certBuf)
    {
# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        if (keys->cert != NULL)
        {
            psTraceInfo("WARNING: An identity certificate already exists\n");
            return PS_UNSUPPORTED_FAIL;
        }
        if ((err = psX509ParseCert(pool, (unsigned char *) certBuf,
                 (uint32) certLen, &keys->cert, flags)) < 0)
        {
            psX509FreeCert(keys->cert);
            keys->cert = NULL;
            return err;
        }
# else
        psTraceInfo("Ignoring certBuf in matrixSslReadKeysMem\n");
# endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
    }

    if (privBuf)
    {
# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
#  ifdef USE_RSA
        if (privKeyType == PS_RSA)
        {
            psInitPubKey(pool, &keys->privKey, PS_RSA);
            if ((err = psRsaParsePkcs1PrivKey(pool, privBuf,
                     privLen, &keys->privKey.key.rsa)) < 0)
            {
#   ifdef USE_PKCS8
                /* Attempt a PKCS#8 but mem parse doesn't take password */
                if ((err = psPkcs8ParsePrivBin(pool, (unsigned char *) privBuf,
                         (uint32) privLen, NULL, &keys->privKey)) < 0)
                {
                    psX509FreeCert(keys->cert); keys->cert = NULL;
                    return err;
                }
#   else
                psX509FreeCert(keys->cert); keys->cert = NULL;
                return err;
#   endif
            }
            keys->privKey.keysize = psRsaSize(&keys->privKey.key.rsa);
        }
#  endif /* USE_RSA */
#  ifdef USE_ECC
        if (privKeyType == PS_ECC)
        {
            psInitPubKey(pool, &keys->privKey, PS_ECC);
            if ((err = psEccParsePrivKey(pool, (unsigned char *) privBuf,
                     (uint32) privLen, &keys->privKey.key.ecc, NULL)) < 0)
            {
#   ifdef USE_PKCS8
                /* Attempt a PKCS#8 but mem parse doesn't take password */
                if ((err = psPkcs8ParsePrivBin(pool, (unsigned char *) privBuf,
                         (uint32) privLen, NULL, &keys->privKey)) < 0)
                {
                    psX509FreeCert(keys->cert); keys->cert = NULL;
                    return err;
                }
#   else
                psX509FreeCert(keys->cert); keys->cert = NULL;
                return err;
#   endif
            }
            keys->privKey.keysize = psEccSize(&keys->privKey.key.ecc);
        }
#  endif /* USE_ECC */
# else
        psTraceInfo("Ignoring privBuf in matrixSslReadKeysMem\n");
# endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
    }

# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (verifyReadKeys(pool, keys, keys->poolUserPtr) < PS_SUCCESS)
    {
        psX509FreeCert(keys->cert);
        psClearPubKey(&keys->privKey);
        keys->cert = NULL;
        return PS_CERT_AUTH_FAIL;
    }
# endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

/*
     Not necessary to store binary representations of CA certs
 */
    flags &= ~CERT_STORE_UNPARSED_BUFFER;

    if (CAbuf)
    {
# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        if (keys->CAcerts != NULL)
        {
            return PS_UNSUPPORTED_FAIL;
        }
#ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
        flags |= CERT_ALLOW_BUNDLE_PARTIAL_PARSE;
#endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
        err = psX509ParseCert(pool, (unsigned char *) CAbuf, (uint32) CAlen,
            &keys->CAcerts, flags);
        if (err < 0)
        {
#ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
            if (err == 0)
            {
                psTraceInfo("Failed to load any CA certs.\n");
                err = PS_PARSE_FAIL;
                goto ca_load_failed;
            }
            else
            {
                psTraceIntInfo("Loaded %d CA certs\n", err);
            }
#endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
        }
# else
        psTraceInfo("Ignoring CAbuf in matrixSslReadKeysMem\n");
# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
    }

#ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
ca_load_failed:
#endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */

    if (err < 0)
    {
#   if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        psClearPubKey(&keys->privKey);
        psX509FreeCert(keys->cert);
        keys->cert = NULL;
#   endif
#   if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        psX509FreeCert(keys->CAcerts);
        keys->CAcerts = NULL;
#   endif
        return err;
    }

    return PS_SUCCESS;
}
#endif /* USE_RSA || USE_ECC */


#if defined(USE_OCSP_RESPONSE) && defined(USE_SERVER_SIDE_SSL)
int32_t matrixSslLoadOCSPResponse(sslKeys_t *keys,
    const unsigned char *OCSPResponseBuf, psSize_t OCSPResponseBufLen)
{
    psPool_t *pool;

    if (keys == NULL || OCSPResponseBuf == NULL || OCSPResponseBufLen == 0)
    {
        return PS_ARG_FAIL;
    }
    pool = keys->pool;
    PS_POOL_USED(pool);

    /* Overwrite/Update any response being set */
    if (keys->OCSPResponseBuf != NULL)
    {
        psFree(keys->OCSPResponseBuf, pool);
        keys->OCSPResponseBufLen = 0;
    }

    keys->OCSPResponseBufLen = OCSPResponseBufLen;
    if ((keys->OCSPResponseBuf = psMalloc(pool, OCSPResponseBufLen)) == NULL)
    {
        return PS_MEM_FAIL;
    }

    memcpy(keys->OCSPResponseBuf, OCSPResponseBuf, OCSPResponseBufLen);
    return PS_SUCCESS;
}
#endif /* USE_OCSP_RESPONSE && USE_SERVER_SIDE_SSL */


#if defined(USE_SCT) && defined(USE_SERVER_SIDE_SSL)
int32_t matrixSslLoadSCTResponse(sslKeys_t *keys,
			const unsigned char *SCTResponseBuf, uint16_t SCTResponseBufLen)
{
	psPool_t	*pool;

	if (keys == NULL || SCTResponseBuf == NULL || SCTResponseBufLen == 0) {
		return PS_ARG_FAIL;
	}
	pool = keys->pool;

	/* Overwrite/Update any response being set */
	if (keys->SCTResponseBuf != NULL) {
		psFree(keys->SCTResponseBuf, pool);
		keys->SCTResponseBufLen = 0;
	}

	keys->SCTResponseBufLen = SCTResponseBufLen;
	if ((keys->SCTResponseBuf = psMalloc(pool, SCTResponseBufLen)) == NULL) {
		return PS_MEM_FAIL;
	}

	memcpy(keys->SCTResponseBuf, SCTResponseBuf, SCTResponseBufLen);
	return PS_SUCCESS;
}
#endif /* USE_OCSP && USE_SERVER_SIDE_SSL */


/******************************************************************************/
/*
    This will free the struct and any key material that was loaded via:
        matrixSslLoadRsaKeys
        matrixSslLoadEcKeys
        matrixSslLoadDhParams
        matrixSslLoadPsk
        matrixSslLoadOCSPResponse
 */
void matrixSslDeleteKeys(sslKeys_t *keys)
{
#ifdef USE_PSK_CIPHER_SUITE
    psPsk_t *psk, *next;
#endif /* USE_PSK_CIPHER_SUITE */
#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
    psSessionTicketKeys_t *tick, *nextTick;
#endif

    if (keys == NULL)
    {
        return;
    }
#ifndef USE_ONLY_PSK_CIPHER_SUITE
# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (keys->cert)
    {
        psX509FreeCert(keys->cert);
    }

    psClearPubKey(&keys->privKey);
# endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (keys->CAcerts)
    {
        psX509FreeCert(keys->CAcerts);
    }
# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef REQUIRE_DH_PARAMS
    psPkcs3ClearDhParams(&keys->dhParams);
#endif /* REQUIRE_DH_PARAMS */

#ifdef USE_PSK_CIPHER_SUITE
    if (keys->pskKeys)
    {
        psk = keys->pskKeys;
        while (psk)
        {
            psFree(psk->pskKey, keys->pool);
            psFree(psk->pskId, keys->pool);
            next = psk->next;
            psFree(psk, keys->pool);
            psk = next;
        }
    }
#endif /* USE_PSK_CIPHER_SUITE */

#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
    if (keys->sessTickets)
    {
        tick = keys->sessTickets;
        while (tick)
        {
            nextTick = tick->next;
            psFree(tick, keys->pool);
            tick = nextTick;
        }
    }
#endif

#if defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
    psDestroyMutex(&keys->cache.lock);
# ifdef USE_ECC
    if (keys->cache.eccPrivKeyUse > 0)
    {
        psEccClearKey(&keys->cache.eccPrivKey);
        psEccClearKey(&keys->cache.eccPubKey);
    }
# endif
    /* Remainder of structure is cleared below */
#endif

#if defined(USE_OCSP_RESPONSE) && defined(USE_SERVER_SIDE_SSL)
    if (keys->OCSPResponseBuf != NULL)
    {
        psFree(keys->OCSPResponseBuf, keys->pool);
        keys->OCSPResponseBufLen = 0;
    }
#endif

    memzero_s(keys, sizeof(sslKeys_t));
    psFree(keys, NULL);
}

#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
# if defined(USE_RSA) || defined(USE_ECC)
/*
    Validate the cert chain and the private key for the material passed
    to matrixSslReadKeys.  Good to catch any user certifiate errors as
    soon as possible

    When the client private key is stored externally, skip all tests
    involving the private key, since MatrixSSL does not have direct
    access to the key.
 */
static int32 verifyReadKeys(psPool_t *pool, sslKeys_t *keys, void *poolUserPtr)
{
#  ifdef USE_CERT_PARSE
    psX509Cert_t *tmp, *found;
#  endif

    if (keys->cert == NULL && keys->privKey.type == 0)
    {
        return PS_SUCCESS;
    }

#  ifndef USE_EXT_CERTIFICATE_VERIFY_SIGNING
/*
     Not allowed to have a certificate with no matching private key or
     private key with no cert to match with
 */
    if (keys->cert != NULL && keys->privKey.type == 0)
    {
        psTraceInfo("No private key given to matrixSslReadKeys cert\n");
        return PS_CERT_AUTH_FAIL;
    }
    if (keys->privKey.type != 0 && keys->cert == NULL)
    {
        psTraceInfo("No cert given with private key to matrixSslReadKeys\n");
        return PS_CERT_AUTH_FAIL;
    }
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

#  ifdef USE_CERT_PARSE
/*
    If this is a chain, we can validate it here with psX509AuthenticateCert
    Don't check the error return code from this call because the chaining
    usage restrictions will test parent-most cert for self-signed.

    But we can look at 'authStatus' on all but the final cert to see
    if the rest looks good
 */
    if (keys->cert != NULL && keys->cert->next != NULL)
    {
        found = NULL;
        psX509AuthenticateCert(pool, keys->cert, NULL, &found, NULL,
            poolUserPtr);
        tmp = keys->cert;
        while (tmp->next != NULL)
        {
            if (tmp->authStatus != PS_TRUE)
            {
                psTraceInfo("Failed to authenticate cert chain\n");
                return PS_CERT_AUTH_FAIL;
            }
            tmp = tmp->next;
        }
    }

#   ifndef USE_EXT_CERTIFICATE_VERIFY_SIGNING
#    ifdef USE_RSA
    if (keys->privKey.type == PS_RSA)
    {
        if (psRsaCmpPubKey(&keys->privKey.key.rsa,
                &keys->cert->publicKey.key.rsa) < 0)
        {
            psTraceInfo("Private key doesn't match cert\n");
            return PS_CERT_AUTH_FAIL;
        }
    }
#    endif /* USE_RSA */
#   endif  /* !USE_EXT_CERTIFICATE_VERIFY_SIGNING */
#  endif   /* USE_CERT_PARSE */
    return PS_SUCCESS;
}
# endif /* USE_RSA || USE_ECC */
#endif  /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
/******************************************************************************/

#ifdef REQUIRE_DH_PARAMS
/******************************************************************************/
/*
    User level API to assign the DH parameter file to the server application.
 */
# ifdef MATRIX_USE_FILE_SYSTEM
int32 matrixSslLoadDhParams(sslKeys_t *keys, const char *paramFile)
{
    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }
    return psPkcs3ParseDhParamFile(keys->pool, (char *) paramFile, &keys->dhParams);
}
# endif /* MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/
int32 matrixSslLoadDhParamsMem(sslKeys_t *keys,  const unsigned char *dhBin,
    int32 dhBinLen)
{
    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }
    return psPkcs3ParseDhParamBin(keys->pool, (unsigned char *) dhBin, dhBinLen,
        &keys->dhParams);
}
#endif /* REQUIRE_DH_PARAMS */

psBool_t matrixSslTlsVersionRangeSupported(int32_t low,
        int32_t high)
{
    if (low < MIN_ENABLED_TLS_VER)
    {
        psTraceIntInfo("Minimum of version range not supported " \
                "by config: %d\n", low);
        return PS_FALSE;
    }
    if (high > MAX_ENABLED_TLS_VER)
    {
        psTraceIntInfo("Maximum of version range not supported " \
                "by config: %d\n", high);
        return PS_FALSE;
    }
    if (low > high)
    {
        psTraceInfo("Invalid version range: low > high\n");
        return PS_FALSE;
    }

    return PS_TRUE;
}

#ifdef USE_CLIENT_SIDE_SSL
static
int32 tlsVerToVersionFlag(int32_t ver)
{
    switch (ver)
    {
    case tls_v_1_2:
        return SSL_FLAGS_TLS_1_2;
    case tls_v_1_1:
        return SSL_FLAGS_TLS_1_1;
    case tls_v_1_0:
        return SSL_FLAGS_TLS_1_0;
    }

    return 0;
}

int32_t matrixSslSessOptsSetClientTlsVersionRange(sslSessOpts_t *options,
        int32_t low, int32_t high)
{
    if (options == NULL)
    {
        return PS_ARG_FAIL;
    }
    if (!matrixSslTlsVersionRangeSupported(low, high))
    {
        psTraceInfo("Please enable more versions in matrixsslConfig.h.\n");
        return PS_ARG_FAIL;
    }
    if (low < tls_v_1_0)
    {
        psTraceInfo("matrixSslSessOptsSetClientTlsVersionRange only " \
                "supports TLS 1.0 to TLS 1.2. SSL 3.0 is not supported\n");
        return PS_ARG_FAIL;
    }

    if (low == high)
    {
        /* Single version. */
        options->clientRejectVersionDowngrade = 1;
    }
    else
    {
        if (low > tls_v_1_0)
        {
            /* Range: TLS 1.1 - TLS 1.2. */
#        ifdef USE_TLS_1_0_TOGGLE
            options->disableTls1_0 = PS_TRUE;
#        else
            psTraceInfo("Need USE_TLS_1_0_TOGGLE for this version range\n");
            return PS_UNSUPPORTED_FAIL;
#        endif /* USE_TLS_1_0_TOGGLE */
        }
    }

    /* Always put the highest version we support to ClientHello.client_version,
       as recommended by the RFC. */
    options->versionFlag = tlsVerToVersionFlag(high);

    return PS_SUCCESS;
}
#endif /* USE_CLIENT_SIDE_SSL */

#ifdef USE_SERVER_SIDE_SSL
int32_t matrixSslSessOptsSetServerTlsVersionRange(sslSessOpts_t *options,
        int32_t low, int32_t high)
{
    if (options == NULL)
    {
        return PS_ARG_FAIL;
    }
    if (!matrixSslTlsVersionRangeSupported(low, high))
    {
        psTraceInfo("Please enable more versions in matrixsslConfig.h.\n");
        return PS_ARG_FAIL;
    }
    if (low < tls_v_1_0)
    {
        psTraceInfo("matrixSslSessOptsSetServerTlsVersionRange only " \
                "supports TLS 1.0 to TLS 1.2. SSL 3.0 is not supported\n");
        return PS_ARG_FAIL;
    }

    if (low == high)
    {
        /* Single version. */
        if (low == tls_v_1_2)
        {
            options->versionFlag = SSL_FLAGS_TLS_1_2;
        }
        else if (low == tls_v_1_1)
        {
            options->versionFlag = SSL_FLAGS_TLS_1_1;
        }
        else if (low == tls_v_1_0)
        {
            options->versionFlag = SSL_FLAGS_TLS_1_0;
        }
        else
        {
            return PS_ARG_FAIL;
        }
    }
    else
    {
        /* Version range. */
        options->versionFlag = 0;
        if (low > tls_v_1_0)
        {
#        ifdef USE_TLS_1_0_TOGGLE
            options->disableTls1_0 = PS_TRUE;
#        else
            psTraceInfo("Need USE_TLS_1_0_TOGGLE for this version range\n");
            return PS_UNSUPPORTED_FAIL;
#        endif /* USE_TLS_1_0_TOGGLE */
        }
        if (high < tls_v_1_2)
        {
#        ifdef USE_TLS_1_2_TOGGLE
            options->serverDisableTls1_2 = PS_TRUE;
#        else
            psTraceInfo("Need USE_TLS_1_2_TOGGLE for this version range\n");
            return PS_UNSUPPORTED_FAIL;
#        endif /* USE_TLS_1_2_TOGGLE */
        }
    }

    return PS_SUCCESS;
}
#endif /* USE_SERVER_SIDE_SSL */

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
    int32_t specificVersion, flags;

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
        psTraceInfo("SSL_FLAGS_SERVER passed to matrixSslNewSession but MatrixSSL lib was not compiled with server support\n");
        return PS_ARG_FAIL;
    }
#endif

#ifndef USE_CLIENT_SIDE_SSL
    if (!(flags & SSL_FLAGS_SERVER))
    {
        psTraceInfo("SSL_FLAGS_SERVER was not passed to matrixSslNewSession but MatrixSSL was not compiled with client support\n");
        return PS_ARG_FAIL;
    }
#endif

#ifndef USE_CLIENT_AUTH
    if (flags & SSL_FLAGS_CLIENT_AUTH)
    {
        psTraceInfo("SSL_FLAGS_CLIENT_AUTH passed to matrixSslNewSession but MatrixSSL was not compiled with USE_CLIENT_AUTH enabled\n");
        return PS_ARG_FAIL;
    }
#endif

    if (flags & SSL_FLAGS_SERVER)
    {
# ifndef USE_PSK_CIPHER_SUITE
        if (keys == NULL)
        {
            psTraceInfo("NULL keys parameter passed to matrixSslNewSession\n");
            return PS_ARG_FAIL;
        }
# endif /* USE_PSK_CIPHER_SUITE */
        if (session != NULL)
        {
            psTraceInfo("Ignoring session parameter to matrixSslNewSession\n");
        }
    }

    if (flags & SSL_FLAGS_INTERCEPTOR)
    {
        psTraceInfo("SSL_FLAGS_INTERCEPTOR not supported\n");
        return PS_ARG_FAIL;
    }

    lssl = psMalloc(pool, sizeof(ssl_t));
    if (lssl == NULL)
    {
        psTraceInfo("Out of memory for ssl_t in matrixSslNewSession\n");
        return PS_MEM_FAIL;
    }
    memset(lssl, 0x0, sizeof(ssl_t));
    lssl->memAllocPtr = options->memAllocPtr;

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
        lssl->userDataPtr = options->userDataPtr;

#ifdef USE_ECC
    /* If user specified EC curves they support, let's check that against
        the key material they provided so there are no conflicts.  Don't
        need to test against default compiled-in curves because the keys
        would not have loaded at all */
    if (options->ecFlags)
    {
        if (testUserEc(options->ecFlags, keys) < 0)
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
        psTraceInfo("Buffer pool is too small\n");
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
        psTraceInfo("Buffer pool is too small\n");
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
            psTraceInfo("Error: External CertificateVerify signing ");
            psTraceInfo("not supported with the DTLS protocol\n");
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

        /* Is caller requesting specific protocol version for this client?
            Make sure it's enabled and use specificVersion var for err */
        specificVersion = 0;
        if (flags & SSL_FLAGS_SSLV3)
        {
#ifndef DISABLE_SSLV3
            lssl->majVer = SSL3_MAJ_VER;
            lssl->minVer = SSL3_MIN_VER;
#else
            specificVersion = 1;
#endif
        }

        if (flags & SSL_FLAGS_TLS_1_0)
        {
#ifdef USE_TLS
# ifndef DISABLE_TLS_1_0
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_MIN_VER;
# else
            specificVersion = 1; /* TLS enabled but TLS_1_0 disabled */
# endif
#else
            specificVersion = 1; /* TLS not even enabled */
#endif
        }

        if (flags & SSL_FLAGS_TLS_1_1)
        {
#ifdef USE_TLS_1_1
# ifndef DISABLE_TLS_1_1
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_1_1_MIN_VER;
# else
            specificVersion = 1; /* TLS_1_1 enabled but TLS_1_1 disabled */
# endif
#else
            specificVersion = 1; /* TLS not even enabled */
#endif
        }

        if (flags & SSL_FLAGS_TLS_1_2)
        {
#ifdef USE_TLS_1_2
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_1_2_MIN_VER;
#else
            specificVersion = 1; /* TLS_1_2 disabled */
#endif
        }

        if (specificVersion)
        {
            psTraceInfo("ERROR: protocol version isn't compiled into matrix\n");
            matrixSslDeleteSession(lssl);
            return PS_ARG_FAIL;
        }

#ifdef USE_DTLS
        /* FLAGS_DTLS used in conjuction with specific 1.1 or 1.2 protocol */
        if (flags & SSL_FLAGS_DTLS)
        {
            if (lssl->majVer)
            {
                if (lssl->minVer == SSL3_MIN_VER || lssl->minVer == TLS_MIN_VER)
                {
                    psTraceInfo("ERROR: Can't use SSLv3 or TLS1.0 with DTLS\n");
                    matrixSslDeleteSession(lssl);
                    return PS_ARG_FAIL;
                }
                lssl->majVer = DTLS_MAJ_VER;
                if (lssl->minVer == TLS_1_2_MIN_VER)
                {
                    lssl->minVer = DTLS_1_2_MIN_VER;
                }
                else if (lssl->minVer == TLS_1_1_MIN_VER)
                {
                    lssl->minVer = DTLS_MIN_VER;
                }
                else
                {
                    psTraceInfo("ERROR: Protocol version parse error\n");
                    matrixSslDeleteSession(lssl);
                    return PS_ARG_FAIL;
                }
            }
        }
#endif

    }
    else
    {
/*
        Client is first to set protocol version information based on
        compile and/or the 'flags' parameter so header information in
        the handshake messages will be correctly set.

        Look for specific version first... but still have to make sure library
        has been compiled to support it
 */
        specificVersion = 0;

        if (flags & SSL_FLAGS_SSLV3)
        {
#ifndef DISABLE_SSLV3
            lssl->majVer = SSL3_MAJ_VER;
            lssl->minVer = SSL3_MIN_VER;
            specificVersion = 1;
#else
            specificVersion = 2;
#endif
        }

        if (flags & SSL_FLAGS_TLS_1_0)
        {
#ifdef USE_TLS
# ifndef DISABLE_TLS_1_0
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_MIN_VER;
            lssl->flags |= SSL_FLAGS_TLS;
            specificVersion = 1;
# else
            specificVersion = 2; /* TLS enabled but TLS_1_0 disabled */
# endif
#else
            specificVersion = 2; /* TLS not even enabled */
#endif
        }

        if (flags & SSL_FLAGS_TLS_1_1)
        {
#ifdef USE_TLS_1_1
# ifndef DISABLE_TLS_1_1
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_1_1_MIN_VER;
            lssl->flags |= SSL_FLAGS_TLS | SSL_FLAGS_TLS_1_1;
            specificVersion = 1;
# else
            specificVersion = 2; /* TLS_1_1 enabled but TLS_1_1 disabled */
# endif
#else
            specificVersion = 2; /* TLS not even enabled */
#endif
        }

        if (flags & SSL_FLAGS_TLS_1_2)
        {
#ifdef USE_TLS_1_2
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_1_2_MIN_VER;
            lssl->flags |= SSL_FLAGS_TLS | SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS_1_2;
            specificVersion = 1;
#else
            specificVersion = 2; /* TLS_1_2 disabled */
#endif
        }

        if (specificVersion == 2)
        {
            psTraceInfo("ERROR: protocol version isn't compiled into matrix\n");
            matrixSslDeleteSession(lssl);
            return PS_ARG_FAIL;
        }

        if (specificVersion == 0)
        {
            /* Highest available if not specified (or not legal value) */
#ifdef USE_TLS
# ifndef DISABLE_TLS_1_0
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_MIN_VER;
# endif
# if defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_1_1_MIN_VER;
            lssl->flags |= SSL_FLAGS_TLS_1_1;
# endif     /* USE_TLS_1_1 */
# ifdef USE_TLS_1_2
            lssl->majVer = TLS_MAJ_VER;
            lssl->minVer = TLS_1_2_MIN_VER;
            lssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1;
# endif
            if (lssl->majVer == 0)
            {
                /* USE_TLS enabled but all DISABLE_TLS versions are enabled so
                    use SSLv3.  Compile time tests would catch if no versions
                    are enabled at all */
                lssl->majVer = SSL3_MAJ_VER;
                lssl->minVer = SSL3_MIN_VER;
            }
            else
            {
                lssl->flags |= SSL_FLAGS_TLS;
            }

# ifdef USE_DTLS
            /* ssl->flags will have already been set above.  Just set version */
            if (flags & SSL_FLAGS_DTLS)
            {
                lssl->minVer = DTLS_MIN_VER;
                lssl->majVer = DTLS_MAJ_VER;
#  ifdef USE_TLS_1_2
                lssl->minVer = DTLS_1_2_MIN_VER;
#  endif
            }
# endif     /* USE_DTLS */

#else /* USE_TLS */
            lssl->majVer = SSL3_MAJ_VER;
            lssl->minVer = SSL3_MIN_VER;
#endif      /* USE_TLS */
        } /* end non-specific version */

#ifdef USE_DTLS
        if (flags & SSL_FLAGS_DTLS && specificVersion == 1)
        {
            lssl->majVer = DTLS_MAJ_VER;
            if (lssl->minVer == TLS_1_2_MIN_VER)
            {
                lssl->minVer = DTLS_1_2_MIN_VER;
            }
            else if (lssl->minVer == TLS_1_1_MIN_VER)
            {
                lssl->minVer = DTLS_MIN_VER;
            }
            else
            {
                psTraceInfo("ERROR: DTLS must be TLS 1.1 or TLS 1.2\n");
                matrixSslDeleteSession(lssl);
                return PS_ARG_FAIL;
            }
        }
#endif

        lssl->hsState = SSL_HS_SERVER_HELLO;
        if (session != NULL && session->cipherId != SSL_NULL_WITH_NULL_NULL)
        {
            lssl->cipher = sslGetCipherSpec(lssl, session->cipherId);
            if (lssl->cipher == NULL)
            {
                psTraceInfo("Invalid session id to matrixSslNewSession\n");
            }
            else
            {
                memcpy(lssl->sec.masterSecret, session->masterSecret,
                    SSL_HS_MASTER_SIZE);
                lssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;
                memcpy(lssl->sessionId, session->id, SSL_MAX_SESSION_ID_SIZE);
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
    /* Clear these to minimize damage on a protocol parsing bug */
    memset(lssl->inbuf, 0x0, lssl->insize);
    memset(lssl->outbuf, 0x0, lssl->outsize);
    lssl->err = SSL_ALERT_NONE;
    lssl->encState = SSL_HS_NONE;
    lssl->decState = SSL_HS_NONE;
    *ssl = lssl;
    return PS_SUCCESS;
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
#ifndef USE_ONLY_PSK_CIPHER_SUITE
# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    if (ssl->sec.cert)
    {
        psX509FreeCert(ssl->sec.cert);
        ssl->sec.cert = NULL;
    }

# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

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
    memset(ssl->inbuf, 0x0, ssl->insize);
    memset(ssl->outbuf, 0x0, ssl->outsize);
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
    memset(ssl, 0x0, sizeof(ssl_t));
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
        memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
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


#ifdef USE_SSL_INFORMATIONAL_TRACE
void matrixSslPrintHSDetails(ssl_t *ssl)
{
    if (ssl->hsState == SSL_HS_DONE)
    {
        psTraceInfo("\n");
        psTracePrintProtocolVersion(NULL, ssl->majVer, ssl->minVer, 0);
        _psTrace(" connection established: ");
        switch (ssl->cipher->ident)
        {
        case SSL_RSA_WITH_NULL_MD5:
            _psTrace("SSL_RSA_WITH_NULL_MD5\n");
            break;
        case SSL_RSA_WITH_NULL_SHA:
            _psTrace("SSL_RSA_WITH_NULL_SHA\n");
            break;
        case SSL_RSA_WITH_RC4_128_MD5:
            _psTrace("SSL_RSA_WITH_RC4_128_MD5\n");
            break;
        case SSL_RSA_WITH_RC4_128_SHA:
            _psTrace("SSL_RSA_WITH_RC4_128_SHA\n");
            break;
        case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
            _psTrace("SSL_RSA_WITH_3DES_EDE_CBC_SHA\n");
            break;
        case TLS_RSA_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_RSA_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_RSA_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_RSA_WITH_AES_256_CBC_SHA\n");
            break;
        case SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            _psTrace("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA\n");
            break;
        case SSL_DH_anon_WITH_RC4_128_MD5:
            _psTrace("SSL_DH_anon_WITH_RC4_128_MD5\n");
            break;
        case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
            _psTrace("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA\n");
            break;
        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_DHE_RSA_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_DHE_RSA_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
            _psTrace("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256\n");
            break;
        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
            _psTrace("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256\n");
            break;
        case TLS_DH_anon_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_DH_anon_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_DH_anon_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_DH_anon_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
            _psTrace("TLS_RSA_WITH_AES_128_CBC_SHA256\n");
            break;
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
            _psTrace("TLS_RSA_WITH_AES_256_CBC_SHA256\n");
            break;
        case TLS_RSA_WITH_SEED_CBC_SHA:
            _psTrace("TLS_RSA_WITH_SEED_CBC_SHA\n");
            break;
        case TLS_RSA_WITH_IDEA_CBC_SHA:
            _psTrace("TLS_RSA_WITH_IDEA_CBC_SHA\n");
            break;
        case TLS_PSK_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_PSK_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_PSK_WITH_AES_128_CBC_SHA256:
            _psTrace("TLS_PSK_WITH_AES_128_CBC_SHA256\n");
            break;
        case TLS_PSK_WITH_AES_256_CBC_SHA384:
            _psTrace("TLS_PSK_WITH_AES_256_CBC_SHA384\n");
            break;
        case TLS_PSK_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_PSK_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_DHE_PSK_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_DHE_PSK_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
            _psTrace("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA\n");
            break;
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            _psTrace("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256\n");
            break;
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            _psTrace("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384\n");
            break;
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            _psTrace("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n");
            break;
        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            _psTrace("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n");
            break;
        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
            _psTrace("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA\n");
            break;
        case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
            _psTrace("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256\n");
            break;
        case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
            _psTrace("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384\n");
            break;
        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
            _psTrace("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256\n");
            break;
        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
            _psTrace("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384\n");
            break;
        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
            _psTrace("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA\n");
            break;
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
            _psTrace("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256\n");
            break;
        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
            _psTrace("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384\n");
            break;
        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
            _psTrace("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256\n");
            break;
        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
            _psTrace("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384\n");
            break;
        case TLS_RSA_WITH_AES_128_GCM_SHA256:
            _psTrace("TLS_RSA_WITH_AES_128_GCM_SHA256\n");
            break;
        case TLS_RSA_WITH_AES_256_GCM_SHA384:
            _psTrace("TLS_RSA_WITH_AES_256_GCM_SHA384\n");
            break;
        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            _psTrace("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\n");
            break;
        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            _psTrace("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n");
            break;
        case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
            _psTrace("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256\n");
            break;
        case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
            _psTrace("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384\n");
            break;
        case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            _psTrace("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\n");
            break;
        case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            _psTrace("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256\n");
            break;
        default:
            psTraceIntInfo("!!!! DEFINE ME %d !!!!\n", ssl->cipher->ident);
        }
    }
    return;
}
#endif

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
    if ((ssl->flags & SSL_FLAGS_DTLS) && ssl->sessionIdLen > 0)
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
    memcpy(g_sessionTable[i].masterSecret, ssl->sec.masterSecret,
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
    memcpy(g_sessionTable[i].id + 4, ssl->sec.serverRandom,
        min(SSL_HS_RANDOM_SIZE, SSL_MAX_SESSION_ID_SIZE) - 4);
    ssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;

    memcpy(ssl->sessionId, g_sessionTable[i].id, SSL_MAX_SESSION_ID_SIZE);
/*
    startTime is used to check expiry of the entry

    The versions are stored, because a cached session must be reused
    with same SSL version.
 */
    psGetTime(&g_sessionTable[i].startTime, ssl->userPtr);
    g_sessionTable[i].majVer = ssl->majVer;
    g_sessionTable[i].minVer = ssl->minVer;

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
        memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
        ssl->sessionIdLen = 0;
        ssl->flags &= ~SSL_FLAGS_RESUMED;
        /* Always preserve the id for chronList */
        memset(g_sessionTable[i].id + 4, 0x0, SSL_MAX_SESSION_ID_SIZE - 4);
        memset(g_sessionTable[i].masterSecret, 0x0, SSL_HS_MASTER_SIZE);
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
    if ((memcmp(g_sessionTable[i].id, id,
             (uint32) min(ssl->sessionIdLen, SSL_MAX_SESSION_ID_SIZE)) != 0) ||
        (psDiffMsecs(g_sessionTable[i].startTime,   accessTime, ssl->userPtr) >
         SSL_SESSION_ENTRY_LIFE) || (g_sessionTable[i].majVer != ssl->majVer)
        || (g_sessionTable[i].minVer != ssl->minVer))
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
    memcpy(ssl->sec.masterSecret, g_sessionTable[i].masterSecret,
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
        memset(g_sessionTable[i].masterSecret, 0x0, SSL_HS_MASTER_SIZE);
        g_sessionTable[i].cipher = NULL;
        psUnlockMutex(&g_sessionTableLock);
        return PS_FAILURE;
    }
    memcpy(g_sessionTable[i].masterSecret, ssl->sec.masterSecret,
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
        if (lkey->inUse == 0 && (memcmp(lkey->name, name, 16) == 0))
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
            psTraceInfo("Session ticket list > SSL_SESSION_TICKET_LIST_LEN\n");
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

    memset(keylist, 0x0, sizeof(psSessionTicketKeys_t));
    keylist->hashkeyLen = hashkeyLen;
    keylist->symkeyLen = symkeyLen;
    memcpy(keylist->name, name, 16);
    memcpy(keylist->hashkey, hashkey, hashkeyLen);
    memcpy(keylist->symkey, symkey, symkeyLen);
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
    memcpy(c, keys->name, 16);
    c += 16;
    memcpy(c, randno, AES_IVLEN);
    c += AES_IVLEN;
    enc = c; /* encrypt start */
    *c = ssl->majVer; c++;
    *c = ssl->minVer; c++;
    *c = (ssl->cipher->ident & 0xFF00) >> 8; c++;
    *c = ssl->cipher->ident & 0xFF; c++;
    /* Need to track if original handshake used extended master secret */
    *c = ssl->extFlags.extended_master_secret; c++;

    memcpy(c, ssl->sec.masterSecret, SSL_HS_MASTER_SIZE);
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
    memcpy(name, c, 16);
    *keys = NULL;
    /* check our cached list beginning with our own encryption key */
    lkey = ssl->keys->sessTickets;
    while (lkey)
    {
        if (memcmp(lkey->name, name, 16) == 0)
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
            if (memcmp(lkey->name, c, 16) != 0)
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
        psTraceInfo("No key found for session ticket\n");
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

    memcpy(name, c, 16);
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

    if (memcmp(hash, c, L_HASHLEN) != 0)
    {
        psTraceInfo("HMAC check failure on session ticket\n");
        return PS_FAILURE;
    }
#   undef L_HASHLEN

    majVer = *enc; enc++;
    minVer = *enc; enc++;

    /* Match protcol version */
    if (majVer != ssl->majVer || minVer != ssl->minVer)
    {
        psTraceInfo("Protocol check failure on session ticket\n");
        return PS_FAILURE;
    }

    cipherSuite = *enc << 8; enc++;
    cipherSuite += *enc; enc++;

    /* Force cipher suite */
    if ((ssl->cipher = sslGetCipherSpec(ssl, cipherSuite)) == NULL)
    {
        psTraceInfo("Cipher suite check failure on session ticket\n");
        return PS_FAILURE;
    }

    /* Did the initial connection use extended master secret? */
    /* First round of "require" testing can be done here.  If server is
        set to require extended master secret and this ticket DOES NOT have it
        then we can stop resumption right now */
    if (*enc == 0x0 && ssl->extFlags.require_extended_master_secret == 1)
    {
        psTraceInfo("Ticket and master secret derivation methods differ\n");
        return PS_FAILURE;
    }
    ssl->extFlags.require_extended_master_secret = *enc; enc++;

    /* Set aside masterSecret */
    memcpy(ssl->sid->masterSecret, enc, SSL_HS_MASTER_SIZE);
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
        psTraceInfo("Session ticket was expired\n");
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
        memcpy(session->id, ssl->sessionId, ssl->sessionIdLen);
        memcpy(session->masterSecret, ssl->sec.masterSecret,
            SSL_HS_MASTER_SIZE);
        return PS_SUCCESS;
    }
# ifdef USE_STATELESS_SESSION_TICKETS
    if (ssl->cipher != NULL && ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL &&
        session->sessionTicket != NULL && session->sessionTicketLen > 0)
    {
        session->cipherId = ssl->cipher->ident;
        memcpy(session->masterSecret, ssl->sec.masterSecret,
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
    memset(c, 0, len);
    *extOut = c;
    *extLen = len;

    *c = ((len - 2) & 0xFF00) >> 8; c++; /* don't include ourself */
    *c = (len - 2) & 0xFF; c++;
    for (i = 0; i < protoCount; i++)
    {
        *c = protoLen[i]; c++;
        memcpy(c, proto[i], protoLen[i]);
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
    memset(c, 0, *extLen);
    *extOut = c;

    *c = ((hostLen + 3) & 0xFF00) >> 8; c++;
    *c = (hostLen + 3) & 0xFF; c++;
    c++; /* host_name enum */
    *c = (hostLen & 0xFF00) >> 8; c++;
    *c = hostLen  & 0xFF; c++;
    memcpy(c, host, hostLen);
    return PS_SUCCESS;
}
#endif /* USE_CLIENT_SIDE_SSL */

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
    If client sent a ServerNameIndication extension, see if we have those
    keys to load
 */
int32 matrixServerSetKeysSNI(ssl_t *ssl, char *host, int32 hostLen)
{
    sslKeys_t *keys;

    if (ssl->sni_cb)
    {
        ssl->extFlags.sni = 1; /* extension was actually handled */
        keys = NULL;
        (ssl->sni_cb)((void *) ssl, host, hostLen, &keys);
        if (keys)
        {
            ssl->keys = keys;
            return 0;
        }
        return PS_UNSUPPORTED_FAIL; /* callback didn't provide keys */
    }

    return 0; /* No callback registered.  Go with default */
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
    if (ssl->flags & SSL_FLAGS_DTLS)
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
        if (strchr(s, '@'))
        {
            return -1;
        }
        if ((e = strchr(s, '.')) == NULL)
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

    if (strlen(expectedEmail) != emailLen)
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
        if (((strncmp(email,
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

    memset(&options, 0, sizeof(matrixValidateCertsOptions_t));

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
                psTraceInfo("expectedName is not a valid GeneralName\n");
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
            if (ic->extensions.bc.pathLenConstraint >= 0)
            {
                /* Make sure the pathLen is not exceeded */
                if (ic->extensions.bc.pathLenConstraint < pathLen)
                {
                    psTraceInfo("Authentication failed due to X.509 pathLen\n");
                    sc->authStatus = PS_CERT_AUTH_FAIL_PATH_LEN;
                    return PS_CERT_AUTH_FAIL_PATH_LEN;
                }
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
        if (ic->extensions.bc.pathLenConstraint >= 0)
        {
            /* Make sure the pathLen is not exceeded */
            if (ic->extensions.bc.pathLenConstraint < pathLen)
            {
                psTraceInfo("Authentication failed due to X.509 pathLen\n");
                sc->authStatus = PS_CERT_AUTH_FAIL_PATH_LEN;
                return PS_CERT_AUTH_FAIL_PATH_LEN;
            }
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
            if (ic->extensions.bc.pathLenConstraint >= 0)
            {
                /* Make sure the pathLen is not exceeded.  If the sc and ic
                    are the same CA at this point, this means the peer
                    included the root CA in the chain it sent.  It's not good
                    practice to do this but implementations seem to allow it.
                    Subtract one from pathLen in this case since one got
                    added when it was truly just self-authenticating */
                if (ic->signatureLen == sc->signatureLen &&
                    (memcmp(ic->signature, sc->signature,
                         sc->signatureLen) == 0))
                {
                    if (pathLen > 0)
                    {
                        pathLen--;
                    }
                }
                if (ic->extensions.bc.pathLenConstraint < pathLen)
                {
                    psTraceInfo("Authentication failed due to X.509 pathLen\n");
                    rc = sc->authStatus = PS_CERT_AUTH_FAIL_PATH_LEN;
                    return rc;
                }
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
                        snprintf(ip, 15, "%u.%u.%u.%u",
                            (unsigned char) (n->data[0]),
                            (unsigned char ) (n->data[1]),
                            (unsigned char ) (n->data[2]),
                            (unsigned char ) (n->data[3]));
                        ip[15] = '\0';
                        if (strcmp(ip, expectedName) == 0)
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

            psTraceInfo("Authentication failed: no matching subject\n");
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

