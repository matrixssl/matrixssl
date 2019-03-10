/**
 *      @file    matrixsslKeys.c
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

#if defined(USE_CA_CERTIFICATES) || defined(USE_IDENTITY_CERTIFICATES)

# ifdef USE_CERT_PARSE
static
psRes_t handleAuthFailDate(matrixSslLoadKeysOpts_t *opts)
{
#  ifdef POSIX /* TODO - implement date check on WIN32, etc. */
    if (opts && (opts->flags & LOAD_KEYS_OPT_ALLOW_OUT_OF_DATE_CERT_PARSE))
    {
        /* Caller deems this as OK. */
        psTraceInfo("Warning: loaded an out-of-date cert\n");
        return PS_SUCCESS;
    }

    psTraceErrr("Error: Tried to load an out-of-date cert\n");
    return PS_CERT_AUTH_FAIL_EXTENSION;
#  endif /* POSIX */
    return PS_SUCCESS;
}
# endif

static
psRes_t checkAuthFailFlags(psX509Cert_t *leafCert,
        matrixSslLoadKeysOpts_t *opts)
{
# ifndef USE_CERT_PARSE
    return PS_SUCCESS;
# else
    if (leafCert->authFailFlags == 0)
    {
        return PS_SUCCESS; /* All OK. */
    }

    switch (leafCert->authFailFlags)
    {
    case PS_CERT_AUTH_FAIL_DATE_FLAG:
        return handleAuthFailDate(opts);
    default:
        psAssert(PS_FALSE);
        psTraceIntInfo("checkAuthFailFlags: add handling for flag: %u\n",
                leafCert->authFailFlags);
        return PS_FAILURE;
        break;
    }

    return PS_SUCCESS;
#  endif /* USE_CERT_PARSE */
}

/* On client add server cert trust anchors, and on server, add trusted client
   certificate issuers. Inputs: either capath or cacert + cacert_len. */
static psRes_t
matrixSslAddTrustAnchors(sslKeys_t *keys,
        const char *capath,
        const unsigned char *cacert,
        psSizeL_t cacert_len,
        matrixSslLoadKeysOpts_t *opts)
{
    psRes_t err = PS_SUCCESS;

    /* Not necessary to store binary representations of CA certs */
    int32 flags = 0;

    flags |= CERT_STORE_DN_BUFFER;
    flags |= CERT_ALLOW_BUNDLE_PARTIAL_PARSE;

# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
#  ifdef MATRIX_USE_FILE_SYSTEM
    if (capath)
    {
        err = psX509ParseCertFile(keys->pool, capath, &keys->CAcerts, flags);
    }
    else
#  endif  /* MATRIX_USE_FILE_SYSTEM */
    {
        if (cacert == NULL || cacert_len == 0)
        {
            return PS_SUCCESS;
        }
        err = psX509ParseCertData(keys->pool,
                cacert,
                cacert_len,
                &keys->CAcerts,
                flags);
    }
    if (err == 0)
    {
        psTraceErrr("Failed to load any CA certs.\n");
        return PS_PARSE_FAIL;
    }
    else if (err > 0)
    {
        psTraceIntInfo("Loaded %d CA certs\n", err);
        err = checkAuthFailFlags(keys->CAcerts, opts);
        if (err != PS_SUCCESS)
        {
            psX509FreeCert(keys->CAcerts);
            keys->CAcerts = NULL;
            return err;
        }

        return PS_SUCCESS;
    }
    else
    {
        /* Generic load failure path. Other paths have returned. */
    }

    psTraceStrInfo("Failed to load CA cert file: %s\n", (char *)capath);
# endif
    return err;
}
#else /* CA or IDENTITY CERTIFICATES */
# define matrixSslAddTrustAnchors(k,capath,cacert,cacert_len,opts) (0)
# define checkAuthFailFlags(leafCert,opts) (0)
#endif /* CA or IDENTITY CERTIFICATES */

/* Have seen cases where the PKCS#12 files are not in a child-to-parent order.
   This function is also used in TLS 1.3, where the spec allows chains to be
   sent in arbitrary order. */
void matrixSslReorderCertChain(psX509Cert_t *a_cert)
{
#ifdef USE_CERT_PARSE
    psX509Cert_t *prevCert = NULL;
    psX509Cert_t *nextCert = NULL;
    psX509Cert_t *currCert = a_cert;

    while (currCert)
    {
        nextCert = currCert->next;
        while (nextCert && Memcmp(currCert->issuer.hash, nextCert->subject.hash,
                   SHA1_HASH_SIZE) != 0)
        {
            prevCert = nextCert;
            nextCert = nextCert->next;

            if (nextCert && Memcmp(currCert->issuer.hash,
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
#else
    return;
#endif
}


#if defined(USE_IDENTITY_CERTIFICATES)

/******************************************************************************/
/*
    Validate the cert chain and the private key for the material passed
    to matrixSslReadKeys.  Good to catch any user certifiate errors as
    soon as possible

    When the client private key is stored externally, skip all tests
    involving the private key, since MatrixSSL does not have direct
    access to the key.
 */
static psRes_t verifyReadKeyPair(psPool_t *pool, sslIdentity_t *p, void *poolUserPtr)
{
#  ifndef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    /* Not allowed to have a certificate with no matching private key or
       private key with no cert to match with */
    if (p->cert != NULL && p->privKey.type == 0)
    {
        psTraceErrr("No private key given to matrixSslReadKeys cert\n");
        return PS_CERT_AUTH_FAIL;
    }
    if (p->privKey.type != 0 && p->cert == NULL)
    {
        psTraceErrr("No cert given with private key to matrixSslReadKeys\n");
        return PS_CERT_AUTH_FAIL;
    }
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

   /*
     If this is a chain, we can validate it here with psX509AuthenticateCert
     Don't check the error return code from this call because the chaining
     usage restrictions will test parent-most cert for self-signed.

     But we can look at 'authStatus' on all but the final cert to see if the
     rest looks good
   */
    if (p->cert != NULL && p->cert->next != NULL)
    {
#   ifdef USE_CERT_PARSE
        psX509Cert_t *tmp, *found = NULL;
        (void)psX509AuthenticateCert(pool, p->cert, NULL, &found, NULL, poolUserPtr);
        for (tmp = p->cert; tmp && tmp->next; tmp = tmp->next)
        {
            if (tmp->authStatus != PS_TRUE)
            {
                psTraceErrr("Failed to authenticate cert chain\n");
                return PS_CERT_AUTH_FAIL;
            }
        }
#   endif
#   ifndef USE_EXT_CERTIFICATE_VERIFY_SIGNING
#    if defined(USE_RSA) && defined(USE_CERT_PARSE)
        if (p->privKey.type == PS_RSA)
        {
            if (psRsaCmpPubKey(&p->privKey.key.rsa,
                               &p->cert->publicKey.key.rsa) < 0)
            {
                psTraceErrr("Private key doesn't match cert\n");
                return PS_CERT_AUTH_FAIL;
            }
        }
#    endif /* USE_RSA */
#   endif  /* !USE_EXT_CERTIFICATE_VERIFY_SIGNING */
    }
    return PS_SUCCESS;
}


/* Create Identity */
sslIdentity_t *
matrixSslMakeIdentity(psPool_t *pool, psPubKey_t idkey, psX509Cert_t *cert)
{
    sslIdentity_t *identity;

    if ((identity = psCalloc(pool, 1, sizeof(*identity))) != NULL)
    {
        identity->privKey = idkey;
        identity->cert = cert;
        identity->next = NULL;
    }
    return identity;
}

/* Free Identity */
void
matrixSslFreeIdentity(psPool_t *pool, sslIdentity_t *identity)
{
    if (identity)
    {
        psX509FreeCert(identity->cert);
        psClearPubKey(&identity->privKey);
        psFree(identity, pool);
    }
}

/* Clear Identity Assignment from SSL keys */
void
matrixSslDelIdentity(sslKeys_t *keys, sslIdentity_t *identity)
{
    sslIdentity_t **p;
    for (p = &(keys->identity); *p && *p != identity; p = &((*p)->next))
        ;
    if (*p)
    {
        psAssert(*p == identity);
        *p = (*p)->next;
    }
}

/* Add Identity Assignment to SSL keys - they keys will take ownership of the
   identity, and thus assigned identity needs to be removed from keys before
   being deallocated. Function returns the 'identity' argument, and can't
   fail.  */
sslIdentity_t *
matrixSslAddIdentity(sslKeys_t *keys, sslIdentity_t *identity)
{
# if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    sslIdentity_t **p;
    /* Push the new key at the end of the list, so that routines using the
       keys can easily prefer the first one added. */
    for (p = &(keys->identity); *p; p = &((*p)->next))
        ;
    *p = identity;
    return identity;
# else
    return NULL;
# endif
}

/* Create Identity from the keypair, and corresponding certificate chain. This
   function will verify that certificate chain is properly ordered, and that
   the subject certificate matches the subject key. */
sslIdentity_t *
matrixSslCreateIdentity(sslKeys_t *keys, psPubKey_t idkey, psX509Cert_t *cert)
{
    sslIdentity_t *identity;

    matrixSslReorderCertChain(cert);
    identity = matrixSslMakeIdentity(keys->pool, idkey, cert);
    if (identity == NULL)
    {
        return NULL;
    }

    /* Validate the public key from the certificate matches the identity key
     * provided. */
    if (verifyReadKeyPair(keys->pool, identity, keys->poolUserPtr) < PS_SUCCESS)
    {
        psTraceInfo("Cert parse success but material didn't validate\n");
        matrixSslFreeIdentity(keys->pool, identity);
        return NULL;
    }
    /* Push the new key at the end of the list, so that routines using the
       keys can easily prefer the first one added. */
    return matrixSslAddIdentity(keys, identity);
}

/* Load keypair from memory buffer to 'keys' */
static psRes_t sslLoadKeyPair(psPool_t *pool,
        psPubKey_t *key,
        int keytype,
        const char *keypass,
        const unsigned char *keydata,
        psSizeL_t keydata_len)
{
    psRes_t err = PS_SUCCESS;
# ifdef USE_PRIVATE_KEY_PARSING
    unsigned char *unarmored;
    psSizeL_t unarmored_len;
    int32_t rc;

    if (keydata == NULL || keydata_len == 0)
    {
        psTraceInfo("slLoadKeyPair(): no key material");
        return PS_SUCCESS;
    }
    rc = psPemTryDecode(pool,
            keydata,
            keydata_len,
            PEM_TYPE_KEY,
            keypass,
            &unarmored,
            &unarmored_len);
    if (rc != PS_SUCCESS)
    {
        /* Not PEM or PEM decoding not supported. Try DER. */
        unarmored = (unsigned char*)keydata;
        unarmored_len = keydata_len;
    }

    psInitPubKey(pool, key, keytype);
    switch (keytype)
    {
#  ifdef USE_RSA
    case PS_RSA:
        err = psRsaParsePkcs1PrivKey(pool,
                unarmored,
                unarmored_len,
                &key->key.rsa);
        if (err < 0)
        {
#   ifdef USE_PKCS8
            /* Attempt a PKCS#8 but mem parse doesn't take password */
            err = psPkcs8ParsePrivBin(pool,
                    unarmored,
                    unarmored_len,
                    NULL,
                    key);
            if (err < 0)
            {
                goto out;
            }
#   else
            goto out;
#   endif
        }
        key->keysize = psRsaSize(&key->key.rsa);
        break;
#  endif /* USE_RSA */

#  ifdef USE_ECC
    case PS_ECC:
        err = psEccParsePrivKey(pool,
                unarmored,
                unarmored_len,
                &key->key.ecc,
                NULL);
        if (err < 0)
        {
#   ifdef USE_PKCS8
            /* Attempt a PKCS#8 but mem parse doesn't take password */
            err = psPkcs8ParsePrivBin(pool,
                    unarmored,
                    unarmored_len,
                    NULL,
                    key);
            if (err < 0)
            {
                goto out;
            }
#   else
            goto out;
#   endif
        }
        key->keysize = psEccSize(&key->key.ecc);
        break;
#  endif /* USE_ECC */

#   ifdef USE_ED25519
    case PS_ED25519:
        err = psEd25519ParsePrivKey(pool,
                unarmored,
                unarmored_len,
                &key->key.ed25519);
        if (err < 0)
        {
            goto out;
        }
        key->keysize = 32;
#   endif /* USE_ED25519 */
    } /* end switch */

  out:
    if (unarmored != keydata)
        psFree(unarmored, pool);
# endif
    return err;
}

/* Load a X509 certificate (chain) from given PEM or binary DER encoded
   data */
static psRes_t sslLoadCert(psPool_t *pool,
        psX509Cert_t **cert,
        const unsigned char *data,
        psSizeL_t data_len,
        matrixSslLoadKeysOpts_t *opts)
{
    psRes_t rc = PS_SUCCESS;

    *cert = NULL;
    if (data == NULL || data_len == 0)
    {
        return PS_SUCCESS;
    }

    rc = psX509ParseCertData(pool,
            data,
            data_len,
            cert,
            (CERT_STORE_UNPARSED_BUFFER|CERT_STORE_DN_BUFFER));
    if (rc < PS_SUCCESS)
    {
        psX509FreeCert((*cert));
        return rc;
    }

    rc = checkAuthFailFlags(*cert, opts);
    if (rc != PS_SUCCESS)
    {
        psX509FreeCert((*cert));
        return rc;
    }

    return rc;
}

psRes_t
matrixSslCreateIdentityFromData(sslKeys_t *keys,
        const unsigned char *cert,
        psSizeL_t cert_len,
        int32 keytype,
        const char *keypass,
        const unsigned char *keydata,
        psSizeL_t keydata_len,
        matrixSslLoadKeysOpts_t *opts)
{
    psPubKey_t idkey;
    psX509Cert_t *idcert = NULL;
    int32 err;
    sslIdentity_t *id;

    err = sslLoadCert(keys->pool, &idcert, cert, cert_len, opts);
    if (err < PS_SUCCESS)
    {
        return err;
    }
    err = sslLoadKeyPair(keys->pool,
            &idkey,
            keytype,
            keypass,
            keydata,
            keydata_len);
    if (err < PS_SUCCESS)
    {
        psX509FreeCert(idcert);
        return err;
    }

    id = matrixSslCreateIdentity(keys, idkey, idcert);
    if (id == NULL)
    {
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}

static psRes_t matrixSslLoadKeyMaterialMem(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        int32 privKeyType,
        matrixSslLoadKeysOpts_t *opts)
{
    psRes_t err;

    if (keys == NULL
        || (certBuf == NULL && privBuf == NULL && CAbuf == NULL))
    {
        return PS_ARG_FAIL;
    }
    err = matrixSslAddTrustAnchors(keys, NULL, CAbuf, CAlen, opts);
    if (err < PS_SUCCESS)
    {
        return err;
    }
    err = matrixSslCreateIdentityFromData(keys,
            certBuf,
            certLen,
            privKeyType,
            NULL,
            privBuf,
            privLen,
            opts);
    if (err < PS_SUCCESS)
    {
# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
        psX509FreeCert(keys->CAcerts);
        keys->CAcerts = NULL;
# endif
        return PS_CERT_AUTH_FAIL;
    }
    return PS_SUCCESS;
}

int32_t matrixSslLoadKeysMem(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        matrixSslLoadKeysOpts_t *opts)
{
    int32_t keytype = 0;
    int32_t rc;

    if (opts)
    {
        keytype = opts->key_type;
    }

    if (privBuf == NULL)
    {
        keytype = 1;
    }

    switch (keytype)
    {
    case 1: /* RSA */
        rc = matrixSslLoadKeyMaterialMem(keys,
                certBuf,
                certLen,
                privBuf,
                privLen,
                CAbuf,
                CAlen,
                PS_RSA,
                opts);
        break;
    case 2: /* ECC */
        rc = matrixSslLoadKeyMaterialMem(keys,
                certBuf,
                certLen,
                privBuf,
                privLen,
                CAbuf,
                CAlen,
                PS_ECC,
                opts);
        break;
    case 3: /* ECDSA*/
        rc = matrixSslLoadKeyMaterialMem(keys,
                certBuf,
                certLen,
                privBuf,
                privLen,
                CAbuf,
                CAlen,
                PS_ED25519,
                opts);
        break;
    case 0:
        {
            int32 try[] = { PS_RSA, PS_ECC, PS_ED25519, -1}, i;
            for (i = 0; try[i] != -1; i++)
            {
                rc = matrixSslLoadKeyMaterialMem(
                        keys,
                        certBuf, certLen, privBuf, privLen,
                        NULL, 0,
                        try[i], opts);
                if (rc == PS_SUCCESS)
                {
                    break;
                }
            }
            if (CAbuf && CAlen > 0)
            {
                rc = matrixSslLoadKeyMaterialMem(
                        keys, NULL, 0, NULL, 0,
                        CAbuf, CAlen, 0, opts);
            }
        }
        break;
    default:
        /* Unknown key type */
        rc = PS_FAILURE;
    }
    return rc;
}


#ifdef USE_RSA
int32 matrixSslLoadRsaKeysMemExt(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        matrixSslLoadKeysOpts_t *opts)
{
    return matrixSslLoadKeyMaterialMem(keys,
            certBuf,
            certLen,
            privBuf,
            privLen,
            CAbuf,
            CAlen,
            PS_RSA,
            opts);
}

int32 matrixSslLoadRsaKeysMem(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen)
{
    return matrixSslLoadKeyMaterialMem(keys,
            certBuf,
            certLen,
            privBuf,
            privLen,
            CAbuf,
            CAlen,
            PS_RSA,
            NULL);
}
#endif /* USE_RSA */

#ifdef USE_ECC
int32 matrixSslLoadEcKeysMemExt(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        matrixSslLoadKeysOpts_t *opts)
{
    return matrixSslLoadKeyMaterialMem(keys,
            certBuf,
            certLen,
            privBuf,
            privLen,
            CAbuf,
            CAlen,
            PS_ECC,
            opts);
}

int32 matrixSslLoadEcKeysMem(sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen)
{
    return matrixSslLoadKeyMaterialMem(keys,
            certBuf,
            certLen,
            privBuf,
            privLen,
            CAbuf,
            CAlen,
            PS_ECC,
            NULL);
}
#endif /* USE_ECC */

#ifdef USE_PKCS12

int32 matrixSslLoadPkcs12Mem(sslKeys_t *keys,
        const unsigned char *p12Buf,
        int32 p12Len,
        const unsigned char *importPass,
        int32 ipasslen,
        const unsigned char *macPass,
        int32 mpasslen,
        int32 flags)
{
    unsigned char *mPass;
    psPool_t *pool;
    int32 rc;
    psX509Cert_t *cert;
    psPubKey_t idkey = {0};
    sslIdentity_t *id;

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
    rc = psPkcs12ParseMem(pool,
            &cert,
            &idkey,
            p12Buf,
            p12Len,
            flags,
            (unsigned char *) importPass,
            ipasslen,
            mPass,
            mpasslen);
    if (rc < 0)
    {
        psX509FreeCert(cert);
        psClearPubKey(&idkey);
        return rc;
    }

    id = matrixSslCreateIdentity(keys, idkey, cert);
    if (id == NULL)
    {
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}
# endif /* USE_PKCS12 */

#endif /* USE_IDENTITY_CERTIFICATES */


#ifdef REQUIRE_DH_PARAMS
int32 matrixSslLoadDhParamsMem(sslKeys_t *keys,
        const unsigned char *dhBin,
        int32 dhBinLen)
{
    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }
    return psPkcs3ParseDhParamBin(keys->pool,
            (unsigned char *) dhBin,
            dhBinLen,
            &keys->dhParams);
}
#endif /* REQUIRE_DH_PARAMS */


#ifdef USE_ECC
/* User is specifying EC curves that are supported so check that against the
    keys they are supporting */

static struct {
    int curveId;
    int flag;
} matrixCurveIdFlag[] = {
    { 19, IS_SECP192R1 },
    { 21, IS_SECP224R1 },
    { 23, IS_SECP256R1 },
    { 24, IS_SECP384R1 },
    { 25, IS_SECP521R1 },
    { 26, IS_BRAIN256R1 },
    { 27, IS_BRAIN384R1 },
    { 28, IS_BRAIN512R1 },
    { 255, IS_BRAIN224R1 },
    { 0, 0 }
};

int32 curveIdToFlag(int32 id)
 {
   int i;
   for (i = 0; i < sizeof(matrixCurveIdFlag)/ sizeof(matrixCurveIdFlag[0]); i++)
   {
       if (matrixCurveIdFlag[i].curveId == id)
           return matrixCurveIdFlag[i].flag;
   }
   return 0;
 }

psRes_t psTestUserEcID(int32 id, int32 ecFlags)
{
   int i;
   for (i = 0; i < sizeof(matrixCurveIdFlag)/ sizeof(matrixCurveIdFlag[0]); i++)
   {
       if (matrixCurveIdFlag[i].curveId == id)
       {
           if (!(ecFlags & matrixCurveIdFlag[i].flag))
               return PS_FAILURE;
           else
               return PS_SUCCESS;
       }
   }
   return PS_UNSUPPORTED_FAIL;
}

int32 psTestUserEc(int32 ecFlags, const sslKeys_t *keys)
{
    const psEccKey_t *eccKey;
    int goodEccCount = 0;
    int otherKeyCount = 0;
    psRes_t res;
# ifdef USE_CERT_PARSE
    psX509Cert_t *cert;
# endif /* USE_CERT_PARSE */

# ifdef USE_IDENTITY_CERTIFICATES
    sslIdentity_t *p;

    for (p = keys->identity; p; p = p->next)
    {
        if (p->privKey.type != PS_ECC)
        {
            otherKeyCount++;
            continue;
        }
        eccKey = &p->privKey.key.ecc;
        res = psTestUserEcID(eccKey->curve->curveId, ecFlags);
        if (res < 0)
        {
            continue;
        }
#  ifdef USE_CERT_PARSE
        for (cert = p->cert; cert; cert = cert->next)
        {
            if (cert->publicKey.type == PS_ECC)
            {
                eccKey = &cert->publicKey.key.ecc;
                res = psTestUserEcID(eccKey->curve->curveId, ecFlags);
                if (res < 0)
                {
                    break;
                }
            }
        }
        if (p->cert && !cert)
        {
            /* had certs, and did not break out from the loop above -
               something fruitful */
            goodEccCount++;
        }
#  else /* USE_CERT_PARSE */
        goodEccCount++;
#  endif /* USE_CERT_PARSE */
    }
# endif  /* USE_IDENTITY_CERTIFICATES */

# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
#   ifdef USE_CERT_PARSE
    for (cert = keys->CAcerts; cert != NULL; cert = cert->next)
    {
        if (cert->publicKey.type == PS_ECC)
        {
            eccKey = &cert->publicKey.key.ecc;
            res = psTestUserEcID(eccKey->curve->curveId, ecFlags);
            if (res == PS_SUCCESS)
            {
                goodEccCount++;
            }
        }
    }
#   endif /* USE_CERT_PARSE */
# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
    return goodEccCount > 0 || otherKeyCount > 0;
}
#endif /* USE_ECC */

#ifdef MATRIX_USE_FILE_SYSTEM
# ifdef USE_PKCS12
/******************************************************************************/
/*
    File should be a binary .p12 or .pfx
 */
int32 matrixSslLoadPkcs12(sslKeys_t *keys,
        const unsigned char *certFile,
        const unsigned char *importPass,
        int32 ipasslen,
        const unsigned char *macPass,
        int32 mpasslen,
        int32 flags)
{
    unsigned char *mPass;
    psPool_t *pool;
    int32 rc;
    psX509Cert_t *cert;
    psPubKey_t idkey = {0};
    sslIdentity_t *id;

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

    rc = psPkcs12Parse(pool,
            &cert,
            &idkey,
            certFile,
            flags,
            (unsigned char *) importPass,
            ipasslen,
            mPass,
            mpasslen);
    if (rc < 0)
    {
        if (cert)
        {
            psX509FreeCert(cert);
        }
        psClearPubKey(&idkey);
        return rc;
    }

    id = matrixSslCreateIdentity(keys, idkey, cert);
    if (id == NULL)
    {
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}
/******************************************************************************/
# endif /* USE_PKCS12 */

# if defined(USE_RSA) || defined(USE_ECC)

static psRes_t matrixSslLoadKeyMaterial(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile,
        int32 privKeyType,
        matrixSslLoadKeysOpts_t *opts)
{
    int32 err = PS_UNSUPPORTED_FAIL;

    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }

    err = matrixSslAddTrustAnchors(keys, CAfile, NULL, 0, opts);
    if (err < PS_SUCCESS)
    {
        return err;
    }
#  if defined(USE_IDENTITY_CERTIFICATES)
    if (privFile && certFile)
    {
        unsigned char *idkey, *cert;
        psSizeL_t idkey_len, cert_len;
        psPool_t *pool = keys->pool;

        err = psGetFileBuf(pool, privFile, &idkey, &idkey_len);
        if (err == PS_SUCCESS)
        {
            err = psGetFileBuf(pool, certFile, &cert, &cert_len);
            if (err == PS_SUCCESS)
            {
                err = matrixSslCreateIdentityFromData(keys,
                        cert,
                        cert_len,
                        privKeyType,
                        privPass,
                        idkey,
                        idkey_len,
                        opts);
                psFree(cert, pool);
            }
            psFree(idkey, pool);
        }
    }
#  endif
    return err;
}
#endif

# ifdef USE_RSA
/******************************************************************************/
PSPUBLIC int32  matrixSslLoadRsaKeysExt(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *trustedCAFile,
        matrixSslLoadKeysOpts_t *opts)
{
    return matrixSslLoadKeyMaterial(keys,
            certFile,
            privFile,
            privPass,
            trustedCAFile,
            PS_RSA,
            opts);
}

int32 matrixSslLoadRsaKeys(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile)
{
    return matrixSslLoadKeyMaterial(keys,
            certFile,
            privFile,
            privPass,
            CAfile,
            PS_RSA,
            NULL);
}

/******************************************************************************/
# endif /* USE_RSA */

# ifdef USE_ECC
/******************************************************************************/
int32 matrixSslLoadEcKeysExt(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile,
        matrixSslLoadKeysOpts_t *opts)
{
    return matrixSslLoadKeyMaterial(keys,
            certFile,
            privFile,
            privPass,
            CAfile,
            PS_ECC,
            opts);
}

int32 matrixSslLoadEcKeys(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile)
{
    return matrixSslLoadKeyMaterial(keys,
            certFile,
            privFile,
            privPass,
            CAfile,
            PS_ECC,
            NULL);
}

/**
    Generate and cache an ephemeral ECC key for later use in ECDHE key exchange.
    @param[out] keys Keys structure to hold ephemeral keys
    @param[in] curve ECC curve to generate key on, or NULL to generate for all
        supported curves.
    @param[in] hwCtx Context for hardware crypto.
 */
int32_t matrixSslGenEphemeralEcKey(sslKeys_t *keys,
        psEccKey_t *ecc,
        const psEccCurve_t *curve,
        void *hwCtx)
{
#  if ECC_EPHEMERAL_CACHE_USAGE > 0
    psTime_t t;
#  endif
    int32_t rc;

    if (keys == NULL  || curve == NULL)
    {
        return PS_ARG_FAIL;
    }

#  if ECC_EPHEMERAL_CACHE_USAGE > 0
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
#  else
    /* Not using ephemeral caching. */
    if (ecc)
    {
        rc = psEccGenKey(keys->pool, ecc, curve, hwCtx);
        return rc;
    }
    rc = PS_SUCCESS;
    return rc;
#  endif /* ECC_EPHEMERAL_CACHE_USAGE > 0 */
}
# endif /* USE_ECC */

# if defined(USE_IDENTITY_CERTIFICATES)
psRes_t matrixSslLoadKeys(sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile,
        matrixSslLoadKeysOpts_t *opts)
{
    int32_t keytype = 0;
    int32_t rc;

    if (opts)
    {
        keytype = opts->key_type;
    }

    if (privFile == NULL)
    {
        keytype = 1;
    }

    switch (keytype)
    {
    case 1: /* RSA */
        rc = matrixSslLoadKeyMaterial(keys,
                certFile,
                privFile,
                privPass,
                CAfile,
                PS_RSA,
                opts);
        break;
    case 2: /* ECC */
        rc = matrixSslLoadKeyMaterial(keys,
                certFile,
                privFile,
                privPass,
                CAfile,
                PS_ECC,
                opts);
        break;
    case 3: /* ED25519 */
        rc = matrixSslLoadKeyMaterial(keys,
                certFile,
                privFile,
                privPass,
                CAfile,
                PS_ED25519,
                opts);
        break;
    case 0:
        {
            int32 try[] = { PS_RSA, PS_ECC, PS_ED25519, -1}, i;
            for (i = 0; try[i] != -1; i++)
            {
                rc = matrixSslLoadKeyMaterial(
                        keys,
                        certFile, privFile, privPass,
                        NULL, try[i], opts);
                if (rc == PS_SUCCESS)
                {
                    break;
                }
            }
            if (CAfile)
            {
                rc = matrixSslLoadKeyMaterial(
                        keys, NULL, NULL, NULL, CAfile, 0, opts);
            }
        }
        break;

    default:
        rc = PS_FAILURE;
        break;
    }

    return rc;
}
# endif
# ifdef REQUIRE_DH_PARAMS
/******************************************************************************/
/*
    User level API to assign the DH parameter file to the server application.
 */
int32 matrixSslLoadDhParams(sslKeys_t *keys, const char *paramFile)
{
    if (keys == NULL)
    {
        return PS_ARG_FAIL;
    }
    return psPkcs3ParseDhParamFile(keys->pool, (char *) paramFile, &keys->dhParams);
}
# endif /* REQUIRE_DH_PARAMS */

#endif /* MATRIX_USE_FILE_SYSTEM */

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

    Memcpy(keys->OCSPResponseBuf, OCSPResponseBuf, OCSPResponseBufLen);
    return PS_SUCCESS;
}
#endif /* USE_OCSP_RESPONSE && USE_SERVER_SIDE_SSL */

/******************************************************************************/


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
    Memset(lkeys, 0x0, sizeof(sslKeys_t));
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
# ifdef USE_IDENTITY_CERTIFICATES
    {
        sslIdentity_t *p, *next;
        for (p = keys->identity; p != NULL; p = next)
        {
            next = p->next;
            psX509FreeCert(p->cert);
            psClearPubKey(&p->privKey);
            psFree(p, keys->pool);
        }
    }
# endif /* USE_IDENTITY_CERTIFICATES */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
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
#ifdef USE_TLS_1_3
    tls13FreePsk(keys->tls13PskKeys, keys->pool);
#endif /* USE_TLS_1_3 */

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
