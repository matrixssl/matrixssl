/**
 *      @file    load_keys.c
 *      @version $Format:%h%d$
 *
 *      MatrixSSL key loading helpers.
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

#include "client_common.h"


/* If the algorithm type is supported, load a CA for it */
#ifdef USE_ECC_CIPHER_SUITE
/*
  If ALLOW_CA_BUNDLE_PARTIAL_PARSE is defined, we can simply try to load
  all EC CA certs, even if we are not able to parse all of them.
*/
# ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/ALL_EC_CAS.h"
#   endif /* USE_HEADER_KEYS */
static char ecCAFile[] = "../../testkeys/EC/ALL_EC_CAS.pem";
# else /* !(ALLOW_CA_BUNDLE_PARTIAL_PARSE) */
/*
  If ALLOW_CA_BUNDLE_PARTIAL_PARSE is not defined, we need the to load
  only those CA bundles, where each cert is supported by the present
  configuration.
*/

#  if defined(USE_SECP192R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/192_EC_CA.h"
#   endif /* USE_HEADER_KEYS */
static const char ecCAFileP192[] = "../../testkeys/EC/192_EC_CA.pem";
#  endif  /* USE_SECP192R1 */

#  if defined(USE_SECP224R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/224_EC_CA.h"
#   endif /* USE_HEADER_KEYS */
static const char ecCAFileP224[] = "../../testkeys/EC/224_EC_CA.pem";
#  endif  /* USE_SECP224R1 */

#  ifdef USE_HEADER_KEYS
#   include "testkeys/EC/256_EC_CA.h"
#  endif /* USE_HEADER_KEYS */
static const char ecCAFileP256[] = "../../testkeys/EC/256_EC_CA.pem";

#  ifdef USE_HEADER_KEYS
#   include "testkeys/EC/384_EC_CA.h"
#  endif /* USE_HEADER_KEYS */
static const char ecCAFileP384[] = "../../testkeys/EC/384_EC_CA.pem";

#  if defined(USE_SECP521R1)
#   ifdef USE_HEADER_KEYS
#    include "testkeys/EC/521_EC_CA.h"
#   endif /* USE_HEADER_KEYS */
static const char ecCAFile521[] = "../../testkeys/EC/521_EC_CA.pem";
#  endif  /* USE_SECP521R1 */

# endif /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#endif  /* USE_ECC_CIPHER_SUITE */

#ifdef USE_HEADER_KEYS
/* CAs */
# ifdef USE_RSA_CIPHER_SUITE
#  include "testkeys/RSA/ALL_RSA_CAS.h"
#  ifdef USE_ECC_CIPHER_SUITE
#   include "testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.h"
#  endif
# endif

/* Identity Certs and Keys for use with Client Authentication */
# ifdef ID_RSA
#  define EXAMPLE_RSA_KEYS
#  include "testkeys/RSA/1024_RSA.h"
#  include "testkeys/RSA/1024_RSA_KEY.h"
#  include "testkeys/RSA/2048_RSA.h"
#  include "testkeys/RSA/2048_RSA_KEY.h"
#  include "testkeys/RSA/3072_RSA.h"
#  include "testkeys/RSA/3072_RSA_KEY.h"
#  include "testkeys/RSA/4096_RSA.h"
#  include "testkeys/RSA/4096_RSA_KEY.h"
# endif

# ifdef ID_ECDH_ECDSA
#  define EXAMPLE_EC_KEYS
#  include "testkeys/EC/384_EC.h"
#  include "testkeys/EC/384_EC_KEY.h"
# endif

# ifdef ID_ECDH_RSA
#  define EXAMPLE_ECDH_RSA_KEYS
#  include "testkeys/ECDH_RSA/521_ECDH-RSA.h"
#  include "testkeys/ECDH_RSA/521_ECDH-RSA_KEY.h"
# endif

#endif /* USE_HEADER_KEYS */

/* CAs */
#ifdef USE_RSA_CIPHER_SUITE
static const char rsaCAFile[] = "../../testkeys/RSA/ALL_RSA_CAS.pem";
#endif

#if defined(USE_RSA_CIPHER_SUITE) && defined(USE_ECC_CIPHER_SUITE)
static const char ecdhRsaCAFile[] = "../../testkeys/ECDH_RSA/ALL_ECDH-RSA_CAS.pem";
#endif

/*
   No file-based keys for PSK.
   Include psk.h even when USE_HEADER_KEYS is not defined.
 */
#ifdef USE_PSK_CIPHER_SUITE
/* Defines PSK_HEADER_TABLE and PSK_HEADER_TABLE_COUNT */
#include "../../testkeys/PSK/psk.h"
#endif


#ifdef USE_HEADER_KEYS
void buildTrustedCABuf(unsigned char **CAstreamOut, int32 *CAstreamLenOut)
{
    unsigned char *CAstream = NULL;
    size_t CAstreamLen = 0;
    size_t bufused = 0;

#ifdef USE_RSA_CIPHER_SUITE
    CAstreamLen += sizeof(RSACAS);
#endif/* USE_RSA_CIPHER_SUITE */

#if defined(USE_ECC_CIPHER_SUITE) && defined(USE_RSA_CIPHER_SUITE)
    CAstreamLen += sizeof(ECDHRSACAS);
#endif /* USE_RSA_CIPHER_SUITE && USE_ECC_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
# ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
    CAstreamLen += sizeof(ECCAS);
# else /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#  if defined(USE_SECP192R1)
    CAstreamLen += sizeof(EC192CA);
#  endif  /* USE_SECP192R1 */

#  if defined(USE_SECP224R1)
    CAstreamLen += sizeof(EC224CA);
#  endif  /* USE_SECP224R1 */

    CAstreamLen += sizeof(EC256CA);
    CAstreamLen += sizeof(EC384CA);

#  if defined(USE_SECP521R1)
    CAstreamLen += sizeof(EC521CA);
#  endif  /* USE_SECP521R1 */
# endif /* !ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#endif /* USE_ECC_CIPHER_SUITE */

    if (CAstreamLen > 0)
    {
        CAstream = psMalloc(NULL, CAstreamLen);
    }

    if (NULL == CAstream) {
        *CAstreamOut = NULL;
        *CAstreamLenOut = 0;
        return;
    }

    memset(CAstream, 0x0, CAstreamLen);

#ifdef USE_RSA_CIPHER_SUITE
    appendCACert(CAstream, CAstreamLen, &bufused, RSACAS, sizeof(RSACAS));
#endif/* USE_RSA_CIPHER_SUITE */

#if defined(USE_ECC_CIPHER_SUITE) && defined(USE_RSA_CIPHER_SUITE)
    appendCACert(CAstream, CAstreamLen, &bufused, ECDHRSACAS, sizeof(ECDHRSACAS));
#endif /* USE_RSA_CIPHER_SUITE && USE_ECC_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
# ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
    appendCACert(CAstream, CAstreamLen, &bufused, ECCAS, sizeof(ECCAS));
# else /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#  if defined(USE_SECP192R1)
    appendCACert(CAstream, CAstreamLen, &bufused, EC192CA, sizeof(EC192CA));
#  endif  /* USE_SECP192R1 */

#  if defined(USE_SECP224R1)
    appendCACert(CAstream, CAstreamLen, &bufused, EC224CA, sizeof(EC224CA));
#  endif  /* USE_SECP224R1 */

    appendCACert(CAstream, CAstreamLen, &bufused, EC256CA, sizeof(EC256CA));
    appendCACert(CAstream, CAstreamLen, &bufused, EC384CA, sizeof(EC384CA));

#  if defined(USE_SECP521R1)
    appendCACert(CAstream, CAstreamLen, &bufused, EC521CA, sizeof(EC521CA));
#  endif  /* USE_SECP521R1 */
# endif /* !ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#endif /* USE_ECC_CIPHER_SUITE */

    *CAstreamOut = CAstream;
    *CAstreamLenOut = bufused;
}
#endif /* USE_HEADER_KEYS */

void buildCAStringFromFiles(const char **CAfileOut)
{
    char *CAstream = NULL;
    int32 CAstreamLen = 0;

#ifdef USE_RSA_CIPHER_SUITE
    CAstreamLen += sizeof(rsaCAFile);
#endif/* USE_RSA_CIPHER_SUITE */

#if defined(USE_ECC_CIPHER_SUITE) && defined(USE_RSA_CIPHER_SUITE)
    CAstreamLen += sizeof(ecdhRsaCAFile);
#endif /* USE_RSA_CIPHER_SUITE && USE_ECC_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
# ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
    CAstreamLen += sizeof(ecCAFile);
# else /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#  if defined(USE_SECP192R1)
    CAstreamLen += sizeof(ecCAFileP192);
#  endif  /* USE_SECP192R1 */

#  if defined(USE_SECP224R1)
    CAstreamLen += sizeof(ecCAFileP224);
#  endif  /* USE_SECP224R1 */

    CAstreamLen += sizeof(ecCAFileP256);
    CAstreamLen += sizeof(ecCAFileP384);

#  if defined(USE_SECP521R1)
    CAstreamLen += sizeof(ecCAFile521);
#  endif  /* USE_SECP521R1 */
# endif /* !ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#endif /* USE_ECC_CIPHER_SUITE */

    if (CAstreamLen > 0)
    {
        CAstream = psMalloc(NULL, CAstreamLen);
    }

    if (NULL == CAstream) {
        *CAfileOut = NULL;
        return;
    }

    memset(CAstream, 0x0, CAstreamLen);

#ifdef USE_RSA_CIPHER_SUITE
    appendCAFilename(CAstream, CAstreamLen, rsaCAFile);
#endif/* USE_RSA_CIPHER_SUITE */

#if defined(USE_ECC_CIPHER_SUITE) && defined(USE_RSA_CIPHER_SUITE)
    appendCAFilename(CAstream, CAstreamLen, ecdhRsaCAFile);
#endif /* USE_RSA_CIPHER_SUITE && USE_ECC_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
# ifdef ALLOW_CA_BUNDLE_PARTIAL_PARSE
    appendCAFilename(CAstream, CAstreamLen, ecCAFile);
# else /* ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#  if defined(USE_SECP192R1)
    appendCAFilename(CAstream, CAstreamLen, ecCAFileP192);
#  endif  /* USE_SECP192R1 */

#  if defined(USE_SECP224R1)
    appendCAFilename(CAstream, CAstreamLen, ecCAFileP224);
#  endif  /* USE_SECP224R1 */

    appendCAFilename(CAstream, CAstreamLen, ecCAFileP256);
    appendCAFilename(CAstream, CAstreamLen, ecCAFileP384);

#  if defined(USE_SECP521R1)
    appendCAFilename(CAstream, CAstreamLen, ecCAFile521);
#  endif  /* USE_SECP521R1 */
# endif /* !ALLOW_CA_BUNDLE_PARTIAL_PARSE */
#endif /* USE_ECC_CIPHER_SUITE */

    *CAfileOut = CAstream;
}

#if defined(USE_HEADER_KEYS) && defined(ID_RSA)
int32 loadRsaExampleKeys(sslKeys_t *keys)
{
    int32 rc;
    const unsigned char *key_buf = NULL;
    const unsigned char *cert_buf = NULL;
    int32 key_buf_len = 0;
    int32 cert_buf_len = 0;
    uint32 key_len = g_key_len;
    unsigned char *trustedCABuf = NULL;
    int32 trustedCALen = 0;

    buildTrustedCABuf(&trustedCABuf, &trustedCALen);

    if (key_len == 1024)
    {
        psTrace("Using 1024 bit RSA private key\n");
        cert_buf = RSA1024;
        cert_buf_len = sizeof(RSA1024);
        key_buf = RSA1024KEY;
        key_buf_len = sizeof(RSA1024KEY);
    }
    else if (key_len == 2048)
    {
        psTrace("Using 2048 bit RSA private key\n");
        cert_buf = RSA2048;
        cert_buf_len = sizeof(RSA2048);
        key_buf = RSA2048KEY;
        key_buf_len = sizeof(RSA2048KEY);
    }
    else if (key_len == 3072)
    {
        psTrace("Using 3072 bit RSA private key\n");
        cert_buf = RSA3072;
        cert_buf_len = sizeof(RSA3072);
        key_buf = RSA3072KEY;
        key_buf_len = sizeof(RSA3072KEY);
    }
    else if (key_len == 4096)
    {
        psTrace("Using 4096 bit RSA private key\n");
        cert_buf = RSA4096;
        cert_buf_len = sizeof(RSA4096);
        key_buf = RSA4096KEY;
        key_buf_len = sizeof(RSA4096KEY);
    }
    else
    {
        psTraceInt("Unsupported RSA private key size: %u\n", key_len);
        rc = PS_FAILURE;
        goto error;
    }

    if (g_enable_ext_cv_sig_op)
    {
        key_buf = NULL;
        key_buf_len = 0;
    }

    psTrace("USE_HEADER_KEYS loadRsaExampleKeys()\n");
    rc = matrixSslLoadRsaKeysMem(keys, cert_buf, cert_buf_len,
        key_buf, key_buf_len, trustedCABuf, trustedCALen);

    if (rc != 0)
    {
        psTraceInt("No certificate material loaded. Error=%d\n", rc);
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

error:
    psFree(trustedCABuf, NULL);
    return rc;
}
#endif /* USE_HEADER_KEYS && ID_RSA */

#if defined(USE_HEADER_KEYS) && defined(ID_ECDH_RSA)
int32 loadECDHRsaExampleKeys(sslKeys_t *keys)
{
    int32 rc;
    const unsigned char *key_buf;
    int32 key_buf_len;
    unsigned char *trustedCABuf = NULL;
    int32 trustedCALen = 0;

    buildTrustedCABuf(&trustedCABuf, &trustedCALen);

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

    psTrace("USE_HEADER_KEYS loadECDHRsaExampleKeys()\n");
    if ((rc = matrixSslLoadEcKeysMem(keys, ECDHRSA521, sizeof(ECDHRSA521),
             key_buf, key_buf_len, trustedCABuf, trustedCALen)) != 0)
    {
        psTraceInt("No certificate material loaded. Error=%d\n", rc);
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

    psFree(trustedCABuf, NULL);
    return rc;
}
#endif /* USE_HEADER_KEYS && ID_ECDH_RSA */

#if defined(USE_HEADER_KEYS) && defined(ID_ECDH_ECDSA)
int32 loadECDH_ECDSAExampleKeys(sslKeys_t *keys)
{
    int32 rc;
    const unsigned char *key_buf;
    int32 key_buf_len;
    unsigned char *trustedCABuf = NULL;
    int32 trustedCALen = 0;

    buildTrustedCABuf(&trustedCABuf, &trustedCALen);

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

    psTrace("USE_HEADER_KEYS loadECDH_ECDSAExampleKeys()\n");
    rc = matrixSslLoadEcKeysMem(keys, EC384, sizeof(EC384),
            key_buf, key_buf_len, trustedCABuf, trustedCALen);

    if (rc != 0)
    {
        psTraceInt("No certificate material loaded. Error=%d\n", rc);
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

    psFree(trustedCABuf, NULL);
    return rc;
}
#endif /* USE_HEADER_KEYS && ID_ECDH_ECDSA */

#ifdef USE_PSK_CIPHER_SUITE
int32 loadExamplePreSharedKeys(sslKeys_t *keys)
{
    int32 rc;
    size_t key_n;

    psTrace("USE_PSK_CIPHER_SUITE loadExamplePreSharedKeys()\n");
    for (key_n = 0; key_n < PSK_HEADER_TABLE_COUNT; key_n++)
    {
        rc = matrixSslLoadPsk(keys,
            PSK_HEADER_TABLE[key_n].key, sizeof(PSK_HEADER_TABLE[key_n].key),
            PSK_HEADER_TABLE[key_n].id, sizeof(PSK_HEADER_TABLE[key_n].id));

        if (rc != PS_SUCCESS) {
            return rc;
        }
    }

    return PS_SUCCESS;
}

int32 loadPreSharedKeys(sslKeys_t *keys)
{
    return loadExamplePreSharedKeys(keys);
}
#endif /* USE_PSK_CIPHER_SUITE */

int32 loadKeysFromFile(sslKeys_t *keys)
{
    int32 rc = PS_FAILURE;
    const char *pCA = clientconfigGetTrustedCA();
    const char *certFile = g_clientconfig.cert_file;
    const char *privFile = g_clientconfig.privkey_file;

    if (g_enable_ext_cv_sig_op)
    {
        privFile = NULL;
    }

# if defined(USE_RSA) || defined(USE_ECC)
    psTrace("loadKeysFromFile()\n");
    psTraceStr("Using CA: %s\n", pCA);
    psTraceStr("Using certificate: %s\n", certFile);
    psTraceStr("Using private key: %s\n", privFile);
    rc = matrixSslLoadKeys(keys, certFile, privFile, NULL, pCA, NULL);
# else
    psTrace("matrixSslLoadKeys() not available\n");
    PS_VARIABLE_SET_BUT_UNUSED(certFile);
    PS_VARIABLE_SET_BUT_UNUSED(privFile);
    PS_VARIABLE_SET_BUT_UNUSED(pCA);
# endif /* USE_RSA || USE_ECC */

    if (rc != 0)
    {
        psTraceInt("No certificate material loaded. Error=%d\n", rc);
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

    return rc;
}

int32 loadRsaKeysFromFile(sslKeys_t *keys)
{
    int32 rc = PS_FAILURE;
    const char *pCA = clientconfigGetTrustedCA();
    const char *certFile = g_clientconfig.cert_file;
    const char *privFile = g_clientconfig.privkey_file;

    if (g_enable_ext_cv_sig_op)
    {
        privFile = NULL;
    }

#ifdef USE_RSA
    psTrace("loadRsaKeysFromFile()\n");
    psTraceStr("Using CA: %s\n", pCA);
    psTraceStr("Using certificate: %s\n", certFile);
    psTraceStr("Using private key: %s\n", privFile);
    rc = matrixSslLoadRsaKeys(keys, certFile, privFile, NULL, pCA);
#else
    psTrace("matrixSslLoadRsaKeys() not available\n");
    PS_VARIABLE_SET_BUT_UNUSED(certFile);
    PS_VARIABLE_SET_BUT_UNUSED(privFile);
    PS_VARIABLE_SET_BUT_UNUSED(pCA);
#endif /* USE_RSA */

    if (rc != 0)
    {
        psTraceInt("No certificate material loaded. Error=%d\n", rc);
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

    return rc;
}

int32 loadECDHRsaKeysFromFile(sslKeys_t *keys)
{
    int32 rc = PS_FAILURE;
    const char *pCA = clientconfigGetTrustedCA();
    const char *certFile = g_clientconfig.cert_file;
    const char *privFile = g_clientconfig.privkey_file;

    if (g_enable_ext_cv_sig_op)
    {
        privFile = NULL;
    }

#ifdef USE_ECC
    psTrace("loadECDHRsaKeysFromFile()\n");
    psTraceStr("Using CA: %s\n", pCA);
    psTraceStr("Using certificate: %s\n", certFile);
    psTraceStr("Using private key: %s\n", privFile);
    rc = matrixSslLoadEcKeys(keys, certFile, privFile, NULL, pCA);
#else
    psTrace("matrixSslLoadEcKeys() not available\n");
    PS_VARIABLE_SET_BUT_UNUSED(certFile);
    PS_VARIABLE_SET_BUT_UNUSED(privFile);
    PS_VARIABLE_SET_BUT_UNUSED(pCA);
#endif /* USE_ECC */

    if (rc != 0)
    {
        psTraceInt("No certificate material loaded. Error=%d\n", rc);
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

    return rc;
}

int32 loadECDH_ECDSAKeysFromFile(sslKeys_t *keys)
{
    int32 rc = PS_FAILURE;
    const char *pCA = clientconfigGetTrustedCA();
    const char *certFile = g_clientconfig.cert_file;
    const char *privFile = g_clientconfig.privkey_file;

    if (g_enable_ext_cv_sig_op)
    {
        privFile = NULL;
    }

#ifdef USE_ECC
    psTrace("loadECDH_ECDSAKeysFromFile()\n");
    psTraceStr("Using CA: %s\n", pCA);
    psTraceStr("Using certificate: %s\n", certFile);
    psTraceStr("Using private key: %s\n", privFile);
    rc = matrixSslLoadEcKeys(keys, certFile, privFile, NULL, pCA);
#else
    psTrace("matrixSslLoadEcKeys() not available\n");
    PS_VARIABLE_SET_BUT_UNUSED(certFile);
    PS_VARIABLE_SET_BUT_UNUSED(privFile);
    PS_VARIABLE_SET_BUT_UNUSED(pCA);
#endif /* USE_ECC */

    if (rc != 0)
    {
        psTraceInt("No certificate material loaded. Error=%d\n", rc);
        matrixSslDeleteKeys(keys);
        matrixSslClose();
    }

    return rc;
}
