/**
 *      @file    matrixsslSecConfig.c
 *      @version $Format:%h%d$
 *
 *      Functions for changing MatrixSSL's security configuration.
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

#include "matrixsslImpl.h"

# ifdef USE_SEC_CONFIG

# ifdef USE_SEC_CONFIG_WPA3_1_0

/* WPA3 1.0 only allows these three ciphersuites. */
static
psCipher16_t cipherlist_wpa3_1_0_enterprise_192[] =
{
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
};
static psSize_t cipherlist_wpa3_1_0_enterprise_192_len = 3;
static uint32_t ec_flags_wpa3_1_0_enterprise_192 = SSL_OPT_SECP384R1;

/* We use the psSecConfig_t to restrict the RSA/ECDSA/DH sizes.
   WPA3 1.0 Enterprise claims to require "192 bits" of security.
   In reality, this is not quite true; it would need a much
   larger RSA key in that case.

   Note that we shall use this only in the TLS layer. So setting
   min_rsa_bits to 3072 does not restrict the use of RSA sigs
   in certificates as the X.509 lib is separate. */
static
psSecConfig_t secconfig_wpa3_1_0_enterprise_192 =
{
    .min_symmetric_key_bits = 192,
    .min_rsa_bits = 3072,
    .min_rsa_verify_bits = 3072,
    .min_dh_key_bits = 3072,
    .min_dh_group_bits = 3072,
    .min_ec_curve_bits = 384,
    .min_ec_verify_curve_bits = 384,
    .min_hmac_bits = 384,
    .min_signature_hash_bits = 0,
    .min_signature_verify_hash_bits = 0,
    .allow_pkcs1_sigs_in_handshake = PS_TRUE,
    .allow_pkcs1_sigs_in_certs = PS_TRUE,
    .allow_rsa_key_transport = PS_FALSE, /* Only (EC)DHE-RSA allowed. */
    .require_sig_hash_group_match = PS_FALSE,
    .min_tls_version = v_tls_1_0
};
# endif /* USE_SEC_CONFIG_WPA3_1_0 */

psRes_t matrixSslSetSecurityProfile(ssl_t *ssl,
        psPreDefinedSecProfile_t profile)
{
    psCipher16_t *cipherList = NULL;
    psSize_t cipherListLen = 0;
    uint32_t ecFlags = 0;

# ifndef USE_SEC_CONFIG
    psTraceErrr("Need USE_SEC_CONFIG for matrixSslSetSecurityProfile\n");
    return PS_UNSUPPORTED_FAIL;
# else
    if (ssl == NULL)
    {
        return PS_ARG_FAIL;
    }

    switch (profile)
    {
    case secprofile_default:
        break;
# ifdef USE_SEC_CONFIG_WPA3_1_0
    case secprofile_wpa3_1_0_enterprise_192:
        cipherList = cipherlist_wpa3_1_0_enterprise_192;
        cipherListLen = cipherlist_wpa3_1_0_enterprise_192_len;
        ecFlags = ec_flags_wpa3_1_0_enterprise_192;
        ssl->secConfig = secconfig_wpa3_1_0_enterprise_192;
        break;
# endif /* USE_SEC_CONFIG_WPA3_1_0 */
    default:
        psTraceErrr("Invalid profile in matrixSslSetSecurityProfile\n");
        return PS_FAILURE;
    }

    if (cipherList != NULL)
    {
        ssl->supportedCiphers = cipherList;
        ssl->supportedCiphersLen = cipherListLen;
    }

    ssl->ecFlagsOverride = ecFlags;
    ssl->secProfile = profile;
    psTraceStrInfo("Using security profile: %s\n",
            SECPROFILE_TO_STR(profile));

    return PS_SUCCESS;
# endif /* USE_SEC_CONFIG */
}

void matrixSslRegisterSecurityCallback(
        ssl_t *ssl,
        securityCb_t cb)
{
    if (ssl == NULL)
    {
        return;
    }
    ssl->secCb = cb;
}

/** MatrixSSL's default TLS security callback.

    This callback uses information in the ssl->secConfig (a struct of
    type psSecConfig_t) to check whether an operation is allowed
    or not. */
static
psRes_t defaultTlsSecCb(void *ctx,
        psSecOperation_t op,
        psSizeL_t nbits,
        void *extraData)
{
    ssl_t *ssl = (ssl_t*)ctx;

    psTraceStrInfo("Checking %s", SECOP_TO_STR(op));
    psTraceIntInfo(" (%zu bits)", nbits);
    psTraceInfo("...\n");

    /* Check whether operation allowed or not. Key size will be
       checked later. */
    switch (op)
    {
    case secop_rsa_encrypt:
    case secop_rsa_decrypt:
        if (!ssl->secConfig.allow_rsa_key_transport)
        {
            psTraceErrr("RSA key transport not allowed by sec config\n");
            return MATRIXSSL_ERROR;
        }
        break;
    default:
        break;
    }

    /* Check that key size is over the minimum required. */
    switch (op)
    {
    case secop_rsa_encrypt:
    case secop_rsa_decrypt:
    case secop_rsa_sign:
    case secop_rsa_verify:
        if (ssl->secConfig.min_rsa_bits > nbits)
        {
            psTraceErrr("RSA key size too low for security config\n");
            psTraceIntInfo("Got: %zu, ", nbits);
            psTraceIntInfo("want: >= %hu\n", ssl->secConfig.min_rsa_bits);
            return MATRIXSSL_ERROR;
        }
        break;
    case secop_ecdsa_sign:
    case secop_ecdsa_verify:
        if (ssl->secConfig.min_ec_curve_bits > nbits)
        {
            psTraceErrr("ECDSA curve size too low for security config\n");
            psTraceInt("Got: %zu, ", nbits);
            psTraceInt("want: >= %hu\n", ssl->secConfig.min_ec_curve_bits);
            return MATRIXSSL_ERROR;
        }
        break;
    case secop_dh_import_pub:
        if (ssl->secConfig.min_dh_group_bits > nbits)
        {
            psTraceErrr("Peer DH group size too low for security config\n");
            psTraceInt("Got: %zu, ", nbits);
            psTraceInt("want: >= %hu\n", ssl->secConfig.min_dh_group_bits);
            return MATRIXSSL_ERROR;
        }
        break;
    case secop_ecdh_import_pub:
        if (ssl->secConfig.min_ec_curve_bits > nbits)
        {
            psTraceErrr("Peer ECDH curve size too low for security config\n");
            psTraceInt("Got: %zu, ", nbits);
            psTraceInt("want: >= %hu\n", ssl->secConfig.min_ec_curve_bits);
            return MATRIXSSL_ERROR;
        }
        break;

    /* Warn if user tries to load too small keys. In the end, it is the
       users responsibility to load the right keys, so do not issue
       an error. */
    case secop_rsa_load_key:
        if (ssl->secConfig.min_rsa_bits > nbits)
        {
            psTraceErrr("Warning: loaded RSA key is below minimum size " \
                    "required by security config\n");
            psTraceIntInfo("Got: %zu, ", nbits);
            psTraceIntInfo("want: >= %hu\n", ssl->secConfig.min_rsa_bits);
        }
        break;
    case secop_ecdsa_load_key:
        if (ssl->secConfig.min_ec_curve_bits > nbits)
        {
            psTraceErrr("Warning: loaded EC key is below minimum size " \
                    "required by security config\n");
            psTraceIntInfo("Got: %zu, ", nbits);
            psTraceIntInfo("want: >= %hu\n", ssl->secConfig.min_ec_curve_bits);
        }
        break;
    default:
        break;
    }

    /* Operation deemed as permissible if we got here. */
    psTraceInfo("OK\n");
    return MATRIXSSL_SUCCESS;
}

psRes_t matrixSslCallSecurityCallback(ssl_t *ssl,
        psSecOperation_t op,
        psSizeL_t nbits,
        void *extraData)
{
    if (ssl->secCb)
    {
        return ssl->secCb(ssl, op, nbits, extraData);
    }
    else
    {
        return defaultTlsSecCb(ssl, op, nbits, extraData);
    }
}


# endif /* USE_SEC_CONFIG */
