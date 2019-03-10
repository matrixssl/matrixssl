/**
 *      @file    matrixssllib_sec_config.h
 *      @version $Format:%h%d$
 *
 *      Internal header file used for the MatrixSSL implementation.
 *      Only modifiers of the library should be intersted in this file.
 *      This file contains run-time security configuration related macros
 *      and constants.
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

#ifndef _h_MATRIXSSLLIB_SEC_CONFIG
# define _h_MATRIXSSLLIB_SEC_CONFIG

# ifdef USE_SEC_CONFIG

/** Run-time security configuration parameters. This struct is used by
    MatrixSSL's default security callback implementation. */
typedef struct {
  /* Minimums. */
  psSize_t min_symmetric_key_bits;
  psSize_t min_rsa_bits; /** Key transport + sig + ver */
  psSize_t min_rsa_verify_bits; /** Sig ver only. */
  psSize_t min_dh_key_bits;
  psSize_t min_dh_group_bits;
  psSize_t min_ec_curve_bits; /** ECDH + sig + ver. */
  psSize_t min_ec_verify_curve_bits; /** Sig ver only. */
  psSize_t min_hmac_bits;
  psSize_t min_signature_hash_bits; /** Sig + ver. */
  psSize_t min_signature_verify_hash_bits; /** Sig ver only. */

  /* Allowed/disallowed operations. */
  psBool_t allow_pkcs1_sigs_in_handshake;
  psBool_t allow_pkcs1_sigs_in_certs;
  psBool_t allow_rsa_key_transport;
  /** Require that hash alg used in sig must curve size. For example,
     SHA-256 is required with P-256. In TLS 1.3, this is always
     required. This setting applies only to <1.3.*/
  psBool_t require_sig_hash_group_match;
  psProtocolVersion_t min_tls_version;
  /* + lots more. The idea is that the user will not need
  to touch these, but use one of the pre-defined security
  levels below. */
} psSecConfig_t;

# define SECOP_TO_STR(op)                                               \
    (op == secop_undefined) ? "secop_undefined" :                       \
    (op == secop_symmetric_encrypt) ? "secop_symmetric_encrypt" :       \
    (op == secop_hmac) ? "secop_hmac" :                                 \
    (op == secop_hash_for_sig) ? "secop_hash_for_sig" :                 \
    (op == secop_rsa_encrypt) ? "secop_rsa_encrypt" :                   \
    (op == secop_rsa_decrypt) ? "secop_rsa_decrypt" :                   \
    (op == secop_rsa_sign) ? "secop_rsa_sign" :                         \
    (op == secop_rsa_verify) ? "secop_rsa_verify" :                     \
    (op == secop_rsa_load_key) ? "secop_rsa_load_key" :                 \
    (op == secop_ecdsa_load_key) ? "secop_ecdsa_load_key" :             \
    (op == secop_ecdsa_sign) ? "secop_ecdsa_sign" :                     \
    (op == secop_ecdsa_verify) ? "secop_ecdsa_verify" :                 \
    (op == secop_dh_import_pub) ? "secop_dh_import_pub" :               \
    (op == secop_ecdh_import_pub) ? "secop_ecdh_import_pub" :           \
    (op == secop_proto_version_check) ? "secop_proto_version_check" :   \
    (op == secop_sigalg_check) ? "secop_sigalg_check" :                 \
    (op == secop_cipher_check) ? "secop_cipher_check" :                 \
    "Unknown/unsupported security operation"

# define SECPROFILE_TO_STR(sp)                                          \
    (sp == secprofile_default) ? "secprofile_default" :                 \
    (sp == secprofile_wpa3_1_0_enterprise_192) ? "wpa3_1_0_enterprise_192" : \
    "Unknown/unsupported security profile"

psRes_t matrixSslCallSecurityCallback(ssl_t *ssl,
        psSecOperation_t op,
        psSizeL_t nbits,
        void *extraData);

# endif /* USE_SEC_CONFIG */
#endif /* _h_MATRIXSSLLIB_SEC_CONFIG */
