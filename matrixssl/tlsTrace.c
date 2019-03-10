/**
 *      @file    tlsTrace.c
 *      @version $Format:%h%d$
 *
 *      Simple logging and tracing functions for TLS.
 *      These functions should be called via the corresponding psTrace* macros
 *      defined in matrixssllib.h, when USE_SSL_HANDSHAKE_MSG_TRACE and/or
 *      USE_SSL_USE_SSL_INFORMATIONAL_TRACE is off.
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

# ifdef USE_SSL_HANDSHAKE_MSG_TRACE
/*
  This module provides TLS-specific logging functions.*/

#  define TO_STRING_INNER(x) #x
#  define TO_STRING(x) TO_STRING_INNER(x)

/*
  These macros provide the final output.*/
#  define _tlsTrace(x) _psTrace(x)
#  define _tlsTraceInt(x) _psTraceInt(x)
#  define _tlsTraceStr(x, y) _psTraceStr(x, y)

static inline
psBool_t tlsTraceDisabled()
{
    /* Could add a run-time disable switch here, if needed. */
    return PS_FALSE;
}

void tlsTrace(const char *str)
{
    if (tlsTraceDisabled())
    {
        return;
    }

    if (str)
    {
        _tlsTrace(str);
    }
}

void tlsTraceInt(const char *str, int32_t value)
{
    if (tlsTraceDisabled())
    {
        return;
    }

    _psTraceInt(str, value);
}

void tlsTraceStr(const char *str, const char *str2)
{
    if (tlsTraceDisabled())
    {
        return;
    }

    _tlsTraceStr(str, str2);
}

static
void tlsTraceHex(unsigned char *bytes, psSizeL_t numBytes)
{
    psSizeL_t i;

    if (numBytes == 0)
    {
        tlsTrace("(empty)");
    }
    else
    {
        for (i = 0; i < numBytes; i++)
        {
            tlsTraceInt("%.2hhx", bytes[i]);
        }
    }
}

void tlsTraceIndent(psSize_t numSpaces,
        const char *str)
{
    psSize_t i;

#  ifndef TLS_TRACE_DISABLE_INDENT
    for (i = 0; i < numSpaces; i++)
    {
#   ifdef TLS_TRACE_OVERRIDE_INDENT_CHAR
        tlsTrace(TO_STRING(TLS_TRACE_OVERRIDE_INDENT_CHAR));
#   else
        tlsTrace(" ");
#   endif /* TLS_TRACE_OVERRIDE_INDENT_CHAR */
    }
#  endif /* TLS_TRACE_DISABLE_INDENT */

    if (str)
    {
        tlsTrace(str);
    }
}

void tlsTraceErrorIndent(psSize_t indentLevel,
        const char *srcFile,
        int srcLine,
        const char *errorMsg)
{
# ifndef TLS_TRACE_FILE_LINE_AS_PREFIX
    /* srcFile:srcLine as a suffix (if errorMsg does not contain newline)
       or on a separate line (otherwise) has the benefit that then the actual
       errorMsg lines up nicely with previous messages that have the same
       indentLevel.
       Add 1 space before and after parenthesis to allow file:line to be
       easily copied from terminal window. */
    tlsTraceIndent(indentLevel, errorMsg);
    tlsTraceStr(" ( %s:", srcFile);
    tlsTraceInt("%d )\n", srcLine);
# else
    tlsTraceIndent(indentLevel, srcFile);
    tlsTraceInt(":%d ", srcLine);
    tlsTrace(errorMsg);
# endif
}

void tlsTraceError(const char *srcFile,
        int srcLine,
        const char *errorMsg)
{
    tlsTraceErrorIndent(0, srcFile, srcLine, errorMsg);
}

void psPrintHsMsgType(int32_t type, psBool_t addNewline)
{
    switch(type)
    {
    case SSL_HS_HELLO_REQUEST:
        tlsTrace("HELLO_REQUEST");
        break;
    case SSL_HS_CLIENT_HELLO:
        tlsTrace("CLIENT_HELLO");
        break;
    case SSL_HS_SERVER_HELLO:
        tlsTrace("SERVER_HELLO");
        break;
    case SSL_HS_HELLO_VERIFY_REQUEST:
        tlsTrace("HELLO_VERIFY_REQUEST");
        break;
    case SSL_HS_NEW_SESSION_TICKET:
        tlsTrace("NEW_SESSION_TICKET");
        break;
    case SSL_HS_ENCRYPTED_EXTENSION:
        tlsTrace("ENCRYPTED_EXTENSION");
        break;
    case SSL_HS_CERTIFICATE:
        tlsTrace("CERTIFICATE");
        break;
    case SSL_HS_SERVER_KEY_EXCHANGE:
        tlsTrace("SERVER_KEY_EXCHANGE");
        break;
    case SSL_HS_CERTIFICATE_REQUEST:
        tlsTrace("CERTIFICATE_REQUEST");
        break;
    case SSL_HS_SERVER_HELLO_DONE:
        tlsTrace("SERVER_HELLO_DONE");
        break;
    case SSL_HS_CERTIFICATE_VERIFY:
        tlsTrace("CERTIFICATE_VERIFY");
        break;
    case SSL_HS_CLIENT_KEY_EXCHANGE:
        tlsTrace("CLIENT_KEY_EXCHANGE");
        break;
    case SSL_HS_FINISHED:
        tlsTrace("FINISHED");
        break;
    case SSL_HS_CERTIFICATE_STATUS:
        tlsTrace("CERTIFICATE_STATUS");
        break;
    case SSL_HS_EOED:
        tlsTrace("END_OF_EARLY_DATA");
        break;
    default:
        tlsTrace("Unknown HS message type");
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintExtensionType(ssl_t *ssl,
        uint16_t extType,
        psBool_t addNewline)
{
    switch(extType)
    {
    case EXT_SNI:
        tlsTrace("server_name");
        break;
    case EXT_MAX_FRAGMENT_LEN:
        tlsTrace("max_fragment_length");
        break;
    case EXT_TRUSTED_CA_KEYS:
        tlsTrace("trusted_ca_keys");
        break;
    case EXT_TRUNCATED_HMAC:
        tlsTrace("truncated_hamc");
        break;
    case EXT_STATUS_REQUEST:
        tlsTrace("status_request");
        break;
    case EXT_SUPPORTED_GROUPS:
        if (USING_TLS_1_3(ssl))
        {
            tlsTrace("supported_groups");
        }
        else
        {
            tlsTrace("elliptic_curves");
        }
        break;
    case EXT_ELLIPTIC_POINTS:
        tlsTrace("ec_point_formats");
        break;
    case EXT_SIGNATURE_ALGORITHMS:
        tlsTrace("signature_algorithms");
        break;
    case EXT_ALPN:
        tlsTrace("alpn");
        break;
    case EXT_SIGNED_CERTIFICATE_TIMESTAMP:
        tlsTrace("signed_certificate_timestamp");
        break;
    case EXT_EXTENDED_MASTER_SECRET:
        tlsTrace("extended_master_secret");
        break;
    case EXT_SESSION_TICKET:
        tlsTrace("session_ticket");
        break;
    case EXT_KEY_SHARE_PRE_DRAFT_23:
        tlsTrace("key_share (pre-draft 23)");
        break;
    case EXT_PRE_SHARED_KEY:
        tlsTrace("pre_shared_key");
        break;
    case EXT_EARLY_DATA:
        tlsTrace("early_data");
        break;
    case EXT_SUPPORTED_VERSIONS:
        tlsTrace("supported_versions");
        break;
    case EXT_COOKIE:
        tlsTrace("cookie");
        break;
    case EXT_PSK_KEY_EXCHANGE_MODES:
        tlsTrace("psk_key_exchange_modes");
        break;
    case EXT_CERTIFICATE_AUTHORITIES:
        tlsTrace("certificate_authorities");
        break;
    case EXT_OID_FILTERS:
        tlsTrace("oid_filters");
        break;
    case EXT_POST_HANDSHAKE_AUTH:
        tlsTrace("post_handshake_auth");
        break;
    case EXT_SIGNATURE_ALGORITHMS_CERT:
        tlsTrace("signature_algorithms_cert");
        break;
    case EXT_KEY_SHARE:
        tlsTrace("key_share");
        break;
    case EXT_RENEGOTIATION_INFO:
        tlsTrace("renegotiation_info");
        break;
    default:
        tlsTraceInt("Unknown extension type: %hu\n", extType);
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintAlertEncodeInfo(ssl_t *ssl, unsigned char alertType)
{
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        tlsTrace("<<< Server");
    }
    else
    {
        tlsTrace("<<< Client");
    }
    if (alertType == SSL_ALERT_CLOSE_NOTIFY)
    {
        tlsTrace(" creating ALERT (CLOSE_NOTIFY) message\n");
    }
    else
    {
        tlsTrace(" creating ALERT message\n");
        tlsTraceInt("Creating alert: %u\n", (unsigned int)alertType);
    }
}

void psPrintAlertReceiveInfo(ssl_t *ssl, unsigned char alertType)
{
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        tlsTrace(">>> Server");
    }
    else
    {
        tlsTrace(">>> Client");
    }
    tlsTraceInt(" received ALERT %u\n", (unsigned int)alertType);
}

void psPrintHsMessageCreate(ssl_t *ssl, unsigned char hsMsgType)
{
    if (IS_SERVER(ssl))
    {
        tlsTrace("<<< Server creating ");
    }
    else
    {
        tlsTrace("<<< Client creating ");
    }
    if (NGTD_VER(ssl, v_tls_1_3_any))
    {
        tlsTrace("TLS 1.3 ");
    }
    psPrintHsMsgType(hsMsgType, PS_FALSE);
    tlsTrace(" message\n");
}

static
psBool_t isTls13ClientHello(ssl_t *ssl, unsigned char hsMsgType)
{
    if (hsMsgType != SSL_HS_CLIENT_HELLO)
    {
        return PS_FALSE;
    }
    if (NGTD_VER(ssl, v_tls_1_3_any))
    {
        return PS_TRUE;
    }
    if (!USING_TLS_1_3(ssl))
    {
        return PS_FALSE;
    }
    if (!IS_SERVER(ssl))
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}

void psPrintHsMessageParse(ssl_t *ssl, unsigned char hsMsgType)
{
    if (IS_SERVER(ssl))
    {
        tlsTrace(">>> Server parsing ");
    }
    else
    {
        tlsTrace(">>> Client parsing ");
    }
    if (NGTD_VER(ssl, v_tls_1_3_any) ||
            isTls13ClientHello(ssl, hsMsgType))
    {
        tlsTrace("TLS 1.3 ");
    }
    psPrintHsMsgType(hsMsgType, PS_FALSE);
    tlsTrace(" message\n");
}

void psPrintChangeCipherSpecParse(ssl_t *ssl)
{
    if (IS_SERVER(ssl))
    {
        tlsTrace(">>> Server parsing ");
    }
    else
    {
        tlsTrace(">>> Client parsing ");
    }
    tlsTrace("CHANGE_CIPHER_SPEC message\n");
}

void psPrintChangeCipherSpecCreate(ssl_t *ssl)
{
    if (IS_SERVER(ssl))
    {
        tlsTrace("<<< Server creating ");
    }
    else
    {
        tlsTrace("<<< Client creating ");
    }
    tlsTrace("CHANGE_CIPHER_SPEC message\n");
}

/*
  Note: higher indentation after ">>>" than psPrintHsMessageParse,
  so that we get e.g. the following kind of output:
>>> Server parsing CLIENT_HELLO
>>>  Server parsing signature_algorithms extension
>>>  Server parsing extended_master_secret extension
<<< Server creating SERVER_HELLO message

*/
void psPrintExtensionParse(ssl_t *ssl, uint16_t extType)
{
    if (IS_SERVER(ssl))
    {
        tlsTrace(">>>  Server parsing ");
    }
    else
    {
        tlsTrace(">>>  Client parsing ");
    }
    if (NGTD_VER(ssl, v_tls_1_3_any))
    {
        tlsTrace("TLS 1.3 ");
    }
    psPrintExtensionType(ssl, extType, PS_FALSE);
    tlsTrace(" extension\n");
}

void psPrintExtensionCreate(ssl_t *ssl, uint16_t extType)
{
    if (IS_SERVER(ssl))
    {
        tlsTrace(">>>  Server adding ");
    }
    else
    {
        tlsTrace(">>>  Client adding ");
    }
    psPrintExtensionType(ssl, extType, PS_FALSE);
    tlsTrace(" extension\n");
}
# endif /* USE_SSL_HANDSHAKE_MSG_TRACE */

/******************************************************************************/

# ifdef USE_SSL_INFORMATIONAL_TRACE
void psPrintHex(psSize_t indentLevel,
        const char *where,
        unsigned char *bytes,
        psSizeL_t numBytes,
        psBool_t addNewline)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
        indentLevel++;
    }

    tlsTraceHex(bytes, numBytes);

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintSigAlgs(psSize_t indentLevel,
        const char *where,
        uint16_t sigAlgs,
        psBool_t addNewline)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s:\n", where);
        indentLevel++;
    }

    if (sigAlgs & HASH_SIG_MD5_RSA_MASK)
    {
       tlsTraceIndent(indentLevel, "RSA-MD5\n");
    }
    if (sigAlgs & HASH_SIG_SHA1_RSA_MASK)
    {
       tlsTraceIndent(indentLevel, "RSA-SHA1\n");
    }
    if (sigAlgs & HASH_SIG_SHA256_RSA_MASK)
    {
       tlsTraceIndent(indentLevel, "RSA-SHA256\n");
    }
    if (sigAlgs & HASH_SIG_SHA384_RSA_MASK)
    {
       tlsTraceIndent(indentLevel, "RSA-SHA384\n");
    }
    if (sigAlgs & HASH_SIG_SHA512_RSA_MASK)
    {
       tlsTraceIndent(indentLevel, "RSA-SHA512\n");
    }
    if (sigAlgs & HASH_SIG_SHA1_ECDSA_MASK)
    {
       tlsTraceIndent(indentLevel, "ECDSA-SHA1\n");
    }
    if (sigAlgs & HASH_SIG_SHA256_ECDSA_MASK)
    {
       tlsTraceIndent(indentLevel, "ECDSA-SHA256\n");
    }
    if (sigAlgs & HASH_SIG_SHA384_ECDSA_MASK)
    {
       tlsTraceIndent(indentLevel, "ECDSA-SHA384\n");
    }
    if (sigAlgs & HASH_SIG_SHA512_ECDSA_MASK)
    {
       tlsTraceIndent(indentLevel, "ECDSA-SHA512\n");
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintTls13SigAlg(psSize_t indentLevel,
        const char *where,
        uint16_t alg,
        psBool_t addNewline)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
    }

    if (alg == sigalg_rsa_pkcs1_sha256)
    {
       tlsTrace("rsa_pkcs1_sha256");
    }
    else if (alg == sigalg_rsa_pkcs1_sha384)
    {
       tlsTrace("rsa_pkcs1_sha384");
    }
    else if (alg == sigalg_rsa_pkcs1_sha512)
    {
       tlsTrace("rsa_pkcs1_sha512");
    }
    else if (alg == sigalg_ecdsa_secp256r1_sha256)
    {
       tlsTrace("ecdsa_secp256r1_sha256");
    }
    else if (alg == sigalg_ecdsa_secp384r1_sha384)
    {
       tlsTrace("ecdsa_secp384r1_sha384");
    }
    else if (alg == sigalg_ecdsa_secp521r1_sha512)
    {
       tlsTrace("ecdsa_secp521r1_sha512");
    }
    else if (alg == sigalg_rsa_pss_rsae_sha256)
    {
       tlsTrace("rsa_pss_rsae_sha256");
    }
    else if (alg == sigalg_rsa_pss_rsae_sha384)
    {
       tlsTrace("rsa_pss_rsae_sha384");
    }
    else if (alg == sigalg_rsa_pss_rsae_sha512)
    {
       tlsTrace("rsa_pss_rsae_sha512");
    }
    else if (alg == sigalg_ed25519)
    {
       tlsTrace("ed25519");
    }
    else if (alg == sigalg_ed448)
    {
       tlsTrace("ed448");
    }
    else if (alg == sigalg_rsa_pss_pss_sha256)
    {
       tlsTrace("rsa_pss_pss_sha256");
    }
    else if (alg == sigalg_rsa_pss_pss_sha384)
    {
       tlsTrace("rsa_pss_pss_sha384");
    }
    else if (alg == sigalg_rsa_pss_pss_sha512)
    {
       tlsTrace("rsa_pss_pss_sha512");
    }
    else if (alg == sigalg_rsa_pkcs1_sha1)
    {
       tlsTrace("rsa_pkcs1_sha1");
    }
    else if (alg == sigalg_ecdsa_sha1)
    {
       tlsTrace("ecdsa_sha1");
    }
    else
    {
        tlsTraceInt("Unknown signature algorithm: %hu\n", alg);
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintTls13SigAlgList(psSize_t indentLevel,
        const char *where,
        uint16_t *algs,
        psSize_t numAlgs,
        psBool_t addNewline)
{
    psSize_t i;

    if (where)
    {
        tlsTraceIndent(indentLevel, NULL);
        tlsTraceStr("%s :\n", where);
        indentLevel++;
    }

    for (i = 0; i < numAlgs; i++)
    {
        psPrintTls13SigAlg(indentLevel, NULL, algs[i], PS_TRUE);
    }
    tlsTrace("\n");
}

void psPrintVer(psProtocolVersion_t ver)
{
    tlsTrace(VER_TO_STR(VER_GET_RAW(ver)));
}

void psPrintProtocolVersionNew(psSize_t indentLevel,
        const char *where,
        psProtocolVersion_t ver,
        psBool_t addNewline)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
    }

    psPrintVer(ver);

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintProtocolVersionNewWithAttribs(psSize_t indentLevel,
        const char *where,
        psProtocolVersion_t ver,
        psBool_t addNewline)
{
    const char *str;

    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
    }

    str = VER_TO_STR(VER_GET_RAW(ver));
    tlsTrace(str);

    if (ver & v_tls_negotiated)
    {
        tlsTrace(" (negotiated)");
    }
    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintProtocolVersion(psSize_t indentLevel,
        const char *where,
        unsigned char majVer,
        unsigned char minVer,
        psBool_t addNewline)
{
    uint32_t ver;
    const char *str;

    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
    }

    ver = (majVer << 8) | minVer;
    str = ENCODED_VER_TO_STR(ver);
    tlsTrace(str);

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

/* Because ssl->{min,maj}Ver may not contain the actual negotiated
   version when TLS 1.3 has been selected, we need this wrapper.*/
void psPrintNegotiatedProtocolVersion(psSize_t indentLevel,
        const char *where,
        ssl_t *ssl,
        psBool_t addNewline)
{
    psProtocolVersion_t ver;

    ver = GET_ACTV_VER(ssl);
    if (!NGTD(ssl))
    {
        ver = v_undefined;
    }

    psTracePrintProtocolVersionNew(indentLevel,
            where,
            ver,
            PS_TRUE);
}

void psPrintVersionsList(psSize_t indentLevel,
        const char *where,
        psProtocolVersion_t *list,
        psSize_t listLen,
        psBool_t addNewline)
{
    psSize_t i;

    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s :\n", where);
        indentLevel++;
    }

    for (i = 0; i < listLen; i++)
    {
        if (list[i] == 0)
        {
            /* Array is 0-terminated. */
            break;
        }
        else
        {
            psPrintProtocolVersionNew(indentLevel,
                    NULL,
                    list[i],
                    PS_TRUE);
        }
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintSupportedVersionsList(psSize_t indentLevel,
        const char *where,
        ssl_t *ssl,
        psBool_t peer,
        psBool_t addNewline)
{
    if (peer)
    {
# ifdef USE_TLS_1_3
        psPrintVersionsList(indentLevel,
                where,
                ssl->peerSupportedVersionsPriority,
                ssl->peerSupportedVersionsPriorityLen,
                addNewline);
# else
        tlsTrace("psPrintSupportedVersionsList error: " \
                "can only print peer list when using TLS 1.3\n");
        psAssert(PS_FALSE);
# endif
    }
    else
    {
        psPrintVersionsList(indentLevel,
                where,
                ssl->supportedVersionsPriority,
                ssl->supportedVersionsPriorityLen,
                addNewline);
    }
}

void psPrintTls13NamedGroup(psSize_t indentLevel,
        const char *where,
        uint16_t namedGroup,
        psBool_t addNewline)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
    }

    if (namedGroup == 0x0000)
    {
        tlsTrace("unallocated_RESERVED");
    }
    else if (namedGroup >= 0x0001 && namedGroup <= 0x0016)
    {
        tlsTrace("obsolete_RESERVED");
    }
    else if (namedGroup == 0x0017)
    {
        tlsTrace("secp256r1");
    }
    else if (namedGroup == 0x0018)
    {
        tlsTrace("secp384r1");
    }
    else if (namedGroup == 0x0019)
    {
        tlsTrace("secp521r1");
    }
    else if (namedGroup >= 0x001a && namedGroup <= 0x001c)
    {
        tlsTrace("obsolete_RESERVED");
    }
    else if (namedGroup == 0x001d)
    {
        tlsTrace("x25519");
    }
    else if (namedGroup == 0x001e)
    {
        tlsTrace("x448");
    }
    else if (namedGroup == 0x0100)
    {
        tlsTrace("ffdhe2048");
    }
    else if (namedGroup == 0x0101)
    {
        tlsTrace("ffdhe3072");
    }
    else if (namedGroup == 0x0102)
    {
        tlsTrace("ffdhe4096");
    }
    else if (namedGroup == 0x0103)
    {
        tlsTrace("ffdhe6144");
    }
    else if (namedGroup == 0x0104)
    {
        tlsTrace("ffdhe8192");
    }
    else if (namedGroup >= 0x01fc && namedGroup <= 0x1ff)
    {
        tlsTrace("ffdhe_private_use");
    }
    else if (namedGroup >= 0xfe00 && namedGroup <= 0xfeff)
    {
        tlsTrace("ecdhe_private_use");
    }
    else if (namedGroup >= 0xfe01 && namedGroup <= 0xff02)
    {
        tlsTrace("obsolete_RESERVED");
    }
    else
    {
        tlsTrace("unrecognized");
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintTls13NamedGroupList(psSize_t indentLevel,
        const char *where,
        const unsigned char *list,
        psSize_t listLen,
        ssl_t *ssl,
        psBool_t addNewline)
{
    psSize_t i;

    if (list == NULL || (listLen & 0x01))
    {
        return;
    }

    if (where)
    {
        tlsTraceIndent(indentLevel, NULL);
        tlsTraceStr("%s :\n", where);
        indentLevel++;
    }

    if (list == NULL || listLen < 2)
    {
        tlsTrace("Empty NamedGroup or curve list");
    }

    if (listLen > 0)
    {
        for (i = 0; i < listLen; i += 2)
        {
            psPrintTls13NamedGroup(indentLevel,
                    NULL,
                    (uint16_t)((list[i] << 8) + list[i + 1]),
                    PS_TRUE);
        }
    }
}

void psPrintTlsKeys(const char *where,
        ssl_t *ssl,
        psBool_t addNewline)
{
    if (where)
    {
        tlsTraceStr("%s :\n", where);
    }

    psTraceBytes("readMAC",  ssl->sec.readMAC, ssl->deMacSize);
    psTraceBytes("readKey", ssl->sec.readKey, ssl->cipher->keySize);
    psTraceBytes("readIV", ssl->sec.readIV, ssl->cipher->ivSize);
    psTraceBytes("writeMAC",  ssl->sec.writeMAC, ssl->enMacSize);
    psTraceBytes("writeKey", ssl->sec.writeKey, ssl->cipher->keySize);
    psTraceBytes("writeIV", ssl->sec.writeIV, ssl->cipher->ivSize);

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintSslFlags(uint32_t flags)
{
    tlsTrace("SSL flags:\n");
    if (flags & SSL_FLAGS_SERVER)
    {
        tlsTrace(" SSL_FLAGS_SERVER");
    }
    if (flags & SSL_FLAGS_READ_SECURE)
    {
        tlsTrace(" SSL_FLAGS_READ_SECURE");
    }
    if (flags & SSL_FLAGS_WRITE_SECURE)
    {
        tlsTrace(" SSL_FLAGS_WRITE_SECURE");
    }
    if (flags & SSL_FLAGS_RESUMED)
    {
        tlsTrace(" SSL_FLAGS_RESUMED");
    }
    if (flags & SSL_FLAGS_CLOSED)
    {
        tlsTrace(" SSL_FLAGS_CLOSED");
    }
    if (flags & SSL_FLAGS_NEED_ENCODE)
    {
        tlsTrace(" SSL_FLAGS_NEED_ENCODE");
    }
    if (flags & SSL_FLAGS_ERROR)
    {
        tlsTrace(" SSL_FLAGS_ERROR");
    }
    if (flags & SSL_FLAGS_CLIENT_AUTH)
    {
        tlsTrace(" SSL_FLAGS_CLIENT_AUTH");
    }
    if (flags & SSL_FLAGS_ANON_CIPHER)
    {
        tlsTrace(" SSL_FLAGS_ANON_CIPHER");
    }
    if (flags & SSL_FLAGS_FALSE_START)
    {
        tlsTrace(" SSL_FLAGS_FALSE_START");
    }
    if (flags & SSL_FLAGS_SSLV3)
    {
        tlsTrace(" SSL_FLAGS_SSLV3");
    }
    if (flags & SSL_FLAGS_TLS)
    {
        tlsTrace(" SSL_FLAGS_TLS");
    }
    if (flags & SSL_FLAGS_TLS_1_0)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_0");
    }
    if (flags & SSL_FLAGS_TLS_1_1)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_1");
    }
    if (flags & SSL_FLAGS_TLS_1_2)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_2");
    }
    if (flags & SSL_FLAGS_TLS_1_3)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_3");
    }
    if (flags & SSL_FLAGS_TLS_1_3_DRAFT_22)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_3_DRAFT_22");
    }
    if (flags & SSL_FLAGS_TLS_1_3_DRAFT_23)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_3_DRAFT_23");
    }
    if (flags & SSL_FLAGS_TLS_1_3_DRAFT_24)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_3_DRAFT_24");
    }
    if (flags & SSL_FLAGS_TLS_1_3_DRAFT_26)
    {
        tlsTrace(" SSL_FLAGS_TLS_1_3_DRAFT_26");
    }
    if (flags & SSL_FLAGS_DTLS)
    {
        tlsTrace(" SSL_FLAGS_DTLS");
    }
    if (flags & SSL_FLAGS_DHE_WITH_RSA)
    {
        tlsTrace(" SSL_FLAGS_DHE_WITH_RSA");
    }
    if (flags & SSL_FLAGS_DHE_WITH_DSA)
    {
        tlsTrace(" SSL_FLAGS_DHE_WITH_DSA");
    }
    if (flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
        tlsTrace(" SSL_FLAGS_DHE_KEY_EXCH");
    }
    if (flags & SSL_FLAGS_PSK_CIPHER)
    {
        tlsTrace(" SSL_FLAGS_PSK_CIPHER");
    }
    if (flags & SSL_FLAGS_ECC_CIPHER)
    {
        tlsTrace(" SSL_FLAGS_ECC_CIPHER");
    }
    if (flags & SSL_FLAGS_AEAD_W)
    {
        tlsTrace(" SSL_FLAGS_AEAD_W");
    }
    if (flags & SSL_FLAGS_AEAD_R)
    {
        tlsTrace(" SSL_FLAGS_AEAD_R");
    }
    if (flags & SSL_FLAGS_NONCE_W)
    {
        tlsTrace(" SSL_FLAGS_NONCE_W");
    }
    if (flags & SSL_FLAGS_NONCE_R)
    {
        tlsTrace(" SSL_FLAGS_NONCE_R");
    }
    if (flags & SSL_FLAGS_HTTP2)
    {
        tlsTrace(" SSL_FLAGS_HTTP2");
    }
# ifdef USE_EAP_FAST
    if (flags & SSL_FLAGS_EAP_FAST)
    {
        tlsTrace(" SSL_FLAGS_EAP_FAST");
    }
# endif

    tlsTrace("\n");

}


void psPrintHsState(uint8_t type, psBool_t addNewline)
{
    switch (type)
    {
    case SSL_HS_TLS_1_3_START:
        tlsTrace("SSL_HS_TLS_1_3_START");
        break;
    case SSL_HS_TLS_1_3_RECVD_CH:
        tlsTrace("SSL_HS_TLS_1_3_RECVD_CH");
        break;
    case SSL_HS_TLS_1_3_NEGOTIATED:
        tlsTrace("SSL_HS_TLS_1_3_NEGOTIATED");
        break;
    case SSL_HS_TLS_1_3_WAIT_FLIGHT_2:
        tlsTrace("SSL_HS_TLS_1_3_WAIT_FLIGHT_2");
        break;
    case SSL_HS_TLS_1_3_WAIT_EOED:
        tlsTrace("SSL_HS_TLS_1_3_WAIT_EOED");
        break;
    case SSL_HS_TLS_1_3_WAIT_CERT:
        tlsTrace("SSL_HS_TLS_1_3_WAIT_CERT");
        break;
    case SSL_HS_TLS_1_3_WAIT_CV:
        tlsTrace("SSL_HS_TLS_1_3_WAIT_CV");
        break;
    case SSL_HS_TLS_1_3_WAIT_FINISHED:
        tlsTrace("SSL_HS_TLS_1_3_WAIT_FINISHED");
        break;
    case SSL_HS_HELLO_REQUEST:
        tlsTrace("SSL_HS_HELLO_REQUEST");
        break;
    case SSL_HS_CLIENT_HELLO:
        tlsTrace("SSL_HS_CLIENT_HELLO");
        break;
    case SSL_HS_SERVER_HELLO:
        tlsTrace("SSL_HS_SERVER_HELLO");
        break;
    case SSL_HS_HELLO_VERIFY_REQUEST:
        tlsTrace("SSL_HS_HELLO_VERIFY_REQUEST");
        break;
    case SSL_HS_NEW_SESSION_TICKET:
        tlsTrace("SSL_HS_NEW_SESSION_TICKET");
        break;
    case SSL_HS_ENCRYPTED_EXTENSION:
        tlsTrace("SSL_HS_ENCRYPTED_EXTENSION");
        break;
    case SSL_HS_CERTIFICATE:
        tlsTrace("SSL_HS_CERTIFICATE");
        break;
    case SSL_HS_SERVER_KEY_EXCHANGE:
        tlsTrace("SSL_HS_SERVER_KEY_EXCHANGE");
        break;
    case SSL_HS_CERTIFICATE_REQUEST:
        tlsTrace("SSL_HS_CERTIFICATE_REQUEST");
        break;
    case SSL_HS_SERVER_HELLO_DONE:
        tlsTrace("SSL_HS_SERVER_HELLO_DONE");
        break;
    case SSL_HS_CERTIFICATE_VERIFY:
        tlsTrace("SSL_HS_CERTIFICATE_VERIFY");
        break;
    case SSL_HS_CLIENT_KEY_EXCHANGE:
        tlsTrace("SSL_HS_CLIENT_KEY_EXCHANGE");
        break;
    case SSL_HS_FINISHED:
        tlsTrace("SSL_HS_FINISHED");
        break;
    case SSL_HS_CERTIFICATE_STATUS:
        tlsTrace("SSL_HS_CERTIFICATE_STATUS");
        break;
    default:
        tlsTrace("Unknown state\n");
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintRecordType(unsigned char type, psBool_t isInnerType,
        psBool_t addNewline)
{
    if (isInnerType)
    {
        tlsTrace("  Record.inner_type: ");
    }
    else
    {
        tlsTrace("  Record.type: ");
    }

    switch (type)
    {
    case SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC:
        tlsTrace("change_cipher_spec");
        break;
    case SSL_RECORD_TYPE_ALERT:
        tlsTrace("alert");
        break;
    case SSL_RECORD_TYPE_HANDSHAKE:
        tlsTrace("handshake");
        break;
    case SSL_RECORD_TYPE_APPLICATION_DATA:
        tlsTrace("application_data");
        break;
    default:
        tlsTraceInt("unknown/unsupported: %u", (unsigned int)type);
        break;
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintRecordHeader(sslRec_t *rec, psBool_t addNewline)
{
    tlsTrace("Record header:\n");
    psPrintRecordType(rec->type, PS_FALSE, PS_TRUE);
    tlsTrace("  Record.legacy_version: ");
    psPrintProtocolVersion(0,
            NULL,
            rec->majVer,
            rec->minVer,
            PS_TRUE);
    tlsTraceInt("  Record.length: %hu", rec->len);

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintHandshakeHeader(unsigned char type,
        uint32_t len,
        psBool_t addNewline)
{
    tlsTrace("Handshake header:\n");
    tlsTrace("  Type: ");
    psPrintHsMsgType(type, PS_TRUE);
    tlsTraceInt("  Length: %u\n", len);

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

# ifdef USE_TLS_1_3
/* Print information about current flight that is being encoded. */
void psPrintCurrentFlight(ssl_t *ssl)
{
    flightEncode_t *msg = ssl->flightEncode;
    int32 rc, flightLen = 0;
    unsigned char trHash[MAX_TLS_1_3_HASH_SIZE];
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    int32_t hmacLen = psGetOutputBlockLength(hmacAlg);
    psBool_t isLastMsg, isHelloRetryRequest;

    if (msg == NULL || hmacLen < 0)
    {
        return;
    }
    tlsTrace("Flight being encoded:\n");
    while (msg)
    {
        tlsTrace(" Record type: ");
        switch(msg->type)
        {
        case SSL_RECORD_TYPE_ALERT:
            tlsTrace("Alert (21) ");
            break;
        case SSL_RECORD_TYPE_HANDSHAKE:
            tlsTraceInt("Handshake (22) (Frag %d) ", msg->fragId);
            break;
        case SSL_RECORD_TYPE_APPLICATION_DATA:
            tlsTrace("Application (23) ");
            break;
        }

        isLastMsg = msg->next == NULL ? PS_TRUE : PS_FALSE;

        isHelloRetryRequest = PS_FALSE;

        if (msg->hsMsg == SSL_HS_SERVER_HELLO &&
                ssl->tls13IncorrectDheKeyShare)
        {
            isHelloRetryRequest = PS_TRUE;
        }
        psPrintHsMsgType(msg->hsMsg, PS_FALSE);

        if (isHelloRetryRequest)
        {
            tlsTrace(" (HelloRetryRequest)");
        }
       tlsTraceInt(" (%d bytes)", msg->len);

        if (isLastMsg)
        {
            tlsTrace (" <-- New");
        }
        tlsTrace("\n");

        flightLen += msg->len;
        msg = msg->next;
    }

    tlsTraceInt("Total flight length: %d\n", flightLen);

    if (hmacAlg != 0)
    {
        rc = tls13TranscriptHashSnapshot(ssl, trHash);
        psAssert(rc == PS_SUCCESS);
        psTraceBytes("Transcript-Hash of flight", trHash, hmacLen);
    }
}
# endif

void psPrintCertSubject(psSize_t indentLevel,
        ssl_t *ssl,
        psX509Cert_t *cert,
        psSize_t indexInChain)
{
# ifdef USE_FULL_CERT_PARSE
    char *dn;
    size_t dn_len;

    tlsTraceIndent(indentLevel, NULL);

    if (psX509GetOnelineDN(&cert->subject, &dn, &dn_len) < 0)
    {
        psAssert(0);
    }
    tlsTraceInt("Cert #%d: ", indexInChain);
    tlsTraceStr("%s\n", dn);
    psFree(dn, NULL);
# endif
}

void psPrintPskKeyExchangeMode(psSize_t indentLevel,
        const char *where,
        psk_key_exchange_mode_e mode,
        psBool_t addNewLine)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
    }

    if (mode == psk_keyex_mode_psk_ke)
    {
        tlsTrace("psk_ke");
    }
    else if (mode == psk_keyex_mode_psk_dhe_ke)
    {
        tlsTrace("psk_dhe_ke");
    }
    else if (mode == psk_keyex_mode_none)
    {
        tlsTrace("non-PSK");
    }
    else
    {
        tlsTrace("unknown");
    }

    if (addNewLine)
    {
        tlsTrace("\n");
    }
}

void psPrintTranscriptHashUpdate(ssl_t *ssl,
        unsigned char *in,
        psSizeL_t inLen,
        int32_t hashAlg)
{
    if (IS_SERVER(ssl))
    {
        tlsTrace("Server ");
    }
    else
    {
        tlsTrace("Client ");
    }
    if (hashAlg == OID_SHA384_ALG)
    {
        tlsTrace("SHA-384:");
    }
    else if (hashAlg == OID_SHA256_ALG)
    {
        tlsTrace("SHA-256:");
    }
    else
    {
        tlsTrace("Unknown digest:");
    }
    tlsTrace(":\n");
    psTraceBytes("Tr-Hash input", in, inLen);
}

void psPrintCiphersuiteName(psSize_t indentLevel,
        const char *where,
        uint16_t cipherId,
        psBool_t addNewline)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
    }

    switch (cipherId)
    {
    case SSL_RSA_WITH_NULL_MD5:
        tlsTrace("SSL_RSA_WITH_NULL_MD5");
        break;
    case SSL_RSA_WITH_NULL_SHA:
        tlsTrace("SSL_RSA_WITH_NULL_SHA");
        break;
    case SSL_RSA_WITH_RC4_128_MD5:
        tlsTrace("SSL_RSA_WITH_RC4_128_MD5");
        break;
    case SSL_RSA_WITH_RC4_128_SHA:
        tlsTrace("SSL_RSA_WITH_RC4_128_SHA");
        break;
    case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
        tlsTrace("SSL_RSA_WITH_3DES_EDE_CBC_SHA");
        break;
    case TLS_RSA_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_RSA_WITH_AES_128_CBC_SHA");
        break;
    case TLS_RSA_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_RSA_WITH_AES_256_CBC_SHA");
        break;
    case SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        tlsTrace("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
        break;
    case SSL_DH_anon_WITH_RC4_128_MD5:
        tlsTrace("SSL_DH_anon_WITH_RC4_128_MD5");
        break;
    case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
        tlsTrace("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA");
        break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
        break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        tlsTrace("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
        break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        tlsTrace("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        break;
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_DH_anon_WITH_AES_128_CBC_SHA");
        break;
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_DH_anon_WITH_AES_256_CBC_SHA");
        break;
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
        tlsTrace("TLS_RSA_WITH_AES_128_CBC_SHA256");
        break;
    case TLS_RSA_WITH_AES_256_CBC_SHA256:
        tlsTrace("TLS_RSA_WITH_AES_256_CBC_SHA256");
        break;
    case TLS_RSA_WITH_SEED_CBC_SHA:
        tlsTrace("TLS_RSA_WITH_SEED_CBC_SHA");
        break;
    case TLS_RSA_WITH_IDEA_CBC_SHA:
        tlsTrace("TLS_RSA_WITH_IDEA_CBC_SHA");
        break;
    case TLS_PSK_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_PSK_WITH_AES_128_CBC_SHA");
        break;
    case TLS_PSK_WITH_AES_128_CBC_SHA256:
        tlsTrace("TLS_PSK_WITH_AES_128_CBC_SHA256");
        break;
    case TLS_PSK_WITH_AES_256_CBC_SHA384:
        tlsTrace("TLS_PSK_WITH_AES_256_CBC_SHA384");
        break;
    case TLS_PSK_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_PSK_WITH_AES_256_CBC_SHA");
        break;
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_DHE_PSK_WITH_AES_128_CBC_SHA");
        break;
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_DHE_PSK_WITH_AES_256_CBC_SHA");
        break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
        break;
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
        break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        break;
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        break;
    case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        tlsTrace("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
        break;
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        tlsTrace("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        break;
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        tlsTrace("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        break;
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        break;
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        tlsTrace("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        break;
    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        tlsTrace("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        break;
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        tlsTrace("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
        break;
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        tlsTrace("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
        break;
    case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        tlsTrace("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256");
        break;
    case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        tlsTrace("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384");
        break;
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        tlsTrace("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
        break;
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        tlsTrace("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384");
        break;
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        tlsTrace("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
        break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        tlsTrace("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        tlsTrace("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        tlsTrace("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
        break;
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        tlsTrace("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
        break;
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
        tlsTrace("TLS_RSA_WITH_AES_128_GCM_SHA256");
        break;
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
        tlsTrace("TLS_RSA_WITH_AES_256_GCM_SHA384");
        break;
    case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
        tlsTrace("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
        break;
    case TLS_FALLBACK_SCSV:
        tlsTrace("TLS_FALLBACK_SCSV");
        break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        tlsTrace("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        tlsTrace("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        break;
    case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        tlsTrace("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        break;
    case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        tlsTrace("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
        break;
    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        tlsTrace("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        break;
    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        tlsTrace("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        break;
    case TLS_AES_128_GCM_SHA256:
        tlsTrace("TLS_AES_128_GCM_SHA256");
        break;
    case TLS_AES_256_GCM_SHA384:
        tlsTrace("TLS_AES_256_GCM_SHA384");
        break;
    case TLS_CHACHA20_POLY1305_SHA256:
        tlsTrace("TLS_CHACHA20_POLY1305_SHA256");
        break;
    case TLS_AES_128_CCM_SHA_256:
        tlsTrace("TLS_AES_128_CCM_SHA_256");
        break;
    case TLS_AES_128_CCM_8_SHA256:
        tlsTrace("TLS_AES_128_CCM_8_SHA_256");
        break;
    default:
        tlsTraceInt("Unknown ciphersuite: %d", cipherId);
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintEncodedCipherList(psSize_t indentLevel,
        const char *where,
        const unsigned char *cipherList,
        psSize_t cipherListLen,
        psBool_t addNewline)
{
    psSize_t i;

    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s:\n", where);
        indentLevel++;
    }

    if (cipherList == NULL || cipherListLen < 2)
    {
        tlsTrace("Empty cipher list");
    }
    else
    {
        for (i = 0; i < cipherListLen; i += 2)
        {
            psPrintCiphersuiteName(indentLevel,
                    NULL,
                    (uint16_t)((cipherList[i] << 8) + cipherList[i+1]),
                    PS_TRUE);
        }
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintCipherList(psSize_t indentLevel,
        const char *where,
        const psCipher16_t *cipherList,
        psSize_t cipherListLen,
        psBool_t addNewline)
{
    psSize_t i;

    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s:\n", where);
        indentLevel++;
    }

    if (cipherList == NULL || cipherListLen == 0)
    {
        tlsTrace("Empty cipher list");
    }
    else
    {
        for (i = 0; i < cipherListLen; i++)
        {
            psPrintCiphersuiteName(indentLevel,
                    NULL,
                    (uint16_t)cipherList[i],
                    PS_TRUE);
        }
    }

    if (addNewline)
    {
        tlsTrace("\n");
    }
}

void psPrintPubKeyTypeAndSize(ssl_t *ssl,
        psPubKey_t *authKey)
{
    switch(authKey->type)
    {
    case PS_RSA:
        tlsTrace("RSA");
# ifdef USE_RSA
        tlsTraceInt(" (%u-bit)\n", authKey->key.rsa.size*8);
# endif /* USE_RSA */
        break;
    case PS_ECC:
        tlsTrace("ECDSA");
# ifdef USE_ECC
        tlsTraceStr(" (%s)\n", authKey->key.ecc.curve->name);
# endif /* USE_ECC */
        break;
    case PS_DSA:
        tlsTrace("DSA\n");
        break;
    case PS_ED25519:
        tlsTrace("Ed25519\n");
        break;
    default:
        tlsTraceInt("Unknown/unsupported key type: %hhu\n", authKey->type);
    }
}

static
void psPrintPubKeyTypeAndSizeRaw(ssl_t *ssl,
        uint8_t keyType,
        psSize_t keyNBits,
        psBool_t eccIsEcdh)
{
    switch(keyType)
    {
    case PS_RSA:
        tlsTrace("RSA");
        break;
    case PS_ECC:
        if (eccIsEcdh)
        {
            tlsTrace("ECDHE");
        }
        else
        {
            tlsTrace("ECDSA");
        }
        if (keyNBits == 528)
        {
            keyNBits = 521; /* Kludge. */
        }
        break;
    case PS_DH:
        tlsTrace("DHE");
        break;
    case PS_DSA:
        tlsTrace("DSA\n");
        break;
    case PS_X25519:
        tlsTrace("X25519\n");
        break;
    case PS_ED25519:
        tlsTrace("Ed25519\n");
        break;
    default:
        tlsTraceInt("Unknown/unsupported key type: %hhu", keyType);
    }

    tlsTraceInt(" (%hu-bit)\n", keyNBits);
}

/* Print out information about a completed handshake. */
void matrixSslPrintHSDetails(ssl_t *ssl)
{
    if (ssl->hsState == SSL_HS_DONE)
    {
        tlsTrace("\n");
        psTracePrintProtocolVersionNew(INDENT_CONN_ESTABLISHED,
                NULL, GET_ACTV_VER(ssl), PS_FALSE);
        tlsTrace(" connection established: ");
        psTracePrintCiphersuiteName(INDENT_CONN_ESTABLISHED,
                NULL, ssl->cipher->ident, PS_TRUE);

        if (IS_SERVER(ssl))
        {
            tlsTrace("  MatrixSSL server\n");
        }
        else
        {
            tlsTrace("  MatrixSSL client\n");
        }
        if (RESUMED_HANDSHAKE(ssl))
        {
            tlsTrace("  Resumed session\n");
        }
        else
        {
            tlsTrace("  New session\n");
        }
# ifdef USE_TLS_1_3
        if (NGTD_VER(ssl, v_tls_1_3_any))
        {

            if (ssl->sec.tls13UsingPsk)
            {
                if (ssl->sec.tls13ChosenPskMode == psk_keyex_mode_psk_ke)
                {
                    tlsTrace(" Keyex mode: PSK only\n");
                }
                else
                {
                    tlsTrace("  Keyex mode: PSK with (EC)DHE\n");
                    tlsTrace("  Group: ");
                    psTracePrintTls13NamedGroup(INDENT_CONN_ESTABLISHED,
                            NULL,
                            ssl->tls13NegotiatedGroup,
                            PS_TRUE);
                }
            }
            else
            {
                tlsTrace("  Keyex mode: (EC)DHE\n");
                tlsTrace("  Keyex group: ");
                psTracePrintTls13NamedGroup(INDENT_CONN_ESTABLISHED,
                        NULL,
                        ssl->tls13NegotiatedGroup,
                        PS_TRUE);
            }
            if (!ssl->sec.tls13UsingPsk)
            {
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
                if (ssl->sec.tls13CvSigAlg != 0)
                {
                    if (IS_SERVER(ssl))
                    {
                        tlsTrace("  Server sig alg: ");
                    }
                    else
                    {
                        tlsTrace("  Client sig alg: ");
                    }
                    psTracePrintTls13SigAlg(INDENT_CONN_ESTABLISHED,
                            NULL,
                            ssl->sec.tls13CvSigAlg,
                            PS_TRUE);
                    if (IS_SERVER(ssl))
                    {
                        tlsTrace("  Server key: ");
                    }
                    else
                    {
                        tlsTrace("  Client key: ");
                    }
                    psTracePrintPubKeyTypeAndSize(ssl,
                            &ssl->keys->identity->privKey);
                }
                if (ssl->sec.tls13PeerCvSigAlg != 0)
                {
                    if (IS_SERVER(ssl))
                    {
                        tlsTrace("  Client sig alg: ");
                    }
                    else
                    {
                        tlsTrace("  Server sig alg: ");
                    }
                    psTracePrintTls13SigAlg(INDENT_CONN_ESTABLISHED,
                            NULL,
                            ssl->sec.tls13PeerCvSigAlg,
                            PS_TRUE);
#   ifdef USE_CERT_PARSE
                    if (IS_SERVER(ssl))
                    {
                        tlsTrace("  Client key: ");
                    }
                    else
                    {
                        tlsTrace("  Server key: ");
                    }
                    psTracePrintPubKeyTypeAndSize(ssl,
                            &ssl->sec.cert->publicKey);
#   endif /* USE_CERT_PARSE */
                }
                else
                {
                    if (IS_SERVER(ssl))
                    {
                        tlsTrace("  No client authentication\n");
                    }
                }
#  endif /* USE_ONLY_PSK_CIPHER_SUITE */
            }
        } /* endif(TLS 1.3) */
# endif
# ifndef USE_ONLY_PSK_CIPHERSUITE
        if (!NGTD_VER(ssl, v_tls_1_3_any))
        {
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                tlsTrace("  Client authenticated\n");
            }
            else
            {
                tlsTrace("  No client authentication\n");
            }
            if (IS_SERVER(ssl))
            {
                if (ssl->keys && ssl->chosenIdentity)
                {
                    tlsTrace("  Server key: ");
                    psTracePrintPubKeyTypeAndSize(ssl,
                            &ssl->chosenIdentity->privKey);
                }
                if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
                {
                    tlsTrace("  Client key: ");
                    psPrintPubKeyTypeAndSizeRaw(ssl,
                            ssl->peerAuthKeyType,
                            ssl->peerAuthKeyNBits,
                            PS_FALSE);
                }
            }
            else /* We are client. */
            {
                if ((ssl->flags & SSL_FLAGS_CLIENT_AUTH) && ssl->chosenIdentity)
                {
                    tlsTrace("  Client key: ");
                    psTracePrintPubKeyTypeAndSize(ssl,
                            &ssl->chosenIdentity->privKey);
                }
                tlsTrace("  Server key: ");
                psPrintPubKeyTypeAndSizeRaw(ssl,
                        ssl->peerAuthKeyType,
                        ssl->peerAuthKeyNBits,
                        PS_FALSE);
            }
            tlsTrace("  Key exchange: ");
            if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
            {
                tlsTrace("PSK\n");
            }
            else
            {
                /* We are not using PSK and we only filled
                   ssl->peerKeyExKeyType if we used (EC)DH. */
                if (ssl->peerKeyExKeyType == 0)
                {
                    tlsTrace("RSA key transport\n");
                }
                else
                {
                    psPrintPubKeyTypeAndSizeRaw(ssl,
                            ssl->peerKeyExKeyType,
                            ssl->peerKeyExKeyNBits,
                            PS_TRUE);
                }
            }
        }
# endif
    }

    return;
}

void psPrintServerName(psSize_t indentLevel,
        const char *where,
        const char *serverName,
        psBool_t addNewline)
{
    tlsTraceIndent(indentLevel, NULL);

    if (where)
    {
        tlsTraceStr("%s: ", where);
        indentLevel++;
    }

    tlsTraceStr("%s", serverName);

    if (addNewline)
    {
        tlsTrace("\n");
    }
}
# endif /* USE_SSL_INFORMATIONAL_TRACE */


/******************************************************************************/
