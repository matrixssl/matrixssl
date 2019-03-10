/**
 *      @file    tls13DecodeExt.c
 *      @version $Format:%h%d$
 *
 *      Functions for decoding TLS 1.3 extensions
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

# include "matrixsslImpl.h"

# ifdef USE_TLS_1_3

#  ifndef DEBUG_TLS_1_3_DECODE_EXTENSIONS
/* #   define DEBUG_TLS_1_3_DECODE_EXTENSIONS */
#  endif
#  ifdef DEBUG_TLS_1_3_ENCODE_EXTENSIONS
#   warning "DEBUG_TLS_1_3_DECODE_EXTENSIONS will leak secrets into logs!"
#  endif

static
psBool_t tls13WeRecognizeExtension(uint16_t extType)
{
    switch (extType)
    {
    case EXT_SERVER_NAME:
    case EXT_MAX_FRAGMENT_LEN:
    case EXT_TRUSTED_CA_KEYS:
    case EXT_TRUNCATED_HMAC:
    case EXT_STATUS_REQUEST:
    case EXT_SUPPORTED_GROUPS:
    case EXT_ELLIPTIC_POINTS:
    case EXT_SIGNATURE_ALGORITHMS:
    case EXT_ALPN:
    case EXT_SIGNED_CERTIFICATE_TIMESTAMP:
    case EXT_EXTENDED_MASTER_SECRET:
    case EXT_SESSION_TICKET:
    case EXT_KEY_SHARE_PRE_DRAFT_23:
    case EXT_PRE_SHARED_KEY:
    case EXT_EARLY_DATA:
    case EXT_SUPPORTED_VERSIONS:
    case EXT_COOKIE:
    case EXT_PSK_KEY_EXCHANGE_MODES:
    case EXT_CERTIFICATE_AUTHORITIES:
    case EXT_OID_FILTERS:
    case EXT_POST_HANDSHAKE_AUTH:
    case EXT_SIGNATURE_ALGORITHMS_CERT:
    case EXT_KEY_SHARE:
    case EXT_RENEGOTIATION_INFO:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }
}

psBool_t tls13ExtensionAllowedInMessage(ssl_t *ssl,
        uint16_t extType,
        unsigned char hsMsgType)
{
    if (!tls13WeRecognizeExtension(extType))
    {
        /* Unrecognized extensions MUST be ignored regardless
           of where they appear. */
        return PS_TRUE;
    }
    /* We recognize extType. */

    /* Based on table in section 4.2. of draft 24. */
    switch (hsMsgType)
    {
    case SSL_HS_CLIENT_HELLO:
        /* All extensions allowed in CH, except oid_filters. */
        if (extType == EXT_OID_FILTERS)
        {
            return PS_FALSE;
        }
        break;
    case SSL_HS_SERVER_HELLO:
        /* Cookie only allowed in HRR. */
        if (extType == EXT_COOKIE &&
                !ssl->tls13IncorrectDheKeyShare)
        {
            return PS_FALSE;
        }
        if (extType != EXT_KEY_SHARE &&
                extType != EXT_KEY_SHARE_PRE_DRAFT_23 &&
                extType != EXT_PRE_SHARED_KEY &&
                extType != EXT_SUPPORTED_VERSIONS &&
                extType != EXT_COOKIE)
        {
            return PS_FALSE;
        }
        break;
    case SSL_HS_ENCRYPTED_EXTENSION:
        if (extType != EXT_SERVER_NAME &&
                extType != EXT_MAX_FRAGMENT_LEN &&
                extType != EXT_SUPPORTED_GROUPS &&
                extType != EXT_ALPN &&
                extType != EXT_EARLY_DATA)
        {
            return PS_FALSE;
        }
        break;
    case SSL_HS_NEW_SESSION_TICKET:
        if (extType != EXT_EARLY_DATA)
        {
            return PS_FALSE;
        }
        break;
    case SSL_HS_CERTIFICATE:
        if (extType != EXT_STATUS_REQUEST)
        {
            return PS_FALSE;
        }
        break;
    default:
        psTraceErrr("Error: no extensions allowed in ");
        psTracePrintHsMsgType(hsMsgType, PS_TRUE);
    }

    return PS_TRUE;
}

# if defined(USE_IDENTITY_CERTIFICATES) && defined(USE_OCSP_RESPONSE)
int32_t tls13ParseStatusRequest(ssl_t *ssl,
        psParseBuf_t *extBuf)
{
    unsigned char type = 0;
    unsigned char *resp;
    psSizeL_t respLen;
    psOcspResponse_t ocspResp;
    psX509Cert_t *cert;
    int32_t rc;

    psTracePrintExtensionParse(ssl, EXT_STATUS_REQUEST);

    if (IS_SERVER(ssl))
    {
        /*
          Server parses the client request:

          struct {
            CertificateStatusType status_type = ocsp(1);
            ResponderID responder_id_list<0..2^16-1>;
            Extensions  request_extensions;
          } CertificateStatusRequest;

          Currently ignoring the request contents.
        */
        ssl->extFlags.status_request = 1;
        return PS_SUCCESS;
    }
    else
    {
        /*
          Client parses the server response:

          struct {
            CertificateStatusType status_type;
            select (status_type) {
              case ocsp: OCSPResponse;
            } response;
          } CertificateStatus;
        */

        if (ssl->keys == NULL || ssl->keys->CAcerts == NULL || ssl->sec.cert == NULL)
        {
            goto out_illegal_parameter;
        }

        /* We are currently parsing the extensions of the certificate
           we parsed last. So the revocation information concerns
           the last parsed certificate. */
        cert = ssl->sec.cert;
        while (cert->next)
        {
            cert = cert->next;
        }

        if (!psParseOctet(extBuf, &type))
        {
            goto out_decode_error;
        }
        if (type != 0x01)
        {
            psTraceErrr("Invalid status_type in status_request\n");
            goto out_illegal_parameter;
        }

        /* opaque OCSPResponse<1..2^24-1>; */
        rc = psParseBufParseTlsVector(extBuf,
                1, (1 << 24) - 1,
                &respLen);
        if (rc < 0)
        {
            psTraceErrr("Malformed status_request extension\n");
            goto out_decode_error;
        }
        resp = extBuf->buf.start;

        /* Parse and validate the response. */
        rc = psOcspParseResponse(ssl->hsPool,
                respLen,
                &resp,
                resp + respLen,
                &ocspResp);
        if (rc < 0)
        {
            psTraceErrr("Unable to parse OCSPResponse\n");
            goto out_decode_error;
        }
        rc = psOcspResponseValidateOld(ssl->hsPool,
                ssl->keys->CAcerts,
                cert,
                &ocspResp);
        if (rc < 0)
        {
            psTraceErrr("Unable to validate OCSPResponse\n");
            psX509FreeCert(ocspResp.OCSPResponseCert);
            goto out_bad_certificate_status_response;
        }
        psTraceInfo("OCSP response OK\n");
        psX509FreeCert(ocspResp.OCSPResponseCert);
    }

    return PS_SUCCESS;

out_illegal_parameter:
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
out_decode_error:
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_bad_certificate_status_response:
    ssl->err = SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE;
    return MATRIXSSL_ERROR;
}
# endif /* USE_IDENTITY_CERTIFICATES && USE_OCSP_RESPONSE */

/*
  Parses a single extension:
   struct {
       ExtensionType extension_type;
       opaque extension_data<0..2^16-1>;
   } Extension;
*/
int32_t tls13ParseSingleExtension(ssl_t *ssl,
        psParseBuf_t *extBuf,
        unsigned char hsMsgType)
{
    psParseBuf_t extDataBuf;
    psSizeL_t extDataLen;
    uint16_t extType;
    uint32_t maxEarlyData;
    int32_t rc;

    /* ExtensionType extension_type; */
    rc = psParseBufTryParseBigEndianUint16(extBuf,
            &extType);
    if (rc != 2)
    {
        goto out_decode_error;
    }

    /*
      4.2.
      "If the received extension is not specified for the message
      in which it appears, we MUST abort the handshake with an
      illegal_parameter alert."

      A very important check, as the code below no longer takes
      into account the type of the handshake message we are parsing.
    */
    if (!tls13ExtensionAllowedInMessage(ssl, extType, hsMsgType))
    {
        goto out_illegal_parameter;
    }

    /*
      opaque extension_data<0..2^16-1>;
    */
    rc = psParseBufParseTlsVector(extBuf,
            0, (1 << 16) - 1,
            &extDataLen);
    if (rc <= 0)
    {
        goto out_decode_error;
    }
    (void)psParseBufFromStaticData(&extDataBuf,
            extBuf->buf.start, extDataLen);
    psParseTryForward(extBuf, extDataLen);
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
    psTraceBytes("extension_data", extDataBuf.buf.start,
            extDataLen);
# endif

    switch (extType)
    {
    case EXT_EARLY_DATA:
        rc = tls13ParseEarlyData(ssl, &extDataBuf, &maxEarlyData);
        if (rc < 0)
        {
            return rc;
        }
        break;
# if defined(USE_IDENTITY_CERTIFICATES) && defined(USE_OCSP_RESPONSE)
    case EXT_STATUS_REQUEST:
        rc = tls13ParseStatusRequest(ssl, &extDataBuf);
        if (rc < 0)
        {
            return rc;
        }
        break;
# endif
    default:
        psTraceIntInfo("Ignoring unknown extension: %hu\n", extType);
    }

    return PS_SUCCESS;

out_decode_error:
    psTraceErrr("Invalid extension format\n");
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_illegal_parameter:
    psTraceErrr("Forbidden extension in message\n");
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
}

/*
  Parses:
  Extensions extensions<0..2^16-1>
*/
int32_t tls13ParseExtensions(ssl_t *ssl,
        psParseBuf_t *pb,
        unsigned char hsMsgType)
{
    psParseBuf_t extBuf;
    psSizeL_t extensionsLen;
    int32_t rc;

    /* Extension extensions<0..2^16-2>; */
    rc = psParseBufParseTlsVector(pb,
            0, (1 << 16) - 2,
            &extensionsLen);
    if (rc <= 0)
    {
        goto out_decode_error;
    }
    (void)psParseBufFromStaticData(&extBuf,
            pb->buf.start, extensionsLen);

    /*
      Minimum length of an Extension is 4
      = 2 (extension_type) + 2 (extension_data length octets)
    */
    while (psParseCanRead(&extBuf, 4))
    {
        rc = tls13ParseSingleExtension(ssl, &extBuf, hsMsgType);
        if (rc < 0)
        {
            return rc;
        }
    }

    /* Return number of bytes consumed from pb. */
    return extensionsLen + 2;

out_decode_error:
    psTraceErrr("Invalid extension vector\n");
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
}

/** Parse supported_versions extension.
    Advance parse pointer c.
    Return number of parsed octets.
*/
psSize_t tls13ParseSupportedVersions(ssl_t *ssl,
        const unsigned char **c,
        psSize_t len)
{
    psSize_t dataLen;
    int32 i = 0;
    unsigned char majVer, minVer;
    psProtocolVersion_t ver;
    const unsigned char *p = *c;
    psSize_t parsedLen;

    psTracePrintExtensionParse(ssl, EXT_SUPPORTED_VERSIONS);

    /*
      uint16 ProtocolVersion;
      struct {
      select (Handshake.msg_type) {
          case client_hello:
               ProtocolVersion versions<2..254>;
           case server_hello:
               ProtocolVersion selected_version;
        };
      } SupportedVersions;
    */

    /* Minimum length: 1 (versions length) + 2 (ProtocolVersion). */
    if (len < 3)
    {
        psTraceErrr("Malformed supported_versions extension\n");
        goto out_decode_error;
    }
    dataLen = *p; p++;
    len--;
    if (dataLen != len)
    {
        psTraceErrr("Malformed supported_versions extension\n");
        goto out_decode_error;
    }
    ssl->extFlags.got_supported_versions = 1;
    ssl->peerSupportedVersionsPriorityLen = 0;
    while(len > 0)
    {
        majVer = *p; p++;
        minVer = *p; p++;
        len -= 2;
        ver = psVerFromEncodingMajMin(majVer, minVer);

        ADD_PEER_SUPP_VER(ssl, ver);
        ADD_PEER_SUPP_VER_PRIORITY(ssl, ver);
        i++;

        if (i >= TLS_MAX_SUPPORTED_VERSIONS)
        {
            psTraceErrr("Error: supported_versions list too big\n");
            goto out_internal_error;
        }
    }

    parsedLen = (p - *c);
    *c = p;

    return parsedLen;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
out_decode_error:
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
}

static
int32_t tls13ParseServerSupportedVersions(ssl_t *ssl,
        psParseBuf_t *pb)
{
    unsigned char maj, min;
    psProtocolVersion_t ver;

    psTracePrintExtensionParse(ssl, EXT_SUPPORTED_VERSIONS);

    if (!psParseOctet(pb, &maj) || !psParseOctet(pb, &min))
    {
        return PS_PARSE_FAIL;
    }
    ver = psVerFromEncodingMajMin(maj, min);

    psTracePrintProtocolVersion(INDENT_EXTENSION,
            "selected_version",
            maj, min, 1);

    if (!SUPP_VER(ssl, ver))
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceIntInfo("Unsupported server version: %u", min);
        return MATRIXSSL_ERROR;
    }

    SET_NGTD_VER(ssl, ver);

    if (ver & v_tls_1_3_any)
    {
        return PS_SUCCESS;
    }
    else
    {
        /* Try the <1.3 code path. */
        return SSL_NO_TLS_1_3;
    }
}

# ifndef USE_ONLY_PSK_CIPHER_SUITE
static
int32_t tls13ParseServerKeyShare(ssl_t *ssl,
        psParseBuf_t *pb)
{
    uint16_t serverGroup;
    psSizeL_t keyExchangeLen;
    int32_t rc;
    psPubKey_t *privKey;

    psTracePrintExtensionParse(ssl, EXT_KEY_SHARE);

    ssl->extFlags.got_key_share = 1;

    rc = psParseBufTryParseBigEndianUint16(pb,
            &serverGroup);
    if (rc != 2)
    {
        psTraceErrr("Error: malformed server key_share\n");
        goto out_decode_error;
    }

    psTracePrintTls13NamedGroup(INDENT_EXTENSION,
            "server_share",
            serverGroup, PS_TRUE);

    /* Is this key_share in HelloRetryRequest */
    if (ssl->tls13IncorrectDheKeyShare)
    {
        /* Check (1) from spec chapter 4.2.8:
           "the selected_group field corresponds to a group
           which was provided in the "supported_groups" extension in the
           original ClientHello;" */
        if (!tls13WeSupportGroup(ssl, serverGroup))
        {
            psTraceErrr("Server sent key_share in HelloRetryRequest" \
                        " and selected group that was not included in"
                        " our supported_groups extension\n");
            goto out_illegal_parameter;
        }

        /* Check (2) in spec chapter 4.2.8:
           "the selected_group field does not correspond to
           a group which was provided in the key_share extension
           in the original ClientHello" */
        if (tls13GetGroupKey(ssl, serverGroup) != NULL)
        {

            psTraceErrr("Server sent key_share in HelloRetryRequest" \
                        " but didn't change the group\n");
            goto out_illegal_parameter;
        }
        ssl->tls13NegotiatedGroup = serverGroup;

        /* Need to trigger ClientHello sending again. */
        return PS_SUCCESS;
    }

    privKey = tls13GetGroupKey(ssl, serverGroup);
    if (privKey == NULL)
    {
        psTraceErrr("Server chose an unsupported group or a group we did not" \
                " generate a key share for.\n");
        goto out_handshake_failure;
    }

    /* opaque key_exchange<1..2^16-1>; */
    /* Consume the length */
    rc = psParseBufParseTlsVector(pb,
            0, (1 << 16) - 1,
            &keyExchangeLen);
    if (rc < 0)
    {
        goto out_decode_error;
    }
    /* Both sides have agreement on the used group */
    ssl->tls13NegotiatedGroup = serverGroup;

    rc = tls13ImportPublicValue(ssl,
            pb->buf.start,
            keyExchangeLen,
            serverGroup);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;

out_decode_error:
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_handshake_failure:
    ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
    return MATRIXSSL_ERROR;
out_illegal_parameter:
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
}
# endif /* USE_ONLY_PSK_CIPHER_SUITE */

static
int32_t tls13VerifyBinder(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc, hmacAlg, hmacLen;
    psSize_t remLen;
    psSizeL_t len;
    unsigned char *peerBinder = NULL;
    psSize_t binderLen = 0;
    uint16_t ix;
    unsigned char ourBinder[MAX_TLS_1_3_HASH_SIZE];
    unsigned char binderKey[MAX_TLS_1_3_HASH_SIZE];
    psSize_t binderKeyLen;
    psHmac_t ctx;

    hmacAlg = tls13GetPskHmacAlg(ssl->sec.tls13ChosenPsk);
    hmacLen = tls13GetPskHashLen(ssl->sec.tls13ChosenPsk);

    tls13TranscriptHashUpdate(ssl,
            ssl->sec.tls13CHStart,
            ssl->sec.tls13CHLen - ssl->sec.tls13BindersLen);
    tls13TranscriptHashSnapshot(ssl,
            ssl->sec.tls13TrHashSnapshotCHWithoutBinders);
    tls13TranscriptHashUpdate(ssl,
            ssl->sec.tls13CHStart +
            ssl->sec.tls13CHLen - ssl->sec.tls13BindersLen,
            ssl->sec.tls13BindersLen);

    /* Find the binder corresponding to the PSK we have chosen. */
    ix = 0;
    remLen = ssl->sec.tls13BindersLen - 2;
    while (peerBinder == NULL
            && ix <= ssl->sec.tls13SelectedIdentityIndex
            && remLen > 0
            && psParseCanRead(pb, remLen) )
    {
        /* opaque PskBinderEntry<32..255>; */
        rc = psParseBufParseTlsVector(pb,
                32, 255,
                &len);
        if (rc < 0)
        {
            goto out_decode_error;
        }
        if (ix == ssl->sec.tls13SelectedIdentityIndex)
        {
            peerBinder = pb->buf.start;
            binderLen = len;
        }
        /* forward over this binder */
        rc = psParseTryForward(pb, len);
        if (rc != len)
        {
            goto out_decode_error;
        }
        remLen -= (len + 1); /* account for binder data and length byte */
        ix++;
    }

    if (peerBinder == NULL || len == 0)
    {
        psTraceErrr("Binder for chosen PSK missing\n");
        goto out_decrypt_error;
    }
    if (binderLen != hmacLen)
    {
        psTraceErrr("Binder for chosen PSK has incorrect length\n");
        goto out_decrypt_error;
    }

    /* Generate the binder_key.*/
    rc = tls13DeriveEarlySecrets(ssl, ssl->sec.tls13ChosenPsk);
    if (rc < 0)
    {
        goto out_internal_error;
    }

# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
    psTraceBytes("early_secret", ssl->sec.tls13EarlySecret, hmacLen);
    psTraceBytes("binder_secret", ssl->sec.tls13ExtBinderSecret, hmacLen);
#endif

    rc = tls13DeriveBinderKey(ssl,
            hmacAlg,
            ssl->sec.tls13ExtBinderSecret,
            hmacLen,
            binderKey,
            &binderKeyLen);
    if (rc < 0)
    {
        goto out_internal_error;
    }
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
    psTraceBytes("binder key", binderKey, binderKeyLen);
    psTraceBytes("snapshot hs hash",
            ssl->sec.tls13TrHashSnapshotCHWithoutBinders, hmacLen);

# endif

    /*
      binder value =
      HMAC(binderKey, Transcript-Hash(Truncate(ClientHello))
    */
    rc = psHmacSingle(&ctx,
        hmacAlg,
        binderKey,
        hmacLen,
        ssl->sec.tls13TrHashSnapshotCHWithoutBinders,
        hmacLen,
        ourBinder);
    if (rc < 0)
    {
        return rc;
    }
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
    psTraceBytes("binder value", ourBinder, hmacLen);
# endif
    if (memcmpct(peerBinder, ourBinder, hmacLen) == 0)
    {
        psTraceInfo("Binder OK\n");
    }
    else
    {
        psTraceErrr("Binder did not validate\n");
        goto out_decrypt_error;
    }

    return PS_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
out_decode_error:
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_decrypt_error:
    ssl->err = SSL_ALERT_DECRYPT_ERROR;
    return MATRIXSSL_ERROR;
}

/** Called after the server has parsed a negotiable PSK from the client's
    pre_shared_key extension. Negotiable means that the server either
    has the same PSK in its run-time PSK cache, or the PSK was decrypted
    from a ticket the server had encrypted earlier. */
static
psBool_t tls13ServerFoundSupportedPsk(ssl_t *ssl,
        psTls13Psk_t *psk,
        uint16_t indexInClientPreSharedKey)
{
    psProtocolVersion_t pskVer;
    uint8_t majVer, minVer;

    (void)pskVer;

    psTraceInfo("Server recognized a PSK in pre_shared_key\n");
    if (psk->isResumptionPsk)
    {
        psTraceInfo("  Trying to resume the associated session\n");
    }

    ssl->sec.tls13UsingPsk = PS_TRUE;
    ssl->sec.tls13ChosenPsk = psk;
    ssl->sec.tls13SelectedIdentityIndex = indexInClientPreSharedKey;
    if (psk->params != NULL)
    {
        majVer = psk->params->majVer;
        minVer = psk->params->minVer;
        if (minVer == 0)
        {
            minVer = TLS_1_2_MIN_VER;
        }
        pskVer = psVerFromEncodingMajMin(majVer, minVer);

        ssl->cipher = sslGetCipherSpec(ssl, psk->params->cipherId);
        if (ssl->cipher == NULL)
        {
            psTraceInfo("Error: PSK is associated with an unsupported " \
                    "ciphersuite\n");
            return PS_FALSE;
        }
        psTracePrintProtocolVersionNew(INDENT_EXTENSION,
                "PSK is associated with protocol version",
                pskVer,
                PS_TRUE);
        psTracePrintCiphersuiteName(INDENT_EXTENSION,
                    "PSK is associated with ciphersuite",
                    ssl->cipher->ident,
                    PS_TRUE);
    }
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
    psTraceBytes("PSK identity", psk->pskId, psk->pskIdLen);
    psTraceBytes("PSK key", psk->pskKey, psk->pskLen);
# endif /* DEBUG_TLS_1_3_DECODE_EXTENSIONS */
    return PS_TRUE;
}

int32_t tls13ParsePreSharedKey(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc;
    uint16_t ix;
    uint32_t obfuscatedTicketAge = 0;
    uint32_t clientTicketAge;
    uint32_t serverTicketAge;
    psTime_t now;
    psSizeL_t idsLen, remIdsLen;
    psSizeL_t bindersLen = 0, identityLen;
    psParseBuf_t idBuf;
    psBool_t foundPsk = PS_FALSE;
    psTls13Psk_t *psk;
    uint16_t selectedIdentity = 0;

    psTracePrintExtensionParse(ssl, EXT_PRE_SHARED_KEY);

    /*
      struct {
          opaque identity<1..2^16-1>;
          uint32 obfuscated_ticket_age;
      } PskIdentity;

      opaque PskBinderEntry<32..255>;

      struct {
          PskIdentity identities<7..2^16-1>;
          PskBinderEntry binders<33..2^16-1>;
      } OfferedPsks;

      struct {
          select (Handshake.msg_type) {
              case client_hello: OfferedPsks;
              case server_hello: uint16 selected_identity;
          };
      } PreSharedKeyExtension;
    */

    if (IS_SERVER(ssl))
    {
        /* PskIdentity identities<7..2^16-1>; */
        rc = psParseBufParseTlsVector(pb,
                7, (1 << 16) - 1,
                &idsLen);
        if (rc < 0)
        {
            goto out_decode_error;
        }

        /* Start parsing the PskIdentities. */
        (void)psParseBufFromStaticData(&idBuf,
                pb->buf.start, idsLen);
        remIdsLen = idsLen;
        ix = 0;

        while (remIdsLen > 0 && psParseCanRead(&idBuf, remIdsLen))
        {
            /* opaque identity<1..2^16-1>; */
            rc = psParseBufParseTlsVector(&idBuf,
                    1, (1 << 16) - 1,
                    &identityLen);
            if (rc < 0)
            {
                goto out_decode_error;
            }
            remIdsLen -= rc;

            if (!psParseCanRead(&idBuf, identityLen))
            {
                goto out_decode_error;
            }

            if (!foundPsk)
            {
                psk = NULL;
                rc = tls13FindSessionPsk(ssl,
                        idBuf.buf.start, identityLen,
                        &psk);
                if (rc == PS_SUCCESS && psk != NULL)
                {
                    foundPsk = tls13ServerFoundSupportedPsk(ssl, psk, ix);
                }
            }

            rc = psParseTryForward(&idBuf, identityLen);
            if (rc < 0)
            {
                goto out_decode_error;
            }
            remIdsLen -= identityLen;

            /* uint32 obfuscated_ticket_age; */
            rc = psParseBufTryParseBigEndianUint32(&idBuf,
                    &obfuscatedTicketAge);
            if (rc < 0)
            {
                goto out_decode_error;
            }
            /* See if early_data can be enabled. */
            if (foundPsk == PS_TRUE &&
                ssl->extFlags.got_early_data == 1 &&
                ssl->sec.tls13ChosenPsk->isResumptionPsk == PS_TRUE &&
                ssl->sec.tls13ChosenPsk->params != NULL &&
                ssl->sec.tls13ChosenPsk->params->maxEarlyData > 0 &&
                ssl->sec.tls13SelectedIdentityIndex == 0 &&
                ssl->tls13IncorrectDheKeyShare != PS_TRUE)
            {
                /* Check ticket age */
                clientTicketAge = obfuscatedTicketAge -
                        ssl->sec.tls13ChosenPsk->params->ticketAgeAdd;
                psGetTime(&now, NULL);
                serverTicketAge = psDiffMsecs(
                            ssl->sec.tls13ChosenPsk->params->timestamp,
                            now,
                            NULL);
                if (abs(clientTicketAge - serverTicketAge) <=
                        TLS_1_3_EARLY_DATA_TICKET_AGE_WINDOW)
                {
                    ssl->tls13ServerEarlyDataEnabled = PS_TRUE;
                }
            }
            remIdsLen -= rc;
            ix++;
        } /* End of PskIdentity parsing. */

        pb->buf.start = idBuf.buf.start;

        /* PskBinderEntry binders<33..2^16-1>; */
        rc = psParseBufParseTlsVector(pb,
                33, (1 << 16) - 1,
                &bindersLen);
        if (rc < 0)
        {
            goto out_decode_error;
        }

        if (foundPsk)
        {
            ssl->sec.tls13BindersLen = bindersLen + 2;

            rc = tls13VerifyBinder(ssl, pb);
            if (rc < 0)
            {
                return rc;
            }
        }
        else
        {
            rc = psParseTryForward(pb, bindersLen);
            if (rc < 0)
            {
                goto out_decode_error;
            }
            psTraceInfo("Did not recognize any PSKs in pre_shared_key.");
            psTraceInfo(" Continuing normal handshake...\n");
        }
    }
    else
    {
        rc = psParseBufTryParseBigEndianUint16(pb, &selectedIdentity);
        if (rc < 0)
        {
            goto out_decode_error;
        }
        psTraceIntInfo("Server selected_identity: %hu\n", selectedIdentity);
        ix = 0;
        psk = ssl->sec.tls13SessionPskList;
        while (psk)
        {
            if (ix == selectedIdentity)
            {
                foundPsk = PS_TRUE;
                ssl->sec.tls13ChosenPsk = psk;
                ssl->sec.tls13UsingPsk = PS_TRUE;
                ssl->sec.tls13SelectedIdentityIndex = selectedIdentity;
            }
            psk = psk->next;
            ix++;
        }
        if (!foundPsk)
        {
            psTraceErrr("Server selected_identity out of range\n");
            goto out_illegal_parameter;
        }
    }

    ssl->extFlags.got_pre_shared_key = 1;

    return MATRIXSSL_SUCCESS;

out_decode_error:
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_illegal_parameter:
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
}

int32_t tls13ParsePskKeyExchangeModes(ssl_t *ssl,
        psParseBuf_t *pb)
{
    psParseBuf_t modesBuf;
    psSizeL_t modesLen, remModesLen;
    uint8_t modeVal = 0;
    int32_t rc;
    psk_key_exchange_mode_e mode;
    psSize_t i, k;
    psBool_t gotPskKe = PS_FALSE;
    psBool_t gotPskDheKe = PS_FALSE;

    psAssert(IS_SERVER(ssl));
    psTracePrintExtensionParse(ssl, EXT_PSK_KEY_EXCHANGE_MODES);

    /*
      enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

      struct {
          PskKeyExchangeMode ke_modes<1..255>;
      } PskKeyExchangeModes;
    */

    /* PskKeyExchangeMode ke_modes<1..255>; */
    rc = psParseBufParseTlsVector(pb,
            1, 255,
            &modesLen);
    if (rc < 0)
    {
        goto out_handshake_failure;
    }

    /* Start parsing the PskKeyExchangeModes. */
    (void)psParseBufFromStaticData(&modesBuf,
            pb->buf.start, modesLen);
    remModesLen = modesLen;

    i = 0;
    k = 0;
    while (remModesLen > 0 && psParseCanRead(&modesBuf, 1))
    {
        if (psParseOctet(&modesBuf, &modeVal) < 0)
        {
            goto out_handshake_failure;
        }
        if (i == 0)
        {
            tlsTraceIndent(INDENT_EXTENSION,
                    "psk_key_exchange_modes:\n");
        }
        psTracePrintPskKeyExchangeMode(INDENT_EXTENSION + 1,
                NULL,
                modeVal+1, PS_TRUE);
        psAssert(k < 2);

        if (modeVal == 0 && !gotPskKe)
        {
            mode = psk_keyex_mode_psk_ke;
            ssl->sec.tls13ClientPskModes[k++] = mode;
            ssl->sec.tls13ClientPskModesLen = k;
            gotPskKe = PS_TRUE;
        }
        else if (modeVal == 1 && !gotPskDheKe)
        {
            mode = psk_keyex_mode_psk_dhe_ke;
            ssl->sec.tls13ClientPskModes[k++] = mode;
            ssl->sec.tls13ClientPskModesLen = k;
            gotPskDheKe = PS_TRUE;
        }

        /* Ignore unknown modes and duplicates. */
        i++;
    }

    if (!gotPskDheKe && !gotPskKe)
    {
        psTraceErrr("Cannot support any PSK key exchange modes offered " \
                "by the client.\n");
        goto out_handshake_failure;
    }

    return PS_SUCCESS;

out_handshake_failure:
    ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
    return PS_PARSE_FAIL;
}

int32_t tls13ParseCookie(ssl_t *ssl,
        psParseBuf_t *pb)
{
    psSizeL_t cookieLen;
    psSize_t copiedLen;
    int32_t rc;

    psTracePrintExtensionParse(ssl, EXT_COOKIE);

    /*
      struct {
          opaque cookie<1..2^16-1>;
      } Cookie;
    */
    /* opaque cookie<1..2^16-1>; */
    rc = psParseBufParseTlsVector(pb,
            0, (1 << 16) - 1,
            &cookieLen);
    if (rc < 0)
    {
        psTraceErrr("Error parsing Cookie extension\n");
        goto out_illegal_parameter;
    }

    /*
      Server are allowed send cookies only in HelloRetryRequest messages,
      not in ordinary ServerHellos. Clients are only allowed to send
      a cookie when responding to a HelloRetryRequest.
    */
    if (!ssl->tls13IncorrectDheKeyShare)
    {
        psTraceErrr("Got unexpected cookie extension\n");
        goto out_unsupported_extension;
    }

    if (IS_SERVER(ssl))
    {
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
        psTraceBytes("Parsed ClientHello.cookie",
                pb->buf.start,
                cookieLen);
# endif

        /*
          "When sending the new ClientHello, the client MUST copy
          the contents of the extension received in the HelloRetryRequest into
          a "cookie" extension in the new ClientHello."
        */
        if (cookieLen != psGetOutputBlockLength(tls13GetCipherHmacAlg(ssl)) ||
                Memcmp(ssl->sec.tls13TrHashSnapshotCH1,
                        pb->buf.start,
                        cookieLen))
        {
            psTraceBytes("Client sent back invalid cookie",
                    pb->buf.start,
                    cookieLen);
            goto out_decrypt_error;
        }
        else
        {
            psTraceInfo("Client cookie OK\n");
            ssl->sec.tls13ClientCookieOk = PS_TRUE;
        }
    }
    else
    {
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
        psTraceBytes("Parsed HelloRetryRequest.cookie",
                pb->buf.start,
                cookieLen);
# endif
        /* As client, we simply store the value we received from the server. */
        if (ssl->sec.tls13CookieFromServer)
        {
            psFree(ssl->sec.tls13CookieFromServer, ssl->hsPool);
            ssl->sec.tls13CookieFromServer = NULL;
            ssl->sec.tls13CookieFromServerLen = 0;
        }
        ssl->sec.tls13CookieFromServer = psMalloc(ssl->hsPool, cookieLen);
        if (ssl->sec.tls13CookieFromServer == NULL)
        {
            goto out_internal_error;
        }
        copiedLen = cookieLen;

        rc = psParseBufCopyNPsSize(pb,
                cookieLen,
                ssl->sec.tls13CookieFromServer,
                &copiedLen);
        if (rc != PS_SUCCESS)
        {
            goto out_internal_error;
        }
        psAssert(copiedLen == cookieLen);
        ssl->sec.tls13CookieFromServerLen = cookieLen;
    }

    return PS_SUCCESS;

out_illegal_parameter:
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
out_decrypt_error:
    ssl->err = SSL_ALERT_DECRYPT_ERROR;
    return MATRIXSSL_ERROR;
out_unsupported_extension:
    ssl->err = SSL_ALERT_UNSUPPORTED_EXTENSION;
    return MATRIXSSL_ERROR;
}

static
int32_t tls13ParseServerName(ssl_t *ssl,
        psParseBuf_t *pb)
{
    /*
      Only handling the client-side case (i.e. parsing the server's
      server_name extension sent in EncryptedExtensions.)
      TLS <1.3 code path handles the ClientHello extension.
    */
    psAssert(!IS_SERVER(ssl));
    psTracePrintExtensionParse(ssl, EXT_SERVER_NAME);
# ifdef USE_CLIENT_SIDE_SSL
    /* Solicited or not? */
    if (ssl->extFlags.req_sni == 0)
    {
        psTraceErrr("Server sent unsolicited server_name extension\n");
        ssl->err = SSL_ALERT_UNSUPPORTED_EXTENSION;
        return MATRIXSSL_ERROR;
    }

    /* Only an empty server_name is allowed from the server. */
    if (psParseCanRead(pb, 1))
    {
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return PS_PARSE_FAIL;
    }

    psTraceInfo("Received empty server_name in EncryptedExtensions\n");
# else
    return MATRIXSSL_ERROR;
# endif
    return PS_SUCCESS;
}

int32_t tls13ParseEarlyData(ssl_t *ssl,
        psParseBuf_t *pb,
        uint32_t *maxEarlyData)
{
    int32_t rc;

    /*
      Only handling the client-side case (i.e. parsing the server's
      early_data extension sent in NewSessionTicket.)
    */
    psAssert(!IS_SERVER(ssl));
    psTracePrintExtensionParse(ssl, EXT_EARLY_DATA);

    rc = psParseBufTryParseBigEndianUint32(pb,
            maxEarlyData);
    if (rc < 0)
    {
        return rc;
    }
    return PS_SUCCESS;
}

/** Parse signature_algorithms or signature_algorithms_cert extension.
    Advance parse pointer c.
    isCert parameter specifies whether the extension is normal
    signature_algorithms or signature_algorithms_cert.
*/
int32_t tls13ParseSignatureAlgorithms(ssl_t *ssl,
        const unsigned char **c,
        psSize_t len,
        psBool_t isCert)
{
    int rc;
    psParseBuf_t pb;
    uint16_t sigAlg;
    psSize_t algsLen;
    psSize_t parsedLen = 0;
    int32_t i = 0;
    uint16_t mask;

    if (isCert)
    {
        psTracePrintExtensionParse(ssl, EXT_SIGNATURE_ALGORITHMS_CERT);
    }
    else
    {
        psTracePrintExtensionParse(ssl, EXT_SIGNATURE_ALGORITHMS);
    }


    (void)psParseBufFromStaticData(&pb, *c, len);
    /* Move the supplied pointer forwards to the end
       of this extension */
    *c += len;

    rc = psParseBufTryParseBigEndianUint16(&pb,
            &algsLen);
    if (rc != 2)
    {
        return rc;
    }

    if (isCert)
    {
#  ifdef USE_IDENTITY_CERTIFICATES
        ssl->sec.keySelect.peerCertSigAlgsLen = 0;
#  endif
    }
    else
    {
        ssl->sec.keySelect.peerSigAlgsLen = 0;
    }

    while (parsedLen < algsLen)
    {
        rc = psParseBufTryParseBigEndianUint16(&pb,
                &sigAlg);
        if (rc != 2)
        {
            return rc;
        }
        parsedLen += 2;
        if (i >= TLS_MAX_SIGNATURE_ALGORITHMS)
        {
            psTraceInfo("Warning: Ignored signature_algorithm. " \
                        "Increase TLS_1_3_MAX_SIGNATURE_ALGORITHMS.\n");
            break;
        }
        /* Save the algoritm based on which extension this is */
        if (isCert)
        {
#  ifdef USE_IDENTITY_CERTIFICATES
            /* Make sure this sig_alg_cert is in our supported list */
            if (findFromUint16Array(
                        ssl->tls13SupportedSigAlgsCert,
                        ssl->tls13SupportedSigAlgsCertLen,
                        sigAlg) != PS_FAILURE)
            {
                mask = HASH_SIG_MASK(((sigAlg >> 8) & 0xff),
                        (sigAlg & 0xff));
                ssl->sec.keySelect.peerCertSigAlgs[i] = sigAlg;
                ssl->sec.keySelect.peerCertSigAlgsLen++;
                ssl->sec.keySelect.peerCertSigAlgMask |= mask;
                i++;
            }
# endif
        }
        else
        {
            /* Make sure this sig_alg is in our supported list */
            if (findFromUint16Array(
                        ssl->supportedSigAlgs,
                        ssl->supportedSigAlgsLen,
                        sigAlg) != PS_FAILURE)
            {
                mask = HASH_SIG_MASK(((sigAlg >> 8) & 0xff),
                        (sigAlg & 0xff));
                ssl->sec.keySelect.peerSigAlgs[i] = sigAlg;
                ssl->sec.keySelect.peerSigAlgsLen++;
                ssl->sec.keySelect.peerSigAlgMask |= mask;
                i++;
            }
        }
    }

    if (isCert)
    {
#  ifdef USE_IDENTITY_CERTIFICATES
        /* signature_algorithms_cert only defined in TLS 1.3. */
        psTracePrintTls13SigAlgList(INDENT_EXTENSION,
                "Parsed signature_algorithms_cert",
                ssl->sec.keySelect.peerCertSigAlgs,
                ssl->sec.keySelect.peerCertSigAlgsLen,
                PS_TRUE);
#  endif
    }
    else
    {
        psTracePrintTls13SigAlgList(INDENT_EXTENSION,
                "Parsed signature_algorithms",
                ssl->sec.keySelect.peerSigAlgs,
                ssl->sec.keySelect.peerSigAlgsLen,
                PS_TRUE);
    }

    return MATRIXSSL_SUCCESS;
}
#  ifdef USE_IDENTITY_CERTIFICATES
psRes_t tls13ParseCertificateAuthorities(ssl_t *ssl,
                                         const unsigned char **start, psSizeL_t len)
{
    sslKeySelectInfo_t *keySelect = &ssl->sec.keySelect;

    psRes_t rc;
    size_t nCas, off;
    const unsigned char *data;
    psParseBuf_t pb;
    psSizeL_t caNamesLen = 0, caNameLen;

    psTracePrintExtensionParse(ssl, EXT_CERTIFICATE_AUTHORITIES);

    /*
      opaque DistinguishedName<1..2^16-1>;
      struct {
          DistinguishedName authorities<3..2^16-1>;
      } CertificateAuthoritiesExtension;
    */

    /* Notice input start and advance to end of extension */
    data = *start;
    *start += len;

    (void)psParseBufFromStaticData(&pb, data, len);
    rc = psParseBufParseTlsVector(&pb, 3, (1 << 16) - 1, &caNamesLen);
    if (rc < 0)
    {
        psTraceErrr(" failed to parse CA names\n");
        return rc;
    }

    /* Count how many issuer names we have. */
    for (nCas = 0, off = 0; off < caNamesLen; nCas += 1, off += (2 + caNameLen))
    {
        rc = psParseBufParseTlsVector(&pb, 1, (1<<16) - 1, &caNameLen);
        if (rc < 0)
        {
            break;
        }
        rc = psParseTryForward(&pb, caNameLen);
        if (rc != caNameLen)
        {
            break;
        }
    }

    /* Allocate space for the issuer names and their lengths.  */
    keySelect->nCas = nCas;
    keySelect->caNames = psCalloc(pool, nCas, sizeof(keySelect->caNames[0]));
    keySelect->caNameLens = psCalloc(pool, nCas, sizeof(keySelect->caNameLens[0]));
    if (keySelect->caNames == NULL || keySelect->caNameLens == NULL)
    {
        psTraceErrr(" failed to allocate space for CA names\n");
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return MATRIXSSL_ERROR;
    }
    /* Rewind and fill - the parseBuf calls have been successful above, and
       they don't allocate memory, therefore they can't fail now.  Note:
       pointer to parse buf internal memory - the keySelect content is thus
       only valid during validity of the contained packet.  */
    (void)psParseBufFromStaticData(&pb, data, len);
    (void)psParseBufParseTlsVector(&pb, 3, (1 << 16) - 1, &caNamesLen);
    for (nCas = 0, off = 0;
         off < caNamesLen && nCas < keySelect->nCas;
         nCas += 1, off += (2 + caNameLen))
    {
        (void)psParseBufParseTlsVector(&pb, 1, (1<<16) - 1, &caNameLen);
        keySelect->caNames[nCas] = pb.buf.start;
        keySelect->caNameLens[nCas] = caNameLen;
        (void)psParseTryForward(&pb, caNameLen);
    }
    psTraceIntInfo(" got %d CA names\n", keySelect->nCas);
    return PS_SUCCESS;
}
# endif

int32_t tls13ParseEncryptedExtensions(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc;
    psSizeL_t vecDataLen, extDataLen;
    uint16_t extensionType;
    psParseBuf_t extBuf, extDataBuf;

    psTracePrintHsMessageParse(ssl, SSL_HS_ENCRYPTED_EXTENSION);

    /*
      struct {
          ExtensionType extension_type;
          opaque extension_data<0..2^16-1>;
      } Extension;

      struct {
          Extension extensions<0..2^16-1>;
      } EncryptedExtensions;
    */

    /* Extension extensions<0..2^16-1>; */
    rc = psParseBufParseTlsVector(pb,
            0, (1 << 16) - 1,
            &vecDataLen);
    if (rc <= 0)
    {
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return PS_PARSE_FAIL;
    }

    /*
      Init sub buffer with the bytes of extensions<0..2^16-1>.
    */
    (void)psParseBufFromStaticData(&extBuf,
            pb->buf.start, vecDataLen);

    while (psParseCanRead(&extBuf, 4))
    {
        /* ExtensionType extension_type; */
        rc = psParseBufTryParseBigEndianUint16(&extBuf,
                &extensionType);
        if (rc != 2)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return PS_PARSE_FAIL;
        }

        /* 4.2. If the received extension is not specified for the message
           in which it appears, we MUST abort the handshake with an
           illegal_parameter alert. */
        if (!tls13ExtensionAllowedInMessage(ssl,
                        extensionType,
                        SSL_HS_ENCRYPTED_EXTENSION))
        {
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            return MATRIXSSL_ERROR;
        }

        /* opaque extension_data<0..2^16-1>;
           Note: this will only consume the length octets from extBuf. */
        rc = psParseBufParseTlsVector(&extBuf,
                0, (1 << 16) - 1,
                &extDataLen);
        if (rc <= 0)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return PS_PARSE_FAIL;
        }
        (void)psParseBufFromStaticData(&extDataBuf,
                extBuf.buf.start, extDataLen);
        psParseTryForward(&extBuf, extDataLen);
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
        psTraceBytes("extension_data", extDataBuf.buf.start,
                extDataLen);
# endif


        switch (extensionType)
        {
        case EXT_SERVER_NAME:
            rc = tls13ParseServerName(ssl, &extDataBuf);
            if (rc < 0)
            {
                return rc;
            }
            break;
        case EXT_EARLY_DATA:
            psTracePrintExtensionParse(ssl, extensionType);
            if (ssl->sec.tls13SelectedIdentityIndex != 0)
            {
                /* Spec 4.2.11: If selected identity is not 0 and server has
                   included EARLY_DATA extension then abort with
                   illegal_parameter alert */
                ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                return MATRIXSSL_ERROR;
            }
            if (ssl->tls13EarlyDataStatus == MATRIXSSL_EARLY_DATA_SENT)
            {
                ssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_ACCEPTED;
            }
            ssl->extFlags.got_early_data = 1;
            break;

        default:
            psTraceIntInfo("Ignoring unknown EE extension: %hu\n",
                    extensionType);
        }
    }
    pb->buf.start = extBuf.buf.start;
    if (ssl->extFlags.got_early_data == 0)
    {
        if (ssl->tls13EarlyDataStatus == MATRIXSSL_EARLY_DATA_SENT)
        {
            ssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_REJECTED;
        }
        ssl->tls13ClientEarlyDataEnabled = PS_FALSE;
    }
    return MATRIXSSL_SUCCESS;
}

int32_t tls13ParseServerHelloExtensions(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc;
    psSizeL_t vecDataLen, extDataLen;
    uint16_t extensionType;
    psParseBuf_t extBuf, extDataBuf;
    psBool_t gotSupportedVersions = PS_FALSE;
    psBool_t gotForbiddenExtension = PS_FALSE;

    /* Minimum length is 0 for the vector here since this could still
       be < TLS1.3 ServerHello which might not have extensions.
       Extension extensions<0..2^16-1>; */
    rc = psParseBufParseTlsVector(pb,
            0, (1 << 16) - 1,
            &vecDataLen);
    if (rc <= 0)
    {
        goto out_decode_error;
    }

    /*
      Init sub buffer with the bytes of extensions<6..2^16-1>.
*/
    (void)psParseBufFromStaticData(&extBuf,
            pb->buf.start, vecDataLen);

    while (psParseCanRead(&extBuf, 4))
    {
        /* ExtensionType extension_type; */
        rc = psParseBufTryParseBigEndianUint16(&extBuf,
                &extensionType);
        if (rc != 2)
        {
            goto out_decode_error;
        }

        /*
          4.2. If the received extension is not specified for the message
          in which it appears, we MUST abort the handshake with an
          illegal_parameter alert.

          However (!) this might actually be a TLS 1.2 ServerHello, for
          which the set of allowed extensions is different. Store
          the error, and let it take effect only after supported_versions
          has been found and TLS 1.3 negotiated. We will drop to <1.3
          code path if we could not negotiate 1.3.
        */
        if (!tls13ExtensionAllowedInMessage(ssl,
                        extensionType,
                        SSL_HS_SERVER_HELLO))
        {
            gotForbiddenExtension = PS_TRUE;
        }

        /* opaque extension_data<0..2^16-1>;
           Note: this will only consume the length octets from extBuf. */
        rc = psParseBufParseTlsVector(&extBuf,
                0, (1 << 16) - 1,
                &extDataLen);
        if (rc <= 0)
        {
            goto out_decode_error;
        }
        (void)psParseBufFromStaticData(&extDataBuf,
                extBuf.buf.start, extDataLen);
        psParseTryForward(&extBuf, extDataLen);
# ifdef DEBUG_TLS_1_3_DECODE_EXTENSIONS
        psTraceBytes("extension_data", extDataBuf.buf.start,
                extDataLen);
# endif

        switch (extensionType)
        {
# ifndef USE_ONLY_PSK_CIPHER_SUITE
        case EXT_KEY_SHARE_PRE_DRAFT_23:
        case EXT_KEY_SHARE:
            rc = tls13ParseServerKeyShare(ssl, &extDataBuf);
            if (rc < 0)
            {
                return rc;
            }
            break;
# endif
        case EXT_PRE_SHARED_KEY:
            rc = tls13ParsePreSharedKey(ssl, &extDataBuf);
            if (rc < 0)
            {
                return rc;
            }
            break;
        case EXT_SUPPORTED_VERSIONS:
            rc = tls13ParseServerSupportedVersions(ssl, &extDataBuf);
            if (rc < 0)
            {
                return rc;
            }
            gotSupportedVersions = PS_TRUE;
            break;
        case EXT_COOKIE:
            rc = tls13ParseCookie(ssl, &extDataBuf);
            if (rc < 0)
            {
                return rc;
            }
            break;
        default:
            psTraceIntInfo("Unknown or forbidden ServerHello extension: %hu\n",
                    extensionType);
        }
    }

    pb->buf.start = extBuf.buf.start;

    if (!gotSupportedVersions)
    {
        ssl->hsState = SSL_HS_SERVER_HELLO;
        return SSL_NO_TLS_1_3;
    }

    /* We should have negotiated 1.3 if we get here. */
    psAssert(NGTD_VER(ssl, v_tls_1_3_any));

    if (gotForbiddenExtension)
    {
        /* We delayed setting the alert until after we are sure TLS 1.3
           has been negotiated. Now we can be sure that the 1.3 set of
           allowed extensions must be enforced. Send the alert now. */
        psTraceErrr("Error: forbidden extension in TLS 1.3 ServerHello\n");
        goto out_illegal_parameter;
    }

    if (ssl->tls13IncorrectDheKeyShare)
    {
        /* This was a HelloRetryRequest. Need to trigger sending of
           ClientHello2. */
        return SSL_ENCODE_RESPONSE;
    }
    else
    {
        return PS_SUCCESS;
    }

out_decode_error:
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_illegal_parameter:
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
}

# endif
