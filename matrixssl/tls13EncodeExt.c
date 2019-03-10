/**
 *      @file    tls13Encode.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 specific functions for extension encoding.
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
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

#ifdef USE_TLS_1_3

# ifndef DEBUG_TLS_1_3_ENCODE_EXTENSIONS
/* #  define DEBUG_TLS_1_3_ENCODE_EXTENSIONS */
# endif

# ifdef DEBUG_TLS_1_3_ENCODE_EXTENSIONS
#  warning "DEBUG_TLS_1_3_ENCODE_EXTENSIONS will leak secrets into logs!"
# endif

#  ifdef USE_CLIENT_SIDE_SSL
static int32_t tls13WriteClientSupportedVersions(ssl_t *ssl,
        psDynBuf_t *extBuf)
{
    uint8_t i = 0;
    psDynBuf_t workBuf;
    unsigned char extensionType[2] = {0x00, EXT_SUPPORTED_VERSIONS};
    unsigned char *extensionData;
    size_t extensionDataLen;
    uint16_t maj, min;

    psDynBufAppendOctets(extBuf, extensionType, 2);

    /* The data for versions vector */
    psDynBufInit(ssl->hsPool, &workBuf,
                 TLS_MAX_SUPPORTED_VERSIONS * 2);

    for (i = 0; i < ssl->supportedVersionsPriorityLen; i++)
    {
        maj = psEncodeVersionMaj(ssl->supportedVersionsPriority[i]);
        min = psEncodeVersionMin(ssl->supportedVersionsPriority[i]);

        psDynBufAppendByte(&workBuf, maj);
        psDynBufAppendByte(&workBuf, min);
    }

    psTracePrintVersionsList(INDENT_HS_MSG,
            "supported_versions",
            ssl->supportedVersionsPriority,
            ssl->supportedVersionsPriorityLen,
            PS_FALSE);

    extensionData = psDynBufDetach(&workBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    /* ProtocolVersion versions<2..254>; */
    psDynBufInit(ssl->hsPool, &workBuf,
                 TLS_MAX_SUPPORTED_VERSIONS * 2 + 1);

    psDynBufAppendTlsVector(&workBuf,
            0, 254,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetach(&workBuf,
                                    &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);
    return PS_SUCCESS;
}

# ifndef USE_ONLY_PSK_CIPHER_SUITE
static
int32_t tls13WriteKeyShareEntry(ssl_t *ssl,
        psDynBuf_t *sharesBuf,
        uint16_t namedGroup,
        psPubKey_t *key)
{
    unsigned char *pubVal;
    psSize_t pubValLen;
    int32_t rc;

    /*
      struct {
          NamedGroup group;
          opaque key_exchange<1..2^16-1>;
      } KeyShareEntry;
    */

    /* NamedGroup group. */
    psDynBufAppendAsBigEndianUint16(sharesBuf, namedGroup);

    psTracePrintTls13NamedGroup(INDENT_EXTENSION,
            NULL,
            namedGroup,
            PS_TRUE);
    rc = tls13ExportPublicValue(ssl,
            namedGroup,
            key,
            &pubVal,
            &pubValLen);
    if (rc < 0)
    {
        return rc;
    }

    /*   opaque key_exchange<1..2^16-1>; */
    psDynBufAppendTlsVector(sharesBuf,
            1, (1 << 16) - 1,
            pubVal,
            pubValLen);

    psFree(pubVal, ssl->hsPool);

    return PS_SUCCESS;
}

static
int32_t tls13WriteClientKeyShare(ssl_t *ssl, psDynBuf_t *extBuf)
{
    psDynBuf_t workBuf;
    unsigned char extensionType[2] = {0x00, EXT_KEY_SHARE};
    unsigned char *extensionData;
    size_t extensionDataLen;
    int32_t rc;
    psSize_t i;

    psTracePrintExtensionCreate(ssl, EXT_KEY_SHARE);

    /* Generate necessary shares for the supported_groups */

    if (ssl->tls13IncorrectDheKeyShare)
    {
        /* This is a reply to HelloRetryRequest which indicated that our
         * key share in the original ClientHello was incorrect.
         * Redo the extension with correct one (in ssl->tls13NegotiatedGroup)*/

        /* Delete the non-needed keys */
        i = 0;
        while (ssl->sec.tls13KeyAgreeKeys[i] != NULL)
        {
            psDeletePubKey(&ssl->sec.tls13KeyAgreeKeys[i]);
            ssl->sec.tls13KeyAgreeKeys[i] = NULL;
            i++;
        }
        /* Search for the negotiated group in the group array */
        for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
        {
            if (ssl->tls13SupportedGroups[i] == ssl->tls13NegotiatedGroup)
            {
                /* Found the negotiated group. Need to swap it with
                   the original first item in the array so that the
                   key share will be generated for it */
                ssl->tls13SupportedGroups[i] = ssl->tls13SupportedGroups[0];
                ssl->tls13SupportedGroups[0] = ssl->tls13NegotiatedGroup;
                break;
            }
        }
        /* Must make only one key share according to spec when replying to
           HelloRetryRequest */
        ssl->tls13NumClientHelloKeyShares = 1;
        ssl->sec.tls13KsState.generateEcdheKeyDone = 0;
    }

    psDynBufAppendOctets(extBuf, extensionType, 2);

#ifndef USE_ONLY_PSK_CIPHER_SUITE
    /* Generate keys. */
    rc = tls13GenerateEphemeralKeys(ssl);
    if (rc < 0)
    {
        return rc;
    }

    /* KeyShareEntry client_shares<0..2^16-1>; */
    psDynBufInit(ssl->hsPool, &workBuf, 256);

    /* Write client shares. */
    for (i = 0; i < ssl->tls13NumClientHelloKeyShares; i++)
    {
        psAssert(ssl->sec.tls13KeyAgreeKeys[i] != NULL);
        rc = tls13WriteKeyShareEntry(ssl,
                &workBuf,
                ssl->tls13SupportedGroups[i],
                ssl->sec.tls13KeyAgreeKeys[i]);
        if (rc < 0)
        {
            psDynBufUninit(&workBuf);
            return rc;
        }
    }
    extensionData = psDynBufDetach(&workBuf,
                                    &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufInit(ssl->hsPool, &workBuf, 256);
    psDynBufAppendTlsVector(&workBuf,
            1, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetach(&workBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);
# endif
    return PS_SUCCESS;
}

static int32_t tls13WriteClientSupportedGroups(ssl_t *ssl, psDynBuf_t *extBuf)
{
    psDynBuf_t workBuf;
    uint32_t i = 0;
    unsigned char extensionType[2] = {0x00, EXT_SUPPORTED_GROUPS};
    unsigned char *extensionData;
    size_t extensionDataLen;

    psTracePrintExtensionCreate(ssl, EXT_SUPPORTED_GROUPS);

    psDynBufAppendOctets(extBuf, extensionType, 2);

    /* NamedGroup named_group_list<2..2^16-1> */
    psDynBufInit(ssl->hsPool, &workBuf, 64);

    /* NamedGroup groups (2-byte curve ID). */
    while (ssl->tls13SupportedGroups[i] != 0)
    {
        psDynBufAppendAsBigEndianUint16(&workBuf, ssl->tls13SupportedGroups[i]);
        i++;
    }

    extensionData = psDynBufDetach(&workBuf,
            &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufInit(ssl->hsPool, &workBuf, 64);
    psDynBufAppendTlsVector(&workBuf,
            1, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetach(&workBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);
    return PS_SUCCESS;
}
#   endif /* USE_ONLY_PSK_CIPHER_SUITE */
#  endif /* USE_CLIENT_SIDE_SSL */

int32_t tls13WriteSigAlgs(ssl_t *ssl,
        psDynBuf_t *extBuf,
        const uint16_t sigAlgs[],
        const psSize_t sigAlgsLen,
        const uint8_t extensionType)
{
    psDynBuf_t workBuf;
    psSize_t i = 0;
    unsigned char extType[2];
    unsigned char *extensionData;
    size_t extensionDataLen;

    psTracePrintExtensionCreate(ssl, extensionType);

    if (sigAlgsLen == 0)
    {
        psTraceInfo("Could not create SIGNATURE_ALGORITHMS extension " \
                "because no sig_algs are enabled \n");
        goto out_internal_error;
    }

    extType[0] = 0;
    extType[1] = extensionType;

    psDynBufAppendOctets(extBuf, extType, 2);

    /* Data for the supported_signature_algorithms vector */
    psDynBufInit(ssl->hsPool, &workBuf,
                 TLS_MAX_SIGNATURE_ALGORITHMS * 2);

    for (i = 0; i < sigAlgsLen; i++)
    {
        psDynBufAppendAsBigEndianUint16(&workBuf, sigAlgs[i]);
    }
    extensionData = psDynBufDetach(&workBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        goto out_internal_error;
    }

    /* SignatureScheme supported_signature_algorithms<2..2^16-2> */
    psDynBufInit(ssl->hsPool, &workBuf,
                 TLS_MAX_SIGNATURE_ALGORITHMS * 2 + 2);
    psDynBufAppendTlsVector(&workBuf,
            1, (1 << 16) - 1,
            extensionData,
            extensionDataLen);

    psFree(extensionData, ssl->hsPool);

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetach(&workBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        goto out_internal_error;
    }

    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);

    return PS_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}

# ifdef USE_IDENTITY_CERTIFICATES
int32_t tls13WriteCertificateAuthorities(ssl_t *ssl,
        psDynBuf_t *extBuf)
{
    psDynBuf_t dnBuf;
    psDynBuf_t caBuf;
    unsigned char extensionType[2] = {0x00, EXT_CERTIFICATE_AUTHORITIES};
    unsigned char *extensionData;
    size_t extensionDataLen;
    psX509Cert_t *cert;

    psTracePrintExtensionCreate(ssl, EXT_CERTIFICATE_AUTHORITIES);

    /* opaque DistinguishedName<1..2^16-1>;
         struct {
             DistinguishedName authorities<3..2^16-1>;
         } CertificateAuthoritiesExtension; */
    cert = ssl->keys->CAcerts;
    if (cert == NULL)
    {
#  ifdef SERVER_CAN_SEND_EMPTY_CERT_REQUEST
        /* Return success even in the case of no CAs in which
           case the extension is omitted. This might not be an error
           situation in case the cert verification is done by the
           application using the callback */
        return MATRIXSSL_SUCCESS;
#  else
        psTraceInfo("Failed writing certificate_authorities because no " \
                    "CA certificates configured. Configure CA certificates or "\
                     "define SERVER_CAN_SEND_EMPTY_CERT_REQUEST.\n");
        return PS_ARG_FAIL;
#  endif
    }
    psDynBufAppendOctets(extBuf, extensionType, 2);
    psDynBufInit(ssl->hsPool, &dnBuf, 1024);
#  ifdef USE_CERT_PARSE
    while (cert)
    {
        if (cert->parseStatus == PS_X509_PARSE_SUCCESS)
        {
            psDynBufAppendTlsVector(&dnBuf,
                    1, (1 << 16) - 1,
                    (unsigned char *)cert->subject.dnenc,
                    cert->subject.dnencLen);
        }
        cert = cert->next;
    }
#  endif
    extensionData = psDynBufDetach(&dnBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        psDynBufUninit(&dnBuf);
        return PS_MEM_FAIL;
    }
    psDynBufInit(ssl->hsPool, &caBuf, 1024);
    psDynBufAppendTlsVector(&caBuf,
            3, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);

    extensionData = psDynBufDetach(&caBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        psDynBufUninit(&caBuf);
        return PS_MEM_FAIL;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);
    return PS_SUCCESS;
}
# endif /* USE_IDENTITY_CERTIFICATES */

int32_t tls13WriteEarlyData(ssl_t *ssl,
                           psDynBuf_t *extBuf,
                           const uint32_t maxEarlyData)
{
    unsigned char extensionType[2] = {0x00, EXT_EARLY_DATA};

    psTracePrintExtensionCreate(ssl, EXT_EARLY_DATA);

    psDynBufAppendOctets(extBuf, extensionType, 2);

    /* Length */
    if (maxEarlyData == 0)
    {
        psDynBufAppendByte(extBuf, 0x00);
        psDynBufAppendByte(extBuf, 0x00);
    }
    else
    {
        psDynBufAppendByte(extBuf, 0x00);
        psDynBufAppendByte(extBuf, 0x04);
        psDynBufAppendAsBigEndianUint32(extBuf, maxEarlyData);
    }

    return PS_SUCCESS;
}

#  ifdef USE_SERVER_SIDE_SSL
static int32_t tls13WriteServerSupportedVersions(ssl_t *ssl,
        psDynBuf_t *extBuf)
{
    psDynBuf_t verBuf;
    unsigned char extensionType[2] = {0x00, EXT_SUPPORTED_VERSIONS};
    unsigned char *extensionData;
    unsigned char maj, min;
    size_t extensionDataLen;

    psTracePrintExtensionCreate(ssl, EXT_SUPPORTED_VERSIONS);

    psDynBufAppendOctets(extBuf, extensionType, 2);

    /* ProtocolVersion selected_version; */
    psDynBufInit(ssl->hsPool, &verBuf, 2);
    maj = psEncodeVersionMaj(GET_ACTV_VER(ssl));
    min = psEncodeVersionMin(GET_ACTV_VER(ssl));
    psDynBufAppendOctets(&verBuf, &maj, 1);
    psDynBufAppendOctets(&verBuf, &min, 1);

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetach(&verBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);
    return PS_SUCCESS;
}

#  endif /* USE_SERVER_SIDE_SSL */

#  ifdef USE_CLIENT_SIDE_SSL
static int32_t tls13WriteExtendedMasterSecret(ssl_t *ssl,
        psDynBuf_t *extBuf,
        sslSessOpts_t *options)
{
    unsigned char extensionType[2] = {0x00, EXT_EXTENDED_MASTER_SECRET};
    short extendedMasterSecret;

    psTracePrintExtensionCreate(ssl, EXT_EXTENDED_MASTER_SECRET);

    /*
      If the ClientHello is a response to a HRR, we don't have
      the session options around anymore. Check if we encoded
      the extension last time, if yes, encode again to comply
      with the requirement that the CH should be unchanged, except
      for the changes listed in 4.1.2.
    */
    if (ssl->tls13IncorrectDheKeyShare
        && ssl->extFlags.req_extended_master_secret == 1)
    {
        extendedMasterSecret = ssl->sec.tls13ExtendedMasterSecretOpt;
    }
    else
    {
        if (!options)
        {
            return PS_ARG_FAIL;
        }
        extendedMasterSecret = options->extendedMasterSecret;
    }

    if (extendedMasterSecret >= 0)
    {
        if (extendedMasterSecret > 0)
        {
            /* User is REQUIRING the server to support it */
            ssl->extFlags.require_extended_master_secret = 1;
        }
        psDynBufAppendOctets(extBuf, extensionType, 2);
        psDynBufAppendByte(extBuf, 0);
        psDynBufAppendByte(extBuf, 0);
        ssl->extFlags.req_extended_master_secret = 1;
        ssl->sec.tls13ExtendedMasterSecretOpt = extendedMasterSecret;
    }

    return PS_SUCCESS;
}

#   ifdef ENABLE_SECURE_REHANDSHAKES
static int32_t tls13WriteRenegotiationInfo(ssl_t *ssl,
        psDynBuf_t *extBuf)
{
    unsigned char emptyRenegotiationInfo[] =
    {
        0xff, 0x01, 0x00, 0x01, 0x00
    };

    psTracePrintExtensionCreate(ssl, EXT_RENEGOTIATION_INFO);

    psDynBufAppendOctets(extBuf, emptyRenegotiationInfo, 5);

    ssl->extFlags.req_renegotiation_info = 1;

    return PS_SUCCESS;
}
#   endif /* ENABLE_SECURE_REHANDSHAKES */
#  endif /* USE_CLIENT_SIDE_SSL */

#  ifdef USE_SERVER_SIDE_SSL
#   ifndef USE_ONLY_PSK_CIPHER_SUITE
static int32_t tls13WriteServerKeyShare(ssl_t *ssl,
        psDynBuf_t *extBuf,
        psBool_t isHelloRetryRequest)
{
    psDynBuf_t keyShareBuf;
    unsigned char extensionType[2];
    unsigned char *extensionData;
    size_t extensionDataLen;
    unsigned char *pubVal;
    psSize_t pubValLen;
    uint16_t namedGroup;
    psPubKey_t *privKey;
    int32_t rc;

    extensionType[0] = 0x00;
    if (NGTD_VER(ssl, v_tls_1_3_key_share_51))
    {
        extensionType[1] = EXT_KEY_SHARE;
    }
    else
    {
        /* Extension had a different ID in pre-23 drafts. */
        extensionType[1] = EXT_KEY_SHARE_PRE_DRAFT_23;
    }

    psTracePrintExtensionCreate(ssl, extensionType[1]);

    psDynBufAppendOctets(extBuf, extensionType, 2);

    psDynBufInit(ssl->hsPool, &keyShareBuf, 128);

    /*
      In a normal ServerHello, this is:
          struct {
               NamedGroup group;
               opaque key_exchange<1..2^16-1>;
          } KeyShareEntry;
          struct {
              KeyShareEntry server_share;
          } KeyShareServerHello;

      In a HelloRetryRequest, we only encode the name of the group
      that we want the client to generate a share for:
          struct {
              NamedGroup selected_group;
          } KeyShareHelloRetryRequest;
    */

    if (isHelloRetryRequest)
    {
        rc = tls13ServerChooseHelloRetryRequestGroup(ssl, &namedGroup);
        if (rc < 0)
        {
            return rc;
        }
    }
    else
    {
        namedGroup = ssl->tls13NegotiatedGroup;
    }

    /* NamedGroup group (2-byte curve ID). */
    psDynBufAppendAsBigEndianUint16(&keyShareBuf, namedGroup);

    if (!isHelloRetryRequest)
    {
        /* Standard ServerHello --> KeyShareServerHello. */
        rc = tls13GenerateEphemeralKeys(ssl);
        if (rc < 0)
        {
            return rc;
        }

        privKey = tls13GetGroupKey(ssl, namedGroup);

        psTracePrintTls13NamedGroup(INDENT_EXTENSION,
                NULL,
                namedGroup,
                PS_TRUE);
        rc = tls13ExportPublicValue(ssl,
                namedGroup,
                privKey,
                &pubVal,
                &pubValLen);
        if (rc < 0)
        {
            return rc;
        }

        /*   opaque key_exchange<1..2^16-1>; */
        psDynBufAppendTlsVector(&keyShareBuf,
                1, (1 << 16) - 1,
                pubVal, pubValLen);
        psFree(pubVal, ssl->hsPool);
    }

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetach(&keyShareBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }

    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);

    psDynBufUninit(&keyShareBuf);

    return PS_SUCCESS;
}
#   endif /* USE_ONLY_PSK_CIPHER_SUITE */
#  endif /* USE_SERVER_SIDE_SSL */

static
int32_t tls13WritePskIdentity(ssl_t *ssl,
        psDynBuf_t *pskBuf,
        psTls13Psk_t *psk)
{
    psDynBuf_t idBuf;
    unsigned char *id;
    psSize_t idLen;
    uint32 zero[] = { 0 };
    uint32 obfuscatedTicketAge = 0;
    psTime_t now;
    psTime_t zeroTime;

    Memset(&zeroTime, 0, sizeof(zeroTime));

    psDynBufInit(ssl->hsPool, &idBuf, psk->pskIdLen);
    psDynBufAppendOctets(&idBuf, psk->pskId, psk->pskIdLen);
    id = psDynBufDetachPsSize(&idBuf, &idLen);
    if (id == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufUninit(&idBuf);

    /* opaque identity<1..2^16-1>; */
    psDynBufAppendTlsVector(pskBuf,
            1, (1 << 16) - 1,
            id,
            idLen);
    psFree(id, ssl->hsPool);

    /* uint32 obfuscated_ticket_age; zero for external PSKs,
       otherwise calculated based on the ticket age and parameters */
    if (psk->params != NULL
            && Memcmp(&psk->params->timestamp, &zeroTime, sizeof(psTime_t)))
    {
        psGetTime(&now, NULL);
        obfuscatedTicketAge = psDiffMsecs(psk->params->timestamp, now, NULL) +
                psk->params->ticketAgeAdd;
        psDynBufAppendAsBigEndianUint32(pskBuf, obfuscatedTicketAge);
    }
    else
    {
        psDynBufAppendOctets(pskBuf, zero, 4);
    }
    return PS_SUCCESS;
}

static
int32_t tls13WritePskBinderPlaceholder(ssl_t *ssl,
        psDynBuf_t *pskBuf,
        psTls13Psk_t *psk)
{
    unsigned char dummyBinder[64] = {0};
    psSize_t hashLen;
    psSize_t binderLen;

    hashLen = tls13GetPskHashLen(psk);
    psAssert(hashLen > 0);

    /* pskLen must be equal to the ciphersuite hash len.
       The binder HMAC will be of the same size. */
    binderLen = hashLen;

    /* opaque PskBinderEntry<32..255>; */
    psDynBufAppendTlsVector(pskBuf,
            32, 255,
            dummyBinder,
            binderLen);

    return PS_SUCCESS;
}

int32_t tls13FillInPskBinders(ssl_t *ssl,
        unsigned char *bindersStart)
{
    int32_t rc;
    unsigned char *p = bindersStart;
    unsigned char binderKey[MAX_TLS_1_3_HASH_SIZE];
    psSize_t binderKeyLen;
    unsigned char binderValue[MAX_TLS_1_3_HASH_SIZE];
    psTls13Psk_t *psk;
    int32_t hmacAlg, hmacLen;
    psHmac_t ctx;

    /* Jump over length octets: PskBinderEntry binders<33..2^16-1> */
    p += 2;

    /* Iterate over PSKs in the same order as we did when writing the
       PskIdentities. */
    psk = ssl->sec.tls13SessionPskList;
    while (psk)
    {
        hmacAlg = tls13GetPskHmacAlg(psk);
        hmacLen = tls13GetPskHashLen(psk);

        psTraceBytes("PSK identity", psk->pskId, psk->pskIdLen);
        psTraceBytes("PSK key", psk->pskKey, psk->pskLen);

        /* Jump over length octet: opaque PskBinderEntry<32..255>; */
        p += 1;

        /* Compute the binder_key for the PSK. */
        rc = tls13DeriveEarlySecrets(ssl, psk);
        if (rc < 0)
        {
            return rc;
        }
# ifdef DEBUG_TLS_1_3_ENCODE_EXTENSIONS
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
            return rc;
        }

# ifdef DEBUG_TLS_1_3_ENCODE_EXTENSIONS
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
                binderValue);
        if (rc < 0)
        {
            return rc;
        }
# ifdef DEBUG_TLS_1_3_ENCODE_EXTENSIONS
        psTraceBytes("binder value", binderValue, hmacLen);
# endif
        Memcpy(p, binderValue, hmacLen);
        p += hmacLen;

        psk = psk->next;
    }

    psAssert(p - bindersStart == ssl->sec.tls13BindersLen);

    return PS_SUCCESS;
}

static
int32_t tls13WritePreSharedKey(ssl_t *ssl,
        psDynBuf_t *extBuf,
        psBool_t isHelloRetryRequest)
{
    psDynBuf_t pskBuf, idBuf, binderBuf;
    unsigned char extensionType[2] = { 0x00, EXT_PRE_SHARED_KEY };
    unsigned char *extensionData;
    psSize_t extensionDataLen;
    psTls13Psk_t *psk;
    unsigned char *ids, *binders;
    psSize_t idsLen, bindersLen;
    int32_t rc;

    psTracePrintExtensionCreate(ssl, EXT_PRE_SHARED_KEY);

    psDynBufAppendOctets(extBuf, extensionType, 2);
    psDynBufInit(ssl->hsPool, &pskBuf, 64);

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
        psDynBufAppendAsBigEndianUint16(&pskBuf,
                ssl->sec.tls13SelectedIdentityIndex);
    }
    else
    {
        psk = ssl->sec.tls13SessionPskList;
        psAssert(psk != NULL);
        psDynBufInit(ssl->hsPool, &idBuf, 128);
        psDynBufInit(ssl->hsPool, &binderBuf, 128);
        while (psk != NULL)
        {
            rc = tls13WritePskIdentity(ssl, &idBuf, psk);
            if (rc < 0)
            {
                goto out_internal_failure;
            }
            rc = tls13WritePskBinderPlaceholder(ssl, &binderBuf, psk);
            if (rc < 0)
            {
                goto out_internal_failure;
            }
            psk = psk->next;
        }

        ids = psDynBufDetachPsSize(&idBuf, &idsLen);
        if (ids == NULL)
        {
            goto out_internal_failure;
        }
        psDynBufUninit(&idBuf);

        /* PskIdentity identities<7..2^16-1>; */
        psDynBufAppendTlsVector(&pskBuf,
                7, (1 << 16) - 1,
                ids,
                idsLen);
        psFree(ids, ssl->hsPool);

        binders = psDynBufDetachPsSize(&binderBuf, &bindersLen);
        if (binders == NULL)
        {
            goto out_internal_failure;
        }
        psDynBufUninit(&binderBuf);

        /* PskBinderEntry binders<33..2^16-1>; */
        psDynBufAppendTlsVector(&pskBuf,
                33, (1 << 16) - 1,
                binders,
                bindersLen);
        psFree(binders, ssl->hsPool);
        ssl->sec.tls13BindersLen = bindersLen + 2;
    }

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetachPsSize(&pskBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        goto out_internal_failure;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);

    psFree(extensionData, ssl->hsPool);
    psDynBufUninit(&pskBuf);

    return PS_SUCCESS;

out_internal_failure:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}


static
int32_t tls13WriteCookie(ssl_t *ssl,
        psDynBuf_t *extBuf,
        psBool_t isHelloRetryRequest)
{
    psDynBuf_t cookieBuf;
    unsigned char *cookie;
    psResSize_t cookieLen;
    unsigned char extensionType[2] = { 0x00, EXT_COOKIE };
    unsigned char *extensionData;
    psSize_t extensionDataLen;

    psTracePrintExtensionCreate(ssl, EXT_COOKIE);

    psDynBufAppendOctets(extBuf, extensionType, 2);
    psDynBufInit(ssl->hsPool, &cookieBuf, 48);

    if (IS_SERVER(ssl))
    {
        psAssert(isHelloRetryRequest);

        /* Server sends the ClientHello1 hash in the cookie.*/
        cookie = ssl->sec.tls13TrHashSnapshotCH1;
        cookieLen = psGetOutputBlockLength(tls13GetCipherHmacAlg(ssl));
        if (cookieLen < 0)
        { /* errorCode returned for unknown hmac */
            return cookieLen;
        }
    }
    else
    {
        /* Client sends back the received cookie. */
        cookie = ssl->sec.tls13CookieFromServer;
        cookieLen = ssl->sec.tls13CookieFromServerLen;
        psAssert(cookie && cookieLen > 0);
    }

    /*
      struct {
          opaque cookie<1..2^16-1>;
      } Cookie;
    */

    /*   opaque cookie<1..2^16-1>;; */
    psDynBufAppendTlsVector(&cookieBuf,
            1, (1 << 16) - 1,
            cookie,
            cookieLen);

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetachPsSize(&cookieBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);

# ifdef DEBUG_TLS_1_3_ENCODE_EXTENSIONS
    if (IS_SERVER(ssl))
    {
        psTraceBytes("Encoded HelloRetryRequest.cookie",
                cookie,
                cookieLen);
    }
    else
    {
        psTraceBytes("Encoded ClientHello.cookie",
                cookie,
                cookieLen);
    }
# endif

    psFree(extensionData, ssl->hsPool);
    psDynBufUninit(&cookieBuf);

    return PS_SUCCESS;
}

#  ifdef USE_SERVER_SIDE_SSL
/*
  Add mandatory extensions to TLS 1.3 ServerHello:
  supported_versions, key_share
*/
int32 tls13WriteServerHelloExtensions(ssl_t *ssl,
        psDynBuf_t *extBuf,
        psBool_t isHelloRetryRequest)
{
    int32 rc;

    /*
         struct {
          ExtensionType extension_type;
          opaque extension_data<0..2^16-1>;
         } Extension;
    */

    rc = tls13WriteServerSupportedVersions(ssl, extBuf);
    if (rc < 0)
    {
        return rc;
    }
# ifndef USE_ONLY_PSK_CIPHER_SUITE
    rc = tls13WriteServerKeyShare(ssl, extBuf, isHelloRetryRequest);
    if (rc < 0)
    {
        return rc;
    }
# endif
    if (ssl->sec.tls13UsingPsk)
    {
        rc = tls13WritePreSharedKey(ssl, extBuf, isHelloRetryRequest);
        if (rc < 0)
        {
            return rc;
        }
    }

    if (isHelloRetryRequest)
    {
        rc = tls13WriteCookie(ssl, extBuf, isHelloRetryRequest);
        if (rc < 0)
        {
            return rc;
        }
    }

    return PS_SUCCESS;
}
#  endif /* USE_SERVER_SIDE_SSL */

#  ifdef USE_CLIENT_SIDE_SSL
static
int32_t tls13WritePskKeyExchangeModes(ssl_t *ssl,
        psDynBuf_t *extBuf)
{
    psDynBuf_t buf, modesBuf;
    unsigned char extensionType[2] = { 0x00, EXT_PSK_KEY_EXCHANGE_MODES };
    unsigned char *modes, *extensionData;
    psSize_t modesLen, extensionDataLen;
    unsigned char psk_ke = 0;
    unsigned char psk_dhe_ke = 1;

    psTracePrintExtensionCreate(ssl, EXT_PSK_KEY_EXCHANGE_MODES);

    /*
      enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

      struct {
          PskKeyExchangeMode ke_modes<1..255>;
      } PskKeyExchangeModes;
    */

    psDynBufAppendOctets(extBuf, extensionType, 2);

    psDynBufInit(ssl->hsPool, &buf, 6);
    psDynBufInit(ssl->hsPool, &modesBuf, 4);

    /* Always support both psk_dhe_ke and psk_ke. We can always support
       psk_dhe_ke, because we always encode a key_share currently. Caller
       has already ensured that we have a PSK for psk_ke. */
    psDynBufAppendOctets(&modesBuf, &psk_dhe_ke, 1);
    psDynBufAppendOctets(&modesBuf, &psk_ke, 1);

    modes = psDynBufDetachPsSize(&modesBuf, &modesLen);
    if (modes == NULL)
    {
        goto out_internal_failure;
    }
    psDynBufUninit(&modesBuf);

    /* PskKeyExchangeMode ke_modes<1..255>; */
    psDynBufAppendTlsVector(&buf,
            1, 255,
            modes,
            modesLen);
    psFree(modes, ssl->hsPool);

    /*   opaque extensionData<0..2^16-1>; */
    extensionData = psDynBufDetachPsSize(&buf, &extensionDataLen);
    if (extensionData == NULL)
    {
        goto out_internal_failure;
    }
    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);

    psFree(extensionData, ssl->hsPool);
    psDynBufUninit(&buf);
    return PS_SUCCESS;

out_internal_failure:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}

int32_t tls13WriteUserExtensions(ssl_t *ssl,
        psDynBuf_t *extBuf,
        tlsExtension_t *userExt)
{
    tlsExtension_t *ext = userExt;
    uint16_t type;

    while (ext)
    {
        type = ext->extType;
        psTracePrintExtensionCreate(ssl, type);

        switch (type)
        {
        case EXT_SERVER_NAME:
            ssl->extFlags.req_sni = 1;
            break;
        case EXT_ALPN:
            ssl->extFlags.req_alpn = 1;
            break;
        default:
            psTraceIntInfo("Unsupported user extension provided: %d\n", type);
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return MATRIXSSL_ERROR;
        }

        psDynBufAppendAsBigEndianUint16(extBuf, type);
        psDynBufAppendTlsVector(extBuf,
                0, (1 << 16) - 1,
                ext->extData,
                ext->extLen);

        ext = ext->next;
    }

    return MATRIXSSL_SUCCESS;
}

#  endif /* USE_CLIENT_SIDE_SSL */

# ifdef USE_OCSP_RESPONSE
int32_t tls13WriteOCSPStatusRequest(ssl_t *ssl,
        psDynBuf_t *extBuf)
{
    psDynBuf_t statReqBuf;
    unsigned char extensionType[2] = { 0x00, EXT_STATUS_REQUEST };
    unsigned char *extensionData;
    psSizeL_t extensionDataLen;
    unsigned char empty_status_request[] =
    {
        0x01, /* status_type */
        0x00, 0x00, /* empty responder_id_list */
        0x00, 0x00 /* empty request_extensions */
    };

    psTracePrintExtensionCreate(ssl, EXT_STATUS_REQUEST);

    /*
      A bit confusingly, the same status_request extension is used
      for the request in ClientHello and for the response in server
      Certificate.

      Client-side:

      struct {
          CertificateStatusType status_type = ocsp(1);
          ResponderID responder_id_list<0..2^16-1>;
          Extensions  request_extensions;
      } CertificateStatusRequest;

      enum { ocsp(1), (255) } CertificateStatusType;

      opaque ResponderID<1..2^16-1>;
      opaque Extensions<0..2^16-1>;

      Server-side:

      struct {
          CertificateStatusType status_type;
          select (status_type) {
              case ocsp: OCSPResponse;
          } response;
      } CertificateStatus;

      opaque OCSPResponse<1..2^24-1>;
    */

    psDynBufAppendOctets(extBuf, extensionType, 2);

    if (IS_SERVER(ssl))
    {
#  ifdef USE_SERVER_SIDE_SSL
        /* Server sends the stored OCSPResponse. */
        psAssert(ssl->keys->OCSPResponseBuf
                && ssl->keys->OCSPResponseBufLen > 0);
        psDynBufInit(ssl->hsPool, &statReqBuf,
                4 + ssl->keys->OCSPResponseBufLen);

        /* CertificateStatusType status_type */
        psDynBufAppendByte(&statReqBuf, 0x01);

        /* opaque OCSPResponse<1..2^24-1>; */
        psDynBufAppendTlsVector(&statReqBuf,
                1, (1 << 24) - 1,
                ssl->keys->OCSPResponseBuf,
                ssl->keys->OCSPResponseBufLen);
#  endif /* ifdef USE_SERVER_SIDE_SSL */
    }
    else
    {
        /* Client sends empty responder_id_list and empty request_extensions
           vectors. */
        psDynBufInit(ssl->hsPool, &statReqBuf, 5);
        psDynBufAppendOctets(&statReqBuf, empty_status_request, 5);
    }

    extensionData = psDynBufDetach(&statReqBuf, &extensionDataLen);
    if (extensionData == NULL)
    {
        goto out_internal_error;
    }

    psDynBufAppendTlsVector(extBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);

    psFree(extensionData, ssl->hsPool);

    return PS_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}
#  endif /* USE_OCSP_RESPONSE */

#  ifdef USE_CLIENT_SIDE_SSL
int32_t tls13WriteClientHelloExtensions(ssl_t *ssl,
        psDynBuf_t *extBuf,
        tlsExtension_t *userExt,
        sslSessOpts_t *options)
{
    int32_t rc;

    /*
       struct {
          ExtensionType extension_type;
          opaque extension_data<0..2^16-1>;
       } Extension;
    */

    rc = tls13WriteClientSupportedVersions(ssl, extBuf);
    if (rc < 0)
    {
        return rc;
    }
    rc = tls13WriteSigAlgs(ssl,
            extBuf,
            ssl->supportedSigAlgs,
            ssl->supportedSigAlgsLen,
            EXT_SIGNATURE_ALGORITHMS);
    if (rc < 0)
    {
        return rc;
    }

    rc = tls13WriteSigAlgs(ssl,
            extBuf,
            ssl->tls13SupportedSigAlgsCert,
            ssl->tls13SupportedSigAlgsCertLen,
            EXT_SIGNATURE_ALGORITHMS_CERT);
    if (rc < 0)
    {
        return rc;
    }
# ifndef USE_ONLY_PSK_CIPHER_SUITE
    rc = tls13WriteClientSupportedGroups(ssl, extBuf);
    if (rc < 0)
    {
        return rc;
    }

    rc = tls13WriteClientKeyShare(ssl, extBuf);
    if (rc < 0)
    {
        return rc;
    }
# endif /* USE_ONLY_PSK_CIPHER_SUITE */
    if (ssl->tls13IncorrectDheKeyShare)
    {
        if (ssl->sec.tls13CookieFromServer
                && ssl->sec.tls13CookieFromServerLen > 0)
        {
            rc = tls13WriteCookie(ssl, extBuf, PS_FALSE);
            if (rc < 0)
            {
                return rc;
            }
        }
    }

#  if defined(USE_OCSP_RESPONSE) && defined(USE_SERVER_SIDE_SSL)
    /*
      Add OCSP status request if:
      - it was requested in the session options
      - we are in the middle of an incorrect DHE handshake and we encoded
        status_request in CH1 (options == NULL in that case).
    */
    if ((options && options->OCSPstapling == 1) ||
            (ssl->tls13IncorrectDheKeyShare
                    && ssl->extFlags.req_status_request == 1))
    {
        rc = tls13WriteOCSPStatusRequest(ssl, extBuf);
        if (rc < 0)
        {
            return rc;
        }
        ssl->extFlags.req_status_request = 1;
    }
#  endif /* USE_OCSP_RESPONSE */
    /* Add user-provided extensions, e.g. server_name (SNI). */
    if (ssl->userExt)
    {
        rc = tls13WriteUserExtensions(ssl, extBuf, ssl->userExt);
        if (rc < 0)
        {
            return rc;
        }
    }
    /*
      When offering TLS 1.0, 1.1 or 1.2, add some security-critical
      TLS 1.2 extensions.

      Not that some old, incompliant TLS 1.0 implementations
      may not be able to parse any extensions.
    */
    if (SUPP_VER(ssl, v_tls_legacy))
    {
        rc = tls13WriteExtendedMasterSecret(ssl, extBuf, options);
        if (rc < 0)
        {
            return rc;
        }
#  ifdef ENABLE_SECURE_REHANDSHAKES
        rc = tls13WriteRenegotiationInfo(ssl, extBuf);
        if (rc < 0)
        {
            return rc;
        }
#  endif
    }

    if (ssl->sec.tls13SessionPskList != NULL ||
            (ssl->sid != NULL && ssl->sid->psk != NULL))
    {
        rc = tls13WritePskKeyExchangeModes(ssl, extBuf);
        if (rc < 0)
        {
            return rc;
        }
        if (ssl->tls13ClientEarlyDataEnabled == PS_TRUE)
        {
            rc = tls13WriteEarlyData(ssl, extBuf, 0);
            if (rc < 0)
            {
                return rc;
            }
        }
        /* Note: this extension MUST be the last one. */
        rc = tls13WritePreSharedKey(ssl, extBuf, PS_FALSE);
        if (rc < 0)
        {
            return rc;
        }
    }

    if (options)
    {
        if (options->maxFragLen == 0x200 ||
            options->maxFragLen == 0x400 ||
            options->maxFragLen == 0x800 ||
            options->maxFragLen == 0x1000)
        {
            ssl->maxPtFrag = options->maxFragLen;
        }
        else
        {
            ssl->maxPtFrag = SSL_MAX_PLAINTEXT_LEN;
        }
    }
    return PS_SUCCESS;
}
#  endif /* USE_CLIENT_SIDE_SSL */
#endif
