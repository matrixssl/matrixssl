/**
 *      @file    hsNegotiateVersion.c
 *      @version $Format:%h%d$
 *
 *      Functions for SSL/TLS version negotiation. Some of this code was
 *      originally in hsDecode.c
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

#include "matrixsslImpl.h"

uint16_t psEncodeVersion(uint32_t ver)
{
    ver = VER_GET_RAW(ver);

    switch (ver)
    {
    case v_ssl_3_0:
        return v_ssl_3_0_enc;
    case v_tls_1_0:
        return v_tls_1_0_enc;
    case v_dtls_1_0:
        return v_dtls_1_0_enc;
    case v_tls_1_1:
        return v_tls_1_1_enc;
    case v_tls_1_2:
        return v_tls_1_2_enc;
    case v_dtls_1_2:
        return v_dtls_1_2_enc;
    case v_tls_1_3_draft_22:
        return v_tls_1_3_draft_22_enc;
    case v_tls_1_3_draft_23:
        return v_tls_1_3_draft_23_enc;
    case v_tls_1_3_draft_24:
        return v_tls_1_3_draft_24_enc;
    case v_tls_1_3_draft_26:
        return v_tls_1_3_draft_26_enc;
    case v_tls_1_3_draft_28:
        return v_tls_1_3_draft_28_enc;
    case v_tls_1_3:
        return v_tls_1_3_enc;
    default:
        psTraceIntInfo("Tried to encode an unsupported version: %u\n", ver);
        return 0;
    }
}

uint8_t psEncodeVersionMin(uint32_t ver)
{
    uint32_t ver_enc = psEncodeVersion(ver);

    return (ver_enc & 0xff);
}

uint8_t psEncodeVersionMaj(uint32_t ver)
{
    uint32_t ver_enc = psEncodeVersion(ver);

    return ((ver_enc & 0xff00) >> 8);
}

psProtocolVersion_t psVerFromEncoding(uint16_t enc)
{
    switch (enc)
    {
    case v_ssl_3_0_enc:
        return v_ssl_3_0;
    case v_tls_1_0_enc:
        return v_tls_1_0;
    case v_tls_1_1_enc:
        return v_tls_1_1;
    case v_tls_1_2_enc:
        return v_tls_1_2;
    case v_tls_1_3_enc:
        return v_tls_1_3;
    case v_tls_1_3_draft_22_enc:
        return v_tls_1_3_draft_22;
    case v_tls_1_3_draft_23_enc:
        return v_tls_1_3_draft_23;
    case v_tls_1_3_draft_24_enc:
        return v_tls_1_3_draft_24;
    case v_tls_1_3_draft_26_enc:
        return v_tls_1_3_draft_26;
    case v_tls_1_3_draft_28_enc:
        return v_tls_1_3_draft_28;
    case v_dtls_1_0_enc:
        return v_dtls_1_0;
    case v_dtls_1_2_enc:
        return v_dtls_1_2;
    default:
        return v_undefined;
    }
}

psProtocolVersion_t psVerFromEncodingMajMin(uint8_t maj, uint8_t min)
{
    uint16_t ver = (maj << 8) | min;

    return psVerFromEncoding(ver);
}

int32_t psVerToFlag(psProtocolVersion_t ver)
{
    int32_t flags = 0;

    if (ver & v_ssl_3_0)
    {
        flags |= SSL_FLAGS_SSLV3;
    }
    else if (ver & v_tls_1_0)
    {
        flags |= SSL_FLAGS_TLS_1_0;
    }
    else if (ver & v_tls_1_1)
    {
        flags |= SSL_FLAGS_TLS_1_1;
    }
    else if (ver & v_tls_1_2)
    {
        flags |= SSL_FLAGS_TLS_1_2;
    }
    else if (ver & v_tls_1_3)
    {
        flags |= SSL_FLAGS_TLS_1_3;
    }
    else if (ver & v_tls_1_3_draft_22)
    {
        flags |= SSL_FLAGS_TLS_1_3_DRAFT_22;
    }
    else if (ver & v_tls_1_3_draft_24)
    {
        flags |= SSL_FLAGS_TLS_1_3_DRAFT_24;
    }
    else if (ver & v_tls_1_3_draft_26)
    {
        flags |= SSL_FLAGS_TLS_1_3_DRAFT_26;
    }
    else if (ver & v_tls_1_3_draft_28)
    {
        flags |= SSL_FLAGS_TLS_1_3_DRAFT_28;
    }
    else if (ver & v_dtls_1_0)
    {
        flags |= SSL_FLAGS_DTLS;
    }
    else if (ver & v_dtls_1_2)
    {
        flags |= SSL_FLAGS_DTLS;
        flags |= SSL_FLAGS_TLS_1_2;
    }

    return flags;
}

psProtocolVersion_t psFlagToVer(int32_t flag)
{
    psProtocolVersion_t ver = v_undefined;

    if (flag & SSL_FLAGS_SSLV3)
    {
        ver |= v_ssl_3_0;
    }
    if (flag & SSL_FLAGS_TLS_1_0)
    {
        ver |= v_tls_1_0;
    }
    if (flag & SSL_FLAGS_TLS_1_1)
    {
        ver |= v_tls_1_1;
    }
    if (flag & SSL_FLAGS_TLS_1_2)
    {
        ver |= v_tls_1_2;
    }
    if (flag & SSL_FLAGS_TLS_1_3)
    {
        ver |= v_tls_1_3;
    }
    if (flag & SSL_FLAGS_TLS_1_3_DRAFT_22)
    {
        ver |= v_tls_1_3_draft_22;
    }
    if (flag & SSL_FLAGS_TLS_1_3_DRAFT_23)
    {
        ver |= v_tls_1_3_draft_23;
    }
    if (flag & SSL_FLAGS_TLS_1_3_DRAFT_24)
    {
        ver |= v_tls_1_3_draft_23;
    }
    if (flag & SSL_FLAGS_TLS_1_3_DRAFT_26)
    {
        ver |= v_tls_1_3_draft_26;
    }
    if (flag & SSL_FLAGS_TLS_1_3_DRAFT_28)
    {
        ver |= v_tls_1_3_draft_28;
    }
    if (flag & SSL_FLAGS_DTLS)
    {
        ver |= v_dtls_1_0;
        if (flag & SSL_FLAGS_TLS_1_2)
        {
            ver |= v_dtls_1_2;
        }
    }

    return ver;
}

psProtocolVersion_t psVerGetLowest(psProtocolVersion_t ver,
        int allowDtls)
{
    psSize_t i;
    psProtocolVersion_t mask = 1;

    ver = VER_GET_RAW(ver);

    for (i = 0; i <= VER_MAX_BIT; i++)
    {
        if (ver & mask)
        {
            if (allowDtls || (mask & v_tls_any))
            {
                return mask;
            }
        }
        mask <<= 1;
    }

    return v_undefined;
}

psProtocolVersion_t psVerGetLowestTls(psProtocolVersion_t ver)
{
    return psVerGetLowest(ver, 0);
}

psProtocolVersion_t psVerGetHighest(psProtocolVersion_t ver,
        int allowDtls)
{
    psSize_t i;
    psProtocolVersion_t mask;

    ver = VER_GET_RAW(ver);

    mask = (1 << VER_MAX_BIT);
    for (i = VER_MAX_BIT; i > 0; i--)
    {
        if (ver & mask)
        {
            if (allowDtls || (mask & v_tls_any))
            {
                return mask;
            }
        }
        mask >>= 1;
    }

    return v_undefined;
}

psProtocolVersion_t psVerGetHighestTls(psProtocolVersion_t ver)
{
    return psVerGetHighest(ver, 0);
}

int32_t checkClientHelloVersion(ssl_t *ssl)
{
    psProtocolVersion_t clientHighest;
    psProtocolVersion_t negotiatedVer;
    psProtocolVersion_t ver;
    psBool_t clientWantsDtls = PS_FALSE, isDtls;
    psSize_t i;

    /*
      Check the client_version (legacy_version in TLS 1.3) field
      and try to negotiate a common version based on the field value.
      The semantics of this field is that it should be the highest
      version supported by the client (in TLS 1.2 and below) or should
      be ignored (in TLS 1.3).
    */

    clientHighest = ssl->peerHelloVersion;
    if (SUPP_VER(ssl, clientHighest))
    {
        negotiatedVer = clientHighest;
        goto out_ok;
    }

    if (clientHighest & v_dtls_any)
    {
        clientWantsDtls = PS_TRUE;
    }

    /* We don't support clientHighest. See if we can propose a downgrade. */

    /* Loop over our supported versions in priority order and select
       the first version lower than clientHighest. */
    for (i = 0; i < ssl->supportedVersionsPriorityLen; i++)
    {
        ver = ssl->supportedVersionsPriority[i];
        isDtls = (ver & v_dtls_any) ? PS_TRUE : PS_FALSE;

        /* Don't downgrade from TLS to DTLS, or vice versa. */
        if ((clientWantsDtls && !isDtls)
                || (!clientWantsDtls && isDtls))
        {
            continue;
        }
        if (ver < clientHighest)
        {
            negotiatedVer = ver;
            goto out_ok;
        }
    }

    /* Legacy (TLS <1.3) version negotiation failed. However, if the
       ClientHello contains a supported_versions extension, we shall
       still try to negotiate based on that. */
    ssl->err = SSL_ALERT_PROTOCOL_VERSION;
    return MATRIXSSL_ERROR;

out_ok:
    SET_NGTD_VER(ssl, negotiatedVer);
    return PS_SUCCESS;
}

/** Check whether the protocol version selected by the server can
    be supported for this handshake.

    @precond: ssl->peerHelloVersion contains the version parsed
    from ServerHello.server_version (called ServerHello.legacy_version
    in TLS 1.3).
*/
int32_t checkServerHelloVersion(ssl_t *ssl)
{
    psProtocolVersion_t serverVer;

    serverVer = ssl->peerHelloVersion;

    if (!SUPP_VER(ssl, serverVer))
    {
        psTraceErrr("Cannot support ServerHello.server_version\n");
        psTracePrintProtocolVersionNew(INDENT_HS_MSG,
                "Unsupported protocol version",
                serverVer,
                PS_TRUE);
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        return MATRIXSSL_ERROR;
    }

    /* Version negotiation complete for now. Result may get
       overriden by the supported_versions check. */
    SET_NGTD_VER(ssl, serverVer);
    return MATRIXSSL_SUCCESS;
}

# ifdef USE_TLS_1_3
int32_t checkSupportedVersions(ssl_t *ssl)
{
    int32 rc;
    psProtocolVersion_t selectedVersion = 0;
    psProtocolVersion_t forbiddenVer[16] = {0};
    psSize_t forbiddenVerLen = 0;
    psSize_t i = 0;

    if (!ssl->gotTls13CiphersuiteInCH)
    {
        /* Forbid TLS 1.3 if the client did not provide any TLS 1.3
           ciphersuites. */
        forbiddenVer[i++] = TLS_1_3_DRAFT_22_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_23_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_24_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_26_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_28_VER;
        forbiddenVer[i++] = TLS_1_3_VER;
        forbiddenVerLen = i;
    }

    /* Choose version from the intersection of our and the client's
       version list. */
    rc = tls13IntersectionPrioritySelect(ssl->supportedVersionsPriority,
            ssl->supportedVersionsPriorityLen,
            ssl->peerSupportedVersionsPriority,
            ssl->peerSupportedVersionsPriorityLen,
            forbiddenVer,
            forbiddenVerLen,
            &selectedVersion);
    if (rc < 0)
    {
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceErrr("Could not find common protocol version\n");
        return MATRIXSSL_ERROR;
    }

    SET_NGTD_VER(ssl, selectedVersion);

    return PS_SUCCESS;
}

/* Check the TLS 1.3 downgrade protection mechanism. */
int32_t performTls13DowngradeCheck(ssl_t *ssl)
{
    if (weOnlySupportTls13(ssl))
    {
        /* Don't allow the server to downgrade to an earlier version
           if we only support 1.3. This check is needed, because the
           legacy_version check above (checkServerHelloVersion) only
           works if not using TLS 1.3. */
        psTraceErrr("Server downgrade to earlier proto version " \
                "rejected: we only support TLS 1.3\n");
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        return MATRIXSSL_ERROR;
    }

    if (SUPP_VER(ssl, v_tls_1_3))
    {
        /* TLS 1.3 downgrade protection: if we support (non-draft)
           TLS 1.3 and the server chose <1.3, check that the last 8
           bytes of server_random do NOT contain a special value used by
           the server to indicate that it also supports TLS 1.3. */
        if (!Memcmp(ssl->sec.serverRandom + 24,
                        TLS13_DOWNGRADE_PROT_TLS12, 8) ||
                !Memcmp(ssl->sec.serverRandom + 24,
                        TLS13_DOWNGRADE_PROT_TLS11_OR_BELOW, 8))
        {
            psTraceErrr("Server downgrade to earlier proto version " \
                    "rejected: both parties support TLS 1.3\n");
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            return MATRIXSSL_ERROR;
        }
    }

    return MATRIXSSL_SUCCESS;
}
#endif /* USE_TLS_1_3 */
/* end of file hsNegotiateVersion.c */
