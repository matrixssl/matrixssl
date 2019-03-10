/**
 *      @file    tls13Resume.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 session resumption.
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

#include "matrixsslImpl.h"

# ifndef DEBUG_TLS_1_3_RESUMPTION
/* #  define DEBUG_TLS_1_3_RESUMPTION */
# endif

#ifdef USE_TLS_1_3
/* Derive a new PSK from the resumption master secret and
   a nonce. */
int32_t tls13DeriveResumptionPsk(ssl_t *ssl,
        int32_t hmacAlg,
        unsigned char *nonce,
        psSize_t nonceLen,
        unsigned char *pskOut,
        psSize_t pskOutLen)
{
    psSize_t secretLen;
    int32_t rc = psGetOutputBlockLength(hmacAlg);

    if (rc < 0)
    { /* this is an error code */
        return rc;
    }
    secretLen = rc;

    if (pskOutLen < secretLen)
    {
        return PS_OUTPUT_LENGTH;
    }


    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            ssl->sec.tls13ResumptionMasterSecret,
            secretLen,
            "resumption",
            10,
            nonce,
            nonceLen,
            secretLen,
            pskOut);
    if (rc < 0)
    {
        return rc;
    }

# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("Derived new PSK", pskOut, secretLen);
# endif

    return PS_SUCCESS;
}

void tls13GetCurrSessParams(ssl_t *ssl,
        psTls13SessionParams_t *params)
{
    params->sni = NULL;
    params->sniLen = 0;
    params->alpn = NULL;
    params->alpnLen = 0;
    params->majVer = psEncodeVersionMaj(GET_ACTV_VER(ssl));
    params->minVer = psEncodeVersionMin(GET_ACTV_VER(ssl));
    params->cipherId = ssl->cipher->ident;
    psGetTime(&params->timestamp, ssl->userPtr);
    params->maxEarlyData = ssl->tls13SessionMaxEarlyData;
}

int32_t tls13StorePsk(ssl_t *ssl,
        const unsigned char *psk,
        psSize_t pskLen,
        const unsigned char *pskId,
        psSize_t pskIdLen,
        psBool_t isResumptionPsk,
        const psTls13SessionParams_t *params)
{
    psTls13SessionParams_t defaultParams;
    int32_t rc;

    if (params == NULL)
    {
        tls13GetCurrSessParams(ssl, &defaultParams);
        /* By default don't support early data. It must be explicitly
           enabled */
        defaultParams.maxEarlyData = 0;
        params = &defaultParams;
    }

    /* Add the new PSK to our database. */
    rc = tls13AddSessionPsk(ssl,
            psk,
            pskLen,
            pskId,
            pskIdLen,
            isResumptionPsk,
            params);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

/**
   Create a new session ticket.
*/
int32_t tls13NewTicket(ssl_t *ssl,
        int32_t hmacAlg,
        uint32_t lifetime,
        uint32_t ageAdd,
        unsigned char *nonce,
        psSize_t nonceLen,
        unsigned char **ticketOut,
        psSizeL_t *ticketOutLen)
{
    int32_t rc;
    psResSize_t pskValLen = psGetOutputBlockLength(hmacAlg);
    unsigned char pskVal[MAX_TLS_1_3_HASH_SIZE];
    psSize_t pskIdLen;
    unsigned char pskId[32], iv[12];
    psDynBuf_t buf;
    psSessionTicketKeys_t *key;
    psAesGcm_t ctx;
    unsigned char *state, *tag, *out;
    psSizeL_t stateLen, outLen;
    psTls13Psk_t *psk;
    psTls13SessionParams_t params;

    if (pskValLen < 0)
    { /* this is an error code */
        return pskValLen;
    }

    /* Derive the PSK value. */
    rc = tls13DeriveResumptionPsk(ssl,
            hmacAlg,
            nonce,
            nonceLen,
            pskVal,
            pskValLen);
    if (rc < 0)
    {
        return rc;
    }

    /* Generate a new random ID for the PSK.*/
    pskIdLen = sizeof(pskId);
    rc = psGetPrng(NULL, pskId, pskIdLen, NULL);
    if (rc != pskIdLen)
    {
        return rc;
    }

    /* Make a new PSK object and associate it with the current
       session parameters. */
    tls13GetCurrSessParams(ssl, &params);
    params.ticketLifetime = lifetime;
    params.ticketAgeAdd = ageAdd;
    psk = tls13NewPsk(pskVal,
            pskValLen,
            pskId,
            pskIdLen,
            PS_TRUE,
            &params);
    if (psk == NULL)
    {
        return PS_MEM_FAIL;
    }

    /*
      Use the recommended ticket format from RFC 5077, adapted
      for AES-GCM:

      struct {
          opaque key_name[16];
          opaque iv[12];
          opaque encrypted_state<0..2^16-1>
          opaque tag[16];
      } ticket;

      Use the first key in ssl->keys->sessTickets.

      encrypted_state is the serialized and encrypted PSK struct
      containing the PSK and the session parameters.
    */

    key = ssl->keys->sessTickets;
    if (key == NULL)
    {
        psTraceErrr("Error: no session ticket keys loaded\n");
        tls13FreePsk(psk, ssl->hsPool);
        return PS_FAILURE;
    }

    psDynBufInit(ssl->hsPool, &buf, 512);
    psDynBufAppendOctets(&buf, key->name, 16);

    psAesInitGCM(&ctx, key->symkey, key->symkeyLen);
    rc = psAesReadyGCMRandomIV(&ctx, iv, NULL, 0, NULL);
    if (rc < 0)
    {
        tls13FreePsk(psk, ssl->hsPool);
        psAesClearGCM(&ctx);
        return rc;
    }

    psDynBufAppendOctets(&buf, iv, 12);

    rc = tls13ExportState(ssl,
            psk,
            &state,
            &stateLen);
    if (rc < 0)
    {
        tls13FreePsk(psk, ssl->hsPool);
        psAesClearGCM(&ctx);
        return rc;
    }

# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("pt", state, stateLen);
    psTraceBytes("IV", iv, 12);
    psTraceBytes("key", key->symkey, key->symkeyLen);
# endif

    psAesEncryptGCM(&ctx,
            state,
            state,
            stateLen);
    psDynBufAppendTlsVector(&buf,
            0, (1 << 16) - 1,
            state,
            stateLen);
# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("ct", state, stateLen);
# endif

    tag = psMalloc(ssl->hsPool, TLS_GCM_TAG_LEN);
    psAesGetGCMTag(&ctx,
            TLS_GCM_TAG_LEN,
            tag);
# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("tag", tag, TLS_GCM_TAG_LEN);
# endif

    psDynBufAppendOctets(&buf, tag, TLS_GCM_TAG_LEN);

    psAesClearGCM(&ctx);

    out = psDynBufDetach(&buf, &outLen);
    if (out == NULL)
    {
        tls13FreePsk(psk, ssl->hsPool);
        psFree(state, ssl->hsPool);
        psFree(tag, ssl->hsPool);
        return PS_MEM_FAIL;
    }

    *ticketOut = out;
    *ticketOutLen = outLen;

    tls13FreePsk(psk, ssl->hsPool);
    psFree(state, ssl->hsPool);
    psFree(tag, ssl->hsPool);

# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("New ticket", *ticketOut, *ticketOutLen);
# endif

    return PS_SUCCESS;
}

int32_t tls13DecryptTicket(ssl_t *ssl,
        psSessionTicketKeys_t *key,
        const unsigned char *ticket,
        psSizeL_t ticketLen,
        psTls13Psk_t **pskOut)
{
    psAesGcm_t ctx;
    int32_t rc;
    const unsigned char *ivStart, *encStart;
    unsigned char *pt;
    psSizeL_t encStateLen, ptLen;
    psParseBuf_t encStateBuf;
    const unsigned char *ticketEnd = ticket + ticketLen;
    psTls13Psk_t *psk;

    /*
      struct {
          opaque key_name[16];
          opaque iv[12];
          opaque encrypted_state<0..2^16-1>
          opaque tag[16];
      } ticket;

      encrypted_state is the serialized and encrypted PSK struct
      containing the PSK and the session parameters.
    */

    if (ticketLen < 16 + 12 + 1 + 16)
    {
        psTraceErrr("Ticket too short\n");
        goto out_illegal_parameter;
    }

    if (Memcmp(ticket, key->name, 16))
    {
        goto out_illegal_parameter;
    }

    ivStart = ticket + 16;
    encStart = ivStart + 12;

    (void)psParseBufFromStaticData(&encStateBuf,
            encStart,
            ticketEnd - encStart);

    /* opaque encrypted_state<0..2^16-1> */
    rc = psParseBufParseTlsVector(&encStateBuf,
            0, (1 << 16) - 1,
            &encStateLen);
    if (rc < 0)
    {
        goto out_illegal_parameter;
    }
    if (encStateLen < 1 ||
            !psParseCanRead(&encStateBuf, encStateLen + TLS_GCM_TAG_LEN))
    {
        psTrace("Decrypted ticket too short\n");
        goto out_illegal_parameter;
    }

    ptLen = encStateLen;
    pt = psMalloc(ssl->hsPool, ptLen);

    rc = psAesInitGCM(&ctx, key->symkey, key->symkeyLen);
    if (rc < 0)
    {
        psFree(pt, ssl->hsPool);
        goto out_internal_error;
    }
    psAesReadyGCM(&ctx, ivStart, NULL, 0);
# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("iv", ivStart, 12);
    psTraceBytes("key", key->symkey, key->symkeyLen);
    psTraceBytes("ct", encStateBuf.buf.start, encStateLen);
# endif

    rc = psAesDecryptGCM(&ctx,
            encStateBuf.buf.start,
            encStateLen + TLS_GCM_TAG_LEN,
            pt,
            ptLen);

    psAesClearGCM(&ctx);
    if (rc < 0)
    {
        psTrace("Ticket decryption failed\n");
        psFree(pt, ssl->hsPool);
        goto out_bad_record_mac;
    }

# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("Decrypted ticket", pt, ptLen);
# endif
    rc = tls13ImportState(ssl,
            pt,
            ptLen,
            &psk);
    if (rc < 0)
    {
        psFree(pt, ssl->hsPool);
        goto out_internal_error;
    }

    psFree(pt, ssl->hsPool);

    *pskOut = psk;

    return MATRIXSSL_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
out_illegal_parameter:
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
out_bad_record_mac:
    ssl->err = SSL_ALERT_BAD_RECORD_MAC;
    return MATRIXSSL_ERROR;
}

/** Serialize a PSK. */
int32_t tls13ExportState(ssl_t *ssl,
        psTls13Psk_t *psk,
        unsigned char **out,
        psSizeL_t *outLen)
{
    psDynBuf_t buf, paramsBuf;
    unsigned char *paramsData;
    psSizeL_t paramsDataLen;

# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("Exporting PSK with value", psk->pskKey, psk->pskLen);
# endif

    /*
      Serialize the PSK and associated session params as follows:

      struct {
          opaque sni<0..2^16-1>;
          opaque alpn<0..2^16-1>;
          uint8 majVer;
          uint8 minVer;
          uint16 cipherId;
          uint32 ticketLifetime;
          uint32 ticketAgeAdd;
          psTime_t timestamp;
          uint32 maxEarlyDataSize;
      } MatrixSessionParams;

      struct {
          opaque psk<0..2^16-1>;
          opaque psk_id<0..2^16-1>;
          MatrixSessionParams params<0..2^16-1>;
      } MatrixSession;
    */
    psDynBufInit(ssl->hsPool, &buf, 256);
    psDynBufAppendTlsVector(&buf,
        0, (1 << 16) - 1,
        psk->pskKey,
        psk->pskLen);
    psDynBufAppendTlsVector(&buf,
        0, (1 << 16) - 1,
        psk->pskId,
        psk->pskIdLen);

    psDynBufInit(ssl->hsPool, &paramsBuf, 256);
    psDynBufAppendTlsVector(&paramsBuf,
        0, (1 << 16) - 1,
        psk->params->sni,
        psk->params->sniLen);
    psDynBufAppendTlsVector(&paramsBuf,
        0, (1 << 16) - 1,
        psk->params->alpn,
        psk->params->alpnLen);
    psDynBufAppendByte(&paramsBuf,
            psEncodeVersionMaj(ssl->activeVersion));
    psDynBufAppendByte(&paramsBuf,
            psEncodeVersionMin(ssl->activeVersion));
    psDynBufAppendAsBigEndianUint16(&paramsBuf, psk->params->cipherId);

    psDynBufAppendAsBigEndianUint32(&paramsBuf, psk->params->ticketLifetime);
    psDynBufAppendAsBigEndianUint32(&paramsBuf, psk->params->ticketAgeAdd);

    psDynBufAppendOctets(&paramsBuf,
                         &psk->params->timestamp,
                         sizeof(psTime_t));

    psDynBufAppendAsBigEndianUint32(&paramsBuf, psk->params->maxEarlyData);

    paramsData = psDynBufDetach(&paramsBuf,
        &paramsDataLen);
    if (paramsData == NULL)
    {
        return PS_MEM_FAIL;
    }
    psDynBufAppendTlsVector(&buf,
            0, (1 << 16) - 1,
            paramsData,
            paramsDataLen);
    psFree(paramsData, ssl->hsPool);

    *out = psDynBufDetach(&buf,
            outLen);
    if (*out == NULL)
    {
        return PS_MEM_FAIL;
    }

    return PS_SUCCESS;
}

static
int32_t tls13ParseMatrixSessionParams(ssl_t *ssl,
        psParseBuf_t *pb,
        psSizeL_t inLen,
        psTls13SessionParams_t *params)
{
    size_t copiedLen = sizeof(psTime_t);
    psSizeL_t sniLen, alpnLen;
    unsigned char majVer = 0, minVer = 0;
    uint16_t cipherId = 0;
    uint32_t ticketLifetime = 0;
    uint32_t ticketAgeAdd = 0;
    psTime_t timestamp;
    uint32_t maxEarlyData = 0;
    int32_t rc;

    /*
      struct {
          opaque sni<0..2^16-1>;
          opaque alpn<0..2^16-1>;
          uint8 majVer;
          uint8 minVer;
          uint16 cipherId;
          uint32 ticketLifetime;
          uint32 tiecketAgeAdd;
          psTime_t timestamp;
          uint32 maxEarlyDataSize;
      } MatrixSessionParams;
    */

    Memset(params, 0, sizeof(*params));

    rc = psParseBufParseTlsVector(pb,
            0, (1 << 16) - 1,
            &sniLen);
    if (rc < 0)
    {
        return rc;
    }
    if (sniLen > 0)
    {
        Memcpy(params->sni, pb->buf.start, sniLen);
    }
    rc = psParseTryForward(pb, sniLen);
    if (rc < 0)
    {
        return rc;
    }

    rc = psParseBufParseTlsVector(pb,
            0, (1 << 16) - 1,
            &alpnLen);
    if (rc < 0)
    {
        return rc;
    }
    if (alpnLen > 0)
    {
        Memcpy(params->alpn, pb->buf.start, alpnLen);
    }
    rc = psParseTryForward(pb, alpnLen);
    if (rc < 0)
    {
        return rc;
    }

    rc = psParseOctet(pb, &majVer);
    if (rc < 0)
    {
        return rc;
    }
    params->majVer = majVer;

    rc = psParseOctet(pb, &minVer);
    if (rc < 0)
    {
        return rc;
    }
    params->minVer = minVer;

    rc = psParseBufTryParseBigEndianUint16(pb,
            &cipherId);
    if (rc < 0)
    {
        return rc;
    }
    params->cipherId = cipherId;


    rc = psParseBufTryParseBigEndianUint32(pb,
            &ticketLifetime);
    if (rc < 0)
    {
        return rc;
    }
    params->ticketLifetime = ticketLifetime;


    rc = psParseBufTryParseBigEndianUint32(pb,
            &ticketAgeAdd);
    if (rc < 0)
    {
        return rc;
    }
    params->ticketAgeAdd = ticketAgeAdd;

    rc = psParseBufCopyN(pb, sizeof(psTime_t), (unsigned char *)&timestamp, &copiedLen);
    if (rc < 0)
    {
        return rc;
    }
    rc = psParseTryForward(pb, copiedLen);
    if (rc < 0)
    {
        return rc;
    }
    params->timestamp = timestamp;

    rc = psParseBufTryParseBigEndianUint32(pb,
            &maxEarlyData);
    if (rc < 0)
    {
        return rc;
    }
    params->maxEarlyData = maxEarlyData;

    return PS_SUCCESS;
}

int32_t tls13ValidateSessionParams(ssl_t *ssl,
        psTls13SessionParams_t *params)
{
    psProtocolVersion_t ver;

    ver = psVerFromEncodingMajMin(params->majVer, params->minVer);
    if (ver != VER_GET_RAW(ssl->activeVersion))
    {
        psTraceErrr("Decrypted session: version mismatch\n");
        psTracePrintProtocolVersionNew(INDENT_ERROR,
                "Got",
                ver,
                PS_TRUE);
        psTracePrintProtocolVersionNew(INDENT_ERROR,
                "Expected",
                ssl->activeVersion,
                PS_TRUE);
        goto out_handshake_failure;
    }

    if (params->cipherId != ssl->cipher->ident)
    {
        psTraceErrr("Decrypted session: cipher mismatch\n");
        psTraceIntInfo("Got %hu ", params->cipherId);
        psTraceIntInfo("Expected: %hu\n",
                ssl->cipher->ident);
        goto out_handshake_failure;
    }



    return PS_SUCCESS;

out_handshake_failure:
    ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
    return MATRIXSSL_ERROR;
}

int32_t tls13ImportState(ssl_t *ssl,
        const unsigned char *in,
        psSizeL_t inLen,
        psTls13Psk_t **pskOut)
{
    psParseBuf_t pb;
    unsigned char *pskVal, *pskId;
    psSizeL_t pskValLen, pskIdLen, paramsLen;
    int32_t rc;
    psTls13Psk_t *psk = NULL;
    psTls13SessionParams_t params;

    (void)psParseBufFromStaticData(&pb, in, inLen);

    /*
      De-serialize the PSK and associated session params as follows:

      struct {
          opaque sni<0..2^16-1>;
          opaque alpn<0..2^16-1>;
          uint8 majVer;
          uint8 minVer;
          uint16 cipherId;
          uint32 timestamp;
          uint32 maxEarlyDataSize;
      } MatrixSessionParams;

      struct {
          opaque psk<0..2^16-1>;
          opaque psk_id<0..2^16-1>;
          MatrixSessionParams params<0..2^16-1>;
      } MatrixSession;
    */

    rc = psParseBufParseTlsVector(&pb,
            0, (1 << 16) - 1,
            &pskValLen);
    if (rc < 0)
    {
        /* Using internal errors for parse failures here, because
           the ticket format is decided by us and not by the protocol
           spec. */
        goto out_internal_error;
    }
    pskVal = pb.buf.start;
    psParseForward(&pb, pskValLen);

    rc = psParseBufParseTlsVector(&pb,
            0, (1 << 16) - 1,
            &pskIdLen);
    if (rc < 0)
    {
        goto out_internal_error;
    }
    pskId = pb.buf.start;
    psParseForward(&pb, pskIdLen);

    rc = psParseBufParseTlsVector(&pb,
            0, (1 << 16) - 1,
            &paramsLen);
    if (rc < 0)
    {
        goto out_internal_error;
    }

    rc = tls13ParseMatrixSessionParams(ssl,
            &pb,
            paramsLen,
            &params);
    if (rc < 0)
    {
        goto out_internal_error;
    }

    /* Postpone validation of the decrypted session parameters
       until after we have negotiated the parameters for the current
       handshake. */

    rc = tls13StorePsk(ssl,
            pskVal,
            pskValLen,
            pskId,
            pskIdLen,
            PS_TRUE,
            &params);
    if (rc < 0)
    {
        goto out_internal_error;
    }

    rc = tls13FindSessionPsk(ssl,
            pskId,
            pskIdLen,
            &psk);
    if (rc < 0 || psk == NULL)
    {
        goto out_internal_error;
    }

    *pskOut = psk;

# ifdef DEBUG_TLS_1_3_RESUMPTION
    psTraceBytes("Imported PSK with value", psk->pskKey, psk->pskLen);
# endif

    return MATRIXSSL_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}

/* Clear the current handshake state. Any resumed handshakes
   must start from scratch (until session params are restored
   from e.g. a ticket.) */
void tls13ClearHsState(ssl_t *ssl)
{
    Memset(&ssl->extFlags, 0, sizeof(ssl->extFlags));
}
#endif
