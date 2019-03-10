/**
 *      @file    tls13Decode.c
 *      @version $Format:%h%d$
 *
 *      Functions for decoding TLS 1.3 records.
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

# ifndef DEBUG_TLS_1_3_DECODE
/* #  define DEBUG_TLS_1_3_DECODE */
# endif

# ifndef DEBUG_TLS_1_3_DECODE_DUMP
/* #  define DEBUG_TLS_1_3_DECODE_DUMP */
# endif

# ifdef USE_TLS_1_3

static inline
int32_t tls13ParseRecordHeader(ssl_t* ssl,
        psParseBuf_t *pb,
        uint32 *needMoreNBytes)
{
    int rc = psParseTlsRecordHeader(pb,
            &ssl->rec.type,
            &ssl->rec.majVer,
            &ssl->rec.minVer,
            &ssl->rec.len);
    if (rc == 0)
    {
        *needMoreNBytes = TLS_REC_HDR_LEN;
        return SSL_PARTIAL;
    }

    return PS_SUCCESS;
}

static inline
int32_t tls13ValidateRecordHeader(sslRec_t *rec)
{
    /* Validate length. */
    if (rec->len > TLS_1_3_MAX_CIPHERTEXT_LEN || rec->len == 0)
    {
        psTraceErrr("Invalid record length\n");
        return PS_PARSE_FAIL;
    }
    if (rec->type == SSL_RECORD_TYPE_ALERT)
    {
        if (rec->len < 2 || rec->len > 2 + TLS_GCM_TAG_LEN)
        psTraceErrr("Invalid alert length\n");
    }
    /* Ignore legacy_version field. */

    return PS_SUCCESS;
}

static inline
int32_t tls13ParseChangeCipherSpec(ssl_t *ssl,
        psParseBuf_t *pb,
        uint32 *needMoreNBytes)
{
    unsigned char octet;

    psTracePrintChangeCipherSpecParse(ssl);

    if (!psParseOctet(pb, &octet))
    {
        *needMoreNBytes = 1;
        return SSL_PARTIAL;
    }
    if (octet != 0x01 || ssl->rec.len != 1)
    {
        return PS_PARSE_FAIL;
    }
    return PS_SUCCESS;
}

static inline
int32_t tls13ValidateRecordType(unsigned char type)
{
    if (type != SSL_RECORD_TYPE_HANDSHAKE &&
            type != SSL_RECORD_TYPE_ALERT &&
            type != SSL_RECORD_TYPE_APPLICATION_DATA &&
            type != SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC)
    {
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}

#define HANDLE_PARSE_RC(rc, alertType)          \
    do                                          \
    {                                           \
        if (rc == SSL_PARTIAL)                  \
        {                                       \
            return rc;                          \
        }                                       \
        else if (rc != PS_SUCCESS)              \
        {                                       \
            ssl->err = alertType;               \
            goto encodeResponse;                \
        }                                       \
    } while(0)

static int32_t tls13ParseHandshakeMessage(ssl_t *ssl,
        unsigned char **bufStart,
        unsigned char *bufEnd);
static int32_t tls13ParseFinished(ssl_t *ssl,
        psParseBuf_t *pb);
static int32_t tls13ParseNewSessionTicket(ssl_t *ssl,
        psParseBuf_t *pb);
static int32_t tls13ParseServerHello(ssl_t *ssl,
        psParseBuf_t *pb);
#ifdef USE_IDENTITY_CERTIFICATES
# ifdef USE_CLIENT_SIDE_SSL
static int32_t tls13ParseCertificateRequest(ssl_t *ssl,
        psParseBuf_t *pb);
# endif
static int32_t tls13ParseCertificate(ssl_t *ssl,
        psParseBuf_t *pb);
# ifdef USE_CERT_VALIDATE
static int32_t tls13ParseCertificateVerify(ssl_t *ssl,
        psParseBuf_t *pb);
# endif
#endif

static int32_t tls13HandleAlert(ssl_t *ssl,
        unsigned char level,
        unsigned char type,
        unsigned char *alertLevel,
        unsigned char *alertDescription);
static int32_t tls13ParseAndHandleAlert(ssl_t *ssl,
        psParseBuf_t *pb,
        unsigned char **in,
        uint32 *len,
        unsigned char *alertLevel,
        unsigned char *alertDescription);
static int32_t tls13ClientActivateHsReadKeys(ssl_t *ssl);

/** Decode incoming peer data, update state machine and encode
    the response.

    The interface of this function is (too) complex. For details,
    see the comments in matrixSslDecode.
*/
int32 matrixSslDecodeTls13(ssl_t *ssl,
        unsigned char **in,
        uint32 *len,
        uint32 size,
        uint32 *remaining,
        uint32 *requiredLen,
        int32 *error,
        unsigned char *alertLevel,
        unsigned char *alertDescription)
{
    unsigned char *p = NULL, *decryptTo, *end;
    unsigned char innerType;
    psParseBuf_t pb, alertBuf;
    int32_t rc;
    psSize_t maxEarlyData = 0;
    int32_t padLen = 0;
    uint32_t ptLen;
    psSize_t parsedBytes = 0;
    psBuf_t tmp;
    psBool_t useOutbufForResponse = PS_FALSE;

    if (ssl->flags & SSL_FLAGS_NEED_ENCODE)
    {
        ssl->flags &= ~SSL_FLAGS_NEED_ENCODE;
        goto encodeResponse;
    }

    *requiredLen = 0;
    (void)psParseBufFromStaticData(&pb, *in, *len);

    /*
      MatrixSSL reuses the input buffer for temporarily storing decrypted
      data before parsing. Data is decrypted to the front.
    */
    decryptTo = *in;

    /* Parse and validate record header. */
parse_next_record_header:
    rc = tls13ParseRecordHeader(ssl,
            &pb,
            requiredLen);
    HANDLE_PARSE_RC(rc, SSL_ALERT_ILLEGAL_PARAMETER);
#ifdef DEBUG_TLS_1_3_DECODE
    psTracePrintRecordHeader(&ssl->rec, PS_TRUE);
#endif
    rc = tls13ValidateRecordHeader(&ssl->rec);
    HANDLE_PARSE_RC(rc, SSL_ALERT_ILLEGAL_PARAMETER);

    if (!psParseCanRead(&pb, ssl->rec.len))
    {
        /* It is possible that we get ChangeCipherSpec and incomplete part
           of some other record (e.g. Certificate) in the same buffer.
           In order for the requiredLen calculation to go correctly, the length
           of ChangeCipherSpec must be taken into account (= parsedBytes) */
        *requiredLen = parsedBytes + ssl->rec.len + ssl->recordHeadLen;
        return SSL_PARTIAL;
    }

#ifdef DEBUG_TLS_1_3_DECODE_DUMP
    psTraceBytes("Got ciphertext", pb.buf.start, ssl->rec.len);
#endif

    if (tls13ValidateRecordType(ssl->rec.type) < 0)
    {
        ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
        psTraceIntInfo("Record type not valid: %d\n", ssl->rec.type);
        goto encodeResponse;
    }

    /*
      Deal with ChangeCipherSpec and plaintext Alerts here.

      ChangeCipherSpec can be received at any time after ClientHello.
      This message is always in plaintext and MUST be ignored.

      Alerts can be either encrypted or (if sent before the peer has
      activated its write key) plaintext. The peer SHOULD upgrade
      to handshake keys before sending alerts as a response to the
      server's first flight, but not all implementations follow that
      recommendation. Handle the latter case here: we have turned
      on our read keys, but the peer sends a plaintext alert.
    */
    if (ssl->rec.type == SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC)
    {
        rc = tls13ParseChangeCipherSpec(ssl, &pb, requiredLen);
        HANDLE_PARSE_RC(rc, SSL_ALERT_ILLEGAL_PARAMETER);
        psTraceInfo("Ignoring change_cipher_spec...\n");
        parsedBytes += pb.buf.start - *in;
        if (pb.buf.start != pb.buf.end)
        {
            /* There is more data to be parsed */
            goto parse_next_record_header; /* Ignore, as per spec. */
        }
        /* Done - tell the caller what we've consumed. */
        *in += parsedBytes;
        *len -= parsedBytes;
        *remaining -= PS_MIN(parsedBytes, *remaining);
        /* If there's handshake message waiting in outbuf then send it */
        if (ssl->outlen > 0)
        {
            return SSL_SEND_RESPONSE;
        }
        else
        {
            return MATRIXSSL_SUCCESS;
        }
    }
    else if (ssl->rec.type == SSL_RECORD_TYPE_ALERT)
    {
        if (ssl->rec.len < 2 + TLS_GCM_TAG_LEN)
        {
            /* If it's this short, it cannot be an encrypted. */
            return tls13ParseAndHandleAlert(ssl,
                    &pb,
                    in,
                    len,
                    alertLevel,
                    alertDescription);
        }
    }

    if (DECRYPTING_RECORDS(ssl))
    {
        decryptTo = pb.buf.start; /* In-situ decryption. */
        if (ssl->decrypt(ssl, pb.buf.start, decryptTo, ssl->rec.len) < 0)
        {
            if (IS_SERVER(ssl) &&
                    ssl->tls13ServerEarlyDataEnabled == PS_FALSE &&
                    ssl->extFlags.got_early_data == 1)
            {
                /* If server does not accept early_data then ignore decrypt errors
                   to up-to configured ssl->tls13SessionMaxEarlyData bytes.
                   (TLS1.3 spec chapt. 4.2.10) */
                psTraceInt("Ignored %d bytes of possible early_data\n",
                        ssl->rec.len - AEAD_TAG_LEN(ssl) - 1);
                ssl->tls13ReceivedEarlyDataLen +=
                    (ssl->rec.len - AEAD_TAG_LEN(ssl)- 1);
                ssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_REJECTED;
                if (ssl->tls13ReceivedEarlyDataLen <= ssl->tls13SessionMaxEarlyData)
                {
                    *in = pb.buf.start + ssl->rec.len;
                    *remaining = pb.buf.end - (pb.buf.start + ssl->rec.len);
                    *len = 0;
                    *alertDescription = SSL_ALERT_NONE;
                    /* If there's handshake message waiting in outbuf then send it */
                    if (*remaining == 0 && ssl->outlen > 0)
                    {
                        return SSL_SEND_RESPONSE;
                    }
                    else
                    {
                        return MATRIXSSL_SUCCESS;
                    }
                }
                psTraceInt("Ignored total of %d bytes of early data. ",
                        ssl->tls13ReceivedEarlyDataLen);
                psTraceInt("Limit was %d bytes (tls13SessionMaxEarlyData). " \
                        "Abort connection.\n",
                        ssl->tls13SessionMaxEarlyData);
            }
            /* 5.2. If the decryption fails, the receiver MUST terminate the
               connection with a "bad_record_mac" alert. */
            ssl->err = SSL_ALERT_BAD_RECORD_MAC;
            psTraceErrr("Couldn't decrypt record data\n");
            goto encodeResponse;
        }

        ptLen = ssl->rec.len - AEAD_TAG_LEN(ssl);
        ptLen--; /* TLSInnerPlaintext type. */

        /* Deal with TLSInnerPlaintext padding. */
        p = decryptTo + ptLen;
        padLen = 0;
        while (*p == 0 && p > decryptTo)
        {
            padLen++;
            p--;
        }
        if (p == decryptTo)
        {
            /* If receiver finds no non-zero octets, it MUST terminate
               the connection with an "unexpected_message" alert. */
            ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
            goto encodeResponse;
        }
        ptLen -= padLen;
        innerType = *p;

#ifdef DEBUG_TLS_1_3_DECODE
        psTracePrintRecordType(innerType, PS_TRUE, PS_TRUE);
        if (ptLen == TLS_1_3_MAX_PLAINTEXT_FRAGMENT_LEN)
        {
            psTraceInfo("Plaintext fragment is maximal\n");
        }
#endif
#ifdef DEBUG_TLS_1_3_DECODE_PADDING
        if (padLen > 0)
        {
            psTraceIntInfo("Removed %d bytes of padding\n", padLen);
            psTraceIntInfo("De-padded plaintext len: %d\n", ptLen);
        }
#endif
#ifdef DEBUG_TLS_1_3_DECODE_DUMP
        psTraceBytes("decrypted", decryptTo, ptLen);
#endif

        if (ptLen > TLS_1_3_MAX_PLAINTEXT_FRAGMENT_LEN)
        {
            ssl->err = SSL_ALERT_RECORD_OVERFLOW;
            psTraceIntInfo("Decrypted TLSInnerPlaintext too large: %u\n", ptLen);
            goto encodeResponse;
        }

        p = decryptTo;
    }
    else
    {
        ptLen = ssl->rec.len;
        innerType = ssl->rec.type;
        p = pb.buf.start;

        if (ptLen > TLS_1_3_MAX_PLAINTEXT_FRAGMENT_LEN)
        {
            ssl->err = SSL_ALERT_RECORD_OVERFLOW;
            psTraceIntInfo("TLSPlaintext too large: %u\n", ptLen);
            goto encodeResponse;
        }
    }

    rc = psParseTryForward(&pb, ssl->rec.len);
    if (rc == 0)
    {
        psTraceErrr("psParseForward failed\n");
        ssl->err = SSL_ALERT_DECODE_ERROR;
        goto encodeResponse;
    }

    /* Deal with the decrypted message. */
    if (innerType == SSL_RECORD_TYPE_HANDSHAKE)
    {
        end = p + ptLen;
        /* Parse handshake messages until buffer runs out */
        while (p != end)
        {
            rc = tls13ParseHandshakeMessage(ssl,
                    &p, end);
            if (rc < 0)
            {
                if (DECRYPTING_RECORDS(ssl))
                {
                    p += TLS_GCM_TAG_LEN;
                    p += 1;
                    p += padLen;
                }
                if (rc == SSL_NO_TLS_1_3)
                {
                    /* Fall back to pre-1.3 decode path for ServerHello. */
                    return rc;
                }
                else if (rc == SSL_PARTIAL)
                {
                    /* Successful read of a handshake message fragment. */
                    *in = p;
                    return MATRIXSSL_SUCCESS;
                }
                /* All other non-zero return value results in reply message.
                 * Either handshake message or alert */
                goto encodeResponse;
            }
        }
    }
    else if (innerType == SSL_RECORD_TYPE_APPLICATION_DATA)
    {
        if (ssl->hsState == SSL_HS_TLS_1_3_WAIT_EOED)
        {
            if (ssl->sec.tls13ChosenPsk != NULL &&
                ssl->sec.tls13ChosenPsk->params != NULL)
            {
                maxEarlyData = PS_MIN(ssl->tls13SessionMaxEarlyData,
                        ssl->sec.tls13ChosenPsk->params->maxEarlyData);
            }
            else
            {
                maxEarlyData = ssl->tls13SessionMaxEarlyData;
            }
            ssl->tls13ReceivedEarlyDataLen += ptLen;
            if (ssl->tls13ReceivedEarlyDataLen > maxEarlyData)
            {
                psTraceIntInfo("Received too much early_data (%d bytes)\n",
                               ssl->tls13ReceivedEarlyDataLen);
                ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
                ssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_REJECTED;
                goto encodeResponse;
            }
            ssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_ACCEPTED;
        }
        *remaining = *len - (pb.buf.start - *in);
        Memmove(*in, *in + TLS_REC_HDR_LEN + parsedBytes, ptLen);
        *in = pb.buf.start;
        *len = ptLen;
        return SSL_PROCESS_DATA;
    }
    else if (innerType == SSL_RECORD_TYPE_ALERT)
    {
        (void)psParseBufFromStaticData(&alertBuf, decryptTo, ptLen);
        return tls13ParseAndHandleAlert(ssl,
                &alertBuf,
                in,
                len,
                alertLevel,
                alertDescription);
    }

    /* Advance pointer to point to after the data we have read. */
    *in = pb.buf.start;
    /* No need to send a response at this point */
    return MATRIXSSL_SUCCESS;

encodeResponse:
    /* Check if there is still unprocessed data in inbuf and
       in that case use outbuf for response. One case
       where this happens is that there is an alert in the inbuf
       after Finished message and that must not be overwritten.
       Exception to this is that if we are going to send an
       alert then the pending contents in inbuf is irrelevant
       and will not be parsed. */
    if ((p != NULL && p != *in + *len) && ssl->err == SSL_ALERT_NONE)
    {
        tmp.buf = tmp.start = tmp.end = ssl->outbuf + ssl->outlen;
        tmp.size = ssl->outsize - ssl->outlen;
        useOutbufForResponse = PS_TRUE;
    }
    else
    {
        tmp.buf = tmp.start = tmp.end = *in;
        tmp.size = size;
        /* SECURITY - Clear the decoded incoming record from outbuf before
           encoding the response into outbuf.*/
        Memset(tmp.buf, 0x0, tmp.size);
    }
    if (ssl->err != SSL_ALERT_NONE)
    {
        *alertDescription = (unsigned char)ssl->err;
        *alertLevel = SSL_ALERT_LEVEL_FATAL;
        rc = tls13EncodeAlert(ssl, ssl->err, &tmp, requiredLen);
    }
    else
    {
        /* Handshake response */
        *alertDescription = SSL_ALERT_NONE;
        rc = sslEncodeResponse(ssl, &tmp, requiredLen);
    }
    if (rc == SSL_FULL)
    {
        ssl->flags |= SSL_FLAGS_NEED_ENCODE;
        *len = 0; /* No data left to decode */
        return SSL_FULL;
    }
    else if (rc < 0)
    {
        /* Setting the error variable indicates an internal error
           in the stack where sending an alert does not seem possible */
        *error = MATRIXSSL_ERROR;
        return rc;
    }
    *len = tmp.end - tmp.start;
    *remaining = 0;
    /* Advance pointer to point to after the data we have read. */
    *in = pb.buf.start;
    if (useOutbufForResponse)
    {
        /* Update outlen with the data we added */
        ssl->outlen += tmp.end - tmp.buf;
        /* Return SUCCESS causes the caller to continue parsing
           the buffer since there is still data left */
        return MATRIXSSL_SUCCESS;
    }
    return SSL_SEND_RESPONSE;
}

static int32_t tls13HandleAlert(ssl_t *ssl,
        unsigned char level,
        unsigned char type,
        unsigned char *alertLevel,
        unsigned char *alertDescription)
{
    int32_t rc = SSL_ALERT;

    psTracePrintAlertReceiveInfo(ssl, type);
    if (type == SSL_ALERT_CLOSE_NOTIFY)
    {
        ssl->flags |= SSL_FLAGS_CLOSED;
    }
    else
    {
        ssl->flags |= SSL_FLAGS_ERROR;
    }
    ssl->decState = SSL_HS_ALERT;

    *alertLevel = level;
    *alertDescription = type;

    return rc;
}

static int32_t tls13ParseAndHandleAlert(ssl_t *ssl,
        psParseBuf_t *pb,
        unsigned char **in,
        uint32 *len,
        unsigned char *alertLevel,
        unsigned char *alertDescription)
{
    unsigned char alertVal[2];

    if (!psParseOctet(pb, &alertVal[0]) ||
            !psParseOctet(pb, &alertVal[1]))
    {
        /* Caller should have checked that there is enough
           data to parse. */
        return MATRIXSSL_ERROR;
    }
    /* The client expects to find the alert data at the start of the buffer */
    Memmove(*in, *in + TLS_REC_HDR_LEN, 2);

    *in = pb->buf.start;
    *len = 2;

    return tls13HandleAlert(ssl,
            alertVal[0], alertVal[1],
            alertLevel, alertDescription);
}

/** Validate state machine transitions.

    Return PS_SUCCESS if and only if we expecting handshake message msg
    in our current state. Send unexpected_message alert otherwise. */
static int32_t tls13CheckHsState(ssl_t *ssl,
        unsigned char msg)
{
    if (msg == SSL_HS_CLIENT_HELLO &&
            ssl->hsState == SSL_HS_TLS_1_3_START)
    {
        return PS_SUCCESS;
    }
    else if (msg == SSL_HS_SERVER_HELLO &&
            ssl->hsState == SSL_HS_TLS_1_3_WAIT_SH)
    {
        return PS_SUCCESS;
    }
    else if (msg == SSL_HS_ENCRYPTED_EXTENSION &&
            ssl->hsState == SSL_HS_TLS_1_3_WAIT_EE)
    {
        return PS_SUCCESS;
    }
    else if (msg == SSL_HS_CERTIFICATE_REQUEST &&
            ssl->hsState == SSL_HS_TLS_1_3_WAIT_CERT_CR)
    {
        return PS_SUCCESS;
    }
    else if (msg == SSL_HS_CERTIFICATE &&
            (ssl->hsState == SSL_HS_TLS_1_3_WAIT_CERT ||
             ssl->hsState == SSL_HS_TLS_1_3_WAIT_CERT_CR))
    {
        return PS_SUCCESS;
    }
    else if (msg == SSL_HS_CERTIFICATE_VERIFY &&
            ssl->hsState == SSL_HS_TLS_1_3_WAIT_CV)
    {
        return PS_SUCCESS;
    }
    else if (msg == SSL_HS_EOED &&
            ssl->hsState == SSL_HS_TLS_1_3_WAIT_EOED)
    {
        return PS_SUCCESS;
    }
    else if (msg == SSL_HS_FINISHED &&
            ssl->hsState == SSL_HS_TLS_1_3_WAIT_FINISHED)
    {
        return PS_SUCCESS;
    }
    /*
      The server may send a NewSessionTicket at any time after
      it has received the client's Finished message.
      In our state machine, there are two allowed states for this:
      - SSL_HS_DONE (after having received and sent Finished)
      - SSL_HS_TLS_1_3_WAIT_FINISHED (after having sent our Finished,
      but before having received the server Finished.)
    */
    else if (!IS_SERVER(ssl) &&
            msg == SSL_HS_NEW_SESSION_TICKET &&
            (ssl->hsState == SSL_HS_DONE ||
            ssl->hsState == SSL_HS_TLS_1_3_WAIT_FINISHED))
    {
        return PS_SUCCESS;
    }
    else
    {
        psTraceErrr("Received unexpected handshake message.\n");
        psTraceInfo(" Got ");
        psTracePrintHsMsgType(msg, PS_FALSE);
        psTraceInfo(" in state ");
        psTracePrintHsState(ssl->hsState, PS_TRUE);
        ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
        return MATRIXSSL_ERROR;
    }
}

/** Initialize reading of a fragmented HS message.
    @precond pb.buf.start must point to the start of the HS message header. */
static
int32_t tls13FragMessageReadInit(ssl_t *ssl,
        psParseBuf_t *pb,
        uint32_t hsMsgLen)
{
    psSizeL_t readableLen, copiedLen;

    readableLen = psParseGetRemainingLen(pb);
    psAssert(readableLen < hsMsgLen);
    psAssert(readableLen > 0);

# ifdef DEBUG_TLS_1_3_DECODE
    psTraceInfo("Start reading fragmented HS message:\n");
    psTraceIntInfo("  Initial fragment: %zu/", readableLen);
    psTraceIntInfo("%zu\n", hsMsgLen);
# endif /* DEBUG_TLS_1_3_DECODE */

    /* Set total length of fragmented message. */
    ssl->fragTotal = hsMsgLen + TLS_HS_HDR_LEN;
    ssl->fragIndex = 0;

    /* Alloc buffer. */
    psAssert(ssl->fragMessage == NULL);
    ssl->fragMessage = psMalloc(ssl->hsPool, ssl->fragTotal);
    if (ssl->fragMessage == NULL)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return PS_MEM_FAIL;
    }

    /* Copy bytes from the initial fragment. */
    copiedLen = ssl->fragTotal;
    psParseBufCopyN(pb, readableLen, ssl->fragMessage, &copiedLen);
    psAssert(copiedLen == readableLen);
    psParseForward(pb, readableLen);
    ssl->fragIndex += readableLen;
    return PS_SUCCESS;
}

/** Finish reading a fragmented HS message. */
static
void tls13FragMessageReadFinish(ssl_t *ssl)
{
    if (ssl->fragMessage != NULL)
    {
        psFree(ssl->fragMessage, ssl->hsPool);
        ssl->fragMessage = NULL;
        ssl->fragIndex = 0;
        ssl->fragTotal = 0;
    }
}

/** Continue reading a HS message fragment.

    @retval MATRIXSSL_SUCCESS : Entire message has been read
    and is now available for parsing.
    @retval SSL_PARTIAL : Still need more fragments to construct
    the whole message.
*/
static
int32_t tls13FragMessageReadContinue(ssl_t *ssl,
        psParseBuf_t *pb, uint32_t *fragmentLen)
{
    psSizeL_t readableLen, remainingLen;
    uint32_t bytesToCopy;
    size_t copiedLen;

    /* Current fragment size. */
    readableLen = psParseGetRemainingLen(pb);
    psAssert(readableLen > 0);

    /* How much is still missing from the full HS message. */
    remainingLen = ssl->fragTotal - ssl->fragIndex;
    bytesToCopy = min(readableLen, remainingLen);

    /* Append current fragment bytes to ssl->fragMessage. */
    copiedLen = ssl->fragTotal - ssl->fragIndex;
    psParseBufCopyN(pb,
            bytesToCopy,
            ssl->fragMessage + ssl->fragIndex,
            &copiedLen);
    ssl->fragIndex += copiedLen;

    psParseForward(pb, bytesToCopy);
    psAssert(copiedLen == bytesToCopy);
    psAssert(ssl->fragIndex <= ssl->fragTotal);
    *fragmentLen = bytesToCopy;
    /* Got entire message now? */
    if (ssl->fragIndex == ssl->fragTotal)
    {
        /* Update pb to point to the header of the (now fully assembled)
           handshake message. */
        psParseBufFromStaticData(pb, ssl->fragMessage, ssl->fragTotal);
        return MATRIXSSL_SUCCESS;
    }

    /* Ask for more fragments. */

    return SSL_PARTIAL;
}

/** Attempt to parse a single handshake message from the supplied buffer.
    Coalesced handshake messages should be handled by calling this
    function in a loop until the entire buffer has been processed.

    @precond *bufStart should point to the start of the handshake
    message header. */
static int32_t tls13ParseHandshakeMessage(ssl_t *ssl,
        unsigned char **bufStart,
        unsigned char *bufEnd)
{
    unsigned char type;
    int32_t rc = MATRIXSSL_SUCCESS;
    psParseBuf_t pb;
    unsigned char *msgStart = *bufStart;
    unsigned char *msgEnd = bufEnd;
    psSizeL_t readableLen = msgEnd - msgStart;
    uint32_t fragmentLen = 0;
    uint32_t hsMsgLen;

    (void)psParseBufFromStaticData(&pb, msgStart, readableLen);

    if (ssl->fragMessage != NULL)
    {
        /* Read another fragment. */
        rc = tls13FragMessageReadContinue(ssl, &pb, &fragmentLen);
        if (rc < 0)
        {
            /* Still need more fragments. */
            *bufStart = pb.buf.start;
            return rc;
        }
        /* Now we have all the fragments appended together and
           pb has been updated to point to the message header. */
    }
    rc = psParseTlsHandshakeHeader(&pb, &type, &hsMsgLen);
    if (rc == 0)
    {
        goto exit;
    }
#ifdef DEBUG_TLS_1_3_DECODE
    psTracePrintHandshakeHeader(type, hsMsgLen, PS_TRUE);
#endif
    rc = psParseCanRead(&pb, hsMsgLen);
    if (rc == 0)
    {
        /* Unable to read the entire HS message.
           Start fragmented read. */
        pb.buf.start -= TLS_HS_HDR_LEN;
        rc = tls13FragMessageReadInit(ssl, &pb, hsMsgLen);
        if (rc < 0)
        {
            goto exit;
        }
        *bufStart = pb.buf.start;
        return SSL_PARTIAL;
    }
#ifdef DEBUG_TLS_1_3_DECODE_DUMP
    psTraceBytes("handshake message", msgStart, hsMsgLen);
#endif
#ifdef DEBUG_TLS_1_3_DECODE
    psTracePrintHandshakeHeader(type, hsMsgLen, PS_TRUE);
#endif

    /* Move the buffer start pointer over this handshake message to signal
       caller how much data was processed */
    if (fragmentLen > 0)
    {
        /* The HS message was fragmented and this was the last
           fragment */
        /* msgStart must point to the start of the HS message */
        msgStart = pb.buf.start - TLS_HS_HDR_LEN;
        /* bufStart must be moved over the last received fragment */
        *bufStart += fragmentLen;
        /* msgEnd points to the end of HS message */
        msgEnd = pb.buf.end;
    }
    else
    {
        *bufStart += hsMsgLen + TLS_HS_HDR_LEN;
        /* End of the single handshake message */
        msgEnd = msgStart + hsMsgLen + TLS_HS_HDR_LEN;
    }

    /* Check that message type is valid for the current state. */
    rc = tls13CheckHsState(ssl, type);
    if (rc < 0)
    {
        goto exit;
    }

    switch(type)
    {
    /* Note: Initial ClientHello parsing is done on the TLS 1.2 code
       path, because TLS 1.3 has not been negotiated yet. */

    case SSL_HS_SERVER_HELLO:
        /* Add serverHello to HS transcript hash */
        rc = tls13ParseServerHello(ssl, &pb);
        if (rc < 0)
        {
            if (rc == SSL_ENCODE_RESPONSE && ssl->tls13IncorrectDheKeyShare)
            {
                /* Need to go back to start state so that next
                 * ClientHello is sent again as a reply to
                 * HelloRetryRequest */
                rc = tls13TranscriptHashReinit(ssl); /* See 4.4.1. */
                if (rc < 0)
                {
                    goto exit;
                }
                tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);
                ssl->hsState = SSL_HS_TLS_1_3_START;
                /* Early data cannot be enabled after HRR */
                ssl->tls13ClientEarlyDataEnabled = PS_FALSE;
                rc = SSL_ENCODE_RESPONSE;
                goto exit;
            }
            /* Alert reason should be set in parse function so just return */
            goto exit;
        }
        /* Now we have everything ready for the secret/key calculations */
        tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);
        rc = tls13ClientActivateHsReadKeys(ssl);
        if (rc < 0)
        {
            goto exit;
        }
        ssl->hsState = SSL_HS_TLS_1_3_WAIT_EE;
        break;
    case SSL_HS_ENCRYPTED_EXTENSION:
        rc = tls13ParseEncryptedExtensions(ssl, &pb);
        if (rc < 0)
        {
            goto exit;
        }
        tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);
        if (ssl->sec.tls13UsingPsk)
        {
            ssl->hsState = SSL_HS_TLS_1_3_WAIT_FINISHED;
        }
        else
        {
            ssl->hsState = SSL_HS_TLS_1_3_WAIT_CERT_CR;
        }
        break;
# ifdef USE_IDENTITY_CERTIFICATES
#  ifdef USE_CLIENT_SIDE_SSL
    case SSL_HS_CERTIFICATE_REQUEST:
        rc = tls13ParseCertificateRequest(ssl, &pb);
        if (rc < 0)
        {
            goto exit;
        }
        tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);
        ssl->hsState = SSL_HS_TLS_1_3_WAIT_CERT;
        break;
#  endif
# endif

#  ifdef USE_CERT_VALIDATE
    case SSL_HS_CERTIFICATE:
        rc = tls13ParseCertificate(ssl, &pb);
        if (rc < 0)
        {
            goto exit;
        }
        tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);
        ssl->hsState = SSL_HS_TLS_1_3_WAIT_CV;
        break;
    case SSL_HS_CERTIFICATE_VERIFY:
        rc = tls13ParseCertificateVerify(ssl, &pb);
        if (rc < 0)
        {
            goto exit;
        }
        /* Hash must be updated _after_ certificate verify
         * because for verification the hash should not contain the CV
         * message itself. */
        tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);
        ssl->hsState = SSL_HS_TLS_1_3_WAIT_FINISHED;
        break;
# endif /* USE_CERT_VALIDATE */
    case SSL_HS_EOED:
        psTracePrintHsMessageParse(ssl, SSL_HS_EOED);
        rc = tls13ActivateHsReadKeys(ssl);
        if (rc < 0)
        {
            goto exit;
        }
        tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);
        ssl->hsState = SSL_HS_TLS_1_3_WAIT_FINISHED;
        break;
    case SSL_HS_FINISHED:
        rc = tls13ParseFinished(ssl, &pb);
        if (rc < 0)
        {
            goto exit;
        }
        tls13TranscriptHashUpdate(ssl, msgStart, msgEnd-msgStart);

        rc = tls13ActivateAppReadKeys(ssl);
        if (rc < 0)
        {
            goto exit;
        }

        if (IS_SERVER(ssl))
        {
            /* Transcript-Hash for ClientHello..Client Finished. */
            rc = tls13TranscriptHashSnapshot(ssl, ssl->sec.tls13TrHashSnapshot);
            if (rc < 0)
            {
                goto exit;
            }
            rc = tls13DeriveResumptionMasterSecret(ssl);
            if (rc < 0)
            {
                goto exit;
            }
# ifdef USE_TLS_1_3_RESUMPTION
            if (ssl->keys->sessTickets)
            {
                /* Send NewSessionTicket using app write keys. */
                ssl->hsState = SSL_HS_TLS_1_3_SEND_NST;
                rc = SSL_ENCODE_RESPONSE;
            }
            else
            {
                tls13ClearHsState(ssl);
                ssl->hsState = SSL_HS_DONE;
            }
# else
            tls13ClearHsState(ssl);
            ssl->hsState = SSL_HS_DONE;
# endif /* USE_TLS_1_3_RESUMPTION */
            goto exit;
        }
        else
        {
            ssl->hsState = SSL_HS_TLS_1_3_SEND_FINISHED;
            rc = SSL_ENCODE_RESPONSE;
            goto exit;
        }
        break;
    case SSL_HS_NEW_SESSION_TICKET:
        rc = tls13ParseNewSessionTicket(ssl, &pb);
        if (rc < 0)
        {
            goto exit;
        }
        /*
          Note: NST not included in the Transcript-Hash.

          No state update after receiving NST, because:
           - The server is allowed to send multiple NSTs.
           - We are either already done with the handshake (SSL_HS_DONE)
             or we still need to receive the server Finished
             (SSL_HS_TLS_1_3_WAIT_FINISHED).
        */
        break;
    default:
        psTraceInfo("TODO: add decoding for this HS message\n");
    }

exit:
    /* In case the message was fragmented it must be freed after
       it now has been processed */
    tls13FragMessageReadFinish(ssl);
    return rc;
}

static int32_t tls13ParseServerHello(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc;
    psSizeL_t sessionIdLen = 0;
    uint32_t cipher;
    unsigned char compressionMethod;
    uint16_t tmp_u16;
    uint16_t legacy_version;

    psTracePrintHsMessageParse(ssl, SSL_HS_SERVER_HELLO);

    /*
      struct {
          ProtocolVersion legacy_version = 0x0303;
          Random random;
          opaque legacy_session_id_echo<0..32>;
          CipherSuite cipher_suite;
          uint8 legacy_compression_method = 0;
          Extension extensions<6..2^16-1>;
      } ServerHello;
    */

    /* ProtocolVersion legacy_version = 0x0303; */
    rc = psParseBufTryParseBigEndianUint16(pb, &legacy_version);
    if (rc != 2)
    {
        return PS_PARSE_FAIL;
    }
    ssl->peerHelloVersion = psVerFromEncoding(legacy_version);
    psTracePrintProtocolVersionNew(INDENT_HS_MSG,
            "legacy_version",
            ssl->peerHelloVersion,
            PS_TRUE);
    /* Ignore legacy_version. */

    /*
      We don't know whether we have negotiated TLS 1.3 until we
      parse supported_versions. So postpone all ServerHello field
      checks that conform to the TLS 1.3 spec.
    */

    /* Random random; */
    if (!psParseBufTryParseOctets(pb, SSL_HS_RANDOM_SIZE,
                    ssl->sec.serverRandom))
    {
        return PS_PARSE_FAIL;
    }
    psTracePrintHex(INDENT_HS_MSG,
            "server_random",
            ssl->sec.serverRandom,
            SSL_HS_RANDOM_SIZE,
            PS_TRUE);


    /* Check if this is HelloRetryRequest */
    if (!Memcmp(&ssl->sec.serverRandom, sha256OfHelloRetryRequest,
                    SSL_HS_RANDOM_SIZE))
    {
        ssl->tls13IncorrectDheKeyShare = PS_TRUE;
        psTraceInfo(">>> Client parsing TLS 1.3 HelloRetryRequest message\n");

    }
    else
    {
        ssl->tls13IncorrectDheKeyShare = PS_FALSE;
    }

    /* opaque legacy_session_id_echo<0..32>; */
    rc = psParseBufParseTlsVector(pb, 0, 32, &sessionIdLen);
    if (rc <= 0)
    {
        return PS_PARSE_FAIL;
    }

    if (sessionIdLen > 0)
    {
        if (!psParseBufTryParseOctets(pb, sessionIdLen, ssl->sessionId))
        {
            return PS_PARSE_FAIL;
        }
    }

    psTracePrintHex(INDENT_HS_MSG,
            "legacy_session_id_echo",
            ssl->sessionId,
            sessionIdLen,
            PS_TRUE);

    /* CipherSuite cipher_suite; */
    if (!psParseBufTryParseBigEndianUint16(pb,
                    &tmp_u16))
    {
        return PS_PARSE_FAIL;
    }
    cipher = tmp_u16;

    psTracePrintCiphersuiteName(INDENT_HS_MSG,
            "cipher_suite",
            cipher,
            PS_TRUE);

    /* uint8 legacy_compression_method = 0; */
    if (!psParseOctet(pb, &compressionMethod))
    {
        return PS_PARSE_FAIL;
    }

    /* If there is no more data then this serverHello cannot be
       a TLS 1.3 server hello .*/
    if (!psParseCanRead(pb, 8)) /* 8 = minimum length of extensions */
    {
        /* Move the state machine to legacy track */
        psTraceInfo("No extensions, so not a valid TLS 1.3 ServerHello\n");
        ssl->hsState = SSL_HS_SERVER_HELLO;
        return SSL_NO_TLS_1_3;
    }

    rc = tls13ParseServerHelloExtensions(ssl, pb);
    if (rc < 0)
    {
        /* In addition to failure cases, we can end up here
           if we negotiated TLS <1.3. In that case, return
           SSL_NO_TLS_1_3 to fall back to the <1.3 decode
           code path. */
        psTraceInfo("Unable to negotiate TLS 1.3, trying <1.3\n");
        return rc;
    }

    /* Now we can do the postponed checks. */
    if ((ssl->cipher = sslGetCipherSpec(ssl, cipher)) == NULL)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceIntInfo("Can't support requested cipher: %d\n", cipher);
        return MATRIXSSL_ERROR;
    }
    if (compressionMethod != 0)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        return MATRIXSSL_ERROR;
    }

    return MATRIXSSL_SUCCESS;
}

static int32_t tls13ClientActivateHsReadKeys(ssl_t *ssl)
{
    int32_t rc = MATRIXSSL_ERROR;

    ssl->err = SSL_ALERT_INTERNAL_ERROR;

    /* Take snapshot of Transcript-Hash(ClientHello..ServerHello). To be used
       in the client and hello handshake_traffic_secret derivation. */
    rc = tls13TranscriptHashSnapshot(ssl, ssl->sec.tls13TrHashSnapshotCHtoSH);
    if (rc < 0)
    {
        goto exit;
    }

    rc = tls13GenerateEarlySecret(ssl,
            ssl->sec.tls13ChosenPsk);
    if (rc < 0)
    {
        goto exit;
    }

    rc = tls13DeriveHandshakeTrafficSecrets(ssl);
    if (rc < 0)
    {
        goto exit;
    }

    rc = tls13DeriveHandshakeKeys(ssl);
    if (rc < 0)
    {
        goto exit;
    }

    /* Read keys are needed when parsing the next expected message
     * Encrypted Extensions.
     * Write keys are needed when sending next message Certificate
     * or Finished */
    rc = tls13ActivateHsReadKeys(ssl);
    if (rc < 0)
    {
        goto exit;
    }
    rc = MATRIXSSL_SUCCESS;
    ssl->err = SSL_ALERT_NONE;

exit:
    return rc;
}

#ifdef USE_IDENTITY_CERTIFICATES
# ifdef USE_CLIENT_SIDE_SSL
static psRes_t tls13ParseCertificateRequest(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc;
    psSizeL_t certificateRequestContextLen;
    psSize_t copiedLen;
    psSizeL_t extensionsLen;
    psSize_t extensionLen;
    uint16_t extensionId;
    const unsigned char *c;
    sslKeySelectInfo_t *keySelect = &ssl->sec.keySelect;

    psTracePrintHsMessageParse(ssl, SSL_HS_CERTIFICATE_REQUEST);

    /* opaque certificate_request_context<0..2^8-1>; */
    rc = psParseBufParseTlsVector(pb, 0, (1 << 8) - 1,
                                  &certificateRequestContextLen);
    if (rc <= 0)
    {
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return PS_PARSE_FAIL;
    }
#  ifdef DEBUG_TLS_1_3_DECODE_DUMP
    psTraceBytes("Parsed CertificateRequest.certRequestContext",
            pb->buf.start,
            certificateRequestContextLen);
#  endif
    if (certificateRequestContextLen > 0)
    {
        /* Store the value from server */
        psAssert(ssl->tls13CertRequestContext == NULL);
        ssl->tls13CertRequestContext = psMalloc(ssl->hsPool,
                certificateRequestContextLen);
        if (ssl->tls13CertRequestContext == NULL)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return PS_MEM_FAIL;
        }
        copiedLen = certificateRequestContextLen;

        rc = psParseBufCopyNPsSize(pb,
                certificateRequestContextLen,
                ssl->tls13CertRequestContext,
                &copiedLen);
        if (rc != PS_SUCCESS)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return MATRIXSSL_ERROR;
        }
        psAssert(copiedLen == certificateRequestContextLen);
        ssl->tls13CertRequestContextLen = certificateRequestContextLen;
    }

    /* Extension extensions<0..2^16-1>; */
    rc = psParseBufParseTlsVector(pb, 0, (1 << 16) - 1,
                                  &extensionsLen);
    if (rc <= 0)
    {
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return PS_PARSE_FAIL;
    }

    while (psParseCanRead(pb, 4)) /* 4 for extensionId and length */
    {
        /* Extension ID */
        rc = psParseBufTryParseBigEndianUint16(pb,
                &extensionId);
        if (rc != 2)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return PS_PARSE_FAIL;
        }
        /* Extension length */
        rc = psParseBufTryParseBigEndianUint16(pb,
                &extensionLen);
        if (rc != 2)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return PS_PARSE_FAIL;
        }
        /* Handle extensions */
        if (extensionId == EXT_SIGNATURE_ALGORITHMS ||
            extensionId == EXT_SIGNATURE_ALGORITHMS_CERT)
        {
            c = pb->buf.start;
            rc = tls13ParseSignatureAlgorithms(ssl, &c, extensionLen,
                          (extensionId == EXT_SIGNATURE_ALGORITHMS) ?
                                                   PS_FALSE : PS_TRUE);
            if (rc < 0)
            {
                ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
                return PS_PARSE_FAIL;
            }
        }

        if (extensionId == EXT_CERTIFICATE_AUTHORITIES)
        {
            c = pb->buf.start;
            rc = tls13ParseCertificateAuthorities(ssl, &c, extensionLen);
            if (rc < 0)
            {
                ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
                return PS_PARSE_FAIL;
            }
        }
        /* TDB: Other extensions are unsupported currently. */

        /* Forward to next extension */
        rc = psParseTryForward(pb, extensionLen);
        if (rc != extensionLen)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return PS_PARSE_FAIL;
        }
    }

    /* If server supplied only signature_algorithms then copy it's contents to
       signature_algorithms_cert */
    if (ssl->sec.keySelect.peerSigAlgsLen > 0
            && ssl->sec.keySelect.peerCertSigAlgsLen == 0)
    {
        Memcpy(ssl->sec.keySelect.peerCertSigAlgs,
               ssl->sec.keySelect.peerSigAlgs,
               sizeof(ssl->sec.keySelect.peerSigAlgs));
        ssl->sec.keySelect.peerCertSigAlgsLen
            = ssl->sec.keySelect.peerSigAlgsLen;
    }
    ssl->tls13GotCertificateRequest = PS_TRUE;

    if (ssl->chosenIdentity == NULL)
    {
        /* try selecting identity, unless already done. */
        rc = matrixSslChooseClientKeys(ssl, keySelect);
        if (rc != PS_SUCCESS)
        {
            psTraceInfo("Unable to load suitable client certificate " \
                    "in TLS 1.3\n");
        }
    }

    return MATRIXSSL_SUCCESS;
}
#  endif /* USE_CLIENT_SIDE_SSL */
# endif /* USE_IDENTITY_CERTIFICATES */

# ifdef USE_CERT_VALIDATE
static int32_t tls13ParseCertificate(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc;
    psSizeL_t certificateRequestContextLen;
    psSizeL_t certificateListLen, remCertListLen;
    psX509Cert_t *cert, **currentCert = NULL;
    psSizeL_t certLen;
    int32 certFlags = 0;
    int32 parseRet, parseLen;
    psSizeL_t numCerts = 0;
    psBool_t skipInternalValidation = PS_FALSE;

    psTracePrintHsMessageParse(ssl, SSL_HS_CERTIFICATE);

    /*
      Note: not allowing RawPublicKey certs.

      struct {
          opaque cert_data<1..2^24-1>;
          Extension extensions<0..2^16-1>;
      } CertificateEntry;

      struct {
          opaque certificate_request_context<0..2^8-1>;
          CertificateEntry certificate_list<0..2^24-1>;
      } Certificate;
    */

    /* opaque certificate_request_context<0..2^8-1>; */
    rc = psParseBufParseTlsVector(pb, 0, (1 << 8) - 1,
                                  &certificateRequestContextLen);
    if (rc <= 0)
    {
        goto out_illegal_parameter;
    }

    /* CertificateEntry certificate_list<0..2^24-1>; */
    rc = psParseBufParseTlsVector(pb, 0, (1 << 24) - 1,
                                  &certificateListLen);
    if (rc <= 0)
    {
        goto out_illegal_parameter;
    }

    /* Deal with an empty certificate list. */
    if (certificateListLen == 0)
    {
        psTraceInfo("Empty certificate_list in Certificate message\n");

        /*
          Empty certificate from client:
          If our config allows, skip internal validation and
          let the callback decide what to do; otherwise send alert.

          Empty certificate_list from the server:
          Always send an alert.
        */
        if (IS_SERVER(ssl))
        {
# ifdef SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG
            psTraceInfo("Received empty client certificate\n");
            skipInternalValidation = PS_TRUE;
# else
            psTraceErrr("Error: empty client certificate\n");
            goto out_certificate_unknown;
# endif
        }
        else
        {
            psTraceErrr("Error: received empty server certificate\n");
            goto out_certificate_unknown;
        }
    }

    if (certificateListLen > 0 && certificateListLen < 3)
    {
        /* Not empty, but obviously corrupted. */
        goto out_illegal_parameter;
    }

    /* Parse the CertificateEntries in certificate_list. */
    remCertListLen = certificateListLen;

    for (currentCert = &(ssl->sec.cert); *currentCert; currentCert = &((*currentCert)->next))
        ;

    while (remCertListLen >= 3)
    {
        /* opaque cert_data<1..2^24-1>; */
        rc = psParseBufParseTlsVector(pb, 1, (1 << 24) - 1,
                                      &certLen);
        if (rc <= 0)
        {
            goto out_illegal_parameter;
        }
        remCertListLen -= 3;

        parseRet = psX509ParseCert(ssl->hsPool,
                pb->buf.start,
                certLen,
                &cert,
                certFlags);
        if (parseRet < 0)
        {
            if (parseRet == PS_MEM_FAIL)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
            }
            else
            {
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            }
            psX509FreeCert(cert);
            return MATRIXSSL_ERROR;
        }
        parseLen = parseRet;

        *currentCert = cert;
        currentCert = &((*currentCert)->next);
        numCerts++;

        psTracePrintCertSubject(INDENT_HS_MSG,
                ssl, cert, numCerts);

        psParseForward(pb, parseLen);
        remCertListLen -= parseLen;

        if (psParseCanRead(pb, 6))
        {
            rc = tls13ParseExtensions(ssl, pb, SSL_HS_CERTIFICATE);
            if (rc < 0)
            {
                return rc;
            }
# ifdef OCSP_MUST_STAPLE
            if (cert == ssl->sec.cert
                    && ssl->extFlags.req_status_request == 1
                    && ssl->extFlags.status_request == 0)
            {
                psTraceErrr("Server did not provide an OCSP response " \
                        "for the server certificate and " \
                        "OCSP_MUST_STAPLE is enabled\n");
                goto out_bad_certificate_status_response;
            }
# endif
            remCertListLen -= rc;
        }
    }

    /* The chain has been succesfully parsed. Now validate it. */
    if (!skipInternalValidation)
    {
        rc = tls13ValidateCertChain(ssl);
        if (rc < 0)
        {
            /* tls13ValidateCertChain sets the alert. */
            return rc;
        }
    }
    else
    {
        /* Skip internal validation and let the callback deal with
           it directly. */
        rc = matrixUserCertValidator(ssl,
            SSL_ALERT_CERTIFICATE_UNKNOWN,
            NULL,
            ssl->sec.validateCert);
        return tls13HandleUserCertCbResult(ssl, rc);
    }

    return MATRIXSSL_SUCCESS;

out_illegal_parameter:
    psTraceErrr("Error: invalid Certificate message\n");
    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
    return MATRIXSSL_ERROR;
out_certificate_unknown:
    ssl->err = SSL_ALERT_CERTIFICATE_UNKNOWN;
    return MATRIXSSL_ERROR;
# ifdef OCSP_MUST_STAPLE
out_bad_certificate_status_response:
    ssl->err = SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE;
    return MATRIXSSL_ERROR;
# endif /* OCSP_MUST_STAPLE */
}

static int32_t tls13ParseCertificateVerify(ssl_t *ssl,
        psParseBuf_t *pb)
{
    int32_t rc;
    uint16_t algorithm;
    uint16_t signatureLen;
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    psSize_t hashLen;
    const char *contextStrServer = "TLS 1.3, server CertificateVerify";
    const char *contextStrClient = "TLS 1.3, client CertificateVerify";

    psTracePrintHsMessageParse(ssl, SSL_HS_CERTIFICATE_VERIFY);

    /* struct {
              SignatureScheme algorithm;
              opaque signature<0..2^16-1>;
          } CertificateVerify;
    */

    /* Algorithm */
    rc = psParseBufTryParseBigEndianUint16(pb,
            &algorithm);
    if (rc != 2)
    {
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return PS_PARSE_FAIL;
    }
    /* Make sure the algorithm is on our supported list */
    if (findFromUint16Array(ssl->supportedSigAlgs,
                            ssl->supportedSigAlgsLen,
                            algorithm) < 0)
    {
        psTraceErrr("Peer sent CertificateVerify with unsupported " \
                    "signature algorithm\n");
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return MATRIXSSL_ERROR;
    }

    psTracePrintTls13SigAlg(INDENT_HS_MSG,
            "algorithm",
            algorithm, PS_TRUE);

    ssl->sec.tls13PeerCvSigAlg = algorithm;

    rc = psParseBufTryParseBigEndianUint16(pb,
            &signatureLen);
    if (rc != 2)
    {
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return PS_PARSE_FAIL;
    }
    if (!psParseCanRead(pb, signatureLen))
    {
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return PS_PARSE_FAIL;
    }
    rc = tls13TranscriptHashSnapshot(ssl, ssl->sec.tls13TrHashSnapshot);
    if (rc < 0)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return rc;
    }
    rc = psGetOutputBlockLength(hmacAlg);
    if (rc < 0)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return rc;
    }
    hashLen = (psSize_t)rc;

    /* Verify the signature */
    rc = tls13Verify(ssl->hsPool,
            &ssl->sec.cert->publicKey,
            algorithm,
            pb->buf.start, signatureLen,
            ssl->sec.tls13TrHashSnapshot, hashLen,
            IS_SERVER(ssl) ? contextStrClient : contextStrServer,
            IS_SERVER(ssl) ? Strlen(contextStrClient) : Strlen(contextStrServer));
    if (rc < 0)
    {
        psTraceErrr("Could not verify peer signature\n");
        ssl->err = SSL_ALERT_DECRYPT_ERROR;
        return rc;
    }
    psTraceInfo("CertificateVerify signature OK\n");

    return MATRIXSSL_SUCCESS;
}
# endif /* USE_CERT_VALIDATE */

static int32_t tls13ParseFinished(ssl_t *ssl, psParseBuf_t *pb)
{
    int32_t rc;
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    psSize_t len;
    unsigned char trHash[MAX_TLS_1_3_HASH_SIZE];
    unsigned char verifyData[MAX_TLS_1_3_HASH_SIZE];
    psHmac_t ctx;

    psTracePrintHsMessageParse(ssl, SSL_HS_FINISHED);

    /*
      struct {
          opaque verify_data[Hash.length];
      } Finished;
    */

    rc = psGetOutputBlockLength(hmacAlg);
    if (rc < 0)
    {
        goto out_decode_error;
    }
    len = (psSize_t)rc;

    if (!psParseCanRead(pb, len))
    {
        goto out_decode_error;
    }

    /* Compute our version of the peer's verify_data. */
    rc = tls13DeriveFinishedKey(ssl, !IS_SERVER(ssl));
    if (rc < 0)
    {
        goto out_internal_error;
    }

    /*
      Handshake Context for client Finished:
        ClientHello ... later of Finished/EndOfEarlyData

      Unless we sent some app data after our Finished (unsupported),
      the Transcript-Hash is be up-to-date. We only need a snapshot.
    */
    rc = tls13TranscriptHashSnapshot(ssl, trHash);
    if (rc < 0)
    {
        goto out_internal_error;
    }

    /*
      verify_data =
          HMAC(finished_key,
               Transcript-Hash(Handshake Context,
                               Certificate*, CertificateVerify*))
    */
    rc = psHmacSingle(&ctx,
            hmacAlg,
            ssl->sec.tls13FinishedKey,
            len,
            trHash,
            len,
            verifyData);
    if (rc < 0)
    {
        goto out_internal_error;
    }
#ifdef DEBUG_TLS_1_3_DECODE_DUMP
    psTraceBytes("Our verify_data", verifyData, len);
#endif

    /* Does our verify_data match the peer's? */
    if (memcmpct(verifyData, pb->buf.start, len))
    {
        psTraceErrr("Finished verify_data mismatch\n");
        goto out_decrypt_error;
    }
    else
    {
        psTraceInfo("verify_data OK\n");
    }

    return MATRIXSSL_SUCCESS;

out_internal_error:
    psTraceErrr("Finished parsing: internal error\n");
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
out_decode_error:
    psTraceErrr("Finished parsing: invalid message format\n");
    ssl->err = SSL_ALERT_DECODE_ERROR;
    return MATRIXSSL_ERROR;
out_decrypt_error:
    ssl->err = SSL_ALERT_DECRYPT_ERROR;
    return MATRIXSSL_ERROR;
}

static int32_t tls13ParseNewSessionTicket(ssl_t *ssl, psParseBuf_t *pb)
{
    int32_t rc;
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    psSize_t pskValLen;
    unsigned char pskVal[MAX_TLS_1_3_HASH_SIZE];
    uint32_t ticketLifetime;
    uint32_t ticketAgeAdd;
    unsigned char *nonce = NULL;
    psSizeL_t nonceLen;
    unsigned char *ticket = NULL;
    psSizeL_t ticketLen, copiedLen, extensionsLen, extDataLen;
    psParseBuf_t extBuf, extDataBuf;
    uint16_t extensionType;
    psTls13SessionParams_t params = {0};
    psTls13Psk_t *psk;
    uint32_t maxEarlyData = 0;
    tlsExtension_t *ext;

    psTracePrintHsMessageParse(ssl, SSL_HS_NEW_SESSION_TICKET);

    rc = psGetOutputBlockLength(hmacAlg);
    if (rc < 0)
    {
        goto out_decode_error;
    }
    pskValLen = (psSize_t)rc;

    /*
      struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce<0..255>;
          opaque ticket<1..2^16-1>;
          Extension extensions<0..2^16-2>;
      } NewSessionTicket;
    */
    rc = psParseBufTryParseBigEndianUint32(pb, &ticketLifetime);
    if (rc != 4)
    {
        goto out_decode_error;
    }
    rc = psParseBufTryParseBigEndianUint32(pb, &ticketAgeAdd);
    if (rc != 4)
    {
        goto out_decode_error;
    }

    /* opaque ticket_nonce<0..255>; */
    rc = psParseBufParseTlsVector(pb,
            0, 255,
            &nonceLen);
    if (rc <= 0)
    {
        goto out_decode_error;
    }
    nonce = psMalloc(ssl->hsPool, nonceLen);
    if (nonce == NULL)
    {
        goto out_internal_error;
    }
    copiedLen = nonceLen;
    rc = psParseBufCopyN(pb,
            nonceLen,
            nonce,
            &copiedLen);
    if (rc != PS_SUCCESS || copiedLen != nonceLen)
    {
        goto out_internal_error;
    }
    psParseForward(pb, copiedLen);

    /* opaque ticket<1..2^16-1>; */
    rc = psParseBufParseTlsVector(pb,
            1, (1 << 16) - 1,
            &ticketLen);
    if (rc <= 0)
    {
        goto out_decode_error;
    }
    ticket = psMalloc(ssl->hsPool, ticketLen);
    if (ticket == NULL)
    {
        goto out_internal_error;
    }
    copiedLen = ticketLen;
    rc = psParseBufCopyN(pb,
            ticketLen,
            ticket,
            &copiedLen);
    if (rc != PS_SUCCESS || copiedLen != ticketLen)
    {
        goto out_internal_error;
    }
    psParseForward(pb, copiedLen);

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

    while (psParseCanRead(&extBuf, 4))
    {
        /* ExtensionType extension_type; */
        rc = psParseBufTryParseBigEndianUint16(&extBuf,
                &extensionType);
        if (rc != 2)
        {
            goto out_decode_error;
        }

        /* 4.2. If the received extension is not specified for the message
           in which it appears, we MUST abort the handshake with an
           illegal_parameter alert. */
        if (!tls13ExtensionAllowedInMessage(ssl,
                        extensionType,
                        SSL_HS_NEW_SESSION_TICKET))
        {
            goto out_decode_error;
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
        case EXT_EARLY_DATA:
            rc = tls13ParseEarlyData(ssl, &extDataBuf, &maxEarlyData);
            if (rc < 0)
            {
                goto out_decode_error;
            }
            break;

        default:
            psTraceIntInfo("Ignoring unknown NewSessionTicket extension: %hu\n",
                    extensionType);
        }
    }

    rc = tls13DeriveResumptionPsk(ssl,
            hmacAlg,
            nonce,
            nonceLen,
            pskVal,
            sizeof(pskVal));
    if (rc < 0)
    {
        goto out_internal_error;
    }

    ext = ssl->userExt;
    while (ext)
    {
        if (ext->extType == EXT_SNI)
        {
            break;
        }
        ext = ext->next;
    }
    if (ext && ext->extType == EXT_SNI)
    {
        /* We could only store the actual SNI values, but there can be
           several. It is simpler to store the entire SNI extension. */
        params.sni = psMalloc(ssl->hsPool, ext->extLen);
        if (params.sni == NULL)
        {
            goto out_internal_error;
        }
        params.sniLen = ext->extLen;
        Memcpy(params.sni, ext->extData, ext->extLen);
# ifdef DEBUG_TLS_1_3_DECODE
        psTraceBytes("Associated PSK with SNI ext", params.sni, ext->extLen);
# endif
    }
    params.alpn = NULL;
    params.alpnLen = 0;
    params.majVer = psEncodeVersionMaj(ssl->activeVersion);
    params.minVer = psEncodeVersionMin(ssl->activeVersion);
    params.cipherId = ssl->cipher->ident;
    params.ticketLifetime = ticketLifetime;
    params.ticketAgeAdd = ticketAgeAdd;
    psGetTime(&params.timestamp, ssl->userPtr);
    params.maxEarlyData = maxEarlyData;

    /* Store copy of the new PSK in our session context. */
    rc = tls13StorePsk(ssl,
            pskVal,
            pskValLen,
            ticket,
            ticketLen,
            PS_TRUE,
            &params);
    if (rc < 0)
    {
        goto out_internal_error;
    }

    /* Get a pointer to the PSK we just added. */
    rc = tls13FindSessionPsk(ssl,
            ticket,
            ticketLen,
            &psk);
    if (rc < 0)
    {
        goto out_internal_error;
    }

    /* Store the session and the received ticket in the session ID struct. */

    if (ssl->sid)
    {
        /* If we have already stored a ticket and the associated PSK in
           the session ID, clear those. The server is allowed to send
           multiple tickets in a single handshake, but we only support
           storing the last one. TODO: add support for storing multiple
           tickets. */
# ifdef USE_STATELESS_SESSION_TICKETS
        if (ssl->sid->sessionTicket)
        {
            psFree(ssl->sid->sessionTicket, ssl->sid->pool);
        }
# endif
        if (ssl->sid->psk)
        {
            tls13FreePsk(ssl->sid->psk, ssl->sid->pool);
        }
    }
    else
    {
        ssl->sid = psMalloc(ssl->hsPool, sizeof(sslSessionId_t));
        if (ssl->sid == NULL)
        {
            goto out_internal_error;
        }
        Memset(ssl->sid, 0, sizeof(sslSessionId_t));
        ssl->sid->pool = ssl->hsPool;
    }
# ifdef USE_STATELESS_SESSION_TICKETS
    ssl->sid->sessionTicket = psMalloc(ssl->sid->pool, ticketLen);
    if (ssl->sid->sessionTicket == NULL)
    {
        goto out_internal_error;
    }
    Memcpy(ssl->sid->sessionTicket, ticket, ticketLen);
    ssl->sid->sessionTicketLen = ticketLen;
# endif
    ssl->sid->cipherId = psk->params->cipherId;

    ssl->sid->psk = tls13NewPsk(psk->pskKey,
            psk->pskLen,
            psk->pskId,
            psk->pskIdLen,
            PS_TRUE,
            psk->params);
    if (ssl->sid->psk == NULL)
    {
        goto out_internal_error;
    }

    rc = PS_SUCCESS;
    goto do_free;

out_internal_error:
    psTraceErrr("NewSessionTicket parsing: internal error\n");
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    rc = MATRIXSSL_ERROR;
    goto do_free;
out_decode_error:
    psTraceErrr("NewSessionTicket parsing: invalid message format\n");
    ssl->err = SSL_ALERT_DECODE_ERROR;
    rc = MATRIXSSL_ERROR;

do_free:
    psFree(nonce, ssl->hsPool);
    psFree(ticket, ssl->hsPool);
    psFree(params.sni, ssl->hsPool);
    return rc;
}
# endif /* USE_TLS_1_3 */

/* end of file tls13Decode.c */
