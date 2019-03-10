/**
 *      @file    tls13Encode.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 specific functions for handshake message and record encoding.
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

#define REC_HDR_LEN 5
#define HS_HDR_LEN 4

/* Message size estimates. Used as initial psDynBuf sizes. */
#define CLIENT_HELLO_SIZE_EST 256
#define SERVER_HELLO_SIZE_EST 256
#define ENCRYPTED_EXTENSIONS_SIZE_EST 32
#define FINISHED_SIZE_EST 64
#define CERTIFICATE_SIZE_EST 8192
#define CERTIFICATE_REQUEST_SIZE_EST 512
#define CERTIFICATE_VERIFY_SIZE_EST 512

# ifndef DEBUG_TLS_1_3_ENCODE
/* #  define DEBUG_TLS_1_3_ENCODE */
# endif

/* Hex-dump plaintext and ciphertext of created messages. */
# ifndef DEBUG_TLS_1_3_ENCODE_DUMP
/* #  define DEBUG_TLS_1_3_ENCODE_DUMP */
# endif

/* Verify all the TLS 1.3 signatures we generate, not just
   RSA signatures. */
# ifndef TLS_1_3_VERIFY_OWN_SIG
/* #  define TLS_1_3_VERIFY_OWN_SIG */
# endif

/** These are defined sslEncode.c */
extern int32 psGenerateServerRandom(ssl_t *ssl);

/** From tlsDefaults.c */
extern int32 getDefaultCipherSuites(ssl_t *ssl, psPool_t *pool,
                             unsigned char** cipherSuites,
                             psSize_t *cipherSuitesLen);

static
int32_t tls13HandleBufferFull(ssl_t *ssl, int32 failedMsgSize)
{
    psTraceInfo("Buffer too small for flight\n");
    ssl->tls13NextMsgRequiredLen = failedMsgSize;
    return SSL_FULL;
}

/*
  Return amount of TLS 1.3 record padding that should be added
  to a plaintext fragment such that the size of the resulting
  TLSInnerPlaintext is either maximal or a multiple of
  ssl->tls13BlockSize.

  @param[in] ssl Pointer to SSL context
  @param[in] len Length of the plaintext fragment
  @retval Amount of padding bytes needed

  @precond: len <= TLS_1_3_MAX_PLAINTEXT_FRAGMENT_LEN
  @postcond: For the returned value n, either
  (len + n + 1) % ssl->tls13BlockSize == 0 or
  TLS_1_3_MAX_INNER_PLAINTEXT_LEN - n == len.
*/
psSizeL_t tls13GetPadLen(ssl_t *ssl, psSizeL_t len)
{
    psSizeL_t bound; /* Size of the resulting TLSInnerPlaintext. */
    psSizeL_t padLen; /* Num of pad bytes needed to reach bound. */

    psAssert(len <= TLS_1_3_MAX_PLAINTEXT_FRAGMENT_LEN);

    /* Add +1 to take into account the TLSInnerplaintext type field. */
    bound = psRoundUpToBlockSize(len + 1,
            ssl->tls13BlockSize);
    if (bound > TLS_1_3_MAX_INNER_PLAINTEXT_LEN)
    {
        bound = TLS_1_3_MAX_INNER_PLAINTEXT_LEN;
    }
    psAssert(bound - 1 >= len);
    padLen = bound - 1 - len;

    psAssert((len + padLen + 1) % ssl->tls13BlockSize == 0
        || TLS_1_3_MAX_INNER_PLAINTEXT_LEN - 1 - padLen == len);

    return padLen;
}

/* Write headers to handshake and application data messages.
*/
static
int32_t tls13WriteRecordHeader(ssl_t *ssl,
        uint8_t recordType,
        uint8_t handshakeMessageType,
        unsigned char *data,
        psSizeL_t dataLen,
        psSizeL_t hsLen,
        psSizeL_t *padLen,
        psSizeL_t fragId,
        psBool_t toBeEncrypted,
        unsigned char **c,
        const unsigned char *end,
        unsigned char **encryptStart,
        unsigned char **encryptEnd)
{
    psDynBuf_t TLSInnerPlaintext;
    psDynBuf_t TLSPlaintext;
    psDynBuf_t TLSCiphertext;
    psDynBuf_t Handshake;
    unsigned char *body, *pt, *inner, *ct;
    size_t bodyLen, ptLen, innerLen, ctLen, cipherOutputLen;
    unsigned char tagPlaceholder[TLS_GCM_TAG_LEN] = {0};
    psPool_t *pool = ssl->hsPool;
    psBool_t mustFreeBody = PS_FALSE;

    psAssert(recordType == SSL_RECORD_TYPE_HANDSHAKE ||
            recordType == SSL_RECORD_TYPE_APPLICATION_DATA ||
            recordType == SSL_RECORD_TYPE_ALERT);


    if (recordType == SSL_RECORD_TYPE_HANDSHAKE)
    {
      /*
        Handshake messages must be wrapped into Handshake types.

        struct {
            HandshakeType msg_type;
            uint24 length;
            select (Handshake.msg_type) {
                case client_hello:          ClientHello;
                case server_hello:          ServerHello;
                case end_of_early_data:     EndOfEarlyData;
                case encrypted_extensions:  EncryptedExtensions;
                case certificate_request:   CertificateRequest;
                case certificate:           Certificate;
                case certificate_verify:    CertificateVerify;
                case finished:              Finished;
                case new_session_ticket:    NewSessionTicket;
                case key_update:            KeyUpdate;
            };
        } Handshake;
      */
        psDynBufInit(pool, &Handshake, dataLen + 4);
        /* Only the first fragment of the HS message has the header */
        if (fragId == 0)
        {
            psDynBufAppendByte(&Handshake, (unsigned char)handshakeMessageType);
            psDynBufAppendByte(&Handshake, (hsLen & 0xff0000) >> 16);
            psDynBufAppendByte(&Handshake, (hsLen & 0x00ff00) >> 8);
            psDynBufAppendByte(&Handshake, hsLen & 0xff );
        }
        psDynBufAppendOctets(&Handshake, data, dataLen);
        body = psDynBufDetach(&Handshake, &bodyLen);
        if (body == NULL)
        {
            return PS_MEM_FAIL;
        }
        mustFreeBody = PS_TRUE;
        psDynBufUninit(&Handshake);
    }
    else
    {
        body = data;
        bodyLen = dataLen;
    }

    if (toBeEncrypted)
    {
        /*
          Wrap Handshake or app data into a TLSInnerPlaintext.

          struct {
              opaque content[TLSPlaintext.length];
              ContentType type;
              uint8 zeros[length_of_padding];
          } TLSInnerPlaintext;
        */
        if (ssl->tls13BlockSize > 0)
        {
            /* If desired block size is given, compute padding accordingly.
               Otherwise, we shall use the padLen that was passed in. */
            *padLen = tls13GetPadLen(ssl, bodyLen);
        }
        if (bodyLen + 1 > TLS_1_3_MAX_INNER_PLAINTEXT_LEN)
        {
            psTraceErrr("Error: tried to encode oversized TLSInnerPlaintext.\n");
            if (mustFreeBody)
            {
                psFree(body, pool);
            }
            return PS_ARG_FAIL;
        }
        psDynBufInit(pool, &TLSInnerPlaintext, bodyLen + 1 + *padLen);
        psDynBufAppendOctets(&TLSInnerPlaintext,
                body,
                bodyLen);
        if (mustFreeBody)
        {
            psFree(body, pool);
        }
        psDynBufAppendByte(&TLSInnerPlaintext,
                (unsigned char)recordType);

        /* Add padding, if desired. */
        if (*padLen > 0)
        {
            psDynBufAppendOctetNTimes(&TLSInnerPlaintext, 0, *padLen);
#ifdef DEBUG_TLS_1_3_ENCODE_PADDING
            psTraceIntInfo(" Orig len: %zu\n", bodyLen + 1);
            psTraceIntInfo(" Added %zu bytes of padding\n", *padLen);
            psTraceIntInfo(" Padded to %zu bytes\n", bodyLen + 1 + *padLen);
#endif /* DEBUG_TLS_1_3_ENCODE_PADDING */
        }

        inner = psDynBufDetach(&TLSInnerPlaintext,
                &innerLen);
        if (inner == NULL)
        {
            psDynBufUninit(&TLSInnerPlaintext);
            return PS_MEM_FAIL;
        }
#ifdef DEBUG_TLS_1_3_ENCODE_DUMP
        psTraceBytes("TLSInnerPlaintext", inner, innerLen);
#endif
        if (innerLen > TLS_1_3_MAX_INNER_PLAINTEXT_LEN)
        {
            psTraceErrr("Tried to create oversized TLSInnerPlaintext\n");
            psDynBufUninit(&TLSInnerPlaintext);
            psFree(inner, pool);
            return PS_ARG_FAIL;
        }

        /*
          Wrap TLSInnerPlaintext into a TLSCiphertext.

          struct {
             ContentType opaque_type = application_data;
             ProtocolVersion legacy_record_version = 0x0303;
             uint16 length;
             opaque encrypted_record[TLSCiphertext.length];
          } TLSCiphertext;
        */
        psDynBufInit(pool, &TLSCiphertext, innerLen + 5 + TLS_GCM_TAG_LEN);
        psDynBufAppendByte(&TLSCiphertext, SSL_RECORD_TYPE_APPLICATION_DATA);
        psDynBufAppendByte(&TLSCiphertext, TLS_MAJ_VER);
        psDynBufAppendByte(&TLSCiphertext, TLS_1_2_MIN_VER);

        cipherOutputLen = innerLen + TLS_GCM_TAG_LEN;
        psDynBufAppendAsBigEndianUint16(&TLSCiphertext, cipherOutputLen);

        /* To be encrypted in-situ in encryptRecord. */
        psDynBufAppendOctets(&TLSCiphertext, inner, innerLen);
        psFree(inner, pool);
        psDynBufUninit(&TLSInnerPlaintext);
        psDynBufAppendOctets(&TLSCiphertext, tagPlaceholder, TLS_GCM_TAG_LEN);

        ct = psDynBufDetach(&TLSCiphertext, &ctLen);
        if (ct == NULL)
        {
            psDynBufUninit(&TLSInnerPlaintext);
            psDynBufUninit(&TLSCiphertext);
            return PS_MEM_FAIL;
        }
        if (end - *c < ctLen)
        {
            psFree(ct, pool);
            /* The handshake message might be much larger than
               ctLen of current fragment, so reserve space for all
               fragments in that case.*/
            return tls13HandleBufferFull(ssl, PS_MAX(ctLen, hsLen));
        }
#ifdef DEBUG_TLS_1_3_ENCODE_DUMP
        psTraceBytes("Unencrypted TLSCiphertext", ct, ctLen);
#endif

        Memcpy(*c, ct, ctLen);
        psFree(ct, pool);
        psDynBufUninit(&TLSCiphertext);
        *encryptStart = *c + REC_HDR_LEN; /* Point to encrypted_record. */
        *encryptEnd = *encryptStart + innerLen;
        *c += ctLen;
    }
    else
    {
        /*
          Wrap Handshake into a TLSPlaintext.

          struct {
          ContentType type;
          ProtocolVersion legacy_record_version;
          uint16 length;
          opaque fragment[TLSPlaintext.length];
          } TLSPlaintext;
        */
        psDynBufInit(pool, &TLSPlaintext, bodyLen + 5);
        psDynBufAppendByte(&TLSPlaintext, recordType);
        psDynBufAppendByte(&TLSPlaintext, TLS_MAJ_VER);
        psDynBufAppendByte(&TLSPlaintext, TLS_1_2_MIN_VER);
        psDynBufAppendAsBigEndianUint16(&TLSPlaintext, bodyLen);
        psDynBufAppendOctets(&TLSPlaintext, body, bodyLen);
        if (mustFreeBody)
        {
            psFree(body, pool);
        }
        pt = psDynBufDetach(&TLSPlaintext, &ptLen);
        if (pt == NULL)
        {
            psDynBufUninit(&TLSPlaintext);
            return PS_MEM_FAIL;
        }
# ifdef DEBUG_TLS_1_3_ENCODE_DUMP
        psTraceBytes("TLSPlaintext", pt, ptLen);
# endif

        /* No encryption, so encode the TLSPlaintext directly. */
        if (end - *c < ptLen)
        {
            psFree(pt, pool);
            psTraceInfo("Buffer too small for flight\n");
            return tls13HandleBufferFull(ssl, ptLen);
        }
        Memcpy(*c, pt, ptLen);
        psFree(pt, pool);
        *encryptStart = *c; /* To be "encrypted" with the NULL cipher. */
        *encryptEnd = *c + ptLen;
        *c += ptLen;
    }

    return MATRIXSSL_SUCCESS;
}

static inline
flightEncode_t *newFlightMessage(ssl_t *ssl)
{
    flightEncode_t *flight;

    if ((flight = psMalloc(ssl->flightPool, sizeof(flightEncode_t))) == NULL)
    {
        return NULL;
    }
    Memset(flight, 0x0, sizeof(flightEncode_t));

    return flight;
}

/* Presently just a simplified version of postponeEncryptRecord.

   Add handshake message to the current flight. The idea is to start encrypting
   only after we have succesfully encoded all messages in the flight.
   Update Transcript-Hash.
*/
static int32_t tls13PostponeEncryptRecord(ssl_t *ssl,
        int32 messageSize,
        int32 type,
        int32 hsMsgType,
        psSize_t fragId,
        psBool_t toBeEncrypted,
        unsigned char *rec,
        unsigned char *pt,
        int32 ptLen,
        psSizeL_t padLen,
        sslBuf_t *out)
{
    flightEncode_t *flightMsg, *msg, *prev;
    int32_t rc;
    unsigned char *trHashInput, *bindersStart;
    psSizeL_t trHashInputLen, chPart1Len;
    psBool_t resumed = PS_FALSE;

    flightMsg = newFlightMessage(ssl);
    if (flightMsg == NULL)
    {
        return PS_MEM_FAIL;
    }

    if (ssl->flightEncode == NULL)
    {
        ssl->flightEncode = flightMsg;
    }
    else
    {
        msg = ssl->flightEncode;
        while (msg)
        {
            if (msg->hsMsg == hsMsgType && msg->fragId == fragId)
            {
                resumed = PS_TRUE;
# ifdef DEBUG_TLS_1_3_ENCODE
                psTraceInfo("Resumed flight message creation\n");
# endif
                psFree(flightMsg, ssl->flightPool);
                flightMsg = msg;
                goto resumedWrite;
            }
            prev = msg;
            msg = msg->next;
        }
# ifdef DEBUG_TLS_1_3_ENCODE
        psTraceInfo("Adding a new message to flight:\n");
# endif
        prev->next = flightMsg;
    }

resumedWrite:
    flightMsg->start = pt;
    flightMsg->len = ptLen;
    flightMsg->type = type;
    flightMsg->padLen = padLen;
    flightMsg->messageSize = messageSize;
    flightMsg->hsMsg = hsMsgType;
    flightMsg->fragId = fragId;
    flightMsg->seqDelay = ssl->seqDelay;

#ifdef DEBUG_TLS_1_3_ENCODE
    psTracePrintHsMsgType(hsMsgType, PS_TRUE);
#endif

    /* Update Transcript-Hash. */
    if (flightMsg->type == SSL_RECORD_TYPE_HANDSHAKE &&
            hsMsgType != SSL_HS_NEW_SESSION_TICKET &&
            !resumed)
    {
        /*
          4.4.1
          "This value is computed by hashing the concatenation
          of each included handshake message, including the handshake message
          header carrying the handshake message type and length fields, but not
          including record layer headers".
        */
        trHashInput = flightMsg->start;
        trHashInputLen = flightMsg->len;
        if (toBeEncrypted)
        {
            /* Not included: TLSInnerPlaintext type (1 byte) and padding. */
            trHashInputLen -= 1;
            trHashInputLen -= flightMsg->padLen;
        }
        else
        {
            /* Not included: TLSPlaintext header. */
            trHashInput += REC_HDR_LEN;
            trHashInputLen -= REC_HDR_LEN;
        }
        if (hsMsgType == SSL_HS_CLIENT_HELLO && ssl->sec.tls13BindersLen > 0)
        {
            /*
              A ClientHello containing PSK binders will need to be hashed
              in two parts:
              1) up to (but not including) the binders list,
              2) the binders list.
              The snapshot hash of part 1 is used as HMAC input when creating
              the binder values. We have previously written a dummy binders
              vector of the correct size.
            */
            chPart1Len = trHashInputLen - ssl->sec.tls13BindersLen;
            bindersStart = trHashInput + chPart1Len;

            /* Part one. */
            rc = tls13TranscriptHashUpdate(ssl, trHashInput, chPart1Len);
            if (rc < 0)
            {
                return rc;
            }
            rc = tls13TranscriptHashSnapshot(ssl,
                    ssl->sec.tls13TrHashSnapshotCHWithoutBinders);
            if (rc < 0)
            {
                return rc;
            }
            /* Now compute and fill in the final binder values. */
            rc = tls13FillInPskBinders(ssl, bindersStart);
            if (rc < 0)
            {
                return rc;
            }
            /* Setup part two. */
            trHashInput += chPart1Len;
            trHashInputLen = ssl->sec.tls13BindersLen;
        }
        rc = tls13TranscriptHashUpdate(ssl,
                trHashInput,
                trHashInputLen);
        if (rc < 0)
        {
            return rc;
        }
    }

# ifdef DEBUG_TLS_1_3_ENCODE
    psTracePrintCurrentFlight(ssl);
# endif

    return MATRIXSSL_SUCCESS;
}

/** Make a record out of a handshake message body.

    Given a handshake message body, add necessary wrappers from the
    set {Handshake, TLSInnerPlaintext, TLSPlaintext, TLSCiphertext}.

    Add message to current flight. Compute pointers for later in-situ
    encryption.
*/
static int32_t makeHsRecord(ssl_t *ssl,
        int32_t hsType,
        unsigned char *msgStart,
        psSizeL_t msgLen,
        psBool_t toBeEncrypted,
        psBuf_t *out)
{
    unsigned char *c, *end;
    unsigned char *encryptStart, *encryptEnd;
    unsigned char *msgEnd = msgStart + msgLen;
    uint8_t recordType = SSL_RECORD_TYPE_HANDSHAKE;
    psSize_t messageSize;
    int32_t rc;
    psSizeL_t fragLen;
    int32 fragId = 0;
    psSizeL_t padLen = ssl->tls13PadLen;

    c = out->end;
    end = out->buf + out->size;

# ifdef DEBUG_TLS_1_3_ENCODE
    psTraceIntInfo("Message body size is %d\n", msgLen);
    psTraceIntInfo("Output buffer has room for %d\n", end - c);
# endif

    if (msgLen > ssl->maxPtFrag)
    {
        /* Need to fragment */
# ifdef DEBUG_TLS_1_3_ENCODE
        psTraceIntInfo("Message must be fragmented. Fragment size: %d\n",
                ssl->maxPtFrag);
# endif
        /* First fragment has the header */
        fragLen = ssl->maxPtFrag - HS_HDR_LEN;
    }
    else
    {
        /* No fragmentation needed */
        fragLen = msgLen;
    }

    /* Divide input msg to maxPtFrag size fragments */
    do
    {
        rc = tls13WriteRecordHeader(ssl,
                recordType,
                hsType,
                msgStart,
                fragLen,
                msgLen,
                &padLen,
                fragId,
                toBeEncrypted,
                &c,
                end,
                &encryptStart, &encryptEnd);
        if (rc < 0)
        {
            return rc;
        }
        messageSize = c - out->end;

        rc = tls13PostponeEncryptRecord(ssl,
                messageSize,
                recordType,
                hsType,
                fragId,
                toBeEncrypted,
                c,
                encryptStart,
                encryptEnd - encryptStart,
                padLen,
                out);
        if (rc < 0)
        {
            return rc;
        }
        out->end = c;
        msgStart += fragLen;
        fragLen = min(ssl->maxPtFrag, msgEnd - msgStart);
        fragId++;
    } while (msgStart < msgEnd);

    return PS_SUCCESS;
}

#ifdef USE_SERVER_SIDE_SSL

static int32 tls13WriteServerHello(ssl_t *ssl, sslBuf_t *out,
                                   psBool_t isHelloRetryRequest)
{
    int32 rc;
    psDynBuf_t extBuf;
    psDynBuf_t shBuf;
    unsigned char *extData, *shData;
    psSize_t extDataLen, shLen;

    psTracePrintHsMessageCreate(ssl, SSL_HS_SERVER_HELLO);
    psDynBufInit(ssl->hsPool, &shBuf, SERVER_HELLO_SIZE_EST);

    /* ProtocolVersion legacy_version == 0x0303 */
    psDynBufAppendByte(&shBuf, TLS_MAJ_VER);
    psDynBufAppendByte(&shBuf, TLS_1_2_MIN_VER);

    if (isHelloRetryRequest)
    {
        /* We can write a HelloRetryRequest using this function
           since the format is identical. Only extensions are
           different. */
        ssl->tls13IncorrectDheKeyShare = PS_TRUE;
        psDynBufAppendOctets(&shBuf, sha256OfHelloRetryRequest, 32);
    }
    else
    {
        ssl->tls13IncorrectDheKeyShare = PS_FALSE;

        /* Random random (32 bytes) */
        if (ssl->sec.tls13KsState.generateRandomDone == 0)
        {
            rc = psGenerateServerRandom(ssl);
            if (rc < 0)
            {
                psDynBufUninit(&shBuf);
                return rc;
            }
            ssl->sec.tls13KsState.generateRandomDone = 1;
        }
        psDynBufAppendOctets(&shBuf, ssl->sec.serverRandom, 32);
# ifdef DEBUG_TLS_1_3_ENCODE_DUMP
        psTraceBytes("server_random", ssl->sec.serverRandom, 32);
# endif
    }

    /* opaque legacy_session_id_echo<0..32> */
    psDynBufAppendTlsVector(&shBuf, 0, 32,
            ssl->sessionId, ssl->sessionIdLen);

    /* CipherSuite ciphersuite (2 bytes) */
    psDynBufAppendAsBigEndianUint16(&shBuf, ssl->cipher->ident);

    /* uint8 legacy_compression_method */
    psDynBufAppendByte(&shBuf, 0);

    /* Construct extensions into extBuf. */
    psDynBufInit(ssl->hsPool, &extBuf, 256);
    rc = tls13WriteServerHelloExtensions(ssl, &extBuf,
                                         isHelloRetryRequest);
    if (rc < 0)
    {
        psDynBufUninit(&shBuf);
        psDynBufUninit(&extBuf);
        return rc;
    }
    extData = psDynBufDetachPsSize(&extBuf, &extDataLen);

    /* Extension extensions<6..2^16-1> */
    psDynBufAppendTlsVector(&shBuf,
            6, (1 << 16) - 1,
            extData,
            extDataLen);
    psFree(extData, ssl->hsPool);

    /* Now have the full ServerHello in shBuf. */
    shData = psDynBufDetachPsSize(&shBuf, &shLen);

    psDynBufUninit(&extBuf);
    psDynBufUninit(&shBuf);

    /* Wrap into Handshake and TLSPlaintext. */
    rc = makeHsRecord(ssl,
            SSL_HS_SERVER_HELLO,
            shData,
            shLen,
            PS_FALSE,
            out);
    if (rc < 0)
    {
        psFree(shData, ssl->hsPool);
        return rc;
    }
    psFree(shData, ssl->hsPool);

    if (ssl->sec.tls13KsState.snapshotCHtoSHDone == 0)
    {
        /* Store Transcript-Hash(ClientHello..ServerHello). To be used
           in key derivation. */
        rc = tls13TranscriptHashSnapshot(ssl,
                ssl->sec.tls13TrHashSnapshotCHtoSH);
        if (rc < 0)
        {
            return rc;
        }
        ssl->sec.tls13KsState.snapshotCHtoSHDone = 1;
    }
    return MATRIXSSL_SUCCESS;
}

static
int32_t tls13WriteEmptyExtension(ssl_t *ssl,
        unsigned char extType[2],
        unsigned char **extOut,
        psSize_t *extOutLen)
{
    unsigned char *out;

    out = psMalloc(ssl->hsPool, 4);
    if (out == NULL)
    {
        return PS_MEM_FAIL;
    }

    out[0] = extType[0];
    out[1] = extType[1];
    out[2] = 0;
    out[3] = 0;

    *extOutLen = 4;
    *extOut = out;

    return PS_SUCCESS;
}

static int32_t tls13WriteEncryptedExtensions(ssl_t *ssl, sslBuf_t *out)
{
    int32_t rc;
    psDynBuf_t eeBuf;
    unsigned char *eeData, *sniExt;
    psSize_t eeLen, sniExtLen;
    unsigned char extTypeServerName[2] = { 0x00, 0x00 };
    unsigned char *extensionData;
    psSize_t extensionDataLen;

    /*
      struct {
          Extension extensions<0..2^16-1>;
      } EncryptedExtensions;
    */

    psTracePrintHsMessageCreate(ssl, SSL_HS_ENCRYPTED_EXTENSION);
    psDynBufInit(ssl->hsPool, &eeBuf, ENCRYPTED_EXTENSIONS_SIZE_EST);

    if (ssl->extFlags.sni_in_last_client_hello == 1)
    {
        /* ClientHello contained server_name extension, which we have
           already processed. Reply with an empty server_name extension. */
        rc = tls13WriteEmptyExtension(ssl,
                extTypeServerName,
                &sniExt,
                &sniExtLen);
        if (rc < 0)
        {
            psDynBufUninit(&eeBuf);
            return rc;
        }
        psDynBufAppendOctets(&eeBuf, sniExt, sniExtLen);
        psFree(sniExt, ssl->hsPool);
    }

    if (ssl->extFlags.got_early_data == 1 &&
        ssl->tls13ServerEarlyDataEnabled == PS_TRUE)
    {
        /* ClientHello contained early_data extension */
        rc = tls13WriteEarlyData(ssl, &eeBuf, 0);
        if (rc < 0)
        {
            psDynBufUninit(&eeBuf);
            return rc;
        }
    }

    extensionData = psDynBufDetachPsSize(&eeBuf, &extensionDataLen);
    psDynBufInit(ssl->hsPool, &eeBuf, ENCRYPTED_EXTENSIONS_SIZE_EST);
    /* Extension extensions<0..2^16-1>; */
    psDynBufAppendTlsVector(&eeBuf,
            0, (1 << 16) - 1,
            extensionData,
            extensionDataLen);
    psFree(extensionData, ssl->hsPool);
    eeData = psDynBufDetachPsSize(&eeBuf, &eeLen);

    /* Wrap into Handshake, TLSPlaintext, TLSInnerPlaintext and
       TLSCiphertext. But don't encrypt yet. */
    rc = makeHsRecord(ssl,
            SSL_HS_ENCRYPTED_EXTENSION,
            eeData,
            eeLen,
            PS_TRUE,
            out);
    if (rc < 0)
    {
        psFree(eeData, ssl->hsPool);
        return rc;
    }
    psFree(eeData, ssl->hsPool);

    return MATRIXSSL_SUCCESS;
}

static int32 tls13WriteCertificateRequest(ssl_t *ssl, sslBuf_t *out)
{
    int32 rc;
    psDynBuf_t certRequestBuf, extBuf;
    unsigned char *certRequest, *ext;
    psSize_t certRequestLen, extLen;

    psTracePrintHsMessageCreate(ssl, SSL_HS_CERTIFICATE_REQUEST);
    psDynBufInit(ssl->hsPool, &certRequestBuf, CERTIFICATE_REQUEST_SIZE_EST);

    /*
        struct {
          opaque certificate_request_context<0..2^8-1>;
          Extension extensions<2..2^16-1>;
      } CertificateRequest;
    */

    /* certificate_request_context<0..2^8-1>; */

    /* Specification: "This field SHALL be zero
       length unless used for the post-handshake authentication exchanges
       described in Section 4.6.2." */
    psDynBufAppendTlsVector(&certRequestBuf,
            0, (1 << 8) - 1,
            NULL,
            0);

    psDynBufInit(ssl->hsPool, &extBuf, CERTIFICATE_REQUEST_SIZE_EST);

    rc = tls13WriteSigAlgs(ssl,
            &extBuf,
            ssl->supportedSigAlgs,
            ssl->supportedSigAlgsLen,
            EXT_SIGNATURE_ALGORITHMS);
    if (rc < 0)
    {
        psDynBufUninit(&certRequestBuf);
        psDynBufUninit(&extBuf);
        return rc;
    }

    rc = tls13WriteSigAlgs(ssl,
            &extBuf,
            ssl->tls13SupportedSigAlgsCert,
            ssl->tls13SupportedSigAlgsCertLen,
            EXT_SIGNATURE_ALGORITHMS_CERT);
    if (rc < 0)
    {
        psDynBufUninit(&certRequestBuf);
        psDynBufUninit(&extBuf);
        return rc;
    }

#  ifdef USE_IDENTITY_CERTIFICATES
    rc = tls13WriteCertificateAuthorities(ssl,
            &extBuf);
    if (rc < 0)
    {
        psDynBufUninit(&certRequestBuf);
        psDynBufUninit(&extBuf);
        return rc;
    }
#  endif
    ext = psDynBufDetachPsSize(&extBuf, &extLen);
    if (ext == NULL)
    {
        goto out_internal_error;
    }
    psDynBufAppendTlsVector(&certRequestBuf,
            0, (1 << 16) - 1,
            ext,
            extLen);
    psFree(ext, ssl->hsPool);
    certRequest = psDynBufDetachPsSize(&certRequestBuf, &certRequestLen);
    if (certRequest == NULL)
    {
        goto out_internal_error;
    }

    /* Wrap into Handshake, TLSPlaintext, TLSInnerPlaintext and
       TLSCiphertext. But don't encrypt yet. */
    rc = makeHsRecord(ssl,
            SSL_HS_CERTIFICATE_REQUEST,
            certRequest,
            certRequestLen,
            PS_TRUE,
            out);
    if (rc < 0)
    {
        psFree(certRequest, ssl->hsPool);
        return rc;
    }

    psFree(certRequest, ssl->hsPool);

    return MATRIXSSL_SUCCESS;

out_internal_error:
    psDynBufUninit(&certRequestBuf);
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}

# endif /* USE_SERVER_SIDE_SSL */

# ifdef USE_IDENTITY_CERTIFICATES
static int32 tls13WriteCertificate(ssl_t *ssl, sslBuf_t *out)
{
    int32 rc;
    psDynBuf_t certBuf, extBuf, certListBuf;
    unsigned char *certData, *certList;
    psSize_t certDataLen, certListLen;
    psX509Cert_t *c;
    int32 i;
# ifdef USE_SSL_INFORMATIONAL_TRACE
    psSize_t k = 0;
# endif
    unsigned char *extData = NULL;
    psSizeL_t extDataLen;

    psTracePrintHsMessageCreate(ssl, SSL_HS_CERTIFICATE);
    psDynBufInit(ssl->hsPool, &certBuf, CERTIFICATE_SIZE_EST);

    /*
      struct {
                opaque cert_data<1..2^24-1>;
          };
          Extension extensions<0..2^16-1>;
      } CertificateEntry;

      struct {
          opaque certificate_request_context<0..2^8-1>;
          CertificateEntry certificate_list<0..2^24-1>;
      } Certificate;
    */

    /* certificate_request_context<0..2^8-1>; */
    psDynBufAppendTlsVector(&certBuf,
            0, (1 << 8) - 1,
            IS_SERVER(ssl) ? NULL : ssl->tls13CertRequestContext,
            IS_SERVER(ssl) ? 0 : ssl->tls13CertRequestContextLen);

    psDynBufInit(ssl->hsPool, &certListBuf, 4096);

    /* Send the cert chain and OCSP reps decided for use. We should really
       really have chosenIdentity by now, but let's be defensive */
    c = (ssl->chosenIdentity) ? ssl->chosenIdentity->cert : NULL;


    /* Note that if client's certificate does not match server's
       signature_algorithms then an empty cert must be sent.
       When the server's cert does not match client's algorithms
       then the server should still send the certificate (spec 4.4.2.2)

       Also note, that on client the code that selects client identity
       key pair should have already performed this check as part of
       the process. */
    if (!IS_SERVER(ssl))
    {
        if (c != NULL)
        {
            for (i = 0; i < ssl->sec.keySelect.peerCertSigAlgsLen; i++)
            {
#  ifdef USE_RSA
                if (c->sigAlgorithm == OID_SHA256_RSA_SIG ||
                    c->sigAlgorithm == OID_SHA384_RSA_SIG ||
                    c->sigAlgorithm == OID_SHA512_RSA_SIG)
                {
                    if (tls13IsRsaSigAlg(ssl->sec.keySelect.peerCertSigAlgs[i]))
                    {
                        break;
                    }
                }
#  endif
#  ifdef USE_ECC
                if (c->sigAlgorithm == OID_SHA256_ECDSA_SIG ||
                    c->sigAlgorithm == OID_SHA384_ECDSA_SIG ||
                    c->sigAlgorithm == OID_SHA512_ECDSA_SIG)
                {
                    if (tls13IsEcdsaSigAlg(ssl->sec.keySelect.peerCertSigAlgs[i]))
                    {
                        break;
                    }
                }
#  endif
            }
        }
        if (c == NULL || i == ssl->sec.keySelect.peerCertSigAlgsLen)
        {
            c = NULL;
            ssl->tls13SentEmptyCertificate = PS_TRUE;
            psTraceInfo("Sending empty cert because no matching signature " \
                    "algorithms\n");
        }
    }

    while (c)
    {
        psTracePrintCertSubject(INDENT_HS_MSG,
                ssl, c, k++);
        psAssert(c->unparsedBin != NULL);

        /* opaque cert_data<1..2^24-1>; */
        psDynBufAppendTlsVector(&certListBuf,
                1, (1 << 24) - 1,
                c->unparsedBin,
                c->binLen);

        extData = NULL;
        extDataLen = 0;

# ifdef USE_OCSP_RESPONSE
        /* Add the OCSP status request extension, if requested.
           Only support adding the extension for our own (server) cert. */
        if (ssl->extFlags.status_request == 1 && c == ssl->chosenIdentity->cert)
        {
            psDynBufInit(ssl->hsPool, &extBuf, 1024);
            rc = tls13WriteOCSPStatusRequest(ssl,
                    &extBuf);
            if (rc < 0)
            {
                return rc;
            }

            extData = psDynBufDetach(&extBuf, &extDataLen);
            if (extData == NULL)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                return MATRIXSSL_ERROR;
            }
        }
# endif

        /* Extension extensions<0..2^16-1>; */
        psDynBufAppendTlsVector(&certListBuf,
                0, (1 << 16) - 1,
                extData,
                extDataLen);
        if (extData != NULL)
        {
            psFree(extData, ssl->hsPool);
            psDynBufUninit(&extBuf);
        }
        c = c->next;
    }

    certList = psDynBufDetachPsSize(&certListBuf, &certListLen);
    if (certList == NULL)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return PS_MEM_FAIL;
    }

    /* CertificateEntry certificate_list<0..2^24-1>; */
    psDynBufAppendTlsVector(&certBuf,
            0, (1 << 24) - 1,
            certList,
            certListLen);
    psFree(certList, ssl->hsPool);

    certData = psDynBufDetachPsSize(&certBuf, &certDataLen);
    if (certData == NULL)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return PS_MEM_FAIL;
    }

    /* Wrap into Handshake, TLSPlaintext, TLSInnerPlaintext and
       TLSCiphertext. But don't encrypt yet. */
    rc = makeHsRecord(ssl,
            SSL_HS_CERTIFICATE,
            certData,
            certDataLen,
            PS_TRUE,
            out);
    psFree(certData, ssl->hsPool);
    return rc;
}

/* Should be good for both client and server? */
static int32 tls13WriteCertificateVerify(ssl_t *ssl, sslBuf_t *out)
{
    int32 rc;
    psDynBuf_t cvBuf;
    unsigned char *cvData;
    psSize_t cvDataLen;
    uint16_t chosenSigAlg;
    unsigned char trHash[MAX_TLS_1_3_HASH_SIZE];
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    int32_t hmacLen = psGetOutputBlockLength(hmacAlg);
    const char *contextStrServer = "TLS 1.3, server CertificateVerify";
    const char *contextStrClient = "TLS 1.3, client CertificateVerify";
    psSize_t contextStrLen = 33;
    psBool_t verifyOwnSig = PS_FALSE;

    /*
      struct {
          SignatureScheme algorithm;
          opaque signature<0..2^16-1>;
      } CertificateVerify;
    */

    psTracePrintHsMessageCreate(ssl, SSL_HS_CERTIFICATE_VERIFY);
    psDynBufInit(ssl->hsPool, &cvBuf, CERTIFICATE_VERIFY_SIZE_EST);

    chosenSigAlg = tls13ChooseSigAlg(ssl,
            ssl->sec.keySelect.peerSigAlgs,
            ssl->sec.keySelect.peerSigAlgsLen);
    if (chosenSigAlg == 0 || hmacLen < 0)
    {
        psTraceErrr("Failed to negotiate CertificateVerify sig alg\n");
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        return SSL_SEND_RESPONSE;
    }
    psTracePrintTls13SigAlg(INDENT_HS_MSG,
            "Signing CertificateVerify with",
            chosenSigAlg, PS_TRUE);
    ssl->sec.tls13CvSigAlg = chosenSigAlg;

    /* SignatureScheme algorithm; */
    psDynBufAppendAsBigEndianUint16(&cvBuf, chosenSigAlg);

    if (ssl->sec.tls13KsState.generateCvSigDone == 0)
    {
        rc = tls13TranscriptHashSnapshot(ssl, trHash);
        if (rc < 0)
        {
            return rc;
        }

# ifdef USE_ED25519
        /* The psEd25519Sign API requires the public key in addition
           to the private key. We don't have a function that would
           compute the public from the private key, so read it off
           our certificate. */

        if (ssl->chosenIdentity->privKey.type == PS_ED25519
            && !ssl->chosenIdentity->privKey.key.ed25519.havePub)
        {
            psAssert(ssl->chosenIdentity->cert);
            Memcpy(ssl->chosenIdentity->privKey.key.ed25519.pub,
                    ssl->chosenIdentity->cert->publicKey.key.ed25519.pub,
                    32);
        }
# endif

        rc = tls13Sign(ssl->hsPool,
                &ssl->chosenIdentity->privKey,
                chosenSigAlg,
                trHash, hmacLen,
                IS_SERVER(ssl) ? contextStrServer : contextStrClient,
                contextStrLen,
                &ssl->sec.tls13CvSig,
                &ssl->sec.tls13CvSigLen);
        if (rc < 0)
        {
            return rc;
        }

#ifdef DEBUG_TLS_1_3_ENCODE_DUMP
        psTraceBytes("CV sig", ssl->sec.tls13CvSig, ssl->sec.tls13CvSigLen);
#endif

#ifdef TLS_1_3_VERIFY_OWN_SIG
        verifyOwnSig = PS_TRUE;
#else
# ifdef USE_RSA
        if (tls13IsRsaSigAlg(chosenSigAlg))
        {
            /*
              RSA signatures should always be verified after they
              have been generated to protect against CRT key leaks
              (see C.3. in the draft spec.)

              When using crypto-cl, the self-verification has already
              been done within CL/SL (CL_HashSafeSign).
            */
#  ifndef USE_CL_RSA
            verifyOwnSig = PS_TRUE;
#  endif
        }
# endif
#endif

        if (verifyOwnSig)
        {
# ifdef USE_CERT_PARSE
            /* Verify the signature we just generated. */
            rc = tls13Verify(ssl->hsPool,
                    &ssl->chosenIdentity->cert->publicKey,
                    chosenSigAlg,
                    ssl->sec.tls13CvSig,
                    ssl->sec.tls13CvSigLen,
                    trHash, hmacLen,
                    IS_SERVER(ssl) ? contextStrServer : contextStrClient,
                    contextStrLen);
            if (rc < 0)
            {
                psFree(ssl->sec.tls13CvSig, ssl->hsPool);
                psFree(ssl->hsPool, tbs);
                psTraceErrr("Could not verify own sig!!\n");
                return rc;
            }
# endif
        }

        ssl->sec.tls13KsState.generateCvSigDone = 1;
    }

    /* opaque signature<0..2^16-1>; */
    psDynBufAppendTlsVector(&cvBuf,
            0, (1 << 16) - 1,
            ssl->sec.tls13CvSig,
            ssl->sec.tls13CvSigLen);

    cvData = psDynBufDetachPsSize(&cvBuf, &cvDataLen);
    if (cvData == NULL)
    {
        return PS_MEM_FAIL;
    }

    rc = makeHsRecord(ssl,
            SSL_HS_CERTIFICATE_VERIFY,
            cvData,
            cvDataLen,
            PS_TRUE,
            out);
    psFree(cvData, ssl->hsPool);
    if (rc < 0)
    {
        return rc;
    }

    return MATRIXSSL_SUCCESS;
}

# endif /* USE_IDENTITY_CERTIFICATES */

# ifdef USE_CLIENT_SIDE_SSL
static int32 tls13WriteEndOfEarlyData(ssl_t *ssl, sslBuf_t *out)
{
    int32 rc;
    psTracePrintHsMessageCreate(ssl, SSL_HS_EOED);

    /*
        struct {} EndOfEarlyData;
    */

    rc = makeHsRecord(ssl,
            SSL_HS_EOED,
            NULL,
            0,
            PS_TRUE,
            out);
    if (rc < 0)
    {
        return rc;
    }
    return PS_SUCCESS;
}
# endif

static int32 tls13WriteFinished(ssl_t *ssl, sslBuf_t *out)
{
    int32 rc;
    unsigned char trHash[MAX_TLS_1_3_HASH_SIZE];
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    int32_t hmacLen = psGetOutputBlockLength(hmacAlg);
    psHmac_t ctx;

    psTracePrintHsMessageCreate(ssl, SSL_HS_FINISHED);

    /*
      struct {
          opaque verify_data[Hash.length];
      } Finished;
    */
    rc = tls13DeriveFinishedKey(ssl, IS_SERVER(ssl));
    if (rc < 0 || hmacLen < 0)
    {
        return rc;
    }

    /*
      Handshake Context for server Finished:
        ClientHello ... later of EncryptedExtensions/CertificateRequest

      Handshake Context for client Finished:
        ClientHello ... later of server Finished/EndOfEarlyData

      Server: We have just written EE or CR and updated our Transcript-Hash.
      Only need to take a snapshot.

      Client: All the messages sent&received with server so far have been
      updated to hash.
    */
    if (ssl->sec.tls13KsState.generateVerifyDataDone == 0)
    {
        rc = tls13TranscriptHashSnapshot(ssl, trHash);
        if (rc < 0)
        {
            return rc;
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
                hmacLen,
                trHash,
                hmacLen,
                ssl->sec.tls13VerifyData);
        if (rc < 0)
        {
            return rc;
        }
        ssl->sec.tls13KsState.generateVerifyDataDone = 1;
    }

#ifdef DEBUG_TLS_1_3_ENCODE_DUMP
    psTraceBytes("verify_data", ssl->sec.tls13VerifyData, hmacLen);
#endif

    rc = makeHsRecord(ssl,
            SSL_HS_FINISHED,
            ssl->sec.tls13VerifyData,
            hmacLen,
            PS_TRUE,
            out);
    if (rc < 0)
    {
        return rc;
    }

    /* Store Transcript-Hash(ClientHello..Server Finished). To be used
       in key derivation. */
    rc = tls13TranscriptHashSnapshot(ssl, ssl->sec.tls13TrHashSnapshot);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

# ifdef USE_SERVER_SIDE_SSL
static
int32_t tls13WriteNewSessionTicket(ssl_t *ssl, sslBuf_t *out)
{
    psDynBuf_t nstBuf, extBuf;
    unsigned char *nstData, *extData = NULL;
    psSize_t nstDataLen, extDataLen = 0;
    int32 rc;
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    uint32 ticketLifetime = TLS_1_3_TICKET_LIFETIME; /* Seconds */
    uint32 ticketAgeAdd;
    unsigned char ticketNonce[4];
    unsigned char *ticket;
    psSizeL_t ticketLen, ticketNonceLen = 4;

    psTracePrintHsMessageCreate(ssl, SSL_HS_NEW_SESSION_TICKET);

    rc = psGetPrng(NULL,
            (unsigned char*)&ticketAgeAdd,
            sizeof(ticketAgeAdd), NULL);
    if (rc != 4)
    {
        goto out_internal_error;
    }
    rc = psGetPrng(NULL, ticketNonce, 4, NULL);
    if (rc != 4)
    {
        goto out_internal_error;
    }

    psDynBufInit(ssl->hsPool, &nstBuf, 128);

    /*
      struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce<0..255>;
          opaque ticket<1..2^16-1>;
          Extension extensions<0..2^16-2>;
      } NewSessionTicket;
     */

    psDynBufAppendAsBigEndianUint32(&nstBuf, ticketLifetime);
    psDynBufAppendAsBigEndianUint32(&nstBuf, ticketAgeAdd);

    rc = tls13NewTicket(ssl,
            hmacAlg,
            ticketLifetime,
            ticketAgeAdd,
            ticketNonce,
            ticketNonceLen,
            &ticket,
            &ticketLen);
    if (rc < 0)
    {
        goto out_internal_error;
    }

    /* opaque ticket_nonce<0..255>; */
    psDynBufAppendTlsVector(&nstBuf,
            0, 255,
            ticketNonce,
            ticketNonceLen);

    /* opaque ticket<1..2^16-1>; */
    psDynBufAppendTlsVector(&nstBuf,
            1, (1 << 16) - 1,
            ticket,
            ticketLen);
    psFree(ticket, ssl->hsPool);

    /* Extension extensions<0..2^16-2>; */
    if (ssl->tls13SessionMaxEarlyData > 0)
    {
        psDynBufInit(ssl->hsPool, &extBuf, 16);

        rc = tls13WriteEarlyData(ssl, &extBuf, ssl->tls13SessionMaxEarlyData);
        if (rc < 0)
        {
            return rc;
        }
        extData = psDynBufDetachPsSize(&extBuf, &extDataLen);
    }
    psDynBufAppendTlsVector(&nstBuf,
            0, (1 << 16) - 1,
            extData, extDataLen);
    psFree(extData, ssl->hsPool);

    nstData = psDynBufDetachPsSize(&nstBuf, &nstDataLen);
    if (nstData == NULL)
    {
        goto out_internal_error;
    }

    rc = makeHsRecord(ssl,
            SSL_HS_NEW_SESSION_TICKET,
            nstData,
            nstDataLen,
            PS_TRUE,
            out);
    psFree(nstData, ssl->hsPool);
    return rc;

out_internal_error:
    psTraceErrr("Finished parsing: internal error\n");
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}
# endif /* USE_SERVER_SIDE_SSL */

/* Estimate buffer size needed for the next flight we are going
   to send. */
psSizeL_t tls13EstimateNextFlightSize(ssl_t *ssl)
{
    flightEncode_t *msg;
    psSizeL_t totalLen = 0;

    /* Compute length of the flight we managed to encode so far. */
    msg = ssl->flightEncode;
    while (msg)
    {
        totalLen += msg->messageSize;
        msg = msg->next;
    }

    /* If the next message did not fit, add space needed for
       that message. Add some extra in case there there will
       more messages added. */
    if (ssl->tls13NextMsgRequiredLen > 0)
    {
        totalLen += 2 * ssl->tls13NextMsgRequiredLen;
    }

    return totalLen;
}

/** Clear our temporary handshake state, i.e. information we no longer
    need after the handshake has completed.

    The reason we maintain some state information about flight creation
    in ssl_t is that the flight creation API must be re-entrant in order
    to handle the SSL_FULL cases.
 */
static inline
void tls13ClearHsTemporaryState(ssl_t *ssl)
{
    psFree(ssl->sec.tls13CvSig, ssl->hsPool);
    Memset(&ssl->sec.tls13KsState, 0, sizeof(ssl->sec.tls13KsState));
}

# ifdef USE_SERVER_SIDE_SSL
static inline
psBool_t clientKeyShareOk(ssl_t *ssl)
{
# ifdef USE_ECC
    if (ssl->sec.eccKeyPub != NULL) return PS_TRUE;
# endif
# ifdef USE_DH
    if (ssl->sec.dhKeyPub != NULL)  return PS_TRUE;
# endif
# ifdef USE_X25519
    if (ssl->sec.x25519KeyPub != NULL) return PS_TRUE;
# endif
    return PS_FALSE;
}

static inline
psBool_t clientPskOk(ssl_t *ssl)
{
    if (ssl->sec.tls13ChosenPsk != NULL)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

static inline
psBool_t needKeyShareFromClient(ssl_t *ssl)
{
    if (ssl->sec.tls13ChosenPskMode == psk_keyex_mode_none ||
        ssl->sec.tls13ChosenPskMode == psk_keyex_mode_psk_dhe_ke)
    {
        return PS_TRUE;
    }

    return PS_FALSE;
}

static inline
psBool_t needHelloRetryRequest(ssl_t *ssl)
{
    if (needKeyShareFromClient(ssl) && !clientKeyShareOk(ssl))
    {
        return PS_TRUE;
    }

    return PS_FALSE;
}

static inline
psBool_t clientSupportsPskMode(ssl_t *ssl,
        psk_key_exchange_mode_e mode)
{
    if (mode == psk_keyex_mode_none)
    {
        return PS_TRUE;
    }

    if (ssl->sec.tls13ClientPskModes[0] == mode ||
            ssl->sec.tls13ClientPskModes[1] == mode)
    {
        return PS_TRUE;
    }

    return PS_FALSE;
}

static inline
psBool_t pskCompatibleWithCiphersuite(ssl_t *ssl)
{
    psTls13Psk_t *psk = ssl->sec.tls13ChosenPsk;
    psResSize_t hashLen = tls13GetCipherHashSize(ssl);

    if (psk == NULL)
    {
        return PS_TRUE;
    }

    if (hashLen > 0 && psk->pskLen == hashLen)
    {
        return PS_TRUE;
    }


    return PS_FALSE;
}

/*
  Select the key exchange mode to use.
  Prefer PSK when we have agreed on a PSK and a PSK mode.

  psk_keyex_mode_psk_dhe_ke : ECDHE with PSK authentication.
  psk_keyex_mode_psk_ke : PSK-only.
  psk_keyex_mode_none : ECDHE without PSK.
*/
static inline
void selectKeyExchangeMode(ssl_t *ssl)
{
    if (clientPskOk(ssl) && pskCompatibleWithCiphersuite(ssl))
    {
        if (clientSupportsPskMode(ssl, psk_keyex_mode_psk_dhe_ke))
        {
            ssl->sec.tls13ChosenPskMode = psk_keyex_mode_psk_dhe_ke;
            ssl->sec.tls13UsingPsk = PS_TRUE;
            goto out;
        }
        else if (clientSupportsPskMode(ssl, psk_keyex_mode_psk_ke))
        {
            ssl->sec.tls13ChosenPskMode = psk_keyex_mode_psk_ke;
            ssl->sec.tls13UsingPsk = PS_TRUE;
            goto out;
        }
    }

    /* Default to standard non-PSK key exchange. */
    ssl->sec.tls13ChosenPsk = NULL;
    ssl->sec.tls13ChosenPskMode = psk_keyex_mode_none;

out:
    psTracePrintPskKeyExchangeMode(INDENT_NEGOTIATED_PARAM,
            "Selected key ex mode",
            ssl->sec.tls13ChosenPskMode,
            PS_TRUE);
}

static inline
int32_t tls13EncodeResponseServer(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen)
{
    int32_t rc;

    switch (ssl->hsState)
    {
    case SSL_HS_TLS_1_3_START:
    case SSL_HS_TLS_1_3_RECVD_CH:
        selectKeyExchangeMode(ssl);
        if (needHelloRetryRequest(ssl))
        {
            psTraceInfo("No acceptable client (EC)DHE share\n");
            Memset(&ssl->sec.tls13KsState, 0, sizeof(ssl->sec.tls13KsState));
            ssl->sec.tls13UsingPsk = PS_FALSE;
            ssl->extFlags.got_pre_shared_key = 0;
            rc = tls13TranscriptHashReinit(ssl); /* See 4.4.1. */
            if (rc < 0)
            {
                return rc;
            }
            psTraceInfo("Writing HelloRetryRequest\n");
            rc = tls13WriteServerHello(ssl, out, PS_TRUE);
            if (rc < 0)
            {
                return rc;
            }
            ssl->hsState = SSL_HS_TLS_1_3_START;
            ssl->sec.tls13KsState.snapshotCHtoSHDone = 0;
            return MATRIXSSL_SUCCESS;
        }
        if (RESUMED_HANDSHAKE(ssl))
        {
            if (ssl->sec.tls13ChosenPsk != NULL)
            {
                /* Validate the params we decrypted from the ticket. */
                rc = tls13ValidateSessionParams(ssl,
                        ssl->sec.tls13ChosenPsk->params);
            }
            else
            {
                rc = MATRIXSSL_ERROR;
            }
            if (rc < 0)
            {
                return rc;
            }
            psTraceInfo("Server successfully resumed a TLS 1.3 session\n");
        }
        ssl->hsState = SSL_HS_TLS_1_3_NEGOTIATED;
        /* Fall-through. */
    case SSL_HS_TLS_1_3_NEGOTIATED:
        if (ssl->sec.tls13ChosenPsk != NULL)
        {
            /* Early data traffic secret derivation needs CH snapshot. */
            rc = tls13TranscriptHashSnapshotAlg(ssl,
                    OID_SHA256_ALG,
                    ssl->sec.tls13TrHashSnapshotCH);
            if (rc < 0)
            {
                return rc;
            }
            rc = tls13TranscriptHashSnapshotAlg(ssl,
                    OID_SHA384_ALG,
                    ssl->sec.tls13TrHashSnapshotCHSha384);
            if (rc < 0)
            {
                return rc;
            }
            rc = tls13DeriveEarlyDataSecret(ssl, ssl->sec.tls13ChosenPsk);
            if (rc < 0)
            {
                return rc;
            }
            rc = tls13DeriveEarlyDataKeys(ssl);
            if (rc < 0)
            {
                return rc;
            }
        }
        rc = tls13WriteServerHello(ssl, out, PS_FALSE);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13DeriveHandshakeTrafficSecrets(ssl);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13DeriveHandshakeKeys(ssl);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13WriteEncryptedExtensions(ssl, out);
        if (rc < 0)
        {
            return rc;
        }
        if (!ssl->sec.tls13UsingPsk)
        {
            /* 4.3.2.
               "Servers which are authenticating with a PSK MUST NOT send
               the CertificateRequest in the main handshake."
            */
#  ifdef USE_SERVER_SIDE_SSL
            if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
            {
                rc = tls13WriteCertificateRequest(ssl, out);
                if (rc < 0)
                {
                    return rc;
                }
            }
#  endif
#  ifdef USE_IDENTITY_CERTIFICATES
            rc = tls13WriteCertificate(ssl, out);
            if (rc < 0)
            {
                return rc;
            }
            rc = tls13WriteCertificateVerify(ssl, out);
            if (rc < 0)
            {
                return rc;
            }
#  endif
        }
        rc = tls13WriteFinished(ssl, out);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13DeriveAppTrafficSecrets(ssl);
        if (rc < 0)
        {
            return rc;
        }
        if (ssl->tls13ServerEarlyDataEnabled)
        {
            rc = tls13ActivateEarlyDataReadKeys(ssl);
            if (rc < 0)
            {
                return rc;
            }
            ssl->hsState = SSL_HS_TLS_1_3_WAIT_EOED;
        }
        else if (!ssl->sec.tls13UsingPsk &&
            (ssl->flags & SSL_FLAGS_CLIENT_AUTH))
        {
            ssl->hsState = SSL_HS_TLS_1_3_WAIT_CERT;
        }
        else
        {
            ssl->hsState = SSL_HS_TLS_1_3_WAIT_FINISHED;
        }
        tls13ClearHsTemporaryState(ssl);
        break;
    case SSL_HS_TLS_1_3_SEND_NST:
        rc = tls13WriteNewSessionTicket(ssl, out);
        if (rc < 0)
        {
            return rc;
        }
        tls13ClearHsState(ssl);
        ssl->hsState = SSL_HS_DONE;
        break;
    }

    return MATRIXSSL_SUCCESS;
}
# endif /* USE_SERVER_SIDE_SSL */

# ifdef USE_CLIENT_SIDE_SSL
static inline
int32 tls13EncodeResponseClient(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen)
{
    int32 rc;

    switch (ssl->hsState)
    {
    case SSL_HS_TLS_1_3_START:
        rc = tls13WriteClientHello(ssl, out, ssl->tls13ClientCipherSuites,
                ssl->tls13ClientCipherSuitesLen,
                requiredLen,
                NULL, NULL); /* Use backed-up user extensions and options. */
        if (rc < 0)
        {
            return rc;
        }
        ssl->hsState = SSL_HS_TLS_1_3_WAIT_SH;
        break;
    case SSL_HS_TLS_1_3_SEND_FINISHED:
        rc = tls13TranscriptHashSnapshot(ssl, ssl->sec.tls13TrHashSnapshot);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13DeriveAppTrafficSecrets(ssl);
        if (rc < 0)
        {
            return rc;
        }
        if (ssl->tls13ClientEarlyDataEnabled == PS_TRUE)
        {
            ssl->tls13ClientEarlyDataEnabled = PS_FALSE;
            rc = tls13WriteEndOfEarlyData(ssl, out);
            if (rc < 0)
            {
                return rc;
            }
        }
        else
        {
            rc = tls13ActivateHsWriteKeys(ssl);
            if (rc < 0)
            {
                 return rc;
            }
        }
#  ifdef USE_IDENTITY_CERTIFICATES
        /* In the client side the only way we know about peer signature
           algorithms is that we have received CertificateRequest. Respond
           to that here */
        if (ssl->tls13GotCertificateRequest)
        {
            rc = tls13WriteCertificate(ssl, out);
            if (rc < 0)
            {
                return rc;
            }
            if (!ssl->tls13SentEmptyCertificate)
            {
                rc = tls13WriteCertificateVerify(ssl, out);
                if (rc < 0)
                {
                    return rc;
                }
            }
        }
#  endif
        rc = tls13WriteFinished(ssl, out);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13TranscriptHashSnapshot(ssl, ssl->sec.tls13TrHashSnapshot);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13DeriveResumptionMasterSecret(ssl);
        if (rc < 0)
        {
            return rc;
        }
        ssl->hsState = SSL_HS_DONE;
        tls13ClearHsState(ssl);
        tls13ClearHsTemporaryState(ssl);
        break;
    }

    return MATRIXSSL_SUCCESS;

}
# endif /* USE_CLIENT_SIDE_SSL */

int32 tls13EncodeResponse(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen)
{
    switch(IS_SERVER(ssl))
    {
#ifdef USE_SERVER_SIDE_SSL
    case PS_TRUE:
        return tls13EncodeResponseServer(ssl, out, requiredLen);
#endif
#ifdef USE_CLIENT_SIDE_SSL
    case PS_FALSE:
        return tls13EncodeResponseClient(ssl, out, requiredLen);
#endif
    default:
        return PS_UNSUPPORTED_FAIL;
    }
}

void tls13ResetState(ssl_t *ssl)
{
    Memset(ssl->peerSupportedVersionsPriority,
            0, sizeof(ssl->peerSupportedVersionsPriority));
    ssl->peerSupportedVersionsPriorityLen = 0;
    ssl->tls13ServerEarlyDataEnabled = PS_FALSE;
# ifdef USE_IDENTITY_CERTIFICATES
    Memset(ssl->sec.keySelect.peerSigAlgs,
            0, sizeof(ssl->sec.keySelect.peerSigAlgs));
    ssl->sec.keySelect.peerSigAlgsLen = 0;
    Memset(ssl->sec.keySelect.peerCertSigAlgs,
            0, sizeof(ssl->sec.keySelect.peerCertSigAlgs));
    ssl->sec.keySelect.peerCertSigAlgsLen = 0;
# endif
    RESET_ACTV_VER(ssl);
    Memset(ssl->sec.seq, 0, sizeof(ssl->sec.seq));
    Memset(ssl->sec.remSeq, 0, sizeof(ssl->sec.remSeq));
}

static inline
int32_t tls13Encrypt(ssl_t *ssl,
        unsigned char *pt,
        unsigned char *ct,
        psSize_t ptLen,
        unsigned char recordType,
        psSize_t recordLen)
{
    ssl->outRecType = recordType;
    ssl->outRecLen = recordLen;

    return ssl->encrypt(ssl, pt, ct, ptLen);
}

int32_t tls13EncryptMessage(ssl_t *ssl,
        flightEncode_t *msg,
        unsigned char **end)
{
    int32_t rc;

# ifdef DEBUG_TLS_1_3_ENCODE
    switch(msg->hsMsg)
    {
    case SSL_HS_SERVER_HELLO:
        psTraceInfo("Creating record for ServerHello\n");
        break;
    case SSL_HS_CERTIFICATE:
        psTraceInfo("Creating record for Certificate\n");
        break;
    case SSL_HS_CERTIFICATE_VERIFY:
        psTraceInfo("Creating record for CertificateVerify\n");
        break;
    case SSL_HS_ENCRYPTED_EXTENSION:
        psTraceInfo("Creating record for EncryptedExtensions\n");
        break;
    case SSL_HS_CERTIFICATE_REQUEST:
        psTraceInfo("Creating record for CertificateRequest\n");
        break;
    case SSL_HS_EOED:
        psTraceInfo("Creating record for EndOfEarlyData\n");
        break;
    case SSL_HS_FINISHED:
        psTraceInfo("Creating record for Finished\n");
        break;
    }
# endif

    /* For handshake messages, we use in-situ encryption. */
    rc = tls13Encrypt(ssl,
            msg->start,
            msg->start,
            msg->len,
            SSL_RECORD_TYPE_APPLICATION_DATA,
            msg->len + TLS_GCM_TAG_LEN);
    if (rc < 0)
    {
        psTraceIntInfo("Error encrypting: %d\n", rc);
        return MATRIXSSL_ERROR;
    }

    /*
      Advance end of output buffer pointer to after the ciphertext.
*/
    *end = msg->start + rc;
    if (ENCRYPTING_RECORDS(ssl))
    {
        *end += TLS_GCM_TAG_LEN;
    }

    /* Update state machine after having successfully written and
       encrypted a message. */
    switch(msg->hsMsg)
    {
    case SSL_HS_SERVER_HELLO:
        if (ssl->hsState == SSL_HS_TLS_1_3_START)
        {
            /* This was actually a HelloRetryRequest.
               Now we need to start over and negotiate TLS 1.3 anew. */
            tls13ResetState(ssl);
            /* Return to the <1.3 code path. We must do this because:
               1) we wish to start version negotiation from scratch
               2) we have no TLS 1.3-specific ClientHello parsing function.
            */
            ssl->hsState = SSL_HS_CLIENT_HELLO;
        }
        else
        {
            rc = tls13ActivateHsWriteKeys(ssl);
            if (rc < 0)
            {
                return rc;
            }
        }
        break;
    case SSL_HS_EOED:
        rc = tls13ActivateHsWriteKeys(ssl);
        if (rc < 0)
        {
            return rc;
        }
        break;
    case SSL_HS_FINISHED:
        rc = tls13DeriveAppKeys(ssl);
        if (rc < 0)
        {
            return rc;
        }
        rc = tls13ActivateAppWriteKeys(ssl);
        if (rc < 0)
        {
            return rc;
        }
        if (IS_SERVER(ssl))
        {
            /* Set-up HS read keys for the client's Finished message if
               early data is not expected to be received */
            if (ssl->hsState != SSL_HS_TLS_1_3_WAIT_EOED)
            {
                rc = tls13ActivateHsReadKeys(ssl);
                if (rc < 0)
                {
                    return rc;
                }
            }
        }
        else
        {
            /* For the client all traffic from here on is using app keys */
            rc = tls13ActivateAppReadKeys(ssl);
            if (rc < 0)
            {
                return rc;
            }
        }
    }
    return rc;
}

static inline
psBool_t isGoodStateForAppDataEncrypt(ssl_t *ssl)
{
    if (ssl->flags & SSL_FLAGS_ERROR ||
        (ssl->hsState != SSL_HS_DONE &&
         !ssl->tls13ClientEarlyDataEnabled &&
         !ssl->tls13ServerEarlyDataEnabled) ||
        ssl->flags & SSL_FLAGS_CLOSED)
    {
        goto fail;
    }

    return PS_TRUE;

fail:
    psTraceErrr("Bad SSL state for matrixSslEncode call attempt: ");
    psTracePrintSslFlags(ssl->flags);
    psTracePrintHsState(ssl->hsState, PS_TRUE);

    return PS_FALSE;
}

/** The TLS 1.3 version of matrixSslEncode. */
int32_t tls13EncodeAppData(ssl_t *ssl,
        unsigned char *buf,
        uint32_t size,
        unsigned char *ptBuf,
        uint32_t *len)
{
    unsigned char *c, *end;
    unsigned char *encryptStart, *encryptEnd;
    psSize_t messageSize, recLen;
    int32_t rc;
    psSizeL_t padLen = ssl->tls13PadLen;

    if (!isGoodStateForAppDataEncrypt(ssl))
    {
        return MATRIXSSL_ERROR;
    }

#ifdef DEBUG_TLS_1_3_ENCODE_DUMP
    psTraceBytes("PT of app data", ptBuf, *len);
#endif

    c = buf;
    end = buf + size;
    messageSize = ssl->recordHeadLen + *len;
    if (messageSize > SSL_MAX_BUF_SIZE)
    {
        psTraceIntInfo("Message too large for matrixSslEncode: %d\n",
            messageSize);
        return PS_MEM_FAIL;
    }

    rc = tls13WriteRecordHeader(ssl,
            SSL_RECORD_TYPE_APPLICATION_DATA,
            0,
            ptBuf,
            *len,
            *len,
            &padLen,
            0,
            PS_TRUE,
            &c,
            end,
            &encryptStart, &encryptEnd);
    if (rc < 0)
    {
        if (rc == SSL_FULL)
        {
            *len = messageSize;
        }
        return rc;
    }
    c += *len;
    recLen = (encryptEnd - encryptStart) + TLS_GCM_TAG_LEN;

    rc = tls13Encrypt(ssl,
            ptBuf,
            buf + TLS_REC_HDR_LEN,
            encryptEnd - encryptStart,
            SSL_RECORD_TYPE_APPLICATION_DATA,
            recLen);
    if (rc < 0)
    {
        psTraceIntInfo("Error encrypting: %d\n", rc);
        return MATRIXSSL_ERROR;
    }

#ifdef DEBUG_TLS_1_3_ENCODE_DUMP
    psTraceBytes("CT record of app data", buf, *len + TLS_REC_HDR_LEN);
#endif

    *len = recLen + TLS_REC_HDR_LEN;
    if (ssl->tls13ClientEarlyDataEnabled == PS_TRUE)
    {
        /* This is an early data send */
        if (ssl->extFlags.got_early_data == 1)
        {
            /* We have already parsed encryptedExtensions and discovered that
               server will accept our early data. */
            ssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_ACCEPTED;
        }
        else
        {
            /* We don't yet know if server will accept the early data */
            ssl->tls13EarlyDataStatus = MATRIXSSL_EARLY_DATA_SENT;
        }
    }
    return *len;
}

/* TLS 1.3 version of writeAlert. */
int32_t tls13EncodeAlert(ssl_t *ssl,
        unsigned char type,
        sslBuf_t *out,
        uint32_t *requiredLen)
{
    unsigned char *c, *end, *encryptStart, *encryptEnd;
    psSize_t messageSize;
    int32_t rc;
    psBool_t mustEncrypt = PS_FALSE;
    unsigned char alertBody[2];
    psSizeL_t padLen = ssl->tls13PadLen;

    psTracePrintAlertEncodeInfo(ssl, type);

    c = out->end;
    end = out->buf + out->size;
    messageSize = 2 + ssl->recordHeadLen;

    if (ENCRYPTING_RECORDS(ssl))
    {
        mustEncrypt = PS_TRUE;
    }

    /*
      In TLS 1.3, the level field should be ignored by the receiver.
      All alerts except close_notify and user_canceled MUST be sent
      with level = fatal. For the two exceptions, we can choose
      either fatal or warning. Choose warning for close_notify,
      because OpenSSL seems to like that.
    */
    if (type == 0)
    {
        alertBody[0] = SSL_ALERT_LEVEL_WARNING;
    }
    else
    {
        alertBody[0] = SSL_ALERT_LEVEL_FATAL;
    }
    alertBody[1] = type;

    rc = tls13WriteRecordHeader(ssl,
            SSL_RECORD_TYPE_ALERT,
            0,
            alertBody,
            2,
            2,
            &padLen,
            0,
            mustEncrypt,
            &c,
            end,
            &encryptStart, &encryptEnd);
    if (rc < 0)
    {
        if (rc == SSL_FULL)
        {
            *requiredLen = messageSize;
        }
        return rc;
    }

    rc = tls13Encrypt(ssl,
            encryptStart,
            encryptStart,
            encryptEnd - encryptStart,
            SSL_RECORD_TYPE_ALERT,
            (encryptEnd - encryptStart) + TLS_GCM_TAG_LEN);
    if (rc < 0)
    {
        psTraceIntInfo("Error encrypting: %d\n", rc);
        return MATRIXSSL_ERROR;
    }

    out->end = c;

    return MATRIXSSL_SUCCESS;
}

# ifdef USE_CLIENT_SIDE_SSL
static int32_t tls13SetUpClientEarlyData(ssl_t *ssl)
{
    int32_t rc;
    int32 hmacAlg;

    hmacAlg = tls13GetPskHmacAlg(ssl->sec.tls13SessionPskList);
    if (hmacAlg == HMAC_SHA256)
    {
        rc = tls13TranscriptHashSnapshotAlg(ssl,
                OID_SHA256_ALG,
                ssl->sec.tls13TrHashSnapshotCH);
        if (rc < 0)
        {
            return rc;
        }
    }
    else
    {
        rc = tls13TranscriptHashSnapshotAlg(ssl,
                 OID_SHA384_ALG,
                 ssl->sec.tls13TrHashSnapshotCHSha384);
        if (rc < 0)
        {
            return rc;
        }
    }
    /* Since client would like to use early_data set-up the
       ciphers and keys for it. The cipher suite is the one that
       is supplied in the session parameters together with the
       PSK.
       Early_data is always set-up with the first PSK */

    if (ssl->sec.tls13SessionPskList->params->cipherId == 0)
    {
        psTraceInfo("Cannot enable early_data because cipherId is " \
                    "not specified in psTls13SessionParams_t\n");
        return PS_ARG_FAIL;
    }
    ssl->cipher = sslGetCipherSpec(ssl,
                               ssl->sec.tls13SessionPskList->params->cipherId);
    rc = tls13DeriveEarlyDataSecret(ssl, ssl->sec.tls13SessionPskList);
    if (rc < 0)
    {
        return rc;
    }
    rc = tls13DeriveEarlyDataKeys(ssl);
    if (rc < 0)
    {
        return rc;
    }
    rc = tls13ActivateEarlyDataWriteKeys(ssl);
    if (rc < 0)
    {
        return rc;
    }
    return MATRIXSSL_SUCCESS;
}

int32 tls13WriteClientHello(ssl_t *ssl, sslBuf_t *out,
        const psCipher16_t cipherSpecs[],
        uint8_t cipherSpecsLen,
        uint32 *requiredLen,
        tlsExtension_t *userExt,
        sslSessOpts_t *options)
{
    int32 rc;
    psDynBuf_t extBuf;
    psDynBuf_t chBuf;
    unsigned char *data;
    psSize_t dataLen;
    uint8_t compressionMethod = 0;
    uint8_t i;
    psDynBuf_t ciphersBuf;
    psSize_t cipherSuitesLen;
    unsigned char *cipherSuites;
    psSize_t messageSize;
    sslInitHSHash(ssl);

    psTracePrintHsMessageCreate(ssl, SSL_HS_CLIENT_HELLO);
    psDynBufInit(ssl->hsPool, &chBuf, CLIENT_HELLO_SIZE_EST);

    /* If this is our initial ClientHello, backup user extensions
       for future HRR responses and TLS <1.3 renegotiations. */
    if (!ssl->tls13IncorrectDheKeyShare)
    {
        psAddUserExtToSession(ssl, userExt);
    }

    /* ProtocolVersion legacy_version == 0x0303 */
    psDynBufAppendByte(&chBuf, TLS_MAJ_VER);
    psDynBufAppendByte(&chBuf, TLS_1_2_MIN_VER);
    ssl->ourHelloVersion = v_tls_1_2;

    if (ssl->sec.tls13KsState.generateRandomDone == 0)
    {
        /* Random random (32 bytes) */
        rc = psGetPrngLocked(ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE, ssl->userPtr);
        if (rc < 0)
        {
            psDynBufUninit(&chBuf);
            return rc;
        }
        ssl->sec.tls13KsState.generateRandomDone = 1;
    }
    psDynBufAppendOctets(&chBuf, ssl->sec.clientRandom, 32);
# ifdef DEBUG_TLS_1_3_ENCODE_DUMP
    psTraceBytes("client_random", ssl->sec.clientRandom, 32);
# endif

    /* opaque legacy_session_id_echo<0..32> */
    psDynBufAppendTlsVector(&chBuf, 0, 32,
            ssl->sessionId, ssl->sessionIdLen);

    /* Cipher suites */
    if (cipherSpecsLen == 0 || cipherSpecs == NULL || cipherSpecs[0] == 0)
    {
        rc = getDefaultCipherSuites(ssl, ssl->hsPool,
                                    &cipherSuites, &cipherSuitesLen);
        if (rc < 0)
        {
            psTraceErrr("Error in getting default cipher suites\n");
            psDynBufUninit(&chBuf);
            return MATRIXSSL_ERROR;
        }
        psTracePrintEncodedCipherList(INDENT_HS_MSG,
                "cipher_suites",
                cipherSuites + 2, /* Skip length encoding. */
                cipherSuitesLen - 2,
                PS_FALSE);
        psDynBufAppendOctets(&chBuf, cipherSuites, cipherSuitesLen);
        psFree(cipherSuites, ssl->hsPool);
    }
    else
    {
        /* Only use those cipher suites that were provided */
        psDynBufInit(ssl->hsPool, &ciphersBuf, 32);
        ssl->tls13ClientCipherSuitesLen = 0;
        ssl->tls13ClientCipherSuites = psMalloc(ssl->hsPool,
                cipherSpecsLen * sizeof(*ssl->tls13ClientCipherSuites));
        if (ssl->tls13ClientCipherSuites == NULL)
        {
            psTraceErrr("Out of mem in tls13WriteClientHello\n");
            goto out_internal_error;
        }
        for (i = 0; i < cipherSpecsLen; i++)
        {
            psDynBufAppendAsBigEndianUint16(&ciphersBuf, cipherSpecs[i]);

            /* Save the supplied cipher suite set. It is needed in case
             * ClientHello needs to be resent because of HelloRetryRequest */
            ssl->tls13ClientCipherSuites[i] = cipherSpecs[i];
            ssl->tls13ClientCipherSuitesLen++;
        }
        psTracePrintCipherList(INDENT_HS_MSG,
                "cipher_suites",
                ssl->tls13ClientCipherSuites,
                ssl->tls13ClientCipherSuitesLen,
                PS_FALSE);
        data = psDynBufDetachPsSize(&ciphersBuf, &dataLen);
        /* CipherSuite cipher_suites<2..2^16-2>; */
        psDynBufAppendTlsVector(&chBuf,
                2, (1 << 16) - 2,
                data,
                dataLen);
        psFree(data, ssl->hsPool);
    }
    /* uint8 legacy_compression_method */
    psDynBufAppendTlsVector(&chBuf, 1, (1 << 8) - 2, &compressionMethod, 1);

    /* Construct extensions into extBuf. */
    psDynBufInit(ssl->hsPool, &extBuf, 256);
    rc = tls13WriteClientHelloExtensions(ssl, &extBuf, userExt, options);
    if (rc < 0)
    {
        psDynBufUninit(&extBuf);
        psDynBufUninit(&chBuf);
        return rc;
    }
    data = psDynBufDetachPsSize(&extBuf, &dataLen);
    /* Extension extensions<6..2^16-1> */
    psDynBufAppendTlsVector(&chBuf,
            6, (1 << 16) - 1,
            data,
            dataLen);
    psFree(data, ssl->hsPool);

    /* Now have the full ClientHello in chBuf. */
    data = psDynBufDetachPsSize(&chBuf, &dataLen);

    messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + dataLen;
    if (messageSize > SSL_MAX_BUF_SIZE)
    {
        psTraceIntInfo("ClientHello message too large: %d\n",
            messageSize);
        psFree(data, ssl->hsPool);
        return PS_MEM_FAIL;
    }

    /* Wrap into Handshake and TLSPlaintext. */
    rc = makeHsRecord(ssl,
            SSL_HS_CLIENT_HELLO,
            data,
            dataLen,
            PS_FALSE,
            out);
    if (rc < 0)
    {
        if (rc == SSL_FULL)
        {
            *requiredLen = messageSize;
        }
        psFree(data, ssl->hsPool);
        return rc;
    }
    psFree(data, ssl->hsPool);

    /* Remove ClientHello from flight list since it will
       not be sent through encodeResponse mechanism like the
       other handshake messages */
    clearFlightList(ssl);

    /* Set-up early_data if possible */
    if (ssl->tls13ClientEarlyDataEnabled == PS_TRUE)
    {
        /* PSK is available with early_data possibility */
        rc = tls13SetUpClientEarlyData(ssl);
        if (rc < 0)
        {
            return rc;
        }
    }
    else
    {
        ssl->tls13ClientEarlyDataEnabled = PS_FALSE;
    }

    ssl->hsState = SSL_HS_TLS_1_3_WAIT_SH;
    return MATRIXSSL_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}

# endif /* USE_CLIENT_SIDE_SSL */
#endif /* USE_TLS_1_3 */
