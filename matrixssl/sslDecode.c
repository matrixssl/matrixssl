/**
 *      @file    sslDecode.c
 *      @version $Format:%h%d$
 *
 *      Secure Sockets Layer protocol message decoding portion of MatrixSSL.
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

#include "matrixsslImpl.h"

/******************************************************************************/

# define LUCKY13

#define SSL_MAX_IGNORED_MESSAGE_COUNT   1024

static int32 parseSSLHandshake(ssl_t *ssl, char *inbuf, uint32 len);

#ifdef USE_CERT_CHAIN_PARSING
static int32 parseSingleCert(ssl_t *ssl, unsigned char *c, unsigned char *end,
                             int32 certLen);
#endif /* USE_CERT_CHAIN_PARSING */

#ifdef LUCKY13
static int32 addCompressCount(ssl_t *ssl, int32 padLen);
#endif

#ifdef USE_ZLIB_COMPRESSION
/* Does not need to be a large value because we're only inflating the 16
    byte FINISHED message.  In fact, compression will grow 16 bytes but
    this is a good reminder that FUTURE support will need to account for
    likely data growth here */
# define MATRIX_INFLATE_FINISHED_OH  128
#endif

/******************************************************************************/
/*
    Parse incoming data per http://wp.netscape.com/eng/ssl3

    Input parameters to decode:
    .   buf points to the start of data to decode
    .   len points to the length in bytes of data to decode
    .   size is the number of allocated bytes that follow buf



    Meaningful parameters after the call to decode:
    MATRIXSSL_SUCCESS
    .   buf will point to the first undecoded byte (could==inbuf or inbuf+inlen)
    .   remaining will indicate how many more bytes of undecoded data remain
 *      call again if more to decode or return if handshake is complete

    SSL_PARTIAL
    .   buf will not have moved (because partials start parse over)
    .   reqLen will indicate how many bytes the entire full record is
 *      get more data from peer and call again

    SSL_FULL (implies decode completed fully but couldn't fit response)
    .   buf will not have moved (it is reset to the front of final record)
    .   len will be 0 to indicate no remaining unprocessed data
    .   reqLen will inform how large buf should be grown before re-invoking
 *      realloc the buf to the reqLen size and call again

    SSL_SEND_RESPONSE
    .   buf will point to the encoded handshake data to send
    .   len will be length of data to send (from start offset)
 *      pass the buf to the transport layer for sending to peer

    SSL_ALERT
    .   buf will point to start of received alert (2 bytes alert level and desc)
    .   len will be length of alert data (should be 2)
    .   alertLevel will be 1 (warning) or 2 (fatal)
    .   alertDesc will be SSL specified alert code

    MATRIXSSL_ERROR (unrecoverable failure)
    .   decodeErr is internal parse err code

    SSL_PROCESS_DATA (ONLY CASE WITH DECRYPTED DATA AND POSSIBLE UNENCRYPTED)
    .   unencrypted user data ready for processing is at prevBuf
    .   buf points to start of any remaining unencrypted data
    .   remaining is length of remaining encrypted data yet to decode
    .   len is length of unencrypted data ready for user processing
 *      pass unencypted data to application level
 *      call decode again if more encrypted data remaining

 */
int32 matrixSslDecode(ssl_t *ssl, unsigned char **buf, uint32 *len,
    uint32 size, uint32 *remaining, uint32 *requiredLen,
    int32 *error, unsigned char *alertLevel,
    unsigned char *alertDescription)
{
    unsigned char *c, *p, *end, *pend, *ctStart, *origbuf;
    unsigned char *mac;
    unsigned char macError;
    int32 rc;
    unsigned char padLen;

# ifdef USE_CLIENT_SIDE_SSL
    sslSessOpts_t options;
# endif
    psBuf_t tmpout;
#ifdef USE_CERT_CHAIN_PARSING
    int32 certlen, i, nextCertLen;
#endif /* USE_CERT_CHAIN_PARSING */
#ifdef USE_ZLIB_COMPRESSION
    int32 preInflateLen, postInflateLen, currLen;
    int zret;
#endif
/*
    If we've had a protocol error, don't allow further use of the session
 */
    *error = PS_SUCCESS;
    if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED)
    {
        psTraceInfo("Can't use matrixSslDecode on closed/error-flagged sess\n");
        *error = PS_PROTOCOL_FAIL;
        return MATRIXSSL_ERROR;
    }

    origbuf = *buf; /* Save the original buffer location */

    p = pend = mac = ctStart = NULL;
    padLen = 0;

#ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
    if (ssl->extClientCertKeyStateFlags ==
            EXT_CLIENT_CERT_KEY_STATE_GOT_CERT_KEY_UPDATE)
    {
        /* Client program has loaded new client cert and keys based on
           the server's CertificateRequest message. We have already parsed
           the server's last flight entirely. Now skip directly to writing
           the response. Reset extClientCertKey state. */
        ssl->extClientCertKeyStateFlags = EXT_CLIENT_CERT_KEY_STATE_INIT;
        goto encodeResponse;
    }
#endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
    if (ssl->hwflags & SSL_HWFLAGS_PENDING_PKA_W ||
        ssl->hwflags & SSL_HWFLAGS_PENDING_FLIGHT_W)
    {
        goto encodeResponse;
    }
# endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

/*
    This flag is set if the previous call to this routine returned an SSL_FULL
    error from encodeResponse, indicating that there is data to be encoded,
    but the out buffer was not big enough to handle it.  If we fall in this
    case, the user has increased the out buffer size and is re-calling this
    routine
 */
    if (ssl->flags & SSL_FLAGS_NEED_ENCODE)
    {
        ssl->flags &= ~SSL_FLAGS_NEED_ENCODE;
        goto encodeResponse;
    }
    *requiredLen = 0;
    c = *buf; /* c is record parse pointer */
    end = *buf + *len;

/*
    Processing the SSL Record header.
    If the high bit of the first byte is set and this is the first
    message we've seen, we parse the request as an SSLv2 request
    @see http://wp.netscape.com/eng/security/SSL_2.html
    SSLv2 also supports a 3 byte header when padding is used, but this should
    not be required for the initial plaintext message, so we don't support it.

    @security SSLV2 ClientHello is deprecated and no longer supported.

    v2 Header:
        2 bytes length (ignore high bit)
    v3 Header:
        1 byte type
        1 byte major version
        1 byte minor version
        2 bytes length
 */
#ifdef USE_DTLS
decodeMore:
#endif
    if (end - c == 0)
    {
/*
        This case could happen if change cipher spec was last
        message in the buffer or if there is a zero-length record
        at the end of a multi-record application data buffer.
 */
        return MATRIXSSL_SUCCESS;
    }
    /* Even for SSLv2, we want at least 5 bytes in the record to continue */
    if (end - c < SSL3_HEADER_LEN)
    {
        *requiredLen = SSL3_HEADER_LEN;
        return SSL_PARTIAL;
    }
#ifdef USE_CERT_CHAIN_PARSING
/*
    If we're in process of parsing a partial record, then skip the
    usual record header parse.  Currently we're only supporting
    partial parsing for the certificate messages since they are the
    largest in size.
 */
    if (ssl->rec.partial != 0x0)
    {
        psAssert(ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE);
        psAssert(ssl->hsState == SSL_HS_CERTIFICATE);
/*
        Get this next record length based on the certificate size,
        which will always be the first three bytes of a partial here
 */
        ssl->rec.len = c[0] << 16;
        ssl->rec.len |= c[1] << 8;
        ssl->rec.len |= c[2];
        ssl->rec.len += 3;
        goto SKIP_RECORD_PARSE;
    }
#endif /* USE_CERT_CHAIN_PARSING */

    if (ssl->majVer != 0 || (*c & 0x80) == 0)
    {
        if (end - c < ssl->recordHeadLen)
        {
            *requiredLen = ssl->recordHeadLen;
            return SSL_PARTIAL;
        }
        ssl->rec.type = *c; c++;
        ssl->rec.majVer = *c; c++;
        ssl->rec.minVer = *c; c++;
#ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            if (ssl->rec.majVer == DTLS_MAJ_VER &&
                ssl->rec.minVer >= DTLS_1_2_MIN_VER)
            {
                ssl->rec.epoch[0] = *c++;
                ssl->rec.epoch[1] = *c++;
                ssl->rec.rsn[0] = *c++;
                ssl->rec.rsn[1] = *c++;
                ssl->rec.rsn[2] = *c++;
                ssl->rec.rsn[3] = *c++;
                ssl->rec.rsn[4] = *c++;
                ssl->rec.rsn[5] = *c++;
            }
            else
            {
                psTraceIntDtls("Expecting DTLS record version. Got %d\n",
                    ssl->rec.majVer);
                *error = PS_PROTOCOL_FAIL;
                return MATRIXSSL_ERROR;
            }
        }
        else   /* Note: The else branch (not DTLS) is below,
                  in code outside USE_DTLS */
#endif /* USE_DTLS */
#ifndef USE_SSL_PROTOCOL_VERSIONS_OTHER_THAN_3
        {
            /* RFC 5246 Suggests to accept all RSA minor versions,
               but only major version 0x03 (SSLv3, TLS 1.0,
               TLS 1.1, TLS 1.2, TLS 1.3 etc) */
            if (ssl->rec.majVer != 0x03)
            {
                /* Consider invalid major version protocol
                   version error. */
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                psTraceInfo(
                    "Won't support client's SSL major version\n");
                return MATRIXSSL_ERROR;
            }
        }
#else
        { } /* No check for rec.MajVer. */
#endif /* USE_SSL_PROTOCOL_VERSIONS_OTHER_THAN_3 */

        ssl->rec.len = *c << 8; c++;
        ssl->rec.len += *c; c++;
    }
    else
    {
#if defined(USE_INTERCEPTOR) || defined(ALLOW_SSLV2_CLIENT_HELLO_PARSE)
        ssl->rec.type = SSL_RECORD_TYPE_HANDSHAKE;
        ssl->rec.majVer = 2;
        ssl->rec.minVer = 0;
        ssl->rec.len = (*c & 0x7f) << 8; c++;
        ssl->rec.len += *c; c++;
#else
        /* OpenSSL 0.9.8 will send a SSLv2 CLIENT_HELLO.  Use the -no_ssl2
            option when running a 0.9.8 client to prevent this */
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceInfo("SSLv2 records not supported\n");
        goto encodeResponse;
#endif
    }
/*
    Validate the various record headers.  The type must be valid,
    the major and minor versions must match the negotiated versions (if we're
    past ClientHello) and the length must be < 16K and > 0
 */
    switch (ssl->rec.type)
    {
    case SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC:
    case SSL_RECORD_TYPE_ALERT:
    case SSL_RECORD_TYPE_HANDSHAKE:
    case SSL_RECORD_TYPE_APPLICATION_DATA:
        break;
    /* Any other case is unrecognized */
    default:
        ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
        psTraceIntInfo("Record header type not valid: %d\n", ssl->rec.type);
        goto encodeResponse;
    }

/*
    Verify the record version numbers unless this is the first record we're
    reading.
 */
    if (ssl->hsState != SSL_HS_SERVER_HELLO &&
        ssl->hsState != SSL_HS_CLIENT_HELLO)
    {
        if (ssl->rec.majVer != ssl->majVer || ssl->rec.minVer != ssl->minVer)
        {
#ifdef SSL_REHANDSHAKES_ENABLED
            /* If in DONE state and this version doesn't match the previously
                negotiated one that can be OK because a CLIENT_HELLO for a
                rehandshake might be acting like a first time send and using
                a lower version to get to the parsing phase.  Unsupported
                versions will be weeded out at CLIENT_HELLO parse time */
            if (ssl->hsState != SSL_HS_DONE ||
                ssl->rec.type != SSL_RECORD_TYPE_HANDSHAKE)
            {
                ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                psTraceInfo("Record header version not valid\n");
                goto encodeResponse;
            }
#else
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            psTraceInfo("Record header version not valid\n");
            goto encodeResponse;
#endif
        }
    }
/*
    Verify max and min record lengths
 */
    if (ssl->rec.len > SSL_MAX_RECORD_LEN || ssl->rec.len == 0)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceIntInfo("Record header length not valid: %d\n", ssl->rec.len);
        goto encodeResponse;
    }
/*
    This implementation requires the entire SSL record to be in the 'in' buffer
    before we parse it.  This is because we need to MAC the entire record before
    allowing it to be used by the caller.
 */
#ifdef USE_CERT_CHAIN_PARSING
SKIP_RECORD_PARSE:
    if ((end - c < ssl->rec.len) || ssl->rec.partial)
    {
/*
        This feature will only work if the CERTIFICATE message is sent in a
        different record from the SERVER_HELLO message.
 */
        if (ssl->hsState != SSL_HS_CERTIFICATE)
        {
            ssl->rec.partial = 0x0;
            *requiredLen = ssl->rec.len + ssl->recordHeadLen;
            return SSL_PARTIAL;
        }
/*
        Not supporting cert stream parsing for re-handshake.  This is
        important because the block cipher assumes a single pass is a record
        and will use explicit IV each pass
 */
        if (ssl->flags & SSL_FLAGS_READ_SECURE)
        {
            ssl->rec.partial = 0x0;
            *requiredLen = ssl->rec.len + ssl->recordHeadLen;
            return SSL_PARTIAL;
        }
/*
        Manipulate the rec.len for partial handling
 */
        i = 0;
        if (ssl->rec.partial == 0x0)
        {
/*
            Initialization for partial parse counters
 */
            ssl->rec.hsBytesHashed = 0;
            ssl->rec.hsBytesParsed = 0;
            ssl->rec.partial = 0x1;
            ssl->rec.trueLen = ssl->rec.len + ssl->recordHeadLen;
            ssl->rec.len = 0;
/*
            Best to identify and isolate full certificate boundaries
            ASAP to keep parsing logic as high level as possible.

            Current state of record buffer: pointer at start of HS record
            which begins with 4 bytes of hsType(1) and hsLen(3).  After
            the header are 3 bytes of certchainlen and 3 bytes of first
            cert len.  Make sure we have at least one full cert here before
            allowing the partial parse.
 */
            if (end - c < (ssl->hshakeHeadLen + 6))   /* 3*2 cert chain len */
            {
                ssl->rec.partial = 0x0;               /* Unusable.  Reset */
                *requiredLen = ssl->hshakeHeadLen + 6;
                return SSL_PARTIAL;
            }
            ssl->rec.len += (ssl->hshakeHeadLen + 3);
            i = ssl->hshakeHeadLen;
            certlen = c[i] << 16; i++;
            certlen |= c[i] << 8; i++;
            certlen |= c[i]; i++;
/*
            This feature only works if the CERTIFICATE message is the only
            message in the record.  Test this by seeing that trueLen doesn't
            claim there is more to follow
 */
            if (ssl->rec.trueLen != (certlen + 3 + ssl->hshakeHeadLen +
                                     ssl->recordHeadLen))
            {
                ssl->rec.partial = 0x0; /* Unusable.  Reset */
                *requiredLen = ssl->rec.trueLen;
                return SSL_PARTIAL;
            }
            /* First cert length */
            ssl->rec.len += 3;
            certlen = c[i] << 16; i++;
            certlen |= c[i] << 8; i++;
            certlen |= c[i];
            ssl->rec.len += certlen;
        }

        /* One complete cert?  */
        if (end - c < ssl->rec.len)
        {
/*
            If there isn't a full cert in the first partial, we reset and
            handle as the standard SSL_PARTIAL case.
 */
            if (ssl->rec.hsBytesParsed == 0)
            {
                ssl->rec.partial = 0x0; /* Unusable.  Reset */
                *requiredLen = ssl->rec.len + ssl->recordHeadLen;
            }
            else
            {
                /* Record header has already been parsed */
                *requiredLen = ssl->rec.len;
            }
            return SSL_PARTIAL; /* Standard partial case */
        }

        /* More than one complete cert?  */
        while (end - c > ssl->rec.len)
        {
            if (ssl->rec.len + ssl->rec.hsBytesParsed == ssl->rec.trueLen)
            {
/*
                Don't try to read another cert if the total of already parsed
                record and the length of the current record match the 'trueLen'.
                If they are equal, we know we are on the final cert and don't
                need to look for more
 */
                break;
            }
            psAssert(ssl->rec.len + ssl->rec.hsBytesParsed <= ssl->rec.trueLen);
            nextCertLen = c[ssl->rec.len] << 16;
            nextCertLen |= c[ssl->rec.len + 1] << 8;
            nextCertLen |= c[ssl->rec.len + 2];
            if (end - c > (ssl->rec.len + nextCertLen + 3))
            {
                ssl->rec.len += (nextCertLen + 3);
            }
            else
            {
                break;
            }
        }
    }
#else
    if (end - c < ssl->rec.len)
    {
# ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            psTraceInfo("DTLS error: Received PARTIAL record from peer.\n");
            psTraceInfo("This indicates a PMTU mismatch\n");
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            goto encodeResponse;
        }
# endif /* USE_DTLS */
        *requiredLen = ssl->rec.len + ssl->recordHeadLen;
        return SSL_PARTIAL;

    }
#endif

#ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {

        /* Epoch and RSN validation. Silently ignore most mismatches (SUCCESS) */
        rc = dtlsCompareEpoch(ssl->rec.epoch, ssl->expectedEpoch);
        /* These cases have become pretty complex due to a code change in which
            the epoch is always incremented when CCS is sent.  We used to
            reset the FINISHED epoch back to +1 of the current epoch when
            resending the FINISHED flight but a customer had a problem with this
            because they thought every single message must be unique for epoch
            and sequence number.  They were probably correct but now it's a
            real mess trying to keep the expectedEpoch up-to-date when we can't
            possibly know how many epoch increments the peer has made before we
            receive a FINISHED message or an APPLICATION DATA record */
        if (rc == 1 && ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE &&
            ssl->hsState == SSL_HS_FINISHED)
        {
            /* Special handlers for these CCS/Finished cases because epoch
                could be larger for a good reason */

            /* This is the case where we are getting a finished without having
                seen a CCS.  Preumably they will be trying again since this is
                an indication that they are aware they are the senders */
            if (ssl->parsedCCS ==  0)
            {
                c += ssl->rec.len;
                *buf = c;
                return MATRIXSSL_SUCCESS;
            }

            /* This is the case where we didn't receive a combo CCS/FINISHED
                flight from the peer and they have resent with a larger epoch
                for the resent FINISHED message (so as not to send a epoch/seqNo
                duplicate on this resend). Make the expected epoch the new one
                to reset the test for any future rehandshakes */
            ssl->expectedEpoch[0] = ssl->rec.epoch[0];
            ssl->expectedEpoch[1] = ssl->rec.epoch[1];
        }
        else if (rc != 0)
        {
            psTraceIntDtls("Epoch mismatch %d ", ssl->rec.epoch[1]);
            psTraceIntDtls("on a record type of %d\n", ssl->rec.type);

            /* Another corner case where the peer has sent repeat FINISHED
                messages when we are in the state where we are finished.
                Need to keep the expectedEpoch up-to-date then because when
                the peer finally gets around to sending application data it
                will be sending it on the last epoch it sent for the final
                FINISHED. */
            if (rc == 1 && ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE &&
                ssl->hsState == SSL_HS_DONE)
            {
                ssl->expectedEpoch[0] = ssl->rec.epoch[0];
                ssl->expectedEpoch[1] = ssl->rec.epoch[1];
            }

            /* Yet another corner case where we are receiving application data
                that has an epoch larger than we were expecting.  This could
                happen if the peer has been sending "duplicate" FINISHED
                messages in which we have already parsed an earlier one and we
                are     in the done state.  If we didn't receive those duplicate
                FINISHED messages and are now getting an APPLICATION record,
                let's just try to decrypt it and get this communication going */
            if (rc == 1 && ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA &&
                ssl->hsState == SSL_HS_DONE)
            {
                ssl->expectedEpoch[0] = ssl->rec.epoch[0];
                ssl->expectedEpoch[1] = ssl->rec.epoch[1];
                goto ADVANCE_TO_APP_DATA;
            }

            /* Now just skip the record as a duplicate */

            c += ssl->rec.len;
            *buf = c;
            /* If this is a ChangeCipherSpec message from the peer
               and we have never received encypted application data this is
               probably the 'endgame' problem in which the peer never received
               our final handshake flight.  Trigger a resend in this specific
               case */
            if ((ssl->rec.type == SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC) &&
                (ssl->appDataExch == 0))
            {
                /* Need to make sure we mark the rest of this buffer as read.
                   The CCS message can be passed in here with the FINISHED tacked
                   on.  OpenSSL sends them separately but most wouldn't */
                if (end != c)
                {
                    psAssert(*c == SSL_RECORD_TYPE_HANDSHAKE); /* Finished */
                    c += 11;                                   /* Skip type, version, epoch to get to length */
                    /* borrow rc since we will be leaving here anyway */
                    rc = *c << 8; c++;
                    rc += *c; c++;
                    c += rc; /* Skip FINISHED message we've already accepted */
                    *buf = c;
                }
                return DTLS_RETRANSMIT;
            }
            if (end - c > 0)
            {
                goto decodeMore;
            }

            /* Next, check if this is a record on a session that the server
               has      already closed. Server timed out this client completely and then
               the client decides to send a new encoded client hello or app data
               on an epoch      that it thinks is fine.  If we are getting an epoch
               greater than ours and we don't even have a state for this client,
               an error should  be returned so the ssl session can be deleted */
            if (rc == 1 && ssl->flags & SSL_FLAGS_SERVER &&
                ssl->hsState == SSL_HS_CLIENT_HELLO)
            {
                *buf = origbuf;
                ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
                psTraceDtls("Client sending record on closed session\n");
                goto encodeResponse;
            }

            /* If getting epoch that is less than expected, we'll resend */
            if (rc == -1)
            {
                return DTLS_RETRANSMIT;
            }
            /* Got FINISHED message without ever getting a change cipher spec */
            return MATRIXSSL_SUCCESS;
        }

        if (dtlsChkReplayWindow(ssl, ssl->rec.rsn) != 1)
        {
            psTraceIntDtls("Seen this record before %d\n", ssl->rec.rsn[5]);
            c += ssl->rec.len;
            *buf = c;
            if (end - c > 0)
            {
                goto decodeMore;
            }
            return MATRIXSSL_SUCCESS;
        }
    }
ADVANCE_TO_APP_DATA:
#endif /* USE_DTLS */

#ifdef USE_MATRIXSSL_STATS
    if (ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA)
    {
        matrixsslUpdateStat(ssl, APP_DATA_RECV_STAT, ssl->rec.len +
            ssl->recordHeadLen);
    }
#endif

/*
    Decrypt the entire record contents.  The record length should be
    a multiple of block size, or decrypt will return an error
    If we're still handshaking and sending plaintext, the decryption
    callback will point to a null provider that passes the data unchanged
 */

    ctStart = origbuf; /* Clear-text start.  Decrypt to the front */

    /* Sanity check ct len.  Step 1 of Lucky 13 MEE-TLS-CBC decryption.
        max{b, t + 1} is always "t + 1" because largest possible blocksize
        is 16 and smallest possible tag len is 16. Multiple of block size test
        is done in decrypt. We return the identical error as if the mac failed,
        since this is a sanity check for pad and mac verification. */
    if ((ssl->flags & SSL_FLAGS_READ_SECURE) && (ssl->deBlockSize > 1) &&
        !(ssl->flags & SSL_FLAGS_AEAD_R))
    {
#ifdef USE_TLS_1_1
        if (ssl->flags & SSL_FLAGS_TLS_1_1)
        {
            if (ssl->rec.len < (ssl->deMacSize + 1 + ssl->deBlockSize))
            {
                ssl->err = SSL_ALERT_BAD_RECORD_MAC;
                psTraceInfo("Ciphertext length failed sanity\n");
                goto encodeResponse;
            }
        }
        else
        {
            if (ssl->rec.len < (ssl->deMacSize + 1))
            {
                ssl->err = SSL_ALERT_BAD_RECORD_MAC;
                psTraceInfo("Ciphertext length failed sanity\n");
                goto encodeResponse;
            }
        }
#else
        if (ssl->rec.len < (ssl->deMacSize + 1))
        {
            ssl->err = SSL_ALERT_BAD_RECORD_MAC;
            psTraceInfo("Ciphertext length failed sanity\n");
            goto encodeResponse;
        }
#endif  /* USE_TLS_1_1 */
    }

    /* CT to PT */
    if (ssl->decrypt(ssl, c, ctStart, ssl->rec.len) < 0)
    {
        ssl->err = SSL_ALERT_DECRYPT_ERROR;
        psTraceInfo("Couldn't decrypt record data 2\n");
        goto encodeResponse;
    }

    c += ssl->rec.len;

    if (ssl->flags & SSL_FLAGS_AEAD_R)
    {
        /* AEAD needs a bit of manual length manipulation for buffer mgmnt */
        ssl->rec.len -= AEAD_TAG_LEN(ssl);
        if (ssl->flags & SSL_FLAGS_NONCE_R)
        {
            ssl->rec.len -= TLS_EXPLICIT_NONCE_LEN;
        }
    }
/*
    If we're reading a secure message, we need to validate the MAC and
    padding (if using a block cipher).  Insecure messages do not have
    a trailing MAC or any padding.

    SECURITY - There are several vulnerabilities in block cipher padding
    that we handle in the below code.  For more information see:
    http://www.openssl.org/~bodo/tls-cbc.txt
 */
    if (ssl->flags & SSL_FLAGS_READ_SECURE && !(ssl->flags & SSL_FLAGS_AEAD_R))
    {
/*
        Start tracking MAC errors, rather then immediately catching them to
        stop timing and alert description attacks that differentiate between
        a padding error and a MAC error.
 */
        macError = 0;
/*
        Decode padding only if blocksize is > 0 (we're using a block cipher),
        otherwise no padding will be present, and the mac is the last
        macSize bytes of the record.
 */
        if (ssl->deBlockSize <= 1)
        {
            mac = ctStart + ssl->rec.len - ssl->deMacSize;
        }
        else
        {
/*
            The goal from here through completion of ssl->verifyMac call is a
            constant processing time for a given record length.  Going to
            follow the suggestions of the Lucky 13 research paper section
            "Careful implementation of MEE-TLS-CBC decryption".
            http://www.isg.rhul.ac.uk/tls/TLStiming.pdf

            Consistent timing is still a "goal" here.  This implementation
            accounts for the largest timing discrepencies but is not a
            strict "clock cycles" equalizer.  The complexity of the attack
            circumstances and plaintext recovery possibilities using these
            techniques is almost entirely in the academic realm. Improvements
            to this code will be an ongoing process as research uncovers
            more practical plaintext recovery threats.

            Verify the pad data for block ciphers
            c points within the cipher text, p points within the plaintext
            The last byte of the record is the pad length
 */
            p = ctStart + ssl->rec.len;
            padLen = *(p - 1);
/*
            SSL3.0 requires the pad length to be less than blockSize
            TLS can have a pad length up to 255 for obfuscating the data len
 */
            if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER &&
                padLen >= ssl->deBlockSize)
            {
                macError = 1;
            }
/*
            The minimum record length is the size of the mac, plus pad bytes
            plus one length byte, plus explicit IV if TLS 1.1 or above
 */
            if (ssl->flags & SSL_FLAGS_TLS_1_1)
            {
                if (ssl->rec.len < ssl->deMacSize + padLen + 1 + ssl->deBlockSize)
                {
                    macError = 2;
                }
            }
            else
            {
                if (ssl->rec.len < ssl->deMacSize + padLen + 1)
                {
                    macError = 3;
                }
            }
            if (macError)
            {
                /* Step 3 of Lucky 13 MEE-TLS-CBC decryption: Run a loop as
                    if there were 256 bytes of padding, with a dummy check
                    in each iteration*/
                for (rc = 255; rc >= 0; rc--)
                {
                    /* make the test a moving target so it doesn't get
                        optimized out at compile. The loop is written
                        this way so the macError assignment will be done
                        only once */
                    if ((unsigned char) rc == padLen)
                    {
                        macError = 1;   /* No incr to avoid any wraps */
                    }
                }
            }
#ifdef USE_TLS
/*
            TLS specifies that all pad bytes must have the same value
            as the final pad length byte.  Some SSL3 implementations also
            do this by convention, but some just fill with random bytes.
            (We're just overloading the 'mac' ptr here, this has nothing to
            do with real MAC.)
 */
            if (!macError && ssl->majVer == TLS_MAJ_VER &&
                ssl->minVer >= TLS_MIN_VER)
            {
                for (mac = p - padLen - 1; mac < p; mac++)
                {
                    if (*mac != padLen)
                    {
                        macError = 1;
                    }
                }
                /* Lucky 13 step 4. If this fails, then run a loop as if there
                    were 256 - padlen - 1 bytes of padding, with a dummy
                    check in each iteration */
                if (macError)
                {
                    for (rc = 256 - padLen - 1; rc > 0; rc--)
                    {
                        /* make the test a moving target so it doesn't get
                            optimized out at compile.  Again, make it so
                            the loop condition doesn't get hit more than
                            once. */
                        if ((unsigned char) rc == padLen)
                        {
                            macError = 2; /* change value for smart compilers */
                        }
                    }
                }
            }
#endif      /* USE_TLS */
/*
            The mac starts macSize bytes before the padding and length byte.
            If we have a macError, just fake the mac as the last macSize bytes
            of the record, so we are sure to have enough bytes to verify
            against, we'll fail anyway, so the actual contents don't matter.
 */
            if (!macError)
            {
                /* No padding errors */
                mac = p - padLen - 1 - ssl->deMacSize;
                /* Lucky 13 step 5: Otherwise (the padding is now correctly
                    formatted) run a loop as if there were 256 - padlen - 1
                    bytes of padding, doing a dummy check in each iteration */
                for (rc = (256 - padLen) - 1; rc > 0; rc--)
                {
                    /* make this test look like the others */
                    if ((unsigned char) rc == padLen)
                    {
                        /* coverity[assigned_value] */
                        macError = 1; /* not really an error.  reset below */
                    }
                }
                (void) macError; /* Suppress static analysis warnings */
                macError = 0;
            }
            else
            {
                /* Lucky 13 step 3 and 4 condition:  Then let P' denote the ﬁrst
                    plen - t bytes of P, compute a MAC on SQN||HDR||P' and do a
                    constant-time comparison of the computed MAC with the
                    last t bytes of P. Return fatal error. */
                mac = origbuf + ssl->rec.len - ssl->deMacSize;
            }
        }
/*
        Verify the MAC of the message by calculating our own MAC of the message
        and comparing it to the one in the message.  We do this step regardless
        of whether or not we've already set macError to stop timing attacks.
        Clear the mac in the callers buffer if we're successful
 */
#ifdef USE_TLS_1_1
        if ((ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->deBlockSize > 1))
        {
            ctStart += ssl->deBlockSize; /* skip explicit IV */
        }
#endif

#ifdef LUCKY13
        /*
            Lucky 13 Step 5. If using a block cipher, blind the mac operation.
            Doing this extra MAC compression here rather
            than inside the real verify to keep this code patch at the
            protocol level.
            The Sha Update calls are with an exact state size for the
            hash, so the compress function will be called 1:1 with the Update.
         */
        if (ssl->deBlockSize > 1)
        {
            /* Run this helper regardless of error status thus far */
            rc = addCompressCount(ssl, padLen);
            if (macError == 0)
            {
                psDigestContext_t md;
                unsigned char tmp[128];
                switch (ssl->deMacSize)
                {
#  ifdef USE_SHA256
                case SHA256_HASH_SIZE:
                    psSha256PreInit(&md.sha256);
                    psSha256Init(&md.sha256);
                    while (rc > 0)
                    {
                        psSha256Update(&md.sha256, tmp, 64);
                        rc--;
                    }
                    psSha256Final(&md.sha256, tmp);
                    break;
#  endif
#  ifdef USE_SHA384
                case SHA384_HASH_SIZE:
                    psSha384PreInit(&md.sha384);
                    psSha384Init(&md.sha384);
                    while (rc > 0)
                    {
                        psSha384Update(&md.sha384, tmp, 128);
                        rc--;
                    }
                    psSha384Final(&md.sha384, tmp);
                    break;
#  endif
#  ifdef USE_SHA1
                case SHA1_HASH_SIZE:
                    psSha1PreInit(&md.sha1);
                    psSha1Init(&md.sha1);
                    while (rc > 0)
                    {
                        psSha1Update(&md.sha1, tmp, 64);
                        rc--;
                    }
                    psSha1Final(&md.sha1, tmp);
                    break;
#  endif
                default:
                    psAssert(0);
                    break;
                }
            }
        }
#endif  /* LUCKY13 */

        if (ssl->verifyMac(ssl, ssl->rec.type, ctStart,
                (uint32) (mac - ctStart), mac) < 0 || macError)
        {
            ssl->err = SSL_ALERT_BAD_RECORD_MAC;
            psTraceInfo("Couldn't verify MAC or pad of record data\n");
            goto encodeResponse;
        }

        memset(mac, 0x0, ssl->deMacSize);

        /* Record data starts at ctStart and ends at mac */
        p = ctStart;
        pend = mac;
    }
    else
    {
/*
        The record data is the entire record as there is no MAC or padding
 */
        p = ctStart;
        pend = mac = ctStart + ssl->rec.len;
    }

#ifdef USE_ZLIB_COMPRESSION
    /* Currently only supporting compression of FINISHED message.
        Compressed application data is handled outside MatrixSSL.
        Re-handshakes are not allowed with compression and we've
        incremented ssl->compression if we've already been through here
        so we'll know */
    if (ssl->compression == 2 && ssl->flags & SSL_FLAGS_READ_SECURE &&
        ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        psTraceInfo("Re-handshakes not supported on compressed sessions\n");
        goto encodeResponse;
    }
    if (ssl->compression && ssl->flags & SSL_FLAGS_READ_SECURE &&
        ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE)
    {
        /* TODO - handle the cases below where the buffer has to grow */
        currLen = ssl->inflate.total_out;
        preInflateLen = (int32) (pend - p);
        ssl->zlibBuffer = psMalloc(ssl->bufferPool, preInflateLen +
            MATRIX_INFLATE_FINISHED_OH);
        if (ssl->zlibBuffer == NULL)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            psTraceInfo("Couldn't allocate compressed scratch pad\n");
            goto encodeResponse;
        }
        memset(ssl->zlibBuffer, 0, preInflateLen + MATRIX_INFLATE_FINISHED_OH);
        if (preInflateLen > 0)   /* zero length record possible */
        {   /* psTraceBytes("pre inflate", ctStart, preInflateLen); */
            ssl->inflate.next_in = ctStart;
            ssl->inflate.avail_in = preInflateLen;
            ssl->inflate.next_out = ssl->zlibBuffer;
            ssl->inflate.avail_out = SSL_MAX_PLAINTEXT_LEN;
            if ((zret = inflate(&ssl->inflate, Z_SYNC_FLUSH)) != Z_OK)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
                inflateEnd(&ssl->inflate);
                psTraceIntInfo("ZLIB inflate failed %d\n", zret);
                goto encodeResponse;
            }
            if (ssl->inflate.avail_in != 0)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
                inflateEnd(&ssl->inflate);
                psTraceInfo("ZLIB inflate didn't work in one pass\n");
                goto encodeResponse;
            }
            postInflateLen = ssl->inflate.total_out - currLen;

            /* psTraceBytes("post inflate", ssl->zlibBuffer,
                postInflateLen); */

            if (postInflateLen <= preInflateLen)
            {
                /* Easy case where compressed data was actually larger.
                    Don't need to update c or inlen because the next
                    good data is already correctly being pointed to */
                memcpy(p, ssl->zlibBuffer, postInflateLen);
                mac = p + postInflateLen;
                pend = mac;
            }
            else
            {
                /* Data expanded.  Fit it in the buffer and update all
                    the associated lengths and pointers

                    Add back in the MAC and pad to preInflate so we're
                    looking at the useful boundaries of the buffers */
                preInflateLen += (int32) (c - mac);
                /* reusing currLen var.  Now the difference in lengths */
                currLen = postInflateLen - preInflateLen;
                if ((int32) (c - ssl->inbuf) == ssl->inlen)
                {
                    /* Good, this was the only data in the buffer.  Just
                        check there is room to append */
                    if ((ssl->insize - ssl->inlen) >= postInflateLen)
                    {
                        memcpy(p, ssl->zlibBuffer, postInflateLen);
                        c += currLen;
                        mac = p + postInflateLen;
                        pend = mac;
                    }
                    else
                    {
                        /* Only one here but not enough room to store it */
                        ssl->err = SSL_ALERT_INTERNAL_ERROR;
                        psFree(ssl->zlibBuffer, ssl->bufferPool);
                        ssl->zlibBuffer = NULL;
                        inflateEnd(&ssl->inflate);
                        psTraceInfo("ZLIB buffer management needed\n");
                        goto encodeResponse;
                    }
                }
                else
                {
                    /* Push any existing data further back in the buffer to
                        make room for this uncompressed length.  c pointing
                        to start of next record that needs to be pushed
                        back. currLen is how far to push back.
                        p pointing to where zlibBuffer should copy
                        to.  postInflateLen is amount to copy there. */
                    if (currLen < (ssl->insize - ssl->inlen))
                    {
                        /* Good, fits in current buffer.  Move all valid
                            data back currLen */
                        memmove(c + currLen, c,
                            ssl->inlen - (int32) (c - ssl->inbuf));
                        c += currLen;
                        memcpy(p, ssl->zlibBuffer, postInflateLen);
                        mac = p + postInflateLen;
                        pend = mac;
                    }
                    else
                    {
                        /* Need to realloc more space AND push the records
                            back */
                        ssl->err = SSL_ALERT_INTERNAL_ERROR;
                        psFree(ssl->zlibBuffer, ssl->bufferPool);
                        ssl->zlibBuffer = NULL;
                        inflateEnd(&ssl->inflate);
                        psTraceInfo("ZLIB buffer management needed\n");
                        goto encodeResponse;
                    }
                }
                /* Finally increase inlen and *len to account for it now */
                ssl->inlen += currLen;
                *len += currLen;
                ssl->rec.len += currLen;
            }
        }
        psFree(ssl->zlibBuffer, ssl->bufferPool); ssl->zlibBuffer = NULL;
        /* Will not need the context any longer since FINISHED is the only
            supported message */
        inflateEnd(&ssl->inflate);
        ssl->compression = 2;
    }
#endif /* USE_ZLIB_COMPRESSION */

    /* Check now for maximum plaintext length of 16kb. */
    if (ssl->maxPtFrag == 0xFF)   /* Still negotiating size */
    {
        if ((int32) (pend - p) > SSL_MAX_PLAINTEXT_LEN)
        {
            ssl->err = SSL_ALERT_RECORD_OVERFLOW;
            psTraceInfo("Record overflow\n");
            goto encodeResponse;
        }
    }
    else
    {
        if ((int32) (pend - p) > ssl->maxPtFrag)
        {
            ssl->err = SSL_ALERT_RECORD_OVERFLOW;
            psTraceInfo("Record overflow\n");
            goto encodeResponse;
        }
    }

/*
    Take action based on the actual record type we're dealing with
    'p' points to the start of the data, and 'pend' points to the end
 */
    switch (ssl->rec.type)
    {
    case SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC:
        psTraceStrHs(">>> %s parsing CHANGE_CIPHER_SPEC message\n",
            (ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");
/*
        Body is single byte with value 1 to indicate that the next message
        will be encrypted using the negotiated cipher suite
 */
        if (pend - p < 1)
        {
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            psTraceInfo("Invalid length for CipherSpec\n");
            goto encodeResponse;
        }
        if (*p == 1)
        {
            p++;
        }
        else
        {
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            psTraceInfo("Invalid value for CipherSpec\n");
            goto encodeResponse;
        }

#ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            if (ssl->hsState != SSL_HS_FINISHED)
            {
                /* Possible to get the changeCipherSpec message out of order */
                psTraceIntInfo("Got out of order CCS: state %d\n", ssl->hsState);
                *buf = c;
                goto decodeMore;
            }
            /* The epoch corner cases surrounding the CHANGE_CIPHER_SPEC
                message are complex.  Let's just finally create a clear signal
                that the CCS was parsed.  The general problem is that our
                state machine is FINISHED when expecting either the CCS or
                the FINISHED message (probably goes back to CCS having some
                special record type in the specs).  This will just be set
                between CCS parse and FINISHED parse */
            ssl->parsedCCS = 1;
            /*
              Expect epoch to increment after successful CCS parse
            */
            incrTwoByte(ssl, ssl->expectedEpoch, 0);
        }
#endif  /* USE_DTLS */

/*
        If we're expecting finished, then this is the right place to get
        this record.  It is really part of the handshake but it has its
        own record type.
        Activate the read cipher callbacks, so we will decrypt incoming
        data from now on.
 */
        if (ssl->hsState == SSL_HS_FINISHED)
        {
            if (sslActivateReadCipher(ssl) < 0)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                goto encodeResponse;
            }
        }
        else
        {
#ifdef USE_STATELESS_SESSION_TICKETS
            /* RFC 5077 allows the server to not acknowlege whether or not it
                accepted our session ticket in the SERVER_HELLO extension so
                there was no place prior to recieving this CCS to find out.
                Different cipher suites types will be in different states */
            if (ssl->hsState == SSL_HS_CERTIFICATE && ssl->sid &&
                ssl->sid->sessionTicketState == SESS_TICKET_STATE_IN_LIMBO)
            {
                /* Do all the things that should have been done earlier */
                ssl->flags |= SSL_FLAGS_RESUMED;
# ifdef USE_MATRIXSSL_STATS
                matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
# endif
                if (sslCreateKeys(ssl) < 0)
                {
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    goto encodeResponse;
                }
                ssl->hsState = SSL_HS_FINISHED;
                if (sslActivateReadCipher(ssl) < 0)
                {
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    goto encodeResponse;
                }
                ssl->sid->sessionTicketState = SESS_TICKET_STATE_INIT;
# ifdef USE_ANON_DH_CIPHER_SUITE
                /* Anon DH could be in SERVER_KEY_EXCHANGE state */
            }
            else if ((ssl->flags & SSL_FLAGS_ANON_CIPHER) &&
                     (ssl->hsState == SSL_HS_SERVER_KEY_EXCHANGE) && ssl->sid &&
                     ssl->sid->sessionTicketState == SESS_TICKET_STATE_IN_LIMBO)
            {
                /* Do all the things that should have been done earlier */
                ssl->flags |= SSL_FLAGS_RESUMED;
#  ifdef USE_MATRIXSSL_STATS
                matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#  endif
                if (sslCreateKeys(ssl) < 0)
                {
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    goto encodeResponse;
                }
                ssl->hsState = SSL_HS_FINISHED;
                if (sslActivateReadCipher(ssl) < 0)
                {
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    goto encodeResponse;
                }
                ssl->sid->sessionTicketState = SESS_TICKET_STATE_INIT;
# endif         /* USE_ANON_DH_CIPHER_SUITE */
# ifdef USE_PSK_CIPHER_SUITE
                /* PSK could be in SERVER_KEY_EXCHANGE state */
            }
            else if ((ssl->flags & SSL_FLAGS_PSK_CIPHER) &&
                     (ssl->hsState == SSL_HS_SERVER_KEY_EXCHANGE) && ssl->sid &&
                     ssl->sid->sessionTicketState == SESS_TICKET_STATE_IN_LIMBO)
            {
                /* Do all the things that should have been done earlier */
                ssl->flags |= SSL_FLAGS_RESUMED;
#  ifdef USE_MATRIXSSL_STATS
                matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#  endif
                if (sslCreateKeys(ssl) < 0)
                {
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    goto encodeResponse;
                }
                ssl->hsState = SSL_HS_FINISHED;
                if (sslActivateReadCipher(ssl) < 0)
                {
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    goto encodeResponse;
                }
                ssl->sid->sessionTicketState = SESS_TICKET_STATE_INIT;
# endif         /* USE_PSK_CIPHER_SUITE */
            }
            else
            {
                ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
                psTraceIntInfo("Invalid CipherSpec order: %d\n", ssl->hsState);
                goto encodeResponse;
            }
#else
            ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
            psTraceIntInfo("Invalid CipherSpec order: %d\n", ssl->hsState);
            goto encodeResponse;
#endif
        }
        ssl->decState = SSL_HS_CCC;
        *remaining = *len - (c - origbuf);
        *buf = c;
        return MATRIXSSL_SUCCESS;

    case SSL_RECORD_TYPE_ALERT:
/*
        Decoded an alert
        1 byte alert level (warning or fatal)
        1 byte alert description corresponding to SSL_ALERT_*
 */
        if (pend - p < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Error in length of alert record\n");
            goto encodeResponse;
        }
        *alertLevel = *p; p++;
        *alertDescription = *p; p++;
        *len =  2;
#ifdef USE_SSL_HANDSHAKE_MSG_TRACE
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            psTraceHs(">>> Server");
        }
        else
        {
            psTraceHs(">>> Client");
        }
        if (*alertDescription == SSL_ALERT_CLOSE_NOTIFY)
        {
            psTraceHs(" parsing ALERT (CLOSE_NOTIFY) message\n");
        }
        else
        {
            psTraceHs(" parsing ALERT message\n");
        }
#endif
        psTraceIntInfo("Received alert %d\n", (int32) (*alertDescription));
/*
        If the alert is fatal, or is a close message (usually a warning),
        flag the session with ERROR so it cannot be used anymore.
        Caller can decide whether or not to close on other warnings.
 */
        if (*alertLevel == SSL_ALERT_LEVEL_FATAL)
        {
            ssl->flags |= SSL_FLAGS_ERROR;
        }
        if (*alertDescription == SSL_ALERT_CLOSE_NOTIFY)
        {
            ssl->flags |= SSL_FLAGS_CLOSED;
        }
        *buf = c;
        ssl->decState = SSL_HS_ALERT;
        return SSL_ALERT;

    case SSL_RECORD_TYPE_HANDSHAKE:
/*
        We've got one or more handshake messages in the record data.
        The handshake parsing function will take care of all messages
        and return an error if there is any problem.
        If there is a response to be sent (either a return handshake
        or an error alert, send it).  If the message was parsed, but no
        response is needed, loop up and try to parse another message
 */
#ifdef USE_CERT_CHAIN_PARSING
        if (ssl->rec.partial)
        {
            if (ssl->rec.hsBytesParsed == 0)
            {
/*
                Account for the SSL record header for first pass
 */
                ssl->rec.hsBytesParsed = ssl->recordHeadLen;
            }
        }
#endif
        rc = parseSSLHandshake(ssl, (char *) p, (uint32) (pend - p));
        /* If the entire fragment is present, the parse has occured */
        if (ssl->fragMessage != NULL)
        {
            if (ssl->fragIndex == ssl->fragTotal)
            {
                psFree(ssl->fragMessage, ssl->hsPool);
                ssl->fragMessage = NULL;
                ssl->fragIndex = ssl->fragTotal = 0;
            }
        }
        switch (rc)
        {
        case MATRIXSSL_SUCCESS:
            *remaining = *len - (c - origbuf);
            *buf = c;
            return MATRIXSSL_SUCCESS;
#ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
        case PS_PENDING:
            if (matrixSslNeedClientCert(ssl))
            {
                /*
                  Do not create the response flight just yet. Instead,
                  return to the client application to give it a chance
                  to load a new client cert and key if desired.
                */
                psTraceInfo("matrixSslDecode returning PS_PENDING\n");
                return PS_PENDING;
            }
#endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
#ifdef USE_DTLS
        case DTLS_RETRANSMIT:
            /* The idea here is to only return retransmit if
               we are seeing the final message in the inbuf as repeat.  Otherwise
               the next msg right in this flight might be able to move our state
               forward without a resend. */
            *remaining = *len - (c - origbuf);
            *buf = c;
            if (*remaining == 0)
            {
                return DTLS_RETRANSMIT;
            }
            else
            {
                return MATRIXSSL_SUCCESS;
            }
#endif      /* USE_DTLS */

        case SSL_PROCESS_DATA:
            /*
                We're here when we've processed an SSL header that requires
                a response. In all cases (except FALSE START), we would not
                expect to have any data remaining in the incoming buffer, since
                the peer would be waiting for our response.
             */
#ifdef ENABLE_FALSE_START
            if (c < origbuf + *len)
            {
                /*
                    If there's still incoming data in the buffer, it could be
                    FALSE START app data immediately after the FINISHED message,
                    and before we've had a chance to encode and send our
                    CHANGE_CIPHER_SPEC and FINISHED message. We hack around
                    some values to support this case.
                    http://tools.ietf.org/html/draft-bmoeller-tls-falsestart-00
                 */
                if (*c == SSL_RECORD_TYPE_APPLICATION_DATA &&
                    ssl->hsState == SSL_HS_DONE &&
                    (ssl->flags & SSL_FLAGS_SERVER))
                {
                    psTraceHs(">>> Server buffering FALSE START APPLICATION_DATA\n");
                    ssl->flags |= SSL_FLAGS_FALSE_START;
                    *remaining = *len - (c - origbuf);
                    *buf = c;
                }
                else
                {
                    /*
                        Implies successful parse of supposed last message in
                        flight so check for the corner cases and reset the
                        buffer to start to write response
                     */
#endif
            if (*c == SSL_RECORD_TYPE_APPLICATION_DATA &&
                ssl->hsState == SSL_HS_DONE &&
                (ssl->flags & SSL_FLAGS_SERVER))
            {
                /* If this asserts, try defining ENABLE_FALSE_START */
                psAssert(origbuf + *len == c);
                *buf = origbuf;
            }
            else if (*c == SSL_RECORD_TYPE_APPLICATION_DATA &&
                     ssl->hsState == SSL_HS_HELLO_REQUEST &&
                     (c < (origbuf + *len)))
            {
                /* message tacked on to end of HELLO_REQUEST. Very
                    complicated scenario for the state machine and
                    API so we're going to ignore the HELLO_REQUEST
                    (fine by the specification) and give precedence to
                    the app data. This backup flag data was set aside
                    in sslResetContext when     the HELLO_REQUEST was
                    received */
                *buf = c;
#ifdef USE_CLIENT_SIDE_SSL
                ssl->sec.anon = ssl->anonBk;
                ssl->flags = ssl->flagsBk;
                ssl->bFlags = ssl->bFlagsBk;
#endif
                ssl->hsState = SSL_HS_DONE;
                return MATRIXSSL_SUCCESS;
            }
            else
            {
                /* If this asserts, please report the values of the
                 * c byte and ssl->hsState to support */
                psAssert(origbuf + *len == c);
                *buf = origbuf;
            }
#ifdef ENABLE_FALSE_START
        }
    }
    else
    {
        *buf = origbuf;
    }
#endif
            goto encodeResponse;

        case MATRIXSSL_ERROR:
        case SSL_MEM_ERROR:
            if (ssl->err == SSL_ALERT_NONE)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
            }
            goto encodeResponse;
        default:
            psTraceIntInfo("Unknown return %d from parseSSLHandshake!\n", rc);
            if (ssl->err == SSL_ALERT_NONE)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
            }
            goto encodeResponse;
        }
        break;

    case SSL_RECORD_TYPE_APPLICATION_DATA:
/*
        Data is in the out buffer, let user handle it
        Don't allow application data until handshake is complete, and we are
        secure.  It is ok to let application data through on the client
        if we are in the SERVER_HELLO state because this could mean that
        the client has sent a CLIENT_HELLO message for a rehandshake
        and is awaiting reply.
 */
        if ((ssl->hsState != SSL_HS_DONE && ssl->hsState != SSL_HS_SERVER_HELLO)
            || !(ssl->flags & SSL_FLAGS_READ_SECURE))
        {
            ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
            psTraceIntInfo("Incomplete handshake: %d\n", ssl->hsState);
            goto encodeResponse;
        }
/*
        Insitu for application data is more tricky than it is for SSL handshake
        messages.  This is because there is never going to be any 'out' data
        for handshake messages until the final record of a flight is parsed.
        Whereas application data necessarily has an 'out' for every 'in'
        record because it is the decrypted data of the 'in'.  So, the managed
        cases result anytime there is more than 1 app record in the 'in' buffer
        where the insitu must hold BOTH a decrypted buffer and the next
        encrypted record.

        Create so that:
        .       buf points to start of any remaining unencrypted data
        .       start is length of remaining encrypted data yet to decode
        .       len is length of unencrypted data ready for user processing

 */
        *buf = c;
        *remaining = *len - (c - origbuf);
        *len = mac - origbuf;
/*
        SECURITY - If the mac is at the current out->end, then there is no data
        in the record.  These records are valid, but are usually not sent by
        the application layer protocol.  Rather, they are initiated within the
        remote SSL protocol implementation to avoid some types of attacks when
        using block ciphers.  For more information see:
        http://www.openssl.org/~bodo/tls-cbc.txt

        SECURITY - Returning blank messages has the potential
        for denial of service, because we are not changing the state of the
        system in any way when processing these messages, (although the upper
        level protocol may). To counteract this, we maintain a counter
        that we share with other types of ignored messages. If too many in a
        row occur, an alert will be sent and the connection closed.
        We implement this as a leaky bucket, so if a non-blank message comes
        in, the ignored message count is decremented, ensuring that we only
        error on a large number of consecutive blanks.
 */
        if (ctStart == mac)
        {
            if (ssl->ignoredMessageCount++ >= SSL_MAX_IGNORED_MESSAGE_COUNT)
            {
                ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
                psTraceIntInfo("Exceeded limit on ignored messages: %d\n",
                    SSL_MAX_IGNORED_MESSAGE_COUNT);
                goto encodeResponse;
            }
        }
        else if (ssl->ignoredMessageCount > 0)
        {
            ssl->ignoredMessageCount--;
        }
#ifdef USE_MATRIXSSL_STATS
        matrixsslUpdateStat(ssl, STAT_PT_DATA_RECV, *len);
#endif
        ssl->decState = SSL_HS_DONE;
        return SSL_PROCESS_DATA;

    default:
        /* Falls to error below */
        break;
    }
/*
    Should not get here under normal operation
 */
    psTraceIntInfo("Invalid record type in matrixSslDecode: %d\n",
        ssl->rec.type);
    *error = PS_PROTOCOL_FAIL;
    return MATRIXSSL_ERROR;

encodeResponse:
/*
    We decoded a record that needs a response, either a handshake response
    or an alert if we've detected an error.
 */
# ifdef ENABLE_FALSE_START
    if ((ssl->flags & SSL_FLAGS_FALSE_START) && *buf != origbuf)
    {
        /*
            Encode the output into ssl->outbuf in this case, rather than back
            into origbuf, since there is still valid data in origbuf that
            needs to be decoded later.
            Other places in this function we do not reference the ssl inbuf
            or outbuf directly, but this was the cleanest way for this hack.
            Caller must test to see if *buf has been modified if
            ssl->flags & SSL_FLAGS_FALSE_START
         */
        tmpout.buf = tmpout.start = tmpout.end = ssl->outbuf + ssl->outlen;
        tmpout.size = ssl->outsize - ssl->outlen;
        memset(origbuf, 0x0, (*buf - origbuf)); /* SECURITY (see below) */
    }
    else
    {
# endif
    psAssert(origbuf == *buf);
    tmpout.buf = tmpout.end = tmpout.start = origbuf;
    tmpout.size = size;

# if defined(USE_HARDWARE_CRYPTO_RECORD) || defined(USE_HARDWARE_CRYPTO_PKA) || defined(USE_EXT_CERTIFICATE_VERIFY_SIGNING)
    if (!(ssl->hwflags & SSL_HWFLAGS_PENDING_PKA_W) &&
        !(ssl->hwflags & SSL_HWFLAGS_PENDING_FLIGHT_W))
    {
        /* If we are coming back through on a pending, this data is GOLD */
        memset(tmpout.buf, 0x0, tmpout.size);
    }
# else
/*
        SECURITY - Clear the decoded incoming record from outbuf before encoding
        the response into outbuf.
 */
    memset(tmpout.buf, 0x0, tmpout.size);
# endif

# ifdef ENABLE_FALSE_START
}
# endif

# ifdef USE_CLIENT_SIDE_SSL
    if (ssl->hsState == SSL_HS_HELLO_REQUEST)
    {
        memset(&options, 0x0, sizeof(sslSessOpts_t));
/*
        Don't clear the session info.  If receiving a HELLO_REQUEST from a
        MatrixSSL enabled server the determination on whether to reuse the
        session is made on that side, so always send the current session
 */
        rc = matrixSslEncodeClientHello(ssl, &tmpout, 0, 0, requiredLen, NULL,
            &options);
    }
    else
    {
# endif /* USE_CLIENT_SIDE_SSL */
    rc = sslEncodeResponse(ssl, &tmpout, requiredLen);
# ifdef USE_CLIENT_SIDE_SSL
}
# endif /* USE_CLIENT_SIDE_SSL */
    *alertDescription = SSL_ALERT_NONE;
    if (rc == MATRIXSSL_SUCCESS)
    {
        if (ssl->err != SSL_ALERT_NONE)
        {
            /* We know this is always a fatal alert due to an error in
                message parsing or creation so flag this session as error */
            ssl->flags |= SSL_FLAGS_ERROR;
/*
            If tmpbuf has data, it is an alert that needs to be sent so let
            it fall through. Not sure how we would ever not have data in tmpout
 */
            if (tmpout.buf == tmpout.end)
            {
                psTraceInfo("Unexpected data\n");
                *error = PS_PROTOCOL_FAIL;
                return MATRIXSSL_ERROR;
            }
            *alertDescription = (unsigned char) ssl->err;
            *alertLevel = SSL_ALERT_LEVEL_FATAL;
        }
# ifdef ENABLE_FALSE_START
        if ((ssl->flags & SSL_FLAGS_FALSE_START) && *buf != origbuf)
        {
            /* Update outlen with the data we added */
            ssl->outlen += tmpout.end - tmpout.buf;
        }
        else
        {
# endif
        *remaining = 0;
        *len = tmpout.end - tmpout.buf;
# ifdef ENABLE_FALSE_START
    }
# endif
        return SSL_SEND_RESPONSE;
    }
    if (rc == SSL_FULL)
    {
# ifdef ENABLE_FALSE_START
        /* We don't support growing outbuf in the false start case */
        if (*buf != origbuf)
        {
            psAssert(rc != SSL_FULL);
            *error = rc;
            return MATRIXSSL_ERROR;
        }
# endif
        ssl->flags |= SSL_FLAGS_NEED_ENCODE;
        *len = 0; /* No data left to decode */
        /* requiredLen is set by sslEncode Response or ClientHello above */
        return SSL_FULL;
    }
    psAssert(rc < 0);
    *error = rc;
    return MATRIXSSL_ERROR;
}

#ifdef LUCKY13
/* Return the number of additional MAC compressions that are needed to blind
    the padding/hmac logic for thwarting Lucky 13 style attacks
 */
static int32 addCompressCount(ssl_t *ssl, int32 padLen)
{
    int32 l1, l2, c1, c2, len;

    c1 = c2 = 0;
    len = ssl->rec.len;

# ifdef USE_TLS_1_1
    if (ssl->flags & SSL_FLAGS_TLS_1_1)
    {
        len -= ssl->deBlockSize; /* skip explicit IV */
    }
# endif
    l1 = 13 + len - ssl->deMacSize;
    l2 = 13 + len - padLen - 1 - ssl->deMacSize;

    if (ssl->deMacSize == SHA1_HASH_SIZE || ssl->deMacSize == SHA256_HASH_SIZE)
    {
        while (l1 > 64)
        {
            c1++; l1 -= 64;
        }
        if (l1 > 56)
        {
            c1++;
        }
        while (l2 > 64)
        {
            c2++; l2 -= 64;
        }
        if (l2 > 56)
        {
            c2++;
        }
# ifdef USE_SHA384
    }
    else if (ssl->deMacSize == SHA384_HASH_SIZE)
    {
        while (l1 > 128)
        {
            c1++; l1 -= 128;
        }
        if (l1 > 112)
        {
            c1++;
        }
        while (l2 > 128)
        {
            c2++; l2 -= 128;
        }
        if (l2 > 112)
        {
            c2++;
        }

# endif
    }

    return c1 - c2;
}
#endif /* LUCKY13 */

/******************************************************************************/
/*
    The workhorse for parsing handshake messages.  Also enforces the state
    machine     for proper ordering of handshake messages.
    Parameters:
    ssl - ssl context
    inbuf - buffer to read handshake message from
    len - data length for the current ssl record.  The ssl record
        can contain multiple handshake messages, so we may need to parse
        them all here.
    Return:
        MATRIXSSL_SUCCESS
        SSL_PROCESS_DATA
        MATRIXSSL_ERROR - see ssl->err for details
        MEM_FAIL
        -MATRIXSSL_ERROR and MEM_FAIL will be caught and an alert sent.  If you
            want to specifiy the alert the set ss->err.  Otherwise it will
            be an INTERNAL_ERROR
 */
static int32 parseSSLHandshake(ssl_t *ssl, char *inbuf, uint32 len)
{
    unsigned char *c, *end;
    unsigned char hsType;
    int32 rc;
    uint32 hsLen;
    unsigned char hsMsgHash[SHA512_HASH_SIZE];

#ifdef USE_DTLS
    uint32 fragLen;
    int32 msn, fragOffset, j;
# ifdef USE_CLIENT_SIDE_SSL
    int32 hvreqMinVer, hvreqMajVer;
# endif
#endif /* USE_DTLS */


    rc = MATRIXSSL_SUCCESS;
    c = (unsigned char *) inbuf;
    end = (unsigned char *) (inbuf + len);

    /* Immediately check if we are working with a fragmented message. */
#ifdef USE_DTLS
    msn = 0;
    /* This is the non-DTLS fragmentation handler */
    if (!(ssl->flags & SSL_FLAGS_DTLS))
    {
#endif
    if (ssl->fragMessage != NULL)
    {
        /* Just borrowing hsLen variable.  Is the rest here or do we still
            need more? */
        hsLen = min((uint32) (end - c), ssl->fragTotal - ssl->fragIndex);
        memcpy(ssl->fragMessage + ssl->fragIndex, c, hsLen);
        ssl->fragIndex += hsLen;
        c += hsLen;

        if (ssl->fragIndex == ssl->fragTotal)
        {
            c = ssl->fragMessage + ssl->hshakeHeadLen;
            end = ssl->fragMessage + ssl->fragTotal;
            hsLen = ssl->fragTotal - ssl->hshakeHeadLen;
            goto SKIP_HSHEADER_PARSE;
        }
        else
        {
            return MATRIXSSL_SUCCESS;
        }
    }
#ifdef USE_DTLS
}
#endif

#ifdef USE_CERT_CHAIN_PARSING
    if (ssl->rec.partial && (ssl->rec.hsBytesParsed > ssl->recordHeadLen))
    {
        goto SKIP_HSHEADER_PARSE;
    }
#endif /* USE_CERT_CHAIN_PARSING */

parseHandshake:
    if (end - c < 1)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid length of handshake message 1\n");
        psTraceIntInfo("%d\n", (int32) (end - c));
        return MATRIXSSL_ERROR;
    }
    hsType = *c; c++;

#ifndef SSL_REHANDSHAKES_ENABLED
/*
    If all rehandshaking is disabled, just catch that here and alert.
 */
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        if (hsType == SSL_HS_CLIENT_HELLO && ssl->hsState == SSL_HS_DONE)
        {
            psTraceInfo("Closing conn with client. Rehandshake is disabled\n");
            ssl->err = SSL_ALERT_NO_RENEGOTIATION;
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        if (hsType == SSL_HS_HELLO_REQUEST && ssl->hsState == SSL_HS_DONE)
        {
            psTraceInfo("Closing conn with server. Rehandshake is disabled\n");
            ssl->err = SSL_ALERT_NO_RENEGOTIATION;
            return MATRIXSSL_ERROR;
        }
    }
#endif  /* SSL_REHANDSHAKES_ENABLED */

#ifdef USE_DTLS
/*
    The MSN helpes keep the state machine sane prior to passing through to
    the hsType exceptions because if they are received out-of-order it could
    choose the wrong handshake type (client auth, rehandshake, or standard)

    It is mostly important to deal with future messages here because those
    are the ones that may bypass us to the wrong handshake type.  Duplicates
    are handled below.
 */
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (end - c < 5)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid length of handshake message\n");
            return MATRIXSSL_ERROR;
        }
        msn = c[3] << 8;
        msn += c[4];
        if (msn > (ssl->lastMsn + 1))
        {
            psTraceIntDtls("Ignoring future handshake msg %d\n", hsType);
            return MATRIXSSL_SUCCESS;
        }
        else if (msn != 0 && ssl->lastMsn >= msn)
        {
            psTraceIntDtls("Ignoring already seen handshake msg %d\n", hsType);
            return DTLS_RETRANSMIT;
        }
    }
#endif /* USE_DTLS */

/*
    hsType is the received handshake type and ssl->hsState is the expected
    handshake type.  If it doesn't match, there are some possible cases
    that are not errors.  These are checked here.
 */
    if (hsType != ssl->hsState &&
        (hsType != SSL_HS_CLIENT_HELLO || ssl->hsState != SSL_HS_DONE))
    {

/*
        A mismatch is possible in the client authentication case.
        The optional CERTIFICATE_REQUEST may be appearing instead of
        SERVER_HELLO_DONE.
 */
        if ((hsType == SSL_HS_CERTIFICATE_REQUEST) &&
            (ssl->hsState == SSL_HS_SERVER_HELLO_DONE))
        {
/*
            This is where the client is first aware of requested client
            authentication so we set the flag here.

 */
            ssl->flags |= SSL_FLAGS_CLIENT_AUTH;
            ssl->hsState = SSL_HS_CERTIFICATE_REQUEST;
            goto hsStateDetermined;
        }
/*
        Another possible mismatch allowed is for a HELLO_REQEST message.
        Indicates a rehandshake initiated from the server.
 */
        if ((hsType == SSL_HS_HELLO_REQUEST) &&
            (ssl->hsState == SSL_HS_DONE) &&
            !(ssl->flags & SSL_FLAGS_SERVER))
        {
            sslResetContext(ssl);
            ssl->hsState = hsType;
            goto hsStateDetermined;
        }

        /* Another possible mismatch is HELLO_REQUEST right after we sent
            a re-handshake CLIENT_HELLO.  Will ignore the request and
            assume this was a timing issue and that the server will reply
            to our CLIENT_HELLO when it is received */
        if ((hsType == SSL_HS_HELLO_REQUEST) &&
            (ssl->hsState == SSL_HS_SERVER_HELLO) &&
            (ssl->flags & SSL_FLAGS_READ_SECURE) &&
            (ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
            !(ssl->flags & SSL_FLAGS_SERVER))
        {
            /* There is no body to the message.  Confirm this and exit happily
                without changing state */
            if (end - c < 3)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid length of handshake message 2\n");
                psTraceIntInfo("%d\n", (int32) (end - c));
                return MATRIXSSL_ERROR;
            }
            hsLen = *c << 16; c++;
            hsLen += *c << 8; c++;
            hsLen += *c; c++;
#ifdef USE_DTLS
            if (ssl->flags & SSL_FLAGS_DTLS)
            {
                if (end - c < 8)
                {
                    ssl->err = SSL_ALERT_DECODE_ERROR;
                    psTraceInfo("Invalid length of handshake message\n");
                    return MATRIXSSL_ERROR;
                }
                c += 8;
            }
#endif
#ifdef SSL_REHANDSHAKES_ENABLED
            if (ssl->rehandshakeCount <= 0)
            {
                ssl->err = SSL_ALERT_NO_RENEGOTIATION;
                psTraceInfo("Server re-handshaking denied.  Out of credits.\n");
                return MATRIXSSL_ERROR;
            }
            ssl->rehandshakeCount--;
#endif
            if (hsLen == 0)
            {
                return MATRIXSSL_SUCCESS;
            }
            else
            {
                return MATRIXSSL_ERROR;
            }
        }

#ifdef USE_STATELESS_SESSION_TICKETS
        /*      Another possible mismatch allowed is for a
            SSL_HS_NEW_SESSION_TICKET message.  */
        if ((hsType == SSL_HS_NEW_SESSION_TICKET) &&
            (ssl->hsState == SSL_HS_FINISHED) && ssl->sid &&
            (ssl->sid->sessionTicketState == SESS_TICKET_STATE_RECVD_EXT) &&
            !(ssl->flags & SSL_FLAGS_SERVER))
        {
            ssl->hsState = hsType;
            goto hsStateDetermined;
        }

#endif  /* USE_STATELESS_SESSION_TICKETS */

#ifdef USE_OCSP_RESPONSE
        /*      Another possible mismatch is server didn't send the optional
            CERTIFICATE_STATUS message.  Unfortunate this was not specified
            to be strictly handled in the status_request extensions */
        if (ssl->hsState == SSL_HS_CERTIFICATE_STATUS)
        {
            /* The two valid states from here are identical
                checking of the next state calculation at the end of the
                SSL_HS_CERTIFICATE message handling.
                (But in reverse order due to the precedence of DHE mode.)
             */
# ifdef USE_OCSP_MUST_STAPLE
            /* This is the case where the server sent a reply to our
                status_request extension but didn't actually send the
                handshake message. If we are in a MUST state, time to fail */
            psTraceInfo("Expecting CERTIFICATE_STATUS message\n");
            ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
            return MATRIXSSL_ERROR;
# else
#  ifdef USE_DHE_CIPHER_SUITE
            if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH &&
                hsType == SSL_HS_SERVER_KEY_EXCHANGE)
            {
                ssl->hsState = hsType;
                goto hsStateDetermined;
            }
#  endif    /* USE_DHE_CIPHER_SUITE */
            if (hsType == SSL_HS_SERVER_HELLO_DONE)
            {
                ssl->hsState = hsType;
                goto hsStateDetermined;
            }
# endif /* USE_OCSP_MUST_STAPLE */
        }
#endif  /* USE_OCSP_RESPONSE */

#ifdef USE_PSK_CIPHER_SUITE
/*
        PSK suites are probably not including SERVER_KEY_EXCHANGE message
 */
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            if ((hsType == SSL_HS_SERVER_HELLO_DONE) &&
                (ssl->hsState == SSL_HS_SERVER_KEY_EXCHANGE))
            {
# ifdef USE_DHE_CIPHER_SUITE
/*
                DH kex suites must be sending a SERVER_KEY_EXCHANGE message
 */
                if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
                {
                    psTraceIntInfo("Expecting SKE message: %d\n", hsType);
                    ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
                    return MATRIXSSL_ERROR;
                }
# endif         /* USE_DHE_CIPHER_SUITE */
                ssl->hsState = hsType;
                goto hsStateDetermined;
            }
        }
#endif  /* USE_PSK_CIPHER_SUITE */

#ifdef USE_DTLS
/*
        DTLS inserts an optional VERIFY_REQUEST back to clients
 */
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
# ifdef USE_CLIENT_SIDE_SSL
            if ((hsType == SSL_HS_HELLO_VERIFY_REQUEST) &&
                (ssl->hsState == SSL_HS_SERVER_HELLO))
            {
                /*      However, if this is a retransmit and we've already parsed
                    the HELLO_VERIFY_REQUEST we can safely skip it */
                if (ssl->haveCookie == 0)
                {
                    ssl->hsState = hsType;
                    goto hsStateDetermined;
                }
            }
# endif
/*
            A final MSN sanity test and handling of duplicate hello messages
 */
            if ((ssl->lastMsn + 1) == msn)
            {
                ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
                psTraceIntDtls("Correct MSN %d on unexpected HS msg ", msn);
                psTraceIntDtls(" %d\n", hsType);
                return MATRIXSSL_ERROR;
            }
            else if (ssl->lastMsn >= msn)
            {
                psTraceDtls("IGNORING ALREADY SEEN HELLO HANDSHAKE MSG\n");
                return DTLS_RETRANSMIT;
            }
        }
#endif  /* USE_DTLS */

        ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
        psTraceIntInfo("Out-of-order handshake message: %d\n", hsType);
        psTraceIntInfo("Wanted: %d\n", ssl->hsState);
        return MATRIXSSL_ERROR;
    }

hsStateDetermined:
    if (hsType == SSL_HS_CLIENT_HELLO)
    {
        sslInitHSHash(ssl);
        if (ssl->hsState == SSL_HS_DONE)
        {
# ifdef SSL_REHANDSHAKES_ENABLED
            /* This is a 'leaky bucket' mechanism where each X bytes of data transfer gains
                you a re-handshake credit.  Prevents the DOS attack     of repeat
                re-handshake requests */
            if (ssl->rehandshakeCount <= 0)
            {
                ssl->err = SSL_ALERT_NO_RENEGOTIATION;
                psTraceInfo("Client re-handshaking denied\n");
                return MATRIXSSL_ERROR;
            }
            ssl->rehandshakeBytes = 0; /* reset */
            ssl->rehandshakeCount--;
# endif /* SSL_REHANDSHAKES_ENABLED */
            /* Rehandshake. Server receiving client hello on existing connection */
            sslResetContext(ssl);
            ssl->hsState = hsType;
        }
    }

/*
    We need to get a copy of the message hashes to compare to those sent
    in the finished message (which does not include a hash of itself)
    before we update the handshake hashes
 */
    if (ssl->hsState == SSL_HS_FINISHED)
    {
        if (sslSnapshotHSHash(ssl, hsMsgHash,
                (ssl->flags & SSL_FLAGS_SERVER) ? 0 : SSL_FLAGS_SERVER) <= 0)
        {
            psTraceInfo("Error snapshotting HS hash\n");
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return MATRIXSSL_ERROR;
        }
    }
#ifdef USE_CLIENT_AUTH
    if (ssl->hsState == SSL_HS_CERTIFICATE_VERIFY)
    {
        /* Same issue as above for client auth.  Need a handshake snapshot
            that doesn't include this message we are about to process */
        if (sslSnapshotHSHash(ssl, hsMsgHash, -1) <= 0)
        {
            psTraceInfo("Error snapshotting HS hash\n");
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return MATRIXSSL_ERROR;
        }
    }
#endif /* USE_CLIENT_AUTH */

/*
    Process the handshake header and update the ongoing handshake hash
    SSLv3:
        1 byte type
        3 bytes length
    SSLv2:
        1 byte type
 */
    if (ssl->rec.majVer >= SSL3_MAJ_VER)
    {
        if (end - c < 3)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid length of handshake message 2\n");
            psTraceIntInfo("%d\n", (int32) (end - c));
            return MATRIXSSL_ERROR;
        }
        hsLen = *c << 16; c++;
        hsLen += *c << 8; c++;
        hsLen += *c; c++;
#ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            if (end - c < 8)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid length of handshake message\n");
                return MATRIXSSL_ERROR;
            }
            msn = *c << 8; c++;
            msn += *c; c++;
            fragOffset = *c << 16; c++;
            fragOffset += *c << 8; c++;
            fragOffset += *c; c++;
            fragLen = *c << 16; c++;
            fragLen += *c << 8; c++;
            fragLen += *c; c++;
            if (fragLen != hsLen)
            {
/*
                Have a fragmented message here.  Allocate if first time
                seen and assign msn.  Can only deal with single fragmented
                message at a time.
 */
                if (ssl->fragTotal == 0)
                {
/*
                    When all the fragments are received, this allocated pointer
                    becomes the 'c' parsing pointer.  With all the potential
                    exit points in the parse code from all the different
                    messages it is not easy to free this on the fly.  So, what
                    happens here is that each first message fragment that is
                    encountered will free the previous message if it exists
                    (not NULL).

                    The final test for freeing this pointer will be in the
                    encoding (client) and decoding (server) of the Finished
                    message.  At this point we know     we can't possibly be
                    recieving any more fragments since the CCS and Finished
                    messages will never be so large that they would require
                    fragmenting.  Also, the handshake pool is freed during
                    the encoding of Finished.
 */
                    if (ssl->fragMessage != NULL )
                    {
                        psFree(ssl->fragMessage, ssl->hsPool);
                        ssl->fragMessage = NULL;
                    }
                    ssl->fragMessage = psMalloc(ssl->hsPool, hsLen);
                    if (ssl->fragMessage == NULL)
                    {
                        return SSL_MEM_ERROR;
                    }
                    ssl->fragMsn = msn;
                }

                if (ssl->fragMsn != msn)
                {
/*
                    Got a fragment from a different msg.  Ignore
 */
                    return MATRIXSSL_SUCCESS;
                }
/*
                Still could be a duplicate fragment.  Make sure we haven't
                seen it before.  If we haven't this routine also returns
                the next open fragment header index for use below.
 */
                if ((rc = dtlsSeenFrag(ssl, fragOffset, &j)) == 1)
                {
                    return MATRIXSSL_SUCCESS;
                }
                else if (rc == -1)     /* MAX_FRAGMENTS exceeded */
                {
                    dtlsInitFrag(ssl); /* init will free memory */
                    if (ssl->fragMessage != NULL)
                    {
                        psFree(ssl->fragMessage, ssl->hsPool);
                        ssl->fragMessage = NULL;
                    }
                    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                    psTraceIntDtls("Max fragment limit exceeded: %d\n",
                        MAX_FRAGMENTS);
                    return PS_LIMIT_FAIL;
                }
/*
                Need to save the hs header info aside as well so that we may
                pass the fragments through the handshake hash mechanism in
                the correct order.  This list also keeps track of the fragment
                offsets and lengths for the same reason.
 */
                ssl->fragHeaders[j].hsHeader = psMalloc(ssl->hsPool,
                    ssl->hshakeHeadLen);
                if (ssl->fragHeaders[j].hsHeader == NULL)
                {
                    dtlsInitFrag(ssl); /* init to free */
                    return SSL_MEM_ERROR;
                }
                memcpy(ssl->fragHeaders[j].hsHeader, c - ssl->hshakeHeadLen,
                    ssl->hshakeHeadLen);
                ssl->fragHeaders[j].offset = fragOffset;
                ssl->fragHeaders[j].fragLen = fragLen;

                ssl->fragTotal += fragLen;
                memcpy(ssl->fragMessage + fragOffset, c, fragLen);
                if (ssl->fragTotal != hsLen)
                {

                    /* Don't have all the fragments yet */
                    return MATRIXSSL_SUCCESS;
                }
                c = ssl->fragMessage;
                end = ssl->fragMessage + hsLen;
            }
        }
#endif  /* USE_DTLS */
#ifdef USE_CERT_CHAIN_PARSING
        if (((uint32) (end - c) < hsLen) && !ssl->rec.partial)
        {
#else
        if ((uint32) (end - c) < hsLen)
        {
#endif
            /* Support for fragmented handshake messages - non-DTLS */
            if (ssl->fragMessage == NULL)
            {
                /* Initial indication there is a fragmented message */
                ssl->fragTotal = hsLen + ssl->hshakeHeadLen;
                ssl->fragMessage = psMalloc(ssl->hsPool, ssl->fragTotal);
                if (ssl->fragMessage == NULL)
                {
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    psTraceInfo("Memory allocation error\n");
                    return MATRIXSSL_ERROR;
                }
                ssl->fragIndex = (uint32) (end - c) + ssl->hshakeHeadLen;
                memcpy(ssl->fragMessage, c - ssl->hshakeHeadLen,
                    ssl->fragIndex);
                return MATRIXSSL_SUCCESS;
            }
            else
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid handshake length\n");
                return MATRIXSSL_ERROR;
            }
        }
#ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            if (ssl->fragTotal > 0)
            {
                /* Run the UpdateHash over the fragmented message */
                dtlsHsHashFragMsg(ssl);
                dtlsInitFrag(ssl);
            }
            else
            {
/*
                The DTLS case in which the message was not fragmented.
                Not at all unusual to hit this
 */
                sslUpdateHSHash(ssl, c - ssl->hshakeHeadLen,
                    hsLen + ssl->hshakeHeadLen);
            }

        }
        else
        {
#endif  /* USE_DTLS */
SKIP_HSHEADER_PARSE:

#ifdef USE_CERT_CHAIN_PARSING
        if (ssl->rec.partial)
        {
/*
                Length of partial certificate records are being managed
                manually with ssl->rec.len.  The first pass will need to
                include the record header in the hash.
 */
            if (ssl->rec.hsBytesHashed == 0)
            {
                sslUpdateHSHash(ssl, c - ssl->hshakeHeadLen, ssl->rec.len);
            }
            else
            {
                sslUpdateHSHash(ssl, c, ssl->rec.len);
            }
            ssl->rec.hsBytesHashed += ssl->rec.len;
        }
        else
        {
            sslUpdateHSHash(ssl, c - ssl->hshakeHeadLen,
                hsLen + ssl->hshakeHeadLen);
        }
#else
        sslUpdateHSHash(ssl, c - ssl->hshakeHeadLen,
            hsLen + ssl->hshakeHeadLen);

#endif
#ifdef USE_DTLS
    }
#endif  /* USE_DTLS */

    }
    else if (ssl->rec.majVer == SSL2_MAJ_VER)
    {
/*
        Assume that the handshake len is the same as the incoming ssl record
        length minus 1 byte (type), this is verified in SSL_HS_CLIENT_HELLO
 */
        hsLen = len - 1;
        sslUpdateHSHash(ssl, (unsigned char *) inbuf, len);
    }
    else
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceIntInfo("Invalid record version: %d\n", ssl->rec.majVer);
        return MATRIXSSL_ERROR;
    }

/******************************************************************************/
/*
    Finished with header.  Process each type of handshake message.
 */
    switch (ssl->hsState)
    {

/******************************************************************************/

#ifdef USE_SERVER_SIDE_SSL
    case SSL_HS_CLIENT_HELLO:
        psAssert(rc == 0); /* checking to see if this is the correct default */
        if (c + hsLen != end)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid length for Client Hello.\n");
            return MATRIXSSL_ERROR;
        }
        rc = parseClientHello(ssl, &c, end);
        /* SSL_PROCESS_DATA is a valid code to indicate the end of a flight */
        if (rc < 0 && rc != SSL_PROCESS_DATA)
        {
            return rc;
        }
        break;

/******************************************************************************/

    case SSL_HS_CLIENT_KEY_EXCHANGE:
        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseClientKeyExchange(ssl, hsLen, &c, end);
        if (rc < 0)
        {
            return rc;
        }
        break;
#endif  /* USE_SERVER_SIDE_SSL */

/******************************************************************************/

    case SSL_HS_FINISHED:
        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseFinished(ssl, hsLen, hsMsgHash, &c, end);
        /* SSL_PROCESS_DATA is a valid code to indicate the end of a flight */
        if (rc < 0 && rc != SSL_PROCESS_DATA)
        {
            return rc;
        }
        break;

/******************************************************************************/
#ifdef USE_CLIENT_SIDE_SSL
    case SSL_HS_HELLO_REQUEST:
        /* No body message and the only one in record flight */
        psTraceHs(">>> Client parsing HELLO_REQUEST message\n");
        if (end - c != 0)
        {
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            psTraceInfo("Invalid hello request message\n");
            return MATRIXSSL_ERROR;
        }
#  ifdef SSL_REHANDSHAKES_ENABLED
        if (ssl->rehandshakeCount <= 0)
        {
            ssl->err = SSL_ALERT_NO_RENEGOTIATION;
            psTraceInfo("Server re-handshaking denied\n");
            /* Reset the state to done */
            ssl->hsState = SSL_HS_DONE;
            return MATRIXSSL_ERROR;
        }
        ssl->rehandshakeCount--;
#  endif
        /* Intentionally not changing state here to SERVER_HELLO.  The
            encodeResponse case this will fall into needs to distinguish
            between calling the normal sslEncodeResponse or encodeClientHello.
            The HELLO_REQUEST state is used to make that determination and the
            writing of CLIENT_HELLO will properly move the state along itself */
        ssl->decState = SSL_HS_HELLO_REQUEST;
        rc = SSL_PROCESS_DATA;
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
        /* Reinitialize the state of the on-demand client cert and key loading
           feature for the re-handshake. */
        ssl->extClientCertKeyStateFlags = EXT_CLIENT_CERT_KEY_STATE_INIT;
# endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
        break;

/******************************************************************************/

    case SSL_HS_SERVER_HELLO:

        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseServerHello(ssl, hsLen, &c, end);
        if (rc < 0)
        {
            return rc;
        }
        break;

#endif  /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/

#ifndef USE_ONLY_PSK_CIPHER_SUITE
# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)

    case SSL_HS_CERTIFICATE:
        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseCertificate(ssl, &c, end);
        if (rc < 0)
        {
            return rc;
        }
        break;

# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
# ifdef USE_OCSP_RESPONSE
    case SSL_HS_CERTIFICATE_STATUS:
        psTraceHs(">>> Client parsing CERTIFICATE_STATUS message\n");
        rc = parseCertificateStatus(ssl, hsLen, &c, end);
        if (rc < 0)
        {
            return rc;
        }
        break;
# endif /* USE_OCSP_RESPONSE */

/******************************************************************************/


# ifdef USE_STATELESS_SESSION_TICKETS
    case SSL_HS_NEW_SESSION_TICKET:

        psTraceHs(">>> Client parsing NEW_SESSION_TICKET message\n");
#  ifdef USE_EAP_FAST
        if (ssl->flags & SSL_FLAGS_EAP_FAST)
        {
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            psTraceInfo("NEW_SESSION_TICKET unsupported in EAP-FAST\n");
            return MATRIXSSL_ERROR;
        }
#  endif
        if (hsLen < 6)
        {
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            psTraceInfo("Invalid NewSessionTicket message\n");
            return MATRIXSSL_ERROR;
        }
        ssl->sid->sessionTicketLifetimeHint = *c << 24; c++;
        ssl->sid->sessionTicketLifetimeHint |= *c << 16; c++;
        ssl->sid->sessionTicketLifetimeHint |= *c << 8; c++;
        ssl->sid->sessionTicketLifetimeHint |= *c; c++;
        /* Reusing hsLen here */
        hsLen = *c << 8; c++;
        hsLen |= *c; c++;

        if ((uint32) (end - c) < hsLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid NewSessionTicket message\n");
            return MATRIXSSL_ERROR;
        }
        if (ssl->sid->sessionTicketLen == 0)
        {
            /* First time receiving a session ticket */
            ssl->sid->sessionTicketLen = hsLen;
            /* This client has a dedicated SessionId pool to draw from. */
            if ((ssl->sid->sessionTicket = psMalloc(ssl->sid->pool,
                     ssl->sid->sessionTicketLen)) != NULL)
            {
                memcpy(ssl->sid->sessionTicket, c, ssl->sid->sessionTicketLen);
                c += ssl->sid->sessionTicketLen;
            }
            else
            {
                /* Don't fail on alloc error.  Just won't have the ticket for
                    next time */
                c += ssl->sid->sessionTicketLen;
                ssl->sid->sessionTicketLen = 0;
            }
        }
        else
        {
            /* Updated (or duplicate) ticket */
            psAssert(ssl->sid->sessionTicket); /* exists from previous hs */
            if (hsLen == ssl->sid->sessionTicketLen &&
                (memcmp(c, ssl->sid->sessionTicket, hsLen) == 0))
            {
                /* server not updating the ticket */
                c += ssl->sid->sessionTicketLen;
            }
            else
            {
                ssl->sid->sessionTicketLen = hsLen;
                psFree(ssl->sid->sessionTicket, ssl->sid->pool);
                if ((ssl->sid->sessionTicket = psMalloc(ssl->sid->pool,
                         ssl->sid->sessionTicketLen)) != NULL)
                {
                    memcpy(ssl->sid->sessionTicket, c,
                        ssl->sid->sessionTicketLen);
                    c += ssl->sid->sessionTicketLen;
                }
                else
                {
                    /* Don't fail on alloc error.  Just won't have the ticket
                        for     next time */
                    c += ssl->sid->sessionTicketLen;
                    ssl->sid->sessionTicketLen = 0;
                }
            }
        }
        ssl->sid->sessionTicketState = SESS_TICKET_STATE_INIT;
        ssl->hsState = SSL_HS_FINISHED;
        ssl->decState = SSL_HS_NEW_SESSION_TICKET;
        break;
# endif /* USE_STATELESS_SESSION_TICKETS */

/******************************************************************************/

    case SSL_HS_SERVER_HELLO_DONE:

        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseServerHelloDone(ssl, hsLen, &c, end);
        if (rc < 0 && rc != SSL_PROCESS_DATA)
        {
            return rc;
        }
#   ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
        /* Note: we must have parsed both CertificateRequest and ServerHelloDone
           before proceeding to new client cert and key loading state. */
        ssl->extClientCertKeyStateFlags |=
            EXT_CLIENT_CERT_KEY_STATE_GOT_SERVER_HELLO_DONE;
#   endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */
        break;


/******************************************************************************/

# ifndef USE_ONLY_PSK_CIPHER_SUITE
    case SSL_HS_CERTIFICATE_REQUEST:

        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseCertificateRequest(ssl, hsLen, &c, end);
        if (rc < 0)
        {
            return rc;
        }
#   ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
        /* Note: we must have parsed both CertificateRequest and ServerHelloDone
           before proceeding to new client cert and key loading state. */
        ssl->extClientCertKeyStateFlags |=
            EXT_CLIENT_CERT_KEY_STATE_GOT_CERTIFICATE_REQUEST;
#   endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */

        break;
# endif /* !USE_ONLY_PSK_CIPHER_SUITE */
#endif  /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/

#ifndef USE_ONLY_PSK_CIPHER_SUITE
# if defined(USE_CLIENT_AUTH) && defined(USE_SERVER_SIDE_SSL)
    case SSL_HS_CERTIFICATE_VERIFY:

        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseCertificateVerify(ssl, hsMsgHash, &c, end);
        if (rc < 0)
        {
            return rc;
        }

        break;
# endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */
#endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/

    case SSL_HS_SERVER_KEY_EXCHANGE:
#ifdef USE_CLIENT_SIDE_SSL
        psAssert(rc == 0); /* checking to see if this is the correct default */
        rc = parseServerKeyExchange(ssl, hsMsgHash, &c, end);
        if (rc < 0)
        {
            return rc;
        }
#else   /* USE_CLIENT_SIDE_SSL */
        ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
        return MATRIXSSL_ERROR;
#endif  /* USE_CLIENT_SIDE_SSL */
        break;

/******************************************************************************/

#ifdef USE_DTLS
# ifdef USE_CLIENT_SIDE_SSL
    case SSL_HS_HELLO_VERIFY_REQUEST:
        psTraceHs(">>> Client parsing HELLO_VERIFY_REQUEST message\n");
/*
        Format for message is two byte version specifier, 1 byte length, and
        the cookie itself
 */
        if ((end - c) < 3)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid HelloVerifyRequest message\n");
            return MATRIXSSL_ERROR;
        }
        hvreqMajVer = *c; c++;
        hvreqMinVer = *c; c++;
        (void) hvreqMajVer; /* Silence a 'set but not used' warning. */
        (void) hvreqMinVer;
        ssl->cookieLen = *c; c++;
        if (ssl->cookieLen > 0)
        {
            if ((end - c) < ssl->cookieLen)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid HelloVerifyRequest message\n");
                return MATRIXSSL_ERROR;
            }
/*
            The handshake pool does exists at this point.  For DTLS handshakes
            the client created the pool during the ClientHello write in order
            to store the initial message in case the Server asks for cookie
            (which is exactly what is happening right here).
 */
            if (ssl->haveCookie)
            {
                /* retransmit.  should match what we already have */
                if (memcmpct(ssl->cookie, c, ssl->cookieLen) != 0)
                {
                    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                    psTraceInfo("Cookie has changed on retransmit\n");
                    return MATRIXSSL_ERROR;
                }
                c += ssl->cookieLen;
            }
            else
            {
                ssl->cookie = psMalloc(ssl->hsPool, ssl->cookieLen);
                if (ssl->cookie == NULL)
                {
                    return SSL_MEM_ERROR;
                }
                memcpy(ssl->cookie, c, ssl->cookieLen);
                c += ssl->cookieLen;
            }
        }
        ssl->haveCookie++;
        ssl->hsState = SSL_HS_SERVER_HELLO;
        ssl->decState = SSL_HS_HELLO_VERIFY_REQUEST;
        rc = SSL_PROCESS_DATA;
        break;
# endif /* USE_CLIENT_SIDE_SSL */
#endif  /* USE_DTLS */

/******************************************************************************/

    default:
        ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
        return MATRIXSSL_ERROR;
    }

#ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        ssl->lastMsn = msn; /* MSN of last message sucessfully parsed */
    }
#endif /* USE_DTLS */

/*
    if we've got more data in the record, the sender has packed
    multiple handshake messages in one record.  Parse the next one.
 */
    if (c < end)
    {
        goto parseHandshake;
    }

# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
    if ((ssl->extClientCertKeyStateFlags &
                EXT_CLIENT_CERT_KEY_STATE_GOT_CERTIFICATE_REQUEST) &&
        (ssl->extClientCertKeyStateFlags &
                EXT_CLIENT_CERT_KEY_STATE_GOT_SERVER_HELLO_DONE))
    {
        psTraceInfo("Received CertificateRequest flight\n");
        psTraceInfo("Now returning PS_PENDING to get client cert and key\n");
        ssl->extClientCertKeyStateFlags =
            EXT_CLIENT_CERT_KEY_STATE_WAIT_FOR_CERT_KEY_UPDATE;
        return PS_PENDING;
    }
# endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */

    return rc;
}

/******************************************************************************/
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
# ifdef USE_CERT_CHAIN_PARSING
static int32 parseSingleCert(ssl_t *ssl, unsigned char *c, unsigned char *end,
    int32 certLen)
{
    int32 parseLen, certFlags;
    psX509Cert_t *cert, *p;

/*
    Extract the binary cert message into the cert structure
 */
    if (ssl->bflags & BFLAG_KEEP_PEER_CERT_DER)
    {
        certFlags |= CERT_STORE_UNPARSED_BUFFER;
    }

    if ((parseLen = psX509ParseCert(ssl->hsPool, c, certLen, &cert, certFlags)) < 0)
    {
        psX509FreeCert(cert);
        if (parseLen == PS_MEM_FAIL)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
        }
        else
        {
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
        }
        return MATRIXSSL_ERROR;
    }
    if (ssl->sec.cert == NULL)
    {
        ssl->sec.cert = cert;
    }
    else
    {
        p = ssl->sec.cert;
        while (p->next != NULL)
        {
            p = p->next;
        }
        p->next = cert;
    }
    return parseLen;
}
# endif /* USE_CERT_CHAIN_PARSING */
#endif  /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */

/******************************************************************************/

