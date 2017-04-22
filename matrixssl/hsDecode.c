/**
 *      @file    hsDecode.c
 *      @version $Format:%h%d$
 *
 *      SSL/TLS handshake message parsing
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

#ifdef USE_ECC
#  define USE_ECC_EPHEMERAL_KEY_CACHE
#endif

#define COMPRESSION_METHOD_NULL                0x0
#define COMPRESSION_METHOD_DEFLATE     0x1

/* Errors from these routines must either be MATRIXSSL_ERROR or PS_MEM_FAIL */

/******************************************************************************/

#ifdef USE_SERVER_SIDE_SSL
int32 parseClientHello(ssl_t *ssl, unsigned char **cp, unsigned char *end)
{
    unsigned char *suiteStart, *suiteEnd;
    unsigned char compareMin, compareMaj, compLen, serverHighestMinor;
    uint32 suiteLen;
    uint32 resumptionOnTrack, cipher = 0;
    int32 rc, i;
    unsigned char *c;

#  ifdef USE_ECC_CIPHER_SUITE
    const psEccCurve_t *curve;
#  endif
#  if defined(USE_ECC) || defined(REQUIRE_DH_PARAMS)
    void *pkiData = ssl->userPtr;
#  endif

    c = *cp;

    /* First two bytes are the highest supported major and minor SSL versions */
    psTraceHs(">>> Server parsing CLIENT_HELLO\n");

# ifdef USE_MATRIXSSL_STATS
    matrixsslUpdateStat(ssl, CH_RECV_STAT, 1);
# endif
    if (end - c < 2)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid ssl header version length\n");
        return MATRIXSSL_ERROR;
    }

    ssl->reqMajVer = *c; c++;
    ssl->reqMinVer = *c; c++;

# ifndef USE_SSL_PROTOCOL_VERSIONS_OTHER_THAN_3
    /* RFC 5246 Suggests to accept all RSA minor versions, but only
       major version 0x03 (SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 etc) */
    if (ssl->reqMajVer != 0x03
#  ifdef USE_DTLS
        && ssl->reqMajVer != DTLS_MAJ_VER
#  endif /* USE_DTLS */
        )
    {
        /* Consider invalid major version protocol version error. */
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceInfo("Won't support client's SSL major version\n");
        return MATRIXSSL_ERROR;
    }
# endif /* USE_SSL_PROTOCOL_VERSIONS_OTHER_THAN_3 */

    /*  Client should always be sending highest supported protocol.  Server
        will reply with a match or a lower version if enabled (or forced). */
    if (ssl->majVer != 0)
    {
        /* If our forced server version is a later protocol than their
            request, we have to exit */
        if (ssl->reqMinVer < ssl->minVer)
        {
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceInfo("Won't support client's SSL version\n");
            return MATRIXSSL_ERROR;
        }
# ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            /* DTLS specfication somehow assigned minimum version of DTLS 1.0
                as 255 so there was nowhere to go but down in DTLS 1.1 so
                that is 253 and requires the opposite test from above */
            if (ssl->reqMinVer > ssl->minVer)
            {
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                psTraceInfo("Won't support client's DTLS version\n");
                return MATRIXSSL_ERROR;
            }
        }
# endif
        /* Otherwise we just set our forced version to act like it was
            what the client wanted in order to move through the standard
            negotiation. */
        compareMin = ssl->minVer;
        compareMaj = ssl->majVer;
        /* Set the highest version to the version explicitly set */
        serverHighestMinor = ssl->minVer;
    }
    else
    {
        compareMin = ssl->reqMinVer;
        compareMaj = ssl->reqMajVer;
        /* If no explicit version was set for the server, use the highest supported */
        serverHighestMinor = TLS_HIGHEST_MINOR;
    }

    if (compareMaj >= SSL3_MAJ_VER)
    {
        ssl->majVer = compareMaj;
# ifdef USE_TLS
        if (compareMin >= TLS_MIN_VER)
        {
#  ifndef DISABLE_TLS_1_0
            ssl->minVer = TLS_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS;
#  endif
#  ifdef USE_TLS_1_1 /* TLS_1_1 */
            if (compareMin >= TLS_1_1_MIN_VER)
            {
#   ifndef DISABLE_TLS_1_1
                ssl->minVer = TLS_1_1_MIN_VER;
                ssl->flags |= SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
#   endif
            }
#   ifdef USE_TLS_1_2
            if (compareMin == TLS_1_2_MIN_VER)
            {
                ssl->minVer = TLS_1_2_MIN_VER;
                ssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
            }
#    ifdef USE_DTLS
            if (ssl->flags & SSL_FLAGS_DTLS)
            {
                if (compareMin == DTLS_1_2_MIN_VER)
                {
                    ssl->minVer = DTLS_1_2_MIN_VER;
                }
            }
#    endif
#   endif /* USE_TLS_1_2 */
#  endif  /* USE_TLS_1_1 */
            if (ssl->minVer == 0)
            {
                /* TLS versions are disabled.  Go SSLv3 if available. */
#  ifdef DISABLE_SSLV3
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                psTraceInfo("Can't support client's SSL version\n");
                return MATRIXSSL_ERROR;
#  else
                ssl->minVer = SSL3_MIN_VER;
#  endif
            }
        }
        else if (compareMin == 0)
        {
#  ifdef DISABLE_SSLV3
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceInfo("Client wanted to talk SSLv3 but it's disabled\n");
            return MATRIXSSL_ERROR;
#  else
            ssl->minVer = SSL3_MIN_VER;
#  endif    /* DISABLE_SSLV3 */
        }
#  ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            if (compareMin < DTLS_1_2_MIN_VER)
            {
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                psTraceInfo("Error: incorrect DTLS required version\n");
                return MATRIXSSL_ERROR;
            }
            ssl->minVer = DTLS_MIN_VER;
#   ifdef USE_TLS_1_2
            if (compareMin == DTLS_1_2_MIN_VER)
            {
                ssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
                ssl->minVer = DTLS_1_2_MIN_VER;
            }
#    ifdef USE_DTLS
            if (ssl->flags & SSL_FLAGS_DTLS)
            {
                if (compareMin == DTLS_1_2_MIN_VER)
                {
                    ssl->minVer = DTLS_1_2_MIN_VER;
                }
            }
#    endif /* USE_DTLS */
#   endif  /* USE_TLS_1_2 */

        }
#  endif /* USE_DTLS */
# else
        ssl->minVer = SSL3_MIN_VER;

# endif /* USE_TLS */

    }
    else
    {
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceIntInfo("Unsupported ssl version: %d\n", compareMaj);
        return MATRIXSSL_ERROR;
    }

    if (ssl->rec.majVer > SSL2_MAJ_VER)
    {
        /*      Next is a 32 bytes of random data for key generation
            and a single byte with the session ID length */
        if (end - c < SSL_HS_RANDOM_SIZE + 1)
        {
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            psTraceIntInfo("Invalid length of random data %d\n",
                (int32) (end - c));
            return MATRIXSSL_ERROR;
        }
        memcpy(ssl->sec.clientRandom, c, SSL_HS_RANDOM_SIZE);
        c += SSL_HS_RANDOM_SIZE;
        ssl->sessionIdLen = *c; c++; /* length verified with + 1 above */
        /*      If a session length was specified, the client is asking to
            resume a previously established session to speed up the handshake */
        if (ssl->sessionIdLen > 0)
        {
            if (ssl->sessionIdLen > SSL_MAX_SESSION_ID_SIZE ||
                end - c < ssl->sessionIdLen)
            {
                ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
# ifdef USE_MATRIXSSL_STATS
                matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
# endif
                return MATRIXSSL_ERROR;
            }
            memcpy(ssl->sessionId, c, ssl->sessionIdLen);
            c += ssl->sessionIdLen;
        }
        else
        {
            /* Always clear the RESUMED flag if no client session id
               It may be re-enabled if a client session ticket extension is recvd */
            ssl->flags &= ~SSL_FLAGS_RESUMED;
        }
# ifdef USE_DTLS
        /*      If DTLS is enabled, make sure we received a valid cookie in the
            CLIENT_HELLO message. */
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            psSize_t cookie_len;
            /* Next field is the cookie length */
            if (end - c < 1)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Cookie length not provided\n");
                return MATRIXSSL_ERROR;
            }
            /** Calculate what we expect the cookie should be by hashing the
                client_hello data up to this point:

                2 byte version + 1 byte session_id_len +
                    session_id + client_random

                @future The creation of the cookie should ideally take some
                IP Tuple information about the client into account.
                @impl MatrixSSL sends a zero length cookie on re-handshake, but
                other implementations may not, so this allows either
                to be supported.
             */
            cookie_len = 3 + ssl->sessionIdLen + SSL_HS_RANDOM_SIZE;
            if (dtlsComputeCookie(ssl, c - cookie_len, cookie_len) < 0)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                psTraceInfo("Invalid cookie length\n");
                return MATRIXSSL_ERROR;
            }
            cookie_len = *c++;
            if (cookie_len > 0)
            {
                if (end - c < cookie_len || cookie_len != DTLS_COOKIE_SIZE)
                {
                    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                    psTraceInfo("Invalid cookie length\n");
                    return MATRIXSSL_ERROR;
                }
                if (memcmpct(c, ssl->srvCookie, DTLS_COOKIE_SIZE) != 0)
                {
                    /* Cookie mismatch. Error to avoid possible DOS */
                    ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                    psTraceInfo("Cookie mismatch\n");
                    return MATRIXSSL_ERROR;
                }
                c += DTLS_COOKIE_SIZE;
            }
            else
            {
                /* If client sent an empty cookie, and we're not secure
                    yet, set the hsState to encode a HELLO_VERIFY message to
                    the client, which will provide a new cookie. */
                if (!(ssl->flags & SSL_FLAGS_READ_SECURE))
                {
                    ssl->hsState = SSL_HS_CLIENT_HELLO;
                    c = end;
                    *cp = c;
                    /* Clear session so it will be found again when the cookie
                        clientHello message comes in next */
                    if (ssl->flags & SSL_FLAGS_RESUMED)
                    {
                        matrixClearSession(ssl, 0);
                    }
                    /* Will cause HELLO_VERIFY to be encoded */
                    return SSL_PROCESS_DATA;
                }
                /** No cookie provided on already secure connection.
                   @impl This is a re-handshake case. MatrixSSL lets it slide
                   since we're already authenticated. */
            }
        }
# endif /* USE_DTLS */
        /*      Next is the two byte cipher suite list length, network byte order.
            It must not be zero, and must be a multiple of two. */
        if (end - c < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid cipher suite list length\n");
            return MATRIXSSL_ERROR;
        }
        suiteLen = *c << 8; c++;
        suiteLen += *c; c++;
        /* Save aside.  We're going to come back after extensions are
            parsed and choose a cipher suite */
        suiteStart = c;

        if (suiteLen <= 0 || suiteLen & 1)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceIntInfo("Unable to parse cipher suite list: %d\n",
                suiteLen);
            return MATRIXSSL_ERROR;
        }
        /* Now is 'suiteLen' bytes of the supported cipher suite list,
            listed in order of preference. */
        if (end - c < suiteLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Malformed clientHello message\n");
            return MATRIXSSL_ERROR;
        }
        /* We do not choose a ciphersuite yet, as the cipher we choose
            may depend on an extension sent by the client. For example,
            ALPN for HTTP/2 limits which suites we can negotiate, and
            ELLIPTIC_CURVE/ELLIPTIC_POINT extensions may not match with
            what we have available and we would have to fall back to a
            non-ECC cipher.
           Still, make one entire pass of the cipher suites now
            to search for SCSV if secure rehandshakes are on. This is
            the exception because SCSV is not a true ciphersuite, but
            more like an extension that can be "hidden" for pre-TLS1.0
            implementations. */
        suiteEnd = c + suiteLen;
        while (c < suiteEnd)
        {
            cipher = *c << 8; c++;
            cipher += *c; c++;
# ifdef ENABLE_SECURE_REHANDSHAKES
            if (ssl->myVerifyDataLen == 0)
            {
                if (cipher == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
                {
                    ssl->secureRenegotiationFlag = PS_TRUE;
                }
            }
# endif
            /** If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the
               highest protocol version supported by the server is higher than
               the version indicated in ClientHello.client_version, the server
               MUST respond with a fatal inappropriate_fallback alert.
               @see https://tools.ietf.org/html/rfc7507#section-3 */
            if (cipher == TLS_FALLBACK_SCSV)
            {
                if (ssl->reqMinVer < serverHighestMinor)
                {
                    ssl->err = SSL_ALERT_INAPPROPRIATE_FALLBACK;
                    psTraceInfo("Inappropriate version fallback\n");
                    return MATRIXSSL_ERROR;
                }
            }
        }

        /*      Compression parameters */
        if (end - c < 1)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid compression header length\n");
            return MATRIXSSL_ERROR;
        }
        compLen = *c++;
        if ((uint32) (end - c) < compLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid compression header length\n");
            return MATRIXSSL_ERROR;
        }
        /* Per TLS RFCs proposing null compression is MUST. Check the other end
           has proposed null compression (amongst possible other choices). */
        for (i = 0; i < compLen; i++)
        {
            if (c[i] == COMPRESSION_METHOD_NULL)
            {
                break;
            }
        }
        if (i == compLen)
        {
            /* Note, also catches compLen == 0 */
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("No compression.null proposed\n");
            return MATRIXSSL_ERROR;
        }
# ifdef USE_ZLIB_COMPRESSION
        while (compLen > 0)
        {
            /* Client wants it and we have it.  Enable if we're not already
                in a compression state.  FUTURE: Could be re-handshake */
            if (ssl->compression == 0)
            {
                if (*c++ == 0x01)
                {
                    ssl->inflate.zalloc = NULL;
                    ssl->inflate.zfree = NULL;
                    ssl->inflate.opaque = NULL;
                    ssl->inflate.avail_in = 0;
                    ssl->inflate.next_in = NULL;
                    if (inflateInit(&ssl->inflate) != Z_OK)
                    {
                        psTraceInfo("inflateInit fail.  No compression\n");
                    }
                    else
                    {
                        ssl->deflate.zalloc = Z_NULL;
                        ssl->deflate.zfree = Z_NULL;
                        ssl->deflate.opaque = Z_NULL;
                        if (deflateInit(&ssl->deflate,
                                Z_DEFAULT_COMPRESSION) != Z_OK)
                        {
                            psTraceInfo("deflateInit fail.  No compression\n");
                            inflateEnd(&ssl->inflate);
                        }
                        else
                        {
                            /* Init good.  Let's enable it */
                            ssl->compression = 1;
                        }
                    }
                }
                compLen--;
            }
            else
            {
                c++;
                compLen--;
            }
        }
# else
        c += compLen;
# endif
        rc = parseClientHelloExtensions(ssl, &c, end - c);
        if (rc < 0)
        {
            /* Alerts are set by the extension parse */
            return rc;
        }
    }
    else
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceInfo("SSLV2 CLIENT_HELLO not supported.\n");
        return MATRIXSSL_ERROR;
    }

    /*  ClientHello should be the only one in the record. */
    if (c != end)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceInfo("Invalid final client hello length\n");
        return MATRIXSSL_ERROR;
    }

    /* Look up the session id for ssl session resumption.  If found, we
        load the pre-negotiated masterSecret and cipher.
        A resumed request must meet the following restrictions:
            The id must be present in the lookup table
            The requested version must match the original version
            The cipher suite list must contain the original cipher suite
     */
    if (ssl->sessionIdLen > 0)
    {
        /* Check if we are resuming on a session ticket first.  It is
            legal for a client to send both a session ID and a ticket.  If
            the ticket is used, the session ID should not be used at all */
# ifdef USE_STATELESS_SESSION_TICKETS
        if ((ssl->flags & SSL_FLAGS_RESUMED) && (ssl->sid) &&
            (ssl->sid->sessionTicketState == SESS_TICKET_STATE_USING_TICKET))
        {
            goto SKIP_STANDARD_RESUMPTION;
        }
# endif

        if (matrixResumeSession(ssl) >= 0)
        {
            ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
            ssl->flags |= SSL_FLAGS_RESUMED;
# ifdef USE_MATRIXSSL_STATS
            matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
# endif
        }
        else
        {
            ssl->flags &= ~SSL_FLAGS_RESUMED;
# ifdef USE_STATELESS_SESSION_TICKETS
            /* Client MAY generate and include a  Session ID in the
                TLS ClientHello.  If the server accepts the ticket
                and the Session ID is not empty, then it MUST respond
                with the same Session ID present in the ClientHello. Check
                if client is even using the mechanism though */
            if (ssl->sid)
            {
                if (ssl->sid->sessionTicketState == SESS_TICKET_STATE_INIT)
                {
                    memset(ssl->sessionId, 0, SSL_MAX_SESSION_ID_SIZE);
                    ssl->sessionIdLen = 0;
                }
                else
                {
                    /* This flag means we received a session we can't resume
                        but we have to send it back if we also get a ticket
                        later that we like */
                    ssl->extFlags.session_id = 1;
                }
            }
            else
            {
                memset(ssl->sessionId, 0, SSL_MAX_SESSION_ID_SIZE);
                ssl->sessionIdLen = 0;
            }
# else
            memset(ssl->sessionId, 0, SSL_MAX_SESSION_ID_SIZE);
            ssl->sessionIdLen = 0;
#  ifdef USE_MATRIXSSL_STATS
            matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
#  endif
# endif
        }
    }

# ifdef USE_STATELESS_SESSION_TICKETS
SKIP_STANDARD_RESUMPTION:
# endif

    /* If resumed, confirm the cipher suite was sent.  Otherwise, choose
        the cipher suite based on what the user has loaded or what the user
        sends in the pubkey callback */
    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        /* Have to rewalk ciphers and see if they sent the cipher.  Can
            move suiteStart safely since we'll be the last to use it */
        suiteEnd = suiteStart + suiteLen;
        resumptionOnTrack = 0;
        while (suiteStart < suiteEnd)
        {
            if (ssl->rec.majVer > SSL2_MAJ_VER)
            {
                cipher = *suiteStart << 8; suiteStart++;
                cipher += *suiteStart; suiteStart++;
            }
            else
            {
                ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
                psTraceInfo("SSLV2 not supported.\n");
                return MATRIXSSL_ERROR;
            }
            if (cipher == ssl->cipher->ident)
            {
                resumptionOnTrack = 1;
            }
        }
        if (resumptionOnTrack == 0)
        {
            /* Previous cipher suite wasn't sent for resumption.  This is an
                error according to the specs */
            psTraceIntInfo("Client didn't send cipher %d for resumption\n",
                ssl->cipher->ident);
            ssl->cipher = sslGetCipherSpec(ssl, SSL_NULL_WITH_NULL_NULL);
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        /* User helps pick the cipher based on the key material.  Successful
            end result will be assignment of ssl->cipher */
        if (chooseCipherSuite(ssl, suiteStart, suiteLen) < 0)
        {
            psTraceInfo("Server could not support any client cipher suites\n");
            ssl->cipher = sslGetCipherSpec(ssl, SSL_NULL_WITH_NULL_NULL);
            if (ssl->err != SSL_ALERT_UNRECOGNIZED_NAME)
            {
                ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            }
            return MATRIXSSL_ERROR;
        }
        if (ssl->cipher->ident == 0)
        {
            psTraceInfo("Client attempting SSL_NULL_WITH_NULL_NULL conn\n");
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return MATRIXSSL_ERROR;
        }
    }

    matrixSslSetKexFlags(ssl);

    /* If we're resuming a handshake, then the next handshake message we
        expect is the finished message.  Otherwise we do the full handshake */
    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        ssl->hsState = SSL_HS_FINISHED;
    }
    else
    {
# ifdef USE_DHE_CIPHER_SUITE
        /* If we are DH key exchange we need to generate some keys.  The
            FLAGS_DHE_KEY_EXCH will eventually drive the state matchine to
            the ServerKeyExchange path, but ECDH_ suites need the key gen now */
        if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
        {

#  ifdef USE_ECC_CIPHER_SUITE
            if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
            {
                /* If ecCurveId is zero and we received the extension, then
                    we really couldn't match and can't continue. */
                if (ssl->ecInfo.ecCurveId == 0 &&
                    (ssl->ecInfo.ecFlags & IS_RECVD_EXT))
                {
                    psTraceInfo("Did not share any EC curves with client\n");
                    /* Don't see any particular alert for this case */
                    ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
                    return MATRIXSSL_ERROR;
                }
                /* A ecCurveId of zero (with no extension) will return a
                    default which is fine according to spec */
                if (getEccParamById(ssl->ecInfo.ecCurveId, &curve) < 0)
                {
                    return MATRIXSSL_ERROR;
                }
                if (psEccNewKey(ssl->hsPool, &ssl->sec.eccKeyPriv, curve) < 0)
                {
                    return PS_MEM_FAIL;
                }
#   ifdef USE_ECC_EPHEMERAL_KEY_CACHE
                if ((rc = matrixSslGenEphemeralEcKey(ssl->keys,
                         ssl->sec.eccKeyPriv, curve, pkiData)) < 0)
                {
#   else
                if ((rc = psEccGenKey(ssl->hsPool, ssl->sec.eccKeyPriv,
                         curve, pkiData)) < 0)
                {

#   endif
                    psEccDeleteKey(&ssl->sec.eccKeyPriv);
                    psTraceInfo("GenEphemeralEcc failed\n");
                    ssl->err = SSL_ALERT_INTERNAL_ERROR;
                    return rc;
                }
            }
            else
            {
#  endif    /* USE_ECC_CIPHER_SUITE */
#  ifdef REQUIRE_DH_PARAMS
            /*  Servers using DH suites know DH key sizes when handshake
                pool is created so that has been accounted for here */
            if ((ssl->sec.dhKeyPriv = psMalloc(ssl->hsPool,
                     sizeof(psDhKey_t))) == NULL)
            {
                return MATRIXSSL_ERROR;
            }
            if ((rc = psDhGenKeyInts(ssl->hsPool, ssl->keys->dhParams.size,
                     &ssl->keys->dhParams.p, &ssl->keys->dhParams.g,
                     ssl->sec.dhKeyPriv, pkiData)) < 0)
            {
                psFree(ssl->sec.dhKeyPriv, ssl->hsPool);
                ssl->sec.dhKeyPriv = NULL;
                psTraceInfo("Error generating DH keys\n");
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                return MATRIXSSL_ERROR;
            }
#  endif
#  ifdef USE_ECC_CIPHER_SUITE
        }
#  endif /* USE_ECC_CIPHER_SUITE */
        }
# endif  /* USE_DHE_CIPHER_SUITE */

        ssl->hsState = SSL_HS_CLIENT_KEY_EXCHANGE;
# ifdef USE_CLIENT_AUTH
        /*      Next state in client authentication case is to receive the cert */
        if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
        {
#  ifdef USE_ANON_DH_CIPHER_SUITE
            /* However, what if the server has called for client auth and
                the     client is requesting an 'anon' cipher suite?

                SECURITY:  Options are to default to what the
                client wants, what the server wants, or error out.  The
                current implementation does what the client wants. */
            if (ssl->flags & SSL_FLAGS_ANON_CIPHER)
            {
                psTraceIntInfo(
                    "Anon cipher %d negotiated.  Disabling client auth\n",
                    ssl->cipher->ident);
                ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
            }
            else
            {
#  endif    /* USE_ANON_DH_CIPHER_SUITE */
            ssl->hsState = SSL_HS_CERTIFICATE;
#  ifdef USE_ANON_DH_CIPHER_SUITE
        }
#  endif /* USE_ANON_DH_CIPHER_SUITE */
        }
# endif  /* USE_CLIENT_AUTH */
    }
    /* Now that we've parsed the ClientHello, we need to tell the caller that
        we have a handshake response to write out.
        The caller should call sslWrite upon receiving this return code. */
    *cp = c;
    ssl->decState = SSL_HS_CLIENT_HELLO;
    return SSL_PROCESS_DATA;
}

/******************************************************************************/

int32 parseClientKeyExchange(ssl_t *ssl, int32 hsLen, unsigned char **cp,
    unsigned char *end)
{
    int32 rc, pubKeyLen;
    unsigned char *c;

# ifdef USE_RSA_CIPHER_SUITE
    unsigned char R[SSL_HS_RSA_PREMASTER_SIZE - 2];
    psPool_t *ckepkiPool = NULL;
# endif
# ifdef USE_PSK_CIPHER_SUITE
    uint8_t pskLen;
    unsigned char *pskKey = NULL;
# endif
    void *pkiData = ssl->userPtr;

    c = *cp;

    /*  RSA: This message contains the premaster secret encrypted with the
        server's public key (from the Certificate).  The premaster
        secret is 48 bytes of random data, but the message will be longer
        than that because the 48 bytes are padded before encryption
        according to PKCS#1v1.5.  After encryption, we should have the
        correct length. */
    psTraceHs(">>> Server parsing CLIENT_KEY_EXCHANGE\n");
    if ((int32) (end - c) < hsLen)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid ClientKeyExchange length 1\n");
        return MATRIXSSL_ERROR;
    }

    pubKeyLen = hsLen;
# ifdef USE_TLS
    /*  TLS - Two byte length is explicit. */
    if (ssl->majVer >= TLS_MAJ_VER && ssl->minVer >= TLS_MIN_VER)
    {
        if (end - c < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ClientKeyExchange length 2\n");
            return MATRIXSSL_ERROR;
        }
#  ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            pubKeyLen = *c; c++;
        }
        else
        {
#  endif /* USE_ECC_CIPHER_SUITE */
        pubKeyLen = *c << 8; c++;
        pubKeyLen += *c; c++;
#  ifdef USE_ECC_CIPHER_SUITE
    }
#  endif /* USE_ECC_CIPHER_SUITE */
        if ((int32) (end - c) < pubKeyLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ClientKeyExchange length 3\n");
            return MATRIXSSL_ERROR;
        }
    }
# endif /* USE_TLS */

# ifdef USE_DHE_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
        if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER)
        {
#  ifdef USE_ECC_CIPHER_SUITE
            /* Support ECC ciphers in SSLv3.  This isn't really a desirable
                combination and it's a fuzzy area in the specs but it works */
            if (!(ssl->flags & SSL_FLAGS_ECC_CIPHER))
            {
#  endif
            /*  DH cipher suites use the ClientDiffieHellmanPublic format
                which always includes the explicit key length regardless
                of protocol.  If TLS, we already stripped it out above. */
            if (end - c < 2)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid ClientKeyExchange length 4\n");
                return MATRIXSSL_ERROR;
            }
            pubKeyLen = *c << 8; c++;
            pubKeyLen += *c; c++;
            if ((int32) (end - c) < pubKeyLen)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid ClientKeyExchange length 5\n");
                return MATRIXSSL_ERROR;
            }
#  ifdef USE_ECC_CIPHER_SUITE
        }
        else
        {
            pubKeyLen = *c; c++;
        }
#  endif
        }
#  ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            /*  That initial pubKeyLen we read off the top was actually the
                length of the PSK id that we need to find a key for */
            if ((uint32) (end - c) < pubKeyLen)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid ClientKeyExchange PSK length\n");
                return MATRIXSSL_ERROR;
            }

            /* If there are PSKs loaded, look at those.  Otherwise see if
                there is a callback. */
            if (ssl->keys && ssl->keys->pskKeys)
            {
                matrixSslPskGetKey(ssl, c, pubKeyLen, &pskKey, &pskLen);
            }
            else if (ssl->sec.pskCb)
            {
                (ssl->sec.pskCb)(ssl, c, pubKeyLen, &pskKey, &pskLen);
            }
            if (pskKey == NULL)
            {
                psTraceInfo("Server doesn't not have matching pre-shared key\n");
                ssl->err = SSL_ALERT_UNKNOWN_PSK_IDENTITY;
                return MATRIXSSL_ERROR;
            }
            c += pubKeyLen;
            /* This is the DH pub key now */
            pubKeyLen = *c << 8; c++;
            pubKeyLen += *c; c++;
            if ((uint32) (end - c) < pubKeyLen)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid ClientKeyExchange length\n");
                return MATRIXSSL_ERROR;
            }
        }
#  endif /* USE_PSK_CIPHER_SUITE */

#  ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            if (psEccNewKey(ssl->hsPool, &ssl->sec.eccKeyPub,
                    ssl->sec.eccKeyPriv->curve) < 0)
            {
                return SSL_MEM_ERROR;
            }
            if (psEccX963ImportKey(ssl->hsPool, c, pubKeyLen,
                    ssl->sec.eccKeyPub, ssl->sec.eccKeyPriv->curve) < 0)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                return MATRIXSSL_ERROR;
            }
            /* BUG FIX after 3.8.1a release.  This increment is done later
                in the function.  So in cases where multiple handshake messages
                were put in a single record, we are moving pubKeyLen farther
                than we want which could still be in the valid buffer.
                The error would be an "unexpected handshake message" when
                the next message parse was attempted */
            /* c += pubKeyLen; */

            ssl->sec.premasterSize = ssl->sec.eccKeyPriv->curve->size;
            ssl->sec.premaster = psMalloc(ssl->hsPool,
                ssl->sec.premasterSize);
            if (ssl->sec.premaster == NULL)
            {
                return SSL_MEM_ERROR;
            }
            if ((rc = psEccGenSharedSecret(ssl->hsPool, ssl->sec.eccKeyPriv,
                     ssl->sec.eccKeyPub, ssl->sec.premaster,
                     &ssl->sec.premasterSize, pkiData)) < 0)
            {
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                psFree(ssl->sec.premaster, ssl->hsPool);
                ssl->sec.premaster = NULL;
                return MATRIXSSL_ERROR;
            }
            psEccDeleteKey(&ssl->sec.eccKeyPub);
            psEccDeleteKey(&ssl->sec.eccKeyPriv);
        }
        else
        {
#  endif /* USE_ECC_CIPHER_SUITE */
#  ifdef REQUIRE_DH_PARAMS
        if ((ssl->sec.dhKeyPub = psMalloc(ssl->hsPool, sizeof(psDhKey_t))) == NULL)
        {
            return MATRIXSSL_ERROR;
        }
        if (psDhImportPubKey(ssl->hsPool, c, pubKeyLen,
                ssl->sec.dhKeyPub) < 0)
        {
            psFree(ssl->sec.dhKeyPub, ssl->hsPool);
            ssl->sec.dhKeyPub = NULL;
            return MATRIXSSL_ERROR;
        }
/*
            Now know the premaster details.  Create it.

            A Diffie-Hellman shared secret has, at maximum, the same number of
            bytes as the prime. Use this number as our max buffer size that
            will be     into psDhGenSecret.
 */
        ssl->sec.premasterSize = ssl->sec.dhPLen;

#   ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
/*
                Premaster is appended with the PSK.  Account for that length
                here to avoid a realloc after the standard DH premaster is
                created below.
 */
            ssl->sec.premasterSize += pskLen + 4;         /* psSize_t len heads */
        }
#   endif /* USE_PSK_CIPHER_SUITE */

        ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
        if (ssl->sec.premaster == NULL)
        {
            return SSL_MEM_ERROR;
        }
        if ((rc = psDhGenSharedSecret(ssl->hsPool, ssl->sec.dhKeyPriv,
                 ssl->sec.dhKeyPub, ssl->sec.dhP, ssl->sec.dhPLen,
                 ssl->sec.premaster,
                 &ssl->sec.premasterSize, pkiData)) < 0)
        {
            return MATRIXSSL_ERROR;
        }
        psFree(ssl->sec.dhP, ssl->hsPool);
        ssl->sec.dhP = NULL; ssl->sec.dhPLen = 0;
        psFree(ssl->sec.dhG, ssl->hsPool);
        ssl->sec.dhG = NULL; ssl->sec.dhGLen = 0;
        psDhClearKey(ssl->sec.dhKeyPub);
        psFree(ssl->sec.dhKeyPub, ssl->hsPool);
        ssl->sec.dhKeyPub = NULL;
        psDhClearKey(ssl->sec.dhKeyPriv);
        psFree(ssl->sec.dhKeyPriv, ssl->hsPool);
        ssl->sec.dhKeyPriv = NULL;
#   ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
/*
                Need to prepend a psSize_t length to the premaster key.
 */
            memmove(&ssl->sec.premaster[2], ssl->sec.premaster,
                ssl->sec.premasterSize);
            ssl->sec.premaster[0] = (ssl->sec.premasterSize & 0xFF00) >> 8;
            ssl->sec.premaster[1] = (ssl->sec.premasterSize & 0xFF);
/*
                Next, uint8_t length of PSK and key itself
 */
            ssl->sec.premaster[ssl->sec.premasterSize + 2] = 0;
            ssl->sec.premaster[ssl->sec.premasterSize + 3] = (pskLen & 0xFF);
            memcpy(&ssl->sec.premaster[ssl->sec.premasterSize + 4], pskKey,
                pskLen);
/*
                Lastly, adjust the premasterSize
 */
            ssl->sec.premasterSize += pskLen + 4;
        }
#   endif /* USE_PSK_CIPHER_SUITE */
#  endif  /* REQUIRE_DH_PARAMS */
#  ifdef USE_ECC_CIPHER_SUITE
    }
#  endif /* USE_ECC_CIPHER_SUITE */
    }
    else
    {
# endif  /* USE_DHE_CIPHER_SUITE */
# ifdef USE_PSK_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {

        if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER)
        {
            /* SSLv3 for basic PSK suites will not have read off
                pubKeyLen at this point */
            pubKeyLen = *c << 8; c++;
            pubKeyLen += *c; c++;
        }
        /* If there are PSKs loaded, look at those.  Otherwise see if
           there is a callback. */
        if (ssl->keys && ssl->keys->pskKeys)
        {
            matrixSslPskGetKey(ssl, c, pubKeyLen, &pskKey,
                &pskLen);
        }
        else if (ssl->sec.pskCb)
        {
            if ((ssl->sec.pskCb)(ssl, c, pubKeyLen, &pskKey, &pskLen)
                < 0)
            {
                psTraceInfo("User couldn't find pre-shared key\n");
                ssl->err = SSL_ALERT_UNKNOWN_PSK_IDENTITY;
                return MATRIXSSL_ERROR;
            }
        }
        if (pskKey == NULL)
        {
            psTraceInfo("Server doesn't have matching pre-shared key\n");
            ssl->err = SSL_ALERT_UNKNOWN_PSK_IDENTITY;
            return MATRIXSSL_ERROR;
        }
        ssl->sec.premasterSize = (pskLen * 2) + 4;
        ssl->sec.premaster = psMalloc(ssl->hsPool,
            ssl->sec.premasterSize);
        if (ssl->sec.premaster == NULL)
        {
            return SSL_MEM_ERROR;
        }
        memset(ssl->sec.premaster, 0, ssl->sec.premasterSize);
        ssl->sec.premaster[0] = 0;
        ssl->sec.premaster[1] = (pskLen & 0xFF);
        /* memset to 0 handled middle portion */
        ssl->sec.premaster[2 + pskLen] = 0;
        ssl->sec.premaster[3 + pskLen] = (pskLen & 0xFF);
        memcpy(&ssl->sec.premaster[4 + pskLen], pskKey, pskLen);
    }
    else
    {
# endif
# ifdef USE_ECC_CIPHER_SUITE
    if (ssl->cipher->type == CS_ECDH_ECDSA ||
        ssl->cipher->type == CS_ECDH_RSA)
    {
        if (ssl->majVer == SSL3_MAJ_VER &&
            ssl->minVer == SSL3_MIN_VER)
        {
            /* Support ECC ciphers in SSLv3.  This isn't really a
                desirable combination and it's a fuzzy area in the
                specs but it works */
            pubKeyLen = *c; c++;
        }
        if (ssl->keys == NULL)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return MATRIXSSL_ERROR;
        }
        if (psEccNewKey(ssl->hsPool, &ssl->sec.eccKeyPub,
                ssl->keys->privKey.key.ecc.curve) < 0)
        {
            return SSL_MEM_ERROR;
        }
        if (psEccX963ImportKey(ssl->hsPool, c, pubKeyLen,
                ssl->sec.eccKeyPub, ssl->keys->privKey.key.ecc.curve)
            < 0)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            return MATRIXSSL_ERROR;
        }
        /* BUG FIX after 3.8.1a release.  This increment is done
            later in the function.  So in cases where multiple
            handshake messages were put in a single record, we are
            moving pubKeyLen farther than we want which could still
            be in the valid buffer. The error would be an
            "unexpected handshake message" when the next message
            parse was attempted */
        /* c += pubKeyLen; */

        ssl->sec.premasterSize =
            ssl->keys->privKey.key.ecc.curve->size;
        ssl->sec.premaster = psMalloc(ssl->hsPool,
            ssl->sec.premasterSize);
        if (ssl->sec.premaster == NULL)
        {
            return SSL_MEM_ERROR;
        }
        if ((rc = psEccGenSharedSecret(ssl->hsPool,
                 &ssl->keys->privKey.key.ecc, ssl->sec.eccKeyPub,
                 ssl->sec.premaster, &ssl->sec.premasterSize,
                 pkiData)) < 0)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            psFree(ssl->sec.premaster, ssl->hsPool);
            ssl->sec.premaster = NULL;
            return MATRIXSSL_ERROR;
        }
        psEccDeleteKey(&ssl->sec.eccKeyPub);
    }
    else
    {
# endif /* USE_ECC_CIPHER_SUITE */

# ifdef USE_RSA_CIPHER_SUITE
    if (ssl->keys == NULL)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return MATRIXSSL_ERROR;
    }
    /*  Standard RSA suite. Now have a handshake pool to allocate
        the premaster storage */
    ssl->sec.premasterSize = SSL_HS_RSA_PREMASTER_SIZE;
    ssl->sec.premaster = psMalloc(ssl->hsPool,
        SSL_HS_RSA_PREMASTER_SIZE);
    if (ssl->sec.premaster == NULL)
    {
        return SSL_MEM_ERROR;
    }

/**
                @security Caution - the results of an RSA private key
                decryption should never have any bearing on timing or response,
                otherwise we can be vulnerable to a side channel attack.
                @see http://web-in-security.blogspot.co.at/2014/08/old-attacks-on-new-tls-implementations.html
                @see https://tools.ietf.org/html/rfc5246#section-7.4.7.1
                "In any case, a TLS server MUST NOT generate an alert if processing an
                RSA-encrypted premaster secret message fails, or the version number
                is not as expected.  Instead, it MUST continue the handshake with a
                randomly generated premaster secret.  It may be useful to log the
                real cause of failure for troubleshooting purposes; however, care
                must be taken to avoid leaking the information to an attacker
                (through, e.g., timing, log files, or other channels.)"
 */
    rc = psRsaDecryptPriv(ckepkiPool, &ssl->keys->privKey.key.rsa, c,
        pubKeyLen, ssl->sec.premaster, ssl->sec.premasterSize,
        pkiData);
    /* Step 1 of Bleichenbacher attack mitigation. We do it here
       after the RSA op, but regardless of the result of the op. */
    if (psGetPrngLocked(R, sizeof(R), ssl->userPtr) < 0)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return MATRIXSSL_ERROR;
    }

    /* Step 3
       If the PKCS#1 padding is not correct, or the length of message
       M is not exactly 48 bytes:
        pre_master_secret = ClientHello.client_version || R
       else
        pre_master_secret = ClientHello.client_version || M[2..47]

       Note that explicitly constructing the pre_master_secret with the
       ClientHello.client_version produces an invalid master_secret if the
       client has sent the wrong version in the original pre_master_secret.

       Note: The version number in the PreMasterSecret is the version
       offered by the client in the ClientHello.client_version, not the
       version negotiated for the connection.  This feature is designed to
       prevent rollback attacks.  Unfortunately, some old implementations
       use the negotiated version instead, and therefore checking the
       version number may lead to failure to interoperate with such
       incorrect client implementations. This is known in OpenSSL as the
       SSL_OP_TLS_ROLLBACK_BUG. MatrixSSL doesn't support these
       incorrect implementations.
     */
    ssl->sec.premaster[0] = ssl->reqMajVer;
    ssl->sec.premaster[1] = ssl->reqMinVer;
    if (rc < 0)
    {
        memcpy(ssl->sec.premaster + 2, R, sizeof(R));
    }
    else
    {
        /* Not necessary, but keep timing similar */
        memcpy(R, ssl->sec.premaster + 2, sizeof(R));
    }

    /* R may contain sensitive data, eg. premaster */
    memzero_s(R, sizeof(R));

# else /* RSA is the 'default' so if that didn't get hit there is a problem */
    psTraceInfo("There is no handler for ClientKeyExchange parse. ERROR\n");
    return MATRIXSSL_ERROR;
# endif /* USE_RSA_CIPHER_SUITE */
# ifdef USE_ECC_CIPHER_SUITE
}
# endif /* USE_ECC_CIPHER_SUITE */
# ifdef USE_PSK_CIPHER_SUITE
}
# endif /* USE_PSK_CIPHER_SUITE */
# ifdef USE_DHE_CIPHER_SUITE
}
# endif /* USE_DHE_CIPHER_SUITE */

    /*  Now that we've got the premaster secret, derive the various
        symmetric keys using it and the client and server random values.
        Update the cached session (if found) with the masterSecret and
        negotiated cipher. */
    if (ssl->extFlags.extended_master_secret == 1)
    {
        if (tlsExtendedDeriveKeys(ssl) < 0)
        {
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        if (sslCreateKeys(ssl) < 0)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return MATRIXSSL_ERROR;
        }
    }
    matrixUpdateSession(ssl);

    c += pubKeyLen;
    ssl->hsState = SSL_HS_FINISHED;

# ifdef USE_DTLS
    /*  The freeing of premaster and cert were not done at the normal time
        because of the retransmit scenarios.  This is server side */
    if (ssl->sec.premaster)
    {
        psFree(ssl->sec.premaster, ssl->hsPool); ssl->sec.premaster = NULL;
        ssl->sec.premasterSize = 0;
    }
# endif /* USE_DTLS */

# ifdef USE_CLIENT_AUTH
    /* In the non client auth case, we are done with the handshake pool */
    if (!(ssl->flags & SSL_FLAGS_CLIENT_AUTH))
    {
#  ifdef USE_DTLS
#   ifndef USE_ONLY_PSK_CIPHER_SUITE
        if (ssl->sec.cert)
        {
            psFree(ssl->sec.cert, NULL); ssl->sec.cert = NULL;
        }
#   endif
        if (ssl->ckeMsg != NULL)
        {
            psFree(ssl->ckeMsg, ssl->hsPool); ssl->ckeMsg = NULL;
        }
#  endif /* USE_DTLS */
        ssl->hsPool = NULL;
    }
# else /* CLIENT_AUTH */
#  ifdef USE_DTLS
    if (ssl->ckeMsg != NULL)
    {
        psFree(ssl->ckeMsg, ssl->hsPool); ssl->ckeMsg = NULL;
    }
#  endif /* USE_DTLS */
    ssl->hsPool = NULL;
# endif


# ifdef USE_CLIENT_AUTH
    /* Tweak the state here for client authentication case */
    if (ssl->flags & SSL_FLAGS_CLIENT_AUTH)
    {
        ssl->hsState = SSL_HS_CERTIFICATE_VERIFY;
    }
# endif /* USE_CLIENT_AUTH */

    *cp = c;
    ssl->decState = SSL_HS_CLIENT_KEY_EXCHANGE;
    return PS_SUCCESS;
}

/******************************************************************************/

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  ifdef USE_CLIENT_AUTH
int32 parseCertificateVerify(ssl_t *ssl,
    unsigned char hsMsgHash[SHA512_HASH_SIZE],
    unsigned char **cp, unsigned char *end)
{
    uint32 certVerifyLen, pubKeyLen;
    int32 rc, i;

#   ifdef USE_RSA
    unsigned char certVerify[SHA512_HASH_SIZE];
#   endif /* USE_RSA */
    unsigned char *c;
    psPool_t *cvpkiPool = NULL;
    void *pkiData = ssl->userPtr;

    c = *cp;
    rc = 0;
    PS_VARIABLE_SET_BUT_UNUSED(rc); /* Note: Only used ifdef USE_ECC. */
    psTraceHs(">>> Server parsing CERTIFICATE_VERIFY message\n");

#   ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        uint32_t hashSigAlg;

        if ((uint32) (end - c) < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid Certificate Verify message\n");
            return MATRIXSSL_ERROR;
        }
        hashSigAlg = HASH_SIG_MASK(c[0], c[1]);

        /* The server-sent algorithms has to be one of the ones we sent in
           our ClientHello extension */
        if (!(ssl->hashSigAlg & hashSigAlg))
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid SigHash\n");
            return MATRIXSSL_ERROR;
        }

        switch (c[0])
        {

        case HASH_SIG_SHA256:
            certVerifyLen = SHA256_HASH_SIZE;
            break;

#    ifdef USE_SHA384
        case HASH_SIG_SHA384:
            /* The one-off grab of SHA-384 handshake hash */
            sslSha384RetrieveHSHash(ssl, hsMsgHash);
            certVerifyLen = SHA384_HASH_SIZE;
            break;
#    endif

#    ifdef USE_SHA512
        case HASH_SIG_SHA512:
            /* The one-off grab of SHA-512 handshake hash */
            sslSha512RetrieveHSHash(ssl, hsMsgHash);
            certVerifyLen = SHA512_HASH_SIZE;
            break;
#    endif

#    ifdef USE_SHA1
        case HASH_SIG_SHA1:
            /* The one-off grab of SHA-1 handshake hash */
            sslSha1RetrieveHSHash(ssl, hsMsgHash);
            certVerifyLen = SHA1_HASH_SIZE;
            break;
#    endif
        default:
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid Certificate Verify message\n");
            return MATRIXSSL_ERROR;
        }
        c += 2;
    }
    else
    {
        certVerifyLen =  MD5_HASH_SIZE + SHA1_HASH_SIZE;
    }
#   else
    certVerifyLen =  MD5_HASH_SIZE + SHA1_HASH_SIZE;
#   endif /* USE_TLS_1_2 */

    if ((uint32) (end - c) < 2)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid Certificate Verify message\n");
        return MATRIXSSL_ERROR;
    }
    pubKeyLen = *c << 8; c++;
    pubKeyLen |= *c; c++;
    if ((uint32) (end - c) < pubKeyLen)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid Certificate Verify message\n");
        return MATRIXSSL_ERROR;
    }
    /*  The server side verification of client identity.  If we can match
        the signature we know the client has possesion of the private key. */
#   ifdef USE_ECC
    /* Need to read sig algorithm type out of cert itself */
    if (ssl->sec.cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        rc = 0;

#    ifdef USE_TLS_1_2
        if (ssl->flags & SSL_FLAGS_TLS_1_2)
        {
            if ((i = psEccDsaVerify(cvpkiPool,
                     &ssl->sec.cert->publicKey.key.ecc,
                     hsMsgHash, certVerifyLen,
                     c, pubKeyLen, &rc, pkiData)) != 0)
            {
                psTraceInfo("ECDSA signature validation failed\n");
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                return MATRIXSSL_ERROR;
            }
        }
        else
        {
            certVerifyLen = SHA1_HASH_SIZE; /* per spec */
            if ((i = psEccDsaVerify(cvpkiPool,
                     &ssl->sec.cert->publicKey.key.ecc,
                     hsMsgHash + MD5_HASH_SIZE, certVerifyLen,
                     c, pubKeyLen,
                     &rc, pkiData)) != 0)
            {
                psTraceInfo("ECDSA signature validation failed\n");
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                return MATRIXSSL_ERROR;
            }
        }
#    else
        certVerifyLen = SHA1_HASH_SIZE; /* per spec */
        if ((i = psEccDsaVerify(cvpkiPool,
                 &ssl->sec.cert->publicKey.key.ecc,
                 hsMsgHash + MD5_HASH_SIZE, certVerifyLen,
                 c, pubKeyLen,
                 &rc, pkiData)) != 0)
        {
            psTraceInfo("ECDSA signature validation failed\n");
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            return MATRIXSSL_ERROR;
        }
#    endif
        if (rc != 1)
        {
            psTraceInfo("Can't verify certVerify sig\n");
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            return MATRIXSSL_ERROR;
        }
        rc = MATRIXSSL_SUCCESS; /* done using rc as a temp */
    }
    else
    {
#   endif /* USE_ECC */
#   ifdef USE_RSA

#    ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        if ((i = pubRsaDecryptSignedElement(cvpkiPool,
                 &ssl->sec.cert->publicKey.key.rsa, c, pubKeyLen, certVerify,
                 certVerifyLen, pkiData)) < 0)
        {
            psTraceInfo("Unable to decrypt CertVerify digital element\n");
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        if ((i = psRsaDecryptPub(cvpkiPool, &ssl->sec.cert->publicKey.key.rsa, c,
                 pubKeyLen, certVerify, certVerifyLen, pkiData)) < 0)
        {
            psTraceInfo("Unable to publicly decrypt Certificate Verify message\n");
            return MATRIXSSL_ERROR;
        }
    }
#    else /* !USE_TLS_1_2 */
    if ((i = psRsaDecryptPub(cvpkiPool, &ssl->sec.cert->publicKey.key.rsa, c,
             pubKeyLen, certVerify, certVerifyLen, pkiData)) < 0)
    {
        psTraceInfo("Unable to publicly decrypt Certificate Verify message\n");
        return MATRIXSSL_ERROR;
    }
#    endif /* USE_TLS_1_2 */

    if (memcmpct(certVerify, hsMsgHash, certVerifyLen) != 0)
    {
        psTraceInfo("Unable to verify client certificate signature\n");
        return MATRIXSSL_ERROR;
    }
#   else /* RSA is 'default' so if that didn't get hit there is a problem */
    psTraceInfo("There is no handler for CertificateVerify parse. ERROR\n");
    return MATRIXSSL_ERROR;
#   endif /* USE_RSA */
#   ifdef USE_ECC
}
#   endif /* USE_ECC*/

    c += pubKeyLen;
    ssl->hsState = SSL_HS_FINISHED;

    *cp = c;
    ssl->decState = SSL_HS_CERTIFICATE_VERIFY;
    return PS_SUCCESS;
}
#  endif /* !USE_ONLY_PSK_CIPHER_SUITE */
# endif  /* USE_ONLY_PSK_CIPHER_SUITE */
#endif   /* USE_SERVER_SIDE_SSL */

/******************************************************************************/

#ifdef USE_CLIENT_SIDE_SSL
int32 parseServerHello(ssl_t *ssl, int32 hsLen, unsigned char **cp,
    unsigned char *end)
{
    uint32 sessionIdLen, cipher = 0;
    int32 rc;
    unsigned char *extData;
    unsigned char *c;

    c = *cp;

    psTraceHs(">>> Client parsing SERVER_HELLO message\n");
# ifdef USE_MATRIXSSL_STATS
    matrixsslUpdateStat(ssl, SH_RECV_STAT, 1);
# endif
    /* Need to track hsLen because there is no explict  way to tell if
        hello extensions are appended so it isn't clear if the record data
        after the compression parameters are a new message or extension data */
    extData = c;

# ifdef USE_DTLS
    /*  Know now that the allocated members that were helping with the
        HELLO_VERIFY_REQUEST exchange have finished serving their purpose */
    if (ssl->cookie)
    {
        psFree(ssl->cookie, ssl->hsPool); ssl->cookie = NULL;
        ssl->cookieLen = 0; ssl->haveCookie = 0;
    }
    if (ssl->helloExt)
    {
        psFree(ssl->helloExt, ssl->hsPool); ssl->helloExt = NULL;
        ssl->helloExtLen = 0;
    }
# endif /* USE_DTLS */

    /*  First two bytes are the negotiated SSL version */
    if (end - c < 2)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid ssl header version length\n");
        return MATRIXSSL_ERROR;
    }
    ssl->reqMajVer = *c; c++;
    ssl->reqMinVer = *c; c++;
    if (ssl->reqMajVer != ssl->majVer)
    {
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceIntInfo("Unsupported ssl version: %d\n", ssl->reqMajVer);
        return MATRIXSSL_ERROR;
    }

# ifdef USE_TLS
    /* See if the protocol is being downgraded */
    if (ssl->reqMinVer != ssl->minVer)
    {
        if (ssl->reqMinVer == SSL3_MIN_VER && ssl->minVer >= TLS_MIN_VER)
        {
#  ifdef DISABLE_SSLV3
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceInfo("Server wants to talk SSLv3 but it's disabled\n");
            return MATRIXSSL_ERROR;
#  else
            /*  Server minVer now becomes OUR initial requested version.
                This is used during the creation of the premaster where
                this initial requested version is part of the calculation.
                The RFC actually says to use the original requested version
                but no implemenations seem to follow that and just use the
                agreed upon one. */
            ssl->reqMinVer = ssl->minVer;
            ssl->minVer = SSL3_MIN_VER;
            ssl->flags &= ~SSL_FLAGS_TLS;
#   ifdef USE_TLS_1_1
            ssl->flags &= ~SSL_FLAGS_TLS_1_1;
#   endif   /* USE_TLS_1_1 */
#   ifdef USE_TLS_1_2
            ssl->flags &= ~SSL_FLAGS_TLS_1_2;
#   endif /* USE_TLS_1_2 */
#  endif  /* DISABLE_SSLV3 */
        }
        else
        {
#  ifdef USE_TLS_1_1
#   ifdef USE_TLS_1_2
            /* Step down one at a time */
            if (ssl->reqMinVer < TLS_1_2_MIN_VER &&
                (ssl->flags & SSL_FLAGS_TLS_1_2))
            {
                ssl->flags &= ~SSL_FLAGS_TLS_1_2;
                if (ssl->reqMinVer == TLS_1_1_MIN_VER)
                {
#    ifdef DISABLE_TLS_1_1
                    ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                    psTraceInfo("Server wants to talk TLS1.1 but it's disabled\n");
                    return MATRIXSSL_ERROR;
#    else
                    ssl->reqMinVer = ssl->minVer;
                    ssl->minVer = TLS_1_1_MIN_VER;
                    goto PROTOCOL_DETERMINED;
#    endif
                }
            }
#   endif   /* USE_TLS_1_2 */
            if (ssl->reqMinVer == TLS_MIN_VER &&
                ssl->minVer <= TLS_1_2_MIN_VER)
            {
#   ifdef DISABLE_TLS_1_0
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                psTraceInfo("Server wants to talk TLS1.0 but it's disabled\n");
                return MATRIXSSL_ERROR;
#   else
                ssl->reqMinVer = ssl->minVer;
                ssl->minVer = TLS_MIN_VER;
                ssl->flags &= ~SSL_FLAGS_TLS_1_1;
#   endif
            }
            else
            {
#  endif    /* USE_TLS_1_1 */
#  ifdef USE_DTLS
            /* Tests for DTLS downgrades */
            if (ssl->flags & SSL_FLAGS_DTLS)
            {
                if (ssl->reqMinVer == DTLS_MIN_VER &&
                    ssl->minVer == DTLS_1_2_MIN_VER)
                {
                    ssl->reqMinVer = ssl->minVer;
                    ssl->minVer = DTLS_MIN_VER;
                    ssl->flags &= ~SSL_FLAGS_TLS_1_2;
                    goto PROTOCOL_DETERMINED;
                }
            }
#  endif
            /* Wasn't able to settle on a common protocol */
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceIntInfo("Unsupported ssl version: %d\n",
                ssl->reqMajVer);
            return MATRIXSSL_ERROR;
#  ifdef USE_TLS_1_1
        }
#  endif    /* USE_TLS_1_1 */
        }
    }
# endif /* USE_TLS */

# if (defined (USE_TLS_1_2) && !defined(DISABLE_TLS_1_1)) || defined (USE_DTLS)
PROTOCOL_DETERMINED:
# endif /* (USE_TLS_1_2 && !DISABLE_TLS_1_1) || USE_DTLS */

    /*  Next is a 32 bytes of random data for key generation
        and a single byte with the session ID length */
    if (end - c < SSL_HS_RANDOM_SIZE + 1)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid length of random data\n");
        return MATRIXSSL_ERROR;
    }
    memcpy(ssl->sec.serverRandom, c, SSL_HS_RANDOM_SIZE);
    c += SSL_HS_RANDOM_SIZE;
    sessionIdLen = *c; c++;
    if (sessionIdLen > SSL_MAX_SESSION_ID_SIZE ||
        (uint32) (end - c) < sessionIdLen)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        return MATRIXSSL_ERROR;
    }
    /*  If a session length was specified, the server has sent us a
        session Id.  We may have requested a specific session, and the
        server may or may not agree to use that session. */
    if (sessionIdLen > 0)
    {
        if (ssl->sessionIdLen > 0)
        {
            if (memcmp(ssl->sessionId, c, sessionIdLen) == 0)
            {
                ssl->flags |= SSL_FLAGS_RESUMED;
            }
            else
            {
                ssl->cipher = sslGetCipherSpec(ssl, SSL_NULL_WITH_NULL_NULL);
                memset(ssl->sec.masterSecret, 0x0, SSL_HS_MASTER_SIZE);
                ssl->sessionIdLen = (unsigned char) sessionIdLen;
                memcpy(ssl->sessionId, c, sessionIdLen);
                ssl->flags &= ~SSL_FLAGS_RESUMED;
# ifdef USE_MATRIXSSL_STATS
                matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
# endif
            }
# ifdef USE_EAP_FAST /* TODO Could also do this for any TICKET */
            if (ssl->sid->sessionTicketState == SESS_TICKET_STATE_SENT_TICKET)
            {
                if (ssl->flags & SSL_FLAGS_RESUMED)
                {
                    /* The server has accepted our session ticket, and indicated that
                        by echoing the random session id we sent. */
                    ssl->extFlags.eap_fast_master_secret = 1;
                    /* TODO could derive eap keys here */
                }
                else
                {
                    /* The server isn't going to use our ticket. But may still
                        send a ticket extension and (possibly blank) ticket message */
                    ssl->extFlags.eap_fast_master_secret = 0;
                }
            }
# endif
        }
        else
        {
            ssl->sessionIdLen = (unsigned char) sessionIdLen;
            memcpy(ssl->sessionId, c, sessionIdLen);
        }
        c += sessionIdLen;
    }
    else
    {
        if (ssl->sessionIdLen > 0)
        {
            ssl->cipher = sslGetCipherSpec(ssl, SSL_NULL_WITH_NULL_NULL);
            memset(ssl->sec.masterSecret, 0x0, SSL_HS_MASTER_SIZE);
            ssl->sessionIdLen = 0;
            memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
            ssl->flags &= ~SSL_FLAGS_RESUMED;
# ifdef USE_MATRIXSSL_STATS
            matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
# endif
        }
    }
    /* Next is the two byte cipher suite */
    if (end - c < 2)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid cipher suite length\n");
        return MATRIXSSL_ERROR;
    }
    cipher = *c << 8; c++;
    cipher += *c; c++;

    /*  A resumed session can only match the cipher originally
        negotiated. Otherwise, match the first cipher that we support */
    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        psAssert(ssl->cipher != NULL);
        if (ssl->cipher->ident != cipher)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            psTraceInfo("Can't support resumed cipher\n");
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
        if ((ssl->cipher = sslGetCipherSpec(ssl, cipher)) == NULL)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            psTraceIntInfo("Can't support requested cipher: %d\n", cipher);
            return MATRIXSSL_ERROR;
        }
    }
    matrixSslSetKexFlags(ssl);

    /* Decode the compression parameter byte. */
# define COMPRESSION_METHOD_NULL     0x0
# define COMPRESSION_METHOD_DEFLATE  0x1
    if (end - c < 1)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceInfo("Expected compression value\n");
        return MATRIXSSL_ERROR;
    }
    switch (*c)
    {
    case COMPRESSION_METHOD_NULL:
        /* No compression */
        break;
# ifdef USE_ZLIB_COMPRESSION
    case COMPRESSION_METHOD_DEFLATE:
        ssl->inflate.zalloc = NULL;
        ssl->inflate.zfree = NULL;
        ssl->inflate.opaque = NULL;
        ssl->inflate.avail_in = 0;
        ssl->inflate.next_in = NULL;
        if (inflateInit(&ssl->inflate) != Z_OK)
        {
            psTraceInfo("inflateInit fail. No compression\n");
        }
        else
        {
            ssl->deflate.zalloc = Z_NULL;
            ssl->deflate.zfree = Z_NULL;
            ssl->deflate.opaque = Z_NULL;
            if (deflateInit(&ssl->deflate, Z_DEFAULT_COMPRESSION) != Z_OK)
            {
                psTraceInfo("deflateInit fail.  No compression\n");
                inflateEnd(&ssl->inflate);
            }
            else
            {
                ssl->compression = 1; /* Both contexts initialized */
            }
        }
        break;
# endif /* USE_ZLIB_COMPRESSION */
    default:
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("zlib compression not enabled.\n");
        return MATRIXSSL_ERROR;
    }
    /*  At this point, if we're resumed, we have all the required info
        to derive keys.  The next handshake message we expect is
        the Finished message.
        After incrementing c below, we will either be pointing at 'end'
        with no more data in the message, or at the first byte of an optional
        extension. */
    c++;

    /*  If our sent ClientHello had an extension there could be extension data
        to parse here:  http://www.faqs.org/rfcs/rfc3546.html

        The explict test on hsLen is necessary for TLS 1.0 and 1.1 because
        there is no good way to tell if the remaining record data is the
        next handshake message or if it is extension data */
    if (c != end && ((int32) hsLen > (c - extData)))
    {
        rc = parseServerHelloExtensions(ssl, hsLen, extData, &c, c - end);
        if (rc < 0)
        {
            /* Alerts will already have been set inside */
            return rc;
        }
    }

# ifdef USE_OCSP_MUST_STAPLE
    /* Will catch cases where a server does not send any extensions at all */
    if (ssl->extFlags.req_status_request == 1)
    {
        if (ssl->extFlags.status_request == 0)
        {
            psTraceInfo("Server doesn't support OCSP stapling\n");
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            return MATRIXSSL_ERROR;
        }
    }
# endif

    if (ssl->maxPtFrag & 0x10000 || ssl->extFlags.req_max_fragment_len)
    {
        /* Server didn't respond to our MAX_FRAG request. Reset default */
        psTraceInfo("Server ignored max fragment length ext request\n");
        ssl->maxPtFrag = SSL_MAX_PLAINTEXT_LEN;
    }

    if (ssl->extFlags.req_sni)
    {
        psTraceInfo("Server ignored SNI ext request\n");
    }

# ifdef USE_STATELESS_SESSION_TICKETS
    if (ssl->sid &&
        ssl->sid->sessionTicketState == SESS_TICKET_STATE_SENT_TICKET)
    {
        /*
            Server did not send an extension reply to our populated ticket.

            From the updated RFC 5077:

            "It is also permissible to have an exchange using the
            abbreviated handshake defined in Figure 2 of RFC 4346, where
            the client uses the SessionTicket extension to resume the
            session, but the server does not wish to issue a new ticket,
            and therefore does not send a SessionTicket extension."

            Lame.  We don't get an indication that the server accepted or
            rejected our ticket until we see the next handshake message.
            If they accepted it we'll see a ChangeCipherSpec message and
            if they rejected it we'll see a Certificate message.  Let's
            flag this case of a non-response and handle it in the CCS parse.

            TODO - could also send a sessionId and see if it is returned here.
            Spec requires the same sessionId to be returned if ticket is accepted.
         */
        ssl->sid->sessionTicketState = SESS_TICKET_STATE_IN_LIMBO;
    }
# endif /* USE_STATELESS_SESSION_TICKETS        */


# if 0 /* TODO moved to extDecode:parseServerHelloExtensions */
#  ifdef ENABLE_SECURE_REHANDSHAKES
    if (renegotiationExt == 0)
    {
#   ifdef REQUIRE_SECURE_REHANDSHAKES
        ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
        psTraceInfo("Srv doesn't support renegotiationInfo\n");
        return MATRIXSSL_ERROR;
#   else
        if (ssl->secureRenegotiationFlag == PS_TRUE)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            psTraceInfo("Srv didn't send renegotiationInfo on re-hndshk\n");
            return MATRIXSSL_ERROR;
        }
#    ifndef ENABLE_INSECURE_REHANDSHAKES
        /*      This case can only be hit if ENABLE_SECURE is on because otherwise
            we wouldn't even have got this far because both would be off. */
        if (ssl->secureRenegotiationFlag == PS_FALSE &&
            ssl->myVerifyDataLen > 0)
        {
            ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
            psTraceInfo("Srv attempting insecure renegotiation\n");
            return MATRIXSSL_ERROR;
        }
#    endif /* !ENABLE_SECURE_REHANDSHAKES */
#   endif  /* REQUIRE_SECURE_REHANDSHAKES */
    }
#  endif   /* ENABLE_SECURE_REHANDSHAKES */
# endif

    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        if (sslCreateKeys(ssl) < 0)
        {
            ssl->err = SSL_ALERT_INTERNAL_ERROR;
            return MATRIXSSL_ERROR;
        }
        ssl->hsState = SSL_HS_FINISHED;
    }
    else
    {
        ssl->hsState = SSL_HS_CERTIFICATE;
# ifdef USE_ANON_DH_CIPHER_SUITE
        /* Anonymous DH uses SERVER_KEY_EXCHANGE message to send key params */
        if (ssl->flags & SSL_FLAGS_ANON_CIPHER)
        {
            ssl->hsState = SSL_HS_SERVER_KEY_EXCHANGE;
        }
# endif /* USE_ANON_DH_CIPHER_SUITE */
# ifdef USE_PSK_CIPHER_SUITE
        /* PSK ciphers never send a CERTIFICATE message. */
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            ssl->hsState = SSL_HS_SERVER_KEY_EXCHANGE;
        }
# endif /* USE_PSK_CIPHER_SUITE */
    }

    *cp = c;
    ssl->decState = SSL_HS_SERVER_HELLO;
    return PS_SUCCESS;
}

/******************************************************************************/

int32 parseServerKeyExchange(ssl_t *ssl,
    unsigned char hsMsgHash[SHA512_HASH_SIZE],
    unsigned char **cp, unsigned char *end)
{
    unsigned char *c;

# ifdef USE_DHE_CIPHER_SUITE
    int32 i;
    uint32 pubDhLen, hashSize;
    psPool_t *skepkiPool = NULL;
#  ifndef USE_ONLY_PSK_CIPHER_SUITE
    psDigestContext_t digestCtx;
    unsigned char *sigStart = NULL, *sigStop = NULL;
#  endif /* USE_ONLY_PSK_CIPHER_SUITE */
#  ifdef USE_TLS_1_2
    uint32 skeHashSigAlg;
#  endif
#  ifdef USE_RSA_CIPHER_SUITE
    unsigned char sigOut[MAX_HASH_SIZE];
#  endif
#  ifdef USE_ECC_CIPHER_SUITE
    uint32 res;
    const psEccCurve_t *curve;
#  endif
    void *pkiData = ssl->userPtr;

# endif /* USE_DHE_CIPHER_SUITE */

    c = *cp;

    psTraceHs(">>> Client parsing SERVER_KEY_EXCHANGE message\n");
# ifdef USE_DHE_CIPHER_SUITE
    /*  Check the DH status.  Could also be a PSK_DHE suite */
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {

#  ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
            /* Using the value of MAX_HINT_SIZE to know if the user is
                expecting a hint.  The PSK specification ONLY allows these
                hints if the "application profile specification" says to
                include them.

                Contact Support if you require assistance here  */
            if (SSL_PSK_MAX_HINT_SIZE > 0)
            {
                if ((end - c) < 2)
                {
                    ssl->err = SSL_ALERT_DECODE_ERROR;
                    psTraceInfo("Invalid PSK Hint Len\n");
                    return MATRIXSSL_ERROR;
                }
                ssl->sec.hintLen = *c << 8; c++;
                ssl->sec.hintLen |= *c; c++;
                if (ssl->sec.hintLen > 0)
                {
                    if ((unsigned short) (end - c) < ssl->sec.hintLen)
                    {
                        ssl->err = SSL_ALERT_DECODE_ERROR;
                        psTraceInfo("Invalid PSK Hint\n");
                        return MATRIXSSL_ERROR;
                    }
                    ssl->sec.hint = psMalloc(ssl->hsPool, ssl->sec.hintLen);
                    if (ssl->sec.hint == NULL)
                    {
                        return SSL_MEM_ERROR;
                    }
                    memcpy(ssl->sec.hint, c, ssl->sec.hintLen);
                    c += ssl->sec.hintLen;
                }
            }
        }
#  endif /* USE_PSK_CIPHER_SUITE */
#  ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            /* Entry point for ECDHE SKE parsing */
            sigStart = c;
            if ((end - c) < 4)       /* ECCurveType, NamedCurve, ECPoint len */
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid ServerKeyExchange message\n");
                return MATRIXSSL_ERROR;
            }
/*
                Only named curves are currently supported

                enum { explicit_prime (1), explicit_char2 (2),
                    named_curve (3), reserved(248..255) } ECCurveType;
 */
            if ((int32) * c != 3)
            {
                ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                psTraceIntInfo("Unsupported ECCurveType message %d\n",
                    (int32) * c);
                return MATRIXSSL_ERROR;
            }
            c++;

            /* Next is curveId */
            i = *c << 8; c++;
            i |= *c; c++;

            /* Return -1 if this isn't a curve we specified in client hello */
            if (getEccParamById(i, &curve) < 0)
            {
                ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                psTraceIntInfo("Error: Could not match EC curve: %d\n", i);
                return MATRIXSSL_ERROR;
            }
/*
                struct {
                    opaque point <1..2^8-1>;
                } ECPoint;

                RFC4492
                This is the byte string representation of an elliptic curve
                point following the conversion routine in Section 4.3.6 of ANSI
                X9.62.  This byte string may represent an elliptic curve point
                in uncompressed or compressed format; it MUST conform to what
                client has requested through a Supported Point Formats Extension
                if this extension was used.
 */
            i = *c; c++;
            if ((end - c) < i)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                psTraceInfo("Invalid ServerKeyExchange message\n");
                return MATRIXSSL_ERROR;
            }
            if (psEccNewKey(ssl->hsPool, &ssl->sec.eccKeyPub, curve) < 0)
            {
                return SSL_MEM_ERROR;
            }
            if (psEccX963ImportKey(ssl->hsPool, c, i,
                    ssl->sec.eccKeyPub, curve) < 0)
            {
                ssl->err = SSL_ALERT_DECODE_ERROR;
                return MATRIXSSL_ERROR;
            }
            c += i;
            sigStop = c;

        }
        else
        {
#  endif /* USE_ECC_CIPHER_SUITE */
#  ifdef REQUIRE_DH_PARAMS
        /* Entry point for standard DH SKE parsing */
        if ((end - c) < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }
#   ifndef USE_ONLY_PSK_CIPHER_SUITE
        sigStart = c;
#   endif
        ssl->sec.dhPLen = *c << 8; c++;
        ssl->sec.dhPLen |= *c; c++;
        if ((uint32) (end - c) < ssl->sec.dhPLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }
        ssl->sec.dhP = psMalloc(ssl->hsPool, ssl->sec.dhPLen);
        if (ssl->sec.dhP == NULL)
        {
            return SSL_MEM_ERROR;
        }
        memcpy(ssl->sec.dhP, c, ssl->sec.dhPLen);
        c += ssl->sec.dhPLen;

        ssl->sec.dhGLen = *c << 8; c++;
        ssl->sec.dhGLen |= *c; c++;
        if ((uint32) (end - c) < ssl->sec.dhGLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }
        ssl->sec.dhG = psMalloc(ssl->hsPool, ssl->sec.dhGLen);
        if (ssl->sec.dhG == NULL)
        {
            return SSL_MEM_ERROR;
        }
        memcpy(ssl->sec.dhG, c, ssl->sec.dhGLen);
        c += ssl->sec.dhGLen;

        pubDhLen = *c << 8; c++;
        pubDhLen |= *c; c++;

        if ((uint32) (end - c) < pubDhLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }
/*
            The next bit on the wire is the public key.  Assign to
            the session in structure format
 */
        if ((ssl->sec.dhKeyPub = psMalloc(ssl->hsPool, sizeof(psDhKey_t))) == NULL)
        {
            return MATRIXSSL_ERROR;
        }
        if (psDhImportPubKey(ssl->hsPool, c, pubDhLen,
                ssl->sec.dhKeyPub) < 0)
        {
            psFree(ssl->sec.dhKeyPub, ssl->hsPool);
            ssl->sec.dhKeyPub = NULL;
            return MATRIXSSL_ERROR;
        }
        c += pubDhLen;
#   ifndef USE_ONLY_PSK_CIPHER_SUITE
        sigStop = c;
#   endif
/*
            Key size is now known for premaster storage.  The extra byte
            is to account for the cases where the pubkey length ends
            up being a byte less than the premaster.  The premaster size
            is adjusted accordingly when the actual secret is generated.
 */
        ssl->sec.premasterSize = ssl->sec.dhPLen;
#   ifdef USE_PSK_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
        {
/*
                In the PSK case, the true premaster size is still unknown
                but didn't want to change the allocation logic so just
                make sure the size is large enough for the additional
                PSK and length bytes
 */
            ssl->sec.premasterSize += SSL_PSK_MAX_KEY_SIZE + 4;
        }
#   endif /* USE_PSK_CIPHER_SUITE */
        ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
        if (ssl->sec.premaster == NULL)
        {
            return SSL_MEM_ERROR;
        }
#   ifdef USE_ANON_DH_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_ANON_CIPHER)
        {
/*
                In the anonymous case, there is no signature to follow
 */
            ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
            *cp = c;
            ssl->decState = SSL_HS_SERVER_KEY_EXCHANGE;
            return PS_SUCCESS;
        }
#   endif /* USE_ANON_DH_CIPHER_SUITE */
#  endif  /* REQUIRE_DH_PARAMS */
#  ifdef USE_ECC_CIPHER_SUITE
    }
#  endif /* USE_ECC_CIPHER_SUITE */
/*
            This layer of authentation is at the key exchange level.
            The server has sent a signature of the key material that
            the client can validate here.
 */
        if ((end - c) < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }

#  ifdef USE_TLS_1_2
        hashSize = 0;
        if (ssl->flags & SSL_FLAGS_TLS_1_2)
        {
            skeHashSigAlg = *c << 8; c++;
            skeHashSigAlg += *c; c++;
            if ((skeHashSigAlg >> 8) == 0x4)
            {
                hashSize = SHA256_HASH_SIZE;
            }
            else if ((skeHashSigAlg >> 8) == 0x5)
            {
                hashSize = SHA384_HASH_SIZE;
            }
            else if ((skeHashSigAlg >> 8) == 0x6)
            {
                hashSize = SHA512_HASH_SIZE;
            }
            else if ((skeHashSigAlg >> 8) == 0x2)
            {
                hashSize = SHA1_HASH_SIZE;
            }
            else
            {
                psTraceIntInfo("Unsupported hashAlg SKE parse: %d\n",
                    skeHashSigAlg);
                return MATRIXSSL_ERROR;
            }
        }
#  endif /* USE_TLS_1_2 */
        pubDhLen = *c << 8; c++;     /* Reusing variable */
        pubDhLen |= *c; c++;

        if ((uint32) (end - c) < pubDhLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }

#  ifdef USE_RSA_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA)
        {
/*
                We are using the public key provided by the server during the
                CERTIFICATE message.  That cert has already been authenticated
                by this point so this signature is to ensure that entity is also
                the one negotiating keys with us.
 */
#   ifdef USE_TLS_1_2
            /* TLS 1.2 uses single hashes everywhere */
            if (ssl->flags & SSL_FLAGS_TLS_1_2)
            {
                if (hashSize == SHA256_HASH_SIZE)
                {
                    psSha256PreInit(&digestCtx.sha256);
                    psSha256Init(&digestCtx.sha256);
                    psSha256Update(&digestCtx.sha256, ssl->sec.clientRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha256Update(&digestCtx.sha256, ssl->sec.serverRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha256Update(&digestCtx.sha256, sigStart,
                        (uint32) (sigStop - sigStart));
                    psSha256Final(&digestCtx.sha256, hsMsgHash);
#    ifdef USE_SHA384
                }
                else if (hashSize == SHA384_HASH_SIZE)
                {
                    psSha384PreInit(&digestCtx.sha384);
                    psSha384Init(&digestCtx.sha384);
                    psSha384Update(&digestCtx.sha384, ssl->sec.clientRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha384Update(&digestCtx.sha384, ssl->sec.serverRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha384Update(&digestCtx.sha384, sigStart,
                        (uint32) (sigStop - sigStart));
                    psSha384Final(&digestCtx.sha384, hsMsgHash);
#    endif          /* USE_SHA384 */
#    ifdef USE_SHA512
                }
                else if (hashSize == SHA512_HASH_SIZE)
                {
                    psSha512PreInit(&digestCtx.sha512);
                    psSha512Init(&digestCtx.sha512);
                    psSha512Update(&digestCtx.sha512, ssl->sec.clientRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha512Update(&digestCtx.sha512, ssl->sec.serverRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha512Update(&digestCtx.sha512, sigStart,
                        (uint32) (sigStop - sigStart));
                    psSha512Final(&digestCtx.sha512, hsMsgHash);
#    endif          /* USE_SHA512 */
#    ifdef USE_SHA1
                }
                else if (hashSize == SHA1_HASH_SIZE)
                {
                    psSha1PreInit(&digestCtx.sha1);
                    psSha1Init(&digestCtx.sha1);
                    psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom,
                        SSL_HS_RANDOM_SIZE);
                    psSha1Update(&digestCtx.sha1, sigStart,
                        (uint32) (sigStop - sigStart));
                    psSha1Final(&digestCtx.sha1, hsMsgHash);
#    endif
                }
                else
                {
                    return MATRIXSSL_ERROR;
                }

            }
            else
            {
#    ifdef USE_MD5SHA1
                psMd5Sha1PreInit(&digestCtx.md5sha1);
                psMd5Sha1Init(&digestCtx.md5sha1);
                psMd5Sha1Update(&digestCtx.md5sha1, ssl->sec.clientRandom,
                    SSL_HS_RANDOM_SIZE);
                psMd5Sha1Update(&digestCtx.md5sha1, ssl->sec.serverRandom,
                    SSL_HS_RANDOM_SIZE);
                psMd5Sha1Update(&digestCtx.md5sha1, sigStart,
                    (uint32) (sigStop - sigStart));
                psMd5Sha1Final(&digestCtx.md5sha1, hsMsgHash);
#    else       /* USE_MD5SHA1 */
                psTraceInfo("USE_MD5SHA1 required\n");
                return MATRIXSSL_ERROR;
#    endif      /* USE_MD5SHA1 */
            }
#   else /* USE_TLS_1_2 */
/*
                The signature portion is an MD5 and SHA1 concat of the randoms
                and the contents of this server key exchange message.
 */
#    ifdef USE_MD5SHA1
            psMd5Sha1PreInit(&digestCtx.md5sha1);
            psMd5Sha1Init(&digestCtx.md5sha1);
            psMd5Sha1Update(&digestCtx.md5sha1, ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE);
            psMd5Sha1Update(&digestCtx.md5sha1, ssl->sec.serverRandom,
                SSL_HS_RANDOM_SIZE);
            psMd5Sha1Update(&digestCtx.md5sha1, sigStart,
                (uint32) (c - sigStart));
            psMd5Sha1Final(&digestCtx.md5sha1, hsMsgHash);
#    else
            psTraceInfo("USE_MD5SHA1 required\n");
            return MATRIXSSL_ERROR;
#    endif /* USE_MD5SHA1 */
#   endif  /* USE_TLS_1_2 */


#   ifdef USE_TLS_1_2
            if (ssl->flags & SSL_FLAGS_TLS_1_2)
            {
                /* TLS 1.2 doesn't just sign the straight hash so we can't
                    pass it through the normal public decryption becuase
                    that expects an output length of a known size. These
                    signatures are done on elements with some ASN.1
                    wrapping so a special decryption with parse is needed */
                if ((i = pubRsaDecryptSignedElement(skepkiPool,
                         &ssl->sec.cert->publicKey.key.rsa, c, pubDhLen, sigOut,
                         hashSize, pkiData)) < 0)
                {

                    psTraceInfo("Can't decrypt serverKeyExchange sig\n");
                    ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                    return MATRIXSSL_ERROR;
                }

            }
            else
            {
                hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;

                if ((i = psRsaDecryptPub(skepkiPool,
                         &ssl->sec.cert->publicKey.key.rsa, c, pubDhLen, sigOut,
                         hashSize, pkiData)) < 0)
                {
                    psTraceInfo("Can't decrypt server key exchange sig\n");
                    ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                    return MATRIXSSL_ERROR;
                }
            }
#   else    /* ! USE_TLS_1_2 */
            hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
            if ((i = psRsaDecryptPub(skepkiPool, &ssl->sec.cert->publicKey.key.rsa,
                     c, pubDhLen, sigOut, hashSize, pkiData)) < 0)
            {
                psTraceInfo("Unable to decrypt server key exchange sig\n");
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                return MATRIXSSL_ERROR;
            }
#   endif   /* USE_TLS_1_2 */

            /* Now have hash from the server. Create ours and check match */
            c += pubDhLen;

            if (memcmpct(sigOut, hsMsgHash, hashSize) != 0)
            {
                psTraceInfo("Fail to verify serverKeyExchange sig\n");
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                return MATRIXSSL_ERROR;
            }
        }
#  endif /* USE_RSA_CIPHER_SUITE */
#  ifdef USE_ECC_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA)
        {
/*
                RFC4492: The default hash function is SHA-1, and sha_size is 20.
 */
#   ifdef USE_TLS_1_2
            if (ssl->flags & SSL_FLAGS_TLS_1_2 &&
                (hashSize == SHA256_HASH_SIZE))
            {
                psSha256PreInit(&digestCtx.sha256);
                psSha256Init(&digestCtx.sha256);
                psSha256Update(&digestCtx.sha256, ssl->sec.clientRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha256Update(&digestCtx.sha256, ssl->sec.serverRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha256Update(&digestCtx.sha256, sigStart,
                    (int32) (sigStop - sigStart));
                psSha256Final(&digestCtx.sha256, hsMsgHash);
#    ifdef USE_SHA384
            }
            else if (ssl->flags & SSL_FLAGS_TLS_1_2 &&
                     (hashSize == SHA384_HASH_SIZE))
            {
                psSha384PreInit(&digestCtx.sha384);
                psSha384Init(&digestCtx.sha384);
                psSha384Update(&digestCtx.sha384, ssl->sec.clientRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha384Update(&digestCtx.sha384, ssl->sec.serverRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha384Update(&digestCtx.sha384, sigStart,
                    (int32) (sigStop - sigStart));
                psSha384Final(&digestCtx.sha384, hsMsgHash);
#    endif
#    ifdef USE_SHA512
            }
            else if (hashSize == SHA512_HASH_SIZE)
            {
                psSha512PreInit(&digestCtx.sha512);
                psSha512Init(&digestCtx.sha512);
                psSha512Update(&digestCtx.sha512, ssl->sec.clientRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha512Update(&digestCtx.sha512, ssl->sec.serverRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha512Update(&digestCtx.sha512, sigStart,
                    (uint32) (sigStop - sigStart));
                psSha512Final(&digestCtx.sha512, hsMsgHash);
#    endif      /* USE_SHA512 */
#    ifdef USE_SHA1
            }
            else if (ssl->minVer < TLS_1_2_MIN_VER ||
#     ifdef USE_DTLS
                     ssl->minVer == DTLS_MIN_VER ||
#     endif
                     ((ssl->flags & SSL_FLAGS_TLS_1_2) &&
                      (hashSize == SHA1_HASH_SIZE)))
            {
                hashSize = SHA1_HASH_SIZE;
                psSha1PreInit(&digestCtx.sha1);
                psSha1Init(&digestCtx.sha1);
                psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom,
                    SSL_HS_RANDOM_SIZE);
                psSha1Update(&digestCtx.sha1, sigStart,
                    (int32) (sigStop - sigStart));
                psSha1Final(&digestCtx.sha1, hsMsgHash);
#    endif
            }
            else
            {
                return MATRIXSSL_ERROR;
            }
#   else    /* USE_TLS_1_2 */
            hashSize = SHA1_HASH_SIZE;
            psSha1Init(&digestCtx.sha1);
            psSha1Update(&digestCtx.sha1, ssl->sec.clientRandom,
                SSL_HS_RANDOM_SIZE);
            psSha1Update(&digestCtx.sha1, ssl->sec.serverRandom,
                SSL_HS_RANDOM_SIZE);
            psSha1Update(&digestCtx.sha1, sigStart,
                (int32) (sigStop - sigStart));
            psSha1Final(&digestCtx.sha1, hsMsgHash);
#   endif   /* USE_TLS_1_2 */

            i = 0;

            if ((res = psEccDsaVerify(skepkiPool,
                     &ssl->sec.cert->publicKey.key.ecc,
                     hsMsgHash, hashSize,
                     c, pubDhLen,
                     &i, pkiData)) != 0)
            {
                psTraceInfo("ECDSA signature validation failed\n");
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                return MATRIXSSL_ERROR;
            }
            c += pubDhLen;
/*
                The validation code comes out of the final parameter
 */
            if (i != 1)
            {
                psTraceInfo("Can't verify serverKeyExchange sig\n");
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
                return MATRIXSSL_ERROR;

            }
        }
#  endif /* USE_ECC_CIPHER_SUITE */

        ssl->hsState = SSL_HS_SERVER_HELLO_DONE;

    }
# endif /* USE_DHE_CIPHER_SUITE */
# ifdef USE_PSK_CIPHER_SUITE
/*
        Entry point for basic PSK ciphers (not DHE or RSA) parsing SKE message
 */
    if (ssl->flags & SSL_FLAGS_PSK_CIPHER)
    {
        if ((end - c) < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }
        ssl->sec.hintLen = *c << 8; c++;
        ssl->sec.hintLen |= *c; c++;
        if ((uint32) (end - c) < ssl->sec.hintLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid ServerKeyExchange message\n");
            return MATRIXSSL_ERROR;
        }
        if (ssl->sec.hintLen > 0)
        {
            ssl->sec.hint = psMalloc(ssl->hsPool, ssl->sec.hintLen);
            if (ssl->sec.hint == NULL)
            {
                return SSL_MEM_ERROR;
            }
            memcpy(ssl->sec.hint, c, ssl->sec.hintLen);
            c += ssl->sec.hintLen;
        }
        ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
    }
# endif /* USE_PSK_CIPHER_SUITE */

    *cp = c;
    ssl->decState = SSL_HS_SERVER_KEY_EXCHANGE;
    return PS_SUCCESS;
}

# ifdef USE_OCSP
int32 parseCertificateStatus(ssl_t *ssl, int32 hsLen, unsigned char **cp,
    unsigned char *end)
{
    unsigned char *c;
    int32_t responseLen, rc;
    psOcspResponse_t response;

    /*
        struct {
            CertificateStatusType status_type;
            select (status_type) {
                case ocsp: OCSPResponse;
            } response;
        } CertificateStatus;

        enum { ocsp(1), (255) } CertificateStatusType;
        opaque OCSPResponse<1..2^24-1>;

        An "ocsp_response" contains a complete, DER-encoded OCSP response
        (using the ASN.1 type OCSPResponse defined in [RFC6960]).  Only one
        OCSP response may be sent.
     */
    c = *cp;
    if ((end - c) < 4)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid CertificateStatus length\n");
        return MATRIXSSL_ERROR;
    }

    if (*c != 0x1)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceInfo("Invalid status_type in certificateStatus message\n");
        return MATRIXSSL_ERROR;
    }
    c++;

    responseLen = *c << 16; c++;
    responseLen |= *c << 8; c++;
    responseLen |= *c; c++;

    if (responseLen > (end - c))
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Malformed CertificateStatus message\n");
        return MATRIXSSL_ERROR;
    }
    memset(&response, 0x0, sizeof(psOcspResponse_t));
    if ((rc = psOcspParseResponse(ssl->hsPool, responseLen, &c, end, &response))
        < 0)
    {
        /* Couldn't parse or no good responses in stream */
        psX509FreeCert(response.OCSPResponseCert);
        ssl->err = SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE;
        psTraceInfo("Unable to parse OCSPResponse\n");
        return MATRIXSSL_ERROR;
    }
    *cp = c;

    /* Authenticate the parsed response based on the registered CA files
        AND passing through the server chain as well because some real
        world examples we have seen use the intermediate cert as the
        OCSP responder */
    if ((rc = psOcspResponseValidateOld(ssl->hsPool, ssl->keys->CAcerts,
             ssl->sec.cert, &response)) < 0)
    {
        /* Couldn't validate */
        psX509FreeCert(response.OCSPResponseCert);
        ssl->err = SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE;
        psTraceInfo("Unable to validate OCSPResponse\n");
        return MATRIXSSL_ERROR;
    }
    psX509FreeCert(response.OCSPResponseCert);

    /* Same logic to determine next state as in end of SSL_HS_CERTIFICATE */
    ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
#  ifdef USE_DHE_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
        ssl->hsState = SSL_HS_SERVER_KEY_EXCHANGE;
    }
#  endif /* USE_DHE_CIPHER_SUITE */
    ssl->decState = SSL_HS_CERTIFICATE_STATUS;
    return PS_SUCCESS;
}
# endif /* USE_OCSP */

/******************************************************************************/

int32 parseServerHelloDone(ssl_t *ssl, int32 hsLen, unsigned char **cp,
    unsigned char *end)
{
    unsigned char *c;

#  if defined(USE_DHE_CIPHER_SUITE) || defined(REQUIRE_DH_PARAMS)
    int32 rc;
    void *pkiData = ssl->userPtr;

#  endif /* DH */

    c = *cp;

    psTraceHs(">>> Client parsing SERVER_HELLO_DONE message\n");
    if (hsLen != 0)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceInfo("Invalid ServerHelloDone message\n");
        return MATRIXSSL_ERROR;
    }

#  ifdef USE_DHE_CIPHER_SUITE
    if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
    {
#   ifdef USE_ECC_CIPHER_SUITE

        if (ssl->flags & SSL_FLAGS_ECC_CIPHER)
        {
            /*  Set up our private side of the ECC key based on the agreed
                upon curve */
            if (psEccNewKey(ssl->sec.eccDhKeyPool, &ssl->sec.eccKeyPriv,
                    ssl->sec.eccKeyPub->curve) < 0)
            {
                return PS_MEM_FAIL;
            }
            if ((rc = matrixSslGenEphemeralEcKey(ssl->keys,
                     ssl->sec.eccKeyPriv, ssl->sec.eccKeyPub->curve,
                     pkiData)) < 0)
            {
                psEccDeleteKey(&ssl->sec.eccKeyPriv);
                psTraceInfo("GenEphemeralEcc failed\n");
                ssl->err = SSL_ALERT_INTERNAL_ERROR;
                return MATRIXSSL_ERROR;
            }
        }
        else
        {
#   endif
#   ifdef REQUIRE_DH_PARAMS
        /* Can safely set up our ssl->sec.dhKeyPriv with DH keys
            based on the parameters passed over from the server.
            Storing these in a client specific DH pool because at
            handshake pool creation, the size for PKI was not known */
        if ((ssl->sec.dhKeyPriv = psMalloc(ssl->sec.dhKeyPool,
                 sizeof(psDhKey_t))) == NULL)
        {
            return MATRIXSSL_ERROR;
        }
        if ((rc = psDhGenKey(ssl->sec.dhKeyPool, ssl->sec.dhPLen,
                 ssl->sec.dhP, ssl->sec.dhPLen, ssl->sec.dhG,
                 ssl->sec.dhGLen, ssl->sec.dhKeyPriv, pkiData)) < 0)
        {
            psFree(ssl->sec.dhKeyPriv, ssl->sec.dhKeyPool);
            ssl->sec.dhKeyPriv = NULL;
            return MATRIXSSL_ERROR;
        }
        /* Freeing as we go.  No more need for G */
        psFree(ssl->sec.dhG, ssl->hsPool); ssl->sec.dhG = NULL;
#   endif /* REQUIRE_DH_PARAMS */
#   ifdef USE_ECC_CIPHER_SUITE
    }
#   endif /* USE_ECC_CIPHER_SUITE */
    }
#  endif  /* USE_DHE_CIPHER_SUITE */

    ssl->hsState = SSL_HS_FINISHED;

    *cp = c;
    ssl->decState = SSL_HS_SERVER_HELLO_DONE;
    return SSL_PROCESS_DATA;
}

/******************************************************************************/

# ifndef USE_ONLY_PSK_CIPHER_SUITE
int32 parseCertificateRequest(ssl_t *ssl, int32 hsLen, unsigned char **cp,
    unsigned char *end)
{
#  ifdef USE_CLIENT_AUTH
    psX509Cert_t *cert;
    int32 i;
#  endif
    int32 certTypeLen, certChainLen;
    uint32 certLen;
#  ifdef USE_TLS_1_2
    uint32 sigAlgMatch;
#   ifdef USE_CLIENT_AUTH
    uint32 hashSigAlg;
#   endif
#  endif
    unsigned char *c;

    c = *cp;

    psTraceHs(">>> Client parsing CERTIFICATE_REQUEST message\n");
    if (hsLen < 4)
    {
        ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
        psTraceInfo("Invalid Certificate Request message\n");
        return MATRIXSSL_ERROR;
    }
    /*  Currently ignoring the authentication type request because it was
        underspecified up to TLS 1.1 and TLS 1.2 is now taking care of this
        with the supported_signature_algorithms handling */
    certTypeLen = *c++;
    if (end - c < certTypeLen)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid Certificate Request message\n");
        return MATRIXSSL_ERROR;
    }
    c += certTypeLen; /* Skipping (RSA_SIGN etc.) */
#  ifdef USE_TLS_1_2
    sigAlgMatch = 0;
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        /* supported_signature_algorithms field
            enum {none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
                sha512(6), (255) } HashAlgorithm;

            enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SigAlg */
        if (end - c < 2)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid SigHash in Certificate Request message\n");
            return MATRIXSSL_ERROR;
        }
        certChainLen = *c << 8; c++; /* just borrowing this variable */
        certChainLen |= *c; c++;
        if (end - c < certChainLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid SigHash in Certificate Request message\n");
            return MATRIXSSL_ERROR;
        }
#   ifdef USE_CLIENT_AUTH
        /* Going to adhere to this supported_signature_algorithm to
            be compliant with the spec.  This is now the first line
            of testing about what certificates the server will accept.
            If any of our certs do not use a signature algorithm
            that the server supports we will flag that here which will
            ultimately result in an empty CERTIFICATE message and
            no CERTIFICATE_VERIFY message.  We're going to convert
            MD5 to use SHA1 instead though.

            Start by building a bitmap of supported algs */
        hashSigAlg = 0;
        while (certChainLen >= 2)
        {
            i = HASH_SIG_MASK(c[0], c[1]);
            /* Our own ssl->hashSigAlg is the list we support.  So choose
                from those only */
            if (ssl->hashSigAlg & i)
            {
                hashSigAlg |= i;
            }
            c += 2;
            certChainLen -= 2;
        }
        /* RFC: The end-entity certificate provided by the client MUST
            contain a key that is compatible with certificate_types.
            If the key is a signature key, it MUST be usable with some
            hash/signature algorithm pair in supported_signature_algorithms.

            So not only do we have to check the signature algorithm, we
            have to check the pub key type as well. */
        sigAlgMatch = 1; /* de-flag if we hit unsupported one */
        if (ssl->keys == NULL || ssl->keys->cert == NULL)
        {
            sigAlgMatch = 0;
        }
        else
        {
            cert = ssl->keys->cert;
            while (cert)
            {
                if (cert->pubKeyAlgorithm == OID_RSA_KEY_ALG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA1_RSA_MASK) &&
#    ifdef USE_SHA384
                        !(hashSigAlg & HASH_SIG_SHA384_RSA_MASK) &&
#    endif
                        !(hashSigAlg & HASH_SIG_SHA256_RSA_MASK) &&
                        !(hashSigAlg & HASH_SIG_MD5_RSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
                if (cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
                    cert->sigAlgorithm == OID_MD5_RSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA1_RSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
                if (cert->sigAlgorithm == OID_SHA256_RSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA256_RSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
#    ifdef USE_SHA384
                if (cert->sigAlgorithm == OID_SHA384_RSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA384_RSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
#    endif
#    ifdef USE_SHA512
                if (cert->sigAlgorithm == OID_SHA512_RSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA512_RSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
#    endif
#    ifdef USE_ECC
                if (cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA1_ECDSA_MASK) &&
#     ifdef USE_SHA384
                        !(hashSigAlg & HASH_SIG_SHA384_ECDSA_MASK) &&
#     endif
#     ifdef USE_SHA512
                        !(hashSigAlg & HASH_SIG_SHA512_ECDSA_MASK) &&
#     endif
                        !(hashSigAlg & HASH_SIG_SHA256_ECDSA_MASK) &&
                        !(hashSigAlg & HASH_SIG_SHA1_ECDSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
                if (cert->sigAlgorithm == OID_SHA1_ECDSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA1_ECDSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
                if (cert->sigAlgorithm == OID_SHA256_ECDSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA256_ECDSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
#     ifdef USE_SHA384
                if (cert->sigAlgorithm == OID_SHA384_ECDSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA384_ECDSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
#     endif
#     ifdef USE_SHA512
                if (cert->sigAlgorithm == OID_SHA512_ECDSA_SIG)
                {
                    if (!(hashSigAlg & HASH_SIG_SHA512_ECDSA_MASK))
                    {
                        sigAlgMatch = 0;
                    }
                }
#     endif
#    endif      /* USE_ECC */
                cert = cert->next;
            }
        }
#   endif /* USE_CLIENT_AUTH */
        c += certChainLen;
    }
#  endif /* TLS_1_2 */

    certChainLen = 0;
    if (end - c >= 2)
    {
        certChainLen = *c << 8; c++;
        certChainLen |= *c; c++;
        if (end - c < certChainLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid Certificate Request message\n");
            return MATRIXSSL_ERROR;
        }
    }
    /*  Check the passed in DNs against our cert issuer to see if they match.
        Only supporting a single cert on the client side. */
    ssl->sec.certMatch = 0;

#  ifdef USE_CLIENT_AUTH
    /*  If the user has actually gone to the trouble to load a certificate
        to reply with, we flag that here so there is some flexibility as
        to whether we want to reply with something (even if it doesn't match)
        just in case the server is willing to do a custom test of the cert */
    if (ssl->keys != NULL && ssl->keys->cert)
    {
        ssl->sec.certMatch = SSL_ALLOW_ANON_CONNECTION;
    }
#  endif /* USE_CLIENT_AUTH */
    while (certChainLen > 2)
    {
        certLen = *c << 8; c++;
        certLen |= *c; c++;
        if ((uint32) (end - c) < certLen || certLen <= 0 ||
            (int32) certLen > certChainLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid CertificateRequest message\n");
            return MATRIXSSL_ERROR;
        }
        certChainLen -= 2;
#  ifdef USE_CLIENT_AUTH
        /*      Can parse the message, but will not look for a match.  The
            setting of certMatch to 1 will trigger the correct response
            in sslEncode */
        if (ssl->keys != NULL && ssl->keys->cert)
        {
            /* Flag a match if the hash of the DN issuer is identical */
            if (ssl->keys->cert->issuer.dnencLen == certLen)
            {
                if (memcmp(ssl->keys->cert->issuer.dnenc, c, certLen) == 0)
                {
                    ssl->sec.certMatch = 1;
                }
            }
        }
#  endif /* USE_CLIENT_AUTH */
        c += certLen;
        certChainLen -= certLen;
    }
#  ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        /* We let the DN parse complete but if we didn't get a sigAlgMatch
            from the previous test we're going to adhere to that for spec
            compliance.  So here goes */
        if (sigAlgMatch == 0)
        {
            ssl->sec.certMatch = 0;
        }
    }
#  endif
    ssl->hsState = SSL_HS_SERVER_HELLO_DONE;

    *cp = c;
    ssl->decState = SSL_HS_CERTIFICATE_REQUEST;
    return PS_SUCCESS;
}
# endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif  /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/

int32 parseFinished(ssl_t *ssl, int32 hsLen,
    unsigned char hsMsgHash[SHA384_HASH_SIZE],
    unsigned char **cp,
    unsigned char *end)
{
    int32 rc;
    unsigned char *c;

    rc = PS_SUCCESS;
    c = *cp;

    psAssert(hsLen <= SHA384_HASH_SIZE);

    /* Before the finished handshake message, we should have seen the
        CHANGE_CIPHER_SPEC message come through in the record layer, which
        would have activated the read cipher, and set the READ_SECURE flag.
        This is the first handshake message that was sent securely. */
    psTraceStrHs(">>> %s parsing FINISHED message\n",
        (ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");
    if (!(ssl->flags & SSL_FLAGS_READ_SECURE))
    {
        ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
        psTraceInfo("Finished before ChangeCipherSpec\n");
        return MATRIXSSL_ERROR;
    }
    /* The contents of the finished message is a 16 byte MD5 hash followed
        by a 20 byte sha1 hash of all the handshake messages so far, to verify
        that nothing has been tampered with while we were still insecure.
        Compare the message to the value we calculated at the beginning of
        this function. */
#ifdef USE_TLS
    if (ssl->flags & SSL_FLAGS_TLS)
    {
        if (hsLen != TLS_HS_FINISHED_SIZE)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid Finished length\n");
            return MATRIXSSL_ERROR;
        }
    }
    else
    {
#endif /* USE_TLS */
    if (hsLen != MD5_HASH_SIZE + SHA1_HASH_SIZE)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid Finished length\n");
        return MATRIXSSL_ERROR;
    }
#ifdef USE_TLS
}
#endif /* USE_TLS */
    if ((int32) (end - c) < hsLen)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid Finished length\n");
        return MATRIXSSL_ERROR;
    }
    if (memcmpct(c, hsMsgHash, hsLen) != 0)
    {
        ssl->err = SSL_ALERT_DECRYPT_ERROR;
        psTraceInfo("Invalid handshake msg hash\n");
        return MATRIXSSL_ERROR;
    }
#ifdef ENABLE_SECURE_REHANDSHAKES
    /* Got the peer verify_data for secure renegotiations */
    memcpy(ssl->peerVerifyData, c, hsLen);
    ssl->peerVerifyDataLen = hsLen;
#endif /* ENABLE_SECURE_REHANDSHAKES */
    c += hsLen;
    ssl->hsState = SSL_HS_DONE;
    /*  Now that we've parsed the Finished message, if we're a resumed
        connection, we're done with handshaking, otherwise, we return
        SSL_PROCESS_DATA to get our own cipher spec and finished messages
        sent out by the caller. */
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        if (!(ssl->flags & SSL_FLAGS_RESUMED))
        {
            rc = SSL_PROCESS_DATA;
        }
        else
        {
#ifdef USE_SSL_INFORMATIONAL_TRACE
            /* Server side resumed completion */
            matrixSslPrintHSDetails(ssl);
#endif
        }
    }
    else
    {
#ifdef USE_STATELESS_SESSION_TICKETS
        /* Now that FINISHED is verified, we can mark the ticket as
            valid to conform to section 3.3 of the 5077 RFC */
        if (ssl->sid && ssl->sid->sessionTicketLen > 0)
        {
            ssl->sid->sessionTicketState = SESS_TICKET_STATE_USING_TICKET;
        }
#endif
        if (ssl->flags & SSL_FLAGS_RESUMED)
        {
            rc = SSL_PROCESS_DATA;
        }
        else
        {
#ifdef USE_SSL_INFORMATIONAL_TRACE
            /* Client side standard completion */
            matrixSslPrintHSDetails(ssl);
#endif
        }
    }
#ifndef USE_ONLY_PSK_CIPHER_SUITE
# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
    /* There is also an attempt to free the cert during
        the sending of the finished message to deal with client
        and server and differing handshake types.  Both cases are
        attempted keep the lifespan of this allocation as short as possible. */
    if (!(ssl->bFlags & BFLAG_KEEP_PEER_CERTS))
    {
        if (ssl->sec.cert)
        {
            psX509FreeCert(ssl->sec.cert);
            ssl->sec.cert = NULL;
        }
    }
# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        /* A successful parse of the FINISHED message means the record sequence
           numbers have been reset so we need to clear out our replay detector */
        zeroSixByte(ssl->lastRsn);

        /* This will just be set between CCS parse and FINISHED parse */
        ssl->parsedCCS = 1;

        /* Look at the comment in the fragment parsing code to see the
            justification of placing this free here.  Bascially, this
            is the best place to do it because we know there can be no
            further fragmented messages.  More importantly, the
            hanshake pool is being freed here! */
        if (ssl->fragMessage != NULL)
        {
            psFree(ssl->fragMessage, ssl->hsPool);
            ssl->fragMessage = NULL;
        }
    }
    /* Premaster was not freed at the usual spot becasue of retransmit cases */
    if (ssl->sec.premaster)
    {
        psFree(ssl->sec.premaster, ssl->hsPool); ssl->sec.premaster = NULL;
    }
    if (ssl->ckeMsg)
    {
        psFree(ssl->ckeMsg, ssl->hsPool); ssl->ckeMsg = NULL;
    }
    if (ssl->certVerifyMsg)
    {
        psFree(ssl->certVerifyMsg, ssl->hsPool); ssl->certVerifyMsg = NULL;
    }
# if defined(USE_PSK_CIPHER_SUITE) && defined(USE_CLIENT_SIDE_SSL)
    if (ssl->sec.hint)
    {
        psFree(ssl->sec.hint, ssl->hsPool); ssl->sec.hint = NULL;
    }
# endif
#endif /* USE_DTLS */
    ssl->hsPool = NULL;

    *cp = c;
    ssl->decState = SSL_HS_FINISHED;
    return rc;
}

/******************************************************************************/

#ifndef USE_ONLY_PSK_CIPHER_SUITE
# if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
int32 parseCertificate(ssl_t *ssl, unsigned char **cp, unsigned char *end)
{
    psX509Cert_t *currentCert, *cert, *foundIssuer;
    unsigned char *c;
    uint32 certLen;
    int32 rc, i, certChainLen, parseLen = 0;
    void *pkiData = ssl->userPtr;
    int32 pathLen;

    psTraceStrHs(">>> %s parsing CERTIFICATE message\n",
        (ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");

    c = *cp;

#  ifdef USE_CERT_CHAIN_PARSING
    if (ssl->rec.partial)
    {
        /* The test for a first pass is against the record header length */
        if (ssl->rec.hsBytesParsed == ssl->recordHeadLen)
        {
            /*  Account for the one-time header portion parsed above
                and the 3 byte cert chain length about to be parsed below.
                The minimum length tests have already been performed. */
            ssl->rec.hsBytesParsed += ssl->hshakeHeadLen + 3;
        }
        else
        {
            goto SKIP_CERT_CHAIN_INIT;
        }
    }
#  endif
    if (end - c < 3)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid Certificate message\n");
        return MATRIXSSL_ERROR;
    }
    certChainLen = *c << 16; c++;
    certChainLen |= *c << 8; c++;
    certChainLen |= *c; c++;
    if (certChainLen == 0)
    {
#  ifdef SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
            goto STRAIGHT_TO_USER_CALLBACK;
        }
#  endif
        if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER)
        {
            ssl->err = SSL_ALERT_NO_CERTIFICATE;
        }
        else
        {
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
        }
        psTraceInfo("No certificate sent to verify\n");
        return MATRIXSSL_ERROR;
    }
    if (end - c < 3)
    {
        ssl->err = SSL_ALERT_DECODE_ERROR;
        psTraceInfo("Invalid Certificate message\n");
        return MATRIXSSL_ERROR;
    }

#  ifdef USE_CERT_CHAIN_PARSING
SKIP_CERT_CHAIN_INIT:
    if (ssl->rec.partial)
    {
        /*      It is possible to activate the CERT_STREAM_PARSE feature and not
            receive a cert chain in multiple buffers.  If we are not flagged
            for 'partial' parsing, we can drop into the standard parse case */
        while (end - c > 0)
        {
            certLen = *c << 16; c++;
            certLen |= *c << 8; c++;
            certLen |= *c; c++;
            if ((parseLen = parseSingleCert(ssl, c, end, certLen)) < 0 )
            {
                return parseLen;
            }
            ssl->rec.hsBytesParsed += parseLen + 3; /* 3 for certLen */
            c += parseLen;
        }
        if (ssl->rec.hsBytesParsed < ssl->rec.trueLen)
        {
            *cp = c;
            return MATRIXSSL_SUCCESS;
        }

        psAssert(ssl->rec.hsBytesParsed == ssl->rec.trueLen);
        /* Got it all.  Disable the stream mechanism. */
        ssl->rec.partial = 0x0;
        ssl->rec.hsBytesParsed = 0;
        ssl->rec.hsBytesHashed = 0;
    }
    else
    {
        psAssert(certChainLen > 0);
#  endif /* USE_CERT_CHAIN_PARSING */
    i = 0;
    currentCert = NULL;

#  if defined(USE_HARDWARE_CRYPTO_PKA) || defined(USE_EXT_CERTIFICATE_VERIFY_SIGNING)
    /* Skip re-parsing the certs if pending. The above few bytes are fine */
    if (ssl->hwflags & SSL_HWFLAGS_PENDING_PKA_R)
    {
        c += certChainLen;
        ssl->hwflags &= ~SSL_HWFLAGS_PENDING_PKA_R;
        goto RESUME_VALIDATE_CERTS;
    }
#  endif /* USE_HARDWARE_CRYPTO_PKA || USE_EXT_CERTIFICATE_VERIFY_SIGNING */
         /* Chain must be at least 3 b certLen */
    while (certChainLen >= 3)
    {
        int32 certFlags = 0;

        certLen = *c << 16; c++;
        certLen |= *c << 8; c++;
        certLen |= *c; c++;
        certChainLen -= 3;

        if ((uint32) (end - c) < certLen || (int32) certLen > certChainLen)
        {
            ssl->err = SSL_ALERT_DECODE_ERROR;
            psTraceInfo("Invalid certificate length\n");
            return MATRIXSSL_ERROR;
        }
        if (ssl->bFlags & BFLAG_KEEP_PEER_CERT_DER)
        {
            certFlags |= CERT_STORE_UNPARSED_BUFFER;
        }
/*
            Extract the binary cert message into the cert structure
 */
        if ((parseLen = psX509ParseCert(ssl->hsPool, c, certLen, &cert, certFlags))
            < 0)
        {
            psTraceInfo("Parsing of the peer certificate failed\n");
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
#  ifdef ALLOW_VERSION_1_ROOT_CERT_PARSE
        /* When ALLOW_VERSION_1_ROOT_CERT_PARSE is defined,
           psX509ParseCert lets version 1 certificates through, in
           order to support loading of locally trusted v1 root
           certs. This means that we need to explicitly reject v1
           certificates sent to us by the peer. They cannot be
           trusted due to missing Basic Constraints, etc. */
        if (cert->version != 2)
        {
            psTraceInfo("Version 1 peer certificates not allowed\n");
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
        }
#  endif /* ALLOW_VERSION_1_ROOT_CERT_PARSE */
        c += parseLen;

        if (i++ == 0)
        {
            ssl->sec.cert = cert;
            currentCert = ssl->sec.cert;
        }
        else
        {
            currentCert->next = cert;
            currentCert = currentCert->next;
        }
        certChainLen -= certLen;
    }
#  ifdef USE_CERT_CHAIN_PARSING
}
#  endif /* USE_CERT_CHAIN_PARSING */

#  ifdef USE_CLIENT_SIDE_SSL
    /*  Now want to test to see if supplied child-most cert is the appropriate
        pubkey algorithm for the chosen cipher suite.  Have seen test
        cases with OpenSSL where an RSA cert will be sent for an ECDHE_ECDSA
        suite, for example.  Just testing on the client side because client
        auth is a bit more flexible on the algorithm choices. */
    if (!(ssl->flags & SSL_FLAGS_SERVER))
    {
        if (csCheckCertAgainstCipherSuite(ssl->sec.cert->publicKey.type,
                ssl->cipher->type) == 0)
        {
            psTraceIntInfo("Server sent bad pubkey type for cipher suite %d\n",
                ssl->cipher->type);
            ssl->err = SSL_ALERT_UNSUPPORTED_CERTIFICATE;
            return MATRIXSSL_ERROR;
        }
    }
#  endif

    /* Time to authenticate the supplied cert against our CAs */
#  if defined(USE_HARDWARE_CRYPTO_PKA) || defined(USE_EXT_CERTIFICATE_VERIFY_SIGNING)
RESUME_VALIDATE_CERTS:
#  endif /* USE_HARDWARE_CRYPTO_PKA || USE_EXT_CERTIFICATE_VERIFY_SIGNING */

    rc = matrixValidateCertsExt(ssl->hsPool, ssl->sec.cert,
        ssl->keys == NULL ? NULL : ssl->keys->CAcerts, ssl->expectedName,
        &foundIssuer, pkiData, ssl->memAllocPtr, &ssl->validateCertsOpts);

    if (rc == PS_MEM_FAIL)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return MATRIXSSL_ERROR;
    }
    /*  Now walk the subject certs and convert any parse or authentication error
        into an SSL alert.  The alerts SHOULD be read by the user callback
        to determine whether they are fatal or not.  If no user callback,
        the first alert will be considered fatal. */
    cert = ssl->sec.cert;
    pathLen = 0;
    while (cert)
    {
        ++pathLen;
        if (ssl->validateCertsOpts.max_verify_depth > 0)
        {
            int exceeded = 0;
            psTraceIntInfo("max_verify_depth: %d\n", ssl->validateCertsOpts.max_verify_depth);
            /*
               A maximum verification depth has been specified in session opts.
             */
            if (pathLen > (ssl->validateCertsOpts.max_verify_depth))
            {
                exceeded = 1;
            }
            else if (pathLen == (ssl->validateCertsOpts.max_verify_depth))
            {
                /*
                   We don't have the root in cert->next. So do the
                   following: If the cert is _not_ self-signed, it must
                   have a valid root cert as the issuer, since this
                   is checked in matrixValidateCerts. Now take that root
                   into account when checking the path length.
                 */
                if (memcmpct(&cert->subject, &cert->issuer,
                        sizeof(cert->subject)))
                {
                    /* Root cert causes depth to be exceeded. */
                    exceeded = 1;
                }
            }
            if (exceeded)
            {
                /* Max depth exceeded. */
                psTraceInfo("Error: max_verify_depth exceeded\n");
                ssl->err = SSL_ALERT_UNKNOWN_CA;
                cert->authStatus |= PS_CERT_AUTH_FAIL_PATH_LEN;
                cert->authFailFlags |= PS_CERT_AUTH_FAIL_VERIFY_DEPTH_FLAG;
            }
        }
        if (ssl->err != SSL_ALERT_NONE)
        {
            break; /* The first alert is the logical one to send */
        }
        switch (cert->authStatus)
        {
        case PS_CERT_AUTH_FAIL_SIG:
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            break;
        case PS_CERT_AUTH_FAIL_REVOKED:
            ssl->err = SSL_ALERT_CERTIFICATE_REVOKED;
            break;
        case PS_CERT_AUTH_FAIL_AUTHKEY:
        case PS_CERT_AUTH_FAIL_PATH_LEN:
            ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            break;
        case PS_CERT_AUTH_FAIL_EXTENSION:
            /* The math and basic constraints matched.  This case is
                for X.509 extension mayhem */
            if (cert->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG)
            {
                ssl->err = SSL_ALERT_CERTIFICATE_EXPIRED;
            }
            else if (cert->authFailFlags & PS_CERT_AUTH_FAIL_SUBJECT_FLAG)
            {
                /* expectedName was giving to NewSession but couldn't
                    match what the peer gave us */
                ssl->err = SSL_ALERT_CERTIFICATE_UNKNOWN;
            }
            else if (cert->next != NULL)
            {
                /* This is an extension problem in the chain.
                    Even if it's minor, we are shutting it down */
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            }
            else
            {
                /* This is the case where we did successfully find the
                    correct CA to validate the cert and the math passed
                    but the     extensions had a problem.  Give app a
                    different message in this case */
                ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            }
            break;
        case PS_CERT_AUTH_FAIL_BC:
        case PS_CERT_AUTH_FAIL_DN:
            /* These two are pre-math tests.  If this was a problem in the
                middle of the chain it means the chain couldn't even
                validate itself.  If it is at the end it means a matching
                CA could not be found */
            if (cert->next != NULL)
            {
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            }
            else
            {
                ssl->err = SSL_ALERT_UNKNOWN_CA;
            }
            break;

        default:
            break;
        }
        cert = cert->next;
    }

    /*  The last thing we want to check before passing the certificates to
        the user callback is the case in which we don't have any
        CA files loaded but we were passed a valid chain that was
        terminated with a self-signed cert.  The fact that a CA on this
        peer has not validated the chain should result in an UNKNOWN_CA alert

        NOTE:  This case should only ever get hit if VALIDATE_KEY_MATERIAL
        has been disabled in matrixssllib.h */

    if (ssl->err == SSL_ALERT_NONE &&
        (ssl->keys == NULL || ssl->keys->CAcerts == NULL))
    {
        ssl->err = SSL_ALERT_UNKNOWN_CA;
        psTraceInfo("WARNING: Valid self-signed cert or cert chain but no local authentication\n");
        rc = -1;  /* Force the check on existence of user callback */
    }

    if (rc < 0)
    {
        psTraceInfo("WARNING: cert did not pass internal validation test\n");
        /*      Cert auth failed.  If there is no user callback issue fatal alert
            because there will be no intervention to give it a second look. */
        if (ssl->sec.validateCert == NULL)
        {
            /*  ssl->err should have been set correctly above but catch
                any missed cases with the generic BAD_CERTIFICATE alert */
            if (ssl->err == SSL_ALERT_NONE)
            {
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            }
            return MATRIXSSL_ERROR;
        }
    }

#  ifdef SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG
STRAIGHT_TO_USER_CALLBACK:
#  endif

    /*  Return from user validation space with knowledge that there is a fatal
        alert or that this is an ANONYMOUS connection. */
    rc = matrixUserCertValidator(ssl, ssl->err, ssl->sec.cert,
        ssl->sec.validateCert);
    /* Test what the user callback returned. */
    ssl->sec.anon = 0;
    if (rc == SSL_ALLOW_ANON_CONNECTION)
    {
        ssl->sec.anon = 1;
    }
    else if (rc > 0)
    {
        /*      User returned an alert.  May or may not be the alert that was
            determined above */
        psTraceIntInfo("Certificate authentication alert %d\n", rc);
        ssl->err = rc;
        return MATRIXSSL_ERROR;
    }
    else if (rc < 0)
    {
        psTraceIntInfo("User certificate callback had an internal error\n", rc);
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return MATRIXSSL_ERROR;
    }

    /*  User callback returned 0 (continue on).  Did they determine the alert
        was not fatal after all? */
    if (ssl->err != SSL_ALERT_NONE)
    {
        psTraceIntInfo("User certificate callback determined alert %d was NOT fatal\n",
            ssl->err);
        ssl->err = SSL_ALERT_NONE;
    }

    /*  Either a client or server could have been processing the cert as part of
        the authentication process.  If server, we move to the client key
        exchange state. */
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        ssl->hsState = SSL_HS_CLIENT_KEY_EXCHANGE;
    }
    else
    {
        ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
#  ifdef USE_DHE_CIPHER_SUITE
        if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH)
        {
            ssl->hsState = SSL_HS_SERVER_KEY_EXCHANGE;
        }
#  endif /* USE_DHE_CIPHER_SUITE */
#  ifdef USE_OCSP
        /* State management for OCSP use.  Testing if we received a
            status_request from the server to set next expected state */
        if (ssl->extFlags.status_request || ssl->extFlags.status_request_v2)
        {
            /*  Why do they allow an ambiguous state here?!  From RFC 6066:

                Note that a server MAY also choose not to send a
                "CertificateStatus" message, even if has received a
                "status_request" extension in the client hello message and has
                sent a "status_request" extension in the server hello message */
            ssl->hsState = SSL_HS_CERTIFICATE_STATUS;
        }
#  endif
    }
    *cp = c;
    ssl->decState = SSL_HS_CERTIFICATE;
    return MATRIXSSL_SUCCESS;
}
# endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif  /* !USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/

