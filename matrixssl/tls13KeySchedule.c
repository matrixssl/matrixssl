/**
 *      @file    tls13.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 secret and key derivation.
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

#ifdef USE_TLS_1_3

static const char *derivedLabel = "derived";
static psSize_t derivedLabelLen = 7;
static const char *extBinderLabel = "ext binder";
static psSize_t extBinderLabelLen = 10;
static const char *resBinderLabel = "res binder";
static psSize_t resBinderLabelLen = 10;
static const char *cEarlyTrafficLabel = "c e traffic";
static psSize_t earlyTrafficLabelLen = 11;
static const char *cHsTrafficLabel = "c hs traffic";
static const char *sHsTrafficLabel = "s hs traffic";
static const char *finishedLabel = "finished";
static psSize_t finishedLabelLen = 8;
static const char *cApTrafficLabel = "c ap traffic";
static const char *sApTrafficLabel = "s ap traffic";
static psSize_t trafficLabelLen = 12;
static const char *resLabel = "res master";
static psSize_t resLabelLen = 10;

# ifndef DEBUG_TLS_1_3_KEY_DERIVE
/* #  define DEBUG_TLS_1_3_KEY_DERIVE */
# endif

/* Secrets SHOULD be cleared after final use. The following define can
   be used to keep them around longer for debugging purposes. */
# ifndef DEBUG_TLS_1_3_KEEP_SECRETS
/* #  define DEBUG_TLS_1_3_KEEP_SECRETS */
#endif

static unsigned char sha256OfEmptyInput[] =
{
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
    0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
static unsigned char sha384OfEmptyInput[] =
{
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
    0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
    0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};

static inline
void tls13ClearSecret(unsigned char *secret,
        psSize_t secretLen)
{
# ifndef DEBUG_TLS_1_3_KEEP_SECRETS
    Memset(secret, 0, secretLen);
# else
    (void)secret;
    (void)secretLen);
# endif
}

/* Derive-Secret(Secret, Label, Transcript-Hash(Messages)) */
int32_t tls13DeriveSecret(ssl_t *ssl,
        int32_t hmacAlg,
        const unsigned char *inSecret,
        psSize_t inSecretLen,
        const char *label,
        psSize_t labelLen,
        const unsigned char *trHash,
        psSize_t trHashLen,
        unsigned char outSecret[MAX_TLS_1_3_HASH_SIZE])
{
    int32_t rc;
    int32_t outLen = psGetOutputBlockLength(hmacAlg);
    const unsigned char *pHash = trHash;

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("inSecret", inSecret, inSecretLen);
    psTraceBytes("label", (unsigned char*)label, labelLen);
    psTraceBytes("context", trHash, trHashLen);
#endif

    if (outLen < 0)
    { /* error code. */
        return outLen;
    }
    if (trHashLen == 0)
    {
        /* Hash of no messages. */
        if (hmacAlg == HMAC_SHA256)
        {
            pHash = sha256OfEmptyInput;
            trHashLen = 32;
        }
        else
        {
            pHash = sha384OfEmptyInput;
            trHashLen = 48;
        }
    }

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inSecret,
            inSecretLen,
            label,
            labelLen,
            pHash,
            trHashLen,
            outLen,
            outSecret);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

int32_t tls13GenerateEarlySecret(ssl_t *ssl,
        psTls13Psk_t *psk)
{
    unsigned char dummyPsk[MAX_TLS_1_3_HASH_SIZE] = {0};
    unsigned char zeroSalt[MAX_TLS_1_3_HASH_SIZE] = {0};
    unsigned char *pskVal;
    psSize_t pskValLen;
    int32_t hmacAlg;
    psResSize_t hashLen;
    psSize_t earlySecretLen;
    int32_t rc;

    if (ssl->sec.tls13KsState.generateEarlySecretDone)
    {
        /* Already generated. Re-entry? */
        return PS_SUCCESS;
    }

    /*
      HKDF-Extract(PSK, 0..0) == Early Secret
     */
    if (psk != NULL)
    {
        pskVal = psk->pskKey;
        pskValLen = psk->pskLen;
        hmacAlg = tls13GetPskHmacAlg(psk);
        hashLen = tls13GetPskHashLen(psk);
    }
    else
    {
        /* When no PSK is used, PSK = 0..0. */
        pskVal = dummyPsk;
        hmacAlg = tls13GetCipherHmacAlg(ssl);
        hashLen = tls13GetCipherHashSize(ssl);
        pskValLen = hashLen;
    }
    if (hashLen < 0)
    { /* hashLen is error code */
        return hashLen;
    }
    earlySecretLen = hashLen;

    rc = psHkdfExtract(hmacAlg,
            zeroSalt,
            hashLen,
            pskVal,
            pskValLen,
            ssl->sec.tls13EarlySecret,
            &earlySecretLen);
    if (rc < 0)
    {
        return rc;
    }
    psAssert(earlySecretLen == hashLen);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("Early Secret", ssl->sec.tls13EarlySecret, hashLen);
#endif

    ssl->sec.tls13KsState.generateEarlySecretDone = 1;
    return PS_SUCCESS;
}

/* Derive the first part of the key schedule: the Early Secret
   and the secrets immediately dependent on it. */
int32_t tls13DeriveEarlySecrets(ssl_t *ssl,
        psTls13Psk_t *psk)
{
    psSize_t secretLen, hashLen;
    unsigned char zeroByte = 0;
    int32_t hmacAlg, rc;
    const char *label;
    psSize_t labelLen;

    rc = tls13GenerateEarlySecret(ssl, psk);
    if (rc < 0)
    {
        return rc;
    }

    if (psk)
    {
        hmacAlg = tls13GetPskHmacAlg(psk);
        hashLen = tls13GetPskHashLen(psk);
        secretLen = hashLen;

        if (psk->isResumptionPsk)
        {
            label = resBinderLabel;
            labelLen = resBinderLabelLen;
        }
        else
        {
            label = extBinderLabel;
            labelLen = extBinderLabelLen;
        }

        /* Derive-Secret(Early Secret, "ext|res_binder", "") */
        rc = tls13DeriveSecret(ssl,
                hmacAlg,
                ssl->sec.tls13EarlySecret,
                secretLen,
                label,
                labelLen,
                &zeroByte,
                0,
                ssl->sec.tls13ExtBinderSecret);
        if (rc < 0)
        {
            return rc;
        }
    }

    return PS_SUCCESS;
}

int32_t tls13DeriveHandshakeTrafficSecrets(ssl_t *ssl)
{
    unsigned char derivedSecret[MAX_TLS_1_3_HASH_SIZE];
    unsigned char *sharedSecret;
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    psResSize_t secretLen = psGetOutputBlockLength(hmacAlg);
    psSize_t sharedSecretLen;
    psSize_t hsSecretLen;
    unsigned char zeroByte = 0;
    int32_t rc;

    if (ssl->sec.tls13KsState.deriveHandshakeTrafficSecretsDone)
    {
        /* Already generated. Re-entry? */
        return PS_SUCCESS;
    }

    if (secretLen < 0)
    { /* this is an error code */
        return secretLen;
    }
    rc = tls13DeriveEarlySecrets(ssl,
            ssl->sec.tls13ChosenPsk);
    if (rc < 0)
    {
        return rc;
    }

    /* Derive-Secret(Early Secret, "derived", "") */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13EarlySecret,
            secretLen,
            derivedLabel,
            derivedLabelLen,
            &zeroByte,
            0,
            derivedSecret);
    if (rc < 0)
    {
        return rc;
    }
    tls13ClearSecret(ssl->sec.tls13EarlySecret, secretLen);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("\"derived\" secret", derivedSecret, secretLen);
#endif

    rc = tls13GenSharedSecret(ssl, &sharedSecret, &sharedSecretLen);
    if (rc < 0)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return rc;
    }

    /* HKDF-Extract(ECDHE, derivedSecret) == Handshake Secret */
    rc = psHkdfExtract(hmacAlg,
            derivedSecret,
            secretLen,
            sharedSecret,
            sharedSecretLen,
            ssl->sec.tls13HandshakeSecret,
            &hsSecretLen);
    if (rc < 0)
    {
        return rc;
    }
    psAssert(hsSecretLen == secretLen);
    tls13ClearSecret(sharedSecret, sharedSecretLen);
    psFree(sharedSecret, ssl->hsPool);
    tls13ClearSecret(derivedSecret, secretLen);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("Handshake Secret",
            ssl->sec.tls13HandshakeSecret, secretLen);
#endif

    /* DeriveSecret(Handshake Secret, "c hs traffic",
                    Transcript-Hash(ClientHello..ServerHello) ) */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13HandshakeSecret,
            secretLen,
            cHsTrafficLabel,
            trafficLabelLen,
            ssl->sec.tls13TrHashSnapshotCHtoSH,
            secretLen,
            ssl->sec.tls13HsTrafficSecretClient);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("client_handshake_traffic_secret",
            ssl->sec.tls13HsTrafficSecretClient, secretLen);
#endif

    /* DeriveSecret(Handshake Secret, "s hs traffic",
                    Transcript-Hash(ClientHello..ServerHello) ) */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13HandshakeSecret,
            secretLen,
            sHsTrafficLabel,
            trafficLabelLen,
            ssl->sec.tls13TrHashSnapshotCHtoSH,
            secretLen,
            ssl->sec.tls13HsTrafficSecretServer);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("server_handshake_traffic_secret",
            ssl->sec.tls13HsTrafficSecretServer, secretLen);
#endif

    ssl->sec.tls13KsState.deriveHandshakeTrafficSecretsDone = 1;
    return PS_SUCCESS;
}

int32_t tls13DeriveAppTrafficSecrets(ssl_t *ssl)
{
    unsigned char derivedSecret[MAX_TLS_1_3_HASH_SIZE];
    unsigned char zeroKey[MAX_TLS_1_3_HASH_SIZE] = {0};
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    psSize_t secretLen;
    psSize_t hsSecretLen;
    unsigned char zeroByte = 0;
    int32_t rc = psGetOutputBlockLength(hmacAlg);

    if (ssl->sec.tls13KsState.deriveAppTrafficSecretsDone)
    {
        return PS_SUCCESS;
    }

    if (rc < 0)
    { /* this is an error code */
        return rc;
    }
    secretLen = rc;

    /* Derive-Secret(Handshake Secret, "derived", "") */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13HandshakeSecret,
            secretLen,
            derivedLabel,
            derivedLabelLen,
            &zeroByte,
            0,
            derivedSecret);
    if (rc < 0)
    {
        return rc;
    }
    tls13ClearSecret(ssl->sec.tls13HandshakeSecret, secretLen);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("\"derived\" secret", derivedSecret, secretLen);
#endif

    /* HKDF-Extract(0..0, derivedSecret) == Master Secret */
    rc = psHkdfExtract(hmacAlg,
            derivedSecret,
            secretLen,
            zeroKey,
            secretLen,
            ssl->sec.tls13MasterSecret,
            &hsSecretLen);
    if (rc < 0)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("Master Secret", ssl->sec.tls13MasterSecret, secretLen);
#endif

    psAssert(hsSecretLen == secretLen);
    tls13ClearSecret(derivedSecret, secretLen);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("HS hash", ssl->sec.tls13TrHashSnapshot, secretLen);
#endif

    /* DeriveSecret(Master Secret, "c ap traffic",
                    Transcript-Hash(ClientHello..Server Finished) ) */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13MasterSecret,
            secretLen,
            cApTrafficLabel,
            trafficLabelLen,
            ssl->sec.tls13TrHashSnapshot,
            secretLen,
            ssl->sec.tls13AppTrafficSecretClient);
    if (rc < 0)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("client_application_data_secret_0",
            ssl->sec.tls13AppTrafficSecretClient, secretLen);
#endif

    /* DeriveSecret(Master Secret, "s ap traffic",
                    Transcript-Hash(ClientHello..Server Finished) ) */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13MasterSecret,
            secretLen,
            sApTrafficLabel,
            trafficLabelLen,
            ssl->sec.tls13TrHashSnapshot,
            secretLen,
            ssl->sec.tls13AppTrafficSecretServer);
    if (rc < 0)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("server_application_data_secret_0",
            ssl->sec.tls13AppTrafficSecretServer, secretLen);
#endif



    ssl->sec.tls13KsState.deriveAppTrafficSecretsDone = 1;
    return PS_SUCCESS;
}

int32_t tls13DeriveResumptionMasterSecret(ssl_t *ssl)
{
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    psSize_t secretLen;
    int32_t rc = psGetOutputBlockLength(hmacAlg);

    if (rc < 0)
    { /* this is an error code */
        return rc;
    }
    secretLen = rc;

    /* Derive-Secret(Master Secret, "res master",
                     Transcript-Hash(ClientHello...client Finished) ) */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13MasterSecret,
            secretLen,
            resLabel,
            resLabelLen,
            ssl->sec.tls13TrHashSnapshot,
            secretLen,
            ssl->sec.tls13ResumptionMasterSecret);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

int32_t tls13DeriveHandshakeKeys(ssl_t *ssl)
{
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    int32_t rc = psGetOutputBlockLength(hmacAlg);
    psSize_t secretLen;
    psBool_t isServer = (ssl->flags & SSL_FLAGS_SERVER) ? PS_TRUE : PS_FALSE;
    unsigned char *inputSecretRead, *inputSecretWrite;

    if (ssl->sec.tls13KsState.deriveHandshakeKeysDone)
    {
        return PS_SUCCESS;
    }

    if (rc < 0)
    { /* this is an error code */
        return rc;
    }
    secretLen = rc;

    if (isServer)
    {
        inputSecretRead = ssl->sec.tls13HsTrafficSecretClient;
        inputSecretWrite = ssl->sec.tls13HsTrafficSecretServer;
    }
    else
    {
        inputSecretRead = ssl->sec.tls13HsTrafficSecretServer;
        inputSecretWrite = ssl->sec.tls13HsTrafficSecretClient;
    }

    /* Read keys. */

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretRead,
            secretLen,
            "key",
            3,
            NULL,
            0,
            ssl->cipher->keySize,
            ssl->sec.tls13HsReadKey);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13HsReadKey",
            ssl->sec.tls13HsReadKey, ssl->cipher->keySize);
#endif

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretRead,
            secretLen,
            "iv",
            2,
            NULL,
            0,
            ssl->cipher->ivSize,
            ssl->sec.tls13HsReadIv);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13HsReadIv",
            ssl->sec.tls13HsReadIv, ssl->cipher->ivSize);
    psTraceBytes("inputSecretWrite", inputSecretWrite, secretLen);
#endif

    /* Write keys. */

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretWrite,
            secretLen,
            "key",
            3,
            NULL,
            0,
            ssl->cipher->keySize,
            ssl->sec.tls13HsWriteKey);
    if (rc < 0)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13HsWriteKey",
            ssl->sec.tls13HsWriteKey, ssl->cipher->keySize);
#endif

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretWrite,
            secretLen,
            "iv",
            2,
            NULL,
            0,
            ssl->cipher->ivSize,
            ssl->sec.tls13HsWriteIv);
    if (rc < 0)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13HsWriteIv",
            ssl->sec.tls13HsWriteIv, ssl->cipher->ivSize);
#endif

    ssl->sec.tls13KsState.deriveHandshakeKeysDone = 1;
    return PS_SUCCESS;
}

int32_t tls13DeriveEarlyDataSecret(ssl_t *ssl, psTls13Psk_t *psk)
{
    int32_t hmacAlg;
    unsigned char *trHash;
    psSize_t secretLen;
    int32_t rc;

    /* A PSK is required for early data. */
    if (psk == NULL)
    {
        return PS_SUCCESS;
    }

    rc = tls13GenerateEarlySecret(ssl, psk);
    if (rc < 0)
    {
        return rc;
    }

    hmacAlg = tls13GetPskHmacAlg(psk);
    secretLen = tls13GetPskHashLen(psk);

    if (hmacAlg == HMAC_SHA256)
    {
        trHash = ssl->sec.tls13TrHashSnapshotCH;
    }
    else
    {
        trHash = ssl->sec.tls13TrHashSnapshotCHSha384;
    }

# ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("ED snapshot CH", trHash, secretLen);
    psTraceIntInfo("ED hmac alg: %d\n", hmacAlg);
# endif

    /* Derive-Secret(Early Secret, "c e traffic", "") */
    rc = tls13DeriveSecret(ssl,
            hmacAlg,
            ssl->sec.tls13EarlySecret,
            secretLen,
            cEarlyTrafficLabel,
            earlyTrafficLabelLen,
            trHash,
            secretLen,
            ssl->sec.tls13EarlyTrafficSecretClient);
    if (rc < 0)
    {
        return rc;
    }
# ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13EarlyTrafficSecretClient",
            ssl->sec.tls13EarlyTrafficSecretClient, secretLen);
# endif
    return PS_SUCCESS;
}


int32_t tls13DeriveEarlyDataKeys(ssl_t *ssl)
{
    int32_t rc;
    int32_t hmacAlg;
    psSize_t secretLen;
    unsigned char *inputSecretRead;

    if (ssl->sec.tls13KsState.deriveEarlyDataKeysDone)
    {
        return PS_SUCCESS;
    }

    hmacAlg = tls13GetPskHmacAlg(ssl->sec.tls13SessionPskList);
    secretLen = tls13GetPskHashLen(ssl->sec.tls13SessionPskList);

    inputSecretRead = ssl->sec.tls13EarlyTrafficSecretClient;

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretRead,
            secretLen,
            "key",
            3,
            NULL,
            0,
            ssl->cipher->keySize,
            ssl->sec.tls13EarlyDataKey);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13EarlyDataKey",
            ssl->sec.tls13EarlyDataKey, ssl->cipher->keySize);
#endif

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretRead,
            secretLen,
            "iv",
            2,
            NULL,
            0,
            ssl->cipher->ivSize,
            ssl->sec.tls13EarlyDataIv);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13EarlyDataIv",
            ssl->sec.tls13EarlyDataIv, ssl->cipher->ivSize);
#endif

    ssl->sec.tls13KsState.deriveEarlyDataKeysDone = 1;
    return PS_SUCCESS;
}

int32_t tls13DeriveAppKeys(ssl_t *ssl)
{
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    int32_t rc = psGetOutputBlockLength(hmacAlg);
    psSize_t secretLen;
    psBool_t isServer = (ssl->flags & SSL_FLAGS_SERVER) ? PS_TRUE : PS_FALSE;
    unsigned char *inputSecretRead, *inputSecretWrite;

    if (ssl->sec.tls13KsState.deriveAppKeysDone)
    {
        return PS_SUCCESS;
    }

    if (rc < 0)
    { /* this is an error code */
        return rc;
    }
    secretLen = rc;

    if (isServer)
    {
        inputSecretRead = ssl->sec.tls13AppTrafficSecretClient;
        inputSecretWrite = ssl->sec.tls13AppTrafficSecretServer;
    }
    else
    {
        inputSecretRead = ssl->sec.tls13AppTrafficSecretServer;
        inputSecretWrite = ssl->sec.tls13AppTrafficSecretClient;
    }

    /* Read keys. */

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretRead,
            secretLen,
            "key",
            3,
            NULL,
            0,
            ssl->cipher->keySize,
            ssl->sec.tls13AppReadKey);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13AppReadKey",
            ssl->sec.tls13AppReadKey, ssl->cipher->keySize);
#endif

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretRead,
            secretLen,
            "iv",
            2,
            NULL,
            0,
            ssl->cipher->ivSize,
            ssl->sec.tls13AppReadIv);
    if (rc < 0)
    {
        return rc;
    }
#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13AppReadIv",
            ssl->sec.tls13AppReadIv, ssl->cipher->ivSize);
    psTraceBytes("inputSecretWrite", inputSecretWrite, secretLen);
#endif

    /* Write keys. */

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretWrite,
            secretLen,
            "key",
            3,
            NULL,
            0,
            ssl->cipher->keySize,
            ssl->sec.tls13AppWriteKey);
    if (rc < 0)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13AppWriteKey",
            ssl->sec.tls13AppWriteKey, ssl->cipher->keySize);
#endif

    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            inputSecretWrite,
            secretLen,
            "iv",
            2,
            NULL,
            0,
            ssl->cipher->ivSize,
            ssl->sec.tls13AppWriteIv);
    if (rc < 0)
    {
        return rc;
    }

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("tls13AppWriteIv",
            ssl->sec.tls13AppWriteIv, ssl->cipher->ivSize);
#endif

    ssl->sec.tls13KsState.deriveAppKeysDone = 1;
    return PS_SUCCESS;
}

int32_t tls13DeriveBinderKey(ssl_t *ssl,
        int32_t hmacAlg,
        unsigned char *binderSecret,
        psSize_t binderSecretLen,
        unsigned char *binderKeyOut,
        psSize_t *binderKeyOutLen)
{
    int32 rc;
    psSize_t secretLen;
    unsigned char *base_key;

    base_key = binderSecret;

    rc = psGetOutputBlockLength(hmacAlg);
    if (rc < 0)
    { /* this is an error code */
        return rc;
    }
    secretLen = rc;

    /*
      finished_key =
      HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    */
    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            base_key,
            secretLen,
            finishedLabel,
            finishedLabelLen,
            NULL,
            0,
            secretLen,
            binderKeyOut);
    if (rc < 0)
    {
        return rc;
    }

    *binderKeyOutLen = secretLen;

    tls13ClearSecret(base_key, secretLen);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("Binder key", binderKeyOut, *binderKeyOutLen);
#endif

    return PS_SUCCESS;
}

int32_t tls13DeriveFinishedKey(ssl_t *ssl, psBool_t wantServerKey)
{
    int32_t hmacAlg = tls13GetCipherHmacAlg(ssl);
    int32 rc = psGetOutputBlockLength(hmacAlg);
    psSize_t secretLen;
    unsigned char *base_key;

    if (wantServerKey)
    {
        if (ssl->sec.tls13KsState.deriveServerFinishedKeyDone)
        {
            return PS_SUCCESS;
        }
        base_key = ssl->sec.tls13HsTrafficSecretServer;
    }
    else
    {
        if (ssl->sec.tls13KsState.deriveClientFinishedKeyDone)
        {
            return PS_SUCCESS;
        }
        base_key = ssl->sec.tls13HsTrafficSecretClient;
    }

    if (rc < 0)
    { /* this is an error code */
        return rc;
    }
    secretLen = rc;

    /*
      finished_key =
      HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    */
    rc = psHkdfExpandLabel(ssl->hsPool,
            hmacAlg,
            base_key,
            secretLen,
            finishedLabel,
            finishedLabelLen,
            NULL,
            0,
            secretLen,
            ssl->sec.tls13FinishedKey);
    if (rc < 0)
    {
        return rc;
    }

    tls13ClearSecret(base_key, secretLen);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("Finished key", ssl->sec.tls13FinishedKey, secretLen);
#endif

    if (wantServerKey)
    {
        ssl->sec.tls13KsState.deriveServerFinishedKeyDone = 1;
    }
    else
    {
        ssl->sec.tls13KsState.deriveClientFinishedKeyDone = 1;
    }

    return PS_SUCCESS;
}

int32_t tls13ActivateEarlyDataWriteKeys(ssl_t *ssl)
{
    int32_t rc;

    psTraceInfo("++++ K_send = early_traffic ++++\n");

    ssl->sec.wKeyptr = ssl->sec.tls13EarlyDataKey;
    ssl->sec.wIVptr = ssl->sec.tls13EarlyDataIv;

    Memcpy(ssl->sec.tls13WriteIv, ssl->sec.tls13EarlyDataIv,
            ssl->cipher->ivSize);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("early_data write key", ssl->sec.tls13EarlyDataKey,
            ssl->cipher->keySize);
    psTraceBytes("early_data write iv", ssl->sec.tls13EarlyDataIv,
            ssl->cipher->ivSize);
#endif

    Memset(ssl->sec.seq, 0, 8);

    rc = sslActivateWriteCipher(ssl);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

int32_t tls13ActivateEarlyDataReadKeys(ssl_t *ssl)
{
    int32_t rc;

    psTraceInfo("++++ K_recv = early_traffic ++++\n");

    ssl->sec.rKeyptr = ssl->sec.tls13EarlyDataKey;
    ssl->sec.rIVptr = ssl->sec.tls13EarlyDataIv;

    Memcpy(ssl->sec.tls13ReadIv, ssl->sec.tls13EarlyDataIv,
            ssl->cipher->ivSize);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("early_data read key", ssl->sec.tls13EarlyDataKey,
            ssl->cipher->keySize);
    psTraceBytes("early_data read iv", ssl->sec.tls13EarlyDataIv,
            ssl->cipher->ivSize);
#endif

    Memset(ssl->sec.seq, 0, 8);

    rc = sslActivateReadCipher(ssl);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

int32_t tls13ActivateHsWriteKeys(ssl_t *ssl)
{
    int32_t rc;

    psTraceInfo("++++ K_send = handshake ++++\n");

    ssl->sec.wKeyptr = ssl->sec.tls13HsWriteKey;
    ssl->sec.wIVptr = ssl->sec.tls13HsWriteIv;

    Memcpy(ssl->sec.tls13WriteIv, ssl->sec.tls13HsWriteIv,
            ssl->cipher->ivSize);

    rc = sslActivateWriteCipher(ssl);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

int32_t tls13ActivateHsReadKeys(ssl_t *ssl)
{
    int32_t rc;

    psTraceInfo("++++ K_recv = handshake ++++\n");

    ssl->sec.rKeyptr = ssl->sec.tls13HsReadKey;
    ssl->sec.rIVptr = ssl->sec.tls13HsReadIv;

    Memcpy(ssl->sec.tls13ReadIv, ssl->sec.tls13HsReadIv,
            ssl->cipher->ivSize);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("handshake read key", ssl->sec.tls13HsReadKey,
            ssl->cipher->keySize);
#endif

    rc = sslActivateReadCipher(ssl);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

int32_t tls13ActivateAppWriteKeys(ssl_t *ssl)
{
    int32_t rc;

    psTraceInfo("++++ K_send = application ++++\n");

    ssl->sec.wKeyptr = ssl->sec.tls13AppWriteKey;
    ssl->sec.wIVptr = ssl->sec.tls13AppWriteIv;

    Memcpy(ssl->sec.tls13WriteIv, ssl->sec.tls13AppWriteIv,
            ssl->cipher->ivSize);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("app write key", ssl->sec.tls13AppWriteKey,
            ssl->cipher->keySize);
    psTraceBytes("app write iv", ssl->sec.tls13AppWriteIv,
            ssl->cipher->ivSize);
#endif

    Memset(ssl->sec.seq, 0, 8);

    rc = sslActivateWriteCipher(ssl);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}

int32_t tls13ActivateAppReadKeys(ssl_t *ssl)
{
    int32_t rc;

    psTraceInfo("++++ K_recv = application ++++\n");

    ssl->sec.rKeyptr = ssl->sec.tls13AppReadKey;
    ssl->sec.rIVptr = ssl->sec.tls13AppReadIv;

    Memcpy(ssl->sec.tls13ReadIv, ssl->sec.tls13AppReadIv,
            ssl->cipher->ivSize);

#ifdef DEBUG_TLS_1_3_KEY_DERIVE
    psTraceBytes("app read key", ssl->sec.tls13AppReadKey,
            ssl->cipher->keySize);
    psTraceBytes("app read iv", ssl->sec.tls13AppReadIv,
            ssl->cipher->ivSize);
#endif

    Memset(ssl->sec.remSeq, 0, 8);

    rc = sslActivateReadCipher(ssl);
    if (rc < 0)
    {
        return rc;
    }

    return PS_SUCCESS;
}


#endif /* USE_TLS_1_3 */
