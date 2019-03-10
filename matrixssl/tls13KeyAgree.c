/**
 *      @file    tls13KeyAgree.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 specific functions for key agreement.
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

# ifndef DEBUG_TLS_1_3_KEY_AGREE
/* #  define DEBUG_TLS_1_3_KEY_AGREE */
# endif

# ifdef USE_TLS_1_3

#  ifdef USE_DH
#   include "tls13DhGroups.h"

int32_t tls13LoadDhParams(ssl_t *ssl,
        uint16_t namedGroup,
        psDhParams_t *params)
{
    int32_t rc;
    const unsigned char *bin;
    psSize_t binLen;

    switch (namedGroup)
    {
    case namedgroup_ffdhe2048:
        bin = ffdhe2048_params;
        binLen = sizeof(ffdhe2048_params);
        break;
    case namedgroup_ffdhe3072:
        bin = ffdhe3072_params;
        binLen = sizeof(ffdhe3072_params);
        break;
    case namedgroup_ffdhe4096:
        bin = ffdhe4096_params;
        binLen = sizeof(ffdhe4096_params);
        break;
    default:
        psTracePrintTls13NamedGroup(0,
                "Unsupported DHE params",
                namedGroup, PS_TRUE);
        return PS_UNSUPPORTED_FAIL;
    }

    rc = psPkcs3ParseDhParamBin(ssl->hsPool,
            bin,
            binLen,
            params);
    if (rc < 0)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return rc;
    }

    psTracePrintTls13NamedGroup(0,
            "Loaded DHE params",
            namedGroup, PS_TRUE);

    return PS_SUCCESS;
}
#  endif /* USE_DH */

# ifndef USE_ONLY_PSK_CIPHER_SUITE
int32_t tls13ImportPublicValue(ssl_t *ssl,
        const unsigned char *keyExchangeData,
        psSize_t keyExchangeDataLen,
        uint16_t namedGroup)
{
    int32_t rc;

    if (psIsEcdheGroup(namedGroup))
    {
        if (namedGroup == namedgroup_x25519)
        {
#   ifdef USE_X25519
            if (keyExchangeDataLen != PS_DH_X25519_PUBLIC_KEY_BYTES)
            {
                ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
                return MATRIXSSL_ERROR;
            }
            if (ssl->sec.x25519KeyPub != NULL)
            {
                psFree(ssl->sec.x25519KeyPub, ssl->sec.eccDhKeyPool);
            }
            ssl->sec.x25519KeyPub = psMalloc(ssl->sec.eccDhKeyPool,
                    PS_DH_X25519_PUBLIC_KEY_BYTES);
            Memcpy(ssl->sec.x25519KeyPub,
                    keyExchangeData,
                    PS_DH_X25519_PUBLIC_KEY_BYTES);
            return PS_SUCCESS;
#   else
            goto out_internal_error;
#   endif
        }
        else
        {
#   ifdef USE_ECC
            const psEccCurve_t *curve;
            rc = getEccParamById(namedGroup, &curve);
            if (rc < 0)
            {
                goto out_internal_error;
            }

            if (ssl->sec.eccKeyPub != NULL)
            {
                psEccClearKey(ssl->sec.eccKeyPub);
            }

            rc = psEccNewKey(ssl->hsPool, &ssl->sec.eccKeyPub, curve);
            if (rc < 0)
            {
                psTraceErrr("Unable to create new EC key\n");
                goto out_internal_error;
            }

            rc = psEccX963ImportKey(
                    ssl->hsPool,
                    keyExchangeData,
                    keyExchangeDataLen,
                    ssl->sec.eccKeyPub,
                    curve);
            if (rc < 0)
            {
                psTraceErrr("Could not import peer ECDHE public value\n");
                goto out_handshake_failure;
            }
#    ifdef DEBUG_TLS_1_3_KEY_AGREE
            psTraceIntInfo("Imported ECDHE pub val of length %d\n",
                           keyExchangeDataLen);
#    endif
#   else
            goto out_internal_error;
#   endif /* USE_ECC */
        }
    }
    else
    {
#   ifndef USE_DH
        psTraceInfo("Need USE_DH to be able to import DHE public values\n");
        goto out_internal_error;
#   else
        ssl->sec.dhKeyPub = psMalloc(ssl->hsPool,
                sizeof(psDhKey_t));
        if (ssl->sec.dhKeyPub == NULL)
        {
            return PS_MEM_FAIL;
        }
        rc = psDhImportPubKey(ssl->hsPool,
                keyExchangeData,
                keyExchangeDataLen,
                ssl->sec.dhKeyPub);
        if (rc < 0)
        {
            psTraceErrr("Could not import peer DHE public value\n");
            goto out_handshake_failure;
        }
#    ifdef DEBUG_TLS_1_3_KEY_AGREE
        psTraceIntInfo("Imported DHE pub val of length %d\n",
                keyExchangeDataLen);
#    endif
#   endif /* USE_DH */
    }

    return MATRIXSSL_SUCCESS;

out_handshake_failure:
    ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
    return MATRIXSSL_ERROR;
out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}

int32_t tls13ExportPublicValue(ssl_t *ssl,
        uint16_t namedGroup,
        psPubKey_t *key,
        unsigned char **out,
        psSize_t *outLen)
{
    int32_t rc;
    psSize_t pubValLen;
    unsigned char *pubVal;

    if (psIsEcdheGroup(namedGroup))
    {
        if (namedGroup == namedgroup_x25519)
        {
#   ifdef USE_X25519
            pubVal = psMalloc(ssl->hsPool,
                    PS_DH_X25519_PUBLIC_KEY_BYTES);
            if (pubVal == NULL)
            {
                goto out_internal_error;
            }
            Memcpy(pubVal,
                    key->key.x25519.pub,
                    PS_DH_X25519_PUBLIC_KEY_BYTES);
            pubValLen = PS_DH_X25519_PUBLIC_KEY_BYTES;
#   else
            goto out_internal_error;
#   endif /* USE_X25519 */
        }
        else
        {
#   ifdef USE_ECC
            pubValLen = key->key.ecc.curve->size*2 + 1;
            pubVal = psMalloc(ssl->hsPool, pubValLen);
            if (pubVal == NULL)
            {
                goto out_internal_error;
            }

            rc = psEccX963ExportKey(ssl->hsPool,
                    &key->key.ecc,
                    pubVal,
                    &pubValLen);
            if (rc < 0)
            {
                psFree(pubVal, ssl->hsPool);
                goto out_internal_error;
            }
#     ifdef DEBUG_TLS_1_3_KEY_AGREE
            psTraceIntInfo("Exported ECDHE pub val of length %d\n",
                           pubValLen);
#     endif
#   else
            goto out_internal_error;
#   endif /* USE_ECC */
        }
    }
    else
    {
#   ifndef USE_DH
        psTraceInfo("Need USE_DH to export DHE pub values\n");
        goto out_internal_error;
#   else
        pubValLen = key->key.dh.size;
        pubVal = psMalloc(ssl->hsPool, pubValLen);
        if (pubVal == NULL)
        {
            goto out_internal_error;
        }

        rc = psDhExportPubKey(ssl->hsPool,
                &key->key.dh,
                pubVal,
                &pubValLen);
        if (rc < 0)
        {
            psFree(pubVal, ssl->hsPool);
            goto out_internal_error;
        }
#   endif /* USE_DH */
    }
    *out = pubVal;
    *outLen = pubValLen;

    return PS_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}


#  ifdef USE_ECC
/** Generate an ECDHE private key given the curve NamedGroup id. */
int32_t tls13GenerateEcdheKey(ssl_t *ssl,
        psEccKey_t *key,
        uint16_t namedGroup)
{
    int32_t rc;
    void *pkiData = ssl->userPtr;
    const psEccCurve_t *curve;

    psTraceInfo("Generating new ECDHE private key\n");

    rc = getEccParamById(namedGroup,
            &curve);
    if (rc < 0)
    {
        return rc;
    }

    rc = psEccInitKey(ssl->hsPool, key, curve);
    if (rc < 0)
    {
        return rc;
    }

    rc = matrixSslGenEphemeralEcKey(ssl->keys,
            key,
            curve,
            pkiData);
    if (rc < 0)
    {
        return rc;
    }

    psTraceStrInfo("Generated new ECDHE key on curve: %s\n",
            key->curve->name);

    return PS_SUCCESS;
}
#  endif /* USE_ECC */

static
int32_t tls13GenerateKeyForGroup(ssl_t *ssl, uint16_t namedGroup)
{
    psSize_t i;
    int32_t rc;

    psAssert(psIsGroupSupported(namedGroup));

# ifdef DEBUG_TLS_1_3_KEY_AGREE
    psTracePrintTls13NamedGroup(0,
            "Generating key for group",
            namedGroup,
            PS_TRUE);
# endif

    /* Find the correct spot. */
    for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
    {
        if (ssl->tls13SupportedGroups[i] == namedGroup)
        {
            break;
        }
    }
    if (i == TLS_1_3_MAX_GROUPS)
    {
        psTraceIntInfo("Unsupported group: %d\n", (int)namedGroup);
        goto out_internal_error;
    }

    /* We might be in the middle of a resumed flight creation,
       where we have to encode the same message again after
       buffer reallocation. Do not re-generate in that case. */
    if (ssl->sec.tls13KeyAgreeKeys[i] != NULL)
    {
# ifdef DEBUG_TLS_1_3_KEY_AGREE
        psTraceInfo("Already generated.\n");
# endif
        return PS_SUCCESS;
    }

    /* Generate the ephemeral key pair. */
    if (psIsEcdheGroup(namedGroup))
    {
# if defined(USE_ECC) || defined(USE_X25519)
        psPubKey_t *key;
        uint8_t keyType;

        if (namedGroup == namedgroup_x25519)
        {
            keyType = PS_X25519;
        }
        else
        {
            keyType = PS_ECC;
        }

        rc = psNewPubKey(ssl->hsPool,
                keyType,
                &ssl->sec.tls13KeyAgreeKeys[i]);
        if (rc < 0)
        {
            goto out_internal_error;
        }
        key = ssl->sec.tls13KeyAgreeKeys[i];

#  ifdef USE_X25519
        if (namedGroup == namedgroup_x25519)
        {
            psRes_t res;

            res = psDhX25519GenKey(key->key.x25519.priv,
                    key->key.x25519.pub);
            if (res < 0)
            {
                goto out_internal_error;
            }
            return PS_SUCCESS;
        }
#  endif /* USE_X25519 */

        rc = tls13GenerateEcdheKey(ssl,
                &key->key.ecc,
                namedGroup);
        if (rc < 0)
        {
            goto out_internal_error;
        }
# else
            goto out_internal_error;
# endif
    }
    else
    {
# ifndef USE_DH
        psTraceErrr("Need USE_DH for ffdhe* group support\n");
        goto out_internal_error;
# else
        rc = psNewPubKey(ssl->hsPool,
                PS_DH,
                &ssl->sec.tls13KeyAgreeKeys[i]);
        if (rc < 0)
        {
            goto out_internal_error;
        }

        /* Ignore whatever DH params the user may have loaded for TLS 1.2. */
        if (ssl->keys->dhParams.size != 0)
        {
            psPkcs3ClearDhParams(&ssl->keys->dhParams);
        }

        rc = tls13LoadDhParams(ssl,
                namedGroup,
                &ssl->keys->dhParams);
        if (rc < 0)
        {
            return rc;
        }

        rc = psDhGenKeyParams(ssl->hsPool,
                &ssl->keys->dhParams,
                &ssl->sec.tls13KeyAgreeKeys[i]->key.dh,
                NULL);
        if (rc < 0)
        {
            goto out_internal_error;
        }
# endif /* !USE_DH */
    }

    return PS_SUCCESS;

out_internal_error:
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/** Return the element with the lowest sum of indexes from the
    intersection of two priority-ordered arrays a and b, such that
    the element does not belong to the forbidden element list f.
    Return error when the intersection is empty or all elements
    in the intersection belong to f. If the intersection has two
    elements with the same index sum, return the latter element.

    Precondition: The input arrays must be arranged in priority
    order such that the highest-priority item is at index 0.
*/
int32_t tls13IntersectionPrioritySelect(const uint32_t *a,
        psSize_t aLen,
        const uint32_t *b,
        psSize_t bLen,
        const uint32_t *f,
        psSize_t fLen,
        uint32_t *selectedElement)
{
    psSize_t sum, minSum;
    uint32_t best;
    psSize_t i, k, l;
    psBool_t foundCommon = PS_FALSE;
    psBool_t forbidden;

    if (aLen == 0 || bLen == 0)
    {
        /* Empty intersection. */
        return PS_ARG_FAIL;
    }

    best = a[0];
    minSum = aLen + bLen - 2;

    for (i = 0; i < aLen; i++)
    {
        for (k = 0; k < bLen; k++)
        {
            if (a[i] == b[k])
            {
                forbidden = PS_FALSE;
                if (f != NULL)
                {
                    for (l = 0; l < fLen; l++)
                    {
                        if (a[i] == f[l])
                        {
                            forbidden = PS_TRUE;
                            break;
                        }
                    }
                }
                if (!forbidden)
                {
                    sum = i + k;
                    if (sum <= minSum)
                    {
                        minSum = sum;
                        best = a[i];
                        foundCommon = PS_TRUE;
                    }
                }
            }
        }
    }

    if (foundCommon)
    {
        if (selectedElement != NULL)
        {
            *selectedElement = best;
        }
        return PS_SUCCESS;
    }
    else
    {
        /* Empty intersection. */
        return PS_ARG_FAIL;
    }
}

/* An uint16_t wrapper for tls13IntersectionPrioritySelect.*/
int32_t tls13IntersectionPrioritySelectU16(const uint16_t *a,
        psSize_t aLen,
        const uint16_t *b,
        psSize_t bLen,
        const uint16_t *f,
        psSize_t fLen,
        uint16_t *selectedElement)
{
    uint32_t selectedElement32 = *selectedElement;
    uint32_t *a32 = NULL;
    uint32_t *b32 = NULL;
    uint32_t *f32 = NULL;
    int32_t rc = PS_ARG_FAIL;
    psSize_t i;

    a32 = psMalloc(ssl->hsPool, aLen * sizeof(uint32_t));
    if (a32 == NULL)
    {
        psTraceInfo("Out of mem in tls13NegotiateGroup\n");
        goto out;
    }
    b32 = psMalloc(ssl->hsPool, bLen * sizeof(uint32_t));
    if (b32 == NULL)
    {
        psTraceInfo("Out of mem in tls13NegotiateGroup\n");
        goto out;
    }
    f32 = psMalloc(ssl->hsPool, bLen * sizeof(uint32_t));
    if (f32 == NULL)
    {
        psTraceInfo("Out of mem in tls13NegotiateGroup\n");
        goto out;
    }
    for (i = 0; i < aLen; i++)
    {
        a32[i] = a[i];
    }
    for (i = 0; i < bLen; i++)
    {
        b32[i] = b[i];
    }
    for (i = 0; i < fLen; i++)
    {
        f32[i] = f[i];
    }

    rc = tls13IntersectionPrioritySelect(a32,
            aLen,
            b32,
            bLen,
            f32,
            fLen,
            &selectedElement32);

    *selectedElement = selectedElement32;

out:
    psFree(a32, ssl->hsPool);
    psFree(b32, ssl->hsPool);
    psFree(f32, ssl->hsPool);

    return rc;
}

/** Given our and the peer's list of supported groups, negotiate
    the group to use, taking into account our and the peer's
    priorities. */
uint16_t tls13NegotiateGroup(ssl_t *ssl,
        uint16_t *peerList,
        psSize_t peerListLen)
{
    uint16_t negotiatedGroup;
    int32_t rc;

    psAssert(ssl->tls13SupportedGroups[0] != 0);

    /* Default. If anything goes wrong, use this. */
    negotiatedGroup = ssl->tls13SupportedGroups[0];

    rc = tls13IntersectionPrioritySelectU16(ssl->tls13SupportedGroups,
            ssl->tls13SupportedGroupsLen,
            peerList,
            peerListLen,
            NULL,
            0,
            &negotiatedGroup);
    if (rc == PS_ARG_FAIL)
    {
        psTraceInfo("tls13IntersectionPrioritySelect failed\n");
    }

    return negotiatedGroup;
}

int32_t tls13ServerChooseGroup(ssl_t *ssl,
        uint16_t *chosenGroup)
{
    uint16_t group;

    group = tls13NegotiateGroup(ssl,
            ssl->tls13PeerKeyShareGroups,
            ssl->tls13PeerKeyShareGroupsLen);

    *chosenGroup = group;
    return PS_SUCCESS;
}

int32_t tls13ServerChooseHelloRetryRequestGroup(ssl_t *ssl,
        uint16_t *chosenGroup)
{
    uint16_t group;

    group = tls13NegotiateGroup(ssl,
            ssl->tls13PeerSupportedGroups,
            ssl->tls13PeerSupportedGroupsLen);

    psTraceInfo("Added key_share to HelloRetryRequest:\n");
    psTracePrintTls13NamedGroup(0, NULL, group, PS_TRUE);

    *chosenGroup = group;
    return PS_SUCCESS;
}

# ifndef USE_ONLY_PSK_CIPHER_SUITE
int32_t tls13GenerateEphemeralKeys(ssl_t *ssl)
{
    psSize_t i;
    psSize_t numKeys;
    uint16_t group;
    int32_t rc;

    if (IS_SERVER(ssl))
    {
        group = ssl->tls13NegotiatedGroup;
        rc = tls13GenerateKeyForGroup(ssl, group);
        if (rc < 0)
        {
                return rc;
        }
        return PS_SUCCESS;
    }
    else
    {
        numKeys = ssl->tls13NumClientHelloKeyShares;
    }

    /*
      If we are the client, we shall use our supported groups list
      and generate shares for the TOP-numKeys groups in that list.
    */

    if (ssl->sec.tls13KsState.generateEcdheKeyDone == 0)
    {
        for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
        {
            /* We shall generate numKeys keys. */
            if (i < numKeys)
            {
                group = ssl->tls13SupportedGroups[i];
                rc = tls13GenerateKeyForGroup(ssl, group);
                if (rc < 0)
                {
                    return rc;
                }
            }
            else
            {
                ssl->sec.tls13KeyAgreeKeys[i] = NULL;
            }
        }
        ssl->sec.tls13KsState.generateEcdheKeyDone = 1;
    }

    return PS_SUCCESS;
}
# endif


# ifdef USE_ECC
static inline
int32_t tls13GenSharedSecretNist(ssl_t *ssl,
        psPubKey_t *privKey,
        unsigned char **secretOut,
        psSize_t *secretOutLen)
{
    unsigned char *secret = NULL;
    psSize_t secretLen;
    int32_t rc;

    psAssert(privKey->type == PS_ECC);
    psAssert(ssl->sec.eccKeyPub != NULL);

    if (privKey->key.ecc.curve != ssl->sec.eccKeyPub->curve)
    {
        goto out_internal_error;
    }

    secretLen = privKey->key.ecc.curve->size;

    secret = psMalloc(ssl->eccDhKeyPool, secretLen);
    if (secret == NULL)
    {
        goto out_internal_error;
    }

    /* Generate ECDHE shared secret. */
    rc = psEccGenSharedSecret(ssl->sec.eccDhKeyPool,
            &privKey->key.ecc,
            ssl->sec.eccKeyPub,
            secret,
            &secretLen,
            NULL);
    if (rc < 0)
    {
        psTraceErrr("Failed to generate ECDHE shared secret\n");
        goto out_internal_error;
    }

    *secretOut = secret;
    *secretOutLen = secretLen;

    return PS_SUCCESS;

out_internal_error:
    if (secret != NULL)
    {
        psFree(secret, ssl->hsPool);
    }
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}

# endif /* USE_ECC */
# ifdef USE_X25519
static inline
int32_t tls13GenSharedSecretX25519(ssl_t *ssl,
        psPubKey_t *privKey,
        unsigned char **secretOut,
        psSize_t *secretOutLen)
{
    unsigned char *secret = NULL;
    psSize_t secretLen;
    psRes_t res;

    psAssert(privKey->type == PS_X25519);
    psAssert(ssl->sec.x25519KeyPub != NULL);

    secretLen = PS_DH_X25519_PUBLIC_KEY_BYTES;
    secret = psMalloc(ssl->eccDhKeyPool, secretLen);
    if (secret == NULL)
    {
        goto out_internal_error;
    }

    res = psDhX25519GenSharedSecret(ssl->sec.x25519KeyPub,
            privKey->key.x25519.priv,
            secret);
    if (res != PS_SUCCESS)
    {
        goto out_internal_error;
    }

    *secretOut = secret;
    *secretOutLen = secretLen;

    return PS_SUCCESS;

out_internal_error:
    if (secret != NULL)
    {
        psFree(secret, ssl->hsPool);
    }
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}
# endif /* USE_X25519 */

# ifdef USE_DH
static inline
int32_t tls13GenSharedSecretDh(ssl_t *ssl,
        psPubKey_t *privKey,
        unsigned char **secretOut,
        psSize_t *secretOutLen)
{
    unsigned char *secret = NULL;
    psSize_t secretLen;
    psSize_t padLen;
    int32_t rc;

    psAssert(privKey->type == PS_DH);
    psAssert(ssl->sec.dhKeyPub != NULL);

    /* psDhGenSharedSecret wants the params as byte arrays.*/
    rc = psDhExportParameters(ssl->hsPool,
            &ssl->keys->dhParams,
            &ssl->sec.dhP,
            &ssl->sec.dhPLen,
            &ssl->sec.dhG,
            &ssl->sec.dhGLen);
    if (rc < 0)
    {
        psTraceErrr("psDhExportParameters failed\n");
        goto out_internal_error;
    }

    secret = psMalloc(ssl->hsPool, privKey->key.dh.size);
    if (secret == NULL)
    {
        goto out_internal_error;
    }

    secretLen = privKey->key.dh.size;

    rc = psDhGenSharedSecret(ssl->hsPool,
            &privKey->key.dh,
            ssl->sec.dhKeyPub,
            ssl->sec.dhP,
            ssl->sec.dhPLen,
            secret,
            &secretLen,
            NULL);
    if (rc < 0)
    {
        psTraceErrr("Failed to generate DHE shared secret\n");
        /* The psDhGenSharedSecret return value is not specific enough
           to know what went wrong. If the 2 <= x < p-1 check failed,
           we should probably send illegal_parameter or insufficient
           security. For now, just map all failures to internal_error
           alerts. */
        goto out_internal_error;
    }

    psAssert(secretLen <= privKey->key.dh.size);
    psAssert(secretLen >= 1);

    /*
      psDhGenSharedSecret removes leading zero octets from the secret.
      However, TLS 1.3 requires that the secret must be of the same
      size as the prime. Reinsert leading zeros here, if needed.
    */
    padLen = privKey->key.dh.size - secretLen;
    if (padLen > 0)
    {
        Memmove(secret + padLen,
                secret,
                secretLen);
        Memset(secret, 0, padLen);
        psTraceIntInfo("Readded %u leading zeros\n", padLen);
        secretLen = privKey->key.dh.size;
    }

    *secretOut = secret;
    *secretOutLen = secretLen;

    return PS_SUCCESS;

out_internal_error:
    if (secret != NULL)
    {
        psFree(secret, ssl->hsPool);
    }
    ssl->err = SSL_ALERT_INTERNAL_ERROR;
    return MATRIXSSL_ERROR;
}
# endif /* USE_DH */

/** Generate shared secret.

    Allocates memory for the secret. Caller must free.

    Preconditions:
    - Private key (ssl->sec.eccKeyPriv) must exist.
    - Peer public value (ssl->sec.eccKeyPub) must exist.
*/
int32_t tls13GenSharedSecret(ssl_t *ssl,
        unsigned char **out,
        psSize_t *outLen)
{
    psSize_t secretLen = 0;
    unsigned char *secret = NULL;
    psPubKey_t *privKey;
    int32_t rc;

    privKey = tls13GetGroupKey(ssl, ssl->tls13NegotiatedGroup);
    psAssert(privKey != NULL);

    switch (privKey->type)
    {
# ifdef USE_ECC
    case PS_ECC:
        rc = tls13GenSharedSecretNist(ssl, privKey, &secret, &secretLen);
        break;
#endif
# ifdef USE_X25519
    case PS_X25519:
        rc = tls13GenSharedSecretX25519(ssl, privKey, &secret, &secretLen);
        break;
# endif
# ifdef USE_DH
    case PS_DH:
        rc = tls13GenSharedSecretDh(ssl, privKey, &secret, &secretLen);
        break;
# endif
    default:
        rc = PS_UNSUPPORTED_FAIL;
        break;
    }

    if (rc == PS_SUCCESS)
    {
# ifdef DEBUG_TLS_1_3_KEY_AGREE
        psTraceBytes("(EC)DHE shared secret", secret, secretLen);
# endif

        *out = secret;
        *outLen = secretLen;
    }
    return rc;
}

/** Return the key corresponding to a NamedGroup.
    Return NULL if we do not support the group.
*/
psPubKey_t *tls13GetGroupKey(ssl_t *ssl,
        uint16_t namedGroup)
{
    psSize_t i;

    for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
    {
        if (ssl->tls13SupportedGroups[i] == namedGroup &&
                ssl->sec.tls13KeyAgreeKeys[i] != NULL)
        {
            return ssl->sec.tls13KeyAgreeKeys[i];
        }
    }

    return NULL;
}

int32_t tls13AddPeerSupportedGroup(ssl_t *ssl,
        uint16_t namedGroup)
{
    psSize_t i;

    /* Find free spot. */
    for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
    {
        if (ssl->tls13PeerSupportedGroups[i] == 0)
        {
            ssl->tls13PeerSupportedGroups[i] = namedGroup;
            ssl->tls13PeerSupportedGroupsLen++;
            return PS_SUCCESS;
        }
    }

    return PS_FAILURE;
}

void tls13ClearPeerSupportedGroupList(ssl_t *ssl)
{
    psSize_t i;

    for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
    {
        ssl->tls13PeerSupportedGroups[i] = 0;
    }

    ssl->tls13PeerSupportedGroupsLen = 0;
}

int32_t tls13AddPeerKeyShareGroup(ssl_t *ssl,
        uint16_t namedGroup)
{
    psSize_t i;

    /* Find free spot. */
    for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
    {
        if (ssl->tls13PeerKeyShareGroups[i] == 0)
        {
            ssl->tls13PeerKeyShareGroups[i] = namedGroup;
            ssl->tls13PeerKeyShareGroupsLen++;
            return PS_SUCCESS;
        }
    }

    return PS_FAILURE;
}

psBool_t tls13WeSupportGroup(ssl_t *ssl,
        uint16_t namedGroup)
{
    psSize_t i;

    for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
    {
        if (ssl->tls13SupportedGroups[i] == namedGroup)
        {
            return PS_TRUE;
        }
    }

    return PS_FALSE;
}

psBool_t tls13PeerSupportsGroup(ssl_t *ssl,
        uint16_t namedGroup)
{
    psSize_t i;

    /* Find it. */
    for (i = 0; i < TLS_1_3_MAX_GROUPS; i++)
    {
        if (ssl->tls13PeerSupportedGroups[i] == namedGroup)
        {
            return PS_TRUE;
        }
    }

    return PS_FALSE;
}

# endif /* USE_TLS_1_3 */
