/**
 *      @file    tls13Psk.c
 *      @version $Format:%h%d$
 *
 *      Functions for dealing with TLS 1.3 PSKs.
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

#  ifndef DEBUG_TLS_1_3_PSK
/* #   define DEBUG_TLS_1_3_PSK */
#  endif

psTls13Psk_t *tls13NewPsk(const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        psBool_t isResumptionPsk,
        const psTls13SessionParams_t *params)
{
    psTls13Psk_t *psk;

    psk = psMalloc(keys->pool, sizeof(psTls13Psk_t));
    if (psk == NULL)
    {
        return NULL;
    }
    Memset(psk, 0, sizeof(psTls13Psk_t));

    psk->pskKey = psMalloc(keys->pool, keyLen);
    if (psk->pskKey == NULL)
    {
        psFree(psk, keys->pool);
        return NULL;
    }
    Memcpy(psk->pskKey, key, keyLen);
    psk->pskLen = keyLen;

    psk->pskId = psMalloc(keys->pool, idLen);
    if (psk->pskId == NULL)
    {
        psFree(psk->pskKey, keys->pool);
        psFree(psk, keys->pool);
        return NULL;
    }
    Memcpy(psk->pskId, id, idLen);
    psk->pskIdLen = idLen;

    psk->isResumptionPsk = isResumptionPsk;

    if (params != NULL)
    {
        psk->params = psMalloc(keys->pool, sizeof(psTls13SessionParams_t));
        Memset(psk->params, 0x0, sizeof(psTls13SessionParams_t));
        if (psk->params == NULL)
        {
            psFree(psk->pskKey, keys->pool);
            psFree(psk->pskId, keys->pool);
            psFree(psk, keys->pool);
            return NULL;
        }
        Memset(psk->params, 0, sizeof(psTls13SessionParams_t));

        if (params->sni != NULL && params->sniLen > 0)
        {
            psk->params->sni = psMalloc(keys->pool, params->sniLen);
            Memcpy(psk->params->sni, params->sni, params->sniLen);
            psk->params->sniLen = params->sniLen;
        }
        if (params->alpn != NULL && params->alpnLen > 0)
        {
            psk->params->alpn = psMalloc(keys->pool, params->alpnLen);
            Memcpy(psk->params->alpn, params->alpn, params->alpnLen);
            psk->params->alpnLen = params->alpnLen;
        }
        psk->params->majVer = params->majVer;
        psk->params->minVer = params->minVer;
        psk->params->cipherId = params->cipherId;
        psk->params->timestamp = params->timestamp;
        psk->params->ticketAgeAdd = params->ticketAgeAdd;
        psk->params->ticketLifetime = params->ticketLifetime;
        psk->params->maxEarlyData = params->maxEarlyData;
    }

#ifdef DEBUG_TLS_1_3_PSK
    psTraceBytes("Created new PSK with ID", psk->pskId, psk->pskIdLen);
#endif

    return psk;
}

void tls13AddPskToList(psTls13Psk_t **list,
                       psTls13Psk_t *psk, psBool_t as_first)
{
    if (as_first)
    {
        /* XXX: resumption PSK's need to be the first ones - this
           should be taken care at the message encoding, not at list
           management.  */
        psk->next = *list;
        *list = psk;
    }
    else
    {
        psTls13Psk_t **p;
        for (p = list; *p; p = &((*p)->next))
            ;
        *p = psk;
    }
}

/** Load a long-term PSK to sslKeys_t. Should only be called during
    program initialization in case several clients or serves share
    the same keys struct. To add a per-session PSK, use
    tls13AddSessionPsk instead. */
int32_t matrixSslLoadTls13Psk(sslKeys_t *keys,
        const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        const psTls13SessionParams_t *params)
{
    psTls13Psk_t *psk;

    psk = tls13NewPsk(key, keyLen, id, idLen, PS_FALSE, params);
    if (psk == NULL)
    {
        return PS_MEM_FAIL;
    }
    tls13AddPskToList(&keys->tls13PskKeys, psk, PS_FALSE);

#ifdef DEBUG_TLS_1_3_PSK
    psTraceBytes("Loaded long-term PSK with ID",
            psk->pskId, psk->pskIdLen);
#endif

    return MATRIXSSL_SUCCESS;
}

/** Add PSKs from sslKeys_t to the current session PSK list. */
int32_t tls13LoadSessionPsks(ssl_t *ssl)
{
    psTls13Psk_t *psk;
    int32_t rc;

    /* First add any resumption PSKs we might have. */
    if (ssl->sid && ssl->sid->psk)
    {
        psk = ssl->sid->psk;
        rc = tls13AddSessionPsk(ssl,
                psk->pskKey,
                psk->pskLen,
                psk->pskId,
                psk->pskIdLen,
                psk->isResumptionPsk,
                psk->params);
        if (rc < 0)
        {
            return rc;
        }
    }

    /* Next, add PSKs loaded during session initialization.
       Most likely these are externally established PSKs.
       The psk->isResumptionPsk field should have already been
       set properly in matrixSslLoadTls13PskKeys. */
    psk = ssl->keys->tls13PskKeys;
    while (psk != NULL)
    {
        rc = tls13AddSessionPsk(ssl,
                psk->pskKey,
                psk->pskLen,
                psk->pskId,
                psk->pskIdLen,
                psk->isResumptionPsk,
                psk->params);
        if (rc < 0)
        {
            return rc;
        }
        psk = psk->next;
    }

    return PS_SUCCESS;
}

/** Add a PSK to the current session. */
int32_t tls13AddSessionPsk(ssl_t *ssl,
        const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        psBool_t isResumptionPsk,
        const psTls13SessionParams_t *params)
{
    psTls13Psk_t *psk;

    psk = tls13NewPsk(key, keyLen, id, idLen, isResumptionPsk, params);
    if (psk == NULL)
    {
        return PS_MEM_FAIL;
    }

    tls13AddPskToList(&ssl->sec.tls13SessionPskList, psk, isResumptionPsk);

#ifdef DEBUG_TLS_1_3_PSK
    psTraceBytes("Loaded session PSK with ID",
            psk->pskId, psk->pskIdLen);
#endif

    return PS_SUCCESS;
}

/** Find a PSK from the session PSK store. */
int32_t tls13FindSessionPsk(ssl_t *ssl,
        const unsigned char *id,
        psSize_t idLen,
        psTls13Psk_t **pskOut)
{
    psTls13Psk_t *psk;

    if (idLen <= 0)
    {
        psTraceIntInfo("Bad PSK identity length: %d\n", idLen);
        return PS_ARG_FAIL;
    }

    /*
      On the server side, we have two possibilities:
      either id is the pskId of an externally shared PSK (loaded via
      matrixSslLoadTls13PskKeys) or the id is an encrypted ticket the
      client is trying to resume with.

      We can distinguish between the two cases by looking at the
      length and the contents of the first 16 bytes. In the resumption
      case, the first 16 bytes should be opaque key_name[16].
    */
    if (IS_SERVER(ssl))
    {
#  ifdef USE_SERVER_SIDE_SSL
        psSessionTicketKeys_t *key;

        if (idLen >= 16 + 12 + 16)
        {
            key = ssl->keys->sessTickets;
            while (key)
            {
                if (!Memcmp(id, key->name, 16))
                {
                    return tls13DecryptTicket(ssl, key, id, idLen, pskOut);
                }
                key = key->next;
            }
        }
#  endif
    }

    psk = ssl->sec.tls13SessionPskList;

    while (psk)
    {
        if (psk->pskIdLen == idLen)
        {
            if (Memcmp(psk->pskId, id, idLen) == 0)
            {
                *pskOut = psk;

                return PS_SUCCESS;
            }
        }
        psk = psk->next;
    }

    psTraceInfo("Can't find PSK key from id\n");
    return PS_SUCCESS;
}

int32_t tls13GetPskHmacAlg(psTls13Psk_t *psk)
{
    /*
      See if the PSK's session params include the cipher id. If yes,
      we can deduce the HMAC from that. If not, or if the PSK does
      not have any associated parameters (which can happen with
      externally shared PSKs), use the length of the PSK key value
      as a clue: 32 likely means SHA-256, 48 means SHA-384.
    */

    if (psk->params && psk->params->cipherId != 0)
    {
        return tls13CipherIdToHmacAlg(psk->params->cipherId);
    }
    else if (psk->pskLen == 32)
    {
        return HMAC_SHA256;
    }
    else if (psk->pskLen == 48)
    {
        return HMAC_SHA384;
    }
    else
    {
        psTraceInfo("Unable to determine hash length of PSK\n");
        return 0;
    }
}

psSize_t tls13GetPskHashLen(psTls13Psk_t *psk)
{
    int32_t hmacAlg;

    if (psk == NULL)
    {
        return 0;
    }

    hmacAlg = tls13GetPskHmacAlg(psk);
    if (hmacAlg == 0)
    {
        return 0;
    }
    else
    {
        psResSize_t len = psGetOutputBlockLength(hmacAlg);
        if (len < 0)
        {
            return 0;
        }
        return (psSize_t)len;
    }
}

void tls13FreePsk(psTls13Psk_t *psk,
                  psPool_t *pool)
{
    psTls13Psk_t *iter = psk;
    psTls13Psk_t *next;

    while (iter)
    {
#ifdef DEBUG_TLS_1_3_PSK
        psTraceBytes("Freeing PSK with ID", iter->pskId, iter->pskIdLen);
#endif
        psFree(iter->pskKey, pool);
        iter->pskKey = NULL;
        psFree(iter->pskId, pool);
        iter->pskId = NULL;
        if (iter->params)
        {
            psFree(iter->params->sni, pool);
            iter->params->sni = NULL;
            psFree(iter->params->alpn, pool);
            iter->params->alpn = NULL;
            psFree(iter->params, pool);
            iter->params = NULL;
        }
        next = iter->next;
        psFree(iter, pool);
        iter = next;
    }
}
# endif /* USE_TLS_1_3 */
