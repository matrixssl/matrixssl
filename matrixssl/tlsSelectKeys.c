/**
 *      @file    tlsSelectKeys.c
 *      @version $Format:%h%d$
 *
 *      Client-side key and certificate selection.
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
/******************************************************************************/

#include "matrixsslImpl.h"

#ifndef DEBUG_TLS_SELECT_KEYS
/* # define DEBUG_TLS_SELECT_KEYS */
#endif

#ifdef USE_IDENTITY_CERTIFICATES

psBool_t matrixSslSetClientIdentity(ssl_t *ssl,
                                    const sslKeys_t *keys)
{
    /* No keys, or no identities -> fail. In case of multiple, use the first. */
    if (keys == NULL || keys->identity == NULL)
        return PS_FALSE;

# ifdef USE_CLIENT_SIDE_SSL
    ssl->sec.certMatch = 1;
# endif
    ssl->chosenIdentity = keys->identity;
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
    /* The client has now set the keys to use - foward the state
       machine accordingly, so that resumed certificateRequest packet
       gets processed. */
    (void) matrixSslClientCertUpdated(ssl);
    (void) matrixSslClientPrivKeyUpdated(ssl);
#endif
    return PS_TRUE;
}

const sslKeySelectInfo_t *matrixSslGetClientKeySelectInfo(ssl_t *ssl)
{
    return &ssl->sec.keySelect;
}

/* Choose a client cert and key from the ssl->keys->identity list. */
static
int32_t chooseFromLoadedKeys(ssl_t *ssl, sslKeySelectInfo_t *keySelect)
{
    psBool_t found;
    int i;

    /* RFC 5246, section 7.4.4: "Any certificates provided by the
       client MUST be signed using a hash/signature algorithm pair
       found in supported_signature_algorithms.". Check our
       certificate chain, and set certMatch = 1 if a suitable
       cert is found. */
    if (keySelect->nCas == 0)
    {
        /* server did not specify CA's. Use the first key */
        ssl->chosenIdentity = ssl->keys->identity;
# ifdef USE_CLIENT_SIDE_SSL
        ssl->sec.certMatch = 1;
# endif
        psTraceInfo("no CA's from peer: using first given\n");
    }

    for (found = PS_FALSE, i = 0; !found && i < keySelect->nCas; i++)
    {
# ifdef USE_CERT_PARSE
      sslIdentity_t *has;
      psX509Cert_t *cert;

        for (has = ssl->keys->identity; !found && has; has = has->next)
        {
            /* traverse up chains to find accepted issuer */
            for (cert = has->cert; cert; cert = cert->next)
            {
                if (cert->issuer.dnencLen == keySelect->caNameLens[i]
                        && Memcmp(cert->issuer.dnenc,
                                keySelect->caNames[i],
                                keySelect->caNameLens[i]) == 0)
                {
                    uint32_t check = 0;

                    if (USING_TLS_1_3(ssl))
                    {
                        check = keySelect->peerCertSigAlgMask;
                    }
                    else
                    {
                        check = keySelect->peerSigAlgMask;
                    }

                    if (check != 0 && !peerSupportsSigAlg(cert->sigAlgorithm, check))
                    {
# ifdef DEBUG_TLS_SELECT_KEYS
                        psTraceIntInfo("identityCb: invalid cert sig algorithm %x ",
                                cert->sigAlgorithm);
                        psTraceIntInfo("Not found in list: %x\n", check);
# endif /* DEBUG_TLS_SELECT_KEYS */
                        continue;
                    }

                    /* This chain was found to be fruitful -
                       issuer is withing the path, and algorithms are fine. */
                    ssl->chosenIdentity = has;
# ifdef USE_CLIENT_SIDE_SSL
                    ssl->sec.certMatch = 1;
# endif
                    found = PS_TRUE;
                    break;
                }
                else
                {
# ifdef DEBUG_TLS_SELECT_KEYS
                    psTraceInfo("identityCb: issuer name mismatch\n");
                    psTraceBytes("has: ",
                            (const unsigned char*)cert->issuer.dnenc,
                            cert->issuer.dnencLen);
                    psTraceBytes("req: ",
                            keySelect->caNames[i],
                            keySelect->caNameLens[i]);
# endif /* DEBUG_TLS_SELECT_KEYS */
                }
            }
        }
#endif /* USE_CERT_PARSE */
    }
    if (ssl->chosenIdentity == NULL)
    {
        psTraceInfo("identityCb: no keys matched\n");
# ifndef USE_CERT_PARSE
        /* XXX: Fallback to the first identity we have in case
           suitable wasn't found due to limited functionality....  Or
           should we send an empty certificate message in this case,
           or maybe fallback to anonymous connection? */
        ssl->chosenIdentity = ssl->keys->identity;
# endif
    }

    if (found)
    {
        psAssert(ssl->chosenIdentity != NULL);
        return PS_SUCCESS;
    }
    return PS_FAILURE;
}

/** Choose the client key and cert to use in client authentication
    in the current handshake.

    There are three ways we can get client keys from the application.
    The list here is in order of priority. For example, key loaded
    via the identity callback will override keys loaded during session
    initialization.

    1. The application has registered an identity callback that will
       load the keys on demand.
    2. The application has loaded some keys with matrix*LoadKeys* during
       session initialization. In this case, the keys are already in
       ssl->keys->identity.
    3. The application uses external client cert and key loading
       (the defined USE_EXT_CLIENT_CERT_KEY_LOADING) is needed for this.
       In this approach, the client will get the PS_PENDING return value
       from matrixSslReceivedData and query matrixSslNeedClientCert
       and matrixSslNeedPrivKey. If they return PS_TRUE, the client
       will load the new keys into ssl->keys and call
       matrixSslClientCertUpdated or matrixSslClientPrivKeyUpdated.
*/
int32_t matrixSslChooseClientKeys(ssl_t *ssl, sslKeySelectInfo_t *keySelect)
{
    int32_t rc;
    psBool_t found = PS_FALSE;

# ifdef USE_CLIENT_SIDE_SSL
    ssl->sec.certMatch = 0;
# endif

    /* Approach 1: the identity callback. */
    if (ssl->sec.identityCb)
    {
        psTraceInfo("matrixSslChooseClientKeys: trying callback\n");
        rc = ssl->sec.identityCb(ssl, keySelect);
        if (rc == PS_SUCCESS && ssl->chosenIdentity != NULL)
        {
            found = PS_TRUE;
        }
    }

    /* Approach 2: pre-loaded keys. */
    if (!found && ssl->keys->identity)
    {
        psTraceInfo("matrixSslChooseClientKeys: trying pre-loaded\n");
        rc = chooseFromLoadedKeys(ssl, keySelect);
        if (rc == PS_SUCCESS && ssl->chosenIdentity != NULL)
        {
            found = PS_TRUE;
        }
    }

    /* Approach 3: external loading (if enabled). */
    if (!found)
    {
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
        /*
          This should result in PS_PENDING to be sent to the
          application after ServerHelloDone has been parsed,
          to try "external" key and cert loading.
        */
        ssl->extClientCertKeyStateFlags =
            EXT_CLIENT_CERT_KEY_STATE_WAIT_FOR_CERT_KEY_UPDATE;
        psTraceInfo("matrixSslChooseClientKeys: trying external load\n");
        return PS_SUCCESS;
# endif
        psTraceInfo("matrixSslChooseClientKeys: no pre-loaded keys, "\
                "nor callback. Going anon.\n");
        /* no keys material given - try anonymous (or fall back to
           external key selection). */
        return PS_SUCCESS;
    }

    psAssert(ssl->chosenIdentity != NULL);
    return PS_SUCCESS;
}
#endif  /* !USE_IDENTITY_CERTIFICATES */

/******************************************************************************/
