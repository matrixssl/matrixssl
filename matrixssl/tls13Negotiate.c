/**
 *      @file    tls13Negotiate.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 specific functions for parameter negotiation.
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
# ifdef USE_IDENTITY_CERTIFICATES
/** This function is called to validate our private key and cert chain
    against against the peer's signature_algorithms,
    signature_algorithms_cert and supported_groups extensions. */
int32_t tls13TryNegotiateParams(ssl_t *ssl,
        const sslCipherSpec_t *spec,
        sslIdentity_t *givenKey)
{
    psSize_t i;
    psBool_t peerCanVerifyCvSig = PS_FALSE;
    psBool_t peerCanVerifyChain = PS_TRUE;
    psBool_t peerCanVerifyCert;
    psX509Cert_t *cert;


    /* Check if we have successfully already chosen common PSK in
       which case it is used in preference to cert-based
       authentication */
    if (ssl->sec.tls13ChosenPsk != NULL)
    {
        return PS_SUCCESS;
    }

    /* Can the peer verify signatures we generate with our private key?
       Note: won't support legacy SHA-1 algorithms in CertificateVerify. */
    for (i = 0; i < ssl->sec.keySelect.peerSigAlgsLen; i++)
    {
        if (tls13IsInsecureSigAlg(ssl->sec.keySelect.peerSigAlgs[i]))
        {
            continue;
        }
#  ifdef USE_RSA
        if (givenKey->privKey.type == PS_RSA &&
                tls13IsRsaSigAlg(ssl->sec.keySelect.peerSigAlgs[i]))
        {
            peerCanVerifyCvSig = PS_TRUE;
            break;
        }
#  endif
#  ifdef USE_ECC
        if (givenKey->privKey.type == PS_ECC &&
                tls13IsEcdsaSigAlg(ssl->sec.keySelect.peerSigAlgs[i]))
        {
            peerCanVerifyCvSig = PS_TRUE;
            break;
        }
#  endif
#  ifdef USE_ED25519
        if (givenKey->privKey.type == PS_ED25519 &&
                ssl->sec.keySelect.peerSigAlgs[i] == sigalg_ed25519)
        {
            peerCanVerifyCvSig = PS_TRUE;
            break;
        }
#  endif
    }

    if (!peerCanVerifyCvSig)
    {
        psTraceErrr("Failed to negotiate CV sig alg\n");
        return PS_UNSUPPORTED_FAIL;
    }

    /*
      Can the peer verify all signatures in our cert chain?
      Note: we always support SHA-256 and SHA-384 in TLS 1.3.*/
    cert = givenKey->cert;

    while (cert)
    {
        peerCanVerifyCert = PS_FALSE;

        for (i = 0; i < ssl->sec.keySelect.peerSigAlgsLen; i++)
        {
#  ifdef USE_CERT_PARSE
            if (!Memcmp(cert->subject.hash,
                            cert->issuer.hash,
                            SHA1_HASH_SIZE))
            {
                /* Root cert. Peer doesn't need to verify. */
                peerCanVerifyCert = PS_TRUE;
            }
#  else
            if (0)
            {
            }
#  endif
#  ifdef USE_RSA
            else if (cert->sigAlgorithm == OID_SHA256_RSA_SIG ||
                    cert->sigAlgorithm == OID_SHA384_RSA_SIG)
            {
                if (tls13IsRsaSigAlg(ssl->sec.keySelect.peerSigAlgs[i]))
                {
                    peerCanVerifyCert = PS_TRUE;

                }
            }
#  endif
#  ifdef USE_ECC
            else if (cert->sigAlgorithm == OID_SHA256_ECDSA_SIG ||
                    cert->sigAlgorithm == OID_SHA384_ECDSA_SIG)
            {
                if (tls13IsEcdsaSigAlg(ssl->sec.keySelect.peerSigAlgs[i]))
                {
                    peerCanVerifyCert = PS_TRUE;
                }
            }
#  endif
#  ifdef USE_ED25519
            else if (cert->sigAlgorithm == OID_ED25519_KEY_ALG &&
                ssl->sec.keySelect.peerSigAlgs[i] == sigalg_ed25519)
            {
                peerCanVerifyCert = PS_TRUE;
            }
#  endif
            else
            {
                if (cert->sigAlgorithm == OID_ED25519_KEY_ALG)
                {
                    psTraceErrr("Need USE_ED25519 for Ed25519 sigs in certs\n");
                }
                else
                {
                    psTraceInfo("TODO: support PSS or SHA-1 sigs in certs.\n");
                }
            }
        }
        if (!peerCanVerifyCert)
        {
            peerCanVerifyChain = PS_FALSE;
            break;
        }
        cert = cert->next;
    }

    if (peerCanVerifyChain)
    {
        return PS_SUCCESS;
    }
    else
    {
        psTraceErrr("Peer does not support our cert chain sig algs\n");
        return PS_UNSUPPORTED_FAIL;
    }
}
# endif
#endif /* USE_TLS_1_3 */
