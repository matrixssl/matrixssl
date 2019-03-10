/**
 *      @file    tls13Authenticate.c
 *      @version $Format:%h%d$
 *
 *      Functions for certificate chain validation in TLS 1.3.
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

# ifndef DEBUG_TLS_1_3_AUTHENTICATE
/* #  define DEBUG_TLS_1_3_AUTHENTICATE */
# endif

# ifdef USE_TLS_1_3
#  ifdef USE_CERT_VALIDATE

static int32_t matrixSslValidatePeerCerts(ssl_t *ssl,
        void *pkiData);
static int32_t psCheckValidationResult(ssl_t *ssl,
        psX509Cert_t *leaf);
static void psCheckSetPathLenFailure(ssl_t *ssl,
        psX509Cert_t *leaf);

int32_t tls13ValidateCertChain(ssl_t *ssl)
{
    matrixSslReorderCertChain(ssl->sec.cert);
    return matrixSslValidatePeerCerts(ssl, NULL);
}

/* Validate the peer certficate chain stored in ssl->sec.cert. */
static
int32_t matrixSslValidatePeerCerts(ssl_t *ssl,
        void *pkiData)
{
    matrixValidateCertsOptions_t *opts;
    psX509Cert_t *foundIssuer;
    int32_t rc;

    opts = &ssl->validateCertsOpts;

    /* Perform MatrixSSL internal validation. */
    rc = matrixValidateCertsExt(ssl->hsPool,
            ssl->sec.cert,
            ssl->keys == NULL ? NULL : ssl->keys->CAcerts,
            ssl->expectedName,
            &foundIssuer,
            pkiData,
            ssl->memAllocPtr,
            opts);
    if (rc == PS_MEM_FAIL)
    {
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return MATRIXSSL_ERROR;
    }

    psCheckSetPathLenFailure(ssl, ssl->sec.cert);
    rc = psCheckValidationResult(ssl,
            ssl->sec.cert);
    if (rc < 0)
    {
        if (ssl->sec.validateCert == NULL)
        {
            /* Internal validation failed and there is no user cert callback. */
            if (ssl->err == SSL_ALERT_NONE)
            {
                ssl->err = SSL_ALERT_BAD_CERTIFICATE;
            }
            return MATRIXSSL_ERROR;
        }
    }

    /* Call the user certificate validation callback. */
    rc = matrixUserCertValidator(ssl, ssl->err, ssl->sec.cert,
        ssl->sec.validateCert);

    return tls13HandleUserCertCbResult(ssl, rc);
}

int32_t tls13HandleUserCertCbResult(ssl_t *ssl, int32 cbRc)
{

    /* Test what the user callback returned. */
    ssl->sec.anon = 0;
    if (cbRc == SSL_ALLOW_ANON_CONNECTION)
    {
        ssl->sec.anon = 1;
    }
    else if (cbRc > 0)
    {
        /*      User returned an alert.  May or may not be the alert that was
            determined above */
        psTraceIntInfo("Certificate authentication alert %d\n", cbRc);
        ssl->err = cbRc;
        return MATRIXSSL_ERROR;
    }
    else if (cbRc < 0)
    {
        psTraceIntInfo("User certificate callback had an internal error " \
                "(cbRc=%d)\n", cbRc);
        ssl->err = SSL_ALERT_INTERNAL_ERROR;
        return MATRIXSSL_ERROR;
    }

    /*  User callback returned 0 (continue on).  Did they determine the alert
        was not fatal after all? */
    if (ssl->err != SSL_ALERT_NONE)
    {
        psTraceIntInfo("User certificate callback determined alert %d " \
                "was NOT fatal\n",
                ssl->err);
        ssl->err = SSL_ALERT_NONE;
    }

    return PS_SUCCESS;
}

static
int32_t psCheckValidationResult(ssl_t *ssl,
        psX509Cert_t *leaf)
{
    psX509Cert_t *cert = leaf;

    while (cert)
    {
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

    if (ssl->err == SSL_ALERT_NONE)
    {
        return PS_SUCCESS;
    }
    else
    {
        return MATRIXSSL_ERROR;
    }
}

static
void psCheckSetPathLenFailure(ssl_t *ssl,
        psX509Cert_t *leaf)
{
    psSize_t pathLen = 0;
    psX509Cert_t *cert = leaf;
    int32_t maxDepth;
    psBool_t exceeded = PS_FALSE;

    maxDepth = ssl->validateCertsOpts.max_verify_depth;

    while (cert)
    {
        pathLen++;

        if (maxDepth > 0)
        {
            exceeded = PS_FALSE;
            psTraceIntInfo("max_verify_depth: %d\n", maxDepth);

            /*
              A maximum verification depth has been specified in session opts.
            */
            if (pathLen > maxDepth)
            {
                exceeded = PS_TRUE;
            }
            else if (pathLen == maxDepth)
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
                    exceeded = PS_TRUE;
                }
            }
            if (exceeded)
            {
                /* Max depth exceeded. */
                psTraceErrr("Error: max_verify_depth exceeded\n");
                ssl->err = SSL_ALERT_UNKNOWN_CA;
                cert->authStatus |= PS_CERT_AUTH_FAIL_PATH_LEN;
                cert->authFailFlags |= PS_CERT_AUTH_FAIL_VERIFY_DEPTH_FLAG;
            }
        }
        if (ssl->err != SSL_ALERT_NONE)
        {
            break; /* The first alert is the logical one to send */
        }

        cert = cert->next;
    }
}
#  endif /* USE_CERT_VALIDATE */
# endif /* USE_TLS_1_3 */
