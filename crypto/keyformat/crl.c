/**
 *      @file    crl.c
 *      @version $Format:%h%d$
 *
 *      Certificate Revocation List tools
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
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

#include "../cryptoImpl.h"

#ifdef USE_CRL
# ifdef USE_CERT_PARSE

#  ifdef USE_MULTITHREADING
static psMutex_t g_crlTableLock;
#  endif

/* Seems like many CRLs are not adhering to the specification that this
    extension be present.  That just leaves us with the DN to match against
    if we disable this define.  Not a big concern to disable it because the
    authentication is either going to pass or fail based on sig validation */
/* #define ENFORCE_CRL_AUTH_KEY_ID_EXT */

static void internalFreeCRL(psX509Crl_t *crl);

/* The global CRL cache is a linked list of psX509Crl_t structures.  A
    psX509Crl_t structure represents a single CRL file */
static psX509Crl_t *g_CRL = NULL;


/* Invoked from psCryptoOpen */
int32_t psCrlOpen()
{
#  ifdef USE_MULTITHREADING
    psCreateMutex(&g_crlTableLock, 0);
#  endif
    return PS_SUCCESS;
}

/* Invoked from psCryptoClose */
void psCrlClose()
{
    psCRL_DeleteAll();
#  ifdef USE_MULTITHREADING
    psDestroyMutex(&g_crlTableLock);
#  endif
}

/* Helper for CRL insert */
static int internalCRLInsert(psX509Crl_t *crl)
{
    psX509Crl_t *next;

    if (crl == NULL)
    {
        return 0;
    }

    if (g_CRL == NULL)
    {
        /* first one */
        g_CRL = crl;
        return 1;
    }
    /* append */
    next = g_CRL;
    if (g_CRL == crl)
    {
        return 0; /* no pointer dups */
    }
    while (next->next)
    {
        next = next->next;
        if (next == crl)   /* no pointer dups */
        {
            return 0;
        }
    }
    next->next = crl;
    return 1;
}

/* Blindly append a CRL to the g_CRL list.      Consider psCRL_Update instead.
    1 - Added, 0 - Didn't */
int psCRL_Insert(psX509Crl_t *crl)
{
    int rc;

#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    rc = internalCRLInsert(crl);

#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
    return rc;
}

/* Helper for Remove and Delete to take a CRL out of g_CRL */
static int internalShrinkCRLtable(psX509Crl_t *crl, int delete)
{
    psX509Crl_t *prev, *curr, *next;

    /* Return whether or not it was found in the list to help with the
        standalone psX509FreeCRL call logic */

    if (g_CRL == NULL || crl == NULL)
    {
        return 0;
    }
    prev = NULL;
    curr = g_CRL;
    next = curr->next;
    while (curr)
    {
        if (curr == crl)
        {
            if (delete)
            {
                internalFreeCRL(crl);
            }
            else
            {
                curr->next = NULL;
            }
            if (prev == NULL && next == NULL)
            {
                /* Only one in list */
                g_CRL = NULL;
            }
            else if (prev == NULL && next != NULL)
            {
                /* Removed first one in list */
                g_CRL = next;
            }
            else if (prev != NULL)
            {
                /* Removed middle or end */
                prev->next = next;
            }
            return 1;
        }
        prev = curr;
        curr = curr->next;
        if (curr)
        {
            /* curr can be NULL if we never found crl */
            next = curr->next;
        }
    }
    return 0;
}

/* Remove a CRL from g_CRL but don't free the associated CRL */
int psCRL_Remove(psX509Crl_t *crl)
{
    int rc;

#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    rc = internalShrinkCRLtable(crl, 0);

#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    return rc;
}

/* Remove a CRL from g_CRL and free the associated CRL */
int psCRL_Delete(psX509Crl_t *crl)
{
    int rc;

#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    rc = internalShrinkCRLtable(crl, 1);

#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
    return rc;
}

/* Remove all CRLs from g_CRL but don't free the associated memory.  Assumes
    the user will be using psX509FreeCRL later */
void psCRL_RemoveAll()
{
    psX509Crl_t *curr, *next;

#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
    curr = g_CRL;
    next = curr->next;
    while (next)
    {
        next = curr->next;
        curr->next = NULL;
        curr = next;
    }
    g_CRL = NULL;
#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
}

/* Remove all CRLs from g_CRL and free the associated memory */
void psCRL_DeleteAll()
{
    psX509Crl_t *curr, *next;

#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    curr = g_CRL;
    while (curr)
    {
        next = curr->next;
        internalShrinkCRLtable(curr, 1);
        curr = next;
    }
    psAssert(g_CRL == NULL);
#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
}

/* Helpers to see if the two CRLs are from the same issuer */
int32 internalCRLmatch(psX509Crl_t *existing, psX509Crl_t *new)
{
    /* Same DN? */
    if (memcmpct(existing->issuer.hash, new->issuer.hash, SHA1_HASH_SIZE) != 0)
    {
        return -1;
    }
#  ifdef ENFORCE_CRL_AUTH_KEY_ID_EXT
    /* Same AuthKeyId? */
    if (existing->extensions.ak.keyId == NULL ||
        new->extensions.ak.keyId == NULL)
    {
        /* Should never be possible */
        return PS_PARSE_FAIL;
    }
    if (existing->extensions.ak.keyLen != new->extensions.ak.keyLen)
    {
        return -1;
    }
    if (memcmpct(existing->extensions.ak.keyId, new->extensions.ak.keyId,
            new->extensions.ak.keyLen) != 0)
    {
        return -1;
    }
#  endif
    /* Looks like a match */
    return PS_TRUE;
}

/* Remove existing CRL if it exists.  Append this one.
    FUTURE: Support Delta CRL */
int psCRL_Update(psX509Crl_t *crl, int deleteExisting)
{
    psX509Crl_t *curr, *next;
    int rc;

    if (crl == NULL)
    {
        return 0;
    }
#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
         /* Currently no Delta CRL support so replace the CRL if we find the
             same issuer.  Add otherwise. */
    curr = g_CRL;
    while (curr)
    {
        next = curr->next;
        if (internalCRLmatch(curr, crl) == PS_TRUE)
        {
            /* Just do a check to make sure the user isn't trying to update
                with the exact same CRL pointer */
            if (curr == crl)
            {
#  ifdef USE_MULTITHREADING
                psUnlockMutex(&g_crlTableLock);
#  endif        /* USE_MULTITHREADING */
                return 0;
            }
            internalShrinkCRLtable(curr, deleteExisting);
            break;
        }
        curr = next;
    }
    rc = internalCRLInsert(crl);
#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
    return rc;
}

/* Helper to see if we have a matching CRL for the given subject cert.  So
    this means we are looking at the issuer/authority fields of the cert */
static int32 internalMatchSubject(psX509Cert_t *cert, psX509Crl_t *CRL)
{
    /* Same DN? */
    if (memcmpct(CRL->issuer.hash, cert->issuer.hash, SHA1_HASH_SIZE) != 0)
    {
        return PS_CERT_AUTH_FAIL_DN;
    }
#  ifdef ENFORCE_CRL_AUTH_KEY_ID_EXT
    /* Same AuthKeyId? */
    if (CRL->extensions.ak.keyId == NULL)
    {
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
    if (cert->extensions.ak.keyId == NULL)
    {
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
    if (CRL->extensions.ak.keyLen != cert->extensions.ak.keyLen)
    {
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
    if (memcmpct(CRL->extensions.ak.keyId, cert->extensions.ak.keyId,
            CRL->extensions.ak.keyLen) != 0)
    {
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
#  endif
    /* Looks good */
    return 1;
}

/* Check if nextUpdate time appears correct. Returns -1 when
   timestamp was unparseable or the CRL was expired. 0 for success. */
static int32_t nextUpdateTest(const char *c, int32 timeType)
{
    int32 err;
    psBrokenDownTime_t timeNow;
    psBrokenDownTime_t nextTime;
    psBrokenDownTime_t nextTimeLinger;

    err = psGetBrokenDownGMTime(&timeNow, 0);
    if (err != PS_SUCCESS)
    {
        return -1;
    }

    err = psBrokenDownTimeImport(
        &nextTime, c, strlen(c),
        timeType == ASN_UTCTIME ?
        PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR : 0);
    if (err != PS_SUCCESS)
    {
        return -1;
    }

    memcpy(&nextTimeLinger, &nextTime, sizeof nextTimeLinger);
    err = psBrokenDownTimeAdd(&nextTimeLinger, PS_CRL_TIME_LINGER);
    if (err != PS_SUCCESS)
    {
        return -1;
    }

    if (psBrokenDownTimeCmp(&timeNow, &nextTimeLinger) > 0)
    {
        /* nextTime is in past. */
        return -1;
    }
    return 0;
}

static psX509Crl_t *internalGetCrlForCert(psX509Cert_t *cert)
{
    psX509Crl_t *curr;

    if (cert == NULL)
    {
        return NULL;
    }
    curr = g_CRL;
    while (curr)
    {
        if (internalMatchSubject(cert, curr) == PS_TRUE)
        {
            /* This is the point where we want to make sure this CRL isn't
                expired.  We do this by looking at the nextUpdate time and
                seeing if we are beyond that */
            if (nextUpdateTest(curr->nextUpdate, curr->nextUpdateType) < 0)
            {
                /* Got it, but it's expired */
                curr->expired = 1;
            }
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/* Given a cert, do we have a CRL match for the issuer?
    Return if so or NULL if not */
psX509Crl_t *psCRL_GetCRLForCert(psX509Cert_t *cert)
{
    psX509Crl_t *rc = NULL;

#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    rc = internalGetCrlForCert(cert);

#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
    return rc;
}


/*
    -1 no entry in the cache for this cert at all
    0 entry is found and cert is NOT revoked
    1 entry is found and cert IS revoked

    A CRL may be passed in if that specific one is being tested.  Otherwise
    pass NULL to search the g_CRL
 */
int32_t internalCrlIsRevoked(psX509Cert_t *cert, psX509Crl_t *CRL,
    psBrokenDownTime_t *bdt)
{
    psX509Crl_t *crl;
    x509revoked_t *entry;

    if (cert == NULL)
    {
        return -1;
    }

    if (CRL)
    {
        crl = CRL;
    }
    else
    {
        if ((crl = internalGetCrlForCert(cert)) == NULL)
        {
            return -1;
        }
    }
    if (crl->revoked == NULL)
    {
        /* It is totally reasonable to have a CRL with no revoked certs */
        return 0;
    }
    for (entry = crl->revoked; entry != NULL; entry = entry->next)
    {
        if (cert->serialNumberLen == entry->serialLen)
        {
            if (memcmpct(cert->serialNumber, entry->serial, entry->serialLen)
                == 0)
            {
                if (bdt)
                {
                    memcpy(bdt, &entry->revocationDateBDT,
                        sizeof(psBrokenDownTime_t));
                }
                return 1; /* REVOKED! */
            }
        }
    }
    return 0; /* never found it.  good to go */
}

/*
    Not sure this needs to be public.  The "determine" API is actually
    doing the full check

    -1 no entry in the cache for this cert at all
    0 entry is found and cert is NOT revoked
    1 entry is found and cert IS revoked

    A CRL may be passed in if that specific one is being tested.  Otherwise
    pass NULL to search the g_CRL
 */
int32_t psCRL_isRevoked(psX509Cert_t *cert, psX509Crl_t *CRL)
{
    int32_t rc;

#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    rc = internalCrlIsRevoked(cert, CRL, NULL);

#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    return rc;
}

static int doesCertExpectCRL(psX509Cert_t *cert)
{
    if (cert->extensions.crlDist)
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}

/*
    Uses the psCRL_ format to highlight the use of g_CRL cache

    Updates the "revokedStatus" member of a psX509Cert_t based on information
    from within the cert itself and on the revocation status if a g_CRL entry
    is found.
 */
int32_t psCRL_determineRevokedStatusBDT(psX509Cert_t *cert,
    psBrokenDownTime_t *bdt)
{
    psX509Crl_t *crl;
    int expectCrl;
    int32_t revoked;

    if (cert == NULL)
    {
        return 0;
    }
#  ifdef USE_MULTITHREADING
    psLockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */

    crl = internalGetCrlForCert(cert);

    if (crl)
    {
        /* Not going to move along if the CRL has expired */
        if (crl->expired)
        {
            cert->revokedStatus = CRL_CHECK_CRL_EXPIRED;
#  ifdef USE_MULTITHREADING
            psUnlockMutex(&g_crlTableLock);
#  endif    /* USE_MULTITHREADING */
            return cert->revokedStatus;
        }

        /* If we now have a CRL that is not authenticated yet, let's see if
            if our subject happens to have a parent that we can try against.
            This case happens if a CRL for an child certificate was
            fetched out-of-handshake and now a reconnection attempt is being
            made.  We now have the parent for that child cert and can
            attempt to authenticate */
        if (crl->authenticated == 0 && cert->next)
        {
            psX509AuthenticateCRL(cert->next, crl, NULL);
        }

        /* test it and set the status */
        revoked = internalCrlIsRevoked(cert, crl, bdt);
        if (revoked == 0 && crl->authenticated == 1)
        {
            cert->revokedStatus = CRL_CHECK_PASSED_AND_AUTHENTICATED;

        }
        else if (revoked == 0 && crl->authenticated == 0)
        {
            cert->revokedStatus = CRL_CHECK_PASSED_BUT_NOT_AUTHENTICATED;

        }
        else if (revoked == 1 && crl->authenticated == 1)
        {
            cert->revokedStatus = CRL_CHECK_REVOKED_AND_AUTHENTICATED;

        }
        else if (revoked == 1 && crl->authenticated == 0)
        {
            cert->revokedStatus = CRL_CHECK_REVOKED_BUT_NOT_AUTHENTICATED;

        }
        else
        {
            psTraceCrypto("Unexpected revoked/authenticated combo\n");
        }
    }
    else
    {
        expectCrl = doesCertExpectCRL(cert);
        if (expectCrl)
        {
            cert->revokedStatus = CRL_CHECK_EXPECTED; /* but no entry */
        }
        else
        {
            cert->revokedStatus = CRL_CHECK_NOT_EXPECTED;
        }
    }
#  ifdef USE_MULTITHREADING
    psUnlockMutex(&g_crlTableLock);
#  endif /* USE_MULTITHREADING */
    return cert->revokedStatus;
}

int32_t psCRL_determineRevokedStatus(psX509Cert_t *cert)
{
    return psCRL_determineRevokedStatusBDT(cert, NULL);
}

/********************* end of psCRL_ family of APIs ***************************/


/******************************************************************************/
static void x509FreeRevoked(x509revoked_t **revoked, psPool_t *pool)
{
    x509revoked_t *next, *curr = *revoked;

    while (curr)
    {
        next = curr->next;
        psFree(curr->serial, pool);
        psFree(curr, pool);
        curr = next;
    }
    *revoked = NULL;
}

static void internalFreeCRL(psX509Crl_t *crl)
{
    psPool_t *pool;

    if (crl == NULL)
    {
        return;
    }
    /* test all components for NULL.  This is used for freeing during
        parse so some might not be there at all */
    pool = crl->pool;

    psX509FreeDNStruct(&crl->issuer, pool);
    x509FreeExtensions(&crl->extensions);
    x509FreeRevoked(&crl->revoked, pool);
    psFree(crl->sig, pool);
    psFree(crl->nextUpdate, pool);

    memset(crl, 0, sizeof(psX509Crl_t));
    psFree(crl, pool);
}

void psX509FreeCRL(psX509Crl_t *crl)
{
    if (crl == NULL)
    {
        return;
    }
    /* Try to delete from g_CRL list first.  Will lock table */
    if (psCRL_Delete(crl))
    {
        return;
    }
    internalFreeCRL(crl);
}


/* Helper for psX509AuthenticateCRL to see if we have a matching CRL for
    the given issuer cert */
static int32 internalMatchIssuer(psX509Cert_t *CA, psX509Crl_t *CRL)
{
    /* Ensure crlSign flag of KeyUsage for the given CA. */
    if ( !(CA->extensions.keyUsageFlags & KEY_USAGE_CRL_SIGN))
    {
#  ifndef ALLOW_CRL_ISSUERS_WITHOUT_KEYUSAGE
        /*
           Fail if there is no keyUsage extension or the cRLSign flag
           is not set.
         */
        return PS_CERT_AUTH_FAIL_EXTENSION;
#  else
        /*
           Allow missing cRLSign flag when there is no keyUsage extension.
         */
        if (CA->extensions.keyUsageFlags != 0)   /* RFC 5280: at least one bit
                                                    must be 1 when keyUsage
                                                    is present. */
        {
            return PS_CERT_AUTH_FAIL_EXTENSION;
        }
#  endif /* !ALLOW_CRL_ISSUERS_WITHOUT_KEYUSAGE */
    }

    /* Same DN? */
    if (memcmpct(CRL->issuer.hash, CA->subject.hash, SHA1_HASH_SIZE) != 0)
    {
        psTraceCrypto("CRL not issued by this CA\n");
        return PS_CERT_AUTH_FAIL_DN;
    }
#  ifdef ENFORCE_CRL_AUTH_KEY_ID_EXT
    /* Same AuthKeyId? */
    if (CRL->extensions.ak.keyId == NULL)
    {
        psTraceCrypto("CRL does not have a AuthKeyId extension\n");
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
    if (CA->extensions.sk.id == NULL)
    {
        psTraceCrypto("CA does not have a SubjectKeyId extension\n");
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
    if (CRL->extensions.ak.keyLen != CA->extensions.sk.len)
    {
        psTraceCrypto("CRL issuer does not have same AuthKeyId as CA\n");
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
    if (memcmpct(CRL->extensions.ak.keyId, CA->extensions.sk.id,
            CRL->extensions.ak.keyLen) != 0)
    {
        psTraceCrypto("CRL issuer does not have same AuthKeyId as CA\n");
        return PS_CERT_AUTH_FAIL_EXTENSION;
    }
#  endif
    /* Looks good */
    return 1;
}

/*
    NO g_CRL used at all

    Worth noting that the authenticated state is reset each time this is
    called so it shouldn't be called blindly in a loop hoping the status
    will come out correctly.

    poolUserPtr is for the TMP_PKI pool
 */
int32_t psX509AuthenticateCRL(psX509Cert_t *CA, psX509Crl_t *CRL,
    void *poolUserPtr)
{
    int32 rc;

    psBool_t verifyResult = PS_FALSE;
    psVerifySigOptions_t opts;

    if (CA == NULL || CRL == NULL)
    {
        return PS_ARG_FAIL;
    }
    if (CRL->authenticated == 1)
    {
        /* Going to have to assume caller knows what they are doing */
        psTraceCrypto("WARNING: this CRL has already been authenticated\n");
    }
    CRL->authenticated = PS_FALSE;

    /* A few tests to see if this CA is the true issuer of the CRL */
    if ((rc = internalMatchIssuer(CA, CRL)) < 0)
    {
        return rc;
    }

    /* Perform the signature verification. */
    memset(&opts, 0, sizeof(psVerifySigOptions_t));
    rc = psVerifySig(NULL,
        CRL->sigHash, CRL->sigHashLen,
        CRL->sig, CRL->sigLen,
        &CA->publicKey,
        CRL->sigAlg,
        &verifyResult,
        &opts);
    if (rc != PS_SUCCESS)
    {
        if (verifyResult == PS_FALSE)
        {
            psTraceCrypto("Unable to verify CRL signature\n");
            return PS_CERT_AUTH_FAIL_SIG;
        }
        else
        {
            psTraceIntCrypto("psVerifySig failed: %d\n", rc);
            return rc;
        }
    }

    if (verifyResult == PS_TRUE)
    {
        CRL->authenticated = PS_TRUE;
    }

    return PS_SUCCESS;
}

int32 psX509GetCRLVersion(const unsigned char *crlBin, int32 crlBinLen)
{
    int version;
    uint32_t glen, tbsCertLen;
    const unsigned char *end, *p = crlBin;

    if (crlBin == NULL || crlBinLen <= 0)
    {
        return PS_ARG_FAIL;
    }
    end = p + crlBinLen;
    if (getAsnSequence32(&p, (uint32) (end - p), &glen, 0) < 0)
    {
        psTraceCrypto("Initial parse error in psX509GetCRLVersion\n");
        return PS_PARSE_FAIL;
    }
    if (getAsnSequence32(&p, (uint32) (end - p), &tbsCertLen, 0) < 0)
    {
        psTraceCrypto("Initial parse error in psX509GetCRLVersion\n");
        return PS_PARSE_FAIL;
    }
    if (end > p && *p == ASN_INTEGER)
    {
        version = 0;
        if (getAsnInteger(&p, (uint32) (end - p), &version) < 0 || version < 0)
        {
            psTraceCrypto("Version parse error in psX509GetCRLVersion.\n");
            return PS_PARSE_FAIL;
        }
        return (int32) version;
    }
    return 1; /* Default version (v2). */
}

/*
    Parse a CRL.
 */
int32 psX509ParseCRL(psPool_t *pool, psX509Crl_t **crl, unsigned char *crlBin,
    int32 crlBinLen)
{
    const unsigned char *end, *start, *sigStart, *sigEnd, *revStart, *p = crlBin;
    int32 oi, version, rc;
    x509revoked_t *curr, *next;
    psX509Crl_t *lcrl;
    uint32_t glen, ilen, tbsCertLen;
    psSize_t timelen, plen;
    unsigned char timetag;

    if (crlBin == NULL || crlBinLen <= 0)
    {
        return PS_ARG_FAIL;
    }
    end = p + crlBinLen;
    /*
        CertificateList  ::=  SEQUENCE  {
            tbsCertList          TBSCertList,
            signatureAlgorithm   AlgorithmIdentifier,
            signatureValue       BIT STRING  }

        TBSCertList  ::=  SEQUENCE  {
            version                 Version OPTIONAL,
                                     -- if present, shall be v2
            signature               AlgorithmIdentifier,
            issuer                  Name,
            thisUpdate              Time,
            nextUpdate              Time OPTIONAL,
            revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                           -- if present, shall be v2
                                  }  OPTIONAL,
            crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                           -- if present, shall be v2
        }
     */
    if (getAsnSequence32(&p, (uint32) (end - p), &glen, 0) < 0)
    {
        psTraceCrypto("Initial parse error in psX509ParseCRL\n");
        return PS_PARSE_FAIL;
    }

    /* Track tbsCert for signature purposes and for encoding where there
        is no revokedCertificate entry */
    sigStart = p;
    if (getAsnSequence32(&p, (uint32) (end - p), &tbsCertLen, 0) < 0)
    {
        psTraceCrypto("Initial parse error in psX509ParseCRL\n");
        return PS_PARSE_FAIL;
    }
    start = p;
    if (end > p && *p == ASN_INTEGER)
    {
        version = 0;
        if (getAsnInteger(&p, (uint32) (end - p), &version) < 0 || version < 0)
        {
            psTraceCrypto("Version parse error in psX509ParseCRL.\n");
            return PS_PARSE_FAIL;
        }
        if (version != 1)
        {
            psTraceIntCrypto("Version parse: unsupported version requested: "
                "%d\n", version);
            return PS_VERSION_UNSUPPORTED;
        }
    }

    /* looking correct.  Allocate the psX509Crl_t */
    if ((lcrl = psMalloc(pool, sizeof(psX509Crl_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }
    memset(lcrl, 0, sizeof(psX509Crl_t));
    lcrl->pool = pool;

    /* signature */
    if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &lcrl->sigAlg, &plen)
        < 0)
    {
        psTraceCrypto("Couldn't parse crl sig algorithm identifier\n");
        psX509FreeCRL(lcrl);
        return PS_PARSE_FAIL;
    }

    /*
        Name            ::=   CHOICE { -- only one possibility for now --
                                 rdnSequence  RDNSequence }

        RDNSequence     ::=   SEQUENCE OF RelativeDistinguishedName

        DistinguishedName       ::=   RDNSequence

        RelativeDistinguishedName  ::=
                    SET SIZE (1 .. MAX) OF AttributeTypeAndValue
     */
    if ((rc = psX509GetDNAttributes(pool, &p, (uint32) (end - p),
             &lcrl->issuer, 0)) < 0)
    {
        psX509FreeCRL(lcrl);
        psTraceCrypto("Couldn't parse crl issuer DN attributes\n");
        return rc;
    }

    /* thisUpdate TIME */
    if ((end - p) < 1 || ((*p != ASN_UTCTIME) && (*p != ASN_GENERALIZEDTIME)))
    {
        psTraceCrypto("Malformed thisUpdate CRL\n");
        psX509FreeCRL(lcrl);
        return PS_PARSE_FAIL;
    }
    timetag = *p;
    p++;
    if (getAsnLength(&p, (uint32) (end - p), &timelen) < 0 ||
        (uint32) (end - p) < timelen)
    {
        psTraceCrypto("Malformed thisUpdate CRL\n");
        psX509FreeCRL(lcrl);
        return PS_PARSE_FAIL;
    }
    if (psBrokenDownTimeImport(
            &lcrl->thisUpdateBDT, (const char *) p, timelen,
            timetag == ASN_UTCTIME ?
            PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR : 0) != PS_SUCCESS)
    {
        psTraceCrypto("Malformed thisUpdate CRL\n");
        psX509FreeCRL(lcrl);
        return PS_PARSE_FAIL;
    }

    p += timelen;   /* Move p beyond thisUpdate TIME. */

    /* nextUpdateTIME - Optional... but required by spec */
    if ((end - p) < 1 || ((*p == ASN_UTCTIME) || (*p == ASN_GENERALIZEDTIME)))
    {
        lcrl->nextUpdateType = timetag = *p;
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &timelen) < 0 ||
            (uint32) (end - p) < timelen)
        {
            psTraceCrypto("Malformed nextUpdateTIME CRL\n");
            psX509FreeCRL(lcrl);
            return PS_PARSE_FAIL;
        }
        if ((lcrl->nextUpdate = psMalloc(pool, timelen + 1)) == NULL)
        {
            psX509FreeCRL(lcrl);
            return PS_PARSE_FAIL;
        }
        memcpy(lcrl->nextUpdate, p, timelen);
        lcrl->nextUpdate[timelen] = '\0';

        if (psBrokenDownTimeImport(
                &lcrl->nextUpdateBDT, (const char *) p, timelen,
                timetag == ASN_UTCTIME ?
                PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR : 0) != PS_SUCCESS)
        {
            psTraceCrypto("Malformed thisUpdate CRL\n");
            psX509FreeCRL(lcrl);
            return PS_PARSE_FAIL;
        }
        p += timelen;

        /* Note: nextUpdate may be in past, but parsing does not
           check that. */
    }
    else
    {
        memset(&lcrl->nextUpdateBDT, 0, sizeof(lcrl->nextUpdateBDT));
    }

    /* Need to see if any data left in tbsCertList.  Could be no revocations */
    if ((p - start) != tbsCertLen)
    {
        /*
            revokedCertificates     SEQUENCE OF SEQUENCE  {
                userCertificate         CertificateSerialNumber,
                revocationDate          Time,
                crlEntryExtensions      Extensions OPTIONAL
                                           -- if present, shall be v2
                                  }  OPTIONAL,
         */

        /* Need to peek at next byte to make sure there are some revoked
            certs here. Could be jumping right to crlExtensions  */
        if (*p != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
        {

            if (getAsnSequence32(&p, (uint32) (end - p), &glen, 0) < 0)
            {
                psTraceCrypto("Initial revokedCert error in psX509ParseCRL\n");
                psX509FreeCRL(lcrl);
                return PS_PARSE_FAIL;
            }

            lcrl->revoked = curr = psMalloc(pool, sizeof(x509revoked_t));
            if (curr == NULL)
            {
                psX509FreeCRL(lcrl);
                return PS_MEM_FAIL;
            }
            memset(curr, 0x0, sizeof(x509revoked_t));
            while (glen > 0)
            {
                revStart = p;
                if (getAsnSequence32(&p, (uint32) (end - p), &ilen, 0) < 0)
                {
                    psTraceCrypto("Deep revokedCert error in psX509ParseCRL\n");
                    psX509FreeCRL(lcrl);
                    return PS_PARSE_FAIL;
                }
                start = p; /* reusing start */
                if ((rc = getSerialNum(pool, &p, ilen, &curr->serial,
                         &curr->serialLen)) < 0)
                {
                    psTraceCrypto("ASN serial number parse error\n");
                    psX509FreeCRL(lcrl);
                    return rc;
                }

                /* revocationDate */
                if ((end - p) < 1 || ((*p != ASN_UTCTIME) &&
                                      (*p != ASN_GENERALIZEDTIME)))
                {
                    psTraceCrypto("Malformed revocationDate CRL\n");
                    psX509FreeCRL(lcrl);
                    return PS_PARSE_FAIL;
                }
                timetag = *p;
                p++;
                if (getAsnLength(&p, (uint32) (end - p), &timelen) < 0 ||
                    (uint32) (end - p) < timelen)
                {
                    psTraceCrypto("Malformed thisUpdate CRL\n");
                    psX509FreeCRL(lcrl);
                    return PS_PARSE_FAIL;
                }
                if (psBrokenDownTimeImport(
                        &curr->revocationDateBDT, (const char *) p,
                        timelen,
                        timetag == ASN_UTCTIME ?
                        PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR : 0) !=
                    PS_SUCCESS)
                {
                    psTraceCrypto("Malformed thisUpdate CRL\n");
                    psX509FreeCRL(lcrl);
                    return PS_PARSE_FAIL;
                }

                /* skipping crlEntryExtensions */
                p += ilen - (uint32) (p - start);
                if (glen < (uint32) (p - revStart))
                {
                    psTraceCrypto("Deeper revokedCert err in psX509ParseCRL\n");
                    psX509FreeCRL(lcrl);
                    return PS_PARSE_FAIL;
                }
                glen -= (uint32) (p - revStart);

                /* psTraceBytes("revoked", curr->serial, curr->serialLen); */
                if (glen > 0)
                {
                    if ((next = psMalloc(pool, sizeof(x509revoked_t))) == NULL)
                    {
                        psX509FreeCRL(lcrl);
                        return PS_MEM_FAIL;
                    }
                    memset(next, 0x0, sizeof(x509revoked_t));
                    curr->next = next;
                    curr = next;
                }
            }
        }
        /* Always treated as OPTIONAL */
        if (getExplicitExtensions(pool, &p, (uint32) (end - p), 0,
                &lcrl->extensions, 0) < 0)
        {
            psTraceCrypto("Extension parse error in psX509ParseCRL\n");
            psX509FreeCRL(lcrl);
            return PS_PARSE_FAIL;
        }
        /* if (lcrl->extensions.ak.keyId) { */
        /*      psTraceBytes("CRL ak", lcrl->extensions.ak.keyId, 20); */
        /* } */
    } /* End tbsCertList */
    sigEnd = p;

    if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi, &plen) < 0)
    {
        psX509FreeCRL(lcrl);
        psTraceCrypto("Couldn't parse crl sig algorithm identifier\n");
        return PS_PARSE_FAIL;
    }
    /* must match */
    if (oi != lcrl->sigAlg)
    {
        psTraceCrypto("Couldn't match crl sig algorithm identifier\n");
        psX509FreeCRL(lcrl);
        return PS_PARSE_FAIL;
    }

    if ((rc = psX509GetSignature(pool, &p, (uint32) (end - p), &lcrl->sig,
             &lcrl->sigLen)) < 0)
    {
        psX509FreeCRL(lcrl);
        psTraceCrypto("Couldn't parse signature\n");
        return rc;
    }

    /* Perform the hashing for later auth */
    rc = psComputeHashForSig(sigStart, sigEnd - sigStart,
        lcrl->sigAlg,
        lcrl->sigHash, &lcrl->sigHashLen);
    if (rc != PS_SUCCESS)
    {
        psX509FreeCRL(lcrl);
        return rc;
    }

    *crl = lcrl;

    return PS_SUCCESS;
}

/*
    If the provided cert has a URL based CRL Distribution point, return
    that.  The url and urlLen point directly into the cert structure so
    must not be modified.
*/
int32 psX509GetCRLdistURL(psX509Cert_t *cert, char **url, uint32_t *urlLen)
{
    x509GeneralName_t *gn;

    if (cert == NULL)
    {
        return PS_ARG_FAIL;
    }
    *url = NULL;
    *urlLen = 0;

    if (cert->extensions.crlDist != NULL)
    {
        gn = cert->extensions.crlDist;
        while (gn)
        {
            if (gn->id == 6)   /* Only pass on URI types */
            {
                *url = (char *) gn->data;
                *urlLen = gn->dataLen;
                return PS_TRUE;
            }
            else
            {
                psTraceIntCrypto("Unsupported CRL distro point format %d\n",
                    gn->id);
            }
            gn = gn->next;
        }
    }
    return PS_FALSE;
}

/******************************************************************************/

# endif /* USE_CERT_PARSE */
#endif  /* USE_CRL */

