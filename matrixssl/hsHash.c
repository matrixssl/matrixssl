/**
 *      @file    hsHash.c
 *      @version $Format:%h%d$
 *
 *      "Native" handshake hash.
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

#include "matrixsslImpl.h"

#ifdef USE_NATIVE_TLS_HS_HASH

# define FINISHED_LABEL_SIZE 15
# define LABEL_CLIENT        "client finished"
# define LABEL_SERVER        "server finished"
/******************************************************************************/
/**
    Initialize the SHA1 and MD5 hash contexts for the handshake messages.
    The handshake hashes are used in 3 messages in TLS:
    ClientFinished, ServerFinished and ClientCertificateVerify.
    The version of TLS affects which hashes are used for the Finished messages.
    TLS 1.2 allows a different hash algorithm for the CertificatVerify message
    than is used by the Finished messages, determined by the
    Signature Algorithms extension.
    Multiple handshake hash contexts must be maintained until the handshake has
    progressed enough to determine the negotiated TLS version and whether or
    not Client Authentication is to be performed. Also, if USE_ONLY_TLS_1_2 is
    defined at compile time, or USE_CLIENT_AUTH is undefined at compile time,
    the potential runtime combinations are reduced.
    The various algorithms are used as follows (+ means concatenation):
        Client and Server Finished messages
            < TLS 1.2 - MD5+SHA1
            TLS 1.2 - SHA256
        Client CertificateVerify message.
            < TLS 1.2 - MD5+SHA1
            TLS 1.2 - One of the hashes present in the union of the
            SignatureAlgorithms Client extension and the CertificateRequest
            message from the server. At most this is the set
            {SHA1,SHA256,SHA384,SHA512}.
    @return < 0 on failure.
    @param[in,out] ssl TLS context
 */
int32_t sslInitHSHash(ssl_t *ssl)
{
# ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        /* Don't allow CLIENT_HELLO message retransmit to reset hash */
        if (ssl->retransmit)
        {
            return 0;
        }
    }
# endif /* USE_DTLS */

# ifndef USE_ONLY_TLS_1_2
    psMd5Sha1Init(&ssl->sec.msgHashMd5Sha1);
# endif

# ifdef USE_TLS_1_2
    psSha256Init(&ssl->sec.msgHashSha256);
#  ifdef USE_SHA1
    psSha1Init(&ssl->sec.msgHashSha1);
#  endif
#  ifdef USE_SHA384
    psSha384Init(&ssl->sec.msgHashSha384);
#  endif
#  ifdef USE_SHA512
    psSha512Init(&ssl->sec.msgHashSha512);
#  endif
# endif

    return 0;
}

/******************************************************************************/
/**
    Add the given data to the running hash of the handshake messages.
    @param[in,out] ssl TLS context
    @param[in] in Pointer to handshake data to hash.
    @param[in] len Number of bytes of handshake data to hash.
    @return < 0 on failure.
 */
int32_t sslUpdateHSHash(ssl_t *ssl, const unsigned char *in, psSize_t len)
{

# ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        /* Don't update handshake hashes on resends.  Already been through here */
        if (ssl->retransmit)
        {
            return 0;
        }
    }
# endif /* USE_DTLS */

# ifdef USE_TLS_1_2
    /* Keep a running total of each for greatest RFC support when it comes
        to the CertificateVerify message.  Although, trying to be smart
        about MD5 and SHA-2 based on protocol version. */
    if ((ssl->majVer == 0 && ssl->minVer == 0) ||
#  ifdef USE_DTLS
        ssl->minVer == DTLS_1_2_MIN_VER ||
#  endif
        ssl->minVer == TLS_1_2_MIN_VER)
    {
        psSha256Update(&ssl->sec.msgHashSha256, in, len);
#  ifdef USE_SHA1
        psSha1Update(&ssl->sec.msgHashSha1, in, len);
#  endif
#  ifdef USE_SHA384
        psSha384Update(&ssl->sec.msgHashSha384, in, len);
#  endif
#  ifdef USE_SHA512
        psSha512Update(&ssl->sec.msgHashSha512, in, len);
#  endif
    }
# endif

# ifndef USE_ONLY_TLS_1_2
    /* Below TLS 1.2, the hash is always the md5sha1 hash. If we negotiate
        to TLS 1.2 and need sha1, we use just that part of the md5Sha1. */
/* TODO if (ssl->reqMinVer == 0 || ssl->minVer != TLS_1_2_MIN_VER) { */
    psMd5Sha1Update(&ssl->sec.msgHashMd5Sha1, in, len);

# endif

    return 0;
}

# ifdef USE_TLS_1_2
/*      Functions necessary to deal with needing to keep track of both SHA-1
    and SHA-256 handshake hash states.  FINISHED message will always be
    SHA-256 but client might be sending SHA-1 CertificateVerify message */
#  if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
#   ifdef USE_SHA1
int32 sslSha1RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
    memcpy(out, ssl->sec.sha1Snapshot, SHA1_HASH_SIZE);
    return SHA1_HASH_SIZE;
}
#   endif
#   ifdef USE_SHA384
int32 sslSha384RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
    memcpy(out, ssl->sec.sha384Snapshot, SHA384_HASH_SIZE);
    return SHA384_HASH_SIZE;
}
#   endif
#   ifdef USE_SHA512
int32 sslSha512RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
    memcpy(out, ssl->sec.sha512Snapshot, SHA512_HASH_SIZE);
    return SHA512_HASH_SIZE;
}
#   endif
#  endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */

#  if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
#   ifdef USE_SHA1
/*      It is possible the certificate verify message wants a non-SHA256 hash */
void sslSha1SnapshotHSHash(ssl_t *ssl, unsigned char *out)
{
    psSha1Final(&ssl->sec.msgHashSha1, out);
}
#   endif
#   ifdef USE_SHA384
void sslSha384SnapshotHSHash(ssl_t *ssl, unsigned char *out)
{
    psSha384_t sha384;

    /* SHA384 must copy the context because it could be needed again for
        final handshake hash.  SHA1 doesn't need this because it will
        not ever be used again after this client auth one-off */
    psSha384Sync(&ssl->sec.msgHashSha384, 0);
    sha384 = ssl->sec.msgHashSha384;
    psSha384Final(&sha384, out);
}
#   endif
#   ifdef USE_SHA512
void sslSha512SnapshotHSHash(ssl_t *ssl, unsigned char *out)
{
    psSha512_t sha512;

    /* SHA512 must copy the context because it could be needed again for
        final handshake hash.  SHA1 doesn't need this because it will
        not ever be used again after this client auth one-off */
    psSha512Sync(&ssl->sec.msgHashSha512, 0);
    sha512 = ssl->sec.msgHashSha512;
    psSha512Final(&sha512, out);
}
#   endif
#  endif /* USE_CLIENT_SIDE_SSL && USE_CLIENT_AUTH */
# endif  /* USE_TLS_1_2 */

# ifdef USE_TLS
/******************************************************************************/
/*
    TLS handshake hash computation
 */
static int32_t tlsGenerateFinishedHash(ssl_t *ssl,
#  ifndef USE_ONLY_TLS_1_2
    psMd5Sha1_t *md5sha1,
#  endif
#  ifdef USE_TLS_1_2
#   ifdef USE_SHA1
    psSha1_t *sha1,
#   endif
#   ifdef USE_SHA256
    psSha256_t *sha256,
#   endif
#   ifdef USE_SHA384
    psSha384_t *sha384,
#   endif
#   ifdef USE_SHA512
    psSha512_t *sha512,
#   endif
#  endif /* USE_TLS_1_2 */
    unsigned char *masterSecret,
    unsigned char *out, int32 senderFlag)
{
    unsigned char tmp[FINISHED_LABEL_SIZE + SHA384_HASH_SIZE];

#  ifndef USE_ONLY_TLS_1_2
    psMd5Sha1_t md5sha1_backup;
#  endif
#  ifdef USE_SHA1
    psSha1_t sha1_backup;
#  endif
#  ifdef USE_SHA256
    psSha256_t sha256_backup;
#  endif
#  ifdef USE_SHA384
    psSha384_t sha384_backup;
#  endif
#  ifdef USE_SHA512
    psSha512_t sha512_backup;
#  endif
/*
    In each branch: Use a backup of the message hash-to-date because we don't
    want to destroy the state of the handshaking until truly complete
 */

    if (senderFlag >= 0)
    {
        memcpy(tmp, (senderFlag & SSL_FLAGS_SERVER) ? LABEL_SERVER : LABEL_CLIENT,
            FINISHED_LABEL_SIZE);
#  ifdef USE_TLS_1_2
        if (ssl->flags & SSL_FLAGS_TLS_1_2)
        {
            if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3)
            {
#   ifdef USE_SHA384
                psSha384Cpy(&sha384_backup, sha384);
                psSha384Final(&sha384_backup, tmp + FINISHED_LABEL_SIZE);
                return prf2(masterSecret, SSL_HS_MASTER_SIZE, tmp,
                    FINISHED_LABEL_SIZE + SHA384_HASH_SIZE, out,
                    TLS_HS_FINISHED_SIZE, CRYPTO_FLAGS_SHA3);
#   endif
            }
            else
            {
                psSha256Cpy(&sha256_backup, sha256);
                psSha256Final(&sha256_backup, tmp + FINISHED_LABEL_SIZE);
                return prf2(masterSecret, SSL_HS_MASTER_SIZE, tmp,
                    FINISHED_LABEL_SIZE + SHA256_HASH_SIZE, out,
                    TLS_HS_FINISHED_SIZE, CRYPTO_FLAGS_SHA2);
            }
#   ifndef USE_ONLY_TLS_1_2
        }
        else
        {
            psMd5Sha1Cpy(&md5sha1_backup, md5sha1);
            psMd5Sha1Final(&md5sha1_backup, tmp + FINISHED_LABEL_SIZE);
            return prf(masterSecret, SSL_HS_MASTER_SIZE, tmp,
                FINISHED_LABEL_SIZE + MD5SHA1_HASHLEN,
                out, TLS_HS_FINISHED_SIZE);
#   endif
        }
#  else
        psMd5Sha1Cpy(&md5sha1_backup, md5sha1);
        psMd5Sha1Final(&md5sha1_backup, tmp + FINISHED_LABEL_SIZE);
        return prf(masterSecret, SSL_HS_MASTER_SIZE, tmp,
            FINISHED_LABEL_SIZE + MD5SHA1_HASHLEN,
            out, TLS_HS_FINISHED_SIZE);
#  endif
    }
    else
    {
        /* Overloading this function to handle the client auth needs of
            handshake hashing. */
#  ifdef USE_TLS_1_2
        if (ssl->flags & SSL_FLAGS_TLS_1_2)
        {
            psSha256Cpy(&sha256_backup, sha256);
            psSha256Final(&sha256_backup, out);
#   if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
            /* Check to make sure we are a server because clients come
                through here as well and they do not need to snapshot any
                hashes because they are in a write state during the
                CERTIFICATE_VERIFY creation.  So if they detect a non-default
                in digest, they just run the sslSha384SnapshotHSHash family
                of functions.  Servers really do have to save aside the
                snapshots beause the CERTIFICATE_VERIFY is a parse and so the
                handshake hash is being set aside for all possible combos
                here so the sslSha384RetrieveHSHash can fetch.  Previous
                versions were not testing for SERVER here so clients were
                running digest operations that were not needed in client auth */
            if (ssl->flags & SSL_FLAGS_SERVER)
            {
#    ifdef USE_SHA384
                psSha384Cpy(&sha384_backup, sha384);
                psSha384Final(&sha384_backup, ssl->sec.sha384Snapshot);
#    endif
#    ifdef USE_SHA512
                psSha512Cpy(&sha512_backup, sha512);
                psSha512Final(&sha512_backup, ssl->sec.sha512Snapshot);
#    endif
#    ifdef USE_SHA1
                psSha1Cpy(&sha1_backup, sha1);
                psSha1Final(&sha1_backup, ssl->sec.sha1Snapshot);
#    endif
            }
#   endif
            return SHA256_HASH_SIZE;
#   ifndef USE_ONLY_TLS_1_2
        }
        else
        {
            psMd5Sha1Cpy(&md5sha1_backup, md5sha1);
            psMd5Sha1Final(&md5sha1_backup, out);
            return MD5SHA1_HASHLEN;
#   endif
        }
#  else
/*
        The handshake snapshot for client authentication is simply the
        appended MD5 and SHA1 hashes
 */
        psMd5Sha1Cpy(&md5sha1_backup, md5sha1);
        psMd5Sha1Final(&md5sha1_backup, out);
        return MD5SHA1_HASHLEN;
#  endif  /* USE_TLS_1_2 */
    }
    return PS_FAILURE; /* Should not reach this */
}
# endif /* USE_TLS */


/* The extended master secret computation uses a handshake hash */
int32_t extMasterSecretSnapshotHSHash(ssl_t *ssl, unsigned char *out,
    uint32 *outLen)
{
# ifndef USE_ONLY_TLS_1_2
    psMd5Sha1_t md5sha1;
# endif
# ifdef USE_SHA256
    psSha256_t sha256;
# endif
# ifdef USE_SHA384
    psSha384_t sha384;
# endif

/*
    Use a backup of the message hash-to-date because we don't want
    to destroy the state of the handshaking until truly complete
 */

    *outLen = 0;

# ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3)
        {
#  ifdef USE_SHA384
            psSha384Cpy(&sha384, &ssl->sec.msgHashSha384);
            psSha384Final(&sha384, out);
            *outLen = SHA384_HASH_SIZE;
#  endif
        }
        else
        {
            psSha256Cpy(&sha256, &ssl->sec.msgHashSha256);
            psSha256Final(&sha256, out);
            *outLen = SHA256_HASH_SIZE;
        }
#  ifndef USE_ONLY_TLS_1_2
    }
    else
    {
        psMd5Sha1Cpy(&md5sha1, &ssl->sec.msgHashMd5Sha1);
        psMd5Sha1Final(&md5sha1, out);
        *outLen = MD5SHA1_HASHLEN;
#  endif
    }
# else /* no TLS 1.2 */
    psMd5Sha1Cpy(&md5sha1, &ssl->sec.msgHashMd5Sha1);
    psMd5Sha1Final(&md5sha1, out);
    *outLen = MD5SHA1_HASHLEN;
# endif

    return *outLen;
}


/******************************************************************************/
/*
    Snapshot is called by the receiver of the finished message to produce
    a hash of the preceeding handshake messages for comparison to incoming
    message.
 */
int32_t sslSnapshotHSHash(ssl_t *ssl, unsigned char *out, int32 senderFlag)
{
    int32 len = PS_FAILURE;

# ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        /* Don't allow FINISHED message retransmit to re-calc hash */
        if (ssl->retransmit)
        {
            memcpy(out, ssl->hsSnapshot, ssl->hsSnapshotLen);
            return ssl->hsSnapshotLen;
        }
    }
# endif /* USE_DTLS */

# ifdef USE_TLS
    if (ssl->flags & SSL_FLAGS_TLS)
    {
        len = tlsGenerateFinishedHash(ssl,
#  ifndef USE_ONLY_TLS_1_2
            &ssl->sec.msgHashMd5Sha1,
#  endif
#  ifdef USE_TLS_1_2
#   ifdef USE_SHA1
            &ssl->sec.msgHashSha1,
#   endif
#   ifdef USE_SHA256
            &ssl->sec.msgHashSha256,
#   endif
#   ifdef USE_SHA384
            &ssl->sec.msgHashSha384,
#   endif
#   ifdef USE_SHA512
            &ssl->sec.msgHashSha512,
#   endif
#  endif /* USE_TLS_1_2 */
            ssl->sec.masterSecret, out, senderFlag);

#  ifndef DISABLE_SSLV3
    }
    else
    {
        len = sslGenerateFinishedHash(&ssl->sec.msgHashMd5Sha1,
            ssl->sec.masterSecret, out, senderFlag);
#  endif /* DISABLE_SSLV3 */
    }
# endif  /* USE_TLS */

# ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (len > 0)
        {
            memcpy(ssl->hsSnapshot, out, len);
            ssl->hsSnapshotLen = len;
        }
    }
# endif /* USE_DTLS */
    return len;
}

#endif /* USE_NATIVE_TLS_HS_HASH */

/******************************************************************************/

