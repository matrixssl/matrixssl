/**
 *      @file    pem_decode_mem.c
 *      @version $Format:%h%d$
 *
 *      Functions for in-memory PEM decoding.
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

#include "../cryptoImpl.h"

# ifdef USE_PRIVATE_KEY_PARSING
int32_t psPemTryDecode(psPool_t *pool,
        const unsigned char *in,
        psSizeL_t inLen,
        psPemType_t pemType,
        const char *password,
        unsigned char **out,
        psSizeL_t *outLen)
{
# ifndef USE_PEM_DECODE
    return PS_UNSUPPORTED_FAIL;
# else
    psBool_t isPem = PS_FALSE;
    int32_t rc;

    isPem = psPemCheckOk(in,
            inLen,
            pemType,
            NULL,
            NULL,
            NULL);
    if (isPem)
    {
        rc = psPemDecode(pool,
                in,
                inLen,
                password,
                out,
                outLen);
        if (rc != PS_SUCCESS)
        {
            return rc;
        }
        return PS_SUCCESS;
    }

    return PS_ARG_FAIL; /* Input not PEM. */
# endif /* USE_PEM_DECODE */
}
# endif /* USE_PRIVATE_KEY_PARSING */

# ifdef USE_PEM_DECODE

psBool_t psPemCheckOk(const unsigned char *pemBuf,
        psSizeL_t pemBufLen,
        psPemType_t pemType,
        char **startp,
        char **endp,
        psSizeL_t *pemlen)
{
    char *start, *end;

    /* Check header and encryption parameters. */
    if (((start = Strstr((char *) pemBuf, "-----BEGIN")) != NULL) &&
            ((start = Strstr((char *) pemBuf, "PRIVATE KEY-----")) != NULL) &&
            ((end = Strstr(start, "-----END")) != NULL) &&
            (Strstr(end, "PRIVATE KEY-----") != NULL))
    {
        if (pemType != PEM_TYPE_KEY &&
                pemType != PEM_TYPE_PRIVATE_KEY &&
                pemType != PEM_TYPE_ANY)
        {
            return PS_FALSE;
        }
        start += Strlen("PRIVATE KEY-----");
        while (*start == '\x0d' || *start == '\x0a')
        {
            start++;
        }
    }
    else if (((start = Strstr((char *) pemBuf, "-----BEGIN")) != NULL) &&
            ((start = Strstr((char *) pemBuf, "PUBLIC KEY-----")) != NULL) &&
            ((end = Strstr(start, "-----END")) != NULL) &&
            (Strstr(end, "PUBLIC KEY-----") != NULL))
    {
        if (pemType != PEM_TYPE_PUBLIC_KEY &&
                pemType != PEM_TYPE_KEY &&
                pemType != PEM_TYPE_ANY)
        {
            return PS_FALSE;
        }
        start += Strlen("PUBLIC KEY-----");
        while (*start == '\x0d' || *start == '\x0a')
        {
            start++;
        }
    }
    else if (((start = Strstr((char *) pemBuf, "-----BEGIN")) != NULL) &&
            ((start = Strstr((char *) pemBuf, "CERTIFICATE-----")) != NULL) &&
            ((end = Strstr(start, "-----END")) != NULL) &&
            (Strstr(end, "CERTIFICATE-----") != NULL))
    {
        if (pemType != PEM_TYPE_CERTIFICATE &&
                pemType != PEM_TYPE_ANY)
        {
            return PS_FALSE;
        }

        start += Strlen("CERTIFICATE-----");
        while (*start == '\x0d' || *start == '\x0a')
        {
            start++;
        }
    }
    else
    {
        return PS_FALSE;
    }

    if (pemlen != NULL)
    {
        *pemlen = (psSizeL_t) (end - start);
    }
    if (startp != NULL && endp != NULL)
    {
        *startp = start;
        *endp = end;
    }

    return PS_TRUE;
}

int32_t psPemDecode(psPool_t *pool,
        const unsigned char *keyBufIn,
        psSizeL_t keyBufLen,
        const char *password,
        unsigned char **out,
        psSizeL_t *outlen)
{
#  if defined(USE_PKCS5) && defined(USE_PBKDF1)
    psDes3_t dctx;
    psAesCbc_t actx;
    unsigned char passKey[32];   /* AES-256 max */
    unsigned char cipherIV[16];  /* AES-256 max */
    int32 tmp, encrypted = 0;
    static const char des3encryptHeader[]   = "DEK-Info: DES-EDE3-CBC,";
    static const char aes128encryptHeader[] = "DEK-Info: AES-128-CBC,";
#  endif /* USE_PKCS5 && USE_PBKDF1 */
    unsigned char *dout;
    char *start, *end;
    int32 rc;
    psSizeL_t PEMlen = 0;
    const char *keyBuf;
    psSize_t outlenPsSize;

    start = end = NULL;

    if (!psPemCheckOk(keyBufIn,
                    keyBufLen,
                    PEM_TYPE_ANY,
                    &start,
                    &end,
                    &PEMlen))
    {
        psTraceCrypto("Input does not look to be in PKCS#1 PEM format\n");
        return PS_PARSE_FAIL;
    }

    keyBuf = (const char *)keyBufIn;
    if (Strstr((char *) keyBuf, "Proc-Type:") &&
        Strstr((char *) keyBuf, "4,ENCRYPTED"))
    {
#  if defined(USE_PKCS5) && defined(USE_PBKDF1)
        if (password == NULL)
        {
            psTraceCrypto("No password given for encrypted private key file\n");
            return PS_ARG_FAIL;
        }
        if ((start = Strstr((char *) keyBuf, des3encryptHeader)) != NULL)
        {
            start += Strlen(des3encryptHeader);
            encrypted = 1;
            /* we assume here that header points to at least 16 bytes of data */
            tmp = psHexToBinary((unsigned char *) start, cipherIV, DES3_IVLEN);
        }
        else if ((start = Strstr((char *) keyBuf, aes128encryptHeader))
                 != NULL)
        {
            start += Strlen(aes128encryptHeader);
            encrypted = 2;
            /* we assume here that header points to at least 32 bytes of data */
            tmp = psHexToBinary((unsigned char *) start, cipherIV, 16);
        }
        else
        {
            psTraceCrypto("Unrecognized private key file encoding\n");
            return PS_PARSE_FAIL;
        }

        if (tmp < 0)
        {
            psTraceCrypto("Invalid private key file salt\n");
            return PS_FAILURE;
        }
        start += tmp;
        if (psPkcs5Pbkdf1((unsigned char *) password, Strlen(password),
                cipherIV, 1, (unsigned char *) passKey) < 0)
        {
            psTraceCrypto("psPkcs5Pbkdf1 failed\n");
            return PS_FAILURE;
        }
        PEMlen = (int32) (end - start);
#  else /* !USE_PKCS5 || !USE_PBKDF1 */
        /* The private key is encrypted, but PKCS5 support has been turned off */
#   ifndef USE_PKCS5
        psTraceCrypto("USE_PKCS5 must be enabled for key file password\n");
#   endif /* USE_PKCS5 */
#   ifndef USE_PBKDF1
        psTraceCrypto("USE_PBKDF1 must be enabled for key file password\n");
#   endif /* USE_PBKDF1 */
        return PS_UNSUPPORTED_FAIL;
#  endif /* USE_PKCS5 && USE_PBKDF1 */
    }

    /* Take the raw input and do a base64 decode */
    dout = psMalloc(pool, PEMlen);
    if (dout == NULL)
    {
        psError("Memory allocation error in psPkcs1DecodePrivFile\n");
        return PS_MEM_FAIL;
    }
    *outlen = PEMlen;
    outlenPsSize = PEMlen;
    rc = psBase64decode((unsigned char *) start,
            PEMlen,
            dout,
            &outlenPsSize);
    if (rc < 0)
    {
        psTraceCrypto("Error base64 decode of private key\n");
        if (password)
        {
            psTraceCrypto("Is it possible the password is incorrect?\n");
        }
        psFree(dout, pool);
        return rc;
    }
    *outlen = outlenPsSize;

#  if defined(USE_PKCS5) && defined(USE_PBKDF1)
    if (encrypted == 1 && password)
    {
        psDes3Init(&dctx, cipherIV, passKey);
        psDes3Decrypt(&dctx, dout, dout, *outlen);
        memset_s(&dctx, sizeof(psDes3_t), 0x0, sizeof(psDes3_t));
    }
    if (encrypted == 2 && password)
    {
        /* AES 128 */
        psAesInitCBC(&actx, cipherIV, passKey, 16, PS_AES_DECRYPT);
        psAesDecryptCBC(&actx, dout, dout, *outlen);
        memset_s(&actx, sizeof(psAesCbc_t), 0x0, sizeof(psAesCbc_t));
    }
    /* SECURITY - zero out keys when finished */
    memset_s(passKey, sizeof(passKey), 0x0, sizeof(passKey));
#  endif /* USE_PKCS5 && USE_PBKDF1 */
    *out = dout;
    return PS_SUCCESS;
}

# ifdef USE_X509
psRes_t psPemCertBufToList(psPool_t *pool,
        const unsigned char *buf,
        psSizeL_t len,
        psList_t **x509certList)
{
    psList_t *front, *prev, *current;
    unsigned char *start, *end, *endTmp;
    const unsigned char *chFileBuf;
    unsigned char l;
    int n = 0;
    int32_t rc;

    *x509certList = NULL;
    prev = NULL;
    if (buf == NULL)
    {
        psTraceCrypto("Bad parameters to pemCertBufToList\n");
        return PS_ARG_FAIL;
    }
    front = current = psMalloc(pool, sizeof(psList_t));
    if (current == NULL)
    {
        psError("Memory allocation error first pemCertBufToList\n");
        return PS_MEM_FAIL;
    }
    l = Strlen("CERTIFICATE-----");
    Memset(current, 0x0, sizeof(psList_t));
    chFileBuf = buf;
    while (len > 0)
    {
        if (
            ((start = (unsigned char *) Strstr((char *) chFileBuf, "-----BEGIN")) != NULL) &&
            ((start = (unsigned char *) Strstr((char *) chFileBuf, "CERTIFICATE-----")) != NULL) &&
            ((end = (unsigned char *) Strstr((char *) start, "-----END")) != NULL) &&
            ((endTmp = (unsigned char *) Strstr((char *) end, "CERTIFICATE-----")) != NULL)
            )
        {
            n++;
            start += l;
            if (current == NULL)
            {
                current = psMalloc(pool, sizeof(psList_t));
                if (current == NULL)
                {
                    psFreeList(front, pool);
                    psError("Memory allocation error: pemCertBufToList\n");
                    return PS_MEM_FAIL;
                }
                Memset(current, 0x0, sizeof(psList_t));
                prev->next = current;
            }
            current->len = (uint16_t) (end - start);
            end = endTmp + l;
            while (*end == '\x0d' || *end == '\x0a' || *end == '\x09'
                   || *end == ' ')
            {
                end++;
            }
        }
        else
        {
            psFreeList(front, pool);
            psTraceCrypto("File buffer does not look to be X.509 PEM format\n");
            return PS_PARSE_FAIL;
        }
        current->item = psMalloc(pool, current->len);
        if (current->item == NULL)
        {
            psFreeList(front, pool);
            psError("Memory allocation error: pemCertBufToList\n");
            return PS_MEM_FAIL;
        }
        Memset(current->item, '\0', current->len);

        len -= (psSizeL_t) (end - buf);
        buf = end;

        rc = psBase64decode(start,
                current->len,
                current->item,
                &current->len);
        if (rc != 0)
        {
            psFreeList(front, pool);
            psTraceCrypto("Unable to base64 decode certificate\n");
            return PS_PARSE_FAIL;
        }
        prev = current;
        current = current->next;
        chFileBuf = buf;
    }
    *x509certList = front;
    return PS_SUCCESS;
}
#  endif /* USE_X509 */

# endif /* USE_PEM_DECODE */
