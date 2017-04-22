/**
 *      @file    aesGCM.c
 *      @version $Format:%h%d$
 *
 *      AES GCM block cipher implementation.
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

#include "../cryptoImpl.h"

#ifdef USE_MATRIX_AES_GCM

/******************************************************************************/

static void psGhashPad(psAesGcm_t *ctx);
static void psGhashInit(psAesGcm_t *ctx,
                        const unsigned char *GHASHKey_p);
static void psGhashUpdate(psAesGcm_t *ctx, const unsigned char *data,
                          uint32 dataLen, int dataType);
static void psGhashFinal(psAesGcm_t *ctx);

# define GHASH_DATATYPE_AAD          0
# define GHASH_DATATYPE_CIPHERTEXT   2

# define FL_GET_BE32(be)                           \
    (((uint32) ((be).be_bytes[0]) << 24) |         \
     ((uint32) ((be).be_bytes[1]) << 16) |         \
     ((uint32) ((be).be_bytes[2]) <<  8) |         \
     (uint32) ((be).be_bytes[3]))

typedef struct { unsigned char be_bytes[4]; } FL_UInt32_BE_UNA_t;

# define FLFBLOCKSIZE 128 /* Maximum block size of a hash function. */

/******************************************************************************/
/*
    Initialize an AES GCM context
 */
int32_t psAesInitGCM(psAesGcm_t *ctx,
    const unsigned char key[AES_MAXKEYLEN], uint8_t keylen)
{
    int32_t rc;
    unsigned char blockIn[16] = { 0 };

    memset(ctx, 0x0, sizeof(psAesGcm_t));
    /* GCM always uses AES in ENCRYPT block mode, even for decrypt */
    rc = psAesInitBlockKey(&ctx->key, key, keylen, PS_AES_ENCRYPT);
    if (rc < 0)
    {
        return rc;
    }
    psAesEncryptBlock(&ctx->key, blockIn, ctx->gInit);
    return PS_SUCCESS;
}

/******************************************************************************/

void psAesClearGCM(psAesGcm_t *ctx)
{
    /* Only need to clear block if it's implemented externally, Matrix block
        is part of AesGcm_t and will be cleared below */
# ifndef USE_MATRIX_AES_BLOCK
    psAesClearBlockKey(&ctx->key);
# endif
    memset_s(ctx, sizeof(psAesGcm_t), 0x0, sizeof(psAesGcm_t));
}

/******************************************************************************/
/*
    Specifiy the IV and additional data to an AES GCM context that was
    created with psAesInitGCM
 */
void psAesReadyGCM(psAesGcm_t *ctx,
    const unsigned char IV[AES_IVLEN],
    const unsigned char *aad, psSize_t aadLen)
{
    psGhashInit(ctx, ctx->gInit);
    /* Save aside first counter for final use */
    memset(ctx->IV, 0, 16);
    memcpy(ctx->IV, IV, 12);
    ctx->IV[15] = 1;

    /* Set up crypto counter starting at nonce || 2 */
    memset(ctx->EncCtr, 0, 16);
    memcpy(ctx->EncCtr, IV, 12);
    ctx->EncCtr[15] = 2;

    psGhashUpdate(ctx, aad, aadLen, GHASH_DATATYPE_AAD);
    psGhashPad(ctx);
}

int32_t psAesReadyGCMRandomIV(psAesGcm_t *ctx,
    unsigned char IV[12],
    const unsigned char *aad, psSize_t aadLen,
    void *poolUserPtr)
{
    int32_t res;

    res = psGetPrng(NULL, IV, 12, poolUserPtr);
    if (res == 12)
    {
        res = PS_SUCCESS;
        psAesReadyGCM(ctx, IV, aad, aadLen);
    }
    return res;
}

/******************************************************************************/
/*
    Internal gcm crypt function that uses direction to determine what gets
    fed to the GHASH update
 */
static void psAesEncryptGCMx(psAesGcm_t *ctx,
    const unsigned char *pt, unsigned char *ct,
    uint32_t len, int8_t direction)
{
    unsigned char *ctStart;
    uint32_t outLen;
    int x;              /* Must be signed due to positive check below */

    outLen = len;
    ctStart = ct;
    if (direction == 0)
    {
        psGhashUpdate(ctx, pt, len, GHASH_DATATYPE_CIPHERTEXT);
    }
    while (len)
    {
        if (ctx->OutputBufferCount == 0)
        {
            ctx->OutputBufferCount = 16;
            psAesEncryptBlock(&ctx->key, ctx->EncCtr, ctx->CtrBlock);

            /* CTR incr */
            for (x = (AES_BLOCKLEN - 1); x >= 0; x--)
            {
                ctx->EncCtr[x] = (ctx->EncCtr[x] +
                                  (unsigned char) 1) & (unsigned char) 255;
                if (ctx->EncCtr[x] != (unsigned char) 0)
                {
                    break;
                }
            }
        }

        *(ct++) = *(pt++) ^ ctx->CtrBlock[16 - ctx->OutputBufferCount];
        len--;
        ctx->OutputBufferCount--;
    }
    if (direction == 1)
    {
        psGhashUpdate(ctx, ctStart, outLen, GHASH_DATATYPE_CIPHERTEXT);
    }
}

/******************************************************************************/
/*
    Public GCM encrypt function.  This will just perform the encryption.  The
    tag should be fetched with psAesGetGCMTag
 */
void psAesEncryptGCM(psAesGcm_t *ctx,
    const unsigned char *pt, unsigned char *ct,
    uint32_t len)
{
    psAesEncryptGCMx(ctx, pt, ct, len, 1);
}

/******************************************************************************/
/*
    After encryption this function is used to retreive the authentication tag
 */
void psAesGetGCMTag(psAesGcm_t *ctx,
    uint8_t tagBytes, unsigned char tag[AES_BLOCKLEN])
{
    unsigned char *pt, *ct;

    psGhashFinal(ctx);

    /* Encrypt authentication tag */
    ctx->OutputBufferCount = 0;

    ct = tag;
    pt = (unsigned char *) ctx->TagTemp;
    while (tagBytes)
    {
        if (ctx->OutputBufferCount == 0)
        {
            ctx->OutputBufferCount = 16;
            /* Initial IV has been set aside in IV */
            psAesEncryptBlock(&ctx->key, ctx->IV, ctx->CtrBlock);
            /* No need to increment since we know tag bytes will never be
                larger than 16 */
        }
        *(ct++) = *(pt++) ^ ctx->CtrBlock[16 - ctx->OutputBufferCount];
        tagBytes--;
        ctx->OutputBufferCount--;

    }
}

/* Just does the GCM decrypt portion.  Doesn't expect the tag to be at the end
    of the ct.  User will invoke psAesGetGCMTag seperately */
void psAesDecryptGCMtagless(psAesGcm_t *ctx,
    const unsigned char *ct, unsigned char *pt,
    uint32_t len)
{
    psAesEncryptGCMx(ctx, ct, pt, len, 0);
}


/******************************************************************************/
/*
    Decrypt will invoke GetGMCTag so the comparison can be done.  ctLen
    will include the appended tag length and ptLen is just the encrypted
    portion
 */
int32_t psAesDecryptGCM(psAesGcm_t *ctx,
    const unsigned char *ct, uint32_t ctLen,
    unsigned char *pt, uint32_t ptLen)
{
    psSize_t tagLen;
    unsigned char tag[AES_BLOCKLEN];

    if (ctLen > ptLen)
    {
        tagLen = ctLen - ptLen;
    }
    else
    {
        return PS_ARG_FAIL;
    }

    psAesEncryptGCMx(ctx, ct, pt, ptLen, 0);
    psAesGetGCMTag(ctx, tagLen, tag);

    if (memcmpct(tag, ct + ptLen, tagLen) != 0)
    {
        psTraceCrypto("GCM didn't authenticate\n");
        return PS_AUTH_FAIL;
    }
    return PS_SUCCESS;
}

int32_t psAesDecryptGCM2(psAesGcm_t *ctx,
    const unsigned char *ct,
    unsigned char *pt, uint32_t len,
    const unsigned char *tag, uint32_t tagLen)
{
    unsigned char tagTmp[AES_BLOCKLEN];

    psAesEncryptGCMx(ctx, ct, pt, len, 0);
    psAesGetGCMTag(ctx, AES_BLOCKLEN, tagTmp);

    if (memcmpct(tag, tagTmp, tagLen) != 0)
    {
        psTraceCrypto("GCM didn't authenticate\n");
        return PS_AUTH_FAIL;
    }
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Ghash code taken from FL
 */
static void FLA_GHASH_128_mul_base(uint32 *op, uint32 moduli)
{
    int carry_bit = op[3] & 0x1;

    op[3] = op[3] >> 1 | (op[2] & 0x1) << 31;
    op[2] = op[2] >> 1 | (op[1] & 0x1) << 31;
    op[1] = op[1] >> 1 | (op[0] & 0x1) << 31;
    op[0] = op[0] >> 1;

    if (carry_bit)
    {
        op[0] ^= moduli;
    }
}

/* Multiplication of X by Y, storing the result to X. */
static void FLA_GHASH_128_mul(uint32 *X, const uint32 *Y, uint32 moduli)
{
    uint32 t[4];
    int i;

    t[0] = X[0];
    t[1] = X[1];
    t[2] = X[2];
    t[3] = X[3];

    X[0] = X[1] = X[2] = X[3] = 0;

    for (i = 0; i < 128; i++)
    {
        if (Y[i / 32] & (1 << (31 - i % 32)))
        {
            X[0] ^= t[0];
            X[1] ^= t[1];
            X[2] ^= t[2];
            X[3] ^= t[3];
        }

        FLA_GHASH_128_mul_base(t, moduli);
    }
}

static int FLFIncreaseCountBits(psAesGcm_t *ctx, unsigned int CounterId,
    int32 NBits)
{
    int32 Lo, Hi;
    int32 Temp;

    Lo = NBits;
    Hi = 0;

    Temp = ctx->ProcessedBitCount[CounterId];
    ctx->ProcessedBitCount[CounterId] += Lo;

    if (Temp > (int32) ctx->ProcessedBitCount[CounterId])
    {
        Hi += 1;
    }

    if (Hi)
    {
        Temp = ctx->ProcessedBitCount[CounterId + 1];
        ctx->ProcessedBitCount[CounterId + 1] += Hi;

        /* Returns true if carry out of highest bits. */
        return Temp > (int32) ctx->ProcessedBitCount[CounterId + 1];
    }

    /* No update of high order bits => No carry. */
    return 0; /* false */
}

static int increaseCountBytes(psAesGcm_t *ctx, int32 NBytes,
    int CounterId)
{
    int carry;

    /* COVN: Test this code with > 2^31 bits. */

    /* Process NBytes (assuming NBytes < 0x10000000) */
    carry = FLFIncreaseCountBits(ctx, CounterId, (NBytes & 0x0FFFFFFF) << 3);

    NBytes &= 0x0FFFFFFF;

    /* For unusually large values of NBytes, process the remaining bytes
       to add 0x10000000 at time. This ensure the value of bytes,
       once converted to bits, does not overflow 32-bit value.

       PORTN: It is assumed NBytes <= 2**61. This is true on 32-bit APIs as
       FL_DataLen_t cannot represent such large value. */
    while (NBytes >= 0x10000000)
    {
        carry |= FLFIncreaseCountBits(ctx, CounterId, 0x10000000U * 8);
        NBytes -= 0x10000000;
    }

    return carry;
}

static void FLAGcmProcessBlock(uint32 *H, FL_UInt32_BE_UNA_t *Buf_p,
    uint32 *InOut)
{
    /* PORTN: Requires sizeof(FL_UInt32_BE_UNA_t) to be 4.
       Some platforms may add padding to FL_UInt32_BE_UNA_t if
       it is represented as a structure. */

    InOut[0] ^= FL_GET_BE32(Buf_p[0]);
    InOut[1] ^= FL_GET_BE32(Buf_p[1]);
    InOut[2] ^= FL_GET_BE32(Buf_p[2]);
    InOut[3] ^= FL_GET_BE32(Buf_p[3]);

    FLA_GHASH_128_mul(InOut, H, (1U << 31) + (1 << 30) + (1 << 29) + (1 << 24));
}

static void UpdateFunc(psAesGcm_t *ctx, const unsigned char *Buf_p,
    int32 Size)
{
    while (Size >= 16)
    {
        FLAGcmProcessBlock((uint32 *) ctx->Hash_SubKey,
            (FL_UInt32_BE_UNA_t *) Buf_p, (uint32 *) ctx->TagTemp);
        Buf_p += 16;
        Size -= 16;
    }
}

static void flf_blocker(psAesGcm_t *ctx, const unsigned char *Data_p,
    uint32 DataCount)
{
    while (DataCount > 0)
    {
        if (ctx->InputBufferCount == FLFBLOCKSIZE)
        {
            UpdateFunc(ctx,
                ctx->Input.Buffer,
                ctx->InputBufferCount);
            ctx->InputBufferCount = 0;
        }
        if (ctx->InputBufferCount < FLFBLOCKSIZE)
        {
            uint32 BytesProcess = min((uint32) DataCount,
                FLFBLOCKSIZE - ctx->InputBufferCount);

            memcpy(ctx->Input.Buffer
                + ctx->InputBufferCount, Data_p, BytesProcess);
            DataCount -= BytesProcess;
            ctx->InputBufferCount += BytesProcess;
            Data_p += BytesProcess;
        }
    }

}

static void psGhashInit(psAesGcm_t *ctx,
    const unsigned char *GHASHKey_p)
{
    uint32 *Key_p = (uint32 *) ctx->Hash_SubKey;

    memset(&ctx->ProcessedBitCount, 0x0,
        sizeof(ctx->ProcessedBitCount));
    ctx->InputBufferCount = 0;
    Key_p[0] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) GHASHKey_p);
    Key_p[1] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) (GHASHKey_p + 4));
    Key_p[2] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) (GHASHKey_p + 8));
    Key_p[3] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) (GHASHKey_p + 12));
    memset(ctx->TagTemp, 0x0, 16);
}

static void psGhashUpdate(psAesGcm_t *ctx, const unsigned char *data,
    uint32 dataLen, int dataType)
{
    increaseCountBytes(ctx, dataLen, dataType);
    flf_blocker(ctx, data, dataLen);

}

static void psGhashPad(psAesGcm_t *ctx)
{
    while ((ctx->InputBufferCount & 15) != 0)
    {
        unsigned char z = 0;
        flf_blocker(ctx, &z, 1);
    }
}

# ifndef ENDIAN_BIG
#  ifdef ENDIAN_NEUTRAL
#   warning ENDIAN_NEUTRAL untested for AES-GCM
#  endif

/* On little endian (and endian neutral untested), we need to reverse bytes
    to big endian mode for GhashFinal */
static uint32 FLM_ReverseBytes32(uint32 Value)
{
    Value = (((Value & 0xff00ff00UL) >> 8) | ((Value & 0x00ff00ffUL) << 8));
    return (Value >> 16) | (Value << 16);
}
static void FLF_ConvertToBE64(uint32 *Swap_p, uint32 num)
{
    uint32 tmp;

    while (num)
    {
        num--;
        tmp = FLM_ReverseBytes32(Swap_p[num * 2]);
        Swap_p[num * 2] = FLM_ReverseBytes32(Swap_p[num * 2 + 1]);
        Swap_p[num * 2 + 1] = tmp;
    }
}
static void FLF_ConvertToBE32(uint32 *Swap_p, uint32 num)
{
    /* PORTN: Byte order specific function. */
    while (num)
    {
        num--;
        Swap_p[num] = FLM_ReverseBytes32(Swap_p[num]);
    }
}

# else

/* On big endian, the 4 bytes in a uint32 are already in the right order! */
static void FLF_ConvertToBE64(uint32 *Swap_p, uint32 num)
{
    uint32 tmp;

    while (num)
    {
        num--;
        tmp = Swap_p[num * 2];
        Swap_p[num * 2] = Swap_p[num * 2 + 1];
        Swap_p[num * 2 + 1] = tmp;
    }
}
#  define FLF_ConvertToBE32(A, B)

# endif /* !ENDIAN_BIG */

static void psGhashFinal(psAesGcm_t *ctx)
{
    psGhashPad(ctx);

    /* TODO COVN: Check GHASH with data > 2^32 bits for word swap logic. */
    /* Swap 32 bit words 0 & 1 and 2 & 3, on ENDIAN_LITTLE, swap bytes too */
    FLF_ConvertToBE64(&ctx->ProcessedBitCount[0], 2);

    UpdateFunc(ctx, ctx->Input.Buffer,
        ctx->InputBufferCount);
    ctx->InputBufferCount = 0;

    UpdateFunc(ctx,
        (const unsigned char *) &ctx->ProcessedBitCount[0], 16);

    /* Convert temporary Tag Value to final Tag Value. NOOP on ENDIAN_BIG */
    FLF_ConvertToBE32(ctx->TagTemp, 4);
}

#endif /* USE_MATRIX_AES_GCM */

/******************************************************************************/

