/**
 *      @file    psbuf.h
 *      @version $Format:%h%d$
 *
 *      API for handling buffers containing binary data.
 */
/*
 *      Copyright (c) 2017 INSIDE Secure Corporation
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

#ifndef _h_PS_BUF
# define _h_PS_BUF

# include "coreApi.h"
# include <string.h>

/* API for psBuf initialization and basic usage.*/
void *psBufInit(psPool_t *pool, psBuf_t *buf, size_t capacity);
void psBufUninit(psPool_t *pool, psBuf_t *buf);
int32_t psBufFromStaticData(psBuf_t *buf, const void *data, size_t len);
int32_t psBufEmptyFromPointerSize(psBuf_t *buf, void *data, size_t len);
void *psBufDetach(psPool_t *pool, psBuf_t *buf, size_t *len_p);
void *psBufAppendSize(psBuf_t *buf, size_t sz);
size_t psBufGetMaxAppendSize(const psBuf_t *buf);
void psBufReservePrepend(psBuf_t *buf, size_t sz);
void *psBufPrependSize(psBuf_t *buf, size_t sz);
size_t psBufGetMaxPrependSize(const psBuf_t *buf);
void *psBufGetData(psBuf_t *buf);
size_t psBufGetDataSize(const psBuf_t *buf);
void psBufNormalize(psBuf_t *buf);
char *psBufAsHex(psPool_t *pool, const psBuf_t *buf);
int32_t psBufCopyDataN(psBuf_t *buf, size_t reqLen,
                       unsigned char *target, size_t *targetlen);

int32_t psBufFromData(psPool_t *pool, psBuf_t *buf,
                      const void *data, size_t len);


static __inline int psBufEq(const psBuf_t *buf1, const psBuf_t *buf2)
{
    return (buf1->end - buf1->start) == (buf2->end - buf2->start) &&
           buf1->start != NULL &&
           buf2->start != NULL &&
           memcmp(buf1->start, buf2->start, (buf1->end - buf1->start))
           == 0;
}

static __inline void *psBufAppendChar(psBuf_t *buf, char ch)
{
    void *loc = psBufAppendSize(buf, 1);

    if (loc)
    {
        *(char *) loc = ch;
    }
    return loc;
}

static __inline void *psBufPrependChar(psBuf_t *buf, char ch)
{
    void *loc = psBufPrependSize(buf, 1);

    if (loc)
    {
        *(char *) loc = ch;
    }
    return loc;
}

/* API for Dynamic Buffers initialization and basic usage. */
void *psDynBufInit(psPool_t *pool, psDynBuf_t *db, size_t capacity);
void psDynBufUninit(psDynBuf_t *db);
void *psDynBufDetach(psDynBuf_t *db, size_t *len_p);
void *psDynBufAppendSize(psDynBuf_t *db, size_t sz);
void psDynBufReservePrepend(psDynBuf_t *db, size_t sz);
void *psDynBufPrependSize(psDynBuf_t *db, size_t sz);

static __inline void *psDynBufAppendChar(psDynBuf_t *db, char ch)
{
    void *loc = psDynBufAppendSize(db, 1);

    if (loc)
    {
        *(char *) loc = ch;
    }
    return loc;
}

void *psDynBufAppendUtf8(psDynBuf_t *db, int chr);
void *psDynBufAppendUtf16(psDynBuf_t *db, int chr);
void *psDynBufAppendUtf32(psDynBuf_t *db, int chr);

static __inline void *psDynBufPrependChar(psDynBuf_t *db, char ch)
{
    void *loc = psDynBufPrependSize(db, 1);

    if (loc)
    {
        *(char *) loc = ch;
    }
    return loc;
}

static __inline void *psDynBufAppendStr(psDynBuf_t *db, const char *s)
{
    size_t len = s ? strlen(s) : 0;
    void *loc = psDynBufAppendSize(db, len);

    if (loc)
    {
        memcpy(loc, s, len);
    }
    return loc;
}

static __inline void *psDynBufPrependStr(psDynBuf_t *db, const char *s)
{
    size_t len = s ? strlen(s) : 0;
    void *loc = psDynBufPrependSize(db, len);

    if (loc)
    {
        memcpy(loc, s, len);
    }
    return loc;
}

static __inline void *psDynBufAppendOctets(psDynBuf_t *db, const void *data,
    size_t len)
{
    void *loc = psDynBufAppendSize(db, len);

    if (loc)
    {
        memcpy(loc, data, len);
    }
    return loc;
}

static __inline void *psDynBufAppendBuf(psDynBuf_t *db, const psBuf_t *b)
{
    return psDynBufAppendOctets(db, b->start, b->end - b->start);
}

static __inline void *psDynBufAppendParseBuf(psDynBuf_t *db,
                                             const psParseBuf_t *pb)
{
    if (!pb || pb->err)
    {
        db->err++;
        return NULL;
    }
    return psDynBufAppendBuf(db, &(pb->buf));
}
    
static __inline void *psDynBufIncorporateDynBuf(psDynBuf_t *db, psDynBuf_t *db2)
{
    size_t len;
    void *data = psDynBufDetach(db2, &len);

    if (data)
    {
        return psDynBufAppendOctets(db, data, len);
    }
    else
    {
        db->err++;
        return NULL;
    }
}

/* Dynamic buffer subbuffers. */
void *psDynBufSubInit(psDynBuf_t *db, psDynBuf_t *sub, size_t capacity);
void *psDynBufSubInitAt(psDynBuf_t *db, psDynBuf_t *sub, size_t at,
                        size_t length);
void *psDynBufSubFinish(psDynBuf_t *sub);

/* Note: This variable argument function is currently implemented as a macro. */
# define psDynBufAppendStrf(ps_dyn_buf_p, ...)               \
    do {                                \
        char tmp;                       \
        size_t len = 1 + snprintf(&tmp, 1, __VA_ARGS__);    \
        char *target = psDynBufAppendSize((ps_dyn_buf_p), len); \
        if (target) {                       \
            snprintf(target, len, __VA_ARGS__);     \
            (ps_dyn_buf_p)->buf.end -= 1;           \
        }                           \
    } while (0)


/* Subset of ASN.1 via psDynBuf. */
char *psDynBufAppendAsn1TagGen(psDynBuf_t *db, unsigned char tag,
                               const unsigned char *bytes, size_t len);

static inline
char *psDynBufAppendAsn1IntegerSmall(psDynBuf_t *db, signed char byte)
{
    unsigned char bytes[1];

    bytes[0] = (unsigned char) byte;
    return psDynBufAppendAsn1TagGen(db, 0x02, bytes, 1);
}

static inline
char *psDynBufAppendAsn1OctetString(psDynBuf_t *db,
                                    const unsigned char *bytes, size_t len)
{
    return psDynBufAppendAsn1TagGen(db, 0x04, bytes, len);
}

static inline
char *psDynBufAppendAsn1Oid(psDynBuf_t *db,
                            const unsigned char *oidbytes, size_t len)
{
    /* Note: oidbytes shall not include OID identifier (6) or length. */
    return psDynBufAppendAsn1TagGen(db, 0x06, oidbytes, len);
}

char *psDynBufBeginConstructedTag(psDynBuf_t *db, psDynBuf_t *sub);
char *psDynBufEndConstructedTag(psDynBuf_t *sub, unsigned char tag);

static __inline char *psDynBufBeginSequence(psDynBuf_t *db, psDynBuf_t *sub)
{
    return psDynBufBeginConstructedTag(db, sub);
}

static __inline char *psDynBufEndSequence(psDynBuf_t *sub)
{
    return psDynBufEndConstructedTag(sub, 0x30);
}

static __inline int32_t psDynBufDetachBuf(psDynBuf_t *db, psBuf_t *target)
{
    size_t sz;
    void *buf;

    buf = psDynBufDetach(db, &sz);
    target->start = target->buf = (unsigned char *) buf;
    if (!buf)
    {
        /* Exception path: memory allocation failure. */
        target->size = 0;
        target->end = (unsigned char *) buf;
        return PS_MEM_FAIL;
    }

    target->size = sz;
    target->end = ((unsigned char *) buf) + sz;
    return PS_SUCCESS;
}

/* Start parsing static data using psParseBuf_t. */
int32_t psParseBufFromStaticData(psParseBuf_t *pb,
                                 const void *data, size_t len);

/* Check if there is sufficient data to parse left. */
static __inline int psParseCanRead(const psParseBuf_t *pb, size_t nbytes)
{
    size_t bytes_readable;

    if (pb->err)
    {
        return 0;
    }

    bytes_readable = pb->buf.end - pb->buf.start;
    return bytes_readable >= nbytes;
}

/* Check if there is sufficient data to parse left. */
PSPUBLIC int psParseBufCanReadUtf8(const psParseBuf_t *pb);

/* Check if there is sufficient data to parse left. */
PSPUBLIC unsigned int psParseBufReadUtf8(psParseBuf_t *pb);

/* Get length of following ASN.1 tag
   (specify tag as unsigned char or 0 for ANY).

   This is for parsing content of parsebuf as ASN.1 DER data.

   If hdrLen_p is non-null, the function also returns the length of tag header.
 */
size_t psParseBufGetTagLen(const psParseBuf_t *pb, unsigned char tag,
                           size_t *hdrLen_p);
/* Test if there is specific (tag > 0) or any (tag == 0) ASN.1 der
   encoding at current parsing location.
   return 0 no, 1 yes */
int psParseBufCanGetTag(const psParseBuf_t *pb, unsigned char tag);
/* Try read ASN.1 DER specific (tag > 0) or any (tag == 0) at the
   current parsing location. Reading will return sub parsebuf,
   which allows reading constructed tags.
   Returns length of tag read (including header) or 0 if no tag was read.
   Parsing location will advance once finished with content.
 */
size_t psParseBufTryReadTagSub(const psParseBuf_t *pb,
                               psParseBuf_t *content, unsigned char tag);
/* Read specified (or any) ASN.1 tag at the current parsing location.
   it is considered error if read fails.
   Parsing location will advance once finished with content. */
size_t psParseBufReadTagSub(psParseBuf_t *pb,
                            psParseBuf_t *content, unsigned char tag);
/* Copy all data from parse buffer. Supports length negotiations.
   Fails if parsing errors have been seen. */
int32_t psParseBufCopyAll(const psParseBuf_t *pb, unsigned char *target,
                          size_t *targetlen);
/* Return true only if buffers have encountered no parsing errors and
   the contents are equal. */
int psParseBufEq(const psParseBuf_t *pb1, const psParseBuf_t *pb2);
/* return PS_SUCCESS if pb has not encountered parsing errors. */
int32_t psParseBufCheckState(const psParseBuf_t *pb);

/* Alias (implemented as a macro) for psParseBufTryReadTagSub used on sequence.
 */
# define psParseBufTryReadSequenceSub(pb, content) \
    psParseBufTryReadTagSub(pb, content, 0x30)

/* Alias (implemented as a macro) for psParseBufReadTagSub used on sequence. */
# define psParseBufReadSequenceSub(pb, content) \
    psParseBufReadTagSub(pb, content, 0x30)

/* Skip tag with specified tag id (or 0 for any) if possible.
   If tag was skipped, return length in bytes that was skipped. */
size_t psParseBufTrySkipTag(psParseBuf_t *pb, unsigned char tag);

/* Skip tag with specified tag id (or 0 for any) if possible.
   Tag not existing is considered error and error is set in pb. */
size_t psParseBufSkipTag(psParseBuf_t *pb, unsigned char tag);

/* Signal errors from sub to master buffer.
   If invoked on allocated main parse buffer, the memory will be freed.
   If invoked on subbuffer, the position on main buffer is advanced.
   The return value will only be PS_SUCCESS is no errors have been observed. */
int32_t psParseBufFinish(psParseBuf_t *buf);

/* Cancel processing of subbuffer.
   Errors are not propagated to the master buffer, and master buffer is not
   advanced.
   If invoked on allocated main parse buffer, any memory allocated will
   still be freed. */
void psParseBufCancel(psParseBuf_t *buf);

/* Skip specified bytes (such as tag with specific contents or non-ASN.1 data)*/
size_t psParseBufTrySkipBytes(psParseBuf_t *pb,
                              const unsigned char *bytes,
                              size_t numbytes);

/* Skip specified bytes. Not finding the bytes is an error. */
size_t psParseBufSkipBytes(psParseBuf_t *pb, const unsigned char *bytes,
                           size_t numbytes);

/* Read given tag and fill-in reference with the content.
   Parse buffer is moved to point to the next parsing location. */
size_t psParseBufReadTagRef(psParseBuf_t *pb,
                            psBuf_t *ref, unsigned char tag);

/* Copy data from parse buffer until stopbyte is seen.
   The target shall be large enough or NULL to inquire size.
   The stopbyte will be included in bytes copied.
   This function does not update buffer parsing position. */
int32_t psParseBufCopyUntilByte(psParseBuf_t *pb, unsigned char stopbyte,
                                unsigned char *target, size_t *targetlen);
/* Copy specified amount of data from parse buffer without moving buffer
   parsing position. */
int32_t psParseBufCopyN(const psParseBuf_t *pb, size_t reqLen,
                        unsigned char *target, size_t *targetlen);
#endif /* _h_PS_BUF */
/* end of file psbuf.h */
