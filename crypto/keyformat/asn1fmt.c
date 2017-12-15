/**
 *      @file    x509dbg.c
 *      @version $Format:%h%d$
 *
 *      ASN.1 Parsing: convenience functions for formatting ASN.1.
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

#if !defined USE_X509 && !defined USE_OCSP_RESPONSE
# include "../cryptoImpl.h" /* MatrixSSL API interface and configuration. */
#endif

#if (defined USE_X509 && defined USE_FULL_CERT_PARSE) || defined USE_OCSP_RESPONSE

# include <stdio.h>   /* for snprintf() */
# include <string.h>  /* for strlen() */
#include "core/psPrnf.h"

/* Constants used in OID formatting code. */
# define OID_STR_BUF_LEN (129 * 4) /* Temporary string length. */
# define OID_STR_MAX_SEQ_LEN 64    /* Maximum octets in sequence. */

/* Access bitarray containing 7 bits of data per octet. */
static unsigned char oid_get_bit7(const unsigned char *bitarray,
    size_t n, int i)
{
    unsigned char byte;
    size_t a = (size_t) (i / 7);
    int bitidx = i % 7;

    if (n <= a)
    {
        return 0;
    }

    byte = bitarray[n - a - 1];
    byte >>= bitidx;
    return byte & 1;
}

/* Perform conversion between OID encoded data (i.e. BER compressed
   integer like perl pack("w"), and a long sequence of octets. */
static
unsigned int oid_double_dabble_workhorse(const unsigned char *b,
    size_t n,
    unsigned char t[],
    int v_bits, size_t t_bytes)
{
    int i;
    size_t j;
    unsigned int x;
    unsigned int overflow = 0;
    size_t t_bcdbytes = (t_bytes + 1) / 2;

    for (j = t_bcdbytes; j-- > 0; )
    {
        t[j] = 0;
    }

    /* Compute BCD corresponding with Buc_p.
       (double-dabble algorithm). */
    for (i = v_bits; i-- > 0; )
    {
        unsigned char c = oid_get_bit7(b, n, i);
        x = c;
        for (j = t_bcdbytes; j-- > 0; )
        {
            x += (2 * (unsigned int) t[j]);
            t[j] = x & 255;
            x >>= 8;
        }
        overflow |= x;
        if (i == 0)
        {
            break;
        }
        for (j = t_bcdbytes; j-- > 0; )
        {
            unsigned char a, add51, m;
            a = t[j];
            add51 = a + 51;
            m = add51 & 0x88;
            m |= m >> 2;
            m |= m >> 1;
            t[j] = (a & ~m) | (add51 & m);
        }
    }

    /* Convert BCD to decimal. */
    if ((t_bytes & 1) == 1)
    {
        /* The result is shifted 4 bits; fix it. */
        overflow |= t[0] >> 4;
        for (j = t_bytes; j-- > 0; )
        {
            if (j & 1)
            {
                t[j] = '0' + (t[j / 2 + 1] >> 4);
            }
            else
            {
                t[j] = '0' + (t[j / 2] & 15);
            }
        }
    }
    else
    {
        for (j = t_bytes; j-- > 0; )
        {
            if (j & 1)
            {
                t[j] = '0' + (t[j / 2] & 15);
            }
            else
            {
                t[j] = '0' + (t[j / 2] >> 4);
            }
        }
    }

    return overflow;
}

/* Append to string s (assumed sufficiently long) a contiguous segment of
   BER compressed integer like perl pack("w") unpacked. This function
   processes at most 64 bytes at once (i.e. up-to 72683872429560689054932380
   7888004534353641360687318060281490199180639288113397923326191050713763565
   560762521606266177933534601628614655).
   This range is sufficient for typical OIDs as well as UUID-based OIDs.
 */
static size_t oid_part_append(char *s, const unsigned char *oid, size_t oidlen)
{
    size_t pos;
    unsigned long long ll;
    const unsigned char *oid_orig = oid;

    /* The most common case: single byte oid segment. */
    if (*oid < 128)
    {
        sprintf(s, ".%d", *oid);
        return 1;
    }
    else if (*oid == 128)
    {
        /* Illegal: One of the highest bits shall be set. */
        return 0;
    }

    /* Handle oid parts smaller than 2**64-1. */
    ll = *oid & 127;
    pos = 1;
    while (pos < oidlen)
    {
        oid++;
        ll *= 128;
        ll += *oid & 127;
        if (*oid < 128)
        {
            if (pos < 8)
            {
                sprintf(s, ".%llu", ll);
                return pos + 1;
            }
            else if (pos < OID_STR_MAX_SEQ_LEN)
            {
                size_t plen;
                size_t ilen;
                /* Precision may exceed capacity of unsigned long long.
                   Use variant of double-dabble that can do arbitrary
                   precision. */
                pos += 1;
                *s = '.';
                memset(s + 1, 0, pos * 3 + 1);
                oid_double_dabble_workhorse(oid_orig, pos,
                    (unsigned char *) (s + 1),
                    pos * 8, pos * 3);

                /* The string formatting generates extra zeroes. Remove them. */
                s += 1; /* Skip '.' */
                ilen = strlen(s);
                plen = 0;
                while (plen < ilen && plen < ilen - 1 && s[plen] == '0')
                {
                    plen++;
                }
                /* Remove initial zeroes. */
                memmove(s, s + plen, ilen + 1 - plen);
                return pos;
            }
            else
            {
                /* Single OID component exceeds sizes required for any
                   known uses. These are not handled. */
                return 0;
            }
        }
        pos++;
    }

    return 0; /* Unable to process. */
}

/* Decrement 1 from number expressed in ascii. */
static void oid_asciidec(char *s, size_t l)
{
    size_t i;
    int dec = 1;

    for (i = l; i-- > 0; )
    {
        s[i] -= dec;
        if (s[i] < '0')
        {
            s[i] = '9';
        }
        else
        {
            dec = 0;
        }
    }
}

/* Format OID to string buffer. Returns position within the buffer
   on successful execution or NULL on failure. */
static char *oid_to_string(const unsigned char *oid, size_t oidlen,
    char str[OID_STR_BUF_LEN])
{
    char *s = str;
    int prefix = 0; /* Ignored bytes in beginning. */

    str[0] = 0;
    /* Only process OID identifiers, and up-to 129 bytes long, with
       correct length identifier. */
    if (oidlen < 3 || oidlen > 129 || oid[0] != 0x06 || oid[1] != oidlen - 2)
    {
        return NULL;
    }
    if (oid[2] < 120)
    {
        /* Simple case, [012].x where x < 40. */
        sprintf(s, "%d.%d", oid[2] / 40, oid[2] % 40);
        s += strlen(s);
        oid += 3;
        oidlen -= 3;
    }
    else
    {
        /* Process 2.xxx, where xxx is arbitrary length number >= 40. */
        size_t bytes = oid_part_append(s + 1, oid + 2, oidlen - 2);
        int i;

        if (bytes < 2)
        {
            return NULL;
        }

        /* Decrement tens eight time. */
        for (i = 0; i < 8; i++)
        {
            oid_asciidec(s + 2, strlen(s + 2) - 1);
        }

        /* Check if there were extra zeroes in s[2]. */
        while (strlen(s + 2) && s[2] == '0')
        {
            s++;
            prefix++;
        }

        s[0] = '2';
        s[1] = '.';
        s += strlen(s);
        oid += 2 + bytes;
        oidlen -= 2 + bytes;
    }
    while (oidlen > 0)
    {
        size_t bytes = oid_part_append(s, oid, oidlen);
        if (bytes == 0)
        {
            return NULL;
        }
        oidlen -= bytes;
        oid += bytes;
        s += strlen(s);
    }
    return str + prefix;
}

# ifndef NO_ASN_FORMAT_OID
char *asnFormatOid(psPool_t *pool,
    const unsigned char *oid, size_t oidlen)
{
    /* Perform formatting for oid. */
    char *out;
    char str_tmp[OID_STR_BUF_LEN];
    char *str = oid_to_string(oid, oidlen, str_tmp);

    if (str == NULL)
    {
        return NULL;
    }

    /* Allocate dynamically new memory for the result. */
    out = psMalloc(pool, strlen(str) + 1);
    if (out)
    {
        memcpy(out, str, strlen(str) + 1);
    }
    return out;
}
# endif /* NO_ASN_FORMAT_OID */

struct asnFormatTagInfo
{
    const char *str_short;
    const char *str_long;
    unsigned char constructed;
    unsigned char omit;
    unsigned char string8bit;
};

static struct asnFormatTagInfo asnFormatTagInfo[128] =
{
    { "END", "End-Of-Contents", 0, 0, 0 },
    { "BOOL", "BOOLEAN", 0, 1, 0 },
    { "INT", "INTEGER", 0, 1, 0 },
    { "BITS", "BIT STRING", 0, 0, 0 },
    { "OCTETS", "OCTET STRING", 0, 0, 0 },
    { "NULL", "NULL", 0, 0, 0 },
    { "OID", "OBJECT IDENTIFIER", 0, 1, 0 },
    { "Obj", "ObjectDescriptor", 0, 0, 0 },
    { "INST", "INSTANCE OF", 0, 0, 0 },
    { "REAL", "REAL", 0, 1, 0 },
    { "ENUM", "ENUMERATED", 0, 0, 0 },
    { "EMB", "EMBEDDED PDV", 0, 0, 0 },
    { "UTF8", "UTF8String", 0, 0, 1 },
    { "REL-OID", "RELATIVE-OID", 0, 0, 0 },
    { "Uni[14]", "Universal[14]", 0, 0, 0 },
    { "Uni[15]", "Universal[15]", 0, 0, 0 },
    { "SEQ", "SEQUENCE", 1, 0, 0 },
    { "SET", "SET", 1, 0, 0 },
    { "Num", "NumericString", 0, 0, 1 },
    { "Print", "PrintableString", 0, 1, 1 },
    { "T.61", "TeletexString", 0, 1, 1 },
    { "VID", "VideotexString", 0, 1, 1 },
    { "ASCII", "IA5String", 0, 0, 1 },
    { "UTCTime", "UTCTime", 0, 1, 1 },
    { "GenTime", "GeneralizedTime", 0, 1, 1 },
    { "Graphic", "GraphicString", 0, 0, 1 },
    { "Visible", "VisibleString", 0, 0, 1 },
    { "Gen", "GeneralString", 0, 0, 1 },
    { "UTF-32", "UniversalString", 0, 0, 0 },
    { "STR", "CHARACTER STRING", 0, 0, 1 },
    { "BMP", "BMP STRING", 0, 0, 1 },
    { "Uni[31]", "Universal[31]", 0, 0, 1 },
    { "App[0]", "Application[0]", 1, 0, 0 },
    { "App[1]", "Application[1]", 1, 0, 0 },
    { "App[2]", "Application[2]", 1, 0, 0 },
    { "App[3]", "Application[3]", 1, 0, 0 },
    { "App[4]", "Application[4]", 1, 0, 0 },
    { "App[5]", "Application[5]", 1, 0, 0 },
    { "App[6]", "Application[6]", 1, 0, 0 },
    { "App[7]", "Application[7]", 1, 0, 0 },
    { "App[8]", "Application[8]", 1, 0, 0 },
    { "App[9]", "Application[9]", 1, 0, 0 },
    { "App[10]", "Application[10]", 1, 0, 0 },
    { "App[11]", "Application[11]", 1, 0, 0 },
    { "App[12]", "Application[12]", 1, 0, 0 },
    { "App[13]", "Application[13]", 1, 0, 0 },
    { "App[14]", "Application[14]", 1, 0, 0 },
    { "App[15]", "Application[15]", 1, 0, 0 },
    { "App[16]", "Application[16]", 1, 0, 0 },
    { "App[17]", "Application[17]", 1, 0, 0 },
    { "App[18]", "Application[18]", 1, 0, 0 },
    { "App[19]", "Application[19]", 1, 0, 0 },
    { "App[20]", "Application[20]", 1, 0, 0 },
    { "App[21]", "Application[21]", 1, 0, 0 },
    { "App[22]", "Application[22]", 1, 0, 0 },
    { "App[23]", "Application[23]", 1, 0, 0 },
    { "App[24]", "Application[24]", 1, 0, 0 },
    { "App[25]", "Application[25]", 1, 0, 0 },
    { "App[26]", "Application[26]", 1, 0, 0 },
    { "App[27]", "Application[27]", 1, 0, 0 },
    { "App[28]", "Application[28]", 1, 0, 0 },
    { "App[29]", "Application[29]", 1, 0, 0 },
    { "App[30]", "Application[30]", 1, 0, 0 },
    { "App[31]", "Application[31]", 1, 0, 0 },
    { "Cont[0]", "Context-Specific[0]", 1, 0, 0 },
    { "Cont[1]", "Context-Specific[1]", 1, 0, 0 },
    { "Cont[2]", "Context-Specific[2]", 1, 0, 0 },
    { "Cont[3]", "Context-Specific[3]", 1, 0, 0 },
    { "Cont[4]", "Context-Specific[4]", 1, 0, 0 },
    { "Cont[5]", "Context-Specific[5]", 1, 0, 0 },
    { "Cont[6]", "Context-Specific[6]", 1, 0, 0 },
    { "Cont[7]", "Context-Specific[7]", 1, 0, 0 },
    { "Cont[8]", "Context-Specific[8]", 1, 0, 0 },
    { "Cont[9]", "Context-Specific[9]", 1, 0, 0 },
    { "Cont[10]", "Context-Specific[10]", 1, 0, 0 },
    { "Cont[11]", "Context-Specific[11]", 1, 0, 0 },
    { "Cont[12]", "Context-Specific[12]", 1, 0, 0 },
    { "Cont[13]", "Context-Specific[13]", 1, 0, 0 },
    { "Cont[14]", "Context-Specific[14]", 1, 0, 0 },
    { "Cont[15]", "Context-Specific[15]", 1, 0, 0 },
    { "Cont[16]", "Context-Specific[16]", 1, 0, 0 },
    { "Cont[17]", "Context-Specific[17]", 1, 0, 0 },
    { "Cont[18]", "Context-Specific[18]", 1, 0, 0 },
    { "Cont[19]", "Context-Specific[19]", 1, 0, 0 },
    { "Cont[20]", "Context-Specific[20]", 1, 0, 0 },
    { "Cont[21]", "Context-Specific[21]", 1, 0, 0 },
    { "Cont[22]", "Context-Specific[22]", 1, 0, 0 },
    { "Cont[23]", "Context-Specific[23]", 1, 0, 0 },
    { "Cont[24]", "Context-Specific[24]", 1, 0, 0 },
    { "Cont[25]", "Context-Specific[25]", 1, 0, 0 },
    { "Cont[26]", "Context-Specific[26]", 1, 0, 0 },
    { "Cont[27]", "Context-Specific[27]", 1, 0, 0 },
    { "Cont[28]", "Context-Specific[28]", 1, 0, 0 },
    { "Cont[29]", "Context-Specific[29]", 1, 0, 0 },
    { "Cont[30]", "Context-Specific[30]", 1, 0, 0 },
    { "Cont[31]", "Context-Specific[31]", 1, 0, 0 },
    { "Priv[0]", "Private[0]", 1, 0, 0 },
    { "Priv[1]", "Private[1]", 1, 0, 0 },
    { "Priv[2]", "Private[2]", 1, 0, 0 },
    { "Priv[3]", "Private[3]", 1, 0, 0 },
    { "Priv[4]", "Private[4]", 1, 0, 0 },
    { "Priv[5]", "Private[5]", 1, 0, 0 },
    { "Priv[6]", "Private[6]", 1, 0, 0 },
    { "Priv[7]", "Private[7]", 1, 0, 0 },
    { "Priv[8]", "Private[8]", 1, 0, 0 },
    { "Priv[9]", "Private[9]", 1, 0, 0 },
    { "Priv[10]", "Private[10]", 1, 0, 0 },
    { "Priv[11]", "Private[11]", 1, 0, 0 },
    { "Priv[12]", "Private[12]", 1, 0, 0 },
    { "Priv[13]", "Private[13]", 1, 0, 0 },
    { "Priv[14]", "Private[14]", 1, 0, 0 },
    { "Priv[15]", "Private[15]", 1, 0, 0 },
    { "Priv[16]", "Private[16]", 1, 0, 0 },
    { "Priv[17]", "Private[17]", 1, 0, 0 },
    { "Priv[18]", "Private[18]", 1, 0, 0 },
    { "Priv[19]", "Private[19]", 1, 0, 0 },
    { "Priv[20]", "Private[20]", 1, 0, 0 },
    { "Priv[21]", "Private[21]", 1, 0, 0 },
    { "Priv[22]", "Private[22]", 1, 0, 0 },
    { "Priv[23]", "Private[23]", 1, 0, 0 },
    { "Priv[24]", "Private[24]", 1, 0, 0 },
    { "Priv[25]", "Private[25]", 1, 0, 0 },
    { "Priv[26]", "Private[26]", 1, 0, 0 },
    { "Priv[27]", "Private[27]", 1, 0, 0 },
    { "Priv[28]", "Private[28]", 1, 0, 0 },
    { "Priv[29]", "Private[29]", 1, 0, 0 },
    { "Priv[30]", "Private[30]", 1, 0, 0 },
    { "Priv[31]", "Private[31]", 1, 0, 0 }
};

static unsigned char idx(unsigned char tag)
{
    unsigned char idx = (tag & 31) | ((tag & 192) >> 1);
    return idx;
}

const char *asnFormatTagId(unsigned char tag)
{
    return asnFormatTagInfo[idx(tag)].str_short;
}

const char *asnFormatTagIdLong(unsigned char tag)
{
    return asnFormatTagInfo[idx(tag)].str_long;
}

static char *internalStrdup(psPool_t *pool, const char *string)
{
    size_t len;
    char *new_str;

    if (string == NULL)
    {
        return NULL;
    }
    len = strlen(string) + 1;
    new_str = psMalloc(pool, len);
    if (new_str)
    {
        memcpy(new_str, string, len);
    }
    return new_str;
}


char *asnFormatDer(psPool_t *pool,
                   const unsigned char *Der_p,
                   size_t DerLen,
                   size_t MaxElements,
                   size_t MaxDepth,
                   size_t MaxElementOutput,
                   unsigned char Flags)
{
    size_t i;
    psParseBuf_t pb;
    psParseBuf_t sub;
    psDynBuf_t str;
    size_t endlen;
    size_t sz;
    size_t MaxElementOutputD2;

    if (MaxElements == 0)
    {
        MaxElements = (size_t) -1;
    }

    if (MaxDepth == 0)
    {
        MaxDepth = (size_t) -1;
    }

    if (MaxElementOutput == 0)
    {
        MaxElementOutput = (size_t) -1;
    }
    MaxElementOutputD2 = MaxElementOutput / 2;

    if (DerLen < 1)
    {
        return internalStrdup(pool, "[length = 0]");
    }
    
    if (psParseBufFromStaticData(&pb, Der_p, DerLen) != PS_SUCCESS)
    {
        return internalStrdup(pool, "[ASN.1 Parser Failure]");
    }
    psDynBufInit(pool, &str, 80);
    for(i = 0; i < MaxElements; i++)
    {
        unsigned char tagid[1];
        const char *tagstr;
        int has_content;
        size_t content_len;
        int printed;
        int negative = 0;
        const unsigned char *content;
        const unsigned char *tagdata;

        if (!psParseCanRead(&pb, 1))
        {
            break; /* All elements read. */
        }

        sz = 1;
        (void) psParseBufCopyN(&pb, 1, tagid, &sz);
        tagdata = psBufGetData(&pb.buf);
        
        if (sz != 1 || !psParseBufTryReadTagSub(&pb, &sub, tagid[0]))
        {
            psDynBufAppendStr(&str, "[unparseable data]");
            break; /* All elements read up-to error. */
        }

        if (i > 0)
        {
            psDynBufAppendStr(&str, ", ");
        }

        tagstr = asnFormatTagId(tagid[0]);
        has_content = psParseCanRead(&sub, 1);
        content = psBufGetData(&sub.buf);
        content_len = psBufGetDataSize(&sub.buf);
        printed = 0;

        /* Formatting: tag specific. */
        switch (tagid[0])
        {
        case 1:
            if (content_len == 1 && content[0] == 0xff)
            {
                psDynBufAppendStrf(&str, "%s(true)", tagstr);
                printed = 1;
            }

            if (content_len == 1 && content[0] == 0x00)
            {
                psDynBufAppendStrf(&str, "%s(false)", tagstr);
                printed = 1;
            }
            break;
        case 2:
            if (content_len > 0 && (content[0] & 0x80) != 0)
            {
                negative = 1;
            }
            /* FALL-THROUGH */
        case 4:
            if (content_len > 0 && content_len <= MaxElementOutputD2)
            {
                /* This is a number or other sequence of hex. */
                PS_PRNF_CTX;
                char *tmp_str = psAsprnf(pool, PSF,
                                         PSA_HEX(content, content_len));
                if (tmp_str)
                {
                    psDynBufAppendStrf(&str, "%s(%s0x%s)",
                                       tagstr, negative ? "-" : "", tmp_str);
                    psFree(tmp_str, pool);
                    printed = 1;
                }
            }
            break;
        case 3:
            if (content_len > 1 && content_len <= MaxElementOutputD2)
            {
                /* Print bit string as hex sequence. */
                PS_PRNF_CTX;
                char *tmp_str = psAsprnf(pool, PSF,
                                         PSA_HEX(content + 1, content_len - 1));
                if (tmp_str)
                {
                    if (content[0] != 0)
                    {
                        psDynBufAppendStrf(&str, "%s(0x%s[padding=%u])",
                                           tagstr, tmp_str, content[0]);
                    }
                    else
                    {
                        psDynBufAppendStrf(&str, "%s(0x%s)",
                                           tagstr, tmp_str);
                    }
                    psFree(tmp_str, pool);
                    printed = 1;
                }
            }
            break;
        case 5:
            /* NULL needs to be used without any content.
               Omit "(empty)" in that case. */
            if (content_len == 0)
            {
                psDynBufAppendStr(&str, tagstr);
                printed = 1;
            }
            break;
        case 6:
            if (content_len > 0 && content_len <= MaxElementOutputD2)
            {
                /* OID: Pass formatter also tag id and tag length. */
                size_t hlen = content - tagdata;
                char *tmp_str = asnFormatOid(pool, tagdata, hlen + content_len);
                if (tmp_str)
                {
                    psDynBufAppendStrf(&str, "%s(%s)", tagstr, tmp_str);
                    psFree(tmp_str, pool);
                    printed = 1;
                }
            }
            break;
        default:
            /* Constructed encodings perform recursion. */
            if ((tagid[0] & 32) == 32 && content_len > 0 && MaxDepth > 1)
            {
                char *tmp_str = asnFormatDer(pool,
                                             content,
                                             content_len,
                                             0,
                                             MaxDepth - 1,
                                             MaxElementOutput,
                                             Flags);
                if (tmp_str)
                {
                    psDynBufAppendStrf(&str, "%s(%s)", tagstr, tmp_str);
                    psFree(tmp_str, pool);
                    printed = 1;
                }
                break;
            }

            /* Generic handling for 8-bit strings. */
            if (asnFormatTagInfo[idx(tagid[0])].string8bit &&
                content_len <= MaxElementOutput)
            {
                /* This is 8bit string. */
                PS_PRNF_CTX;
                char *tmp_str = psAsprnf(pool, PSF,
                                         PSA_SSTR((const char *)content,
                                                  content_len));
                if (tmp_str)
                {
                    psDynBufAppendStrf(&str, "%s(\"%s\")", tagstr, tmp_str);
                    psFree(tmp_str, pool);
                    printed = 1;
                }
            }
        }

        /* Last resort: Indicate number of bytes. */
        if (!printed)
        {
            psDynBufAppendStrf(&str, "%s(%s)",
                               tagstr, has_content? "..." : "empty");
        }
        (void)psParseBufFinish(&sub);
    }
    endlen = 0;
    while(psParseCanRead(&pb, 1))
    {
        psParseBufSkipBytes(&pb, NULL, 1);
        endlen++;
    }
    if (endlen > 0)
    {
        psDynBufAppendStrf(&str, "[%llu unprocessed bytes]",
                           (unsigned long long) endlen);
    }
    (void)psParseBufFinish(&pb);
    psDynBufAppendChar(&str, 0); /* Add terminating NUL character. */
    return psDynBufDetach(&str, &sz);
}

#endif  /* compilation selector: full X.509 or OCSP enabled */

