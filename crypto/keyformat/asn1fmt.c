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

#if !defined USE_X509 && !defined USE_OCSP
# include "../cryptoImpl.h" /* MatrixSSL API interface and configuration. */
#endif

#if (defined USE_X509 && defined USE_FULL_CERT_PARSE) || defined USE_OCSP

# include <stdio.h>   /* for snprintf() */
# include <string.h>  /* for strlen() */

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

#endif  /* compilation selector: full X.509 or OCSP enabled */

