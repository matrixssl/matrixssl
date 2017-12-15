#include "../psPrnf.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../psmalloc.h"

char *psPrnfDup(psPrnf_t *ctx, const char *src, psSizeL_t sz, const char *def)
{
    struct psPrnfStrNode *node;

    if (sz == ~(psSizeL_t)0)
    {
        sz = src ? strlen(src) : strlen(def);
    }
    node = (struct psPrnfStrNode *)malloc(sizeof(struct psPrnfStrNode) + sz + 1);
    if (node)
    {
        node->str = node->strstorage;
        node->str[sz] = 0;
        if (src)
        {
            memcpy(node->str, src, sz);
        }
        node->next = ctx->list;
        ctx->list = node;
        return node->str;
    }
    ctx->err = 1;
    return (char *)def;
}

char *psPrnfDupf(psPrnf_t *ctx, const char *def, const char *fmt, ...)
{
    char buf[1];
    char *newbuf = NULL;
    va_list ap;
    va_list ap2;
    int res;
    int res2 = -1;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    res = vsnprintf(buf, 1, fmt, ap);
    if (res >= 0 && res <= (int)PS_RES_SIZE_OK_MAX - 1)
    {
        newbuf = psPrnfDup(ctx, NULL, res, def);
        if (newbuf && newbuf != def)
        {
            res2 = vsnprintf(newbuf, res + 1, fmt, ap2);
        }
        if (res2 != res && newbuf != def)
        {
            newbuf = (char *)def;
        }
    }
    va_end(ap);
    va_end(ap2);
    return newbuf;
}

char *psPrnfDup2(psPrnf_t *ctx, const char *src, psSizeL_t sz,
                 const char *src2, psSizeL_t sz2, const char *def)
{
    struct psPrnfStrNode *node;

    if (sz == ~(psSizeL_t)0)
    {
        sz = src ? strlen(src) : strlen(def);
    }
    if (sz2 == ~(psSizeL_t)0)
    {
        sz2 = src2 ? strlen(src2) : 0;
    }
    node = (struct psPrnfStrNode *)malloc(sizeof(struct psPrnfStrNode) + sz + sz2 + 1);
    if (node)
    {
        node->str = node->strstorage;
        node->str[sz + sz2] = 0;
        if (src)
        {
            memcpy(node->str, src, sz);
        }
        if (src2)
        {
            memcpy(node->str + sz, src2, sz2);
        }
        node->next = ctx->list;
        ctx->list = node;
        return node->str;
    }
    ctx->err = 1;
    return (char *)def;
}

char *psPrnfDupFree(psPrnf_t *ctx, char *src, psSizeL_t sz, const char *def)
{
    char *str = psPrnfDup(ctx, src, sz, def);
    free(src);
    return str;
}

char *psPrnfCopyDupFree(psPrnf_t *ctx, const char *src, psSizeL_t sz,
                        char *src2, psSizeL_t sz2, const char *def)
{
    char *str = psPrnfDup2(ctx, src, sz, src2, sz2, def);
    free(src2);
    return str;
}

void psPrnfFree(psPrnf_t *ctx)
{
    /* Note: You may uncomment printfs to debug this function. */
    /* printf("Scanning list (%p)\n", ctx->list); */
    while(ctx->list)
    {
        struct psPrnfStrNode *this_node = ctx->list;
        /* printf("Freeing: %p\n", (void *) this_node); */
        ctx->list = this_node->next;
        free(this_node);
    }
}

int psPrnf_(psPrnf_t *ctx, const char *fmt, ...)
{
    va_list ap;
    int res;
    va_start(ap, fmt);
    res = vprintf(fmt, ap);
    va_end(ap);
    psPrnfFree(ctx);
    return res;
}

int psSnprnf_(char *str, psSizeL_t size, psPrnf_t *ctx, const char *fmt, ...)
{
    va_list ap;
    int res;
    va_start(ap, fmt);
    res = vsnprintf(str, size, fmt, ap);
    va_end(ap);
    psPrnfFree(ctx);
    return res;
}

char *psAsprnf_(psPool_t *pool, psPrnf_t *ctx, const char *fmt, ...)
{
    char buf[1];
    char *newbuf = NULL;
    va_list ap;
    va_list ap2;
    int res;
    int res2 = -1;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    res = vsnprintf(buf, 1, fmt, ap);
    if (res >= 0 && res <= (int)PS_RES_SIZE_OK_MAX - 1)
    {
        newbuf = psMalloc(pool, (psSize_t) res + 1);
        if (newbuf)
        {
            res2 = vsnprintf(newbuf, res + 1, fmt, ap2);
        }
        if (res2 != res)
        {
            psFree(newbuf, pool);
            newbuf = NULL;
        }
    }
    va_end(ap);
    va_end(ap2);
    psPrnfFree(ctx);
    return newbuf;
}

const char *psPrnfBool(psBool_t b)
{
    static const char *tab[2] =
    {
        "false",
        "true"
    };
    /* In case b is not boolean, !! will force it on range 0-1. */
    return tab[!!(int)b];
}

const char *psPrnfStr(psPrnf_t *ctx, const char *str)
{
    if (str == NULL)
    {
        ctx->err = 1;
        return "[null]";
    }
    return psPrnfDup(ctx, str, strlen(str), "[STRING]");
}

const char *psPrnfSStr(psPrnf_t *ctx, const char *str, psSizeL_t len)
{
    char *ostr;
    const char *def = "[STRING]";
    if (str == NULL && len > 0)
    {
        ctx->err = 1;
        return "[null]";
    }
    if (len == ~(psSizeL_t)0)
    {
        len = strlen(str);
    }
    ostr = psPrnfDup(ctx, str, len, def);
    if (ostr != def)
    {
        psSizeL_t i;
        for(i = 0; i < len; i++)
        {
            int ch = (unsigned char) ostr[i];
            int dch = '.';
            int flag = (ch - 32) | (126 - ch); /* flag < 0 if ch outside ASCII. */
            flag >>= 9;
            ostr[i] = (char) ((flag & 255) & dch) | ((~flag & 255) & ch);
        }
    }
    return ostr;
}

const char *psPrnfQStr(psPrnf_t *ctx, const char *str)
{
    char *ostr;
    psSizeL_t len;
    const char *def = "[STRING]";
    if (str == NULL)
    {
        ctx->err = 1;
        return "[null]";
    }
    len = strlen(str);
    ostr = psPrnfDup(ctx, NULL, len * 4, def);
    if (str != def)
    {
        char *s = ostr;
        psSizeL_t i;
        for(i = 0; i < len; i++)
        {
            int ch = (unsigned char) str[i];
            if (ch < 32 || ch >= 127)
            {
                snprintf(s, 5, "\\x%02X", ch);
                s += 4;
            } else {
                *(s++) = (char) ch;
            }
        }
        *s = 0;
    }
    return ostr;
}

const char *psPrnfHex(psPrnf_t *ctx, const unsigned char *hex, psSizeL_t len)
{
    char *str;
    const char *def = "[HEX]";
    if (hex == NULL && len > 0)
    {
        ctx->err = 1;
        return "[null]";
    }
    /* Note: psPrnfDup() allocates always one extra byte for termination.*/
    str = psPrnfDup(ctx, NULL, len * 2, def);
    if (str != def)
    {
        psSizeL_t i;
        for(i = 0; i < len; i++)
        {
            unsigned char ch = hex[i];
            unsigned char a = (ch >> 4);
            unsigned char b = (ch & 15);
            unsigned char t;
            t = (a + 6) & 16;
            t = (t >> 1) - (t >> 4);
            a += '0' + t;
            t = (b + 6) & 16;
            t = (t >> 1) - (t >> 4);
            b += '0' + t;
            str[i * 2] = a;
            str[i * 2 + 1] = b;
        }
        str[i * 2] = 0; /* Terminating zero. */
    }
    return str;
}

const char *psPrnfHex2(psPrnf_t *ctx, const unsigned char *hex, psSizeL_t len)
{
    char *str;
    const char *def = "[HEX]";
    if (hex == NULL && len > 0)
    {
        ctx->err = 1;
        return "[null]";
    }

    /* Truncate: */
    while (len > 1 && hex[len - 1] == 0)
    {
        len--;
    }

    /* Note: psPrnfDup() allocates always one extra byte for termination.*/
    str = psPrnfDup(ctx, NULL, len * 2, def);
    if (str != def)
    {
        psSizeL_t i;
        for(i = 0; i < len; i++)
        {
            unsigned char ch = hex[len - i - 1];
            unsigned char a = (ch >> 4);
            unsigned char b = (ch & 15);
            unsigned char t;
            t = (a + 6) & 16;
            t = (t >> 1) - (t >> 4);
            a += '0' + t;
            t = (b + 6) & 16;
            t = (t >> 1) - (t >> 4);
            b += '0' + t;
            str[i * 2] = a;
            str[i * 2 + 1] = b;
        }
        str[i * 2] = 0; /* Terminating zero. */
    }
    return str;
}

const char *psPrnfIpv4(psPrnf_t *ctx, uint32_t ipv4_addr)
{
    union conv_ipv4
    {
        uint32_t ipv4_addr_net;
        unsigned char bytes[4];
    } conv;

    conv.ipv4_addr_net = ipv4_addr;

    return psPrnfDupf(ctx, "[IPV4]", "%d.%d.%d.%d",
                      conv.bytes[0], conv.bytes[1], conv.bytes[2], conv.bytes[3]);
}

const char *psPrnfBase64(psPrnf_t *ctx, const unsigned char *octets, psSizeL_t len,
                         int(*formatter)(const unsigned char *, size_t, const char *, char **))
{
    char *str = NULL; 
    int rv;

    /* Handle null pointer. */
    if (octets == NULL && len > 0)
    {
        return psPrnfStr(ctx, NULL);
    }
    
    rv = (formatter)(octets, len, NULL, &str);
    if (rv != 0)
    {
        str = NULL;
    }

    if (str == NULL)
    {
        return "[BASE64]";
    }
    return psPrnfDupFree(ctx, str, strlen(str) - 1, "[BASE64]");
}
