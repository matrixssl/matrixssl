/**
 *      @file    http.c
 *      @version $Format:%h%d$
 *
 *      Simple INCOMPLETE HTTP parser for example applications.
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

#include "app.h"
/* Currently this example uses _psTrace for tracing, so osdep.h is needed: */
#include "core/osdep.h"
#include "core/psUtil.h"

/* #define TEST */

/******************************************************************************/
/*
    EXAMPLE ONLY - SHOULD NOT BE USED FOR PRODUCTION CODE

    Process an HTTP request from a client.
    Very simple - we just print it, and return success.
    No HTTP validation at all is done on the data.
 */
int32 httpBasicParse(httpConn_t *cp, unsigned char *buf, uint32 len,
    int32 trace)
{
    unsigned char *c, *end, *tmp;
    int32 l;

    /*
        SSL/TLS can provide zero length records, which we just ignore here
        because the code below assumes we have at least one byte
     */
    if (len == 0)
    {
        return HTTPS_PARTIAL;
    }

    c = buf;
    end = c + len;
/*
    If we have an existing partial HTTP buffer, append to it the data in buf
    up to the first newline, or 'len' data, if no newline is in buf.
 */
    if (cp->parsebuf != NULL)
    {
        for (tmp = c; c < end && *c != '\n'; c++)
        {
            ;
        }
        /* We want c to point to 'end' or to the byte after \r\n */
        if (*c == '\n')
        {
            c++;
        }
        l = (int32) (c - tmp);
        if (l > HTTPS_BUFFER_MAX)
        {
            return HTTPS_ERROR;
        }
        cp->parsebuf = realloc(cp->parsebuf, l + cp->parsebuflen);
        memcpy(cp->parsebuf + cp->parsebuflen, tmp, l);
        cp->parsebuflen += l;
        /* Parse the data out of the saved buffer first */
        c = cp->parsebuf;
        end = c + cp->parsebuflen;
        /* We've "moved" some data from buf into parsebuf, so account for it */
        buf += l;
        len -= l;
    }

L_PARSE_LINE:
    for (tmp = c; c < end && *c != '\n'; c++)
    {
        ;
    }
    if (c < end)
    {
        if (*(c - 1) != '\r')
        {
            return HTTPS_ERROR;
        }
        /* If the \r\n started the line, we're done reading headers */
        if (*tmp == '\r' && (tmp + 1 == c))
        {
/*
            if ((c + 1) != end) {
                _psTrace("HTTP data parsing not supported, ignoring.\n");
            }
 */
            if (cp->parsebuf != NULL)
            {
                free(cp->parsebuf); cp->parsebuf = NULL;
                cp->parsebuflen = 0;
                if (len != 0)
                {
                    _psTrace("HTTP data parsing not supported, ignoring.\n");
                }
            }
            if (trace)
            {
                _psTrace("RECV COMPLETE HTTP MESSAGE\n");
            }
            return HTTPS_COMPLETE;
        }
    }
    else
    {
        /* If parsebuf is non-null, we have already saved it */
        if (cp->parsebuf == NULL && (l = (int32) (end - tmp)) > 0)
        {
            cp->parsebuflen = l;
            cp->parsebuf = malloc(cp->parsebuflen);
            psAssert(cp->parsebuf != NULL);
            memcpy(cp->parsebuf, tmp, cp->parsebuflen);
        }
        return HTTPS_PARTIAL;
    }
    *(c - 1) = '\0';    /* Replace \r with \0 just for printing */
    if (trace)
    {
        _psTraceStr("RECV PARSED: [%s]\n", (char *) tmp);
    }
    /* Finished parsing the saved buffer, now start parsing from incoming buf */
    if (cp->parsebuf != NULL)
    {
        free(cp->parsebuf); cp->parsebuf = NULL;
        cp->parsebuflen = 0;
        c = buf;
        end = c + len;
    }
    else
    {
        c++;    /* point c to the next char after \r\n */
    }
    goto L_PARSE_LINE;

    return HTTPS_ERROR;
}

/******************************************************************************/
