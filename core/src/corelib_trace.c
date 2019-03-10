/**
 *      @file    corelib_trace.c
 *      @version $Format:%h%d$
 *
 *      Tracing and error functions.
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

#include "osdep_stdio.h"
#include "coreApi.h"
#include "osdep.h"
#include "psUtil.h"


/******************************************************************************/
/*
    ERROR FUNCTIONS
    Tap into platform trace and break execution if DEBUG compile

    Modules should tie themselves to these low levels
    with compile-time defines
 */
void _psError(const char *msg)
{
    _psTrace(msg);
    _psTrace("\n");
#ifdef HALT_ON_PS_ERROR
    osdepBreak();
#endif
}
void _psErrorInt(const char *msg, int32 val)
{
    _psTraceInt(msg, val);
    _psTrace("\n");
#ifdef HALT_ON_PS_ERROR
    osdepBreak();
#endif
}
void _psErrorStr(const char *msg, const char *val)
{
    _psTraceStr(msg, val);
    _psTrace("\n");
#ifdef HALT_ON_PS_ERROR
    osdepBreak();
#endif
}

void psTraceBytes(const char *tag, const unsigned char *p, int l)
{
    char s[17];
    int i;

    s[16] = '\0';
    if (tag)
    {
        _psTraceStr("psTraceBytes(%s, ", tag);
        _psTraceInt("%d);", l);
    }
    else
    {
        _psTrace("\"");
    }
    for (i = 0; i < l; i++)
    {
        if (!(i & 0xF))
        {
            if (tag)
            {
                if (i != 0)
                {
                    psMem2Str(s, p - 16, 16);
                    _psTraceStr("  %s", s);
                }
#ifdef _LP64
                _psTraceInt("\n0x%08x:", (int64) p);
#else
                _psTraceInt("\n0x%04x:", (int32) p);
#endif
            }
            else
            {
                _psTrace("\"\n\"");
            }
        }
        if (tag)
        {
            _psTraceInt("%02x ", *p++);
        }
        else
        {
            _psTraceInt("\\x%02x", *p++);
        }
    }
    if (tag)
    {
        Memset(s, 0x0, 16);
        i = l & 0xF;
        psMem2Str(s, p - i, (unsigned int) i);
        for (; i < 16; i++)
        {
            _psTrace("   ");
        }
        _psTraceStr("  %s", s);
        _psTrace("\n");
    }
    else
    {
        _psTrace("\"\n");
    }
}
