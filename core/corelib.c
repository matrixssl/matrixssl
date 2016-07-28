/**
 *	@file    corelib.c
 *	@version $Format:%h%d$
 *
 *	Open and Close APIs and utilities for Matrix core library.
 */
/*
 *	Copyright (c) 2013-2016 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software
 *	into proprietary programs.  If you are unable to comply with the GPL, a
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/
 *
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *	See the GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "coreApi.h"

/******************************************************************************/
/*
	Open (initialize) the Core module
	The config param should always be passed as:
		PSCORE_CONFIG
*/
static char g_config[32] = "N";

/******************************************************************************/
int32 psCoreOpen(const char *config)
{
	if (*g_config == 'Y') {
		return PS_CORE_IS_OPEN;
	}
	strncpy(g_config, PSCORE_CONFIG, sizeof(g_config) - 1);
	if (strncmp(g_config, config, strlen(PSCORE_CONFIG)) != 0) {
		psErrorStr( "Core config mismatch.\n" \
			"Library: " PSCORE_CONFIG\
			"\nCurrent: %s\n", config);
		return -1;
	}

	if (osdepTimeOpen() < 0) {
		psTraceCore("osdepTimeOpen failed\n");
		return PS_FAILURE;
	}
	if (osdepEntropyOpen() < 0) {
		psTraceCore("osdepEntropyOpen failed\n");
		osdepTimeClose();
		return PS_FAILURE;
	}

#ifdef USE_MULTITHREADING
	if (osdepMutexOpen() < 0) {
		psTraceCore("osdepMutexOpen failed\n");
		osdepEntropyClose();
		osdepTimeClose();
		return PS_FAILURE;
	}
#endif /* USE_MULTITHREADING */

	return PS_SUCCESS;
}

/******************************************************************************/
void psCoreClose(void)
{
	if (*g_config == 'Y') {
		*g_config = 'N';

#ifdef USE_MULTITHREADING
		osdepMutexClose();
#endif /* USE_MULTITHREADING */

		osdepEntropyClose();

		osdepTimeClose();
	}
}

/******************************************************************************/
/**
	Constant time memory comparison - like memcmp but w/o data dependent branch.
	@security SECURITY - Should be used when comparing values that use or have
	been derived or have been decrypted/encrypted/signed from secret information.

	@param[in] s1 Pointer to first buffer to compare
	@param[in] s2 Pointer to first buffer to compare
	@param[in] len number of bytes to compare in s1 and s2
	@return 0 on successful match, nonzero on failure.
*/
int32 memcmpct(const void *s1, const void *s2, size_t len)
{
	int		xor = 0;

	while(len > 0) {
		len--;
		xor |= ((unsigned char *)s1)[len] ^ ((unsigned char *)s2)[len];
	}
	return xor;
}

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

/*
	copy 'len' bytes from 'b' to 's', converting all to printable characters
*/
static void mem2str(char *s, const unsigned char *b, uint32 len)
{
	for (; len > 0; len--) {
		if (*b > 31 && *b < 127) {
			*s = *b;
		} else {
			*s = '.';
		}
		b++;
		s++;
	}
}

void psTraceBytes(const char *tag, const unsigned char *p, int l)
{
	char	s[17];
	int		i;

	s[16] = '\0';
	if (tag) {
		_psTraceStr("psTraceBytes(%s, ", tag);
		_psTraceInt("%d);", l);
	} else {
		_psTrace("\"");
	}
	for (i = 0; i < l; i++) {
		if (!(i & 0xF)) {
			if (tag) {
				if (i != 0) {
					mem2str(s, p - 16, 16);
					_psTraceStr("  %s", s);
				}
#ifdef _LP64
				_psTraceInt("\n0x%08x:", (int64)p);
#else
				_psTraceInt("\n0x%04x:", (int32)p);
#endif
			} else {
				_psTrace("\"\n\"");
			}
		}
		if (tag) {
			_psTraceInt("%02x ", *p++);
		} else {
			_psTraceInt("\\x%02x", *p++);
		}
	}
	if (tag) {
		memset(s, 0x0, 16);
		i = l & 0xF;
		mem2str(s, p - i, (unsigned int)i);
		for (;i < 16; i++) {
			_psTrace("   ");
		}
		_psTraceStr("  %s", s);
		_psTrace("\n");
	} else {
		_psTrace("\"\n");
	}
}

/******************************************************************************/
/*
	Creates a simple linked list from a given stream and separator char

	Memory info:
	Callers do not have to free 'items' on function failure.
*/
int32 psParseList(psPool_t *pool, char *list, const char separator,
		psList_t **items)
{
	psList_t	*litems, *start, *prev;
	uint32		itemLen, listLen;
	char		*tmp;

	*items = NULL;
	prev = NULL;

	listLen = (int32)strlen(list) + 1;
	if (listLen == 1) {
		return PS_ARG_FAIL;
	}
	start = litems = psMalloc(pool, sizeof(psList_t));
	if (litems == NULL) {
		return PS_MEM_FAIL;
	}
	memset(litems, 0, sizeof(psList_t));

	while (listLen > 0) {
		itemLen = 0;
		tmp = list;
		if (litems == NULL) {
			litems = psMalloc(pool, sizeof(psList_t));
			if (litems == NULL) {
				psFreeList(start, pool);
				return PS_MEM_FAIL;
			}
			memset(litems, 0, sizeof(psList_t));
			prev->next = litems;

		}
		while (*list != separator && *list != '\0') {
			itemLen++;
			listLen--;
			list++;
		}
		litems->item = psMalloc(pool, itemLen + 1);
		if (litems->item == NULL) {
			psFreeList(start, pool);
			return PS_MEM_FAIL;
		}
		litems->len = itemLen;
		memset(litems->item, 0x0, itemLen + 1);
		memcpy(litems->item, tmp, itemLen);
		list++;
		listLen--;
		prev = litems;
		litems = litems->next;
	}
	*items = start;
	return PS_SUCCESS;
}

void psFreeList(psList_t *list, psPool_t *pool)
{
	psList_t	*next, *current;

	if (list == NULL) {
		return;
	}
	current = list;
	while (current) {
		next = current->next;
		if (current->item) {
			psFree(current->item, pool);
		}
		psFree(current, pool);
		current = next;
	}
}

/******************************************************************************/
/*
	Clear the stack deeper than the caller to erase any potential secrets
	or keys.
*/
void psBurnStack(uint32 len)
{
	unsigned char buf[32];

	memset_s(buf, sizeof(buf), 0x0, sizeof(buf));
	if (len > (uint32)sizeof(buf)) {
		psBurnStack(len - sizeof(buf));
	}
}

/******************************************************************************/
/*
	Support for memory allocation in order to avoid applications that redefine
	malloc/free (see Perl)
*/
void *psMallocNative(size_t size)
{
	return malloc(size);
}

void psFreeNative(void *ptr)
{
	free(ptr);
}
