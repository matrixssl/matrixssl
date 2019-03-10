/**
 *      @file    coreApi.h
 *      @version $Format:%h%d$
 *
 *      Internal or extended definitions for Matrix core.
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

#ifndef _h_PS_COREAPIEXT
# define _h_PS_COREAPIEXT

# ifdef __cplusplus
extern "C" {
# endif

# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <coreConfig.h> /* Must be first included */
# else
#  include "coreConfig.h" /* Must be first included */
# endif
# include "osdep-types.h"
# include "list.h"
# include "psmalloc.h"

/******************************************************************************/
/*
    Statistics helpers
 */

/** Number of samples to store take for running average. */
# define STAT_AVG_SAMPLES    32

typedef struct
{
    uint32_t h;                         /**< High water */
    uint32_t a[STAT_AVG_SAMPLES];       /**< Values */
    uint32_t atot;                      /**< Running total of a[] values */
    uint16_t ai;                        /**< Most recent index into a[] */
    uint16_t an;                        /**< Current number of valid entries in a[] */
} psAvgStat_t;

static inline void STAT_INC_AVG(psAvgStat_t *s, uint32_t val)
{
    /* Update high water */
    if (val > s->h)
    {
        s->h = val;
    }
    if (s->an < STAT_AVG_SAMPLES)
    {
        /* Update total number of stats, if not at max */
        s->an++;
    }
    else
    {
        /* Subtract the oldest value from the running total, if we're replacing */
        s->atot -= s->a[s->ai];
    }
    /* Point to next entry, replace it and increment running total */
    s->ai = (s->ai + 1) % STAT_AVG_SAMPLES;
    s->a[s->ai] = val;
    s->atot += val;
}

static inline uint32_t STAT_AVG(psAvgStat_t *s)
{
    return s->atot / s->an;
}

static inline uint32_t STAT_HIGH(psAvgStat_t *s)
{
    return s->h;
}

/******************************************************************************/
/*
    Formatted printing.

    These functions implement printf-like formatting.
    Instead of the functions, please use e.g. Snprintf() for formatting
    basic data types. For formatting more complex inputs, use psPrnf().
    Note: On embedded platforms without standard formatting facilities,
    these functions can be used to implement Snprintf().
 */
#include "osdep_stdarg.h"
int psSbufprintf(psBuf_t *buf, const char *format, ...)
#ifdef __GNUC__
__attribute__((__format__(printf, 2, 3)))
#endif /* __GNUC__ */
;
int psSnprintf(char *str, size_t size, const char *format, ...)
#ifdef __GNUC__
__attribute__((__format__(printf, 3, 4)))
#endif /* __GNUC__ */
;
int psVsnprintf(char *str, size_t size, const char *format, va_list ap);

# ifdef __cplusplus
}
# endif

#endif /* _h_PS_COREAPIEXT */
/******************************************************************************/

