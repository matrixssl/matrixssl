/**
 *      @file    ps_chacha20poly1305ietf.h
 *      @version $Format:%h%d$
 *
 *      Header for MatrixSSL Chacha20-poly1305 (IETF) interface.
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

#ifndef _h_PS_CHACHA20_POLY1305IETF
# define _h_PS_CHACHA20_POLY1305IETF

# include "cryptoApi.h"

/******************************************************************************/

/** Keylength of CHACHA20-POLY1305 IETF cipher. */
#define PS_CHACHA20POLY1305_IETF_KEYBYTES 32U

/** IV length of CHACHA20-POLY1305 IETF cipher. */
#define PS_CHACHA20POLY1305_IETF_NPUBBYTES 12U

/** Tag length of CHACHA20-POLY1305 IETF cipher. */
#define PS_CHACHA20POLY1305_IETF_ABYTES 16U

# ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
#  ifndef PS_CHACHA20POLY1305IETF_DEFINED
typedef struct
{
    unsigned char key[PS_CHACHA20POLY1305_IETF_KEYBYTES];
} psChacha20Poly1305Ietf_t;
#  define PS_CHACHA20POLY1305IETF_DEFINED 1
#  endif /* PS_CHACHA20POLY1305IETF_DEFINED */
# endif /* USE_MATRIX_CHACHA20_POLY1305_IETF */

/******************************************************************************/

#endif /* _h_PS_CHACHA20_POLY1305IETF */

