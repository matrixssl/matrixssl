/**
 *      @file    ps_ed25519.h
 *      @version $Format:%h%d$
 *
 *      Matrix Ed25519 interface.
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

#ifndef _h_PS_ED25519
#define _h_PS_ED25519

# include "coreApi.h" /* Must be included first */
# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <cryptoConfig.h>   /* Must be included second */
# else
#  include "../cryptoConfig.h"   /* Must be included second */
# endif
# include "osdep-types.h"

#ifdef USE_MATRIX_ED25519
int32_t psEd25519Sign(const unsigned char *msg,
        psSizeL_t msgLen,
        unsigned char *sigOut,
        psSizeL_t *sigOutLen,
        const unsigned char privKey[32],
        const unsigned char pubKey[32]);
int32_t psEd25519Verify(const unsigned char sig[64],
        const unsigned char *msg,
        psSizeL_t msgLen,
        const unsigned char pubKey[32]);
#endif /* USE_MATRIX_ED25519 */
#endif /* _h_PS_ED25519 */
