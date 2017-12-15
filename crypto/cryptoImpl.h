/**
 *      @file    cryptoImpl.h
 *      @version $Format:%h%d$
 *
 *      Include common include files for compiling part of MatrixSSL's crypto.
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

#ifndef _h_PS_CRYPTOIMPL
# define _h_PS_CRYPTOIMPL

# define PS_CRYPTO_IMPLEMENTATION 1
# ifndef PS_LOGF_WITH_PRNF
#  include "cryptoApi.h"
#  include "../core/osdep.h"
#  include "../core/psUtil.h"
# else
/* Note: The inclusion order of headers is very important when
   PS_LOGF_WITH_PRNF is defined. */
#  include "../core/coreApi.h"
#  include "../core/osdep.h"
#  include "../core/psPrnf.h"
#  include "../core/psLog.h"
#  include "cryptoApi.h"
#  include "cryptolib.h"
# endif

#endif /* _h_PS_CRYPTOIMPL */
