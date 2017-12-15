/**
 *      @file    cryptoCheck.h
 *      @version $Format:%h%d$
 *
 *      Configuration validation/sanity checks.
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

#ifndef _h_PS_CRYPTOCHECK
# define _h_PS_CRYPTOCHECK

/******************************************************************************/
/*
 */
# ifdef USE_CERT_PARSE
#  ifndef USE_X509
#   error "Must enable USE_X509 if USE_CERT_PARSE is enabled"
#  endif
#  if !defined(USE_MD5) && !defined(USE_SHA1) && !defined(USE_SHA256)
#   error "At least one of USE_MD5, USE_SHA1 or USE_SHA256 must be enabled for USE_CERT_PARSE"
#  endif
# endif

# ifdef USE_PBKDF1
#  ifndef USE_PKCS5
#   error "Enable USE_PKCS5 in cryptoConfig.h for PKBDF1 support"
#  endif
# endif

# ifdef USE_PKCS5
#  ifdef USE_PBKDF1
#   ifndef USE_MD5
#    error "Enable USE_MD5 in cryptoConfig.h for PBKDF1 support"
#   endif
#  endif
#  ifndef USE_3DES
#   error "Enable USE_3DES in cryptoConfig.h for PKCS5 support"
#  endif
#  ifndef USE_AES
#   error "Enable USE_AES in cryptoConfig.h for PKCS5 support"
#  endif
# endif

# ifdef USE_PKCS8
#  ifndef USE_HMAC_SHA1
#   error "Enable USE_HMAC_SHA1 in cryptoConfig.h for PKCS8 support"
#  endif
# endif

#  define USE_NATIVE_ECC
#  define USE_NATIVE_AES
#  define USE_NATIVE_HASH

# ifdef USE_PKCS12
#  ifndef USE_PKCS8
#   error "Enable USE_PKCS8 in cryptoConfig.h for PKCS12 support"
#  endif
# else
#  ifdef USE_RC2
#   error "RC2 only allowed for PKCS12 support"
#  endif
# endif

# ifdef USE_CERT_PARSE
#  ifndef USE_X509
#   error "USE_X509 required for USE_CERT_PARSE"
#  endif
# endif

# ifdef USE_FULL_CERT_PARSE
#  ifndef USE_CERT_PARSE
#   error "USE_CERT_PARSE required for USE_FULL_CERT_PARSE"
#  endif
# endif

# ifdef ENABLE_CA_CERT_HASH
#  if !defined(USE_SHA1) || !defined(USE_X509)
#   error "USE_SHA1 and USE_X509 required for ENABLE_CA_CERT_HASH"
#  endif
# endif

# ifdef USE_OCSP_RESPONSE
#  ifndef USE_SHA1
#   error "Enable USE_SHA1 in cryptoConfig.h for OCSP support"
#  endif
# endif

# ifdef USE_OCSP_REQUEST
#  ifndef USE_SHA1
#   error "Enable USE_SHA1 in cryptoConfig.h for OCSP support"
#  endif
#   error "Enable USE_CERT_GEN in cryptoConfig.h for USE_OCSP_REQUEST"
# endif

#endif  /* _h_PS_CRYPTOCHECK */

/******************************************************************************/

