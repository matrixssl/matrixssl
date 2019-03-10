/* cfg_pkcslib.h
 *
 * Description: PKCS library distribution constants
 */

/*****************************************************************************
* Copyright (c) 2007-2017 INSIDE Secure Oy. All Rights Reserved.
*
* The latest version of this code is available at http://www.matrixssl.org
*
* This software is open source; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This General Public License does NOT permit incorporating this software
* into proprietary programs.  If you are unable to comply with the GPL, a
* commercial license for this software may be purchased from INSIDE at
* http://www.insidesecure.com/
*
* This program is distributed in WITHOUT ANY WARRANTY; without even the
* implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef CFG_PKCSLIB_H
#define CFG_PKCSLIB_H

/* This configure must be enabled to use MD5 digests.
   The MD5 digests have been demonstrated to be insecure and therefore
   they are not recommended. Support for MD5 digests can
   be disabled by this switch if needed. */
#define SFZCLDIST_CRYPT_MD5

/* Uncomment if making freestanding build. */
/* Freestanding build will work on bare operating systems without
   basic ISO C90/C99/C11 time, string, I/O and dynamic memory management
   libraries. */
/* #define SFZCLDIST_FREESTANDING */

/* Provide SIZEOF_LONG to sfzclmp. */
#ifndef SIZEOF_LONG
# ifdef __LP64__
#  define SIZEOF_LONG 8
# else
#  define SIZEOF_LONG 4
# endif
#endif

/* ---- Predefined options ---- */

/* The library is designed for this option combination and
   altering these options means the build procedure and tests need
   to be tweaked to adjust. */

/* Cryptographic options. */
#define WITH_RSA
#define SFZCLDIST_CERT
#define SFZCLDIST_CRYPT_DL
#define SFZCLDIST_CRYPTO_HASH
#define SFZCLDIST_CRYPT_SHA
#define SFZCLDIST_CRYPT_DSA
#define SFZCLDIST_CRYPTO_PK
#define SFZCLDIST_CRYPTO
#define SFZCLDIST_CRYPT
#define SFZCLDIST_CRYPT_DES
#define SFZCLDIST_CRYPT_SHA256

#endif /* CFG_PKCSLIB_H */

/* end of file cfg_pkcslib.h */
