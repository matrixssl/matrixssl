/**
 *      @file    matrixsslApiCipher.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains ciphersuite IDs.
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

#ifndef _h_MATRIXSSL_API_CIPHER
# define _h_MATRIXSSL_API_CIPHER

#if defined __APPLE__
#include <Security/CipherSuite.h>
#else
/* Cipher suite specification IDs, in numerical order. */
# define SSL_NULL_WITH_NULL_NULL                 0x0000
# define SSL_RSA_WITH_NULL_MD5                   0x0001
# define SSL_RSA_WITH_NULL_SHA                   0x0002
# define SSL_RSA_WITH_RC4_128_MD5                0x0004
# define SSL_RSA_WITH_RC4_128_SHA                0x0005
# define TLS_RSA_WITH_IDEA_CBC_SHA               0x0007
# define SSL_RSA_WITH_3DES_EDE_CBC_SHA           0x000A /* 10 */
# define SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA       0x0016 /* 22 */
# define SSL_DH_anon_WITH_RC4_128_MD5            0x0018 /* 24 */
# define SSL_DH_anon_WITH_3DES_EDE_CBC_SHA       0x001B /* 27 */
# define TLS_RSA_WITH_AES_128_CBC_SHA            0x002F /* 47 */
# define TLS_DHE_RSA_WITH_AES_128_CBC_SHA        0x0033 /* 51 */
# define TLS_DH_anon_WITH_AES_128_CBC_SHA        0x0034 /* 52 */
# define TLS_RSA_WITH_AES_256_CBC_SHA            0x0035 /* 53 */
# define TLS_DHE_RSA_WITH_AES_256_CBC_SHA        0x0039 /* 57 */
# define TLS_DH_anon_WITH_AES_256_CBC_SHA        0x003A /* 58 */
# define TLS_RSA_WITH_AES_128_CBC_SHA256         0x003C /* 60 */
# define TLS_RSA_WITH_AES_256_CBC_SHA256         0x003D /* 61 */
# define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256     0x0067 /* 103 */
# define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256     0x006B /* 107 */
# define TLS_RSA_WITH_SEED_CBC_SHA               0x0096 /* 150 */
# define TLS_PSK_WITH_AES_128_CBC_SHA            0x008C /* 140 */
# define TLS_PSK_WITH_AES_128_CBC_SHA256         0x00AE /* 174 */
# define TLS_PSK_WITH_AES_256_CBC_SHA384         0x00AF /* 175 */
# define TLS_PSK_WITH_AES_256_CBC_SHA            0x008D /* 141 */
# define TLS_DHE_PSK_WITH_AES_128_CBC_SHA        0x0090 /* 144 */
# define TLS_DHE_PSK_WITH_AES_256_CBC_SHA        0x0091 /* 145 */
# define TLS_RSA_WITH_AES_128_GCM_SHA256         0x009C /* 156 */
# define TLS_RSA_WITH_AES_256_GCM_SHA384         0x009D /* 157 */
# define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     0x009F /* 159 */
#endif // __APPLE__

# define TLS_EMPTY_RENEGOTIATION_INFO_SCSV       0x00FF /**< @see RFC 5746 */
# define TLS_FALLBACK_SCSV                       0x5600 /**< @see RFC 7507 */

# define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA     0xC004 /* 49156 */
# define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA     0xC005 /* 49157 */
# define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    0xC009 /* 49161 */
# define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    0xC00A /* 49162 */
# define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     0xC012 /* 49170 */
# define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      0xC013 /* 49171 */
# define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      0xC014 /* 49172 */
# define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA       0xC00E /* 49166 */
# define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA       0xC00F /* 49167 */
# define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC023 /* 49187 */
# define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xC024 /* 49188 */
# define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  0xC025 /* 49189 */
# define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  0xC026 /* 49190 */
# define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   0xC027 /* 49191 */
# define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   0xC028 /* 49192 */
# define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256    0xC029 /* 49193 */
# define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384    0xC02A /* 49194 */
# define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B /* 49195 */
# define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C /* 49196 */
# define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256  0xC02D /* 49197 */
# define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384  0xC02E /* 49198 */
# define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F /* 49199 */
# define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xC030 /* 49200 */
# define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256    0xC031 /* 49201 */
# define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384    0xC032 /* 49202 */
/* Defined in https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305 */
#  define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xCCA8 /* 52392 */
#  define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA9 /* 52393 */
/* TLS 1.3 ciphersuites. */
#  define TLS_AES_128_GCM_SHA256                 0x1301 /* 4865 */
#  define TLS_AES_256_GCM_SHA384                 0x1302 /* 4866 */
#  define TLS_CHACHA20_POLY1305_SHA256           0x1303 /* 4867 */
#  define TLS_AES_128_CCM_SHA_256                0x1304 /* 4868 */
#  define TLS_AES_128_CCM_8_SHA256               0x1305 /* 4869 */

#endif
