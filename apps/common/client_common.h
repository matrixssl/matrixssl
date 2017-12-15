/**
 *      @file    client_common.h
 *      @version $Format:%h%d$
 *
 *      MatrixSSL client common code.
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

#ifndef _h_CLIENT_COMMON
#define _h_CLIENT_COMMON

#include <string.h>
#include <ctype.h>
#include "matrixssl/matrixsslApi.h"

#include "core/coreApi.h"
#include "core/psUtil.h"

/*
    If supporting client authentication, pick ONE identity to auto select a
    certificate and private key that support desired algorithms.
 */
/* #define ID_RSA */ /* RSA Certificate and Key */
/* #define ID_ECDH_ECDSA */ /* EC Certificate and Key */
/* #define ID_ECDH_RSA */ /* EC Key with RSA signed certificate */

#if !defined(ID_RSA) && !defined(ID_ECDH_ECDSA) && !defined(ID_ECDH_RSA)
/* Choose a default identity based on which algorithms are supported. */
# ifdef USE_RSA_CIPHER_SUITE
#  define ID_RSA
# else
#  ifdef USE_ECC_CIPHER_SUITE
#   define ID_ECDH_ECDSA
#  else
#   ifndef USE_PSK_CIPHER_SUITE
#    error "Please enable either RSA or ECC for client when not using PSK"
#   endif /* !USE_PSK_CIPHER_SUITE */
#  endif  /* USE_ECC_CIPHER_SUITE */
# endif   /* USE_RSA_CIPHER_SUITE */
#endif    /* !ID_RSA && !ID_ECDH_ECDSA && !ID_ECDH_RSA */

#define USE_HEADER_KEYS

/* clientconfig.c
   Client configuration, changeable through command line arguments
 */
typedef int32 (*load_key_func)(sslKeys_t *);

typedef struct {

    /* Path to CA */
    const char *ca_file;
    const char *default_ca_file;

    /* Path to client certificate and matching private key */
    const char *cert_file;
    const char *privkey_file;

    int loadKeysFromMemory;

    /* Function for loading the client certificate key material, must be != NULL */
    load_key_func load_key;
} clientconfig_t;

extern clientconfig_t g_clientconfig;

void clientconfigInitialize();
void clientconfigFree();
void clientconfigUseFileKeys();
const char *clientconfigGetTrustedCA();
int32 clientconfigLoadKeys(sslKeys_t *keys);

/* load_keys.c
 */
void buildTrustedCABuf(unsigned char **CAstreamOut, int32 *CAstreamLenOut);
void buildCAStringFromFiles(const char **CAfileOut);

/* Example keys */
int32 loadRsaExampleKeys(sslKeys_t *keys);
int32 loadECDHRsaExampleKeys(sslKeys_t *keys);
int32 loadECDH_ECDSAExampleKeys(sslKeys_t *keys);
int32 loadExamplePreSharedKeys(sslKeys_t *keys);

int32 loadPreSharedKeys(sslKeys_t *keys);
int32 loadKeysFromFile(sslKeys_t *keys);
int32 loadRsaKeysFromFile(sslKeys_t *keys);
int32 loadECDHRsaKeysFromFile(sslKeys_t *keys);
int32 loadECDH_ECDSAKeysFromFile(sslKeys_t *keys);

/* client_common.c
 */
extern int g_enable_ext_cv_sig_op;
extern int g_key_len;

int appendCACert(unsigned char *buf, const size_t bufsize, size_t *bufused,
                 const unsigned char *data, const size_t datasize);
int appendCAFilename(char *strbuf, const size_t strbufsize, const char *str);
void chdirToAppsSSL();

#endif /* _h_CLIENT_COMMON */
