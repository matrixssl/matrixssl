/**
 *      @file    clientconfig.c
 *      @version $Format:%h%d$
 *
 *      MatrixSSL client configuration code.
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
#include "client_common.h"

/* Identity Certs and Keys for use with Client Authentication */
#ifdef ID_RSA
#define EXAMPLE_RSA_KEYS
#define EXAMPLE_FILE_KEYS
static const char rsaCertFile[] = "../../testkeys/RSA/2048_RSA.pem";
static const char rsaPrivkeyFile[] = "../../testkeys/RSA/2048_RSA_KEY.pem";
#endif

#ifdef ID_ECDH_ECDSA
#define EXAMPLE_EC_KEYS
#define EXAMPLE_FILE_KEYS
static const char ecCertFile[] = "../../testkeys/EC/384_EC.pem";
static const char ecPrivkeyFile[] = "../../testkeys/EC/384_EC_KEY.pem";
#endif

#ifdef ID_ECDH_RSA
#define EXAMPLE_ECDH_RSA_KEYS
#define EXAMPLE_FILE_KEYS
static const char ecdhRsaCertFile[] = "../../testkeys/ECDH_RSA/521_ECDH-RSA.pem";
static const char ecdhRsaPrivkeyFile[] = "../../testkeys/ECDH_RSA/521_ECDH-RSA_KEY.pem";
#endif

clientconfig_t g_clientconfig;

#ifdef EXAMPLE_FILE_KEYS
/* Attempts to find the correct path for the example files
   If unable to find it, assume it is correct, and fail later.
 */
static const char* example_file_path(const char* filepath)
{
    const char* ret_filepath = filepath;
    unsigned char *tmp_buf;
    int32 tmp_buf_len;
    int32 rc;

    rc = psGetFileBuf(NULL, filepath, &tmp_buf, &tmp_buf_len);
    psFree(tmp_buf, NULL);
    tmp_buf = NULL;

    if (rc != PS_SUCCESS)
    {
        /* Try filepath by stripping any ../ in the path
         */
        size_t ignore_bytes = strspn(filepath, "./");

        if (ignore_bytes > 0) {
            rc = psGetFileBuf(NULL, filepath + ignore_bytes, &tmp_buf, &tmp_buf_len);
            psFree(tmp_buf, NULL);
            tmp_buf = NULL;

            if (rc == PS_SUCCESS) {
                ret_filepath = filepath + ignore_bytes;
            }
        }
    }

    return ret_filepath;
}
#endif /* EXAMPLE_FILE_KEYS */

void clientconfigInitialize()
{
    g_clientconfig.ca_file = NULL;
    g_clientconfig.default_ca_file = NULL;
    g_clientconfig.cert_file = NULL;
    g_clientconfig.privkey_file = NULL;
    g_clientconfig.load_key = &loadKeysFromFile;
    g_clientconfig.loadKeysFromMemory = 0;

# ifdef EXAMPLE_RSA_KEYS
    g_clientconfig.cert_file = example_file_path(rsaCertFile);
    g_clientconfig.privkey_file = example_file_path(rsaPrivkeyFile);
    g_clientconfig.load_key = &loadRsaKeysFromFile;
    g_clientconfig.loadKeysFromMemory = 0;
# elif defined(EXAMPLE_EC_KEYS)
    g_clientconfig.cert_file = example_file_path(ecCertFile);
    g_clientconfig.privkey_file = example_file_path(ecPrivkeyFile);
    g_clientconfig.load_key = &loadECDH_ECDSAKeysFromFile;
    g_clientconfig.loadKeysFromMemory = 0;
# elif defined(EXAMPLE_ECDH_RSA_KEYS)
    g_clientconfig.cert_file = example_file_path(ecdhRsaCertFile);
    g_clientconfig.privkey_file = example_file_path(ecdhRsaPrivkeyFile);
    g_clientconfig.load_key = &loadECDHRsaKeysFromFile;
    g_clientconfig.loadKeysFromMemory = 0;
# elif defined(USE_PSK_CIPHER_SUITE)
    g_clientconfig.load_key = &loadPreSharedKeys;
    g_clientconfig.loadKeysFromMemory = 1;
# endif

# ifdef USE_HEADER_KEYS
    g_clientconfig.cert_file = NULL;
    g_clientconfig.privkey_file = NULL;
#  if defined(ID_RSA)
    g_clientconfig.load_key = &loadRsaExampleKeys;
#  elif defined(ID_ECDH_RSA)
    g_clientconfig.load_key = &loadECDHRsaExampleKeys;
#  elif defined(ID_ECDH_ECDSA)
    g_clientconfig.load_key = &loadECDH_ECDSAExampleKeys;
#  elif defined(USE_PSK_CIPHER_SUITE)
    g_clientconfig.load_key = &loadPreSharedKeys;
#  endif
    g_clientconfig.loadKeysFromMemory = 1;
# endif /* USE_HEADER_KEYS */

    buildCAStringFromFiles(&g_clientconfig.default_ca_file);
}

void clientconfigFree()
{
    psFree((char*)g_clientconfig.default_ca_file, NULL);
    g_clientconfig.default_ca_file = NULL;
}

void clientconfigUseFileKeys()
{
    /* Do not overwrite load_key if not loaded from memory */
    if (g_clientconfig.loadKeysFromMemory) {
        g_clientconfig.loadKeysFromMemory = 0;
        g_clientconfig.load_key = &loadKeysFromFile;
    }
}

const char *clientconfigGetTrustedCA()
{
    if (g_clientconfig.ca_file) {
        return g_clientconfig.ca_file;
    }

    return g_clientconfig.default_ca_file;
}

int32 clientconfigLoadKeys(sslKeys_t *keys)
{
    int32 rc;

#ifdef USE_ONLY_PSK_CIPHER_SUITE
    /* Override load_key if USE_ONLY_PSK_CIPHER_SUITE is specified
     */
    g_clientconfig.load_key = &loadPreSharedKeys;
    g_clientconfig.loadKeysFromMemory = 1;
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

    rc = g_clientconfig.load_key(keys);

    if (rc < 0)
    {
        return 0;
    }

#ifdef USE_PSK_CIPHER_SUITE
    /* Additionally always load PSK keys unless they are already loaded
     */
    if (g_clientconfig.load_key != &loadPreSharedKeys &&
        g_clientconfig.load_key != &loadExamplePreSharedKeys)
    {
        rc = loadPreSharedKeys(keys);

        if (rc < 0)
        {
            return 0;
        }
    }
#endif

    return 1;
}
