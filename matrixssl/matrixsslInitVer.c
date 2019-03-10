/**
 *      @file    matrixsslInitVer.c
 *      @version $Format:%h%d$
 *
 *      Functions for initialization protocol versions in a session.
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

#include "matrixsslImpl.h"

int32 initSupportedVersions(ssl_t *ssl, sslSessOpts_t *options);
extern int32 getClientDefaultVersions(ssl_t *ssl);
extern int32 getServerDefaultVersions(ssl_t *ssl);
extern int32 getDefaultVersions(ssl_t *ssl);

psBool_t matrixSslTlsVersionRangeSupported(psProtocolVersion_t low,
        psProtocolVersion_t high)
{
    if (low > high)
    {
        psTraceInfo("Invalid version range: low > high\n");
        return PS_FALSE;
    }

    if (!COMPILED_IN_VER(low) || !COMPILED_IN_VER(high))
    {
        return PS_FALSE;
    }

    low <<= 1;
    while (low < high)
    {
        if (!COMPILED_IN_VER(low))
        {
            return PS_FALSE;
        }
        low <<= 1;
    }
    return PS_TRUE;
}

#ifdef USE_CLIENT_SIDE_SSL
int32_t
matrixSslSessOptsSetClientTlsVersionRange(sslSessOpts_t *options,
        psProtocolVersion_t low,
        psProtocolVersion_t high)
{
    psProtocolVersion_t versions[TLS_MAX_SUPPORTED_VERSIONS] = {0};
    uint8_t numVersions = 0;
    uint32_t i;

    if (low > high)
    {
        return PS_ARG_FAIL;
    }

    /* Copy the range to array for SetClientTlsVersions */
    i = 0;
    do
    {
        if (COMPILED_IN_VER(high))
        {
            versions[i] = high;
        }
        numVersions++;
        i++;
        high >>= 1;
    } while (high >= low);

    return matrixSslSessOptsSetClientTlsVersions(options,
            versions,
            numVersions);
}

PSPUBLIC int32_t
matrixSslSessOptsSetClientTlsVersions(sslSessOpts_t *options,
        const psProtocolVersion_t versions[],
        int32_t versionsLen)
{
    uint8_t i, k;
    psProtocolVersion_t highestVersion = 0;
# ifdef USE_TLS_1_3
    psBool_t haveTls13Draft28 = PS_FALSE;
# endif

    if (options == NULL)
    {
        return PS_ARG_FAIL;
    }
    if (versionsLen == 0)
    {
        psTraceErrr("Please enable at least one version.\n");
        return PS_ARG_FAIL;
    }
    if (versionsLen > TLS_MAX_SUPPORTED_VERSIONS)
    {
        psTraceErrr("Too many supported versions. Increase " \
                    "TLS_MAX_SUPPORTED_VERSIONS.\n");
        return PS_ARG_FAIL;
    }
# ifdef USE_TLS_1_3
    for (i = 0; i < versionsLen; i++)
    {
        if (versions[i] == v_tls_1_3_draft_28)
        {
            haveTls13Draft28 = PS_TRUE;
        }
    }
# endif

    options->supportedVersionsLen = 0;
    for (i = 0, k = 0; i < versionsLen; i++)
    {
        if (!matrixSslTlsVersionRangeSupported(versions[i], versions[i]))
        {
            psTraceErrr("Unsupported version. Please enable more " \
                        "versions in matrixsslConfig.h.\n");
            return PS_ARG_FAIL;
        }
        options->supportedVersions[k++] = versions[i];
        options->supportedVersionsLen++;
        if (versions[i] > highestVersion)
        {
            highestVersion = versions[i];
        }
# ifdef USE_TLS_1_3
        if (versions[i] == v_tls_1_3 && !haveTls13Draft28)
        {
            /* Very little support in the wild for TLS 1.3 RFC version,
               so add draft #28 as well. TODO: remove.*/
            options->supportedVersions[k++] = v_tls_1_3_draft_28;
            options->supportedVersionsLen++;
        }
# endif
    }

    /* Set the versionFlag always to highest version. Note that
       versionFlag is not the same as the legacy version field
       so it can contain also the 1.3 version.
       Note that the priority order of the versions only affects to order of
       versions in the TLS1.3 supportedVersions extension, nothing else */
    options->versionFlag = VER_TO_FLAG(highestVersion);

    return PS_SUCCESS;
}

#endif /* USE_CLIENT_SIDE_SSL */

#ifdef USE_SERVER_SIDE_SSL

int32_t
matrixSslSessOptsSetServerTlsVersionRange(sslSessOpts_t *options,
        psProtocolVersion_t low,
        psProtocolVersion_t high)
{
    psProtocolVersion_t versions[TLS_MAX_SUPPORTED_VERSIONS] = {0};
    uint8_t numVersions = 0;
    uint32_t i;

    if (low > high)
    {
        return PS_ARG_FAIL;
    }

    /* Copy the range to array for SetClientTlsVersions */
    i = 0;
    do
    {
        if (COMPILED_IN_VER(high))
        {
            versions[i] = high;
        }
        numVersions++;
        i++;
        high >>= 1;
    } while (high >= low);

    return matrixSslSessOptsSetServerTlsVersions(options,
            versions,
            numVersions);
}

PSPUBLIC int32_t
matrixSslSessOptsSetServerTlsVersions(sslSessOpts_t *options,
        const psProtocolVersion_t versions[],
        int32_t versionsLen)
{
    uint8_t i, k;
# ifdef USE_TLS_1_3
    psBool_t haveTls13Draft28 = PS_FALSE;
# endif

    /*
      On the server side the version handling goes either of two
      ways:
      1. If single version is selected it is set to versionFlag
      2. If multiple versions are selected then the non-enabled
      versions are disabled through the disable flags and
      the versionFlag = 0
    */
    if (options == NULL)
    {
        return PS_ARG_FAIL;
    }
    if (versionsLen == 0)
    {
        psTraceErrr("Please enable at least one version.\n");
        return PS_ARG_FAIL;
    }
    if (versionsLen > TLS_MAX_SUPPORTED_VERSIONS)
    {
        psTraceErrr("Too many supported versions. Increase " \
                    "TLS_MAX_SUPPORTED_VERSIONS.\n");
        return PS_ARG_FAIL;
    }

# ifdef USE_TLS_1_3
    for (i = 0; i < versionsLen; i++)
    {
        if (versions[i] == v_tls_1_3_draft_28)
        {
            haveTls13Draft28 = PS_TRUE;
        }
    }
# endif
    for (i = 0, k = 0; i < versionsLen; i++)
    {
        if (!matrixSslTlsVersionRangeSupported(versions[i], versions[i]))
        {
            psTraceErrr("Unsupported version. Please enable more " \
                        "versions in matrixsslConfig.h.\n");
            psTracePrintProtocolVersionNew(INDENT_ERROR,
                    "unsupported version",
                    versions[i],
                    PS_TRUE);
            return PS_ARG_FAIL;
        }
        options->supportedVersions[k++] = versions[i];
        options->supportedVersionsLen++;
# ifdef USE_TLS_1_3
        if (versions[i] == v_tls_1_3 && !haveTls13Draft28)
        {
            /* Very little support in the wild for TLS 1.3 RFC version,
               so add draft #28 as well. TODO: remove.*/
            options->supportedVersions[k++] = v_tls_1_3_draft_28;
            options->supportedVersionsLen++;
        }
# endif
    }

    if (versionsLen == 1)
    {
        /* If on the server side only one version is enabled then it
         * is handled through the versionFlag. If there are many versions
         * enabled then they are handled through the supportedVersions */
        options->versionFlag = VER_TO_FLAG(versions[0]);
    }

    return PS_SUCCESS;
}

#endif /* USE_SERVER_SIDE_SSL */

void addVersion(ssl_t *ssl, psProtocolVersion_t ver)
{
    /* First, make sure the version to be added is supported by our
       build-time config. */
    if (!VER_SUPPORTED_BY_BUILD(ver))
    {
        psTraceErrr("Warning: tried to add a version not supported by " \
                "the build-time configuration\n");
        psTracePrintProtocolVersionNew(INDENT_WARNING,
                "Unsupported version",
                ver,
                PS_TRUE);
        return;
    }

# ifdef USE_TLS_1_3
    /*
      Don't include TLS 1.3 in ClientHello supported_versions if the
      user did not enable any 1.3 suites.

      Without TLS 1.3 suites in ClientHello, TLS 1.3 cannot be
      negotiated. And if the server then chooses <1.3, the TLS 1.3
      downgrade protection mechanism will be triggered on the client-side,
      causing handshake failure.
    */
    if ((ver & v_tls_1_3_any)
            && IS_CLIENT(ssl)
            && !ssl->tls13CiphersuitesEnabledClient)
    {
        psTraceInfo("Warning: tried to enable TLS 1.3 without enabling " \
                "any TLS 1.3 ciphersuites. Disabling TLS 1.3 for this " \
                "connection.\n");
        return;
    }
# endif /* USE_TLS_1_3 */

    ADD_VER(ssl->supportedVersions, ver);

    psAssert(ssl->supportedVersionsPriorityLen < TLS_MAX_SUPPORTED_VERSIONS);
    ssl->supportedVersionsPriority[ssl->supportedVersionsPriorityLen] = ver;
    ssl->supportedVersionsPriorityLen++;

    return;
}

/* Gets the supportedVersions list from options and saves it to ssl struct. */
int32 initSupportedVersions(ssl_t *ssl, sslSessOpts_t *options)
{
    psSize_t i;
    uint32 flags;
    psBool_t userProvidedVersions = PS_FALSE;
    psProtocolVersion_t highestSupported = v_undefined;

    userProvidedVersions = PS_TRUE;
    if (options->supportedVersionsLen == 0 &&
            !(options->versionFlag & ANY_VERSION_FLAG))
    {
        userProvidedVersions = PS_FALSE;
    }

    for (i = 0; i < options->supportedVersionsLen; i++)
    {
        addVersion(ssl, options->supportedVersions[i]);
    }

    /* Unfortunately API user can bypass the API and just set the
       version flags in options struct directly without settings
       supportedVersions, in which case we must do it here. */

    if (options->supportedVersionsLen == 0)
    {
        flags = options->versionFlag;
        if (flags & SSL_FLAGS_DTLS)
        {
            addVersion(ssl, v_dtls_1_0);
            highestSupported = v_dtls_1_0;
            if (flags & SSL_FLAGS_TLS_1_2)
            {
                addVersion(ssl, v_dtls_1_2);
                highestSupported = v_dtls_1_2;
            }
        }
        else
        {
            if ((flags & SSL_FLAGS_TLS_1_0)
                    && !SUPP_VER(ssl, v_tls_1_0))
            {
                addVersion(ssl, v_tls_1_0);
            }
            if ((flags & SSL_FLAGS_TLS_1_1)
                    && !SUPP_VER(ssl, v_tls_1_1))
            {
                addVersion(ssl, v_tls_1_1);
            }
            if ((flags & SSL_FLAGS_TLS_1_2)
                    && !SUPP_VER(ssl, v_tls_1_2))
            {
                addVersion(ssl, v_tls_1_2);
            }
#ifdef USE_TLS_1_3
            if ((flags & SSL_FLAGS_TLS_1_3)
                    && !SUPP_VER(ssl, v_tls_1_3))
            {
                addVersion(ssl, v_tls_1_3);
            }
            if ((flags & SSL_FLAGS_TLS_1_3_DRAFT_22)
                    && !SUPP_VER(ssl, v_tls_1_3_draft_22))
            {
                addVersion(ssl, v_tls_1_3_draft_22);
            }
            if ((flags & SSL_FLAGS_TLS_1_3_DRAFT_23) &&
                    !SUPP_VER(ssl, v_tls_1_3_draft_23))
            {
                addVersion(ssl, v_tls_1_3_draft_23);
            }
            if ((flags & SSL_FLAGS_TLS_1_3_DRAFT_24) &&
                    !SUPP_VER(ssl, v_tls_1_3_draft_24))
            {
                addVersion(ssl, v_tls_1_3_draft_24);
            }
            if ((flags & SSL_FLAGS_TLS_1_3_DRAFT_26) &&
                    !SUPP_VER(ssl, v_tls_1_3_draft_26))
            {
                addVersion(ssl, v_tls_1_3_draft_26);
            }
            if ((flags & SSL_FLAGS_TLS_1_3_DRAFT_28) &&
                    !SUPP_VER(ssl, v_tls_1_3_draft_28))
            {
                addVersion(ssl, v_tls_1_3_draft_28);
            }
#endif
        }
    }

    if (userProvidedVersions && ssl->supportedVersions == v_undefined)
    {
        /* User provided some versions, but we could not enable any of
           them, probably due to build-time configuration. */
        psTraceErrr("Invalid version configuration\n");
        return MATRIXSSL_ERROR;
    }

    if (!userProvidedVersions)
    {
        /* Get the default versions. */
        (void)getDefaultVersions(ssl);
    }

    /*
      We set the highest version we support as the active version.
      This has the following implications:

      - If server, we initially try to decode the first ClientHello
        as if it were in the TLS 1.3 ClientHello format. If this
        doesn't work, we will try with TLS 1.2 and below.

      - If client, we shall encode the first ClientHello according
        in the TLS 1.3 ClientHello format.
    */
    if (IS_CLIENT(ssl))
    {
        if (highestSupported == v_undefined)
        {
            highestSupported = psVerGetHighestTls(GET_SUPP_VER(ssl));
        }
        SET_ACTV_VER(ssl, highestSupported);
    }

    return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
