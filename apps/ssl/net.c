/* net.c
 *
 * Generic networking tool.
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
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

#include "osdep_stdio.h"
#include "osdep_stdlib.h"
#include "osdep_string.h"
#include "osdep_unistd.h"
#include "core/coreApi.h"
#include "matrixssl/matrixsslApi.h"
#include "matrixssl/matrixsslNet.h"
#include "matrixssl/matrixsslSocket.h"
/* Currently this example uses _psTrace for tracing, so osdep.h is needed: */
#include "core/osdep.h"
#include "core/psUtil.h"

#define USE_MATRIX_NET_DEBUG
#undef DEBUGF                /* Protect against possible multiple definition. */
#ifdef USE_MATRIX_NET_DEBUG
# define DEBUGF(...) Printf(__VA_ARGS__)
#else
# define DEBUGF(...) do {} while (0)
#endif

#if defined(USE_PS_NETWORKING) && !defined(USE_ONLY_PSK_CIPHER_SUITE)

/* The flags used by this program for TLS versions. */
# define FLAG_TLS_1_0 (1 << 10)
# define FLAG_TLS_1_1 (1 << 11)
# define FLAG_TLS_1_2 (1 << 12)
# define FLAG_TLS_1_3 (1 << 13)

/* Highlight text from peer. */
static char start_remote_text[] = "\033[1m";
static char end_remote_text[] = "\033[0m";

static int g_ciphers = 1;
static uint16_t g_cipher[] = { 47 };

# define HTTP_BUFFER_SIZE (1024 * 1024)

# define logMessage(l, t, ...) do { Printf(#l " " #t ": " __VA_ARGS__); Printf("\n"); } while (0) /* Log_Verbose, TAG, "Wrote %d bytes", transferred */

static int usage(FILE *out, const char *program)
{
    Fprintf(out, "usage: %s [options]\n", program);
    Fprintf(out, "Where options may include: ");
    Fprintf(out, "\t--help (-h)        Get this usage\n");
    Fprintf(out, "\t--host hostname    Specify host or address\n");
    Fprintf(out, "\t--port port        Specify target port\n");
    Fprintf(out, "\t--get http://url/  Get URL (supports HTTP protocol)\n");
    return 0;
}

/* Get the first argument from arguments. */
static
int option(int *argc_p, char ***argv_p, const char *opt, char **target)
{
    if (*argc_p == 1)
    {
        return 0; /* No arguments. */
    }
    if (*argc_p == 2 && target != NULL)
    {
        return 0; /* No space for argument with string. */

    }
    if (Strcmp((*argv_p)[1], opt) == 0)
    {
        (*argc_p) -= 1;
        (*argv_p)[1] = (*argv_p)[0];
        (*argv_p) += 1;

        if (target != NULL)
        {
            *target = (*argv_p)[1];
            (*argc_p) -= 1;
            (*argv_p)[1] = (*argv_p)[0];
            (*argv_p) += 1;
        }
        return 1;
    }
    return 0;
}

extern const char *capath_global;
extern int tls_global;

static int32 getHTTPResponse(const char *url,
    unsigned char *httpResponseBuf,
    size_t *httpResponseBufLen_p,
    psSocketType_t type,
    void *typespecific,
    const psSocketFunctions_t *func)
{
    int32 err;
    psUrlInteractState_t state = { type, typespecific, func };

    /* HTTP headers for HTTP request/response. */
    static const char *http_request_headers[] = {
        "User-Agent"
    };

    static const char *http_request_header_values[] = {
        "Basic-HTTP-Request/1.0"
    };

    err = psUrlInteract("GET", url,
        http_request_headers,
        http_request_header_values, 1,
        NULL, 0,
        NULL, NULL, NULL, 0,
        httpResponseBuf, httpResponseBufLen_p, &state);

    return err;
}

int do_get(const char *url, psSocketType_t type,
    const char *capath, int tls_version)
{
    void *buf = Malloc(HTTP_BUFFER_SIZE);
    size_t bufsz = HTTP_BUFFER_SIZE;
    int32 res;
    struct psSocketTls tls = { capath, tls_version };
    void *typespecific = &tls;
    const psSocketFunctions_t *func = NULL;

    if (type == PS_SOCKET_TLS)
    {
        func = psGetSocketFunctionsTLS();
    }
    else
    {
        typespecific = NULL;
    }

    if (!buf)
    {
        Fprintf(stderr, "Unable to allocate buffer %d bytes\n",
            HTTP_BUFFER_SIZE);
        return 2;
    }

    res = getHTTPResponse(url, buf, &bufsz, type, typespecific, func);
    if (res == PS_INSECURE_PROTOCOL)
    {
        Fprintf(stderr, "Do not try to use capath or tls version with http protocol\n");
        Fprintf(stderr, "these are for https protocol.\n");
        exit(1);
    }
    else if (res < 0)
    {
        /* Connection error. */
        Fprintf(stderr, "Connect error: %d\n", res);
    }
    else if (res != 0)
    {
        /* HTTP error. */
        Fprintf(stderr, "HTTP return code: %d\n", res);
    }
    else if (res == 0)
    {
        /* Write output (HTTP code 200 OK). */
        Fwrite(buf, bufsz, 1, stdout);
    }
    return res >= 0 ? 0 : 1;
}

# include <sys/select.h>

int do_dialog(psSocket_t *sock)
{
    int32 rc;
    unsigned char ch512[512];
    unsigned char ch1024[1024];
    psBuf_t buf;
    psBuf_t buf2;

    /* loop: send and receive. */
    do
    {
        static int count = 0;
        fd_set fds;
        int sockfd = psSocketGetFd(sock);

        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sockfd, &fds);
        Select(sockfd + 1, &fds, NULL, NULL, NULL);
        DEBUGF("an fd ready: stdin: %d sock_read: %d\n",
            FD_ISSET(STDIN_FILENO, &fds),
            FD_ISSET(sockfd, &fds));
        if (count++ == 100000)
        {
            Printf("Finished\n");
            return 1;
        }
        buf.buf = buf.start = buf.end = ch1024;
        buf.size = (uint32) sizeof(ch1024);
        rc = psSocketReadAppendBuf(sock, &buf, PS_SOCKET_OPTION_NONBLOCK);
        Printf("Got SOCK bytes: %d\n", rc);
        if (rc == 0)
        {
            Printf("Peer disconnected\n");
            return 0;
        }
        else if (rc > 0)
        {
            Printf("%s%.*s%s",
                start_remote_text,
                (int) (buf.end - buf.start),
                (const char *) buf.start,
                end_remote_text);
        }
        psSocketSetOptions(sock, PS_SOCKET_OPTION_BLOCK);

        buf2.buf = buf2.start = buf2.end = ch512;
        buf2.size = (uint32) sizeof(ch512);
        buf.buf = buf.start = buf.end = ch1024;
        buf.size = (uint32) sizeof(ch1024);
        rc = psSocketReadAppendBuf(STDIN_FILENO, &buf2,
            PS_SOCKET_OPTION_NONBLOCK);
        Printf("Got STDIN bytes: %d\n", rc);
        if (rc == 0)
        {
            Printf("Quit from keyboard\n");
            return 0;
        }
        /* Copy input to send buffer. */
        if (rc > 0)
        {
            while (buf2.start != buf2.end)
            {
                unsigned char uch = *(buf2.start++);
                if (uch == '\n')
                {
                    *(buf.end++) = '\r';
                }
                *(buf.end++) = uch;
            }

            if (psSocketWriteShiftBuf(sock, &buf, 0) < 1)
            {
                Fprintf(stderr, "Connection error\n");
                return 1;
            }
        }
    }
    while (1);
    /* Above loop newer breaks. */
}

int do_dialog_matrixssl(matrixSslInteract_t *msi_p)
{
    int32 rc;
    unsigned char ch512[512];
    unsigned char ch1024[1024];
    psBuf_t buf;
    psBuf_t buf2;
    psSocket_t *sock = msi_p->sock;

    /* loop: send and receive. */
    do
    {
        static int count = 0;
        fd_set fds;
        fd_set except_fds;
        int sockfd = psSocketGetFd(sock);

        FD_ZERO(&fds);
        FD_ZERO(&except_fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(STDIN_FILENO, &except_fds);
        FD_SET(sockfd, &fds);
        Select(sockfd + 1, &fds, NULL, NULL, NULL);
        DEBUGF("an fd ready stdin: %d sock_read: %d\n",
            FD_ISSET(STDIN_FILENO, &fds),
            FD_ISSET(sockfd, &fds));

        if (count++ == 2000000000)
        {
            Printf("Finished\n");
            return 1;
        }
        buf.buf = buf.start = buf.end = ch1024;
        buf.size = (uint32) sizeof(ch1024);
        rc = matrixSslInteract(msi_p, PS_FALSE, PS_TRUE);
        if (rc == MATRIXSSL_RECEIVED_ALERT)
        {
alert_handler:
            if (msi_p->ch2[0] == 1 && msi_p->ch2[1] == 0)
            {
                Printf("Peer terminated connection.\n");
                psSocketShutdown(sock, 0);
                matrixSslInteractClose(msi_p);
                return 0;
            }

            Fprintf(stderr, "Got alert: level=%d desc=%d\n",
                (int) msi_p->ch2[0], (int) msi_p->ch2[1]);
            return 1;
        }
        if (rc == MATRIXSSL_NET_DISCONNECTED)
        {
            Fprintf(stderr, "The peer has disconnected\n");
            exit(0);
        }
        if (rc < 0)
        {
            Fprintf(stderr, "matrixSslInteract error: %d\n",
                (int) rc);
            exit(1);
        }
again_read:
        if (rc == MATRIXSSL_APP_DATA &&
            matrixSslInteractReadLeft(msi_p))
        {
            rc = matrixSslInteractRead(
                msi_p, buf.end,
                buf.buf + buf.size - buf.end);
            if (rc < 0)
            {
                Fprintf(stderr, "Read error: rc=%d\n", rc);
                return 1;
            }
            DEBUGF("Interact read gave %d\n", (int) rc);
            Printf("%s", start_remote_text);
            Printf("%.*s", (int) (rc), (const char *) buf.start);
            Printf("%s", end_remote_text);
            Fflush(stdout);
        }
        psSocketSetOptions(sock, PS_SOCKET_OPTION_BLOCK);

        buf2.buf = buf2.start = buf2.end = ch512;
        buf2.size = (uint32) sizeof(ch512);
        buf.buf = buf.start = buf.end = ch1024;
        buf.size = (uint32) sizeof(ch1024);
        if (!FD_ISSET(STDIN_FILENO, &fds) &&
            !FD_ISSET(STDIN_FILENO, &except_fds))
        {
            goto no_kbd_input;
        }
        rc = psSocketReadAppendBuf(STDIN_FILENO, &buf2,
            PS_SOCKET_OPTION_NONBLOCK);
        if (rc > 0)
        {
            DEBUGF("Got STDIN bytes: %d\n", rc);
        }
        else if (rc < 0 && rc != PS_EAGAIN)
        {
            DEBUGF("Got STDIN read error: %d\n", rc);
        }
        if (rc == 0)
        {
            Printf("Quit from keyboard\n");
            return 0;
        }
        /* Copy input to send buffer. */
        if (rc > 0)
        {
            while (buf2.start != buf2.end)
            {
                unsigned char uch = *(buf2.start++);
                if (uch == '\n')
                {
                    *(buf.end++) = '\r';
                }
                *(buf.end++) = uch;
            }

            DEBUGF("Interact write %d bytes {%.*s}\n",
                (int) (buf.end - buf.start),
                (int) (buf.end - buf.start),
                (const char *) buf.start);

            if (matrixSslInteractWrite(msi_p,
                    buf.start,
                    buf.end - buf.start) < 0)
            {
                Fprintf(stderr, "Connection error\n");
                return 1;
            }
            /* Mark the buffer as handled. */
            buf2.start = buf2.end;
        }

no_kbd_input:
        /* Forward packets sent, if necessary. */
        rc = matrixSslInteract(msi_p, PS_TRUE, PS_FALSE);
        if (rc == MATRIXSSL_RECEIVED_ALERT)
        {
            goto alert_handler;
        }
        if (matrixSslInteractReadLeft(msi_p))
        {
            rc = MATRIXSSL_APP_DATA;
            goto again_read;
        }
        if (rc == MATRIXSSL_NET_DISCONNECTED)
        {
            Fprintf(stderr, "The peer has disconnected\n");
            exit(0);
        }
    }
    while (1);
    /* Above loop never breaks. */
}

int do_dialog_client(const char *host, const char *port)
{
    int32 rc;
    psSocket_t *sock;

    rc = psSocketConnect(host, port, 0, PS_SOCKET_STREAM, NULL, NULL, &sock);
    if (rc == PS_SUCCESS)
    {
        Printf("Connected to %s:%s\n", host, port);
        return do_dialog(sock);
    }
    Printf("Unable to connect\n");
    return 2;
}

/* The MatrixSSL certificate validation callback. */
# ifdef USE_CLIENT_SIDE_SSL
static int32 ssl_cert_auth(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
    return MATRIXSSL_SUCCESS;
}

static int32 extensionCb(ssl_t *ssl, uint16_t extType, uint8_t extLen, void *e)
{

    if (extType == EXT_SNI)
    {
        logMessage(Log_Info, TAG, "SNI extension callback called");
    }
    return PS_SUCCESS;
}
# endif /* USE_CLIENT_SIDE_SSL */


int32 do_tls_handshake(matrixSslInteract_t *msi_p, int32 rc)
{
    fd_set fds;

    if (rc < PS_SUCCESS)
    {
        return rc;
    }


    do
    {
        int sockfd = psSocketGetFd(msi_p->sock);
        if (rc == MATRIXSSL_REQUEST_RECV)
        {
            DEBUGF("wait for data from peer\n");
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);
            Select(sockfd + 1, &fds, NULL, NULL, NULL);
        }
        else if (rc ==  MATRIXSSL_REQUEST_SEND ||
                 msi_p->send_len_left > 0)
        {
            DEBUGF("wait for sending data to peer\n");
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);
            Select(sockfd + 1, NULL, &fds, NULL, NULL);
        }
/*              if (rc != 0) */
        DEBUGF("hs rc code: %d\n", rc);
        if (rc == MATRIXSSL_REQUEST_RECV)
        {
            rc = matrixSslInteractHandshake(msi_p, PS_FALSE, PS_TRUE);
        }
        else
        {
            rc = matrixSslInteractHandshake(msi_p, PS_TRUE, PS_TRUE);
        }
        DEBUGF("hs msi rc code: %d\n", rc);
    }
    while (rc > PS_SUCCESS && rc != MATRIXSSL_RECEIVED_ALERT);
    return rc;
}

static void set_tls_options_version(sslSessOpts_t *options_p, int tls)
{
    if ((tls & FLAG_TLS_1_0) || tls == 0)
    {
        options_p->versionFlag |= SSL_FLAGS_TLS_1_0;
    }
    if ((tls & FLAG_TLS_1_1) || tls == 0)
    {
        options_p->versionFlag |= SSL_FLAGS_TLS_1_1;
    }
    if ((tls & FLAG_TLS_1_2) || tls == 0)
    {
        options_p->versionFlag |= SSL_FLAGS_TLS_1_2;
    }
    if ((tls & FLAG_TLS_1_3) || tls == 0)
    {
        options_p->versionFlag |= SSL_FLAGS_TLS_1_3_DRAFT_23;
    }
}

# ifdef USE_CLIENT_SIDE_SSL
int do_dialog_client_tls(const char *host, const char *port,
    const char *capath, int tls)
{
    int32 rc;
    sslSessOpts_t options;
    sslKeys_t *keys = NULL;
    sslSessionId_t *sid = NULL;
    matrixSslInteract_t msi;
    tlsExtension_t *extension;
    unsigned char *ext = NULL;
    int32 extLen;

    Memset(&options, 0x0, sizeof(sslSessOpts_t));
    set_tls_options_version(&options, tls);

    if (matrixSslOpen() < 0)
    {
        Fprintf(stderr, "Error initializing MatrixSSL\n");
        return 3;
    }

    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        Fprintf(stderr, "Error initializing MatrixSSL: "
            "matrixSslNewKeys error\n");
        return 3;
    }
    if (matrixSslNewSessionId(&sid, NULL) < 0)
    {
        Fprintf(stderr, "Error initializing MatrixSSL: "
            "matrixSslNewSessionId error\n");
        return 3;
    }

    if (capath != NULL)
    {
#  ifdef USE_RSA
        rc = matrixSslLoadRsaKeys(keys, NULL, NULL, NULL, capath);
#  else
#   ifdef USE_ECC
        rc = matrixSslLoadEcKeys(keys, NULL, NULL, NULL, capath);
#   else
#    error either USE_RSA or USE_ECC needed in net.c
#   endif
#  endif
        if (rc != PS_SUCCESS)
        {
            Fprintf(stderr, "No certificate material loaded.\n");
            matrixSslDeleteSessionId(sid);
            matrixSslDeleteKeys(keys);
            matrixSslClose();
            return rc;
        }
    }

    matrixSslNewHelloExtension(&extension, NULL);
    matrixSslCreateSNIext(NULL, (unsigned char *) host, (uint32) Strlen(host),
        &ext, &extLen);
    if (ext)
    {
        matrixSslLoadHelloExtension(extension, ext, extLen, EXT_SNI);
        psFree(ext, NULL);
    }

    rc = matrixSslInteractBeginConnected(&msi, host, port, 0, NULL,
        keys, sid,
        g_cipher, g_ciphers,
        ssl_cert_auth, NULL,
        extension,
        extensionCb, &options);
    matrixSslDeleteHelloExtension(extension);

    if (rc >= PS_SUCCESS)
    {
        /* Interact until connected. */
        Printf("Connected to %s:%s (using TLS)\n", host, port);
        rc = do_tls_handshake(&msi, rc);
        if (rc == MATRIXSSL_REQUEST_CLOSE)
        {
            Printf("Connection close requested.\n");
            exit(1);
        }
        if (rc != PS_SUCCESS)
        {
            Printf("Handshake failure: %d\n", rc);
            exit(1);
        }
        Printf("Successful handshake\n");

        rc = do_dialog_matrixssl(&msi);

        /* Free all allocated/opened resources. */
        matrixSslDeleteSessionId(sid);

        matrixSslDeleteKeys(keys);
        matrixSslClose();
        Printf("Closed down\n");
        return rc;
    }
    Printf("Unable to connect\n");

    /* Free all allocated/opened resources. */
    matrixSslDeleteSessionId(sid);
    matrixSslDeleteKeys(keys);
    matrixSslClose();

    return 2;
}
# endif /* USE_CLIENT_SIDE_SSL */

int do_dialog_server(const char *host, const char *port)
{
    int32 rc;
    psSocket_t *sock;
    psSocket_t *sock2;

    rc = psSocketListen(host, port, 0, 0, PS_SOCKET_STREAM, NULL, NULL, &sock);
    if (rc == PS_SUCCESS)
    {
        Printf("Waiting for connection\n");
        rc = psSocketAccept(sock, 0, &sock2);
        Printf("Connected.\n");
        rc = do_dialog(sock2);
        psSocketShutdown(sock, 0);
        return rc;
    }
    Printf("Cannot listen to specified address/port\n");
    return 2;
}

# if defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS)
static int32 sessTicketCb(void *keys, unsigned char name[16], short found);

static unsigned char sessTicketSymKey[32] = { 0 };
static unsigned char sessTicketMacKey[32] = { 0 };

int32 sessTicketCb(void *keys, unsigned char name[16], short found)
{
    if (found)
    {
        /* Was already cached */
        return PS_SUCCESS;
    }
    /* Example.  If name was located, the keys would be loaded this way */
    return matrixSslLoadSessionTicketKeys((sslKeys_t *) keys, name,
        sessTicketSymKey, 32, sessTicketMacKey, 32);
}
# endif /* USE_SERVER_SIDE_SSL && USE_STATELESS_SESSION_TICKETS */

# ifdef USE_SERVER_SIDE_SSL
int do_dialog_server_tls(const char *host, const char *port,
    const char *certpath, const char *keypath,
    const char *capath, int tls)
{
    int32 rc;
    psSocket_t *sock;
    sslSessOpts_t options;
    sslKeys_t *keys = NULL;
    matrixSslInteract_t msi;

#  ifdef USE_STATELESS_SESSION_TICKETS
    unsigned char sessTicketName[16];
#  endif

    Memset(&options, 0x0, sizeof(sslSessOpts_t));
    set_tls_options_version(&options, tls);

    if (matrixSslOpen() < 0)
    {
        Fprintf(stderr, "Error initializing MatrixSSL\n");
        return 3;
    }

    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        Fprintf(stderr, "Error initializing MatrixSSL: "
            "matrixSslNewKeys error\n");
        return 3;
    }

    options.userPtr = keys;

#  ifdef USE_STATELESS_SESSION_TICKETS
    matrixSslSetSessionTicketCallback(keys, sessTicketCb);
    if (psGetPrngLocked(sessTicketSymKey,
            sizeof(sessTicketSymKey), NULL) < 0 ||
        psGetPrngLocked(sessTicketMacKey,
            sizeof(sessTicketMacKey), NULL) < 0 ||
        psGetPrngLocked(sessTicketName,
            sizeof(sessTicketName), NULL) < 0)
    {
        _psTrace("Error generating session ticket encryption key\n");
        return EXIT_FAILURE;
    }

    if (matrixSslLoadSessionTicketKeys(keys, sessTicketName,
            sessTicketSymKey, 32,
            sessTicketMacKey, 32) < 0)
    {
        _psTrace("Error loading session ticket encryption key\n");
    }
#  endif

#  ifdef USE_RSA
    rc = matrixSslLoadRsaKeys(keys, certpath, keypath, NULL, capath);
#  else
#   ifdef USE_ECC
    rc = matrixSslLoadEcKeys(keys, certpath, keypath, NULL, capath);
#   else
#    error either USE_RSA or USE_ECC needed in net.c
#   endif
#  endif
    if (rc < 0)
    {
        _psTrace("Unable to load static key material.  Exiting\n");
        matrixSslDeleteKeys(keys);
        matrixSslClose();
        return rc;
    }

    rc = psSocketListen(host, port, 0, 0, PS_SOCKET_STREAM, NULL, NULL, &sock);
    if (rc == PS_SUCCESS)
    {
        Printf("Waiting for connection\n");
        rc = matrixSslInteractBeginAccept(&msi, sock, 0,
            keys, NULL, &options);
        if (rc < 0)
        {
            Printf("Accept failed\n");
            exit(1);
        }

        if (rc >= PS_SUCCESS)
        {
            /* Interact until connected. */
            Printf("Client connected\n");
            /* TOOD: Fake read needed. */
            rc = do_tls_handshake(&msi,
                MATRIXSSL_REQUEST_RECV);
            if (rc == MATRIXSSL_REQUEST_CLOSE)
            {
                Printf("Connection close requested.\n");
                exit(1);
            }
            if (rc != PS_SUCCESS)
            {
                Printf("Handshake failure: %d\n", rc);
                exit(1);
            }
            Printf("Successful handshake\n");

            rc = do_dialog_matrixssl(&msi);

            /* Free all allocated/opened resources. */
            matrixSslDeleteKeys(keys);
            matrixSslClose();
            Printf("Closed down\n");
            psSocketShutdown(sock, 0);
            return rc;
        }
    }
    Printf("Cannot listen to specified address/port\n");
    return 2;
}
# endif /* USE_SERVER_SIDE_SSL */

int main(int argc, char **argv)
{
    int listen = 0;
    int tls = 0;
    int tls_version = 0;
    char *host = NULL;
    char *port = NULL;
    char *get = NULL;
    char *capath = NULL;
    char *certpath = NULL;
    char *keypath = NULL;

    while (argc > 1)
    {
        if (option(&argc, &argv, "-h", NULL))
        {
            exit(usage(stdout, argv[0]));
        }
        else if (option(&argc, &argv, "--help", NULL))
        {
            exit(usage(stdout, argv[0]));
        }
        else if (option(&argc, &argv, "--host", &host))
        {
            ;
        }
        else if (option(&argc, &argv, "--port", &port))
        {
            ;
        }
        else if (option(&argc, &argv, "--get", &get))
        {
            ;
        }
        else if (option(&argc, &argv, "--tls", NULL))
        {
            tls = 1;
        }
        else if (option(&argc, &argv, "--tlsv10", NULL))
        {
            tls_version |= FLAG_TLS_1_0;
        }
        else if (option(&argc, &argv, "--tlsv11", NULL))
        {
            tls_version |= FLAG_TLS_1_1;
        }
        else if (option(&argc, &argv, "--tlsv12", NULL))
        {
            tls_version |= FLAG_TLS_1_2;
        }
        else if (option(&argc, &argv, "--tlsv13", NULL))
        {
            tls_version |= FLAG_TLS_1_3;
        }
        else if (option(&argc, &argv, "--capath", &capath))
        {
            tls = 1; /* CApath also enables tls. */
        }
        else if (option(&argc, &argv, "--cert", &certpath))
        {
            tls = 1; /* certpath also enables tls. */
        }
        else if (option(&argc, &argv, "--key", &keypath))
        {
            tls = 1; /* keypath also enables tls. */
        }
        else if (option(&argc, &argv, "--listen", NULL))
        {
            listen = 1;
        }
        else if (option(&argc, &argv, "--no-highlighting", NULL))
        {
            *start_remote_text = 0;
            *end_remote_text = 0;
        }
        else
        {
            break;
        }
    }
    if (argc > 1)
    {
        Fprintf(stderr, "Invalid arguments: Unable to process %s\n",
            argv[1]);
        usage(stderr, argv[0]);
        exit(1);
    }
    if (tls_version > 0)
    {
        tls = 1;
    }

    if (get != NULL && capath != NULL && tls)
    {
        exit(do_get(get, PS_SOCKET_TLS, capath, tls_version));
    }
    if (get != NULL)
    {
        exit(do_get(get, PS_SOCKET_STREAM, NULL, 0));
    }
    if (listen && port && certpath && keypath && tls)
    {
# ifdef USE_SERVER_SIDE_SSL
        exit(do_dialog_server_tls(host, port,
                certpath, keypath, capath,
                tls_version));
# else
        Fprintf(stderr, "USE_SERVER_SIDE_SSL required\n");
        return EXIT_FAILURE;
# endif
    }
    if (listen && port)
    {
        exit(do_dialog_server(host, port));
    }
    if (host && port && tls)
    {
# ifdef USE_CLIENT_SIDE_SSL
        exit(do_dialog_client_tls(host, port, capath, tls_version));
# else
        Fprintf(stderr, "USE_CLIENT_SIDE_SSL required\n");
        return EXIT_FAILURE;
# endif
    }
    if (host && port)
    {
        exit(do_dialog_client(host, port));
    }

    Fprintf(stderr, "Invalid arguments\n");
    usage(stderr, argv[0]);
    exit(1);
    return 0;
}

#else

/******************************************************************************/
/*
        Stub main for compiling without proper options enabled
 */
int32 main(int32 argc, char **argv)
{
# ifndef USE_PS_NETWORKING
    Printf("USE_PS_NETWORKING must be enabled at build"
        " time to run this application\n");
# endif
# ifdef USE_ONLY_PSK_CIPHER_SUITE
    Printf("This application is not compatible with"
        " USE_ONLY_PSK_CIPHER_SUITE.\n");
# endif
    return 1;
}
#endif /* define USE_PS_NETWORKING */

/* end of file net.c */
