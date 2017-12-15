/**
 *      @file    dtlsClient.c
 *      @version $Format:%h%d$
 *
 *      MatrixDTLS client example.
 */
/*
 *      Copyright (c) 2014-2017 INSIDE Secure Corporation
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

#include "dtlsCommon.h"
/* Currently this example uses _psTrace for tracing, so osdep.h is needed: */
#include "core/osdep.h"
#include "core/psUtil.h"
#include "../common/client_common.h"

#if defined(USE_DTLS) && defined(USE_CLIENT_SIDE_SSL)

static int packet_loss_prob = 0; /* Reciprocal of packet loss probability
                                    (i.e. P(packet loss) = 1/x).
                                    Default value is 0 (no packet loss). */

# ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
static int test_lost_cipherspec_change_rehandshake = 0;
# endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */

/* Client DTLS context data type */
typedef struct
{
    SOCKET fd;
    struct sockaddr_in addr;
    ssl_t *ssl;
} sslDtls_t;

# ifndef MATRIX_TESTING_ENVIRONMENT /* Omit the message when testing. */
#  ifdef WIN32
#   pragma message("DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS.")
#  else
#   warning "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#  endif
# endif

# define ALLOW_ANON_CONNECTIONS  1
# define USE_HEADER_KEYS

/*
    Test rehandshakes
 */
# ifndef TEST_DTLS_CLIENT_REHANDSHAKE
#  define TEST_DTLS_CLIENT_REHANDSHAKE 0
# endif /* TEST_DTLS_CLIENT_REHANDSHAKE */
# ifndef TEST_DTLS_CLIENT_RESUMED_REHANDSHAKE
#  define TEST_DTLS_CLIENT_RESUMED_REHANDSHAKE 0
# endif /* TEST_DTLS_CLIENT_RESUMED_REHANDSHAKE */

/********************************** Globals ***********************************/

static unsigned char helloWorld[] = "!!! MatrixDTLS Connection Complete !!!\n\n";

extern int opterr;
static char g_ip[16];
static char g_path[256];
static int g_port, g_new, g_resumed, g_ciphers;
static int g_disableCertNameChk;
static uint16_t g_cipher[16];

/****************************** Local Functions *******************************/

static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
static void closeConn(sslDtls_t *dtls, SOCKET fd);
static int32 sendHelloWorld(sslDtls_t *dtlsCtx);

/******************************************************************************/
/*
    Allocate the data structure to manage the socket and ssl combo of
    a DTLS client.
 */
static SOCKET dtlsInitClientSocket(sslDtls_t **newCtx, ssl_t *ssl)
{
    sslDtls_t *dtls;

    *newCtx = NULL;

    if ((dtls = psMalloc(NULL, sizeof(sslDtls_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }
    dtls->ssl = ssl;

    if ((dtls->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        _psTrace("Error creating INET UDP socket\n");
        psFree(dtls, NULL);
        return INVALID_SOCKET;
    }

    memset(&dtls->addr, 0x0, sizeof(struct sockaddr_in));
    dtls->addr.sin_family = AF_INET;
    dtls->addr.sin_port = htons((short) g_port);
    dtls->addr.sin_addr.s_addr = inet_addr(g_ip);
    *newCtx = dtls;

    udpInitProxy();

    return dtls->fd;
}

/******************************************************************************/
/*
    Make a secure HTTP request to a defined IP and port
    Connection is made in blocking socket mode
    The connection is considered successful if the SSL/TLS session is
    negotiated successfully, a request is sent, and a HTTP response is received.
 */
static int32 dtlsClientConnection(sslKeys_t *keys, sslSessionId_t *sid)
{
    int32 rc, transferred, len, val, weAreDone;
    ssl_t *ssl;
    sslDtls_t *dtlsCtx;
    unsigned char *buf;
    socklen_t addrlen;
    struct sockaddr_in from;
    socklen_t fromLen;
    struct timeval timeout;
    long tSec;
    fd_set readfd;
    SOCKET fd;
    sslSessOpts_t options;
    int16 rehandshakeTestDone, resumedRehandshakeTestDone;

# ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
    int drop_next_cipherspec_packet = 0;
# endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */

    memset(&options, 0x0, sizeof(sslSessOpts_t));
    options.versionFlag = SSL_FLAGS_DTLS;
    options.trustedCAindication = 1;


    /* We are passing the IP address of the server as the expected name */
    /* To skip certificate subject name tests, pass NULL instead of g_ip */
    if (g_disableCertNameChk == 0)
    {
        rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
            certCb, g_ip, NULL, NULL, &options);
    }
    else
    {
        rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
            certCb, NULL, NULL, NULL, &options);
    }

    if (rc != MATRIXSSL_REQUEST_SEND)
    {
        _psTraceInt("New Client Session Failed: %d.  Exiting\n", rc);
        return PS_ARG_FAIL;
    }

/*
    Create the UDP socket and associate the SSL context with it
 */
    if ((fd = dtlsInitClientSocket(&dtlsCtx, ssl)) < 0)
    {
        matrixSslDeleteSession(ssl);
        return fd;
    }
/*
    Local inits
 */
    rehandshakeTestDone = resumedRehandshakeTestDone = 0;
    weAreDone = 0; /* resumed handshake exit hint mechanism */
    addrlen =  sizeof(dtlsCtx->addr);
    memset(&from, 0x0, sizeof(struct sockaddr_in));

/*
    Timeout mechanism is implemented according to guidelines in spec
 */
    tSec = MIN_WAIT_SECS;
    timeout.tv_usec = 0;

/*
    matrixDtlsGetOutdata will always return data to send.  If a new outgoing
    flight is not waiting to be send a resend of the previous flight will be
    returned.
 */
WRITE_MORE:
    while ((len = matrixDtlsGetOutdata(ssl, &buf)) > 0)
    {
# ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
        if (test_lost_cipherspec_change_rehandshake && drop_next_cipherspec_packet)
        {
            transferred = udpSend(fd, buf, len, (struct sockaddr *) &dtlsCtx->addr,
                addrlen, (int) tSec,
                packet_loss_prob, &drop_next_cipherspec_packet);
        }
        else
# endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
        transferred = udpSend(fd, buf, len, (struct sockaddr *) &dtlsCtx->addr,
            addrlen, (int) tSec,
            packet_loss_prob, NULL);

        if (transferred <= 0)
        {
            goto L_CLOSE_ERR;
        }
        else
        {
            /* Always indicate the entire datagram was sent as there is no
               way for DTLS to handle partial records.  Resends and timeouts will
               handle any problems */
            if ((rc = matrixDtlsSentData(ssl, len)) < 0)
            {
                goto L_CLOSE_ERR;
            }
            if (rc == MATRIXSSL_REQUEST_CLOSE)
            {
                /* This is a 'graceful' exit so return success */
                closeConn(dtlsCtx, fd);
                return MATRIXSSL_SUCCESS;
            }
            if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
            {
                /* This is the resumed handshake endgame case and is a bit more
                   problematic than the standard case because we are the last
                   to send and we can't be sure the server received our FINISHED
                   message.  Let's handle this in our example by waiting another
                   timeout to see if the server is trying to resend */
                _psTrace("Resumed handshake case. Pausing to check ");
                _psTrace("server received final FINISHED message\n");
                tSec = 4;
                timeout.tv_usec = 0;
                weAreDone = 1;
            }
            /* SSL_REQUEST_SEND is handled by loop logic */
        }
    }

READ_MORE:
    /*  Select is the DTLS timeout/resend mechanism */
    FD_ZERO(&readfd);
    FD_SET(fd, &readfd);
    timeout.tv_sec = tSec;

    if ((val = select(fd + 1, &readfd, NULL, NULL, &timeout)) < 0)
    {
        if (SOCKET_ERRNO != EINTR)
        {
            psTraceIntDtls("unhandled error %d from select", SOCKET_ERRNO);
            goto L_CLOSE_ERR;
        }
        goto READ_MORE;
    }
    /* Check for timeout or select wake-up */
    if (!FD_ISSET(fd, &readfd))
    {
        /* Timed out.  For good? */
        psTraceIntDtls("select timed out %d\n", val);
        if (tSec == MAX_WAIT_SECS)
        {
            psTraceDtls("Max Timeout.  Leaving\n");
            goto L_CLOSE_ERR;
        }
        tSec *= 2;
        /* Our special exit case for resumed handshakes was simply to wait
           and see if the server was resending its FINISHED message.  If not,
           safe to assume we are connected.  Send app data and leave */
        if (weAreDone == 1)
        {
            if (TEST_DTLS_CLIENT_RESUMED_REHANDSHAKE == 1 &&
                resumedRehandshakeTestDone == 0)
            {
                sendHelloWorld(dtlsCtx);
                _psTrace("--- Initiating resumed rehandshake ---\n");
                resumedRehandshakeTestDone = 1;
                weAreDone = 0;
                matrixSslEncodeRehandshake(ssl, NULL, NULL, 0, g_cipher,
                    g_ciphers);
                goto WRITE_MORE;
            }
            sendHelloWorld(dtlsCtx);
            closeConn(dtlsCtx, fd);
            return MATRIXSSL_SUCCESS;
        }
        /* Normal timeout case is to resend flight */
        goto WRITE_MORE;
    }

    /* Select woke.  Reset timeout */
    tSec = MIN_WAIT_SECS;

    if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0)
    {
        goto L_CLOSE_ERR;
    }
    fromLen =  sizeof(struct sockaddr_in);
    if ((transferred = (int32) recvfrom(fd, buf, len, MSG_DONTWAIT,
             (struct sockaddr *) &from, &fromLen)) < 0)
    {
        goto L_CLOSE_ERR;
    }

# ifdef USE_DTLS_DEBUG_TRACE
    /* nice for debugging */
    psTraceIntDtls("Read %d bytes from server\n", transferred);
# endif

    /*  If EOF, remote socket closed. But we haven't received the HTTP response
        so we consider it an error in the case of an HTTP client */
    if (transferred == 0)
    {
        goto L_CLOSE_ERR;
    }
    if ((rc = matrixSslReceivedData(ssl, (int32) transferred, &buf,
             (uint32 *) &len)) < 0)
    {
        goto L_CLOSE_ERR;
    }

PROCESS_MORE:
    switch (rc)
    {
    case MATRIXSSL_HANDSHAKE_COMPLETE:
        /* This is the ideal protocol scenario to know that the handshake is
           complete when the client sends app data first.  This is the normal
           handshake case and the client is the last to receive FINISHED

           If enabled, perform a rehandshake test */
        if (TEST_DTLS_CLIENT_REHANDSHAKE == 1 && rehandshakeTestDone == 0)
        {
            sendHelloWorld(dtlsCtx);
            _psTrace("--- Initiating rehandshake ---\n");

# ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
            if (test_lost_cipherspec_change_rehandshake)
            {
                /*
                   Cause an encryption algorithm change during a re-handshake.
                   The aim here is to test the dtlsRevertWriteCipher() function,
                   in the situation where the CHANGE_CIPHER_SPEC message
                   that is supposed to inform the server about the
                   algorithm change gets lost.
                   The following cipher spec changes are supported:
                   TLS_RSA_WITH_AES_128_GCM_SHA256 --> TLS_RSA_WITH_AES_128_CBC_SHA256
                   (anything) --> TLS_RSA_WITH_AES_128_GCM_SHA256.
                 */
                _psTrace("Forcing a change cipher spec...\n");
                if (g_cipher[0] == TLS_RSA_WITH_AES_128_GCM_SHA256)
                {
                    g_cipher[0] = TLS_RSA_WITH_AES_128_CBC_SHA256;
                }
                else
                {
                    g_cipher[0] = TLS_RSA_WITH_AES_128_GCM_SHA256;
                }
                if (drop_next_cipherspec_packet == 1)
                {
                    drop_next_cipherspec_packet = 0;
                }
                else
                {
                    drop_next_cipherspec_packet = 1;
                }
            }
# endif     /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
            if (matrixSslEncodeRehandshake(ssl, NULL, NULL,
                    SSL_OPTION_FULL_HANDSHAKE,
                    g_cipher, g_ciphers) == MATRIXSSL_SUCCESS)
            {
                rehandshakeTestDone = 1;
                goto WRITE_MORE;
            }
            else
            {
                _psTrace("matrixSslEncodeRehandshake failed\n");
                goto L_CLOSE_ERR;
            }
        }

        sendHelloWorld(dtlsCtx);
        closeConn(dtlsCtx, fd);
        return MATRIXSSL_SUCCESS;

    case MATRIXSSL_APP_DATA:
/*
            Would process app data here
 */
        if ((rc = matrixSslProcessedData(ssl, &buf, (uint32 *) &len)) == 0)
        {
            goto READ_MORE;
        }
        goto PROCESS_MORE;
    case MATRIXSSL_REQUEST_SEND:
        goto WRITE_MORE;
    case MATRIXSSL_REQUEST_RECV:
        goto READ_MORE;
    case MATRIXSSL_RECEIVED_ALERT:
        /* The first byte of the buffer is the level */
        /* The second byte is the description */
        if (*buf == SSL_ALERT_LEVEL_FATAL)
        {
            psTraceIntInfo("Fatal alert: %d, closing connection.\n",
                *(buf + 1));
            goto L_CLOSE_ERR;
        }
        /* Closure alert is normal (and best) way to close */
        if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY)
        {
            closeConn(dtlsCtx, fd);
            return MATRIXSSL_SUCCESS;
        }
        psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
        if ((rc = matrixSslProcessedData(ssl, &buf, (uint32 *) &len)) == 0)
        {
            /* No more data in buffer. Might as well read for more. */
            goto READ_MORE;
        }
        goto PROCESS_MORE;
    default:
        /* If rc <= 0 we fall here */
        goto L_CLOSE_ERR;
    }

L_CLOSE_ERR:
    _psTrace("DTLS Connection FAIL.  Exiting\n");
    closeConn(dtlsCtx, fd);
    return MATRIXSSL_ERROR;
}

/******************************************************************************/
/*
    Example application data send
 */
static int32 sendHelloWorld(sslDtls_t *dtlsCtx)
{
    unsigned char *buf;
    int32 avail, len, ret;

    _psTrace("DTLS handshake complete.  Sending sample application data\n");
    len = (int32) strlen((char *) helloWorld) + 1;
/*
    Get free buffer, copy in plaintext, and encode
 */
    if ((avail = matrixSslGetWritebuf(dtlsCtx->ssl, &buf, len)) < 0)
    {
        return PS_MEM_FAIL;
    }
    avail = min(avail, len);
    strncpy((char *) buf, (char *) helloWorld, avail);

    if ((ret = matrixSslEncodeWritebuf(dtlsCtx->ssl, avail)) < 0)
    {
        return ret;
    }
/*
    Get the encoded buffer and write it out
 */
    while ((len = matrixDtlsGetOutdata(dtlsCtx->ssl, &buf)) > 0)
    {
        ret = (int32) sendto(dtlsCtx->fd, buf, len, 0,
            (struct sockaddr *) &dtlsCtx->addr, sizeof(struct sockaddr_in));
        if (ret == -1)
        {
            perror("sendto");
            exit(1);
        }
        matrixDtlsSentData(dtlsCtx->ssl, len);
    }
    return PS_SUCCESS;
}

static void usage(void)
{
    printf("\nusage: client { option }\n"
        "\n"
        "where option can be one of the following:\n"
        "\n"
        "-c <cipherList>         - Comma separated list of ciphers numbers\n"
        "--ciphers <cipherList\n"
        "                        - Example cipher numbers:\n"
        "                        - '53' TLS_RSA_WITH_AES_256_CBC_SHA\n"
        "                        - '47' TLS_RSA_WITH_AES_128_CBC_SHA\n"
        "                        - '10' SSL_RSA_WITH_3DES_EDE_CBC_SHA\n"
        "                        - '5'  SSL_RSA_WITH_RC4_128_SHA\n"
        "                        - '4'  SSL_RSA_WITH_RC4_128_MD5\n"
        "-C <caFile>             - Path to certificate authority file\n"
        "--ca <caFile>\n"
        "-d                      - Disable server certicate name/addr chk\n"
        "--no-name-check\n"
        "-h                      - Help, print usage and exit\n"
        "--help\n"
        "-k <keyLen>             - RSA keyLen (if using client auth)\n"
        "--rsa-key-len\n"
        "                        - Must be one of 1024, 2048 or 4096\n"
        "-n <numNewSessions>     - Num of new (full handshake) sessions\n"
        "--handshakes <numNewSessions>\n"
        "-p <serverPortNum>      - Port number for DTLS server\n"
        "--port <serverPortNum>\n"
        "-r <numResumedSessions> - Num of resumed DTLS sesssions\n"
        "--resumed <numResumedSessions>\n"
        "-s <serverIpAddress>    - IP address of server machine/interface\n"
        "--server <serverIpAddress>\n"
# ifdef DTLS_PACKET_LOSS_TEST
        "-l <value>              - Reciprocal of packet loss probability\n"
        "--packet-loss <value>\n"
        "                          (for packet loss simulation tests)\n"
# endif /* DTLS_PACKET_LOSS_TEST */
# ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
        "-x                      - Run test, where the client tries to change\n"
        "                          the cipher spec during a re-handshake and\n"
        "                          the CHANGE_CIPHER_SPEC message is lost.\n"
        "--drop-change-cipher-spec\n"
# endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
        "--no-cert               - Unset client certificate\n"
        "--cert <certificateFile>\n"
        "                        - Path to client certificate file\n"
        "--key <privateKeyFile>  - Path to client private key file\n"
        "--keytype <loadKeyMethod>\n"
        "                        - Specify format of client certificate:\n"
        "                          any (detect key and signature type)\n"
        "                          rsa (for RSA keys)\n"
        "                          ec (for EC keys ECDSA signature)\n"
        "                          ecrsa (for EC keys with RSA signature)\n"
        "\n"
        "where -s is a required option (i.e. has no current default, and\n"
        "serverPortNum is usually 443 or 4433. The cipherList is a comma separated list\n"
        "of cipher numbers to propose.  It should NOT contain any spaces.\n\n");

    printf("Common ciphers and the cipher number to use in the cipherList:\n"
        "    53 TLS_RSA_WITH_AES_256_CBC_SHA\n"
        "    47 TLS_RSA_WITH_AES_128_CBC_SHA\n"
        "    10 SSL_RSA_WITH_3DES_EDE_CBC_SHA\n"
        "     5 SSL_RSA_WITH_RC4_128_SHA\n"
        "     4 SSL_RSA_WITH_RC4_128_MD5\n");
}

/* Returns number of cipher numbers found, or -1 if an error. */
static int32 parse_cipher_list(char *cipherListString,
    psCipher16_t cipher_array[],
    uint32 size_of_cipher_array)
{
    int32 numCiphers, cipher;
    char *endPtr;

    /* Convert the cipherListString into an array of cipher numbers. */
    numCiphers = 0;
    while (cipherListString != NULL)
    {
        cipher = (int32) strtol(cipherListString, &endPtr, 10);
        if (endPtr == cipherListString)
        {
            printf("The remaining cipherList has no cipher numbers - '%s'\n",
                cipherListString);
            return -1;
        }
        else if (size_of_cipher_array <= numCiphers)
        {
            printf("Too many cipher numbers supplied.  limit is %d\n",
                size_of_cipher_array);
            return -1;
        }
        else
        {
            cipher_array[numCiphers++] = cipher;
            if (*endPtr == '\0')
            {
                break;
            }
            else if (*endPtr != ',')
            {
                printf("\n");
                return -1;
            }

            cipherListString = endPtr + 1;
        }
    }

    return numCiphers;
}

/* Return 0 on good set of cmd options, return -1 if a bad cmd option is
   encountered OR a request for help is seen (i.e. '-h' option). */
static int32 process_cmd_options(int32 argc, char **argv)
{
    int optionChar, key_len, numCiphers;
    char *cipherListString;

    /* Set some default options: */
    memset(g_cipher, 0, sizeof(g_cipher));
    memset(g_ip,     0, sizeof(g_ip));
    memset(g_path,   0, sizeof(g_path));

    strcpy(g_ip,          "127.0.0.1");
    g_ciphers            = 1;
    g_cipher[0]          = 47;
    g_disableCertNameChk = 0;
    g_key_len            = 2048;
    g_new                = 1;
    g_port               = 4433;
    g_resumed            = 1;

    /* External certificate validation not supported with DTLS client */
    g_enable_ext_cv_sig_op = 0;

    opterr = 0;

    const char *optstring = "C:c:dhk:n:p:r:s:l:x";

#ifdef USE_GETOPT_LONG
#define ARG_NO_CERT 1
#define ARG_CERT 2
#define ARG_KEY 3
#define ARG_KEYTYPE 4

    static struct option long_options[] =
    {
        {"ciphers", required_argument, NULL, 'c'},
        {"ca", required_argument, NULL, 'C'},
        {"no-name-check", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"rsa-key-len", required_argument, NULL, 'k'},
        {"handshakes", required_argument, NULL, 'n'},
        {"port", required_argument, NULL, 'p'},
        {"resumed", required_argument, NULL, 'r'},
        {"server", required_argument, NULL, 's'},
        {"packet-loss", required_argument, NULL, 'l'},
        {"drop-change-cipher-spec", no_argument, NULL, 'x'},
        {"no-cert", no_argument, NULL, ARG_NO_CERT},
        {"cert", required_argument, NULL, ARG_CERT},
        {"key", required_argument, NULL, ARG_KEY},
        {"keytype", required_argument, NULL, ARG_KEYTYPE},
        {0, 0, 0, 0}
    };

    int opt_index = 0;

    while ((optionChar = getopt_long(argc, argv, optstring, long_options, &opt_index)) != -1)
#else
    while ((optionChar = getopt(argc, argv, optstring)) != -1)
#endif
    {
        switch (optionChar)
        {
        case '?':
            return -1;

        case 'C':
            g_clientconfig.ca_file = optarg;
            clientconfigUseFileKeys();
            break;

        case 'c':
            /* Convert the cipherListString into an array of cipher numbers. */
            cipherListString = optarg;
            numCiphers = parse_cipher_list(cipherListString, g_cipher, 16);
            if (numCiphers <= 0)
            {
                return -1;
            }

            g_ciphers = numCiphers;
            break;

        case 'd':
            g_disableCertNameChk = 1;
            break;

        case 'h':
            return -1;

        case 'k':
            key_len = atoi(optarg);
            if ((key_len != 1024) && (key_len != 2048) && (key_len != 3072)
                && (key_len != 4096))
            {
                printf("-k option must be followed by a key_len whose value "
                    " must be 1024, 2048, 3072 or 4096\n");
                return -1;
            }

            g_key_len = key_len;
            break;

        case 'n':
            g_new = atoi(optarg);
            break;

        case 'p':
            g_port = atoi(optarg);
            break;

        case 'r':
            g_resumed = atoi(optarg);
            break;

        case 's':
            strncpy(g_ip, optarg, 15);
            break;

# ifdef DTLS_PACKET_LOSS_TEST
        case 'l':
            packet_loss_prob = atoi(optarg);
            if (packet_loss_prob < 0)
            {
                printf("invalid -l option\n");
                return -1;
            }
            if (packet_loss_prob > 0)
            {
                printf("Client simulating packet loss with probability 1/%d\n",
                    packet_loss_prob);
            }
            break;

#  ifdef DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
        case 'x':
            test_lost_cipherspec_change_rehandshake = 1;
            break;
#  endif /* DTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE */
# endif  /* DTLS_PACKET_LOSS_TEST */

#ifdef USE_GETOPT_LONG
/* Additional options not supported through short arguments */

        case ARG_CERT:
            g_clientconfig.cert_file = optarg;
            clientconfigUseFileKeys();
            break;

        case ARG_NO_CERT:
            g_clientconfig.cert_file = NULL;
            g_clientconfig.privkey_file = optarg;
            clientconfigUseFileKeys();
            break;

        case ARG_KEY:
            g_clientconfig.privkey_file = optarg;
            clientconfigUseFileKeys();
            break;

        case ARG_KEYTYPE:
            if (strcmp("any", optarg) == 0) {
                g_clientconfig.load_key = &loadKeysFromFile;
            } else if (strcmp("rsa", optarg) == 0) {
                g_clientconfig.load_key = &loadRsaKeysFromFile;
            } else if (strcmp("ec", optarg) == 0) {
                g_clientconfig.load_key = &loadECDH_ECDSAKeysFromFile;
            } else if (strcmp("ecrsa", optarg) == 0) {
                g_clientconfig.load_key = &loadECDHRsaKeysFromFile;
            } else {
                printf("Invalid option: %s\n", optarg);
                return -1;
            }

            g_clientconfig.loadKeysFromMemory = 0;
            break;
#endif /* USE_GETOPT_LONG */
        }
    }

    return 0;
}


/******************************************************************************/
/*
    Main routine. Initialize SSL keys and structures, and make two DTLS
    connections, the first with a blank session Id, and the second with
    a session ID populated during the first connection to do a much faster
    session resumption connection the second time.
 */
int32 main(int32 argc, char **argv)
{
    int32 rc;
    sslKeys_t *keys;
    sslSessionId_t *sid;
    int32 rv;

# ifdef WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(1, 1), &wsaData);
# endif

    clientconfigInitialize();

    if ((rc = matrixSslOpen()) < 0)
    {
        _psTrace("MatrixSSL library init failure.  Exiting\n");
        return rc;
    }
    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        matrixSslClose();
        _psTrace("MatrixSSL library key init failure.  Exiting\n");
        return -1;
    }

    if (0 != process_cmd_options(argc, argv))
    {
        usage();
        clientconfigFree();
        return 0;
    }
    printf("client https://%s:%d%s "
        "new:%d resumed:%d keylen:%d nciphers:%d\n",
        g_ip, g_port, g_path, g_new, g_resumed, g_key_len,
        g_ciphers);

    if (!clientconfigLoadKeys(keys))
    {
        return EXIT_FAILURE;
    }

    rv = MATRIXSSL_ERROR;

    matrixSslNewSessionId(&sid, NULL);
    printf("=== %d new connections ===\n", g_new);
    for (rc = 0; rc < g_new; rc++)
    {
        matrixSslNewSessionId(&sid, NULL);
        rv = dtlsClientConnection(keys, sid);
        if (rv < 0)
        {
            goto out_main;
        }
        /* Leave the final sessionID for resumed connections */
        if (rc + 1 < g_new)
        {
            matrixSslDeleteSessionId(sid);
        }
    }
    if (g_new)
    {
        printf("\n");
    }



    printf("=== %d resumed connections ===\n", g_resumed);
    for (rc = 0; rc < g_resumed; rc++)
    {
        rv = dtlsClientConnection(keys, sid);
        if (rv < 0)
        {
            goto out_main;
        }
    }

out_main:
    matrixSslDeleteSessionId(sid);
    matrixSslDeleteKeys(keys);
    matrixSslClose();

    clientconfigFree();

# ifdef WIN32
    _psTrace("Press any key to close");
    getchar();
# endif

    if (rv == 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

/******************************************************************************/
/*
    Close a socket and free associated SSL context and buffers
    An attempt is made to send a closure alert
 */
static void closeConn(sslDtls_t *dtls, SOCKET fd)
{
    ssl_t *ssl;
    unsigned char *buf;
    int32 len, ret;

    ssl = dtls->ssl;

    /* Quick attempt to send a closure alert, don't worry about failure */
    if (matrixSslEncodeClosureAlert(ssl) >= 0)
    {
        if ((len = matrixDtlsGetOutdata(ssl, &buf)) > 0)
        {
            ret = (int32) sendto(fd, buf, len, 0, (struct sockaddr *) &dtls->addr,
                sizeof(struct sockaddr_in));
            if (ret == -1)
            {
                /* sendto failed, but we don't care about that because
                   the connection was closing. Maybe server was faster
                   in closing the connection down. */
            }
            matrixDtlsSentData(ssl, len);
        }
    }
    psFree(dtls, NULL);
    matrixSslDeleteSession(ssl);
    close(fd);
}

/******************************************************************************/
/*
    Example callback to do additional certificate validation.
    If this callback is not registered in matrixSslNewService,
    the connection will be accepted or closed based on the status flag.
 */
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
# ifndef USE_ONLY_PSK_CIPHER_SUITE

    /* Example to allow anonymous connections based on a define */
    if (alert > 0)
    {
        if (ALLOW_ANON_CONNECTIONS)
        {
            _psTraceStr("Allowing anonymous connection for: %s.\n",
                cert->subject.commonName);
            return SSL_ALLOW_ANON_CONNECTION;
        }
        _psTrace("Certificate callback returning fatal alert\n");
        return alert;
    }

    psTraceStrDtls("Validated cert for: %s.\n", cert->subject.commonName);

# endif /* !USE_ONLY_PSK_CIPHER_SUITE */
    return PS_SUCCESS;
}

#else
/******************************************************************************/
/*
    Stub main for compiling without dtls and client enabled
 */
int32 main(int32 argc, char **argv)
{
    printf("USE_DTLS and USE_CLIENT_SIDE_SSL must be enabled in " \
        "matrixsslConfig.h at build time to run this application\n");
    return -1;
}
#endif /* USE_DTLS && USE_CLIENT_SIDE_SSL */

/******************************************************************************/

