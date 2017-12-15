/* psnet.h
 *
 * Basic sockets based networking support.
 */

/*****************************************************************************
* Copyright (c) 2007-2017 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*****************************************************************************/

#ifndef INCLUDE_GUARD_PSNET_H
#define INCLUDE_GUARD_PSNET_H

#include <stddef.h>
#include <unistd.h>
#ifdef __cplusplus
extern "C" {
#endif

#ifdef USE_PS_NETWORKING
/* Use sockets to connect external host and use HTTP protocol to fetch external
   resource(s). These APIs are optional, because the smallest embedded
   devices do not have standard networking APIs. */

struct psSocketFunctions; /* Forward reference. */
struct psSocketTls;       /* Extra information of TLS socket. */

typedef enum
{
    PS_SOCKET_UNKNOWN,
    PS_SOCKET_STREAM,
    PS_SOCKET_DATAGRAM,
    PS_SOCKET_TLS
} psSocketType_t;

typedef struct
{
# ifdef IMPLEMENT_MATRIXSSL_PSNET
    int fd;
# else
    int internal_fd; /* Use prefix internal_ to discourage access. */
# endif
    const struct psSocketFunctions *func;
    /* Socket type */
    psSocketType_t type;
    union
    {
        struct psSocketTls *tls;
    } extra;
} psSocket_t;
# define PS_INVALID_SOCKET   (NULL)

/* Select access mode and other options for socket.
   Note: Depending on option, function and operating system, specifying some of
   these options may affect the executing function only or affect also
   subsequent socket operations. */
# define PS_SOCKET_OPTION_NONE 0                 /* No options. */
# define PS_SOCKET_OPTION_BLOCK 1                /* Set socket to blocking mode. */
# define PS_SOCKET_OPTION_NONBLOCK 2             /* Set socket to non-blocking mode. */
# define PS_SOCKET_OPTION_NODELAY 4              /* Set nodelay option to socket. */
# define PS_SOCKET_OPTION_DELAY 8                /* Enable nagle algorithm. */
# define PS_SOCKET_OPTION_DATAGRAM 16            /* Use datagram protocol (UDP).
                                                    TCP / stream protocol is the default. */
/* These are only for psSocketGetOptions(). */
# define PS_SOCKET_OPTION_STATUS_CONNECTED 65536 /* Connected (not yet supported). */
# define PS_SOCKET_OPTION_STATUS_ERROR 131072    /* The socket is inoperable. */
typedef uint32 psSocketOptions_t;

/* send/recv larger than this will need to be performed in multiple parts. */
# define PS_MAX_SOCKET_SIZE ((~(size_t) 0) >> 1)

/******************************************************************************/
/* Structure for extending psUrlInteract() API. */
struct sockaddr;
struct addrinfo;
typedef struct psSocketFunctions
{
    /* The API matches POSIX standards for interaction with socket,
       with sockfd replace with pointer to psSocket_t.
       socklen_t is replaced with size_t. */
    ssize_t (*psWrite)(psSocket_t *sock, const void *buf, size_t len);
    ssize_t (*psRead)(psSocket_t *sock, void *buf, size_t len);
    int (*psIsConnected)(psSocket_t *sock);
    int (*psIoctl)(psSocket_t *sock, unsigned long request, void *opt_argp);
    int (*psSetsockopt)(psSocket_t *sock, int level, int optname,
                        const void *optval, size_t optlen);
    int (*psGetsockopt)(psSocket_t *sock, int level, int optname,
                        void *optval, size_t *optlen);
    int (*psFcntl)(psSocket_t *sock, int cmd, int opt_argp);
    /* The provide sock only has func filled in. */
    int (*psSocket)(psSocket_t *sock, int domain, psSocketType_t type, int protocol,
                    void *typespecific);
    int (*psShutdown)(psSocket_t *sock, int how);
    int (*psClose)(psSocket_t *sock);
    int (*psConnect)(psSocket_t *sock, const struct sockaddr *addr,
                     size_t addrlen);
    int (*psBind)(psSocket_t *sock, const struct sockaddr *addr,
                  size_t addrlen);
    int (*psListen)(psSocket_t *sock, int backlog);
    int (*psAccept)(psSocket_t *listen_sock,
                    struct sockaddr *addr, size_t *addrlen);
    /* Note: no socket for addres resolution functions. */
    int (*psGetaddrinfo)(const char *node, const char *service,
                         const struct addrinfo *hints,
                         struct addrinfo **res);
    void (*psFreeaddrinfo)(struct addrinfo *res);
    int (*psFd)(const psSocket_t *sock);
    ssize_t (*psPeek)(psSocket_t *sock, void *buf, size_t len);
} psSocketFunctions_t;

/*
   Get default implementation of psSocketFunctions_t. This
   implementation only provides unencrypted networking.
 */
const psSocketFunctions_t *psGetSocketFunctionsDefault(void);

/*
    Open an outgoing blocking socket connection to a remote host and port.
    The host can be expressed as DNS name or IP address, and port can be
    either number (represented as a C string) or name.
    This function is used for "stream" connections like HTTP or HTTPS
    protocol.

    @param hostname IPv4 or IPv6 address or name of the target host
    @param port service name or port number
    @param socket_p Will be written with the resulting socket handle or
    INVALID_SOCKET on failure. This handle will be used to interact with
    the socket using platform dependent function calls.
    @param state Must be NULL currently. In future this parameter can be
    used to provide additional information to psUrlInteract and to allow
    asynchronous requests.

    @retval PS_SUCCESS On successful execution of the function.
    @retval PS_ARG_FAIL Invalid arguments to the function.
    @retval PS_HOSTNAME_RESOLUTION Could not resolve hostname or
    service port.
    @retval PS_CONNECT Could not connect to the peer.
 */
PSPUBLIC int32 psSocketConnect(const char *hostname, const char *port,
                               psSocketOptions_t opts,
                               psSocketType_t type,
                               void *typespecific,
                               const psSocketFunctions_t *func,
                               psSocket_t **socket_p);

/*
    Open a socket based on pre-existing file descriptor (e.g. connection).
    This function is used for "stream" connections like HTTP or HTTPS
    protocol.

    @param fd file descriptor
    @param socket_p Will be written with the resulting socket handle or
    INVALID_SOCKET on failure. This handle will be used to interact with
    the socket using platform dependent function calls.

    @retval PS_SUCCESS On successful execution of the function.
    @retval PS_ARG_FAIL Invalid arguments to the function.
    @retval PS_HOSTNAME_RESOLUTION Could not resolve hostname or
    service port.
    @retval PS_CONNECT Could not connect to the peer.
 */
PSPUBLIC int32 psSocketConnected(int fd,
                                 psSocketOptions_t opts,
                                 psSocketType_t type,
                                 void *typespecific,
                                 const psSocketFunctions_t *func,
                                 psSocket_t **socket_p);

/*
    Socket apis
 */
PSPUBLIC int32 psSocketListen(const char *hostname, const char *port,
                              int max_backlog, psSocketOptions_t opts,
                              psSocketType_t type,
                              void *typespecific,
                              const psSocketFunctions_t *func,
                              psSocket_t **socketListen_p);
PSPUBLIC int32 psSocketAccept(psSocket_t *listenfd, psSocketOptions_t opts,
                              psSocket_t **socketAccept_p);
PSPUBLIC void psSocketShutdown(psSocket_t *sock,
                               psSocketOptions_t opts);
PSPUBLIC int32 psSocketReadAppendBuf(psSocket_t *sock, psBuf_t *in,
                                     psSocketOptions_t opts);
PSPUBLIC ssize_t psSocketReadData(psSocket_t *sock, void *data,
                                  size_t len, psSocketOptions_t opts);
PSPUBLIC int32 psSocketPeekAppendBuf(psSocket_t *sock, psBuf_t *in,
                                     psSocketOptions_t opts);
PSPUBLIC ssize_t psSocketPeekData(psSocket_t *sock, void *data,
                                  size_t len, psSocketOptions_t opts);
PSPUBLIC int32 psSocketReadBufferSequence(psSocket_t *sock,
                                          void *response,
                                          size_t *responseLen,
                                          psBuf_t *inputbuf_p,
                                          int prefetch,
                                          psSocketOptions_t opts);
PSPUBLIC ssize_t psSocketWriteData(psSocket_t *sock, const void *data,
                                   size_t len, psSocketOptions_t opts);
PSPUBLIC int32 psSocketWriteShiftBuf(psSocket_t *sock, psBuf_t *out,
                                     psSocketOptions_t opts);
PSPUBLIC int32 psSocketSetOptions(psSocket_t *sock, psSocketOptions_t opts);
PSPUBLIC void psSocketSetBlock(psSocket_t *sock);
PSPUBLIC void psSocketSetNonblock(psSocket_t *sock);
PSPUBLIC void psSocketSetNodelay(psSocket_t *sock);
PSPUBLIC void psSocketSetDelay(psSocket_t *sock);
PSPUBLIC psSocketOptions_t psSocketGetOptions(psSocket_t *sock);
PSPUBLIC int psSocketGetFd(psSocket_t *sock);

/* Structure for extending psUrlInteract() API.
   Currently only used for psSocketFunctions_t pointer. */
typedef struct
{
    /* Describe socket interface. */
    psSocketType_t type;
    void *typespecific;
    const psSocketFunctions_t *func;
} psUrlInteractState_t;

/* Invoke specified URL (i.e. web address).

   The function allows passing in addition values for HTTP request and response.

   @param method String "GET" or "POST" etc. (see RFC 2616)
   @param url String like "http://target.addr.com:port/index2.php"
   @param headers_names_in List of strings containing extra header field names
   @param headers_values_in List of strings containing extra header field values
   @param headers_in_count Number of entries in headers_names_in and
   headers_values_in
   @param request Pointer to binary data to send to method "POST" or other
   HTTP methods requiring data to be sent. For methods not not sending data,
   provide NULL for request and requestLen.
   @param requestLen Length of binary data to send in bytes.
   @param headers_names_out List of interesting response fields.
   @param headers_values_out List of response value. The fields found in server
   response have their values replaced with server response.
   @param headers_values_out_length List of lengths of response values.
   The values returned are adjusted to the actual length returned. The
   length needs to include space also for zero termination.
   @param headers_out_count Number of entries in headers_names_out,
   headers_values_out and headers_values_out_length.
   @param response Pointer to binary data to send to method "POST".
      If there is no data to send, provide zero.
   @param responseLen Pointer to response length. On input the size of
   memory available, on output the size actually used or amount of output
   that would have been needed.
   @param state Must be NULL currently. In future this parameter can be
   used to provide additional information to psUrlInteract and to allow
   asynchronous requests.

   @retval PS_SUCCESS On successful execution of the function. The
   response has been filled with values from HTTP server 200 OK response.
   @retval 100-505 If the HTTP service responded to the request with
   return code that is not 200, then the return code and no response will be
   returned.
   @retval PS_ARG_FAIL Invalid arguments to the function.
   @retval PS_HOSTNAME_RESOLUTION Could not resolve hostname or
   service port.
   @retval PS_CONNECT Could not connect to the peer.
   @retval PS_PROTOCOL_FAIL The peer did not respond correctly to the request.

   @note This function currently does not support https URLs. The function is
   intended for retrieving resources that use http URLs such as CRL or OCSP.
   (The MatrixSSL provides other functions to deal with SSL/TLS based protocols,
   such as https.)
 */

PSPUBLIC int32 psUrlInteract(const char *method,
                             const char *url,
                             const char **headers_names_in,
                             const char **headers_values_in,
                             int headers_in_count,
                             void *request,
                             size_t requestLen,
                             const char **headers_names_out,
                             char **headers_values_out,
                             size_t *headers_values_out_length,
                             int headers_out_count,
                             void *response, size_t *responseLen,
                             psUrlInteractState_t *state);

/* Process HTTP response with input from specified file handle.
   This function implements part of psUrlInteract, where HTTP response
   is received.
 */
PSPUBLIC int32 psUrlInteractProcessHTTPResponse(
    psPool_t *pool,
    psSocket_t *sock,
    const char **headers_names_out,
    char **headers_values_out,
    size_t *headers_values_out_length,
    int headers_out_count,
    void *response,
    size_t *responseLen,
    psUrlInteractState_t *state);

#endif /* USE_PS_NETWORKING */

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_GUARD_PSNET_H */

/* end of file psnet.h */
