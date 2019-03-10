/**
 *      @file    coreApi.h
 *      @version $Format:%h%d$
 *
 *      Prototypes for the Matrix core public APIs.
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

#ifndef _h_PS_COREAPI
# define _h_PS_COREAPI

# ifdef __cplusplus
extern "C" {
# endif

# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <coreConfig.h> /* Must be first included */
# else
#  include "coreConfig.h" /* Must be first included */
# endif
# include "osdep-types.h"
# include "list.h"
# include "psmalloc.h"
# include "osdep_stdio.h"

/******************************************************************************/
/*
    macros for function definitions.
 */
# ifndef PS_C99
#  if defined(__cplusplus) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#   define PS_C99(X)
#  else
/** C99 only code.
  Produce output for compiler that is only processed if compiler is in C99
  mode or later. This macro can be used to use security enhancing constructs
  in C99 without losing backwards compatibility with ANSI-C or C++. */
#   define PS_C99(X) X
#  endif
# endif
#ifndef PS_AT_LEAST
/** Pointer needs to point at least x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.
 */
#define PS_AT_LEAST(x) PS_C99(static) x
#endif /* PS_AT_LEAST */
#ifndef PS_AT_LEAST_EXPR
/** Pointer needs to point at least x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.

    The limit is expressed as expression of other inputs to the function.

    @note: Due to implementation, the value of expr needs to be at least 1. */
#define PS_AT_LEAST_EXPR(x) PS_C99(static) 1
#endif /* PS_AT_LEAST_EXPR */
#ifndef PS_EXACTLY
/** Pointer needs to point exactly x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.
 */
#define PS_EXACTLY(x) PS_C99(static) x
#endif /* PS_EXACTLY */
#ifndef PS_EXACTLY_EXPR
/** Pointer needs to point exactly x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.

    @note: Due to implementation, the value of expr needs to be at least 1. */
#define PS_EXACTLY_EXPR(x) PS_C99(static) 1
#endif /* PS_EXACTLY_EXPR */

/******************************************************************************/
/*
    psCore return codes
 */
# define PS_CORE_IS_OPEN     1

/******************************************************************************/
/*
    Universal return codes
 */
# define PS_SUCCESS          0
# define PS_FAILURE          -1
# define PS_FAIL             PS_FAILURE/* Just another name */

/*      NOTE: Failure return codes MUST be < 0 */
/*      NOTE: The range for core error codes should be between -2 and -29 */
# define PS_ARG_FAIL         -6       /* Failure due to bad function param */
# define PS_PLATFORM_FAIL    -7       /* Failure as a result of system call error */
# define PS_MEM_FAIL         -8       /* Failure to allocate requested memory */
# define PS_LIMIT_FAIL       -9       /* Failure on sanity/limit tests */
# define PS_UNSUPPORTED_FAIL -10      /* Unimplemented feature error */
# define PS_DISABLED_FEATURE_FAIL -11 /* Incorrect #define toggle for feature */
# define PS_PROTOCOL_FAIL    -12      /* A protocol error occurred */
# define PS_TIMEOUT_FAIL     -13      /* A timeout occurred and MAY be an error */
# define PS_INTERRUPT_FAIL   -14      /* An interrupt occurred and MAY be an error */
# define PS_PENDING          -15      /* In process. Not necessarily an error */
# define PS_EAGAIN           -16      /* Try again later. Not necessarily an error */
# define PS_OUTPUT_LENGTH    -17      /* Output length negotiation:
                                         output buffer is too small. */
# define PS_HOSTNAME_RESOLUTION -18   /* Cannot resolve host name. */
# define PS_CONNECT -19               /* Cannot connect to remote host. */
# define PS_INSECURE_PROTOCOL   -20   /* The operation needs to use insecure protocol.
                                         The caller needs to accept use of insecure
                                         protocol. */
# define PS_VERIFICATION_FAILED -21   /* Signature verification failed. */
# define PS_TRUE     1
# define PS_FALSE    0

/******************************************************************************/
/* Public structures */
/******************************************************************************/
/*
    psBuf_t
    Empty buffer:
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   |.|.|.|.|.|.|.|.|.|.|.|.|.|.|.|.|
     ^
     \end
     \start
     \buf
     size = 16
     len = (end - start) = 0

    Buffer with data:

     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   |.|.|a|b|c|d|e|f|g|h|i|j|.|.|.|.|
     ^   ^                   ^
 |   |                   \end
 |   \start
     \buf
    size = 16
    len = (end - start) = 10

    Read from start pointer
    Write to end pointer
    Free from buf pointer
 */
typedef struct
{
    unsigned char *buf;     /* Pointer to the start of the buffer */
    unsigned char *start;   /* Pointer to start of valid data */
    unsigned char *end;     /* Pointer to first byte of invalid data */
    int32 size;             /* Size of buffer in bytes */
} psBuf_t;

/* Dynamically allocated automatically resizing psBuf_t. */
struct psDynBuf;
typedef struct psDynBuf psDynBuf_t;
struct psDynBuf
{
    psBuf_t buf;
    psPool_t *pool;
    int err;
    psDynBuf_t *master;
};
# define PS_DYNBUF_GROW 256 /* Usual grow amount. */

/* Buffer for parsing input. */
struct psParseBuf;
typedef struct psParseBuf psParseBuf_t;
/* The contents of parsebuf are exactly the same than psDynBuf_t.
   this allows them to share some of implementation. */
struct psParseBuf
{
    psBuf_t buf;
    psPool_t *pool;
    int err;
    psParseBuf_t *master;
};

/* psDynBuf or psParseBuf allocated from this pool
   is never freed automatically. */
extern psPool_t * const psStaticAllocationsPool;

/* Function definitions for Static and Dynamic Buffer API. */
# include "psbuf.h"

/******************************************************************************/

# ifdef MATRIX_USE_FILE_SYSTEM
#  define FILESYSTEM_CONFIG_STR "Y"
# else
#  define FILESYSTEM_CONFIG_STR "N"
# endif
#  define PSMALLOC_CONFIG_STR "N"
# ifdef USE_MULTITHREADING
#  define MULTITHREAD_CONFIG_STR "Y"
# else
#  define MULTITHREAD_CONFIG_STR "N"
# endif

# define PSCORE_CONFIG \
    "Y" \
    FILESYSTEM_CONFIG_STR \
    PSMALLOC_CONFIG_STR \
    MULTITHREAD_CONFIG_STR

/******************************************************************************/
/* Public APIs */
# include "osdep_time.h"
/******************************************************************************/

/* struct tm is standard for representing broken-down time in C89, C99 and
   POSIX.1 standards. The psBrokenDownTime_t is defined as an alias for
   struct tm for compatibility with possible non-standard compliant targets. */
typedef struct tm psBrokenDownTime_t;
/* time_t is a standard type for representing calendar time as a counter in
   C89, C99.
 */
typedef time_t psTimeSeconds_t;

PSPUBLIC int32      psCoreOpen(const char *config);
PSPUBLIC void       psCoreClose(void);
PSPUBLIC void       psBurnStack(uint32 len);
PSPUBLIC int32      memcmpct(const void *s1, const void *s2, size_t len);

PSPUBLIC void       psFreeAndClear(void *ptrptr, psPool_t *pool);

/******************************************************************************/
/*
    Public interface to functionality defined by functions in C89/C99 standards.
    These function may be substituted with OS/psdep.c in nonstandard
    systems.
*/

/* Return time in seconds since the epoch (1970-01-01 00:00:00)
   or (psTimeSeconds_t) -1 on error. */
PSPUBLIC psTimeSeconds_t psGetEpochTime(void);

/*
    Return broken-down time similar to gmtime(&time(NULL)). The function allows
    offset in seconds.
 */
PSPUBLIC int32      psGetBrokenDownGMTime(psBrokenDownTime_t *t,
                                          int offset);
/* Add specified value to broken down time. */
PSPUBLIC int32 psBrokenDownTimeAdd(psBrokenDownTime_t *res, int32 offset);
# define PS_BROKENDOWN_TIME_STR_LEN 16    /* Good until year 9999. */
# define PS_BROKENDOWN_TIME_IMPORT_LEN 12 /* Minimum proper time import format
                                             length. */
PSPUBLIC int32 psBrokenDownTimeStr(const psBrokenDownTime_t *t1,
                                   char (*string)[PS_BROKENDOWN_TIME_STR_LEN]);
PSPUBLIC int32 psBrokenDownTimeStrTwoDigitYear(const psBrokenDownTime_t *t,
        char (*string)[PS_BROKENDOWN_TIME_STR_LEN]);
# define PS_BROKENDOWN_TIME_IMPORT_STRICT_ZULU 1 /* Require Z as timezone. */
# define PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR 2 /* Use two digit year for
                                                    range 1950-2049. */
PSPUBLIC int32 psBrokenDownTimeImportSeconds(psBrokenDownTime_t *t,
                                             psTimeSeconds_t s);
PSPUBLIC int32 psBrokenDownTimeImport(
    psBrokenDownTime_t *t,
    const char *string, size_t time_string_len,
    unsigned int opts);
PSPUBLIC int psBrokenDownTimeCmp(const psBrokenDownTime_t *t1,
                                 const psBrokenDownTime_t *t2);

/******************************************************************************/
/*
    Public interface to OS-dependant core functionality

    OS/osdep.c must implement the below functions
 */
PSPUBLIC int32      psGetEntropy(unsigned char *bytes, uint32 size,
                                 void *userPtr);

PSPUBLIC int32      psGetTime(psTime_t *t, void *userPtr);
PSPUBLIC int32      psDiffMsecs(psTime_t then, psTime_t now, void *userPtr);

/* psCompareTime is no longer used */
PSPUBLIC int32      psCompareTime(psTime_t a, psTime_t b, void *userPtr);

# ifdef MATRIX_USE_FILE_SYSTEM
#  ifdef USE_POSIX
PSPUBLIC psRes_t    psGetFileBufFp(psPool_t *pool, FILE *fp,
                                   unsigned char **buf, psSizeL_t *bufLen);
#  endif /* USE_POSIX */
PSPUBLIC psRes_t    psGetFileBuf(psPool_t *pool, const char *fileName,
                                 unsigned char **buf, psSizeL_t *bufLen);
# endif /* MATRIX_USE_FILE_SYSTEM */

# ifdef USE_MULTITHREADING
#  define PS_SHARED   0x1
PSPUBLIC int32_t    psCreateMutex(psMutex_t *mutex, uint32_t flags);
PSPUBLIC void       psLockMutex(psMutex_t *mutex);
PSPUBLIC void       psUnlockMutex(psMutex_t *mutex);
PSPUBLIC void       psDestroyMutex(psMutex_t *mutex);
# else
/** @note These are defines rather than inline functions because it allows
   the caller to not allocate a mutex that will never be used. */
#  define psCreateMutex(A, B) (PS_SUCCESS)
#  define psLockMutex(A)      do { } while (0)
#  define psUnlockMutex(A)    do { } while (0)
#  define psDestroyMutex(A)
# endif /* USE_MULTITHREADING */

/* Convert memory bytes to string.
   Characters outside ASCII and non-printable characters are replaced
   with dot characters.
   The resulting string s is exactly len bytes long and it is not
   zero-terminated. */
PSPUBLIC void psMem2Str(char *s, const unsigned char *b, uint32 len);

/* Create hexadecimal trace of packet or bianry data.
   This function is an internal helper function for debug printing
   hexadecimal data such as network packets or protocol messages. */
void psTraceBytes(const char *tag, const unsigned char *p, int l);

/******************************************************************************/
/*
    Internal list helpers
 */
extern int32 psParseList(psPool_t *pool, const char *list, const char separator,
                         psList_t **items);
extern void psFreeList(psList_t *list, psPool_t *pool);

/* Identifiers to describe type of string contained in char or
   unsigned char array. */
typedef enum
{
    /* Note: The values intentionally match ASN.1 BER/DER string type tags. */
    PS_STRING_UTF8_STRING = 12,
    PS_STRING_NUMERIC_STRING = 18,
    PS_STRING_PRINTABLE_STRING = 19,
    PS_STRING_TELETEX_STRING = 20,
    PS_STRING_VIDEOTEX_STRING = 21,
    PS_STRING_IA5_STRING = 22,
    PS_STRING_GRAPHIC_STRING = 25,
    PS_STRING_VISIBLE_STRING = 26,
    PS_STRING_GENERAL_STRING = 27,
    PS_STRING_UNIVERSAL_STRING = 28,
    PS_STRING_CHARACTER_STRING = 29,
    PS_STRING_BMP_STRING = 30, /* This is BMP (Basic Multilingual Plane)
                                  string, i.e. 2 byte characters only.
                                  Use #PS_STRING_UTF16_STRING instead if
                                  any UTF-16 encoding is allowed. */
    PS_STRING_CHAR_STRING = 256,  /* Input is represented as C string. */
    PS_STRING_WCHAR_STRING = 257, /* Input is represented as wchar_t string. */
    PS_STRING_UTF16_STRING = 258,  /* Input is represented as UTF-16 encoding.
                                    */
} psStringType_t;

/* Option for strictly checking input to UTF8 String.
   The option is not currently implemented, and the function
   psGetUtf8String() will always fail if you attempt to use the option. */
# define PS_STRING_STRICT 1
/* Uses sequence \0\0 as terminator for string. */
# define PS_STRING_DUAL_NIL 2

/******************************************************************************/
/*
    Helper function for usual string conversions.
    The current version allows conversion of
    PS_STRING_NUMERIC_STRING, PS_STRING_PRINTABLE_STRING, PS_STRING_BMP_STRING
    to UTF-8. In case conversion succeeds with PS_SUCCESS, *output will
    point to a newly allocated string. The allocated string needs to be freed
    with psFree(). The string will have terminating \0.
 * output_len will be written string length not counting terminating \0.
    output_len can be provided as NULL if user wants to use functions like
    Strlen() to obtain length of the string instead.
 */
PSPUBLIC int32 psToUtf8String(psPool_t *pool,
                              const unsigned char *input, size_t input_len,
                              psStringType_t input_type,
                              unsigned char **output, size_t *output_len,
                              int opts);

/*
    Helper function for usual string conversions.
    The current version allows conversion of
    PS_STRING_NUMERIC_STRING, PS_STRING_PRINTABLE_STRING, PS_STRING_BMP_STRING
    to UTF-16 (BE). This function produces unsigned char (generic octet string)
    output for compatibility with other functions although the output length
    is always multiple of two.
    The string will have terminating \0\0.
    output_len will be written string length not counting terminating \0\0.
    output_len can be provided as NULL.
 */
PSPUBLIC int32 psToUtf16String(psPool_t *pool,
                              const unsigned char *input, size_t input_len,
                              psStringType_t input_type,
                              unsigned char **output, size_t *output_len,
                              int opts);

/*
    Helper function for usual string conversions.
    The current version allows conversion of
    PS_STRING_NUMERIC_STRING, PS_STRING_PRINTABLE_STRING, PS_STRING_BMP_STRING
    to UTF-32 (BE). This function produces unsigned char (generic octet string)
    output for compatibility with other functions although the output length
    is always multiple of four.
    The string will have terminating \0\0\0\0.
    output_len will be written string length not counting terminating \0\0\0\0.
    output_len can be provided as NULL.
 */
PSPUBLIC int32 psToUtf32String(psPool_t *pool,
                              const unsigned char *input, size_t input_len,
                              psStringType_t input_type,
                              unsigned char **output, size_t *output_len,
                              int opts);

/*
    Convert an ASCII hex representation to a binary buffer.
    Decode enough data out of 'hex' buffer to produce 'binlen' bytes in 'bin'
    Two digits of ASCII hex map to the high and low nybbles (in that order),
    so this function assumes that 'hex' points to 2x 'binlen' bytes of data.
    Return the number of bytes processed from hex (2x binlen) or < 0 on error.
*/
PSPUBLIC int32 psHexToBinary(unsigned char *hex,
        unsigned char *bin,
        int32 binlen);

/*
    Each bin char converts to two hex values.  High four bits for first hex
    value and low four for second in pair.
*/
PSPUBLIC int32 psBinaryToHex(unsigned char *bin,
        int32 binLen,
        char *hex);

/*
    Case insignificant comparison of two strings. Case insignificance is
    only effective for ASCII characters.
*/
PSPUBLIC int32 psStrCaseCmp(const char *s1, const char *s2);

# ifdef __cplusplus
}
# endif

/* Additional extended functionality, that is currently not intended to be
   used directly. */
#include "private/coreApiExt.h"

#endif /* _h_PS_COREAPI */
/******************************************************************************/
