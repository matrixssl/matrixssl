/**
 *      @file    psPrnf.h
 *      @version $Format:%h%d$
 *
 *  Extended formatting: Allow complex objects to be printed with
 *  printf() style formatting.
 *
 *  These macros and functions can be used in programs using SafeZone
 *  and MatrixSSL software or related software components.
 */
/*
 *      Copyright (c) 2017 INSIDE Secure Corporation
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

#ifndef _h_PS_CORECONFIG
# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <coreConfig.h> /* Must be first included */
# else
#  include "coreConfig.h" /* Must be first included */
# endif
#endif /* _h_PS_CORECONFIG */

#include "osdep-types.h"

/* Only needs stub psPool_t. */
#ifndef PS_POOL_T_DEFINED
#define PS_POOL_T_DEFINED
typedef int32 psPool_t;
#endif

#ifndef _h_PS_PRNF
#include <stdarg.h>
# define _h_PS_PRNF
# ifndef PS_NO_PRNF
#  define PS_PRNF_STRUCT_VARIABLE_LENGTH_MEMBER 1
#  ifdef __STDC_VERSION__
#   if __STDC_VERSION__ >= 199901L
#    undef PS_PRNF_STRUCT_VARIABLE_LENGTH_MEMBER
#   define PS_PRNF_STRUCT_VARIABLE_LENGTH_MEMBER /* empty */
#  endif
# endif

struct psPrnfStrNode
{
    struct psPrnfStrNode *next;
    char *str;
    
    char strstorage[PS_PRNF_STRUCT_VARIABLE_LENGTH_MEMBER];
};

typedef struct
{
    struct psPrnfStrNode *list;
    int err;
} psPrnf_t;

/** Extended format.

  Use this instead of "%s" formatting code to format using PSA_HEX() and other
  extended formats. */
#define PSF "%s"
#define PSFS_(x) #x
#define PSFS(x) PSFS_(x)
/** Extended format with length constraints.

    Provide constant integers to use as minimum and maximum length of resulting formatting.
    If input is shorter than the field, spaces will be added on left.
    If input is longer than the field, the field is truncated on right.

    @warning Truncation from right is not recommended for (big) integers, as it is not
             a common convention to truncate rightmost digits.

    Either minsz or maxsz can be omitted.
 */
#define PSFX(minsz, maxsz) "%" PSFS(minsz) "." PSFS(maxsz) "s"
/** Extended format with length constraints aligned left.

    Provide constant integers to use as minimum and maximum length of resulting formatting.
    If input is shorter than the field, spaces will be added on right.
    If input is longer than the field, the field is truncated on right.

    @warning Truncation from right is not recommended for (big) integers, as it is not
             a common convention to truncate rightmost digits.

    Either minsz or maxsz can be omitted.
 */
#define PSFLX(minsz, maxsz) "%-" PSFS(minsz) "." PSFS(maxsz) "s"
/** Check if formatting errors took place.

    The printing functions will allow some output even presence of errors, like NULL pointers
    or memory allocation failures. These issue will be repalced with place holders on formatted
    string. This macro allows to check if formatting error has been detected.
*/
#define PSPRNF_ERR() (psPrnfCtx.err)
/** Indefinite size string.

    Some functions accept this instead of size as identifier to request determination of size from
    string (using strlen()).
 */
#define PS_SIZE_STR (~(psSizeL_t)0)

/* Functions: intentionally undocumented, because these are invoked via
   macros. */
char *psPrnfDup(psPrnf_t *ctx, const char *src, psSizeL_t sz, const char *def);
char *psPrnfDupFree(psPrnf_t *ctx, char *src, psSizeL_t sz, const char *def);
char *psPrnfDup2(psPrnf_t *ctx, const char *src, psSizeL_t sz,
                 const char *src2, psSizeL_t sz2, const char *def);
char *psPrnfCopyDupFree(psPrnf_t *ctx, const char *src, psSizeL_t sz,
                        char *src2, psSizeL_t sz2,  const char *def);
char *psPrnfDupf(psPrnf_t *ctx, const char *def, const char *fmt, ...);
const char *psPrnfBool(psBool_t b);
const char *psPrnfStr(psPrnf_t *ctx, const char *str);
const char *psPrnfSStr(psPrnf_t *ctx, const char *str, psSizeL_t len);
const char *psPrnfQStr(psPrnf_t *ctx, const char *str);
const char *psPrnfHex(psPrnf_t *ctx, const unsigned char *hex, psSizeL_t len);
const char *psPrnfHex2(psPrnf_t *ctx, const unsigned char *hex, psSizeL_t len);
const char *psPrnfBase64(psPrnf_t *ctx, const unsigned char *octets, psSizeL_t len,
                         int(*formatter)(const unsigned char *, size_t, const char *, char **));
const char *psPrnfIpv4(psPrnf_t *ctx, uint32_t ipv4_addr);

int psPrnf_(psPrnf_t *ctx, const char *fmt, ...) __attribute__((__format__(printf, 2, 3)));
int psSnprnf_(char *str, psSizeL_t size, psPrnf_t *ctx, const char *fmt, ...) __attribute__((__format__(printf, 4, 5)));
char *psAsprnf_(psPool_t *pool, psPrnf_t *ctx, const char *fmt, ...) __attribute__((__format__(printf, 3, 4)));

/** Extended formatted printing.

   The function behaves like printf, except it requires
   #PS_PRNF_CTX in functions using the printing. In return for use of
   #PS_PRNF_CTX, the user may use extended formatting codes
   PSA_STR(), PSA_SSTR(), PSA_OSTR(), PSA_HEX() etc.
 */
#define psPrnf(...) psPrnf_(&psPrnfCtx, __VA_ARGS__)

/** Extended formatted printing into string.

   The function behaves like snprintf, except it requires
   #PS_PRNF_CTX in functions using the printing. In return for use of
   #PS_PRNF_CTX, the user may use extended formatting codes
   PSA_STR(), PSA_SSTR(), PSA_OSTR(), PSA_HEX() etc.
 */
#define psSnprnf(buf, sz, ...) psSnprnf_((buf), (sz), &psPrnfCtx, __VA_ARGS__)

/** Extended formatted printing into newly allocated string.

   The function behaves like snprintf, except it requires
   #PS_PRNF_CTX in functions using the printing. In return for use of
   #PS_PRNF_CTX, the user may use extended formatting codes
   PSA_STR(), PSA_SSTR(), PSA_OSTR(), PSA_HEX() etc.
 */
#define psAsprnf(pool, ...) psAsprnf_((pool), &psPrnfCtx, __VA_ARGS__)

/** Extended format a string.

   Format argument as a string in psPrnf() output.
   There needs to be #PSF, PSFX() or PSFLX() in the equivalent position
   on format string.

   Example:
   @code
       psPrnf(PSF PSF PSLN, PSA_STR("hello"), PSA_STR(", world!"));
   @endcode
 **/
#define PSA_STR(str) psPrnfStr(&psPrnfCtx, (str))


/** Extended format ASCII string.

   Format argument as a string in psPrnf() output.
   There needs to be #PSF, PSFX() or PSFLX() in the equivalent position
   on format string. This formatting function will protect against
   non-ASCII characters and control characters in the string. They are printed
   as . characters, similar to `hd` command.

   Example:
   @code
       psPrnf(PSF PSLN, PSA_SSTR("hello\n"));
   @endcode

 **/
#define PSA_SSTR(str, len) psPrnfSStr(&psPrnfCtx, (str), (len))


/** Extended format string with quoting.

   Format argument as a string in psPrnf() output.
   There needs to be #PSF, PSFX() or PSFLX() in the equivalent position
   on format string. This formatting function will protect against
   non-ASCII characters and control characters in the string. They are printed
   as \xXX notation. The resulting strings are often suitable for inclusion
   in C source code.

   Example:
   @code
       psPrnf(PSF PSLN, PSA_QSTR("hello\n"));
   @endcode

 **/
#define PSA_QSTR(str) psPrnfQStr(&psPrnfCtx, (str))

/** Linefeed character. */
#define PSLN "\n"

/** Extended format octet string as hex digits.

   Format argument (unsigned char pointer) as a string containing hexadecimal
   numbers. Formatting operation is constant time: timing will only reveal
   length of the octet string.

   Example:
   @code
       psPrnf(PSF " me!" PSLN, PSA_HEX((unsigned char *)"\xFE\xED", 2));
   @endcode
*/
#define PSA_HEX(octetstring, len) psPrnfHex(&psPrnfCtx, (octetstring), (len))

/** Extended format octet string as base64.

   Format argument (unsigned char pointer) as a string containing base64 encoding.

   @note The formatting requires `cl_pem.h`.
*/
#define PSA_BASE64(octetstring, len) \
    psPrnfBase64(&psPrnfCtx, (octetstring), (len), \
                 (int(*)(const unsigned char *, size_t, const char *, char **)) &CL_PEM_EncodeAlloc)

/** Extended format big integer as hexadecimal.

   Format argument (CL_BUC_t *) as a string containing hexadecimal
   numbers. Note: Executing this macro requires `cl_bu.h`.

   @note The resulting string will always have 0x prefix to identify number format.
*/
#define PSA_BUC(buc_p) \
    psPrnfCopyDupFree(&psPrnfCtx, "0x", 2, CL_BUC_ExportHexStr(buc_p), (PS_SIZE_STR), "[HEX]")

/** Extended format big integer as hexadecimal (no prefix).

   Format argument (CL_BUC_t *) as a string containing hexadecimal
   numbers. Note: Executing this macro requires `cl_bu.h`.

   @note The string never contains initial 0x prefix. Use PSA_BUC() instead for printing
   hexadecimal number with prefix.
*/
#define PSA_BUC_HEX(buc_p)                                              \
    psPrnfDupFree(&psPrnfCtx, CL_BUC_ExportHexStr(buc_p), (PS_SIZE_STR), "[HEX]")

/** Extended format big integer as hexadecimal (no prefix).

   Format arguments (SLMWord p[], SLMWords) as a string containing
   number.
   Note: Executing this macro requires `slm.h`.
*/
#define PSA_SLMW_HEX(p, n)                                              \
    psPrnfHex2(&psPrnfCtx, ((unsigned char *)(p)), (4 * (n)))

/** Extended format big integer as hexadecimal (no prefix).

   Format argument (CL_BUC_t *) as a string containing decimal number.
   Note: Executing this macro requires `cl_bu.h`.
*/
#define PSA_BUC_DEC(buc_p) \
    psPrnfDupFree(&psPrnfCtx, CL_BUC_ExportDecStr(buc_p), (PS_SIZE_STR), "[NUMBER]")

/** Extended format boolean.

   Format argument (bool) as a string containing true or false.
*/
#define PSA_BOOL(bool) psPrnfBool(bool)

/** Extended format IPV4 address.

   Format argument (in_addr_t) as a string containing decimal number.
   @note Executing this macro requires `arpa/inet.h`.
   The function is multi-threading safe unlike inet_ntoa() on some systems.
*/
#define PSA_IPV4(ipv4_addr) \
    psPrnfIpv4(&psPrnfCtx, (uint32_t) (ipv4_addr))

/** Piece of ASN.1 data.

   Format piece of data within memory, assuming it contains ASN.1 DER encoded
   data. Note: Executing this macro requires `asn1.h`.

   @note The macro takes six arguments: pointer, length, number of der
   elements to process, maximum formatting depth, maximum field length and
   optional flags. See asnFormatDer() for details of underlying formatting
   function.
   In most cases, ptr, len, 1, 1, 0, 0 sufficies to format single element
   without recursion and ptr, len, 0, 0, 0, 0 is good when trying to print
   recursively as many elements as possible.
*/
#define PSA_DER(der, derlen, maxelem, maxdepth, maxelemlen, flags) \
    psPrnfDupFree(&psPrnfCtx, asnFormatDer(NULL, (der), (derlen), (maxelem), \
                                           (maxdepth), (maxelemlen), (flags)), \
                  (PS_SIZE_STR), "[DER]")
# endif
#endif

/* Allow multiple inclusion with changing of PS_NO_PRF macro. */
#undef PS_PRNF_CTX
#ifdef PS_NO_PRNF
# define PS_PRNF_CTX extern int no_ps_prnf_ctx /* N/A: Formatting. */
#else
# ifdef __GNUC__
/** Extended printing formatting buffer.
    Function needs to use this macro within local variable declarations
    to make use of psPrnf(). */
#  define PS_PRNF_CTX                                                   \
    psPrnf_t psPrnfCtx __attribute__((__unused__)) = { NULL, 0 }
# else
#  define PS_PRNF_CTX psPrnf_t psPrnfCtx = { NULL, 0 }
# endif
#endif
/* end of psPrnf.h */
