/* cl_types_base.h
 *
 * Data types used by SafeZone CL Lib.
 */

/*****************************************************************************
* Copyright (c) 2011-2017 INSIDE Secure Oy. All Rights Reserved.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef INCLUDE_GUARD_CL_TYPES_BASE_H
#define INCLUDE_GUARD_CL_TYPES_BASE_H

/* Include C99 boolean. */
#include "osdep_stdbool.h"

#include "cl_header_begin.h"

/* Note: the following headers must exist in compilation environments
   compliant with ISO C99. In compilation environments prior ISO C99,
   replacements of stdint.h may need to be provided. The replacement
   only needs to define subset of full ISO C99 stdint.h.

   Alternatively, you may define CL_NO_STDDEF_H and CL_NO_STDINT_H and
   define, e.g. using compiler definitions or -Duint32_t=int or
   preincludes the appropriate configuration for your platform.

   Note: The remaining files of CL attempt to avoid any reference to
   stddef.h or stdint.h. */
#ifndef CL_NO_STDDEF_H
# include "osdep_stddef.h"
#else
/* You shall provide replacements for stddef.h (definition of ). */
#endif /* CL_NO_STDDEF_H */

#ifndef CL_NO_STDINT_H
# include "osdep_stdint.h"
#else
/* You shall provide replacements for stdint.h
   (definitions of uint8_t, uint16_t, uint32_t, uintptr_t). */
#endif /* CL_NO_STDINT_H */

/** @addtogroup CL11TYPES
    @{ */

/******************************************************************************/
/*
    macros for function definitions.
 */
/** @defgroup CL11TYPES_CONVENTIONS The CL Lib types: API interface details
 * @ingroup CL11TYPES
 *
 * Macros used to detail usage of API.
 * @{
 */

# ifndef CL_C99
#  if defined(__cplusplus) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#   define CL_C99(X)
#  else
/** C99 only code.
  Produce output for compiler that is only processed if compiler is in C99
  mode or later. This macro can be used to use security enhancing constructs
  in C99 without losing backwards compatibility with ANSI-C or C++. */
#   define CL_C99(X) X
#  endif
# endif
#ifndef CL_AT_LEAST
/** Pointer needs to point at least x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.
 */
#define CL_AT_LEAST(x) CL_C99(static) x
#endif /* CL_AT_LEAST */
#ifndef CL_AT_LEAST_EXPR
/** Pointer needs to point at least x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.

    The limit is expressed as expression of other inputs to the function.

    @note: Due to implementation, the value of expr needs to be at least 1. */
#define CL_AT_LEAST_EXPR(x) CL_C99(static) 1
#endif /* CL_AT_LEAST_EXPR */
#ifndef CL_EXACTLY
/** Pointer needs to point exactly x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.
 */
#define CL_EXACTLY(x) CL_C99(static) x
#endif /* CL_EXACTLY */
#ifndef CL_EXACTLY_EXPR
/** Pointer needs to point exactly x items.
    Usage of this macro enhances interface with known restrictions on
    intended amount of input elements. The macro is intended for compiler
    guidance and documentation.

    @note: Due to implementation, the value of expr needs to be at least 1. */
#define CL_EXACTLY_EXPR(x) CL_C99(static) 1
#endif /* CL_EXACTLY_EXPR */

/** @} */

/** @defgroup CL11TYPES_DIR The CL Lib types: Data direction
 * @ingroup CL11TYPES
 *
 * Data direction indicators in function API.
 *
 * Access types used in function definitions.
 * These are used to describe mapping between FIPS 140-2
 * logical interfaces and the function API.
 * @{
 */
#define CL_DI /* Data Input */ /**< @brief The pointed memory area acts as Data Input. */
#define CL_DO /* Data Output */ /**< @brief The pointed memory area acts as Data Output. */
#define CL_SO /* Status Output */ /**< @brief The pointed memory area acts as Status Output. */
#define CL_HO /* Handle Output */ /**< @brief The pointed memory area acts as Handle Output.
                   [For purposes of FIPS 140-2 Logical interfaces, the
                   handle Output is considered Status Output.] */

/* Note:
 * The actual pointer values passed to the function parameters are
 * considered Control Input for purposes FIPS 140-2, but depending
 * on the value, the pointed memory area can be considered
 * Data Input/Data Output. Also, all values provided on the function call
 * (not via pointer) are considered Control Input. */

/** @} */

/*
 * Definitions for Data Types used by CL interface.
 */

/** @defgroup CL11TYPES_COMMON The CL Lib types: Common
 * @ingroup CL11TYPES
 *
 * Common data types for CL Lib API.
 *
 * The basic data types are based on C99 types.
 * In absence of these ISO C99 types, other data types with equivalent
 * size and range can be substituted.
 * @{
 */

/** 64-bit unsigned integer

   sizeof(CL_UInt64_t) == 8 \n
   \f$alignment \leq 8\f$ \n
   range \f$[0,2^{64}-1]\f$
 */
typedef uint64_t CL_UInt64_t;
/** 32-bit unsigned integer

   sizeof(CL_UInt32_t) == 4 \n
   \f$alignment \leq 4\f$ \n
   range \f$[0,2^{32}-1]\f$
 */
typedef uint32_t CL_UInt32_t;
/** 16-bit unsigned integer

   sizeof(CL_UInt16_t) == 2 \n
   \f$alignment \leq 2\f$ \n
   range \f$[0,65535]\f$
 */
typedef uint16_t CL_UInt16_t;
/** 8-bit unsigned integer

   sizeof(CL_UInt8_t) == 1 \n
   alignment == 1 \n
   range \f$[0,255]\f$
 */
typedef uint8_t CL_UInt8_t;

/* Short aliases for above, just for convenience. */
typedef CL_UInt8_t CL_U8_t;   /**< Short for CL_UInt8_t. */
typedef CL_UInt16_t CL_U16_t; /**< Short for CL_UInt16_t. */
typedef CL_UInt32_t CL_U32_t; /**< Short for CL_UInt32_t. */
typedef CL_UInt64_t CL_U64_t; /**< Short for CL_UInt64_t. */

/* Type definitions for Key or Data Input. */
typedef const CL_U8_t *CL_KeyPtr_t;    /**< Pointer to key material. */
typedef const CL_U8_t *CL_DataInPtr_t; /**< Input octets (Data Input). */

typedef CL_U8_t CL_Data_t;             /**< Type for arrays of data. */

/* Type definitions for Data Output. */
typedef CL_U8_t *CL_DataOutPtr_t;        /**< Output octets (Data Output). */

/* Type definitions for size of Input/Output or negotiating output size. */
typedef CL_U32_t CL_KeyLen_t;          /**< The Length of key material. */
typedef CL_U32_t CL_DataLen_t;         /**< The length of Input/Output data. */
typedef CL_DataLen_t *CL_DataLenPtr_t; /**< The length of Output data
                                          in functions using variable size. */
typedef CL_U32_t CL_BitsLen_t;         /**< Length of Input/Key data, in bits. */
typedef CL_U32_t CL_Count_t;           /**< The number of items. */

/* Type definitions for functions returning combined return value. */
typedef int CL_RvOrSize_t;
#define CL_RV_OR_SIZE_OK_MAX ((CL_RvOrSize_t)0x7FFFFFFF)

#ifndef CL_ASSET_32BIT
/* Assets (handles to key material and objects stored via CL.)
   For convenience, the functions in this API use type corresponding
   to type required by the API entry point. */
typedef CL_U64_t CL_AnyAsset_t;           /**< Any type of Asset. */
#ifndef CL_ASSET_64BIT
#define CL_ASSET_64BIT 1 /* Compile time detect current 64-bit assets. */
#endif
#else
/* backwards compatibility with platforms using 32-bit asset.
   Avoid this flag on all platforms. */
typedef CL_U32_t CL_AnyAsset_t;           /**< Any type of Asset. */
#endif

typedef CL_AnyAsset_t CL_KeyAsset_t;      /**< Key reference. */
typedef CL_AnyAsset_t CL_StateAsset_t;    /**< IV/temporary digest reference. */
typedef CL_KeyAsset_t CL_KeyExtraAsset_t; /**< Key extra asset. */

/* An array of key assets (for output of key derivation to assets.)
   The key derivation functions allow the output to be created into
   an array of key assets. This allows the user of key derivation functions
   to implement key material to keys convertion easily and securely.
   (Please, reference chapter 7.3 in NIST SP 800-108 @cite nist_sp_800_108
   for details on Converting Key Material to Cryptographic Keys.)
   This same convention is used in addition to key derivation functions
   with other functions where convention is commonly used (Key Transport). */
typedef const CL_KeyAsset_t *CL_KeyAssetArray_t; /**< Asset Array */
/* Number of entriens in asset array. */
typedef CL_Count_t CL_KeyAssetArrayCount_t;      /**< Asset Array Length */

/* New asset is allocated by function. */
typedef CL_AnyAsset_t * const CL_AnyAssetNew_t;   /**< Function allocates new asset (out). */
typedef CL_AnyAssetNew_t CL_KeyAssetNew_t;        /**< Function allocates new asset for key (out). */
typedef CL_AnyAssetNew_t CL_TrustedKeyAssetNew_t; /**< Function allocates new asset for trusted key (out). */

/* Locals (handles to key material and objects stored for use with CL.
   These are just pointers with associated policy.)
   For convenience, the functions in this API use type corresponding
   to type required by the API entry point. */
struct CL_Local;
typedef struct CL_Local *CL_AnyLocal_t; /**< Any type of Local. */
typedef CL_AnyLocal_t CL_KeyLocal_t;      /**< Key reference. */
typedef CL_AnyLocal_t CL_StateLocal_t;    /**< IV/temporary digest reference. */
typedef CL_KeyLocal_t CL_KeyExtraLocal_t; /**< Key extra local. */

/* An array of key locals (for output of key derivation to locals.)
   The key derivation functions allow the output to be created into
   an array of key locals. This allows the user of key derivation functions
   to implement key material to keys convertion easily and securely.
   (Please, reference chapter 7.3 in NIST SP 800-108 @cite nist_sp_800_108
   for details on Converting Key Material to Cryptographic Keys.)
   This same convention is used in addition to key derivation functions
   with other functions where convention is commonly used (Key Transport). */
typedef const CL_KeyLocal_t *CL_KeyLocalArray_t; /**< Local Array */
/* Number of entriens in local array. */
typedef CL_Count_t CL_KeyLocalArrayCount_t;      /**< Local Array Length */

/* New local is allocated by function. */
typedef CL_AnyLocal_t * const CL_AnyLocalNew_t;   /**< Function allocates new local (out). */
typedef CL_AnyLocalNew_t CL_KeyLocalNew_t;        /**< Function allocates new local for key (out). */
typedef CL_AnyLocalNew_t CL_TrustedKeyLocalNew_t; /**< Function allocates new local for trusted key (out). */

/** @} */

#include "cl_header_end.h"

#endif /* INCLUDE_GUARD_CL_TYPES_BASE_H */
