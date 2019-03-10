/* cl_basic.h
 *
 * Basic Utility operations aiding correctly implementing cryptography.
 */

/*****************************************************************************
* Copyright (c) 2016-2017 INSIDE Secure Oy. All Rights Reserved.
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

#ifndef INCLUDE_GUARD_CL_BASIC_H
#define INCLUDE_GUARD_CL_BASIC_H

#include "cl_types_base.h"
#include "cl_header_begin.h"

/** @defgroup CL11BASIC The CL Lib API Functions: Utility functions
 *  CL Lib 1.1 API: Utility Functions
 *
 *  CL Lib 1.1 is commonly used in programs aiming to implement cryptography
 *  correctly. This file defines some useful utility functionality to be
 *  used with cryptographic functionality. These functions do not have
 *  CLS API counterparts as the functions never need locking.
 * @{
 */

/** Fill memory with given value.
 * This function fills given memory area with given byte.
 * The memory fill operation happens even if the C compiler can detect the
 * area is no longer needed. This is beneficial for Cryptography, where it
 * is important to carefully erase all memory areas containing sensitive
 * materials to ensure they do not accidentally leak.
 *
 * @param s    Target area
 * @param smax Size of whole target area
 * @param c    Byte to use (usually 0; only 8 bits of the value is used.)
 * @param n    The number of bytes to erase.
 */
void CL_MemSet(void *s, CL_DataLen_t smax, int c, CL_DataLen_t n);

/** Check if two memory areas have identical contents.
 *
 * If array sizes differ, the function returns 0.
 * This function compares contents of two memory areas for equality in
 * data independent time.
 *
 * @param p1   Source area 1
 * @param sz1  Size of source area 1
 * @param p2   Source area 2
 * @param sz2  Size of source area 2
 * @retval 1   only if the areas are same size and have same contents.
 */
int CL_MemEqual(const void *p1, size_t sz1, const void *p2, size_t sz2);

/** Compare two arrays and identify if one of arrays is smaller, or same
 *  than the other array.
 *
 * If array sizes differ, the function always returns <0 or >0.
 * This function compares contents of two memory areas in
 * data independent time. The comparison is based on value of bytes, resulting
 * e.g. ASCII code based sorting of the values.
 *
 * @param p1   Source area 1
 * @param sz1  Size of source area 1
 * @param p2   Source area 2
 * @param sz2  Size of source area 2
 * @retval <0  If source area is smaller.
 * @retval  0  If the areas are equal.
 * @retval >0  If source area is greater.
 */
int CL_MemCmp(const void *p1, size_t sz1, const void *p2, size_t sz2);

/** Compare two arrays and identify if one of arrays is smaller, or same
 *  than the other array, with masking for the last byte.
 *
 * If array sizes differ, the function always returns <0 or >0.
 * This function compares contents of two memory areas in
 * data independent time. The comparison is based on value of bytes, resulting
 * e.g. ASCII code based sorting of the values.
 *
 * This function can be seen as a special version of CL_MemCmp(), which
 * partially ignore the last byte(s).
 *
 * @param p1   Source area 1
 * @param sz1  Size of source area 1
 * @param p2   Source area 2
 * @param sz2  Size of source area 2
 * @param mask1 Mask for the last byte of source area 1
 * @param mask2 Mask for the last byte of source area 2
 * @retval <0  If source area is smaller.
 * @retval  0  If the areas are equal.
 * @retval >0  If source area is greater.
 */
int CL_MemCmpEndMask(const void *p1, size_t sz1, const void *p2, size_t sz2,
                     const unsigned char mask1,
                     const unsigned char mask2);

/** @} */

#include "cl_header_end.h"

#endif /* INCLUDE_GUARD_CL_BASIC_H */

/* end of file cl_basic.h */
