/** @file cl_header_start.h

   @copyright Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.

   Start header file.
 */

/* CL header files are intended for C.
   This header produces sufficient prologue to introduce
   header file in C mode. */

/* Note: Add CL_NO_EXTERN_C to predefined symbols if you have manually
   created extern "C" block. */

/* Unusual multi-inclusion guard as multi-inclusion is allowed. */
#ifndef CL_HEADER_BEGIN_H
#define CL_HEADER_BEGIN_H 1
#if defined __cplusplus && !defined CL_NO_EXTERN_C
extern "C" {
#endif

#undef CL_HEADER_BEGIN_H /* Allow multiple inclusion and nesting. */
#endif /* CL_HEADER_BEGIN_H */

