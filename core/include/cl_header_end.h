/** @file cl_header_start.h

   @copyright Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.

   End header file.
 */

/* CL header files are intended for C.
   This header produces sufficient epilogue to switch back to usual mode
   of the compiler. */

/* Note: Add CL_NO_EXTERN_C to predefined symbols if you have manually
   created extern "C" block. */

/* Unusual multi-inclusion guard as multi-inclusion is allowed. */
#ifndef CL_HEADER_END_H
#define CL_HEADER_END_H 1

#if defined __cplusplus && !defined CL_NO_EXTERN_C
}
#endif
#undef CL_HEADER_END_H /* Forget this include was already defined. */
#endif /* CL_HEADER_END_H */
