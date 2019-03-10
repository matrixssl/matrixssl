/**
 *      @file    pscompilerwarning.h
 *      @version $Format:%h%d$
 *
 *      Compiler Warning: Similar to #warning "XXX", but with handling
 *      to support as many compilers as possible.
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
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

/* Use multiple inclusion allowed pattern. */
#ifndef PSCOMPILER_WARNING_INCLUDED
# define PSCOMPILER_WARNING_INCLUDED 1

# ifndef WARNING_MESSAGE
#  error "Preprocessor WARNING_MESSAGE is not defined."
#  error "Usage: #define WARNING_MESSAGE \"Warning Message.\"\n#include \"pscompilerwarning.h\""
# endif

/* Get compiler version if not known. */
# ifndef __GCC_VERSION
#  include "pscompilerdep.h"
# endif /* __GCC_VERSION */

/* Detect common compilers with support for #warning. */
# if defined(__GNUC__) || defined(_ARMCC5)
#  ifndef COMPILER_CAN_DO_WARNING
#   define COMPILER_CAN_DO_WARNING 1
#  endif /* COMPILER_CAN_DO_WARNING */
# endif /* for compilers with #warning support. */

/* Default branches for for common compile time warnings. */
# if defined WARNING_MESSAGE_DEFAULT_KEY && defined COMPILER_CAN_DO_WARNING
#  warning "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
/* Use the common #pragma message syntax for producing warnings. */
# elif !defined COMPILER_DOES_NOT_SUPPORT_PRAGMA_MESSAGE
#  define PSCOMPILERWARNING_STRING_(m_arg_) #m_arg_
#  define PSCOMPILERWARNING_STRING(m_arg_) PSCOMPILERWARNING_STRING_(m_arg_)
#  ifdef _MSC_VER
#   pragma message("WARNING: " PSCOMPILERWARNING_STRING(WARNING_MESSAGE))
#  elif defined __ARMCC5
/* We produce the warning with #warning, but the message will unfortunately
   not be able to inline WARNING_MESSAGE with this compiler. */
#   warning "Source file issued warning messages. See the source file for details."
#  else
/* Produce a warning in a compiler specific way. */
#  endif
# else
   /* Compiler with support for generic pragma message. */
#  pragma message "WARNING: " PSCOMPILERWARNING_STRING(WARNING_MESSAGE)
# endif

/* Undefine the message for next use. */
# undef PSCOMPILERWARNING_STRING_
# undef PSCOMPILERWARNING_STRING

# undef WARNING_MESSAGE
# undef WARNING_MESSAGE_DEFAULT_KEY

/* Allow multiple inclusion. */
# undef PSCOMPILER_WARNING_INCLUDED
#endif /* PSCOMPILER_WARNING_INCLUDED */
