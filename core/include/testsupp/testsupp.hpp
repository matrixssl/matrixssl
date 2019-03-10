/* testsupp.hpp
 *
 * SafeZone/MatrixSSL specific wrapper for catch.hpp.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef TESTSUPP_H
#define TESTSUPP_H 1

#ifdef TESTSUPP_MAIN
#define CATCH_CONFIG_MAIN
#endif

/* Classification of test results (for compatibility with testsupp.h). */
typedef enum { OK, FAILED, WEAK, SKIPPED } TEST_RESULT;

/* Assumes catch.hpp 1.8.2. */
#include "thirdparty/catch.hpp"

/* Helper functionality to aid with catch.hpp we have developed. */

/* Converts memory containing digest into std:string 0xdigestvalue. */
#define HEXDIGEST(output_buffer, size)                  \
    Util::rawMemoryToString((const void *)(output_buffer), (size))

/* Converts memory to hexadecimal (any content). */
#define HEX(output_buffer, size)                        \
    Util::rawMemoryToString((const void *)(output_buffer), (size))

/* Converts any content to string. */
#define STRING(output_buffer, size)                             \
    std::string((output_buffer), (output_buffer) + (size))

/* Note: Also available: opt_WRITE_FILE(filename_string, data, size). */

/* ----------------------------------------------------------------------- */

/* Implementation of utility functions. */
/* Note: This is under libboost license because of sources. */

/* Loaned from catch.hpp with different endianness detail: */
namespace Util {

    const std::string unprintableString = "{?}";

    static inline std::string rawMemoryToString(
            const void *object,
            std::size_t size)
    {
        // Reverse order for little endian architectures
        int i = 0, end = static_cast<int>( size ), inc = 1;

        unsigned char const *bytes = static_cast<unsigned char const *>(object);
        std::ostringstream os;
        os << "0x" << std::setfill('0') << std::hex;
        for( ; i != end; i += inc )
             os << std::setw(2) << static_cast<unsigned>(bytes[i]);
       return os.str();
    }
}

bool testsupp_write_debug_files;
static inline
void opt_WRITE_FILE(
        const char *target,
        const void *data,
        size_t data_length)
{
    FILE *f;

    if (!testsupp_write_debug_files && !getenv("TESTSUPP_WRITE_DEBUG_FILES"))
    {
        return; /* Do not produce debugging files. */
    }

    f = fopen(target, "w");
    if (f)
    {
        if (fwrite(data, data_length, 1, f) != 1)
        {
            fprintf(stderr, "write error\n");
            exit(1);
        }
        fprintf(stderr, "(Written %lu data bytes to %s)\n",
                (long unsigned int) data_length, target);
    }
    fclose(f);
}

#endif /* testsupp.hpp */
