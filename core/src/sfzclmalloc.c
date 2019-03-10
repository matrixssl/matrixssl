/* sfzclmalloc.c
 */

/*****************************************************************************
* Copyright (c) 2006-2016 INSIDE Secure Oy. All Rights Reserved.
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#include "implementation_defs.h"
#include "sfzclincludes.h"
#include "spal_memory.h"

void *
sfzcl_realloc(void *ptr, size_t old_size, size_t new_size)
{
    void *new_ptr = NULL;

    /* sfzcl_realloc API requires old_size to ensure caller of the API
       keeps track of the size, which is usually required for correct
       usage of the reallocated memory. However, this implementation of
       sfzcl_realloc does not validate the value. */
    PARAMETER_NOT_USED(old_size);

    if (ptr == NULL)
    {
        return SPAL_Memory_Alloc(new_size);
    }

    if (new_size == 0)
    {
        new_size = 1;
    }

    new_ptr = (void *) SPAL_Memory_ReAlloc(ptr, (size_t) new_size);

    return new_ptr;
}

void *
sfzcl_strdup(const void *p)
{
    const char *str;
    char *cp = NULL;

    if (p)
    {
        str = (const char *) p;
        if ((cp = SPAL_Memory_Alloc(c_strlen(str) + 1)) != NULL)
        {
            c_strcpy(cp, str);
        }
    }
    return (void *) cp;
}

void *
sfzcl_memdup(const void *p, size_t len)
{
    const char *str = (const char *) p;
    char *cp = NULL;

    /* argument validation */
    if (p == NULL)
    {
        return NULL;
    }

    if ((cp = SPAL_Memory_Alloc(len + 1)) != NULL)
    {
        c_memcpy(cp, str, (size_t) len);
        cp[len] = '\0';
    }

    return (void *) cp;
}

/* end of file sfzclmalloc.c */
