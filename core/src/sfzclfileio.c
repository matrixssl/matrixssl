/* sfzclfileio.c

   Description       : Read and write file from and to the disk
                        in various formats.
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

#include "sfzclincludes.h"
#include "sfzclfileio.h"
#include "sfzclbase64.h"
#include "implementation_defs.h"

#define FILEBUF_SIZE 1024
#define DEBUG_print

/* Check for the max size */
#define SFZCL_FILEIO_CHECK_MAX_SIZE                                           \
    do {                                                                          \
        if (size_limit && size_limit < offset)                                      \
        {                                                                         \
            L_DEBUG(LF_CERTLIB, "File '%s': Size limit (%lu) exceeded (%lu)",       \
                file_name, (unsigned long) size_limit, (unsigned long) offset); \
            goto failed;                                                            \
        }                                                                         \
    } while (0)

#define SFZCL_DEBUG_MODULE "SfzclUtilFile"

/* Read binary file from the disk giving a size limit for the
   file. Return mallocated buffer and the size of the buffer. If the
   reading of file failes return FALSE. If the file name is NULL or
   "-" then read from the stdin. The size_limit is in bytes. If zero
   is used, the read file will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned.  */
bool
sfzcl_read_file_with_limit(const char *file_name,
    uint32_t size_limit,
    unsigned char **buf, size_t *buf_len)
{
#ifdef NO_FS
    PARAMETER_NOT_USED(file_name);
    PARAMETER_NOT_USED(size_limit);
    PARAMETER_NOT_USED(buf);
    PARAMETER_NOT_USED(buf_len);
    return FALSE;
#else
    FILE *fp = NULL;
    unsigned char *iobuf, *tmp;
    size_t len, plen, growth, t, offset, ret;

    /* Read the file */
    if (file_name == NULL || c_strcmp(file_name, "-") == 0)
    {
        fp = stdin;
        file_name = NULL;
    }
    else
    {
        fp = Fopen(file_name, "rb");
    }

    if (fp == NULL)
    {
        return FALSE;
    }

    offset = 0;
    growth = len = plen = FILEBUF_SIZE;
    if ((iobuf = SPAL_Memory_Alloc(len)) == NULL)
    {
        goto failed;
    }

    /* Read the file */
    while ((ret = Fread(iobuf + offset, 1, growth, fp)) == growth)
    {
        offset += growth;
        SFZCL_FILEIO_CHECK_MAX_SIZE;

        /* Fibonacci series on buffer size growth */
        t = len;
        len += plen;
        growth = plen;
        plen = t;

        /* L_DEBUG(LF_CERTLIB, "Growing input buffer from %ld to %ld bytes", plen, len); */
        if ((tmp = sfzcl_realloc(iobuf, plen, len)) == NULL)
        {
            goto failed;
        }
        iobuf = tmp;
    }

    /* L_DEBUG(LF_CERTLIB, */
    /* "Last read from file %ld bytes to offset %ld, total %ld bytes.", */
    /* ret, offset, ret + offset); */

    if (Ferror(fp))
    {
        goto failed;
    }

    offset += ret;
    SFZCL_FILEIO_CHECK_MAX_SIZE;
    if (file_name)
    {
        Fclose(fp);
    }

    *buf = iobuf;
    *buf_len = offset;
    return TRUE;

failed:
    if (file_name && fp)
    {
        Fclose(fp);
    }
    SPAL_Memory_Free(iobuf);
    return FALSE;
#endif /* NO_FS */
}

/* Read binary file from the disk. Return mallocated buffer and the size of the
   buffer. If the reading of file failes return FALSE. If the file name is NULL
   or "-" then read from the stdin. */
bool
sfzcl_read_file(const char *file_name, unsigned char **buf, size_t *buf_len)
{
    return sfzcl_read_file_with_limit(file_name, SFZCL_READ_FILE_NO_LIMIT,
        buf, buf_len);
}

/* Read base 64 encoded file from the disk. Return mallocated buffer
   and the size of the buffer. If the reading of file failes return
   FALSE. If the file name is NULL or "-" then read from the
   stdin. The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
bool
sfzcl_read_file_base64_with_limit(const char *file_name,
    uint32_t size_limit,
    unsigned char **buf, size_t *buf_len)
{
    unsigned char *tmp = NULL, *cp = NULL;
    size_t len, start, end;

    if (!sfzcl_read_file_with_limit(file_name, size_limit, &tmp, &len))
    {
        SPAL_Memory_Free(tmp);
        return FALSE;
    }

    if (sfzcl_base64_remove_headers(tmp, len, &start, &end) == FALSE)
    {
        SPAL_Memory_Free(tmp);
        return FALSE;
    }

    cp = sfzcl_base64_remove_whitespace(tmp + start, end - start);

    if (NULL == cp)
    {
        SPAL_Memory_Free(tmp);
        return FALSE;
    }

    *buf = sfzcl_base64_to_buf(cp, &len);
    *buf_len = len;

    SPAL_Memory_Free(cp);
    SPAL_Memory_Free(tmp);
    return TRUE;
}

/* Read base 64 encoded file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name is NULL or "-" then read from the stdin. */
bool
sfzcl_read_file_base64(const char *file_name, unsigned char **buf,
    size_t *buf_len)
{
    return sfzcl_read_file_base64_with_limit(file_name,
        SFZCL_READ_FILE_NO_LIMIT, buf,
        buf_len);
}

/* Read hexl encoded file from the disk. Return mallocated buffer and
   the size of the buffer. If the reading of file failes return
   FALSE. If the file name is NULL or "-" then read from the
   stdin. The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
bool
sfzcl_read_file_hexl_with_limit(const char *file_name,
    uint32_t size_limit,
    unsigned char **buf, size_t *buf_len)
{
    unsigned char *tmp = NULL, *p = NULL, *q = NULL;
    size_t len, i = 0;
    int state, l = 0;

    if (!sfzcl_read_file_with_limit(file_name, size_limit, &tmp, &len))
    {
        SPAL_Memory_Free(tmp);
        return FALSE;
    }

    *buf_len = 0;
    if ((*buf = SPAL_Memory_Alloc(len + 1)) == NULL)
    {
        SPAL_Memory_Free(tmp);
        return FALSE;
    }

    for (state = 0, p = *buf, q = tmp; len > 0; len--, q++)
    {
        if (state == 0)
        {
            i = 0;
            l = 0;
            if (*q == ':')
            {
                state++;
            }
            continue;
        }
        if (state == 1)
        {
            if (Isxdigit(*q))
            {
                if (Isdigit(*q))
                {
                    l = (l << 4) | (*q - '0');
                }
                else
                {
                    l = (l << 4) | (c_tolower(*q) - 'a' + 10);
                }
                i++;
                if ((i & 1) == 0)
                {
                    *p++ = l;
                    (*buf_len)++;
                    l = 0;
                }
                if (i == 32)
                {
                    state++;
                }
            }
            else if (q[0] == ' ' && q[1] == ' ')
            {
                state++;
            }
            continue;
        }
        if (*q == '\n' || *q == '\r')
        {
            state = 0;
        }
    }

    SPAL_Memory_Free(tmp);
    return TRUE;
}

/* Read pem/hexl/binary file from the disk. Return mallocated buffer
   and the size of the buffer. If the reading of file failes return
   FALSE. If the file name starts with :p: then assume file is pem
   encoded, if it starts with :h: then it is assumed to be hexl
   format, and if it starts with :b: then it is assumed to be
   binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning
   message is printed and operation fails. If the file name is NULL or
   "-" then read from the stdin (":p:-" == stdin in pem encoded
   format). The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
bool
sfzcl_read_gen_file_with_limit(const char *file_name,
    uint32_t size_limit,
    unsigned char **buf, size_t *buf_len)
{
    if (c_strlen(file_name) < 3 || file_name[0] != ':' || file_name[2] != ':')
    {
        return sfzcl_read_file_with_limit(file_name, size_limit, buf, buf_len);
    }
    if (file_name[1] == 'b')
    {
        return sfzcl_read_file_with_limit(file_name + 3, size_limit,
            buf, buf_len);
    }
    if (file_name[1] == 'p')
    {
        return sfzcl_read_file_base64_with_limit(file_name + 3, size_limit,
            buf, buf_len);
    }
    if (file_name[1] == 'h')
    {
        return sfzcl_read_file_hexl_with_limit(file_name + 3, size_limit,
            buf, buf_len);
    }
    L_DEBUG(LF_CERTLIB, "Unknown file format given to sfzcl_read_gen_file");
    return FALSE;
}

/* Read pem/hexl/binary file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name starts with :p: then assume file is pem encoded, if it starts with :h:
   then it is assumed to be hexl format, and if it starts with :b: then it is
   assumed to be binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning message is
   printed and operation fails. If the file name is NULL or "-" then read from
   the stdin (":p:-" == stdin in pem encoded format). */
bool
sfzcl_read_gen_file(const char *file_name,
    unsigned char **buf, size_t *buf_len)
{
    return sfzcl_read_gen_file_with_limit(file_name, SFZCL_READ_FILE_NO_LIMIT,
        buf, buf_len);
}

/* end of file sfzclfileio.c */
