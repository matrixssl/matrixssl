/* sfzclfileio.h

   Description       : Read and write file from and to the disk
                      in various formats.  The reading functions
                      with suffix with_limit have a maximum length
                      for the file that is being read.
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

#ifndef SFZCLFILEIO_H
#define SFZCLFILEIO_H

/* Read binary file from the disk. Return mallocated buffer and the size of the
   buffer. If the reading of file failes return FALSE. If the file name is NULL
   or "-" then read from the stdin. */
bool sfzcl_read_file(const char *file_name,
                     unsigned char **buf, size_t *buf_len);
/* Read binary file from the disk giving a size limit for the
   file. Return mallocated buffer and the size of the buffer. If the
   reading of file failes return FALSE. If the file name is NULL or
   "-" then read from the stdin. The size_limit is in bytes. If zero
   is used, the read file will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned.  */
bool sfzcl_read_file_with_limit(const char *file_name,
                                uint32_t size_limit,
                                unsigned char **buf, size_t *buf_len);

/* Read base 64 encoded file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name is NULL or "-" then read from the stdin. */
bool sfzcl_read_file_base64(const char *file_name,
                            unsigned char **buf, size_t *buf_len);

/* Read pem/hexl/binary file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name starts with :p: then assume file is pem encoded, if it starts with :h:
   then it is assumed to be hexl format, and if it starts with :b: then it is
   assumed to be binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning message is
   printed and operation fails. If the file name is NULL or "-" then
   read from the stdin (":p:-" == stdin in pem encoded format). */
bool sfzcl_read_gen_file(const char *file_name,
                         unsigned char **buf, size_t *buf_len);

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
bool sfzcl_read_gen_file_with_limit(const char *file_name,
                                    uint32_t size_limit,
                                    unsigned char **buf, size_t *buf_len);

/* Write binary file to the disk. If the write fails retuns FALSE. If the file
   name is NULL or "-" then write to the stdout */
bool sfzcl_write_file(const char *file_name,
                      const unsigned char *buf, size_t buf_len);

/* Some predefined size limits to be used with functions that limit
   the size of the file read.  Adjust or add more if necessary. */

/* Use this as a size_limit argument not to have any max
   length for the file */
#define SFZCL_READ_FILE_NO_LIMIT 0

/* A default size limit for config files, etc... */
#define SFZCL_READ_FILE_LIMIT_CONFIG_FILE 1024000

/* A default size limit for certificates, keys, etc. */
#define SFZCL_READ_FILE_LIMIT_CRYPTO_OBJ 96000

/* Commonly used PEM begin and end strings */

/* Generic pem encoded block */
#define SFZCL_PEM_GENERIC_BEGIN     "-----BEGIN PEM ENCODED DATA-----"
#define SFZCL_PEM_GENERIC_END       "-----END PEM ENCODED DATA-----"
#define SFZCL_PEM_GENERIC        SFZCL_PEM_GENERIC_BEGIN, SFZCL_PEM_GENERIC_END

/* X.509 Certificate Block */
#define SFZCL_PEM_X509_BEGIN        "-----BEGIN X509 CERTIFICATE-----"
#define SFZCL_PEM_X509_END          "-----END X509 CERTIFICATE-----"
#define SFZCL_PEM_X509              SFZCL_PEM_X509_BEGIN, SFZCL_PEM_X509_END

/* SFZCL X.509 Private Key Block */
#define SFZCL_PEM_SFZCL_PRV_KEY_BEGIN "-----BEGIN SFZCL X.509 PRIVATE KEY-----"
#define SFZCL_PEM_SFZCL_PRV_KEY_END   "-----END SFZCL X.509 PRIVATE KEY-----"
#define SFZCL_PEM_SFZCL_PRV_KEY \
    SFZCL_PEM_SFZCL_PRV_KEY_BEGIN, SFZCL_PEM_SFZCL_PRV_KEY_END

/* X.509 Certificate Revocation List Block */
#define SFZCL_PEM_X509_CRL_BEGIN    "-----BEGIN X509 CRL-----"
#define SFZCL_PEM_X509_CRL_END      "-----END X509 CRL-----"
#define SFZCL_PEM_X509_CRL     SFZCL_PEM_X509_CRL_BEGIN, SFZCL_PEM_X509_CRL_END

/* PKCS#10 Certificate Request Block */
#define SFZCL_PEM_CERT_REQ_BEGIN    "-----BEGIN CERTIFICATE REQUEST-----"
#define SFZCL_PEM_CERT_REQ_END      "-----END CERTIFICATE REQUEST-----"
#define SFZCL_PEM_CERT_REQ     SFZCL_PEM_CERT_REQ_BEGIN, SFZCL_PEM_CERT_REQ_END

/* PKCS#1 Private Key block */
#define SFZCL_PEM_PKCS1_RSA_BEGIN    "-----BEGIN RSA PRIVATE KEY-----"
#define SFZCL_PEM_PKCS1_RSA_END      "-----END RSA PRIVATE KEY-----"
#define SFZCL_PEM_PKCS1_RSA  SFZCL_PEM_PKCS1_RSA_BEGIN, SFZCL_PEM_PKCS1_RSA_END

#define SFZCL_PEM_PKCS1_DSA_BEGIN    "-----BEGIN DSA PRIVATE KEY-----"
#define SFZCL_PEM_PKCS1_DSA_END      "-----END DSA PRIVATE KEY-----"
#define SFZCL_PEM_PKCS1_DSA  SFZCL_PEM_PKCS1_DSA_BEGIN, SFZCL_PEM_PKCS1_DSA_END

/* PKCS#8 Private Key block */
#define SFZCL_PEM_PKCS8_BEGIN    "-----BEGIN PRIVATE KEY-----"
#define SFZCL_PEM_PKCS8_END      "-----END PRIVATE KEY-----"
#define SFZCL_PEM_PKCS8          SFZCL_PEM_PKCS8_BEGIN, SFZCL_PEM_PKCS8_END

/* Encrypted PKCS#8 Private Key block */
#define SFZCL_PEM_ENCRYPTED_PKCS8_BEGIN "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define SFZCL_PEM_ENCRYPTED_PKCS8_END   "-----END ENCRYPTED PRIVATE KEY-----"
#define SFZCL_PEM_ENCRYPTED_PKCS8 \
    SFZCL_PEM_ENCRYPTED_PKCS8_BEGIN, SFZCL_PEM_ENCRYPTED_PKCS8_END

#endif                          /* SFZCLFILEIO_H */
