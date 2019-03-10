/** osdep_netdb.h
 *
 * Wrapper for system header osdep_netdb.h
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

/* This file just includes system header netdb.h.
   In case your system does not include all functions
    via that file or
   does not have implementation of netdb.h, please
   customize this place holder header.
*/

#ifndef OSDEP_NETDB_H_DEFINED
#define OSDEP_NETDB_H_DEFINED 1


#include <netdb.h>


/* You may redefine the wrappers below in case your target system does not
   provide all of the functions below. The functions are from POSIX.1-2001.
   The getaddrinfo() function is documented in RFC 2553.
   The defines may be overrided from command line. */

/* Macro that provides Getaddrinfo, which is macro wrapper for getaddrinfo. */
#ifndef Getaddrinfo
#define Getaddrinfo getaddrinfo
#endif /* Getaddrinfo */

/* Macro that provides Freeaddrinfo, which is macro wrapper for freeaddrinfo. */
#ifndef Freeaddrinfo
#define Freeaddrinfo freeaddrinfo
#endif /* Freeaddrinfo */

#endif /* OSDEP_NETDB_H_DEFINED */
