/* Copyright 2008-2009 Bernhard R. Fischer.
 *
 * This file is part of OnionCat.
 *
 * OnionCat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * OnionCat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OnionCat. If not, see <http://www.gnu.org/licenses/>.
 */

/** This file contains missing headers for the IPv6 system part of
 *  OnionCat.
 *  There are several definitions at the beginning.
 *
 *  At the bottom it includes three header files files which
 *  are taken directly from OpenBSD. Those files have been
 *  truncated by unnecessary code lines mainly the KERNEL stuff.
 */

#ifndef OCAT_CYGWIN_H
#define OCAT_CYGWIN_H

#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

// this seems to be missing in Cygwin/w32api 1.5.25-15 IPv6 extension 0.22
// (2008/07/05) (author contacted on 2009/02/24)
#ifndef IPV6_ADDR_MC_SCOPE
#define IPV6_ADDR_MC_SCOPE(a) ((a)->s6_addr[1] & 0x0f)
#endif

//! '__packed' is defined in OpenBSD's sys/cdefs.h
#ifndef __packed
#define __packed __attribute__((packed))
#endif

//! 'LIST_ENTRY' is defined in OpenBSD's sys/queue.h
#define LIST_ENTRY(type)                                                \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

//! define OpenBSD-style byteorder macros
#ifndef _BYTE_ORDER
#define _BYTE_ORDER BYTE_ORDER
#endif
#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN BIG_ENDIAN
#endif

#include "openbsd_netinet_ip6.h"
#include "openbsd_netinet_icmp6.h"
#include "openbsd_netinet_if_ether.h"

#endif

