/* Copyright 2008 Bernhard R. Fischer, Daniel Haslinger.
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

#ifndef OCAT_NETDESC_H
#define OCAT_NETDESC_H


#include "ocat.h"


//! This structure contains information that's specifc for an anonymization
//  network.
struct NetDesc
{
   struct in6_addr prefix;
   int prefix_len;
   struct in_addr prefix4;
   int addr4_mask;
   int name_size;
   char *domain;
   short listen_port;
   short ctrl_port;
   short vdest_port;
   short socks_port;
};

extern const struct NetDesc netdesc_[2];

#define NDESC(x) (netdesc_[CNF(net_type)].x)


// ----- these are #defines for Tor -----
//
//! TOR prefix: FD87:D87E:EB43::/48
#define TOR_PREFIX {{{0xfd,0x87,0xd8,0x7e,0xeb,0x43,0,0,0,0,0,0,0,0,0,0}}}
#define TOR_PREFIX_LEN 48
#if BYTE_ORDER == LITTLE_ENDIAN
#define TOR_PREFIX4 {0x0000000a}
#define TOR_PREFIX4_MASK 0x000000ff
#else
#define TOR_PREFIX4 {0x0a000000}
#define TOR_PREFIX4_MASK 0xff000000
#endif
//! internal domain
#define TOR_DOMAIN ".onion"
//! Total length of .onion-URL
#define TOR_ONION_NAME_SIZE (ONION_URL_LEN + 7)
//! Local listening port for incoming connections from TOR.
#define TOR_OCAT_LISTEN_PORT 8060
//! Local control port for querying status information.
#define TOR_OCAT_CTRL_PORT 8066
//! Virtual destination port for hidden services
#define TOR_OCAT_DEST_PORT 8060
//! SOCKS port of TOR proxy
#define TOR_SOCKS_PORT 9050


// ----- these are #defines for I2P -----
//
//! TOR prefix: FD60:DB4D:DDB5::/48
#define I2P_PREFIX {{{0xfd,0x60,0xdb,0x4d,0xdd,0xb5,0,0,0,0,0,0,0,0,0,0}}}
#define I2P_PREFIX_LEN TOR_PREFIX_LEN
#define I2P_PREFIX4 TOR_PREFIX4
#define I2P_PREFIX4_MASK TOR_PREFIX4_MASK
//! internal domain
#define I2P_DOMAIN ".oc.b32.i2p"
//! Total length of .onion-URL
#define I2P_ONION_NAME_SIZE (ONION_URL_LEN + 12)
//! Local listening port for incoming connections from TOR.
#define I2P_OCAT_LISTEN_PORT 8061
//! Local control port for querying status information.
#define I2P_OCAT_CTRL_PORT 8067
//! Virtual destination port for hidden services
#define I2P_OCAT_DEST_PORT I2P_OCAT_LISTEN_PORT
//! SOCKS port of TOR proxy
#define I2P_SOCKS_PORT 9051


#endif

