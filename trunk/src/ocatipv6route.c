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

/*! @file
 *  This file contains functions for managing IPv6 routing and
 *  forwarding.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/09/03-01
 */

#include "config.h"

#include <netinet/in.h>

#include "ocat.h"


/*! IPv6 Routing table. Each entry contains 3 values:
 *  destination network, prefix length, gateway
 */
static IPv6Route_t v6route_[] =
{
   // enter static IPv6 routes here for each host! (prefix lengths are not supported yet)
   //
   // sample entry
   // route 3001::1 via fd87:d87e:eb43:1e53:0c75:2a27:72dc:c9a8
   //
   //{{{{0x30,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}}, 0, {{{0xfd,0x87,0xd8,0x7e,0xeb,0x43,0x1e,0x53,0x0c,0x75,0x2a,0x27,0x72,0xdc,0xc9,0xa8}}}},

   // do NOT remove this entry, it terminates the array!
   {IN6ADDR_ANY_INIT, 0, IN6ADDR_ANY_INIT}
};


/*! Lookup IPv6 route. 
 */
struct in6_addr *ipv6_lookup_route(const struct in6_addr *dest)
{
   int i;

   for (i = 0; !IN6_IS_ADDR_UNSPECIFIED(&v6route_[i].dest); i++)
      if (IN6_ARE_ADDR_EQUAL(&v6route_[i].dest, dest))
      {
         log_debug("IPv6 route found");
         return &v6route_[i].gw;
      }
   return NULL;
}

