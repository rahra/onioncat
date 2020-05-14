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


#include "ocat.h"


/*! IPv6 Routing table. Each entry contains 3 values:
 *  destination network, prefix length, gateway
 */
static IPv6Route_t *v6route_ = NULL;
static int v6route_cnt_ = 0;
static pthread_mutex_t v6route_mutex_ = PTHREAD_MUTEX_INITIALIZER;


/*! Reduce IPv6 address to prefix, i.e. cut off host id.
 *  @param net IPv6 address
 *  @param prefixlen Prefix length
 */
void ipv6_reduce(struct in6_addr *net, int prefixlen)
{
   int i;
   char m;

   // safety check
   if (prefixlen < 0 || prefixlen >= 128)
      return;

   for (i = 0; i < ((128 - prefixlen) >> 3); i++)
      net->s6_addr[15 - i] = 0;

   m = 0xff << (8 - (prefixlen % 8));
   net->s6_addr[prefixlen >> 3] &= m;

}


/*! Lookup IPv6 route. 
 */
struct in6_addr *ipv6_lookup_route(const struct in6_addr *dest)
{
   struct in6_addr addr;
   int i, n;

   pthread_mutex_lock(&v6route_mutex_);
   n = v6route_cnt_;
   for (i = 0; i < n; i++)
   {
      addr = *dest;
      ipv6_reduce(&addr, v6route_[i].prefixlen);
      if (IN6_ARE_ADDR_EQUAL(&v6route_[i].dest, &addr))
      {
         log_debug("IPv6 route found");
         break;
      }
   }
   pthread_mutex_unlock(&v6route_mutex_);
   return i < n ? &v6route_[i].gw : NULL;
}


/*! Add an IPv6 route to IPv6 routing table.
 *  @return -1 if table is full else return index of entry.
 */
int ipv6_add_route(const IPv6Route_t *route)
{
   int r = -1;
   IPv6Route_t *rt;

   pthread_mutex_lock(&v6route_mutex_);
   if ((rt = realloc(v6route_, sizeof(IPv6Route_t) * (v6route_cnt_ + 1))))
   {
      v6route_ = rt;
      r = v6route_cnt_;
      memcpy(&v6route_[v6route_cnt_++], route, sizeof(IPv6Route_t));
   }
   pthread_mutex_unlock(&v6route_mutex_);
   return r;
}


void ipv6_print(IPv6Route_t *route, void *f)
{
   char addr[INET6_ADDRSTRLEN];

   inet_ntop(AF_INET6, &route->dest, addr, INET6_ADDRSTRLEN);
   fprintf(f, "IN6 %s %3d ", addr, route->prefixlen);
   inet_ntop(AF_INET6, &route->gw, addr, INET6_ADDRSTRLEN);
   fprintf(f, "%s %p\n", addr, route);
}


void ipv6_print_routes(FILE *f)
{
   int i;

   pthread_mutex_lock(&v6route_mutex_);
   for (i = 0; i < v6route_cnt_; i++)
      ipv6_print(&v6route_[i], f);
   pthread_mutex_unlock(&v6route_mutex_);
}


/*! Parse IPv6 route and add it to routing table.
 *  @return index of routing table entry (>= 0) or an integer < 0 on failure.
 */
int ipv6_parse_route(const char *rs)
{
   char buf[strlen(rs) + 1], *s, *b;
   IPv6Route_t route6;

   if (!rs)
      return E_RT_NULLPTR;

   log_debug("IPv6 route parser: \"%s\"", rs);

   strlcpy(buf, rs, strlen(rs) + 1);
   if (!(s = strtok_r(buf, " \t", &b)))
      return E_RT_SYNTAX;

   if (inet_pton(AF_INET6, s, &route6.dest) != 1)
      return E_RT_SYNTAX;

   if (!(s = strtok_r(NULL, " \t", &b)))
      return E_RT_SYNTAX;

   errno = 0;
   route6.prefixlen = strtol(s, NULL, 10);
   if (errno)
      return E_RT_SYNTAX;
   if ((route6.prefixlen < 0) || (route6.prefixlen > 128))
      return E_RT_ILLNM;

   if (!(s = strtok_r(NULL, " \t", &b)))
      return E_RT_SYNTAX;

   if (inet_pton(AF_INET6, s, &route6.gw) != 1)
      return E_RT_SYNTAX;

   if (!has_tor_prefix(&route6.gw))
      return E_RT_NOTORGW;

   if (IN6_ARE_ADDR_EQUAL(&route6.gw, &CNF(ocat_addr)))
      return E_RT_GWSELF;

   ipv6_reduce(&route6.dest, route6.prefixlen);
   if (ipv6_lookup_route(&route6.dest))
      return E_RT_DUP;

   return ipv6_add_route(&route6);
}

