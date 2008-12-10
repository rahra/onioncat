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

/*! ocatipv4route.c
 *  This file contains functions for managing IPv4 routing and
 *  forwarding.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/09/03-01
 */


#include "ocat.h"

#define NMBIT(i,n) ((i&n)&~(n<<1))
#define BRANCH(i,n) (NMBIT(i,n)!=0)


static IPv4Route_t *rroot_ = NULL;
static pthread_mutex_t route_mutex_ = PTHREAD_MUTEX_INITIALIZER;


/*! Add an IPv4 route to IPv4 routing table.
 *  @return 0 on success or < 0 on failure.
 */
int ipv4_add_route(IPv4Route_t *route, IPv4Route_t **root, uint32_t cur_nm)
{
   if (!(*root))
   {
      if (!(*root = calloc(1, sizeof(IPv4Route_t))))
      {
         log_msg(LOG_EMERG, "ipv4_add_route: %s", strerror(errno));
         return E_RT_NOMEM;
      }
      (*root)->dest = route->dest & cur_nm;
      (*root)->netmask = cur_nm;
   }

   if (route->netmask == cur_nm /*(*root)->netmask*/)
   {
      if (IN6_ARE_ADDR_EQUAL(&(*root)->gw, &in6addr_any))
      {
         memcpy(&(*root)->gw, &route->gw, sizeof(struct in6_addr));
         return 0;
      }

      if (IN6_ARE_ADDR_EQUAL(&(*root)->gw, &route->gw))
         return 0;

      log_msg(LOG_ERR, "route already exists");
      return E_RT_DUP;
   }

   // break recursion in case of error
   if (cur_nm == 0xffffffff)
   {
      log_msg(LOG_ERR, "netmask error in netmask of route: %08x", route->netmask);
      return E_RT_ILLNM;
   }

   //now branch to subs
   cur_nm >>= 1;
   cur_nm |= 0x80000000;

   return ipv4_add_route(route, &(*root)->next[BRANCH(route->dest, cur_nm)], cur_nm);
}


IPv4Route_t *ipv4_lookup_route__(uint32_t ip, IPv4Route_t *route, uint32_t cur_nm)
{
   if (!route)
   {
      log_debug("NULL route");
      return NULL;
   }

   cur_nm >>= 1;
   cur_nm |= 0x80000000;

   if (route->next[BRANCH(ip, cur_nm)])
      return ipv4_lookup_route__(ip, route->next[BRANCH(ip, cur_nm)], cur_nm);

   //if (memcmp(&route->gw, &in6addr_any, sizeof(struct in6_addr)))
   if (!IN6_ARE_ADDR_EQUAL(&route->gw, &in6addr_any))
      return route;

   return NULL;
}


/*! Lookup a route to an ip address in routing table.
 *  @param Ip to find a route for. The Ip must be given in host byte order.
 *  @return Pointer to IPv6 TOR address. */
struct in6_addr *ipv4_lookup_route(uint32_t ip)
{
   IPv4Route_t *r;

   pthread_mutex_lock(&route_mutex_);
   r = ipv4_lookup_route__(ip, rroot_, 0);
   pthread_mutex_unlock(&route_mutex_);

   return r ? &r->gw : NULL;
}


void ipv4_traverse(IPv4Route_t *route, void (func)(IPv4Route_t*, void*), void *p)
{
   if (!route)
      return;

   func(route, p);
   ipv4_traverse(route->next[0], func, p);
   ipv4_traverse(route->next[1], func, p);
}


void ipv4_print(IPv4Route_t *route, void *f)
{
   char addr[INET6_ADDRSTRLEN];
   struct in_addr iaddr;

   //if (!memcmp(&route->gw, &in6addr_any, sizeof(struct in6_addr)))
   if (IN6_ARE_ADDR_EQUAL(&route->gw, &in6addr_any))
      return;

   iaddr.s_addr = htonl(route->dest);
   fprintf(f, "IN  %s ", inet_ntoa(iaddr));
   iaddr.s_addr = htonl(route->netmask);
   fprintf(f, "%s ", inet_ntoa(iaddr));
   inet_ntop(AF_INET6, &route->gw, addr, INET6_ADDRSTRLEN);
   fprintf(f, "%s %p\n", addr, route);
}


void print_routes(FILE *f)
{
   ipv4_traverse(rroot_, ipv4_print, f);
}


int parse_route(const char *rs)
{
   char buf[strlen(rs) + 1], *s, *b;
   IPv4Route_t route;
   int r;

   if (!rs)
      return E_RT_NULLPTR;

   log_debug("IPv4 route parser: \"%s\"", rs);

   strlcpy(buf, rs, strlen(rs) + 1);
   if (!(s = strtok_r(buf, " \t", &b)))
      return E_RT_SYNTAX;

   if (inet_pton(AF_INET, s, &route.dest) != 1)
      return E_RT_SYNTAX;

   if (!(s = strtok_r(NULL, " \t", &b)))
      return E_RT_SYNTAX;

   if (inet_pton(AF_INET, s, &route.netmask) != 1)
      return E_RT_SYNTAX;

   if (!(s = strtok_r(NULL, " \t", &b)))
      return E_RT_SYNTAX;

   if (inet_pton(AF_INET6, s, &route.gw) != 1)
      return E_RT_SYNTAX;

   if (!has_tor_prefix(&route.gw))
      return E_RT_NOTORGW;

   if (IN6_ARE_ADDR_EQUAL(&route.gw, &CNF(ocat_addr)))
      return E_RT_GWSELF;

   route.netmask = ntohl(route.netmask);
   route.dest = ntohl(route.dest);

   pthread_mutex_lock(&route_mutex_);
   r = ipv4_add_route(&route, &rroot_, 0);
   pthread_mutex_unlock(&route_mutex_);

   return r;
}

