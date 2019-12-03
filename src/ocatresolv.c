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

/* This files contains DNS interception stuff. This routines are not used, yet.
 */

#include "ocat.h"

#ifdef USE_DNS_REDIRECT

int check_dns(const struct ip6_hdr *ip6, int len)
{
   uint16_t *ckbuf, sum;
   struct udphdr *udp;
   HEADER *dns;
#ifdef DEBUG
   int i;
   char tmp[100];
#endif

   log_debug("check_dns");
   if (len < sizeof(*ip6))
      return -1;

#ifdef DEBUG
   tmp[0] = '\0';
   for (i = 0; i < 40; i++)
      snprintf(tmp + strlen(tmp), 100 - strlen(tmp), "%02x", ((char*)ip6)[i]);
   log_debug("ip6: %s", tmp);
#endif

   if (ip6->ip6_nxt != IPPROTO_UDP)
      return -1;

   if (!IN6_ARE_ADDR_EQUAL(&CNF(oc_vdns), &ip6->ip6_dst))
      return -1;

   log_debug("destination is virtual OC DNS server");
   udp = (struct udphdr*) (ip6 + 1);
   ckbuf = malloc_ckbuf(ip6->ip6_src, ip6->ip6_dst, ntohs(ip6->ip6_plen), IPPROTO_UDP, udp);
   sum = checksum(ckbuf, ntohs(ip6->ip6_plen) + sizeof(struct ip6_psh));
   free_ckbuf(ckbuf);

   if (sum)
   {
      log_debug("checksum error");
      return -1;
   }

   log_debug("dport = %d", ntohs(udp->uh_dport));
   if (ntohs(udp->uh_dport) != 53)
      return -1;

   log_debug("DNS request found");
   dns = (HEADER*) (udp + 1);

   return 0;
}

#endif

