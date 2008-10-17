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

/*! ocateth.c
 *  Contains Ethernet (for TAP) and ICMPv6 (for NDP) code.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/10/10
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#include <net/ethernet.h>
#include <netinet/icmp6.h>

#include "ocat.h"


static MACTable_t mac_tbl_[MAX_MAC_ENTRY];
static int mac_cnt_ = 0;
static pthread_mutex_t mac_mutex_ = PTHREAD_MUTEX_INITIALIZER;


/*! Pseudo header for IPv6 checksum calculation.
 *  RFC2460 8.1, (RFC1885 2.3) RFC2463, RFC1071. */

void mac_cleanup(void)
{
   int i;

   pthread_mutex_lock(&mac_mutex_);

   for (i = 0; i < mac_cnt_; i++)
      if (mac_tbl_[i].age + MAX_MAC_AGE < time(NULL))
      {
         memmove(&mac_tbl_[i], &mac_tbl_[i + 1], sizeof(MACTable_t) * (MAX_MAC_ENTRY - i));
         mac_cnt_--;
         i--;
      }

   pthread_mutex_unlock(&mac_mutex_);
}


int mac_get_mac(const struct in6_addr *in6, uint8_t *hwaddr)
{
   int i;

   pthread_mutex_lock(&mac_mutex_);

   for (i = 0; i < mac_cnt_; i++)
      if (IN6_ARE_ADDR_EQUAL(in6, &mac_tbl_[i].in6addr))
      {
         memcpy(hwaddr, &mac_tbl_[i].hwaddr, ETH_ALEN);
         mac_tbl_[i].age = time(NULL);
         break;
      }

   pthread_mutex_unlock(&mac_mutex_);

   return i < mac_cnt_ ? i : -1;
}


int mac_add_entry(const uint8_t *hwaddr, const struct in6_addr *in6)
{
   int e = -1;

   if (mac_cnt_ < MAX_MAC_ENTRY)
   {
      log_debug("adding entry to MAC table %d", mac_cnt_);
      memcpy(&mac_tbl_[mac_cnt_].hwaddr, hwaddr, ETH_ALEN);
      memcpy(&mac_tbl_[mac_cnt_].in6addr, in6, sizeof(struct in6_addr));
      mac_tbl_[mac_cnt_].age = time(NULL);
      e = mac_cnt_++;
   }

   return e;
}


int mac_get_ip(const uint8_t *hwaddr, struct in6_addr *in6)
{
   int i;

   pthread_mutex_lock(&mac_mutex_);

   for (i = 0; i < mac_cnt_; i++)
      if (!memcmp(hwaddr, &mac_tbl_[i].hwaddr, ETH_ALEN))
      {
         memcpy(in6, &mac_tbl_[i].in6addr, sizeof(struct in6_addr));
         mac_tbl_[i].age = time(NULL);
         break;
      }

   if (i == mac_cnt_)
      i = mac_add_entry(hwaddr, in6);

   pthread_mutex_unlock(&mac_mutex_);

   return i;
}


/*! Calculate 16 bit one's complement sum (RFC1071).
 *  @param buf Pointer to buffer.
 *  @param len Number of bytes in buffer.
 */
uint16_t checksum(const uint16_t *buf, int len)
{
   uint32_t sum = 0;

   // sum up all 16 bit words
   // (Note that it's endiness independent)
   for (; len > 1 ; len -= 2, buf++)
      sum += *buf;

   // add last byte if buffer has odd length
   if (len)
      sum += *((uint8_t*) buf);

   // add carries
   while (sum >> 16)
      sum = (sum & 0xffff) + (sum >> 16);

   // return complement
   return ~sum;
}


void free_ckbuf(uint16_t *buf)
{
   free(buf);
}


uint16_t *malloc_ckbuf(const struct in6_addr *src, const struct in6_addr *dst, uint16_t plen, uint8_t proto, const void *payload)
{
   struct ip6_psh *psh;

   if (!(psh = calloc(1, sizeof(struct ip6_psh) + plen)))
   {
      log_msg(L_FATAL, "error creating checksum buffer: %s", strerror(errno));
      //return NULL;
      exit(1);
   }

   psh->src = *src;
   psh->dst = *dst;
   psh->len = htons(plen);
   psh->nxt = proto;
   memcpy(psh + 1, payload, plen);

   return (uint16_t*) psh;
}


int ndp_solicit(char *buf, int rlen)
{
   struct ether_header *eh = (struct ether_header*) (buf + 4);
   struct ip6_hdr *ip6 = (struct ip6_hdr*) (eh + 1); // ip6 header starts behind ether_header
   struct icmp6_hdr *icmp6 = (struct icmp6_hdr*) (ip6 + 1); // imcp6 header starts behind ip6 header
   struct nd_neighbor_solicit *nds = (struct nd_neighbor_solicit*) icmp6;
   struct nd_neighbor_advert *nda = (struct nd_neighbor_advert*) icmp6;
   struct nd_opt_hdr *ohd = (struct nd_opt_hdr*) (nds + 1);
   uint16_t *ckb, cksum;
   struct in6_addr in6;
   int minlen = 4 + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);

   if (rlen < minlen)
   {
      log_debug("frame too short for ICMP6 %d < %d", rlen, minlen);
      return -1;
   }

   if (eh->ether_type != htons(ETHERTYPE_IPV6))
   {
      log_debug("protocol 0x%04x not implemented yet", htons(eh->ether_type));
      return -1;
   }

   if (ip6->ip6_nxt != IPPROTO_ICMPV6)
   {
      log_debug("frame contains not ICMPV6, next header = %d", ip6->ip6_nxt);
      return -1;
   }

   if (icmp6->icmp6_type != ND_NEIGHBOR_SOLICIT)
   {
      log_debug("icmpv6 type %d not implemented", icmp6->icmp6_type);
      return -1;
   }

   log_debug("ICMPv6 ND_NEIGHBOR_SOLICIT received");

   minlen = minlen - sizeof(struct icmp6_hdr) + sizeof(struct nd_neighbor_solicit);
   if (rlen < minlen)
   {
      log_debug("frame too short for ND_NEIGHBOR_SOLICIT");
      return -1;
   }

   /*
   memcpy(&ip6ph->src, &ip6->ip6_src, sizeof(struct in6_addr));
   memcpy(&ip6ph->dst, &ip6->ip6_dst, sizeof(struct in6_addr));
   ip6ph->len = ip6->ip6_plen;
   ip6ph->nxt = IPPROTO_ICMPV6;
   memcpy(ip6ph + 1, icmp6, ntohs(ip6->ip6_plen));
   */

   ckb = malloc_ckbuf(&ip6->ip6_src, &ip6->ip6_dst, ntohs(ip6->ip6_plen), IPPROTO_ICMPV6, icmp6);
   cksum = checksum(ckb, ntohs(ip6->ip6_plen) + sizeof(struct ip6_psh));
   free_ckbuf(ckb);
   if (cksum)
   {
      log_msg(L_ERROR, "icmpv6 checksum wrong");
      return -1;
   }

   log_debug("checksum correct, generating response");

   // set MAC addresses in ethernet header
   if (mac_get_ip(eh->ether_shost, &in6) < 0)
      log_msg(L_ERROR, "MAC table full");
   memcpy(eh->ether_dhost, eh->ether_shost, ETH_ALEN);
   memcpy(eh->ether_shost, setup.ocat_hwaddr, ETH_ALEN);

   // init ip6 header
   memcpy(&ip6->ip6_dst, &ip6->ip6_src, sizeof(struct in6_addr));
   memcpy(&ip6->ip6_src, &nds->nd_ns_target, sizeof(struct in6_addr));

   // init nda icmp6 header
   nda->nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
   nda->nd_na_hdr.icmp6_code = 0;
   nda->nd_na_hdr.icmp6_cksum = 0;
   nda->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED;
   ohd->nd_opt_type = ND_OPT_TARGET_LINKADDR;
   memcpy(ohd + 1, setup.ocat_hwaddr, ETH_ALEN);

   /*
   memcpy(&ip6ph->src, &ip6->ip6_src, sizeof(struct in6_addr));
   memcpy(&ip6ph->dst, &ip6->ip6_dst, sizeof(struct in6_addr));
   ip6ph->len = ip6->ip6_plen;
   ip6ph->nxt = IPPROTO_ICMPV6;
   memcpy(ip6ph + 1, icmp6, ntohs(ip6->ip6_plen));
   */

   ckb = malloc_ckbuf(&ip6->ip6_src, &ip6->ip6_dst, ntohs(ip6->ip6_plen), IPPROTO_ICMPV6, icmp6);
   nda->nd_na_hdr.icmp6_cksum = checksum(ckb, ntohs(ip6->ip6_plen) + sizeof(struct ip6_psh));
   free_ckbuf(ckb);

   log_debug("writing %d bytes to tunfd %d", rlen, setup.tunfd[1]);
   if (write(setup.tunfd[1], buf, rlen) < rlen)
      log_msg(L_ERROR, "short write");

   return 0;
}

