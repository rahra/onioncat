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

   pthread_mutex_unlock(&mac_mutex_);

   return i < mac_cnt_ ? i : -1;
}


int mac_add_entry(const uint8_t *hwaddr, const struct in6_addr *in6)
{
   int e = -1;

   pthread_mutex_lock(&mac_mutex_);

   if (mac_cnt_ < MAX_MAC_ENTRY)
   {
      memcpy(&mac_tbl_[mac_cnt_].hwaddr, hwaddr, ETH_ALEN);
      memcpy(&mac_tbl_[mac_cnt_].in6addr, in6, sizeof(struct in6_addr));
      mac_tbl_[mac_cnt_].age = time(NULL);
      e = ++mac_cnt_;
   }

   pthread_mutex_unlock(&mac_mutex_);

   return e;
}


struct ip6_psh
{
   struct in6_addr src;
   struct in6_addr dst;
   uint32_t len;
   char _pad[3];
   uint8_t nxt;
} __attribute__((packed));


#if 0
/*! Swap to memory areas. Those may not overlap.*/
int memswp(void *dst, void *src, int len)
{
   char tmp[FRAME_SIZE];

   if (len > FRAME_SIZE)
   {
      log_debug("buffers too large to swap");
      return -1;
   }

   memcpy(tmp, dst, len);
   memcpy(dst, src, len);
   memcpy(src, tmp, len);

   return len;
}
#endif


/*! Calculate 16 bit one's complement sum (RFC1071).
 *  @param buf Pointer to buffer.
 *  @param len Number of bytes in buffer.
 */
uint16_t checksum(const uint16_t *buf, int len)
{
   uint32_t sum = 0;

//   len >>= 1;
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


void *icmpv6_handler(void *p)
{
   char buf[FRAME_SIZE], ckbuf[FRAME_SIZE];
   struct ether_header *eh = (struct ether_header*) (buf + 4);
   struct ip6_hdr *ip6 = (struct ip6_hdr*) (eh + 1); // ip6 header starts behind ether_header
   struct icmp6_hdr *icmp6 = (struct icmp6_hdr*) (ip6 + 1); // imcp6 header starts behind ip6 header
   struct nd_neighbor_solicit *nds = (struct nd_neighbor_solicit*) icmp6;
   struct nd_neighbor_advert *nda = (struct nd_neighbor_advert*) icmp6;
   struct nd_opt_hdr *ohd = (struct nd_opt_hdr*) (nds + 1);
   struct ip6_psh *ip6ph = (struct ip6_psh*) ckbuf;
   int rlen;

   memset(ckbuf, 0, sizeof(struct ip6_psh));

//   if (pipe(setup.icmpv6fd) == -1)
//      log_msg(L_FATAL, "cannot create pipe: %s", strerror(errno)), exit(1);

   while ((rlen = read(setup.icmpv6fd[0], buf, FRAME_SIZE)) != -1)
   {
      log_debug("received %d bytes on icmp pipe", rlen);

      if (rlen < 4 + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))
      {
         log_debug("frame too short: %d < %d", rlen, 4 + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr));
         continue;
      }

      // just to be on the safe side check icmpv6_mcast and ethertype
//      if ((*((uint16_t*) &buf[4]) != 0x3333) || (*((uint16_t*) &buf[12]) != htons(ETHERTYPE_IPV6)))
      if (eh->ether_type != htons(ETHERTYPE_IPV6))
      {
         log_debug("protocol 0x%04x not implemented yet", htons(eh->ether_type));
         continue;
      }

      if (ip6->ip6_nxt != IPPROTO_ICMPV6)
      {
         log_debug("frame contains not ICMPV6, next header = %d", ip6->ip6_nxt);
         continue;
      }

      if (icmp6->icmp6_type != ND_NEIGHBOR_SOLICIT)
      {
         log_debug("icmpv6 type %d not implemented", icmp6->icmp6_type);
         continue;
      }

      log_debug("ICMPv6 ND_NEIGHBOR_SOLICIT received");

      memcpy(&ip6ph->src, &ip6->ip6_src, sizeof(struct in6_addr));
      memcpy(&ip6ph->dst, &ip6->ip6_dst, sizeof(struct in6_addr));
      ip6ph->len = ip6->ip6_plen;
      ip6ph->nxt = IPPROTO_ICMPV6;
      memcpy(ip6ph + 1, icmp6, ntohs(ip6->ip6_plen));

      if (checksum((uint16_t*) ip6ph, ntohs(ip6->ip6_plen) + sizeof(struct ip6_psh)))
      {
         log_msg(L_ERROR, "icmpv6 checksum wrong");
         continue;
      }

      log_debug("checksum correct, generating response");
      memcpy(eh->ether_dhost, eh->ether_shost, ETH_ALEN);
      memcpy(eh->ether_shost, setup.ocat_hwaddr, ETH_ALEN);

      memcpy(&ip6->ip6_dst, &ip6->ip6_src, sizeof(struct in6_addr));
      memcpy(&ip6->ip6_src, &nds->nd_ns_target, sizeof(struct in6_addr));
      icmp6->icmp6_type = ND_NEIGHBOR_ADVERT;
      icmp6->icmp6_code = 0;
      icmp6->icmp6_cksum = 0;

      memcpy(&ip6ph->src, &ip6->ip6_src, sizeof(struct in6_addr));
      memcpy(&ip6ph->dst, &ip6->ip6_dst, sizeof(struct in6_addr));
      ip6ph->len = ip6->ip6_plen;
      ip6ph->nxt = IPPROTO_ICMPV6;

      nda->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED;
      ohd->nd_opt_type = ND_OPT_TARGET_LINKADDR;
      memcpy(ohd + 1, setup.ocat_hwaddr, ETH_ALEN);

      memcpy(ip6ph + 1, icmp6, ntohs(ip6->ip6_plen));

      icmp6->icmp6_cksum = checksum((uint16_t*) ip6ph, ntohs(ip6->ip6_plen) + sizeof(struct ip6_psh));

      log_debug("writing %d bytes to tunfd %d", rlen, setup.tunfd[1]);
      if (write(setup.tunfd[1], buf, rlen) < rlen)
         log_msg(L_ERROR, "short write");
   }

   log_msg(L_FATAL, "error reading from pipe fd %d: %s", setup.icmpv6fd[0], strerror(errno));
   exit(1);
}


#if 0
#ifdef DEBUG
static char hexbuf_[FRAME_SIZE];
static char convbuf_[] = "0123456789ABCDEF";

char *buf2hex(const char *buf, int len)
{
   char *b = hexbuf_;
   for (; len; buf++, len--)
   {
      *b++ = convbuf_[((*buf) >> 4) & 0xf];
      *b++ = convbuf_[(*buf) & 0xf];
      *b++ = ' ';
   }
   *(b - 1) = '\0';
   return hexbuf_;
}

#endif


void *icmpv6_handler(void *p)
{
   char buf[FRAME_SIZE];
   int s, offset = 2, rlen;
   struct sockaddr_in6 in6;
   socklen_t slen;

   if ((s = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
   {
      log_msg(L_ERROR, "could not create ICMPv6 socket: %s", strerror(errno));
      return NULL;
   }

   if (setsockopt(s, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) == -1)
      log_msg(L_ERROR, "could not set IPV6_CHECKSUM on raw socket: %s", strerror(errno));

   for (;;)
   {
      slen = sizeof(in6);
      if ((rlen = recvfrom(s, buf, FRAME_SIZE, 0, (struct sockaddr*) &in6, &slen)) == -1)
      {
         log_msg(L_ERROR, "could not recvfrom(): %s", strerror(errno));
         continue;
      }
      log_debug("received %d bytes on raw socket %d", rlen, s);
      log_debug("%s", buf2hex(buf, rlen));
   }
}
#endif

