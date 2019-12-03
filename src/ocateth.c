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


#include "ocat.h"


static MACTable_t mac_tbl_[MAX_MAC_ENTRY];
static int mac_cnt_ = 0;
static pthread_mutex_t mac_mutex_ = PTHREAD_MUTEX_INITIALIZER;


/*! Pseudo header for IPv6 checksum calculation.
 *  RFC2460 8.1, (RFC1885 2.3) RFC2463, RFC1071. */
/* RFC2461, rfc2462, RFC2464 ipv6 ethernet enc.
 * RFC2373 is obsoleted by RFC3513 addressing ipv6
 * RFC2461 is obsoleted by RFC4861
 * RFC4862 IPv6 Stateless Address Autoconfiguration
 * RFC4443 ICMP6 (updates 2780, obsoletes 2463) (20101230)
 */

/* IPv6 Ethernet Multicast: (MAC) 33:33:xx:xx:xx:xx, xx -> 4 lowest order bytes of IPv6 destination
 * Solicited-Node address: (IPv6) FF02:0:0:0:0:1:ffxx:xxxx, -> xx -> 3 lowest order bytes of IPv6 destination (RFC4291)
 * IPv4 Ethernet Multicast: 01:00:5e:0xx:xx:xx, */


void print_mac_tbl(FILE *f)
{
   int i;
   char buf[INET6_ADDRSTRLEN];

   //fprintf(f, "  # age MAC               C   address\n");
   pthread_mutex_lock(&mac_mutex_);

   for (i = 0; i < mac_cnt_; i++)
   {
      fprintf(f, "%3d %3d %s ", i, (int) (time(NULL) - mac_tbl_[i].age), ether_ntoa_r((struct ether_addr*) mac_tbl_[i].hwaddr, buf));
      fprintf(f, "%s ", mac_tbl_[i].family == AF_INET6 ? "IN6" : "IN ");
      inet_ntop(mac_tbl_[i].family, &mac_tbl_[i].in6addr, buf, INET6_ADDRSTRLEN);
      fprintf(f, "%s\n", buf);
   }

   pthread_mutex_unlock(&mac_mutex_);
}


/*! Scan MAC table for outages (age > MAX_MAC_AGE) and remove entries.
 */
void mac_cleanup(void)
{
   int i;
#ifdef DEBUG
   char hw[20];
#endif

   pthread_mutex_lock(&mac_mutex_);

   for (i = 0; i < mac_cnt_; i++)
      if (mac_tbl_[i].age + MAX_MAC_AGE < time(NULL))
      {
         log_debug("mac table entry %d (%s) timed out", i, ether_ntoa_r((struct ether_addr*) mac_tbl_[i].hwaddr, hw));
         memmove(&mac_tbl_[i], &mac_tbl_[i + 1], sizeof(MACTable_t) * (MAX_MAC_ENTRY - i));
         mac_cnt_--;
         i--;
      }

   pthread_mutex_unlock(&mac_mutex_);
}


/*! Lookup an entry in the MAC-table by IP, update age.
 *  If hwaddr != NULL and MAC eq 00:00:00:00:00:00 then copy MAC entry
 *  from MAC table to hwaddr, otherwise copy hwaddr to MAC table.
 *  @return -1 if no entry available, otherwise index of entry in table starting with 0.
 */
int mac_set(const struct in6_addr *in6, uint8_t *hwaddr)
{
   int i;

   pthread_mutex_lock(&mac_mutex_);

   for (i = mac_cnt_ - 1; i >= 0; i--)
      if (IN6_ARE_ADDR_EQUAL(in6, &mac_tbl_[i].in6addr))
      {
         if (hwaddr)
         {
            if (!hwaddr[0] && !hwaddr[1] && !hwaddr[2] && !hwaddr[3] && !hwaddr[4] && !hwaddr[5])
               memcpy(hwaddr, &mac_tbl_[i].hwaddr, ETHER_ADDR_LEN);
            else
               memcpy(&mac_tbl_[i].hwaddr, hwaddr, ETHER_ADDR_LEN);
         }
         mac_tbl_[i].age = time(NULL);
         break;
      }

   pthread_mutex_unlock(&mac_mutex_);

   return i;
}


/*! Wrapper function for mac_set() (see above) to keep valid pointer alignment. */
int mac_set_s(struct in6_addr in6, uint8_t *hwaddr)
{
   return mac_set(&in6, hwaddr);
}


/*! Add MAC/IPv6-pair to MAC table.
 *  @param hwaddr MAC address.
 *  @param in6 IPv6 address.
 *  @return Index of entry (starting with 0) or -1 if MAC table is full (MAX_MAC_ENTRY)
 */
int mac_add_entry(const uint8_t *hwaddr, struct in6_addr in6)
{
   int e = -1;

   pthread_mutex_lock(&mac_mutex_);

   if (mac_cnt_ < MAX_MAC_ENTRY)
   {
      log_debug("adding entry to MAC table %d", mac_cnt_);
      memcpy(&mac_tbl_[mac_cnt_].hwaddr, hwaddr, ETHER_ADDR_LEN);
      IN6_ADDR_COPY(&mac_tbl_[mac_cnt_].in6addr, &in6);
      mac_tbl_[mac_cnt_].age = time(NULL);
      mac_tbl_[mac_cnt_].family = AF_INET6;
      e = mac_cnt_++;
   }

   pthread_mutex_unlock(&mac_mutex_);

   return e;
}


/*! Lookup entry by MAC address in MAC-table. It returns the first
 *  occurence and updates the age.
 *  @param hwaddr MAC address to search for.
 *  @param in6 If not NULL, this buffer is filled with the IPv6 address.
 *  @return Index of entry or -1 if no entry exists.
 */
int mac_get_ip(const uint8_t *hwaddr, struct in6_addr *in6)
{
   int i;

   pthread_mutex_lock(&mac_mutex_);

   for (i = mac_cnt_ - 1; i >= 0; i--)
      if (!memcmp(hwaddr, &mac_tbl_[i].hwaddr, ETHER_ADDR_LEN))
      {
         if (in6)
            memcpy(in6, &mac_tbl_[i].in6addr, sizeof(struct in6_addr));
         mac_tbl_[i].age = time(NULL);
         break;
      }

   pthread_mutex_unlock(&mac_mutex_);

   return i;
}


/*! Calculate 16 bit one's complement checksum (RFC1071) suitable for ICMPv6.
 *  @param buf Pointer to buffer.
 *  @param len Number of bytes in buffer.
 *  @return Checksum of buffer.
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


/*! Free checksum buffer.
 */
void free_ckbuf(uint16_t *buf)
{
   free(buf);
}


/*! Malloc and fill buffer suitable for ICMPv6 checksum calculation.
 */
uint16_t *malloc_ckbuf(struct in6_addr src, struct in6_addr dst, uint16_t plen, uint8_t proto, const void *payload)
{
   struct ip6_psh *psh;

   if (!(psh = calloc(1, sizeof(struct ip6_psh) + plen)))
   {
      log_msg(LOG_EMERG, "error creating checksum buffer: %s", strerror(errno));
      //return NULL;
      exit(1);
   }

   psh->src = src;
   psh->dst = dst;
   psh->len = htons(plen);
   psh->nxt = proto;
   memcpy(psh + 1, payload, plen);

   return (uint16_t*) psh;
}


/*! Send NDP solicitation for dst to appropriate IPv6 multicast address.
 *  @param src Source address.
 *  @param dst Solicited target address.
 *  @return Returns always 0.
 */
int ndp_solicit(const struct in6_addr *src, const struct in6_addr *dst)
{
   char buf[sizeof(ndp6_t) + sizeof(struct nd_opt_hdr) + 4 + ETHER_ADDR_LEN];
   ndp6_t *ndp6 = (ndp6_t*) (buf + 4);
   struct nd_opt_hdr *ohd = (struct nd_opt_hdr*) (ndp6 + 1);
   uint16_t *ckb;
   struct in6_addr mcastd = {{{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0}}};

   // clear buffer and setup ipv6 multicast destination
   memset(buf, 0, sizeof(buf));
   memcpy(((char*) &mcastd) + 13, ((char*) dst) + 13, 3);

   // tunnel header
   set_tunheader(buf, htonl(CNF(fhd_key[IPV6_KEY])));

   // ethernet header
   ndp6->eth.ether_dst[0] = 0x33;
   ndp6->eth.ether_dst[1] = 0x33;
   memcpy(&ndp6->eth.ether_dst[2], ((char*) &mcastd) + 12, 4);
   memcpy(ndp6->eth.ether_src, CNF(ocat_hwaddr), ETHER_ADDR_LEN);
   ndp6->eth.ether_type = htons(ETHERTYPE_IPV6);

   // ipv6 header
   ndp6->ip6.ip6_vfc = 0x60;
   ndp6->ip6.ip6_plen = htons(sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + ETHER_ADDR_LEN);
   ndp6->ip6.ip6_nxt = IPPROTO_ICMPV6;
   ndp6->ip6.ip6_hlim = 255;
   memcpy(&ndp6->ip6.ip6_src, src, sizeof(struct in6_addr));
   memcpy(&ndp6->ip6.ip6_dst, &mcastd, sizeof(struct in6_addr));

   // icmpv6 header (partially)
   ndp6->icmp6.icmp6_type = ND_NEIGHBOR_SOLICIT;

   // ndp solicit header
   memcpy(&ndp6->ndp_sol.nd_ns_target, dst, sizeof(struct in6_addr));

   // icmpv6 ndp option
   ohd->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
   ohd->nd_opt_len = 1;
   memcpy(ohd + 1, ndp6->eth.ether_src, ETHER_ADDR_LEN);

   // calculate checksum
   ckb = malloc_ckbuf(ndp6->ip6.ip6_src, ndp6->ip6.ip6_dst, ntohs(ndp6->ip6.ip6_plen), IPPROTO_ICMPV6, &ndp6->icmp6);
   ndp6->icmp6.icmp6_cksum = checksum(ckb, ntohs(ndp6->ip6.ip6_plen) + sizeof(struct ip6_psh));
   free_ckbuf(ckb);

#ifdef __CYGWIN__
   log_debug("writing %d bytes ndp solicitation to TAP driver", sizeof(buf) - 4);
   // FIXME: there's no error checking
   win_write_tun(buf + 4, sizeof(buf) - 4);
#else
   log_debug("writing %d bytes ndp solicitation to tunfd %d", sizeof(buf), CNF(tunfd[1]));
   if (write(CNF(tunfd[1]), buf, sizeof(buf)) < sizeof(buf))
      log_msg(LOG_ERR, "short write to tun fd %d", CNF(tunfd[1]));
#endif

   return 0;
}


/*! Wrapper function for macro IN6_IS_ADDR_MULTICAST to keep valid pointer alignment. */
static int IN6_IS_ADDR_MULTICAST_S(struct in6_addr a)
{
   return IN6_IS_ADDR_MULTICAST(&a);
}


/*! Wrapper function for macro IN6_IS_ADDR_MC_LINKLOCAL to keep valid pointer alignment. */
static int IN6_IS_ADDR_MC_LINKLOCAL_S(struct in6_addr a)
{
   return IN6_IS_ADDR_MC_LINKLOCAL(&a);
}


/*! Wrapper function for macro IN6_IS_ADDR_UNSPECIFIED_S to keep valid pointer alignment. */
static int IN6_IS_ADDR_UNSPECIFIED_S(struct in6_addr a)
{
   return IN6_IS_ADDR_UNSPECIFIED(&a);
}


/*! Check neighbor solicitation and generate advertisement.
 *  @param buf pointer to frame buffer.
 *  @param rlen buffer length, must be at least sizeof(ICMPv6 header) + 4.
 *  @return 0 if everything gone write, -1 on failure.
 */
int ndp_soladv(char *buf, int rlen)
{
   ndp6_t *ndp6 = (ndp6_t*) (buf + 4);
   struct nd_opt_hdr *ohd = (struct nd_opt_hdr*) (ndp6 + 1);
   uint16_t *ckb, cksum;
#ifdef DEBUG
   char hw[20];
#endif

   if (ndp6->eth.ether_dst[0] & 1)
   {
      // check for right multicast destination on ethernet
      if (ndp6->eth.ether_dst[2] != 0xff)
      {
         log_debug("ethernet multicast destination %s cannot be solicited node address", ether_ntoa_r((struct ether_addr*) ndp6->eth.ether_dst, hw));
         return -1;
      }

      // check for right multicast destination in IPv6
      if (!IN6_IS_ADDR_MULTICAST_S(ndp6->ip6.ip6_dst) || !IN6_IS_ADDR_MC_LINKLOCAL_S(ndp6->ip6.ip6_dst))
      {
         log_debug("IPv6 multicast destination not solicited node address");
         return -1;
      }
   }

   ckb = malloc_ckbuf(ndp6->ip6.ip6_src, ndp6->ip6.ip6_dst, ntohs(ndp6->ip6.ip6_plen), IPPROTO_ICMPV6, &ndp6->icmp6);
   cksum = checksum(ckb, ntohs(ndp6->ip6.ip6_plen) + sizeof(struct ip6_psh));
   free_ckbuf(ckb);

   if (cksum)
   {
      log_msg(LOG_ERR, "icmpv6 checksum wrong");
      return -1;
   }

   // check for duplicate address detection
   if (IN6_IS_ADDR_UNSPECIFIED_S(ndp6->ip6.ip6_src))
   {
      log_debug("duplicate address detection in progress");
      //FIXME: we should check something more here. See RFC2462
      return -1;
   }

   struct in6_addr _nst;
   IN6_ADDR_COPY(&_nst, &ndp6->ndp_sol.nd_ns_target);
   if (!has_tor_prefix(&_nst))
   //if (!IN6_HAS_TOR_PREFIX(&ndp6->ndp_sol.nd_ns_target))
   {
      log_debug("solicit target is not TOR IPv6");
      return -1;
   }

   log_debug("generating response");
   // add source MAC to table
   if (mac_set_s(ndp6->ip6.ip6_src, ndp6->eth.ether_src) == -1)
      if (mac_add_entry(ndp6->eth.ether_src, ndp6->ip6.ip6_src) == -1)
      {
         log_msg(LOG_ERR, "MAC table full");
         return -1;
      }

   // set MAC addresses for response
   memcpy(ndp6->eth.ether_dst, ndp6->eth.ether_src, ETHER_ADDR_LEN);
   memcpy(ndp6->eth.ether_src, CNF(ocat_hwaddr), ETHER_ADDR_LEN);

   // init ip6 header
   memcpy(&ndp6->ip6.ip6_dst, &ndp6->ip6.ip6_src, sizeof(struct in6_addr));
   memcpy(&ndp6->ip6.ip6_src, &ndp6->ndp_sol.nd_ns_target, sizeof(struct in6_addr));

   // init nda icmp6 header
   ndp6->ndp_adv.nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
   ndp6->ndp_adv.nd_na_hdr.icmp6_code = 0;
   ndp6->ndp_adv.nd_na_hdr.icmp6_cksum = 0;
   ndp6->ndp_adv.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED;

   //FIXME: setting target option does not check total frame length!
   ohd->nd_opt_type = ND_OPT_TARGET_LINKADDR;
   memcpy(ohd + 1, CNF(ocat_hwaddr), ETHER_ADDR_LEN);

   ckb = malloc_ckbuf(ndp6->ip6.ip6_src, ndp6->ip6.ip6_dst, ntohs(ndp6->ip6.ip6_plen), IPPROTO_ICMPV6, &ndp6->icmp6);
   ndp6->ndp_adv.nd_na_hdr.icmp6_cksum = checksum(ckb, ntohs(ndp6->ip6.ip6_plen) + sizeof(struct ip6_psh));
   free_ckbuf(ckb);

#ifdef __CYGWIN__
   log_debug("writing %d bytes to TAP driver", rlen);
   // FIXME: there's no error checking
   win_write_tun(buf + 4, rlen - 4);
#else
   log_debug("writing %d bytes to tunfd %d", rlen, CNF(tunfd[1]));
   if (write(CNF(tunfd[1]), buf, rlen) < rlen)
      log_msg(LOG_ERR, "short write");
#endif

   return 0;
}


/*! Extract source ipv6 and MAC address and add/update MAC table.
 *  FIXME: there should be some additional checks!
 */
int ndp_recadv(char *buf, int len)
{
   ndp6_t *ndp6 = (ndp6_t*) (buf + 4);

   // add source MAC to table
   if (mac_set_s(ndp6->ip6.ip6_src, ndp6->eth.ether_src) == -1)
      if (mac_add_entry(ndp6->eth.ether_src, ndp6->ip6.ip6_src) == -1)
      {
         log_msg(LOG_ERR, "MAC table full");
         return -1;
      }
   return 0;
}


int eth_ndp(char *buf, int len, int ndp_type)
{
   switch (ndp_type)
   {
      case ND_NEIGHBOR_SOLICIT:
         log_debug("ND_NEIGHBOR_SOLICIT received");
         (void) ndp_soladv(buf, len);
         return 0;

      case ND_NEIGHBOR_ADVERT:
         log_debug("ND_NEIGHBOR_ADVERT received");
         (void) ndp_recadv(buf, len);
         return 0;
   }
   return -1;
}


/*! Check if destination MAC is designated for OnionCat and
 *  L4-Protocol is ICMPv6.
 *  @return 0 if packet does not match criteria, -1 else.
 */
int eth_check(char *buf, int len)
{
   ndp6_t *ndp6= (ndp6_t*) (buf + 4);

   // check minimum frame length
   if (len < sizeof(struct ether_header) + 4)
   {
      log_msg(LOG_ERR, "frame too short, len = %d < 4 + %d", len, sizeof(struct ether_header));
      return E_ETH_TRUNC;
   }

   // check ethernet destination
   if ((ndp6->eth.ether_dst[0] != 0x33) && (ndp6->eth.ether_dst[1] != 0x33) && memcmp(ndp6->eth.ether_dst, CNF(ocat_hwaddr), ETHER_ADDR_LEN))
   {
      log_debug("unknown destination MAC");
      return E_ETH_ILLDEST;
   }

   // check L3 protocol
   if (ndp6->eth.ether_type != htons(ETHERTYPE_IPV6))
   {
      log_msg(LOG_ERR, "L3 protocol not implemented 0x%04x", ntohs(ndp6->eth.ether_type));
      return E_ETH_ILLPROTO;
   }

   // check for ndp
   if ((len >= sizeof(ndp6_t) + 4) && (ndp6->ip6.ip6_nxt == IPPROTO_ICMPV6))
   {
      log_debug("ICMPv6 frame intercepted, icmp6_type = %d", ndp6->icmp6.icmp6_type);
      if (eth_ndp(buf, len, ndp6->icmp6.icmp6_type) != -1)
         return E_ETH_INTERCEPT;
   }

   // else forward as usual
   return 0;
}


#ifndef HAVE_ETHER_NTOA

#define ETHER_ADDR_BUF_SIZE 18
static char ether_addr_buf_[ETHER_ADDR_BUF_SIZE];

char *ether_ntoa(const struct ether_addr *addr)
{
   snprintf(ether_addr_buf_, ETHER_ADDR_BUF_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
         addr->ether_addr_octet[0], addr->ether_addr_octet[1], addr->ether_addr_octet[2],
         addr->ether_addr_octet[3], addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
   return ether_addr_buf_;
}

#endif


#ifndef HAVE_ETHER_NTOA_R

static pthread_mutex_t ether_ntoa_mutex_ = PTHREAD_MUTEX_INITIALIZER;

char *ether_ntoa_r(const struct ether_addr *addr, char *buf)
{
   if (!buf)
      return NULL;

   pthread_mutex_lock(&ether_ntoa_mutex_);
   strlcpy(buf, ether_ntoa((struct ether_addr*) addr), 18);
   pthread_mutex_unlock(&ether_ntoa_mutex_);
   return buf;
}

#endif

