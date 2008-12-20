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
 *  ocatv6conv.c
 *  These functions convert IPv6 addresses to onion URLs
 *  and vice versa.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunkt at>
 *  @version 2008/02/03-01
 */


#include "ocat.h"

static const char BASE32[] = "abcdefghijklmnopqrstuvwxyz234567";
static const struct in6_addr tor_prefix_ = TOR_PREFIX;


int has_tor_prefix(const struct in6_addr *addr)
{
   return memcmp(addr, &tor_prefix_, 6) == 0;
}


void set_tor_prefix(struct in6_addr *addr)
{
   memcpy(addr, &tor_prefix_, 6);
}


/*! Shift byte buffer of size ONION_URL_LEN (=17) 5 bits to the left.
 *  @param bin Pointer to byte buffer, must be at least ONION_URL_LEN
 *             bytes long.
 */
void shl5(char *bin)
{
   int i;

   for (i = 0; i < ONION_URL_LEN - 1; i++)
   {
      bin[i] <<= 5;
      bin[i] |= (bin[i + 1] >> 3) & 0x1f;
   }
   bin[i] <<= 5;
}


int oniontipv6(const char *onion, struct in6_addr *ip6)
{
   int i, j;

   memset(ip6, 0, sizeof(struct in6_addr));

   for (i = 0; i < 16; i++)
   {
      shl5((char*) ip6);
      for (j = 0; j < 32; j++)
         if (tolower(onion[i]) == BASE32[j])
            break;
      if (j == 32)
         return -1;
      *(((char*) ip6) + 15) |= j;
   }
   set_tor_prefix(ip6);
   return 0;
}


int oniontipv4(const char *onion, struct in_addr *ip, int prefix_mask)
{
   struct in6_addr ip6;
   //uint32_t netmask = 0xffffffff << (32 - prefix_len);
   uint32_t netmask = prefix_mask;
   uint32_t ip4;

   if (oniontipv6(onion, &ip6))
      return -1;
   memcpy(&ip4, &ip6.s6_addr[12], sizeof(ip4));
   ip4 &= htonl(~netmask);
   ip->s_addr |= ip4;
   return 0;
}


/*! Convert IPv6 address to onion-URL (without ".onion").
 *  @param ip6 Pointer to IPv6 address of type struct in6_addr.
 *  @param onion Pointer to buffer to should receive onion-URL.
 *         The buffer *must* be at least ONION_URL_LEN + 1 (=17) bytes long.
 *  @return Returns always again pointer to buffer.
 */
char *ipv6tonion(const struct in6_addr *ip6, char *onion)
{
   int i;
   char bin[ONION_URL_LEN], *r = onion;

   memcpy(bin, (char*) ip6 + 6, 10);

   for (i = 0; i < ONION_URL_LEN; i++, onion++)
   {
      *onion = BASE32[bin[0] >> 3 & 0x1f];
      shl5(bin);
   }
   *onion = '\0';
   return r;
}

