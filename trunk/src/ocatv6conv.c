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

/*! ocatv6conv.c
 *  These functions convert IPv6 addresses to onion URLs
 *  and vice versa.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunkt at>
 *  @version 2008/02/03-01
 */

#include "config.h"

#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#include "ocat.h"

static const char BASE32[] = "abcdefghijklmnopqrstuvwxyz234567";
static const char tor_prefix_[] = TOR_PREFIX;


int is_testping(const struct in6_addr *addr)
{
   char to[10] = {0,0,0,0,0,0,0,0,0,1};
   return memcmp((char*) addr + 6, to, 10) == 0;
}


int has_tor_prefix(const struct in6_addr *addr)
{
   return memcmp(addr, tor_prefix_, 6) == 0;
}


void set_tor_prefix(struct in6_addr *addr)
{
   memcpy(addr, tor_prefix_, 6);
}


void shl5(char *bin)
{
   int i;

   for (i = 0; i < 15; i++)
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


char *ipv6tonion(const struct in6_addr *ip6, char *onion)
{
   int i;
   char bin[16], *r = onion;

   memcpy(bin, (char*) ip6 + 6, 16);

   for (i = 0; i < 16; i++, onion++)
   {
      *onion = BASE32[bin[0] >> 3 & 0x1f];
      shl5(bin);
   }
   *onion = '\0';
   return r;
}

