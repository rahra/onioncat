/* Copyright 2008,2009 Bernhard R. Fischer.
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
#include "ocat_netdesc.h"

static const char BASE32[] = "abcdefghijklmnopqrstuvwxyz234567";
//! array contains inverse mapping of base32 starting with '2'.
static const char deBASE32_[] = {
   /*          2   3   4   5   6   7   8   9   
              32  33  34  35  36  37  38  39  3a  3b  3c  3d  3e  3f */
              26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1,
   /*      A   B   C   D   E   F   G   H   I   J   K   L   M   N   O 
      40  41  42  43  44  45  46  47  48  49  4a  4b  4c  4d  4e  4f */
      -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 
   /*  P   Q   R   S   T   U   V   W   X   Y   Z
      50  51  52  53  54  55  56  57  58  59  5a */
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25 };  


int has_tor_prefix(const struct in6_addr *addr)
{
   return memcmp(addr, &NDESC(prefix), 6) == 0;
}


void set_tor_prefix(struct in6_addr *addr)
{
   memcpy(addr, &NDESC(prefix), 6);
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
      j = toupper((int) onion[i]);
      if ((j < '2') || (j > 'Z'))
         return -1;
      if ((j = deBASE32_[j - '2']) == -1)
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


/*! Generate a random onion-URL.
 *  @paran onion must be of at least ONION_URL_LEN + 1 (=17).
 */
void rand_onion(char *onion)
{
   int i;

   if (RAND_MAX < 32)
      log_msg(LOG_WARNING, "weak randomness: RAND_MAX = %d < 32", RAND_MAX);

   for (i = 0; i < ONION_URL_LEN; i++, onion++)
      *onion = BASE32[rand() & 0x1f];
   *onion = '\0';
}


/*! Convert struct sockaddr to stuct sockaddr_str which holds the address
 *  in string representation.
 *  @param saddr Const pointer to source of type struct sockaddr-
 *  @param sas Pointer to destination of type struct sockaddr_str.
 *  @return Pointer to string (sas->sstr_addr) or NULL on error. In the
 *          latter case errno will be set correctly.
 */
const char *inet_ntops(const struct sockaddr *saddr, struct sockaddr_str *sas)
{
   char *src;

   log_debug("convert sockaddr %p to sockaddr_str %p", saddr, sas);
   switch (saddr->sa_family)
   {
      case AF_INET:
         src = (char*) &((struct sockaddr_in*) saddr)->sin_addr;
         sas->sstr_port = ((struct sockaddr_in*) saddr)->sin_port;
         break;

      case AF_INET6:
         src = (char*) &((struct sockaddr_in6*) saddr)->sin6_addr;
         sas->sstr_port = ((struct sockaddr_in6*) saddr)->sin6_port;
         break;

      default:
         errno = EAFNOSUPPORT;
         return NULL;
   }

   sas->sstr_family = saddr->sa_family;
   return inet_ntop(saddr->sa_family, src, sas->sstr_addr, sizeof(sas->sstr_addr));
}

