/*! ocatv6conv.c
 *  These functions convert IPv6 addresses to onion URLs
 *  and vice versa.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunkt at>
 *  @version 2008/02/03-01
 */

#include <string.h>
#include <netinet/ip6.h>

#include "ocat.h"

static const char BASE32[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','j','k','m','n','o','p','q','r','s','t','v','w','x','y','z'};


void shl5(char *bin)
{
   int i;

   for (i = 0; i < 15; i++)
   {
      bin[i] <<= 5;
      bin[i] |= (bin[i + 1] >> 3) & 0x1f;
   }
}


int oniontipv6(const char *onion, struct in6_addr *ip6)
{
   int i, j, c;

   memset(ip6, 0, 16);
   for (i = 0; i < 16; i++)
   {
      shl5((char*) ip6);
      for (j = 0; j < 32; j++)
         if (tolower(*onion) == BASE32[j])
            break;
      if (j == 32)
         return -1;
      *(((char*) ip6) + 15) |= j;
   }
   return 0;
}


void ipv6tonion(const struct in6_addr *ip6, char *onion)
{
   int i, j;
   char bin[16];

   memcpy(bin, (char*) ip6 + 6, 16);

   for (i = 0; i < 16; i++, onion++)
   {
      *onion = BASE32[bin[0] >> 3 & 0x1f];
      shl5(bin);
      /*
      for (j = 0; j < 15; j++)
      {
         bin[j] <<= 5;
         bin[j] |= (bin[j + 1] >> 3) & 0x1f;
      }
      */
   }
   *onion = '\0';
}

