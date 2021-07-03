/* Copyright 2008-2021 Bernhard R. Fischer.
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

/*! \file ocatdns.c
 *
 *  \author Bernhard Fischer <bf@abenteuerland.at>
 *  \date 2021/07/02
 */


#include "ocat.h"
#include "ocat_netdesc.h"

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif


/*! Convert an IPv6 address to a DNS reverse name of the format
 * x.x.x.x...ip6.arpa suitable for a DNS query message.
 * @param in6addr Pointer to the IPv6 address.
 * @param dst Pointer to the destination buffer. The buffer must have at least
 * 74 bytes.
 */
void oc_ip6_ptr(const char *in6addr, char *dst)
{
   static char _dh[] = "0123456789abcdef";

   for (int i = 15; i >= 0; i--)
   {
      *dst++ = 1;
      *dst++ = _dh[in6addr[i] & 0xf];
      *dst++ = 1;
      *dst++ = _dh[(in6addr[i] >> 4) & 0xf];
   }
   strcat(dst, "\003ip6\004arpa");
}


/*! Create a DNS message for a reverse query for a specific IPv6 address.
 * @param in6addr Pointer to the IPv6 address which should be queried.
 * @param buf Pointer to the destination buffer.
 * @param len Maximum length of the buffer.
 * @return Returns the total length of the final message (which is always 90),
 * or -1 in case of error.
 */
int oc_mk_ptrquery(const char *in6addr, char *buf, int len)
{
   HEADER *dh;

   // safety checks
   if (buf == NULL || in6addr == NULL || len < (int) sizeof(*dh) + 78)
      return -1;

   dh = (HEADER*) buf;
   memset(dh, 0, sizeof(*dh));
   dh->id = rand();
   dh->qdcount = htons(1);

   oc_ip6_ptr(in6addr, (char*) (dh + 1));
   *((uint16_t*) (buf + sizeof(*dh) + 74)) = htons(T_PTR);
   *((uint16_t*) (buf + sizeof(*dh) + 76)) = htons(C_IN);

   return sizeof(*dh) + 74 + 2 + 2;
}

