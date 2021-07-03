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

/*! \file ocatresolv.c
 *  This file contains all code for the OnionCat name/revptr resolution as well
 *  as the server code.
 *  There is no portable thread-safe low level resolver interface, thus, I
 *  wrote the code completely new for OnionCat. Although it is not a full
 *  resolver nor a full nameserver. It just implements those parts which are
 *  necessary as far as the conform to the standards, which is manly RFC1034
 *  and RFC1035.
 *
 *  Note: The code previously found in this file was deleted since it was never
 *  used.
 *
 *  \author Bernhard Fischer <bf@abenteuerland.at>
 *  \date 2021/07/03
 */


#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif


#define IP6REVLEN 74


/*! Convert an IPv6 address to a DNS reverse name of the format
 * x.x.x.x...ip6.arpa suitable for a DNS query message.
 * @param in6addr Pointer to the IPv6 address.
 * @param dst Pointer to the destination buffer. The buffer must have at least
 * 74 (IP6REVLEN) bytes.
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
   *((uint16_t*) (buf + sizeof(*dh) + IP6REVLEN)) = htons(T_PTR);
   *((uint16_t*) (buf + sizeof(*dh) + IP6REVLEN + 2)) = htons(C_IN);

   return sizeof(*dh) + IP6REVLEN + 2 + 2;
}


static char a2b(char a)
{
   if (a >= '0' && a <= '9')
      return a - '0';
   if (a >= 'a' && a <= 'f')
      return a - 'a' + 0xa;
   if (a >= 'A' && a <= 'F')
      return a - 'A' + 0xa;
   return '\0';
}


int oc_rev6ptr_addr(const char *buf, char *in6)
{
   int i, x;

   memset(in6, 0, 16);
   for (i = 31, x = 0; i >= 0; i--, x ^= 1)
   {
      if (*buf++ != '\001')
         return -1;
      in6[i >> 1] |= a2b(*buf++) << (4 * x);
   }
   return 0;
}


int oc_label_len(const char *s)
{
   char *t;

   t = strchr(s, '.');
   return t == NULL ? (int) strlen(s) : t - s;
}


/*! This function converts a DNS name in the regular form (xyz.example.com) to
 * the format suitable for a dns message.
 * @param name Pointer to the name (source).
 * @param buf Pointer to the destination.
 * @param len Bytes available in buf.
 * @return The function returns the total length of the final message name
 * including the terminating \0 (the root). On error, -1 is returned.
 */
int oc_name_dn(const char *name, char *buf, int len)
{
   int llen, dlen;

   // safety check
   if (name == NULL || buf == NULL || len < 1)
      return -1;

   // skip leading '.'s
   for (; *name == '.'; name++);

   for (dlen = 0; len > 0;)
   {
      // get length of label
      if ((llen = oc_label_len(name)) > 63)
         return -1;

      // check if there is enough space in the destination buffer
      if (len < llen + 2)
         return -1;

      // store label length
      *buf++ = llen;
      dlen++;

      // check if it was the last label
      if (!llen)
         break;

      // store label
      memcpy(buf, name, llen);
      buf += llen;
      dlen += llen;
      // decrease buffer length counter
      len -= llen + 1;
      name += llen;
      name++;
   }

   return dlen;
}


int oc_proc_request(char *buf, int msglen, int buflen)
{
   struct in6_addr in6;
   char name[NI_MAXHOST];
   HEADER *dh;
   time_t age;
   int n, source;

   // safety check
   if (buf == NULL || msglen < (int) sizeof(*dh))
      return -1;

   // init pointers
   dh = (HEADER*) buf;
   buf = (char*) (dh + 1);

   // basic header check
   if (dh->qr || dh->opcode != QUERY || dh->qdcount != htons(1) || dh->ancount || dh->nscount)
   {
      log_msg(LOG_WARNING, "query format error");
      dh->rcode = FORMERR;
      dh->qr = 1;
      return msglen;
   }
   dh->qr = 1;
   dh->ad = 0;

   // get length of query name
   n = strlen((char*) (dh + 1)) + 1;
   log_debug("query name length = %d", n);

   // remove EDSN0 .. FIXME: should be handled
   if (dh->arcount)
   {
      dh->arcount = 0;
      msglen = sizeof(*dh) + n + 2 + 2;
      log_debug("removed additional section, msglen = %d", msglen);
   }

   // check if it is a IN PTR query
   if (n != IP6REVLEN || *((uint16_t*) &buf[n]) != htons(T_PTR) || *((uint16_t*) &buf[n + 2]) != htons(C_IN))
   {
      log_debug("no ptr query");
      dh->rcode = NXDOMAIN;
      return msglen;
   }

   // check if it is a query for ip6.arpa.
   if (strcasecmp((char*) &buf[64], "\003ip6\004arpa"))
   {
      log_debug("no ip6.arpa query");
      dh->rcode = NXDOMAIN;
      return msglen;
   }

   // convert reverse name to address
   if (oc_rev6ptr_addr(buf, (char*) &in6) == -1)
   {
      log_debug("name error");
      dh->rcode = NXDOMAIN;
      return msglen;
   }

   inet_ntop(AF_INET6, &in6, name, sizeof(name));
   log_msg(LOG_INFO, "got dns request for address %s", name);

   // make sure to read hosts file
   hosts_check();
   // lookup hostname in memory
   if (hosts_get_name_ext(&in6, name, sizeof(name), &source, &age) == -1)
   {
      log_debug("no such name");
      dh->rcode = NXDOMAIN;
      return msglen;
   }

   // set authorative answer for hosts file entries
   if (source == HSRC_HOSTS)
      dh->aa = 1;

   // advance buf pointer to section befind question
   buf += n + 2 + 2;

   // construct compress name (same as question)
   buf[0] = 0xc0;
   buf[1] = sizeof(*dh);

   *((uint16_t*) &buf[2]) = htons(T_PTR);
   *((uint16_t*) &buf[4]) = htons(C_IN);
   int ttl = 3600;
   *((uint32_t*) &buf[6]) = htonl(ttl);
   //convert c string do dns string
   if ((n = oc_name_dn(name, &buf[12], buflen - msglen - 12)) == -1)
   {
      dh->rcode = SERVFAIL;
      return msglen;
   }
   *((uint16_t*) &buf[10]) = htons(n);
   dh->ancount = htons(1);
   msglen += n + 12;

   return msglen;
}


void *oc_nameserver(void *p)
{
   struct sockaddr_str ssaddr;
   struct sockaddr_in6 s6addr;
   char buf[PACKETSZ + 1];
   int fd = -1, len, n;
   struct timeval tv;
   socklen_t slen;
   fd_set rset;

   // create UDP socket
   if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
   {
      log_msg(LOG_ERR, "could not create nameserver socket");
      return NULL;
   }
   log_debug("created DNS socket on fd %d", fd);

   // init sockaddr structure for socket address
   slen = sizeof(s6addr);
   memset(&s6addr, 0, slen);
   s6addr.sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
   s6addr.sin6_len = slen;
#endif
   s6addr.sin6_port = htons(CNF(ocat_dest_port));
   IN6_ADDR_COPY(&s6addr.sin6_addr, &CNF(ocat_addr));

   // bind socket to address
   if (bind(fd, (struct sockaddr*) &s6addr, slen) == -1)
   {
      log_msg(LOG_ERR, "could not bind DNS socket: %s", strerror(errno));
      oe_close(fd);
      return NULL;
   }
   log_debug("bound dns socket %d", fd);

   // loop over connections
   for (;;)
   {
      if (term_req())
         break;

      FD_ZERO(&rset);
      FD_SET(fd, &rset);
      set_select_timeout(&tv);
      if ((n = select(fd + 1, &rset, NULL, NULL, &tv)) == -1)
      {
         log_msg(LOG_EMERG, "select encountered error: \"%s\", restarting", strerror(errno));
         continue;
      }

      if (!n)
         continue;

      slen = sizeof(s6addr);
      if ((len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*) &s6addr, &slen)) == -1)
      {
         log_msg(LOG_ERR, "recvfrom() failed: %s", strerror(errno));
         continue;
      }

      inet_ntops((struct sockaddr*) &s6addr, &ssaddr);
      log_msg(LOG_INFO, "received %d bytes by %s", len, ssaddr.sstr_addr);

      // make sure that there is \0-termination in the buffer
      buf[sizeof(buf) - 1] = '\0';

      if ((len = oc_proc_request(buf, len, sizeof(buf))) == -1)
      {
         log_msg(LOG_WARNING, "ignoring ill request");
         continue;
      }

      log_msg(LOG_INFO, "sending %d bytes reply", len);
      if ((len = sendto(fd, buf, len, 0, (struct sockaddr*) &s6addr, sizeof(s6addr))) == -1)
         log_msg(LOG_ERR, "sendto() failed: %s", strerror(errno));
      else
         log_msg(LOG_INFO, "dns reply sent");
   }

   oe_close(fd);
   return NULL;
}

