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


/*! This function returns the length (number of bytes) of raw dns name in a dns
 * message.
 * @param buf Pointer to the beginning of the name.
 * @param buflen Total number of bytes in the buffer.
 * @return The function returns the number of bytes of the name in the message
 * (including the terminating \0 for the root). On error, -1 is returned. The
 * error occurs if there is a format error in the name or buflen was shorter
 * than the name.
 */
int oc_dn_len(const char *buf, int buflen)
{
   int len;
   uint8_t c;

   for (len = 0; buflen > 0;)
   {
      c = *buf++;
      buflen--;
      len++;

      // check if it is the root
      if (!c)
         return len;

      if (c <= 0x3f)
      {
         // buffer too small
         if (buflen < c)
            return -1;

         len += c;
         buflen -= c;
         buf += c;
         continue;
      }

      // check if it is a compressed name
      if (c == 0xc0)
      {
         if (buflen < 1)
            return -1;

         return len + 1;
      }

      log_msg(LOG_ERR, "error in DNS name");
      return -1;
   }

   return -1;
}


/*! Convert an IPv6 address to a DNS reverse name of the format
 * x.x.x.x...ip6.arpa suitable for a DNS query message.
 * @param in6addr Pointer to the IPv6 address.
 * @param dst Pointer to the destination buffer. The buffer must have at least
 * 74 (IP6REVLEN) bytes.
 */
void oc_ip6_ptr(const char *in6addr, char *dst)
{
   static char _dh[] = "0123456789abcdef";
   int i;

   for (i = 15; i >= 0; i--)
   {
      *dst++ = 1;
      *dst++ = _dh[in6addr[i] & 0xf];
      *dst++ = 1;
      *dst++ = _dh[(in6addr[i] >> 4) & 0xf];
   }
   strcpy(dst, "\003ip6\004arpa");
}


/*! Create a DNS message for a reverse query for a specific IPv6 address.
 * @param in6addr Pointer to the IPv6 address which should be queried.
 * @param buf Pointer to the destination buffer.
 * @param len Maximum length of the buffer.
 * @param id ID for the message.
 * @return Returns the total length of the final message (which is always 90),
 * or -1 in case of error.
 */
int oc_mk_ptrquery(const char *in6addr, char *buf, int len, uint16_t id)
{
   HEADER *dh;

   // safety checks
   if (buf == NULL || in6addr == NULL || len < (int) sizeof(*dh) + 78)
      return -1;

   dh = (HEADER*) buf;
   memset(dh, 0, sizeof(*dh));
   dh->id = id;
   dh->qdcount = htons(1);

   oc_ip6_ptr(in6addr, (char*) (dh + 1));
   *((uint16_t*) (buf + sizeof(*dh) + IP6REVLEN)) = htons(T_PTR);
   *((uint16_t*) (buf + sizeof(*dh) + IP6REVLEN + 2)) = htons(C_IN);

   return sizeof(*dh) + IP6REVLEN + 2 + 2;
}


static int a2b(char a)
{
   if (a >= '0' && a <= '9')
      return a - '0';
   if (a >= 'a' && a <= 'f')
      return a - 'a' + 0xa;
   if (a >= 'A' && a <= 'F')
      return a - 'A' + 0xa;
   return -1;
}


/*! This function converts an ip6 DNS reverse pointer (e.g.
 * 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa.)
 * to an IPv6 address in its binary format (struct in6_addr).
 * @param buf Pointer to the reverse pointer as found in a DNS message as
 * described in RFC1035.
 * @param in6 Destination pointer. The destination must be at least 16 bytes
 * long.
 * @return On success 0 is returned. In case of a format error -1 is returned.
 */
int oc_rev6ptr_addr(const char *buf, char *in6)
{
   int i, x, c;

   memset(in6, 0, 16);
   for (i = 31, x = 0; i >= 0; i--, x ^= 1)
   {
      if (*buf++ != '\001')
         return -1;
      if ((c = a2b(*buf++)) == -1)
         return -1;
      in6[i >> 1] |= c << (4 * x);
   }
   return 0;
}


/*! Determine the lenght of a label, i.e. the number of characters until a '.'
 * or '\0' character is found. The separating character is not included in the
 * result.
 * @param s Pointer to a \0-terminated string.
 * @return Returnes the number of chars to the next '.' or '\0'. The return
 * value always is >= 0.
 */
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


#define MAX_DECOMPRESS_LEVEL 3
static int oc_dn_name0(int level, const char *msg, int msglen, const char *dn, char *buf, int len)
{
   int dnlen, wlen;
   uint8_t c;

   // take care on endless recursion (cyclic compression dependency)
   if (level > MAX_DECOMPRESS_LEVEL)
   {
      log_msg(LOG_WARNING, "maximum recursion level, probably malicious dns response");
      return -1;
   }

   // get max dn length
   dnlen = msglen - (dn - msg);
   if (dnlen <= 0)
      return -1;

   for (wlen = 0; len > 0 && dnlen > 0;)
   {
      c = *dn++;
      dnlen--;

      if (!c)
      {
         *buf = '\0';
         // this it the only successful return from this function
         return wlen;
      }

      // check if it is a regular label
      if (c <= 0x3f)
      {
         if (wlen)
         {
            *buf++ = '.';
            len--;
            wlen++;
         }

         // check if dest buffer is long enough
         if (len <= c || dnlen < c)
            return -1;

         // copy label to dest buffer and handle counters
         memcpy(buf, dn, c);
         buf += c;
         len -= c;
         dn += c;
         dnlen -= c;
         wlen += c;
         continue;
      }

      // if it is a compressed label, recurse
      if (c == 0xc0)
         return oc_dn_name0(level + 1, msg, msglen, msg + *((unsigned char*) dn), buf, len);
   }

   return -1;
}


int oc_dn_name(const char *msg, int msglen, const char *dn, char *buf, int len)
{
   return oc_dn_name0(0, msg, msglen, dn, buf, len);
}


/*! This function processes a DNS request and constructs the answer directly
 * into the same buffer. If the request contains a value PTR request and the
 * name is found in the local database, a valid reply message is formed. If the
 * request contains any valid query or the name of the PTR request is not
 * found, a NXDOMAIN message is formed. If a format error in the request is
 * found, a FORMERR message is formed. If any other error occurred, -1 is
 * returned. No reply should be sent.
 * @param buf Pointer to the request/response buffer.
 * @param msglen Length of the request message.
 * @param buflen Total length of the buffer.
 * @return If a valid reply could be constructed, the length of the message is
 * replied. On error, -1 is returned.
 */
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
   log_msg(LOG_INFO, "got valid DNS request for address %s", name);

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


int oc_proc_response(const char *buf, int msglen, uint16_t org_id, const struct in6_addr *org_addr)
{
   char name[SIZE_256];
   struct in6_addr in6;
   unsigned ttl;
   HEADER *dh;
   int n, omsglen;

   // safety check
   if (buf == NULL || msglen < (int) sizeof(*dh))
      return -1;

   // init pointers
   dh = (HEADER*) buf;
   buf = (char*) (dh + 1);
   omsglen = msglen;
   msglen -= sizeof(*dh);

   // check message id
   if (dh->id != org_id)
   {
      log_msg(LOG_ERR, "DNS response id does not match request");
      return -1;
   }

   if (!dh->qr || dh->opcode != QUERY || ntohs(dh->qdcount) != 1)
   {
      log_msg(LOG_ERR, "DNS response format error");
      return -1;
   }

   if (dh->rcode != NOERROR)
   {
      log_msg(LOG_ERR, "DNS server replied error: %d", dh->rcode);
      return -1;
   }

   if (ntohs(dh->ancount) != 1)
   {
      log_msg(LOG_ERR, "DNS reply has unexpected number of answers: %d", ntohs(dh->ancount));
      return -1;
   }

   n = oc_dn_len(buf, msglen);
   // check if it is a IN PTR query
   if (n != IP6REVLEN || *((uint16_t*) &buf[n]) != htons(T_PTR) || *((uint16_t*) &buf[n + 2]) != htons(C_IN))
   {
      log_debug("no ptr query");
      return -1;
   }

   // convert reverse name to address
   if (oc_rev6ptr_addr(buf, (char*) &in6) == -1)
   {
      log_debug("name error");
      return -1;
   }

   if (!IN6_ARE_ADDR_EQUAL(&in6, org_addr))
   {
      log_msg(LOG_ERR, "query name does not match expected query name");
      return -1;
   }

   // advance buffer to answer section
   buf += n + 2 + 2;
   msglen -= n + 2 + 2;
   n = oc_dn_len(buf, msglen);

   if (*((uint16_t*) &buf[n]) != htons(T_PTR) || *((uint16_t*) &buf[n + 2]) != htons(C_IN))
   {
      log_msg(LOG_ERR, "malformed answer");
      return -1;
   }

   ttl = ntohl(*((uint32_t*) &buf[n + 4]));

   if (oc_dn_name((char*) dh, omsglen, buf + n + 10, name, sizeof(name)) == -1)
   {
      log_msg(LOG_WARNING, "could not decode name");
      return -1;
   }

   if (hosts_add_entry(org_addr, name, dh->aa ? HSRC_NET_AA : HSRC_NET, time(NULL), ttl) == -1)
   {
      log_msg(LOG_WARNING, "could not add new hosts entry: %s", name);
      return -1;
   }

   return 0;
}


int oc_ns_socket(void)
{
   struct sockaddr_in6 s6addr;
   socklen_t slen;
   int fd;

   // create UDP socket
   if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
   {
      log_msg(LOG_ERR, "could not create nameserver socket");
      return -1;
   }
   log_debug("created DNS socket on fd %d", fd);

   // init sockaddr structure for socket address
   slen = sizeof(s6addr);
   memset(&s6addr, 0, slen);
   s6addr.sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
   s6addr.sin6_len = slen;
#endif
   s6addr.sin6_port = htons(CNF(ocat_ns_port));
   IN6_ADDR_COPY(&s6addr.sin6_addr, &CNF(ocat_addr));

   // cannot bind before address was assigned in the main thread
   //wait_thread_by_name_ready("main");

   // bind socket to address
   if (bind(fd, (struct sockaddr*) &s6addr, slen) == -1)
   {
      log_msg(LOG_ERR, "could not bind DNS socket: %s", strerror(errno));
      oe_close(fd);
      return -1;
   }

   return fd;
}


/*! This is the nameserver main loop. It waits for incoming packets, receives
 * on after the other end processes the requests. If the requests are valid,
 * answers are sent dependent if the names in the queries are found in the
 * local DB, or not. In the latter case NXDOMAIN is relied.
 */
void *oc_nameserver(void *UNUSED(p))
{
   struct sockaddr_str ssaddr;
   struct sockaddr_in6 s6addr;
   char buf[PACKETSZ + 1];
   int fd = -1, len, n;
   struct timeval tv;
   socklen_t slen;
   fd_set rset;

   detach_thread();

   if ((fd = oc_ns_socket()) == -1)
      return NULL;

   set_thread_ready();

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
         log_msg(LOG_ERR, "select encountered error: \"%s\", restarting", strerror(errno));
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
      log_debug("received %d bytes by %s", len, ssaddr.sstr_addr);

      // make sure that there is \0-termination in the buffer
      buf[sizeof(buf) - 1] = '\0';

      if ((len = oc_proc_request(buf, len, sizeof(buf))) == -1)
      {
         log_msg(LOG_WARNING, "ignoring ill request");
         continue;
      }

      log_debug("sending %d bytes reply", len);
      if ((len = sendto(fd, buf, len, 0, (struct sockaddr*) &s6addr, sizeof(s6addr))) == -1)
      {
         log_msg(LOG_ERR, "sendto() failed: %s", strerror(errno));
         continue;
      }

      log_msg(LOG_INFO, "DNS reply sent to %s", ssaddr.sstr_addr);
   }

   oe_close(fd);
   return NULL;
}

