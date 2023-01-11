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
 *  necessary as far as the conform to the standards, which is mainly RFC1034
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
#include "ocatresolv.h"

/*#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif*/
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif


#define IP6REVLEN 74


#ifdef WITH_DNS_RESOLVER
static ocres_state_t *orstate_ = NULL;
static pthread_mutex_t orstate_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static int ocres_pipe_fd_[2];
#endif


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


/*! Determine the length of a label, i.e. the number of characters until a '.'
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
      if ((c & 0xc0) == 0xc0)
         return oc_dn_name0(level + 1, msg, msglen, msg + *((unsigned char*) dn) + ((c & 0x3f) << 8), buf, len);
   }

   return -1;
}


/*! This function decodes a name as found in a dns message into a regular dns
 * name aaa.bbb.tld.
 * @param msg Pointer to the beginning of the message.
 * @param msglen Length of the message in bytes.
 * @param dn Pointer to name within the message to decoded.
 * @param buf Pointer to the destination buffer.
 * @param len Size of the destination buffer.
 * @return The function returns the length of the decoded string or -1 in case
 * of error.
 */
int oc_dn_name(const char *msg, int msglen, const char *dn, char *buf, int len)
{
   return oc_dn_name0(0, msg, msglen, dn, buf, len);
}


/*! This function processes a DNS request and constructs the answer directly
 * into the same buffer. If the request contains a valid PTR request and the
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

   // make sure to read hosts file FIXME: this may cause unnecessary load -> socket_cleaner()
   hosts_check();
   // lookup hostname in memory
   if (hosts_get_name_ext(&in6, name, sizeof(name), &source, &age) == -1)
   {
      log_debug("no such name");
      dh->rcode = NXDOMAIN;
      return msglen;
   }

   // set authorative answer for hosts file entries
   if (source <= HSRC_HOSTS)
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


/*! This function processes the response message of a DNS query and adds the
 * answer to the internal hosts db if the message was correct. A thourough
 * error checking of the message is done.
 * @param buf Pointer to the received message.
 * @param msglen Length of the message in bytes.
 * @param orig_id Expected id (which was set in the original query).
 * @param org_addr Address which was queried.
 * @param ns_src Source of the name server which was queried.
 * @return On success, the function returned 0. On error a negative value is
 * returned which allows to distinguish the kind of error. The error is one of
 * OCRES_Exxx which are defined in ocatresolv.h (see their for description).
 */
int oc_proc_response(const char *buf, int msglen, uint16_t org_id, const struct in6_addr *org_addr, hsrc_t ns_src)
{
   char name[SIZE_256];
   struct in6_addr in6;
   unsigned ttl;
   HEADER *dh;
   int n, omsglen;

   // safety check
   if (buf == NULL || msglen < (int) sizeof(*dh))
      return OCRES_EPARAM;

   // init pointers
   dh = (HEADER*) buf;
   buf = (char*) (dh + 1);
   omsglen = msglen;
   msglen -= sizeof(*dh);

   // check message id
   if (dh->id != org_id)
   {
      log_msg(LOG_ERR, "DNS response id does not match request");
      return OCRES_EID;
   }

   if (!dh->qr || dh->opcode != QUERY || ntohs(dh->qdcount) != 1)
   {
      log_msg(LOG_ERR, "DNS response format error");
      return OCRES_EFORMAT;
   }

   if (dh->rcode == NXDOMAIN)
   {
      log_msg(LOG_INFO, "DNS server replied with NXDOMAIN");
      return OCRES_ENXDOMAIN;
   }

   if (dh->rcode != NOERROR)
   {
      log_msg(LOG_INFO, "DNS server replied error: %d", dh->rcode);
      return OCRES_ERCODE;
   }

   if (ntohs(dh->ancount) != 1)
   {
      log_msg(LOG_ERR, "DNS reply has unexpected number of answers: %d", ntohs(dh->ancount));
      return OCRES_EFORMAT;
   }

   n = oc_dn_len(buf, msglen);
   // check if it is a IN PTR query
   if (n != IP6REVLEN || *((uint16_t*) &buf[n]) != htons(T_PTR) || *((uint16_t*) &buf[n + 2]) != htons(C_IN))
   {
      log_debug("no ptr query");
      return OCRES_EFORMAT;
   }

   // convert reverse name to address
   if (oc_rev6ptr_addr(buf, (char*) &in6) == -1)
   {
      log_debug("name error");
      return OCRES_EFORMAT;
   }

   if (!IN6_ARE_ADDR_EQUAL(&in6, org_addr))
   {
      log_msg(LOG_ERR, "query name does not match expected query name");
      return OCRES_EFORMAT;
   }

   // advance buffer to answer section
   buf += n + 2 + 2;
   msglen -= n + 2 + 2;
   n = oc_dn_len(buf, msglen);

   if (*((uint16_t*) &buf[n]) != htons(T_PTR) || *((uint16_t*) &buf[n + 2]) != htons(C_IN))
   {
      log_msg(LOG_ERR, "malformed answer");
      return OCRES_EFORMAT;
   }

   ttl = ntohl(*((uint32_t*) &buf[n + 4]));

   if (oc_dn_name((char*) dh, omsglen, buf + n + 10, name, sizeof(name)) == -1)
   {
      log_msg(LOG_WARNING, "could not decode name");
      return OCRES_EFORMAT;
   }

   log_msg(LOG_INFO, "DNS server replied name: %s", name);
   if (hosts_add_entry(org_addr, name, dh->aa && ns_src <= HSRC_HOSTS ? HSRC_NET_AA : HSRC_NET, time(NULL), ttl) == -1)
   {
      log_msg(LOG_WARNING, "could not add new hosts entry: %s", name);
      return OCRES_EHDB;
   }

   return 0;
}


/*! This function creates a DGRAM socket suitable to receive OnionCat DNS
 * queries.
 * @param port Port number of UDP port.
 * @return On success the function returns a valid filedescriptor. On error, -1
 * is returned.
 */
int oc_ns_socket(int port)
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
   s6addr.sin6_port = htons(port);
   IN6_ADDR_COPY(&s6addr.sin6_addr, &CNF(ocat_addr));

   // cannot bind before address was assigned in the main thread
   //wait_thread_by_name_ready("main");

   // bind socket to address
   for (int i = 0; bind(fd, (struct sockaddr*) &s6addr, slen) == -1; i++)
   {
      if (i < 3 && errno == EADDRNOTAVAIL)
      {
         log_msg(LOG_INFO, "bind failed, waiting for interface address to get ready...");
         sleep(1);
         continue;
      }
      log_msg(LOG_ERR, "could not bind DNS socket to port %d: %s", port, strerror(errno));
      oe_close(fd);
      return -1;
   }

   return fd;
}


/*! This is the nameserver main loop. It waits for incoming packets, receives
 * one after the other, and processes the requests. If the requests are valid,
 * answers are sent dependent if the names in the queries are found in the
 * local DB, or not. In the latter case NXDOMAIN is replied.
 */
void *oc_nameserver(void *p)
{
   struct sockaddr_str ssaddr;
   struct sockaddr_in6 s6addr;
   char buf[PACKETSZ + 1];
   int fd = -1, len, n;
   socklen_t slen;
   fd_set rset;

   detach_thread();

   if ((fd = oc_ns_socket((intptr_t) p)) == -1)
      return NULL;

   set_thread_ready();

   // loop over connections
   for (;;)
   {
      if (term_req())
         break;

      FD_ZERO(&rset);
      FD_SET(fd, &rset);
      if ((n = oc_select(fd + 1, &rset, NULL, NULL)) == -1)
         continue;

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


#ifdef WITH_DNS_RESOLVER
/*! This function receives a DNS response to one of the queries in orstate. If
 * a message could successfully be related to a query in orstate, the orstate
 * counter is decreased and the state of the query is set to OCRES_UNUSED.
 * @param orstate Pointer to the orstate struct which should receive a message.
 * @return The function returnes the index of the query within orstate, which
 * is 0 <= index < MAX_CONCURRENT_Q. In case of error, -1 is returned.
 */
int ocres_recv(ocres_state_t *orstate)
{
   struct sockaddr_in6 saddr;
   char buf[PACKETSZ];
   socklen_t slen;
   int i, len;

   slen = sizeof(saddr);
   if ((len = recvfrom(orstate->fd, buf, sizeof(buf), 0, (struct sockaddr*) &saddr, &slen)) == -1)
   {
      log_msg(LOG_ERR, "failed to receive DNS data on fd %d: %s", orstate->fd, strerror(errno));
      return -1;
   }

   log_debug("received %d bytes on fd %d, checking identity", len, orstate->fd);

   for (i = 0; i < MAX_CONCURRENT_Q; i++)
   {
      // ignore unused entries
      if (orstate->qry[i].retry > DNS_MAX_RETRY)
         continue;

      // check if sender socket address matches nameserver
      if (saddr.sin6_port != orstate->qry[i].ns.sin6_port || !IN6_ARE_ADDR_EQUAL(&saddr.sin6_addr, &orstate->qry[i].ns.sin6_addr))
         continue;

      // check if id of DNS message matches
      if (((HEADER*) buf)->id != orstate->qry[i].id)
         continue;

      // process response
      orstate->qry[i].code = oc_proc_response(buf, sizeof(buf), orstate->qry[i].id, &orstate->addr, orstate->qry[i].ns_src);
      host_stats_inc_ans(&orstate->qry[i].ns.sin6_addr, orstate->qry[i].code);
      orstate->qry[i].retry = DNS_MAX_RETRY + 1;
      orstate->cnt--;
      if (orstate->callback != NULL)
         orstate->callback(orstate->p, orstate->addr, orstate->qry[i].code);
      break;
   }

   return i >= MAX_CONCURRENT_Q ? -1 : i;
}


/*! This function queues new reverse queries for address addr. There will be
 * MAX_CONCURRENT_Q queries or less if there are not enough available
 * nameservers.
 * @param addr Pointer to IPv6 address to do query for.
 * @param callback Pointer to callback function. If not NULL, this function is
 * called after a response was received. The function will receive the IPv6
 * address of the query and parameter p is directly passed to it.
 * @param p This argument is passed directly to the callback function.
 * @return The function returns the number of queued queries which is 0 <
 * queries <= MAX_CONCURRENT_Q. If no suitable nameserver is found, 0 is
 * returned. In case of error, -1 is returned.
 */
int ocres_query_callback(const struct in6_addr *addr, void (callback)(void *, struct in6_addr, int), void *p)
{
   ocres_state_t *orstate;
   int i, n, on, ret;

   if ((orstate = malloc(sizeof(*orstate))) == NULL)
   {
      log_msg(LOG_ERR, "malloc() failed: %s", strerror(errno));
      return -1;
   }

   orstate->cnt = 0;
   orstate->p = p;
   orstate->callback = callback;

   if ((orstate->fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
   {
      log_msg(LOG_ERR, "could not create resolver socket: %s", strerror(errno));
      free(orstate);
      return -1;
   }

   for (i = 0, n = 0; i < MAX_CONCURRENT_Q; i++)
   {
      // get next nameserver address
      on = n;
      ret = hosts_get_ns_rr_metric(&orstate->qry[i].ns.sin6_addr, &orstate->qry[i].ns_src, &n);

      // check if there aren't any potential nameservers
      if (!i && ret == -1)
      {
         log_msg(LOG_ERR, "no nameservers available");
         oe_close(orstate->fd);
         free(orstate);
         return 0;
      }

      // check if round robin list repeated
      if (i && ret <= on)
         break;

      // init other fields of sockaddr struct
      orstate->qry[i].ns.sin6_family = AF_INET6;
      orstate->qry[i].ns.sin6_port = htons(CNF(ocat_ns_port));
#ifdef HAVE_SIN_LEN
      orstate->qry[i].ns.sin6_len = sizeof(orstate->qry[i].ns);
#endif

      // init other fields of this query
      orstate->qry[i].id = rand() & 0xffff;
      orstate->qry[i].retry = 0;
      orstate->qry[i].restart_time = 0;
      orstate->cnt++;
   }

   // mark remaining entries as 'unused
   for (; i < MAX_CONCURRENT_Q; i++)
      orstate->qry[i].retry = DNS_MAX_RETRY + 1;

   IN6_ADDR_COPY(&orstate->addr, addr);
   orstate->msg_len = oc_mk_ptrquery((char*) addr, orstate->msg, sizeof(orstate->msg), 0);

   // safe return value
   n = orstate->cnt;
   // queue new entry
   pthread_mutex_lock(&orstate_mutex_);
   orstate->next = orstate_;
   orstate_ = orstate;
   pthread_mutex_unlock(&orstate_mutex_);

   on = 1;
   if (write(ocres_pipe_fd_[1], &on, sizeof(on)) == -1)
      log_msg(LOG_ERR, "could not write to resolver pipe: %s", strerror(errno));

   return n;
}


/*! This function queues a new PTR query. It directly calls
 * ocres_query_callback() without a calback function. See
 * ocres_query_callback() for further function details.
 */
int ocres_query(const struct in6_addr *addr)
{
   return ocres_query_callback(addr, NULL, NULL);
}


/*! This function removes elements ready for deletion from lookup queue.
 */
static void ocres_cleanup(ocres_state_t **osp)
{
   ocres_state_t *orstate;

   pthread_mutex_lock(&orstate_mutex_);
   for (; *osp != NULL;)
   {
      if (!(*osp)->cnt)
      {
         log_debug("removing entry, fd = %d", (*osp)->fd);
         orstate = *osp;
         *osp = (*osp)->next;
         oe_close(orstate->fd);
         free(orstate);
         continue;
      }
      osp = &(*osp)->next;
   }
   pthread_mutex_unlock(&orstate_mutex_);
}


/*! Just a debug logging function.
 */
static void log_query(const ocres_state_t *os, int n)
{
   char astr[INET6_ADDRSTRLEN], nstr[INET6_ADDRSTRLEN];

   inet_ntop(AF_INET6, &os->addr, astr, INET6_ADDRSTRLEN);
   inet_ntop(AF_INET6, &os->qry[n].ns.sin6_addr, nstr, INET6_ADDRSTRLEN);
   log_msg(LOG_INFO, "sending query for %s to NS %s", astr, nstr);
}


/*! This is the resolver main loop. It works on the resolver queue, (re-)sends
 * queries and receives and processes the responses.
 */
void *oc_resolver(void *UNUSED(p))
{
   ocres_state_t *orstate;
   int i, n, maxfd, len;
   fd_set rset;
   time_t tm;

   detach_thread();

   // init communication pipe
   if (pipe(ocres_pipe_fd_) == -1)
   {
      log_msg(LOG_ERR, "could not create resolver pipe: %s", strerror(errno));
      return NULL;
   }

   set_thread_ready();

   while (!term_req())
   {
      // clean queue entries which are ready for deletion
      ocres_cleanup(&orstate_);

      // init read set and add communication pipe
      FD_ZERO(&rset);
      FD_SET(ocres_pipe_fd_[0], &rset);
      maxfd = ocres_pipe_fd_[0];

      tm = time(NULL);

      // loop over all entries in the queue
      pthread_mutex_lock(&orstate_mutex_);
      for (orstate = orstate_; orstate != NULL; orstate = orstate->next)
      {
         // ignore entries which are ready for deletion
         if (!orstate->cnt)
            continue;

         // loop over all queries per entry
         for (i = 0, n = 0; i < MAX_CONCURRENT_Q && n < orstate->cnt; i++)
         {
            // ignore those which already exeeded retry limit
            if (orstate->qry[i].retry > DNS_MAX_RETRY)
               continue;

            // ignore if restart time did not elapse yet
            if (orstate->qry[i].restart_time > tm)
               continue;

            // after max retries decease counter
            if (orstate->qry[i].retry == DNS_MAX_RETRY)
            {
               orstate->qry[i].retry++;
               orstate->cnt--;
               continue;
            }

            // prepare for sending query
            n++;
            orstate->qry[i].restart_time = tm + DNS_RETRY_TIMEOUT;
            orstate->qry[i].retry++;
            ((HEADER*) orstate->msg)->id = orstate->qry[i].id;

            // send query
            log_query(orstate, i);
            len = sendto(orstate->fd, orstate->msg, orstate->msg_len, 0, (struct sockaddr*) &orstate->qry[i].ns, sizeof(orstate->qry[i].ns));
            // and check for errors
            if (len == -1)
            {
               log_msg(LOG_ERR, "could not send dns query: %s", strerror(errno));
               break;
            }
            host_stats_inc_q(&orstate->qry[i].ns.sin6_addr);
            // and check if read was truncated (which should never happen...)
            if (len < orstate->msg_len)
               log_msg(LOG_ERR, "truncated write on fd %d: %d < %d", orstate->fd, len, orstate->msg_len);
         }
         // add file descriptor to read set
         MFD_SET(orstate->fd, &rset, maxfd);
      }
      pthread_mutex_unlock(&orstate_mutex_);

      // wait for any fd to get ready
      if ((n = oc_select0(maxfd + 1, &rset, NULL, NULL, DNS_RETRY_TIMEOUT)) == -1)
         continue;

      // check if resolver pipe is ready
      if (FD_ISSET(ocres_pipe_fd_[0], &rset))
      {
         n--;
         len = read(ocres_pipe_fd_[0], &maxfd, sizeof(maxfd));
         if (len == -1)
         {
            log_msg(LOG_ERR, "could not read from resolver pipe: %s", strerror(errno));
         }
         else if (!len)
         {
            log_msg(LOG_NOTICE, "resolver pipe was closed");
            break;
         }
         else
         {
            log_debug("received %d on resolver pipe", maxfd);
         }
      }

      // receive messages on sockets that are ready
      pthread_mutex_lock(&orstate_mutex_);
      for (orstate = orstate_; orstate != NULL && n > 0; orstate = orstate->next)
      {
         if (FD_ISSET(orstate->fd, &rset))
         {
            n--;
            (void) ocres_recv(orstate);
         }
      }
      pthread_mutex_unlock(&orstate_mutex_);
   }

   // close pipe
   oe_close(ocres_pipe_fd_[0]);
   oe_close(ocres_pipe_fd_[1]);

   // set active query counters to 0
   pthread_mutex_lock(&orstate_mutex_);
   for (orstate = orstate_; orstate != NULL; orstate = orstate->next)
      orstate->cnt = 0;
   pthread_mutex_unlock(&orstate_mutex_);

   // cleanup (close & free) all remaining queries
   ocres_cleanup(&orstate_);

   return NULL;
}
#endif
