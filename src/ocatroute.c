/* Copyright 2008-2022 Bernhard R. Fischer.
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

/*! \file ocatroute.c
 *  Contains functions for managing both kind of TCP peers.
 *  Those are active SOCKS4A and passive TCP-LISTEN.
 *
 *  \author Bernhard Fischer <bf@abenteuerland.at>
 *  \date 2022/05/06
 */


#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"

#ifdef HAVE_STRUCT_IPHDR
#define IPPKTLEN(x) ntohs(((struct iphdr*) (x))->tot_len)
#define IPHDLEN sizeof(struct iphdr)
#else
#define IPPKTLEN(x) ntohs(((struct ip*) (x))->ip_len)
#define IPHDLEN sizeof(struct ip)
#endif

// file descriptors of socket_receiver pipe
// used for internal communication
static int lpfd_[2];

#ifdef PACKET_QUEUE
// packet queue pointer
static PacketQueue_t *queue_ = NULL;
// mutex and condition variable for packet queue
static pthread_mutex_t queue_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond_ = PTHREAD_COND_INITIALIZER;
#endif


int forward_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   OcatPeer_t *peer;
   int len;

   lock_peers();
   if ((peer = search_peer(addr)))
      lock_peer(peer);
   unlock_peers();

   if (!peer)
   {
      log_debug("no peer for forwarding");
      return E_FWD_NOPEER;
   }

   log_debug("forwarding %d bytes to TCP fd %d", buflen, peer->tcpfd);

   if ((len = send(peer->tcpfd, buf, buflen, MSG_DONTWAIT)) == -1)
   {
      log_msg(LOG_ERR, "could not write %d bytes to peer %d: \"%s\", dropping", buflen, peer->tcpfd, strerror(errno));
   }
   else
   {
      if (len != buflen)
      {
         // FIXME: there should be sender frag handling!
         log_msg(LOG_ERR, "could not write %d bytes to peer %d, %d bytes written", buflen, peer->tcpfd, len);
      }
      peer->time = time(NULL);
      peer->out += len;
   }
   unlock_peer(peer);

   return 0;
}


#ifdef PACKET_QUEUE
void queue_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   PacketQueue_t *queue;

   log_debug("copying packet to heap for queue");
   if (!(queue = malloc(sizeof(PacketQueue_t) + buflen)))
   {
      log_msg(LOG_ERR, "%s for packet to queue", strerror(errno));
      return;
   }

   //memcpy(&queue->addr, addr, sizeof(struct in6_addr));
   IN6_ADDR_COPY(&queue->addr, addr);
   queue->psize = buflen;
   queue->data = ((char*)queue) + sizeof(PacketQueue_t);
   memcpy(queue->data, buf, buflen);
   queue->time = time(NULL);

   log_debug("queuing packet");
   pthread_mutex_lock(&queue_mutex_);
   queue->next = queue_;
   queue_ = queue;
   log_debug("waking up dequeuer");
   pthread_cond_signal(&queue_cond_);
   pthread_mutex_unlock(&queue_mutex_);
}


void *packet_dequeuer(void *p)
{
   PacketQueue_t **queue, *fqueue;
   struct timespec ts;
   struct timeval tv;
   int rc, timed = 0;
   time_t delay;

   for (;;)
   {
      pthread_mutex_lock(&queue_mutex_);
      if (timed)
      {
          // replaced clock_gettime() due to portability issues
         if (gettimeofday(&tv, NULL) == -1)
         {
            log_msg(LOG_ERR, "couldn't gettime: \"%s\"", strerror(errno));
            memset(&tv, 0, sizeof(tv));
         }
         else
         {
            ts.tv_sec = tv.tv_sec;
            ts.tv_nsec = tv.tv_usec * 1000;
         }
         ts.tv_sec += DEQUEUER_WAKEUP;
         log_debug("timed conditional wait...");
         rc = pthread_cond_timedwait(&queue_cond_, &queue_mutex_, &ts);
      }
      else
      {
         log_debug("conditional wait...");
         rc = pthread_cond_wait(&queue_cond_, &queue_mutex_);
      }

      if (rc)
         log_msg(LOG_EMERG, "woke up: \"%s\"", strerror(rc));

      log_debug("starting dequeuing");
      for (queue = &queue_; *queue; /*queue = &(*queue)->next*/)
      {
         rc = forward_packet(&(*queue)->addr, (*queue)->data, (*queue)->psize);

         // delete packet from queue if it was sent or is too old
         delay = time(NULL) - (*queue)->time;
         if (!rc || (delay > MAX_QUEUE_DELAY))
         {
            fqueue = *queue;
            *queue = (*queue)->next;
            free(fqueue);
            log_debug("packet dequeued, delay = %d", delay);
            continue;
         }
         queue = &(*queue)->next;
      }
      timed = queue_ != NULL;
      pthread_mutex_unlock(&queue_mutex_);
   }
}
#endif


void cleanup_socket(int fd, OcatPeer_t *peer)
{
   log_msg(LOG_INFO | LOG_FCONN, "fd %d reached EOF, closing.", fd);
   oe_close(fd);
   lock_peers();
   delete_peer(peer);
   unlock_peers();
}


#ifdef HANDLE_HTTP
#define BSTRLEN 1024

int handle_http(const OcatPeer_t *peer)
{
   time_t t;
   char response[BSTRLEN], timestr[BSTRLEN];
   struct tm tm;

   // simple check if packet could be an HTTP request
   if (strncmp(peer->fragbuf, "GET ", 4))
      return 0;

   t = time(NULL);
   (void) localtime_r(&t, &tm);
   strftime(timestr, BSTRLEN, "%a, %d %b %Y %H:%M:%S %z", &tm);
   snprintf(response, BSTRLEN,
         "HTTP/1.0 301 HTTP not possible\r\nLocation: %s\r\nDate: %s\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n"
         "<html><body><h1>HTTP not possible!<br>OnionCat is running on this port at \"%s.onion\"</h1></body></html>\r\n",
         OCAT_URL, timestr, CNF(onion_url)
         );
   log_msg(LOG_NOTICE, "request seems to be HTTP");
   if (send(peer->tcpfd, response, strlen(response), MSG_DONTWAIT) == -1)
      log_msg(LOG_ERR, "could not send html response");

   return 1;
}
#endif


int set_peer_dest(struct in6_addr *dest, const struct in6_addr *addr)
{
   if (!has_tor_prefix(addr))
   {
      log_debug("remote address does not have OC prefix");
      return -1;
   }

   if (IN6_ARE_ADDR_EQUAL(addr, &CNF(ocat_addr)))
   {
      log_debug("source address is local address");
      return -1;
   }

   *dest = *addr;
   return 0;
}


/*! Set select timeout a little bit "random" to diverse wakeup periods. */
void set_select_timeout(struct timeval *tv)
{
   set_select_timeout0(tv, SELECT_TIMEOUT);
}


/*! Set select timeout a little bit "random" to diverse wakeup periods. */
void set_select_timeout0(struct timeval *tv, int t)
{
   tv->tv_usec = rand() % 1000000;
   tv->tv_sec = t + (tv->tv_usec & 1);
   log_debug2("timeout %d.%06d", tv->tv_sec, tv->tv_usec);
}


void set_tunheader(char *buf, uint32_t tunhdr)
{
   uint32_t *ibuf = (uint32_t*) buf;
   *ibuf = tunhdr;
}


uint32_t get_tunheader(char *buf)
{
   uint32_t *ibuf = (uint32_t*) buf;
   return *ibuf;
}


/*! This function parses the keepalive packet. If it is valid, a new hosts
 * entry is added to the hosts DB.
 * @param i6h Pointer to IPv6 packet.
 * @return The function returns 0 on success if a valid OC4 keepalive was
 * found. 1 is returned if the keepalive contains no data. This may be the case
 * for pre OC4 keepalives. They are sufficient for HSv2. In case of error -1 is
 * returned.
 */
int handle_keepalive(const struct ip6_hdr *i6h)
{
   // FIXME: should that be activated only if lookup is enabled?
   char *buf;
   int len;

   // check if ip6 packet without specific content (header only)
   if (i6h->ip6_nxt != IPPROTO_NONE)
      return -1;

   // extract payload data
   len = ntohs(i6h->ip6_plen);

#if 0
   if (!len)
   {
      log_msg(LOG_INFO, "may be v2 keepalive");
      return 1;
   }
#endif

   if (len < 2)
   {
      log_debug("not enough data for hostname in keepalive");
      return -1;
   }

   // create pointer to payload
   buf = (char*) (i6h + 1);

   // check version info
   if (buf[0] != 1)
   {
      log_debug("version %d in keepalive not supported", buf[0]);
      return -1;
   }

   log_msg(LOG_INFO, "seems to be OC4 keepalive");
   // advance pointer to hostname
   buf++;
   len--;
   // make sure it is \0-terminated
   buf[len] = '\0';

   hosts_add_entry(&i6h->ip6_src, buf, HSRC_KPLV, time(NULL), HOSTS_KPLV_TTL);
   return 0;
}


/*! Try to identify own incoming loopback peer. This is if it is a keepalive
 * (i.e. nextheader == IPPROTO_NONE (59)) and the flow label matches. The flow
 * label is set to random number when it sends keepalives.
 * @param peer Pointer to peer on which the packet was received.
 * @param i6h Pointer to IPv6 packet.
 * @return The function returns 0 if it was its own loopback keepalive,
 * otherwise -1 is returned.
 */
int ident_loopback(OcatPeer_t *peer, const struct ip6_hdr *i6h)
{
   OcatPeer_t *lpeer;
   int flow;

   // check if ip6 packet without content (header only)
   if (i6h->ip6_nxt != IPPROTO_NONE)
      return -1;
   log_debug("packet seems to be keepalive");

   // check if flowlabel is set
   if (!(flow = ntohl(i6h->ip6_flow) & 0xfffff))
      return -1;

   lock_peers();
   if ((lpeer = search_peer(&CNF(ocat_addr))))
   {
      if (lpeer == peer)
      {
         log_msg(LOG_ERR, "peer points back to self, this should not happen!");
         unlock_peers();
         return -1;
      }
      lock_peer(lpeer);
   }
   unlock_peers();

   if (lpeer == NULL)
   {
      log_debug("ident_loopback: peer not found");
      return -1;
   }

   log_debug("found peer to myself");
   if (lpeer->dir != PEER_OUTGOING)
   {
      unlock_peer(lpeer);
      log_msg(LOG_ERR, "peer is not OUTGOING, something went wrong...");
      return -1;
   }

   if ((lpeer->rand & 0xfffff) != flow)
   {
      log_msg(LOG_ERR, "flowlabel does not match: rand = 0x%05x, flow = 0x%05x", lpeer->rand & 0xfffff, flow);
      unlock_peer(lpeer);
      return -1;
   }

   log_debug("identified valid loopback keepalive");

   unlock_peer(lpeer);
   return 0;
}


/*! This function tries to identify if data in a buffer is either IPv6 or IPv4.
 * It does not fully check everything just as much as necessary. If the
 * function returns 0 it is for sure neither IPv4 nor IPv6. Otherwise it may be
 * right or may be wrong. Since the packet gets forwarded to the OS further
 * checking is left over to it.
 * @param buf Pointer to the buffer.
 * @param len Bytes available in the buffer.
 * @param tunhdr Pointer to a variable which will receiver either
 * CNF(fhd_key[IPV6_KEY]) or CNF(fhd_key[IPV4_KEY]) if a packet was identified.
 * @return On success the function returnes the length of the packet (>0) and
 * sets tunhdr accordingly. If the data may be a partial IPv6 packet -6 is
 * returned, if it may be a partial IPv4 packet -4 is returned. If the data is
 * neither IPv6 nor IPv4, 0 is returned and the data should be dropped
 * subsequently.
 */
int ident_packet(const char *buf, int len, uint32_t *tunhdr)
{
   // incoming packet seems to be IPv6
   if ((buf[0] & 0xf0) == 0x60)
   {
      log_debug("identified IPv6 packet");
      if ((len < (int) IP6HLEN) || (len < ntohs(((struct ip6_hdr*) buf)->ip6_plen) + (int) IP6HLEN))
      {
         log_debug("keeping %d bytes frag", len);
         return -6;
      }
      *tunhdr = CNF(fhd_key[IPV6_KEY]);
      return ntohs(((struct ip6_hdr*) buf)->ip6_plen) + IP6HLEN;
   }

   // incoming packet seems to be IPv4
   if ((buf[0] & 0xf0) == 0x40)
   {
      if ((buf[0] & 0x0f) >= 5)
      {
         log_debug("identified IPv4 packet");
         if ((len < (int) IPHDLEN) || (len < IPPKTLEN(buf)))
         {
            log_debug("keeping %d bytes frag", len);
            return -4;
         }
         *tunhdr = CNF(fhd_key[IPV4_KEY]);
         return IPPKTLEN(buf);
      }
   }

   log_debug("ill data");
   return 0;
}


void *socket_receiver(void *UNUSED(p))
{
   int maxfd, len;
   char buf[FRAME_SIZE];
   char addr[INET6_ADDRSTRLEN];
   fd_set rset;
   OcatPeer_t *peer;
   struct in6_addr *in6;
   int drop = 0;
   struct ether_header *eh = (struct ether_header*) (buf + 4);
   struct timeval tv;

   if (pipe(lpfd_) < 0)
      log_msg(LOG_EMERG, "could not create pipe for socket_receiver: \"%s\"", strerror(errno)), exit(1);

   for (;;)
   {
      // check for termination request
      if (term_req())
         break;

      FD_ZERO(&rset);
      FD_SET(lpfd_[0], &rset);
      maxfd = lpfd_[0];

      // create set for all available peers to read
      lock_peers();
      for (peer = get_first_peer(); peer; peer = peer->next)
      {
         lock_peer(peer);
         // only select active peers
         if (peer->state != PEER_ACTIVE)
         {
            unlock_peer(peer);
            continue;
         }

         if (peer->tcpfd >= FD_SETSIZE)
            log_msg(LOG_EMERG, "%d >= FD_SETIZE(%d)", peer->tcpfd, FD_SETSIZE), exit(1);

         FD_SET(peer->tcpfd, &rset);
         if (peer->tcpfd > maxfd)
            maxfd = peer->tcpfd;
         unlock_peer(peer);
      }
      unlock_peers();

      set_select_timeout(&tv);
      log_debug2("selecting (maxfd = %d)", maxfd);
      if ((maxfd = select(maxfd + 1, &rset, NULL, NULL, &tv)) == -1)
      {
         log_msg(LOG_ERR, "select encountered error: \"%s\", restarting", strerror(errno));
         continue;
      }

      // thread woke up because of internal pipe read => restart selection
      if (FD_ISSET(lpfd_[0], &rset))
      {
         read(lpfd_[0], buf, FRAME_SIZE - 4);
         maxfd--;
      }

      peer = NULL;
      while (maxfd)
      {
         // the following 10 locs look somehow strange and someone may tend
         // to write this as a for loop but it's necessary for thread locking!
         lock_peers();
         if (!peer)
         {
            peer = get_first_peer();
            if (peer == NULL)
            {
               log_msg(LOG_INFO, "no peers, looks like program exiting");
               unlock_peers();
               break;
            }
         }
         else if (!(peer = peer->next))
         {
            log_msg(LOG_DEBUG, "fd ready but no peer found, probably cleaned");
            unlock_peers();
            break;
         }
         lock_peer(peer);
         unlock_peers();

         if (peer->state != PEER_ACTIVE)
         {
            unlock_peer(peer);
            continue;
         }

         if (!FD_ISSET(peer->tcpfd, &rset))
         {
            unlock_peer(peer);
            continue;
         }

         maxfd--;
         log_debug("reading from %d", peer->tcpfd);

         // read/append data to peer's fragment buffer
         if ((len = read(peer->tcpfd, peer->fragbuf + peer->fraglen, FRAME_SIZE - 4 - peer->fraglen)) == -1)
         {
            // this might happen on linux, see SELECT(2)
            log_debug("spurious wakup of %d: \"%s\"", peer->tcpfd, strerror(errno));
            unlock_peer(peer);
            continue;
         }

         log_debug("received %d bytes on %d", len, peer->tcpfd);
         // if len == 0 EOF reached => close session
         if (!len)
         {
            log_msg(LOG_INFO | LOG_FCONN, "fd %d reached EOF, closing.", peer->tcpfd);
            oe_close(peer->tcpfd);
            // restart connection of permanent peers
            if (peer->perm)
            {
               log_debug("reconnection permanent peer");
               socks_queue(peer->addr, 1);
            }
            unlock_peer(peer);

            // deleting peer
            // FIXME: there might be a race-condition with restarted permanent peers
            lock_peers();
            delete_peer(peer);
            unlock_peers();

            continue;
         }

         peer->fraglen += len;
         // update timestamp
         peer->time = time(NULL);
         peer->in += len;

         while (peer->fraglen)
         {
            if ((len = ident_packet(peer->fragbuf, peer->fraglen, peer->tunhdr)) <= 0)
            {
               if (!len)
               {
                  /* Some testing showed that resetting the fragment buffer
                   * completely works better that trying to find new packets by
                   * moving forward byte-by-byte. */
                  log_debug("fragment buffer reset");
                  peer->fraglen = 0;
               }
               break;
            }

            // FIXME: the following if should check if it is IPv6 and "drop" may be unnecessary
            // identify remote loopback
            if (!drop && IN6_IS_ADDR_UNSPECIFIED(&peer->addr))
            {
               if (!ident_loopback(peer, (struct ip6_hdr*)peer->fragbuf))
               {
                  run_ocat_thread("rloopback", remote_loopback_responder, (void*)(uintptr_t) peer->tcpfd);

                  // remove peer
                  log_msg(LOG_INFO, "mark peer on fd %d for deletion", peer->tcpfd);
                  peer->state = PEER_DELETE;
               }
               else
               {
                  if (handle_keepalive((struct ip6_hdr*)peer->fragbuf) >= 0 && CNF(unidirectional))
                  {
                     OcatPeer_t *rpeer;
                     lock_peers();
                     rpeer = search_peer(&((struct ip6_hdr*)peer->fragbuf)->ip6_src);
                     unlock_peers();
                     if (rpeer == NULL)
                     {
                        log_msg(LOG_INFO, "creating immediate return peer to %s", inet_ntop(AF_INET6, &((struct ip6_hdr*)peer->fragbuf)->ip6_src, addr, INET6_ADDRSTRLEN));
                        socks_queue(((struct ip6_hdr*)peer->fragbuf)->ip6_src, 0);
                     }
                  }
               }
            }

            // set IP address if it is not set yet and frame is valid and in bidirectional mode
            if (!CNF(unidirectional) && !drop && IN6_IS_ADDR_UNSPECIFIED(&peer->addr))
            {
               if (*peer->tunhdr == CNF(fhd_key[IPV6_KEY]))
               {
                  //memcpy(&peer->addr, &((struct ip6_hdr*)peer->fragbuf)->ip6_src, sizeof(struct in6_addr));
                  if (set_peer_dest(&peer->addr, &((struct ip6_hdr*)peer->fragbuf)->ip6_src))
                     drop = 1;
               }
               else if (*peer->tunhdr == CNF(fhd_key[IPV4_KEY]))
               {
                  // check if there is a route back
#ifdef HAVE_STRUCT_IPHDR
                  if (!(in6 = ipv4_lookup_route(ntohl(((struct iphdr*) peer->fragbuf)->saddr))))
#else
                  if (!(in6 = ipv4_lookup_route(ntohl(((struct ip*) peer->fragbuf)->ip_src.s_addr))))
#endif
                  {
                     drop = 1;
                     log_debug("no route back");
                  }
                  else
                  {
                     //memcpy(&peer->addr, in6, sizeof(struct in6_addr));
                     if (set_peer_dest(&peer->addr, in6))
                        drop = 1;
                  }
               }

               if (!drop)
                  log_msg(LOG_INFO | LOG_FCONN, "incoming connection on %d from %s is now identified", peer->tcpfd,
                     inet_ntop(AF_INET6, &peer->addr, addr, INET6_ADDRSTRLEN));
            }

            if (!drop)
            {
               // write directly on TUN device
               if (!CNF(use_tap))
               {
                  log_debug("writing to tun %d framesize %d + %d", CNF(tunfd[1]), len, 4 - BUF_OFF);
                  if (tun_write(CNF(tunfd[1]), ((char*) peer->tunhdr) + BUF_OFF, len + 4 - BUF_OFF) != (len + 4 - BUF_OFF))
                     log_msg(LOG_ERR, "could not write %d bytes to tunnel %d", len + 4 - BUF_OFF, CNF(tunfd[1]));
               }
               // create ethernet header and handle MAC on TAP device
               else if (*peer->tunhdr == CNF(fhd_key[IPV6_KEY]))
               {
                  log_debug("creating ethernet header");

                  // FIXME: should differentiate between IPv6 and IP!!
                  memset(eh->ether_dst, 0, ETHER_ADDR_LEN);
                  if (mac_set(&((struct ip6_hdr*)peer->fragbuf)->ip6_dst, eh->ether_dst) == -1)
                  {
                     log_debug("dest MAC unknown, resolving");
                     ndp_solicit(&((struct ip6_hdr*)peer->fragbuf)->ip6_src, &((struct ip6_hdr*)peer->fragbuf)->ip6_dst);
                  }
                  else
                  {
                     set_tunheader(buf, *peer->tunhdr);
                     memcpy(buf + 4 + sizeof(struct ether_header), peer->fragbuf, len);
                     memcpy(eh->ether_src, CNF(ocat_hwaddr), ETHER_ADDR_LEN);

                     if (*peer->tunhdr == CNF(fhd_key[IPV6_KEY]))
                        eh->ether_type = htons(ETHERTYPE_IPV6);
                     else if (*peer->tunhdr == CNF(fhd_key[IPV4_KEY]))
                        eh->ether_type = htons(ETHERTYPE_IP);

                     if (tun_write(CNF(tunfd[1]), buf + BUF_OFF, len + 4 + sizeof(struct ether_header) - BUF_OFF) != (len + 4 + (int) sizeof(struct ether_header) - BUF_OFF))
                        log_msg(LOG_ERR, "could not write %d bytes to tunnel %d", len + 4 + sizeof(struct ether_header) - BUF_OFF, CNF(tunfd[1]));
                  }
               }
               else
               {
                  log_debug("protocol %x not implemented on TAP device", ntohs(*peer->tunhdr));
               }
            }
            else
            {
               log_msg(LOG_ERR, "dropping packet with %d bytes", len);
               drop = 0;
            }

            peer->fraglen -= len;
            if (peer->fraglen)
            {
               log_debug("moving fragment. fragsize %d", peer->fraglen);
               memmove(peer->fragbuf, peer->fragbuf + len, FRAME_SIZE - 4 - len);
            }
            else
            {
               log_debug("fragbuf empty");
            }
         } // while (peer->fraglen)

         if (peer->state == PEER_DELETE)
         {
            unlock_peer(peer);
            lock_peers();
            delete_peer(peer);
            unlock_peers();
            continue;
         }
         unlock_peer(peer);
      } // while (maxfd)
   } // for (;;)

   // closing pipe
   oe_close(lpfd_[0]);
   oe_close(lpfd_[1]);

   return NULL;
}


void set_nonblock(int fd)
{
   long flags;

   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
   {
      log_msg(LOG_ERR, "could not get socket flags for %d: \"%s\"", fd, strerror(errno));
      flags = 0;
   }
   log_debug("O_NONBLOCK currently is %x", flags & O_NONBLOCK);

   if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1)
      log_msg(LOG_ERR, "could not set O_NONBLOCK for %d: \"%s\"", fd, strerror(errno));
}


int insert_peer(int fd, const SocksQueue_t *sq, /*const struct in6_addr *addr,*/ time_t dly)
{
   OcatPeer_t *peer;

   log_msg(LOG_INFO | LOG_FCONN, "inserting peer fd %d to active peer list", fd);

   set_nonblock(fd);

   lock_peers();
   if (!(peer = get_empty_peer()))
   {
      unlock_peers();
      log_msg(LOG_ERR, "could not get new empty peer");
      return 0;
   } 
   lock_peer(peer);
   unlock_peers();

   peer->tcpfd = fd;
   peer->state = PEER_ACTIVE;
   peer->otime = peer->time = time(NULL);
   peer->sdelay = dly;
   if (sq)
   {
      //memcpy(&peer->addr, &sq->addr, sizeof(struct in6_addr));
      IN6_ADDR_COPY(&peer->addr, &sq->addr);
      peer->dir = PEER_OUTGOING;
      peer->perm = sq->perm;
   }
   else
      peer->dir = PEER_INCOMING;
   unlock_peer(peer);

   // wake up socket_receiver
   log_debug("waking up socket_receiver");
   if (write(lpfd_[1], &fd, 1) != 1)
      log_msg(LOG_EMERG, "couldn't write to socket_receiver pipe: \"%s\"", strerror(errno));

   return 1;
}


int insert_anon_peer(int fd)
{
   return insert_peer(fd, NULL, 0);
}


int create_listener(struct sockaddr *addr, int sock_len)
{
   int family;
   int fd, so;

   switch (addr->sa_family)
   {
      case AF_INET:
         family = PF_INET;
         break;
      case AF_INET6:
         family = PF_INET6;
         break;
      default:
         log_msg(LOG_EMERG, "unknown address family %d", addr->sa_family);
         return -1;
   }

   if ((fd = socket(family, SOCK_STREAM, 0)) < 0)
   {
      log_msg(LOG_EMERG, "could not create listener socker: \"%s\"", strerror(errno));
      return -1;
   }

   so = 1;  
   if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &so, sizeof(so)) == -1)
      log_msg(LOG_WARNING, "could not set socket %d to SO_REUSEADDR: \"%s\"", fd, strerror(errno));
   if (bind(fd, addr, sock_len) == -1)
   {
      log_msg(LOG_EMERG, "could not bind listener %d: \"%s\"", fd, strerror(errno));
      oe_close(fd);
      return -1;
   }

   if (listen(fd, 32) < 0)
   {
      log_msg(LOG_EMERG, "could not bring listener %d to listening state: \"%s\"", fd, strerror(errno));
      oe_close(fd);
      return -1;
   }

   log_debug("created listener, fd = %d", fd);
   return fd;
}


/*! run_listeners(...) is a generic socket acceptor for TCP ports.  It listens
 * on a given list of sockets.  Every time a connection comes in the function
 * action_accept is called with the incoming file descriptor as parameter.
 *
 * @param addr Double pointer to sockaddr structs. It MUST be terminated by a
 * null pointer.  
 * @param sockfd Points to an int array. The array must contain at least as
 * much entries as the sockaddr pointer has entries.  
 * @param action_accept Function pointer to function that should be called if a
 * connection arrives.  
 * @return Always 0.
 */
int run_listeners(struct sockaddr **addr, int *sockfd, int cnt, int (action_accept)(int))
{
   int fd;
   struct sockaddr_in6 in6;
   fd_set rset;
   int maxfd, i;
   socklen_t alen;
   char iabuf[INET6_ADDRSTRLEN];
   struct timeval tv;

   for (i = 0; i < cnt; i++)
   {
      log_debug("create listener");
      if ((sockfd[i] = create_listener(addr[i], SOCKADDR_SIZE(addr[i]))) == -1)
         log_msg(LOG_EMERG, "exiting"), exit(1);
   }

   set_thread_ready();
   for (;;)
   {
      // check for termination request
      if (term_req())
         break;

      log_debug2("setting up fd_set");
      FD_ZERO(&rset);
      maxfd = -1;
      for (i = 0; i < cnt; i++)
      {
         if (sockfd[i] == -1)
            continue;

         FD_SET(sockfd[i], &rset);
         if (sockfd[i] > maxfd)
            maxfd = sockfd[i];
      }

      if (maxfd == -1)
      {
         log_debug("no active listener fds available");
         break;
      }

      set_select_timeout(&tv);
      log_debug2("selecting (maxfd = %d)", maxfd);
      if ((maxfd = select(maxfd + 1, &rset, NULL, NULL, &tv)) == -1)
      {
         log_debug("select returned: \"%s\"", strerror(errno));
         continue;
      }
      log_debug2("select returned %d fds ready", maxfd);

      for (i = 0; maxfd && (i < cnt); i++)
      {
         log_debug("checking fd %d (maxfd = %d, i = %d)", sockfd[i], maxfd, i);
         if (!FD_ISSET(sockfd[i], &rset))
            continue;
         maxfd--;
         alen = sizeof(in6);
         log_debug("accepting connection on %d", sockfd[i]);
         if ((fd = accept(sockfd[i], (struct sockaddr*) &in6, &alen)) < 0)
         {
            log_msg(LOG_ERR, "error accepting connection on %d: \"%s\"", sockfd[i], strerror(errno));
            // FIXME: there should be additional error handling!
            continue;
         }

         inet_ntop(in6.sin6_family,
               in6.sin6_family == AF_INET6 ? &in6.sin6_addr :
               (void*) &((struct sockaddr_in*) &in6)->sin_addr,
               iabuf, INET6_ADDRSTRLEN);
         log_msg(LOG_INFO | LOG_FCONN, "connection %d [%d] accepted on listener %d from %s port %d", fd, i, sockfd[i], iabuf, ntohs(in6.sin6_port));
         (void) action_accept(fd);
      } // for
   }

   // closing listeners
   for (i = 0; i < cnt; i++)
      oe_close(sockfd[i]);

   log_debug("run_listeners returns");
   return 0;
}


void *socket_acceptor(void *UNUSED(p))
{
   run_listeners(CNF(oc_listen), CNF(oc_listen_fd), CNF(oc_listen_cnt), insert_anon_peer);
   return NULL;
}


#ifdef HAVE_STRUCT_IPHDR
/* helper function to avoid pointer aliasing */
static uint32_t get_saddr(const struct iphdr *ihdr)
{
   return ihdr->daddr;
}
#else
/* helper function to avoid pointer aliasing */
static uint32_t get_saddr(const struct ip *ihdr)
{
   return ihdr->ip_dst.s_addr;
}
#endif
 

void packet_forwarder(void)
{
   char buf[FRAME_SIZE];
   int rlen;
   struct in6_addr *dest, destbuf;
   struct in_addr in;
   struct ether_header *eh = (struct ether_header*) &buf[4];
#ifdef PACKET_LOG
   int pktlog;

   log_debug("opening packetlog");
   if ((pktlog = open("pkt_log", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) == -1)
      log_debug("could not open packet log: %s", strerror(errno));
#endif

   for (;;)
   {
      // check for termination request
      if (term_req())
         break;

#ifdef __OpenBSD__
      // workaround for OpenBSD userland threads
      fcntl(CNF(tunfd[0]), F_SETFL, fcntl(CNF(tunfd[0]), F_GETFL) & ~O_NONBLOCK);
#endif
      log_debug("reading from tunfd[0] = %d", CNF(tunfd[0]));
      if ((rlen = tun_read(CNF(tunfd[0]), buf + BUF_OFF, FRAME_SIZE - BUF_OFF)) == -1)
      {
         rlen = errno;
         log_debug("read from tun %d returned on error: \"%s\"", CNF(tunfd[0]), strerror(rlen));
         if (rlen == EINTR)
         {
            log_debug("signal caught");
            if (CNF(sig_term))
            {
               log_msg(LOG_NOTICE, "caught termination request");
               // set global termination flag
               set_term_req();
            }
            if (CNF(sig_usr1))
            {
               lock_setup();
               CNF(clear_stats) = 1;
               unlock_setup();
               log_msg(LOG_NOTICE, "stats will be cleared after next stats output");
            }
         }
         log_debug("restarting");
         continue;
      }
      rlen += BUF_OFF;

      log_debug("received on tunfd %d, framesize %d + %d", CNF(tunfd[0]), rlen - 4, 4 - BUF_OFF);

#ifdef PACKET_LOG
      if ((pktlog != -1) && (write(pktlog, buf, rlen) == -1))
         log_debug("could not write frame to packet log: %s", strerror(errno));
#endif

      // just to be on the safe side but this should never happen
      if ((!CNF(use_tap) && (rlen < 4)) || (CNF(use_tap) && (rlen < 4 + (int) sizeof(struct ether_header))))
      {
         log_msg(LOG_ERR, "frame effectively too short (rlen = %d)", rlen);
         continue;
      }

      // in case of TAP device handle ethernet header
      if (CNF(use_tap))
      {
         if (eth_check(buf, rlen))
            continue;

         // removing ethernet header
         // FIXME: it would be better to adjust pointers instead of moving data
         rlen -= sizeof(struct ether_header);
         memmove(eh, eh + 1, rlen - 4);
      }

#if defined(__sun__) || defined(__CYGWIN__)
      // Solaris tunnel driver does not send tunnel
      // header thus we guess and set it manually
      if ((buf[BUF_OFF] & 0xf0) == 0x60)
         set_tunheader(buf, CNF(fhd_key[IPV6_KEY]));
      else if ((buf[BUF_OFF] & 0xf0) == 0x40)
         set_tunheader(buf, CNF(fhd_key[IPV4_KEY]));
      else
         set_tunheader(buf, -1);
#endif

      if (get_tunheader(buf) == CNF(fhd_key[IPV6_KEY]))
      {
         if (((rlen - 4) < (int) IP6HLEN))
         {
            log_debug("IPv6 packet too short (%d bytes). dropping", rlen - 4);
            continue;
         }

         IN6_ADDR_COPY(&destbuf, &buf[4 + offsetof(struct ip6_hdr, ip6_dst)]);
         if (!(dest = ipv6_lookup_route(&destbuf)))
            dest = &destbuf;

         if (!has_tor_prefix(dest))
         {
            char abuf[INET6_ADDRSTRLEN];
            if (!IN6_IS_ADDR_MULTICAST(&destbuf))
               log_msg(LOG_ERR, "no route to destination %s, dropping frame.", inet_ntop(AF_INET6, &destbuf, abuf, INET6_ADDRSTRLEN));
            continue;
         }
      }
      else if (get_tunheader(buf) == CNF(fhd_key[IPV4_KEY]))
      {
         if (((rlen - 4) < (int) IPHDLEN))
         {
            log_debug("IPv4 packet too short (%d bytes). dropping", rlen - 4);
            continue;
         }

#ifdef HAVE_STRUCT_IPHDR
         in.s_addr = get_saddr((struct iphdr*) &buf[4]);
#else
         in.s_addr = get_saddr((struct ip*) &buf[4]);
#endif
         if (!(dest = ipv4_lookup_route(ntohl(in.s_addr))))
         {
            log_msg(LOG_ERR, "no route to destination %s, dropping frame.", inet_ntoa(in));
            continue;
         }
      }
      else
      {
         log_msg(LOG_ERR, "protocol 0x%08x not supported. dropping frame.", ntohl(get_tunheader(buf)));
         continue;
      }

      // now forward either directly or to the queue
      if (forward_packet(dest, buf + 4, rlen - 4) == E_FWD_NOPEER)
      {
         log_debug("adding destination to SOCKS queue");
         socks_queue(*dest, 0);
#ifdef PACKET_QUEUE
         log_debug("queuing packet");
         queue_packet(dest, buf + 4, rlen - 4);
#endif
      }
   }
}


int make_keepalive(const struct in6_addr *src, const struct in6_addr *dst, int flowlabel, const char *hostname, char *buf, int buflen)
{
   struct ip6_hdr *hdr;
   int len, slen;

   // safety check
   if (src == NULL || dst == NULL || buf == NULL)
   {
      log_msg(LOG_CRIT, "NULL pointer caught in make_keepalive()");
      return -1;
   }

   hdr = (struct ip6_hdr*) buf;

   memset(buf, 0, buflen);
   IN6_ADDR_COPY(&hdr->ip6_dst, dst);
   IN6_ADDR_COPY(&hdr->ip6_src, src);
   hdr->ip6_flow = htonl(flowlabel & 0xfffff);
   hdr->ip6_vfc = 0x60;
   hdr->ip6_nxt = IPPROTO_NONE;
   hdr->ip6_hops = 1;
   slen = sizeof(*hdr);

   if (hostname != NULL && *hostname != '\0')
   {
      len = snprintf(buf + slen, buflen - slen, "%c%s%s", 1, hostname, CNF(domain));
      if (len != -1 && len < buflen - slen)
      {
         len++;
         hdr->ip6_plen = htons(len);
         slen += len;
      }
      else
      {
         log_msg(LOG_CRIT, "keepalive truncated, this should never happen");
      }
   }

   return slen;
}


int send_keepalive(OcatPeer_t *peer)
{
   char buf[512];
   int len, slen;

   slen = make_keepalive(&CNF(ocat_addr), &peer->addr, peer->rand, CNF(onion3_url), buf, sizeof(buf));

   log_debug("sending %d bytes keepalive to fd %d", slen, peer->tcpfd);

   if ((len = send(peer->tcpfd, buf, slen, MSG_DONTWAIT)) == -1)
   {
      log_msg(LOG_ERR, "could not send keepalive: %s", strerror(errno));
      return -1;
   }
   peer->out += len;
   if (len != slen)
   {
      log_msg(LOG_ERR, "sending of %d bytes keepalive truncated to %d", slen, len);
      return -1;
   }
   return 0;
}


/*! This thread wakes up every CLEANER_WAKUP seconds and does some house
 * keeping.
 */
void *socket_cleaner(void *UNUSED(ptr))
{
   OcatPeer_t *peer, **p;
   int stat_wup = 0;
   time_t act_time, saved_time = time(NULL);

   for (;;)
   {
      // check for termination request
      if (term_req())
         break;

      sleep(CLEANER_WAKEUP);
      log_debug2("wakeup");

      act_time = time(NULL);

      // save cached hosts
      if (is_hosts_db_modified() && act_time - saved_time > HOSTS_TIME)
      {
         saved_time = act_time;
         hosts_save(OCAT_HOSTS_STATE);
      }

      // stats output
      if (act_time - stat_wup >= STAT_WAKEUP)
      {
         stat_wup = act_time;
         //log_msg(LOG_INFO, "stats: ... (not implemented yet)");

         lock_setup();
         if (CNF(clear_stats))
         {
            CNF(clear_stats) = 0;
            // FIXME: implement stats clearing here
            log_debug("stats cleared");
         }
         unlock_setup();
      }

      // cleanup MAC table
      mac_cleanup();

      // cleanup peers
      lock_peers();
      for (p = get_first_peer_ptr(); *p; p = &(*p)->next)
      {
         lock_peer(*p);

         // handle permanent connections
         if ((*p)->perm)
         {
            // sending keepalive
            if (act_time - (*p)->time >= KEEPALIVE_TIME)
            {
               send_keepalive(*p);
               (*p)->time = act_time;
            }
            unlock_peer(*p);
         }
         // handle temporary connections
         else if ((*p)->state && act_time - (*p)->time >= MAX_IDLE_TIME)
         {
            peer = *p;
            *p = peer->next;
            log_msg(LOG_INFO | LOG_FCONN, "peer %d timed out, closing.", peer->tcpfd);
            oe_close(peer->tcpfd);
            unlock_peer(peer);
            delete_peer(peer);
            if (!(*p))
            {
               log_debug("last peer in list deleted, breaking loop");
               break;
            }
         }
         else
            unlock_peer(*p);
      }
      unlock_peers();
   }
   return NULL;
}


#ifdef WITH_LOOPBACK_RESPONDER
static void memor(void *dst, const void *src, int n)
{
   char *d = dst;
   const char *s = src;

   // safety check
   if (d == NULL || s == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in memor()");
      return;
   }

   for (; n > 0; n--)
      *d++ |= *s++;
}


/*! This is the actual loopback loop. It reflects all valid IPv6 packets with
 * swapped IP addresses.
 * @param fd File descriptor to receive and send packets.
 * @return The function always returns 0.
 */
int loopback_loop(int fd)
{
   char buf[FRAME_SIZE];
   struct in6_addr addr;
   struct ip6_hdr *ip6h = (struct ip6_hdr*) buf;
   int len, wlen, maxfd;
   fd_set rset;

   log_debug("starting loopback loop on fd %d", fd);
   while (!term_req())
   {
      FD_ZERO(&rset);
      FD_SET(fd, &rset);
      log_debug("selecting in fd %d", fd);
      if ((maxfd = select(fd + 1, &rset, NULL, NULL, NULL)) == -1)
      {
         log_msg(LOG_ERR, "select encountered error: \"%s\", restarting", strerror(errno));
         continue;
      }

      if (!FD_ISSET(fd, &rset))
      {
         log_msg(LOG_ERR, "fd %d not in fdset, this should not happen");
         continue;
      }

      // read from pipe
      len = read(fd, buf, sizeof(buf));
      // check for error
      if (len == -1)
      {
         log_msg(LOG_ERR, "read failed: %s", strerror(errno));
         break;
      }
      if (len == 0)
      {
         log_msg(LOG_INFO, "socket was closed");
         break;
      }
      log_debug("read %d bytes", len);
      // check for minimum length of packet
      if (len < (int) IP6HLEN)
      {
         log_msg(LOG_ERR, "packet too small (%d bytes), dropping", len);
         continue;
      }
      // check for IPv6
      if ((buf[0] & 0xf0) != 0x60)
      {
         log_msg(LOG_ERR, "ill packet, starts with 0x%02x, dropping", buf[0]);
         continue;
      }

      log_debug("swapping IPs and sending back");
      // swapping source and destination address
      addr = ip6h->ip6_src;
      ip6h->ip6_src = ip6h->ip6_dst;
      ip6h->ip6_dst = addr;

      wlen = write(fd, buf, len);
      if (wlen == -1)
      {
         log_msg(LOG_ERR, "write failed: %s", strerror(errno));
         break;
      }
      if (wlen < len)
         log_msg(LOG_ERR, "truncated write: %d < %d", wlen, len);
   }

   return 0;
}


int loopback_handler(int fd, const struct in6_addr *laddr)
{
   char buf[FRAME_SIZE];
   int len, wlen, uni;
   OcatPeer_t *peer;

   log_debug("starting loopback_handler");
   wlen = make_keepalive(laddr, &CNF(ocat_addr), 0, NULL, buf, sizeof(buf));

   log_debug("clearing unidirectional mode and sending packet");
   uni = CNF(unidirectional);
   CNF(unidirectional) = 0;
   len = write(fd, buf, wlen);
   log_debug("sent %d of %d bytes to fd %d", len, wlen, fd);

   for (peer = NULL; peer == NULL; )
   {
      lock_peers();
      if ((peer = search_peer(laddr)))
         lock_peer(peer);
      unlock_peers();

      if (peer == NULL)
      {
         log_debug("peer not found, waiting...");
         usleep(100000);
      }
   }

   // reset unidirectional mode
   log_debug("resetting unidirectional mode to %d and setting peer parameters", uni);
   CNF(unidirectional) = uni;
   //peer->addr = addr;
   peer->perm = 1;
   unlock_peer(peer);

   set_thread_ready();
   log_msg(LOG_INFO, "loopback_handler ready listening on %s", inet_ntop(AF_INET6, laddr, buf, INET6_ADDRSTRLEN));

   loopback_loop(fd);

   return 0;
}


/*! This is the local loopback responder thread (the dead-beef-responder). It
 * connects locally to the OnionCat TCP port (the acceptor/receiver thread).
 * Once connected, it receives IPv6 packets and reflects it with swapped IP
 * addresses.
 * @return This function always returns NULL.
 */
void *local_loopback_responder(void *UNUSED(ptr))
{
   struct in6_addr addr = {{{0,0,0,0,0,0,0,0,0,0,0,0,0xde,0xad,0xbe,0xef}}};
   int fd;

   log_debug("initializing dead_beef_responder");
   if ((fd = socket((*CNF(oc_listen))->sa_family, SOCK_STREAM, 0)) == -1)
   {
      log_msg(LOG_ERR, "failed to create socket: %s", strerror(errno));
      goto loop_exit1;
   }

   wait_thread_by_name_ready("acceptor");

   log_debug("connecting...");
   if (connect(fd, *CNF(oc_listen), SOCKADDR_SIZE(*CNF(oc_listen))) == -1)
   {
      log_msg(LOG_ERR, "could not connect(): %s", strerror(errno));
      goto loop_exit2;
   }

   memor(&addr, &NDESC(prefix), sizeof(addr));
   loopback_handler(fd, &addr);

loop_exit2:
   oe_close(fd);

loop_exit1:
   log_msg(LOG_INFO, "local_looback_responder exiting");

   return NULL;
}


/*! This is the remote loopback responder thread. It receives IPv6 packets on a
 * file descriptor and reflects the packets with swapped IP addresses.
 * @param ptr The pointer contains the int file descriptor casted to a pointer.
 * @return The function always return NULL.
 */
void *remote_loopback_responder(void *ptr)
{
   int fd = (uintptr_t) ptr;

   log_debug("initializing feed_beef_responder");

   detach_thread();
   set_thread_ready();

   loopback_loop(fd);

   oe_close(fd);

   log_msg(LOG_INFO, "remote_looback_responder exiting");

   return NULL;
}


/*! This function adds a route for remote loopback responder (the
 * feed-beef-responder). This is an IPv6 route to itself which can not
 * regularly be added.
 * @return On success the function returns 0, otherwise -1.
 */
int add_remote_loopback_route(void)
{
   IPv6Route_t br;

   br.dest = (struct in6_addr) {{{0,0,0,0,0,0,0,0,0,0,0,0,0xfe,0xed,0xbe,0xef}}};
   memor(&br.dest, &NDESC(prefix), sizeof(br.dest));
   br.prefixlen = 128;
   IN6_ADDR_COPY(&br.gw, &CNF(ocat_addr));

   log_debug("adding feed:beef route");
   if (ipv6_add_route(&br))
   {
      log_msg(LOG_ERR, "ipv6_add_route() failed!");
      return -1;
   }

   return 0;
}
#endif

