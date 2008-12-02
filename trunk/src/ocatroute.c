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

/*! ocatroute.c
 *  Contains functions for managing both kind of TCP peers.
 *  Those are active SOCKS4A and passive TCP-LISTEN.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#include "ocat.h"

#ifdef HAVE_STRUCT_IPHDR
#define IPPKTLEN(x) ntohs(((struct iphdr*) (x))->tot_len)
#define IPHDLEN sizeof(struct iphdr)
#else
#define IPPKTLEN(x) ntohs(((struct ip*) (x))->ip_len)
#define IPHDLEN sizeof(struct ip)
#endif

// file descriptor of tcp listener
int sockfd_[2];
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

   memcpy(&queue->addr, addr, sizeof(struct in6_addr));
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


/*! Check if source and destination address has
 *  the TOR IPv6 prefix.
 *  @return 0 on error or packet length else. */
int check_tor_prefix(const struct ip6_hdr *ihd)
{
   char buf[INET6_ADDRSTRLEN];

   if (!has_tor_prefix(&ihd->ip6_dst))
   {
      log_msg(LOG_ERR, "destination %s unreachable", inet_ntop(AF_INET6, &ihd->ip6_dst, buf, INET6_ADDRSTRLEN));
      return 0;
   }
   if (!has_tor_prefix(&ihd->ip6_src))
   {
      log_msg(LOG_ERR, "source address invalid. Remote ocat could not reply");
      return 0;
   }
   return ntohs(ihd->ip6_plen);
}


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


void *socket_receiver(void *p)
{
   int maxfd, len;
   char buf[FRAME_SIZE];
   char addr[INET6_ADDRSTRLEN];
   fd_set rset;
   OcatPeer_t *peer;
   struct in6_addr *in6;
   int drop = 0;
   struct ether_header *eh = (struct ether_header*) (buf + 4);

   if (pipe(lpfd_) < 0)
      log_msg(LOG_EMERG, "could not create pipe for socket_receiver: \"%s\"", strerror(errno)), exit(1);

   for (;;)
   {
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

      log_debug("selecting...");
      if ((maxfd = select(maxfd + 1, &rset, NULL, NULL, NULL)) == -1)
      {
         log_msg(LOG_EMERG, "select encountered error: \"%s\", restarting", strerror(errno));
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
            peer = get_first_peer();
         else if (!(peer = peer->next))
         {
            log_msg(LOG_EMERG, "fd %d ready but no peer found");
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
               socks_queue(&peer->addr, 1);
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
            // incoming packet seems to be IPv6
            if ((peer->fragbuf[0] & 0xf0) == 0x60)
            {
               log_debug("identified IPv6 packet");
               if ((peer->fraglen < IP6HLEN) || (peer->fraglen < ntohs(((struct ip6_hdr*) peer->fragbuf)->ip6_plen) + IP6HLEN))
               {
                  log_debug("keeping %d bytes frag", peer->fraglen);
                  break;
               }

               len = ntohs(((struct ip6_hdr*)peer->fragbuf)->ip6_plen) + IP6HLEN;
               *peer->tunhdr = CNF(fhd_key[IPV6_KEY]);
            }
            // incoming packet seems to be IPv4
            else if ((peer->fragbuf[0] & 0xf0) == 0x40)
            {
               if ((peer->fragbuf[0] & 0x0f) < 5)
               {
                  log_debug("dropping packet, not IPv4 - resetting fragment buffer");
                  peer->fraglen = 0;
                  break;
               }

 #ifdef HANDLE_HTTP
               if (handle_http(peer))
               {
                  log_msg(LOG_INFO | LOG_FCONN, "closing %d due to HTTP", peer->tcpfd);
                  oe_close(peer->tcpfd);
                  unlock_peer(peer);
                  lock_peers();
                  delete_peer(peer);
                  unlock_peers();
               }
#endif
              
               log_debug("identified IPv4 packet");
               if ((peer->fraglen < IPHDLEN) || (peer->fraglen < IPPKTLEN(peer->fragbuf)))
               {
                  log_debug("keeping %d bytes frag", peer->fraglen);
                  break;
               }

               len = IPPKTLEN(peer->fragbuf);
               *peer->tunhdr = CNF(fhd_key[IPV4_KEY]);
            }
            else
            {
               log_debug("fragment buffer reset");
               peer->fraglen = 0;
               break;
            }

            // set IP address if it is not set yet and frame is valid
            if (IN6_IS_ADDR_UNSPECIFIED(&peer->addr))
            {
               if (*peer->tunhdr == CNF(fhd_key[IPV6_KEY]))
                  memcpy(&peer->addr, &((struct ip6_hdr*)peer->fragbuf)->ip6_src, sizeof(struct in6_addr));
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
                     memcpy(&peer->addr, in6, sizeof(struct in6_addr));
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
                  log_debug("writing to tun %d framesize %d + 4", CNF(tunfd[1]), len);
                  if (write(CNF(tunfd[1]), peer->tunhdr, len + 4) != (len + 4))
                     log_msg(LOG_ERR, "could not write %d bytes to tunnel %d", len + 4, CNF(tunfd[1]));
               }
               // create ethernet header and handle MAC on TAP device
               else if (*peer->tunhdr == CNF(fhd_key[IPV6_KEY]))
               {
                  log_debug("creating ethernet header");

                  // FIXME: should differentiate between IPv6 and IP!!
                  memset(eh->ether_dhost, 0, ETHER_ADDR_LEN);
                  if (mac_set(&((struct ip6_hdr*)peer->fragbuf)->ip6_dst, eh->ether_dhost) == -1)
                  {
                     log_debug("dest MAC unknown, resolving");
                     ndp_solicit(&((struct ip6_hdr*)peer->fragbuf)->ip6_src, &((struct ip6_hdr*)peer->fragbuf)->ip6_dst);
                  }
                  else
                  {
                     *((uint32_t*) buf) = *peer->tunhdr;
                     memcpy(buf + 4 + sizeof(struct ether_header), peer->fragbuf, len);
                     memcpy(eh->ether_shost, CNF(ocat_hwaddr), ETHER_ADDR_LEN);

                     if (*peer->tunhdr == CNF(fhd_key[IPV6_KEY]))
                        eh->ether_type = htons(ETHERTYPE_IPV6);
                     else if (*peer->tunhdr == CNF(fhd_key[IPV4_KEY]))
                        eh->ether_type = htons(ETHERTYPE_IP);

                     if (write(CNF(tunfd[1]), buf, len + 4 + sizeof(struct ether_header)) != (len + 4 + sizeof(struct ether_header)))
                        log_msg(LOG_ERR, "could not write %d bytes to tunnel %d", len + 4 + sizeof(struct ether_header), CNF(tunfd[1]));
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
               log_debug("fragbuf empty");

        } // while (peer->fraglen)

        unlock_peer(peer);
      } // while (maxfd)
   } // for (;;)
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
      memcpy(&peer->addr, &sq->addr, sizeof(struct in6_addr));
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
   int fd;

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

   if (bind(fd, addr, sock_len) < 0)
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


/** run_local_listeners(...) is a generic socket acceptor for
 *  local TCP ports (IPv4+IPv6).
 *  Every time a connection comes in the function action_accept is
 *  called with the incoming file descriptor as parameter.
 */
int run_local_listeners(short port, int *sockfd, int (action_accept)(int))
{
   int fd;
   struct sockaddr_in in;
   struct sockaddr_in6 in6;
   fd_set rset;
   int maxfd, i;
   socklen_t alen;
   char iabuf[INET6_ADDRSTRLEN];

   memset(&in, 0, sizeof(in));
   memset(&in6, 0, sizeof(in6));

   in.sin_family = AF_INET;
   in.sin_port = htons(port);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

   in6.sin6_family = AF_INET6;
   in6.sin6_port = htons(port);
   memcpy(&in6.sin6_addr.s6_addr, &in6addr_loopback, sizeof(in6addr_loopback));

#ifdef HAVE_SIN_LEN
   in.sin_len = sizeof(in);
   in6.sin6_len = sizeof(in6);
#endif

   log_debug("creating IPv4 listener");
   if ((sockfd[0] = create_listener((struct sockaddr*) &in, sizeof(in))) == -1)
      log_msg(LOG_EMERG, "exiting"), exit(1);

   log_debug("creating IPv6 listener");
   if ((sockfd[1] = create_listener((struct sockaddr*) &in6, sizeof(in6))) == -1)
      log_msg(LOG_EMERG, "exiting"), exit(1);

   for (;;)
   {
      log_debug("setting up fd_set");
      FD_ZERO(&rset);
      FD_SET(sockfd[0], &rset);
      FD_SET(sockfd[1], &rset);

      maxfd = sockfd[0] > sockfd[1] ? sockfd[0] : sockfd[1];
      log_debug("selecting locally (maxfd = %d)", maxfd);
      if ((maxfd = select(maxfd + 1, &rset, NULL, NULL, NULL)) == -1)
      {
         log_debug("select returned: \"%s\"", strerror(errno));
         continue;
      }
      log_debug("select returned %d fds ready", maxfd);

      for (i = 0; maxfd && (i < 2); i++)
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
         log_msg(LOG_INFO | LOG_FCONN, "connection %d accepted on listener %d from %s port %d", fd, sockfd[i], iabuf, ntohs(in6.sin6_port));
         (void) action_accept(fd);
      }
   }
   return 0;
}


void *socket_acceptor(void *p)
{
   run_local_listeners(CNF(ocat_listen_port), sockfd_, insert_anon_peer);
   return NULL;
}


void packet_forwarder(void)
{
   char buf[FRAME_SIZE];
   int rlen;
   struct in6_addr *dest;
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
      if ((rlen = read(CNF(tunfd[0]), buf, FRAME_SIZE)) == -1)
      {
         rlen = errno;
         log_debug("read from tun %d returned on error: \"%s\"", CNF(tunfd[0]), strerror(rlen));
         if (rlen == EINTR)
         {
            log_debug("signal caught, exiting");
            return;
         }
         log_debug("restart reading");
         continue;
      }

      log_debug("received on tunfd %d, framesize %d + 4", CNF(tunfd[0]), rlen - 4);

#ifdef PACKET_LOG
      if ((pktlog != -1) && (write(pktlog, buf, rlen) == -1))
         log_debug("could not write frame to packet log: %s", strerror(errno));
#endif

      // just to be on the safe side but this should never happen
      if ((!CNF(use_tap) && (rlen < 4)) || (CNF(use_tap) && (rlen < 4 + sizeof(struct ether_header))))
      {
         log_msg(LOG_ERR, "frame effektively too short (rlen = %d)", rlen);
         continue;
      }

      // in case of TAP device handle ethernet header
      if (CNF(use_tap))
      {
         if (eth_check(buf, rlen))
            continue;

         // removing ethernet header
         // FIXME: it would be better to adjust pointers instead of moving data
         memmove(eh, eh + 1, rlen - 4 - sizeof(struct ether_header));
      }

      if (*((uint32_t*) buf) == CNF(fhd_key[IPV6_KEY]))
      {
         if (((rlen - 4) < IP6HLEN))
         {
            log_debug("IPv6 packet too short (%d bytes). dropping", rlen - 4);
            continue;
         }

         if (!check_tor_prefix((struct ip6_hdr*) &buf[4]))
         {
            log_msg(LOG_ERR, "dropping frame");
            continue;
         }

         dest = &((struct ip6_hdr*) &buf[4])->ip6_dst;
      }
      else if (*((uint32_t*) buf) == CNF(fhd_key[IPV4_KEY]))
      {
         if (((rlen - 4) < IPHDLEN))
         {
            log_debug("IPv4 packet too short (%d bytes). dropping", rlen - 4);
            continue;
         }

#ifdef HAVE_STRUCT_IPHDR
         in.s_addr = ((struct iphdr*) &buf[4])->daddr;
#else
         in.s_addr = ((struct ip*) &buf[4])->ip_dst.s_addr;
#endif
         if (!(dest = ipv4_lookup_route(ntohl(in.s_addr))))
         {
            log_msg(LOG_ERR, "no route to destination %s, dropping frame.", inet_ntoa(in));
            continue;
         }
      }
      else
      {
         log_msg(LOG_ERR, "protocol 0x%08x not supported. dropping frame.", ntohl(*((uint32_t*) buf)));
         continue;
      }

      // now forward either directly or to the queue
      if (forward_packet(dest, buf + 4, rlen - 4) == E_FWD_NOPEER)
      {
         log_debug("adding destination to SOCKS queue");
         socks_queue(dest, 0);
#ifdef PACKET_QUEUE
         log_debug("queuing packet");
         queue_packet(dest, buf + 4, rlen - 4);
#endif
      }
   }
}


int send_keepalive(OcatPeer_t *peer)
{
   struct ip6_hdr hdr;
   int len;

   memset(&hdr, 0, sizeof(hdr));
   memcpy(&hdr.ip6_dst, &peer->addr, sizeof(struct in6_addr));
   memcpy(&hdr.ip6_src, &CNF(ocat_addr), sizeof(struct in6_addr));
   hdr.ip6_vfc = 0x60;
   hdr.ip6_nxt = IPPROTO_NONE;
   hdr.ip6_hops = 1;

   log_debug("sending %d bytes keepalive to fd %d", sizeof(hdr), peer->tcpfd);

   if ((len = send(peer->tcpfd, &hdr, sizeof(hdr), MSG_DONTWAIT)) == -1)
   {
      log_msg(LOG_ERR, "could not send keepalive: %s", strerror(errno));
      return -1;
   }
   peer->out += len;
   if (len != sizeof(hdr))
   {
      log_msg(LOG_ERR, "sending of %d bytes keepalive truncated to %d", sizeof(hdr), len);
      return -1;
   }
   return 0;
}


void *socket_cleaner(void *ptr)
{
   OcatPeer_t *peer, **p;
   int stat_wup = 0;
   time_t act_time;

   for (;;)
   {
      sleep(CLEANER_WAKEUP);
      log_debug("wakeup");

      act_time = time(NULL);

      // stats output
      if (act_time - stat_wup >= STAT_WAKEUP)
      {
         stat_wup = act_time;
         log_msg(LOG_INFO, "stats: ... (not implemented yet)");
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
}

