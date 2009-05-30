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
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#include "ocat.h"


// file descriptor of tcp listener
static int sockfd_[2];
// file descriptors of control port
static int ctrlfd_[2];
// file descriptors of socket_receiver pipe
// used for internal communication
static int lpfd_[2];
// packet queue pointer
static PacketQueue_t *queue_ = NULL;
// mutex and condition variable for packet queue
static pthread_mutex_t queue_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond_ = PTHREAD_COND_INITIALIZER;

// SOCKS connector queue vars
static SocksQueue_t *socks_queue_ = NULL;
static int socks_connect_cnt_ = 0;
static int socks_thread_cnt_ = 0;
static pthread_mutex_t socks_queue_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t socks_queue_cond_ = PTHREAD_COND_INITIALIZER;

// frame header of local OS in network byte order
// it is initialized in ocattun.c
uint32_t fhd_key_ = 0;

uint16_t tor_socks_port_ = TOR_SOCKS_PORT;
uint16_t ocat_listen_port_ = OCAT_LISTEN_PORT;
uint16_t ocat_dest_port_ = OCAT_DEST_PORT;
uint16_t ocat_ctrl_port_ = OCAT_CTRL_PORT;

int vrec_ = 0;

#ifdef SNDBUF
int snd_buf_size_ = 0;
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
      log_msg(L_DEBUG, "no peer for forwarding");
      return E_FWD_NOPEER;
   }

   log_msg(L_DEBUG, "forwarding %d bytes to TCP fd %d", buflen, peer->tcpfd);

#ifdef SNDBUF
   if (ioctl(peer->tcpfd, TIOCOUTQ, &len) != -1)
   {
      if (snd_buf_size_ - len < buflen)
      {
         log_msg(L_ERROR, "OUTQ too less space, dropping packet");
         unlock_peer(peer);
         return E_FWD_NOBUF;
      }
   }
   else
      log_msg(L_ERROR, "could not get OUTQ size: \"%s\"", strerror(errno));

   if ((len = write(peer->tcpfd, buf, buflen)) == -1)
#else
   if ((len = send(peer->tcpfd, buf, buflen, MSG_DONTWAIT)) == -1)
#endif
   {
      log_msg(L_ERROR, "could not write %d bytes to peer %d: \"%s\", dropping", buflen, peer->tcpfd, strerror(errno));
   }
   else
   {
      if (len != buflen)
      {
         // FIXME: there should be sender frag handling!
         log_msg(L_ERROR, "could not write %d bytes to peer %d, %d bytes written", buflen, peer->tcpfd, len);
      }
      peer->time = time(NULL);
      peer->out += len;
   }
   unlock_peer(peer);

   return 0;
}


void queue_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   PacketQueue_t *queue;

   log_msg(L_DEBUG, "copying packet to heap for queue");
   if (!(queue = malloc(sizeof(PacketQueue_t) + buflen)))
   {
      log_msg(L_ERROR, "%s for packet to queue", strerror(errno));
      return;
   }

   memcpy(&queue->addr, addr, sizeof(struct in6_addr));
   queue->psize = buflen;
   queue->data = ((char*)queue) + sizeof(PacketQueue_t);
   memcpy(queue->data, buf, buflen);
   queue->time = time(NULL);

   log_msg(L_DEBUG, "queuing packet");
   pthread_mutex_lock(&queue_mutex_);
   queue->next = queue_;
   queue_ = queue;
   log_msg(L_DEBUG, "waking up dequeuer");
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
#ifdef USE_CLOCK_GETTIME
         clock_gettime(CLOCK_REALTIME, &ts);
#else
          // replaced clock_gettime() due to portability issues
         if (gettimeofday(&tv, NULL) == -1)
         {
            log_msg(L_ERROR, "couldn't gettime: \"%s\"", strerror(errno));
            memset(&tv, 0, sizeof(tv));
         }
         else
         {
            ts.tv_sec = tv.tv_sec;
            ts.tv_nsec = tv.tv_usec * 1000;
         }
#endif
         ts.tv_sec += DEQUEUER_WAKEUP;
         log_msg(L_DEBUG, "timed conditional wait...");
         rc = pthread_cond_timedwait(&queue_cond_, &queue_mutex_, &ts);
      }
      else
      {
         log_msg(L_DEBUG, "conditional wait...");
         rc = pthread_cond_wait(&queue_cond_, &queue_mutex_);
      }

      if (rc)
         log_msg(L_FATAL, "woke up: \"%s\"", strerror(rc));

      log_msg(L_DEBUG, "starting dequeuing");
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
            log_msg(L_DEBUG, "packet dequeued, delay = %d", delay);
            continue;
         }
         queue = &(*queue)->next;
      }
      timed = queue_ != NULL;
      pthread_mutex_unlock(&queue_mutex_);
   }
}


const static char hdigit_[] = "0123456789abcdef";

void hex_code_header(const char *frame, int len, char *buf)
{
   int i;

   for (i = 0; i < len; i++, frame++)
   {
      *buf++ = hdigit_[(*frame >> 4) & 0x0f];
      *buf++ = hdigit_[*frame & 0x0f];
      *buf++ = ' ';
   }
   *--buf = '\0';
}


// do some packet validation
int validate_frame(const struct ip6_hdr *ihd, int len)
{
   char buf[INET6_ADDRSTRLEN];
   char hexbuf[IP6HLEN * 3 + 1];

   if ((ihd->ip6_vfc & 0xf0) != 0x60)
   {
      hex_code_header((char*) ihd, len > IP6HLEN ? IP6HLEN : len, hexbuf);
      log_msg(L_DEBUG, "header \"%s\"", hexbuf);
      return 0;
   }

   if (!has_tor_prefix(&ihd->ip6_dst))
   {
      log_msg(L_ERROR, "destination %s unreachable", inet_ntop(AF_INET6, &ihd->ip6_dst, buf, INET6_ADDRSTRLEN));
      return 0;
   }
   if (!has_tor_prefix(&ihd->ip6_src))
   {
      log_msg(L_ERROR, "source address invalid. Remote ocat could not reply");
      return 0;
   }
#ifdef TEST_TUN_HDR
   if (is_testping(&ihd->ip6_dst))
   {
      log_msg(L_DEBUG, "test ping detected");
      return 0;
   }
#endif
   return ntohs(ihd->ip6_plen);
}


void cleanup_socket(int fd, OcatPeer_t *peer)
{
   log_msg(L_NOTICE, "fd %d reached EOF, closing.", fd);
   close(fd);
   lock_peers();
   delete_peer(peer);
   unlock_peers();
}


#define HANDLE_HTTP
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
         OCAT_URL, timestr, onion_url_
         );
   log_msg(L_INFO, "request seems to be HTTP");
   if (send(peer->tcpfd, response, strlen(response), MSG_DONTWAIT) == -1)
      log_msg(L_ERROR, "could not send html response");

   return 1;
}
#endif


void *socket_receiver(void *p)
{
   int maxfd, len, plen;
   char buf[FRAME_SIZE];
   char addr[INET6_ADDRSTRLEN];
   fd_set rset;
   OcatPeer_t *peer;

   if (pipe(lpfd_) < 0)
      log_msg(L_FATAL, "could not create pipe for socket_receiver: \"%s\"", strerror(errno)), exit(1);

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
            log_msg(L_FATAL, "%d >= FD_SETIZE(%d)", peer->tcpfd, FD_SETSIZE), exit(1);

         FD_SET(peer->tcpfd, &rset);
         if (peer->tcpfd > maxfd)
            maxfd = peer->tcpfd;
         unlock_peer(peer);
      }
      unlock_peers();

      log_msg(L_DEBUG, "selecting...");
      if ((maxfd = select(maxfd + 1, &rset, NULL, NULL, NULL)) == -1)
      {
         log_msg(L_FATAL, "select encountered error: \"%s\", restarting", strerror(errno));
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
            log_msg(L_FATAL, "fd %d ready but no peer found");
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
         log_msg(L_DEBUG, "reading from %d", peer->tcpfd);

         // read/append data to peer's fragment buffer
         if ((len = read(peer->tcpfd, peer->fragbuf + peer->fraglen, FRAME_SIZE - 4 - peer->fraglen)) == -1)
         {
            // this might happen on linux, see SELECT(2)
            log_msg(L_DEBUG, "spurious wakup of %d: \"%s\"", peer->tcpfd, strerror(errno));
            unlock_peer(peer);
            continue;
         }
         log_msg(L_DEBUG, "received %d bytes on %d", len, peer->tcpfd);
         // if len == 0 EOF reached => close session
         if (!len)
         {
            log_msg(L_NOTICE, "fd %d reached EOF, closing.", peer->tcpfd);
            close(peer->tcpfd);
            unlock_peer(peer);
            lock_peers();
            delete_peer(peer);
            unlock_peers();
            continue;
         }

         peer->fraglen += len;
         // update timestamp
         peer->time = time(NULL);
         peer->in += len;
               
         while (peer->fraglen >= IP6HLEN)
         {
            // check frame
            plen = validate_frame((struct ip6_hdr*) peer->fragbuf, peer->fraglen);

            if (!plen)
            {
#ifdef HANDLE_HTTP
               if (handle_http(peer))
               {
                  log_msg(L_NOTICE, "closing %d due to HTTP.", peer->tcpfd);
                  close(peer->tcpfd);
                  unlock_peer(peer);
                  lock_peers();
                  delete_peer(peer);
                  unlock_peers();
               }
#endif
               log_msg(L_DEBUG, "FRAGBUF RESET!");
               peer->fraglen = 0;
               break;
            }

            if (vrec_ && !plen)
            {
               log_msg(L_ERROR, "dropping frame");
               break;
            }

            len = plen + IP6HLEN;
            if (peer->fraglen < len)
            {
               log_msg(L_DEBUG, "keeping %d bytes frag", peer->fraglen);
               break;
            }

            // set IP address if it is not set yet and frame is valid
            if (plen && !memcmp(&peer->addr, &in6addr_any, sizeof(struct in6_addr)))
            {
               memcpy(&peer->addr, &((struct ip6_hdr*)peer->fragbuf)->ip6_src, sizeof(struct in6_addr));
               log_msg(L_NOTICE, "incoming connection on %d from %s is now identified", peer->tcpfd,
                  inet_ntop(AF_INET6, &peer->addr, addr, INET6_ADDRSTRLEN));
            }
            
            log_msg(L_DEBUG, "writing to tun %d framesize %d + 4", tunfd_[1], len);
            if (write(tunfd_[1], &peer->fraghdr, len + 4) != (len + 4))
               log_msg(L_ERROR, "could not write %d bytes to tunnel %d", len + 4, tunfd_[1]);

            peer->fraglen -= len;

            if (peer->fraglen)
            {
               log_msg(L_DEBUG, "moving fragment. fragsize %d", peer->fraglen);
               memmove(peer->fragbuf, peer->fragbuf + len, FRAME_SIZE - 4 - len);
            }
            else
               log_msg(L_DEBUG, "fragbuf empty");
         } // while (peer->fraglen >= IP6HLEN)
         unlock_peer(peer);
      } // while (maxfd)
   } // for (;;)
}


void set_nonblock(int fd)
{
   long flags;

#ifdef SNDBUF
   if (!snd_buf_size_)
   {
      flags = sizeof(snd_buf_size_);
      if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd_buf_size_, (socklen_t*) &flags) == -1)
         log_msg(L_FATAL, "could not get TCP send buffer size: \"%s\"", strerror(errno));
      else
         log_msg(L_DEBUG, "SO_SNDBF = %d", snd_buf_size_);
   }
#endif

   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
   {
      log_msg(L_ERROR, "could not get socket flags for %d: \"%s\"", fd, strerror(errno));
      flags = 0;
   }
   log_msg(L_DEBUG, "O_NONBLOCK currently is %x", flags & O_NONBLOCK);

   if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1)
      log_msg(L_ERROR, "could not set O_NONBLOCK for %d: \"%s\"", fd, strerror(errno));
}


int insert_peer(int fd, const struct in6_addr *addr, time_t dly)
{
   OcatPeer_t *peer;

   log_msg(L_DEBUG, "inserting peer fd %d", fd);

   set_nonblock(fd);

   lock_peers();
   if (!(peer = get_empty_peer()))
   {
      unlock_peers();
      log_msg(L_ERROR, "could not get new empty peer");
      return 0;
   } 
   lock_peer(peer);
   unlock_peers();

   peer->tcpfd = fd;
   peer->state = PEER_ACTIVE;
   peer->otime = peer->time = time(NULL);
   peer->sdelay = dly;
   if (addr)
   {
      memcpy(&peer->addr, addr, sizeof(struct in6_addr));
      peer->dir = PEER_OUTGOING;
   }
   else
      peer->dir = PEER_INCOMING;
   unlock_peer(peer);

   // wake up socket_receiver
   log_msg(L_DEBUG, "waking up socket_receiver");
   if (write(lpfd_[1], &fd, 1) != 1)
      log_msg(L_FATAL, "couldn't write to socket_receiver pipe: \"%s\"", strerror(errno));

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
         log_msg(L_FATAL, "unknown address family %d", addr->sa_family);
         return -1;
   }

   if ((fd = socket(family, SOCK_STREAM, 0)) < 0)
   {
      log_msg(L_FATAL, "could not create listener socker: \"%s\"", strerror(errno));
      return -1;
   }

   if (bind(fd, addr, sock_len) < 0)
   {
      log_msg(L_FATAL, "could not bind listener %d: \"%s\"", fd, strerror(errno));
      close(fd);
      return -1;
   }

   if (listen(fd, 32) < 0)
   {
      log_msg(L_FATAL, "could not bring listener %d to listening state: \"%s\"", fd, strerror(errno));
      close(fd);
      return -1;
   }

   log_msg(L_NOTICE, "created listener, fd = %d", fd);
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

   log_msg(L_DEBUG, "creating IPv4 listener");
   if ((sockfd[0] = create_listener((struct sockaddr*) &in, sizeof(in))) == -1)
      log_msg(L_FATAL, "exiting"), exit(1);

   log_msg(L_DEBUG, "creating IPv6 listener");
   if ((sockfd[1] = create_listener((struct sockaddr*) &in6, sizeof(in6))) == -1)
      log_msg(L_FATAL, "exiting"), exit(1);

   for (;;)
   {
      log_msg(L_DEBUG, "setting up fd_set");
      FD_ZERO(&rset);
      FD_SET(sockfd[0], &rset);
      FD_SET(sockfd[1], &rset);

      maxfd = sockfd[0] > sockfd[1] ? sockfd[0] : sockfd[1];
      log_msg(L_DEBUG, "selecting locally (maxfd = %d)", maxfd);
      if ((maxfd = select(maxfd + 1, &rset, NULL, NULL, NULL)) == -1)
      {
         log_msg(L_DEBUG, "select returned: \"%s\"", strerror(errno));
         continue;
      }
      log_msg(L_DEBUG, "select returned %d fds ready", maxfd);

      for (i = 0; maxfd && (i < 2); i++)
      {
         log_msg(L_DEBUG, "checking fd %d (maxfd = %d, i = %d)", sockfd[i], maxfd, i);
         if (!FD_ISSET(sockfd[i], &rset))
            continue;
         maxfd--;
         log_msg(L_DEBUG, "accepting connection on %d", sockfd[i]);
         if ((fd = accept(sockfd[i], NULL, NULL)) < 0)
         {
            log_msg(L_ERROR, "error accepting connection on %d: \"%s\"", sockfd[i], strerror(errno));
            // FIXME: there should be additional error handling!
            continue;
         }

         log_msg(L_NOTICE, "connection %d accepted on listener %d", fd, sockfd[i]);
         (void) action_accept(fd);
      }
   }
   return 0;
}


void *socket_acceptor(void *p)
{
   run_local_listeners(ocat_listen_port_, sockfd_, insert_anon_peer);
   return NULL;
}


int socks_connect(const struct in6_addr *addr)
{
   struct sockaddr_in in;
   int fd, t, len;
   char buf[FRAME_SIZE], onion[ONION_NAME_SIZE];
   SocksHdr_t *shdr = (SocksHdr_t*) buf;

   log_msg(L_DEBUG, "called");

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(tor_socks_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   in.sin_len = sizeof(in);
#endif

   ipv6tonion(addr, onion);
   strlcat(onion, ".onion", sizeof(onion));

   log_msg(L_NOTICE, "trying to connecto to \"%s\" [%s]", onion, inet_ntop(AF_INET6, addr, buf, FRAME_SIZE));

   if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      return E_SOCKS_SOCK;

   t = time(NULL);
   if (connect(fd, (struct sockaddr*) &in, sizeof(in)) < 0)
   {
      log_msg(L_ERROR, "connect() to TOR failed");
      close(fd);
      return E_SOCKS_CONN;
   }

   log_msg(L_DEBUG, "connected to TOR, doing SOCKS handshake");

   shdr->ver = 4;
   shdr->cmd = 1;
   shdr->port = htons(ocat_dest_port_);
   shdr->addr.s_addr = htonl(0x00000001);
   /*
   strlcpy(buf + sizeof(SocksHdr_t), usrname_, strlen(usrname_) + 1);
   strlcpy(buf + sizeof(SocksHdr_t) + strlen(usrname_) + 1, onion, sizeof(onion));
   */
   memcpy(buf + sizeof(SocksHdr_t), usrname_, strlen(usrname_) + 1);
   memcpy(buf + sizeof(SocksHdr_t) + strlen(usrname_) + 1, onion, strlen(onion) + 1);
   len = sizeof(SocksHdr_t) + strlen(usrname_) + strlen(onion) + 2;
   if (write(fd, shdr, len) != len)
      // FIXME: there should be some additional error handling
      log_msg(L_ERROR, "couldn't write %d bytes to SOCKS connection %d", len, fd);
   log_msg(L_DEBUG, "connect request sent");

   if (read(fd, shdr, sizeof(SocksHdr_t)) < sizeof(SocksHdr_t))
   {
      log_msg(L_ERROR, "short read, closing.");
      close(fd);
      return E_SOCKS_REQ;
   }
   log_msg(L_DEBUG, "SOCKS response received");

   if (shdr->ver || (shdr->cmd != 90))
   {
      log_msg(L_ERROR, "request failed, reason = %d", shdr->cmd);
      close(fd);
      return E_SOCKS_RQFAIL;
   }
   log_msg(L_NOTICE, "connection to %s successfully opened on fd %d", onion, fd);

   insert_peer(fd, addr, time(NULL) - t);

   return fd;
}


void socks_queue(const struct in6_addr *addr)
{
   SocksQueue_t *squeue;

   pthread_mutex_lock(&socks_queue_mutex_);
   for (squeue = socks_queue_; squeue; squeue = squeue->next)
      if (!memcmp(&squeue->addr, addr, sizeof(struct in6_addr)))
         break;
   if (!squeue)
   {
      log_msg(L_DEBUG, "queueing new SOCKS connection request");
      if (!(squeue = calloc(1, sizeof(SocksQueue_t))))
         log_msg(L_FATAL, "could not get memory for SocksQueue entry: \"%s\"", strerror(errno)), exit(1);
      memcpy(&squeue->addr, addr, sizeof(struct in6_addr));
      squeue->next = socks_queue_;
      socks_queue_ = squeue;
      log_msg(L_DEBUG, "signalling connector");
      pthread_cond_signal(&socks_queue_cond_);
   }
   else
      log_msg(L_DEBUG, "connection already exists, not queueing SOCKS connection");
   pthread_mutex_unlock(&socks_queue_mutex_);
}


void *socks_connector(void *p)
{
   OcatPeer_t *peer;
   SocksQueue_t **squeue, *sq;
   int i, rc, ps, run = 1;

   if ((rc = pthread_detach(pthread_self())))
      log_msg(L_ERROR, "couldn't detach: \"%s\"", rc);

   pthread_mutex_lock(&socks_queue_mutex_);
   socks_thread_cnt_++;
   pthread_mutex_unlock(&socks_queue_mutex_);

   while (run)
   {
      pthread_mutex_lock(&socks_queue_mutex_);
      do
      {
         pthread_cond_wait(&socks_queue_cond_, &socks_queue_mutex_);
         for (squeue = &socks_queue_; *squeue; squeue = &(*squeue)->next)
            if (!(*squeue)->state)
               break;
      }
      while (!(*squeue));

      // spawn spare thread if there is no one left
      (*squeue)->state = SOCKS_CONNECTING;
      socks_connect_cnt_++;
      if (socks_thread_cnt_ <= socks_connect_cnt_)
         run_ocat_thread("connector", socks_connector, NULL);
      pthread_mutex_unlock(&socks_queue_mutex_);

      // search for existing peer
      lock_peers();
      peer = search_peer(&(*squeue)->addr);
      unlock_peers();

      // connect via SOCKS if no peer exists
      if (!peer)
         for (i = 0, ps = -1; i < SOCKS_MAX_RETRY && ps < 0; i++)
            ps = socks_connect(&(*squeue)->addr);
      else
         log_msg(L_NOTICE, "peer already exists, ignoring");

      // remove request from queue after connect
      log_msg(L_NOTICE, "removing from SOCKS queue");
      pthread_mutex_lock(&socks_queue_mutex_);
      sq = *squeue;
      *squeue = (*squeue)->next;
      free(sq);
      socks_connect_cnt_--;

      // if there are more threads then pending connections
      // terminate thread
      if (socks_connect_cnt_ < socks_thread_cnt_ - 1)
      {
         socks_thread_cnt_--;
         run = 0;
      }
      pthread_mutex_unlock(&socks_queue_mutex_);
   }
   return NULL;
}


void packet_forwarder(void)
{
   char buf[FRAME_SIZE];
   struct ip6_hdr *ihd;
   int rlen;

   ihd = (struct ip6_hdr*) &buf[4];

   for (;;)
   {
      if ((rlen = read(tunfd_[0], buf, FRAME_SIZE)) == -1)
      {
         rlen = errno;
         log_msg(L_DEBUG, "read from tun %d returned on error: \"%s\"", strerror(rlen));
         if (rlen == EINTR)
         {
            log_msg(L_DEBUG, "signal caught, exiting");
            return;
         }
         log_msg(L_DEBUG, "restart reading");
         continue;
      }

      log_msg(L_DEBUG, "received on tunfd %d, framesize %d + 4", tunfd_[0], rlen - 4);

      if (!validate_frame(ihd, rlen - 4))
      {
         log_msg(L_ERROR, "dropping frame");
         continue;
      }

      // now forward either directly or to the queue
      if (forward_packet(&ihd->ip6_dst, buf + 4, rlen - 4) == E_FWD_NOPEER)
      {
         log_msg(L_NOTICE, "establishing new socks peer");
         socks_queue(&ihd->ip6_dst);
         log_msg(L_DEBUG, "queuing packet");
         queue_packet(&ihd->ip6_dst, buf + 4, rlen - 4);
      }
   }
}


void *socket_cleaner(void *ptr)
{
   OcatPeer_t *peer, **p;

   for (;;)
   {
      sleep(CLEANER_WAKEUP);
      log_msg(L_DEBUG, "wakeup");
      lock_peers();
      for (p = get_first_peer_ptr(); *p; p = &(*p)->next)
      {
         lock_peer(*p);
         if ((*p)->state && (*p)->time + MAX_IDLE_TIME < time(NULL))
         {
            peer = *p;
            *p = peer->next;
            log_msg(L_NOTICE, "peer %d timed out, closing.", peer->tcpfd);
            close(peer->tcpfd);
            unlock_peer(peer);
            delete_peer(peer);
            if (!(*p))
            {
               log_msg(L_DEBUG, "last peer in list deleted, breaking loop");
               break;
            }
         }
         else
            unlock_peer(*p);
      }
      unlock_peers();
   }
}


void _remtr(char *s)
{
   if (!s[0])
      return;
   if (s[strlen(s) - 1] != '\n' && s[strlen(s) - 1] != '\r')
      return;
   s[strlen(s) - 1] = '\0';
   _remtr(s);
}


/**! ctrl_handler handles connections to local control port.
 *   @param p void* typcasted to int contains fd of connected socket.
 *   @return Currently always returns NULL.
 */
// FIXME: ctrl_handler probably is not thread-safe.
void *ctrl_handler(void *p)
{

   int fd;
   FILE *ff;
   char buf[FRAME_SIZE], addrstr[INET6_ADDRSTRLEN], onionstr[ONION_NAME_SIZE], timestr[32];
   int rlen, cfd;
   struct tm *tm;
   OcatThread_t *th;
   OcatPeer_t *peer;

   if ((rlen = pthread_detach(pthread_self())))
      log_msg(L_ERROR, "thread couldn't self-detach: \"%s\"", strerror(rlen));
   log_msg(L_DEBUG, "thread detached");

   fd = (int) p;
   if (!(ff = fdopen(fd, "r+")))
   {
      log_msg(L_ERROR, "could not open %d for writing", fd);
      return NULL;
   }
   log_msg(L_DEBUG, "fd %d fdopen'ed", fd);

   for (;;)
   {
      fprintf(ff, "> ");
      if (!fgets(buf, FRAME_SIZE, ff))
      {
         if (!feof(ff))
            log_msg(L_ERROR, "error reading from %d");
         break;
      }
      // remove trailing \r\n character
      _remtr(buf);
      // continue if string now is empty
      if (!buf[0])
         continue;

      // "exit"/"quit" => terminate thread
      if (buf[0] == 4 || !strncmp(buf, "exit", 4) || !strncmp(buf, "quit", 4))
         break;
      // "status"
      else if (!strncmp(buf, "status", 6))
      {
         lock_peers();
         for (peer = get_first_peer(); peer; peer = peer->next)
            // FIXME: should peer be locked?
            if (peer->state == PEER_ACTIVE)
            {
               tm = localtime(&peer->otime);
               strftime(timestr, 32, "%c", tm);
               fprintf(ff, "[%s]\n fd = %d\n addr = %s\n dir = \"%s\"\n idle = %lds\n bytes_in = %ld\n bytes_out = %ld\n setup_delay = %lds\n opening_time = \"%s\"\n",
                     ipv6tonion(&peer->addr, onionstr), peer->tcpfd,
                     inet_ntop(AF_INET6, &peer->addr, addrstr, INET6_ADDRSTRLEN),
                     peer->dir == PEER_INCOMING ? "in" : "out",
                     time(NULL) - peer->time, peer->in, peer->out, peer->sdelay, timestr);
            }
         unlock_peers();
      }
      else if (!strncmp(buf, "close ", 6))
      {
         cfd = atoi(&buf[6]);
         lock_peers();
         for (peer = get_first_peer(); peer; peer = peer->next)
            if (peer->tcpfd == cfd)
            {
               log_msg(L_NOTICE, "close request for %d", cfd);
               close(cfd);
               delete_peer(peer);
               break;
            }
         if (!peer)
         {
            log_msg(L_NOTICE, "no peer with fd %d exists\n", cfd);
            fprintf(ff, "no peer with fd %d exists\n", cfd);
         }
         unlock_peers();
      }
      else if (!strncmp(buf, "threads", 7))
      {
         pthread_mutex_lock(&thread_mutex_);
         for (th = octh_; th; th = th->next)
            fprintf(ff, "%2d: %s\n", th->id, th->name);
         pthread_mutex_unlock(&thread_mutex_);
      }
      else if (!strncmp(buf, "terminate", 9))
      {
         log_msg(L_NOTICE, "terminate request from control port");
         //FIXME: fds should be closed properly
         exit(0);
      }
      else if (!strncmp(buf, "fds", 3))
      {
         fprintf(ff, "acceptor sockets: %d/%d\nconntroller sockets: %d/%d\n", sockfd_[0], sockfd_[1], ctrlfd_[0], ctrlfd_[1]);
      }
      else if (!strncmp(buf, "help", 4))
      {
         fprintf(ff, "commands:\nexit\nquit\nterminate\nclose <n>\nstatus\nthreads\nfds\n");
      }
      else
      {
         fprintf(ff, "unknown command: \"%s\"\n", buf);
      }
   }

   log_msg(L_NOTICE, "closing session %d", fd);
   if (fclose(ff) == EOF)
      log_msg(L_ERROR, "error closing control stream: \"%s\"", strerror(errno));
   // fclose also closes the fd according to the man page

   return NULL;
}


int run_ctrl_handler(int fd)
{
   return (int) run_ocat_thread("ctrl_handler", ctrl_handler, (void*) fd);
}


void *ocat_controller(void *p)
{
   run_local_listeners(ocat_ctrl_port_, ctrlfd_, run_ctrl_handler);
   return NULL;
}
