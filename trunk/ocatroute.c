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
//#include <netinet/in.h>
//#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "ocat.h"


// file descriptor of tcp listener
static int sockfd_;
// file descriptors of socket_receiver pipe
// used for internal communication
static int lpfd_[2];
// array of active peers
static OcatPeer_t *peer_ = NULL;
// mutex for locking array of peers
pthread_mutex_t peer_mutex_ = PTHREAD_MUTEX_INITIALIZER;
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

int vrec_ = 0;


//k
OcatPeer_t *search_peer(const struct in6_addr *addr)
{
   OcatPeer_t *peer;

   for (peer = peer_; peer; peer = peer->next)
      if (!memcmp(addr, &peer->addr, sizeof(struct in6_addr)))
         return peer;
   return NULL;
}


//k
OcatPeer_t *get_empty_peer(void)
{
   int rc;
   OcatPeer_t *peer;

   if (!(peer = calloc(1, sizeof(OcatPeer_t))))
   {
      log_msg(L_ERROR, "cannot get memory for new peer: \"%s\"", strerror(errno));
      return NULL;
   }

   peer->fraghdr = fhd_key_;
   if ((rc = pthread_mutex_init(&peer->mutex, NULL)))
   {
      log_msg(L_FATAL, "cannot init new peer mutex: \"%s\"", strerror(rc));
      free(peer);
      return NULL;
   }

   peer->next = peer_;
   peer_ = peer;

   return peer;  
}


//k
void delete_peer(OcatPeer_t *peer)
{
   int rc;
   OcatPeer_t **p;

   for (p = &peer_; *p; p = &(*p)->next)
      if (*p == peer)
      {
         pthread_mutex_lock(&peer->mutex);
         *p = peer->next;
         pthread_mutex_unlock(&peer->mutex);
         if ((rc = pthread_mutex_destroy(&peer->mutex)))
            log_msg(L_FATAL, "cannot destroy mutex: \"%s\"", strerror(rc));
         free(peer);
         return;
      }
}


//k
int forward_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   OcatPeer_t *peer;

   pthread_mutex_lock(&peer_mutex_);
   if ((peer = search_peer(addr)))
   {
      pthread_mutex_lock(&peer->mutex);
      log_msg(L_DEBUG, "forwarding %d bytes to TCP fd %d", buflen, peer->tcpfd);
      if (write(peer->tcpfd, buf, buflen) != buflen)
         log_msg(L_ERROR, "could not write %d bytes to peer %d", buflen, peer->tcpfd);
      peer->time = time(NULL);
      peer->out += buflen;
      pthread_mutex_unlock(&peer->mutex);
   }
   pthread_mutex_unlock(&peer_mutex_);

   return peer != NULL;
}


//k
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


//k
void *packet_dequeuer(void *p)
{
   PacketQueue_t **queue, *fqueue;
//   OcatPeer_t *peer;
   struct timespec ts;
   int rc, timed = 0;
   time_t delay;

   for (;;)
   {
      pthread_mutex_lock(&queue_mutex_);
      if (timed)
      {
         clock_gettime(CLOCK_REALTIME, &ts);
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
         if (rc || (delay > MAX_QUEUE_DELAY))
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
//k
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


//k
void cleanup_socket(int fd, OcatPeer_t *peer)
{
   log_msg(L_NOTICE, "fd %d reached EOF, closing.", fd);
   close(fd);
   pthread_mutex_lock(&peer_mutex_);
   delete_peer(peer);
   pthread_mutex_unlock(&peer_mutex_);
}


//k
void *socket_receiver(void *p)
{
   int maxfd, len, plen;
   char buf[FRAME_SIZE];
   char addr[INET6_ADDRSTRLEN];
   fd_set rset;
   //struct ip6_hdr *ihd;
   //ihd = (struct ip6_hdr*) &buf[4];
   OcatPeer_t *peer;

   if (pipe(lpfd_) < 0)
      log_msg(L_FATAL, "could not create pipe for socket_receiver: \"%s\"", strerror(errno)), exit(1);

   //*((uint32_t*) buf) = fhd_key_;

   for (;;)
   {
      FD_ZERO(&rset);
      FD_SET(lpfd_[0], &rset);
      maxfd = lpfd_[0];

      // create set for all available peers to read
      pthread_mutex_lock(&peer_mutex_);
      for (peer = peer_; peer; peer = peer->next)
      {
         pthread_mutex_lock(&peer->mutex);
         // only select active peers
         if (peer->state != PEER_ACTIVE)
         {
            pthread_mutex_unlock(&peer->mutex);
            continue;
         }

         if (peer->tcpfd >= FD_SETSIZE)
            log_msg(L_FATAL, "%d >= FD_SETIZE(%d)", peer->tcpfd, FD_SETSIZE), exit(1);

         FD_SET(peer->tcpfd, &rset);
         if (peer->tcpfd > maxfd)
            maxfd = peer->tcpfd;
         pthread_mutex_unlock(&peer->mutex);
      }
      pthread_mutex_unlock(&peer_mutex_);

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

      //FIXME: should only run until num select returned
      //for (peer = peer_; peer; peer = peer->next)

      peer = NULL;
      while (maxfd)
      {
         // the following 10 loc look somehow strange and someone may tend
         // to write this as a for loop but it's necessary for thread locking!
         pthread_mutex_lock(&peer_mutex_);
         if (!peer)
            peer = peer_;
         else if (!(peer = peer->next))
         {
            log_msg(L_FATAL, "fd %d ready but no peer found");
            pthread_mutex_unlock(&peer_mutex_);
            break;
         }
         pthread_mutex_lock(&peer->mutex);
         pthread_mutex_unlock(&peer_mutex_);

         //state = peer->state;
         //fd = peer->tcpfd;

         if (peer->state != PEER_ACTIVE)
         {
            pthread_mutex_unlock(&peer->mutex);
            continue;
         }

         if (!FD_ISSET(peer->tcpfd, &rset))
         {
            pthread_mutex_unlock(&peer->mutex);
            continue;
         }

         maxfd--;

         //if (FD_ISSET(fd, &rset))
         //{
            log_msg(L_DEBUG, "reading from %d", peer->tcpfd);

            // read/append data to peer's fragment buffer
            if ((len = read(peer->tcpfd, peer->fragbuf + peer->fraglen, FRAME_SIZE - 4 - peer->fraglen)) == -1)
            {
               // this might happen on linux, see SELECT(2)
               log_msg(L_DEBUG, "spurious wakup of %d: \"%s\"", peer->tcpfd, strerror(errno));
               pthread_mutex_unlock(&peer->mutex);
               continue;
            }
            log_msg(L_DEBUG, "received %d bytes on %d", len, peer->tcpfd);
            // if len == 0 EOF reached => close session
            if (!len)
            {
               log_msg(L_NOTICE, "fd %d reached EOF, closing.", peer->tcpfd);
               close(peer->tcpfd);
               pthread_mutex_unlock(&peer->mutex);
               pthread_mutex_lock(&peer_mutex_);
               delete_peer(peer);
               pthread_mutex_unlock(&peer_mutex_);
               continue;
            }

            //pthread_mutex_lock(&peer_mutex_);
            peer->fraglen += len;
            // update timestamp
            peer->time = time(NULL);
            peer->in += len;
            //pthread_mutex_unlock(&peer_mutex_);
               
            while (peer->fraglen >= IP6HLEN)
            {
               // check frame
               plen = validate_frame((struct ip6_hdr*) peer->fragbuf, peer->fraglen);

               // <FIXME> sometimes defragmentation looses sync due to currently unknown bug!
               if (!plen)
               {
                  log_msg(L_DEBUG, "FRAGBUF RESET!");
                  //pthread_mutex_lock(&peer_mutex_);
                  peer->fraglen = 0;
                  //pthread_mutex_unlock(&peer_mutex_);
                  break;
               }
               // </FIXME>

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

               //pthread_mutex_lock(&peer_mutex_);
               // set IP address if it is not set yet and frame is valid
               if (plen && !memcmp(&peer->addr, &in6addr_any, sizeof(struct in6_addr)))
               {
                  memcpy(&peer->addr, &((struct ip6_hdr*)peer->fragbuf)->ip6_src, sizeof(struct in6_addr));
                  log_msg(L_NOTICE, "incoming connection on %d from %s is now identified", peer->tcpfd,
                        inet_ntop(AF_INET6, &peer->addr, addr, INET6_ADDRSTRLEN));
               }
               //pthread_mutex_unlock(&peer_mutex_);
            
               log_msg(L_DEBUG, "writing to tun %d framesize %d + 4", tunfd_[1], len);
               if (write(tunfd_[1], &peer->fraghdr, len + 4) != (len + 4))
                  log_msg(L_ERROR, "could not write %d bytes to tunnel %d", len + 4, tunfd_[1]);


               //pthread_mutex_lock(&peer_mutex_);
               peer->fraglen -= len;
               //pthread_mutex_unlock(&peer_mutex_);

               if (peer->fraglen)
               {
                  log_msg(L_DEBUG, "moving fragment. fragsize %d", peer->fraglen);
                  memmove(peer->fragbuf, peer->fragbuf + len, FRAME_SIZE - 4 - len);
               }
               else
                  log_msg(L_DEBUG, "fragbuf empty");
            } // while (peer->fraglen >= IP6HLEN)
         //}
         pthread_mutex_unlock(&peer->mutex);
      } // while (maxfd)
   } // for (;;)
}


//k
void set_nonblock(int fd)
{
   long flags;

   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
   {
      log_msg(L_ERROR, "could not get socket flags for %d: \"%s\"", fd, strerror(errno));
      flags = 0;
   }
   log_msg(L_DEBUG, "O_NONBLOCK currently is %x", flags & O_NONBLOCK);

   if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1)
      log_msg(L_ERROR, "could not set O_NONBLOCK for %d: \"%s\"", fd, strerror(errno));
}


//k
int insert_peer(int fd, const struct in6_addr *addr, time_t dly)
{
   OcatPeer_t *peer;

   log_msg(L_DEBUG, "inserting peer fd %d", fd);

   set_nonblock(fd);

   pthread_mutex_lock(&peer_mutex_);
   if (!(peer = get_empty_peer()))
   {
      pthread_mutex_unlock(&peer_mutex_);
      log_msg(L_ERROR, "could not get new empty peer");
      return 0;
   } 
   pthread_mutex_lock(&peer->mutex);
   pthread_mutex_unlock(&peer_mutex_);

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
   pthread_mutex_unlock(&peer->mutex);

   // wake up socket_receiver
   log_msg(L_DEBUG, "waking up socket_receiver");
   if (write(lpfd_[1], &fd, 1) != 1)
      log_msg(L_FATAL, "couldn't write to socket_receiver pipe: \"%s\"", strerror(errno));

   return 1;
}


//k
void *socket_acceptor(void *p)
{
   int fd;
   struct sockaddr_in in;

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(ocat_listen_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   in.sin_len = sizeof(in);
#endif

   if ((sockfd_ = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      log_msg(L_FATAL, "could not create listener socker: \"%s\"", strerror(errno)), exit(1);

   if (bind(sockfd_, (struct sockaddr*) &in, sizeof(struct sockaddr_in)) < 0)
      log_msg(L_FATAL, "could not bind listener: \"%s\"", strerror(errno)), exit(1);

   if (listen(sockfd_, 32) < 0)
      log_msg(L_FATAL, "could not bring listener to listening state: \"%s\"", strerror(errno)), exit(1);
   
   log_msg(L_NOTICE, "created local listener %d on port %d", sockfd_, ocat_listen_port_);

   for (;;)
   {
      log_msg(L_DEBUG, "[socket acceptor] is accepting further connections");
      if ((fd = accept(sockfd_, NULL, NULL)) < 0)
         perror("onion_receiver:accept"), exit(1);

      log_msg(L_NOTICE, "connection %d accepted on listener %d", fd, sockfd_);
      insert_peer(fd, NULL, 0);
   }

   return NULL;
}


//k
int socks_connect(const struct in6_addr *addr)
{
   struct sockaddr_in in;
   int fd, t;
   char buf[FRAME_SIZE], onion[ONION_NAME_SIZE];
   SocksHdr_t *shdr = (SocksHdr_t*) buf;
//   OcatPeer_t *ohd;

   log_msg(L_DEBUG, "[socks_connect] called");

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(tor_socks_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   in.sin_len = sizeof(in);
#endif

   ipv6tonion(addr, onion);
   strcat(onion, ".onion");

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
   strcpy(buf + sizeof(SocksHdr_t), "tor6");
   strcpy(buf + sizeof(SocksHdr_t) + 5, onion);

   if (write(fd, shdr, sizeof(SocksHdr_t) + strlen(onion) + 6) != sizeof(SocksHdr_t) + strlen(onion) + 6)
      // FIXME: there should be some additional error handling
      log_msg(L_ERROR, "couldn't write %d bytes to SOCKS connection %d", sizeof(SocksHdr_t) + strlen(onion) + 6, fd);
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


//k
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


//k
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
         run_ocat_thread("connector", socks_connector);
      pthread_mutex_unlock(&socks_queue_mutex_);

      // search for existing peer
      pthread_mutex_lock(&peer_mutex_);
      peer = search_peer(&(*squeue)->addr);
      pthread_mutex_unlock(&peer_mutex_);

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


//k
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
      if (!forward_packet(&ihd->ip6_dst, buf + 4, rlen - 4))
      {
         log_msg(L_NOTICE, "establishing new socks peer");
         socks_queue(&ihd->ip6_dst);
         log_msg(L_DEBUG, "queuing packet");
         queue_packet(&ihd->ip6_dst, buf + 4, rlen - 4);
      }
   }
}


//k
void *socket_cleaner(void *ptr)
{
   OcatPeer_t *peer, **p;

   for (;;)
   {
      sleep(CLEANER_WAKEUP);
      log_msg(L_DEBUG, "wakeup");
      pthread_mutex_lock(&peer_mutex_);
      for (p = &peer_; *p; p = &(*p)->next)
      {
         pthread_mutex_lock(&(*p)->mutex);
         if ((*p)->state && (*p)->time + MAX_IDLE_TIME < time(NULL))
         {
            peer = *p;
            *p = peer->next;
            log_msg(L_NOTICE, "peer %d timed out, closing.", peer->tcpfd);
            close(peer->tcpfd);
            pthread_mutex_unlock(&peer->mutex);
            delete_peer(peer);
            continue;
         }
         pthread_mutex_unlock(&(*p)->mutex);
      }
      pthread_mutex_unlock(&peer_mutex_);
   }
}


void *ocat_controller(void *p)
{
   int fd, sfd;
   struct sockaddr_in in;
   char buf[FRAME_SIZE], addrstr[INET6_ADDRSTRLEN], onionstr[ONION_NAME_SIZE], timestr[32];
   int rlen, cfd;
   struct tm *tm;
   OcatThread_t *th;
   OcatPeer_t *peer;

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(OCAT_CTRL_PORT);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   in.sin_len = sizeof(in);
#endif

   if ((sfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      log_msg(L_FATAL, "could not create listener socker: \"%s\"", strerror(errno)), exit(1);

   if (bind(sfd, (struct sockaddr*) &in, sizeof(struct sockaddr_in)) < 0)
      log_msg(L_FATAL, "could not bind listener: \"%s\"", strerror(errno)), exit(1);

   if (listen(sfd, 5) < 0)
      log_msg(L_FATAL, "could not bring listener to listening state: \"%s\"", strerror(errno)), exit(1);
   
   log_msg(L_NOTICE, "created local listener %d on port %d", sfd, ocat_listen_port_);

   for (;;)
   {
      log_msg(L_DEBUG, "accepting connections on %d", sfd);
      if ((fd = accept(sfd, NULL, NULL)) < 0)
         log_msg(L_FATAL, "error in acception: \"%s\"", strerror(errno)), exit(1);
      log_msg(L_NOTICE, "connection %d accepted on %d", fd, sfd);

      for (;;)
      {
         if (write(fd, "> ", 2) != 2)
            log_msg(L_ERROR, "couldn't write %d bytes to control socket %d", 2, fd);

         if ((rlen = read(fd, buf, FRAME_SIZE)) == -1)
         {
            log_msg(L_FATAL, "read error on %d: \"%s\", closing", fd, strerror(errno));
            break;
         }

         if (!rlen || buf[0] == 4 || !strncmp(buf, "exit", 4) || !strncmp(buf, "quit", 4))
            break;
         else if (!strncmp(buf, "status", 6))
         {
            pthread_mutex_lock(&peer_mutex_);
            for (peer = peer_; peer; peer = peer->next)
               if (peer->state == PEER_ACTIVE)
               {
                  tm = localtime(&peer->otime);
                  strftime(timestr, 32, "%c", tm);
                  sprintf(buf, "[%s]\n fd = %d\n addr = %s\n dir = \"%s\"\n idle = %lds\n bytes_in = %ld\n bytes_out = %ld\n setup_delay = %lds\n opening_time = \"%s\"\n",
                        ipv6tonion(&peer->addr, onionstr), peer->tcpfd,
                        inet_ntop(AF_INET6, &peer->addr, addrstr, INET6_ADDRSTRLEN),
                        peer->dir == PEER_INCOMING ? "in" : "out",
                        time(NULL) - peer->time, peer->in, peer->out, peer->sdelay, timestr);
                  if (write(fd, buf, strlen(buf)) != strlen(buf))
                     log_msg(L_ERROR, "couldn't write %d bytes to control socket %d", strlen(buf), fd);
               }
            pthread_mutex_unlock(&peer_mutex_);
         }
         else if (!strncmp(buf, "close ", 6))
         {
            cfd = atoi(&buf[6]);
            pthread_mutex_lock(&peer_mutex_);
            for (peer = peer_; peer; peer = peer->next)
               if (peer->tcpfd == cfd)
               {
                  log_msg(L_NOTICE, "close request for %d", cfd);
                  close(cfd);
                  delete_peer(peer);
                  break;
               }
            pthread_mutex_unlock(&peer_mutex_);
         }
         else if (!strncmp(buf, "threads", 7))
         {
            pthread_mutex_lock(&thread_mutex_);
            for (th = octh_; th; th = th->next)
            {
               sprintf(buf, "%2d: %s\n", th->id, th->name);
               if (write(fd, buf, strlen(buf)) != strlen(buf))
                  log_msg(L_ERROR, "couldn't write %d bytes to control socket %d", strlen(buf), fd);
            }
            pthread_mutex_unlock(&thread_mutex_);
         }
         else if (!strncmp(buf, "terminate", 9))
         {
            log_msg(L_NOTICE, "terminate request from control port");
            //FIXME: fds should be closed properly
            exit(0);
         }
         else
         {
            strcpy(buf, "unknown command\n");
            if (write(fd, buf, strlen(buf)) != strlen(buf))
               log_msg(L_ERROR, "couldn't write %d bytes to control socket %d", strlen(buf), fd);
         }
      }
      log_msg(L_NOTICE, "closing session %d", fd);
      close(fd);
   }

   return NULL;
}

