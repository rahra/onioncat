/*! ocatroute.c
 *  Contains functions for managing both kind of TCP peers.
 *  Those are active SOCKS4A and passive TCP-LISTEN.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
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
static OcatPeer_t peer_[MAXPEERS];
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


void init_peers(void)
{
   memset(peer_, 0, sizeof(OcatPeer_t) * MAXPEERS);
}


OcatPeer_t *search_peer(const struct in6_addr *addr)
{
   int i;

   for (i = 0; i < MAXPEERS; i++)
      if (!memcmp(addr, &peer_[i].addr, sizeof(struct in6_addr)))
         break;
         //return &peer_[i];

   if (i >= MAXPEERS)
      return NULL;

   return &peer_[i];
}


OcatPeer_t *get_empty_peer(void)
{
   int i;

   for (i = 0; i < MAXPEERS; i++)
      if (!peer_[i].state)
         return &peer_[i];

   return NULL;
}


void delete_peer(OcatPeer_t *peer)
{
   memset(peer, 0, sizeof(OcatPeer_t));
}


void rewrite_framehdr(char *buf, int len)
{
   uint32_t *fhd = (uint32_t*) buf;
   struct ip6_hdr *ihd;
   int ofs;

   if (*fhd == fhd_key_)
   {
      log_msg(L_DEBUG, "[rewrite_framehdr] frame header already of correct type");
      return;
   }

   while(len > 4)
   {
      if (*fhd != htonl(0x1c) && *fhd != htonl(0x86dd))
      {
         log_msg(L_DEBUG, "[rewrite_framehdr] frame seems to be fragment");
         return;
      }
      // replace header type
      log_msg(L_DEBUG, "[rewrite_framehdr] rewriting");
      *fhd = fhd_key_;
      // finding next header
      if (len < 4 + sizeof(struct ip6_hdr))
      {
         log_msg(L_DEBUG, "[rewrite_framehdr] short frag");
         return;
      }
      ihd = (struct ip6_hdr*) (fhd + 1);
      ofs = 4 + sizeof(struct ip6_hdr) + ihd->ip6_plen;
      len -= ofs;
      fhd = (uint32_t*) (buf + ofs);
   }
}


/*const*/ OcatPeer_t *forward_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   OcatPeer_t *peer;

   pthread_mutex_lock(&peer_mutex_);
   if ((peer = search_peer(addr)))
   {
      log_msg(L_DEBUG, "[forwarding_packet]");
      if (write(peer->tcpfd, buf, buflen) != buflen)
         log_msg(L_ERROR, "could not write %d bytes to peer %d", buflen, peer->tcpfd);
      peer->time = time(NULL);
      peer->out += buflen;
   }
   pthread_mutex_unlock(&peer_mutex_);

   return peer;
}


void queue_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   PacketQueue_t *queue;

   log_msg(L_DEBUG, "[queue_packet] copying packet to heap for queue");
   if (!(queue = malloc(sizeof(PacketQueue_t) + buflen)))
   {
      log_msg(L_ERROR, "[queue_packet] %s for packet to queue", strerror(errno));
      return;
   }

   memcpy(&queue->addr, addr, sizeof(struct in6_addr));
   queue->psize = buflen;
   queue->data = ((char*)queue) + sizeof(PacketQueue_t);
   memcpy(queue->data, buf, buflen);
   queue->time = time(NULL);

   log_msg(L_DEBUG, "[queue_packet] queuing packet");
   pthread_mutex_lock(&queue_mutex_);
   queue->next = queue_;
   queue_ = queue;
   log_msg(L_DEBUG, "[queue_packet] waking up dequeuer");
   pthread_cond_signal(&queue_cond_);
   pthread_mutex_unlock(&queue_mutex_);
}


void *packet_dequeuer(void *p)
{
   PacketQueue_t **queue, *fqueue;
   OcatPeer_t *peer;
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
         log_msg(L_DEBUG, "[packet_dequeuer] timed conditional wait...");
         rc = pthread_cond_timedwait(&queue_cond_, &queue_mutex_, &ts);
      }
      else
      {
         log_msg(L_DEBUG, "[packet_dequeuer] conditional wait...");
         rc = pthread_cond_wait(&queue_cond_, &queue_mutex_);
      }

      if (rc)
         log_msg(L_FATAL, "[packet_dequeuer] woke up: \"%s\"", strerror(rc));

      log_msg(L_DEBUG, "[packet_dequeuer] starting dequeuing");
      for (queue = &queue_; *queue; /*queue = &(*queue)->next*/)
      {
         peer = forward_packet(&(*queue)->addr, (*queue)->data, (*queue)->psize);

         // delete packet from queue if it was sent or is too old
         delay = time(NULL) - (*queue)->time;
         if (peer || (delay > MAX_QUEUE_DELAY))
         {
            fqueue = *queue;
            *queue = (*queue)->next;
            free(fqueue);
            log_msg(L_DEBUG, "[packet_dequeuer] packet dequeued, delay = %d", delay);
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

   hex_code_header((char*) ihd, len > IP6HLEN ? IP6HLEN : len, hexbuf);
   log_msg(L_DEBUG, "[validate_frame] header \"%s\"", hexbuf);

   if (!has_tor_prefix(&ihd->ip6_dst))
   {
      log_msg(L_ERROR, "[validate_frame] destination %s unreachable", inet_ntop(AF_INET6, &ihd->ip6_dst, buf, INET6_ADDRSTRLEN));
      return 0;
   }
   if (!has_tor_prefix(&ihd->ip6_src))
   {
      log_msg(L_ERROR, "[validate_frame] source address invalid. Remote ocat could not reply");
      return 0;
   }
#ifdef TEST_TUN_HDR
   if (is_testping(&ihd->ip6_dst))
   {
      log_msg(L_DEBUG, "[validate_frame] test ping detected");
      return 0;
   }
#endif
   return ntohs(ihd->ip6_plen);
}


void cleanup_socket(int fd, OcatPeer_t *peer)
{
   log_msg(L_NOTICE, "[cleanup_socket] fd %d reached EOF, closing.", fd);
   close(fd);
   pthread_mutex_lock(&peer_mutex_);
   delete_peer(peer);
   pthread_mutex_unlock(&peer_mutex_);
}


void *socket_receiver(void *p)
{
   int i, fd, maxfd, len, state, plen;
   char buf[FRAME_SIZE];
   char addr[INET6_ADDRSTRLEN];
   fd_set rset;
   struct ip6_hdr *ihd;
   ihd = (struct ip6_hdr*) &buf[4];

   if (pipe(lpfd_) < 0)
      log_msg(L_FATAL, "[init_socket_receiver] could not create pipe for socket_receiver: \"%s\"", strerror(errno)), exit(1);

   for (;;)
   {
      FD_ZERO(&rset);
      FD_SET(lpfd_[0], &rset);
      maxfd = lpfd_[0];

      // create set for all available peers to read
      pthread_mutex_lock(&peer_mutex_);
      for (i = 0; i < MAXPEERS; i++)
      {
         // only select active peers
         if (peer_[i].state != PEER_ACTIVE)
            continue;
         if ((fd = peer_[i].tcpfd) >= FD_SETSIZE)
            log_msg(L_FATAL, "%d >= FD_SETIZE(%d)", fd, FD_SETSIZE), exit(1);
         FD_SET(fd, &rset);
         if (fd > maxfd)
            maxfd = fd;
      }
      pthread_mutex_unlock(&peer_mutex_);

      log_msg(L_DEBUG, "[socket_receiver] is selecting...");
      if (select(maxfd + 1, &rset, NULL, NULL, NULL) == -1)
      {
         log_msg(L_FATAL, "[socket_receiver] select encountered error: \"%s\", restarting", strerror(errno));
         continue;
      }

      // thread woke up because of internal pipe read => restart selection
      if (FD_ISSET(lpfd_[0], &rset))
      {
         read(lpfd_[0], buf, FRAME_SIZE);
         continue;
      }

      //FIXME: should only run until num select returned
      for (i = 0; i < MAXPEERS; i++)
      {
         pthread_mutex_lock(&peer_mutex_);
         state = peer_[i].state;
         fd = peer_[i].tcpfd;
         pthread_mutex_unlock(&peer_mutex_);

         if (state != PEER_ACTIVE)
            continue;

         if (FD_ISSET(fd, &rset))
         {
            log_msg(L_DEBUG, "[socket_receiver] reading from %d", fd);

            // *** unframed receiver
            // write reordered after IP validation
            // this might happen on linux, see SELECT(2)
            if ((len = read(fd, buf, FRAME_SIZE)) == -1)
            {
               log_msg(L_DEBUG, "[socket_receiver] spurious wakup of %d: \"%s\"", fd, strerror(errno));
               continue;
            }
            // if len == 0 EOF reached => close session
            if (!len)
            {
               log_msg(L_NOTICE, "[socket_receiver] fd %d reached EOF, closing.", fd);
               close(fd);
               pthread_mutex_lock(&peer_mutex_);
               delete_peer(&peer_[i]);
               pthread_mutex_unlock(&peer_mutex_);
               continue;
            }
            // check frame
            plen = validate_frame(ihd, len);
            if (vrec_ && !plen)
            {
               log_msg(L_ERROR, "[socket_receiver] dropping frame");
               continue;
            }

            pthread_mutex_lock(&peer_mutex_);
            // update timestamp
            peer_[i].time = time(NULL);
            peer_[i].in += len;
            // set IP address if it is not set yet and frame is valid
            if (plen && !memcmp(&peer_[i].addr, &in6addr_any, sizeof(struct in6_addr)))
            {
               memcpy(&peer_[i].addr, &ihd->ip6_src, sizeof(struct in6_addr));
               log_msg(L_NOTICE, "[socket_receiver] incoming connection on %d from %s is now identified", fd,
                     inet_ntop(AF_INET6, &peer_[i].addr, addr, INET6_ADDRSTRLEN));
            }
            pthread_mutex_unlock(&peer_mutex_);
            
            log_msg(L_DEBUG, "[socket_receiver] trying fhdr rewriting");
            rewrite_framehdr(buf, len);
            log_msg(L_DEBUG, "[socket_receiver] writing to tun %d framesize %d", tunfd_[1], len);
            if (write(tunfd_[1], buf, len) != len)
               log_msg(L_ERROR, "could not write %d bytes to tunnel %d", len, tunfd_[1]);
         }
      }
   }
}


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
      log_msg(L_ERROR, "[set_nonblock] could not set O_NONBLOCK for %d: \"%s\"", fd, strerror(errno));
}


OcatPeer_t *insert_peer(int fd, const struct in6_addr *addr)
{
   OcatPeer_t *peer;

   log_msg(L_DEBUG, "[inserting_peer] %d", fd);

   set_nonblock(fd);

   pthread_mutex_lock(&peer_mutex_);
   peer = get_empty_peer();
   peer->tcpfd = fd;
   peer->state = PEER_ACTIVE;
   peer->otime = peer->time = time(NULL);
   if (addr)
   {
      memcpy(&peer->addr, addr, sizeof(struct in6_addr));
      peer->dir = PEER_OUTGOING;
   }
   else
      peer->dir = PEER_INCOMING;
   pthread_mutex_unlock(&peer_mutex_);

   // wake up socket_receiver
   log_msg(L_DEBUG, "[inser_peer] waking up socket_receiver");
   if (write(lpfd_[1], &fd, 1) != 1)
      log_msg(L_FATAL, "couldn't write to socket_receiver pipe: \"%s\"", strerror(errno));

   return peer;
}


void *socket_acceptor(void *p)
{
   int fd;
   struct sockaddr_in in;

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(ocat_listen_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef linux
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
      insert_peer(fd, NULL);
   }

   return NULL;
}


int socks_connect(const struct in6_addr *addr)
{
   struct sockaddr_in in /* = {AF_INET, htons(tor_socks_port_), {htonl(INADDR_LOOPBACK)}}*/;
   int fd, t;
   char buf[FRAME_SIZE], onion[ONION_NAME_SIZE];
   SocksHdr_t *shdr = (SocksHdr_t*) buf;
   OcatPeer_t *ohd;

   log_msg(L_DEBUG, "[socks_connect] called");

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(tor_socks_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef __linux__
   in.sin_len = sizeof(in);
#endif

   ipv6tonion(addr, onion);
   strcat(onion, ".onion");

   log_msg(L_NOTICE, "[socks_connect] trying to connecto to \"%s\" [%s]", onion, inet_ntop(AF_INET6, addr, buf, FRAME_SIZE));

   if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      return E_SOCKS_SOCK;

   t = time(NULL);
   if (connect(fd, (struct sockaddr*) &in, sizeof(in)) < 0)
   {
      log_msg(L_ERROR, "[socks_connect] connect() failed");
      close(fd);
      return E_SOCKS_CONN;
   }
   t = time(NULL) - t;

   log_msg(L_DEBUG, "[socks_connect] connect()");

   shdr->ver = 4;
   shdr->cmd = 1;
   shdr->port = htons(ocat_dest_port_);
   shdr->addr.s_addr = 0x01000000;
   strcpy(buf + sizeof(SocksHdr_t), "tor6");
   strcpy(buf + sizeof(SocksHdr_t) + 5, onion);

   if (write(fd, shdr, sizeof(SocksHdr_t) + strlen(onion) + 6) != sizeof(SocksHdr_t) + strlen(onion) + 6)
      log_msg(L_ERROR, "couldn't write %d bytes to SOCKS connection %d", sizeof(SocksHdr_t) + strlen(onion) + 6, fd);
   log_msg(L_DEBUG, "[socks_connect] connect request sent");

   if (read(fd, shdr, sizeof(SocksHdr_t)) < sizeof(SocksHdr_t))
   {
      log_msg(L_ERROR, "[socks_connect] short read, closing.");
      close(fd);
      return E_SOCKS_REQ;
   }
   log_msg(L_DEBUG, "[socks_connect] socks response received");

   if (shdr->ver || (shdr->cmd != 90))
   {
      log_msg(L_ERROR, "[socks_connect] request failed, reason = %d", shdr->cmd);
      close(fd);
      return E_SOCKS_RQFAIL;
   }
   log_msg(L_NOTICE, "[socks_connect] connection to %s successfully opened on fd %d", onion, fd);

   ohd = insert_peer(fd, addr);
   pthread_mutex_lock(&peer_mutex_);
   ohd->sdelay = t;
   pthread_mutex_unlock(&peer_mutex_);

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

      log_msg(L_DEBUG, "[packet_forwarder] received on tunfd %d, framesize %d", tunfd_[0], rlen);

      if (!validate_frame(ihd, rlen - 4))
      {
         log_msg(L_ERROR, "[packet_forwarder] dropping frame");
         continue;
      }

      // now forward either directly or to the queue
      if (!forward_packet(&ihd->ip6_dst, buf, rlen))
      {
         log_msg(L_NOTICE, "[packet_forwarder] establishing new socks peer");
         socks_queue(&ihd->ip6_dst);
         log_msg(L_DEBUG, "[packet_forwarder] queuing packet");
         queue_packet(&ihd->ip6_dst, buf, rlen);
      }
   }
}


void *socket_cleaner(void *p)
{
   int i;

   for (;;)
   {
      sleep(CLEANER_WAKEUP);
      log_msg(L_DEBUG, "wakeup");
      pthread_mutex_lock(&peer_mutex_);
      for (i = 0; i < MAXPEERS; i++)
      {
         if (peer_[i].state && peer_[i].time + MAX_IDLE_TIME < time(NULL))
         {
            log_msg(L_NOTICE, "peer %d timed out, closing.", peer_[i].tcpfd);
            close(peer_[i].tcpfd);
            delete_peer(&peer_[i]);
         }
      }
      pthread_mutex_unlock(&peer_mutex_);
   }
}


void *ocat_controller(void *p)
{
   int fd, sfd;
   struct sockaddr_in in;
   char buf[FRAME_SIZE], addrstr[INET6_ADDRSTRLEN], onionstr[ONION_NAME_SIZE], timestr[32];
   int rlen, i, cfd;
   struct tm *tm;
   OcatThread_t *th;

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(OCAT_CTRL_PORT);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef linux
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
            for (i = 0; i < MAXPEERS; i++)
               if (peer_[i].state == PEER_ACTIVE)
               {
                  tm = localtime(&peer_[i].otime);
                  strftime(timestr, 32, "%c", tm);
                  sprintf(buf, "[%s]\n fd = %d\n addr = %s\n dir = \"%s\"\n idle = %lds\n bytes_in = %ld\n bytes_out = %ld\n setup_delay = %lds\n opening_time = \"%s\"\n",
                        ipv6tonion(&peer_[i].addr, onionstr), peer_[i].tcpfd,
                        inet_ntop(AF_INET6, &peer_[i].addr, addrstr, INET6_ADDRSTRLEN),
                        peer_[i].dir == PEER_INCOMING ? "in" : "out",
                        time(NULL) - peer_[i].time, peer_[i].in, peer_[i].out, peer_[i].sdelay, timestr);
                  if (write(fd, buf, strlen(buf)) != strlen(buf))
                     log_msg(L_ERROR, "couldn't write %d bytes to control socket %d", strlen(buf), fd);
               }
            pthread_mutex_unlock(&peer_mutex_);
         }
         else if (!strncmp(buf, "close ", 6))
         {
            cfd = atoi(&buf[6]);
            pthread_mutex_lock(&peer_mutex_);
            for (i = 0; i < MAXPEERS; i++)
               if (peer_[i].tcpfd == cfd)
               {
                  log_msg(L_NOTICE, "close request for %d", cfd);
                  close(cfd);
                  delete_peer(&peer_[i]);
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

