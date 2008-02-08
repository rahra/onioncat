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
// file descriptors of socks_connector pipe
// used for internal communication
static int cpfd_[2];
// array of active peers
static OnionPeer_t peer_[MAXPEERS];
// mutex for locking array of peers
pthread_mutex_t peer_mutex_ = PTHREAD_MUTEX_INITIALIZER;
// packet queue pointer
static PacketQueue_t *queue_ = NULL;
// mutex and condition variable for packet queue
static pthread_mutex_t queue_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond_ = PTHREAD_COND_INITIALIZER;

// frame header of local OS in network byte order
uint32_t fhd_key_ = 0;

uint16_t tor_socks_port_ = TOR_SOCKS_PORT;
uint16_t ocat_listen_port_ = OCAT_LISTEN_PORT;
uint16_t ocat_dest_port_ = OCAT_DEST_PORT;

int vrec_ = 0;


void init_peers(void)
{
   memset(peer_, 0, sizeof(OnionPeer_t) * MAXPEERS);
}


OnionPeer_t *search_peer(const struct in6_addr *addr)
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


OnionPeer_t *get_empty_peer(void)
{
   int i;

   for (i = 0; i < MAXPEERS; i++)
      if (!peer_[i].state)
         return &peer_[i];

   return NULL;
}


void delete_peer(OnionPeer_t *peer)
{
   memset(peer, 0, sizeof(OnionPeer_t));
}


void mk_ocat_frame(const struct in6_addr *addr, const struct ip6_hdr *ihd, OcatHdr_t *ohd)
{
   memcpy(ohd, ihd, sizeof(struct ip6_hdrctl));
   memcpy(ohd->oh_srcid, (char*)addr + 6, 10);
   memcpy(ohd + 1, ihd + 1, ihd->ip6_plen);
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


/*const*/ OnionPeer_t *forward_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   OnionPeer_t *peer;

   pthread_mutex_lock(&peer_mutex_);
   if ((peer = search_peer(addr)))
   {
      log_msg(L_DEBUG, "[forwarding_packet]");
      write(peer->tcpfd, buf, buflen);
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
   OnionPeer_t *peer;
   struct timespec ts;
   int rc, timed = 0;
   time_t delay;

   (void) init_ocat_thread(p);

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
         //FIXME: this could be more performant of locking is done outside of for(...)
#if 0
         pthread_mutex_lock(&peer_mutex_);
         if ((peer = search_peer(&(*queue)->addr)))
         {
            write(peer->tcpfd, (*queue)->data, (*queue)->psize);
            peer->time = time(NULL);
         }
         pthread_mutex_unlock(&peer_mutex_);
#else 
         peer = forward_packet(&(*queue)->addr, (*queue)->data, (*queue)->psize);
#endif

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


/*
void init_packet_dequeuer(void)
{
   pthread_t thread;
   int rc;

   if ((rc = pthread_create(&thread, NULL, packet_dequeuer, NULL)))
      log_msg(L_FATAL, "[init_packet_dequeuer] could not start socket_receiver thread: \"%s\"", strerror(rc));
}
*/


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
   //struct ip6_hdr *ihd = (struct ip6_hdr*) (frame + 4);
   char hexbuf[IP6HLEN * 3 + 1];

   hex_code_header((char*) ihd, len > IP6HLEN ? IP6HLEN : len, hexbuf);
   log_msg(L_DEBUG, "[validate_frame] header \"%s\"", hexbuf);

   /*
   if (len < IP6HLEN + 4)
   {
      log_msg(L_ERROR, "[validate_frame] frame too short: %d bytes", len);
      return 0;
   }
   if (*((uint16_t*) &frame[2]) != htons(0x86dd))
   {
      log_msg(L_ERROR, "[validate_frame] ethertype is not IPv6");
      return 0;
   }
   */
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
   if (is_testping(&ihd->ip6_dst))
   {
      log_msg(L_DEBUG, "[validate_frame] test ping detected");
      return 0;
   }
   return ntohs(ihd->ip6_plen);
}


void cleanup_socket(int fd, OnionPeer_t *peer)
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

   (void) init_ocat_thread(p);

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
            write(tunfd_[1], buf, len);
         }
      }
   }
}


/*
void init_socket_receiver(void)
{
   pthread_t thread;
   int rc;

   if (pipe(lpfd_) < 0)
      log_msg(L_FATAL, "[init_socket_receiver] could not create pipe for socket_receiver: \"%s\"", strerror(errno)), exit(1);

   if ((rc = pthread_create(&thread, NULL, socket_receiver, NULL)))
      log_msg(L_FATAL, "[init_socket_receiver] could not start socket_receiver thread: \"%s\"", strerror(rc));
}
*/


void set_nonblock(int fd)
{
   long flags;

   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
   {
      log_msg(L_ERROR, "[set_nonblock] could not get socket flags for %d: \"%s\"", fd, strerror(errno));
      flags = 0;
   }

   log_msg(L_DEBUG, "[set_nonblock] O_NONBLOCK currently is %x", flags & O_NONBLOCK);

   if ((fcntl(socket, F_SETFL, flags | O_NONBLOCK)) == -1)
      log_msg(L_ERROR, "[set_nonblock] could not set O_NONBLOCK for %d: \"%s\"", fd, strerror(errno));
}


void insert_peer(int fd, const struct in6_addr *addr)
{
   OnionPeer_t *peer;

   log_msg(L_DEBUG, "[inserting_peer] %d", fd);

   set_nonblock(fd);

   pthread_mutex_lock(&peer_mutex_);
   peer = get_empty_peer();
   peer->tcpfd = fd;
   peer->state = PEER_ACTIVE;
   peer->time = time(NULL);
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
   write(lpfd_[1], &fd, 1);
}


void *socket_acceptor(void *p)
{
   int fd;
   struct sockaddr_in in;

   (void) init_ocat_thread(p);

   log_msg(L_NOTICE, "[socket_acceptor] running");

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(ocat_listen_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef linux
   in.sin_len = sizeof(in);
#endif

   if ((sockfd_ = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      log_msg(L_FATAL, "[init_socket_acceptor] could not create listener socker: \"%s\"", strerror(errno)), exit(1);

   if (bind(sockfd_, (struct sockaddr*) &in, sizeof(struct sockaddr_in)) < 0)
      log_msg(L_FATAL, "[init_socket_acceptor] could not bind listener: \"%s\"", strerror(errno)), exit(1);

   if (listen(sockfd_, 32) < 0)
      log_msg(L_FATAL, "[init_socket_acceptor] could not bring listener to listening state: \"%s\"", strerror(errno)), exit(1);
   
   log_msg(L_NOTICE, "[init_socket_acceptor] created local listener on port %d", ocat_listen_port_);

   for (;;)
   {
      log_msg(L_DEBUG, "[socket acceptor] is accepting further connections");
      if ((fd = accept(sockfd_, NULL, NULL)) < 0)
         perror("onion_receiver:accept"), exit(1);

      log_msg(L_NOTICE, "[socket acceptor] connection accepted on listener");
      insert_peer(fd, NULL);
   }

   return NULL;
}


/*
void init_socket_acceptor(void)
{
   struct sockaddr_in in;
   pthread_t thread;
   int rc;

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(ocat_listen_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef linux
   in.sin_len = sizeof(in);
#endif

   if ((sockfd_ = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      log_msg(L_FATAL, "[init_socket_acceptor] could not create listener socker: \"%s\"", strerror(errno)), exit(1);

   if (bind(sockfd_, (struct sockaddr*) &in, sizeof(struct sockaddr_in)) < 0)
      log_msg(L_FATAL, "[init_socket_acceptor] could not bind listener: \"%s\"", strerror(errno)), exit(1);

   if (listen(sockfd_, 32) < 0)
      log_msg(L_FATAL, "[init_socket_acceptor] could not bring listener to listening state: \"%s\"", strerror(errno)), exit(1);
   
   log_msg(L_NOTICE, "[init_socket_acceptor] created local listener on port %d", ocat_listen_port_);

   if ((rc = pthread_create(&thread, NULL, socket_acceptor, NULL)))
      log_msg(L_FATAL, "[init_socket_acceptor] could not create socket_acceptor: \"%s\"", strerror(rc)), exit(1);
}
*/


//int socks_connect(const char *onion)
int socks_connect(const struct in6_addr *addr)
{
   struct sockaddr_in in /* = {AF_INET, htons(tor_socks_port_), {htonl(INADDR_LOOPBACK)}}*/;
   int fd;
   char buf[FRAME_SIZE], onion[ONION_NAME_SIZE];
   SocksHdr_t *shdr = (SocksHdr_t*) buf;

   log_msg(L_DEBUG, "[socks_connect] called");

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(tor_socks_port_);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef linux
   in.sin_len = sizeof(in);
#endif

   ipv6tonion(addr, onion);
   strcat(onion, ".onion");

   log_msg(L_NOTICE, "[socks_connect] trying to connecto to \"%s\" [%s]", onion, inet_ntop(AF_INET6, addr, buf, FRAME_SIZE));

   if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      return E_SOCKS_SOCK;

   if (connect(fd, (struct sockaddr*) &in, sizeof(in)) < 0)
   {
      log_msg(L_ERROR, "[socks_connect] connect() failed");
      close(fd);
      return E_SOCKS_CONN;
   }

   log_msg(L_DEBUG, "[socks_connect] connect()");

   shdr->ver = 4;
   shdr->cmd = 1;
   shdr->port = htons(ocat_dest_port_);
   shdr->addr.s_addr = 0x01000000;
   strcpy(buf + sizeof(SocksHdr_t), "tor6");
   strcpy(buf + sizeof(SocksHdr_t) + 5, onion);

   write(fd, shdr, sizeof(SocksHdr_t) + strlen(onion) + 6);
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

   insert_peer(fd, addr);

   return fd;
}


void *socks_connector(void *p)
{
   OnionPeer_t *peer;
   struct in6_addr addr;
   int len;

   (void) init_ocat_thread(p);

   if (pipe(cpfd_) < 0)
      log_msg(L_FATAL, "[init_socks_connector] could not create pipe for socks_connector: \"%s\"", strerror(errno)), exit(1);

   log_msg(L_NOTICE, "[socks_connector] running");

   for (;;)
   {
      log_msg(L_DEBUG, "[socks_connector] reading from connector pipe %d", cpfd_[0]);
      if ((len = read(cpfd_[0], &addr, sizeof(addr))) == -1)
         log_msg(L_FATAL, "[socks_connector] error reading from connector pipe %d: %s", cpfd_[0], strerror(errno)), exit(1);
      if (len != sizeof(addr))
      {
         log_msg(L_ERROR, "[socks_connector] illegal read on connector pipe %d: %d bytes", cpfd_[0], len);
         continue;
      }

      pthread_mutex_lock(&peer_mutex_);
      peer = search_peer(&addr);
      pthread_mutex_unlock(&peer_mutex_);

      if (peer)
      {
         log_msg(L_NOTICE, "[socks_connector] peer already exists, ignoring");
         continue;
      }

      socks_connect(&addr);
   }
}

/*
void init_socks_connector(void)
{
   pthread_t thread;
   int rc;

   if (pipe(cpfd_) < 0)
      log_msg(L_FATAL, "[init_socks_connector] could not create pipe for socks_connector: \"%s\"", strerror(errno)), exit(1);

   if ((rc = pthread_create(&thread, NULL, socks_connector, NULL)))
      log_msg(L_FATAL, "[init_socks_connector] could not start socks_connector thread: \"%s\"", strerror(rc));
}
*/


void packet_forwarder(void)
{
   char buf[FRAME_SIZE];
   char addr[INET6_ADDRSTRLEN];
   struct ip6_hdr *ihd;
   int rlen;

   ihd = (struct ip6_hdr*) &buf[4];

   for (;;)
   {
      //rlen = receive_packet(tunfd_, data);
      rlen = read(tunfd_[0], buf, FRAME_SIZE);
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
         //push_socks_connector(&ihd->ip6_dst);
         log_msg(L_DEBUG, "[packet_forwarder] writing %s to socks connector pipe %d", inet_ntop(AF_INET6, &ihd->ip6_dst, addr, INET6_ADDRSTRLEN), cpfd_[1]);
         write(cpfd_[1], &ihd->ip6_dst, sizeof(struct in6_addr));
         log_msg(L_DEBUG, "[packet_forwarder] queuing packet");
         queue_packet(&ihd->ip6_dst, buf, rlen);
      }
   }
}


void *socket_cleaner(void *p)
{
   int i;

   (void) init_ocat_thread(p);

   log_msg(L_NOTICE, "running");
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

/*
void init_socket_cleaner(void)
{
   pthread_t thread;
   int rc;

   if ((rc = pthread_create(&thread, NULL, socket_cleaner, NULL)))
      log_msg(L_FATAL, "[init_socket_cleaner] could not start thread: \"%s\"", strerror(rc));
}
*/


void *ocat_controller(void *p)
{
   int fd;
   struct sockaddr_in in;
   char buf[FRAME_SIZE], addrstr[INET6_ADDRSTRLEN], onionstr[ONION_NAME_SIZE];
   int rlen, i, cfd;

   (void) init_ocat_thread(p);

   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(OCAT_CTRL_PORT);
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef linux
   in.sin_len = sizeof(in);
#endif

   if ((sockfd_ = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      log_msg(L_FATAL, "could not create listener socker: \"%s\"", strerror(errno)), exit(1);

   if (bind(sockfd_, (struct sockaddr*) &in, sizeof(struct sockaddr_in)) < 0)
      log_msg(L_FATAL, "could not bind listener: \"%s\"", strerror(errno)), exit(1);

   if (listen(sockfd_, 5) < 0)
      log_msg(L_FATAL, "could not bring listener to listening state: \"%s\"", strerror(errno)), exit(1);
   
   log_msg(L_NOTICE, "created local listener on port %d", ocat_listen_port_);

   for (;;)
   {
      log_msg(L_DEBUG, "accepting connections");
      if ((fd = accept(sockfd_, NULL, NULL)) < 0)
         log_msg(L_FATAL, "error in acception: \"%s\"", strerror(errno)), exit(1);
      log_msg(L_NOTICE, "connection accepted");

      for (;;)
      {
         /*
         for (i = 0; (rlen = read(fd, &buf[i], 1)) > 0; i++)
            if (buf[i] == '\n')
            {
               buf[i] = '\0';
               break;
            }
            */

         write(fd, "> ", 2);

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
                  sprintf(buf, "[%s]\n fd = %d\n addr = %s\n dir = \"%s\"\n idle = %ld\n bytes_in = %ld\n bytes_out = %ld\n\n",
                        ipv6tonion(&peer_[i].addr, onionstr), peer_[i].tcpfd,
                        inet_ntop(AF_INET6, &peer_[i].addr, addrstr, INET6_ADDRSTRLEN),
                        peer_[i].dir == PEER_INCOMING ? "in" : "out",
                        time(NULL) - peer_[i].time, peer_[i].in, peer_[i].out);
                  write(fd, buf, strlen(buf));
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
         else
         {
            strcpy(buf, "unknown command\n");
            write(fd, buf, strlen(buf));
         }
      }
      log_msg(L_NOTICE, "closing session %d", fd);
      close(fd);
   }

   return NULL;
}

