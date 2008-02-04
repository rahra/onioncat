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
#include <errno.h>
#include <sys/select.h>

#include "ocat.h"


// TUN file descriptor
extern int tunfd_;
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


void init_peers(void)
{
   memset(peer_, 0, sizeof(OnionPeer_t) * MAXPEERS);
}


OnionPeer_t *search_peer(const struct in6_addr *addr)
{
   int i;

//   pthread_mutex_lock(&peer_mutex_);
   for (i = 0; i < MAXPEERS; i++)
      if (!memcmp(addr, &peer_[i].addr, sizeof(struct in6_addr)))
         break;
         //return &peer_[i];
//   pthread_mutex_unlock(&peer_mutex_);

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


/*
void *socks_reader(OnionPeer_t *peer)
{
   int len;
   char buf[FRAME_SIZE];

   log_msg(L_NOTICE, "socks_reader: __called__");
   while (peer->time)
   {
      if ((len = read(peer->tcpfd, buf, FRAME_SIZE)) > 0)
      {
         peer->time = time(NULL);
         write(peer->tunfd, buf, len);
      }

      if (len < FRAME_SIZE)
      {
         log_msg(L_DEBUG, "socks_reader: short read, closing.");
         close(peer->tcpfd);
         delete_peer(peer);
      }
   }
   log_msg(L_NOTICE, "socks_reader: terminating");
   return NULL;
}
*/


/*
OnionPeer_t *establish_peer(int fd, const struct in6_addr *addr)
{
   char onion[32];
   char soarg[128];
   OnionPeer_t *peer;
   pthread_t thread;

   log_msg(L_DEBUG, "establish_peer: __called__");

   ipv6tonion(addr, onion);
   strcat(onion, ".onion");

   peer = get_empty_peer();
   memcpy(&peer->addr, addr, 16);
   peer->tunfd = fd;
   if ((peer->tcpfd = socks_connect(onion)) < 0)
   {
      log_msg(L_ERROR, "establish_peer: socks_connect() failed");
      delete_peer(peer);
      return NULL;
   }
   log_msg(L_DEBUG, "establish_peer: socks_connect() successful");
   

   peer->time = time(NULL);
   if (pthread_create(&thread, NULL, (void*)(socks_reader), peer))
   {
      log_msg(L_ERROR, "establish_peer: pthread_create() failed");
      close(peer->tcpfd);
      delete_peer(peer);
      return NULL;
   }

   log_msg(L_NOTICE, "establish_peer: peer successfully established");

   return peer;
}
*/


/*
void update_peer_time(const OnionPeer_t *peer)
{
   pthread_mutex_lock(&peer_mutex_);
   peer->time = time(NULL);
   pthread_mutex_unlock(&peer_mutex_);
}
*/


const OnionPeer_t *forward_packet(const struct in6_addr *addr, const char *buf, int buflen)
{
   OnionPeer_t *peer;

   log_msg(L_DEBUG, "forwarding packet");
   pthread_mutex_lock(&peer_mutex_);
   if ((peer = search_peer(addr)))
   {
      write(peer->tcpfd, buf, buflen);
      peer->time = time(NULL);
   }
   pthread_mutex_unlock(&peer_mutex_);

   return peer;
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

   log_msg(L_DEBUG, "queuing packet");
   pthread_mutex_lock(&queue_mutex_);
   queue->next = queue_;
   queue_ = queue;
   pthread_cond_signal(&queue_cond_);
   pthread_mutex_unlock(&queue_mutex_);
}


void *packet_dequeuer(void *p)
{
   PacketQueue_t **queue, *fqueue;
   OnionPeer_t *peer;

   for (;;)
   {
      log_msg(L_NOTICE, "packet dequeuer waiting for packets");
      pthread_mutex_lock(&queue_mutex_);
      if (!queue_)
         pthread_cond_wait(&queue_cond_, &queue_mutex_);

      log_msg(L_DEBUG, "starting dequeuing");
      for (queue = &queue_; *queue; /*queue = &(*queue)->next*/)
      {
         //FIXME: this could be more performant of locking is done outside of for(...)
         pthread_mutex_lock(&peer_mutex_);
         if ((peer = search_peer(&(*queue)->addr)))
         {
            write(peer->tcpfd, (*queue)->data, (*queue)->psize);
            peer->time = time(NULL);
         }
         pthread_mutex_unlock(&peer_mutex_);

         // delete packet from queue if it was sent
         if (peer)
         {
            fqueue = *queue;
            *queue = (*queue)->next;
            free(fqueue);
            log_msg(L_DEBUG, "packet dequeued");
            continue;
         }
         queue = &(*queue)->next;
      }
      pthread_mutex_unlock(&queue_mutex_);
   }
}


void init_packet_dequeuer(void)
{
   pthread_t thread;

   if (pthread_create(&thread, NULL, packet_dequeuer, NULL))
      log_msg(L_FATAL, "could not start socket_receiver thread");
}


void *socket_receiver(void *p)
{
   int i, fd, maxfd, len, state;
   char buf[FRAME_SIZE];
   fd_set rset;
   struct ip6_hdr *ihd;

   log_msg(L_DEBUG, "socket_receiver running");
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

      if (select(maxfd + 1, &rset, NULL, NULL, NULL) == -1)
         log_msg(L_FATAL, "select encountered error: \"%s\"", strerror(errno));

      // thread woke up because of internal pipe read => restart selection
      if (FD_ISSET(lpfd_[0], &rset))
      {
         read(lpfd_[0], buf, FRAME_SIZE);
         continue;
      }

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
            if ((len = read(fd, buf, FRAME_SIZE)) > 0)
               write(tunfd_, buf, len);

            // if len == 0 EOF reached => close session
            if (!len)
            {
               log_msg(L_NOTICE, "fd %d reached EOF, closing.", fd);
               close(fd);
               pthread_mutex_lock(&peer_mutex_);
               delete_peer(&peer_[i]);
               pthread_mutex_unlock(&peer_mutex_);
               continue;
            }
            // this might happen on linux, see SELECT(2)
            else if (len == -1)
            {
               log_msg(L_DEBUG, "spurious wakup of %d: \"%s\"", fd, strerror(errno));
               continue;
            }

            pthread_mutex_lock(&peer_mutex_);
            // update timestamp
            peer_[i].time = time(NULL);
            // set IP address if it has non yet
            if (!memcmp(&peer_[i].addr, &in6addr_any, sizeof(struct in6_addr)))
            {
               memcpy(&peer_[i].addr, &((struct ip6_hdr*) (buf + 4))->ip6_src, sizeof(struct in6_addr));
               log_msg(L_NOTICE, "incoming connection from %s now identified",
                     inet_ntop(AF_INET6, &peer_[i].addr, buf, FRAME_SIZE));
            }
            pthread_mutex_unlock(&peer_mutex_);
         }
      }
   }
}


void init_socket_receiver(void)
{
   pthread_t thread;

   if (pipe(lpfd_) < 0)
      log_msg(L_FATAL, "could not create pipe for socket_receiver: \"%s\"", strerror(errno)), exit(1);

   if (pthread_create(&thread, NULL, socket_receiver, NULL))
      log_msg(L_FATAL, "could not start socket_receiver thread");

/* thread should never terminate
   if (pthread_detach(thread))
      log_msg(L_ERROR, "could not detach socket_receiver thread"); */
}


void set_nonblock(int fd)
{
   long flags;

   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
   {
      log_msg(L_ERROR, "could not get socket flags for %d: \"%s\"", fd, strerror(errno));
      flags = 0;
   }

   if ((fcntl(socket, F_SETFL, flags | O_NONBLOCK)) == -1)
      log_msg(L_ERROR, "could not set O_NONBLOCK for %d: \"%s\"", fd, strerror(errno));
}


void insert_peer(int fd, const struct in6_addr *addr)
{
   OnionPeer_t *peer;

   log_msg(L_DEBUG, "inserting peer %d", fd);

   set_nonblock(fd);

   pthread_mutex_lock(&peer_mutex_);
   peer = get_empty_peer();
   peer->tcpfd = fd;
   peer->state = PEER_ACTIVE;
   peer->time = time(NULL);
   if (addr)
      memcpy(&peer->addr, addr, sizeof(struct in6_addr));
   pthread_mutex_unlock(&peer_mutex_);

   // wake up socket_receiver
   log_msg(L_DEBUG, "waking up socket_receiver");
   write(lpfd_[1], &fd, 1);
}


void *socket_acceptor(void *p)
{
//   struct ReceiverInfo *fwinfo;
   OnionPeer_t *peer;
   int fd;

   log_msg(L_NOTICE, "socket_acceptor running");
   for (;;)
   {
      if ((fd = accept(sockfd_, NULL, NULL)) < 0)
         perror("onion_receiver:accept"), exit(1);

      log_msg(L_NOTICE, "connection accepted on listener");
      insert_peer(fd, NULL);
   }

   return NULL;
}


void init_socket_acceptor(void)
{
   struct sockaddr_in in = {AF_INET, htons(OCAT_PORT), {htonl(INADDR_LOOPBACK)}};
   pthread_t thread;

   if ((sockfd_ = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      log_msg(L_FATAL, "could not create listener socker: \"%s\"", strerror(errno)), exit(1);

   if (bind(sockfd_, (struct sockaddr*) &in, sizeof(struct sockaddr_in)) < 0)
      log_msg(L_FATAL, "could not bind listener: \"%s\"", strerror(errno)), exit(1);

   if (listen(sockfd_, 32) < 0)
      log_msg(L_FATAL, "could not bring listener to listening state: \"%s\"", strerror(errno)), exit(1);

   if (pthread_create(&thread, NULL, socket_acceptor, NULL))
      log_msg(L_FATAL, "could not create socket_acceptor"), exit(1);
}


//int socks_connect(const char *onion)
int socks_connect(const struct in6_addr *addr)
{
   struct sockaddr_in in = {AF_INET, htons(TOR_SOCKS_PORT), {htonl(INADDR_LOOPBACK)}};
   int fd;
   char buf[128], onion[32];
   SocksHdr_t *shdr = (SocksHdr_t*) buf;

   ipv6tonion(addr, onion);
   strcat(onion, ".onion");

   log_msg(L_DEBUG, "socks_connect: __called__");

   if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      return E_SOCKS_SOCK;

   if (connect(fd, (struct sockaddr*) &in, sizeof(in)) < 0)
   {
      log_msg(L_ERROR, "socks_connect: connect() failed");
      close(fd);
      return E_SOCKS_CONN;
   }

   log_msg(L_DEBUG, "socks_connect: connect()");

   shdr->ver = 4;
   shdr->cmd = 1;
   shdr->port = htons(OCAT_PORT);
   shdr->addr.s_addr = 0x01000000;
   strcpy(buf + sizeof(SocksHdr_t), "tor6");
   strcpy(buf + sizeof(SocksHdr_t) + 5, onion);

   write(fd, shdr, sizeof(SocksHdr_t) + strlen(onion) + 6);
   log_msg(L_DEBUG, "socks_connect: connect request sent");

   if (read(fd, shdr, sizeof(SocksHdr_t)) < sizeof(SocksHdr_t))
   {
      log_msg(L_ERROR, "socks_connect: short read, closing.");
      close(fd);
      return E_SOCKS_REQ;
   }
   log_msg(L_DEBUG, "socks_connect: socks response received");

   if (shdr->ver || (shdr->cmd != 90))
   {
      log_msg(L_ERROR, "socks_connect: request failed");
      close(fd);
      return E_SOCKS_RQFAIL;
   }
   log_msg(L_NOTICE, "SOCKS connection to %s successfully opened on fd %d", onion, fd);

   insert_peer(fd, addr);

   return fd;
}


void *socks_connector(void *p)
{
   OnionPeer_t *peer;
   struct in6_addr addr;
   int len;

   log_msg(L_NOTICE, "socks_connector running");

   for (;;)
   {
      log_msg(L_DEBUG, "reading from connector pipe %d", cpfd_[0]);
      if ((len = read(cpfd_[0], &addr, sizeof(addr))) == -1)
         log_msg(L_FATAL, "error reading from connector pipe %d: %s", cpfd_[0], strerror(errno)), exit(1);
      if (len < sizeof(addr))
      {
         log_msg(L_ERROR, "short read on connector pipe %d: %d bytes", cpfd_[0], len);
         continue;
      }

      pthread_mutex_lock(&peer_mutex_);
      peer = search_peer(&addr);
      pthread_mutex_unlock(&peer_mutex_);

      if (peer)
      {
         log_msg(L_NOTICE, "peer already exists, ignoring");
         continue;
      }

      socks_connect(&addr);
   }
}


void init_socks_connector(void)
{
   pthread_t thread;

   if (pipe(cpfd_) < 0)
      log_msg(L_FATAL, "could not create pipe for socks_connector: \"%s\"", strerror(errno)), exit(1);

   if (pthread_create(&thread, NULL, socks_connector, NULL))
      log_msg(L_FATAL, "could not start socks_connector thread");
}


void push_socks_connector(const struct in6_addr *addr)
{
   log_msg(L_DEBUG, "writing to socks connector pipe %d", cpfd_[1]);
   write(cpfd_[1], addr, sizeof(*addr));
}

