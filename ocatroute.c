#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>

#include "ocat.h"


static OnionPeer_t peer_[MAXPEERS];


void init_peers(void)
{
   memset(peer_, 0, sizeof(OnionPeer_t) * MAXPEERS);
}

OnionPeer_t *search_peer(const struct in6_addr *addr)
{
   int i;

   for (i = 0; i < MAXPEERS; i++)
      if (!memcmp(addr, &peer_[i].addr, 16))
         return &peer_[i];
   return NULL;
}


OnionPeer_t *get_empty_peer(void)
{
   int i;
   struct in6_addr addr;

   memset(&addr, 0, sizeof(addr));
   for (i = 0; i < MAXPEERS; i++)
      if (!memcmp(&addr, &peer_[i].addr, 16))
         return &peer_[i];
   return NULL;
}


void delete_peer(OnionPeer_t *peer)
{
   memset(peer, 0, sizeof(OnionPeer_t));
}


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

   /*
   if (pipe(peer->fd) == -1)
      return NULL;

   switch(fork())
   {
      case -1:
         close(peer->fd[0]);
         close(peer->fd[1]);
         delete_peer(peer);
         return NULL;

      // child
      case 0:
         // connect stdin to pipe
         close(0);
         dup(peer->fd[0]);
         // connect stdout to tun
         close(1);
         dup(fd);
         // close writing end of pipe
         close(peer->fd[1]);

         // generate args and exec socat
         sprintf(soarg, "SOCKS4A:127.0.0.1:%s:%d,socksport=9050", onion, OCAT_PORT);
         if (execlp("socat", "socat", "STDIO", soarg, NULL) == -1)
            exit(1);

      // parent
      default:

         // close reading end of pipe 
         close(peer->fd[0]);
   }
   */

   return peer;
}


void *onion_forwarder(struct ReceiverInfo *rinfo)
{
   char buf[BUFLEN];
   int rlen;

   rlen = receive_packet(rinfo->listenfd, buf);

   return NULL;
}


void *onion_receiver(struct ReceiverInfo *rinfo)
{
   struct ReceiverInfo *fwinfo;
   int fd;


   for (;;)
   {
      if ((fd = accept(rinfo->listenfd, NULL, NULL)) < 0)
         perror("onion_receiver:accept"), exit(1);


      if (!(fwinfo = malloc(sizeof(struct ReceiverInfo))))
         perror("onion_receiver:malloc"), exit(1);

      fwinfo->tunfd = rinfo->tunfd;
      fwinfo->listenfd = fd;

      if (pthread_create(&fwinfo->thread, NULL, (void*)(onion_forwarder), fwinfo))
         fprintf(stderr, "pthread_create\n"), exit(1);
   }

   return NULL;
}


void onion_listen(int fd)
{
   struct sockaddr_in in = {AF_INET, htons(OCAT_PORT), {0x0100007f}};
   struct ReceiverInfo *rinfo;

   if (!(rinfo = malloc(sizeof(struct ReceiverInfo))))
         perror("onion_listen:malloc"), exit(1);

   if ((rinfo->listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
      perror("onion_listen:socket"), exit(1);

   if (bind(rinfo->listenfd, (struct sockaddr*) &in, sizeof(struct sockaddr_in)) < 0)
      perror("onion_listen:bind"), exit(1);

   if (listen(rinfo->listenfd, 32) < 0)
      perror("onion_listen:listen"), exit(1);

   if (pthread_create(&rinfo->thread, NULL, (void*)(onion_receiver), rinfo))
      fprintf(stderr, "pthread_create\n"), exit(1);

}


