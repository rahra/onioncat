#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <net/if.h>

#include "ocat.h"

static int debug_level_ = 4;
int tunfd_;

void log_msg(int lf, const char *fmt, ...)
{
   va_list ap;

   if (debug_level_ < lf)
      return;

   switch (lf)
   {
      case L_DEBUG:
         fprintf(stderr, "debug: ");
         break;

      case L_NOTICE:
         fprintf(stderr, "notice: ");
         break;

      case L_ERROR:
         fprintf(stderr, "error: ");
         break;

      case L_FATAL:
         fprintf(stderr, "FATAL: ");
         break;

      default:
         return;
   }

   va_start(ap, fmt);
   vfprintf(stderr, fmt, ap);
   va_end(ap);

   fprintf(stderr, "\n");
}

void print_v6_hd(FILE *out, const struct ip6_hdr *ihd)
{
   char asip[32], adip[32];
   char onion[32];

   inet_ntop(AF_INET6, &ihd->ip6_src, asip, 32);
   inet_ntop(AF_INET6, &ihd->ip6_dst, adip, 32);
   fprintf(out, "playload: %d\nsrcip: %s\ndstip: %s\n", ntohs(ihd->ip6_ctlun.ip6_un1.ip6_un1_plen), asip, adip);
   ipv6tonion(&ihd->ip6_dst, onion);
   fprintf(out, "dst onion: %s\n", onion);
   fprintf(out, "\n");
}


int receive_packet(int fd, char *buf)
{
   int rlen;
   struct ip6_hdr *ihd = (struct ip6_hdr*) (buf + 4);

   if ((rlen = read(fd, buf, IP6HLEN + 4)) == -1)
      perror("main:read header"), exit(1);

   if (rlen < IP6HLEN)
      fprintf(stderr, "short read. Eof, exiting...\n"), exit(0);

   if ((rlen = read(fd, buf + IP6HLEN + 4, ntohs(ihd->ip6_ctlun.ip6_un1.ip6_un1_plen))) == -1)
      perror("main:read data"), exit(1);

   return rlen;
}


int main(int argc, char *argv[])
{
   char data[BUFLEN];
   struct ip6_hdr *ihd = (struct ip6_hdr*) &data[4];
   ssize_t rlen;
   FILE *out = stdout;
   char tunname[IFNAMSIZ] = "";
   OnionPeer_t *peer;

   // init peer structure
   init_peers();
   // create TUN device
   tunfd_ = tun_alloc(tunname, "FD87:D87E:EB43::1");
   // start socket receiver thread
   init_socket_receiver();
   // create listening socket and start socket acceptor
   init_socket_acceptor();
   // create socks connector thread
   init_socks_connector();
   // start packet dequeuer
   init_packet_dequeuer();

   for (;;)
   {
      /*
      if ((rlen = read(tunfd, data, IP6HLEN + 4)) == -1)
         perror("main:read header"), exit(1);
      if (rlen < IP6HLEN)
         fprintf(stderr, "short read. Eof, exiting...\n"), exit(0);

      if ((rlen = read(tunfd, data + IP6HLEN + 4, ntohs(ihd->ip6_ctlun.ip6_un1.ip6_un1_plen))) == -1)
         perror("main:read data"), exit(1);
         */

      rlen = receive_packet(tunfd_, data);
      log_msg(L_DEBUG, "received packet on tunfd %d", tunfd_);

      if (!forward_packet(&ihd->ip6_dst, data, rlen))
      {
         log_msg(L_NOTICE, "establishing new socks peer");
         push_socks_connector(&ihd->ip6_dst);
         log_msg(L_DEBUG, "queuing packet");
         queue_packet(&ihd->ip6_dst, data, rlen);
      }
   }

   return 0;
}

