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
//static int route_packets_ = 0;
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

   rlen = read(fd, buf, FRAME_SIZE);
   log_msg(L_DEBUG, "read frame with framesize %d", rlen);

   return rlen;
}


void usage(const char *s)
{
   fprintf(stderr, "usage: %s [OPTIONS] <onion_hostname>\n", s);
}


int main(int argc, char *argv[])
{
   char data[FRAME_SIZE];
   struct ip6_hdr *ihd = (struct ip6_hdr*) &data[4];
   ssize_t rlen;
   char tunname[IFNAMSIZ] = "", onion[ONION_NAME_SIZE], *s;
   struct in6_addr addr;
   int c;

   if (argc < 2)
      usage(argv[0]), exit(1);

   while ((c = getopt(argc, argv, "d:h")) != -1)
      switch (c)
      {
         case 'd':
            debug_level_ = atoi(optarg);
            break;

         case 'h':
         default:
            usage(argv[0]);
            exit(1);
      }

   if (!argv[optind])
      usage(argv[0]), exit(1);

   // convert parameter to IPv6 address
   strncpy(onion, argv[optind], ONION_NAME_SIZE);
   if ((s = strchr(onion, '.')))
         *s = '\0';
   if (strlen(onion) != 16)
      fprintf(stderr, "parameter seems not to be valid onion hostname.\n"), exit(1);
   if (oniontipv6(onion, &addr) == -1)
      fprintf(stderr, "parameter seems not to be valid onion hostname.\n"), exit(1);

   // init peer structure
   init_peers();
   // create TUN device
   tunfd_ = tun_alloc(tunname, addr);
   // start socket receiver thread
   init_socket_receiver();
   // create listening socket and start socket acceptor
   init_socket_acceptor();
   // create socks connector thread
   init_socks_connector();
   // start packet dequeuer
   init_packet_dequeuer();

   log_msg(L_NOTICE, "[main] local IP is %s on %s", inet_ntop(AF_INET6, &addr, data, FRAME_SIZE), tunname);

   for (;;)
   {
      rlen = receive_packet(tunfd_, data);
      log_msg(L_DEBUG, "received packet on tunfd %d", tunfd_);

      // do some packet validation
      if (*((uint16_t*) &data[2]) != htons(0x86dd))
      {
         log_msg(L_ERROR, "ethertype is not IPv6, dropping packet");
         continue;
      }
      if (!has_tor_prefix(&ihd->ip6_dst))
      {
         log_msg(L_ERROR, "destination %s unreachable, dropping packet", inet_ntop(AF_INET6, &ihd->ip6_dst, data, FRAME_SIZE));
         continue;
      }
      if (!has_tor_prefix(&ihd->ip6_src))
      {
         log_msg(L_ERROR, "source address invalid. Remote ocat could not reply, dropping packet");
         continue;
      }

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

