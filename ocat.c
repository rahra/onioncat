#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

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
         fprintf(stderr, "debug : ");
         break;

      case L_NOTICE:
         fprintf(stderr, "notice: ");
         break;

      case L_ERROR:
         fprintf(stderr, "error : ");
         break;

      case L_FATAL:
         fprintf(stderr, "FATAL : ");
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


void usage(const char *s)
{
   fprintf(stderr, "usage: %s [OPTIONS] <onion_hostname>\n", s);
}


int main(int argc, char *argv[])
{
   char tunname[IFNAMSIZ] = "", onion[ONION_NAME_SIZE], *s, ip6addr[INET6_ADDRSTRLEN];
   struct in6_addr addr;
   int c, runasroot = 0;
   uid_t uid = 133;
   gid_t gid = 133;

   if (argc < 2)
      usage(argv[0]), exit(1);

   while ((c = getopt(argc, argv, "d:hr")) != -1)
      switch (c)
      {
         case 'd':
            debug_level_ = atoi(optarg);
            break;

         case 'r':
            runasroot = 1;
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
   log_msg(L_NOTICE, "[main] local IP is %s on %s", inet_ntop(AF_INET6, &addr, ip6addr, INET6_ADDRSTRLEN), tunname);
   // start socket receiver thread
   init_socket_receiver();
   // create listening socket and start socket acceptor
   init_socket_acceptor();

/*   // create socks connector thread
   init_socks_connector();
   // start packet dequeuer
   init_packet_dequeuer();
*/
   
   if (!runasroot && !getuid())
   {
      log_msg(L_NOTICE, "[main] running as root, changing uid/gid to %d/%d", uid, gid);
      if (setgid(gid))
         log_msg(L_ERROR, "[main] could not change gid: \"%s\"", strerror(errno));
      if (setuid(uid))
         log_msg(L_ERROR, "[main] could not change uid: \"%d\"", strerror(errno));
   }
   log_msg(L_NOTICE, "[main] uid/gid = %d/%d", getuid(), getgid());

   // create socks connector thread
   init_socks_connector();
   // start packet dequeuer
   init_packet_dequeuer();

   // start forwarding packets from tunnel
   log_msg(L_NOTICE, "[main] starting packet forwarder");
   packet_forwarder();

   return 0;
}

