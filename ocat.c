#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include "ocat.h"


int tunfd_[2] = {0, 1};

extern int debug_level_;


void usage(const char *s)
{
   fprintf(stderr, 
         "onioncat (c) Bernhard R. Fischer -- compiled %s %s\n"
         "usage: %s [OPTIONS] <onion_hostname>\n"
         "   -h                    display usage message\n"
         "   -d <n>                set debug level to n, default = %d\n"
         "   -i <onion_hostname>   convert onion hostname to IPv6 and exit\n"
         "   -l <port>             set ocat listen port, default = %d\n"
         "   -o <ipv6_addr>        convert IPv6 address to onion url and exit\n"
         "   -r                    run as root, i.e. do not change uid/gid\n"
         "   -s <port>             set hidden service virtual port, default = %d\n"
         "   -t <port>             set tor SOCKS port, default = %d\n"
#ifndef WITHOUT_TUN
         "   -p                    test tun header and exit\n"
         "   -T <tun_device>       path to tun character device\n"
#endif
         "   -v                    validate packets from sockets, default = %d\n"
         , __DATE__, __TIME__, s, debug_level_, ocat_listen_port_, ocat_dest_port_, tor_socks_port_, vrec_);
}


int main(int argc, char *argv[])
{
   char tunname[IFNAMSIZ] = "", onion[ONION_NAME_SIZE], *s, ip6addr[INET6_ADDRSTRLEN];
   struct in6_addr addr;
   int c, runasroot = 0;
   uid_t uid = 504;
   gid_t gid = 504;
   int urlconv = 0, test_only = 0;

   if (argc < 2)
      usage(argv[0]), exit(1);

   while ((c = getopt(argc, argv, "d:hriopl:t:T:s:")) != -1)
      switch (c)
      {
         case 'd':
            debug_level_ = atoi(optarg);
            break;

         case 'i':
            urlconv = 1;
            break;

         case 'l':
            ocat_listen_port_ = atoi(optarg);
            break;

         case 'o':
            urlconv = 2;
            break;

         case 'r':
            runasroot = 1;
            break;

         case 's':
            ocat_dest_port_ = atoi(optarg);
            break;

         case 't':
            tor_socks_port_ = atoi(optarg);
            break;

#ifndef WITHOUT_TUN
         case 'p':
            test_only = 1;
            break;

         case 'T':
            tun_dev_ = optarg;
            break;
#endif

         case 'v':
            vrec_ = 1;
            break;

         case 'h':
         default:
            usage(argv[0]);
            exit(1);
      }

   if (!argv[optind])
      usage(argv[0]), exit(1);

   // init main thread
   (void) init_ocat_thread("main");

   if (urlconv == 2)
   {
      if (inet_pton(AF_INET6, argv[optind], &addr) <= 0)
         log_msg(L_ERROR, "%s", strerror(errno)), exit(1);
      if (!has_tor_prefix(&addr))
         log_msg(L_ERROR, "address does not have TOR prefix"), exit(1);
      ipv6tonion(&addr, onion);
      printf("%s.onion\n", onion);
      exit(0);
   }

   // convert parameter to IPv6 address
   strncpy(onion, argv[optind], ONION_NAME_SIZE);
   if ((s = strchr(onion, '.')))
         *s = '\0';
   if (strlen(onion) != 16)
      log_msg(L_ERROR, "[main] parameter seems not to be valid onion hostname"), exit(1);
   if (oniontipv6(onion, &addr) == -1)
      log_msg(L_ERROR, "[main] parameter seems not to be valid onion hostname"), exit(1);

   inet_ntop(AF_INET6, &addr, ip6addr, INET6_ADDRSTRLEN);

   if (urlconv == 1)
   {
      printf("%s\n", ip6addr);
      exit(0);
   }

   log_msg(L_NOTICE, "onioncat (c) Bernhard R. Fischer -- compiled %s %s", __DATE__, __TIME__);

   // init peer structure
   init_peers();

#ifndef WITHOUT_TUN
   // create TUN device
   tunfd_[0] = tunfd_[1] = tun_alloc(tunname, addr);
#ifdef TEST_TUN_HDR
   test_tun_hdr();
   if (test_only)
      exit(0);
#endif
#endif

   log_msg(L_NOTICE, "local IP is %s on %s", ip6addr, tunname);
   log_msg(L_DEBUG, "tun frameheader = 0x%08x", ntohl(fhd_key_));

   // start socket receiver thread
   run_ocat_thread("receiver", socket_receiver);
   // create listening socket and start socket acceptor
   run_ocat_thread("acceptor", socket_acceptor);
   // starting socket cleaner
   run_ocat_thread("cleaner", socket_cleaner);

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
   run_ocat_thread("connector", socks_connector);
   // start packet dequeuer
   run_ocat_thread("dequeuer", packet_dequeuer);
   // start controller socket thread
   run_ocat_thread("controller", ocat_controller);

   // start forwarding packets from tunnel
   log_msg(L_NOTICE, "[main] starting packet forwarder");
   packet_forwarder();

   return 0;
}

