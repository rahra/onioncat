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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "ocat.h"


void usage(const char *s)
{
   fprintf(stderr, 
         "%s (c) Bernhard R. Fischer -- compiled %s %s\n"
         "usage: %s [OPTIONS] <onion_hostname>\n"
         "   -a                    create connect log at \"$HOME/%s/%s\" (default = %d)\n"
         "   -h                    display usage message\n"
         "   -C                    disable local controller interface\n"
         "   -d <n>                set debug level to n, default = %d\n"
         "   -f <config_file>      read config from config_file\n"
         "   -i                    convert onion hostname to IPv6 and exit\n"
         "   -l <port>             set ocat listen port, default = %d\n"
         "   -o <ipv6_addr>        convert IPv6 address to onion url and exit\n"
         "   -r                    run as root, i.e. do not change uid/gid\n"
         "   -s <port>             set hidden service virtual port, default = %d\n"
         "   -t <port>             set tor SOCKS port, default = %d\n"
#ifndef WITHOUT_TUN
         "   -T <tun_device>       path to tun character device, default = \"%s\"\n"
#endif
         "   -u <user>             change UID to user, default = \"%s\"\n"
         "   -4                    enable IPv4 support (default = %d)\n"
         , PACKAGE_STRING, __DATE__, __TIME__, s,
         // option defaults start here
         OCAT_DIR, OCAT_CONNECT_LOG, setup.create_clog, setup.debug_level, setup.ocat_listen_port, setup.ocat_dest_port, setup.tor_socks_port, 
#ifndef WITHOUT_TUN
         TUN_DEV,
#endif
         OCAT_UNAME, setup.ipv4_enable
            );
}


int main(int argc, char *argv[])
{
   char tunname[IFNAMSIZ] = {0}, *s, ip6addr[INET6_ADDRSTRLEN];
   int c, runasroot = 0;
   struct passwd *pwd;
   int urlconv = 0;

   if (argc < 2)
      usage(argv[0]), exit(1);

   while ((c = getopt(argc, argv, "aCd:f:hriopl:t:T:s:u:4")) != -1)
      switch (c)
      {
         case 'a':
            setup.create_clog = 1;
            break;

         case 'C':
            setup.controller = 0;
            break;

         case 'd':
            setup.debug_level = atoi(optarg);
            break;

         case 'f':
            setup.config_file = optarg;
            setup.config_read = 0;
            break;

         case 'i':
            urlconv = 1;
            break;

         case 'l':
            setup.ocat_listen_port = atoi(optarg);
            break;

         case 'o':
            urlconv = 2;
            break;

         case 'r':
            runasroot = 1;
            setup.usrname = "root";
            break;

         case 's':
            setup.ocat_dest_port = atoi(optarg);
            break;

         case 't':
            setup.tor_socks_port = atoi(optarg);
            break;

#ifndef WITHOUT_TUN
         case 'T':
            tun_dev_ = optarg;
            break;
#endif

         case 'u':
            setup.usrname = optarg;
            break;

         case '4':
            setup.ipv4_enable = 1;
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
      if ((c = inet_pton(AF_INET6, argv[optind], &setup.ocat_addr)) < 0)
         log_msg(L_ERROR, "inet_pton failed: %s", strerror(errno)), exit(1);
      else if (!c)
         log_msg(L_ERROR, "%s is not a valid IPv6 address", argv[optind]), exit(1);
      if (!has_tor_prefix(&setup.ocat_addr))
         log_msg(L_ERROR, "address does not have TOR prefix"), exit(1);
      ipv6tonion(&setup.ocat_addr, setup.onion_url);
      printf("%s.onion\n", setup.onion_url);
      exit(0);
   }

   // convert parameter to IPv6 address
   strncpy(setup.onion_url, argv[optind], ONION_NAME_SIZE);
   if ((s = strchr(setup.onion_url, '.')))
         *s = '\0';
   if (strlen(setup.onion_url) != 16)
      log_msg(L_ERROR, "parameter seems not to be valid onion hostname"), exit(1);
   if (oniontipv6(setup.onion_url, &setup.ocat_addr) == -1)
      log_msg(L_ERROR, "parameter seems not to be valid onion hostname"), exit(1);
   if (setup.ipv4_enable)
      oniontipv4(setup.onion_url, &setup.ocat_addr4, ntohl(setup.ocat_addr4_mask));

   inet_ntop(AF_INET6, &setup.ocat_addr, ip6addr, INET6_ADDRSTRLEN);

   if (urlconv == 1)
   {
      printf("%s\n", ip6addr);
      if (setup.ipv4_enable)
         printf("%s\n", inet_ntoa(setup.ocat_addr4));
      exit(0);
   }

   log_msg(L_NOTICE, "%s (c) Bernhard R. Fischer -- compiled %s %s", PACKAGE_STRING, __DATE__, __TIME__);

   if (setup.config_file)
   {
      log_msg(L_NOTICE, "reading config file %s", setup.config_file);
      if ((c = open(setup.config_file, O_RDONLY)) == -1)
         log_msg(L_ERROR, "error opening file: %s", strerror(errno)), exit(1);
      ctrl_handler((void*) c);
   }

#ifndef WITHOUT_TUN
   // create TUN device
   setup.tunfd[0] = setup.tunfd[1] = tun_alloc(tunname, setup.ocat_addr);
#endif

   log_msg(L_NOTICE, "local IP is %s on %s", ip6addr, tunname);
   log_debug("tun frameheader v6 = 0x%08x, v4 = 0x%08x", ntohl(setup.fhd_key[IPV6_KEY]), ntohl(setup.fhd_key[IPV4_KEY]));

   // start socket receiver thread
   run_ocat_thread("receiver", socket_receiver, NULL);
   // create listening socket and start socket acceptor
   run_ocat_thread("acceptor", socket_acceptor, NULL);
   // starting socket cleaner
   run_ocat_thread("cleaner", socket_cleaner, NULL);

   // getting passwd info for user
   errno = 0;
   if (!(pwd = getpwnam(setup.usrname)))
      log_msg(L_FATAL, "can't get information for user \"%s\": \"%s\"", setup.usrname, errno ? strerror(errno) : "user not found"), exit(1);

   if (!runasroot && !getuid())
   {
      log_msg(L_NOTICE, "running as root, changing uid/gid to %s (uid %d/gid %d)", setup.usrname, pwd->pw_uid, pwd->pw_gid);
      if (setgid(pwd->pw_gid))
         log_msg(L_ERROR, "could not change gid: \"%s\"", strerror(errno)), exit(1);
      if (setuid(pwd->pw_uid))
         log_msg(L_ERROR, "could not change uid: \"%d\"", strerror(errno)), exit(1);
   }
   log_debug("uid/gid = %d/%d", getuid(), getgid());

   if (setup.create_clog)
      open_connect_log(pwd->pw_dir);

   // create socks connector thread
   run_ocat_thread("connector", socks_connector, NULL);
   // start packet dequeuer
   run_ocat_thread("dequeuer", packet_dequeuer, NULL);
   // start controller socket thread
   if (setup.controller)
      run_ocat_thread("controller", ocat_controller, NULL);

   // start forwarding packets from tunnel
   log_msg(L_NOTICE, "starting packet forwarder");
   packet_forwarder();

   return 0;
}

