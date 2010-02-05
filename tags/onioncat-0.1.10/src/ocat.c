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


#include "ocat.h"


void usage(const char *s)
{
   fprintf(stderr, 
         "%s\n"
         "usage: %s [OPTIONS] <onion_hostname>\n"
         "   -a                    create connect log at \"$HOME/%s/%s\" (default = %d)\n"
         "   -b                    daemonize\n"
         "   -h                    display usage message\n"
         "   -C                    disable local controller interface\n"
         "   -d <n>                set debug level to n, default = %d\n"
         "   -f <config_file>      read config from config_file\n"
         "   -i                    convert onion hostname to IPv6 and exit\n"
         "   -l [<ip>:]<port>      set ocat listen address and port, default = 127.0.0.1:%d\n"
         "   -L <log_file>         log output to <log_file> (default = stderr)\n"
         "   -o <ipv6_addr>        convert IPv6 address to onion url and exit\n"
         "   -p                    use TAP device instead of TUN\n"
         "   -P <pid_file>         create pid file at location of <pid_file> (default = %s)\n"
         "   -r                    run as root, i.e. do not change uid/gid\n"
         "   -R                    generate a random local onion URL\n"
         "   -s <port>             set hidden service virtual port, default = %d\n"
         "   -t [<ip>:]<port>      set Tor SOCKS address and port, default = 127.0.0.1:%d\n"
#ifndef WITHOUT_TUN
         "   -T <tun_device>       path to tun character device, default = \"%s\"\n"
#endif
         "   -u <user>             change UID to user, default = \"%s\"\n"
         "   -4                    enable IPv4 support (default = %d)\n"
         , CNF(version), s,
         // option defaults start here
         OCAT_DIR, OCAT_CONNECT_LOG, CNF(create_clog), CNF(debug_level), OCAT_LISTEN_PORT,
         CNF(pid_file),
         CNF(ocat_dest_port), ntohs(CNF(socks_dst)->sin_port), 
#ifndef WITHOUT_TUN
         TUN_DEV,
#endif
         OCAT_UNAME, CNF(ipv4_enable)
            );
}


/*! Open the message log. It's set by command line option -L.
 *  @return 0 if file was successfully opened, -1 if stderr is
 *  used instead.
 */
int open_logfile(void)
{
   if (CNF(logfn))
   {
      if ((CNF(logf) = fopen(CNF(logfn), "a")))
      {
         log_debug("logfile %s opened", CNF(logfn));
         if (setvbuf(CNF(logf), NULL, _IOLBF, 0))
            log_msg(LOG_ERR, "could not setup line buffering: %s", strerror(errno));
         fflush(CNF(logf));
         return 0;
      }
      CNF(logf) = stderr;
      log_msg(LOG_ERR, "could not open logfile %s: %s. Defaulting to stderr", CNF(logfn), strerror(errno));
   }
   return -1;
}


int mk_pid_file(void)
{
   FILE *f;

   if (!(f = fopen(CNF(pid_file), "w")))
   {
      log_msg(LOG_ERR, "could not create pid_file %s: %s", CNF(pid_file), strerror(errno));
      return -1;
   }

   fprintf(f, "%d\n", getpid());
   fclose(f);
   log_debug("pid_file %s created, pid = %d", CNF(pid_file), getpid());

   return 0;
}


void background(void)
{
   log_msg(LOG_INFO, "backgrounding");

   switch(fork())
   {
      case -1:
         log_msg(LOG_ERR, "fork failed: %s. Staying in foreground", strerror(errno));
         return;

      case 0:
         log_debug("child successfully forked");
         return;

      default:
         exit(0);
   }
}


int main(int argc, char *argv[])
{
   //char tunname[IFNAMSIZ] = {0}, 
   char *s, ip6addr[INET6_ADDRSTRLEN], hw[20];
   int c, runasroot = 0;
   struct passwd *pwd;
   int urlconv = 0;

   init_setup();

   if (argc < 2)
      usage(argv[0]), exit(1);

   while ((c = getopt(argc, argv, "abCd:f:hrRiopl:t:T:s:u:4L:P:")) != -1)
      switch (c)
      {
         case 'a':
            CNF(create_clog) = 1;
            break;

         case 'b':
            CNF(daemon) = 1;
            break;

         case 'C':
            CNF(controller) = 0;
            break;

         case 'd':
            CNF(debug_level) = atoi(optarg);
            break;

         case 'f':
            CNF(config_file) = optarg;
            CNF(config_read) = 0;
            break;

         case 'i':
            urlconv = 1;
            break;

         case 'l':
            //CNF(ocat_listen_port) = atoi(optarg);
            if (strsockaddr(optarg, (struct sockaddr*) CNF(oc_listen)) == -1)
               exit(1);
            break;

         case 'L':
            CNF(logfn) = optarg;
            break;

         case 'o':
            urlconv = 2;
            break;

         case 'p':
            CNF(use_tap) = 1;
            break;

         case 'P':
            CNF(pid_file) = optarg;
            break;

         case 'r':
            runasroot = 1;
            CNF(usrname) = "root";
            break;

         case 'R':
            CNF(rand_addr) = 1;
            break;

         case 's':
            CNF(ocat_dest_port) = atoi(optarg);
            break;

         case 't':
            if (strsockaddr(optarg, (struct sockaddr*) CNF(socks_dst)) == -1)
               exit(1);
            break;

#ifndef WITHOUT_TUN
         case 'T':
            tun_dev_ = optarg;
            break;
#endif

         case 'u':
            CNF(usrname) = optarg;
            break;

         case '4':
            CNF(ipv4_enable) = 1;
            break;

         case 'h':
         default:
            usage(argv[0]);
            exit(1);
      }

   if (!CNF(rand_addr) && !argv[optind])
      usage(argv[0]), exit(1);

   // init main thread
   (void) init_ocat_thread("main");

   if (urlconv == 2)
   {
      if ((c = inet_pton(AF_INET6, argv[optind], &CNF(ocat_addr))) < 0)
         log_msg(LOG_ERR, "inet_pton failed: %s", strerror(errno)), exit(1);
      else if (!c)
         log_msg(LOG_ERR, "%s is not a valid IPv6 address", argv[optind]), exit(1);
      if (!has_tor_prefix(&CNF(ocat_addr)))
         log_msg(LOG_ERR, "address does not have TOR prefix"), exit(1);
      ipv6tonion(&CNF(ocat_addr), CNF(onion_url));
      printf("%s.onion\n", CNF(onion_url));
      exit(0);
   }

   // copy onion-URL from command line
   if (!CNF(rand_addr))
      strncpy(CNF(onion_url), argv[optind], ONION_NAME_SIZE);
   // ...or generate a random one
   else
      rand_onion(CNF(onion_url));

   // convert parameter to IPv6 address
   if ((s = strchr(CNF(onion_url), '.')))
         *s = '\0';
   if (strlen(CNF(onion_url)) != 16)
      log_msg(LOG_ERR, "parameter seems not to be valid onion hostname"), exit(1);
   if (oniontipv6(CNF(onion_url), &CNF(ocat_addr)) == -1)
      log_msg(LOG_ERR, "parameter seems not to be valid onion hostname"), exit(1);
   if (CNF(ipv4_enable))
      oniontipv4(CNF(onion_url), &CNF(ocat_addr4), ntohl(CNF(ocat_addr4_mask)));

   inet_ntop(AF_INET6, &CNF(ocat_addr), ip6addr, INET6_ADDRSTRLEN);

   if (urlconv == 1)
   {
      printf("%s\n", ip6addr);
      if (CNF(ipv4_enable))
         printf("%s\n", inet_ntoa(CNF(ocat_addr4)));
      exit(0);
   }

   log_msg(LOG_INFO, "%s (c) %s -- compiled %s %s", OCAT_AUTHOR, PACKAGE_STRING, __DATE__, __TIME__);

#if 0
   if (CNF(config_file))
   {
      log_msg(LOG_INFO, "reading config file %s", CNF(config_file));
      if ((c = open(CNF(config_file), O_RDONLY)) == -1)
         log_msg(LOG_ERR, "error opening file: %s", strerror(errno)), exit(1);
      ctrl_handler((void*) c);
   }
#endif

   memcpy(&CNF(ocat_hwaddr[3]), &CNF(ocat_addr.s6_addr[13]), 3);
   if (CNF(use_tap));
      log_msg(LOG_INFO, "MAC address %s", ether_ntoa_r((struct ether_addr*) CNF(ocat_hwaddr), hw));

#ifndef WITHOUT_TUN
   // create TUN device
   CNF(tunfd[0]) = CNF(tunfd[1]) = tun_alloc(CNF(tunname), CNF(ocat_addr));
#endif

   log_msg(LOG_INFO, "IPv6 address %s", ip6addr);
   log_msg(LOG_INFO, "TUN/TAP device %s", CNF(tunname));
   if (CNF(ipv4_enable))
      log_msg(LOG_INFO, "IP address %s", inet_ntoa(CNF(ocat_addr4)));
 
   log_debug("tun frameheader v6 = 0x%08x, v4 = 0x%08x", ntohl(CNF(fhd_key[IPV6_KEY])), ntohl(CNF(fhd_key[IPV4_KEY])));

   // daemonize of required
   if (CNF(daemon))
      background();

   // start socket receiver thread
   run_ocat_thread("receiver", socket_receiver, NULL);
   // create listening socket and start socket acceptor
   run_ocat_thread("acceptor", socket_acceptor, NULL);
   // starting socket cleaner
   run_ocat_thread("cleaner", socket_cleaner, NULL);

   // getting passwd info for user
   errno = 0;
   if (!(pwd = getpwnam(CNF(usrname))))
      log_msg(LOG_EMERG, "can't get information for user \"%s\": \"%s\"", CNF(usrname), errno ? strerror(errno) : "user not found"), exit(1);

   // create pid_file
   mk_pid_file();

   if (!runasroot && !getuid())
   {
      log_msg(LOG_INFO, "running as root, changing uid/gid to %s (uid %d/gid %d)", CNF(usrname), pwd->pw_uid, pwd->pw_gid);
      if (setgid(pwd->pw_gid))
         log_msg(LOG_ERR, "could not change gid: \"%s\"", strerror(errno)), exit(1);
      if (setuid(pwd->pw_uid))
         log_msg(LOG_ERR, "could not change uid: \"%d\"", strerror(errno)), exit(1);
   }
   log_debug("uid/gid = %d/%d", getuid(), getgid());

   // opening logfile
   if (CNF(daemon) && !CNF(logfn))
   {
      log_debug("connecting logfile to /dev/null because of daemon option");
      CNF(logfn) = "/dev/null";
   }
   if ((open_logfile() == -1) && CNF(daemon))
   {
      log_msg(LOG_NOTICE, "staying in foreground");
      CNF(daemon) = 0;
   }

   if (CNF(create_clog))
      open_connect_log(pwd->pw_dir);

   // create socks connector thread
   run_ocat_thread("connector", socks_connector, NULL);
#ifdef PACKET_QUEUE
   // start packet dequeuer
   run_ocat_thread("dequeuer", packet_dequeuer, NULL);
#endif
   // start controller socket thread
   if (CNF(controller))
      run_ocat_thread("controller", ocat_controller, NULL);

   // initiate connections to permanent root peers
   log_debug("connecting root peers");
   for (c = 0; c < ROOT_PEERS; c++)
      if (!IN6_ARE_ADDR_EQUAL(&CNF(root_peer[c]), &CNF(ocat_addr)))
         socks_queue(CNF(root_peer[c]), 1);

   // reading config file
   if (CNF(config_file))
   {
      log_msg(LOG_INFO, "reading config file %s", CNF(config_file));
      if ((c = open(CNF(config_file), O_RDONLY)) == -1)
         log_msg(LOG_ERR, "error opening file: %s", strerror(errno)), exit(1);
      ctrl_handler((void*) c);
   }

   // start forwarding packets from tunnel
   log_msg(LOG_INFO, "starting packet forwarder");
   packet_forwarder();

   return 0;
}
