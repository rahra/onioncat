/* Copyright 2008-2017 Bernhard R. Fischer.
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

/*! \file ocat.c
 * This is the main file OnionCat. It initializes everything, runs all threads,
 * and finally terminates OnionCat again.
 * \date 2019/09/08
 * \author Bernhard R. Fischer, <bf@abenteuerland.at>
 */

#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"


void usage(const char *s)
{
   fprintf(stderr, 
         "%s\n"
         "usage: %s [OPTIONS] <onion_hostname>\n"
         "   -a                    create connect log at \"$HOME/%s/%s\" (default = %d)\n"
         "   -b                    daemonize (default = %d)\n"
         "   -B                    do not daemonize (default = %d)\n"
         "   -h                    display usage message\n"
         "   -H                    toggle hosts lookup (default = %d, see also option -g)\n"
         "   -C                    disable local controller interface\n"
         "   -d <n>                set debug level to n, default = %d\n"
         "   -e <ifup-script>      execute ifup-script after opening interface\n"
         "   -f <config_file>      read config from config_file (default = %s)\n"
         "   -g <hosts_path>       set path to hosts file for hosts lookup, defaults to system hosts file, if not set.\n"
         "                         This option implicitly activates -H.\n"
         "   -i                    convert onion hostname to IPv6 and exit\n"
         "   -I                    GarliCat mode, use I2P instead of Tor\n"
         "   -l [<ip>:]<port>      set ocat listen address and port, default = 127.0.0.1:%d\n"
         "   -L <log_file>         log output to <log_file> (default = stderr)\n"
         "   -n <tunname>          set the tun device name, may contain format string (e.g. tun%%d)\n"
         "   -o <ipv6_addr>        convert IPv6 address to onion url and exit\n"
         "   -p                    use TAP device instead of TUN\n"
         "   -P [<pid_file>]       create pid file at location of <pid_file> (default = %s)\n"
         "   -r                    run as root, i.e. do not change uid/gid\n"
         "   -R                    generate a random local onion URL\n"
         "   -s <port>             set hidden service virtual port, default = %d\n"
         "   -t [<ip>:]<port>      set Tor SOCKS address and port, default = 127.0.0.1:%d\n"
#ifndef WITHOUT_TUN
         "   -T <tun_device>       path to tun character device, default = \"%s\"\n"
#endif
         "   -U                    disable unidirectional mode\n"
         "   -u <user>             change UID to user, default = \"%s\"\n"
         "   -4                    enable IPv4 support (default = %d)\n"
         "   -5 [socks5|direct]    use SOCKS5 or direct connections instead of SOCKS4A (default = %d)\n"
         , CNF(version), s,
         // option defaults start here
         OCAT_DIR, NDESC(clog_file), CNF(create_clog), 
         CNF(daemon), CNF(daemon) ^ 1, CNF(hosts_lookup),
         CNF(debug_level), CNF(config_file), NDESC(listen_port),
         CNF(pid_file),
         CNF(ocat_dest_port), ntohs(CNF(socks_dst)->sin_port), 
#ifndef WITHOUT_TUN
         TUN_DEV,
#endif
         OCAT_UNAME, CNF(ipv4_enable), CNF(socks5)
            );
}


/*! Open the message log. It's set by command line option -L.
 *  @return 0 if file was successfully opened, -1 if stderr is
 *  used instead.
 */
int open_logfile(void)
{
   FILE *f;

   if (CNF(logfn))
   {
      log_debug("opening log file \"%s\"", CNF(logfn));
      if ((f = fopen(CNF(logfn), "a")))
      {
         CNF(logf) = f;
         log_debug("logfile %s opened", CNF(logfn));
         if (setvbuf(CNF(logf), NULL, _IOLBF, 0))
            log_msg(LOG_ERR, "could not setup line buffering: %s", strerror(errno));
         fflush(CNF(logf));
         return 0;
      }
      //CNF(logf) = stderr;
      log_msg(LOG_ERR, "could not open logfile %s: %s.", CNF(logfn), strerror(errno));
   }
   return -1;
}


int mk_pid_file(void)
{
   FILE *f;
   char c;

   if (!(f = fopen(CNF(pid_file), "w")))
   {
      log_msg(LOG_ERR, "could not create pid_file %s: %s", CNF(pid_file), strerror(errno));
      return -1;
   }

   fprintf(f, "%d\n", (int) getpid());
   fclose(f);
   log_debug("pid_file %s created, pid = %d", CNF(pid_file), getpid());

   if (pipe(CNF(pid_fd)) == -1)
   {
      log_msg(LOG_WARNING, "could not open pid pipe: \"%s\"", strerror(errno));
      return -1;
   }

   switch (fork())
   {
      case -1:
         oe_close(CNF(pid_fd[0]));
         oe_close(CNF(pid_fd[1]));
         return -1;

      // child
      case 0:
         oe_close(CNF(pid_fd[1]));

         // close tunnel device
         oe_close(CNF(tunfd[0]));
         if (CNF(tunfd[0]) != CNF(tunfd[1]))
            oe_close(CNF(tunfd[1]));

         // wait for something happening on pipe
         if (read(CNF(pid_fd[0]), &c, 1) == -1)
            log_msg(LOG_ERR, "error reading from pid_fd %d: \"%s\"",
                  CNF(pid_fd[0]), strerror(errno)), exit(1);

         if (unlink(CNF(pid_file)) == -1)
            log_msg(LOG_WARNING, "error deleting pid file \"%s\": \"%s\"",
                  CNF(pid_file), strerror(errno)), exit(1);
         log_msg(LOG_INFO, "pid file deleted, exiting.");
         _exit(0);

      // parent
      default:
         oe_close(CNF(pid_fd[0]));

   }

   return CNF(pid_fd[1]);
}


void background(void)
{
   pid_t pid, ppid;
   log_debug("backgrounding");

   ppid = getpid();
   pid = fork();
   switch(pid)
   {
      case -1:
         CNF(daemon) = 0;
         log_msg(LOG_ERR, "fork failed: %s. Staying in foreground", strerror(errno));
         return;

      case 0:
         log_msg(LOG_INFO, "process backgrounded by parent %d, new pid = %d", ppid, getpid());
         (void) umask(0);
         if (setsid() == -1)
            log_msg(LOG_ERR, "could not set process group ID: \"%s\"", strerror(errno));
         if (chdir("/") == -1)
            log_msg(LOG_ERR, "could not change directory to /: \"%s\"", strerror(errno));
         // redirect standard files to /dev/null
         if (!freopen( "/dev/null", "r", stdin))
            log_msg(LOG_ERR, "could not reconnect stdin to /dev/null: \"%s\"", strerror(errno));
         if (!freopen( "/dev/null", "w", stdout))
            log_msg(LOG_ERR, "could not reconnect stdout to /dev/null: \"%s\"", strerror(errno));
         if (!freopen( "/dev/null", "w", stderr))
            log_msg(LOG_ERR, "could not reconnect stderr to /dev/null: \"%s\"", strerror(errno));
         return;

      default:
         log_debug("parent %d exits, background pid = %d", ppid, pid);
         if (CNF(logf))
            fclose(CNF(logf));
         exit(0);
   }
}


/*! Signal handler for SIGINT. */
void sig_handler(int sig)
{
   int status;

   switch (sig)
   {
      case SIGCHLD:
         // FIXME: there should be some error handling
         (void) waitpid(-1, &status, WNOHANG);
         break;

      case SIGTERM:
      case SIGINT:
         // emergency shutdown if signalled twice
         if (CNF(sig_term))
            exit(0);

         CNF(sig_term) = 1;
         break;

      case SIGUSR1:
         CNF(sig_usr1) = 1;
         break;
   }
}


void install_sig(void)
{
   struct sigaction sa;

   memset(&sa, 0, sizeof(sa));
   sa.sa_handler = sig_handler;
   log_debug("installing signal handler");
   if (sigaction(SIGTERM, &sa, NULL) == -1)
      log_msg(LOG_ERR, "could not install SIGINT handler: \"%s\"", strerror(errno)), exit(1);
   if (sigaction(SIGINT, &sa, NULL) == -1)
      log_msg(LOG_ERR, "could not install SIGINT handler: \"%s\"", strerror(errno)), exit(1);
   if (sigaction(SIGHUP, &sa, NULL) == -1)
      log_msg(LOG_ERR, "could not install SIGHUP handler: \"%s\"", strerror(errno)), exit(1);
   if (sigaction(SIGUSR1, &sa, NULL) == -1)
      log_msg(LOG_ERR, "could not install SIGUSR1 handler: \"%s\"", strerror(errno)), exit(1);
   if (sigaction(SIGCHLD, &sa, NULL) == -1)
      log_msg(LOG_ERR, "could not install SIGCHLD handler: \"%s\"", strerror(errno)), exit(1);

}


void cleanup_system(void)
{
   OcatPeer_t *peer, *next;
   char c;

   log_msg(LOG_NOTICE, "waiting for system cleanup...");
   // close tunnel interface
#ifdef __CYGWIN__
   (void) win_close_tun();
#else
   log_debug("closing tunfd %d (and %d)", CNF(tunfd[0]), CNF(tunfd[1]));
   oe_close(CNF(tunfd[0]));
   if (CNF(tunfd[0]) != CNF(tunfd[1]))
      oe_close(CNF(tunfd[1]));
#endif

   // close and delete all peers
   log_debug("deleting peers");
   lock_peers();
   for (peer = get_first_peer(); peer; peer = next)
   {
      lock_peer(peer);
      log_debug("closing tcpfd %d", peer->tcpfd);
      oe_close(peer->tcpfd);
      unlock_peer(peer);
      // get pointer to next before freeing struct
      next = peer->next;
      log_debug("deleting peer at %p", peer);
      delete_peer(peer);
   }
   unlock_peers();

   sig_socks_connector();

   // join threads
   if (join_threads() > 1)
   {
      // waiting for detached threads
      log_debug("waiting %ds for detached threads", SELECT_TIMEOUT);
      sleep(SELECT_TIMEOUT);
   }

   delete_listeners(CNF(oc_listen), CNF(oc_listen_fd), CNF(oc_listen_cnt));

   if (CNF(create_pid_file) && (CNF(pid_fd[1]) != -1))
   {
      if (write(CNF(pid_fd[1]), &c, 1) == -1)
         log_msg(LOG_ERR, "cout not write to pid fd %d: \"%s\"", CNF(pid_fd[1]), strerror(errno));
   }
}


void parse_opt_early(int argc, char *argv_orig[])
{
   int c, optf = 0;
   char *argv[argc + 1];

   log_debug("parse_opt_early()");
   // argv array is copied to prevent the original one from being modified by
   // getopt(). This behavior is at least true for Linux.
   memcpy(&argv, argv_orig, sizeof(char*) * (argc + 1));
   opterr = 0;
   while ((c = getopt(argc, argv, "f:I")) != -1)
   {
      log_debug("getopt(): c = %c, optind = %d, opterr = %d, optarg = \"%s\"", c, optind, opterr, SSTR(optarg));
      switch (c)
      {
         case 'f':
            if (!optf)
            {
               free(CNF(config_file));
               CNF(config_file) = optarg;
               optf++;
            }
            else
               log_msg(LOG_ERR, "multiple options -f ignored");
            break;

         case 'I':
            CNF(net_type) = NTYPE_I2P;
            break;

         case '?':
            break;
      }
   }
}

 
int parse_opt(int argc, char *argv[])
{
   int c, urlconv = 0;

   log_debug("parse_opt_early()");
   opterr = 1;
   optind = 1;
   while ((c = getopt(argc, argv, "f:IabBCd:e:g:hHrRiopl:t:T:s:Uu:45:L:P:n:")) != -1)
   {
      log_debug("getopt(): c = %c, optind = %d, opterr = %d, optarg = \"%s\"", c, optind, opterr, SSTR(optarg));
      switch (c)
      {
         // use SOCKS5 instead of SOCKS4A
         case '5':
            if (!strcasecmp(optarg, "socks5"))
               CNF(socks5) = CONNTYPE_SOCKS5;
            else if (!strcasecmp(optarg, "direct"))
            {
               CNF(socks5) = CONNTYPE_DIRECT;
               CNF(hosts_lookup) = 1;
               hosts_init("");
            }
            else
               log_msg(LOG_ERR, "unknown type \"%s\", ignoring", optarg);
            break;

         // those options are parsed in parse_opt_early()
         case 'f':
         case 'I':
            break;

         case 'a':
            CNF(create_clog) = 1;
            break;

         case 'b':
            CNF(daemon) = 1;
            break;

         case 'B':
            CNF(daemon) = 0;
            break;

         case 'C':
            CNF(controller) = 0;
            break;

         case 'd':
            CNF(debug_level) = atoi(optarg);
            break;

         case 'e':
            CNF(ifup) = optarg;
            break;

         case 'g':
            CNF(hosts_path) = optarg;
            hosts_set_path(CNF(hosts_path));
            CNF(hosts_lookup) = 1;
            break;

         case 'i':
            urlconv = 1;
            break;

         case 'h':
            usage(argv[0]);
            exit(1);

         case 'H':
            CNF(hosts_lookup) = 1;
            break;

         case 'l':
            if (CNF(oc_listen_cnt) == -1)
               break;
            if (!strcasecmp(optarg, "none"))
               CNF(oc_listen_cnt) = -1;
            else
               add_listener(optarg);
            break;

         case 'L':
            if (!strcmp(optarg, "syslog"))
               CNF(use_syslog) = 1;
            else
               CNF(logfn) = optarg;
            break;

         case 'o':
            urlconv = 2;
            break;

         case 'p':
            CNF(use_tap) = 1;
            CNF(ipconfig) = 0;
            break;

         case 'P':
            CNF(create_pid_file) = 1;
            if (optarg[0] == '-')
               optind--;
            else
               CNF(pid_file) = optarg;
            break;

         case 'r':
            CNF(runasroot) = 1;
            CNF(usrname) = "root";
            break;

         case 'R':
            CNF(rand_addr) = 1;
            break;

         case 's':
            CNF(ocat_dest_port) = atoi(optarg);
            break;

         case 't':
            if (!strcasecmp(optarg, "none"))
               CNF(socks_dst)->sin_family = 0;
            else if (strsockaddr(optarg, (struct sockaddr*) CNF(socks_dst)) == -1)
               exit(1);
            break;

#ifndef WITHOUT_TUN
         case 'T':
            tun_dev_ = optarg;
            break;

         case 'n':
            strlcpy(CNF(tunname), optarg, sizeof(CNF(tunname)));
            break;
#endif

         case 'U':
            CNF(unidirectional) = 0;
            break;

         case 'u':
            CNF(usrname) = optarg;
            break;

         case '4':
            CNF(ipv4_enable) = 1;
            break;

         default:
            usage(argv[0]);
            exit(1);
      }
   }

   return urlconv;
}


int main(int argc, char *argv[])
{
   char *charset = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM234567";
#ifdef HAVE_GETPWNAM_R
   char pwdbuf[SIZE_1K];
#endif
   char *s, ip6addr[INET6_ADDRSTRLEN], hw[20], def[100];
   int c;
   struct passwd *pwd, pwdm;
   int urlconv = 0, mode_detect = 0;

   init_setup();
   // detect network type by command file name
   // FIXME: this should be not hardcoded in that way
   // FIXME: basename() should better be used instead of strstr()
   if (strstr(argv[0], "gcat"))
   {
      CNF(net_type) = NTYPE_I2P;
      snprintf(def, 100, "127.0.0.1:%d", NDESC(listen_port));
      post_init_setup();
      mode_detect = 1;
   }

#ifdef DEBUG
   for (c = 0; c < argc; c++) log_debug("argv[%d] = \"%s\"", c, argv[c]);
#endif
   parse_opt_early(argc, argv);

   if (!mode_detect)
   {
      snprintf(def, 100, "127.0.0.1:%d", NDESC(listen_port));
      post_init_setup();
   }

   if ((c = open(CNF(config_file), O_RDONLY)) == -1)
   {
      CNF(config_failed) = errno;
      CNF(config_read) = 1;
      log_debug("opening config file \"%s\" failed: \"%s\"", CNF(config_file), strerror(CNF(config_failed)));
   }
   else
      ctrl_handler((void*) (long) c);
 
#ifdef DEBUG
   for (c = 0; c < argc; c++) log_debug("argv[%d] = \"%s\"", c, argv[c]);
#endif
   urlconv = parse_opt(argc, argv);

   // usage output must be after mode detection (Tor/I2P)
   if (argc < 2)
      usage(argv[0]), exit(1);

   if (!CNF(rand_addr) && !argv[optind])
      usage(argv[0]), exit(1);

   if (urlconv)
      CNF(daemon) = 0;

   // log to stderr if in foreground
   if (!CNF(daemon) && !CNF(use_syslog))
      CNF(logf) = stderr;
 
   if ((open_logfile() == -1) && !CNF(logf))
      openlog(PACKAGE_NAME, LOG_NDELAY | LOG_PID, LOG_DAEMON);

   // init main thread
   (void) init_ocat_thread("main");
   detach_thread();

   if (CNF(config_failed) && (CNF(config_failed != ENOENT)))
      log_msg(LOG_NOTICE, "could not open config file %s: %s", CNF(config_file), strerror(CNF(config_failed)));

   if (urlconv == 2)
   {
      if ((c = inet_pton(AF_INET6, argv[optind], &CNF(ocat_addr))) < 0)
         log_msg(LOG_ERR, "inet_pton failed: %s", strerror(errno)), exit(1);
      else if (!c)
         log_msg(LOG_ERR, "%s is not a valid IPv6 address", argv[optind]), exit(1);
      if (!has_tor_prefix(&CNF(ocat_addr)))
         log_msg(LOG_ERR, "address does not have TOR prefix"), exit(1);
      ipv6tonion(&CNF(ocat_addr), CNF(onion_url));
      printf("%s%s\n", CNF(onion_url), NDESC(domain));
      exit(0);
   }

   // copy onion-URL from command line
   log_debug("argv[%d] = \"%s\"", optind, SSTR(argv[optind]));
   if (!CNF(rand_addr))
      strlcpy(CNF(onion_url), argv[optind], sizeof(CNF(onion_url)));
   // ...or generate a random one
   else
      rand_onion(CNF(onion_url));

   // convert parameter to IPv6 address
   if ((s = strchr(CNF(onion_url), '.')))
         *s = '\0';
   // check for valid onion name length (v2 -> 16, HSv3 -> 56, I2P -> 52)
   if ((strlen(CNF(onion_url)) != 16) && (strlen(CNF(onion_url)) != CNF(l_hs_namelen)))
      log_msg(LOG_ERR, "parameter seems not to be valid onion hostname: invalid length"), exit(1);
   // check for valid base32 charset
   if (strspn(CNF(onion_url), charset) != strlen(CNF(onion_url)))
      log_msg(LOG_ERR, "parameter seems not to be valid onion hostname: invalid characters"), exit(1);
   // if it is a v3 hostname
   if (strlen(CNF(onion_url)) == CNF(l_hs_namelen))
   {
      // copy it to the dedicated v3 variable
      strlcpy(CNF(onion3_url), CNF(onion_url), sizeof(CNF(onion3_url)));
      // truncate name for IPv6 conversion to the lower 16 chars
      strlcpy(CNF(onion_url), &CNF(onion_url[CNF(l_hs_namelen) - 16]), 17);
   }
   if (oniontipv6(CNF(onion_url), &CNF(ocat_addr)) == -1)
      log_msg(LOG_ERR, "parameter seems not to be valid onion hostname"), exit(1);
   if (CNF(ipv4_enable))
      oniontipv4(CNF(onion_url), &CNF(ocat_addr4), ntohl(CNF(ocat_addr4_mask)));

   if (!inet_ntop(AF_INET6, &CNF(ocat_addr), ip6addr, INET6_ADDRSTRLEN))
      log_msg(LOG_ERR, "cannot convert IP address with inet_ntop: \"%s\"", strerror(errno)),
         exit(1);

   if (urlconv == 1)
   {
      printf("%s\n", ip6addr);
      if (CNF(ipv4_enable))
         printf("%s\n", inet_ntoa(CNF(ocat_addr4)));
      exit(0);
   }

   log_msg(LOG_INFO, "%s", CNF(version));

   memcpy(&CNF(ocat_hwaddr[3]), &CNF(ocat_addr.s6_addr[13]), 3);
   if (CNF(use_tap))
      log_msg(LOG_INFO, "MAC address %s", ether_ntoa_r((struct ether_addr*) CNF(ocat_hwaddr), hw));

#ifndef WITHOUT_TUN
   // create TUN device
   if ((CNF(tunfd[0]) = CNF(tunfd[1]) = tun_alloc(CNF(tunname), sizeof(CNF(tunname)), CNF(ocat_addr))) == -1)
   {
      log_msg(LOG_CRIT, "error opening TUN/TAP device");
      exit(1);
   }
#endif

   log_msg(LOG_INFO, "IPv6 address %s", ip6addr);
   log_msg(LOG_INFO, "TUN/TAP device %s", CNF(tunname));
   if (CNF(ipv4_enable))
      log_msg(LOG_INFO, "IP address %s", inet_ntoa(CNF(ocat_addr4)));
 
   log_debug("tun frameheader v6 = 0x%08x, v4 = 0x%08x", ntohl(CNF(fhd_key[IPV6_KEY])), ntohl(CNF(fhd_key[IPV4_KEY])));

   // daemonize of required
   if (CNF(daemon))
      background();

   // create pid_file
   if (CNF(create_pid_file))
      mk_pid_file();

   if (!CNF(oc_listen_cnt))
      add_listener(def);

   // start socket receiver thread
   run_ocat_thread("receiver", socket_receiver, NULL);
   // create listening socket and start socket acceptor
   if (CNF(oc_listen_cnt) > 0)
      run_ocat_thread("acceptor", socket_acceptor, NULL);
   else
      log_msg(LOG_INFO, "acceptor not started");
   // starting socket cleaner
   run_ocat_thread("cleaner", socket_cleaner, NULL);

   // getting passwd info for user
   log_debug("getting user info for \"%s\"", CNF(usrname));
#ifdef HAVE_GETPWNAM_R
   c = getpwnam_r(CNF(usrname), &pwdm, pwdbuf, SIZE_1K, &pwd);
#else
   if ((pwd = getpwnam(CNF(usrname))) == NULL)
      c = errno;
#endif
   if (!pwd)
   {
      log_msg(LOG_WARNING, "can't get information for user \"%s\": \"%s\", defaulting to uid %d",
            CNF(usrname), c ? strerror(c) : "user not found", OCAT_UNPRIV_UID);
      // if no passwd entry exists then default to some unprivileged user
      memset(&pwdm, 0, sizeof(pwdm));
      pwd = &pwdm;
      pwd->pw_name = OCAT_UNPRIV_UNAME;
      pwd->pw_uid = OCAT_UNPRIV_UID;
      pwd->pw_gid = OCAT_UNPRIV_UID;
      CNF(usrname) = pwd->pw_name;
      log_msg(LOG_NOTICE, "disabling connect log");
      CNF(create_clog) = 0;
   }

   if (!CNF(runasroot) && !getuid())
   {
      log_msg(LOG_INFO, "running as root, changing uid/gid to %s (uid %d/gid %d)", CNF(usrname), pwd->pw_uid, pwd->pw_gid);
      if (setgid(pwd->pw_gid))
         log_msg(LOG_ERR, "could not change gid: \"%s\"", strerror(errno)), exit(1);
      if (setuid(pwd->pw_uid))
         log_msg(LOG_ERR, "could not change uid: \"%d\"", strerror(errno)), exit(1);
   }
   log_debug("uid/gid = %d/%d", getuid(), getgid());

   if (CNF(create_clog))
      open_connect_log(pwd->pw_dir);

   // create socks connector thread and communication queue
   if (pipe(CNF(socksfd)) == -1)
      log_msg(LOG_EMERG, "couldn't create socks connector pipe: \"%s\"", strerror(errno)), exit(1);
   if (CNF(socks_dst)->sin_family)
      run_ocat_thread("connector", socks_connector_sel, NULL);
   else
      log_msg(LOG_INFO, "connector not started");

#ifdef PACKET_QUEUE
   // start packet dequeuer
   run_ocat_thread("dequeuer", packet_dequeuer, NULL);
#endif
   // start controller socket thread
   if (CNF(controller))
      run_ocat_thread("controller", ocat_controller, NULL);

#ifdef WITH_LOOPBACK_RESPONDER
   // starting loopback responder
   run_ocat_thread("lloopback", local_loopback_responder, NULL);
   add_remote_loopback_route();
#endif

   // install signal handler
   install_sig();

   // start forwarding packets from tunnel
   log_msg(LOG_INFO, "starting packet forwarder");
   packet_forwarder();

   // initiate termination
   cleanup_system();

   log_msg(LOG_INFO, "Thanks for using OnionCat. Good Bye!");

   // delete main thread's struct
   free((OcatThread_t*) get_thread());
   return 0;
}

