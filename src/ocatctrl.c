/* Copyright 2008-2023 Bernhard R. Fischer.
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

/*! \file ocatctrl.c
 *  This file contains all functions for local controller interface.
 *
 *  \author Bernhard Fischer <bf@abenteuerland.at>
 *  \version 2023/01/24
 */


#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"
#include "ocatfdbuf.h"

#define MAX_COMMANDS 32


typedef struct ctrl_data
{
   int display_prompt;
} ctrl_data_t;


typedef struct ctrl_cmd
{
   const char *cmd;
   int (*func)(fdbuf_t*, int, char**);
   int min_argc;
} ctrl_cmd_t;



#ifdef WITH_DNS_RESOLVER
static const char *code_str(int code)
{
   switch (code)
   {
      case 0:
         return "OK";
      case OCRES_ENXDOMAIN:
         return "NXDOMAIN";
      default:
         return "ERROR";
   }
}


void ctrl_ns_response(void *p, struct in6_addr addr, int code)
{
   char buf[256], name[128], in6[INET6_ADDRSTRLEN];
   int source;
   time_t age;
   if (!code)
   {
      if (hosts_get_name_ext(&addr, name, sizeof(name), &source, &age) == -1)
         snprintf(buf, sizeof(buf), "response received, code = %s (%d), hosts_get_name_ext() failed!\n", code_str(code), code);
      else
         snprintf(buf, sizeof(buf), "%s %s # age = %ld, src = %d\n", inet_ntop(AF_INET6, &addr, in6, sizeof(in6)), name, (long) age, source);
   }
   else
   {
      snprintf(buf, sizeof(buf), "response received, code = %s (%d)\n", code_str(code), code);
   }
   write((long) p, buf, strlen(buf));
}
#endif


long unit_scale0(int depth, long n, const char **unit)
{
   static const char *units_[] = {"", "K", "M", "G", "T"};

   *unit = units_[depth];
   if (n <= 10240)
      return n;

   depth++;
   if (depth >= (int) (sizeof(units_) / sizeof(*units_)))
      return n;

   return unit_scale0(depth, n >> 10, unit);
}


long unit_scale(long n, const char **unit)
{
   return unit_scale0(0, n, unit);
}


int ctrl_cmd_random_write(fdbuf_t *fdb, int UNUSED(argc), char **argv)
{
   char *buf;
   int i;

   int fd = atoi(argv[1]);
   int n = atoi(argv[2]);

   if (fd < 0)
   {
      log_msg_fd(fdb->fd, LOG_ERR, "fd must be >= 0");
      return -1;
   }
   if (n < 1)
   {
      log_msg_fd(fdb->fd, LOG_ERR, "n must be > 0");
      return -1;
   }

   if ((buf = malloc(n)) == NULL)
   {
      log_msg_fd(fdb->fd, LOG_ERR, "cannot get %d bytes of memory", n);
      return -1;
   }

   for (i = 0; i < n; i++)
      buf[i] = rand();

   log_msg_fd(fdb->fd, LOG_INFO, "writing %d random bytes to fd %d", n, fd);
   n = write(fd, buf, n);
   if (n == -1)
   {
      n = errno;
      log_msg_fd(fdb->fd, LOG_ERR, "write failed: %s", strerror(n));
   }
   log_msg_fd(fdb->fd, LOG_INFO, "%d bytes written", n);

   free(buf);
   return 1;
}


int ctrl_cmd_usage(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   dprintf(fdb->fd,
         "commands:\n"
         "exit | quit .... exit from control interface\n"
         "terminate ...... terminate OnionCat\n"
         "close <n> ...... close file descriptor <n> of a peer\n"
#ifdef WITH_DNS_RESOLVER
         "dig <ipv6> ..... Do a hostname lookup.\n"
#endif
         "hosts .......... list hosts database\n"
         "hreload ........ reload hosts database\n"
         "status [detail]. list peer status\n"
         "threads ........ show active threads\n"
         "route .......... show routing table\n"
         "route <dst IP> <netmask> <IPv6 gw>\n"
         "   ............. add route to routing table\n"
         "connect <.onion-URL> [\"perm\"]\n"
         "   ............. connect to a hidden service. if \"perm\" is set,\n"
         "   ............. connection will stay open forever\n"
         "macs ........... show MAC address table\n"
         "ns ............. List OnionCat peer nameservers.\n"
         "queue .......... list pending SOCKS connections\n"
         "setup .......... show internal setup struct\n"
         "version ........ show version\n"
         "write <f> <n> .. write n random bytes to fd f\n"
         );

   return 1;
}


int ctrl_cmd_status(fdbuf_t *fdb, int argc, char **argv)
{
   char addrstr[INET6_ADDRSTRLEN], addrstr2[INET6_ADDRSTRLEN], onionstr[SIZE_256], timestr[32];
   struct tm *tm;
   OcatPeer_t *peer;
   int detail = 0;
   long in, out;
   const char *u[2];

   if (argc > 1)
   {
      if (!strcmp("detail", argv[1]))
         detail = 1;
      else
         log_msg_fd(fdb->fd, LOG_WARNING, "unknown parameter \"%s\"", argv[1]);
   }

   lock_peers();
   for (peer = get_first_peer(); peer; peer = peer->next)
   {
      if (IN6_IS_ADDR_UNSPECIFIED(&peer->addr))
      {
         strcpy(onionstr, "--unidentified--");
      }
      else
      {
         if (hosts_get_name(&peer->addr, onionstr, sizeof(onionstr)) < 0)
            ipv6tonion(&peer->addr, onionstr);
      }

      // FIXME: should peer be locked?
      if (peer->state == PEER_ACTIVE)
      {
         in = unit_scale(peer->in, &u[0]);
         out = unit_scale(peer->out, &u[1]);

         if (detail)
         {
         tm = localtime(&peer->otime);
         strftime(timestr, sizeof(timestr), "%c", tm);
         dprintf(fdb->fd, "[%s]\n fd = %d\n addr = %s\n dir = \"%s\" (%d)\n idle = %lds\n bytes_in = %ld (%ld%s)\n bytes_out = %ld (%ld%s)\n setup_delay = %lds\n opening_time = \"%s\"\n conn_type = \"%s\" (%d)\n rand = 0x%08x\n saddr = %s\n sname = \"%s\"\n",
               onionstr, peer->tcpfd,
               inet_ntop(AF_INET6, &peer->addr, addrstr, INET6_ADDRSTRLEN),
               peer->dir == PEER_INCOMING ? "IN" : "OUT", peer->dir,
               (long) (time(NULL) - peer->time), peer->in, in, u[0], peer->out, out, u[1], (long) peer->sdelay, timestr,
               peer->perm ? "PERMANENT" : "TEMPORARY", peer->perm, peer->rand,
               inet_ntop(AF_INET6, &peer->saddr, addrstr2, sizeof(addrstr2)), peer->sname
               );
         }
         else
         {
            dprintf(fdb->fd, "fd = %d, addr = %s, saddr = %s, idle = %ld, bytes_in = %ld%s, bytes_out = %ld%s, name = \"%s\"\n",
                  peer->tcpfd,
                  inet_ntop(AF_INET6, &peer->addr, addrstr, sizeof(addrstr)),
                  inet_ntop(AF_INET6, &peer->saddr, addrstr2, sizeof(addrstr2)),
                  time(NULL) - peer->time, in, u[0], out, u[1], onionstr
                  );
         }
      }
   }
   unlock_peers();
   return 1;
}
 

int ctrl_cmd_exit(fdbuf_t *UNUSED(fdb), int UNUSED(argc), char **UNUSED(argv))
{
   return 0;
}


int ctrl_cmd_dig(fdbuf_t *fdb, int UNUSED(argc), char **argv)
{
   struct in6_addr in6;

   if (inet_pton(AF_INET6, argv[1], &in6) != 1)
   {
      log_msg_fd(fdb->fd, LOG_ERR, "param is no valid IPv6 address");
      return -1;
   }

   int n = ocres_query_callback(&in6, ctrl_ns_response, (void*)(long) fdb->fd);
   if (n >= 0)
      log_msg_fd(fdb->fd, LOG_INFO, "PTR query sent to %d nameservers", n);
   else
      log_msg_fd(fdb->fd, LOG_ERR, "ocres_query() failed");

   return 1;
}


int ctrl_cmd_close(fdbuf_t *fdb, int UNUSED(argc), char **argv)
{
   OcatPeer_t *peer;

   int fd = atoi(argv[1]);

   lock_peers();
   for (peer = get_first_peer(); peer; peer = peer->next)
      if (peer->tcpfd == fd)
      {
         oe_close(fd);
         delete_peer(peer);
         log_msg(LOG_INFO | LOG_FCONN, "%d was successfully closed up on user request", fd);
         break;
      }

   if (!peer)
   {
      log_msg_fd(fdb->fd, LOG_INFO, "no peer with fd %d exists", fd);
   }

   unlock_peers();
   return 1;
}
 

int ctrl_cmd_threads(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   char buf[4096];

   snprint_threads(buf, sizeof(buf), "\n");
   dprintf(fdb->fd, "%s", buf);
   return 1;
}


int ctrl_cmd_term(fdbuf_t *UNUSED(fdb), int UNUSED(argc), char **UNUSED(argv))
{
   set_term_req();
   return 1;
}


int ctrl_cmd_kill(fdbuf_t *UNUSED(fdb), int UNUSED(argc), char **UNUSED(argv))
{
   log_msg(LOG_NOTICE, "exit by controller request");
   exit(0);
}


int ctrl_cmd_route(fdbuf_t *fdb, int argc, char **argv)
{
   char *s;
   int c;

   if (argc == 1)
   {
      print_routes(fdb->fd);
      ipv6_print_routes(fdb->fd);
      return 1;
   }

   if (argc != 4)
   {
      log_msg_fd(fdb->fd, LOG_ERR, "ill args");
      return -1;
   }

   if ((c = ipv4_add_route_a(argv[1], argv[2], argv[3])) == E_RT_SYNTAX)
      if ((c = ipv6_add_route_a(argv[1], argv[2], argv[3])) > 0)
         c = 0;

   switch (c)
   {
      case E_RT_NOTORGW:
         s = "gateway has not TOR prefix";
         break;

      case E_RT_ILLNM:
         s = "illegal netmask or prefix length";
         break;

      case E_RT_DUP:
         s = "route already exists";
         break;

      case E_RT_GWSELF:
         s = "gateway points to me";
         break;

      default:
         s = "";
   }

   if (c)
      log_msg_fd(fdb->fd, LOG_ERR, "%d %s", c, s);

   return 1;
}


int ctrl_cmd_macs(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   print_mac_tbl(fdb->fd);
   return 1;
}


int ctrl_cmd_queue(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   char buf[4096];
   int fd[2], len;

   if (pipe(fd) == -1)
   {
      log_msg(LOG_ERR, "could not create pipe: %s", strerror(errno));
      return -1;
   }

   print_socks_queue(fd[1]);
   for (int e = 0; !e;)
   {
      len = read(fd[0], buf, sizeof(buf));
      log_debug("read %d bytes on pipe %d", len, fd[0]);

      if (!len)
         break;
      if (len == -1)
         log_msg(LOG_ERR, "pipe read failed: %s", strerror(errno));

      if (!buf[len - 1])
      {
         len--;
         e++;
      }
      write(fdb->fd, buf, len);
   }

   oe_close(fd[0]);
   oe_close(fd[1]);
   return 1;
}


int ctrl_cmd_setup(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   print_setup_struct(fdb->fd);
   return 1;
}


int ctrl_cmd_version(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   dprintf(fdb->fd, "%s\n", CNF(version));
   return 1;
}


int ctrl_cmd_hosts(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   hosts_list(fdb->fd);
   return 1;
}


int ctrl_cmd_hreload(fdbuf_t *UNUSED(fdb), int UNUSED(argc), char **UNUSED(argv))
{
   hosts_check();
   return 1;
}


int ctrl_cmd_connect(fdbuf_t *fdb, int argc, char **argv)
{
   struct in6_addr in6;
   int perm = 0;

   if (validate_onionname(argv[1], &in6) == -1)
   {
      log_msg_fd(fdb->fd, LOG_ERR, "\"%s\" not a valid .onion-URL", argv[1]);
      return -1;
   }

   if (argc > 2 && !strcmp("perm", argv[2]))
      perm = 1;

   socks_queue(in6, perm);
   return 1;
}


int ctrl_cmd_ns(fdbuf_t *fdb, int UNUSED(argc), char **UNUSED(argv))
{
   print_ns(fdb->fd);
   return 1;
}


static ctrl_cmd_t cmd_[] =
{
   {"help", ctrl_cmd_usage, 1},
   {"status", ctrl_cmd_status, 1},
   {"exit", ctrl_cmd_exit, 1},
   {"quit", ctrl_cmd_exit, 1},
   {"dig", ctrl_cmd_dig, 2},
   {"close", ctrl_cmd_close, 2},
   {"write", ctrl_cmd_random_write, 3},
   {"threads", ctrl_cmd_threads, 1},
   {"terminate", ctrl_cmd_term, 1},
   {"kill", ctrl_cmd_kill, 1},
   {"route", ctrl_cmd_route, 1},
   {"macs", ctrl_cmd_macs, 1},
   {"queue", ctrl_cmd_queue, 1},
   {"setup", ctrl_cmd_setup, 1},
   {"version", ctrl_cmd_version, 1},
   {"hosts", ctrl_cmd_hosts, 1},
   {"hreload", ctrl_cmd_hreload, 1},
   {"connect", ctrl_cmd_connect, 1},
   {"ns", ctrl_cmd_ns, 1},

   {NULL, NULL, 0}
};


/*! Parse command line into argv array. As usual, the last entry in the list of
 * arguments will be NULL.
 * @param argv Array of char pointers.
 * @param maxv Number of array elements, should be at least >= 2.
 * @param buf Buffer to parse.
 * @return Returns the number of elements found excluding the terminating NULL
 * element. In case of error, -1 is returned. The only error condition is that
 * maxc was < 2.
 */
int ctrl_parse_cmd(char **argv, int maxv, char *buf)
{
   const char *delim = " \r\n";
   char *eptr;
   int argc;

   // safety ceck
   if (maxv < 2)
      return -1;
   maxv -= 2;

   if ((*argv = strtok_r(buf, delim, &eptr)) == NULL)
      return 0;

   for (argc = 1, argv++; maxv; maxv--, argv++, argc++)
   {
      if ((*argv = strtok_r(NULL, delim, &eptr)) == NULL)
         break;
   }
   *argv = NULL;

   return argc;
}


int ctrl_exec(fdbuf_t *fdb, int argc, char **argv)
{
   ctrl_cmd_t *cmd;

   for (cmd = cmd_; cmd->cmd != NULL; cmd++)
      if (!strcmp(cmd->cmd, argv[0]))
      {
         if (argc < cmd->min_argc)
         {
            log_msg_fd(fdb->fd, LOG_ERR, "missing args");
            return -1;
         }
         return cmd->func(fdb, argc, argv);
      }

   log_msg_fd(fdb->fd, LOG_ERR, "unknown command \"%s\"", argv[0]);
   return 1;
}


int ctrl_proc_line(fdbuf_t *fdb, char *buf)
{
#define MAX_CTRL_ARGV 10
   char *argv[MAX_CTRL_ARGV];
   int argc;

   if ((argc = ctrl_parse_cmd(argv, MAX_CTRL_ARGV, buf)) <= 0)
      return 1;

   return ctrl_exec(fdb, argc, argv);
}


int ctrl_loop(fdbuf_t *fdb, ctrl_data_t *cd)
{
   fd_set rset;
   int len;
   char buf[1024];

   update_thread_activity();
   if (term_req())
      return 0;

   // command line prompt
   if (cd->display_prompt)
   {
      cd->display_prompt = 0;
      dprintf(fdb->fd, "%s> ", CNF(onion_url));
   }

   // get and handle data from buffer if available
   if ((len = fd_bufgets(fdb, buf, sizeof(buf))) > 0)
   {
      cd->display_prompt = 1;
      return ctrl_proc_line(fdb, buf);
   }

   FD_ZERO(&rset);
   FD_SET(fdb->fd, &rset);

   // wait for data
   switch (oc_select(fdb->fd + 1, &rset, NULL, NULL))
   {
      // timeout
      case 0:
         return 1;

      // check error
      case -1:
         // interrupted
         if (errno == EINTR)
            return -1;
         // other errors
         return 0;
   }

   // read data into buffer
   len = fd_fill(fdb);
   //check EOF
   if (!len)
   {
      log_msg(LOG_INFO, "EOF received on fd %d", fdb->fd);
      return 0;
   }
   // check error
   if (len == -1)
   {
      log_msg(LOG_ERR, "read failed on %d: %s", fdb->fd, strerror(errno));
      return 0;
   }

   return 1;
}


/*! ctrl_handler handles connections to local control port.
 *  @param p void* typcasted to int contains fd of connected socket.
 *  @return Currently always returns NULL.
 */
void *ctrl_handler(void *p)
{
   ctrl_data_t cd;
   fdbuf_t fdb;

   detach_thread();

   memset(&cd, 0, sizeof(cd));
   cd.display_prompt = 1;
   fd_init(&fdb, (intptr_t) p);

   lock_setup();
   CNF(ctrl_active)++;
   unlock_setup();

   set_thread_ready();

   dprintf(fdb.fd, "%s\n", CNF(version));

   while (ctrl_loop(&fdb, &cd));

   dprintf(fdb.fd, "Good bye!\n");

   lock_setup();
   CNF(ctrl_active)--;
   unlock_setup();

   oe_close(fdb.fd);
   return NULL;
}


int run_ctrl_handler(int fd)
{
   // check number of controller sessions
   // FIXME: listener should be closed or acceptor delayed instead of
   // counting after session acceptance.
   lock_setup();
   if (CNF(ctrl_active) >= CNF(max_ctrl))
   {
      log_msg(LOG_WARNING, "maximum number of controller sessions reached");
      oe_close(fd);
      fd = -1;
   }
   unlock_setup();
   if (fd == -1)
      return -1;

   return (int) run_ocat_thread("ctrl_handler", ctrl_handler, (void*) (long) fd);
}


void *ocat_controller(void *UNUSED(p))
{
   if (run_listeners(CNF(ctrl_listen), CNF(ctrl_listen_fd), CNF(ctrl_listen_cnt), run_ctrl_handler) == -1)
      log_msg(LOG_WARNING, "could not start controller");
   return NULL;
}

