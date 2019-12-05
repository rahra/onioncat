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

/*! @file
 *  Contains functions for local controller interface.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */


#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"


/*! ctrl_handler handles connections to local control port.
 *  @param p void* typcasted to int contains fd of connected socket.
 *  @return Currently always returns NULL.
 *
 *  FIXME: ctrl_handler probably is not thread-safe.
 */
void *ctrl_handler(void *p)
{
   int fd, c;
   FILE *ff, *fo;
   char buf[FRAME_SIZE], addrstr[INET6_ADDRSTRLEN], onionstr[NDESC(name_size)], timestr[32], *s, *tokbuf, *bufp;
   int rlen, cfd;
   struct tm *tm;
   OcatPeer_t *peer;
   struct in6_addr in6;
   int pfd[2];

   detach_thread();

   if (pipe(pfd) == -1)
      log_msg(LOG_EMERG, "couldn't create pipe: \"%s\"", strerror(errno)), exit(1);

   fd = (long) p;
   if (CNF(config_read))
   {
      if (!(ff = fdopen(fd, "r+")))
      {
         log_msg(LOG_ERR, "could not open %d for writing: %s", fd, strerror(errno));
         oe_close(pfd[0]);
         oe_close(pfd[1]);
         return NULL;
      }
      log_debug("fd %d fdopen'ed \"r+\"", fd);
      fo = ff;
      if (setvbuf(ff, NULL, _IONBF, 0))
         log_msg(LOG_ERR, "could not setup line buffering: %s", strerror(errno));
   }
   else
   {
      if (!(ff = fdopen(fd, "r")))
      {
         log_msg(LOG_ERR, "could not open %d for reading: %s", fd, strerror(errno));
         CNF(config_read) = 1;
         oe_close(pfd[0]);
         oe_close(pfd[1]);
         return NULL;
      }
      log_debug("fd %d fdopen'ed \"r\"", fd);
      fo = CNF(logf) ? CNF(logf) : stderr;
      //CNF(config_read) = 1;
   }

   lock_setup();
   CNF(ctrl_active)++;
   unlock_setup();

   fprintf(fo, "%s\n", CNF(version));
   fprintf(fo, "*** ATTENTION! Controller interface not thread-safe yet! Usage could cause deadlocks. ***\n");

   for (;;)
   {
      if (CNF(config_read))
         fprintf(fo, "%s> ", CNF(onion_url));

      c = getc(ff);
      if (c == EOF)
      {
         log_debug("EOF received.");
         break;
      }
      else if (c == 4)
      {
         log_debug("^D received.");
         break;
      }
      else if (c == 0x1b)
      {
         log_debug("ESC received");
         if (ungetc(c, ff) == EOF)
         {
            log_debug("received EOF on ungetc");
            break;
         }
      }
      else
      {
         if (ungetc(c, ff) == EOF)
         {
            log_debug("received EOF on ungetc");
            break;
         }
      }

      if (!fgets(buf, FRAME_SIZE, ff))
      {
         if (!feof(ff))
            log_msg(LOG_ERR, "error reading from %d");
         break;
      }

#ifdef DEBUG
      for (c = 0; c < strlen(buf); c++)
         snprintf(&buf[strlen(buf) + 2 + c * 3], FRAME_SIZE - strlen(buf) - 2 - c * 3, "%02x ", buf[c]);
      log_debug("xenc input buf: %s", &buf[strlen(buf) + 2]);
#endif 

      if (!(rlen = oe_remtr(buf)))
         continue;

      if (!(bufp = strtok_r(buf, " \t\r\n", &tokbuf)))
         continue;

      // "exit"/"quit" => terminate thread
      if (!strncmp(bufp, "exit", 4) || !strncmp(bufp, "quit", 4))
         break;
      // "status"
      else if (!strcmp(bufp, "status"))
      {
         lock_peers();
         for (peer = get_first_peer(); peer; peer = peer->next)
            // FIXME: should peer be locked?
            if (peer->state == PEER_ACTIVE)
            {
               tm = localtime(&peer->otime);
               strftime(timestr, 32, "%c", tm);
               fprintf(fo, "[%s]\n fd = %d\n addr = %s\n dir = \"%s\" (%d)\n idle = %lds\n bytes_in = %ld\n bytes_out = %ld\n setup_delay = %lds\n opening_time = \"%s\"\n conn type = \"%s\" (%d)\n rand = 0x%08x\n",
                     IN6_IS_ADDR_UNSPECIFIED(&peer->addr) ? "--unidentified--" : ipv6tonion(&peer->addr, onionstr), peer->tcpfd,
                     inet_ntop(AF_INET6, &peer->addr, addrstr, INET6_ADDRSTRLEN),
                     peer->dir == PEER_INCOMING ? "IN" : "OUT", peer->dir,
                     (long) (time(NULL) - peer->time), peer->in, peer->out, (long) peer->sdelay, timestr,
                     peer->perm ? "PERMANENT" : "TEMPORARY", peer->perm, peer->rand
                     );
            }
         unlock_peers();
      }
      else if (!strcmp(bufp, "close"))
      {
         cfd = atoi(bufp +6);
         lock_peers();
         for (peer = get_first_peer(); peer; peer = peer->next)
            if (peer->tcpfd == cfd)
            {
               oe_close(cfd);
               delete_peer(peer);
               log_msg(LOG_INFO | LOG_FCONN, "%d was successfully closed up on user request", cfd);
               break;
            }
         if (!peer)
         {
            log_msg(LOG_INFO, "no peer with fd %d exists\n", cfd);
            fprintf(fo, "no peer with fd %d exists\n", cfd);
         }
         unlock_peers();
      }
      else if (!strcmp(bufp, "threads"))
      {
         print_threads(ff);
      }
      else if (!strcmp(bufp, "terminate"))
      {
         log_msg(LOG_INFO, "terminate request from control port");
         kill(getpid(), SIGINT);
      }
      else if (!strcmp(bufp, "route"))
      {
         if (rlen > 6)
         {
            if ((c = parse_route(bufp + 6)) == E_RT_SYNTAX)
               if ((c = ipv6_parse_route(bufp + 6)) > 0)
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
               fprintf(ff, "ERR %d %s\n", c, s);
         }
         else
         {
            print_routes(fo);
            ipv6_print_routes(fo);
         }
      }
      else if (!strcmp(bufp, "connect"))
      {
         if ((s = strtok_r(NULL, " \t\r\n", &tokbuf)))
         {
            if ((strlen(s) != 16) || (oniontipv6(s, &in6) == -1))
               fprintf(ff, "ERR \"%s\" not valid .onion-URL\n", bufp + 8);
            else
            {
               if (!(s = strtok_r(NULL, " \t\r\n", &tokbuf)))
                  socks_queue(in6, 0);
               else if (!strcmp(s, "perm"))
                  socks_queue(in6, 1);
               else
                  fprintf(ff, "ERR unknown param \"%s\"\n", s);
            }
         }
         else
            fprintf(ff, "ERR missing args\n");
      }
      else if (!strcmp(bufp, "macs"))
      {
         print_mac_tbl(ff);
      }
      else if (!strcmp(bufp, "queue"))
      {
         print_socks_queue((FILE*) (long) pfd[1]);
         for (;;)
         {
            read(pfd[0], buf, 1);
            if (!buf[0])
               break;
            fprintf(ff, "%c", buf[0]);
         }
      }
      else if (!strcmp(bufp, "setup"))
      {
         print_setup_struct(ff);
      }
      else if (!strcmp(bufp, "version"))
      {
         fprintf(ff, "%s\n", CNF(version));
      }
      else if (!strcmp(bufp, "hosts"))
      {
         hosts_list(ff);
      }
      else if (!strcmp(bufp, "hreload"))
      {
         hosts_check();
      }
      else if (!strcmp(bufp, "help") || !strcmp(bufp, "?"))
      {
         fprintf(fo,
               "commands:\n"
               "exit | quit .... exit from control interface\n"
               "terminate ...... terminate OnionCat\n"
               "close <n> ...... close file descriptor <n> of a peer\n"
               "hosts .......... list hosts database\n"
               "hreload ........ reload hosts database\n"
               "status ......... list peer status\n"
               "threads ........ show active threads\n"
               "route .......... show routing table\n"
               "route <dst IP> <netmask> <IPv6 gw>\n"
               "   ............. add route to routing table\n"
               "connect <.onion-URL> [\"perm\"]\n"
               "   ............. connect to a hidden service. if \"perm\" is set,\n"
               "   ............. connection will stay open forever\n"
               "macs ........... show MAC address table\n"
               "queue .......... list pending SOCKS connections\n"
               "setup .......... show internal setup struct\n"
               "version ........ show version\n"
               );
      }
      else
      {
         fprintf(fo, "ERR unknown command: \"%s\"\n", buf);
      }
   }

   if (CNF(config_read))
      fprintf(fo, "Good bye!\n");
   log_msg(LOG_INFO | LOG_FCONN, "closing session %d", fd);
   if (fclose(ff) == EOF)
      log_msg(LOG_ERR, "error closing control stream: \"%s\"", strerror(errno));
   // fclose also closes the fd according to the man page

   if (!CNF(config_read))
      CNF(config_read) = 1;

   // close pipe
   oe_close(pfd[0]);
   oe_close(pfd[1]);

   lock_setup();
   CNF(ctrl_active)--;
   unlock_setup();

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


void *ocat_controller(void *p)
{
   run_listeners(CNF(ctrl_listen), CNF(ctrl_listen_fd), CNF(ctrl_listen_cnt), run_ctrl_handler);
   return NULL;
}

