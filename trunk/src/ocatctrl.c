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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>

#include "ocat.h"

//! file descriptors of control port
static int ctrlfd_[2];


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
   char buf[FRAME_SIZE], addrstr[INET6_ADDRSTRLEN], onionstr[ONION_NAME_SIZE], timestr[32], *s, *tokbuf;
   int rlen, cfd;
   struct tm *tm;
   OcatThread_t *th;
   OcatPeer_t *peer;
   struct in6_addr in6;

   if ((rlen = pthread_detach(pthread_self())))
      log_msg(LOG_ERR, "thread couldn't self-detach: \"%s\"", strerror(rlen));

   fd = (int) p;
   if (CNF(config_read))
   {
      if (!(ff = fdopen(fd, "r+")))
      {
         log_msg(LOG_ERR, "could not open %d for writing: %s", fd, strerror(errno));
         return NULL;
      }
      log_debug("fd %d fdopen'ed \"r+\"", fd);
      fo = ff;
   }
   else
   {
      if (!(ff = fdopen(fd, "r")))
      {
         log_msg(LOG_ERR, "could not open %d for reading: %s", fd, strerror(errno));
         CNF(config_read) = 1;
         return NULL;
      }
      log_debug("fd %d fdopen'ed \"r\"", fd);
      fo = CNF(logf);
      //CNF(config_read) = 1;
   }

   fprintf(fo, "%s (c) %s -- %s %s\n", PACKAGE_STRING, OCAT_AUTHOR, __DATE__, __TIME__);
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

      if (!(rlen = oe_remtr(buf)))
         continue;

      if (!strtok_r(buf, " \t\r\n", &tokbuf))
         continue;

      // "exit"/"quit" => terminate thread
      if (!strncmp(buf, "exit", 4) || !strncmp(buf, "quit", 4))
         break;
      // "status"
      else if (!strcmp(buf, "status"))
      {
         lock_peers();
         for (peer = get_first_peer(); peer; peer = peer->next)
            // FIXME: should peer be locked?
            if (peer->state == PEER_ACTIVE)
            {
               tm = localtime(&peer->otime);
               strftime(timestr, 32, "%c", tm);
               fprintf(fo, "[%s]\n fd = %d\n addr = %s\n dir = \"%s\" (%d)\n idle = %lds\n bytes_in = %ld\n bytes_out = %ld\n setup_delay = %lds\n opening_time = \"%s\"\n conn type = \"%s\" (%d)\n",
                     IN6_IS_ADDR_UNSPECIFIED(&peer->addr) ? "--unidentified--" : ipv6tonion(&peer->addr, onionstr), peer->tcpfd,
                     inet_ntop(AF_INET6, &peer->addr, addrstr, INET6_ADDRSTRLEN),
                     peer->dir == PEER_INCOMING ? "IN" : "OUT", peer->dir,
                     time(NULL) - peer->time, peer->in, peer->out, peer->sdelay, timestr,
                     peer->perm ? "PERMANENT" : "TEMPORARY", peer->perm
                     );
            }
         unlock_peers();
      }
      else if (!strcmp(buf, "close"))
      {
         cfd = atoi(&buf[6]);
         lock_peers();
         for (peer = get_first_peer(); peer; peer = peer->next)
            if (peer->tcpfd == cfd)
            {
               log_msg(LOG_INFO | LOG_FCONN, "close request for %d", cfd);
               oe_close(cfd);
               delete_peer(peer);
               break;
            }
         if (!peer)
         {
            log_msg(LOG_INFO, "no peer with fd %d exists\n", cfd);
            fprintf(fo, "no peer with fd %d exists\n", cfd);
         }
         unlock_peers();
      }
      else if (!strcmp(buf, "threads"))
      {
         pthread_mutex_lock(&thread_mutex_);
         for (th = octh_; th; th = th->next)
            fprintf(ff, "%2d: %s\n", th->id, th->name);
         pthread_mutex_unlock(&thread_mutex_);
      }
      else if (!strcmp(buf, "terminate"))
      {
         log_msg(LOG_INFO, "terminate request from control port");
         //FIXME: fds should be closed properly
         exit(0);
      }
      else if (!strcmp(buf, "fds"))
      {
         fprintf(fo, "acceptor sockets: %d/%d\nconntroller sockets: %d/%d\n", sockfd_[0], sockfd_[1], ctrlfd_[0], ctrlfd_[1]);
      }
      else if (!strcmp(buf, "route"))
      {
         if (rlen > 6)
         {
            if ((c = parse_route(&buf[6])) == E_RT_SYNTAX)
               if ((c = ipv6_parse_route(&buf[6])) > 0)
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
      else if (!strcmp(buf, "connect"))
      {
         if ((s = strtok_r(NULL, " \t\r\n", &tokbuf)))
         {
            if ((strlen(s) != 16) || (oniontipv6(s, &in6) == -1))
               fprintf(ff, "ERR \"%s\" not valid .onion-URL\n", &buf[8]);
            else
            {
               if (!(s = strtok_r(NULL, " \t\r\n", &tokbuf)))
                  socks_queue(&in6, 0);
               else if (!strcmp(s, "perm"))
                  socks_queue(&in6, 1);
               else
                  fprintf(ff, "ERR unknown param \"%s\"\n", s);
            }
         }
         else
            fprintf(ff, "ERR missing args\n");
      }
      else if (!strcmp(buf, "macs"))
      {
         print_mac_tbl(ff);
      }
      else if (!strcmp(buf, "setup"))
      {
         print_setup_struct(ff);
      }
      else if (!strcmp(buf, "version"))
      {
         fprintf(ff, "%s (c) Bernhard R. Fischer -- compiled %s %s\n", PACKAGE_STRING, __DATE__, __TIME__);
      }
      else if (!strcmp(buf, "help") || !strcmp(buf, "?"))
      {
         fprintf(fo,
               "commands:\n"
               "exit | quit .... exit from control interface\n"
               "terminate ...... terminate OnionCat\n"
               "close <n> ...... close file descriptor <n> of a peer\n"
               "status ......... list peer status\n"
               "threads ........ show active threads\n"
               "fds ............ show open file descriptors (w/o peers)\n"
               "route .......... show routing table\n"
               "route <dst IP> <netmask> <IPv6 gw>\n"
               "   ............. add route to routing table\n"
               "connect <.onion-URL> [\"perm\"]\n"
               "   ............. connect to a hidden service. if \"perm\" is set,\n"
               "   ............. connection will stay open forever\n"
               "macs ........... show MAC address table\n"
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

   return NULL;
}


int run_ctrl_handler(int fd)
{
   return (int) run_ocat_thread("ctrl_handler", ctrl_handler, (void*) fd);
}


void *ocat_controller(void *p)
{
   run_local_listeners(CNF(ocat_ctrl_port), ctrlfd_, run_ctrl_handler);
   return NULL;
}

