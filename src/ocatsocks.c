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

/*! ocatsocks.c
 *  Contains functions for connecting to TOR via SOCKS.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

/* SOCKS5 is defined in RFC1928 */

#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"


// SOCKS connector queue vars
static SocksQueue_t *socks_queue_ = NULL;

#define SOCKS_MIN_BUFLEN (sizeof(SocksHdr_t) + NDESC(name_size) + strlen(CNF(usrname)) + 2)
#define SOCKS_BUFLEN (SOCKS_MIN_BUFLEN + NI_MAXHOST + 32)


static void get_hostname(const SocksQueue_t *sq, char *onion, int onion_size)
{
   int ret = -1;

   // Do a hostname lookup if option set.
   // This is done in order to be able to retrieve a 256 bit base32 
   // host from e.g. /etc/hosts.
   if (CNF(hosts_lookup))
   {
      hosts_check();
      ret = hosts_get_name(&sq->addr, onion, onion_size);
   }

   // If no hostname was found above or network type is Tor
   // do usual OnionCat name transformation.
   if (ret == -1)
   {
      ipv6tonion(&sq->addr, onion);
      strlcat(onion, CNF(domain), onion_size);
   }
}


int socks_send_request(const SocksQueue_t *sq)
{
   int len, ret = -1;
   char buf[SOCKS_BUFLEN], onion[NI_MAXHOST];
   SocksHdr_t *shdr = (SocksHdr_t*) buf;

   get_hostname(sq, onion, sizeof(onion));

   log_debug("SOCKS_BUFLEN = %d, NI_MAXHOST = %d", SOCKS_BUFLEN, NI_MAXHOST);
   if (inet_ntop(AF_INET6, &sq->addr, buf, sizeof(buf)) == NULL)
   {
      log_msg(LOG_WARNING, "inet_ntop failed: \"%s\"", strerror(errno));
      buf[0] = '\0';
   }
   log_msg(LOG_INFO, "trying to connect to \"%s\" [%s] on %d", onion, buf, sq->fd);

   log_debug("doing SOCKS4a handshake");
   shdr->ver = 4;
   shdr->cmd = 1;
   shdr->port = htons(CNF(ocat_dest_port));
   shdr->addr.s_addr = htonl(0x00000001);
   memcpy(buf + sizeof(SocksHdr_t), CNF(usrname), strlen(CNF(usrname)) + 1);
   memcpy(buf + sizeof(SocksHdr_t) + strlen(CNF(usrname)) + 1, onion, strlen(onion) + 1);
   len = sizeof(SocksHdr_t) + strlen(CNF(usrname)) + strlen(onion) + 2;
   if ((ret = write(sq->fd, shdr, len)) == -1)
   {
      log_msg(LOG_ERR, "error writing %d bytes to fd %d: \"%s\"", len, sq->fd, strerror(errno));
      return -1;
   }
   if (ret < len)
   {
      log_msg(LOG_ERR, "SOCKS request truncated to %d of %d bytes", ret, len);
      return -1;
   }
   log_debug("SOCKS request sent successfully");
   return 0;
}


int socks_rec_response(SocksQueue_t *sq)
{
   SocksHdr_t shdr;
   int ret, len;

   len = sizeof(SocksHdr_t);
   if ((ret = read(sq->fd, &shdr, len)) == -1)
   {
      log_msg(LOG_ERR, "reading SOCKS response on fd %d failed: \"%s\"", sq->fd, strerror(errno));
      return -1;
   }
   if (ret < len)
   {
      log_msg(LOG_ERR, "SOCKS response truncated to %d of %d bytes", ret, len);
      return -1;
   }

   log_debug("SOCKS response received");
   if (shdr.ver || (shdr.cmd != 90))
   {
      log_msg(LOG_ERR, "SOCKS request failed, reason = %d", shdr.cmd);
      return -1;
   }

   log_msg(LOG_INFO | LOG_FCONN, "SOCKS connection successfully opened on fd %d", sq->fd);
   return 0;
}


int socks_activate_peer(SocksQueue_t *sq)
{
   OcatPeer_t *peer;

   insert_peer(sq->fd, sq, time(NULL) - sq->connect_time);

   // Send first keepalive immediately
   lock_peers();
   if ((peer = search_peer(&sq->addr)))
      lock_peer(peer);
   else
      log_msg(LOG_EMERG, "newly inserted peer not found, fd = %d", sq->fd);
   unlock_peers();
   if (peer)
   {
      send_keepalive(peer);
      unlock_peer(peer);
   }

   return 0;
}


void socks_pipe_request(const SocksQueue_t *sq)
{
   fd_set wset;
   int maxfd;
   int len = sizeof(*sq), ret;

   FD_ZERO(&wset);
   FD_SET(CNF(socksfd[1]), &wset);
   maxfd = CNF(socksfd[1]);

   log_debug("selecting until socks request pipe gets ready");

      log_debug("selecting (maxfd = %d)", maxfd);
      if ((maxfd = select(maxfd + 1, NULL, &wset, NULL, NULL)) == -1)
      {
         log_msg(LOG_EMERG, "select encountered error: \"%s\", restarting", strerror(errno));
         return;
      }
      log_debug("select returned %d", maxfd);


      if (maxfd && FD_ISSET(CNF(socksfd[1]), &wset))
      {

   log_debug("writing %d bytes to fd %d", len, CNF(socksfd[1]));
   if ((ret = write(CNF(socksfd[1]), sq, len)) == -1)
   {
      log_msg(LOG_WARNING, "error writing to SOCKS request pipe fd %d: \"%s\"", CNF(socksfd[1]), strerror(errno));
   }
   else if (ret < len)
   {
      log_msg(LOG_WARNING, "write to SOCKS request pipe fd %d truncated to %d bytes of %d", CNF(socksfd[1]), ret, len);
   }
   else
   {
      log_debug("wrote %d bytes to SOCKS request pipe fd %d", len, CNF(socksfd[1]));
   }
      }
      else
         log_msg(LOG_WARNING, "fd %d not in write set", CNF(socksfd[1]));
}


void sig_socks_connector(void)
{
   SocksQueue_t sq;

   memset(&sq, 0, sizeof(sq));
   socks_pipe_request(&sq);
}


/*! Add and link a SOCKS request to the SOCKS queue.
 *  @param sq Request structure to add.
 */
void socks_enqueue(const SocksQueue_t *sq)
{
   SocksQueue_t *squeue;

   log_debug("queueing new SOCKS connection request");
   if (!(squeue = malloc(sizeof(SocksQueue_t))))
      log_msg(LOG_EMERG, "could not get memory for SocksQueue entry: \"%s\"", strerror(errno)), exit(1);
   memcpy(squeue, sq, sizeof(*squeue));

   squeue->next = socks_queue_;
   socks_queue_ = squeue;
}


/*! Send a SOCKS request to the request pipe in order to get
 *  added to the SOCKS queue with socks_enqueue()
 *  @param addr IPv6 address to be requested
 *  @param perm 1 if connection should kept opened inifitely after successful request, 0 else.
 */
void socks_queue(struct in6_addr addr, int perm)
{
   SocksQueue_t *squeue, sq;

   // dont queue if SOCKS is disabled (-t none)
   if (!CNF(socks_dst)->sin_family)
      return;

   for (squeue = socks_queue_; squeue; squeue = squeue->next)
      if (IN6_ARE_ADDR_EQUAL(&squeue->addr, &addr))
         break;

   if (!squeue)
   {
      log_debug("queueing new SOCKS connection request");
      memset(&sq, 0, sizeof(sq));
      IN6_ADDR_COPY(&sq.addr, &addr);
      sq.perm = perm;
      log_debug("signalling connector");
      socks_pipe_request(&sq);
   }
   else
      log_debug("connection already exists, not queueing SOCKS connection");
}


/*! Remove SocksQueue_t element from SOCKS queue.
 *  @param sq Pointer to element to remove.
 */
void socks_unqueue(SocksQueue_t *squeue)
{
   SocksQueue_t **sq;

   for (sq = &socks_queue_; *sq; sq = &(*sq)->next)
      if (*sq == squeue)
      {
         *sq = (*sq)->next;
         log_debug("freeing SOCKS queue element at %p", squeue);
         free(squeue);
         break;
      }
}


void print_socks_queue(FILE *f)
{
   SocksQueue_t sq;

   memset(&sq, 0, sizeof(sq));
   sq.next = (SocksQueue_t*) f;
   socks_pipe_request(&sq);
}


void socks_output_queue(FILE *f)
{
   int i;
   char addrstr[INET6_ADDRSTRLEN], onstr[NDESC(name_size)], buf[SIZE_1K];
   SocksQueue_t *squeue;

   for (squeue = socks_queue_, i = 0; squeue; squeue = squeue->next, i++)
   {
      if (!inet_ntop(AF_INET6, &squeue->addr, addrstr, INET6_ADDRSTRLEN))
      {
         log_msg(LOG_ERR, "inet_ntop returned NULL pointer: \"%s\"", strerror(errno));
         strlcpy(addrstr, "ERROR", INET6_ADDRSTRLEN);
      }

      snprintf(buf, SIZE_1K, "%d: %39s, %s%s, state = %d, %s(%d), retry = %d, connect_time = %d, restart_time = %d",
            i, 
            addrstr, 
            ipv6tonion(&squeue->addr, onstr),
            CNF(domain),
            squeue->state,
            squeue->perm ? "PERMANENT" : "TEMPORARY",
            squeue->perm,
            squeue->retry,
            (int) squeue->connect_time,
            (int) squeue->restart_time
            );
//      log_debug("%s", buf);
      write((int) (long) f, buf, strlen(buf));
      write((int) (long) f, "\n", 1);
   }
   write((int) (long) f, "\0", 1);
   log_debug("socks_output_queue() finished");
}


int socks5_greet(const SocksQueue_t *sq)
{
   char buf[] = {5, 1, 0}; // version 5, 1 auth method, method no_auth (0)
   int ret, len = sizeof(buf);

   if ((ret = write(sq->fd, buf, len)) == -1)
   {
      log_msg(LOG_ERR, "error writing %d bytes to fd %d: \"%s\"", len, sq->fd, strerror(errno));
      return -1;
   }
   if (ret < len)
   {
      log_msg(LOG_ERR, "SOCKS5 greeting truncated to %d of %d bytes", ret, len);
      return -1;
   }
   log_debug("SOCKS5 greeting sent successfully");
   return 0;
}


int socks5_greet_response(const SocksQueue_t *sq)
{
   char buf[2];
   int ret, len = sizeof(buf);

   if ((ret = read(sq->fd, buf, len)) == -1)
   {
      log_msg(LOG_ERR, "reading SOCKS5 greet response on fd %d faile: \"%s\"", sq->fd, strerror(errno));
      return -1;

   }
   if (ret < len)
   {
      log_msg(LOG_ERR, "SOCKS5 greet response truncated to %d of %d bytes", ret, len);
      return -1;
   }
   log_debug("SOCKS5 greet response received");
   if (buf[0] != 5 || buf[1] != 0)
   {
      log_msg(LOG_ERR, "unexpected SOCKS5 greet response: ver = %d, method = %d", buf[0], buf[1]);
      return -1;
   }
   log_msg(LOG_INFO | LOG_FCONN, "SOCKS5 greeting handshake on fd %d successful", sq->fd);
   return 0;
}


int socks5_send_request(const SocksQueue_t *sq)
{
   char buf[sizeof(Socks5Hdr_t) + sizeof(uint16_t) + NI_MAXHOST];
   char onion[NI_MAXHOST];
   Socks5Hdr_t *s5hdr = (Socks5Hdr_t*) buf;
   int len, ret;

   get_hostname(sq, onion, sizeof(onion));
   s5hdr->ver = 5;
   s5hdr->cmd = 1;   // CONNECT
   s5hdr->rsv = 0;   // reserved
   s5hdr->atyp = 3;  // DOMAIN
   s5hdr->addr = strlen(onion);
   memcpy(buf + sizeof(*s5hdr), onion, strlen(onion));
   *((uint16_t*) &buf[sizeof(*s5hdr) + strlen(onion)]) = htons(CNF(ocat_dest_port));

   len = sizeof(*s5hdr) + strlen(onion) + sizeof(uint16_t);
   if ((ret = write(sq->fd, s5hdr, len)) == -1)
   {
      log_msg(LOG_ERR, "error writing %d bytes to fd %d: \"%s\"", len, sq->fd, strerror(errno));
      return -1;
   }
   if (ret < len)
   {
      log_msg(LOG_ERR, "SOCKS5 request truncated to %d of %d bytes", ret, len);
      return -1;
   }
   log_debug("SOCKS5 request sent successfully");
   return 0;
}


int socks5_rec_response(SocksQueue_t *sq)
{
   char buf[sizeof(Socks5Hdr_t) + sizeof(uint16_t) + NI_MAXHOST];
   Socks5Hdr_t *s5hdr = (Socks5Hdr_t*) buf;
   int len, ret;

   len = sizeof(buf);
   if ((ret = read(sq->fd, s5hdr, len)) == -1)
   {
      log_msg(LOG_ERR, "reading SOCKS5 response on fd %d failed: \"%s\"", sq->fd, strerror(errno));
      return -1;
   }

   log_debug("got %d bytes as SOCKS5 response", ret);
   if (ret < sizeof(*s5hdr))
   {
      log_msg(LOG_ERR, "SOCKS5 response seems truncated to %d of at least %d bytes", ret, sizeof(*s5hdr));
      return -1;
   }

   if (s5hdr->ver != 5 || s5hdr->rsv != 0)
   {
      log_msg(LOG_ERR, "unexpected SOCKS5 response");
      return -1;
   }
   if (s5hdr->cmd != 0)
   {
      log_msg(LOG_ERR, "SOCKS5 server returned error %d", s5hdr->cmd);
      return -1;
   }
   log_msg(LOG_INFO | LOG_FCONN, "SOCKS5 connection successfully opened on fd %d", sq->fd);
   return 0;
}


int socks_tcp_connect(int fd, struct sockaddr *addr, int len)
{
   char astr[INET6_ADDRSTRLEN];
   if (connect(fd, addr, len) == -1)
   {
      if (errno != EINPROGRESS)
      {
         log_msg(LOG_ERR, "connect() to SOCKS port %s:%d failed: \"%s\". Sleeping for %d seconds.", 
            inet_ntop(CNF(socks_dst)->sin_family, 
               CNF(socks_dst)->sin_family == AF_INET ? (char*) &CNF(socks_dst)->sin_addr : (char*) &CNF(socks_dst6)->sin6_addr, astr, sizeof(astr)), 
            ntohs(CNF(socks_dst)->sin_port), strerror(errno), TOR_SOCKS_CONN_TIMEOUT);
         return -1;
      }
      log_debug("connection in progress");
   }
   else
      log_debug("connected");

   return 0;
}


void socks_reschedule(SocksQueue_t *squeue)
{
   log_msg(LOG_ERR, "rescheduling SOCKS request");
   if (squeue->fd > 0)
   {
      oe_close(squeue->fd);
      squeue->fd = 0;
   }
   squeue->restart_time = time(NULL) + TOR_SOCKS_CONN_TIMEOUT;
   squeue->state = SOCKS_NEW;
}

 
void *socks_connector_sel(void *p)
{
   fd_set rset, wset;
   int maxfd = 0, len, so_err;
   SocksQueue_t *squeue, sq;
   time_t t;
   struct timeval tv;
   socklen_t err_len;

   for (;;)
   {
      if (term_req())
         return NULL;

      FD_ZERO(&rset);
      FD_ZERO(&wset);
      MFD_SET(CNF(socksfd[0]), &rset, maxfd);
      t = time(NULL);

      for (squeue = socks_queue_; squeue; squeue = squeue->next)
      {
         switch (squeue->state)
         {
            case SOCKS_NEW:
               /*if (!squeue->fd)
               {
                  log_msg(LOG_CRIT, "SOCKS_NEW and fd = %d, but should be 0", squeue->fd);
                  squeue->state = SOCKS_DELETE;
                  continue;
               }*/

               if (t < squeue->restart_time)
               {
                  log_debug("SOCKS request is scheduled for connection not before %ds", squeue->restart_time - t);
                  continue;
               }

               // check and increase retry counter
               squeue->retry++;
               if (!squeue->perm && (squeue->retry > SOCKS_MAX_RETRY))
               {
                  log_msg(LOG_NOTICE, "temporary request failed %d times and will be removed", squeue->retry - 1);
                  squeue->state = SOCKS_DELETE;
                  continue;
               }

               log_debug("creating socket for unconnected SOCKS request");
               if ((squeue->fd = socket(CNF(socks_dst)->sin_family == AF_INET ? PF_INET : PF_INET6, SOCK_STREAM, 0)) == -1)
               {
                  log_msg(LOG_ERR, "cannot create socket for new SOCKS request: \"%s\"", strerror(errno));
                  continue;
               }

               set_nonblock(squeue->fd);
               log_debug("queueing fd %d for connect", squeue->fd);
               squeue->connect_time = t;
               if (socks_tcp_connect(squeue->fd, (struct sockaddr*) CNF(socks_dst), SOCKADDR_SIZE(CNF(socks_dst))) == -1)
               {
                  socks_reschedule(squeue);
                  continue;
               }

               squeue->state = SOCKS_CONNECTING;
               MFD_SET(squeue->fd, &wset, maxfd);

               break;

            case SOCKS_4AREQ_SENT:
            case SOCKS_5GREET_SENT:
            case SOCKS_5REQ_SENT:
               MFD_SET(squeue->fd, &rset, maxfd);
               break;
         }
      }

      // select all file descriptors
      set_select_timeout(&tv);
      log_debug("selecting (maxfd = %d)", maxfd);
      if ((maxfd = select(maxfd + 1, &rset, &wset, NULL, &tv)) == -1)
      {
         log_msg(LOG_EMERG, "select encountered error: \"%s\", restarting", strerror(errno));
         continue;
      }
      log_debug("select returned %d", maxfd);

      // check socks request pipe
      if (FD_ISSET(CNF(socksfd[0]), &rset))
      {
         maxfd--;
         if ((len = read(CNF(socksfd[0]), &sq, sizeof(sq))) == -1)
            log_msg(LOG_ERR, "failed to read from SOCKS request pipe, fd = %d: \"%s\"", 
                  CNF(socksfd[0]), strerror(errno));
         if (len < sizeof(sq))
            log_msg(LOG_ERR, "read from SOCKS request pipe truncated to %d of %d bytes, ignoring.", 
                  len, sizeof(sq));
         else
         {
            log_debug("received %d bytes on SOCKS request pipe fd %d", len, CNF(socksfd[0]));
            if (sq.next)
            {
               log_debug("output of SOCKS request queue triggered");
               socks_output_queue((FILE*) sq.next);
            }
            else if (IN6_IS_ADDR_UNSPECIFIED(&sq.addr))
            {
               log_debug("termination request on SOCKS request queue received");
            }
            else
            {
               log_debug("SOCKS queuing request received");
               socks_enqueue(&sq);
            }
         }
      }

      // handle all other file descriptors
      t = time(NULL);
      for (squeue = socks_queue_; maxfd && squeue; squeue = squeue->next)
      {
         // check write set, this is valid after connect()
         if (FD_ISSET(squeue->fd, &wset))
         {
            maxfd--;
            if (squeue->state == SOCKS_CONNECTING)
            {
               // test if connect() worked
               log_debug("check socket error");
               err_len = sizeof(so_err);
               if (getsockopt(squeue->fd, SOL_SOCKET, SO_ERROR, &so_err, &err_len) == -1)
               {
                  log_msg(LOG_ERR, "getsockopt failed: \"%s\", rescheduling request", strerror(errno));
                  socks_reschedule(squeue);
                  continue;
               }
               if (so_err)
               {
                  log_msg(LOG_ERR, "getsockopt returned %d (\"%s\")", so_err, strerror(so_err));
                  socks_reschedule(squeue);
                  continue;
               }
               // SOCKS4A
               if (!CNF(socks5))
               {
                  // everything seems to be ok, now check request status
                  if (socks_send_request(squeue) == -1)
                  {
                     log_msg(LOG_ERR, "SOCKS request failed");
                     socks_reschedule(squeue);
                     continue;
                  }
                  // request successfully sent, advance state machine
                  squeue->state = SOCKS_4AREQ_SENT;
               }
               else
               {
                  // everything seems to be ok, now check request status
                  if (socks5_greet(squeue) == -1)
                  {
                     log_msg(LOG_ERR, "SOCKS5 request failed");
                     socks_reschedule(squeue);
                     continue;
                  }
                  // request successfully sent, advance state machine
                  squeue->state = SOCKS_5GREET_SENT;
               }
            }
            else
               log_debug("unknown state %d in write set", squeue->state);
         }

         // check read set, this is valid after write, i.e. receiving SOCKS response
         if (FD_ISSET(squeue->fd, &rset))
         {
            maxfd--;
            if (squeue->state == SOCKS_4AREQ_SENT)
            {
               if (socks_rec_response(squeue) == -1)
               {
                  socks_reschedule(squeue);
                  continue;
               }
               // success
               log_debug("activating peer fd %d", squeue->fd);
               socks_activate_peer(squeue);
               squeue->state = SOCKS_DELETE;
            }
            else if (squeue->state == SOCKS_5GREET_SENT)
            {
               // check greet response
               if (socks5_greet_response(squeue) == -1)
               {
                  socks_reschedule(squeue);
                  continue;
               }
               // greeting was successful, send request
               if (socks5_send_request(squeue) == -1)
               {
                  log_msg(LOG_ERR, "sending SOCKS5 request failed");
                  socks_reschedule(squeue);
                  continue;
               }
               // request successfully sent, advance state machine
               squeue->state = SOCKS_5REQ_SENT;
            }
            else if (squeue->state == SOCKS_5REQ_SENT)
            {
               if (socks5_rec_response(squeue) == -1)
               {
                  socks_reschedule(squeue);
                  continue;
               }
               // success
               log_debug("activating peer fd %d", squeue->fd);
               socks_activate_peer(squeue);
               squeue->state = SOCKS_DELETE;
            }
            else
               log_debug("unknown state %d in read set", squeue->state);
         }
      }

      // delete requests from queue which are marked for deletion
      for (squeue = socks_queue_; squeue; squeue = squeue->next)
         if (squeue->state == SOCKS_DELETE)
         {
            socks_unqueue(squeue);
            // restart loop
            squeue = socks_queue_;
            if (!squeue)
            {
               log_debug("last entry deleted, breaking loop");
               break;
            }
         }
   }
}


int test_socks_server(void)
{
   int fd, err = -1;

   if ((fd = socket(CNF(socks_dst)->sin_family == AF_INET ? PF_INET : PF_INET6, SOCK_STREAM, 0)) == -1)
   {
      log_msg(LOG_ERR, "Failed to create socket for SOCKS test request: \"%s\"", strerror(errno));
      return -1;
   }

   if (!socks_tcp_connect(fd, (struct sockaddr*) CNF(socks_dst), SOCKADDR_SIZE(CNF(socks_dst))))
   {
      log_msg(LOG_INFO, "SOCKS server tested successfully");
      err = 0;
   }
   else
      log_msg(LOG_ERR, "Could not connect to SOCKS server (i.e. Tor/I2P). Please check!");

   oe_close(fd);
   return err;
}

