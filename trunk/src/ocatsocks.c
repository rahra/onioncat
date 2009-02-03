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


// SOCKS connector queue vars
static SocksQueue_t *socks_queue_ = NULL;
static int socks_connect_cnt_ = 0;
static int socks_thread_cnt_ = 0;
static pthread_mutex_t socks_queue_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t socks_queue_cond_ = PTHREAD_COND_INITIALIZER;


int socks_srv_con(void)
{
   int fd, t;
   char addr[INET6_ADDRSTRLEN];

   if ((fd = socket(CNF(socks_dst)->sin_family == AF_INET ? PF_INET : PF_INET6, SOCK_STREAM, 0)) < 0)
      return E_SOCKS_SOCK;

   t = time(NULL);
   if (connect(fd, (struct sockaddr*) CNF(socks_dst), SOCKADDR_SIZE(CNF(socks_dst))) == -1)
   {
      log_msg(LOG_ERR, "connect() to SOCKS port %s:%d failed: \"%s\". Sleeping for %d seconds.", inet_ntop(CNF(socks_dst)->sin_family, CNF(socks_dst)->sin_family == AF_INET ? (char*) &CNF(socks_dst)->sin_addr : (char*) &CNF(socks_dst6)->sin6_addr, addr, sizeof(addr)), ntohs(CNF(socks_dst)->sin_port), strerror(errno), TOR_SOCKS_CONN_TIMEOUT);
      oe_close(fd);
      sleep(TOR_SOCKS_CONN_TIMEOUT);
      return E_SOCKS_CONN;
   }
   log_debug("connected");
   return fd;
}


int socks_connect(const SocksQueue_t *sq)
{
//   struct sockaddr_in in;
   int fd, t, len;
   char buf[FRAME_SIZE], onion[ONION_NAME_SIZE];
   //char addr[INET6_ADDRSTRLEN];
   SocksHdr_t *shdr = (SocksHdr_t*) buf;
   OcatPeer_t *peer;

   /*
   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(CNF(tor_socks_port));
   in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   in.sin_len = sizeof(in);
#endif
*/

   ipv6tonion(&sq->addr, onion);
   strlcat(onion, ".onion", sizeof(onion));

   log_msg(LOG_INFO, "trying to connect to \"%s\" [%s]", onion, inet_ntop(AF_INET6, &sq->addr, buf, FRAME_SIZE));
   if ((fd = socks_srv_con()) < 0)
      return fd;

   /*
   if ((fd = socket(CNF(socks_dst)->sin_family == AF_INET ? PF_INET : PF_INET6, SOCK_STREAM, 0)) < 0)
      return E_SOCKS_SOCK;

   t = time(NULL);
   if (connect(fd, (struct sockaddr*) CNF(socks_dst), sizeof(struct sockaddr_in6)) == -1)
   {
      log_msg(LOG_ERR, "connect() to TOR's SOCKS port %s:%d failed: \"%s\". Sleeping for %d seconds.", inet_ntop(CNF(socks_dst)->sin_family, CNF(socks_dst)->sin_family == AF_INET ? (char*) &CNF(socks_dst)->sin_addr : (char*) &CNF(socks_dst6)->sin6_addr, addr, sizeof(addr)), ntohs(CNF(socks_dst)->sin_port), strerror(errno), TOR_SOCKS_CONN_TIMEOUT);
      oe_close(fd);
      sleep(TOR_SOCKS_CONN_TIMEOUT);
      return E_SOCKS_CONN;
   }
   */

   log_debug("doing SOCKS4a handshake");

   shdr->ver = 4;
   shdr->cmd = 1;
   shdr->port = htons(CNF(ocat_dest_port));
   shdr->addr.s_addr = htonl(0x00000001);
   /*
   strlcpy(buf + sizeof(SocksHdr_t), usrname_, strlen(usrname_) + 1);
   strlcpy(buf + sizeof(SocksHdr_t) + strlen(usrname_) + 1, onion, sizeof(onion));
   */
   memcpy(buf + sizeof(SocksHdr_t), CNF(usrname), strlen(CNF(usrname)) + 1);
   memcpy(buf + sizeof(SocksHdr_t) + strlen(CNF(usrname)) + 1, onion, strlen(onion) + 1);
   len = sizeof(SocksHdr_t) + strlen(CNF(usrname)) + strlen(onion) + 2;
   if (write(fd, shdr, len) != len)
      // FIXME: there should be some additional error handling
      log_msg(LOG_ERR, "couldn't write %d bytes to SOCKS connection %d", len, fd);
   log_debug("connect request sent");

   if (read(fd, shdr, sizeof(SocksHdr_t)) < sizeof(SocksHdr_t))
   {
      log_msg(LOG_ERR | LOG_FCONN, "short read, closing.");
      oe_close(fd);
      return E_SOCKS_REQ;
   }
   log_debug("SOCKS response received");

   if (shdr->ver || (shdr->cmd != 90))
   {
      log_msg(LOG_ERR, "request failed, reason = %d", shdr->cmd);
      oe_close(fd);
      return E_SOCKS_RQFAIL;
   }
   log_msg(LOG_INFO | LOG_FCONN, "connection to %s successfully opened on fd %d", onion, fd);

   insert_peer(fd, sq, time(NULL) - t);

   // Send first keepalive immediately
   lock_peers();
   if ((peer = search_peer(&sq->addr)))
      lock_peer(peer);
   else
      log_msg(LOG_EMERG, "newly inserted peer not found, fd = %d", fd);
   unlock_peers();
   if (peer)
   {
      send_keepalive(peer);
      unlock_peer(peer);
   }

   // return new file descriptor
   return fd;
}


void socks_queue(struct in6_addr addr, int perm)
{
   SocksQueue_t *squeue;

   pthread_mutex_lock(&socks_queue_mutex_);
   for (squeue = socks_queue_; squeue; squeue = squeue->next)
      if (IN6_ARE_ADDR_EQUAL(&squeue->addr, &addr))
         break;
   if (!squeue)
   {
      log_debug("queueing new SOCKS connection request");
      if (!(squeue = calloc(1, sizeof(SocksQueue_t))))
         log_msg(LOG_EMERG, "could not get memory for SocksQueue entry: \"%s\"", strerror(errno)), exit(1);
      IN6_ADDR_COPY(&squeue->addr, &addr);
      squeue->perm = perm;
      squeue->next = socks_queue_;
      socks_queue_ = squeue;
      log_debug("signalling connector");
      pthread_cond_signal(&socks_queue_cond_);
   }
   else
      log_debug("connection already exists, not queueing SOCKS connection");
   pthread_mutex_unlock(&socks_queue_mutex_);
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


void *socks_connector(void *p)
{
   OcatPeer_t *peer;
   SocksQueue_t *squeue;
   int i, ps, run = 1, t_abs, t_diff;
   char thn[THREAD_NAME_LEN] = "cn:", on[ONION_NAME_LEN];

   detach_thread();

   pthread_mutex_lock(&socks_queue_mutex_);
   socks_thread_cnt_++;
   log_debug("%d connector threads running", socks_thread_cnt_);
   pthread_mutex_unlock(&socks_queue_mutex_);

   while (run)
   {
      pthread_mutex_lock(&socks_queue_mutex_);
      for (;;)
      {
         for (squeue = socks_queue_; squeue; squeue = squeue->next)
            if (!squeue->state)
            {
               log_debug("unhandled queue entry found");
               break;
            }

         if (squeue)
            break;

         log_debug("waiting for new queue entry");
         pthread_cond_wait(&socks_queue_cond_, &socks_queue_mutex_);
      }

      // spawn spare thread if there is no one left
      log_debug("change queue element state to CONNECTING");
      squeue->state = SOCKS_CONNECTING;
      socks_connect_cnt_++;
      if (socks_thread_cnt_ <= socks_connect_cnt_)
      {
         log_debug("spawning new connector threads");
         run_ocat_thread("connector", socks_connector, NULL);
      }
      pthread_mutex_unlock(&socks_queue_mutex_);

      // changing thread name
      log_debug("changing thread name");
      ipv6tonion(&squeue->addr, on);
      strlcat(thn, on, THREAD_NAME_LEN);
      set_thread_name(thn);

      // search for existing peer
      lock_peers();
      peer = search_peer(&squeue->addr);
      unlock_peers();

      // connect via SOCKS if no peer exists
      if (!peer)
         for (i = 0, ps = -1, t_abs = 0; ((i < SOCKS_MAX_RETRY) || squeue->perm) && ps < 0; i++)
         {
            // every third connection attempt
            if (!(i % RECONN_ATTEMPTS))
            {
               // check that it does not reconnect too fast
               t_diff = time(NULL) - t_abs;
               if (t_diff < MIN_RECONNECT_TIME)
               {
                  // and sleep if necessary
                  log_msg(LOG_WARNING, "reconnecting too fast. sleeping %d seconds", MIN_RECONNECT_TIME - t_diff);
                  sleep(MIN_RECONNECT_TIME - t_diff);
               }
               t_abs = time(NULL);
            }
            log_debug("%d. SOCKS connection attempt", i + 1);
            ps = socks_connect(squeue);
         }
      else
         log_msg(LOG_INFO, "peer already exists, ignoring");

      // remove request from queue after connect
      log_debug("removing destination from SOCKS queue");
      pthread_mutex_lock(&socks_queue_mutex_);

      socks_unqueue(squeue);
      socks_connect_cnt_--;

      // if there are more threads then pending connections
      // terminate thread
      if (socks_connect_cnt_ < socks_thread_cnt_ - 1)
      {
         log_debug("going to terminate connector thread");
         socks_thread_cnt_--;
         run = 0;
      }
      pthread_mutex_unlock(&socks_queue_mutex_);
   }
   return NULL;
}


void print_socks_queue(FILE *f)
{
   int i;
   char addrstr[INET6_ADDRSTRLEN], onstr[ONION_NAME_LEN];
   SocksQueue_t *squeue;

   pthread_mutex_lock(&socks_queue_mutex_);

   for (squeue = socks_queue_, i = 0; squeue; squeue = squeue->next, i++)
   {
      if (!inet_ntop(AF_INET6, &squeue->addr, addrstr, INET6_ADDRSTRLEN))
      {
         log_msg(LOG_ERR, "inet_ntop returned NULL pointer: \"%s\"", strerror(errno));
         strlcpy(addrstr, "ERROR", INET6_ADDRSTRLEN);
      }

      fprintf(f, "%d %39s %s.onion %s(%d) %s(%d)\n",
            i, 
            addrstr, 
            ipv6tonion(&squeue->addr, onstr),
            squeue->state == SOCKS_CONNECTING ? "CONNECTING" : "QUEUED", 
            squeue->state,
            squeue->perm ? "PERMANENT" : "TEMPORARY",
            squeue->perm);
   }

   pthread_mutex_unlock(&socks_queue_mutex_);
}


int socks5_connect(const SocksQueue_t *sq)
{
   char buf[256 + sizeof(uint16_t) + sizeof(Socks5Hdr_t)];
   char dest[ONION_URL_LEN + 1];
   Socks5Hdr_t *shdr = (Socks5Hdr_t*) buf;
   int fd;

   log_msg(LOG_INFO, "trying to connect to \"%s\" [%s]", dest, inet_ntop(AF_INET6, &sq->addr, buf, 256));
   if ((fd = socks_srv_con()) < 0)
      return fd;

   memset(buf, 0, sizeof(buf));
   shdr->ver = '\x05';  // Version 5
   shdr->cmd = '\x01';  // CONNECT
   shdr->atyp = '\x03'; // DOMAINNAME

   ipv6tonion(&sq->addr, dest);
   shdr->addr = strlen(dest);
   memcpy(&buf[sizeof(Socks5Hdr_t)], dest, strlen(dest));
   *((uint16_t*) &buf[sizeof(Socks5Hdr_t) + strlen(dest)]) = htons(CNF(ocat_dest_port));

   return fd;
}

