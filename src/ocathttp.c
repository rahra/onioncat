/* Copyright 2021 Bernhard R. Fischer.
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

/*! @file ocathttp.c
 *  Contains functions for the tiny HTTP service.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2021/06/09
 */

#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"


#ifdef HANDLE_HTTP
int is_http_request(const OcatPeer_t *peer)
{
   return !strncmp(peer->fragbuf, "GET ", 4);
}


/*! This function fills the buffer until the buffer is full or no more data is
 * available.
 * @param peer Pointer to the peer.
 * @return On succes the function returns a value >= 0. On error, -1 is
 * returned.
 */
static int fill_buffer(OcatPeer_t *peer)
{
   int len, rlen;

   // loop until buffer is full
   for (rlen = 0; peer->fraglen < FRAME_SIZE - 4;)
   {
      // append-read data into the buffer
      len = read(peer->tcpfd, peer->fragbuf + peer->fraglen, FRAME_SIZE - 4 - peer->fraglen);

      // eof (actually this will not happen because of non-blocking io, just a safety measure)
      if (!len)
         break;

      // error check
      if (len == -1)
      {
         // some error occured
         if (errno != EAGAIN && errno != EWOULDBLOCK)
            log_msg(LOG_ERR, "read() on buffer fill failed: %s", strerror(errno));
         // no more data available
         else
            len = 0;
         break;
      }

      rlen += len;
      peer->fraglen += len;
      peer->in += len;
   }

   return rlen;
}


/*! Write buffer to fd of peer, handle error and byte counters of peer.
 */
static int peer_write(OcatPeer_t *peer, const char *buf, int len)
{
   if ((len = write(peer->tcpfd, buf, len)) == -1)
   {
      log_msg(LOG_ERR, "write failed: %s", strerror(errno));
      return -1;
   }

   peer->out += len;
   return len;
}


void *http_handler(void *p)
{
   char buf[4096], timestr[64], *s;
   OcatPeer_t *peer;
   struct tm tm;
   time_t t;
   int len, fd;
   char *uri, *ver;

   detach_thread();

   // safety check
   if (p == NULL)
   {
      log_msg(LOG_ERR, "param should not be NULL!");
      return NULL;
   }

   peer = (OcatPeer_t*) p;

   t = time(NULL);
   (void) localtime_r(&t, &tm);
   strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);
 
   log_debug("locking peer");
   lock_peers();
   lock_peer(peer);
   unlock_peers();

   if (strncmp(peer->fragbuf, "GET ", 4))
   {
      log_msg(LOG_INFO, "this is not a GET request");
      len = snprintf(buf, sizeof(buf),
            "HTTP/1.0 501 Not Implemented\r\nDate: %s\r\nContent-Type: text/html\r\n\r\n"
            "<!doctype html>\n<html><body>501 Not Implemented</body></html>\n",
            timestr);
      peer_write(peer, buf, len);

      goto hh_exit;
   }

   //make sure that buffer is 0-terminated
   if (peer->fraglen >= FRAME_SIZE - 4)
      peer->fraglen = FRAME_SIZE - 4 - 1;
   peer->fragbuf[peer->fraglen] = '\0';

   s = peer->fragbuf + 4;
   // skip spaces
   for (; *s == ' '; s++);
   if ((s = strtok(s, " ")) == NULL)
      goto hh_bad;
   if (strlen(s) > 1024)
      goto hh_bad;

   uri = s;
   if ((ver = strtok(NULL, "\r\n")) == NULL)
      goto hh_bad;
   if (strcmp(ver, "HTTP/1.0") && strcmp(ver, "HTTP/1.1"))
      goto hh_bad;

   if (!strcmp(uri, "/api/v1/hosts"))
   {
      log_msg(LOG_INFO, "hosts request", uri);
      len = snprintf(buf, sizeof(buf), "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Type: text/plain\r\n\r\n", timestr);
      sn_hosts_list(buf + len, sizeof(buf) - len);
      len = strlen(buf); // FIXME: sn_hosts_list should return number of bytes written
   }
   else
   {
      log_msg(LOG_WARNING, "uri \"%s\" not found", uri);
      len = snprintf(buf, sizeof(buf),
            "HTTP/1.0 404 Not Found\r\nDate: %s\r\nContent-Type: text/html\r\n\r\n"
            "<!doctype html>\n<html><body>404 Not Found</body></html>\n",
            timestr);
   }
   peer_write(peer, buf, len);

   goto hh_exit;

hh_bad:
   log_msg(LOG_INFO, "this is a bad request");
   len = snprintf(buf, sizeof(buf),
         "HTTP/1.0 400 Bad Request\r\nDate: %s\r\nContent-Type: text/html\r\n\r\n"
         "<!doctype html>\n<html><body>400 Bad Request</body></html>\n",
         timestr);
   peer_write(peer, buf, len);

hh_exit:
   fill_buffer(peer);
   log_debug("closing and deleting http peer fd %d", peer->tcpfd);
   fd = peer->tcpfd;
   peer->state = PEER_DELETE;
   unlock_peer(peer);
   lock_peers();
   delete_peer(peer);
   unlock_peers();
   oe_close(fd);
   return NULL;
}

#endif

