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


void *http_handler(void *p)
{
   char buf[4096], timestr[64], *s;
   OcatPeer_t *peer;
   struct tm tm;
   time_t t;
   int len;

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
   lock_peer(peer);
   if (strncmp(peer->fragbuf, "GET ", 4))
   {
      log_msg(LOG_INFO, "this is not a GET request");
      len = snprintf(buf, sizeof(buf),
            "HTTP/1.0 501 Not Implemented\r\nDate: %s\r\nContent-Type: text/html\r\n\r\n"
            "<!doctype html>\n<html><body>501 Not Implemented</body></html>\n",
            timestr);
      write(peer->tcpfd, buf, len);
      len = read(peer->tcpfd, peer->fragbuf, FRAME_SIZE - 4);
      log_debug("buffer emptied (%d)", len);
      oe_close(peer->tcpfd);
      peer->state = PEER_DELETE;
      unlock_peer(peer);
      return NULL;
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

   log_msg(LOG_INFO, "returning some info");
   len = snprintf(buf, sizeof(buf),
         "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Type: text/html\r\n\r\n"
         "<!doctype html>\n<html><body>200 OK</body></html>\n",
         timestr);
   write(peer->tcpfd, buf, len);
   len = read(peer->tcpfd, peer->fragbuf, FRAME_SIZE - 4);
   log_debug("buffer emptied (%d)", len);
   oe_close(peer->tcpfd);
   peer->state = PEER_DELETE;
   unlock_peer(peer);
   return NULL;

hh_bad:
   log_msg(LOG_INFO, "this is a bad request");
   len = snprintf(buf, sizeof(buf),
         "HTTP/1.0 400 Bad Request\r\nDate: %s\r\nContent-Type: text/html\r\n\r\n"
         "<!doctype html>\n<html><body>400 Bad Request</body></html>\n",
         timestr);
   write(peer->tcpfd, buf, len);
   len = read(peer->tcpfd, peer->fragbuf, FRAME_SIZE - 4);
   log_debug("buffer emptied (%d)", len);
   oe_close(peer->tcpfd);
   peer->state = PEER_DELETE;
   unlock_peer(peer);
   return NULL;
}

#endif

