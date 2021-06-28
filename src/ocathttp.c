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
#include "bstring.h"

#ifdef HANDLE_HTTP
int is_http_request(const OcatPeer_t *peer)
{
   return !strncmp(peer->fragbuf, "GET ", 4);
}


/*! Return the next line in the HTTP header. The line will be returned in dst
 * (basepointer and data length). The source pointer src will be advanced to
 * the beginning of the next line. A HTTP line is terminated by \r\n.
 * @param src Pointer to the HTTP header.
 * @param dst Pointer to a bstring which will receive the result.
 * @return The function returns 0 on success. In case of a format error, 1 is
 * returned. In case of NULL pointers where passed to the function -1 is
 * returned.
 */
int get_http_line(bstring_t *src, bstring_t *dst)
{
   //safety check
   if (src == NULL || dst == NULL)
   {
      log_msg(LOG_CRIT, "this should never happen");
      return -1;
   }

   // find 1st occurance of '\r'
   for (*dst = *src; src->len > 0 && *src->buf != '\r'; bs_advance(src));
   dst->len -= src->len;

   if (src->len <= 0)
      goto ghl_err;

   // skip '\r'
   bs_advance(src);

   if (src->len <= 0)
      goto ghl_err;

   if (*src->buf != '\n')
      goto ghl_err;

   // skip '\n'
   bs_advance(src);
   return 0;

ghl_err:
   log_msg(LOG_WARNING, "HTTP format incorrect");
   return 1;
}


int parse_sp_sep_token(bstring_t *src, bstring_t *dst)
{
   //safety check
   if (src == NULL || dst == NULL)
   {
      log_msg(LOG_CRIT, "this should never happen");
      return -1;
   }

   // find 1st occurance of ' '
   for (*dst = *src; src->len > 0 && *src->buf != ' '; bs_advance(src));
   dst->len -= src->len;

   // find 1st occurance of !' '
   for (; src->len > 0 && *src->buf == ' '; bs_advance(src));

   return 0;
}


void parse_status_line(bstring_t *sline, bstring_t *s1, bstring_t *s2, bstring_t *s3)
{
   parse_sp_sep_token(sline, s1);
   parse_sp_sep_token(sline, s2);
   parse_sp_sep_token(sline, s3);
}


static void gmtime_str(char *timestr, int tslen, time_t t)
{
   struct tm tm;

   // safety check
   if (timestr == NULL)
   {
      log_msg(LOG_CRIT, "this should never happen");
      return;
   }

   (void) gmtime_r(&t, &tm);
   strftime(timestr, tslen, "%a, %d %b %Y %H:%M:%S %z", &tm);
}


const char *response_msg(int n)
{
   switch (n)
   {
      case 200:
         return "OK";
      case 400:
         return "Bad Request";
      case 404:
         return "Not Found";
      case 501:
         return "Not Implemented";
      default:
         return "";
   }
}


int mk_http_error_msg(char *buf, int buflen, int code)
{
   int len;

   len = snprintf(buf, buflen, "<!doctype html>\n<html><header><meta charset=\"UTF-8\"/></head><body>%d %s</body></html>\n", code, response_msg(code));
   if (len >= buflen)
      return -1;
   return len;
}


int mk_response_header(char *buf, int buflen, int code, const char *type, time_t t)
{
   char timestr[64];
   int len;

   // safety check
   if (buf == NULL || type == NULL)
   {
      log_msg(LOG_CRIT, "this should never happen");
      return -1;
   }

   gmtime_str(timestr, sizeof(timestr), t);
   len = snprintf(buf, buflen, "HTTP/1.0 %d %s\r\nDate: %s\r\nContent-Type: %s\r\n\r\n", code, response_msg(code), timestr, type);

   // error checking
   if (len >= buflen)
   {
      log_msg(LOG_WARNING, "data buffer too small, len = %d", len);
      return -1;
   }

   return len;
}


int mk_error_response(char *buf, int buflen, int code)
{
   int len;

   if ((len = mk_response_header(buf, buflen, code, "text/html", time(NULL))) == -1)
      return -1;
   if ((buflen = mk_http_error_msg(buf + len, buflen - len, code)) == -1)
      return -1;
   return len + buflen;
}


int mk_hosts_response(char *buf, int buflen)
{
   int len;

   log_debug("creating hosts response");
   if ((len = mk_response_header(buf, buflen, 200, "text/plain", hosts_time())) == -1)
      return -1;

   if ((buflen = sn_hosts_list(buf + len, buflen - len)) <= 0)
      return -1;

   return len + buflen;
}


int handle_request(OcatPeer_t *peer, char *resp, int len)
{
   bstring_t req, line, method, uri, version;

   req.buf = peer->fragbuf;
   req.len = peer->fraglen;

   if (get_http_line(&req, &line))
      return mk_error_response(resp, len, 400);

   parse_status_line(&line, &method, &uri, &version);

   if (bs_cmp(method, "GET"))
      return mk_error_response(resp, len, 501);

   if (bs_cmp(uri, "/api/v1/hosts"))
      return mk_error_response(resp, len, 404);

   len = mk_hosts_response(resp, len);

   return len;
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
   char buf[8192], timestr[64], *s;
   OcatPeer_t *peer;
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

   log_debug("locking peer");
   lock_peers();
   lock_peer(peer);
   unlock_peers();

   log_debug("handling request");
   if ((len = handle_request(peer, buf, sizeof(buf))) > 0)
      peer_write(peer, buf, len);

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

