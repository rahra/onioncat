/* Copyright 2008-2022 Bernhard R. Fischer.
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

/*! \file ocatlibe.c
 *  Contains some helper functions.
 *
 *  \author Bernhard Fischer <bf@abenteuerland.at>
 *  \version 2022/07/29
 */


#include "ocat.h"


/*! oe_close is a more robust close() function.
 *  @param fd File descriptor to close.
 */
void oe_close(int fd)
{
   struct timeval tv;
   int r;

   log_debug("closing %d", fd);
   while (close(fd) == -1)
   {
      r = errno;
      if (r == EINTR)
      {
         log_msg(LOG_ERR, "close(%d) failed: \"%s\". restarting in a moment...", fd, strerror(r));
         set_select_timeout(&tv);
         oc_select(0, NULL, NULL, NULL);
      }
      log_msg(LOG_CRIT, "close(%d) failed: \"%s\"", fd, strerror(r));
      break;
   }
}


/*! This function is wrapper for write(2) which creates a log message in case
 * of write failes (i.e. returns -1).
 */
ssize_t oe_write(int fd, const void *buf, size_t count)
{
   ssize_t len;

   if ((len = write(fd, buf, count)) == -1)
      log_msg(LOG_ERR, "write on fd %d failed: %s", fd, strerror(errno));
   return len;
}


/*! Remove leading and trailing spaces of a string.
 *  @param s Pointer to string.
 *  @return Length of string after character removal.
 */ 
int oe_remtr(char *s)
{
   if (!s[0])
      return 0;
   if (s[0] && (s[strlen(s) - 1] == '\n'))
      s[strlen(s) - 1] = '\0';
   if (s[0] && (s[strlen(s) - 1] == '\r'))
      s[strlen(s) - 1] = '\0';
   return strlen(s);
}


/*! Convert character string into struct sockaddr of appropriate address family.
 *  AF_INET and AF_INET6 are supported yet.
 *  @param src Pointer to character string.
 *  @param addr Pointer to struct sockaddr of appropriate type (and size).
 *         It should be pre-initialized. strsockaddr() will not init all fields.
 *  @return address family on success or -1 on error.
 */
int strsockaddr(const char *src, struct sockaddr *addr)
{
   char *s, buf[100];
   int p;

   strlcpy(buf, src, 100);
   if ((s = strchr(buf, '[')))
   {
      s++;
      ((struct sockaddr_in6*) addr)->sin6_family = AF_INET6;
      s = strtok(s, "]");
      if (!inet_pton(AF_INET6, s, &((struct sockaddr_in6*) addr)->sin6_addr))
      {
         log_msg(LOG_ALERT, "\"%s\" contains no valid IPv6 address", s);
         return -1;
      }
      if ((s = strtok(NULL, " ")))
      {
         if (*s == ':')
         {
            s++;
            if ((p = atoi(s)) > 0)
               ((struct sockaddr_in6*) addr)->sin6_port = htons(p);
         }
      }
#ifdef HAVE_SIN_LEN
      ((struct sockaddr_in6*) addr)->sin6_len = sizeof(struct sockaddr_in6);
#endif
      return AF_INET6;
   }

   if (strchr(buf, '.'))
   {
      ((struct sockaddr_in*) addr)->sin_family = AF_INET;
      s = strtok(buf, ":");
      if (!inet_pton(AF_INET, s, &((struct sockaddr_in*) addr)->sin_addr))
      {
         log_msg(LOG_ALERT, "\"%s\" is not a valid IPv4 address", s);
         return -1;
      }
      s = strtok(NULL, ":");
      if (s)
         if ((p = atoi(s)) > 0)
            ((struct sockaddr_in*) addr)->sin_port = htons(p);
#ifdef HAVE_SIN_LEN
      ((struct sockaddr_in*) addr)->sin_len = sizeof(struct sockaddr_in);
#endif
      return AF_INET;
   }

   if ((p = atoi(buf)) > 0)
   {
      switch (((struct sockaddr_in*) addr)->sin_family)
      {
         case AF_INET:
            ((struct sockaddr_in*) addr)->sin_port = htons(p);
            return AF_INET;

         case AF_INET6:
            ((struct sockaddr_in6*) addr)->sin6_port = htons(p);
            return AF_INET;

         default:
            log_debug("address family 0x%04x not supported", ((struct sockaddr_in*) addr)->sin_family);
            return -1;
      }
   }

   return -1;
}


void add_listener(const char *buf)
{
   struct sockaddr_in6 saddr;

   memset(&saddr, 0, sizeof(saddr));
   if (strsockaddr(buf, (struct sockaddr*) &saddr) == -1)
      log_msg(LOG_EMERG, "could not convert address string '%s'", buf), exit(1);

   CNF(oc_listen_cnt)++;
   log_debug("reallocating sockaddr list to %d elements", CNF(oc_listen_cnt));
   if (!(CNF(oc_listen) = realloc(CNF(oc_listen), sizeof(struct sockaddr*) * CNF(oc_listen_cnt))))
      log_msg(LOG_ERR, "could not get memory for listener list: \"%s\"", strerror(errno)), exit(1);
   if (!(CNF(oc_listen_fd) = realloc(CNF(oc_listen_fd), sizeof(int) * CNF(oc_listen_cnt))))
      log_msg(LOG_ERR, "could not get memory for listener fds: \"%s\"", strerror(errno)), exit(1);

   log_debug("allocating sockaddr mem for \"%s\"", buf);
   if (!(CNF(oc_listen)[CNF(oc_listen_cnt) - 1] = calloc(1, sizeof(struct sockaddr_in6))))
      log_msg(LOG_ERR, "could not get memory for listener : \"%s\"", strerror(errno)), exit(1);

   CNF(oc_listen_fd)[CNF(oc_listen_cnt) - 1] = -1;
   memcpy(CNF(oc_listen)[CNF(oc_listen_cnt) - 1], &saddr, sizeof(saddr));
}


void delete_listeners(struct sockaddr **addr, int *fd, int cnt)
{
   log_debug("freeing %d sockaddrs", cnt);
   for (; cnt; cnt--)
      free(addr[cnt - 1]);
   log_debug("freeing sockaddr lists");
   free(addr);
   free(fd);
}


/*! Generic implementation of the select(2) call suitable for OnionCat. All
 * parameters are equal to the original select(2) call except t. t is used to
 * fill in a timeval structure.
 */
int oc_select0(int maxfd, fd_set *rset, fd_set *wset, fd_set *eset, int t)
{
   struct timeval tv;

   set_select_timeout0(&tv, t);
   log_debug2("selecting (maxfd = %d)", maxfd);
   if ((maxfd = select(maxfd + 1, rset, wset, eset, &tv)) == -1)
   {
      int e = errno;
      log_debug("select returned: \"%s\"", strerror(errno));
      errno = e;
   }
   else
   {
      log_debug2("select returned %d fds ready", maxfd);
   }

   return maxfd;
}


/*! This is a wrapper function for oc_select0() with a fixed value of t
 * (SELECT_TIMEOUT).
 */
int oc_select(int maxfd, fd_set *rset, fd_set *wset, fd_set *eset)
{
   return oc_select0(maxfd, rset, wset, eset, SELECT_TIMEOUT);
}

