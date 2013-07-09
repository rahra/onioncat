/* Copyright 2008,2009 Bernhard R. Fischer.
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

/*! ocatlibe.c
 *  Contains some helper functions.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */


#include "ocat.h"


/*! oe_close is a more robust close() function.
 *  @param fd File descriptor to close.
 */
void oe_close(int fd)
{
   int r;

   log_debug("closing %d", fd);
   while (close(fd) == -1)
   {
      r = errno;
      log_msg(LOG_CRIT, "close(%d) failed: \"%s\"", fd, strerror(r));
      if (r == EINTR)
      {
         log_msg(LOG_ERR, "close(%d) failed: \"%s\". restarting...", fd, strerror(r));
         continue;
      }
      break;
   }
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


int fdaprintf(int fd, int bsiz, const char *fmt, va_list ap)
{
   char buf[bsiz];
   int s, e;

   if ((s = vsnprintf(buf, bsiz, fmt, ap)) >= bsiz)
   {
      return fdaprintf(fd, s + 1, fmt, ap);
   }
   else if (s == -1)
   {
      e = errno;
      log_msg(LOG_WARNING, "vnsprintf failed: \"%s\"", strerror(e));
      errno = e;
      return -1;
   }

   if ((s = write(fd, buf, s)) == -1)
   {
      e = errno;
      log_msg(LOG_WARNING, "write failed: \"%s\"", strerror(e));
      errno = e;
      return -1;
   }
   return s;
}


/*! Output formatted string to file using with a file descriptor.
 *  This function behaves like fprintf().
 *  @param fd File descriptor of file.
 *  @param fmt Format string.
 *  @param ap Variable parameter list.
 *  @return number of bytes written (not including '\0').
 */
int fdprintf(int fd, const char *fmt, va_list ap)
{
   return fdaprintf(fd, SIZE_256, fmt, ap);
}

