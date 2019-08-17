/* Copyright 2008-2010 Bernhard R. Fischer.
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// For testing compile this file with
// gcc -DINC_MAIN -Wall -DHAVE_CONFIG_H -I.. -o ocathosts -lpthread ocathosts.c strlcpy.c
#ifndef INC_MAIN
#include "ocat.h"
#else
#define log_msg(x,y...) fprintf(stderr, ## y),fprintf(stderr, "\n")
#define log_debug(x...) log_msg(LOG_DEBUG, ## x)
#endif
#include "ocathosts.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif


static struct hosts_info hosts_ = {{0, 0}, -1, NULL, 0, ""};
static char *path_hosts_ = NULL;
static pthread_mutex_t hosts_mutex_ = PTHREAD_MUTEX_INITIALIZER;


/*! Set path to hosts file.
 * @param s Char pointer to string.
 * @return Returns old pointer.
 **/
char *hosts_set_path(char *s)
{
   char *op = path_hosts_;

   path_hosts_ = s;
   return op;
}


/*! Test if modification time changed.
 *  @param fd File descriptor of file to test;
 *  @param ts Pointer to buffer of old timespec.
 *  @return 0 if nothing changed, -1 on error (i.e. file
 *          might have changed) and 1 if mtime changed. In the latter case
 *          ts will be updated.
 **/
int hosts_file_modified_r(struct timespec *ts)
{
   struct stat st;

   log_debug("checking if file \"%s\" was modified", path_hosts_);
   if (stat(path_hosts_, &st) == -1)
   {
      log_msg(LOG_ERR, "stat on \"%s\" failed: \"%s\"", path_hosts_, strerror(errno));
      return -1;
   }

#ifdef HAVE_STAT_ST_MTIM
   if ((st.st_mtim.tv_sec == ts->tv_sec) && (st.st_mtim.tv_nsec == ts->tv_nsec))
#elif HAVE_STAT_ST_MTIMESPEC
   if ((st.st_mtimespec.tv_sec == ts->tv_sec) && (st.st_mtimespec.tv_nsec == ts->tv_nsec))
#else
   if (st.st_mtime == ts->tv_sec)
#endif
      return 0;

   log_debug("%s modified", path_hosts_);
#ifdef HAVE_STAT_ST_MTIM
   *ts = st.st_mtim;
#elif HAVE_STAT_ST_MTIMESPEC
   *ts = st.st_mtimespec;
#else
   ts->tv_sec = st.st_mtime;
#endif
   return 1;
}


int hosts_read(struct hosts_ent **hent)
{
   int e, n = 0, c;
   char buf[HOSTS_LINE_LENGTH + 1], *s;
   struct addrinfo hints, *res;
   struct hosts_ent *h;
   FILE *f;

   if ((f = fopen(path_hosts_, "r")) == NULL)
   {
      log_msg(LOG_ERR, "fopen(\"%s\"...) failed: \"%s\"", path_hosts_, strerror(errno));
      return -1;
   }

   pthread_mutex_lock(&hosts_mutex_);
   if (*hent)
   {
      free(*hent);
      *hent = NULL;
   }

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_INET6;
   hints.ai_flags = AI_NUMERICHOST;
   while (fgets(buf, HOSTS_LINE_LENGTH, f) != NULL)
   {
      if ((s = strtok(buf, " \t\r\n")) == NULL)
         continue;

      // skip comments
      if (s[0] == '#')
         continue;

      if ((e = getaddrinfo(s, NULL, &hints, &res)) != 0)
      {
         log_debug("getaddrinfo(\"%s\"...) failed: \"%s\"", s, gai_strerror(e));
         continue;
      }

      // to be on the safe side check address family
      if (res->ai_family != AF_INET6)
      {
         // this should never happen
         log_debug("ai_family = %d (!= AF_INET6)", res->ai_family);
         freeaddrinfo(res);
         continue;
      }

      // parse all hostnames behind IPv6 address
      for (c = 0; (s = strtok(NULL, " \t\r\n")); c++)
      {
         // copy hostname if it ends with "${hdom_}"
         if ((strlen(s) > strlen(hosts_.hdom)) && !strcasecmp(s + (strlen(s) - strlen(hosts_.hdom)), hosts_.hdom))
         {
            if ((*hent = realloc(*hent, ++n * sizeof(struct hosts_ent))) == NULL)
            {
               log_msg(LOG_ERR, "realloc failed: \"%s\"", strerror(errno));
               n--;
               break;
            }

            h = (*hent) + n - 1;
            h->addr = ((struct sockaddr_in6*) res->ai_addr)->sin6_addr;
            strlcpy(h->name, s, NI_MAXHOST);
            break;
         }
      }
      freeaddrinfo(res);
   }

   pthread_mutex_unlock(&hosts_mutex_);
   (void) fclose(f);

   log_debug("found %d valid IPv6 records in %s", n, path_hosts_);

   return n;
}


/*! Open hosts file and read IPv6 records.
 *  @return -1 on error and 0 on success.
 */
int hosts_check(void)
{
#ifdef __CYGWIN__
   static char path_hosts[1024] = {'\0'};
   char *s;
#endif

   if (path_hosts_ == NULL)
   {
#ifdef __CYGWIN__
      if ((s = getenv("WINDIR")) != NULL)
      {
         snprintf(path_hosts, sizeof(path_hosts), "%s\\system32\\drivers\\etc\\hosts", s);
         path_hosts_ = path_hosts;
      }
#else
      path_hosts_ = _PATH_HOSTS;
#endif
   }

   if (hosts_file_modified_r(&hosts_.hosts_ts))
      hosts_.hosts_ent_cnt = hosts_read(&hosts_.hosts_ent);

   return 0;
}


/*! Return name for IPv6 address.
 *  @return 0 on success, -1 on error.
 **/
int hosts_get_name(const struct in6_addr *addr, char *buf, int s)
{
   int i;
   struct hosts_ent *h;

   log_debug("looking up name");
   pthread_mutex_lock(&hosts_mutex_);
   for (i = hosts_.hosts_ent_cnt - 1, h = hosts_.hosts_ent; i >= 0; i--, h++)
      if (IN6_ARE_ADDR_EQUAL(addr, &h->addr))
      {
         strlcpy(buf, h->name, s);
         log_debug("name \"%s\" found", buf);
         break;
      }
   pthread_mutex_unlock(&hosts_mutex_);

   if (i < 0)
      return -1;

   return 0;
}


/*! Output list of hosts to file.
 *  @return Returns always 0.
 **/
int hosts_list(FILE *f)
{
   char in6[INET6_ADDRSTRLEN];
   int i;
   struct hosts_ent *h;

   pthread_mutex_lock(&hosts_mutex_);
   for (i = hosts_.hosts_ent_cnt - 1, h = hosts_.hosts_ent; i >= 0; i--, h++)
   {
      if (inet_ntop(AF_INET6, &h->addr, in6, sizeof(in6)) == NULL)
      {
         log_msg(LOG_ERR, "inet_ntop() failed: %s", strerror(errno));
         continue;
      }
      fprintf(f, "%s %s\n", in6, h->name);
   }
   pthread_mutex_unlock(&hosts_mutex_);
   return 0;
}


void hosts_init(const char *dom)
{
   hosts_.hdom = dom;
}


#ifdef INC_MAIN
int main()
{
   int i;
   struct hosts_ent *h;
   struct in6_addr addr = IN6ADDR_LOOPBACK_INIT;
   char buf[NI_MAXHOST];

   hosts_init(".b32.i2p");
   hosts_check();

   h = hosts_.hosts_ent;
   for (i = 0; i < hosts_.hosts_ent_cnt; i++, h++)
   {
      printf("%s\n", h->name);
   }

   if (!hosts_get_name(&addr, buf, NI_MAXHOST))
      printf("loopname = \"%s\"\n", buf);

   return 0;
}
#endif

