/* Copyright 2008-2021 Bernhard R. Fischer.
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

/*! \file ocathosts.c
 * This file contains the code of the hosts file handling and OnionCat's
 * internal database of hosts.
 * \author Bernhard R. Fischer
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


int hosts_add_entry_unlocked(const struct in6_addr *addr, const char *name, int source, time_t age);


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


int hosts_read(time_t age)
{
   int e, n = hosts_.hosts_ent_cnt, o = 0, c, rem;
   char buf[HOSTS_LINE_LENGTH + 1], *s;
   struct addrinfo hints, *res;
   FILE *f;

   if ((f = fopen(path_hosts_, "r")) == NULL)
   {
      log_msg(LOG_ERR, "fopen(\"%s\"...) failed: \"%s\"", path_hosts_, strerror(errno));
      return -1;
   }

   pthread_mutex_lock(&hosts_mutex_);
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
      for (c = 0, rem = 0; (s = strtok(NULL, " \t\r\n")) != NULL; c++)
      {
         // ignore anything behind a comment
         if (s[0] == '#')
         {
            rem++;
            if (rem > 1)
            {
               log_debug("ignoring everything after comment in comment");
               break;
            }
         }

         // handling data in comment
         if (rem)
         {
            log_debug("handling data in comment");
            continue;
         }

         // copy hostname if it ends with "${hdom_}"
         if ((strlen(s) > strlen(hosts_.hdom)) && !strcasecmp(s + (strlen(s) - strlen(hosts_.hdom)), hosts_.hdom))
         {
            o++;
            hosts_add_entry_unlocked(&((struct sockaddr_in6*) res->ai_addr)->sin6_addr, s, HSRC_HOSTS, age);
            break;
         }
      }
      freeaddrinfo(res);
   }

   pthread_mutex_unlock(&hosts_mutex_);
   (void) fclose(f);

   log_debug("found %d valid IPv6 records in %s (total %d)", o, path_hosts_, n);

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
      hosts_read(hosts_.hosts_ts.tv_sec);

   return 0;
}


/*! Return name for IPv6 address.
 *  @return On success it returns index >= 0 within host_ent array. If not
 *  found, -1 on error.
 **/
int hosts_get_name_unlocked(const struct in6_addr *addr, char *buf, int s)
{
   int i;
   struct hosts_ent *h;

   for (i = 0, h = hosts_.hosts_ent; i < hosts_.hosts_ent_cnt; i++, h++)
      if (IN6_ARE_ADDR_EQUAL(addr, &h->addr))
      {
         if (buf != NULL)
            strlcpy(buf, h->name, s);
         log_debug("name \"%s\" found", h->name);
         return i;
      }

   return -1;
}


/*! Return name for IPv6 address.
 *  @return On success it returns index >= 0 within host_ent array. If not
 *  found, -1 on error.
 **/
int hosts_get_name_ext(const struct in6_addr *addr, char *buf, int s, int *source, time_t *age)
{
   int i;

   pthread_mutex_lock(&hosts_mutex_);
   if ((i = hosts_get_name_unlocked(addr, buf, s)) != -1)
   {
      if (source != NULL)
         *source = hosts_.hosts_ent[i].source;
      if (age != NULL)
         *age = hosts_.hosts_ent[i].age;
   }
   pthread_mutex_unlock(&hosts_mutex_);

   return i;
}


int hosts_get_name(const struct in6_addr *addr, char *buf, int s)
{
   return hosts_get_name_ext(addr, buf, s, NULL, NULL);
}


/*! Get address of ith hosts entry.
 * @param n Index to hosts table.
 * @param addr Pointer to adress which will receive address.
 * @return On success n is returned, on error -1 is returned.
 */
int hosts_get_addr(int n, struct in6_addr *addr)
{
   // safety check
   if (addr == NULL)
      return -1;

   pthread_mutex_lock(&hosts_mutex_);
   if (n < hosts_.hosts_ent_cnt)
      IN6_ADDR_COPY(addr, &hosts_.hosts_ent[n].addr);
   else
      n = -1;
   pthread_mutex_unlock(&hosts_mutex_);

   return n;
}


static void hosts_copy_data(struct hosts_ent *h, const char *name, int source, time_t age)
{
   h->source = source;
   h->age = age;
   if (strcmp(h->name, name))
   {
      strlcpy(h->name, name, NI_MAXHOST);
      log_msg(LOG_INFO, "name %s updated, source = %d", name, source);
   }
}


/*! Add an entry to the hosts memory database.
 * @return Returns the index in the database or -1 on error.
 */
int hosts_add_entry_unlocked(const struct in6_addr *addr, const char *name, int source, time_t age)
{
   struct hosts_ent *h;
   int n;

   // check if entry already exists
   if ((n = hosts_get_name_unlocked(addr, NULL, 0)) == -1)
   {
      // create new entry if there is no entry yet
      if ((h = realloc(hosts_.hosts_ent, (hosts_.hosts_ent_cnt + 1) * sizeof(*h))) == NULL)
      {
         log_msg(LOG_ERR, "realloc failed: %s", strerror(errno));
         return -1;
      }

      // maintain memory pointers
      hosts_.hosts_ent = h;
      n = hosts_.hosts_ent_cnt;
      hosts_.hosts_ent_cnt++;
      log_debug("created new hosts entry, cnt = %d", hosts_.hosts_ent_cnt);

      // copy address to new entry
      hosts_.hosts_ent[n].addr = *addr;

      // copy data to new entry
      hosts_copy_data(&hosts_.hosts_ent[n], name, source, age);
   }
   else if (source == HSRC_HOSTS || hosts_.hosts_ent[n].source == HSRC_NET || (source != HSRC_NET && hosts_.hosts_ent[n].source == HSRC_KPLV))
   {
      log_debug("overwriting old.source = %d, new.source = %d", hosts_.hosts_ent[n].source, source);
      hosts_copy_data(&hosts_.hosts_ent[n], name, source, age);
   }
   else
   {
      log_debug("hosts file entries cannot be overwritten with this function");
   }

   return n;
}


int hosts_add_entry(const struct in6_addr *addr, const char *name, int source, time_t age)
{
   int n;

   pthread_mutex_lock(&hosts_mutex_);
   n = hosts_add_entry_unlocked(addr, name, source, age);
   pthread_mutex_unlock(&hosts_mutex_);
   return n;
}


/*! Output list of hosts to file.
 *  @return Returns always 0.
 **/
int hosts_list(FILE *f)
{
   char *buf;
   size_t blen;

   // safety check
   if (f == NULL)
      return 0;

   // get memory buffer
   blen = hosts_.hosts_ent_cnt * HOSTS_LINE_LENGTH_OUT;
   if ((buf = malloc(blen)) == NULL)
   {
      log_msg(LOG_CRIT, "malloc failed: %s", strerror(errno));
      return -1;
   }

   // write hosts to buffer
   if ((blen = sn_hosts_list(buf, blen)) <= 0)
   {
      log_msg(LOG_ERR, "hosts buffer should be realloced or increased, not implemented yet...");
      goto hl_exit;
   }

   // write buffer to stream
   if (fwrite(buf, blen, 1, f) != 1)
      log_msg(LOG_WARNING, "could not write data to stream");

   // free buffer and return
hl_exit:
   free(buf);
   return 0;
}


/*! Output the list of hosts to a memory buffer. The function does not write
 * more then len bytes to the buffer.
 * @param buf Pointer to the memory buffer.
 * @param len Size of the buffer.
 * @return On success the function returns the number of bytes written to buf
 * excluding the terminating '\0'. If the buffer was too small, 0 is returned.
 * On error, -1 is returned.
 **/
int sn_hosts_list(char *buf, int len)
{
   char in6[INET6_ADDRSTRLEN];
   int i, plen, wlen = 0;
   struct hosts_ent *h;

   // safety check
   if (buf == NULL || len <= 0)
      return -1;

   wlen = snprintf(buf, len, "# hosts_ent_cnt = %d\n", hosts_.hosts_ent_cnt);
   len -= wlen;
   buf += wlen;

   pthread_mutex_lock(&hosts_mutex_);
   for (i = hosts_.hosts_ent_cnt - 1, h = hosts_.hosts_ent; i >= 0; i--, h++)
   {
      if (inet_ntop(AF_INET6, &h->addr, in6, sizeof(in6)) == NULL)
      {
         log_msg(LOG_ERR, "inet_ntop() failed: %s", strerror(errno));
         continue;
      }
      if ((plen = snprintf(buf, len, "%s %s # age = %ld, src = %d\n", in6, h->name, h->age, h->source)) == -1)
      {
         log_msg(LOG_CRIT, "snprintf() failed");
         wlen = -1;
         break;
      }
      // check if buffer is full
      if (plen >= len)
      {
         log_msg(LOG_WARNING, "output buffer is full");
         wlen = 0;
         break;
      }
      len -= plen;
      buf += plen;
      wlen += plen;
   }
   pthread_mutex_unlock(&hosts_mutex_);

   return wlen;
}


void hosts_init(const char *dom)
{
   hosts_.hdom = dom;
}


time_t hosts_time(void)
{
   return hosts_.hosts_ts.tv_sec;
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

   if (hosts_get_name(&addr, buf, NI_MAXHOST) != -1)
      printf("loopname = \"%s\"\n", buf);

   return 0;
}
#endif

