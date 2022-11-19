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
static int hosts_db_modified_ = 0;
static ns_ent_t ns_[MAX_NS];


int hosts_add_entry_unlocked(const struct in6_addr *addr, const char *name, hsrc_t source, time_t age, int ttl);


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


/*! Remove all elements from hosts db where ttl expired (== 0).
 */
void hosts_cleanup(void)
{
   int i;

   pthread_mutex_lock(&hosts_mutex_);
   for (i = 0; i < hosts_.hosts_ent_cnt; i++)
   {
      // ignore hosts with ttl not expired
      if (hosts_.hosts_ent[i].ttl)
         continue;

      log_debug("removing host %s", hosts_.hosts_ent[i].name);
      // if ith element is not the last element in the list...
      if (i < hosts_.hosts_ent_cnt - 1)
         // copy last element to ith position
         memcpy(&hosts_.hosts_ent[i], &hosts_.hosts_ent[hosts_.hosts_ent_cnt - 1], sizeof(hosts_.hosts_ent[i]));

      // dec length of list
      hosts_.hosts_ent_cnt--;
      // mark db as modified
      hosts_db_modified_ = 1;
      // restart again on same position (undo i++ of for loop)
      i--;
   }
   pthread_mutex_unlock(&hosts_mutex_);
}


/*! Read and parse hosts file and add new elements to the internal hosts db.
 * Entries which were removed from the hosts file are removed by expiring the
 * ttl. The age of the new entries are set to ´age´ which typically is the
 * modification time of the file. The ttl of the entries are set to -1 which
 * means that they never expire.
 * @param age Age to be set for new entries. This is a Unix timestamp.
 * @return The function returns the total number of entries in the internal
 * hosts db. On error, -1 is returned.
 */
int hosts_read(time_t age, const char *phosts)
{
   int e, n, o = 0, c, src, ttl;
   char buf[HOSTS_LINE_LENGTH + 1], *s, *nptr, *rem, *host;
   struct addrinfo hints, *res;
   FILE *f;

   log_msg(LOG_INFO, "reading hosts file %s", phosts);
   if ((f = fopen(phosts, "r")) == NULL)
   {
      log_msg(LOG_ERR, "fopen(\"%s\"...) failed: \"%s\"", phosts, strerror(errno));
      return -1;
   }

   pthread_mutex_lock(&hosts_mutex_);
   // expire all hosts file entries in memory DB
   for (n = 0; n < hosts_.hosts_ent_cnt; n++)
      if (hosts_.hosts_ent[n].source == HSRC_HOSTS)
         hosts_.hosts_ent[n].ttl = 0;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_INET6;
   hints.ai_flags = AI_NUMERICHOST;
   while (fgets(buf, HOSTS_LINE_LENGTH, f) != NULL)
   {
      // skip leading spaces
      s = buf;
      for (; isblank(*s); s++);

      // ignore lines which contain only a comment
      if (*s == '#')
         continue;

      // split remark portion
      rem = NULL;
      if ((s = strtok_r(s, "#", &rem)) == NULL)
         continue;

      nptr = NULL;
      if ((s = strtok_r(s, " \t\r\n", &nptr)) == NULL)
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
      for (host = NULL; (s = strtok_r(NULL, " \t\r\n", &nptr)) != NULL;)
      {
         // copy hostname if it ends with "${hdom_}"
         if ((strlen(s) > strlen(hosts_.hdom)) && !strcasecmp(s + (strlen(s) - strlen(hosts_.hdom)), hosts_.hdom))
         {
            o++;
            host = s;
            //hosts_add_entry_unlocked(&((struct sockaddr_in6*) res->ai_addr)->sin6_addr, s, HSRC_HOSTS, age, -1);
            break;
         }
      }

      // parse comment part, split at every ','
      ttl = -1;
      src = HSRC_HOSTS;
      for (; (s = strtok_r(NULL, ",\r\n", &rem)) != NULL;)
      {
         // split sub portions at '='
         nptr = NULL;
         if ((s = strtok_r(s, "=", &nptr)) == NULL)
            continue;

         if ((s = strtok(s, " \t")) == NULL)
            continue;

         // parse source
         if (!strcmp(s, "src"))
         {
            if ((s = strtok_r(NULL, " \t", &nptr)) == NULL)
               continue;
            if ((c = strtol(s, &nptr, 0)) > HSRC_HOSTS)
               src = c;
         }

         // parse ttl
         if (!strcmp(s, "ttl"))
         {
            if ((s = strtok_r(NULL, " \t", &nptr)) == NULL)
               continue;
            if ((c = strtol(s, &nptr, 0)) > HSRC_HOSTS)
               ttl = c;
         }
      }

      if (host != NULL)
      {
         // hosts file entry do not expire
         if (src <= HSRC_HOSTS)
            ttl = -1;
         // prevent entry from immediate expiry
         else if (age + ttl - time(NULL) <= HOSTS_EXP_REFRESH)
            ttl = time(NULL) - age + HOSTS_EXP_REFRESH;

         hosts_add_entry_unlocked(&((struct sockaddr_in6*) res->ai_addr)->sin6_addr, host, src, age, ttl);
      }

      freeaddrinfo(res);
   }

   pthread_mutex_unlock(&hosts_mutex_);
   (void) fclose(f);

   hosts_cleanup();
   log_debug("found %d valid IPv6 records in %s (total %d)", o, phosts, hosts_.hosts_ent_cnt);

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
      path_hosts_ = CNF(hosts_path);
#if 0
#ifdef __CYGWIN__
      if ((s = getenv("WINDIR")) != NULL)
      {
         snprintf(path_hosts, sizeof(path_hosts), "%s\\system32\\drivers\\etc\\hosts", s);
         path_hosts_ = path_hosts;
      }
#else
      path_hosts_ = _PATH_HOSTS;
#endif
#endif
   }

   if (hosts_file_modified_r(&hosts_.hosts_ts))
      hosts_read(hosts_.hosts_ts.tv_sec, path_hosts_);

   return 0;
}


int validate_hostname(const char *src)
{
   const char * const charset = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM234567";
   char *s, buf[128];
   int len;

   // check if a domain is appended
   if ((s = strchr(src, '.')) == NULL)
   {
      log_msg(LOG_ERR, "name has no domain");
      return -1;
   }

   // check if correct domain is appended
   if (strcmp(s, CNF(domain)))
   {
      log_msg(LOG_ERR, "incorrect domain \"%s\"", s);
      return -1;
   }

   // copy data to buffer and \0-terminate
   strlcpy(buf, src, sizeof(buf));
   buf[s - src] = '\0';
   len = strlen(buf);

   // check for valid onion name length (v2 -> 16, HSv3 -> 56, I2P -> 52)
   if ((len != 16) && (len != CNF(l_hs_namelen)))
   {
      log_msg(LOG_ERR, "parameter seems not to be valid onion hostname: invalid length");
      return -1;
   }

   // check for valid base32 charset
   if ((int) strspn(buf, charset) != len)
   {
      log_msg(LOG_ERR, "parameter seems not to be valid onion hostname: invalid characters");
      return -1;
   }

   return len;
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
 *  @return On success it returns a value >= 0. If not found, -1 is returned.
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


/*! Search for slot with lower metric than m.
 * @return Returns index of an empty slot which is 0 <= index < MAX_NS. If not
 * empty slot was found, MAX_NS is returned.
 */
int hosts_search_ns_metric_lt(int m)
{
   int i;

   for (i = 0; i < MAX_NS; i++)
      if (ns_[i].metric < m)
         break;
   return i;
}


/*! Search for empty slot in NS list.
 * @return Returns index of an empty slot which is 0 <= index < MAX_NS. If not
 * empty slot was found, MAX_NS is returned.
 */
int hosts_search_ns_empty(void)
{
   int i;

   for (i = 0; i < MAX_NS; i++)
      if (!ns_[i].metric)
         break;
   return i;
}


/*! Search address in NS list.
 * @param addr Adress to search for.
 * @return Returns index in NS list which is 0 <= index < MAX_NS. If the
 * address is not found, MAX_NS is returned.
 */
int hosts_search_ns(const struct in6_addr *addr)
{
   int i;

   for (i = 0; i < MAX_NS; i++)
      if (ns_[i].metric && IN6_ARE_ADDR_EQUAL(addr, &ns_[i].addr))
         break;
   return i;
}


/*! Compare two ns_ent_t structures by its metric.
 */
static int cmp_ns(const void *a, const void *b)
{
   if (((ns_ent_t*) a)->metric == ((ns_ent_t*) b)->metric)
      return 0;
   return ((ns_ent_t*) a)->metric < ((ns_ent_t*) b)->metric ? -1 : 1;

}


/*! Update NS list.
 */
static int hosts_update_ns0(void)
{
   int mod[MAX_NS];
   int i, j, m;

   log_debug("updating NS list");
   memset(mod, 0, sizeof(mod));
   j = -1;

   pthread_mutex_lock(&hosts_mutex_);
   for (i = 0; i < hosts_.hosts_ent_cnt; i++)
   {
      // ignore self and empty entries
      if (hosts_.hosts_ent[i].source <= HSRC_SELF)
         continue;

      // look of NS entry was already in the list
      if ((j = hosts_search_ns(&hosts_.hosts_ent[i].addr)) < MAX_NS)
      {
         // just update the metric
         ns_[j].metric = hosts_metric(&hosts_.hosts_ent[i]);
         ns_[j].source = hosts_.hosts_ent[i].source;
         mod[j] = 1;
      }
      // else if NS entry was not found
      else
      {
         // look for empty slot in NS list
         if ((j = hosts_search_ns_empty()) < MAX_NS)
         {
            ns_[j].metric = hosts_metric(&hosts_.hosts_ent[i]);
            ns_[j].source = hosts_.hosts_ent[i].source;
            IN6_ADDR_COPY(&ns_[j].addr, &hosts_.hosts_ent[i].addr);
            mod[j] = 1;
         }
         // no empty slot was found
         else
         {
            m = hosts_metric(&hosts_.hosts_ent[i]);
            // search for slot with smaller metric
            if ((j = hosts_search_ns_metric_lt(m)) < MAX_NS)
            {
               ns_[j].metric = hosts_metric(&hosts_.hosts_ent[i]);
               ns_[j].source = hosts_.hosts_ent[i].source;
               IN6_ADDR_COPY(&ns_[j].addr, &hosts_.hosts_ent[i].addr);
               mod[j] = 1;
            }
         }
      }
   }

   // finally cleanup now unused NS slots
   for (i = 0; i < MAX_NS; i++)
      if (!mod[j])
         ns_[j].metric = 0;

   // sort list
   qsort(ns_, MAX_NS, sizeof(ns_[0]), cmp_ns);

   pthread_mutex_unlock(&hosts_mutex_);

   return 0;
}


int hosts_update_ns(void)
{
   static time_t _t = 0;

   if (_t > time(NULL))
      return 0;

   _t = time(NULL) + NS_UPDATE_TIME;
   return hosts_update_ns0();
}


/*! Get nameserver of the list of nameservers in round robin order. The list of
 * nameservers is a subset of hosts db. It contains not more than MAX_NS
 * entries with the highest metrics of the hosts db. the nameserver list is
 * sorted descendingly by the metic, i.e. the best nameserver is found on index
 * 0.
 * @param addr If not NULL the address of the nameserver will be copied here.
 * @param ns_src If not NULL, the source of nameserver address will be copied
 * here.
 * @param nptr If not NULL, the index to the next entry will be copied here.
 * Start calling with 0 and then repeatedly call with the same variable to
 * round robin over the list. It will automatically wrap back to 0. So be
 * carefull detecting the end!
 * @return On success the function returns a value >= 0 which is the same as
 * stored in nptr. If no nameservers are found in the list -1 is returned.
 */
int hosts_get_ns_rr_metric(struct in6_addr *addr, hsrc_t *ns_src, int *nptr)
{
   int i, j, n;

   // update ns list
   hosts_update_ns();

   n = nptr == NULL ? -1 : *nptr;

   // safety check
   if (n < 0) n = 0;

   pthread_mutex_lock(&hosts_mutex_);
   for (i = 0; i < MAX_NS; i++)
   {
      j = (i + n) % MAX_NS;
      if (ns_[j].metric)
      {
         if (addr != NULL)
            IN6_ADDR_COPY(addr, &ns_[j].addr);
         if (ns_src != NULL)
            *ns_src = ns_[j].source;
         break;
      }
   }
   pthread_mutex_unlock(&hosts_mutex_);

   if (i >= MAX_NS)
      return -1;

   if (nptr != NULL)
      *nptr = j + 1;

   return j + 1;
}


/*! Get address of a name server from the hosts db in round robin order.
 * @param addr Pointer to memory which will receive the address.
 * @param ns_src Pointer will receive the NS source (hsrc_t).
 * @param nptr Pointer to index in hosts DB to get NS from. This will be
 * increased by 1 on each call (and set back to 0 at the end of the list).
 * @return The function returns the index in the hosts table of the entry which
 * is always >= 0. On error, -1 is returned.
 */
int hosts_get_ns_rr(struct in6_addr *addr, hsrc_t *ns_src, int *nptr)
{
   int n;

   // safety check
   if (addr == NULL || nptr == NULL)
      return -1;

   n = *nptr;
   n++;

   // safety check
   if (n < 0) n = 0;

   pthread_mutex_lock(&hosts_mutex_);

   // make sure n is smaller than table num of entries (i.e. if length of list decreased since the last call)
   if (n >= hosts_.hosts_ent_cnt)
      n = 0;

   for (; n < hosts_.hosts_ent_cnt; n++)
      if (hosts_.hosts_ent[n].source > HSRC_SELF)
      {
         IN6_ADDR_COPY(addr, &hosts_.hosts_ent[n].addr);
         if (ns_src != NULL)
            *ns_src = hosts_.hosts_ent[n].source;
         break;
      }
   pthread_mutex_unlock(&hosts_mutex_);

   *nptr = n;
   return n < hosts_.hosts_ent_cnt ? n : -1;
}


int hosts_get_ns(struct in6_addr *addr, hsrc_t *ns_src)
{
   static int n = 0;
   return hosts_get_ns_rr(addr, ns_src, &n);
}


static void hosts_copy_data(struct hosts_ent *h, const char *name, int source, time_t age, int ttl)
{
   h->source = source;
   h->age = age;
   h->ttl = ttl;
   if (strcmp(h->name, name))
   {
      strlcpy(h->name, name, NI_MAXHOST);
      log_msg(LOG_INFO, "name %s updated, source = %d", name, source);
   }
}


/*! Create a random number dependet of the IPv6 address is lower or greater
 * than the own address. If the own address is lower than addr, 0 is returned.
 * If the own address is greater than addr, a random value 10 <= x <= 60 is
 * returned. This is meant to be additional to the TTL in the hosts db to avoid
 * concurrent reconnects for the cache refresh. As a result, the OnionCat with
 * the lower address will refresh first.
 * @param addr Pointer to the IPv6 address of the hosts db to check.
 * @return Returns Either 0, or 10 <= x <= 60.
 */
int hosts_ttl_delay(const struct in6_addr *addr)
{
   if (memcmp(&CNF(ocat_addr), addr, sizeof(*addr)) < 0)
      return 0;

   return rand() % 50 + 10;
}


/*! Add an entry to the hosts memory database. If the entry (based on addr)
 * does already exist, it is updated accordingly if the source is less or equal
 * the source value in the hosts db.
 * @param addr Pointer to IPv6 address of hostame.
 * @param name Pointer to hostname.
 * @param source Source of entry of type hsrc_t (see ocathosts.h).
 * @param age Time when the entry was created/updated. This typically is the
 * current time.
 * @param ttl TTL of the entry. If set to -1 it will never expire.
 * @return Returns the index in the database or -1 on error.
 */
int hosts_add_entry_unlocked(const struct in6_addr *addr, const char *name, hsrc_t source, time_t age, int ttl)
{
   struct in6_addr taddr;
   struct hosts_ent *h;
   int n;

   if (CNF(validate_remnames) && source > HSRC_HOSTS)
   {
      // check if hostname is valid
      if (validate_onionname(name, &taddr) == -1)
         return -1;

      // check if ip address is a valid OnionCat address
      if (!IN6_ARE_ADDR_EQUAL(addr, &taddr))
         return -1;
   }

   // add random delay
   if (ttl > 0)
      ttl += hosts_ttl_delay(addr);

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

      // clear new memory area
      memset(&hosts_.hosts_ent[n], 0, sizeof(hosts_.hosts_ent[n]));

      // copy address to new entry
      hosts_.hosts_ent[n].addr = *addr;

      // copy data to new entry
      hosts_copy_data(&hosts_.hosts_ent[n], name, source, age, ttl);
      // mark db as modified
      hosts_db_modified_ = 1;
   }
   else if (hosts_.hosts_ent[n].source >= source)
   {
      log_debug("overwriting old.source = %d, new.source = %d", hosts_.hosts_ent[n].source, source);
      hosts_copy_data(&hosts_.hosts_ent[n], name, source, age, ttl);
      // mark db as modified
      hosts_db_modified_ = 1;
   }
   else
   {
      log_debug("hosts file entries cannot be overwritten with this function");
   }

   return n;
}


/*! Calculate metric of host.
 * The metric depends on source of the entry and the query stats. This is the
 * number of queries sent out and the postive responses that came back. The
 * metric gets higher with a lower source and a higher number of positive
 * responses.
 * A higher metric is better than a lower.
 * @param hent Pointer to entry in hosts db.
 * @return Returns the metric of the host which is a positive integer number. 0
 * is the worst and should be interpreted as "do not use". The current maximum
 * value is 2000.
 */
int hosts_metric(const host_ent_t *hent)
{
   int m;

   if (hent->source <= 0)
      return 0;

   m = 1000 / hent->source;

   if (hent->stat.q_cnt > 0)
      m += hent->stat.ans_cnt * 1000 / hent->stat.q_cnt;

   return m;
}


/*! Increase query counter in host stats.
 **/
void host_stats_inc_q(const struct in6_addr *addr)
{
   int i;

   pthread_mutex_lock(&hosts_mutex_);
   if ((i = hosts_get_name_unlocked(addr, NULL, 0)) != -1)
      hosts_.hosts_ent[i].stat.q_cnt++;
   pthread_mutex_unlock(&hosts_mutex_);
}


/*! Increase answer counter(s) in host stats.
 **/
void host_stats_inc_ans(const struct in6_addr *addr, int code)
{
   int i;

   pthread_mutex_lock(&hosts_mutex_);
   if ((i = hosts_get_name_unlocked(addr, NULL, 0)) != -1)
   {
      switch (code)
      {
         case 0:
            hosts_.hosts_ent[i].stat.ans_cnt++;
            break;
         case OCRES_ENXDOMAIN:
            hosts_.hosts_ent[i].stat.nx_cnt++;
            break;
      }
   }
   pthread_mutex_unlock(&hosts_mutex_);
}


/*! Add or update hosts db entry.
 * @param addr Pointer to IPv6 address of hostame.
 * @param name Pointer to hostname.
 * @param source Source of entry of type hsrc_t (see ocathosts.h).
 * @param age Time when the entry was created/updated. This typically is the
 * current time.
 * @param ttl TTL of the entry. If set to -1 it will never expire.
 * @return On error -1 is returned, otherwise a value >= 0.
 */
int hosts_add_entry(const struct in6_addr *addr, const char *name, hsrc_t source, time_t age, int ttl)
{
   int n;

   pthread_mutex_lock(&hosts_mutex_);
   n = hosts_add_entry_unlocked(addr, name, source, age, ttl);
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


/*! Return current TTL of hosts entry based on age, ttl, and current time. A
 * ttl of -1 means infinite ttl.
 * @param age Time when the entry was added to the hosts db.
 * @param ttl TTL as set when entry was added.
 * @return Returns the current TTL.
 */
int hosts_ttl(const host_ent_t *h)
{
   int ttl;

   if (h->ttl < 0)
      return h->ttl;

   ttl = h->ttl + h->age - time(NULL);

   return ttl >= 0 ? ttl : 0;
}


static int hosts_should_refresh(int ttl)
{
   return ttl >= 0 && ttl <= HOSTS_EXP_REFRESH;
}


/*! Trigger new outgoing connection for all remote hosts entries to refresh
 * hosts db (because of resulting keepalives).
 */
void hosts_refresh(void)
{
   int i;

   pthread_mutex_lock(&hosts_mutex_);
   for (i = 0; i < hosts_.hosts_ent_cnt; i++)
      if (hosts_.hosts_ent[i].source > HSRC_HOSTS)
      {
         if (CNF(expire) > 0 && hosts_.hosts_ent[i].age + CNF(expire) < time(NULL))
         {
            log_debug("entry expired");
            hosts_.hosts_ent[i].ttl = 0;
         }
         else if (hosts_should_refresh(hosts_ttl(&hosts_.hosts_ent[i])))
         {
            log_debug("trying to refresh entry");
            socks_queue(hosts_.hosts_ent[i].addr, 0);
            hosts_.hosts_ent[i].ttl = time(NULL) - hosts_.hosts_ent[i].age + HOSTS_KPLV_TTL;
         }
      }
   pthread_mutex_unlock(&hosts_mutex_);
}


/*! Return string according to hosts source type.
 * @param source Hosts source type.
 * @return Returns a constant string.
 */
const char *hosts_source(hsrc_t source)
{
   switch (source)
   {
      case HSRC_SELF:
         return "own address";
      case HSRC_CLI:
         return "cli";
      case HSRC_HOSTS:
         return "hosts file";
      case HSRC_KPLV:
         return "keepalive";
      case HSRC_NET_AA:
         return "authorative NS response";
      case HSRC_NET:
         return "NS response";
      default:
         return "unknown";
   }
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
   char in6[INET6_ADDRSTRLEN], tstr[32];
   struct tm tm;
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
      strftime(tstr, sizeof(tstr), "%Y-%m-%dT%H:%M:%S%z", localtime_r(&h->age, &tm));
      if ((plen = snprintf(buf, len, "# hostname =\"%s\", entry_time = \"%s\", source_str = \"%s\"\n%s %s # age = %ld, ttl = %d, src = %d, qcnt = %d, anscnt = %d, nxcnt = %d, metric = %d\n",
                  h->name, tstr, hosts_source(h->source),
                  in6, h->name, (long) h->age, hosts_ttl(h), h->source, h->stat.q_cnt, h->stat.ans_cnt, h->stat.nx_cnt, hosts_metric(h))) == -1)
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
   memset(ns_, 0, sizeof(ns_));
}


time_t hosts_time(void)
{
   return hosts_.hosts_ts.tv_sec;
}


int hosts_save(const char *name)
{
   char buf[64];
   struct tm tm;
   time_t t;
   FILE *f;

   // safety check
   if (name == NULL)
      return -1;

   log_msg(LOG_INFO, "saving hosts db to file '%s'", name);

   if ((f = fopen(name, "w")) == NULL)
   {
      log_msg(LOG_ERR, "fopen(\"%s\"...) failed: \"%s\"", name, strerror(errno));
      return -1;
   }

   t = time(NULL);
   localtime_r(&t, &tm);
   strftime(buf, sizeof(buf), "%a, %d %b %Y %T %z", &tm);

   fprintf(f, "# FILE GENERATED BY ONIONCAT\n# %s\n#\n", buf);

   hosts_list(f);

   fclose(f);

   pthread_mutex_lock(&hosts_mutex_);
   hosts_db_modified_ = 0;
   pthread_mutex_unlock(&hosts_mutex_);

   return 0;
}


/*! This function changes the owner of the state directory.
 */
int mk_cache_dir(const char *dir, uid_t uid, gid_t gid)
{
   struct stat st;

   if (stat(dir, &st) == -1)
   {
      log_msg(LOG_ERR, "failed to stat dir \"%s\": \"%s\" ...will not be able to save hosts db on exit", dir, strerror(errno));
      return -1;
   }

   if (st.st_uid != uid || st.st_gid != gid)
   {
      if (chown(dir, uid, gid) == -1)
      {
         log_msg(LOG_ERR, "failed to chown dir \"%s\": \"%s\" ...will not be able to save hosts db on exit", dir, strerror(errno));
         return -1;
      }
   }

   return 0;
}


int is_hosts_db_modified(void)
{
   int m;

   pthread_mutex_lock(&hosts_mutex_);
   m = hosts_db_modified_;
   pthread_mutex_unlock(&hosts_mutex_);

   return m;
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

