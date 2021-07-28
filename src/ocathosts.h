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

#ifndef OCATHOSTS_H
#define OCATHOSTS_H

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif


#define HOSTS_LINE_LENGTH 1024
#define HOSTS_LINE_LENGTH_OUT 256
#define HOSTS_KPLV_TTL 3600

typedef enum {HSRC_SELF, HSRC_CLI, HSRC_HOSTS, HSRC_KPLV, HSRC_NET_AA, HSRC_NET} hsrc_t;

struct hosts_ent
{
   struct in6_addr addr;
   char name[NI_MAXHOST];
   time_t age;
   hsrc_t source;
   int ttl;
};

struct hosts_info
{
   struct timespec hosts_ts;
   int hosts_fd;
   struct hosts_ent *hosts_ent;
   int hosts_ent_cnt;
   const char *hdom;
};

char *hosts_set_path(char *);
int hosts_check(void);
int hosts_get_name(const struct in6_addr*, char*, int);
int hosts_get_name_ext(const struct in6_addr *, char *, int, int *, time_t *);
int hosts_get_ns_rr(struct in6_addr *, int *);
int hosts_get_ns(struct in6_addr *);
int hosts_get_addr(int n, struct in6_addr *addr);
int hosts_add_entry(const struct in6_addr *, const char *, hsrc_t, time_t, int);
void hosts_init(const char*);
int hosts_list(FILE *);
int sn_hosts_list(char*, int);
time_t hosts_time(void);


#endif

