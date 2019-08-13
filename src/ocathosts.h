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

struct hosts_ent
{
   struct in6_addr addr;
   char name[NI_MAXHOST];
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
void hosts_init(const char*);
int hosts_list(FILE *);

#endif

