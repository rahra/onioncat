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

/*! \file ocatresolv.h
 * This file contains declaration for the resolver and the nameserver
 * functions.
 * \author Bernhard R. Fischer
 * \date 2021/07/25
 */

#ifndef OCATRESOLV_H
#define OCATRESOLV_H

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include "ocathosts.h"


#define DNS_MAX_RETRY 5
#define DNS_RETRY_TIMEOUT 5
#define MAX_CONCURRENT_Q 5

/*! resolver error codes */
//! error in function parameters
#define OCRES_EPARAM -1
//! unexpected dns message id
#define OCRES_EID -2
//! format error in dns message
#define OCRES_EFORMAT -3
//! NXDOMAIN response
#define OCRES_ENXDOMAIN -4
//! any other RCODE in dns response
#define OCRES_ERCODE -5
//! internal hosts db error
#define OCRES_EHDB -6


typedef struct ocres_query
{
   time_t restart_time;
   int retry;
   int id;
   int code;
   struct sockaddr_in6 ns;
   hsrc_t ns_src;
} ocres_query_t;

typedef struct ocres_state
{
   struct ocres_state *next;
   int fd;
   int cnt;
   struct in6_addr addr;
   void *p;
   void (*callback)(void *, struct in6_addr, int);
   ocres_query_t qry[MAX_CONCURRENT_Q];
   int msg_len;
   char msg[PACKETSZ];
} ocres_state_t;


int oc_mk_ptrquery(const char *, char *, int, uint16_t);
int oc_proc_response(const char *, int , uint16_t , const struct in6_addr *, hsrc_t );
void *oc_nameserver(void *);
void *oc_resolver(void *);
int ocres_query_callback(const struct in6_addr *, void (*)(void *, struct in6_addr, int), void *);
int ocres_query(const struct in6_addr *);


#endif

