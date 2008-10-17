/* Copyright 2008 Bernhard R. Fischer, Daniel Haslinger.
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

#ifndef OCAT_H
#define OCAT_H

#include "config.h"

#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <time.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
#include <pthread.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#elif HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#include <net/ethernet.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#define IP6HLEN sizeof(struct ip6_hdr)
//! TOR prefix: FD87:D87E:EB43::/48
#define TOR_PREFIX {0xfd,0x87,0xd8,0x7e,0xeb,0x43}
#define TOR_PREFIX_LEN 48
#if BYTE_ORDER == LITTLE_ENDIAN
#define TOR_PREFIX4 {0x0000000a}
#define TOR_PREFIX4_MASK 0x000000ff
#else
#define TOR_PREFIX4 {0x0a000000}
#define TOR_PREFIX4_MASK 0xff000000
#endif
#define MAXPEERS 1024
//! Local listening port for incoming connections from TOR.
#define OCAT_LISTEN_PORT 8060
//! Local control port for querying status information.
#define OCAT_CTRL_PORT 8066
//! Virtual destination port for hidden services
#define OCAT_DEST_PORT 8060
//! SOCKS port of TOR proxy
#define TOR_SOCKS_PORT 9050
#define OCAT_UNAME "tor"
#define OCAT_UID 112
#define OCAT_URL "http://www.abenteuerland.at/onioncat/"
#define OCAT_DIR ".ocat"
#define OCAT_CONNECT_LOG "connect_log"

//! Maximum frame (packet) size, should be able to keep one maximum size ipv6-packet: 2^16 + 40 + 4
#define FRAME_SIZE 65580
#define ONION_NAME_SIZE 23

#define DEQUEUER_WAKEUP 3
//! maximum number a packet stays in queue
#define MAX_QUEUE_DELAY 10

//! Maximum idle time for a peer, after that time the peer is closed.
#define MAX_IDLE_TIME 120
#define CLEANER_WAKEUP 10
#define STAT_WAKEUP (120/CLEANER_WAKEUP)

//! log flags. word is considered as 16 bit, lower byte for level, upper byte for additional flags.
#define L_LEVEL_MASK 0x00ff
#define L_FLAG_MASK 0xff00
#define L_INFO 0
#define L_NOTICE 1
#define L_ERROR 2
#define L_FATAL 3
#define L_DEBUG 4
#define L_FCONN (1 << 15)

#define E_SOCKS_SOCK -1
#define E_SOCKS_CONN -2
#define E_SOCKS_REQ -3
#define E_SOCKS_RQFAIL -4

#define E_FWD_NOPEER -1
#define E_FWD_NOBUF -2

//#define PEER_CONNECT 0
#define PEER_ACTIVE 1

#define PEER_INCOMING 0
#define PEER_OUTGOING 1

#define THREAD_NAME_LEN 11

#define SOCKS_CONNECTING 1
#define SOCKS_MAX_RETRY 3

#define E_RT_NOMEM -1
#define E_RT_DUP -2
#define E_RT_ILLNM -3
#define E_RT_SYNTAX -4
#define E_RT_NULLPTR -5
#define E_RT_NOTORGW -6
#define E_RT_GWSELF -7

//! maximum number of MAC address entries in table
#define MAX_MAC_ENTRY 128
//! maximum age of MAC address in table
#define MAX_MAC_AGE 120

#define IPV4_KEY 0
#define IPV6_KEY 1

struct OcatSetup
{
   //! frame header of local OS in network byte order
   //! it is initialized in ocattun.c
   uint32_t fhd_key[2];
   //! TCP port of SOCKS port of local Tor proxy
   uint16_t tor_socks_port;
   //! reload port of OnionCat listening for connections
   uint16_t ocat_listen_port;
   //! virtual port of OnionCat hidden service
   uint16_t ocat_dest_port;
   //! local port of controller interface
   uint16_t ocat_ctrl_port;
   //! file descriptors of TUN device (usually tunfd[0] == tunfd[1])
   int tunfd[2];
   int debug_level;
   //! user name to change uid to
   char *usrname;
   char onion_url[ONION_NAME_SIZE];
   struct in6_addr ocat_addr;
   //! flag to create connection log
   int create_clog;
   //! flag to not change uid to unprivileged user
   int runasroot;
   //int urlconv;
   //int test_only;
   int controller;
   char *ocat_dir;
   char *tun_dev;
   int ipv4_enable;
   struct in_addr ocat_addr4;
   int ocat_addr4_mask;
   char *config_file;
   int config_read;
   int use_tap;
   int icmpv6fd[2];
   uint8_t ocat_hwaddr[ETH_ALEN];
};

typedef struct PacketQueue
{
   struct PacketQueue *next;
   struct in6_addr addr;
   int psize;
   time_t time;
   void *data;
} PacketQueue_t;

typedef struct SocksHdr
{
   char ver;
   char cmd;
   uint16_t port;
   struct in_addr addr;
} __attribute__((packed)) SocksHdr_t;

typedef struct OcatPeer
{
   struct OcatPeer *next;  //!< pointer to next peer in list
   struct in6_addr addr;   //!< remote address of peer
   int tcpfd;              //!< remote file descriptor
   time_t time;            //!< timestamp of latest packet
   time_t sdelay;          //!< connection setup delay
   time_t otime;           //!< opening time
   int state;              //!< status of peer
   int dir;                //!< direction this session was opened
   unsigned long out;      //!< bytes output
   unsigned long in;       //!< bytes input
   uint32_t fraghdr;       //!< local tun frame header
   char fragbuf[FRAME_SIZE - 4]; //!< (de)frag buffer
   int fraglen;            //!< current frag buffer size
   pthread_mutex_t mutex;  //!< mutex for thread locking
} __attribute__((packed)) OcatPeer_t;

typedef struct OcatThread
{
   struct OcatThread *next;
   pthread_t handle;
   int id;
   char name[THREAD_NAME_LEN];
   void *(*entry)(void*);
   void *parm;
} OcatThread_t;

typedef struct SocksQueue
{
   struct SocksQueue *next;
   struct in6_addr addr;
   int state;
} SocksQueue_t;

typedef struct IPv4Route
{
   struct IPv4Route *next[2];    //!< next routes in binary tree
   uint32_t dest;
   uint32_t netmask;
   struct in6_addr gw;
} IPv4Route_t;

typedef struct MACTable
{
   struct in6_addr in6addr;
   uint8_t hwaddr[ETH_ALEN];
   time_t age;
} MACTable_t;

/*
// next header value for ocat internal use (RFC3692)
#define OCAT_NEXT_HEADER 254

typedef struct OcatHdr
{
   uint16_t oh_plen;
   uint8_t oh_nxt;
//   struct ip6_hdrctl oh_ip6hdrctl;
//   char oh_srcid[10];
} OcatHdr_t;


#define OCAT_CTL_SRC 1
#define OCAT_CTL_EREQ 2
#define OCAT_CTL_ERES 3

typedef struct OcatCtrlHdr
{
   uint8_t oct_type;
   char oct_srcid[10];
} OcatCtrlHdr_t;
*/


#ifndef HAVE_STRUCT_IP6_HDR
struct ip6_hdr
  {
    union
      {
   struct ip6_hdrctl
     {
       uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                   20 bits flow-ID */
       uint16_t ip6_un1_plen;   /* payload length */
       uint8_t  ip6_un1_nxt;    /* next header */
       uint8_t  ip6_un1_hlim;   /* hop limit */
     } ip6_un1;
   uint8_t ip6_un2_vfc;         /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct in6_addr ip6_src;    /* source address */
    struct in6_addr ip6_dst;    /* destination address */
  };

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim
#endif

#ifndef WITHOUT_TUN
#define TUN_DEV "/dev/net/tun"
extern char *tun_dev_;
#endif

extern pthread_mutex_t thread_mutex_;
extern OcatThread_t *octh_;

/* ocat.c */


/* ocatlog.c */
int open_connect_log(const char*);
void log_msg(int, const char *, ...);
#define DEBUG
#ifdef DEBUG
#define log_debug(x...) log_msg(L_DEBUG, ## x)
#else
#define log_debug(x...)
#endif

/* ocatv6conv.c */
char *ipv6tonion(const struct in6_addr *, char *);
int oniontipv6(const char *, struct in6_addr *);
int oniontipv4(const char *, struct in_addr *, int);
int has_tor_prefix(const struct in6_addr *);

/* ocattun.c */
#ifndef WITHOUT_TUN
int tun_alloc(char *, struct in6_addr);
#endif

/* ocatroute.c */
void init_peers(void);
void *socket_receiver(void *);
void packet_forwarder(void);
void *packet_dequeuer(void *);
void *socket_acceptor(void *);
void *socks_connector(void *);
void *socket_cleaner(void *);
void *ocat_controller(void *);
void *ctrl_handler(void *);

/* ocatthread.c */
const OcatThread_t *init_ocat_thread(const char *);
int run_ocat_thread(const char *, void *(*)(void*), void*);
const OcatThread_t *get_thread(void);

/* ocatcompat.c */
#ifndef HAVE_STRLCAT
size_t strlcat(char*, const char*, size_t);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char*, const char*, size_t);
#endif

/* ocatpeer.c */
OcatPeer_t *get_first_peer(void);
OcatPeer_t **get_first_peer_ptr(void);
int lock_peers(void);
int unlock_peers(void);
int lock_peer(OcatPeer_t *);
int unlock_peer(OcatPeer_t *);
OcatPeer_t *search_peer(const struct in6_addr *);
OcatPeer_t *get_empty_peer(void);
void delete_peer(OcatPeer_t *);

/* ocatsetup.c */
extern struct OcatSetup setup;

/* ocatipv4route.c */
struct in6_addr *ipv4_lookup_route(uint32_t);
int parse_route(const char *);
void print_routes(FILE *);

/* ocateth.c */
void *icmpv6_handler(void *);

#endif

