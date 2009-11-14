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
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <syslog.h>

#include <arpa/inet.h>

#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#elif HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif
#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h>
#endif
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif
#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif
#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef __CYGWIN__
#include "cygwin/ocat_cygwin.h"
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#define IP6HLEN sizeof(struct ip6_hdr)
/*//! TOR prefix: FD87:D87E:EB43::/48
#define TOR_PREFIX {{{0xfd,0x87,0xd8,0x7e,0xeb,0x43,0,0,0,0,0,0,0,0,0,0}}}
#define TOR_PREFIX_LEN 48
#if BYTE_ORDER == LITTLE_ENDIAN
#define TOR_PREFIX4 {0x0000000a}
#define TOR_PREFIX4_MASK 0x000000ff
#else
#define TOR_PREFIX4 {0x0a000000}
#define TOR_PREFIX4_MASK 0xff000000
#endif*/
//! Length of an .onion-URL (without ".onion" and '\0')
#define ONION_URL_LEN 16
/*//! Total length of .onion-URL
#define ONION_NAME_SIZE (ONION_URL_LEN + 7)
//! Total length of .onion-URL (equal to ONION_NAME_SIZE)
#define ONION_NAME_LEN ONION_NAME_SIZE*/

#define MAXPEERS 1024
/*//! Local listening port for incoming connections from TOR.
#define OCAT_LISTEN_PORT 8060
//! Local control port for querying status information.
#define OCAT_CTRL_PORT 8066
//! Virtual destination port for hidden services
#define OCAT_DEST_PORT 8060
//! SOCKS port of TOR proxy
#define TOR_SOCKS_PORT 9050*/
#ifdef __OpenBSD__
#define OCAT_UNAME "_tor"
#elif __FreeBSD__
#define OCAT_UNAME "_tor"
#else
#define OCAT_UNAME "tor"
#endif
#define OCAT_UNPRIV_UID 65534
#define OCAT_UNPRIV_UNAME "(unknown)"
#define OCAT_URL "http://www.abenteuerland.at/onioncat/"
#define OCAT_DIR ".ocat"
#define OCAT_CONNECT_LOG "connect_log"
#define PID_FILE "/var/run/ocat.pid"
#define OCAT_AUTHOR "Bernhard R. Fischer"

//! Maximum frame (packet) size, should be able to keep one maximum size ipv6-packet: 2^16 + 40 + 4
#define FRAME_SIZE 65580

//! Standard buffer size 1024 bytes
#define SIZE_1K 1024
#define SIZE_256 256

#define DEQUEUER_WAKEUP 3
//! maximum number a packet stays in queue
#define MAX_QUEUE_DELAY 10

//! Maximum idle time for a peer, after that time the peer is closed.
#define MAX_IDLE_TIME 180
//! # of secs after a cleaner wakeup occurs
#define CLEANER_WAKEUP 10
//! # of secs after stats output is generated
#define STAT_WAKEUP 600
//! keepalive time
#define KEEPALIVE_TIME 60
//! select timeout (to avoid endless blocking)
#define SELECT_TIMEOUT 10

#define LOG_FCONN 0x400
#define LOG_FERR 0x800

#define E_SOCKS_SOCK -1
#define E_SOCKS_CONN -2
#define E_SOCKS_REQ -3
#define E_SOCKS_RQFAIL -4
#define E_SOCKS_TERMREQ -5

#define E_FWD_NOPEER -1
#define E_FWD_NOBUF -2

//#define PEER_CONNECT 0
#define PEER_ACTIVE 1

#define PEER_INCOMING 0
#define PEER_OUTGOING 1

#define THREAD_NAME_LEN 11
//! thread stack size (default stack size on OpenBSD is too small)
#define THREAD_STACK_SIZE 262144

#define SOCKS_NEW 0
#define SOCKS_CONNECTING 1
#define SOCKS_4AREQ_SENT 2
#define SOCKS_4ARESPONSE 3
#define SOCKS_DELETE 127

#define SOCKS_MAX_RETRY 3

#define E_RT_NOMEM -1
#define E_RT_DUP -2
#define E_RT_ILLNM -3
#define E_RT_SYNTAX -4
#define E_RT_NULLPTR -5
#define E_RT_NOTORGW -6
#define E_RT_GWSELF -7

#define E_ETH_TRUNC -8
#define E_ETH_ILLDEST -9
#define E_ETH_ILLPROTO -10
#define E_ETH_INTERCEPT -11

//! maximum number of MAC address entries in table
#define MAX_MAC_ENTRY 128
//! maximum age of MAC address in table
#define MAX_MAC_AGE 120
/*
//! maximum number of IPv6 routes
#define MAX_IPV6_ROUTE 1024
*/
//! retry-delay if connection to TOR's SOCKS port fails
#define TOR_SOCKS_CONN_TIMEOUT 30
//! number of attempts for MIN_RECONNECT_TIME is measured
#define RECONN_ATTEMPTS 3
//! RECONN_ATTEMPTS must not be faster than MIN_RECONNECT_TIME
#define MIN_RECONNECT_TIME 30

#define MFD_SET(f,s,m) {FD_SET(f, s); m = f > m ? f : m;}

//! copy an IPv6 address from b to a
#define IN6_ADDR_COPY(a,b) *((struct in6_addr*)a)=*(struct in6_addr*)b

#define IPV4_KEY 0
#define IPV6_KEY 1

#define SOCKADDR_SIZE(x) (((struct sockaddr*) x)->sa_family == AF_INET ? sizeof(struct sockaddr_in) : ((struct sockaddr*) x)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : 0)

#define VERSION_STRING_LEN 256


#define NTYPE_TOR 0
#define NTYPE_I2P 1


struct OcatSetup
{
   //! frame header of local OS in network byte order
   //! it is initialized in ocattun.c
   uint32_t fhd_key[2];
   int fhd_key_len;
   //! TCP port of SOCKS port of local Tor proxy
   //uint16_t tor_socks_port;
   //! reload port of OnionCat listening for connections
   //uint16_t ocat_listen_port;
   //! virtual port of OnionCat hidden service
   uint16_t ocat_dest_port;
   //! local port of controller interface
   uint16_t ocat_ctrl_port;
   //! file descriptors of TUN device (usually tunfd[0] == tunfd[1])
   int tunfd[2];
   int debug_level;
   //! user name to change uid to
   char *usrname;
   char onion_url[SIZE_256];
   struct in6_addr ocat_addr;
   //! flag to create connection log
   int create_clog;
   //! flag to not change uid to unprivileged user
   int runasroot;
   int controller;
   char *ocat_dir;
   //! name of tunnel charcter device
   char *tun_dev;
   //! tunnel interface name
   char tunname[SIZE_256];
   int ipv4_enable;
   struct in_addr ocat_addr4;
   int ocat_addr4_mask;
   char *config_file;
   int config_read;
   int use_tap;
   //! local OnionCat MAC address
   uint8_t ocat_hwaddr[ETHER_ADDR_LEN];
   char *pid_file;
   int create_pid_file;
   char *logfn;
   FILE *logf;
   int use_syslog;
   int daemon;
   //! hardcoded permanent peers
#define ROOT_PEERS 1
   struct in6_addr root_peer[ROOT_PEERS];
   time_t uptime;
   char *frandn;
   //! destination socket address of Tor's SOCKS port
   union
   {
      struct sockaddr_in *socks_dst;
      struct sockaddr_in6 *socks_dst6;
   };
   //! local listening socket address for incoming connections
   struct sockaddr **oc_listen;
   int *oc_listen_fd;
   int oc_listen_cnt;
   int rand_addr;
   char version[VERSION_STRING_LEN];
   int sizeof_setup;
   int sig_term, term_req;
   pthread_mutex_t mutex;
   //! listening sockets for controller interface
   struct sockaddr **ctrl_listen;
   int *ctrl_listen_fd;
   int ctrl_listen_cnt;
   //! communication pipe for socks "selected" connector
   int socksfd[2];
   int net_type;
};

#ifdef PACKET_QUEUE
typedef struct PacketQueue
{
   struct PacketQueue *next;
   struct in6_addr addr;
   int psize;
   time_t time;
   void *data;
} PacketQueue_t;
#endif

typedef struct SocksHdr
{
   char ver;
   char cmd;
   uint16_t port;
   struct in_addr addr;
} __attribute__((packed)) SocksHdr_t;

typedef struct Socks5Hdr
{
   char ver;
   char cmd;
   char rsv;
   char atyp;
   char addr;
} __attribute__((packed)) Socks5Hdr_t;

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
   uint32_t *tunhdr;       //!< pointer to local tun frame header
   char *fragbuf;          //!< pointer to (de)frag buffer
   char _fragbuf[FRAME_SIZE]; //!< (de)frag buffer
   int fraglen;            //!< current frag buffer size
   pthread_mutex_t mutex;  //!< mutex for thread locking
   int perm;               //!< keep peer permanently open
   time_t last_io;         //!< timestamp when last I/O packet measurement started
   unsigned inm;
   unsigned outm;
} OcatPeer_t;

typedef struct OcatThread
{
   struct OcatThread *next;
   pthread_t handle;
   pthread_attr_t attr;
   int detached;
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
   int perm;
   int fd;
   time_t restart_time;
   time_t connect_time;
   int retry;
} SocksQueue_t;

//! IPv4 routing table entry
typedef struct IPv4Route
{
   struct IPv4Route *next[2];    //!< pointer to next routes in binary tree
   uint32_t dest;
   uint32_t netmask;
   struct in6_addr gw;
} IPv4Route_t;

//! IPv6 routing table entry
typedef struct IPv6Route
{
   struct in6_addr dest;
   int prefixlen;
   struct in6_addr gw;
} IPv6Route_t;

//! IPv6 pseudo header used for checksum calculation
struct ip6_psh
{
   struct in6_addr src;
   struct in6_addr dst;
   uint32_t len;
   char _pad[3];
   uint8_t nxt;
} __attribute__((packed));

typedef struct MACTable
{
   uint16_t family;
   union
   {
      struct in6_addr in6addr;
      struct in_addr inaddr;
   };
   uint8_t hwaddr[ETHER_ADDR_LEN];
   time_t age;
} MACTable_t;

typedef struct ndp6
{
   struct ether_header eth;
   struct ip6_hdr ip6;
   union
   {
      struct icmp6_hdr icmp6;
      struct nd_neighbor_solicit ndp_sol;
      struct nd_neighbor_advert ndp_adv;
   };
   //struct nd_opt_hdr ndp_opt;
} __attribute__((packed)) ndp6_t;

struct sockaddr_str
{
   sa_family_t sstr_family;
   uint16_t sstr_port; 
   char sstr_addr[INET6_ADDRSTRLEN];
};

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


#ifndef WITHOUT_TUN
#ifdef __FreeBSD__
#define TUN_DEV "/dev/tun0"
#elif __OpenBSD__
#define TUN_DEV "/dev/tun0"
#else
#define TUN_DEV "/dev/net/tun"
#endif
extern char *tun_dev_;
#endif

extern pthread_mutex_t thread_mutex_;
extern OcatThread_t *octh_;

/* ocat.c */


/* ocatlog.c */
int open_connect_log(const char*);
void log_msg(int, const char *, ...);
#ifdef DEBUG
#define log_debug(x...) log_msg(LOG_DEBUG, ## x)
#else
#define log_debug(x...)
#endif

/* ocatv6conv.c */
char *ipv6tonion(const struct in6_addr *, char *);
int oniontipv6(const char *, struct in6_addr *);
int oniontipv4(const char *, struct in_addr *, int);
int has_tor_prefix(const struct in6_addr *);
void rand_onion(char *);
const char *inet_ntops(const struct sockaddr *, struct sockaddr_str *);
/*
#define IN6_HAS_TOR_PREFIX(a) ((((__const uint32_t *) (a))[0] == ((__const uint32_t*)(TOR_PREFIX))[0]) \
      && (((__const uint16_t*)(a))[2] == ((__const uint16_t*)(TOR_PREFIX))[2]))
      */

/* ocattun.c */
#ifndef WITHOUT_TUN
int tun_alloc(char *, int, struct in6_addr);
#endif

/* ocatroute.c */
extern int sockfd_[2];
void init_peers(void);
void *socket_receiver(void *);
void packet_forwarder(void);
#ifdef PACKET_QUEUE
void *packet_dequeuer(void *);
#endif
void *socket_acceptor(void *);
void *socket_cleaner(void *);
void *ocat_controller(void *);
void *ctrl_handler(void *);
int insert_peer(int, const SocksQueue_t *, time_t);
int run_listeners(struct sockaddr **, int *, int, int (*)(int));
int send_keepalive(OcatPeer_t *);
void set_select_timeout(struct timeval *);
void set_nonblock(int);

/* ocatthread.c */
const OcatThread_t *init_ocat_thread(const char *);
int run_ocat_thread(const char *, void *(*)(void*), void*);
const OcatThread_t *get_thread(void);
int set_thread_name(const char *);
int join_threads(void);
void detach_thread(void);
void print_threads(FILE *);
int term_req(void);
void set_term_req(void);

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
#define CNF(x) setup_.x
extern struct OcatSetup setup_;
void print_setup_struct(FILE *);
void init_setup(void);
void post_init_setup(void);
void lock_setup(void);
void unlock_setup(void);

/* ocatipv4route.c */
struct in6_addr *ipv4_lookup_route(uint32_t);
int parse_route(const char *);
void print_routes(FILE *);

/* ocateth.c */
int eth_check(char *, int);
int mac_set(const struct in6_addr *, uint8_t *);
void print_mac_tbl(FILE *);
void mac_cleanup(void);
char *mac_hw2str(const uint8_t *, char *);
int ndp_solicit(const struct in6_addr *, const struct in6_addr *);
#ifndef HAVE_ETHER_NTOA_R
char *ether_ntoa_r(const struct ether_addr *, char *);
#endif
uint16_t checksum(const uint16_t *, int);
void free_ckbuf(uint16_t *);
uint16_t *malloc_ckbuf(const struct in6_addr *, const struct in6_addr *, uint16_t, uint8_t, const void *);

/* ocatsocks.c */
void socks_queue(struct in6_addr, int);
void print_socks_queue(FILE *);
void sig_socks_connector(void);
void *socks_connector_sel(void *);

/* ocatlibe.c */
void oe_close(int);
int oe_remtr(char *);
int strsockaddr(const char *, struct sockaddr *);
void add_local_listeners(void);
void add_listener(const char *);
void delete_listeners(struct sockaddr **, int *, int);
int fdprintf(int, const char *, va_list);

/* ocatipv6route.c */
struct in6_addr *ipv6_lookup_route(const struct in6_addr *);
void ipv6_print_routes(FILE *);
int ipv6_parse_route(const char *);

#ifdef __CYGWIN__
/* ocat_wintuntap.c */
int win_open_tun(char *, int);
int win_close_tun(void);
int win_read_tun(char *, int);
int win_write_tun(const char *, int);
#endif

#endif

