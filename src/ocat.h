/* Copyright 2008-2019 Bernhard R. Fischer, Daniel Haslinger.
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

/*! \file ocat.h
 * This file is the central header file of OnionCat. It includes all other
 * headers and contains all macros, structures, typedefs,...
 * \author Bernhard R. Fischer
 * \date 2019/09/08
 */

#ifndef OCAT_H
#define OCAT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
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


#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#elif HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_ETHERNET_H
#include <sys/ethernet.h>
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
#ifdef HAVE_NETINET6_IN6_VAR_H
#include <netinet6/in6_var.h>
#endif
#ifdef HAVE_NETINET6_ND6_H
#include <netinet6/nd6.h>
#endif
#include <arpa/inet.h>
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
#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
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
#ifdef HAVE_LINUX_IPV6_H
#include <linux/ipv6.h>
#endif
#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif
#ifdef HAVE_NET_TUN_IF_TUN_H
#include <net/tun/if_tun.h>
#endif

#ifdef __CYGWIN__
#include "cygwin/ocat_cygwin.h"
#endif

#ifndef ETHERTYPE_IP
//! Ether type for IPv4.
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
//! Ether type for IPv6.
#define ETHERTYPE_IPV6 0x86dd
#endif

#ifndef ETHER_ADDR_LEN
#ifdef ETHERADDRL
#define ETHER_ADDR_LEN ETHERADDRL
#endif
#endif

// At least on Solaris the Ethernet addresses are defined as struct containing
// an array of bytes.  This is different from most other OSes which define the
// addresses directly as array.
#ifdef HAVE_ETHER_ADDR_OCTET
#define ether_dst ether_dhost.ether_addr_octet
#define ether_src ether_shost.ether_addr_octet
#else
#define ether_dst ether_dhost
#define ether_src ether_shost
#endif

#define IP6HLEN sizeof(struct ip6_hdr)
//! Length of an .onion-URL (without ".onion" and '\0')
#define ONION_URL_LEN 16

//! Maximum number of peers allowed.
#define MAXPEERS 1024
#ifdef __OpenBSD__
#define OCAT_UNAME "_tor"
#elif __FreeBSD__
#define OCAT_UNAME "_tor"
#else
#define OCAT_UNAME "tor"
#endif
//! Uid of unprivileged user.
#define OCAT_UNPRIV_UID 65534
//! Name of unprivileged user (if system offers no name).
#define OCAT_UNPRIV_UNAME "(unknown)"
//! Project URL of OnionCat.
#define OCAT_URL "https://www.onioncat.org/"
//! Path to OnionCat logging directory (see option -a).
#define OCAT_DIR ".ocat"
//#define OCAT_CONNECT_LOG "connect_log"
//! Default path to PID file (option -P).
#define PID_FILE "/var/run/ocat.pid"
//! Name of the author of OnionCat.
#define OCAT_AUTHOR "Bernhard R. Fischer"

//! Maximum frame (packet) size, should be able to keep one maximum size ipv6-packet: 2^16 + 40 + 4
#define FRAME_SIZE 65580

//! Standard buffer size 1024 bytes
#define SIZE_1K 1024
//! Standard buffer size 256 bytes
#define SIZE_256 256

#define DEQUEUER_WAKEUP 3
//! maximum number a packet stays in queue
#define MAX_QUEUE_DELAY 10

//! Maximum idle time for a peer, after that time the peer is closed.
#define MAX_IDLE_TIME 180
//! \# of secs after a cleaner wakeup occurs
#define CLEANER_WAKEUP 10
//! \# of secs after stats output is generated
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
#define PEER_DELETE 2

//! Outgoing peer => connect().
#define PEER_INCOMING 0
//! Incoming peer => accept().
#define PEER_OUTGOING 1

//! Maximum length of thread names.
#define THREAD_NAME_LEN 11
//! thread stack size (default stack size on OpenBSD is too small)
#define THREAD_STACK_SIZE 262144

//! Connection type SOCKS4A (option -5).
#define CONNTYPE_SOCKS4A 0
//! Connection type SOCKS5 (option -5).
#define CONNTYPE_SOCKS5 1
//! Connection type direct, i.e. no SOCKS (option -5).
#define CONNTYPE_DIRECT 2

//! SOCKS state machine: new connection
#define SOCKS_NEW 0
//! SOCKS state machine: connect() in progress
#define SOCKS_CONNECTING 1
//! SOCKS state machine: SOCKS4A request sent
#define SOCKS_4AREQ_SENT 2
//! SOCKS state machine: this state is NOT used!
#define SOCKS_4ARESPONSE 3
//! SOCKS state machine: SOCKS5 greeting sent
#define SOCKS_5GREET_SENT 4
//! SOCKS state machine: SOCK5 request sent
#define SOCKS_5REQ_SENT 5
//! SOCKS state machine: successfully opened, ready for data transfer
#define SOCKS_READY 126
//! SOCKS state machine: request ready for deletion
#define SOCKS_DELETE 127

//! maximum number of SOCKS retries before becoming deleted
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
//! define default maximum number of concurrent controller sessions
#define MAX_DEF_CTRL_SESS 5

#define MFD_SET(f,s,m) {FD_SET(f, s); m = f > m ? f : m;}

//! copy an IPv6 address from b to a
//#define IN6_ADDR_COPY(a,b) *((struct in6_addr*)a)=*(struct in6_addr*)b
#define IN6_ADDR_COPY(a,b) memcpy(a, b, sizeof(struct in6_addr))

//! Index to OcatSetup.fhd_key for IPv4.
#define IPV4_KEY 0
//! Index to OcatSetup.fhd_key for IPv6.
#define IPV6_KEY 1
//! Macro to return size of anonymous sockaddr structure (only AF_INET and AF_INET6).
#define SOCKADDR_SIZE(x) (((struct sockaddr*) x)->sa_family == AF_INET ? sizeof(struct sockaddr_in) : ((struct sockaddr*) x)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : 0)

#define VERSION_STRING_LEN 256

#define MAX_DEF_CTRL 6

#define NTYPE_TOR 0
#define NTYPE_I2P 1

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

// this macro returns a constains string if a buffer points to NULL.
#define SSTR(x) (x != NULL ? x : "(nil)")

// Solaris and the Windows OpenVPN tunnel driver do not send a 4 byte tunnel
// header thus we adjust reads and writes.
#if defined(__sun__) || defined(__CYGWIN__)
#define BUF_OFF 4
#else
#define BUF_OFF 0
#endif


//! General configuration data
/*! OcatSetup is used as a global structure holding general configuration
 * parameters for OnionCat.
 */
struct OcatSetup
{
   //! frame header of local OS in network byte order
   /*! for IPV4 (IPV4_KEY => 0) and IPv6 (IPV6_KEY => 1), it is initialized in ocattun.c */
   uint32_t fhd_key[2];
   //! size of the frame header, actually this is sizeof(uint32_t) which is 4
   int fhd_key_len;
   //! virtual port of OnionCat hidden service
   uint16_t ocat_dest_port;
   //! local port of controller interface
   uint16_t ocat_ctrl_port;
   //! file descriptors of TUN device (usually tunfd[0] == tunfd[1])
   int tunfd[2];
   //! configure IP addresses on startup
   int ipconfig;
   //! debug level
   int debug_level;
   //! user name to change uid to
   char *usrname;
   //! onion URL which corresponds to the IPv6 address
   char onion_url[SIZE_256];
   //! long hs v3 onion name
   char onion3_url[SIZE_256];
   //! IPv6 address of OnionCat
   struct in6_addr ocat_addr;
   //! flag to create connection log
   int create_clog;
   //! flag to not change uid to unprivileged user
   int runasroot;
   //! controller interface enabled/disabled (option -C)
   int controller;
   //! directory where OnionCat puts the connect log
   char *ocat_dir;
   //! name of tunnel charcter device FIXME: seems to be unnused, uses tun_dev_ instead -> needs fix
   char *tun_dev;
   //! Connection type (SOCKS4a, 5, or direct).
   /*! use SOCKS5 (CONNTYPE_SOCKS5 => 1) or direct connects (CONNTYPE_DIRECT =>
    * 2) instead of SOCKS4A (CONNTYPE_SOCKS4A => 0), option -5 */
   int socks5;
   //! length of long HS names
   int l_hs_namelen;
   //! tunnel interface name
   char tunname[SIZE_256];
   //! transport of IPv4 enabled (option -4)
   int ipv4_enable;
   //! IPv4 address of OnionCat
   struct in_addr ocat_addr4;
   //! IPv4 netmask
   union
   {
      //! netmask as int type
      int ocat_addr4_mask;
      //! netmask is struct in_addr type
      struct in_addr ocat_addr4_netmask;
   };
   char *config_file;
   int config_read;
   int config_failed;
   char *ifup;             //!< path to ifup scripts
   int use_tap;
   //! local OnionCat MAC address
   uint8_t ocat_hwaddr[ETHER_ADDR_LEN];
   char *pid_file;
   int create_pid_file;
   char *logfn;
   FILE *logf;
   int use_syslog;
   int daemon;
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
   int max_ctrl, ctrl_active;
   //! pipe filedescriptors for pid deletion process
   int pid_fd[2];
   int sig_usr1, clear_stats;
   /*! Define if OC connection should be used uni- or bidirectional.
      Bidirectional has a faster setup time but unidirectional is more safe in
      respect to security because both ends are verfied. */
   int unidirectional;
   int hosts_lookup;
   char *hosts_path;       //!< path to hosts file, defaults to system hosts file if NULL
   const char *domain;     //!< domain name appended to network host name
   struct in6_addr oc_vdns;
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

//! This structure holds the SOCKS4A header.
typedef struct SocksHdr
{
   char ver;
   char cmd;
   uint16_t port;
   struct in_addr addr;
} __attribute__((packed)) SocksHdr_t;

//! Structure to hold the SOCKS5 header.
typedef struct Socks5Hdr
{
   char ver;
   char cmd;
   char rsv;
   char atyp;
   char addr;
} __attribute__((packed)) Socks5Hdr_t;

//! This structure holds all data associated with a peer (a remote OnionCat).
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
   int rand;               //!< random peer number
} OcatPeer_t;

//! OcatThread is a control structure to manage each thread of OnionCat.
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
   int ready;              //!< thread is ready, i.e. every initialization is done
} OcatThread_t;

//! Data structure for SOCKS connections in progress.
/*! This structure holds all data associate with SOCKS connections which are
 * currently in opening state, i.e. not connected but trying to connect.
 */
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

//! MAC table entry for TAP mode.
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

//! NDP protocol header.
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

//! Structure to hold socket address as a literal string.
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
#ifdef __sun__
#define TUN_DEV "/dev/tun"
#elif __ANDROID__
#define TUN_DEV "/dev/tun"
#elif __linux__
#define TUN_DEV "/dev/net/tun"
#else
#define TUN_DEV "/dev/tun0"
#endif
extern char *tun_dev_;
#else
#define TUN_DEV "STDIO"
#endif

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
void set_tunheader(char *, uint32_t);
uint32_t get_tunheader(char *);
#ifdef WITH_LOOPBACK_RESPONDER
void *local_loopback_responder(void *);
void *remote_loopback_responder(void *);
int add_remote_loopback_route(void);
#endif

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
int wait_thread_by_name_ready(const char *);
int set_thread_ready(void);

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
uint16_t *malloc_ckbuf(struct in6_addr, struct in6_addr, uint16_t, uint8_t, const void *);

/* ocatsocks.c */
void socks_queue(struct in6_addr, int);
void print_socks_queue(FILE *);
void sig_socks_connector(void);
void *socks_connector_sel(void *);
int test_socks_server(void);
int synchron_socks_connect(const struct in6_addr *);

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
int ipv6_add_route(const IPv6Route_t *);

#ifdef __CYGWIN__
/* ocat_wintuntap.c */
int win_open_tun(char *, int);
int win_close_tun(void);
int win_read_tun(char *, int);
int win_write_tun(const char *, int);
#define tun_read(x,y,z) win_read_tun(y,z)
#define tun_write(x,y,z) win_write_tun(y,z)
#else
#define tun_read(x,y,z) read(x,y,z)
#define tun_write(x,y,z) write(x,y,z)
#endif

/* ocatresolv.c */
int check_dns(const struct ip6_hdr *, int);

#endif

