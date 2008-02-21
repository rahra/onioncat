#ifndef OCAT_H
#define OCAT_H


#include <time.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
#include <pthread.h>

#include "config.h"


#define IP6HLEN sizeof(struct ip6_hdr)
// TOR prefix : FD87:D87E:EB43::/40
#define TOR_PREFIX {0xfd,0x87,0xd8,0x7e,0xeb,0x43}
#define TOR_PREFIX_LEN 48
#define MAXPEERS 1024
#define OCAT_LISTEN_PORT 8000
#define OCAT_CTRL_PORT 8001
#define OCAT_DEST_PORT 80
#define TOR_SOCKS_PORT 9050


#define FRAME_SIZE 1504
#define ONION_NAME_SIZE 23

#define DEQUEUER_WAKEUP 3
//! maximum number a packet stays in queue
#define MAX_QUEUE_DELAY 10

#define MAX_IDLE_TIME 120
#define CLEANER_WAKEUP 10

#define L_INFO 0
#define L_NOTICE 1
#define L_ERROR 2
#define L_FATAL 3
#define L_DEBUG 4

#define E_SOCKS_SOCK -1
#define E_SOCKS_CONN -2
#define E_SOCKS_REQ -3
#define E_SOCKS_RQFAIL -4

//#define PEER_CONNECT 0
#define PEER_ACTIVE 1

#define PEER_INCOMING 0
#define PEER_OUTGOING 1

#define THREAD_NAME_LEN 11

#define SOCKS_CONNECTING 1
#define SOCKS_MAX_RETRY 3


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
} SocksHdr_t;

typedef struct OcatPeer
{
   struct in6_addr addr;   //<! remote address of peer
   int tcpfd;              //<! remote file descriptor
   time_t time;            //<! timestamp of latest packet
   time_t sdelay;          //<! connection setup delay
   time_t otime;           //<! opening time
   int state;              //<! status of peer
   int dir;
   unsigned long out;
   unsigned long in;
} OcatPeer_t;

typedef struct OcatThread
{
   struct OcatThread *next;
   pthread_t handle;
   int id;
   char name[THREAD_NAME_LEN];
   void *(*entry)(void*);
} OcatThread_t;

typedef struct SocksQueue
{
   struct SocksQueue *next;
   struct in6_addr addr;
   int state;
//   int retry;
} SocksQueue_t;

// next header value for ocat internal use (RFC3692)
#define OCAT_NEXT_HEADER 254

typedef struct OcatHdr
{
   uint16_t oh_plen;
   uint8_t oh_nxt;
/*   struct ip6_hdrctl oh_ip6hdrctl;
   char oh_srcid[10];*/
} OcatHdr_t;


#define OCAT_CTL_SRC 1
#define OCAT_CTL_EREQ 2
#define OCAT_CTL_ERES 3

typedef struct OcatCtrlHdr
{
   uint8_t oct_type;
   char oct_srcid[10];
} OcatCtrlHdr_t;

//#ifdef __CYGWIN__
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
   uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
  };

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim
#endif

extern uint16_t tor_socks_port_;
extern uint16_t ocat_listen_port_;
extern uint16_t ocat_dest_port_;
extern int vrec_;
extern int tunfd_[2];

#ifndef WITHOUT_TUN
#define TUN_DEV "/dev/net/tun"
extern char *tun_dev_;
extern uint32_t fhd_key_;
#endif

extern pthread_mutex_t thread_mutex_;
extern OcatThread_t *octh_;

/* ocatlog.c */
void log_msg(int, const char *, ...);

/* ocatsv6.c -- this function is sourced out
 * here because of conflicting headers. */
void set_ipv6_addr(int, struct in6_addr, int);

/* ocatv6conv.c */
char *ipv6tonion(const struct in6_addr *, char *);
int oniontipv6(const char *, struct in6_addr *);
int has_tor_prefix(const struct in6_addr *);

/* ocattun.c */
#ifndef WITHOUT_TUN
int tun_alloc(char *, struct in6_addr);
void test_tun_hdr(void);
#endif

/* ocatroute.c */
//OnionPeer_t *search_peer(const struct in6_addr *);
//OnionPeer_t *establish_peer(int fd, const struct in6_addr *);
void init_peers(void);
//void init_socket_acceptor(void);
//void init_socket_receiver(void);
//void init_socks_connector(void);
//void push_socks_connector(const struct in6_addr *);
//int socks_connect(const char *);
void *socket_receiver(void *);
//void update_peer_time(const OnionPeer_t *);
//const OnionPeer_t *forward_packet(const struct in6_addr *, const char *, int);
//void queue_packet(const struct in6_addr *, const char *, int);
//void init_packet_dequeuer(void);
void packet_forwarder(void);
//void init_socket_cleaner(void);
void *packet_dequeuer(void *);
void *socket_acceptor(void *);
void *socks_connector(void *);
void *socket_cleaner(void *);
void *ocat_controller(void *);


/* ocatthread.c */
//void init_threads(void);
const OcatThread_t *init_ocat_thread(const char *);
int run_ocat_thread(const char *, void *(*)(void*));
const OcatThread_t *get_thread(void);


#endif

