#ifndef OCAT_H
#define OCAT_H

//#define _POSIX_C_SOURCE 199309L

#include <netinet/ip6.h>


//#define BUFLEN 64*1024

#define IP6HLEN sizeof(struct ip6_hdr)
// TOR prefix : FD87:D87E:EB43::/40
#define TOR_PREFIX {0xfd,0x87,0xd8,0x7e,0xeb,0x43}
#define TOR_PREFIX_LEN 48
#define MAXPEERS 1024
#define OCAT_LISTEN_PORT 8000
#define OCAT_DEST_PORT 80
#define TOR_SOCKS_PORT 9050

#define FRAME_SIZE 1504
#define ONION_NAME_SIZE 23

#define DEQUEUER_WAKEUP 3
//! maximum number a packet stays in queue
#define MAX_QUEUE_DELAY 10

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

typedef struct OnionPeer
{
   struct in6_addr addr;   //<! remote address of peer
//   int tunfd;              //<! local file descriptor
   int tcpfd;              //<! remote file descriptor
   time_t time;            //<! timestamp of latest packet
   int state;              //<! status of peer
   int dir;
//   PacketQueue_t *queue;   //<! first packet in send queue
//   pid_t pid;
} OnionPeer_t;

/*
struct ReceiverInfo
{
   int listenfd;
   int tunfd;
   pthread_t thread;
};
*/

extern uint16_t tor_socks_port_;
extern uint16_t ocat_listen_port_;
extern uint16_t ocat_dest_port_;


/* ocatlog.c */
void log_msg(int, const char *, ...);

/* ocatsv6.c -- this function is sourced out
 * here because of conflicting headers. */
void set_ipv6_addr(int, struct in6_addr, int);

/* ocatv6conv.c */
void ipv6tonion(const struct in6_addr *, char *);
int oniontipv6(const char *, struct in6_addr *);
int has_tor_prefix(const struct in6_addr *);

/* ocattun.c */
//int tun_alloc(char *, const char *);
int tun_alloc(char *, struct in6_addr);

/* ocatroute.c */
OnionPeer_t *search_peer(const struct in6_addr *);
OnionPeer_t *establish_peer(int fd, const struct in6_addr *);
void init_peers(void);
void init_socket_acceptor(void);
void init_socket_receiver(void);
void init_socks_connector(void);
//void push_socks_connector(const struct in6_addr *);
//int socks_connect(const char *);
//void *socket_receiver(void *p);
//void update_peer_time(const OnionPeer_t *);
//const OnionPeer_t *forward_packet(const struct in6_addr *, const char *, int);
//void queue_packet(const struct in6_addr *, const char *, int);
void init_packet_dequeuer(void);
void packet_forwarder(void);



#endif

