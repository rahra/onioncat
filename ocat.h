#ifndef OCAT_H
#define OCAT_H

#include <netinet/ip6.h>


#define BUFLEN 64*1024

#define IP6HLEN sizeof(struct ip6_hdr)
#define TOR_PREF 0xFD87D87EEB43LL
#define MAXPEERS 1024
#define OCAT_PORT 8000
#define TOR_SOCKS_PORT 9050

#define FRAME_SIZE 1500


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

typedef struct PacketQueue
{
   struct PacketQueue *next;
   struct in6_addr addr;
   int psize;
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
   int tunfd;              //<! local file descriptor
   int tcpfd;              //<! remote file descriptor
   time_t time;            //<! timestamp of latest packet
   int state;              //<! status of peer
   PacketQueue_t *queue;   //<! first packet in send queue
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

/* ocat.c */
void log_msg(int, const char *, ...);


/* ocatsv6.c -- this function is sourced out
 * here because of conflicting headers. */
void set_ipv6_addr(int, struct in6_addr, int);

/* ocatv6conv.c */
void ipv6tonion(const struct in6_addr *, char *);
int oniontipv6(const char *, struct in6_addr *);

/* ocattun.c */
int tun_alloc(char *, const char *);

/* ocatroute.c */
OnionPeer_t *search_peer(const struct in6_addr *);
OnionPeer_t *establish_peer(int fd, const struct in6_addr *);
void init_socket_acceptor(void);
void init_socket_receiver(void);
void init_socks_connector(void);
void push_socks_connector(const struct in6_addr *);
//int socks_connect(const char *);
//void *socket_receiver(void *p);
void update_peer_time(const OnionPeer_t *);
const OnionPeer_t *forward_packet(const struct in6_addr *, const char *, int);
void queue_packet(const struct in6_addr *, const char *, int);
void init_packet_dequeuer(void);


#endif

