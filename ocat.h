#ifndef OCAT_H
#define OCAT_H

#include <netinet/ip6.h>


#define BUFLEN 64*1024

#define IP6HLEN sizeof(struct ip6_hdr)
#define TOR_PREF 0xFD87D87EEB43LL
#define MAXPEERS 1024
#define OCAT_PORT 8000
#define TOR_SOCKS_PORT 9050

#define FRAME_SIZE 128


#define L_NOTICE 1
#define L_ERROR 2
#define L_DEBUG 3


#define E_SOCKS_SOCK -1
#define E_SOCKS_CONN -2
#define E_SOCKS_REQ -3
#define E_SOCKS_RQFAIL -4


typedef struct SocksHdr
{
   char ver;
   char cmd;
   uint16_t port;
   struct in_addr addr;
} SocksHdr_t;

typedef struct OnionPeer
{
   struct in6_addr addr;
   int tunfd;
   int tcpfd;
   time_t time;
   pid_t pid;
} OnionPeer_t;

struct ReceiverInfo
{
   int listenfd;
   int tunfd;
   pthread_t thread;
};

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
void onion_listen(int);

/* ocatsocks.c */
int socks_connect(const char *);


#endif

