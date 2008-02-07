/*! ocattun.c
 *  These functions create the TUN device.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#ifndef WITHOUT_TUN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include "ocat.h"

/* FIXME: this is defined in linux/ipv6.h but including
 * it conflicts with other headers. */
struct in6_ifreq 
{
   struct in6_addr ifr6_addr;
   uint32_t ifr6_prefixlen;
   int ifr6_ifindex;
};

char *tun_dev_ = TUN_DEV;


int tun_alloc(char *dev, struct in6_addr addr)
{
   struct ifreq ifr;
   struct in6_ifreq ifr6;
//   struct sockaddr_in6 addr;
   int fd, sfd;

   if( (fd = open(tun_dev_, O_RDWR)) < 0 )
      perror("open tun"), exit(1);

   memset(&ifr, 0, sizeof(ifr));
   ifr.ifr_flags = IFF_TUN /*| IFF_NO_PI*/;
   if(*dev)
      strncpy(ifr.ifr_name, dev, IFNAMSIZ);

   if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
      perror("TUNSETIFF"), exit(1);
   strcpy(dev, ifr.ifr_name);

   if ((sfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
      perror("socket"), exit(1);

   if (ioctl(sfd, SIOCGIFINDEX, &ifr ) < 0)
      perror("SIOCGIFINDEX"), exit(1);

   /*
   memset(&addr, 0, sizeof(addr));
   addr.sin6_family = AF_INET6;
   if (inet_pton(AF_INET6, ipv6, &addr.sin6_addr) < 0)
      perror("inet_pton"), exit(1);

   ifr6.ifr6_addr = addr.sin6_addr;*/
   ifr6.ifr6_addr = addr;
   ifr6.ifr6_ifindex = ifr.ifr_ifindex;
   ifr6.ifr6_prefixlen = TOR_PREFIX_LEN;
   if (ioctl(sfd, SIOCSIFADDR, &ifr6) < 0)
      perror("SIOCIFADDR"), exit(1);

   if (ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0)
      perror("SIOCGIFFLAGS"), exit(1);

   ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
   if (ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0) 
      perror("SIOCSIFFLAGS"), exit(1);

   close(sfd);
   return fd;
}              
 
#endif

