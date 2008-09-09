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

/*! ocattun.c
 *  These functions create the TUN device.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#ifndef WITHOUT_TUN

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif
#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif
#include <net/ethernet.h>

#include "ocat.h"


char *tun_dev_ = TUN_DEV;


int tun_alloc(char *dev, struct in6_addr addr)
{
   struct ifreq ifr;
   int fd;
   char astr[INET6_ADDRSTRLEN];
   char astr4[INET_ADDRSTRLEN];
   char buf[FRAME_SIZE];
   struct in_addr netmask = {setup.ocat_addr4_mask};

	log_debug("opening tun \"%s\"", tun_dev_);
   if ((fd = open(tun_dev_, O_RDWR)) < 0)
      perror("open tun"), exit(1);
   inet_ntop(AF_INET6, &addr, astr, INET6_ADDRSTRLEN);
   inet_ntop(AF_INET, &setup.ocat_addr4, astr4, INET_ADDRSTRLEN);

#ifdef __linux__

   memset(&ifr, 0, sizeof(ifr));
   ifr.ifr_flags = IFF_TUN;
   //ifr.ifr_flags |= IFF_NO_PI;
   if (*dev)
      strncpy(ifr.ifr_name, dev, IFNAMSIZ);

   if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
      perror("TUNSETIFF"), exit(1);
   strlcpy(dev, ifr.ifr_name, IFNAMSIZ);
   sprintf(buf, "ifconfig %s add %s/%d up", dev, astr, TOR_PREFIX_LEN);
   log_msg(L_NOTICE, "configuring tun IP: \"%s\"", buf);
   if (system(buf) == -1)
      log_msg(L_ERROR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));

   // according to drivers/net/tun.c only IFF_MULTICAST and IFF_PROMISC are supported.
/*   ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;
   if (ioctl(fd, SIOCSIFFLAGS, (void*) &ifr) < 0)
      log_msg(L_ERROR, "could not set interface flags: \"%s\"", strerror(errno));
      */

   // set tun frame header to ethertype IPv6
   setup.fhd_key[IPV6_KEY] = htonl(ETHERTYPE_IPV6);
   setup.fhd_key[IPV4_KEY] = htonl(ETHERTYPE_IP);

#else

   // set tun frame header to address family AF_INET6 (FreeBSD = 0x1c, OpenBSD = 0x18)
   setup.fhd_key[IPV6_KEY] = htonl(AF_INET6);
   setup.fhd_key[IPV4_KEY] = htonl(AF_INET);

#ifdef __FreeBSD__

   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      perror("ioctl:TUNSIFHEAD"), exit(1);
   prm = IFF_POINTOPOINT;
   if (ioctl(fd, TUNSIFMODE, &prm) == -1)
      perror("ioctl:TUNSIFMODE"), exit(1);

#endif

   sprintf(buf, "ifconfig tun0 inet6 %s/%d up", astr, TOR_PREFIX_LEN);
   log_debug("setting IP on tun: \"%s\"", buf);
   if (system(buf) == -1)
      log_msg(L_ERROR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));

#endif

   // setting up IPv4 address
   if (setup.ipv4_enable)
   {
      sprintf(buf, "ifconfig %s %s netmask %s", dev, astr4, inet_ntoa(netmask));
      log_msg(L_NOTICE, "configuring tun IP: \"%s\"", buf);
      if (system(buf) == -1)
         log_msg(L_ERROR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));
   }

   return fd;
}              
 
#endif

