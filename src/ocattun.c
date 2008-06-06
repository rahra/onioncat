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

#include "ocat.h"


char *tun_dev_ = TUN_DEV;


int tun_alloc(char *dev, struct in6_addr addr)
{
   struct ifreq ifr;
   int fd;
   char astr[INET6_ADDRSTRLEN];
   char buf[FRAME_SIZE];

	log_msg(L_DEBUG, "opening tun \"%s\"", tun_dev_);
   if( (fd = open(tun_dev_, O_RDWR)) < 0 )
      perror("open tun"), exit(1);
   inet_ntop(AF_INET6, &addr, astr, INET6_ADDRSTRLEN);

#ifdef __linux__

   memset(&ifr, 0, sizeof(ifr));
   ifr.ifr_flags = IFF_TUN;
   //ifr.ifr_flags |= IFF_NO_PI;
   if(*dev)
      strncpy(ifr.ifr_name, dev, IFNAMSIZ);

   if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
      perror("TUNSETIFF"), exit(1);
   strlcpy(dev, ifr.ifr_name, IFNAMSIZ);
   sprintf(buf, "ifconfig tun0 add %s/%d up", astr, TOR_PREFIX_LEN);
   log_msg(L_NOTICE, "configuring tun IP: \"%s\"", buf);
   if (system(buf) == -1)
      log_msg(L_ERROR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));
   // set tun frame header to ethertype IPv6
   fhd_key_ = htonl(0x86dd);

#else

   // set tun frame header to address family AF_INET6 (FreeBSD = 0x1c, OpenBSD = 0x18)
   fhd_key_ = htonl(AF_INET6);

#ifdef __FreeBSD__

   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      perror("ioctl:TUNSIFHEAD"), exit(1);
   prm = IFF_POINTOPOINT;
   if (ioctl(fd, TUNSIFMODE, &prm) == -1)
      perror("ioctl:TUNSIFMODE"), exit(1);

#endif

   sprintf(buf, "ifconfig tun0 inet6 %s/%d up", astr, TOR_PREFIX_LEN);
   log_msg(L_DEBUG, "setting IP on tun: \"%s\"", buf);
   if (system(buf) == -1)
      log_msg(L_ERROR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));

#endif

   return fd;
}              
 

#ifdef TEST_TUN_HDR

/*! This is a test function which detects the frame
 *  header of the local OS by sending a ping into
 *  the tun by a call to system("ping6..."). */
void test_tun_hdr(void)
{
   struct in6_addr addr;
   char addrstr[INET6_ADDRSTRLEN];
   char buf[FRAME_SIZE];
   int rlen;

   if (oniontipv6("aaaaaaaaaaaaaaab", &addr) == -1)
      log_msg(L_FATAL, "[test_tun_hdr] this should never happen..."), exit(1);

   inet_ntop(AF_INET6, &addr, addrstr, INET6_ADDRSTRLEN);
#ifdef __linux__
   sprintf(buf, "ping6 -c 1 -w 1 %s >/dev/null 2>&1", addrstr);
#else
   //sprintf(buf, "ping6 -c 1 %s >/dev/null 2>&1", addrstr);
   sprintf(buf, "ping6 -c 1 %s", addrstr);
#endif
   log_msg(L_NOTICE, "[test_tun_hdr] testing tun header: \"%s\"", buf);
   // FIXME: This is somehow an unclean try to wait for ifconfig to finish
   sleep(1);
   if (system(buf) == -1)
      log_msg(L_FATAL, "[test_tun_hdr] test failed: \"%s\"", strerror(errno));
   rlen = read(tunfd_[0], buf, FRAME_SIZE);
   log_msg(L_DEBUG, "[test_tun_hdr] read %d bytes from %d, head = 0x%08x", rlen, tunfd_[0], ntohl(*((uint32_t*)buf)));

   if ((buf[0] & 0xf0) == 0x60)
   {
      log_msg(L_NOTICE, "[test_tun_hdr] tun doesn't seem to have any frame header");
      return;
   }
   
   fhd_key_ = *((uint32_t*)buf);
   log_msg(L_NOTICE, "[test_tun_hdr] using 0x%08x as local frame header", ntohl(fhd_key_));
}

#endif

#endif

