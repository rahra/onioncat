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


#include "ocat.h"


char *tun_dev_ = TUN_DEV;


int tun_alloc(char *dev, struct in6_addr addr)
{
   struct ifreq ifr;
   int fd;
   char astr[INET6_ADDRSTRLEN];
   char astr4[INET_ADDRSTRLEN];
   char buf[FRAME_SIZE];
   struct in_addr netmask = {CNF(ocat_addr4_mask)};

	log_debug("opening tun \"%s\"", tun_dev_);
   if ((fd = open(tun_dev_, O_RDWR)) < 0)
      log_msg(LOG_EMERG, "could not open tundev %s: %s", tun_dev_, strerror(errno)), exit(1);
   inet_ntop(AF_INET6, &addr, astr, INET6_ADDRSTRLEN);
   inet_ntop(AF_INET, &CNF(ocat_addr4), astr4, INET_ADDRSTRLEN);

#ifdef __linux__

   memset(&ifr, 0, sizeof(ifr));
   if (CNF(use_tap))
      ifr.ifr_flags = IFF_TAP;
   else
      ifr.ifr_flags = IFF_TUN;
   //ifr.ifr_flags |= IFF_NO_PI;
   if (*dev)
      strncpy(ifr.ifr_name, dev, IFNAMSIZ);

   if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
      log_msg(LOG_EMERG, "could not set TUNSETIFF: %s", strerror(errno)), exit(1);
   strlcpy(dev, ifr.ifr_name, IFNAMSIZ);
   if (!CNF(use_tap))
   {
      snprintf(buf, sizeof(buf), "ifconfig %s add %s/%d up", dev, astr, TOR_PREFIX_LEN);
      log_msg(LOG_INFO, "configuring tun IP: \"%s\"", buf);
      if (system(buf) == -1)
         log_msg(LOG_ERR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));
   }

   // according to drivers/net/tun.c only IFF_MULTICAST and IFF_PROMISC are supported.
/*   ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;
   if (ioctl(fd, SIOCSIFFLAGS, (void*) &ifr) < 0)
      log_msg(LOG_ERR, "could not set interface flags: \"%s\"", strerror(errno));
      */

   // set tun frame header to ethertype IPv6
   CNF(fhd_key[IPV6_KEY]) = htonl(ETHERTYPE_IPV6);
   CNF(fhd_key[IPV4_KEY]) = htonl(ETHERTYPE_IP);

#else

   // set tun frame header to address family AF_INET6 (FreeBSD = 0x1c, OpenBSD = 0x18)
   CNF(fhd_key[IPV6_KEY]) = htonl(AF_INET6);
   CNF(fhd_key[IPV4_KEY]) = htonl(AF_INET);

#ifdef __FreeBSD__

   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFHEAD: %s", strerror(errno)), exit(1);
   prm = IFF_POINTOPOINT;
   if (ioctl(fd, TUNSIFMODE, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFMODE: %s", strerror(errno)), exit(1);

#endif

#ifdef __APPLE__

// see http://svn.deepdarc.com/code/miredo-osx/trunk/tuntap/README
#define TUNSIFHEAD  _IOW('t', 96, int)

   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFHEAD: %s", strerror(errno)), exit(1);

#endif

   if (!CNF(use_tap))
   {
      snprintf(buf, sizeof(buf), "ifconfig tun0 inet6 %s/%d up", astr, TOR_PREFIX_LEN);
      log_debug("setting IP on tun: \"%s\"", buf);
      if (system(buf) == -1)
         log_msg(LOG_ERR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));
   }

#endif

   // setting up IPv4 address
   if (CNF(ipv4_enable) && !CNF(use_tap))
   {
      snprintf(buf, sizeof(buf), "ifconfig %s %s netmask %s", dev, astr4, inet_ntoa(netmask));
      log_msg(LOG_INFO, "configuring tun IP: \"%s\"", buf);
      if (system(buf) == -1)
         log_msg(LOG_ERR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));
   }

   // bring up tap device
   if (CNF(use_tap))
   {
       snprintf(buf, sizeof(buf), "ifconfig %s up", dev);
      log_msg(LOG_INFO, "bringing up TAP device \"%s\"", buf);
      if (system(buf) == -1)
         log_msg(LOG_ERR, "could not exec \"%s\": \"%s\"", buf, strerror(errno));
   }

   return fd;
}              
 
#endif

