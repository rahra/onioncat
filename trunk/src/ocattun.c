/* Copyright 2008-2009 Bernhard R. Fischer.
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



#include "ocat.h"
#include "ocat_netdesc.h"

#ifndef WITHOUT_TUN

char *tun_dev_ = TUN_DEV;

#define IFCBUF 1024


void system_w(const char *s)
{
   int e;

   log_debug("running command \"%s\"", s);
   if ((e = system(s)) == -1)
      log_msg(LOG_ERR, "could not exec \"%s\": \"%s\"", s, strerror(errno));
   log_debug("exit status = %d", WEXITSTATUS(e));
}


int tun_alloc(char *dev, int dev_s, struct in6_addr addr)
{
#ifdef __linux__
   struct ifreq ifr;
#endif
#ifdef __sun__
   int ppa = -1;
#endif
   int fd;
   char astr[INET6_ADDRSTRLEN];
   char astr4[INET_ADDRSTRLEN];
   char buf[IFCBUF];
   struct in_addr netmask;// = {CNF(ocat_addr4_mask)};

   memcpy(&netmask, &CNF(ocat_addr4_mask), sizeof(netmask));
   inet_ntop(AF_INET6, &addr, astr, INET6_ADDRSTRLEN);
   inet_ntop(AF_INET, &CNF(ocat_addr4), astr4, INET_ADDRSTRLEN);

#ifdef __CYGWIN__
   if ((fd = win_open_tun(dev, dev_s)) == -1)
      return -1;

      // set IPv6 address
      // 181    // % netsh interface ipv6 add address "LAN-Verbindung 2" fd87:d87e:eb43:0:84:2100:0:8421
      // 182    // add route
      // 183    // % netsh interface ipv6 add route  fd87:d87e:eb43::/48 "LAN-Verbindung 2"

   snprintf(buf, sizeof(buf), "netsh interface ipv6 add address \"%s\" %s", dev, astr);
   system_w(buf);

   snprintf(buf, sizeof(buf), "netsh interface ipv6 add route %s/%d \"%s\"", astr, NDESC(prefix_len), dev);
   system_w(buf);

   return 0;
#endif

	log_debug("opening tun \"%s\"", tun_dev_);
   if ((fd = open(tun_dev_, O_RDWR)) < 0)
   {
      log_msg(LOG_EMERG, "could not open tundev %s: %s", tun_dev_, strerror(errno));
      return -1;
   }

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
      snprintf(buf, sizeof(buf), "ifconfig %s add %s/%d up", dev, astr, NDESC(prefix_len));
      system_w(buf);
   }

   // according to drivers/net/tun.c only IFF_MULTICAST and IFF_PROMISC are supported.
/*   ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;
   if (ioctl(fd, SIOCSIFFLAGS, (void*) &ifr) < 0)
      log_msg(LOG_ERR, "could not set interface flags: \"%s\"", strerror(errno));
      */

#else

   // get interface name
   if (!CNF(use_tap))
   {
      if (strstr(tun_dev_, "tun"))
         strlcpy(dev, strstr(tun_dev_, "tun"), IFNAMSIZ);
      else
         strlcpy(dev, "tun0", IFNAMSIZ);
   }
   else
   {
       if (strstr(tun_dev_, "tap"))
         strlcpy(dev, strstr(tun_dev_, "tap"), IFNAMSIZ);
      else
         strlcpy(dev, "tap0", IFNAMSIZ);
   }
   /*
   if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
   {
      log_msg(LOG_ERR, "could not SIOCGIFADDR to get interface name: \"%s\"", strerror(errno));
      strlcpy(dev, "tun0", IFNAMSIZ);
   }
   else
   {
      strlcpy(dev, ifr.ifr_name, IFNAMSIZ);
   }
   */

#if defined __FreeBSD__ || defined __DragonFly__

   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFHEAD: %s", strerror(errno)), exit(1);
   prm = IFF_POINTOPOINT;
   if (ioctl(fd, TUNSIFMODE, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFMODE: %s", strerror(errno)), exit(1);

#endif

#ifdef __APPLE__

// see http://svn.deepdarc.com/code/miredo-osx/trunk/tuntap/README
// FIXME: this should be included by the right header file
//        but I couldn't find it
#define TUNSIFHEAD  _IOW('t', 96, int)

   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFHEAD: %s", strerror(errno)), exit(1);

#endif /* __linux__ */

#ifdef __sun__
   if( (ppa = ioctl(fd, TUNNEWPPA, ppa)) == -1)
      log_msg(LOG_ERR, "Can't assign new interface");
   else
      snprintf(dev, dev_s, "%s%d", dev, ppa);

#endif

   if (!CNF(use_tap))
   {
#ifdef __OpenBSD__
      snprintf(buf, sizeof(buf), "ifconfig %s inet6 %s prefixlen %d up", dev, astr, NDESC(prefix_len));
#elif __sun__
      snprintf(buf, sizeof(buf), "ifconfig %s inet6 plumb %s/%d %s up", dev, astr, NDESC(prefix_len), astr);
#else
      snprintf(buf, sizeof(buf), "ifconfig %s inet6 %s/%d up", dev, astr, NDESC(prefix_len));
#endif
      system_w(buf);

      // some OSes require routes to be set manually
#ifdef __APPLE__
      // MacOSX requires the route to be set up manually
      // FIXME: the prefix shouldn't be hardcoded here
      snprintf(buf, sizeof(buf), "route add -inet6 -net fd87:d87e:eb43:: -prefixlen %d -gateway %s", NDESC(prefix_len), astr);
      system_w(buf);
#elif __sun__
      // Solaris requires the route to be set up manually
      // FIXME: the prefix shouldn't be hardcoded here
      snprintf(buf, sizeof(buf), "route add -inet6 fd87:d87e:eb43::/%d %s -iface", NDESC(prefix_len), astr);
      system_w(buf);
#endif

   }

#endif

   // setting up IPv4 address
   if (CNF(ipv4_enable) && !CNF(use_tap))
   {
      snprintf(buf, sizeof(buf), "ifconfig %s %s netmask %s", dev, astr4, inet_ntoa(netmask));
      system_w(buf);
   }

   // bring up tap device
   if (CNF(use_tap))
   {
      snprintf(buf, sizeof(buf), "ifconfig %s up", dev);
      system_w(buf);
   }

   return fd;
}              
 
#endif /* WITHOUT_TUN */

