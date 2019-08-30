/* Copyright 2008-2017 Bernhard R. Fischer.
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
 *  @version 2019/08/28
 */



#include "ocat.h"
#include "ocat_netdesc.h"

#ifndef WITHOUT_TUN

char *tun_dev_ = TUN_DEV;

#define IFCBUF 1024


int system_w(const char *s)
{
   int e;

   log_debug("running command \"%s\"", s);
   if ((e = system(s)) == -1)
      log_msg(LOG_ERR, "could not exec \"%s\": \"%s\"", s, strerror(errno));
   else if (WEXITSTATUS(e))
      log_msg(LOG_ERR, "exit status = %d", WEXITSTATUS(e));
   log_debug("exit status = %d", WEXITSTATUS(e));

   return e;
}


#define ENVLEN 64
extern char **environ;


int run_tun_ifup(const char *ifname, const char *astr, int prefix_len)
{
   char env_ifname[ENVLEN], env_address[ENVLEN], env_prefix[ENVLEN], env_prefix_len[ENVLEN];
   char *env[] = {env_ifname, env_address, env_prefix, env_prefix_len, NULL};
   pid_t pid;

   log_msg(LOG_INFO, "running ifup script \"%s\"", CNF(ifup));
   switch (pid = fork())
   {
      // fork failed
      case -1:
         log_msg(LOG_ERR, "could not fork sub process for script execution: \"%s\"", strerror(errno));
         return -1;

      // child
      case 0:
         snprintf(env_ifname, sizeof(env_ifname), "OCAT_IFNAME=%s", ifname);
         snprintf(env_address, sizeof(env_address), "OCAT_ADDRESS=%s", astr);
         strlcpy(env_prefix, "OCAT_PREFIX=", sizeof(env_prefix));
         inet_ntop(AF_INET6, &NDESC(prefix), env_prefix + strlen(env_prefix), sizeof(env_prefix) - strlen(env_prefix));
         snprintf(env_prefix_len, sizeof(env_prefix_len), "OCAT_PREFIXLEN=%d", prefix_len);
         environ = env;

         execlp(CNF(ifup), CNF(ifup), NULL);

         log_msg(LOG_ERR, "execlp(\"%s\") failed: %s", CNF(ifup), strerror(errno));
         _exit(1);

      // parent
      default:
         return 0;
   }
}


int mk_in6_mask(struct in6_addr *msk, int prefixlen)
{
   char *buf;

   // safety check
   if (msk == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in mk_in6_mask()");
      return -1;
   }

   memset(msk, 0, sizeof(*msk));
   for (buf = (char*) msk; prefixlen >= 8; buf++, prefixlen -= 8)
      *buf = 0xff;

   if (prefixlen > 0)
      *buf = ~((8 - prefixlen) - 1);

   return 0;
}


int sin6_set_addr(struct sockaddr_in6 *sin6, const struct in6_addr *addr)
{
   if (sin6 == NULL || addr == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in sin6_set_addr()");
      return -1;
   }
#ifdef HAVE_SIN_LEN
   sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
   sin6->sin6_family = AF_INET6;
   memcpy(&sin6->sin6_addr, addr, sizeof(struct in6_addr));

   return 0;
}


int tun_alloc(char *dev, int dev_s, struct in6_addr addr)
{
#ifdef __linux__
   struct ifreq ifr;
   int sockfd;
   struct in6_ifreq ifr6;
#endif
#ifdef __sun__
   int ppa = -1;
#endif
   int fd;
   char astr[INET6_ADDRSTRLEN];
   char pfx[INET6_ADDRSTRLEN];
   char astr4[INET_ADDRSTRLEN];
   char buf[IFCBUF];
   struct in_addr netmask;// = {CNF(ocat_addr4_mask)};

   memcpy(&netmask, &CNF(ocat_addr4_mask), sizeof(netmask));
   inet_ntop(AF_INET6, &addr, astr, INET6_ADDRSTRLEN);
   inet_ntop(AF_INET6, &NDESC(prefix), pfx, INET6_ADDRSTRLEN);
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

   if (!CNF(use_tap) && (CNF(ifup) == NULL))
   {
      log_msg(LOG_INFO, "setting interface IPv6 address %s/%d", astr, NDESC(prefix_len));
      if ((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) == -1)
      {
         log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      }
      else
      {
         if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
         {
            log_msg(LOG_ERR, "SIOCGIFINDEX: %s", strerror(errno));
         }

         memcpy(&ifr6.ifr6_addr, &addr, sizeof(struct in6_addr));
         ifr6.ifr6_ifindex = ifr.ifr_ifindex;
         ifr6.ifr6_prefixlen = NDESC(prefix_len);
         if (ioctl(sockfd, SIOCSIFADDR, &ifr6) == -1)
         {
            log_msg(LOG_ERR, "SIOCSIFADDR: %s", strerror(errno));
         }

         if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1)
         {
            log_msg(LOG_ERR, "SIOCGIFFLAGS: %s", strerror(errno));
            ifr.ifr_flags = 0;
         }

         ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
         if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
         {
            log_msg(LOG_ERR, "SIOCSIFFLAGS: %s", strerror(errno));
         }

         close(sockfd);
      }
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

#endif

#ifdef __sun__
   if( (ppa = ioctl(fd, TUNNEWPPA, ppa)) == -1)
      log_msg(LOG_ERR, "Can't assign new interface");
   else
      snprintf(dev, dev_s, "%s%d", dev, ppa);

#endif

   if (!CNF(use_tap) && (CNF(ifup) == NULL))
   {
// #if defined __OpenBSD__ || defined __FreeBSD__
// I guess this works for all *BSD flavors
#ifdef SIOCAIFADDR_IN6
      int sockfd;
      struct in6_aliasreq ifr6a;
      struct in6_addr ifmask;

      log_msg(LOG_INFO, "setting interface IPv6 address %s/%d", astr, NDESC(prefix_len));
      if ((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) == -1)
      {
         log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      }
      else
      {
/*#ifdef HAVE_STRUCT_IF_AFREQ
         struct if_afreq ifar;

         strlcpy(ifar.ifar_name, dev, sizeof(ifar.ifar_name));
         ifar.ifar_af = AF_INET6;
         if (ioctl(sockfd, SIOCIFAFDETACH, &ifar) == -1)
            log_msg(LOG_ERR, "ioctl(SIOCIFAFDETACH) failed: %s", strerror(errno));
#endif
*/
         memset(&ifr6a, 0, sizeof(ifr6a));
         strlcpy(ifr6a.ifra_name, dev, sizeof(ifr6a.ifra_name));

         sin6_set_addr(&ifr6a.ifra_addr, &addr);

         mk_in6_mask(&ifmask, NDESC(prefix_len));
         sin6_set_addr(&ifr6a.ifra_prefixmask, &ifmask);

         ifr6a.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
         ifr6a.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;

         if (ioctl(sockfd, SIOCAIFADDR_IN6, &ifr6a) == -1)
         {
            log_msg(LOG_ERR, "SIOCAIFADDR_IN6: %s", strerror(errno));
         }
         close(sockfd);
      }
#else /* __OpenBSD__ */

#if __sun__
      snprintf(buf, sizeof(buf), "ifconfig %s inet6 plumb %s/%d %s up", dev, astr, NDESC(prefix_len), astr);
#else
      snprintf(buf, sizeof(buf), "ifconfig %s inet6 %s/%d up", dev, astr, NDESC(prefix_len));
#endif
      system_w(buf);
#endif

      // some OSes require routes to be set manually
#ifdef __APPLE__
      // MacOSX requires the route to be set up manually
      snprintf(buf, sizeof(buf), "route add -inet6 -net %s -prefixlen %d -gateway %s", pfx, NDESC(prefix_len), astr);
      system_w(buf);
#elif __sun__
      // Solaris requires the route to be set up manually
      snprintf(buf, sizeof(buf), "route add -inet6 %s/%d %s -iface", pfx, NDESC(prefix_len), astr);
      system_w(buf);
#endif

   }

#endif /* __linux__ */

   if (CNF(ifup) != NULL)
   {
      run_tun_ifup(dev, astr, NDESC(prefix_len));
      return fd;
   }

   // setting up IPv4 address
   if (CNF(ipv4_enable) && !CNF(use_tap))
   {
#ifdef __linux__
      log_msg(LOG_INFO, "setting interface IPv4 address %s/%s", astr4, inet_ntoa(netmask));
      if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
      {
         log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      }
      else
      {
         ifr.ifr_addr.sa_family = AF_INET;
         memcpy(&((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr, &CNF(ocat_addr4), sizeof(struct in_addr));
         if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1)
         {
            log_msg(LOG_ERR, "SIOCSIFADDR: %s", strerror(errno));
         }
         ifr.ifr_addr.sa_family = AF_INET;
         memcpy(&((struct sockaddr_in*) &ifr.ifr_netmask)->sin_addr, &netmask, sizeof(struct in_addr));
         if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) == -1)
         {
            log_msg(LOG_ERR, "SIOCSIFNETMASK: %s", strerror(errno));
         }
         close(sockfd);
      }
#else
      snprintf(buf, sizeof(buf), "ifconfig %s %s netmask %s", dev, astr4, inet_ntoa(netmask));
      system_w(buf);
#endif
   }

   // bring up tap device
   if (CNF(use_tap))
   {
#ifdef __linux__
      log_msg(LOG_INFO, "bringing up TAP interface");
      if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
      {
         log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      }
      else
      {
         if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1)
         {
            log_msg(LOG_ERR, "SIOCGIFFLAGS: %s", strerror(errno));
            ifr.ifr_flags = 0;
         }

         ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
         if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
         {
            log_msg(LOG_ERR, "SIOCSIFFLAGS: %s", strerror(errno));
         }
         close(sockfd);
      }
#else
      snprintf(buf, sizeof(buf), "ifconfig %s up", dev);
      system_w(buf);
#endif
   }

   return fd;
}
 
#endif /* WITHOUT_TUN */

