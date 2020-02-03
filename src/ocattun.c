/* Copyright 2008-2019 Bernhard R. Fischer.
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

/*! \file ocattun.c
 *  These functions create and initialized the TUN/TAP device.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunk at>
 *  \date 2019/09/08
 */



#include "ocat.h"
#include "ocat_netdesc.h"

#ifndef WITHOUT_TUN

char *tun_dev_ = TUN_DEV;

#define IFCBUF 1024


/*! system_w() is a wrapper function for system(3). It checks return codes and
 * outputs some logging messages.
 * @param s Parameter directly passed to system(3).
 * @return Returns return value of system(3).
 */
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


/*! This function executes the ifup script (see option -e). The function forks
 * a child, sets the environment variables OCAT_IFNAME, OCAT_ADDRESS,
 * OCAT_PREFIX, and OCAT_PREFIXLEN and finally executes the ifup shell script
 * by calling execlp(3).
 * The parent does not wait for the child to exit.
 * @param ifname Pointer to interface name string.
 * @param astr Pointer to literal IPv6 address string.
 * @param prefix_len Prefix length.
 * @return On success (if the child could be forked) 0 is returned, otherwise
 * -1 is returned.
 */
int run_tun_ifup(const char *ifname, const char *astr, int prefix_len)
{
   char env_ifname[ENVLEN], env_address[ENVLEN], env_prefix[ENVLEN], env_prefix_len[ENVLEN], env_onion_url[ENVLEN], env_onion3_url[ENVLEN], env_domain[ENVLEN];
   char *env[] = {env_ifname, env_address, env_prefix, env_prefix_len, env_onion_url, env_onion3_url, env_domain, NULL};
   pid_t pid;

   if (ifname == NULL || astr == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in run_tun_ifup()");
      return -1;
   }

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
         snprintf(env_onion_url, sizeof(env_onion_url), "OCAT_ONION_URL=%s", CNF(onion_url));
         snprintf(env_onion3_url, sizeof(env_onion3_url), "OCAT_ONION3_URL=%s", CNF(onion3_url));
         snprintf(env_domain, sizeof(env_domain), "OCAT_DOMAIN=%s", CNF(domain));
         environ = env;

         execlp(CNF(ifup), CNF(ifup), NULL);

         log_msg(LOG_ERR, "execlp(\"%s\") failed: %s", CNF(ifup), strerror(errno));
         _exit(1);

      // parent
      default:
         return 0;
   }
}


/*! mk_in6_mask() creates an IPv6 network mask according to the number
 * specified in prefixlen.
 * @param msk Pointer to in6_addr which will receive the result.
 * @param prefixlen Prefix length.
 * @return On success 0 is returned, otherwise -1.
 */
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


/*! sin_set_addr() fills in a sockaddr_in structure appropriately.
 * @param sin Pointer to a sockaddr_in structure which will be filled in.
 * @param addr Network address which will be copied into sin.
 * @return On success 0 is return, otherwise -1. The function may only fail of
 * NULL pointers are passed.
 * FIXME: This function should be moved to ocatlibe.c.
 */
int sin_set_addr(struct sockaddr_in *sin, const struct in_addr *addr)
{
   if (sin == NULL || addr == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in sin_set_addr()");
      return -1;
   }
#ifdef HAVE_SIN_LEN
   sin->sin_len = sizeof(struct sockaddr_in);
#endif
   sin->sin_family = AF_INET;
   sin->sin_addr = *addr;

   return 0;
}


/*! sin6_set_addr() fills in a sockaddr_in6 structure appropriately.
 * @param sin Pointer to a sockaddr_in6 structure which will be filled in.
 * @param addr Network address which will be copied into sin.
 * @return On success 0 is return, otherwise -1. The function may only fail of
 * NULL pointers are passed.
 * FIXME: This function should be moved to ocatlibe.c.
 */
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
   sin6->sin6_addr = *addr;

   return 0;
}


/*! This function tries to find the network interface name (e.g. tun0).
 * Typically this is the basename of the character device which is opened. On
 * Linux and Solaris these are clone devices, thus the name is found by an
 * ioctl().
 * @param dev Char pointer which will receive the name. It must point to a
 * '\0', i.e. strlen must be 0, otherwise the function immediately returns.
 * @param devlen Number of bytes available in dev.
 * @return Returns 0 if string was copied, -1 if the string was not empty or a
 * NULL pointer was passed.
 */
int tun_guess_ifname(char *dev, int devlen)
{
#ifdef __sun__
   char buf[devlen];
   buf[0] = '\0';
#endif
   char *s = CNF(use_tap) ? "tap" : "tun";

   // safety check
   if (dev == NULL)
   {
      log_msg(LOG_EMERG, "NULL pointer caught in tun_guess_ifname()");
      return -1;
   }

   // check if name already set
   if (*dev)
   {
#ifdef __sun__
      strlcpy(buf, dev, sizeof(buf));
#else
      log_debug("ifname already set: \"%s\"", dev);
      return -1;
#endif
   }

   if (strstr(tun_dev_, s))
      strlcpy(dev, strstr(tun_dev_, s), devlen);
   else // default faulback
      snprintf(dev, devlen, "%s0", s);

#ifdef __sun__
   strlcat(dev, buf, devlen);
#endif

   log_debug("ifname = \"%s\"", dev);
   return 0;
}


/*! tun_config() does some basic initialization on the newly opened tun device.
 * This is highly OS-specific.
 * @param fd File descriptor of tunnel device.
 * @param dev Pointer to string which may contain interface name.
 * @param devlen Number of bytes available in dev.
 * @return Returns 0 on success.
 */
int tun_config(int fd, char *dev, int devlen)
{
#ifdef __linux__
   struct ifreq ifr;

   memset(&ifr, 0, sizeof(ifr));

   if (CNF(use_tap))
      ifr.ifr_flags = IFF_TAP;
   else
      ifr.ifr_flags = IFF_TUN;

   // safety checks
   if (dev != NULL && *dev)
      strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

   if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
      log_msg(LOG_EMERG, "could not set TUNSETIFF: %s", strerror(errno)), exit(1);

   if (dev != NULL)
      strlcpy(dev, ifr.ifr_name, devlen);
#endif

#if defined __FreeBSD__ || defined __DragonFly__
   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFHEAD: %s", strerror(errno)), exit(1);
   prm = IFF_POINTOPOINT;
   if (ioctl(fd, TUNSIFMODE, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFMODE: %s", strerror(errno)), exit(1);
#endif

#ifdef __APPLE__
#ifndef TUNSIFHEAD
// see http://svn.deepdarc.com/code/miredo-osx/trunk/tuntap/README
// FIXME: this should be included by the right header file
//        but I couldn't find it
#warning Using hardcoded value for TUNSIFHEAD
#define TUNSIFHEAD  _IOW('t', 96, int)
#endif
   int prm = 1;
   if (ioctl(fd, TUNSIFHEAD, &prm) == -1)
      log_msg(LOG_EMERG, "could not ioctl:TUNSIFHEAD: %s", strerror(errno)), exit(1);
#endif

#ifdef __sun__
#ifndef TUNNEWPPA
#warning Missing net/if_tun.h, using hardcoded value for TUNNEWPPA
#define TUNNEWPPA       (('T'<<16) | 0x0001)
#endif
   int ppa = -1;
   if( (ppa = ioctl(fd, TUNNEWPPA, ppa)) == -1)
      log_msg(LOG_ERR, "Can't assign new interface: %s", strerror(errno));
   else
      snprintf(dev, devlen, "%d", ppa);
#endif

   return 0;
}


/*! This function configures an IPv6 address to the network device (TUN).
 *  @param dev Char pointer to device name.
 *  @param addr Pointer to IPv6 address.
 *  @param prefix_len Prefix length.
 *  @return Returns 0 on success, otherwise -1 is returned.
 */
int tun_ipv6_config(const char *dev, const struct in6_addr *addr, int prefix_len)
{
   char astr[INET6_ADDRSTRLEN];
   inet_ntop(AF_INET6, addr, astr, INET6_ADDRSTRLEN);

#ifdef __CYGWIN__
   char buf[IFCBUF];

   snprintf(buf, sizeof(buf), "netsh interface ipv6 add address \"%s\" %s/%d", dev, astr, prefix_len);
   system_w(buf);

#else
   int sockfd;

   log_msg(LOG_INFO, "setting interface IPv6 address %s/%d", astr, prefix_len);
   if ((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) == -1)
   {
      log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      return -1;
   }

#ifdef __linux__
   struct in6_ifreq ifr6;
   struct ifreq ifr;

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
   if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
   {
      log_msg(LOG_ERR, "SIOCGIFINDEX: %s", strerror(errno));
   }

   ifr6.ifr6_addr = *addr;
   ifr6.ifr6_ifindex = ifr.ifr_ifindex;
   ifr6.ifr6_prefixlen = prefix_len;

   log_debug("calling ioctl(SIOCSIFADDR)");
   if (ioctl(sockfd, SIOCSIFADDR, &ifr6) == -1)
   {
      log_msg(LOG_ERR, "SIOCSIFADDR: %s", strerror(errno));
   }
#elif defined SIOCAIFADDR_IN6
// I guess this works for all *BSD flavors
   struct in6_aliasreq ifr6a;
   struct in6_addr ifmask;

   memset(&ifr6a, 0, sizeof(ifr6a));
   strlcpy(ifr6a.ifra_name, dev, sizeof(ifr6a.ifra_name));

   sin6_set_addr(&ifr6a.ifra_addr, addr);

   mk_in6_mask(&ifmask, prefix_len);
   sin6_set_addr(&ifr6a.ifra_prefixmask, &ifmask);

   ifr6a.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
   ifr6a.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;

   log_debug("calling ioctl(SIOCAIFADDR_IN6)");
   if (ioctl(sockfd, SIOCAIFADDR_IN6, &ifr6a) == -1)
   {
      log_msg(LOG_ERR, "SIOCAIFADDR_IN6: %s", strerror(errno));
   }
#else
   char buf[IFCBUF];
#ifdef __sun__
   // FIXME: This command does not work on Solaris 11, but could not figure out how to do it.
   snprintf(buf, sizeof(buf), "ifconfig %s inet6 plumb addif %s/%d :: up", dev, astr, prefix_len);
#else
   snprintf(buf, sizeof(buf), "ifconfig %s inet6 %s/%d up", dev, astr, prefix_len);
#endif
   system_w(buf);
#endif
   close(sockfd);
#endif

   return 0;
}


/*! This function configures an IPv4 address to the network device (TUN).
 *  @param dev Char pointer to device name.
 *  @param addr Pointer to IPv6 address.
 *  @param prefix_len Prefix length.
 *  @return Returns 0 on success, otherwise -1 is returned.
 */
int tun_ipv4_config(const char *dev, const struct in_addr *addr, const struct in_addr *netmask)
{
#ifdef __CYGWIN__
   log_msg(LOG_NOTICE, "IPv4 IP config not implemented for Cygwin, use if-up script!");
   return -1;

#else
   int sockfd;

   log_msg(LOG_INFO, "setting interface IPv4 address %s/%s", inet_ntoa(*addr), inet_ntoa(*netmask));
   if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
   {
      log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      return -1;
   }

#ifdef __linux__
   struct ifreq ifr;

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

   sin_set_addr((struct sockaddr_in*) &ifr.ifr_addr, addr);
   log_debug("calling ioctl(SIOCSIFADDR)");
   if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1)
   {
      log_msg(LOG_ERR, "SIOCSIFADDR: %s", strerror(errno));
   }

   sin_set_addr((struct sockaddr_in*) &ifr.ifr_netmask, netmask);
   log_debug("calling ioctl(SIOCSIFNETMASK)");
   if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) == -1)
   {
      log_msg(LOG_ERR, "SIOCSIFNETMASK: %s", strerror(errno));
   }
#elif defined SIOCAIFADDR
   struct ifaliasreq ifra;

   memset(&ifra, 0, sizeof(ifra));
   strlcpy(ifra.ifra_name, dev, sizeof(ifra.ifra_name));

   sin_set_addr((struct sockaddr_in*) &ifra.ifra_addr, addr);
   sin_set_addr((struct sockaddr_in*) &ifra.ifra_mask, netmask);

   log_debug("calling ioctl(SIOCAIFADDR)");
   if (ioctl(sockfd, SIOCAIFADDR, &ifra) == -1)
   {
      log_msg(LOG_ERR, "SIOCAIFADDR: %s", strerror(errno));
   }
#else
   char buf[SIZE_256];
   snprintf(buf, sizeof(buf), "ifconfig %s %s netmask %s", dev, inet_ntoa(*addr), inet_ntoa(*netmask));
   system_w(buf);
#endif
   close(sockfd);
#endif

   return 0;
}


/*! This function simply set the interface link up.
 *  @param dev Char pointer to device name.
 *  @return Returns 0 on success, otherwise -1 is returned.
 */
int tun_ifup(const char *dev)
{
#ifdef SIOCSIFFLAGS
   struct ifreq ifr;
   int sockfd;

   log_msg(LOG_INFO, "bringing up interface");
   if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
   {
      log_msg(LOG_ERR, "failed to create temp socket: %s", strerror(errno));
      return -1;
   }

   memset(&ifr, 0, sizeof(ifr));
   strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

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
#else
#ifndef __CYGWIN__
   char buf[SIZE_256];
   // try generic interface up command
   snprintf(buf, sizeof(buf), "ifconfig %s up", dev);
   system_w(buf);
#endif
#endif

   return 0;
}


/*! Some operating systems do not automatically install a route into the
 * routing table if an IP address/netmask is assigned to an interface. This
 * function add the routes appropriately by calling external shell commands.
 * @param dev Pointer to interface name.
 * @param dev Pointer to IPv6 prefix.
 * @param prefix_len Prefix length.
 * @param addr Pointer to OnionCat address (i.e. the nexthop).
 * @return The function always returns the return value of system(3) which is 0
 * on success.
 */
int tun_add_route(const char *dev, const struct in6_addr *prefix, int prefix_len, const struct in6_addr *addr)
{
   char pfx[INET6_ADDRSTRLEN];
   char astr[INET6_ADDRSTRLEN];
   char buf[SIZE_256] = "";
   int e = 0;

   inet_ntop(AF_INET6, prefix, pfx, INET6_ADDRSTRLEN);
   inet_ntop(AF_INET6, addr, astr, INET6_ADDRSTRLEN);

   // some OSes require routes to be set manually
#ifdef __APPLE__
   // MacOSX requires the route to be set up manually
   snprintf(buf, sizeof(buf), "route add -inet6 -net %s -prefixlen %d -gateway %s", pfx, prefix_len, astr);
#elif __sun__
   // Solaris requires the route to be set up manually
   snprintf(buf, sizeof(buf), "route add -inet6 %s/%d %s -iface", pfx, prefix_len, astr);
#elif __ANDROID__
   snprintf(buf, sizeof(buf), "ip route add table local %s/%d dev %s", pfx, prefix_len, dev);
#endif

   if (buf[0] != '\0')
      e = system_w(buf);

   return e;
}


/*! Completely set up tun device for Onioncat.
 * @param dev Char pointer to ifname if the name should be customized (only
 * supported for Linux yet), must point otherwise to a string with length 0
 * (i.e. it points to a \0-char). The string will be initialized by this
 * function.
 * @param dev_s Number of bytes available in dev.
 * @param in6_addr DEPRECATED.
 * @return On success it returns a filedescriptor >= 0, otherwise -1 is returned.
 */
int tun_alloc(char *dev, int dev_s, struct in6_addr addr)
{
   int fd;

	log_debug("opening tun \"%s\"", tun_dev_);
#ifdef __CYGWIN__
   // FIXME: win_open_tun() does not set errno
   if ((fd = win_open_tun(dev, dev_s)) == -1)
#else
   if ((fd = open(tun_dev_, O_RDWR)) == -1)
#endif
   {
      log_msg(LOG_EMERG, "could not open tundev %s: %s", tun_dev_, strerror(errno));
      return -1;
   }

   log_debug("tun base config");
   tun_config(fd, dev, dev_s);

   log_debug("trying to find ifname");
   tun_guess_ifname(dev, dev_s);

   if (CNF(ifup) != NULL)
   {
      char astr[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &CNF(ocat_addr), astr, INET6_ADDRSTRLEN);
      log_debug("running ifup script");
      run_tun_ifup(dev, astr, NDESC(prefix_len));
      return fd;
   }

   if (CNF(ipconfig))
   {
      log_debug("setting up IPv6 address");
      tun_ipv6_config(dev, &CNF(ocat_addr), NDESC(prefix_len));

      // setting up IPv4 address
      if (CNF(ipv4_enable))
      {
         log_debug("setting up IPv4 address");
         tun_ipv4_config(dev, &CNF(ocat_addr4), &CNF(ocat_addr4_netmask));
      }
   }

   // bring up device
   tun_ifup(dev);

   // set route if necessary
   if (CNF(ipconfig))
      tun_add_route(dev, &NDESC(prefix), NDESC(prefix_len), &CNF(ocat_addr));

   return fd;
}
#endif /* WITHOUT_TUN */

