/* Copyright 2008-2023 Bernhard R. Fischer.
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

/*! \file ocatsetup.c
 *  This file contains the global settings structure.
 *
 *  @author Bernhard Fischer <bf@abenteuerland.at>
 *  \date 2023/01/24
 */


#include "ocat.h"
#include "ocat_netdesc.h"
#include "ocathosts.h"


static struct sockaddr_in6 socks_dst6_;
static struct sockaddr_in ctrl_listen_;
static struct sockaddr_in6 ctrl_listen6_;
static struct sockaddr *ctrl_listen_ptr_[] = 
{
   (struct sockaddr*) &ctrl_listen_, 
#ifndef __CYGWIN__
   (struct sockaddr*) &ctrl_listen6_, 
#endif
      NULL};
static int ctrl_fd_[2] = {-1, -1};

struct OcatSetup setup_ =
{
   // fhd_keys
   {0, 0},
   // fhd_key_len
   sizeof(uint32_t),
   //TOR_SOCKS_PORT, 
   //OCAT_LISTEN_PORT, 
   0, 0,
   //! default tunfd is stdin/stdout
   {0, 1},
   1, // ipconfig
   //! default debug level
   LOG_DEBUG,
   OCAT_UNAME, {0}, {0}, IN6ADDR_ANY_INIT, 0,
#ifndef __ANDROID__
   0,                                     // run as root (dont drop privs)
#else
   1,                                     // currently require for Android (cause theres now APK...)
#endif
   1,                                     // enable controller interface
   OCAT_DIR,
   TUN_DEV,
   0,                                     // enable SOCKS5
   16,                                    // l_hs_namelen
   {'\0'},                                // tunname
   0, 
   //ADDR4_PREFIX, ADDR4_MASK
   {0}, {0},
   // config_file, config_read, config_failed
   NULL, 0, 0,
   NULL,                                  // ifup
#ifdef __CYGWIN__
   1,
#else
   0,                                      // use_tap
#endif
   {0x00, 0x00, 0x6c, 0x00, 0x00, 0x00},   // ocat_hwaddr (OnionCat MAC address)
   PID_FILE,                               // pid_file
   0,                                      // create_pid_file
   NULL, 2,                                // logfile
   0,                                      // use_syslog
#ifdef __CYGWIN__
   0,
#else
   1,                                      // daemon
#endif
   0,
   "/dev/urandom",
   {(struct sockaddr_in*) &socks_dst6_},
   // oc_listen
   NULL,
   // oc_listen_fd
   NULL,
   // oc_listen_cnt
   0,
   //! rand_addr
   0,
   {0},
   sizeof(struct OcatSetup),
   PTHREAD_MUTEX_INITIALIZER,
   // ctrl_listen
   ctrl_listen_ptr_,
   // oc_listen_fd
   ctrl_fd_,
   // oc_listen_cnt
#if defined(__CYGWIN__)
   1
#else
   2
#endif
   ,
   // socksfd
   {-1, -1},
   // net_type
   NTYPE_TOR,
   // max_ctrl, ctrl_active
   MAX_DEF_CTRL_SESS, 0,
   // pid_fd
   {-1, -1},
   // clear_stats
   0,
   // unidirectional
   1,
   // hosts_lookup, default is value set by ocat_netdesc.c
   0,
   // hosts_path
   SYSCONFDIR"/tor/onioncat.hosts",
   // hosts cache
   OCAT_HOSTS_STATE,
   // domain
   "",
   // dns_loopup
   1,
   // dns_server
   1,
   // validate_remnames
   1,
   // ocat_ns_port
   OCAT_NS_PORT,
   // expiry time
   HOSTS_EXPIRE,
   // verify_dest
   1
};


#define IADDRSTRLEN 128


void init_setup(void)
{
   struct timeval tv;
   const uint32_t loop_ = htonl(INADDR_LOOPBACK);

   // seeding PRNG rand()
   if (gettimeofday(&tv, NULL) == -1)
      log_msg(LOG_WARNING, "could gettimeofday(): \"%s\"", strerror(errno));
   srand(tv.tv_sec ^ tv.tv_usec);

   //setup_.logf = stderr;
   setup_.uptime = time(NULL);
   memset(&socks_dst6_, 0, sizeof(socks_dst6_));
   setup_.socks_dst->sin_family = AF_INET;
   //setup_.socks_dst->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   memcpy(&setup_.socks_dst->sin_addr, &loop_, sizeof(setup_.socks_dst->sin_addr));
#ifdef HAVE_SIN_LEN
   setup_.socks_dst->sin_len = SOCKADDR_SIZE(setup_.socks_dst);
#endif

   memset(&ctrl_listen_, 0, sizeof(ctrl_listen_));
   memset(&ctrl_listen6_, 0, sizeof(ctrl_listen6_));

#ifdef __linux__
   CNF(fhd_key[IPV6_KEY]) = htonl(ETHERTYPE_IPV6);
   CNF(fhd_key[IPV4_KEY]) = htonl(ETHERTYPE_IP);
#else
   CNF(fhd_key[IPV6_KEY]) = htonl(AF_INET6);
   CNF(fhd_key[IPV4_KEY]) = htonl(AF_INET);
#endif
}


void post_init_setup(void)
{
   static char _config_file[1024];
   const uint32_t loop_ = htonl(INADDR_LOOPBACK);

   setup_.ocat_addr4 = NDESC(prefix4);
   setup_.ocat_addr4_mask = NDESC(addr4_mask);
   setup_.ocat_dest_port = NDESC(vdest_port);
   setup_.ocat_ctrl_port = NDESC(ctrl_port);
   setup_.hosts_lookup = NDESC(hosts_lookup);
   setup_.domain = NDESC(domain);
   setup_.l_hs_namelen = NDESC(l_hs_namelen);
   hosts_init(NDESC(domain));

   if (!setup_.config_file)
   {
      snprintf(_config_file, sizeof(_config_file), "%s/%s", SYSCONFDIR, NDESC(config_file));
      setup_.config_file = _config_file;
   }

   if (!setup_.socks_dst->sin_port)
      setup_.socks_dst->sin_port = htons(NDESC(socks_port));

   ctrl_listen_.sin_family = AF_INET;
   ctrl_listen_.sin_port = htons(setup_.ocat_ctrl_port);
   //ctrl_listen_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
   memcpy(&ctrl_listen_.sin_addr, &loop_, sizeof(ctrl_listen_.sin_addr));
#ifdef HAVE_SIN_LEN
   ctrl_listen_.sin_len = sizeof(ctrl_listen_);
#endif

   ctrl_listen6_.sin6_family = AF_INET6;
   ctrl_listen6_.sin6_port = htons(setup_.ocat_ctrl_port);
   ctrl_listen6_.sin6_addr = in6addr_loopback; //IN6ADDR_LOOPBACK_INIT;
#ifdef HAVE_SIN_LEN
   ctrl_listen6_.sin6_len = sizeof(ctrl_listen6_);
#endif

   snprintf(setup_.version, VERSION_STRING_LEN, "%s (c) %s (%s mode)", PACKAGE_STRING, OCAT_AUTHOR, setup_.net_type == NTYPE_TOR ? "OnionCat" : setup_.net_type == NTYPE_I2P ? "GarliCat" : "unknown");

   // You may comment-in the following lines for debugging purpose. Code was
   // removed due to request of Debian package maintainer.
#if 0
   snprintf(&setup_.version[strlen(setup_.version)], VERSION_STRING_LEN - strlen(setup_.version), " -- compiled %s %s", __DATE__, __TIME__);
#endif

   setup_.pid_file = NDESC(pid_file);
}


#define SBUF 100


void print_setup_struct(int fd)
{
   char *c, ip[SBUF], nm[SBUF], ip6[SBUF], hw[SBUF];
   int i, t;
   struct sockaddr_str sas;

   inet_ntop(AF_INET, &setup_.ocat_addr4, ip, SBUF);
   inet_ntop(AF_INET, &setup_.ocat_addr4_mask, nm, SBUF);
   inet_ntop(AF_INET6, &setup_.ocat_addr, ip6, SBUF);
   ether_ntoa_r((struct ether_addr*) setup_.ocat_hwaddr, hw);

   t = time(NULL) - setup_.uptime;

   dprintf(fd,
         "fhd_key[IPV4(%d)]       = 0x%04x\n"
         "fhd_key[IPV6(%d)]       = 0x%04x\n"
         "fhd_key_len            = %d\n"
         //"tor_socks_port    = %d\n"
         //"ocat_listen_port       = %d\n"
         "ocat_dest_port         = %d\n"
         "ocat_ctrl_port         = %d\n"
         "tunfd[0]               = %d\n"
         "tunfd[1]               = %d\n"
         "ipconfig               = %d\n"
         "debug_level            = %d\n"
         "usrname                = \"%s\"\n"
         "onion_url              = \"%s\"\n"
         "onion3_url             = \"%s\"\n"
         "ocat_addr              = %s\n"
         "create_clog            = %d\n"
         "runasroot              = %d\n"
         "controller             = %d\n"
         "ocat_dir               = \"%s\"\n"
         "tun_dev                = \"%s\"\n"
         "socks5                 = %d\n"
         "l_hs_namelen           = %d\n"
         "tunname                = \"%s\"\n"
         "ipv4_enable            = %d\n"
         "ocat_addr4             = %s\n"
         "ocat_addr4_mask        = %s\n"
         "config_file            = \"%s\"\n"
         "config_read            = %d\n"
         "use_tap                = %d\n"
         "ocat_hwaddr            = %s\n"
         "pid_file               = \"%s\"\n"
         "logfn                  = \"%s\"\n"
         "logfd                  = %d\n"
         "daemon                 = %d\n"
         "uptime                 = %d days, %d:%02d\n"
         "version[%3d+1/%3d]     = \"%s\"\n"
         "sizeof_setup           = %d\n"
         "net_type               = %d (%s)\n"
         "max_ctrl               = %d\n"
         "ctrl_active            = %d\n"
         "pid_fd[2]              = {%d, %d}\n"
         "clear_stats            = %d\n"
         "ctrl_listen_cnt        = %d\n"
         "unidirectional         = %d\n"
         "hosts_lookup           = %d\n"
         "hosts_path             = %s\n"
         "hosts_cache            = %s\n"
         "domain                 = \"%s\"\n"
         "dns_lookup             = %d\n"
         "dns_server             = %d\n"
         "validate_remnames      = %d\n"
         "ocat_ns_port           = %d\n"
         "expire                 = %d\n"
         "verify_dest            = %d\n"
         "----------------------\n"
         ,
         IPV4_KEY, ntohl(setup_.fhd_key[IPV4_KEY]), IPV6_KEY, ntohl(setup_.fhd_key[IPV6_KEY]),
         setup_.fhd_key_len,
         //setup_.tor_socks_port,
         //setup_.ocat_listen_port,
         setup_.ocat_dest_port,
         setup_.ocat_ctrl_port,
         setup_.tunfd[0], setup_.tunfd[1],
         setup_.ipconfig,
         setup_.debug_level,
         setup_.usrname,
         setup_.onion_url,
         setup_.onion3_url,
         ip6,
         setup_.create_clog,
         setup_.runasroot,
         setup_.controller,
         setup_.ocat_dir,
         setup_.tun_dev,
         setup_.socks5,
         setup_.l_hs_namelen,
         setup_.tunname,
         setup_.ipv4_enable,
         ip,
         nm,
         setup_.config_file,
         setup_.config_read,
         setup_.use_tap,
         hw,
         setup_.pid_file,
         SSTR(setup_.logfn),
         setup_.logfd,
         setup_.daemon,
         t / (3600 * 24), t / 3600 % 24, t / 60 % 60,
         (int) strlen(setup_.version), VERSION_STRING_LEN, setup_.version,
         setup_.sizeof_setup,
         setup_.net_type, setup_.net_type == NTYPE_TOR ? "NTYPE_TOR" : setup_.net_type == NTYPE_I2P ? "NTYPE_I2P" : "unknown",
         setup_.max_ctrl, setup_.ctrl_active,
         setup_.pid_fd[0], setup_.pid_fd[1],
         setup_.clear_stats,
         setup_.ctrl_listen_cnt,
         setup_.unidirectional,
         setup_.hosts_lookup,
         SSTR(setup_.hosts_path),
         setup_.hosts_cache,
         setup_.domain,
         setup_.dns_lookup,
         setup_.dns_server,
         setup_.validate_remnames,
         setup_.ocat_ns_port,
         setup_.expire,
         setup_.verify_dest
         );

   if (inet_ntops((struct sockaddr*) setup_.socks_dst, &sas))
   {
      c = sas.sstr_family == AF_INET6 ? "6" : "";
      dprintf(fd,
         "socks_dst%s.sin_family   = 0x%04x\n"
         "socks_dst%s.sin_port     = %d\n"
         "socks_dst%s.sin_addr     = %s\n",
         c, sas.sstr_family,
         c, ntohs(sas.sstr_port),
         c, sas.sstr_addr);
   }
   else
      log_msg(LOG_WARNING, "could not convert struct sockaddr: \"%s\"", strerror(errno));

   for (i = 0; i < CNF(oc_listen_cnt); i++)
   {
      if (inet_ntops(CNF(oc_listen)[i], &sas))
         dprintf(fd, "oc_listen[%d]           = %s:%d\n", i, sas.sstr_addr, ntohs(sas.sstr_port));
      else
         log_msg(LOG_WARNING, "could not convert struct sockaddr: \"%s\"", strerror(errno));
      dprintf(fd, "oc_listen_fd[%d]        = %d\n", i, CNF(oc_listen_fd)[i]);
   }

   for (i = 0; i < CNF(ctrl_listen_cnt); i++)
   {
      if (inet_ntops(ctrl_listen_ptr_[i], &sas))
         dprintf(fd, "ctrl_listen_ptr_[%d]    = %s:%d (0x%04x)\n", i, sas.sstr_addr, ntohs(sas.sstr_port), sas.sstr_family);
      else
         log_msg(LOG_WARNING, "could not convert struct sockaddr: \"%s\"", strerror(errno));
   }
}


void lock_setup(void)
{
   pthread_mutex_lock(&setup_.mutex);
}


void unlock_setup(void)
{
   pthread_mutex_unlock(&setup_.mutex);
}

