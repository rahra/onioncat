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

/*! ocatsetup_.c
 *  This file contains the global settings structure.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */


#include "ocat.h"
#include "ocat_netdesc.h"


static struct sockaddr_in6 socks_dst6_;
static struct sockaddr_in ctrl_listen_;
static struct sockaddr_in6 ctrl_listen6_;
static struct sockaddr *ctrl_listen_ptr_[] = 
   {(struct sockaddr*) &ctrl_listen_, 
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
   //! default debug level
   LOG_DEBUG,
   OCAT_UNAME, {0}, {{{0}}}, 0, 0, 1, OCAT_DIR, TUN_DEV,
   {'\0'},                                // tunname
   0, 
   //ADDR4_PREFIX, ADDR4_MASK
   {0}, 0,
   NULL, 1,
#ifdef __CYGWIN__
   1,
#else
   0,                                      // use_tap
#endif
   {0x00, 0x00, 0x6c, 0x00, 0x00, 0x00},   // ocat_hwaddr (OnionCat MAC address)
   PID_FILE,                               // pid_file
   0,                                      // create_pid_file
   NULL, NULL,                             // logfile
   0,                                      // use_syslog
#ifdef __CYGWIN__
   0,
#else
   1,                                      // daemon
#endif
#ifdef CONNECT_ROOT_PEERS
   {
      /*
      {{{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43,
           0xed, 0xb1, 0x08, 0xe4, 0x35, 0x88, 0xe5, 0x46, 0x35, 0xca}}}, // initial permanent peer "5wyqrzbvrdsumnok" (mail.root-servers.cat)
           */
      {{{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43,
           0xf6, 0x83, 0x64, 0xac, 0x73, 0xf9, 0x61, 0xac, 0x9a, 0x00}}}  // initial permanent peer "62bwjldt7fq2zgqa" (dot.cat)
   },
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
   //! sig_term, term_req
   0, 0,
   PTHREAD_MUTEX_INITIALIZER,
   // ctrl_listen
   ctrl_listen_ptr_,
   // oc_listen_fd
   ctrl_fd_,
   // oc_listen_cnt
#ifdef __CYGWIN__
   1
#else
   2
#endif
   ,
   // socksfd
   {-1, -1},
   // net_type
   NTYPE_TOR
};


#define IADDRSTRLEN 128


void init_setup(void)
{
   struct timeval tv;

   // seeding PRNG rand()
   if (gettimeofday(&tv, NULL) == -1)
      log_msg(LOG_WARNING, "could gettimeofday(): \"%s\"", strerror(errno));
   srand(tv.tv_sec ^ tv.tv_usec);

   //setup_.logf = stderr;
   setup_.uptime = time(NULL);
}


void post_init_setup(void)
{
   setup_.ocat_addr4 = NDESC(prefix4);
   setup_.ocat_addr4_mask = NDESC(addr4_mask);
   setup_.ocat_dest_port = NDESC(vdest_port);
   setup_.ocat_ctrl_port = NDESC(ctrl_port);

   setup_.socks_dst->sin_family = AF_INET;
   setup_.socks_dst->sin_port = htons(NDESC(socks_port));
   setup_.socks_dst->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   setup_.socks_dst->sin_len = SOCKADDR_SIZE(setup_.socks_dst);
#endif

   ctrl_listen_.sin_family = AF_INET;
   ctrl_listen_.sin_port = htons(setup_.ocat_ctrl_port);
   ctrl_listen_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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
#ifdef DEBUG
   snprintf(&setup_.version[strlen(setup_.version)], VERSION_STRING_LEN - strlen(setup_.version), " -- compiled %s %s", __DATE__, __TIME__);
#endif
}


#define SBUF 100


void print_setup_struct(FILE *f)
{
   char *c, ip[SBUF], nm[SBUF], ip6[SBUF], logf[SBUF], hw[SBUF];
   int i, t;
   struct sockaddr_str sas;

   inet_ntop(AF_INET, &setup_.ocat_addr4, ip, SBUF);
   inet_ntop(AF_INET, &setup_.ocat_addr4_mask, nm, SBUF);
   inet_ntop(AF_INET6, &setup_.ocat_addr, ip6, SBUF);
   ether_ntoa_r((struct ether_addr*) setup_.ocat_hwaddr, hw);

   if (setup_.logf == stderr)
      strlcpy(logf, "stderr", sizeof(logf));
   else
      snprintf(logf, sizeof(logf), "%p", setup_.logf);

   t = time(NULL) - setup_.uptime;


   fprintf(f,
         "fhd_key[IPV4(%d)]       = 0x%04x\n"
         "fhd_key[IPV6(%d)]       = 0x%04x\n"
         "fhd_key_len            = %d\n"
         //"tor_socks_port    = %d\n"
         //"ocat_listen_port       = %d\n"
         "ocat_dest_port         = %d\n"
         "ocat_ctrl_port         = %d\n"
         "tunfd[0]               = %d\n"
         "tunfd[1]               = %d\n"
         "debug_level            = %d\n"
         "usrname                = \"%s\"\n"
         "onion_url              = \"%s\"\n"
         "ocat_addr              = %s\n"
         "create_clog            = %d\n"
         "runasroot              = %d\n"
         "controller             = %d\n"
         "ocat_dir               = \"%s\"\n"
         "tun_dev                = \"%s\"\n"
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
         "logf                   = %s\n"
         "daemon                 = %d\n"
         "uptime                 = %d days, %d:%02d\n"
         "version[%3d+1/%3d]     = \"%s\"\n"
         "sizeof_setup           = %d\n"
         "term_req               = %d\n"
         "net_type               = %d (%s)\n"
         ,
         IPV4_KEY, ntohl(setup_.fhd_key[IPV4_KEY]), IPV6_KEY, ntohl(setup_.fhd_key[IPV6_KEY]),
         setup_.fhd_key_len,
         //setup_.tor_socks_port,
         //setup_.ocat_listen_port,
         setup_.ocat_dest_port,
         setup_.ocat_ctrl_port,
         setup_.tunfd[0], setup_.tunfd[1],
         setup_.debug_level,
         setup_.usrname,
         setup_.onion_url,
         ip6,
         setup_.create_clog,
         setup_.runasroot,
         setup_.controller,
         setup_.ocat_dir,
         setup_.tun_dev,
         setup_.tunname,
         setup_.ipv4_enable,
         ip,
         nm,
         setup_.config_file,
         setup_.config_read,
         setup_.use_tap,
         hw,
         setup_.pid_file,
         setup_.logfn,
         logf,
         setup_.daemon,
         t / (3600 * 24), t / 3600 % 24, t / 60 % 60,
         (int) strlen(setup_.version), VERSION_STRING_LEN, setup_.version,
         setup_.sizeof_setup,
         setup_.term_req,
         setup_.net_type, setup_.net_type == NTYPE_TOR ? "NTYPE_TOR" : setup_.net_type == NTYPE_I2P ? "NTYPE_I2P" : "unknown"
         );

#ifdef CONNECT_ROOT_PEERS
   for (i = 0; i < ROOT_PEERS; i++)
      if (inet_ntop(AF_INET6, &setup_.root_peer[i], ip6, SBUF))
         fprintf(f, "root_peer[%d]           = %s\n", i, ip6);
#endif

   if (inet_ntops((struct sockaddr*) setup_.socks_dst, &sas))
   {
      c = sas.sstr_family == AF_INET6 ? "6" : "";
      fprintf(f,
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
         fprintf(f, "oc_listen[%d]           = %s:%d\n", i, sas.sstr_addr, ntohs(sas.sstr_port));
      else
         log_msg(LOG_WARNING, "could not convert struct sockaddr: \"%s\"", strerror(errno));
      fprintf(f, "oc_listen_fd[%d]        = %d\n", i, CNF(oc_listen_fd)[i]);
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

