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


static struct sockaddr_in6 socks_dst6_;
static struct sockaddr_in6 oc_listen6_;
static struct sockaddr* oc_listen_a_[] = {(struct sockaddr*) &oc_listen6_, NULL};

struct OcatSetup setup_ =
{
   // fhd_keys
   {0, 0},
   // fhd_key_len
   sizeof(uint32_t),
   //TOR_SOCKS_PORT, 
   OCAT_LISTEN_PORT, 
   OCAT_DEST_PORT, OCAT_CTRL_PORT, 
   //! default tunfd is stdin/stdout
   {0, 1},
   //! default debug level
   LOG_DEBUG,
   OCAT_UNAME, {0}, {{{0}}}, 0, 0, 1, OCAT_DIR, TUN_DEV,
   {'\0'},                                // tunname
   0, TOR_PREFIX4, TOR_PREFIX4_MASK,
   NULL, 1,
   0,                                      // use_tap
   {0x00, 0x00, 0x6c, 0x00, 0x00, 0x00},   // ocat_hwaddr (OnionCat MAC address)
   PID_FILE,
   NULL, NULL,                             // logfile
   0,                                      // daemon
   {
      /*
      {{{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43,
           0xed, 0xb1, 0x08, 0xe4, 0x35, 0x88, 0xe5, 0x46, 0x35, 0xca}}}, // initial permanent peer "5wyqrzbvrdsumnok" (mail.root-servers.cat)
           */
      {{{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43,
           0xf6, 0x83, 0x64, 0xac, 0x73, 0xf9, 0x61, 0xac, 0x9a, 0x00}}}  // initial permanent peer "62bwjldt7fq2zgqa" (dot.cat)
   },
   0,
   "/dev/urandom",
   {(struct sockaddr_in*) &socks_dst6_},
   oc_listen_a_,
   //! rand_addr
   0,
   {0},
   sizeof(struct OcatSetup)
};


void init_setup(void)
{
   struct timeval tv;

   // seeding PRNG rand()
   if (gettimeofday(&tv, NULL) == -1)
      log_msg(LOG_WARNING, "could gettimeofday(): \"%s\"", strerror(errno));
   srand(tv.tv_sec ^ tv.tv_usec);

   setup_.logf = stderr;
   setup_.uptime = time(NULL);

   setup_.socks_dst->sin_family = AF_INET;
   setup_.socks_dst->sin_port = htons(TOR_SOCKS_PORT);
   setup_.socks_dst->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   setup_.socks_dst->sin_len = sizeof(socks_dst6_);
#endif

   /*
   ((struct sockaddr_in*) *setup_.oc_listen)->sin_family = AF_INET;
   setup_.oc_listen->sin_port = htons(OCAT_LISTEN_PORT);
   setup_.oc_listen->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef HAVE_SIN_LEN
   setup_.oc_listen->sin_len = sizeof(oc_listen6_);
#endif
*/

   snprintf(setup_.version, VERSION_STRING_LEN, "%s (c) %s -- compiled %s %s", PACKAGE_STRING, OCAT_AUTHOR, __DATE__, __TIME__);
}


#define SBUF 100

void print_setup_struct(FILE *f)
{
   char *c, ip[SBUF], nm[SBUF], ip6[SBUF], logf[SBUF], hw[SBUF], rp[SBUF];
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
         "ocat_listen_port       = %d\n"
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
         ,
         IPV4_KEY, ntohl(setup_.fhd_key[IPV4_KEY]), IPV6_KEY, ntohl(setup_.fhd_key[IPV6_KEY]),
         setup_.fhd_key_len,
         //setup_.tor_socks_port,
         setup_.ocat_listen_port,
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
         strlen(setup_.version), VERSION_STRING_LEN, setup_.version,
         setup_.sizeof_setup
         );

   for (i = 0; i < ROOT_PEERS; i++)
      if (inet_ntop(AF_INET6, &setup_.root_peer[i], rp, SBUF))
         fprintf(f, "root_peer[%d]           = %s\n", i, rp);

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
 
}

