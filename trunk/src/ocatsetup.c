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

struct OcatSetup setup_ =
{
   // fhd_keys
   {0, 0},
   // fhd_key_len
   sizeof(uint32_t),
   TOR_SOCKS_PORT, OCAT_LISTEN_PORT, OCAT_DEST_PORT, OCAT_CTRL_PORT, 
   //! default tunfd is stdin/stdout
   {0, 1},
   //! default debug level
   LOG_DEBUG,
   OCAT_UNAME, {0}, {{{0}}}, 0, 0, 1, OCAT_DIR, TUN_DEV,
   0, TOR_PREFIX4, TOR_PREFIX4_MASK,
   NULL, 1,
   0,                                      // use_tap
   {0x00, 0x00, 0x6c, 0x00, 0x00, 0x00},   // ocat_hwaddr (OnionCat MAC address)
   PID_FILE,
   NULL, NULL,                             // logfile
   0,                                      // daemon
   {
      {{{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43,
           0xed, 0xb1, 0x8, 0xe4, 0x35, 0x88, 0xe5, 0x46, 0x35, 0xca}}} // initial permanent peer "5wyqrzbvrdsumnok"
   }
};


void init_setup(void)
{
   setup_.logf = stderr;
}


#define _SB 100

void print_setup_struct(FILE *f)
{
   char ip[_SB], nm[_SB], ip6[_SB], logf[_SB], rp[ROOT_PEERS][_SB];
   int i;

   inet_ntop(AF_INET, &setup_.ocat_addr4, ip, _SB);
   inet_ntop(AF_INET, &setup_.ocat_addr4_mask, nm, _SB);
   inet_ntop(AF_INET6, &setup_.ocat_addr, ip6, _SB);
   for (i = 0; i < ROOT_PEERS; i++)
      inet_ntop(AF_INET6, &setup_.root_peer[i], rp[i], _SB);

   if (setup_.logf == stderr)
      strlcpy(logf, "stderr", sizeof(logf));
   else
      snprintf(logf, sizeof(logf), "%p", setup_.logf);

   fprintf(f,
         "fhd_key[IPV4(%d)]  = 0x%04x\n"
         "fhd_key[IPV6(%d)]  = 0x%04x\n"
         "fhd_key_len       = %d\n"
         "tor_socks_port    = %d\n"
         "ocat_listen_port  = %d\n"
         "ocat_dest_port    = %d\n"
         "ocat_ctrl_port    = %d\n"
         "tunfd[0]          = %d\n"
         "tunfd[1]          = %d\n"
         "debug_level       = %d\n"
         "usrname           = \"%s\"\n"
         "onion_url         = \"%s\"\n"
         "ocat_addr         = %s\n"
         "create_clog       = %d\n"
         "runasroot         = %d\n"
         "controller        = %d\n"
         "ocat_dir          = \"%s\"\n"
         "tun_dev           = \"%s\"\n"
         "ipv4_enable       = %d\n"
         "ocat_addr4        = %s\n"
         "ocat_addr4_mask   = %s\n"
         "config_file       = \"%s\"\n"
         "config_read       = %d\n"
         "use_tap           = %d\n"
         "ocat_hwaddr       = %s\n"
         "pid_file          = \"%s\"\n"
         "logfn             = \"%s\"\n"
         "logf              = %s\n"
         "daemon            = %d\n"
         "root_peer[0]      = %s\n",
 
         IPV4_KEY, ntohl(setup_.fhd_key[IPV4_KEY]), IPV6_KEY, ntohl(setup_.fhd_key[IPV6_KEY]),
         setup_.fhd_key_len,
         setup_.tor_socks_port,
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
         setup_.ipv4_enable,
         ip,
         nm,
         setup_.config_file,
         setup_.config_read,
         setup_.use_tap,
         ether_ntoa((struct ether_addr*) setup_.ocat_hwaddr),
         setup_.pid_file,
         setup_.logfn,
         logf,
         setup_.daemon,
         rp[0]
         );
}

