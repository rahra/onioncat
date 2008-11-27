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

/*! ocatsetup.c
 *  This file contains the global settings structure.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "ocat.h"

struct OcatSetup setup = {
   // fhd_keys
   {0, 0},
   // fhd_key_len
   sizeof(uint32_t),
   TOR_SOCKS_PORT, OCAT_LISTEN_PORT, OCAT_DEST_PORT, OCAT_CTRL_PORT, 
   //! default tunfd is stdin/stdout
   {0, 1},
   4, OCAT_UNAME, {0}, {{{0}}}, 0, 0, 1, OCAT_DIR, TUN_DEV,
   0, TOR_PREFIX4, TOR_PREFIX4_MASK,
   NULL, 1,
   0,                                      // use_tap
   {0x00, 0x00, 0x6c, 0x00, 0x00, 0x00},   // ocat_hwaddr (OnionCat MAC address)
   PID_FILE,
   NULL, NULL,                             // logfile
   0                                       // daemon
};


void init_setup(void)
{
   setup.logf = stderr;
}


#define _SB 100

void print_setup_struct(FILE *f)
{
   char ip[_SB], nm[_SB], ip6[_SB], hw[_SB], logf[_SB];

   inet_ntop(AF_INET, &setup.ocat_addr4, ip, _SB);
   inet_ntop(AF_INET, &setup.ocat_addr4_mask, nm, _SB);
   inet_ntop(AF_INET6, &setup.ocat_addr, ip6, _SB);
   mac_hw2str(setup.ocat_hwaddr, hw);

   if (setup.logf == stderr)
      strcpy(logf, "stderr");
   else
      sprintf(logf, "%p", setup.logf);

   fprintf(f,
         "fhd_key[]        = [IPV4(%d) => 0x%04x, IPV6(%d) => 0x%04x]\n"
         "fhd_key_len      = %d\n"
         "tor_socks_port   = %d\n"
         "ocat_listen_port = %d\n"
         "ocat_dest_port   = %d\n"
         "ocat_ctrl_port   = %d\n"
         "tunfd[]          = [(0) => %d, (1) => %d]\n"
         "debug_level      = %d\n"
         "usrname          = \"%s\"\n"
         "onion_url        = \"%s\"\n"
         "ocat_addr        = %s\n"
         "create_clog      = %d\n"
         "runasroot        = %d\n"
         "controller       = %d\n"
         "ocat_dir         = \"%s\"\n"
         "tun_dev          = \"%s\"\n"
         "ipv4_enable      = %d\n"
         "ocat_addr4       = %s\n"
         "ocat_addr4_mask  = %s\n"
         "config_file      = \"%s\"\n"
         "config_read      = %d\n"
         "use_tap          = %d\n"
         "ocat_hwaddr      = %s\n"
         "pid_file         = \"%s\"\n"
         "logfn            = \"%s\"\n"
         "logf             = %s\n"
         "daemon           = %d\n",

         IPV4_KEY, ntohl(setup.fhd_key[IPV4_KEY]), IPV6_KEY, ntohl(setup.fhd_key[IPV6_KEY]),
         setup.fhd_key_len,
         setup.tor_socks_port,
         setup.ocat_listen_port,
         setup.ocat_dest_port,
         setup.ocat_ctrl_port,
         setup.tunfd[0], setup.tunfd[1],
         setup.debug_level,
         setup.usrname,
         setup.onion_url,
         ip6,
         setup.create_clog,
         setup.runasroot,
         setup.controller,
         setup.ocat_dir,
         setup.tun_dev,
         setup.ipv4_enable,
         ip,
         nm,
         setup.config_file,
         setup.config_read,
         setup.use_tap,
         hw,
         setup.pid_file,
         setup.logfn,
         logf,
         setup.daemon
         );
}

