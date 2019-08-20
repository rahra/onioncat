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


#include "ocat_netdesc.h"


const struct NetDesc netdesc_[2] =
{
   {
      TOR_PREFIX, TOR_PREFIX_LEN,
      TOR_PREFIX4, TOR_PREFIX4_MASK,
      TOR_ONION_NAME_SIZE,
      TOR_DOMAIN,
      TOR_OCAT_LISTEN_PORT,
      TOR_OCAT_CTRL_PORT,
      TOR_OCAT_DEST_PORT,
      TOR_SOCKS_PORT,
      TOR_OCAT_CONNECT_LOG,
      TOR_PID_FILE,
      "ocat.conf",
      0,
      TOR_HS_NAMELEN
   },
   {
      I2P_PREFIX, I2P_PREFIX_LEN,
      I2P_PREFIX4, I2P_PREFIX4_MASK,
      I2P_ONION_NAME_SIZE,
      I2P_DOMAIN,
      I2P_OCAT_LISTEN_PORT,
      I2P_OCAT_CTRL_PORT,
      I2P_OCAT_DEST_PORT,
      I2P_SOCKS_PORT,
      I2P_OCAT_CONNECT_LOG,
      I2P_PID_FILE,
      "gcat.conf",
      1,
      I2P_HS_NAMELEN
   },
};

