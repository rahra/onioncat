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

#include "ocat.h"

struct OcatSetup setup = {{0, 0}, TOR_SOCKS_PORT, OCAT_LISTEN_PORT, OCAT_DEST_PORT, OCAT_CTRL_PORT, 0, {0, 1}, 4, OCAT_UNAME, {0}, {{{0}}}, 0, 0, 0, 0, 1, OCAT_DIR, TUN_DEV,
   0, TOR_PREFIX4, TOR_PREFIX4_MASK,
   NULL, 1
};

