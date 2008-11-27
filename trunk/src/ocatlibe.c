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

/*! ocatlibe.c
 *  Contains some helper functions.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "ocat.h"


void oe_close(int fd)
{
   int r;

   while (close(fd) == -1)
   {
      r = errno;
      log_msg(L_ERROR, "failed to close %d: \"%s\"", fd, strerror(r));
      if (r == EINTR)
      {
         log_debug("re-closing %d", fd);
         continue;
      }
      break;
   }
}


int oe_remtr(char *s)
{
   if (!s[0])
      return 0;
   if (s[0] && (s[strlen(s) - 1] == '\n'))
      s[strlen(s) - 1] = '\0';
   if (s[0] && (s[strlen(s) - 1] == '\r'))
      s[strlen(s) - 1] = '\0';
   return strlen(s);
}

