/* Copyright 2008-2025 Bernhard R. Fischer.
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

/*! \file ocatcompat.c
 *
 * This file contains function implementations of some library functions if
 * they are missing on the target system.
 *
 * \date 2025/10/04
 * \author Bernhard R. Fischer, <bf@abenteuerland.at>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#ifndef HAVE_STRLCAT
#include "strlcat.c"
#endif
#ifndef HAVE_STRLCPY
#include "strlcpy.c"
#endif

#ifndef HAVE_VDPRINTF
int vdprintf(int fd, const char *fmt, va_list ap)
{
   int len;
   char buf[2048];

   len = vsnprintf(buf, sizeof(buf), fmt, ap);
   // safety check for return value of vsnprintf()
   if (len > (int) sizeof(buf))
      len = sizeof(buf);

   return write(fd, buf, len);
}
#endif

#ifndef HAVE_DPRINTF
int dprintf(int fd, const char *fmt, ...)
{
   va_list ap;
   int len;

   va_start(ap, fmt);
   len = vdprintf(fd, fmt, ap);
   va_end(ap);

   return len;
}
#endif
