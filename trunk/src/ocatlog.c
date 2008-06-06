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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include "ocat.h"


int debug_level_ = 4;
static pthread_mutex_t log_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static const char *flty_[] = {"info", "notice", "error", "fatal", "debug"};


void log_msg(int lf, const char *fmt, ...)
{
   struct tm *tm;
   time_t t;
   FILE *out = stderr;
   char timestr[32] = "";
   va_list ap;
   const OcatThread_t *th = get_thread();

   if (debug_level_ < lf || lf < 0)
      return;

   t = time(NULL);
   tm = localtime(&t);
   if (tm)
      strftime(timestr, 32, "%c", tm);

   pthread_mutex_lock(&log_mutex_);
   fprintf(out, "%s [%d:%-*s:%6s] ", timestr, th->id, THREAD_NAME_LEN - 1, th->name, flty_[lf]);

   va_start(ap, fmt);
   vfprintf(out, fmt, ap);
   va_end(ap);

   fprintf(out, "\n");
   pthread_mutex_unlock(&log_mutex_);
}

