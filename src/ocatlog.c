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
#include <sys/stat.h>

#include "ocat.h"

#define TIMESTRLEN 64
#define CBUFLEN 1024

static pthread_mutex_t log_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static const char *flty_[8] = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"};
//! FILE pointer to connect log
static FILE *clog_ = NULL;


int open_connect_log(const char *dir)
{
   char buf[CBUFLEN];

   if (clog_)
      return 0;

   strlcpy(buf, dir, CBUFLEN);
   strlcat(buf, "/", CBUFLEN);
   strlcat(buf, CNF(ocat_dir), CBUFLEN);

   log_debug("creating ocat log dir \"%s\"", buf);
   if (mkdir(buf, S_IRWXU | S_IRGRP | S_IXGRP) && (errno != EEXIST))
   {
      log_msg(LOG_ERR, "could not create ocat directory \"%s\": \"%s\"", buf, strerror(errno));
      return -1;
   }

   strlcat(buf, "/", CBUFLEN);
   strlcat(buf, OCAT_CONNECT_LOG, CBUFLEN);

   log_debug("opening connect log \"%s\"", buf);
   if (!(clog_ = fopen(buf, "a")))
   {
      log_msg(LOG_ERR, "could not open connect log \"%s\": \"%s\"", buf, strerror(errno));
      return -1;
   }
   log_msg(LOG_NOTICE | LOG_FCONN, "connect log started");
   return 0;
}


void vlog_msgf(FILE *out, int lf, const char *fmt, va_list ap)
{
   struct tm *tm;
   time_t t;
   char timestr[TIMESTRLEN] = "";
   const OcatThread_t *th = get_thread();
   int level = LOG_PRI(lf);

   if (CNF(debug_level) < level)
      return;

   t = time(NULL);
   if ((tm = localtime(&t)))
      strftime(timestr, TIMESTRLEN, "%a, %d %b %Y %H:%M:%S %z", tm);

   (void) pthread_mutex_lock(&log_mutex_);
   fprintf(out, "%s [%d:%-*s:%6s] ", timestr, th->id, THREAD_NAME_LEN - 1, th->name, flty_[level]);
   vfprintf(out, fmt, ap);
   fprintf(out, "\n");
   (void) pthread_mutex_unlock(&log_mutex_);
}


void log_msg(int lf, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vlog_msgf(CNF(logf), lf, fmt, ap);
   va_end(ap);
   if (clog_ && (lf & LOG_FCONN))
   {
      va_start(ap, fmt);
      vlog_msgf(clog_, lf, fmt, ap);
      va_end(ap);
      (void) fflush(clog_);
   }
}

