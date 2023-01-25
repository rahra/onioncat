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

/*! @file
 *  File contains logging functions.
 *  @author Bernhard R. Fischer
 *  @version 2008/10/1
 */

#include "ocat.h"
#include "ocat_netdesc.h"

#define TIMESTRLEN 64
#define CBUFLEN 1024

#ifndef LOG_PRI
#define LOG_PRI(p) ((p) & LOG_PRIMASK)
#endif

static pthread_mutex_t log_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static const char *flty_[8] = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"};
//! FILE pointer to connect log
static int clog_ = 0;


/*! Open connect log.
 *  The connect log contains logging entries regarding
 *  incoming or outgoing connections.
 *  @param dir Name of directory which should contain the log file
 *  @return 0 if log was opened or -1 on failure.
 */
int open_connect_log(const char *dir)
{
   char buf[CBUFLEN];

   if (clog_)
      return 0;

   if (!dir)
   {
      log_debug("dir has NULL pointer");
      return -1;
   }

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
   strlcat(buf, NDESC(clog_file), CBUFLEN);

   log_debug("opening connect log \"%s\"", buf);
   if ((clog_ = open(buf, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) == -1)
   {
      log_msg(LOG_ERR, "could not open connect log \"%s\": \"%s\"", buf, strerror(errno));
      clog_ = 0;
      return -1;
   }
   log_msg(LOG_NOTICE | LOG_FCONN, "connect log started");
   return 0;
}


static const char *level_color(int level)
{
   switch (level)
   {
      case LOG_INFO:
      case LOG_NOTICE:
         return "\033[32m";
      case LOG_WARNING:
         return "\033[33m";
      case LOG_EMERG:
      case LOG_ALERT:
      case LOG_CRIT:
      case LOG_ERR:
         return "\033[31m";
      case -1:
      default:
         return "\033[m";
   }
}


/*! Log a message to a file.
 *  @param out Open FILE pointer
 *  @param lf Logging priority (equal to syslog)
 *  @param fmt Format string
 *  @param ap Variable parameter list
 */
void vlog_msgf(int out, int lf, const char *fmt, va_list ap)
{
   struct timeval tv;
   struct tm *tm;
   time_t t;
   char timestr[TIMESTRLEN] = "", timez[TIMESTRLEN] = "";
   const OcatThread_t *th = get_thread();
   OcatThread_t ths;
   int level = LOG_PRI(lf);
   char buf[SIZE_1K];

   if (CNF(debug_level) < level)
      return;

   //t = time(NULL);
   if (gettimeofday(&tv, NULL) == -1)
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, strerror(errno)), exit(1);
   t = tv.tv_sec;
   if ((tm = localtime(&t)))
   {
      (void) strftime(timestr, TIMESTRLEN, "%a, %d %b %Y %H:%M:%S", tm);
      (void) strftime(timez, TIMESTRLEN, "%z", tm);
   }

   // if thread struct not in list
   if (!th)
   {
      strlcpy(ths.name, "<NEW/DIE>", THREAD_NAME_LEN);
      ths.id = -1;
      th = &ths;
   }

   (void) pthread_mutex_lock(&log_mutex_);
   if (out)
   {
      if (lf & LOG_FFD)
         dprintf(out, "[%s%s%s] ", level_color(level), flty_[level], level_color(-1));
      else
         dprintf(out, "%s.%03d %s [%d:%-*s:%6s] ", timestr, (int) (tv.tv_usec / 1000), timez, th->id, THREAD_NAME_LEN - 1, th->name, flty_[level]);
      vdprintf(out, fmt, ap);
      dprintf(out, "\n");
   }
   else
   {
      // log to syslog if no output stream is available
      //vsyslog(level | LOG_DAEMON, fmt, ap);
      vsnprintf(buf, SIZE_1K, fmt, ap);
      syslog(level | LOG_DAEMON, "[%s] %s", th->name, buf);

   }
   (void) pthread_mutex_unlock(&log_mutex_);
}


/*! Log a message. This function automatically determines
 *  to which streams the message is logged.
 *  @param lf Log priority.
 *  @param fmt Format string.
 *  @param ... arguments
 */
void log_msg_fd(int fd, int lf, const char *fmt, ...)
{
   va_list ap;

   // standard logging
   va_start(ap, fmt);
   vlog_msgf(CNF(logfd), lf, fmt, ap);
   va_end(ap);

   // connect log
   if (clog_ && (lf & LOG_FCONN))
   {
      va_start(ap, fmt);
      vlog_msgf(clog_, lf, fmt, ap);
      va_end(ap);
   }

   // additional stderr
   if (lf & LOG_FERR)
   {
      va_start(ap, fmt);
      vdprintf(2, fmt, ap);
      va_end(ap);
      dprintf(2, "\n");
   }

   // ...and on some other fd
   if (fd)
   {
      va_start(ap, fmt);
      vlog_msgf(fd, lf | LOG_FFD, fmt, ap);
      va_end(ap);
   }
}

