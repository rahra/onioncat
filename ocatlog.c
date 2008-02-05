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
   unsigned tid;
   struct tm *tm;
   time_t t;
   FILE *out = stderr;
   char timestr[32] = "";
   va_list ap;

   if (debug_level_ < lf || lf < 0)
      return;

   t = time(NULL);
   tm = localtime(&t);
   if (tm)
      strftime(timestr, 32, "%c", tm);
   tid = (unsigned) pthread_self();

   /*
   fprintf(out, "%s ", timestr);
   switch (lf)
   {
      case L_DEBUG:
         fprintf(stderr, "debug : ");
         break;

      case L_NOTICE:
         fprintf(stderr, "notice: ");
         break;

      case L_ERROR:
         fprintf(stderr, "error : ");
         break;

      case L_FATAL:
         fprintf(stderr, "FATAL : ");
         break;

      default:
         return;
   }
   */

   pthread_mutex_lock(&log_mutex_);
   fprintf(out, "%s [%08x] %6s ", timestr, tid, flty_[lf]);

   va_start(ap, fmt);
   vfprintf(out, fmt, ap);
   va_end(ap);

   fprintf(out, "\n");
   pthread_mutex_unlock(&log_mutex_);
}

