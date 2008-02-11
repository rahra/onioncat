/*! ocatroute.c
 *  Contains functions for managing both kind of TCP peers.
 *  Those are active SOCKS4A and passive TCP-LISTEN.
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "ocat.h"


// global thread id var and mutex for thread initializiation
static int thread_id_ = 0;
pthread_mutex_t thread_mutex_ = PTHREAD_MUTEX_INITIALIZER;
OcatThread_t *octh_ = NULL;

/*
void init_threads(void)
{
   memset(octh_, 0, sizeof(OcatThread_t) * MAX_THREADS);
}
*/


const OcatThread_t *init_ocat_thread(const char *name)
{
   OcatThread_t *th;

   if (!(th = malloc(sizeof(OcatThread_t))))
      return NULL;

   pthread_mutex_lock(&thread_mutex_);
   th->id = thread_id_++;
   strncpy(th->name, name, THREAD_NAME_LEN);
   th->name[THREAD_NAME_LEN - 1] = '\0';
   th->handle = pthread_self();
   th->next = octh_;
   octh_ = th;
   pthread_mutex_unlock(&thread_mutex_);

   log_msg(L_NOTICE, "running");
   return th;
}



void *thread_run(void *p)
{
   (void) init_ocat_thread(p);
   return NULL;
}


int run_ocat_thread(const char *name, void *(*thfunc)(void*))
{
   int rc;
   pthread_t th;

   log_msg(L_DEBUG, "starting [%s]", name);
   if ((rc = pthread_create(&th, NULL, thfunc, (void*) name)))
      log_msg(L_FATAL, "could not start thread %s: \"%s\"", name, strerror(rc));

   return rc;
}


const OcatThread_t *get_thread(void)
{
   OcatThread_t *th;
   pthread_t thread = pthread_self();

   pthread_mutex_lock(&thread_mutex_);
   for (th = octh_; th; th = th->next)
      if (th->handle == thread)
         break;
   pthread_mutex_unlock(&thread_mutex_);

   return th;
}

