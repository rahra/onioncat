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
#include <signal.h>

#include "ocat.h"


// global thread id var and mutex for thread initializiation
static int thread_id_ = 0;
pthread_mutex_t thread_mutex_ = PTHREAD_MUTEX_INITIALIZER;
OcatThread_t *octh_ = NULL;


const OcatThread_t *init_ocat_thread(const char *name)
{
   OcatThread_t *th;

   // get memory for the ocat internal thread structure
   if (!(th = malloc(sizeof(OcatThread_t))))
      return NULL;

   // init ocat thread structure
   pthread_mutex_lock(&thread_mutex_);
   th->id = thread_id_++;
   strncpy(th->name, name, THREAD_NAME_LEN);
   th->name[THREAD_NAME_LEN - 1] = '\0';
   th->handle = pthread_self();
   th->next = octh_;
   octh_ = th;
   pthread_mutex_unlock(&thread_mutex_);

   return th;
}



void *thread_run(void *p)
{
   OcatThread_t **tl;
   void *r;
   sigset_t ss;

   // block all signals for the thread
   sigfillset(&ss);
   pthread_sigmask(SIG_BLOCK, &ss, NULL);

   // init internal ocat thread structure
   (void) init_ocat_thread(((OcatThread_t *)p)->name);

   // call thread entry function
   log_msg(L_NOTICE, "running");
   r = ((OcatThread_t*)p)->entry(NULL);
   log_msg(L_NOTICE, "terminating");

   pthread_mutex_lock(&thread_mutex_);
   for (tl = &octh_; *tl; tl = &(*tl)->next)
      if ((*tl)->handle == ((OcatThread_t*)p)->handle)
         break;
   free(p);
   if ((p = *tl))
   {
      *tl = (*tl)->next;
      free(p);
   }
   pthread_mutex_unlock(&thread_mutex_);

   return NULL;
}


int run_ocat_thread(const char *name, void *(*thfunc)(void*))
{
   int rc;
   OcatThread_t *th;

   // we need a helper structure on startup.
   // this is because pthread_create pushes only one arg.
   // the helper struct is freed again from the thread
   // (within thread_run()).
   if (!(th = malloc(sizeof(OcatThread_t))))
   {
      rc = errno;
      log_msg(L_FATAL, "could not create thread %s: \"%s\"", name, strerror(errno));
      return rc;
   }

   strncpy(th->name, name, THREAD_NAME_LEN);
   th->entry = thfunc;

   log_msg(L_DEBUG, "starting [%s]", name);
   if ((rc = pthread_create(&th->handle, NULL, thread_run, th)))
   {
      log_msg(L_FATAL, "could not start thread %s: \"%s\"", name, strerror(rc));
      free(th);
   }

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

