/* Copyright 2008-2019 Bernhard R. Fischer, Daniel Haslinger.
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

/*! \file ocatthread.c
 *  contains thread management functions. Basically these are
 *  wrapper functions around create_pthread.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunk at>
 *  \date 2019/09/08
 */


#include "ocat.h"


// global thread id var and mutex for thread initializiation
static int thread_id_ = 0;
static pthread_mutex_t thread_mutex_ = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t thread_cond_ = PTHREAD_COND_INITIALIZER;
static OcatThread_t *octh_ = NULL;


void init_ocat_thread_struct(OcatThread_t *th)
{
   // init ocat thread structure
   th->handle = pthread_self();
   pthread_mutex_lock(&thread_mutex_);
   th->id = thread_id_++;
   th->next = octh_;
   octh_ = th;
   pthread_mutex_unlock(&thread_mutex_);
   log_debug("_init_ thread %d", th->id);
}


const OcatThread_t *init_ocat_thread(const char *name)
{
   OcatThread_t *th;

   // get memory for the ocat internal thread structure
   if (!(th = calloc(1, sizeof(OcatThread_t))))
   {
      log_msg(LOG_ERR, "could not get memory for thread struct: \"%s\"", strerror(errno));
      return NULL;
   }

   strlcpy(th->name, name, THREAD_NAME_LEN);
   init_ocat_thread_struct(th);

   return th;
}


void *thread_run(void *p)
{
   OcatThread_t **tl;
   void *r;
   sigset_t ss;
#ifdef DEBUG
   int ecnt, icnt;
   static int exit_cnt_ = 0;
#endif

   // block all signals for the thread
   sigfillset(&ss);
   pthread_sigmask(SIG_BLOCK, &ss, NULL);

   // init internal ocat thread structure
   init_ocat_thread_struct((OcatThread_t *) p);

   // call thread entry function
   log_debug("calling thread entry");
   r = ((OcatThread_t*)p)->entry(((OcatThread_t*)p)->parm);
   log_debug("thread function returned");

   // delete thread struct from list and free memory
   pthread_mutex_lock(&thread_mutex_);
   for (tl = &octh_; *tl; tl = &(*tl)->next)
      if ((*tl)->handle == ((OcatThread_t*)p)->handle)
         break;
   //free(p);
   if ((p = *tl))
   {
      *tl = (*tl)->next;
      free(p);
   }
#ifdef DEBUG
   ecnt = ++exit_cnt_;
   icnt = thread_id_;
#endif
   pthread_mutex_unlock(&thread_mutex_);

   log_debug("_exit_ thread, %d inits, %d exits", icnt, ecnt);
   return r;
}


int run_ocat_thread(const char *name, void *(*thfunc)(void*), void *parm)
{
   int rc;
   OcatThread_t *th;

   // we need a helper structure on startup.
   // this is because pthread_create pushes only one arg.
   // the helper struct is freed again from the thread
   // (within thread_run()).
   if (!(th = calloc(1, sizeof(OcatThread_t))))
   {
      rc = errno;
      log_msg(LOG_EMERG, "could not create thread %s: \"%s\"", name, strerror(errno));
      return rc;
   }

   strlcpy(th->name, name, THREAD_NAME_LEN);
   th->entry = thfunc;
   th->parm = parm;

   if ((rc = pthread_attr_init(&th->attr)))
   {
      log_msg(LOG_ERR, "could not init pthread attr: \"%s\"", strerror(rc));
      return rc;
   }

#ifdef DEBUG
   size_t ss;
   if ((rc - pthread_attr_getstacksize(&th->attr, &ss)))
      log_debug("could not get thread stack size attr: \"%s\"", strerror(rc));
   else
      log_debug("default thread stack size %dk, setting to %dk", ss / 1024, THREAD_STACK_SIZE / 1024);
#endif

   if ((rc - pthread_attr_setstacksize(&th->attr, THREAD_STACK_SIZE)))
   {
      log_msg(LOG_EMERG, "could not init thread stack size attr - system may be unstable: \"%s\"", strerror(rc));
      return rc;
   }

   log_debug("starting [%s]", name);
   if ((rc = pthread_create(&th->handle, &th->attr, thread_run, th)))
   {
      log_msg(LOG_EMERG, "could not start thread %s: \"%s\"", name, strerror(rc));
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


int set_thread_name(const char *n)
{
   int e = -1;
   OcatThread_t *th;
   pthread_t thread = pthread_self();

   pthread_mutex_lock(&thread_mutex_);
   for (th = octh_; th; th = th->next)
      if (th->handle == thread)
      {
         strlcpy(th->name, n, THREAD_NAME_LEN);
         e = 0;
         break;
      }
   pthread_mutex_unlock(&thread_mutex_);

   return e;
}


/*! This function waits for a thread identified by name to become ready,
 * meaning it set its ready flag with set_thread_ready(). If the thread is not
 * found in the thread list, the function blocks. It wakes up again if any
 * thread calls set_thread_ready() which reinitiates the reevaluation of the
 * thread list. A thread my not appear in the thread list because it was not
 * created, yet.
 * @param s Pointer to thread name.
 * @return The function always returns 1.
 */
int wait_thread_by_name_ready(const char *s)
{
   OcatThread_t *th;
   int e;

   log_debug("waiting for [%s] to become ready", s);
   pthread_mutex_lock(&thread_mutex_);
   for (e = 0; !e; )
   {
      // loop over all threads
      for (th = octh_; th; th = th->next)
      {
         // match thread name
         if (!strcmp(th->name, s))
         {
            // check if it is ready
            while (!th->ready)
               // and wait if not
               pthread_cond_wait(&thread_cond_, &thread_mutex_);
            // set ready flag and break loop
            e = 1;
            break;
         }
      }

      // check if ready flag still not set, meaning thread was not found by name
      if (!e)
      {
         pthread_cond_wait(&thread_cond_, &thread_mutex_);
      }
   }
   pthread_mutex_unlock(&thread_mutex_);
   log_debug("[%s] ready", s);

   return e;
}


int set_thread_ready(void)
{
   int e = -1;
   OcatThread_t *th;
   pthread_t thread = pthread_self();

   log_debug("set_thread_ready()");
   pthread_mutex_lock(&thread_mutex_);
   for (th = octh_; th; th = th->next)
      if (th->handle == thread)
      {
         th->ready = 1;
         pthread_cond_broadcast(&thread_cond_);
         e = 0;
         break;
      }
   pthread_mutex_unlock(&thread_mutex_);

   return e;
}


void print_threads(FILE *f)
{
   OcatThread_t *th;

   pthread_mutex_lock(&thread_mutex_);
   for (th = octh_; th; th = th->next)
   {
      fprintf(f, "[%s] "
            "handle = 0x%08lx, "
            "id = %d, "
            "entry = %p, "
            "parm = %p, "
            "detached = %d\n",
            th->name, (long) th->handle, th->id, th->entry, th->parm, th->detached);
   }
   pthread_mutex_unlock(&thread_mutex_);
}


int join_threads(void)
{
   OcatThread_t *th, thb;
   void *ret;
   int rc;

   for (;;)
   {
      pthread_mutex_lock(&thread_mutex_);
      for (th = octh_, rc = 0; th && th->detached; th = th->next, rc++);
      if (!th)
      {
         pthread_mutex_unlock(&thread_mutex_);
         break;
      }
      memcpy(&thb, th, sizeof(OcatThread_t));
      pthread_mutex_unlock(&thread_mutex_);

      log_debug("joing thread \"%s\" (%d)", thb.name, thb.id);
      if ((rc = pthread_join(thb.handle, &ret)))
         log_msg(LOG_ERR, "error joining thread: \"%s\"", strerror(rc));
      log_debug("thread successful joined and return %p", ret);
   }
   log_debug("no more joinable threads available, %d detached", rc);
   return rc;
}


void detach_thread(void)
{
   OcatThread_t *th;
   pthread_t thread = pthread_self();
   int rc = 0;

   pthread_mutex_lock(&thread_mutex_);
   for (th = octh_; th; th = th->next)
      if (th->handle == thread)
         break;
   if (th && !(rc = pthread_detach(thread)))
      th->detached = 1;
   pthread_mutex_unlock(&thread_mutex_);

   if (!th)
      log_msg(LOG_EMERG, "thread tries to detach but is not in list");
   else if (rc)
      log_msg(LOG_ERR, "could not detach thread: \"%s\"", strerror(rc));
   else
      log_debug("thread detached");
}


/*! Check for termination request.
 *  @return 1 if termination requested, otherwise 0.
 */
int term_req(void)
{
   int trq;

   lock_setup();
   trq = CNF(term_req);
   unlock_setup();

   return trq;
}


/*! Set termination request. */
void set_term_req(void)
{
   lock_setup();
   CNF(term_req) = 1;
   unlock_setup();
}

