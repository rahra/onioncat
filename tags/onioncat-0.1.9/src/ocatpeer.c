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

/*! ocatpeer.c
 *  This file contains function on managing the peer list, i.e.
 *  adding, removing peers and thread locking mechanism.
 *
 *  @author Bernhard R. Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/02/03-01
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "ocat.h"


// array of active peers
static OcatPeer_t *peer_ = NULL;
// mutex for locking array of peers
static pthread_mutex_t peer_mutex_ = PTHREAD_MUTEX_INITIALIZER;


OcatPeer_t *get_first_peer(void)
{
   return peer_;
}


OcatPeer_t **get_first_peer_ptr(void)
{
   return &peer_;
}


int lock_peers(void)
{
   return pthread_mutex_lock(&peer_mutex_);
}


int unlock_peers(void)
{
   return pthread_mutex_unlock(&peer_mutex_);
}


int lock_peer(OcatPeer_t *peer)
{
   return pthread_mutex_lock(&peer->mutex);
}


int unlock_peer(OcatPeer_t *peer)
{
   return pthread_mutex_unlock(&peer->mutex);
}


OcatPeer_t *search_peer(const struct in6_addr *addr)
{
   OcatPeer_t *peer;

   for (peer = peer_; peer; peer = peer->next)
      if (!memcmp(addr, &peer->addr, sizeof(struct in6_addr)))
         return peer;
   return NULL;
}


OcatPeer_t *get_empty_peer(void)
{
   int rc;
   OcatPeer_t *peer;

   if (!(peer = calloc(1, sizeof(OcatPeer_t))))
   {
      log_msg(L_ERROR, "cannot get memory for new peer: \"%s\"", strerror(errno));
      return NULL;
   }

   //peer->fraghdr = setup.fhd_key;
   if ((rc = pthread_mutex_init(&peer->mutex, NULL)))
   {
      log_msg(L_FATAL, "cannot init new peer mutex: \"%s\"", strerror(rc));
      free(peer);
      return NULL;
   }

   peer->next = peer_;
   peer_ = peer;

   return peer;  
}


/** peer list must be locked with lock_peers() in advance!
 *  @param peer pointer to peer that shall be deleted.
 */
void delete_peer(OcatPeer_t *peer)
{
   int rc;
   OcatPeer_t **p;

   for (p = &peer_; *p; p = &(*p)->next)
      if (*p == peer)
      {
         // unlink peer from list
         lock_peer(peer);
         *p = peer->next;
         unlock_peer(peer);

         // effectively delete it
         if ((rc = pthread_mutex_destroy(&peer->mutex)))
            log_msg(L_FATAL, "cannot destroy mutex: \"%s\"", strerror(rc));
         free(peer);
         return;
      }
}

