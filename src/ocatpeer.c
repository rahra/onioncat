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


#include "ocat.h"


// array of active peers
static OcatPeer_t *peer_ = NULL;
// mutex for locking array of peers
static pthread_mutex_t peer_mutex_ = PTHREAD_MUTEX_INITIALIZER;


/*! Return pointer to first peer. */
OcatPeer_t *get_first_peer(void)
{
   return peer_;
}


/*! Return double pointer to first peer. */
OcatPeer_t **get_first_peer_ptr(void)
{
   return &peer_;
}


/*! Lock complete peer list. */
int lock_peers(void)
{
   return pthread_mutex_lock(&peer_mutex_);
}


/*! Unlock peer list. */
int unlock_peers(void)
{
   return pthread_mutex_unlock(&peer_mutex_);
}


/*! Lock specific peer. Peer list MUST be locked before and
 *  maybe unlock directly after lock_peer(). */
int lock_peer(OcatPeer_t *peer)
{
   return pthread_mutex_lock(&peer->mutex);
}


/*! Unlock secific peer. Lock must NOT be reclaimed without
 *  calling lock_peers() before! */
int unlock_peer(OcatPeer_t *peer)
{
   return pthread_mutex_unlock(&peer->mutex);
}


/*! Search a specific peer by IPv6 address.
 *  Peer list MUST be locked before. */
OcatPeer_t *search_peer(const struct in6_addr *addr)
{
   OcatPeer_t *peer;

   for (peer = peer_; peer; peer = peer->next)
      //if (!memcmp(addr, &peer->addr, sizeof(struct in6_addr)))
      if (IN6_ARE_ADDR_EQUAL(addr, &peer->addr))
         return peer;
   return NULL;
}


/*! Create a new empty peer and add it to the peer list.
 *  Peer list MUST be locked befored. */
OcatPeer_t *get_empty_peer(void)
{
   int rc;
   OcatPeer_t *peer;

   if (!(peer = calloc(1, sizeof(OcatPeer_t))))
   {
      log_msg(LOG_ERR, "cannot get memory for new peer: \"%s\"", strerror(errno));
      return NULL;
   }

   peer->tunhdr = (uint32_t*) peer->_fragbuf;
   peer->fragbuf = &peer->_fragbuf[CNF(fhd_key_len)];
   if ((rc = pthread_mutex_init(&peer->mutex, NULL)))
   {
      log_msg(LOG_EMERG, "cannot init new peer mutex: \"%s\"", strerror(rc));
      free(peer);
      return NULL;
   }
   peer->rand = random();

   peer->next = peer_;
   peer_ = peer;

   return peer;  
}


/*! peer list MUST be locked with lock_peers() in advance!
 *  @param peer pointer to peer that shall be deleted.
 */
void delete_peer(OcatPeer_t *peer)
{
   int rc;
   OcatPeer_t **p;

   for (p = &peer_; *p; p = &(*p)->next)
      if (*p == peer)
      {
         log_debug("going to delete peer at %p", peer);
         // unlink peer from list
         lock_peer(peer);
         *p = peer->next;
         unlock_peer(peer);

         // effectively delete it
         if ((rc = pthread_mutex_destroy(&peer->mutex)))
            log_msg(LOG_EMERG, "cannot destroy mutex: \"%s\"", strerror(rc));
         free(peer);
         return;
      }
}

