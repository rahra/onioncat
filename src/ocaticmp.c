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
 *  Contains functions for internal echo request/responses
 *
 *  @author Bernhard Fischer <rahra _at_ cypherpunk at>
 *  @version 2008/10/10
 */

#ifdef MEASURE_RTT

#include "ocat.h"


#define ECHO_SIZE 400
#define E_ECHO_NOMEM -1
#define E_ECHO_DUP -2


typedef struct IcmpTree
{
   struct IcmpTree *next[2];
   uint32_t idseq;
   struct timeval tv;
} IcmpTree_t;


static IcmpTree_t *itree_ = NULL;


IcmpTree_t *get_icmp(IcmpTree_t *tree, uint32_t id)
{
   if (!tree)
      return NULL;

   if (tree->idseq == id)
      return tree;

   return get_icmp(tree->next[tree->idseq > id], id);
}


int reg_icmp(IcmpTree_t **tree, uint32_t id)
{
   if (!(*tree))
   {
      if (!(*tree = malloc(sizeof(IcmpTree_t))))
      {
         log_msg(LOG_ERR, "error allocating icmp tree: \"%s\"", strerror(errno));
         return E_ECHO_NOMEM;
      }
      (*tree)->next[0] = (*tree)->next[1] = NULL;
      (*tree)->idseq = 0;
   }

   if (!(*tree)->idseq)
   {
      (*tree)->idseq = id;
      if (gettimeofday(&(*tree)->tv, NULL) == -1)
         log_msg(LOG_ERR, "gettimeofday: \"%s\"", strerror(errno));
      return 0;
   }

   if (id == (*tree)->idseq)
   {
      log_debug("duplicate icmp id 0x%08x", id);
      return E_ECHO_DUP;
   }

   return reg_icmp(&(*tree)->next[(*tree)->idseq > id], id);
}


uint16_t ocat_rand(void)
{
   return rand();
}


uint64_t icmp_data(void)
{
   return 0x28af362ee6d0937eLL;
}


int ocat_echo_request(void)
{
   char buf[ECHO_SIZE];
   struct ip6_hdr *hdr = (struct ip6_hdr*) buf;
   struct icmp6_hdr *icmp = (struct icmp6_hdr*) (hdr + 1);
   uint16_t *ckb;

   memset(buf, ECHO_SIZE, 0);
   hdr->ip6_vfc = 0x60;
   hdr->ip6_nxt = IPPROTO_ICMPV6;
   hdr->ip6_plen = htons(ECHO_SIZE - sizeof(struct ip6_hdr));
   hdr->ip6_hlim = 255;
   icmp->icmp6_type = ICMP6_ECHO_REQUEST;

   for (;;)
   {
      icmp->icmp6_id = ocat_rand();
      icmp->icmp6_seq = ocat_rand();
      log_debug("registering icmp, id = %d, seq = %d", icmp->icmp6_id, icmp->icmp6_seq);
      if (!reg_icmp(&itree_, ((uint32_t) icmp->icmp6_id << 16) | icmp->icmp6_seq))
         break;
   }

   // calculate checksum
   ckb = malloc_ckbuf(hdr->ip6_src, hdr->ip6_dst, ntohs(hdr->ip6_plen), IPPROTO_ICMPV6, icmp);
   icmp->icmp6_cksum = checksum(ckb, ntohs(hdr->ip6_plen) + sizeof(struct ip6_psh));
   free_ckbuf(ckb);

   return 0;
}

#endif

