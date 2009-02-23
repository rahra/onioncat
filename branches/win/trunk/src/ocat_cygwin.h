/* Copyright 2008-2009 Bernhard R. Fischer.
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

/** This file contains missing headers for the IPv6 system part of
 *  OnionCat.
 *  There are several definitions at the beginning.
 *  Behind I copied the originial include files
 *  - netinet/ip6.h
 *  - netinet/icmp6.h
 *  from Linux and
 *  - net/ethernet.h
 *  from FreeBSD.
 *  The files are unchanged and the copyrights are included in front
 *  as it is in the original files.
 */

#ifndef OCAT_CYGWIN_H
#define OCAT_CYGWIN_H

#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
// this seems to be missing in Cygwin/w32api 1.5.25-15 IPv6 extension 0.22 (2008/07/05)
#ifndef IPV6_ADDR_MC_SCOPE
#define IPV6_ADDR_MC_SCOPE(a) ((a)->s6_addr[1] & 0x0f)
#endif

// this is necessary for the FreeBSD-style "packed" attribute.
#define __packed __attribute__((packed))

#endif


/* Copyright (C) 1991-1997, 2001, 2003, 2006 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _NETINET_IP6_H
#define _NETINET_IP6_H 1

#include <inttypes.h>
#include <netinet/in.h>

struct ip6_hdr
  {
    union
      {
	struct ip6_hdrctl
	  {
	    uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
					20 bits flow-ID */
	    uint16_t ip6_un1_plen;   /* payload length */
	    uint8_t  ip6_un1_nxt;    /* next header */
	    uint8_t  ip6_un1_hlim;   /* hop limit */
	  } ip6_un1;
	uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
  };

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

/* Generic extension header.  */
struct ip6_ext
  {
    uint8_t  ip6e_nxt;		/* next header.  */
    uint8_t  ip6e_len;		/* length in units of 8 octets.  */
  };

/* Hop-by-Hop options header.  */
struct ip6_hbh
  {
    uint8_t  ip6h_nxt;		/* next header.  */
    uint8_t  ip6h_len;		/* length in units of 8 octets.  */
    /* followed by options */
  };

/* Destination options header */
struct ip6_dest
  {
    uint8_t  ip6d_nxt;		/* next header */
    uint8_t  ip6d_len;		/* length in units of 8 octets */
    /* followed by options */
  };

/* Routing header */
struct ip6_rthdr
  {
    uint8_t  ip6r_nxt;		/* next header */
    uint8_t  ip6r_len;		/* length in units of 8 octets */
    uint8_t  ip6r_type;		/* routing type */
    uint8_t  ip6r_segleft;	/* segments left */
    /* followed by routing type specific data */
  };

/* Type 0 Routing header */
struct ip6_rthdr0
  {
    uint8_t  ip6r0_nxt;		/* next header */
    uint8_t  ip6r0_len;		/* length in units of 8 octets */
    uint8_t  ip6r0_type;	/* always zero */
    uint8_t  ip6r0_segleft;	/* segments left */
    uint8_t  ip6r0_reserved;	/* reserved field */
    uint8_t  ip6r0_slmap[3];	/* strict/loose bit map */
    /* followed by up to 127 struct in6_addr */
    struct in6_addr ip6r0_addr[0];
  };

/* Fragment header */
struct ip6_frag
  {
    uint8_t   ip6f_nxt;		/* next header */
    uint8_t   ip6f_reserved;	/* reserved field */
    uint16_t  ip6f_offlg;	/* offset, reserved, and flag */
    uint32_t  ip6f_ident;	/* identification */
  };

#if BYTE_ORDER == BIG_ENDIAN
# define IP6F_OFF_MASK       0xfff8  /* mask out offset from _offlg */
# define IP6F_RESERVED_MASK  0x0006  /* reserved bits in ip6f_offlg */
# define IP6F_MORE_FRAG      0x0001  /* more-fragments flag */
#else   /* BYTE_ORDER == LITTLE_ENDIAN */
# define IP6F_OFF_MASK       0xf8ff  /* mask out offset from _offlg */
# define IP6F_RESERVED_MASK  0x0600  /* reserved bits in ip6f_offlg */
# define IP6F_MORE_FRAG      0x0100  /* more-fragments flag */
#endif

/* IPv6 options */
struct ip6_opt
  {
    uint8_t  ip6o_type;
    uint8_t  ip6o_len;
  };

/* The high-order 3 bits of the option type define the behavior
 * when processing an unknown option and whether or not the option
 * content changes in flight.
 */
#define IP6OPT_TYPE(o)		((o) & 0xc0)
#define IP6OPT_TYPE_SKIP	0x00
#define IP6OPT_TYPE_DISCARD	0x40
#define IP6OPT_TYPE_FORCEICMP	0x80
#define IP6OPT_TYPE_ICMP	0xc0
#define IP6OPT_TYPE_MUTABLE	0x20

/* Special option types for padding.  */
#define IP6OPT_PAD1	0
#define IP6OPT_PADN	1

#define IP6OPT_JUMBO		0xc2
#define IP6OPT_NSAP_ADDR	0xc3
#define IP6OPT_TUNNEL_LIMIT	0x04
#define IP6OPT_ROUTER_ALERT	0x05

/* Jumbo Payload Option */
struct ip6_opt_jumbo
  {
    uint8_t  ip6oj_type;
    uint8_t  ip6oj_len;
    uint8_t  ip6oj_jumbo_len[4];
  };
#define IP6OPT_JUMBO_LEN	6

/* NSAP Address Option */
struct ip6_opt_nsap
  {
    uint8_t  ip6on_type;
    uint8_t  ip6on_len;
    uint8_t  ip6on_src_nsap_len;
    uint8_t  ip6on_dst_nsap_len;
      /* followed by source NSAP */
      /* followed by destination NSAP */
  };

/* Tunnel Limit Option */
struct ip6_opt_tunnel
  {
    uint8_t  ip6ot_type;
    uint8_t  ip6ot_len;
    uint8_t  ip6ot_encap_limit;
  };

/* Router Alert Option */
struct ip6_opt_router
  {
    uint8_t  ip6or_type;
    uint8_t  ip6or_len;
    uint8_t  ip6or_value[2];
  };

/* Router alert values (in network byte order) */
#if BYTE_ORDER == BIG_ENDIAN
# define IP6_ALERT_MLD	0x0000
# define IP6_ALERT_RSVP	0x0001
# define IP6_ALERT_AN	0x0002
#else /* BYTE_ORDER == LITTLE_ENDING */
# define IP6_ALERT_MLD	0x0000
# define IP6_ALERT_RSVP	0x0100
# define IP6_ALERT_AN	0x0200
#endif

#endif /* netinet/ip6.h */



/* Copyright (C) 1991-1997,2000,2006 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _NETINET_ICMP6_H
#define _NETINET_ICMP6_H 1

#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#define ICMP6_FILTER 1

#define ICMP6_FILTER_BLOCK		1
#define ICMP6_FILTER_PASS		2
#define ICMP6_FILTER_BLOCKOTHERS	3
#define ICMP6_FILTER_PASSONLY		4

struct icmp6_filter
  {
    uint32_t icmp6_filt[8];
  };

struct icmp6_hdr
  {
    uint8_t     icmp6_type;   /* type field */
    uint8_t     icmp6_code;   /* code field */
    uint16_t    icmp6_cksum;  /* checksum field */
    union
      {
	uint32_t  icmp6_un_data32[1]; /* type-specific field */
	uint16_t  icmp6_un_data16[2]; /* type-specific field */
	uint8_t   icmp6_un_data8[4];  /* type-specific field */
      } icmp6_dataun;
  };

#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0]  /* parameter prob */
#define icmp6_mtu       icmp6_data32[0]  /* packet too big */
#define icmp6_id        icmp6_data16[0]  /* echo request/reply */
#define icmp6_seq       icmp6_data16[1]  /* echo request/reply */
#define icmp6_maxdelay  icmp6_data16[0]  /* mcast group membership */

#define ICMP6_DST_UNREACH             1
#define ICMP6_PACKET_TOO_BIG          2
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_PARAM_PROB              4

#define ICMP6_INFOMSG_MASK  0x80    /* all informational messages */

#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129
#define MLD_LISTENER_QUERY          130
#define MLD_LISTENER_REPORT         131
#define MLD_LISTENER_REDUCTION      132

#define ICMP6_DST_UNREACH_NOROUTE     0 /* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN       1 /* communication with destination */
                                        /* administratively prohibited */
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2 /* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR        3 /* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT      4 /* bad port */

#define ICMP6_TIME_EXCEED_TRANSIT     0 /* Hop Limit == 0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY  1 /* Reassembly time out */

#define ICMP6_PARAMPROB_HEADER        0 /* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER    1 /* unrecognized Next Header */
#define ICMP6_PARAMPROB_OPTION        2 /* unrecognized IPv6 option */

#define ICMP6_FILTER_WILLPASS(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) == 0)

#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) != 0)

#define ICMP6_FILTER_SETPASS(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) &= ~(1 << ((type) & 31))))

#define ICMP6_FILTER_SETBLOCK(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) |=  (1 << ((type) & 31))))

#define ICMP6_FILTER_SETPASSALL(filterp) \
	memset (filterp, 0, sizeof (struct icmp6_filter));

#define ICMP6_FILTER_SETBLOCKALL(filterp) \
	memset (filterp, 0xFF, sizeof (struct icmp6_filter));

#define ND_ROUTER_SOLICIT           133
#define ND_ROUTER_ADVERT            134
#define ND_NEIGHBOR_SOLICIT         135
#define ND_NEIGHBOR_ADVERT          136
#define ND_REDIRECT                 137

struct nd_router_solicit      /* router solicitation */
  {
    struct icmp6_hdr  nd_rs_hdr;
    /* could be followed by options */
  };

#define nd_rs_type               nd_rs_hdr.icmp6_type
#define nd_rs_code               nd_rs_hdr.icmp6_code
#define nd_rs_cksum              nd_rs_hdr.icmp6_cksum
#define nd_rs_reserved           nd_rs_hdr.icmp6_data32[0]

struct nd_router_advert       /* router advertisement */
  {
    struct icmp6_hdr  nd_ra_hdr;
    uint32_t   nd_ra_reachable;   /* reachable time */
    uint32_t   nd_ra_retransmit;  /* retransmit timer */
    /* could be followed by options */
  };

#define nd_ra_type               nd_ra_hdr.icmp6_type
#define nd_ra_code               nd_ra_hdr.icmp6_code
#define nd_ra_cksum              nd_ra_hdr.icmp6_cksum
#define nd_ra_curhoplimit        nd_ra_hdr.icmp6_data8[0]
#define nd_ra_flags_reserved     nd_ra_hdr.icmp6_data8[1]
#define ND_RA_FLAG_MANAGED       0x80
#define ND_RA_FLAG_OTHER         0x40
#define ND_RA_FLAG_HOME_AGENT    0x20
#define nd_ra_router_lifetime    nd_ra_hdr.icmp6_data16[1]

struct nd_neighbor_solicit    /* neighbor solicitation */
  {
    struct icmp6_hdr  nd_ns_hdr;
    struct in6_addr   nd_ns_target; /* target address */
    /* could be followed by options */
  };

#define nd_ns_type               nd_ns_hdr.icmp6_type
#define nd_ns_code               nd_ns_hdr.icmp6_code
#define nd_ns_cksum              nd_ns_hdr.icmp6_cksum
#define nd_ns_reserved           nd_ns_hdr.icmp6_data32[0]

struct nd_neighbor_advert     /* neighbor advertisement */
  {
    struct icmp6_hdr  nd_na_hdr;
    struct in6_addr   nd_na_target; /* target address */
    /* could be followed by options */
  };

#define nd_na_type               nd_na_hdr.icmp6_type
#define nd_na_code               nd_na_hdr.icmp6_code
#define nd_na_cksum              nd_na_hdr.icmp6_cksum
#define nd_na_flags_reserved     nd_na_hdr.icmp6_data32[0]
#if     BYTE_ORDER == BIG_ENDIAN
#define ND_NA_FLAG_ROUTER        0x80000000
#define ND_NA_FLAG_SOLICITED     0x40000000
#define ND_NA_FLAG_OVERRIDE      0x20000000
#else   /* BYTE_ORDER == LITTLE_ENDIAN */
#define ND_NA_FLAG_ROUTER        0x00000080
#define ND_NA_FLAG_SOLICITED     0x00000040
#define ND_NA_FLAG_OVERRIDE      0x00000020
#endif

struct nd_redirect            /* redirect */
  {
    struct icmp6_hdr  nd_rd_hdr;
    struct in6_addr   nd_rd_target; /* target address */
    struct in6_addr   nd_rd_dst;    /* destination address */
    /* could be followed by options */
  };

#define nd_rd_type               nd_rd_hdr.icmp6_type
#define nd_rd_code               nd_rd_hdr.icmp6_code
#define nd_rd_cksum              nd_rd_hdr.icmp6_cksum
#define nd_rd_reserved           nd_rd_hdr.icmp6_data32[0]

struct nd_opt_hdr             /* Neighbor discovery option header */
  {
    uint8_t  nd_opt_type;
    uint8_t  nd_opt_len;        /* in units of 8 octets */
    /* followed by option specific data */
  };

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			5
#define ND_OPT_RTR_ADV_INTERVAL		7
#define ND_OPT_HOME_AGENT_INFO		8

struct nd_opt_prefix_info     /* prefix information */
  {
    uint8_t   nd_opt_pi_type;
    uint8_t   nd_opt_pi_len;
    uint8_t   nd_opt_pi_prefix_len;
    uint8_t   nd_opt_pi_flags_reserved;
    uint32_t  nd_opt_pi_valid_time;
    uint32_t  nd_opt_pi_preferred_time;
    uint32_t  nd_opt_pi_reserved2;
    struct in6_addr  nd_opt_pi_prefix;
  };

#define ND_OPT_PI_FLAG_ONLINK	0x80
#define ND_OPT_PI_FLAG_AUTO	0x40
#define ND_OPT_PI_FLAG_RADDR	0x20

struct nd_opt_rd_hdr          /* redirected header */
  {
    uint8_t   nd_opt_rh_type;
    uint8_t   nd_opt_rh_len;
    uint16_t  nd_opt_rh_reserved1;
    uint32_t  nd_opt_rh_reserved2;
    /* followed by IP header and data */
  };

struct nd_opt_mtu             /* MTU option */
  {
    uint8_t   nd_opt_mtu_type;
    uint8_t   nd_opt_mtu_len;
    uint16_t  nd_opt_mtu_reserved;
    uint32_t  nd_opt_mtu_mtu;
  };

struct mld_hdr
  {
    struct icmp6_hdr    mld_icmp6_hdr;
    struct in6_addr     mld_addr; /* multicast address */
  };

#define mld_type        mld_icmp6_hdr.icmp6_type
#define mld_code        mld_icmp6_hdr.icmp6_code
#define mld_cksum       mld_icmp6_hdr.icmp6_cksum
#define mld_maxdelay    mld_icmp6_hdr.icmp6_data16[0]
#define mld_reserved    mld_icmp6_hdr.icmp6_data16[1]

#define ICMP6_ROUTER_RENUMBERING    138

struct icmp6_router_renum    /* router renumbering header */
  {
    struct icmp6_hdr    rr_hdr;
    uint8_t             rr_segnum;
    uint8_t             rr_flags;
    uint16_t            rr_maxdelay;
    uint32_t            rr_reserved;
  };

#define rr_type		rr_hdr.icmp6_type
#define rr_code         rr_hdr.icmp6_code
#define rr_cksum        rr_hdr.icmp6_cksum
#define rr_seqnum       rr_hdr.icmp6_data32[0]

/* Router renumbering flags */
#define ICMP6_RR_FLAGS_TEST             0x80
#define ICMP6_RR_FLAGS_REQRESULT        0x40
#define ICMP6_RR_FLAGS_FORCEAPPLY       0x20
#define ICMP6_RR_FLAGS_SPECSITE         0x10
#define ICMP6_RR_FLAGS_PREVDONE         0x08

struct rr_pco_match    /* match prefix part */
  {
    uint8_t             rpm_code;
    uint8_t             rpm_len;
    uint8_t             rpm_ordinal;
    uint8_t             rpm_matchlen;
    uint8_t             rpm_minlen;
    uint8_t             rpm_maxlen;
    uint16_t            rpm_reserved;
    struct in6_addr     rpm_prefix;
  };

/* PCO code values */
#define RPM_PCO_ADD             1
#define RPM_PCO_CHANGE          2
#define RPM_PCO_SETGLOBAL       3

struct rr_pco_use      /* use prefix part */
  {
    uint8_t             rpu_uselen;
    uint8_t             rpu_keeplen;
    uint8_t             rpu_ramask;
    uint8_t             rpu_raflags;
    uint32_t            rpu_vltime;
    uint32_t            rpu_pltime;
    uint32_t            rpu_flags;
    struct in6_addr     rpu_prefix;
  };

#define ICMP6_RR_PCOUSE_RAFLAGS_ONLINK  0x20
#define ICMP6_RR_PCOUSE_RAFLAGS_AUTO    0x10

#if BYTE_ORDER == BIG_ENDIAN
# define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME 0x80000000
# define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME 0x40000000
#elif BYTE_ORDER == LITTLE_ENDIAN
# define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME 0x80
# define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME 0x40
#endif

struct rr_result       /* router renumbering result message */
  {
    uint16_t            rrr_flags;
    uint8_t             rrr_ordinal;
    uint8_t             rrr_matchedlen;
    uint32_t            rrr_ifid;
    struct in6_addr     rrr_prefix;
  };

#if BYTE_ORDER == BIG_ENDIAN
# define ICMP6_RR_RESULT_FLAGS_OOB       0x0002
# define ICMP6_RR_RESULT_FLAGS_FORBIDDEN 0x0001
#elif BYTE_ORDER == LITTLE_ENDIAN
# define ICMP6_RR_RESULT_FLAGS_OOB       0x0200
# define ICMP6_RR_RESULT_FLAGS_FORBIDDEN 0x0100
#endif

/* Mobile IPv6 extension: Advertisement Interval.  */
struct nd_opt_adv_interval
  {
    uint8_t   nd_opt_adv_interval_type;
    uint8_t   nd_opt_adv_interval_len;
    uint16_t  nd_opt_adv_interval_reserved;
    uint32_t  nd_opt_adv_interval_ival;
  };

/* Mobile IPv6 extension: Home Agent Info.  */
struct nd_opt_home_agent_info
  {
    uint8_t   nd_opt_home_agent_info_type;
    uint8_t   nd_opt_home_agent_info_len;
    uint16_t  nd_opt_home_agent_info_reserved;
    int16_t   nd_opt_home_agent_info_preference;
    uint16_t  nd_opt_home_agent_info_lifetime;
  };

#endif /* netinet/icmpv6.h */



/* Copyright (C) 1997, 1999, 2001, 2008 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/* Based on the FreeBSD version of this file. Curiously, that file
   lacks a copyright in the header. */

#ifndef __NET_ETHERNET_H
#define __NET_ETHERNET_H 1

#include <sys/cdefs.h>
#include <sys/types.h>
//#include <linux/if_ether.h>     /* IEEE 802.3 Ethernet constants */

__BEGIN_DECLS

/* This is a name for the 48 bit ethernet address available on many
   systems.  */
struct ether_addr
{
  u_int8_t ether_addr_octet[ETH_ALEN];
} __attribute__ ((__packed__));

/* 10Mb/s ethernet header */
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  u_int16_t ether_type;		        /* packet type ID field	*/
} __attribute__ ((__packed__));

/* Ethernet protocol ID's */
#define	ETHERTYPE_PUP		0x0200          /* Xerox PUP */
#define ETHERTYPE_SPRITE	0x0500		/* Sprite */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
#define ETHERTYPE_AT		0x809B		/* AppleTalk protocol */
#define ETHERTYPE_AARP		0x80F3		/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX		0x8137		/* IPX */
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */


#define	ETHER_ADDR_LEN	ETH_ALEN                 /* size of ethernet addr */
#define	ETHER_TYPE_LEN	2                        /* bytes in type field */
#define	ETHER_CRC_LEN	4                        /* bytes in CRC field */
#define	ETHER_HDR_LEN	ETH_HLEN                 /* total octets in header */
#define	ETHER_MIN_LEN	(ETH_ZLEN + ETHER_CRC_LEN) /* min packet length */
#define	ETHER_MAX_LEN	(ETH_FRAME_LEN + ETHER_CRC_LEN) /* max packet length */

/* make sure ethenet length is valid */
#define	ETHER_IS_VALID_LEN(foo)	\
	((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#define	ETHERTYPE_NTRAILER	16

#define	ETHERMTU	ETH_DATA_LEN
#define	ETHERMIN	(ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)

__END_DECLS

#endif	/* net/ethernet.h */
