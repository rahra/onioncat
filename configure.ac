
AC_PREREQ(2.62)
define([svnversion], esyscmd([sh -c "echo -n $(wc -l <GitLog)"]))dnl
AC_INIT([onioncat],[[0.2.3.g]svnversion],[rahra@cypherpunk.at])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_HEADERS([config.h])

AC_DEFINE(SVN_REVISION, "svnversion", [SVN Revision])


AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug],[enable debugging]), 
   AC_DEFINE([DEBUG], [1], [enable debugging])
   )

AC_ARG_ENABLE([packet-log], AS_HELP_STRING([--enable-packet-log],[enable packet logging]), 
   AC_DEFINE([PACKET_LOG], [], [enable packet logging]))

AC_ARG_ENABLE([handle-http], AS_HELP_STRING([--enable-handle-http],[enable handling of accidental HTTP requests]),
   AC_DEFINE([HANDLE_HTTP], [], [enable handling of accidental HTTP requests]))

AC_ARG_ENABLE([packet-queue], AS_HELP_STRING([--enable-packet-queue],[enable queueuing of packets while connecting setup]),
   AC_DEFINE([PACKET_QUEUE], [], [enable packet queue]))

AC_ARG_ENABLE([check-ipsrc], AS_HELP_STRING([--disable-check-ipsrc],[disable source ip checking before forwarding]),
   AC_DEFINE([CHECK_IPSRC], [1], [disable source ip checking]))

AC_ARG_ENABLE([rtt], AS_HELP_STRING([--enable-rtt],[enable inband RTT measurement]), 
   AC_DEFINE([MEASURE_RTT], [1], [enable RTT measurement]))

AC_ARG_ENABLE([tundev], AS_HELP_STRING([--disable-tundev],[compile without tunnel device code]),
   AC_DEFINE([WITHOUT_TUN], [1], [exclude tunnel device code]))


if test "${enable_debug+set}" = set ; then
   CFLAGS="$CFLAGS -g"
else
   CFLAGS="$CFLAGS -O2"
fi

# Checks for programs.
AC_PROG_CC
#AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

m4_include([ax_pthread.m4])
ACX_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"


# Checks for libraries.
#AC_CHECK_LIB([pthread], [pthread_create])
#AC_CHECK_LIB([rt], [clock_gettime])
#AC_CHECK_LIB([readline], [main])

AC_SEARCH_LIBS([bind], [socket])
AC_SEARCH_LIBS([inet_ntop], [nsl])

# Checks for header files.
#AC_HEADER_STDC
AC_CHECK_HEADERS([sys/types.h sys/wait.h sys/socket.h sys/stat.h netdb.h arpa/nameser.h netinet/in.h netinet/in_systm.h netinet/ip.h netinet/ip6.h netinet/in6.h net/if.h net/if_tun.h net/tun/if_tun.h linux/if_tun.h linux/sockios.h endian.h sys/endian.h netinet/icmp6.h net/ethernet.h netinet/if_ether.h netinet/ether.h netinet/udp.h sys/ethernet.h fcntl.h time.h], [], [],
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
]]
)
#AC_CHECK_HEADERS([readline/readline.h readline/history.h], [], [], [])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
#AC_TYPE_UID_T
#AC_STRUCT_TM
#AC_TYPE_UINT16_T
#AC_TYPE_UINT32_T
#AC_TYPE_UINT8_T
#AC_CHECK_MEMBER([struct sockaddr_in.sin_addr], [AC_DEFINE([HAVE_SIN_LEN], [1], [define if struct sockaddr_in.sin_len exists])])
#AC_CHECK_TYPE([struct sockaddr_in], [AC_DEFINE([HAVE_STRUCT_IP6_HDR],[1],[define if struct ip6_hdr exists])])

AC_CHECK_TYPES([struct ip6_hdr], , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
])

AC_CHECK_TYPES([struct iphdr], , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
])

AC_CHECK_TYPES([struct ip], , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
])

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
      [ AC_DEFINE(HAVE_SIN_LEN, 1, [Do we have sockaddr_in.sin_len?]) ],
      [],
      [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])

AC_CHECK_MEMBER([struct stat.st_mtim],
                [AC_DEFINE(HAVE_STAT_ST_MTIM, 1, [Do we have stat.st_mtim?])],
                [
AC_CHECK_MEMBER([struct stat.st_mtimespec],
                [AC_DEFINE(HAVE_STAT_ST_MTIMESPEC, 1, [Do we have stat.st_mtimespec?])],
                [],
                [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
                 ])
                 ],
                [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
                 ])

AC_CHECK_MEMBER([struct ether_header.ether_dhost.ether_addr_octet],
                [AC_DEFINE(HAVE_ETHER_ADDR_OCTET, 1, [Do we have ether_header.ether_dhost.ether_addr_octet])],
                [],
                [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_ETHERNET_H
#include <sys/ethernet.h>
#endif
])

# Checks for library functions.
#AC_PROG_GCC_TRADITIONAL
#AC_FUNC_MALLOC
#AC_FUNC_MEMCMP
#AC_FUNC_SELECT_ARGTYPES
#AC_FUNC_STRFTIME
#AC_FUNC_VPRINTF
#AC_CHECK_FUNCS([clock_gettime memset select socket strchr strerror])
AC_CHECK_FUNCS([strlcat strlcpy ether_ntoa ether_ntoa_r getpwnam_r])

AC_CONFIG_FILES([Makefile src/cygwin/Makefile src/Makefile man/Makefile i2p/Makefile])
AC_OUTPUT

