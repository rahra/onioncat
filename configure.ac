#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([onioncat], [0.1.5], [eagle@cypherpunk.at])
AM_INIT_AUTOMAKE([-Wall -Werror])
#AC_CONFIG_SRCDIR([ocatroute.c])
AC_CONFIG_HEADERS([config.h])

AC_SUBST([CFLAGS], [-Wall])

# Checks for programs.
AC_PROG_CC
#AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
#AC_CHECK_LIB([rt], [clock_gettime])

# Checks for header files.
#AC_HEADER_STDC
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])
AC_CHECK_HEADERS([sys/types.h sys/socket.h netinet/in.h netinet/ip6.h netinet/in6.h net/if.h linux/if_tun.h net/if_tun.h linux/sockios.h], [], [],
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
]]
)

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

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
      [ AC_DEFINE(HAVE_SIN_LEN, 1, [Do we have sockaddr_in.sin_len?]) ],
      [],
      [
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
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
AC_CHECK_FUNCS([strlcat])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

