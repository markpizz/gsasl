# getaddrinfo.m4 serial 8
dnl Copyright (C) 2004, 2005, 2006 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_GETADDRINFO],
[
  AC_MSG_NOTICE([checking how to do getaddrinfo])

  AC_SEARCH_LIBS(getaddrinfo, [nsl socket])
  AC_SEARCH_LIBS(gethostbyname, [inet nsl])
  AC_SEARCH_LIBS(getservbyname, [inet nsl socket xnet])

  if test "$ac_cv_search_gethostbyname" = "no"; then
    save_LIBS="$LIBS"
    LIBS="$LIBS -lws2_32"
    AC_MSG_CHECKING([whether we need -lws2_32 for gethostbyname])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#include <winsock2.h>
]], [gethostbyname (0);])],
      need_ws2=yes, need_ws2=no)
    AC_MSG_RESULT($need_ws2)
    LIBS="$save_LIBS"
    if test "$need_ws2" = "yes"; then
      LIBS="$LIBS -lws2_32"
    fi
  fi

  AC_REPLACE_FUNCS(getaddrinfo gai_strerror)
  gl_PREREQ_GETADDRINFO
])

# Prerequisites of lib/getaddrinfo.h and lib/getaddrinfo.c.
AC_DEFUN([gl_PREREQ_GETADDRINFO], [
  AC_REQUIRE([gl_C_RESTRICT])
  AC_REQUIRE([gl_SOCKET_FAMILIES])
  AC_REQUIRE([AC_C_INLINE])
  AC_REQUIRE([AC_GNU_SOURCE])
  AC_CHECK_HEADERS_ONCE(netinet/in.h sys/socket.h netdb.h ws2tcpip.h)
  AC_CHECK_DECLS([getaddrinfo, freeaddrinfo, gai_strerror],,,[
  /* sys/types.h is not needed according to POSIX, but the
     sys/socket.h in i386-unknown-freebsd4.10 and
     powerpc-apple-darwin5.5 required it. */
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NETDB_H
# include <netdb.h>
#endif
#if HAVE_WS2TCPIP_H
# include <ws2tcpip.h>
#endif
])
  AC_CHECK_TYPES([struct addrinfo],,,[
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NETDB_H
# include <netdb.h>
#endif
#if HAVE_WS2TCPIP_H
# include <ws2tcpip.h>
#endif
])
])
