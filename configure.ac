dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2002, 2003 Simon Josefsson.
#
# This file is part of GNU SASL.
#
# GNU SASL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GNU SASL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU SASL; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

AC_PREREQ(2.50)
AC_INIT(gsasl, 0.0.9, bug-gsasl@gnu.org)

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
LT_CURRENT=4
LT_REVISION=1
LT_AGE=3
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

AM_INIT_AUTOMAKE(gnits)
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.12.1)
AC_PROG_CC
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(TEXI2PDF, texi2pdf, $missing_dir)
AM_MISSING_PROG(DOCBOOK2TXT, docbook2txt, $missing_dir)
AM_MISSING_PROG(DOCBOOK2HTML, docbook2html, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PS, docbook2ps, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PDF, docbook2pdf, $missing_dir)
AC_GNU_SOURCE
gl_USE_SYSTEM_EXTENSIONS
AC_PROG_LIBTOOL
AM_WITH_DMALLOC

# ANONYMOUS
AC_ARG_ENABLE(anonymous,
  AC_HELP_STRING([--disable-anonymous], [don't use the ANONYMOUS mechanism]),
  anonymous=$enableval)
if test "$anonymous" != "no" ; then
	anonymous=yes
	AC_DEFINE(USE_ANONYMOUS, 1, [Define to 1 if you want ANONYMOUS.])
fi
AC_MSG_CHECKING([if ANONYMOUS should be used])
AC_MSG_RESULT($anonymous)
AM_CONDITIONAL(ANONYMOUS, test x$anonymous = xyes)

# EXTERNAL
AC_ARG_ENABLE(external,
  AC_HELP_STRING([--disable-external], [don't use the EXTERNAL mechanism]),
  external=$enableval)
if test "$external" != "no" ; then
	external=yes
	AC_DEFINE(USE_EXTERNAL, 1, [Define to 1 if you want EXTERNAL.])
fi
AC_MSG_CHECKING([if EXTERNAL should be used])
AC_MSG_RESULT($external)
AM_CONDITIONAL(EXTERNAL, test x$external = xyes)

# PLAIN
AC_ARG_ENABLE(plain,
  AC_HELP_STRING([--disable-plain], [don't use the PLAIN mechanism]),
  plain=$enableval)
if test "$plain" != "no" ; then
	plain=yes
	AC_DEFINE(USE_PLAIN, 1, [Define to 1 if you want PLAIN.])
fi
AC_MSG_CHECKING([if PLAIN should be used])
AC_MSG_RESULT($plain)
AM_CONDITIONAL(PLAIN, test x$plain = xyes)

# LOGIN
AC_ARG_ENABLE(login,
  AC_HELP_STRING([--disable-login], [don't use the LOGIN mechanism]),
  login=$enableval)
if test "$login" != "no" ; then
	login=yes
	AC_DEFINE(USE_LOGIN, 1, [Define to 1 if you want LOGIN.])
fi
AC_MSG_CHECKING([if LOGIN should be used])
AC_MSG_RESULT($login)
AM_CONDITIONAL(LOGIN, test x$login = xyes)

# SECURID
AC_ARG_ENABLE(securid,
  AC_HELP_STRING([--disable-securid], [don't use the SECURID mechanism]),
  securid=$enableval)
if test "$securid" != "no" ; then
	securid=yes
	AC_DEFINE(USE_SECURID, 1, [Define to 1 if you want SECURID.])
fi
AC_MSG_CHECKING([if SECURID should be used])
AC_MSG_RESULT($securid)
AM_CONDITIONAL(SECURID, test x$securid = xyes)

# NTLM
AC_ARG_ENABLE(ntlm,
  AC_HELP_STRING([--disable-ntlm], [don't use the NTLM mechanism]),
  ntlm=$enableval)
if test "$ntlm" != "no" ; then
	PKG_CHECK_MODULES(LIBNTLM, libntlm >= 0.3.1, [ntlm=yes], [ntlm=no])
	if test "$ntlm" != "yes" ; then
		ntlm=no
		AC_MSG_WARN([libntlm not found, disabling NTLM])
	else
		ntlm=yes
		AC_DEFINE(USE_NTLM, 1, [Define to 1 if you want NTLM.])
	fi
fi
AC_MSG_CHECKING([if NTLM should be used])
AC_MSG_RESULT($ntlm)
AM_CONDITIONAL(NTLM, test x$ntlm = xyes)

# Libgcrypt
AM_PATH_LIBGCRYPT(1.1.7, [have_gcrypt=yes], [have_gcrypt=no])
if test "$have_gcrypt" = "yes"; then
  save_LIBS=$LIBS
  LIBS="$LIBS $LIBGCRYPT_LIBS"
  # libgcrypt in CVS has a very different API that we don't support,
  # and it defines this function.
  AC_CHECK_FUNC(gcry_md_is_secure, [have_gcrypt=no])
  LIBS=$save_LIBS
  if test "$have_gcrypt" = "no"; then
    AC_MSG_WARN([[Too recent libgcrypt found, not using it]])
  fi
fi

# CRAM-MD5
AC_ARG_ENABLE(cram-md5,
  AC_HELP_STRING([--disable-cram-md5], [don't use the CRAM-MD5 mechanism]),
  cram_md5=$enableval)
if test "$cram_md5" != "no" ; then
	if test "$have_gcrypt" != "yes" ; then
		cram_md5=no
		AC_MSG_WARN([libgcrypt not found, disabling CRAM-MD5])
	else
		cram_md5=yes
		AC_DEFINE(USE_CRAM_MD5, 1, [Define to 1 if you want CRAM-MD5.])
	fi
fi
AC_MSG_CHECKING([if CRAM-MD5 should be used])
AC_MSG_RESULT($cram_md5)
AM_CONDITIONAL(CRAM_MD5, test x$cram_md5 = xyes)

# DIGEST-MD5
AC_ARG_ENABLE(digest-md5,
  AC_HELP_STRING([--disable-digest-md5], [don't use the DIGEST-MD5 mechanism]),
  digest_md5=$enableval)
if test "$digest_md5" != "no" ; then
	if test "$have_gcrypt" != "yes" ; then
		digest_md5=no
		AC_MSG_WARN([libgcrypt not found, disabling DIGEST-MD5])
	else
		digest_md5=yes
		AC_DEFINE(USE_DIGEST_MD5, 1, [Define to 1 if you want DIGEST-MD5.])
	fi
fi
AC_MSG_CHECKING([if DIGEST-MD5 should be used])
AC_MSG_RESULT($digest_md5)
AM_CONDITIONAL(DIGEST_MD5, test x$digest_md5 = xyes)

# Disable libgcrypt unless we need.
if test "$digest_md5" != "yes" && test "$cram_md5" != "yes"; then
    LIBGCRYPT_CFLAGS=""
    LIBGCRYPT_LIBS=""
fi

# GSSAPI.
AC_ARG_ENABLE(gssapi,
  AC_HELP_STRING([--disable-gssapi], [don't use the GSSAPI mechanism]),
  gssapi=$enableval, gssapi=yes)
AC_MSG_NOTICE([checking for GSS implementation])
if test "$gssapi" = "gss"; then
	AC_MSG_NOTICE([trying GSS])
	PKG_CHECK_MODULES(GSS, gss >= 0.0.0, [gss=yes], [gss=no])
	if test "$gss" = "yes" ; then
		AC_DEFINE(USE_GSS, 1, [Define to 1 if you want GSS.])
		gssapi=yes
	fi
elif test "$gssapi" = "mit"; then
	AC_MSG_NOTICE([trying MIT])
	AC_PATH_PROG(KRB5_CONFIG, krb5-config, no)
	if test "$KRB5_CONFIG" != "no" ; then
		GSSAPI_CFLAGS=`$KRB5_CONFIG --cflags`
		GSSAPI_LIBS=`$KRB5_CONFIG --libs gssapi`
		save_CPPFLAGS=$CPPFLAGS
		CPPFLAGS=$GSSAPI_CFLAGS
		AC_CHECK_HEADERS(gssapi/gssapi.h gssapi/gssapi_generic.h)
		AC_CHECK_DECL(GSS_C_NT_HOSTBASED_SERVICE,,
			[AC_DEFINE(GSS_C_NT_HOSTBASED_SERVICE,
				gss_nt_service_name,
				[Work around buggy MIT library])],[
#ifdef HAVE_GSSAPI_GSSAPI_H
# include <gssapi/gssapi.h>
#endif
#ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
# include <gssapi/gssapi_generic.h>
#endif
])
		CPPFLAGS=$save_CPPFLAGS
		AC_SUBST(GSSAPI_CFLAGS)
		AC_SUBST(GSSAPI_LIBS)
		gssapi=yes
	else
		AC_MSG_WARN([krb5-config not found, disabling GSSAPI])
		gssapi=no
	fi
elif test "$gssapi" = "heimdal"; then
	AC_MSG_NOTICE([trying Heimdal])
	AC_PATH_PROG(KRB5_CONFIG, krb5-config, no)
	if test "$KRB5_CONFIG" != "no" ; then
		GSSAPI_CFLAGS=`$KRB5_CONFIG --cflags`
		GSSAPI_LIBS=`$KRB5_CONFIG --libs gssapi`
		save_CPPFLAGS=$CPPFLAGS
		CPPFLAGS=$GSSAPI_CFLAGS
		AC_CHECK_HEADERS(gssapi.h)
		CPPFLAGS=$save_CPPFLAGS
		AC_SUBST(GSSAPI_CFLAGS)
		AC_SUBST(GSSAPI_LIBS)
		gssapi=yes
	else
		AC_MSG_WARN([krb5-config not found, disabling GSSAPI])
		gssapi=no
	fi
elif test "$gssapi" != "no" ; then
	AC_MSG_NOTICE([auto-detecing GSS/MIT/Heimdal])
	AC_MSG_NOTICE([use --enable-gssapi=IMPL to override])
	AC_MSG_NOTICE([where IMPL is `gss', `mit', or `heimdal'])
	PKG_CHECK_MODULES(GSS, gss >= 0.0.0, [gss=yes], [gss=no])
	if test "$gss" = "yes" ; then
		AC_MSG_NOTICE([GSS found])
		AC_DEFINE(USE_GSS, 1, [Define to 1 if you want GSS.])
		gssapi=yes
	else
		AC_MSG_WARN([GSS not found (see http://josefsson.org/gss/)...])
		AC_PATH_PROG(KRB5_CONFIG, krb5-config, no)
		if test "$KRB5_CONFIG" != "no" ; then
			AC_MSG_NOTICE([MIT/Heimdal found])
			GSSAPI_CFLAGS=`$KRB5_CONFIG --cflags`
			GSSAPI_LIBS=`$KRB5_CONFIG --libs gssapi`
			save_CPPFLAGS=$CPPFLAGS
			CPPFLAGS=$GSSAPI_CFLAGS
			AC_CHECK_HEADERS(gssapi.h gssapi/gssapi.h gssapi/gssapi_generic.h)
			if test "$ac_cv_header_gssapi_h" = "yes" && \
			   test	"$ac_cv_header_gssapi_gssapi_h" = "yes"; then
				AC_MSG_WARN([Both Heimdal and MIT GSSAPI header files found.  Will use Heimdal.])
				AC_MSG_WARN([Use --enable-gssapi=mit to override.])
			fi
			if test -n "$ac_cv_header_gssapi_h"; then
				AC_MSG_NOTICE([Heimdal found])
			else
				AC_MSG_NOTICE([MIT found])
				AC_CHECK_DECL(GSS_C_NT_HOSTBASED_SERVICE,,
					[AC_DEFINE(GSS_C_NT_HOSTBASED_SERVICE,
					gss_nt_service_name,
					[Work around buggy MIT library])],[
#ifdef HAVE_GSSAPI_GSSAPI_H
# include <gssapi/gssapi.h>
#endif
#ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
# include <gssapi/gssapi_generic.h>
#endif
])
			fi
			CPPFLAGS=$save_CPPFLAGS
			AC_SUBST(GSSAPI_CFLAGS)
			AC_SUBST(GSSAPI_LIBS)
			gssapi=yes
		else
			AC_MSG_WARN([krb5-config not found, disabling GSSAPI])
			gssapi=no
		fi
	fi
fi
if test "$gssapi" = "yes"; then
	AC_DEFINE(USE_GSSAPI, 1, [Define to 1 if you want GSSAPI.])
fi
AC_MSG_CHECKING([if GSSAPI should be used])
AC_MSG_RESULT($gssapi)
AM_CONDITIONAL(GSSAPI, test x$gssapi = xyes)

# KERBEROS_V5
AC_ARG_ENABLE(kerberos_v5,
	AC_HELP_STRING([--disable-kerberos_v5],
                       [don't use the KERBEROS_V5 mechanism]),
	kerberos_v5=$enableval, kerberos_v5=no)
if test "$kerberos_v5" != "no" ; then
	PKG_CHECK_MODULES(SHISHI, shishi >= 0.0.0, [kerberos_v5=yes],
                                                   [kerberos_v5=no])
	if test "$kerberos_v5" != "yes" ; then
		kerberos_v5=no
		AC_MSG_WARN([shishi not found, disabling KERBEROS_V5])
	else
		kerberos_v5=yes
		AC_DEFINE(USE_KERBEROS_V5, 1,
                          [Define to 1 if you want KERBEROS_V5.])
	fi
fi
AC_MSG_CHECKING([if KERBEROS_V5 should be used])
AC_MSG_RESULT($kerberos_v5)
AM_CONDITIONAL(KERBEROS_V5, test x$kerberos_v5 = xyes)

# Check for idn
AC_ARG_WITH(stringprep,
  AC_HELP_STRING([--without-stringprep],
		[don't use libidn for string processing even if available]),
	stringprep=$withval, stringprep=yes)
if test "$stringprep" != "no"; then
	AC_CHECK_HEADER(stringprep.h,, stringprep=no)
fi
if test "$stringprep" != "no"; then
	AC_CHECK_LIB(idn, stringprep_check_version,,
		stringprep=no
		AC_MSG_WARN([Libidn not found.  String process disabled.]))
fi
if test "$stringprep" != "no"; then
	AC_DEFINE(WITH_STRINGPREP, 1, [Define to 1 if you want to use libidn.])
fi
AM_CONDITIONAL(STRINGPREP, test x$stringprep = xyes)

# Allow disabling of client or server.
AC_ARG_ENABLE(client,
              AC_HELP_STRING([--disable-client], [Disable client code]),
	      client=$enableval)
AC_ARG_ENABLE(server,
              AC_HELP_STRING([--disable-server], [Disable server code]),
	      server=$enableval)
if test "$client" != "no"; then
  AC_DEFINE(USE_CLIENT, 1, [Define to 1 if you want client code.])
  client=yes
fi
if test "$server" != "no"; then
  AC_DEFINE(USE_SERVER, 1, [Define to 1 if you want server code.])
  server=yes
fi
if test "$server" = "no" && test "$client" = "no"; then
  AC_MSG_ERROR([Disabling both client and server mode is meaningless])
fi
AC_MSG_CHECKING([if client code should be built])
AC_MSG_RESULT($client)
AC_MSG_CHECKING([if server code should be built])
AC_MSG_RESULT($server)
AM_CONDITIONAL(CLIENT, test x$client = xyes)
AM_CONDITIONAL(SERVER, test x$server = xyes)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/types.h sys/poll.h sys/time.h sys/select.h sys/socket.h)
AC_CHECK_HEADERS(unistd.h netdb.h netinet/in.h errno.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_HEADER_TIME
AC_CHECK_DECLS(errno)

# For gnulib stuff in gl/.
gl_FUNC_ALLOCA
gl_ARGP
gl_ERROR
gl_EXITFAIL
AM_FUNC_GETLINE
gl_GETOPT
jm_FUNC_MALLOC
gl_FUNC_MEMPCPY
jm_FUNC_REALLOC
gl_C_RESTRICT
gl_FUNC_STRCHRNUL
gl_FUNC_STRNDUP
gl_FUNC_STRNLEN
gl_SYSEXITS
jm_FUNC_GLIBC_UNLOCKED_IO
gl_XALLOC

# Checks for library functions.
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)

# Check for gtk-doc.
AC_ARG_WITH(html-dir, [  --with-html-dir=PATH path to installed docs ])
if test "x$with_html_dir" = "x" ; then
  HTML_DIR='${datadir}/gtk-doc/html'
else
  HTML_DIR=$with_html_dir
fi
AC_SUBST(HTML_DIR)
AC_CHECK_PROG(GTKDOC, gtkdoc-mkdb, true, false)
gtk_doc_min_version=0.6
if $GTKDOC ; then 
    gtk_doc_version=`gtkdoc-mkdb --version`
    AC_MSG_CHECKING([gtk-doc version ($gtk_doc_version) >= $gtk_doc_min_version])
    if perl <<EOF ; then
      exit (("$gtk_doc_version" =~ /^[[0-9]]+\.[[0-9]]+$/) &&
            ("$gtk_doc_version" >= "$gtk_doc_min_version") ? 0 : 1);
EOF
      AC_MSG_RESULT(yes)
   else
      AC_MSG_RESULT(no)
      GTKDOC=false
   fi
fi

# Let people disable the gtk-doc stuff.
AC_ARG_ENABLE(gtk-doc, [  --enable-gtk-doc  Use gtk-doc to build documentation [default=auto]], enable_gtk_doc="$enableval", enable_gtk_doc=auto)
if test x$enable_gtk_doc = xauto ; then
  if test x$GTKDOC = xtrue ; then
    enable_gtk_doc=yes
  else
    enable_gtk_doc=no 
  fi
fi
AM_CONDITIONAL(ENABLE_GTK_DOC, test x$enable_gtk_doc = xyes)

# We are done
AC_CONFIG_FILES(Makefile libgsasl.pc po/Makefile.in m4/Makefile \
		gl/Makefile gl/m4/Makefile \
		doc/Makefile doc/reference/Makefile doc/man/Makefile \
		lib/Makefile lib/gsasl.h \
		src/Makefile tests/Makefile)
AC_OUTPUT
