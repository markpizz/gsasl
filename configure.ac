dnl Process this file with autoconf to produce a configure script.

dnl Copyright (C) 2002 Simon Josefsson.
dnl
dnl This file is part of Libgsasl.
dnl
dnl Libgsasl is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU Lesser General Public License as
dnl published by the Free Software Foundation; either version 2.1 of
dnl the License, or (at your option) any later version.
dnl
dnl Libgsasl is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with Libgsasl; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

AC_PREREQ(2.50)
AC_INIT(libgsasl, 0.0.4, bug-libgsasl@josefsson.org)

# Interfaces removed:       CURRENT++ AGE=0 REVISION=0
# Interfaces added:         CURRENT++ AGE++ REVISION=0
# Interfaces changed:       CURRENT++       REVISION=0
# No interfaces changed:                    REVISION++
LT_CURRENT=2
LT_AGE=1
LT_REVISION=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_AGE)
AC_SUBST(LT_REVISION)

AM_INIT_AUTOMAKE(gnits)
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AM_GNU_GETTEXT(use-libtool)
AM_GNU_GETTEXT_VERSION(0.11.5)
AC_PROG_LIBTOOL
AC_PROG_CC
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(TEXI2PDF, texi2pdf, $missing_dir)
AM_MISSING_PROG(DOCBOOK2TXT, docbook2txt, $missing_dir)
AM_MISSING_PROG(DOCBOOK2HTML, docbook2html, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PS, docbook2ps, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PDF, docbook2pdf, $missing_dir)
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

# NTLM
PKG_CHECK_MODULES(LIBNTLM, libntlm >= 0.3.1, [have_ntlm=yes], [:])
AC_ARG_ENABLE(ntlm,
  AC_HELP_STRING([--disable-ntlm], [don't use the NTLM mechanism]),
  ntlm=$enableval)
if test "$ntlm" != "no" ; then
	if test "$have_ntlm" != "yes" ; then
		ntlm=no
		AC_MSG_WARN([libntlm not found, disabling NTLM])
	else
		ntlm=yes
		AC_DEFINE(USE_NTLM, 1, [Define to 1 if you want NTLM.])
	fi
fi
AC_MSG_CHECKING([if NTLM should be used])
AC_MSG_RESULT($ntlm)

# CRAM-MD5
AC_ARG_ENABLE(cram-md5,
  AC_HELP_STRING([--disable-cram-md5], [don't use the CRAM-MD5 mechanism]),
  cram_md5=$enableval)
AM_PATH_LIBGCRYPT(1.1.7, [have_gcrypt=yes])
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

# SRP
#AC_ARG_ENABLE(srp,
#  AC_HELP_STRING([--disable-srp], [don't use the SRP mechanism]),
#  srp=$enableval)
#if test "$srp" != "no" ; then
#	if test "$have_gcrypt" != "yes" ; then
#		srp=no
#		AC_MSG_WARN([libgcrypt not found, disabling SRP])
#	else
#		srp=yes
#		AC_DEFINE(USE_SRP, 1, [Define to 1 if you want SRP.])
#	fi
#fi
#AC_MSG_CHECKING([if SRP should be used])
#AC_MSG_RESULT($srp)

# GSSAPI (tests partially stolen from mailutils and fetchmail)
AC_ARG_ENABLE(gssapi,
  AC_HELP_STRING([--disable-gssapi], [don't use the GSSAPI mechanism]),
  gssapi=$enableval)
if test "$gssapi" != "no" ; then
	AC_PATH_PROG(KRB5_CONFIG, krb5-config, no)
	if test "$KRB5_CONFIG" != "no" ; then
		GSSAPI_CFLAGS=`$KRB5_CONFIG --cflags`
		GSSAPI_LIBS=`$KRB5_CONFIG --libs gssapi`
		save_CPPFLAGS=$CPPFLAGS
		CPPFLAGS=$GSSAPI_CFLAGS
		AC_CHECK_HEADERS(gssapi.h gssapi/gssapi.h gssapi/gssapi_generic.h)
		CPPFLAGS=$save_CPPFLAGS
		if test "$ac_cv_header_gssapi_h" = "yes"; then
			AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi.h, AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE, 1, [Define to 1 if you have GSS_C_NT_HOSTBASED_SERVICE.]))
		else
			AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi/gssapi.h, AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE, 1, [Define to 1 if you have GSS_C_NT_HOSTBASED_SERVICE.]))
		fi
		AC_SUBST(GSSAPI_CFLAGS)
		AC_SUBST(GSSAPI_LIBS)
		gssapi=yes
		AC_DEFINE(USE_GSSAPI, 1, [Define to 1 if you want GSSAPI.])
	else
		gssapi=no
		AC_MSG_WARN([krb5-config not found, disabling GSSAPI])
	fi
fi
AC_MSG_CHECKING([if GSSAPI should be used])
AC_MSG_RESULT($gssapi)

# Check for stringprep
AC_ARG_WITH(system-stringprep,
  AC_HELP_STRING([--without-system-stringprep],
		[don't use the system's libstringprep]))
if test "$with_system_stringprep" != "no" ; then
	PKG_CHECK_MODULES(LIBSTRINGPREP, libstringprep >= 0.0.1,
		with_system_stringprep=yes,
		with_system_stringprep=no)
fi
if test "$with_system_stringprep" = "no"; then
	AC_MSG_WARN([[

The system's libstringprep 0.0.1 or later not used. Using copy
distributed with shishi instead.

See <http://josefsson.org/libstringprep/>.

Don't worry.
]])
	LIBSTRINGPREP_CFLAGS="-I\$(top_srcdir)/libstringprep"
	LIBSTRINGPREP_LIBS="\$(top_builddir)/libstringprep/libstringprep.la"
	LIBSTRINGPREP=libstringprep
fi
AC_SUBST(LIBSTRINGPREP)
AC_SUBST(LIBSTRINGPREP_CFLAGS)
AC_SUBST(LIBSTRINGPREP_LIBS)
AC_MSG_CHECKING([if system's libstringprep should be used])
AC_MSG_RESULT($with_system_stringprep)
AC_CONFIG_SUBDIRS(libstringprep)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/socket.h unistd.h strings.h netdb.h math.h limits.h)
AC_CHECK_HEADERS(sys/poll.h sys/time.h sys/types.h sys/select.h sys/socket.h)
AC_CHECK_HEADERS(netinet/in.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_HEADER_TIME

# Checks for library functions.
AC_REPLACE_FUNCS(gethostname strdup strerror memmove memset)
AC_SEARCH_LIBS(gethostbyname, xnet)

# Test if the libc includes a good enough argp.
AC_ARG_WITH(system-argp,
  AC_HELP_STRING([--without-system-argp], [Don't use the system's argp]))
if test "$with_system_argp" != "no" ; then
  AC_LIB_ARGP(,with_system_argp=no)
fi
if test "$with_system_argp" = "no" ; then
  ARGP_LIBS="\$(top_builddir)/argp/libargp.a"
  ARGP_CFLAGS="-I\$(top_srcdir)/argp"
  ARGP=argp
fi
AC_SUBST(ARGP)
AC_SUBST(ARGP_LIBS)
AC_SUBST(ARGP_CFLAGS)
AC_CONFIG_SUBDIRS(argp)

AC_CONFIG_FILES(Makefile po/Makefile.in m4/Makefile intl/Makefile \
		doc/Makefile lib/gsasl.h lib/Makefile \
		libgsasl.pc src/Makefile tests/Makefile)

AC_OUTPUT
