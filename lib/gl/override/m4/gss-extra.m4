# gss-extra.m4 serial 1

dnl Copyright (C) 2010 Simon Josefsson
dnl
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([sj_GSS_EXTRA],
[
  # Test for GSS-API library features.
  # XXX this assumes GNU SASL specific configure.ac ordering and variables.
  if test "$gssapi_impl" != "no"; then
    save_CPPFLAGS="$CPPFLAGS"
    save_LIBS="$LIBS"
    CPPFLAGS="$CPPFLAGS $GSS_CFLAGS"
    LIBS="$LIBS $LIBGSS $GSS_LIBS"
    AC_CHECK_FUNCS([gss_encapsulate_token])
    AC_CHECK_FUNCS([gss_decapsulate_token])
    AC_CHECK_FUNCS([gss_oid_equal])
    AC_CHECK_FUNCS([gss_inquire_mech_for_saslname])
    AC_CHECK_FUNCS([GSS_C_NT_HOSTBASED_SERVICE])
    if test "$gssapi_impl" != "gss"; then
      AC_CHECK_HEADERS([gssapi.h gssapi/gssapi.h])
      if test "$ac_cv_header_gssapi_h$ac_cv_header_gssapi_gssapi_h" = "nono"; then
        gssapi_impl=no
        AC_MSG_WARN([Cannot find gssapi.h or gssapi/gssapi.h, disabling GSSAPI])
      fi
    fi
    CPPFLAGS="$save_CPPFLAGS"
    LIBS="$save_LIBS"
  fi
  if test "$gssapi_impl" != "no"; then
    AC_LIBOBJ([gss-extra])
  fi
])
