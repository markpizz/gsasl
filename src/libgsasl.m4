dnl Autoconf macros for libgsasl
dnl       Copyright (C) 2002 Free Software Foundation, Inc.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


dnl AM_PATH_LIBGSASL([MINIMUM-VERSION,
dnl                  [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for liblibgsasl and define LIBGSASL_CFLAGS and LIBGSASL_LIBS
dnl
AC_DEFUN(AM_PATH_LIBGSASL,
[ AC_ARG_WITH(libgsasl-prefix,
            AC_HELP_STRING([--with-libgsasl-prefix=PFX],
                           [prefix where LIBGSASL is installed (optional)]),
     libgsasl_config_prefix="$withval", libgsasl_config_prefix="")
  if test x$libgsasl_config_prefix != x ; then
     libgsasl_config_args="$libgsasl_config_args --prefix=$libgsasl_config_prefix"
     if test x${LIBGSASL_CONFIG+set} != xset ; then
        LIBGSASL_CONFIG=$libgsasl_config_prefix/bin/libgsasl-config
     fi
  fi

  AC_PATH_PROG(LIBGSASL_CONFIG, libgsasl-config, no)
  min_libgsasl_version=ifelse([$1], ,0.4.4,$1)
  AC_MSG_CHECKING(for LIBGSASL - version >= $min_libgsasl_version)
  ok=no
  if test "$LIBGSASL_CONFIG" != "no" ; then
    req_major=`echo $min_libgsasl_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libgsasl_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libgsasl_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    libgsasl_config_version=`$LIBGSASL_CONFIG $libgsasl_config_args --version`
    major=`echo $libgsasl_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $libgsasl_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $libgsasl_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
    if test "$major" -gt "$req_major"; then
        ok=yes
    else 
        if test "$major" -eq "$req_major"; then
            if test "$minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$minor" -eq "$req_minor"; then
                   if test "$micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
  fi
  if test $ok = yes; then
    LIBGSASL_CFLAGS=`$LIBGSASL_CONFIG $libgsasl_config_args --cflags`
    LIBGSASL_LIBS=`$LIBGSASL_CONFIG $libgsasl_config_args --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    LIBGSASL_CFLAGS=""
    LIBGSASL_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBGSASL_CFLAGS)
  AC_SUBST(LIBGSASL_LIBS)
])
