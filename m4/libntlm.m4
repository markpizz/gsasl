dnl Autoconf macros for libntlm
dnl       Copyright (C) 2002 Free Software Foundation, Inc.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


dnl AM_PATH_LIBNTLM([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for liblibntlm and define LIBNTLM_CFLAGS and LIBNTLM_LIBS
dnl
AC_DEFUN(AM_PATH_LIBNTLM,
[ AC_ARG_WITH(libntlm-prefix,
            AC_HELP_STRING([--with-libntlm-prefix=PFX],
                           [prefix where LIBNTLM is installed (optional)]),
     libntlm_config_prefix="$withval", libntlm_config_prefix="")
  if test x$libntlm_config_prefix != x ; then
     libntlm_config_args="$libntlm_config_args --prefix=$libntlm_config_prefix"
     if test x${LIBNTLM_CONFIG+set} != xset ; then
        LIBNTLM_CONFIG=$libntlm_config_prefix/bin/libntlm-config
     fi
  fi

  AC_PATH_PROG(LIBNTLM_CONFIG, libntlm-config, no)
  min_libntlm_version=ifelse([$1], ,0.3.0,$1)
  AC_MSG_CHECKING(for LIBNTLM - version >= $min_libntlm_version)
  ok=no
  if test "$LIBNTLM_CONFIG" != "no" ; then
    req_major=`echo $min_libntlm_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libntlm_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libntlm_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    libntlm_config_version=`$LIBNTLM_CONFIG $libntlm_config_args --version`
    major=`echo $libntlm_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $libntlm_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $libntlm_config_version | \
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
    LIBNTLM_CFLAGS=`$LIBNTLM_CONFIG $libntlm_config_args --cflags`
    LIBNTLM_LIBS=`$LIBNTLM_CONFIG $libntlm_config_args --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    LIBNTLM_CFLAGS=""
    LIBNTLM_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBNTLM_CFLAGS)
  AC_SUBST(LIBNTLM_LIBS)
])
