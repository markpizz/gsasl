# readline.m4 serial 1
dnl Copyright (C) 2005 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_READLINE],
[
  AC_LIBSOURCES([readline.c, readline.h])

  AC_CHECK_HEADERS(readline/readline.h)
  AC_CHECK_LIB(readline, readline)
  if test "$ac_cv_lib_readline_readline" = no then
    AC_LIBOBJ(readline)
    gl_PREREQ_READLINE
  fi
])

# Prerequisites of lib/readline.c.
AC_DEFUN([gl_PREREQ_READLINE], [
  :
])
