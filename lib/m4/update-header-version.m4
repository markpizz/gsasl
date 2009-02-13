# update-header-version.m4 serial 2
dnl Copyright (C) 2008, 2009 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Simon Josefsson

# sj_UPDATE_HEADER(HEADER-FILE, EXPR)
# -------------
# Update HEADER-FILE with sed expression EXPR.
AC_DEFUN([sj_UPDATE_HEADER],
[
  if ! sed $2 $1 > fixhdr.tmp; then
    AC_MSG_ERROR([[*** Failed to update version number in $1...]])
  fi
  if cmp -s $1 fixhdr.tmp 2>/dev/null; then
    rm -f fixhdr.tmp
  elif ! mv fixhdr.tmp $1; then
    AC_MSG_ERROR([[*** Failed to move fixhdr.tmp to $1...]])
  fi
])

# sj_UPDATE_HEADER_VERSION(HEADER-FILE)
# -------------
# Update version number in HEADER-FILE.  It searches for '_VERSION ".*"'
# and replaces the .* part with the $PACKAGE_VERSION.
AC_DEFUN([sj_UPDATE_HEADER_VERSION],
[
  sj_UPDATE_HEADER($1, 's/_VERSION ".*"/_VERSION "'$PACKAGE_VERSION'"/')
])
