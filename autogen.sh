#!/bin/sh -x
autoreconf --install --force --verbose
./configure CFLAGS="-g -Wall -W -Wtraditional -Wundef -Wpointer-arith -Wbad-function-cast -Wcast-align -Wsign-compare -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn -Wnested-externs -Winline" --enable-maintainer-mode --with-dmalloc "$@"
# maybe add: -Wconversion
# perhaps add: -Wwrite-strings
# bad: -Wredundant-decls -Wshadow
