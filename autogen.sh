#!/bin/sh -x
autoreconf --install --force --verbose
: './configure CFLAGS="-g -Wall -pedantic" --enable-maintainer-mode --with-dmalloc --disable-shared'
