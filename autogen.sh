#!/bin/sh -x
autoreconf --install --force --verbose
: 'You can now run ./configure CFLAGS="-g -Wall" --enable-maintainer-mode and then make.'
