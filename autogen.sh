#!/bin/sh -x
autoreconf --install --force --verbose
: 'You can now run CFLAGS="-g -Wall" ./configure --enable-maintainer-mode and then make.'
