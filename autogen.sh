#!/bin/sh -x
gtkdocize
autoreconf --install --force
: 'Run "./configure --enable-gtk-doc && make" now.'
