#!/bin/sh -x
cat<<EOF > doc/Makefile.gdoc
gdoc_MANS =
gdoc_TEXINFOS =
EOF
autoreconf --install --force --verbose --warnings=all
