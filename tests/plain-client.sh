#! /bin/sh
# -*- coding: utf-8 -*-
# This script contains UTF-8 characters, tell shell about it.
# Maybe this isn't portable...
export LC_CTYPE=en_US.UTF-8

# simple test

B64OUT=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=bar --password=baz --silent`

if test "$B64OUT" != "YmFyAGZvbwBiYXo="; then
    exit 1;
fi

# NFKC on authentication ID

B64OUT1=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=a --authorization-id=bar --password=baz --silent`
B64OUT2=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=ª --authorization-id=bar --password=baz --silent`

if test "$B64OUT1" != "$B64OUT2"; then
    exit 1;
fi

B64OUT1=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=ª --authorization-id=bar --password=baz --silent`
B64OUT2=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=a --authorization-id=bar --password=baz --silent`

if test "$B64OUT1" != "$B64OUT2"; then
    exit 1;
fi

# NFKC on authorization ID

B64OUT1=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=ª --password=baz --silent`
B64OUT2=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=a --password=baz --silent`

if test "$B64OUT1" != "$B64OUT2"; then
    exit 1;
fi

B64OUT1=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=a --password=baz --silent`
B64OUT2=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=ª --password=baz --silent`

if test "$B64OUT1" != "$B64OUT2"; then
    exit 1;
fi

# NFKC on password

B64OUT1=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=bar --password=ª --silent`
B64OUT2=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=bar --password=a --silent`

if test "$B64OUT1" != "$B64OUT2"; then
    exit 1;
fi

B64OUT1=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=bar --password=a --silent`
B64OUT2=`echo | ../src/gsasl --client --mechanism PLAIN --authentication-id=foo --authorization-id=bar --password=ª --silent`

if test "$B64OUT1" != "$B64OUT2"; then
    exit 1;
fi

exit 0
