## Process this file with automake to produce Makefile.in.

SUBDIRS = m4

AUTOMAKE_OPTIONS = 1.5 gnits no-dependencies

noinst_LIBRARIES = libfoo.a

libfoo_a_SOURCES =
libfoo_a_LIBADD = @LIBOBJS@
#libfoo_la_LIBADD = @LTLIBOBJS@
EXTRA_DIST =
BUILT_SOURCES =
SUFFIXES =
MOSTLYCLEANFILES =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
EXTRA_DIST += alloca_.h

# We need the following in order to create an <alloca.h> when the system
# doesn't have one that works with the given compiler.
all-local $(libfoo_a_OBJECTS): @ALLOCA_H@
alloca.h: alloca_.h
	cp $(srcdir)/alloca_.h alloca.h-t
	mv alloca.h-t alloca.h
MOSTLYCLEANFILES += alloca.h alloca.h-t

libfoo_a_LIBADD += @ALLOCA@
#libfoo_la_LIBADD += @LTALLOCA@
libfoo_a_SOURCES += argp.h argp-ba.c argp-eexst.c \
           argp-fmtstream.c argp-fmtstream.h argp-fs-xinl.c argp-help.c \
           argp-namefrob.h argp-parse.c argp-pv.c argp-pvh.c argp-xinl.c



libfoo_a_SOURCES += getopt.h getopt.c getopt1.c

libfoo_a_SOURCES += gettext.h








EXTRA_DIST += sysexit_.h

# We need the following in order to create a <sysexits.h> when the system
# doesn't have one that works with the given compiler.
all-local $(libfoo_a_OBJECTS): @SYSEXITS_H@
sysexits.h: sysexit_.h
	cp $(srcdir)/sysexit_.h sysexits.h-t
	mv sysexits.h-t sysexits.h
MOSTLYCLEANFILES += sysexits.h sysexits.h-t

libfoo_a_SOURCES += unlocked-io.h

libfoo_a_SOURCES += xalloc.h xmalloc.c xstrdup.c

