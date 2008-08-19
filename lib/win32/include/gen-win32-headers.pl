#!/usr/bin/perl -w

# Copyright (C) 2008  Free Software Foundation, Inc.
#
# Author: Adam Strzelecki <ono@java.pl>.
#
# This file is part of GNU SASL Library.
#
# GNU SASL Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU SASL Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU SASL Library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# I consider the output of this program to be unrestricted.  Use it as
# you will.

# This script generates win32 (Visual Studio) include files for libidn
# using configure.ac.
# Usage:
#  gen-win32-headers.pl configure.ac > config.h

use strict;

my $version = "";
my $package = "";
my $upackage = "";

if(@ARGV < 1) {
	print "#error \"gen-win32-headers.pl requires at least one parameter.\"\n";
	exit;
}

if(!(open CONFIG, "<$ARGV[0]")) {
	print "#error \"Cannot open $ARGV[0] for version information.\"\n";
	exit;
};
while(<CONFIG>) {
	if(m/AC_INIT\s*\(\s*\[([^\]]+)\]\s*,\s*\[([^\]]+)\]\s*,\s*\[([^\]]+)\]\s*\)/gi) {
		$package = $1;
		$version = $2;
		$package =~ s/^GNU\s//;
		$upackage = uc($package);
		last;
	}
}
close CONFIG;

if($version eq "") {
	print "#error \"Cannot find version information in $ARGV[0]\"\n";
	exit;
}

shift @ARGV;

print <<CONFIG;
#ifndef _CONFIG_H
#define _CONFIG_H

#define PACKAGE "$package"
#define PACKAGE_VERSION "$version"

#define strcasecmp stricmp
#define strncasecmp strnicmp

#define LOCALEDIR "."

#if _MSC_VER && !__cplusplus
# define inline __inline
#endif

#define EOVERFLOW E2BIG
#define GNULIB_GC_HMAC_MD5 1
#define GNULIB_GC_MD5 1
#define GNULIB_GC_RANDOM 1
#define HAVE_ALLOCA 1
#define HAVE_DECL_GETDELIM 0
#define HAVE_DECL_GETLINE 0
#define HAVE_DECL_STRDUP 1
#define HAVE_DECL__SNPRINTF 1
#define HAVE_FLOAT_H 1
#define HAVE_INCLUDE_NEXT 1
#define HAVE_INTMAX_T 1
#define HAVE_INTTYPES_H 1
#define HAVE_INTTYPES_H_WITH_UINTMAX 1
#define HAVE_LONG_LONG_INT 1
#define HAVE_MEMORY_H 1
#define HAVE_SNPRINTF 1
#define HAVE_STDBOOL_H 1
// #define HAVE_STDINT_H 1
#define HAVE_STDINT_H_WITH_UINTMAX 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_UNSIGNED_LONG_LONG_INT 1
#define HAVE_WCHAR_H 1
#define HAVE_WCHAR_T 1
#define HAVE_WCSLEN 1
#define HAVE_WINT_T 1
#define HAVE__BOOL 1
#define NAME_OF_NONCE_DEVICE "/dev/urandom"
#define NAME_OF_PSEUDO_RANDOM_DEVICE "/dev/urandom"
#define NAME_OF_RANDOM_DEVICE "/dev/random"

#define STDC_HEADERS 1
#define USE_ANONYMOUS 1
#define USE_CLIENT 1
#define USE_CRAM_MD5 1
#define USE_DIGEST_MD5 1
#define USE_EXTERNAL 1
#define USE_LOGIN 1
#define USE_PLAIN 1
#define USE_SECURID 1
#define USE_SERVER 1
#define VERSION "$version"

#define restrict
#define __attribute__(x)

#ifndef _AC_STDINT_H
#include <sys/types.h>
#include "ac-stdint.h"
#endif

#endif /* _CONFIG_H */
CONFIG
