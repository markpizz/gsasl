/* internal.h	internal header file for gsasl
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gettext.h"

#include <stringprep.h>
#include <argp.h>
#include <gsasl.h>

#ifdef ENABLE_NLS
extern char *_gsasl_gettext (const char *str);
#define _(String) _gsasl_gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)
#endif

#endif /* _INTERNAL_H */
