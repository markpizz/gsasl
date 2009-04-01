/* internal.h --- internal header file for gsasl
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>		/* for AF_INET */
#include <poll.h>		/* poll() */
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_PWD_H
# include <pwd.h>		/* getpwnam */
#endif

#include <gsasl.h>

/* Gnulib. */
#include "progname.h"
#include "error.h"
#include "getpass.h"
#include "readline.h"
#include "quote.h"
#include "version-etc.h"
#include "xalloc.h"

/* Get i18n. */
#include <gettext.h>
#include <locale.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

extern int writeln (const char *str);
extern int readln (char **out);

#include "gsasl_cmd.h"
extern struct gengetopt_args_info args_info;

#endif /* _INTERNAL_H */
