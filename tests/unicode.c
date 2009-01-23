/* unicode.c --- Self tests for unicode related functions.
 * Copyright (C) 2002, 2005, 2007, 2009  Simon Josefsson
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <gsasl.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static int debug = 0;
static int error_count = 0;
static int break_on_error = 0;

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
  if (break_on_error)
    exit (1);
}

static void
escapeprint (char *str, int len)
{
  int i;

  printf ("\t ;; `");
  for (i = 0; i < len; i++)
    if ((str[i] >= 'A' && str[i] <= 'Z') ||
	(str[i] >= 'a' && str[i] <= 'z') ||
	(str[i] >= '0' && str[i] <= '9') || str[i] == '.')
      printf ("%c", str[i]);
    else
      printf ("\\x%02x", str[i]);
  printf ("' (length %d bytes)\n", len);
}

static void
hexprint (char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", str[i]);
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

static void
binprint (char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%d%d%d%d%d%d%d%d ",
	      str[i] & 0x80 ? 1 : 0,
	      str[i] & 0x40 ? 1 : 0,
	      str[i] & 0x20 ? 1 : 0,
	      str[i] & 0x10 ? 1 : 0,
	      str[i] & 0x08 ? 1 : 0,
	      str[i] & 0x04 ? 1 : 0,
	      str[i] & 0x02 ? 1 : 0, str[i] & 0x01 ? 1 : 0);
      if ((i + 1) % 3 == 0)
	printf (" ");
      if ((i + 1) % 6 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

struct nfkc
{
  char *in;
  char *out;
}
nfkc[] =
{
  {
  "\xC2\xB5", "\xCE\xBC"}
  ,
  {
  "\xC2\xAA", "\x61"}
};

int
main (int argc, char *argv[])
{
  char *out;
  int i;

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vbh?] [--verbose] [--break-on-error] [--help]\n",
		argv[0]);
	return 1;
      }
  while (argc-- > 1);

  for (i = 0; i < sizeof (nfkc) / sizeof (nfkc[0]); i++)
    {
      if (debug)
	printf ("NFKC entry %d\n", i);

      out = stringprep_utf8_nfkc_normalize (nfkc[i].in, strlen (nfkc[i].in));
      if (out == NULL)
	{
	  fail ("gsasl_utf8_nfkc_normalize() entry %d failed fatally\n", i);
	  continue;
	}

      if (debug)
	{
	  printf ("in:\n");
	  escapeprint (nfkc[i].in, strlen (nfkc[i].in));
	  hexprint (nfkc[i].in, strlen (nfkc[i].in));
	  puts ("");
	  binprint (nfkc[i].in, strlen (nfkc[i].in));
	  puts ("");

	  printf ("out:\n");
	  escapeprint (out, strlen (out));
	  hexprint (out, strlen (out));
	  puts ("");
	  binprint (out, strlen (out));
	  puts ("");

	  printf ("expected out:\n");
	  escapeprint (nfkc[i].out, strlen (nfkc[i].out));
	  hexprint (nfkc[i].out, strlen (nfkc[i].out));
	  puts ("");
	  binprint (nfkc[i].out, strlen (nfkc[i].out));
	  puts ("");
	}

      if (strlen (nfkc[i].out) != strlen (out) ||
	  memcmp (nfkc[i].out, out, strlen (out)) != 0)
	{
	  fail ("gsasl_utf8_nfkc_normalize() entry %d failed\n", i);
	  if (debug)
	    printf ("ERROR\n");
	}
      else if (debug)
	printf ("OK\n");
    }

  if (debug)
    printf ("Libgsasl unicode self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
