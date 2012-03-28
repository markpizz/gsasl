/* smtp.c --- Implement SMTP profile of SASL login.
 * Copyright (C) 2002-2012 Simon Josefsson
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

#include "smtp.h"

int
smtp_greeting (void)
{
  char *in;

  if (!readln (&in))
    return 0;

  return 1;
}

int
smtp_has_starttls (void)
{
  char *in;
  int has_tls = 0;

  if (!writeln ("EHLO [127.0.0.1]"))
    return 0;

  do
    {
      if (!readln (&in))
	return 0;

#define TLSGREETING "250-STARTTLS"
      if (strncmp (in, TLSGREETING, strlen (TLSGREETING)) == 0)
	has_tls = 1;
    }
  while (strncmp (in, "250 ", 4) != 0);

  return has_tls;
}

int
smtp_starttls (void)
{
  char *in;

  if (!writeln ("STARTTLS"))
    return 0;

  if (!readln (&in))
    return 0;

  return 1;
}

int
smtp_select_mechanism (char **mechlist)
{
  char *in;

  if (args_info.server_flag)
    {
      if (!args_info.quiet_given)
	fprintf (stderr, _("Chose SASL mechanisms:\n"));
      if (!readln (&in))
	return 0;
      *mechlist = in;
    }
  else
    {
      if (!writeln ("EHLO [127.0.0.1]"))
	return 0;

      do
	{
	  if (!readln (&in))
	    return 0;

#define GREETING1 "250-AUTH "
#define GREETING2 "250 AUTH "
	  if (strncmp (in, GREETING1, strlen (GREETING1)) == 0)
	    *mechlist = in + strlen (GREETING1);
	  else if (strncmp (in, GREETING2, strlen (GREETING2)) == 0)
	    *mechlist = in + strlen (GREETING2);
	}
      while (strncmp (in, "250 ", 4) != 0);
    }

  return 1;
}

int
smtp_authenticate (const char *mech)
{
  if (args_info.server_flag)
    {
      if (!args_info.quiet_given)
	fprintf (stderr, _("Using mechanism:\n"));
      puts (mech);
    }
  else
    {
      char *buf;
      int rc;
      int len;

      len = asprintf (&buf, "AUTH %s", mech);
      if (len < 0)
	return 0;
      rc = writeln (buf);
      free (buf);
      if (!rc)
	return 0;
    }

  return 1;
}

int
smtp_step_send (const char *data)
{
  char *buf;
  int rc;
  int len;

  if (args_info.server_flag)
    len = asprintf (&buf, "334 %s", data);
  else
    len = asprintf (&buf, "%s", data);
  if (len < 0)
    return 0;
  rc = writeln (buf);
  free (buf);
  if (!rc)
    return 0;

  return 1;
}

/* Return 1 on token, 2 on protocol success, 3 on protocol fail, 0 on
   errors. */
int
smtp_step_recv (char **data)
{
  char *p;

  if (!readln (data))
    return 0;

  p = *data;

  if (strlen (p) <= 3)
    return 0;

  if (strncmp (p, "334 ", 4) == 0)
    {
      memmove (&p[0], &p[4], strlen (p) - 3);

      if (p[strlen (p) - 1] == '\n')
	p[strlen (p) - 1] = '\0';
      if (p[strlen (p) - 1] == '\r')
	p[strlen (p) - 1] = '\0';

      return 1;
    }

  if (strncmp (p, "235 ", 4) == 0)
    {
      /* Never a token here, we don't support additional server
	 information on success. */
      return 2;
    }

  if (strncmp (p, "535 ", 4) == 0)
    return 3;

  fprintf (stderr, _("error: could not parse server data:\n%s\n"), p);

  return 0;
}

int
smtp_logout (void)
{
  char *in;

  if (!writeln ("QUIT"))
    return 0;

  /* read "221 2.0.0 foo closing ..." */
  if (!readln (&in))
    return 0;

  free (in);

  return 1;
}
