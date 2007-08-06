/* smtp.c --- Implement SMTP profile of SASL login.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007  Simon Josefsson
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

#define MAX_LINE_LENGTH BUFSIZ

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
  char *in, *capa;
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

#define GREETING "250-AUTH "
	  if (strncmp (in, GREETING, strlen (GREETING)) == 0)
	    *mechlist = in + strlen (GREETING);
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
      char input[MAX_LINE_LENGTH];

      sprintf (input, "AUTH %s", mech);
      if (!writeln (input))
	return 0;
    }

  return 1;
}

int
smtp_step_send (const char *data)
{
  char input[MAX_LINE_LENGTH];

  if (args_info.server_flag)
    sprintf (input, "334 %s", data);
  else
    sprintf (input, "%s", data);
  if (!writeln (input))
    return 0;

  return 1;
}

int
smtp_step_recv (char **data)
{
  char *p;

  if (!readln (data))
    return 0;

  p = *data;

  if (p[0] != '3' || p[1] != '3' || p[2] != '4' || p[3] != ' ')
    {
      fprintf (stderr, _("error: Server did not return expected SASL "
			 "data (it must begin with '334 '):\n%s\n"), p);
      return 0;
    }

  memmove (&p[0], &p[4], strlen (p) - 3);

  if (p[strlen (p) - 1] == '\n')
    p[strlen (p) - 1] = '\0';
  if (p[strlen (p) - 1] == '\r')
    p[strlen (p) - 1] = '\0';

  return 1;
}

int
smtp_auth_finish (void)
{
  char *in;

  if (!readln (&in))
    return 0;

  return 1;
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
