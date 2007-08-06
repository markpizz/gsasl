/* imap.c --- Implement IMAP profile of SASL login.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007  Simon Josefsson
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

#include "imap.h"

#define MAX_LINE_LENGTH BUFSIZ

int
imap_greeting (void)
{
  char *in;

  if (!readln (&in))
    return 0;

  return 1;
}

int
imap_has_starttls (void)
{
  char *in, *capa;
  int has_tls = 0;

  if (!writeln (". CAPABILITY"))
    return 0;

  if (!readln (&in))
    return 0;

  has_tls = strstr (in, "STARTTLS") != NULL;

  if (!readln (&in))
    return 0;

  return has_tls;
}

int
imap_starttls (void)
{
  char *in;

  if (!writeln (". STARTTLS"))
    return 0;

  if (!readln (&in))
    return 0;

  return 1;
}

int
imap_select_mechanism (char **mechlist)
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
      if (!writeln (". CAPABILITY"))
	return 0;

      if (!readln (&in))
	return 0;

      /* XXX parse IMAP capability line */

      *mechlist = in;

      if (!readln (&in))
	return 0;
    }

  return 1;
}

int
imap_authenticate (const char *mech)
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

      sprintf (input, ". AUTHENTICATE %s", mech);
      if (!writeln (input))
	return 0;
    }

  return 1;
}

int
imap_step_send (const char *data)
{
  char input[MAX_LINE_LENGTH];

  if (args_info.server_flag)
    sprintf (input, "+ %s", data);
  else
    sprintf (input, "%s", data);
  if (!writeln (input))
    return 0;

  return 1;
}

int
imap_step_recv (char **data)
{
  char *p;

  if (!readln (data))
    return 0;

  p = *data;

  if (!args_info.server_flag)
    {
      if (p[0] != '+' || p[1] != ' ')
	{
	  fprintf (stderr, _("error: Server did not return expected SASL "
			     "data (it must begin with '+ '):\n%s\n"), p);
	  return 0;
	}

      memmove (&p[0], &p[2], strlen (p) - 1);
    }

  if (p[strlen (p) - 1] == '\n')
    p[strlen (p) - 1] = '\0';
  if (p[strlen (p) - 1] == '\r')
    p[strlen (p) - 1] = '\0';

  return 1;
}

int
imap_auth_finish (void)
{
  char *in;

  if (!readln (&in))
    return 0;

  return 1;
}

int
imap_logout (void)
{
  char *in;

  if (!writeln (". LOGOUT"))
    return 0;

  /* read "* BYE ..." */
  if (!readln (&in))
    return 0;

  free (in);

  /* read ". OK ..." */
  if (!readln (&in))
    return 0;

  free (in);

  return 1;
}
