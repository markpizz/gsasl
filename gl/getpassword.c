/* getpassword.c --- Get password from user.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with This file; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include "strdup.h"

static int
tty_set_echo (int echo)
{
  struct termios termios_p;
  int fd = fileno (stdin);

  if (fd < 0)
    return -1;

  if (tcgetattr (fd, &termios_p) != 0)
    return -1;

  if (echo)
    termios_p.c_lflag |= ECHO;
  else
    termios_p.c_lflag &= ~ECHO;

  if (tcsetattr (fd, TCSANOW, &termios_p) != 0)
    return -1;

  return 0;
}

char *
getpassword (char *prompt)
{
  char buf[BUFSIZ];
  char *p;
  int rc;

  printf ("%s", prompt);
  fflush (stdout);

  if (tty_set_echo (0))
    return NULL;

  p = fgets (buf, sizeof (buf), stdin);

  /* Remove \n. */
  buf[strlen (buf) - 1] = '\0';

  if (tty_set_echo (1))
    return NULL;

  if (!p)
    return NULL;

  return strdup (buf);
}
