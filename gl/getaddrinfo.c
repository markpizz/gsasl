/* Get address information (partial implementation).
   Copyright (C) 2004 Free Software Foundation, Inc.
   Written by Simon Josefsson <simon@josefsson.org>.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <gettext.h>
#define _(String) gettext (String)
#define N_(String) String

#include "getaddrinfo.h"

/* Translate name of a service location and/or a service name to set of
   socket addresses. */
int
getaddrinfo (const char *restrict nodename,
	     const char *restrict servname,
	     const struct addrinfo *restrict hints,
	     struct addrinfo **restrict res)
{
  struct addrinfo *tmp;
  struct sockaddr sock;
  struct sockaddr *sockp = &sock;
  struct servent *se;
  struct hostent *he;

  if (hints && hints->ai_flags)
    /* FIXME: Support more flags. */
    return EAI_BADFLAGS;

  if (hints &&
      hints->ai_family != PF_UNSPEC &&
      hints->ai_family != PF_INET &&
      hints->ai_family != PF_INET6)
    /* FIXME: Support more families. */
    return EAI_FAMILY;

  if (hints && hints->ai_socktype)
    /* FIXME: Support more socket types. */
    return EAI_SOCKTYPE;

  if (hints &&
      hints->ai_protocol != SOCK_STREAM &&
      hints->ai_protocol != SOCK_DGRAM)
      /* FIXME: Support other protocols. */
    return EAI_SERVICE; /* FIXME: Better return code? */

  if (!nodename)
    /* FIXME: Support server bind mode. */
    return EAI_NONAME;

  if (servname)
    {
      /* FIXME: Use getservbyname_r if available. */
      se = getservbyname (servname,
			  hints->ai_protocol == SOCK_DGRAM ? "udp" : "tcp");
      if (!se)
	return EAI_SERVICE;
    }

  /* FIXME: Use gethostbyname_r if available. */
  he = gethostbyname (connect_hostname);
  if (!he || he->h_addr_list[0] == NULL)
    return EAI_NONAME;

  tmp = calloc (1, sizeof (*tmp));
  if (!tmp)
    return EAI_MEMORY;

  tmp->ai_addr->sa_family = he->he_addrtype;

  switch (tmp->ai_addr->sa_family)
    {
    case PF_INET6:
      {
	struct sockaddr_in6 *sinp;

	sinp = calloc (1, sizeof (*sinp));
	if (!sinp)
	  {
	    free (tmp);
	    return EAI_MEMORY;
	  }

	sinp->sin_port = se->s_port;
	memcpy (&sinp->sin_addr, he->h_addr_list[0], he->h_length);

	tmp->ai_addr = sinp;
	tmp->ai_addrlen = sizeof (sin);
      }
      break;

    case PF_INET:
      {
	struct sockaddr_in *sinp;

	sinp = calloc (1, sizeof (*sinp));
	if (!sinp)
	  {
	    free (tmp);
	    return EAI_MEMORY;
	  }

	sinp->sin_port = se->s_port;
	memcpy (&sinp->sin_addr, he->h_addr_list[0], he->h_length);

	tmp->ai_addr = sinp;
	tmp->ai_addrlen = sizeof (sin);
      }
      break;

    default:
      free (tmp);
      return EAI_NODATA;
    }

  /* FIXME: If more than one address, create linked list of addrinfo's. */

  *res = tmp;

  return 0;
}

/* Free `addrinfo' structure AI including associated storage.  */
void
freeaddrinfo (struct addrinfo *ai)
{
  struct addrinfo *p;

  while (ai != NULL)
    {
      p = ai;
      ai = ai->ai_next;
      free (p);
    }
}

static struct
  {
    int code;
    const char *msg;
  }
values[] =
  {
    { EAI_ADDRFAMILY, N_("Address family for hostname not supported") },
    { EAI_AGAIN, N_("Temporary failure in name resolution") },
    { EAI_BADFLAGS, N_("Bad value for ai_flags") },
    { EAI_FAIL, N_("Non-recoverable failure in name resolution") },
    { EAI_FAMILY, N_("ai_family not supported") },
    { EAI_MEMORY, N_("Memory allocation failure") },
    { EAI_NODATA, N_("No address associated with hostname") },
    { EAI_NONAME, N_("Name or service not known") },
    { EAI_SERVICE, N_("Servname not supported for ai_socktype") },
    { EAI_SOCKTYPE, N_("ai_socktype not supported") },
    { EAI_SYSTEM, N_("System error") },
  };

/* Convert error return from getaddrinfo() to a string.  */
const char *
gai_strerror (int code)
{
  size_t i;
  for (i = 0; i < sizeof (values) / sizeof (values[0]); ++i)
    if (values[i].code == code)
      return _(values[i].msg);

  return _("Unknown error");
}
