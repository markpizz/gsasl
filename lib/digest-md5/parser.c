/* parser.c --- DIGEST-MD5 parser.
 * Copyright (C) 2004  Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get prototypes. */
#include "parser.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Parse comma separate list into words.
   Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc.
   From the GNU C Library, under GNU LGPL version 2.1.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.
   Modified for Libgsasl by Simon Josefsson <simon@josefsson.org>
   Copyright (C) 2002  Simon Josefsson

   Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.  */
static int
digest_md5_getsubopt (char **optionp,
		      const char *const *tokens,
		      char **valuep)
{
  char *endp, *vstart;
  int cnt;
  int inside_quote = 0;

  if (**optionp == '\0')
    return -1;

  /* Find end of next token.  */
  endp = *optionp;
  while (*endp != '\0' && (inside_quote || (!inside_quote && *endp != ',')))
    {
      if (*endp == '"')
	inside_quote = !inside_quote;
      endp++;
    }

  /* Find start of value.  */
  vstart = memchr (*optionp, '=', endp - *optionp);
  if (vstart == NULL)
    vstart = endp;

  /* Try to match the characters between *OPTIONP and VSTART against
     one of the TOKENS.  */
  for (cnt = 0; tokens[cnt] != NULL; ++cnt)
    if (memcmp (*optionp, tokens[cnt], vstart - *optionp) == 0
	&& tokens[cnt][vstart - *optionp] == '\0')
      {
	/* We found the current option in TOKENS.  */
	*valuep = vstart != endp ? vstart + 1 : NULL;

	while (*valuep && (**valuep == ' ' ||
			   **valuep == '\t' ||
			   **valuep == '\r' ||
			   **valuep == '\n' || **valuep == '"'))
	  (*valuep)++;

	if (*endp != '\0')
	  {
	    *endp = '\0';
	    *optionp = endp + 1;
	  }
	else
	  *optionp = endp;
	endp--;
	while (*endp == ' ' ||
	       *endp == '\t' ||
	       *endp == '\r' || *endp == '\n' || *endp == '"')
	  *endp-- = '\0';
	while (**optionp == ' ' ||
	       **optionp == '\t' || **optionp == '\r' || **optionp == '\n')
	  (*optionp)++;

	return cnt;
      }

  /* The current suboption does not match any option.  */
  *valuep = *optionp;

  if (*endp != '\0')
    *endp++ = '\0';
  *optionp = endp;
  while (**optionp == ' ' ||
	 **optionp == '\t' || **optionp == '\r' || **optionp == '\n')
    (*optionp)++;

  return -1;
}
#define MAXBUF_MIN 17
#define MAXBUF_MAX 16777215
#define DEFAULT_CHARSET "utf-8"
#define DEFAULT_ALGORITHM "md5-sess"

enum
  {
    /* the order must match the following struct */
    CHALLENGE_REALM = 0,
    CHALLENGE_NONCE,
    CHALLENGE_QOP,
    CHALLENGE_STALE,
    CHALLENGE_MAXBUF,
    CHALLENGE_CHARSET,
    CHALLENGE_ALGORITHM,
    CHALLENGE_CIPHER
  };

const char *const digest_challenge_opts[] = {
  /* the order must match the previous enum */
  "realm",
  "nonce",
  "qop",
  "stale",
  "maxbuf",
  "charset",
  "algorithm",
  "cipher",
  NULL
};

static int
parse_challenge (char *challenge, digest_md5_challenge *out)
{
  int done_algorithm;
  char *value;

  memset (out, 0, sizeof (*out));

  while (*challenge != '\0')
    switch (digest_md5_getsubopt (&challenge, digest_challenge_opts, &value))
      {
      case CHALLENGE_REALM:
	{
	  char **tmp;
	  out->nrealms++;
	  tmp = realloc (out->realms, out->nrealms * sizeof (*out->realms));
	  if (!tmp)
	    return -1;
	  out->realms = tmp;
	  out->realms[out->nrealms - 1] = strdup (value);
	  if (!out->realms[out->nrealms - 1])
	    return -1;
	}
	break;

      case CHALLENGE_NONCE:
	if (out->nonce)
	  return -1;
	out->nonce = strdup (value);
	if (!out->nonce)
	  return -1;
	break;

      case CHALLENGE_QOP:
	/* FIXME: sub-parse. */
	if (out->qop)
	  return -1;
	out->qop = strdup (value);
	if (!out->qop)
	  return -1;
	break;

      case CHALLENGE_STALE:
	if (out->stale)
	  return -1;
	out->stale = 1;
	break;

      case CHALLENGE_MAXBUF:
	if (out->servermaxbuf)
	  return -1;
	out->servermaxbuf = strtoul (value, NULL, 10);
	if (out->servermaxbuf < MAXBUF_MIN
	    || out->servermaxbuf > MAXBUF_MAX)
	  return -1;
	break;

      case CHALLENGE_CHARSET:
	if (strcmp (DEFAULT_CHARSET, value) != 0)
	  return -1;
	out->utf8 = 1;
	break;

      case CHALLENGE_ALGORITHM:
	if (done_algorithm)
	  return -1;
	if (strcmp (DEFAULT_ALGORITHM, value) != 0)
	  return -1;
	done_algorithm = 1;
	break;

      case CHALLENGE_CIPHER:
	/* FIXME: sub-parse. */
	if (out->ciphers)
	  return -1;
	out->ciphers = strdup (value);
	if (!out->ciphers)
	  return -1;
	break;

      default:
	/* Unknown suboption, we MUST ignore it. */
	break;
      }

  return 0;
}

enum
  {
    /* the order must match the following struct */
    RESPONSE_USERNAME = 0,
    RESPONSE_REALM,
    RESPONSE_NONCE,
    RESPONSE_CNONCE,
    RESPONSE_NC,
    RESPONSE_QOP,
    RESPONSE_DIGEST_URI,
    RESPONSE_RESPONSE,
    RESPONSE_MAXBUF,
    RESPONSE_CHARSET,
    RESPONSE_CIPHER,
    RESPONSE_AUTHZID
  };

const char *const digest_response_opts[] = {
  /* the order must match the previous enum */
  "username",
  "realm",
  "nonce",
  "cnonce",
  "nc",
  "qop",
  "digest-uri",
  "response",
  "maxbuf",
  "charset",
  "cipher",
  "authzid",
  NULL
};

static int
parse_response (char *response, digest_md5_response *out)
{
  char *value;

  memset (out, 0, sizeof (*out));

  while (*response != '\0')
    switch (digest_md5_getsubopt (&response, digest_response_opts, &value))
      {

      default:
	/* Unknown suboption.  Not clear if this should be ignored or
	   treated as a failure.  We do the latter for now.  */
	return -1;
	break;
      }

  return 0;
}

enum
  {
    /* the order must match the following struct */
    RESPONSEAUTH_RSPAUTH = 0
  };

const char *const digest_responseauth_opts[] = {
  /* the order must match the previous enum */
  "rspauth",
  NULL
};

static int
parse_finish (char *finish, digest_md5_finish *out)
{
  char *value;

  out->rspauth = NULL;

  while (*finish != '\0')
    switch (digest_md5_getsubopt (&finish, digest_responseauth_opts, &value))
      {
      case RESPONSEAUTH_RSPAUTH:
	if (out->rspauth)
	  return -1;
	out->rspauth = strdup (value);
	break;

      default:
	/* Unknown suboption.  Not clear if this should be ignored or
	   treated as a failure.  We do the latter for now.  */
	return -1;
	break;
      }

  return 0;
}

int
digest_md5_parse_challenge (const char *challenge, digest_md5_challenge *out)
{
  char *subopts = strdup (challenge);
  int rc;

  if (!subopts)
    return -1;

  rc = parse_challenge (subopts, out);

  free (subopts);

  return rc;
}

int
digest_md5_parse_response (const char *response, digest_md5_response *out)
{
  char *subopts = strdup (response);
  int rc;

  if (!subopts)
    return -1;

  rc = parse_response (subopts, out);

  free (subopts);

  return rc;
}

int
digest_md5_parse_finish (const char *finish, digest_md5_finish *out)
{
  char *subopts = strdup (finish);
  int rc;

  if (!subopts)
    return -1;

  rc = parse_finish (subopts, out);

  free (subopts);

  return rc;
}
