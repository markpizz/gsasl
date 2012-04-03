/* qop.c --- DIGEST-MD5 QOP handling.
 * Copyright (C) 2002-2012 Simon Josefsson
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Get prototypes. */
#include "qop.h"

#include "tokens.h"
#include "parser.h"

#include <string.h>
#include <stdlib.h>

int
digest_md5_qopstr2qops (const char *qopstr)
{
  int qops = 0;
  enum
  {
    /* the order must match the following struct */
    QOP_AUTH = 0,
    QOP_AUTH_INT,
    QOP_AUTH_CONF
  };
  const char *const qop_opts[] = {
    /* the order must match the previous enum */
    "qop-auth",
    "qop-int",
    "qop-conf",
    NULL
  };
  char *subsubopts;
  char *val;
  char *qopdup;

  if (!qopstr)
    return 0;

  qopdup = strdup (qopstr);
  if (!qopdup)
    return -1;

  subsubopts = qopdup;
  while (*subsubopts != '\0')
    switch (digest_md5_getsubopt (&subsubopts, qop_opts, &val))
      {
      case QOP_AUTH:
	qops |= DIGEST_MD5_QOP_AUTH;
	break;

      case QOP_AUTH_INT:
	qops |= DIGEST_MD5_QOP_AUTH_INT;
	break;

      case QOP_AUTH_CONF:
	qops |= DIGEST_MD5_QOP_AUTH_CONF;
	break;

      default:
	/* ignore unrecognized options */
	break;
      }

  free (qopdup);

  return qops;
}

const char *
digest_md5_qops2qopstr (int qops)
{
  const char *qopstr[] = {
    /* 0 */ "qop-auth",
    /* 1 */ "qop-auth",
    /* 2 */ "qop-int",
    /* 3 */ "qop-auth, qop-int",
    /* 4 */ "qop-conf",
    /* 5 */ "qop-auth, qop-conf",
    /* 6 */ "qop-int, qop-conf",
    /* 7 */ "qop-auth, qop-int, qop-conf"
  };

  return qopstr[qops & 0x07];
}
