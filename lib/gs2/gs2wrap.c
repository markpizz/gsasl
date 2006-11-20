/* gs2parser.h --- GS2 parser.
 * Copyright (C) 2006  Simon Josefsson
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

#include "gs2parser.h"

#include <stdint.h>

/*
 *
 *  1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  client_qops  |               client_maxbuf                   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   channel_binding_length                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |[client_cbqops]|          [channel_binding_data]               /
 *  /                                                               /
 *  /                         /      [authzid]                      /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
int
gs2_parse_request (const char *request, size_t reqlen,
		   int clientp,
		   int *qop, size_t *maxbuf, size_t *cblen,
		   int *cbqops, char **cbdata, char **authzid)
{
  size_t l;

  if (reqlen < 8)
    return -1;

  if (qop)
    *qop = request[0];

  if (maxbuf)
    *maxbuf =
      (request[1] << 16) & 0xFF0000 |
      (request[2] << 8) & 0xFF00 |
      (request[3]) & 0xFF;

  l = (request[4] << 24) & 0xFF000000 |
    (request[5] << 16) & 0xFF0000 |
    (request[6] << 8) & 0xFF00 |
    (request[7]) & 0xFF;

  if (l > 0 && reqlen == 8)
    return -2;

  if (cblen)
    *cblen = l;

  if (l > 0)
    {
      if (cbqops)
	*cbqops = request[8];
      if (cbdata)
	*cbdata = &request[9];
      if (authzid)
	*authzid = &request[9] + l;
    }
  else
    {
      if (cbqops)
	*cbqops = 0;
      if (cbdata)
	*cbdata = NULL;
      if (authzid)
	*authzid = NULL;
    }

  return 0;
}
