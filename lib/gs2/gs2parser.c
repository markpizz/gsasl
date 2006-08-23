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

#include "parser.h"

int
gs2_parser (const char *token, size_t toklen, struct gs2_token *out)
{
  uint32_t ctxlen;

  /* Packets shorter than 4 octets are invalid. */
  if (toklen < 4)
    return 1;

  ctxlen = token[0] << 24 | token[1] << 16 | token[2] << 8 | token[3];

  /* If the length field is longer than the entire packet size, minus
     4 octets, the packet is invalid. */
  if (ctxlen > toklen - 4)
    return 1;

  out->context_length = ctxlen;
  out->context_token = token + 4;

  out->wrap_length = toklen - ctxlen - 4;
  out->wrap_token = out->wrap_length > 0 ? token + 4 + out->wrap_length : NULL;

  return 0;
}
