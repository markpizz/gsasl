/* challenge.c --- Generate a CRAM-MD5 challenge string.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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

#include "challenge.h"

/* Get gsasl_nonce. */
#include "gsasl.h"

#define DECCHAR(c) ((c & 0x0F) > 9 ? '0' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

void
cram_md5_challenge (char challenge[32])
{
  size_t i;

  /*
   * From draft-ietf-sasl-crammd5-02.txt:
   *
   *   The data encoded in the challenge contains a presumptively
   *   arbitrary string of random digits, a time-stamp, and the
   *   fully-qualified primary host name of the server.
   *
   * This implementation avoid the information leakage by always using
   * 0 as the time stamp and "example" as the host name.  This is
   * unproblematic, as any client that try to validate the challenge
   * string somehow, would violate the same specification:
   *
   *   The client MUST NOT interpret or attempt to validate the
   *   contents of the challenge in any way.
   *
   */

  strcpy (challenge, "<XXXXXXXXXXXXXXXXXXXX.0@example>");

  gsasl_nonce (&challenge[1], 10);

  for (i = 0; i < 10; i++)
    {
      /* The probabilities for each digit are skewed (0-6 more likely
	 than 7-9), but it is just used as a nonce anyway. */
      challenge[11 + i] = DECCHAR (challenge[1 + i]);
      challenge[ 1 + i] = DECCHAR (challenge[1 + i] >> 4);
    }
}
