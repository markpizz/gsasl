/* digest.c --- Generate a CRAM-MD5 hex encoded HMAC-MD5 response string.
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

/* Get prototype. */
#include "digest.h"

/* Get gsasl_hmac_md5. */
#include "gsasl.h"

#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

#define MD5LEN 16

void
cram_md5_digest (const char *challenge,
		 size_t challengelen,
		 const char *secret,
		 size_t secretlen,
		 char response[CRAM_MD5_DIGEST_LEN])
{
  char *hash;
  size_t i;

  gsasl_hmac_md5 (secret, secretlen ? secretlen : strlen (secret),
		  challenge, strlen (challenge),
		  &hash);

  for (i = 0; i < MD5LEN; i++)
    {
      *response++ = HEXCHAR (hash[i] >> 4);
      *response++ = HEXCHAR (hash[i]);
    }

  free (hash);
}
