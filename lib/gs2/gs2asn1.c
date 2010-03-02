/* gs2asn1.h --- ASN.1 helper functions for GS2
 * Copyright (C) 2010  Simon Josefsson
 * Copyright (C) 2002, 2004, 2006, 2008, 2009, 2010 Free Software
 * Foundation, Inc.
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
# include "config.h"
#endif

#include "gs2asn1.h"

/* The following function is copied from GNU Libtasn1 (under
   LGPLv2.1+) lib/decoding.c:asn1_get_length_der.  It is renamed for
   namespace reasons, and uses better types and error codes. */

ssize_t
gs2_asn1_get_length_der (const char *der, size_t der_len, size_t *len)
{
  ssize_t ans;
  size_t k, punt;

  *len = 0;
  if (der_len <= 0)
    return -3;

  if (!(der[0] & 128))
    {
      /* short form */
      *len = 1;
      return (unsigned char) der[0];
    }
  else
    {
      /* Long form */
      k = (unsigned char) der[0] & 0x7F;
      punt = 1;
      if (k)
	{			/* definite length method */
	  ans = 0;
	  while (punt <= k && punt < der_len)
	    {
	      ssize_t last = ans;

	      ans = ans * 256 + (unsigned char) der[punt++];
	      if (ans < last)
		/* we wrapped around, no bignum support... */
		return -2;
	    }
	}
      else
	{			/* indefinite length method */
	  ans = -1;
	}

      *len = punt;
      return ans;
    }
}
