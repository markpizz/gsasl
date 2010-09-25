/* gss-extra.c --- Provide GSS-API symbols when missing from library.
 * Copyright (C) 2010  Simon Josefsson
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

/* Get specification. */
#include "gss-extra.h"

/* Get strcmp. */
#include <string.h>

/* Get malloc, free. */
#include <stdlib.h>

#ifndef HAVE_GSS_C_NT_HOSTBASED_SERVICE

/* MIT Kerberos for Windows version 3.2.2 lacks this. */
static gss_OID_desc tmp = {
  10,
  (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"
};
gss_OID GSS_C_NT_HOSTBASED_SERVICE = &tmp;

#endif

#ifndef HAVE_GSS_OID_EQUAL

int
gss_oid_equal (const gss_OID first_oid, const gss_OID second_oid)
{
  return first_oid && second_oid &&
    first_oid->length == second_oid->length &&
    memcmp (first_oid->elements, second_oid->elements,
	    second_oid->length) == 0;
}

#endif

#ifndef HAVE_GSS_INQUIRE_MECH_FOR_SASLNAME

/* Provide a dummy replacement function for GSS-API libraries that
   lacks gss_inquire_mech_for_saslname.  This function only works for
   Kerberos V5.  */

OM_uint32
gss_inquire_mech_for_saslname (OM_uint32 * minor_status,
			       const gss_buffer_t sasl_mech_name,
			       gss_OID * mech_type)
{
  static gss_OID_desc krb5oid_static = {
    9, (char *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
  };

  if (sasl_mech_name->value == NULL ||
      sasl_mech_name->length != 8 ||
      memcmp (sasl_mech_name->value, "GS2-KRB5", 8) != 0)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  if (mech_type)
    *mech_type = &krb5oid_static;

  return GSS_S_COMPLETE;
}

#endif

/*
 * The functions _gss_asn1_length_der and _gss_asn1_get_length_der are
 * borrowed from GNU Libtasn1, under LGPLv2.1+.
 * Copyright (C) 2002 Fabio Fiorina.
 * The remaining functions below are copied from GNU GSS but re-licensed
 * to LGPLv2.1+.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010  Simon Josefsson
 */

#ifndef HAVE_GSS_ENCAPSULATE_TOKEN

static void
_gss_asn1_length_der (size_t len, unsigned char *ans, size_t * ans_len)
{
  size_t k;
  unsigned char temp[sizeof (len)];

  if (len < 128)
    {
      if (ans != NULL)
	ans[0] = (unsigned char) len;
      *ans_len = 1;
    }
  else
    {
      k = 0;

      while (len)
	{
	  temp[k++] = len & 0xFF;
	  len = len >> 8;
	}

      *ans_len = k + 1;

      if (ans != NULL)
	{
	  ans[0] = ((unsigned char) k & 0x7F) + 128;
	  while (k--)
	    ans[*ans_len - 1 - k] = temp[k];
	}
    }
}

static OM_uint32
_gss_encapsulate_token_prefix (const char *prefix, size_t prefixlen,
			       const char *in, size_t inlen,
			       const char *oid, OM_uint32 oidlen,
			       void **out, size_t * outlen)
{
  size_t oidlenlen;
  size_t asn1len, asn1lenlen;
  unsigned char *p;

  if (prefix == NULL)
    prefixlen = 0;

  _gss_asn1_length_der (oidlen, NULL, &oidlenlen);
  asn1len = 1 + oidlenlen + oidlen + prefixlen + inlen;
  _gss_asn1_length_der (asn1len, NULL, &asn1lenlen);

  *outlen = 1 + asn1lenlen + asn1len;
  p = *out = malloc (*outlen);
  if (!p)
    return -1;

  *p++ = '\x60';
  _gss_asn1_length_der (asn1len, p, &asn1lenlen);
  p += asn1lenlen;
  *p++ = '\x06';
  _gss_asn1_length_der (oidlen, p, &oidlenlen);
  p += oidlenlen;
  memcpy (p, oid, oidlen);
  p += oidlen;
  if (prefixlen > 0)
    {
      memcpy (p, prefix, prefixlen);
      p += prefixlen;
    }
  memcpy (p, in, inlen);

  return 0;
}

extern OM_uint32
gss_encapsulate_token (const gss_buffer_t input_token,
		       const gss_OID token_oid, gss_buffer_t output_token)
{
  int rc;

  if (!input_token)
    return GSS_S_CALL_INACCESSIBLE_READ;
  if (!token_oid)
    return GSS_S_CALL_INACCESSIBLE_READ;
  if (!output_token)
    return GSS_S_CALL_INACCESSIBLE_WRITE;

  rc = _gss_encapsulate_token_prefix (NULL, 0,
				      input_token->value,
				      input_token->length,
				      token_oid->elements,
				      token_oid->length,
				      &output_token->value,
				      &output_token->length);
  if (rc != 0)
    return GSS_S_FAILURE;

  return GSS_S_COMPLETE;
}

#endif /* HAVE_GSS_ENCAPSULATE_TOKEN */

#ifndef HAVE_GSS_ENCAPSULATE_TOKEN

static size_t
_gss_asn1_get_length_der (const char *der, size_t der_len, size_t * len)
{
  size_t ans;
  size_t k, punt;

  *len = 0;
  if (der_len <= 0)
    return 0;

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
	      size_t last = ans;

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

static int
_gss_decapsulate_token (const char *in, size_t inlen,
			char **oid, size_t * oidlen,
			char **out, size_t * outlen)
{
  size_t i;
  size_t asn1lenlen;

  if (inlen-- == 0)
    return -1;
  if (*in++ != '\x60')
    return -1;

  i = inlen;
  asn1lenlen = _gss_asn1_get_length_der (in, inlen, &i);
  if (inlen < i)
    return -1;

  inlen -= i;
  in += i;

  if (inlen != asn1lenlen)
    return -1;

  if (inlen-- == 0)
    return -1;
  if (*in++ != '\x06')
    return -1;

  i = inlen;
  asn1lenlen = _gss_asn1_get_length_der (in, inlen, &i);
  if (inlen < i)
    return -1;

  inlen -= i;
  in += i;

  if (inlen < asn1lenlen)
    return -1;

  *oidlen = asn1lenlen;
  *oid = (char *) in;

  inlen -= asn1lenlen;
  in += asn1lenlen;

  *outlen = inlen;
  *out = (char *) in;

  return 0;
}

OM_uint32
gss_decapsulate_token (const gss_buffer_t input_token,
		       const gss_OID token_oid, gss_buffer_t output_token)
{
  gss_OID_desc tmpoid;
  char *oid = NULL, *out = NULL;
  size_t oidlen = 0, outlen = 0;

  if (!input_token)
    return GSS_S_CALL_INACCESSIBLE_READ;
  if (!token_oid)
    return GSS_S_CALL_INACCESSIBLE_READ;
  if (!output_token)
    return GSS_S_CALL_INACCESSIBLE_WRITE;

  if (_gss_decapsulate_token ((char *) input_token->value,
			      input_token->length,
			      &oid, &oidlen, &out, &outlen) != 0)
    return GSS_S_DEFECTIVE_TOKEN;

  tmpoid.length = oidlen;
  tmpoid.elements = oid;

  if (!gss_oid_equal (token_oid, &tmpoid))
    return GSS_S_DEFECTIVE_TOKEN;

  output_token->length = outlen;
  output_token->value = malloc (outlen);
  if (!output_token->value)
    return GSS_S_FAILURE;

  memcpy (output_token->value, out, outlen);

  return GSS_S_COMPLETE;
}

#endif
