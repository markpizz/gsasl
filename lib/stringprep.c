/* stringprep.c	internationalized SASL string processing
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/*
 * Note: this file is not used when --disable-stringprep is specified.
 * Refer to stringprep-no.c for dummy declarations used in that case.
 */

#include "internal.h"

#include <stringprep.h>

/**
 * gsasl_stringprep_nfkc:
 * @in: a UTF-8 encoded string.
 * @len: length of @str, in bytes, or -1 if @str is nul-terminated.
 *
 * Converts a string into canonical form, standardizing such issues as
 * whether a character with an accent is represented as a base
 * character and combining accent or as a single precomposed
 * character.
 *
 * The normalization mode is NFKC (ALL COMPOSE).  It standardizes
 * differences that do not affect the text content, such as the
 * above-mentioned accent representation. It standardizes the
 * "compatibility" characters in Unicode, such as SUPERSCRIPT THREE to
 * the standard forms (in this case DIGIT THREE). Formatting
 * information may be lost but for most text operations such
 * characters should be considered the same. It returns a result with
 * composed forms rather than a maximally decomposed form.
 *
 * Return value: Return a newly allocated string, that is the NFKC
 *   normalized form of @str, o %NULL on error.
 **/
char *
gsasl_stringprep_nfkc (const char *in, ssize_t len)
{
  char *out;

  out = stringprep_utf8_nfkc_normalize (in, len);

  return out;
}

/**
 * gsasl_stringprep_saslprep:
 * @in: input ASCII or UTF-8 string with data to prepare according to SASLprep.
 * @stringprep_rc: pointer to output variable with stringprep error code,
 *   or %NULL to indicate that you don't care about it.
 *
 * Process a Unicode string for comparison, according to the
 * "SASLprep" stringprep profile.  This function is intended to be
 * used by Simple Authentication and Security Layer (SASL) mechanisms
 * (such as PLAIN, CRAM-MD5, and DIGEST-MD5) as well as other
 * protocols exchanging user names and/or passwords.
 *
 * Return value: Return a newly allocated string that is the
 *   "SASLprep" processed form of the input string, or %NULL on error,
 *   in which case @stringprep_rc contain the stringprep library error
 *   code.
 **/
char *
gsasl_stringprep_saslprep (const char *in, int *stringprep_rc)
{
  char *out;
  int rc;

  rc = stringprep_profile (in, &out, "SASLprep", 0);
  if (stringprep_rc)
    *stringprep_rc = rc;
  if (!rc)
    out = NULL;

  return out;
}

/**
 * gsasl_stringprep_trace:
 * @in: input ASCII or UTF-8 string with data to prepare according to "trace".
 * @stringprep_rc: pointer to output variable with stringprep error code,
 *   or %NULL to indicate that you don't care about it.
 *
 * Process a Unicode string for use as trace information, according to
 * the "trace" stringprep profile.  The profile is designed for use
 * with the SASL ANONYMOUS Mechanism.
 *
 * Return value: Return a newly allocated string that is the "trace"
 *   processed form of the input string, or %NULL on error, in which
 *   case @stringprep_rc contain the stringprep library error code.
 **/
char *
gsasl_stringprep_trace (const char *in, int *stringprep_rc)
{
  char *out;
  int rc;

  rc = stringprep_profile (in, &out, "trace", 0);
  if (stringprep_rc)
    *stringprep_rc = rc;
  if (!rc)
    out = NULL;

  return out;
}
