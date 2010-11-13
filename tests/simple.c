/* simple.c --- Test the simple SASL mechanisms.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <gsasl.h>

#include "utils.h"

#define MAXSTEP 50
#define CLIENT 1
#define SERVER 0
#define UTF8_a "\xC2\xAA"

struct sasltv
{
  int clientp;
  const char *mech;
  const char *step[MAXSTEP];
  const char *password;
  const char *authzid;
  const char *authid;
  const char *service;
  const char *hostname;
  const char *servicename;
  const char *anonymous;
  const char *passcode;
  const char *suggestpin;
  const char *pin;
  int securidrc;
};
static struct sasltv sasltv[] = {
  {CLIENT, "EXTERNAL", {"", NULL}},
  {SERVER, "EXTERNAL", {"", NULL}},
  {CLIENT, "ANONYMOUS", {"", "Zm9vQGJhci5jb20=", NULL, NULL}, NULL, NULL,
   NULL, NULL, NULL, NULL, "foo@bar.com"},
  {SERVER, "ANONYMOUS", {"Zm9vQGJhci5jb20=", NULL, NULL}, NULL, NULL, NULL,
   NULL, NULL, NULL, "foo@bar.com"},
  {CLIENT, "NTLM",
   {"Kw==", "TlRMTVNTUAABAAAAB7IAAAYABgAgAAAAAAAAACYAAABhdXRoaWQ=",
    "TlRMTVNTUAAAAAAAAAAAAAAAAAAAAGFiY2RlZmdoMDEyMzQ1Njc4ODY2NDQwMTIz",
    "TlRMTVNTUAADAAAAGAAYAFgAAAAYABgAcAAAAAAAAABAAAAADAAMAEAAAAAMAAwATAAAA"
    "AAAAACIAAAAAABhYmEAdQB0AGgAaQBkAGEAdQB0AGgAaQBkABeBBp9xJad9eYo3oh1k55"
    "GNFDIui8H8Qz4CfWYVVToBhVzFFbzyzqAZN5Wl59K/Fg==",
    NULL, NULL}, "password", "authzid", "authid"},
  {CLIENT, "PLAIN",
   {"", "YXV0aHppZABhdXRoaWQAcGFzc3dvcmQ=", NULL, NULL}, "password",
   "authzid", "authid"},
  {CLIENT, "PLAIN",
   {"", "YQBhAGE=", NULL, NULL}, "a", "a", "a"},
  {CLIENT, "PLAIN",
   {"", "wqoAwqoAwqo=", NULL, NULL}, UTF8_a, UTF8_a, UTF8_a},
  {SERVER, "PLAIN",
   {"YXV0aHppZABhdXRoaWQAcGFzc3dvcmQ=", NULL, NULL}, "password", "authzid",
   "authid"},
  {SERVER, "PLAIN",
   {"", "", "YXV0aHppZABhdXRoaWQAcGFzc3dvcmQ=", NULL, NULL}, "password",
   "authzid", "authid"},
  {CLIENT, "LOGIN",
   {"VXNlciBOYW1l", "YXV0aGlk", "UGFzc3dvcmQ=", "cGFzc3dvcmQ=", NULL,
    NULL}, "password", NULL, "authid"},
  {CLIENT, "LOGIN",
   {"VXNlciBOYW1l", "YXV0aGlk", "UGFzc3dvcmQ=", "YQ==", NULL, NULL}, "a",
   NULL,
   "authid"},
  {CLIENT, "LOGIN",
   {"VXNlciBOYW1l", "YXV0aGlk", "UGFzc3dvcmQ=", "wqo=", NULL, NULL}, UTF8_a,
   NULL, "authid"},
  {SERVER, "LOGIN",
   {"", "VXNlciBOYW1l", "YXV0aGlk", "UGFzc3dvcmQ=", "cGFzc3dvcmQ=",
    NULL, NULL}, "password", NULL, "authid"},
  {CLIENT, "CRAM-MD5",
   {"PGNiNmQ5YTQ5ZDA3ZjEwY2MubGliZ3Nhc2xAbG9jYWxob3N0Pg==",
    "YXV0aGlkIGZkNjRmMjYxZWYxYjBjYjg0ZmZjNGVmYzgwZDk3NjFj", NULL, NULL},
   "password", "authzid", "authid"},
  {CLIENT, "SECURID",
   {"", "YXV0aHppZABhdXRoaWQANDcxMQA=", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711"},
  {CLIENT, "SECURID",
   {"", "YXV0aHppZABhdXRoaWQANDcxMQA=", "cGFzc2NvZGU=",
    "YXV0aHppZABhdXRoaWQANDcxMQA=", NULL, NULL}, NULL, "authzid", "authid",
   NULL, NULL, NULL, NULL, "4711"},
  {CLIENT, "SECURID",
   {"", "YXV0aHppZABhdXRoaWQANDcxMQA=", "cGlu",
    "YXV0aHppZABhdXRoaWQANDcxMQA0MgA=", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711", NULL, "42"},
  {CLIENT, "SECURID",
   {"", "YXV0aHppZABhdXRoaWQANDcxMQA=", "cGluMjM=",
    "YXV0aHppZABhdXRoaWQANDcxMQA0MgA=", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711", "23", "42"},
  {CLIENT, "SECURID",
   {"", "YXV0aHppZABhdXRoaWQANDcxMQA=", "cGluMjM=",
    "YXV0aHppZABhdXRoaWQANDcxMQA0MgA=", "cGFzc2NvZGU=",
    "YXV0aHppZABhdXRoaWQANDcxMQA=", NULL, NULL}, NULL, "authzid", "authid",
   NULL, NULL, NULL, NULL, "4711", "23", "42"},
  {SERVER, "SECURID",
   {"YXV0aHppZABhdXRoaWQANDcxMQA=", "", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711"},
  {SERVER, "SECURID",
   {"YXV0aHppZABhdXRoaWQANDcxMQA=", "", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711"},
#if 0
  {SERVER, "SECURID",
   {"YXV0aHppZABhdXRoaWQANDcxMQA=", "cGlu",
    "YXV0aHppZABhdXRoaWQANDcxMQA0MgA=", "", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711", NULL, "42",
   GSASL_SECURID_SERVER_NEED_NEW_PIN},
#endif
  {SERVER, "SECURID",
   {"YXV0aHppZABhdXRoaWQANDcxMQA=", "cGluMTc=",
    "YXV0aHppZABhdXRoaWQANDcxMQAyMwA=", "", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711", "17", "23",
   GSASL_SECURID_SERVER_NEED_NEW_PIN},
  {SERVER, "SECURID",
   {"YXV0aHppZABhdXRoaWQANDcxMQA=", "cGFzc2NvZGU=",
    "YXV0aHppZABhdXRoaWQANDcxMQA=", NULL, NULL}, NULL, "authzid", "authid",
   NULL, NULL, NULL, NULL, "4711", NULL, NULL,
   GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE}
};

static int
cb (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;
  int i = 0, j = 0;

  if (gsasl_callback_hook_get (ctx))
    i = *(int *) gsasl_callback_hook_get (ctx);
  if (gsasl_session_hook_get (sctx))
    j = *(int *) gsasl_session_hook_get (sctx);

  if (j < 0 || j > 5)
    fail ("j out of bounds: %d\n", j);

  switch (prop)
    {
    case GSASL_AUTHID:
      gsasl_property_set (sctx, prop, sasltv[i].authid);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHZID:
      gsasl_property_set (sctx, prop, sasltv[i].authzid);
      rc = GSASL_OK;
      break;

    case GSASL_PASSWORD:
      gsasl_property_set (sctx, prop, sasltv[i].password);
      rc = GSASL_OK;
      break;

    case GSASL_ANONYMOUS_TOKEN:
      gsasl_property_set (sctx, prop, sasltv[i].anonymous);
      rc = GSASL_OK;
      break;

    case GSASL_SERVICE:
      rc = GSASL_OK;
      break;

    case GSASL_PASSCODE:
      gsasl_property_set (sctx, prop, sasltv[i].passcode);
      rc = GSASL_OK;
      break;

    case GSASL_SUGGESTED_PIN:
    case GSASL_PIN:
      {
	const char *suggestion = gsasl_property_fast (sctx, GSASL_SUGGESTED_PIN);
	if (suggestion && sasltv[i].suggestpin
	    && strcmp (suggestion, sasltv[i].suggestpin) != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	if ((suggestion == NULL && sasltv[i].suggestpin != NULL) ||
	    (suggestion != NULL && sasltv[i].suggestpin == NULL))
	  return GSASL_AUTHENTICATION_ERROR;

	gsasl_property_set (sctx, prop, sasltv[i].pin);
	rc = GSASL_OK;
      }

    case GSASL_REALM:
      break;

    case GSASL_VALIDATE_EXTERNAL:
      rc = GSASL_OK;
      break;

    case GSASL_VALIDATE_ANONYMOUS:
      if (strcmp (sasltv[i].anonymous,
		  gsasl_property_fast (sctx, GSASL_ANONYMOUS_TOKEN)) == 0)
	rc = GSASL_OK;
      else
	rc = GSASL_AUTHENTICATION_ERROR;
      break;

    case GSASL_VALIDATE_SECURID:
      {
	const char *passcode = gsasl_property_fast (sctx, GSASL_PASSCODE);
	const char *pin = gsasl_property_fast (sctx, GSASL_PIN);

	if (strcmp (passcode, sasltv[i].passcode) != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	if (sasltv[i].securidrc == GSASL_SECURID_SERVER_NEED_NEW_PIN)
	  {
	    rc = sasltv[i].securidrc;
	    sasltv[i].securidrc = GSASL_OK;

	    if (sasltv[i].suggestpin)
	      {
		gsasl_property_set (sctx, GSASL_SUGGESTED_PIN,
				    sasltv[i].suggestpin);
	      }
	  }
	else if (sasltv[i].securidrc ==
		 GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE)
	  {
	    rc = sasltv[i].securidrc;
	    sasltv[i].securidrc = GSASL_OK;
	  }
	else
	  {
	    rc = sasltv[i].securidrc;

	    if (pin && sasltv[i].pin && strcmp (pin, sasltv[i].pin) != 0)
	      return GSASL_AUTHENTICATION_ERROR;

	    if ((pin == NULL && sasltv[i].pin != NULL) ||
		(pin != NULL && sasltv[i].pin == NULL))
	      return GSASL_AUTHENTICATION_ERROR;
	  }
      }
      break;

    default:
      printf ("Unknown property %d\n", prop);
      break;
    }

  return rc;
}

void
doit (void)
{
  Gsasl *ctx = NULL;
  Gsasl_session *sctx = NULL;
  char *out = NULL;
  int i, j;
  int res;

  if (!gsasl_check_version (GSASL_VERSION))
    fail ("gsasl_check_version failure");

  success ("Header version %s library version %s\n",
	   GSASL_VERSION, gsasl_check_version (NULL));

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  gsasl_callback_set (ctx, cb);

  res = gsasl_client_mechlist (ctx, &out);
  if (res != GSASL_OK)
    fail ("gsasl_client_mechlist() failed (%d):\n%s\n",
	  res, gsasl_strerror (res));
  success("client_mechlist: %s\n", out);
  gsasl_free (out); out = NULL;

  res = gsasl_server_mechlist (ctx, &out);
  if (res != GSASL_OK)
    fail ("gsasl_server_mechlist() failed (%d):\n%s\n",
	  res, gsasl_strerror (res));
  success("server_mechlist: %s\n", out);
  gsasl_free (out); out = NULL;

  for (i = 0; i < sizeof (sasltv) / sizeof (sasltv[0]); i++)
    {
      gsasl_callback_hook_set (ctx, &i);

      if (debug)
	printf ("Entry %d %s mechanism %s:\n",
		i, sasltv[i].clientp ? "client" : "server", sasltv[i].mech);

      if (sasltv[i].clientp)
	res = gsasl_client_support_p (ctx, sasltv[i].mech);
      else
	res = gsasl_server_support_p (ctx, sasltv[i].mech);
      if (!res)
	continue;

      if (sasltv[i].clientp)
	res = gsasl_client_start (ctx, sasltv[i].mech, &sctx);
      else
	res = gsasl_server_start (ctx, sasltv[i].mech, &sctx);
      if (res != GSASL_OK)
	{
	  fail ("SASL %s start for mechanism %s failed (%d):\n%s\n",
		sasltv[i].clientp ? "client" : "server",
		sasltv[i].mech, res, gsasl_strerror (res));
	  continue;
	}

      for (j = 0; sasltv[i].step[j]; j += 2)
	{
	  gsasl_session_hook_set (sctx, &j);

	  if (debug)
	    printf ("Input : %s\n",
		    sasltv[i].step[j] ? sasltv[i].step[j] : "");

	  res = gsasl_step64 (sctx, sasltv[i].step[j], &out);

	  if (debug)
	    printf ("Output: %s\n", out ? out : "(null)");

	  if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	    {
	      fail ("gsasl_step64 failed (%d): %s", res, gsasl_strerror (res));
	      break;
	    }

	  if (strlen (out) !=
	      strlen (sasltv[i].step[j + 1] ? sasltv[i].step[j + 1] : ""))
	    {
	      printf ("Expected: %s\n", sasltv[i].step[j + 1] ?
		      sasltv[i].step[j + 1] : "");
	      fail
		("SASL entry %d mechanism %s client step %d length error\n",
		 i, sasltv[i].mech, j);
	      j = -1;
	      break;
	    }

	  if (strcmp (out, sasltv[i].step[j + 1] ?
		      sasltv[i].step[j + 1] : "") != 0)
	    {
	      printf ("Expected: %s\n", sasltv[i].step[j + 1] ?
		      sasltv[i].step[j + 1] : "");
	      fail ("SASL entry %d mechanism %s client step %d data error\n",
		    i, sasltv[i].mech, j);
	      j = -1;
	      break;
	    }

	  gsasl_free (out); out = NULL;

	  if (strcmp (sasltv[i].mech, "SECURID") != 0 && res == GSASL_OK)
	    break;
	}

      if (j != (size_t) -1 && res == GSASL_OK && sasltv[i].step[j + 2])
	fail ("SASL entry %d mechanism %s step %d code ended prematurely\n",
	      i, sasltv[i].mech, j);
      else if (j != (size_t) -1 && res == GSASL_NEEDS_MORE)
	fail ("SASL entry %d mechanism %s step %d table ended prematurely\n",
	      i, sasltv[i].mech, j);
      else if (j != (size_t) -1 && res != GSASL_OK)
	fail ("SASL entry %d mechanism %s step %d failed (%d):\n%s\n",
	      i, sasltv[i].mech, j, res, gsasl_strerror (res));
      else
	printf ("PASS: simple %s %s %d\n", sasltv[i].mech,
		sasltv[i].clientp ? "client" : "server", i);

      {
	size_t outlen;

	res = gsasl_encode (sctx, "foo", 3, &out, &outlen);
	if (res != GSASL_OK)
	  fail ("gsasl_encode %d: %s\n", res, gsasl_strerror (res));
	if (outlen != 3 && memcmp (out, "foo", outlen) != 0)
	  fail ("gsasl_encode memcmp: %.*s\n", (int) outlen, out);
	gsasl_free (out); out = NULL;

	res = gsasl_decode (sctx, "foo", 3, &out, &outlen);
	if (res != GSASL_OK)
	  fail ("gsasl_decode %d: %s\n", res, gsasl_strerror (res));
	if (outlen != 3 && memcmp (out, "foo", outlen) != 0)
	  fail ("gsasl_decode memcmp: %.*s\n", (int) outlen, out);
	gsasl_free (out); out = NULL;
      }

      gsasl_finish (sctx);

      if (debug)
	printf ("\n");
    }

  gsasl_done (ctx);

  /* Sanity check interfaces. */
  gsasl_finish (NULL);
  gsasl_done (NULL);
}
