/* simple.c --- Test the simple SASL mechanisms.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* FIXME. We need the library config.h too. */
#undef PACKAGE
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#include "lib/config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <gsasl.h>

#include "utils.h"

#define MAX_LINE_LENGTH BUFSIZ

#define MAXSTEP 50
#define CLIENT 1
#define SERVER 0
#define UTF8_a "\xC2\xAA"

struct sasltv
{
  int clientp;
  char *mech;
  char *step[MAXSTEP];
  char *password;
  char *authzid;
  char *authid;
  char *service;
  char *hostname;
  char *servicename;
  char *anonymous;
  char *passcode;
  char *suggestpin;
  char *pin;
  int securidrc;
};
static struct sasltv sasltv[] = {
#ifdef USE_EXTERNAL
  {CLIENT, "EXTERNAL", {"", NULL}},
  {SERVER, "EXTERNAL", {"", NULL}},
#endif
#ifdef USE_ANONYMOUS
  {CLIENT, "ANONYMOUS", {"", "Zm9vQGJhci5jb20=", NULL, NULL}, NULL, NULL,
   NULL, NULL, NULL, NULL, "foo@bar.com"},
  {SERVER, "ANONYMOUS", {"Zm9vQGJhci5jb20=", NULL, NULL}, NULL, NULL, NULL,
   NULL, NULL, NULL, "foo@bar.com"},
#endif
#ifdef USE_NTLM
  {CLIENT, "NTLM",
   {"Kw==", "TlRMTVNTUAABAAAAB7IAAAcABwAgAAAAAAAAAAcAAABhdXRoemlk",
    "TlRMTVNTUAAAAAAAAAAAAAAAAAAAAGFiY2RlZmdoMDEyMzQ1Njc4ODY2NDQwMTIz",
    "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAAAAAAwAAAADgAOAHAAAAAOAA4AfgAAA"
    "AAAAABMAAAAAABhYheBBp9xJad9eYo3oh1k55GNFDIui8H8Qz4CfWYVVToBhVzFFbzyzq"
    "AZN5Wl59K/FmEAdQB0AGgAegBpAGQAYQB1AHQAaAB6AGkAZAA=",
    NULL, NULL}, "password", "authzid", "authid"},
#endif
#ifdef USE_PLAIN
  {CLIENT, "PLAIN",
   {"", "YXV0aHppZABhdXRoaWQAcGFzc3dvcmQ=", NULL, NULL}, "password",
   "authzid", "authid"},
  {CLIENT, "PLAIN",
   {"", "YQBhAGE=", NULL, NULL}, "a", "a", "a"},
#ifdef WITH_STRINGPREP
  {CLIENT, "PLAIN",
   {"", "YQBhAGE=", NULL, NULL}, UTF8_a, UTF8_a, UTF8_a},
#endif
  {SERVER, "PLAIN",
   {"YXV0aHppZABhdXRoaWQAcGFzc3dvcmQ=", NULL, NULL}, "password", "authzid",
   "authid"},
  {SERVER, "PLAIN",
   {"", "", "YXV0aHppZABhdXRoaWQAcGFzc3dvcmQ=", NULL, NULL}, "password",
   "authzid", "authid"},
#endif
#ifdef USE_LOGIN
  {CLIENT, "LOGIN",
   {"VXNlciBOYW1l", "YXV0aHppZA==", "UGFzc3dvcmQ=", "cGFzc3dvcmQ=", NULL,
    NULL}, "password", "authzid", "authid"},
  {CLIENT, "LOGIN",
   {"VXNlciBOYW1l", "YQ==", "UGFzc3dvcmQ=", "YQ==", NULL, NULL}, "a", "a",
   "authid"},
#ifdef WITH_STRINGPREP
  {CLIENT, "LOGIN",
   {"VXNlciBOYW1l", "YQ==", "UGFzc3dvcmQ=", "YQ==", NULL, NULL}, UTF8_a,
   UTF8_a, "authid"},
#endif
  {SERVER, "LOGIN",
   {"", "VXNlciBOYW1l", "YXV0aHppZA==", "UGFzc3dvcmQ=", "cGFzc3dvcmQ=",
    NULL, NULL}, "password", "authzid", "authid"},
#endif
#ifdef USE_CRAM_MD5
  {CLIENT, "CRAM-MD5",
   {"PGNiNmQ5YTQ5ZDA3ZjEwY2MubGliZ3Nhc2xAbG9jYWxob3N0Pg==",
    "YXV0aGlkIGZkNjRmMjYxZWYxYjBjYjg0ZmZjNGVmYzgwZDk3NjFj", NULL, NULL},
   "password", "authzid", "authid"},
#endif
#ifdef USE_SECURID
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
  {SERVER, "SECURID",
   {"YXV0aHppZABhdXRoaWQANDcxMQA=", "cGlu",
    "YXV0aHppZABhdXRoaWQANDcxMQA0MgA=", "", NULL, NULL}, NULL, "authzid",
   "authid", NULL, NULL, NULL, NULL, "4711", NULL, "42",
   GSASL_SECURID_SERVER_NEED_NEW_PIN},
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
#endif
};

static int
client_callback_authorization_id (Gsasl_session_ctx * xctx,
				  char *out, size_t * outlen)
{
  Gsasl_ctx *ctx = gsasl_client_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  size_t needlen = sasltv[i].authzid ? strlen (sasltv[i].authzid) : 0;

  if (*outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out && sasltv[i].authzid)
    memcpy (out, sasltv[i].authzid, needlen);

  return GSASL_OK;
}

static int
client_callback_authentication_id (Gsasl_session_ctx * xctx,
				   char *out, size_t * outlen)
{
  Gsasl_ctx *ctx = gsasl_client_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  size_t needlen = strlen (sasltv[i].authid);

  if (*outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, sasltv[i].authid, needlen);

  return GSASL_OK;
}

static int
client_callback_password (Gsasl_session_ctx * xctx, char *out,
			  size_t * outlen)
{
  Gsasl_ctx *ctx = gsasl_client_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  size_t needlen = strlen (sasltv[i].password);

  if (*outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, sasltv[i].password, needlen);

  return GSASL_OK;
}

static int
server_callback_validate (Gsasl_session_ctx * xctx,
			  const char *authorization_id,
			  const char *authentication_id, const char *password)
{
  Gsasl_ctx *ctx = gsasl_server_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);

  if (authorization_id && sasltv[i].authzid &&
      strcmp (authorization_id, sasltv[i].authzid) != 0)
    return GSASL_AUTHENTICATION_ERROR;

  if ((authorization_id == NULL && sasltv[i].authzid != NULL) ||
      (authorization_id != NULL && sasltv[i].authzid == NULL))
    return GSASL_AUTHENTICATION_ERROR;

  if (authentication_id && sasltv[i].authid &&
      strcmp (authentication_id, sasltv[i].authid) != 0)
    return GSASL_AUTHENTICATION_ERROR;

  if (strcmp (password, sasltv[i].password) != 0)
    return GSASL_AUTHENTICATION_ERROR;

  return GSASL_OK;
}

static int
server_callback_retrieve (Gsasl_session_ctx * xctx,
			  const char *authentication_id,
			  const char *authorization_id,
			  const char *realm, char *key, size_t * keylen)
{
  Gsasl_ctx *ctx = gsasl_server_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  size_t needlen = strlen (sasltv[i].password);

  if (*keylen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *keylen = strlen (sasltv[i].password);
  if (key)
    memcpy (key, sasltv[i].password, needlen);

  return GSASL_OK;
}

static int
client_callback_service (Gsasl_session_ctx * ctx,
			 char *srv,
			 size_t * srvlen,
			 char *host,
			 size_t * hostlen, char *srvname, size_t * srvnamelen)
{
  return GSASL_OK;
}

static int
client_callback_anonymous (Gsasl_session_ctx * xctx, char *out,
			   size_t * outlen)
{
  Gsasl_ctx *ctx = gsasl_client_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  size_t needlen = strlen (sasltv[i].anonymous);

  if (*outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, sasltv[i].anonymous, strlen (sasltv[i].anonymous));

  return GSASL_OK;
}

static int
server_callback_anonymous (Gsasl_session_ctx * xctx, const char *token)
{
  Gsasl_ctx *ctx = gsasl_client_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);

  return strcmp (sasltv[i].anonymous, token) == 0 ? GSASL_OK :
    GSASL_AUTHENTICATION_ERROR;
}

static int
server_callback_external (Gsasl_session_ctx * xctx)
{
  return GSASL_OK;
}

static int
client_callback_passcode (Gsasl_session_ctx * xctx, char *out,
			  size_t * outlen)
{
  Gsasl_ctx *ctx = gsasl_client_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  size_t needlen = strlen (sasltv[i].passcode);

  if (*outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, sasltv[i].passcode, needlen);

  return GSASL_OK;
}

static int
client_callback_pin (Gsasl_session_ctx * xctx, char *suggestion,
		     char *out, size_t * outlen)
{
  Gsasl_ctx *ctx = gsasl_client_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  size_t needlen = strlen (sasltv[i].pin);

  if (suggestion && sasltv[i].suggestpin &&
      strcmp (suggestion, sasltv[i].suggestpin) != 0)
    return GSASL_AUTHENTICATION_ERROR;

  if ((suggestion == NULL && sasltv[i].suggestpin != NULL) ||
      (suggestion != NULL && sasltv[i].suggestpin == NULL))
    return GSASL_AUTHENTICATION_ERROR;

  if (*outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, sasltv[i].pin, needlen);

  return GSASL_OK;
}

static int
server_callback_securid (Gsasl_session_ctx * xctx,
			 const char *authentication_id,
			 const char *authorization_id,
			 const char *passcode,
			 char *pin, char *suggestpin, size_t * suggestpinlen)
{
  Gsasl_ctx *ctx = gsasl_server_ctx_get (xctx);
  int i = *(int *) gsasl_application_data_get (ctx);
  int res;

  if (strcmp (passcode, sasltv[i].passcode) != 0)
    return GSASL_AUTHENTICATION_ERROR;

  if (sasltv[i].securidrc == GSASL_SECURID_SERVER_NEED_NEW_PIN)
    {
      res = sasltv[i].securidrc;
      sasltv[i].securidrc = GSASL_OK;

      if (sasltv[i].suggestpin)
	{
	  if (*suggestpinlen)
	    *suggestpinlen = strlen (sasltv[i].suggestpin);
	  if (suggestpin)
	    memcpy (suggestpin, sasltv[i].suggestpin,
		    strlen (sasltv[i].suggestpin));
	}
      else if (*suggestpinlen)
	*suggestpinlen = 0;
    }
  else if (sasltv[i].securidrc ==
	   GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE)
    {
      res = sasltv[i].securidrc;
      sasltv[i].securidrc = GSASL_OK;
    }
  else
    {
      res = sasltv[i].securidrc;

      if (pin && sasltv[i].pin && strcmp (pin, sasltv[i].pin) != 0)
	return GSASL_AUTHENTICATION_ERROR;

      if ((pin == NULL && sasltv[i].pin != NULL) ||
	  (pin != NULL && sasltv[i].pin == NULL))
	return GSASL_AUTHENTICATION_ERROR;

      if (*suggestpinlen)
	*suggestpinlen = 0;
    }

  return res;
}

void
doit (void)
{
  Gsasl_ctx *ctx = NULL;
  Gsasl_session_ctx *xctx = NULL;
  char output[MAX_LINE_LENGTH];
  size_t outputlen;
  size_t i, j;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  gsasl_client_callback_authentication_id_set
    (ctx, client_callback_authentication_id);
  gsasl_client_callback_authorization_id_set
    (ctx, client_callback_authorization_id);
  gsasl_client_callback_password_set (ctx, client_callback_password);
  gsasl_server_callback_validate_set (ctx, server_callback_validate);
  gsasl_server_callback_retrieve_set (ctx, server_callback_retrieve);
  gsasl_client_callback_service_set (ctx, client_callback_service);
  gsasl_client_callback_anonymous_set (ctx, client_callback_anonymous);
  gsasl_server_callback_anonymous_set (ctx, server_callback_anonymous);
  gsasl_server_callback_external_set (ctx, server_callback_external);
  gsasl_client_callback_passcode_set (ctx, client_callback_passcode);
  gsasl_client_callback_pin_set (ctx, client_callback_pin);
  gsasl_server_callback_securid_set (ctx, server_callback_securid);

  outputlen = sizeof (output);
  res = gsasl_client_listmech (ctx, output, &outputlen);
  if (res != GSASL_OK)
    fail ("gsasl_client_listmech() failed (%d):\n%s\n",
	  res, gsasl_strerror (res));

  outputlen = sizeof (output);
  res = gsasl_server_listmech (ctx, output, &outputlen);
  if (res != GSASL_OK)
    fail ("gsasl_server_listmech() failed (%d):\n%s\n",
	  res, gsasl_strerror (res));

  for (i = 0; i < sizeof (sasltv) / sizeof (sasltv[0]); i++)
    {
      gsasl_application_data_set (ctx, &i);

#if !USE_CLIENT
      if (sasltv[i].clientp)
	continue;
#endif
#if !USE_SERVER
      if (!sasltv[i].clientp)
	continue;
#endif

      if (debug)
	printf ("Entry %d %s mechanism %s:\n",
		i, sasltv[i].clientp ? "client" : "server", sasltv[i].mech);

      if (sasltv[i].clientp)
	res = gsasl_client_start (ctx, sasltv[i].mech, &xctx);
      else
	res = gsasl_server_start (ctx, sasltv[i].mech, &xctx);
      if (res != GSASL_OK)
	{
	  fail ("SASL %s start for mechanism %s failed (%d):\n%s\n",
		sasltv[i].clientp ? "client" : "server",
		sasltv[i].mech, res, gsasl_strerror (res));
	  continue;
	}

      for (j = 0; sasltv[i].step[j]; j += 2)
	{
	  if (sasltv[i].clientp)
	    gsasl_client_application_data_set (xctx, &j);
	  else
	    gsasl_server_application_data_set (xctx, &j);

	  if (debug)
	    printf ("Input : %s\n",
		    sasltv[i].step[j] ? sasltv[i].step[j] : "");

	  output[0] = '\0';
	  outputlen = sizeof (output);
	  if (sasltv[i].clientp)
	    res = gsasl_client_step_base64 (xctx, sasltv[i].step[j],
					    output, outputlen);
	  else
	    res = gsasl_server_step_base64 (xctx, sasltv[i].step[j],
					    output, outputlen);

	  if (debug)
	    printf ("Output: %s\n", output);

	  if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	    break;

	  if (strlen (output) !=
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

	  if (strcmp (output, sasltv[i].step[j + 1] ?
		      sasltv[i].step[j + 1] : "") != 0)
	    {
	      printf ("Expected: %s\n", sasltv[i].step[j + 1] ?
		      sasltv[i].step[j + 1] : "");
	      fail ("SASL entry %d mechanism %s client step %d data error\n",
		    i, sasltv[i].mech, j);
	      j = -1;
	      break;
	    }
	}

      if ((int) j != -1 && res == GSASL_OK && sasltv[i].step[j + 2])
	fail ("SASL entry %d mechanism %s step %d code ended prematurely\n",
	      i, sasltv[i].mech, j);
      else if ((int) j != -1 && res == GSASL_NEEDS_MORE)
	fail ("SASL entry %d mechanism %s step %d table ended prematurely\n",
	      i, sasltv[i].mech, j, res, gsasl_strerror (res));
      else if ((int) j != -1 && res != GSASL_OK)
	fail ("SASL entry %d mechanism %s step %d failed (%d):\n%s\n",
	      i, sasltv[i].mech, j, res, gsasl_strerror (res));
      else
	printf ("PASS: simple %s %s %d\n", sasltv[i].mech,
		sasltv[i].clientp ? "client" : "server", i);

      if (sasltv[i].clientp)
	gsasl_client_finish (xctx);
      else
	gsasl_server_finish (xctx);

      if (debug)
	printf ("\n");
    }

  gsasl_done (ctx);
}
