/* symbols.c --- Test if all exported symbols are available.
 * Copyright (C) 2010  Simon Josefsson
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

#include <assert.h>

#include <gsasl.h>

static void
assert_symbol_exists (const void *p)
{
  assert (p);
}

int
main (void)
{
  /* LIBGSASL_1.1 */
  assert_symbol_exists ((const void *) GSASL_VALID_MECHANISM_CHARACTERS);
  assert_symbol_exists ((const void *) gsasl_base64_from);
  assert_symbol_exists ((const void *) gsasl_base64_to);
  assert_symbol_exists ((const void *) gsasl_callback);
  assert_symbol_exists ((const void *) gsasl_callback_hook_get);
  assert_symbol_exists ((const void *) gsasl_callback_hook_set);
  assert_symbol_exists ((const void *) gsasl_callback_set);
  assert_symbol_exists ((const void *) gsasl_check_version);
  assert_symbol_exists ((const void *) gsasl_client_mechlist);
  assert_symbol_exists ((const void *) gsasl_client_start);
  assert_symbol_exists ((const void *) gsasl_client_suggest_mechanism);
  assert_symbol_exists ((const void *) gsasl_client_support_p);
  assert_symbol_exists ((const void *) gsasl_decode);
  assert_symbol_exists ((const void *) gsasl_done);
  assert_symbol_exists ((const void *) gsasl_encode);
  assert_symbol_exists ((const void *) gsasl_finish);
  assert_symbol_exists ((const void *) gsasl_free);
  assert_symbol_exists ((const void *) gsasl_hmac_md5);
  assert_symbol_exists ((const void *) gsasl_init);
  assert_symbol_exists ((const void *) gsasl_md5);
  assert_symbol_exists ((const void *) gsasl_mechanism_name);
  assert_symbol_exists ((const void *) gsasl_nonce);
  assert_symbol_exists ((const void *) gsasl_property_fast);
  assert_symbol_exists ((const void *) gsasl_property_get);
  assert_symbol_exists ((const void *) gsasl_property_set);
  assert_symbol_exists ((const void *) gsasl_property_set_raw);
  assert_symbol_exists ((const void *) gsasl_random);
  assert_symbol_exists ((const void *) gsasl_register);
  assert_symbol_exists ((const void *) gsasl_saslprep);
  assert_symbol_exists ((const void *) gsasl_server_mechlist);
  assert_symbol_exists ((const void *) gsasl_server_start);
  assert_symbol_exists ((const void *) gsasl_server_support_p);
  assert_symbol_exists ((const void *) gsasl_session_hook_get);
  assert_symbol_exists ((const void *) gsasl_session_hook_set);
  assert_symbol_exists ((const void *) gsasl_simple_getpass);
  assert_symbol_exists ((const void *) gsasl_step64);
  assert_symbol_exists ((const void *) gsasl_step);
  assert_symbol_exists ((const void *) gsasl_strerror);
  assert_symbol_exists ((const void *) gsasl_strerror_name);

#ifndef GSASL_NO_OBSOLETE
  /* LIBGSASL_1.1: Old interfaces */
  assert_symbol_exists ((const void *) gsasl_appinfo_get);
  assert_symbol_exists ((const void *) gsasl_appinfo_set);
  assert_symbol_exists ((const void *) gsasl_application_data_get);
  assert_symbol_exists ((const void *) gsasl_application_data_set);
  assert_symbol_exists ((const void *) gsasl_base64_decode);
  assert_symbol_exists ((const void *) gsasl_base64_encode);
  assert_symbol_exists ((const void *) gsasl_client_application_data_get);
  assert_symbol_exists ((const void *) gsasl_client_application_data_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_anonymous_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_anonymous_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_authentication_id_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_authentication_id_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_authorization_id_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_authorization_id_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_maxbuf_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_maxbuf_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_passcode_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_passcode_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_password_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_password_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_pin_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_pin_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_qop_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_qop_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_realm_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_realm_set);
  assert_symbol_exists ((const void *) gsasl_client_callback_service_get);
  assert_symbol_exists ((const void *) gsasl_client_callback_service_set);
  assert_symbol_exists ((const void *) gsasl_client_ctx_get);
  assert_symbol_exists ((const void *) gsasl_client_finish);
  assert_symbol_exists ((const void *) gsasl_client_listmech);
  assert_symbol_exists ((const void *) gsasl_client_step);
  assert_symbol_exists ((const void *) gsasl_client_step_base64);
  assert_symbol_exists ((const void *) gsasl_ctx_get);
  assert_symbol_exists ((const void *) gsasl_decode_inline);
  assert_symbol_exists ((const void *) gsasl_encode_inline);
  assert_symbol_exists ((const void *) gsasl_md5pwd_get_password);
  assert_symbol_exists ((const void *) gsasl_randomize);
  assert_symbol_exists ((const void *) gsasl_server_application_data_get);
  assert_symbol_exists ((const void *) gsasl_server_application_data_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_anonymous_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_anonymous_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_cipher_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_cipher_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_cram_md5_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_cram_md5_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_digest_md5_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_digest_md5_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_external_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_external_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_gssapi_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_gssapi_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_maxbuf_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_maxbuf_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_qop_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_qop_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_realm_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_realm_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_retrieve_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_retrieve_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_securid_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_securid_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_service_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_service_set);
  assert_symbol_exists ((const void *) gsasl_server_callback_validate_get);
  assert_symbol_exists ((const void *) gsasl_server_callback_validate_set);
  assert_symbol_exists ((const void *) gsasl_server_ctx_get);
  assert_symbol_exists ((const void *) gsasl_server_finish);
  assert_symbol_exists ((const void *) gsasl_server_listmech);
  assert_symbol_exists ((const void *) gsasl_server_step);
  assert_symbol_exists ((const void *) gsasl_server_step_base64);
  assert_symbol_exists ((const void *) gsasl_server_suggest_mechanism);
  assert_symbol_exists ((const void *) gsasl_stringprep_nfkc);
  assert_symbol_exists ((const void *) gsasl_stringprep_saslprep);
  assert_symbol_exists ((const void *) gsasl_stringprep_trace);
#endif

  /* LIBGSASL_1.4 */
  assert_symbol_exists ((const void *) gsasl_sha1);
  assert_symbol_exists ((const void *) gsasl_hmac_sha1);

  return 0;
}
