/* common.c --- Static variables.
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
 * You should have received a copy of the GNU Lesser General Public License
 * License along with GNU SASL Library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "cram-md5/cram-md5.h"
#include "external/external.h"
#include "gssapi/x-gssapi.h"
#include "anonymous/anonymous.h"
#include "plain/plain.h"
#include "securid/securid.h"
#include "digest-md5/digest-md5.h"

#include "login/login.h"
#include "ntlm/x-ntlm.h"
#include "kerberos_v5/kerberos_v5.h"

const char *GSASL_VALID_MECHANISM_CHARACTERS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

Gsasl_mechanism *_gsasl_all_mechanisms[] = {
#ifdef USE_ANONYMOUS
  &gsasl_anonymous_mechanism,
#endif /* USE_ANONYMOUS */

#ifdef USE_EXTERNAL
  &gsasl_external_mechanism,
#endif /* USE_EXTERNAL */

#ifdef USE_PLAIN
  &gsasl_plain_mechanism,
#endif /* USE_PLAIN */

#ifdef USE_LOGIN
  &gsasl_login_mechanism,
#endif /* USE_LOGIN */

#ifdef USE_SECURID
  &gsasl_securid_mechanism,
#endif /* USE_SECURID */

#ifdef USE_NTLM
  &gsasl_ntlm_mechanism,
#endif /* USE_NTLM */

#ifdef USE_CRAM_MD5
  &gsasl_cram_md5_mechanism,
#endif /* USE_CRAM_MD5 */

#ifdef USE_DIGEST_MD5
  &gsasl_digest_md5_mechanism,
#endif /* USE_DIGEST_MD5 */

#ifdef USE_GSSAPI
  &gsasl_gssapi_mechanism,
#endif /* USE_GSSAPI */

  NULL
};
