/* common.c	static variables
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

_Gsasl_mechanism _gsasl_all_mechanisms[] = {
#ifdef USE_ANONYMOUS
  {_GSASL_ANONYMOUS_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_anonymous_client_init,
    _gsasl_anonymous_client_done,
    _gsasl_anonymous_client_start,
    _gsasl_anonymous_client_step,
    _gsasl_anonymous_client_finish,
    NULL,
    NULL
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_anonymous_server_init,
    _gsasl_anonymous_server_done,
    _gsasl_anonymous_server_start,
    _gsasl_anonymous_server_step,
    _gsasl_anonymous_server_finish,
    NULL,
    NULL
#endif
    }
   },
#endif /* USE_ANONYMOUS */

#ifdef USE_EXTERNAL
  {_GSASL_EXTERNAL_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_external_client_init,
    _gsasl_external_client_done,
    _gsasl_external_client_start,
    _gsasl_external_client_step,
    _gsasl_external_client_finish,
    NULL,
    NULL
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_external_server_init,
    _gsasl_external_server_done,
    _gsasl_external_server_start,
    _gsasl_external_server_step,
    _gsasl_external_server_finish,
    NULL,
    NULL
#endif
    }
   },
#endif /* USE_EXTERNAL */

#ifdef USE_PLAIN
  {_GSASL_PLAIN_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_plain_client_init,
    _gsasl_plain_client_done,
    _gsasl_plain_client_start,
    _gsasl_plain_client_step,
    _gsasl_plain_client_finish,
    NULL,
    NULL
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_plain_server_init,
    _gsasl_plain_server_done,
    _gsasl_plain_server_start,
    _gsasl_plain_server_step,
    _gsasl_plain_server_finish,
    NULL,
    NULL
#endif
    }
   },
#endif /* USE_PLAIN */

#ifdef USE_LOGIN
  {_GSASL_LOGIN_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_login_client_init,
    _gsasl_login_client_done,
    _gsasl_login_client_start,
    _gsasl_login_client_step,
    _gsasl_login_client_finish,
    NULL,
    NULL
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_login_server_init,
    _gsasl_login_server_done,
    _gsasl_login_server_start,
    _gsasl_login_server_step,
    _gsasl_login_server_finish,
    NULL,
    NULL
#endif
    }
   },
#endif /* USE_LOGIN */

#ifdef USE_SECURID
  {_GSASL_SECURID_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_securid_client_init,
    _gsasl_securid_client_done,
    _gsasl_securid_client_start,
    _gsasl_securid_client_step,
    _gsasl_securid_client_finish,
    NULL,
    NULL
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_securid_server_init,
    _gsasl_securid_server_done,
    _gsasl_securid_server_start,
    _gsasl_securid_server_step,
    _gsasl_securid_server_finish,
    NULL,
    NULL
#endif
    }
   },
#endif /* USE_SECURID */

#ifdef USE_NTLM
  {_GSASL_NTLM_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_ntlm_client_init,
    _gsasl_ntlm_client_done,
    _gsasl_ntlm_client_start,
    _gsasl_ntlm_client_step,
    _gsasl_ntlm_client_finish,
    NULL,
    NULL
#endif
    },
   {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL}
   },
#endif /* USE_NTLM */

#ifdef USE_CRAM_MD5
  {_GSASL_CRAM_MD5_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_cram_md5_client_init,
    _gsasl_cram_md5_client_done,
    _gsasl_cram_md5_client_start,
    _gsasl_cram_md5_client_step,
    _gsasl_cram_md5_client_finish,
    NULL,
    NULL
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_cram_md5_server_init,
    _gsasl_cram_md5_server_done,
    _gsasl_cram_md5_server_start,
    _gsasl_cram_md5_server_step,
    _gsasl_cram_md5_server_finish,
    NULL,
    NULL
#endif
    }
   },
#endif /* USE_CRAM_MD5 */

#ifdef USE_DIGEST_MD5
  {_GSASL_DIGEST_MD5_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_digest_md5_client_init,
    _gsasl_digest_md5_client_done,
    _gsasl_digest_md5_client_start,
    _gsasl_digest_md5_client_step,
    _gsasl_digest_md5_client_finish,
    _gsasl_digest_md5_client_encode,
    _gsasl_digest_md5_client_decode
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_digest_md5_server_init,
    _gsasl_digest_md5_server_done,
    _gsasl_digest_md5_server_start,
    _gsasl_digest_md5_server_step,
    _gsasl_digest_md5_server_finish,
    _gsasl_digest_md5_server_encode,
    _gsasl_digest_md5_server_decode
#endif
    }
   },
#endif /* USE_DIGEST_MD5 */

#if USE_KERBEROS_V5
  {_GSASL_KERBEROS_V5_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_kerberos_v5_client_init,
    _gsasl_kerberos_v5_client_done,
    _gsasl_kerberos_v5_client_start,
    _gsasl_kerberos_v5_client_step,
    _gsasl_kerberos_v5_client_finish,
    _gsasl_kerberos_v5_client_encode,
    _gsasl_kerberos_v5_client_decode
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_kerberos_v5_server_init,
    _gsasl_kerberos_v5_server_done,
    _gsasl_kerberos_v5_server_start,
    _gsasl_kerberos_v5_server_step,
    _gsasl_kerberos_v5_server_finish,
    _gsasl_kerberos_v5_server_encode,
    _gsasl_kerberos_v5_server_decode
#endif
    }
   },
#endif /* USE_KERBEROS_V5 */

#if USE_GSSAPI
  {_GSASL_GSSAPI_NAME,
   {
#ifdef USE_CLIENT
    _gsasl_gssapi_client_init,
    _gsasl_gssapi_client_done,
    _gsasl_gssapi_client_start,
    _gsasl_gssapi_client_step,
    _gsasl_gssapi_client_finish,
    NULL,
    NULL
#endif
    },
   {
#ifdef USE_SERVER
    _gsasl_gssapi_server_init,
    _gsasl_gssapi_server_done,
    _gsasl_gssapi_server_start,
    _gsasl_gssapi_server_step,
    _gsasl_gssapi_server_finish,
    NULL,
    NULL
#endif
    }
   },
#endif /* USE_GSSAPI */
  {NULL,
   {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL},
   {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL}
   }
};
