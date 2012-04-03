/* mechinfo.c --- Definition of SCRAM mechanism.
 * Copyright (C) 2009-2012 Simon Josefsson
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
#include "config.h"
#endif

/* Get specification. */
#include "scram.h"

#ifdef USE_SCRAM_SHA1
Gsasl_mechanism gsasl_scram_sha1_mechanism = {
  GSASL_SCRAM_SHA1_NAME,
  {
   NULL,
   NULL,
#ifdef USE_CLIENT
   _gsasl_scram_sha1_client_start,
   _gsasl_scram_sha1_client_step,
   _gsasl_scram_sha1_client_finish,
#else
   NULL,
   NULL,
   NULL,
#endif
   NULL,
   NULL}
  ,
  {
   NULL,
   NULL,
#ifdef USE_SERVER
   _gsasl_scram_sha1_server_start,
   _gsasl_scram_sha1_server_step,
   _gsasl_scram_sha1_server_finish,
#else
   NULL,
   NULL,
   NULL,
#endif
   NULL,
   NULL}
};
#endif


#ifdef USE_SCRAM_SHA1
Gsasl_mechanism gsasl_scram_sha1_plus_mechanism = {
  GSASL_SCRAM_SHA1_PLUS_NAME,
  {
   NULL,
   NULL,
#ifdef USE_CLIENT
   _gsasl_scram_sha1_plus_client_start,
   _gsasl_scram_sha1_client_step,
   _gsasl_scram_sha1_client_finish,
#else
   NULL,
   NULL,
   NULL,
#endif
   NULL,
   NULL}
  ,
  {
   NULL,
   NULL,
#ifdef USE_SERVER
   _gsasl_scram_sha1_plus_server_start,
   _gsasl_scram_sha1_server_step,
   _gsasl_scram_sha1_server_finish,
#else
   NULL,
   NULL,
   NULL,
#endif
   NULL,
   NULL}
};
#endif
