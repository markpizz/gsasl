## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003 Simon Josefsson.
#
# This file is part of GNU SASL.
#
# GNU SASL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GNU SASL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU SASL; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

apis = gsasl_base64_encode.3 gsasl_base64_decode.3 gsasl_client_ctx_get.3 gsasl_client_application_data_set.3 gsasl_client_application_data_get.3 gsasl_client_callback_authentication_id_set.3 gsasl_client_callback_authentication_id_get.3 gsasl_client_callback_authorization_id_set.3 gsasl_client_callback_authorization_id_get.3 gsasl_client_callback_password_set.3 gsasl_client_callback_password_get.3 gsasl_client_callback_passcode_set.3 gsasl_client_callback_passcode_get.3 gsasl_client_callback_pin_set.3 gsasl_client_callback_pin_get.3 gsasl_client_callback_service_set.3 gsasl_client_callback_service_get.3 gsasl_client_callback_anonymous_set.3 gsasl_client_callback_anonymous_get.3 gsasl_client_callback_qop_set.3 gsasl_client_callback_qop_get.3 gsasl_client_callback_maxbuf_set.3 gsasl_client_callback_maxbuf_get.3 gsasl_client_callback_realm_set.3 gsasl_client_callback_realm_get.3 gsasl_server_ctx_get.3 gsasl_server_application_data_set.3 gsasl_server_application_data_get.3 gsasl_server_callback_validate_set.3 gsasl_server_callback_validate_get.3 gsasl_server_callback_retrieve_set.3 gsasl_server_callback_retrieve_get.3 gsasl_server_callback_cram_md5_set.3 gsasl_server_callback_cram_md5_get.3 gsasl_server_callback_digest_md5_set.3 gsasl_server_callback_digest_md5_get.3 gsasl_server_callback_external_set.3 gsasl_server_callback_external_get.3 gsasl_server_callback_anonymous_set.3 gsasl_server_callback_anonymous_get.3 gsasl_server_callback_realm_set.3 gsasl_server_callback_realm_get.3 gsasl_server_callback_qop_set.3 gsasl_server_callback_qop_get.3 gsasl_server_callback_maxbuf_set.3 gsasl_server_callback_maxbuf_get.3 gsasl_server_callback_cipher_set.3 gsasl_server_callback_cipher_get.3 gsasl_server_callback_securid_set.3 gsasl_server_callback_securid_get.3 gsasl_server_callback_gssapi_set.3 gsasl_server_callback_gssapi_get.3 gsasl_server_callback_service_set.3 gsasl_server_callback_service_get.3 gsasl_application_data_set.3 gsasl_application_data_get.3 gsasl_done.3 gsasl_strerror.3 gsasl_hexdump.3 gsasl_init.3 gsasl_client_mechlist.3 gsasl_server_mechlist.3 gsasl_md5pwd_get_password.3 gsasl_client_listmech.3 gsasl_server_listmech.3 gsasl_stringprep_nfkc.3 gsasl_stringprep_saslprep.3 gsasl_stringprep_trace.3 gsasl_client_suggest_mechanism.3 gsasl_server_suggest_mechanism.3 gsasl_client_support_p.3 gsasl_server_support_p.3 gsasl_check_version.3 gsasl_encode.3 gsasl_decode.3 gsasl_client_finish.3 gsasl_server_finish.3 gsasl_client_start.3 gsasl_server_start.3 gsasl_client_step.3 gsasl_client_step_base64.3 gsasl_server_step.3 gsasl_server_step_base64.3

dist_man_MANS = gsasl.1 $(apis)

DISTCLEANFILES = $(dist_man_MANS)

gsasl.1: $(top_srcdir)/src/gsasl.c $(top_builddir)/src/gsasl
	$(HELP2MAN) \
		--name="SASL library command line interface" \
		--help-option="--program-name gsasl --help" \
		--output=$@ $(top_builddir)/src/gsasl

$(apis):
	(files=`echo $(top_srcdir)/lib/*.c`; \
	for file in $$files; do \
		apis=`$(PERL) $(top_srcdir)/doc/gdoc -listfunc $$file`; \
		for api in $$apis; do \
			echo "-- Creating man page for $$api" ; \
			$(PERL) $(top_srcdir)/doc/gdoc -module $(PACKAGE) \
				-man -function $$api $$file > $$api.3 ; \
		done; \
	done)

# Maintainer targets

.PHONY: update-api
update-api:
	(apis=`$(PERL) $(top_srcdir)/doc/gdoc -listfunc \
			$(top_srcdir)/lib/*.c | \
		sed 's/$$/.3/g'`; \
	apis=`echo $$apis`; \
	perl -pi -e "s/^apis = .*/apis = $$apis/" Makefile.am)
