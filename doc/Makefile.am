## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004 Simon Josefsson.
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

if ENABLE_GTK_DOC
SUBDIRS = reference
endif

EXTRA_DIST = gdoc gdoc-error \
	controlflow.dia controlflow2.dia abstraction.dia \
	gsasl.html gsasl.ps gsasl.pdf texinfo.css \
	doxygen/Doxyfile.in doxygen/gdoc2doxygen

.dia.png:
	dia --export=$@ --export-to-format=png $<

.dia.eps:
	dia --export=$@ --export-to-format=eps $<

.eps.pdf:
	epstopdf $<

info_TEXINFOS = gsasl.texi
gsasl_TEXINFOS = fdl.texi $(gdoc_TEXINFOS) \
	controlflow.eps controlflow.png controlflow.pdf \
	controlflow2.eps controlflow2.png controlflow2.pdf \
	abstraction.eps abstraction.png abstraction.pdf \
	gsasl-callback-password.texi gsasl-callback-authorization.texi \
	gsasl-callback-authentication.texi gsasl-callback-validate.texi \
	gsasl-callback-retrieve.texi gsasl-callback-cram-md5.texi \
	gsasl-callback-digest-md5.texi gsasl-callback-passcode.texi \
	gsasl-callback-gssapi.texi gsasl-callback-securid.texi \
	gsasl-callback-client-service.texi gsasl-callback-server-service.texi \
	gsasl-api-error-labels.texi

gsasl-api-error-labels.texi: $(top_srcdir)/lib/src/error.c
	$(PERL) $(srcdir)/gdoc-error $^ > $@

AM_MAKEINFOHTMLFLAGS = --no-split --number-sections --css-include=texinfo.css

dist_man_MANS = gsasl.1 $(gdoc_MANS)
MAINTAINERCLEANFILES = $(dist_man_MANS)

gsasl.1: $(top_srcdir)/src/gsasl.c $(top_srcdir)/src/gsasl.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="SASL library command line interface" \
		--output=$@ $(top_builddir)/src/gsasl

gdoc_MANS = man/gsasl_callback_set.3 man/gsasl_callback.3 man/gsasl_callback_hook_set.3 man/gsasl_callback_hook_get.3 man/gsasl_nonce.3 man/gsasl_random.3 man/gsasl_md5.3 man/gsasl_hmac_md5.3 man/gsasl_done.3 man/gsasl_strerror.3 man/gsasl_init.3 man/gsasl_client_mechlist.3 man/gsasl_server_mechlist.3 man/gsasl_md5pwd_get_password.3 man/gsasl_client_listmech.3 man/gsasl_server_listmech.3 man/gsasl_client_step.3 man/gsasl_server_step.3 man/gsasl_client_step_base64.3 man/gsasl_server_step_base64.3 man/gsasl_client_finish.3 man/gsasl_server_finish.3 man/gsasl_client_ctx_get.3 man/gsasl_client_application_data_set.3 man/gsasl_client_application_data_get.3 man/gsasl_server_ctx_get.3 man/gsasl_server_application_data_set.3 man/gsasl_server_application_data_get.3 man/gsasl_randomize.3 man/gsasl_ctx_get.3 man/gsasl_encode_inline.3 man/gsasl_decode_inline.3 man/gsasl_application_data_set.3 man/gsasl_application_data_get.3 man/gsasl_appinfo_set.3 man/gsasl_appinfo_get.3 man/gsasl_server_suggest_mechanism.3 man/gsasl_client_callback_authentication_id_set.3 man/gsasl_client_callback_authentication_id_get.3 man/gsasl_client_callback_authorization_id_set.3 man/gsasl_client_callback_authorization_id_get.3 man/gsasl_client_callback_password_set.3 man/gsasl_client_callback_password_get.3 man/gsasl_client_callback_passcode_set.3 man/gsasl_client_callback_passcode_get.3 man/gsasl_client_callback_pin_set.3 man/gsasl_client_callback_pin_get.3 man/gsasl_client_callback_service_set.3 man/gsasl_client_callback_service_get.3 man/gsasl_client_callback_anonymous_set.3 man/gsasl_client_callback_anonymous_get.3 man/gsasl_client_callback_qop_set.3 man/gsasl_client_callback_qop_get.3 man/gsasl_client_callback_maxbuf_set.3 man/gsasl_client_callback_maxbuf_get.3 man/gsasl_client_callback_realm_set.3 man/gsasl_client_callback_realm_get.3 man/gsasl_server_callback_validate_set.3 man/gsasl_server_callback_validate_get.3 man/gsasl_server_callback_retrieve_set.3 man/gsasl_server_callback_retrieve_get.3 man/gsasl_server_callback_cram_md5_set.3 man/gsasl_server_callback_cram_md5_get.3 man/gsasl_server_callback_digest_md5_set.3 man/gsasl_server_callback_digest_md5_get.3 man/gsasl_server_callback_external_set.3 man/gsasl_server_callback_external_get.3 man/gsasl_server_callback_anonymous_set.3 man/gsasl_server_callback_anonymous_get.3 man/gsasl_server_callback_realm_set.3 man/gsasl_server_callback_realm_get.3 man/gsasl_server_callback_qop_set.3 man/gsasl_server_callback_qop_get.3 man/gsasl_server_callback_maxbuf_set.3 man/gsasl_server_callback_maxbuf_get.3 man/gsasl_server_callback_cipher_set.3 man/gsasl_server_callback_cipher_get.3 man/gsasl_server_callback_securid_set.3 man/gsasl_server_callback_securid_get.3 man/gsasl_server_callback_gssapi_set.3 man/gsasl_server_callback_gssapi_get.3 man/gsasl_server_callback_service_set.3 man/gsasl_server_callback_service_get.3 man/gsasl_base64_encode.3 man/gsasl_base64_decode.3 man/gsasl_property_set.3 man/gsasl_property_set_raw.3 man/gsasl_property_fast.3 man/gsasl_property_get.3 man/gsasl_register.3 man/gsasl_stringprep_nfkc.3 man/gsasl_stringprep_saslprep.3 man/gsasl_stringprep_trace.3 man/gsasl_client_suggest_mechanism.3 man/gsasl_client_support_p.3 man/gsasl_server_support_p.3 man/gsasl_check_version.3 man/gsasl_encode.3 man/gsasl_decode.3 man/gsasl_finish.3 man/gsasl_client_start.3 man/gsasl_server_start.3 man/gsasl_step.3 man/gsasl_step64.3
gdoc_TEXINFOS = texi/base64.c.texi texi/callback.c.texi texi/crypto.c.texi texi/done.c.texi texi/error.c.texi texi/init.c.texi texi/listmech.c.texi texi/md5pwd.c.texi texi/obsolete.c.texi texi/property.c.texi texi/register.c.texi texi/stringprep.c.texi texi/stringprep-no.c.texi texi/suggest.c.texi texi/supportp.c.texi texi/version.c.texi texi/xcode.c.texi texi/xfinish.c.texi texi/xstart.c.texi texi/xstep.c.texi texi/gsasl_callback_set.texi texi/gsasl_callback.texi texi/gsasl_callback_hook_set.texi texi/gsasl_callback_hook_get.texi texi/gsasl_nonce.texi texi/gsasl_random.texi texi/gsasl_md5.texi texi/gsasl_hmac_md5.texi texi/gsasl_done.texi texi/gsasl_strerror.texi texi/gsasl_init.texi texi/gsasl_client_mechlist.texi texi/gsasl_server_mechlist.texi texi/gsasl_md5pwd_get_password.texi texi/gsasl_client_listmech.texi texi/gsasl_server_listmech.texi texi/gsasl_client_step.texi texi/gsasl_server_step.texi texi/gsasl_client_step_base64.texi texi/gsasl_server_step_base64.texi texi/gsasl_client_finish.texi texi/gsasl_server_finish.texi texi/gsasl_client_ctx_get.texi texi/gsasl_client_application_data_set.texi texi/gsasl_client_application_data_get.texi texi/gsasl_server_ctx_get.texi texi/gsasl_server_application_data_set.texi texi/gsasl_server_application_data_get.texi texi/gsasl_randomize.texi texi/gsasl_ctx_get.texi texi/gsasl_encode_inline.texi texi/gsasl_decode_inline.texi texi/gsasl_application_data_set.texi texi/gsasl_application_data_get.texi texi/gsasl_appinfo_set.texi texi/gsasl_appinfo_get.texi texi/gsasl_server_suggest_mechanism.texi texi/gsasl_client_callback_authentication_id_set.texi texi/gsasl_client_callback_authentication_id_get.texi texi/gsasl_client_callback_authorization_id_set.texi texi/gsasl_client_callback_authorization_id_get.texi texi/gsasl_client_callback_password_set.texi texi/gsasl_client_callback_password_get.texi texi/gsasl_client_callback_passcode_set.texi texi/gsasl_client_callback_passcode_get.texi texi/gsasl_client_callback_pin_set.texi texi/gsasl_client_callback_pin_get.texi texi/gsasl_client_callback_service_set.texi texi/gsasl_client_callback_service_get.texi texi/gsasl_client_callback_anonymous_set.texi texi/gsasl_client_callback_anonymous_get.texi texi/gsasl_client_callback_qop_set.texi texi/gsasl_client_callback_qop_get.texi texi/gsasl_client_callback_maxbuf_set.texi texi/gsasl_client_callback_maxbuf_get.texi texi/gsasl_client_callback_realm_set.texi texi/gsasl_client_callback_realm_get.texi texi/gsasl_server_callback_validate_set.texi texi/gsasl_server_callback_validate_get.texi texi/gsasl_server_callback_retrieve_set.texi texi/gsasl_server_callback_retrieve_get.texi texi/gsasl_server_callback_cram_md5_set.texi texi/gsasl_server_callback_cram_md5_get.texi texi/gsasl_server_callback_digest_md5_set.texi texi/gsasl_server_callback_digest_md5_get.texi texi/gsasl_server_callback_external_set.texi texi/gsasl_server_callback_external_get.texi texi/gsasl_server_callback_anonymous_set.texi texi/gsasl_server_callback_anonymous_get.texi texi/gsasl_server_callback_realm_set.texi texi/gsasl_server_callback_realm_get.texi texi/gsasl_server_callback_qop_set.texi texi/gsasl_server_callback_qop_get.texi texi/gsasl_server_callback_maxbuf_set.texi texi/gsasl_server_callback_maxbuf_get.texi texi/gsasl_server_callback_cipher_set.texi texi/gsasl_server_callback_cipher_get.texi texi/gsasl_server_callback_securid_set.texi texi/gsasl_server_callback_securid_get.texi texi/gsasl_server_callback_gssapi_set.texi texi/gsasl_server_callback_gssapi_get.texi texi/gsasl_server_callback_service_set.texi texi/gsasl_server_callback_service_get.texi texi/gsasl_base64_encode.texi texi/gsasl_base64_decode.texi texi/gsasl_property_set.texi texi/gsasl_property_set_raw.texi texi/gsasl_property_fast.texi texi/gsasl_property_get.texi texi/gsasl_register.texi texi/gsasl_stringprep_nfkc.texi texi/gsasl_stringprep_saslprep.texi texi/gsasl_stringprep_trace.texi texi/gsasl_client_suggest_mechanism.texi texi/gsasl_client_support_p.texi texi/gsasl_server_support_p.texi texi/gsasl_check_version.texi texi/gsasl_encode.texi texi/gsasl_decode.texi texi/gsasl_finish.texi texi/gsasl_client_start.texi texi/gsasl_server_start.texi texi/gsasl_step.texi texi/gsasl_step64.texi

$(gdoc_MANS) $(gdoc_TEXINFOS):
	make update-makefile
	make Makefile
	make doit

GDOC_SRC = $(top_srcdir)/lib/src/*.c

update-makefile:
	@MANS=""; \
	TEXINFOS=""; \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		TEXINFOS="$$TEXINFOS texi/$$BASE.texi"; \
	done; \
	FUNCS=`./gdoc -listfunc $(GDOC_SRC)`; \
	for i in $$FUNCS; do \
		MANS="$$MANS man/$$i.3"; \
		TEXINFOS="$$TEXINFOS texi/$$i.texi"; \
	done; \
	perl -pi -e "s,^gdoc_MANS =.*,gdoc_MANS =$$MANS,;" \
		-e "s,^gdoc_TEXINFOS =.*,gdoc_TEXINFOS =$$TEXINFOS,;" \
		Makefile.am

doit:
	@$(mkdir_p) man texi; \
	for i in `./gdoc -listfunc $(GDOC_SRC)`; do \
		echo -n "Creating documentation for $$i... " && \
		./gdoc -man \
			-module $(PACKAGE) -sourceversion $(VERSION) \
			-bugsto $(PACKAGE_BUGREPORT) \
			-includefuncprefix \
			-seeinfo $(PACKAGE) -verbatimcopying \
			-copyright "2002, 2003, 2004 Simon Josefsson" \
			-function $$i \
			$(GDOC_SRC) > man/$$i.3 && \
		./gdoc -texinfo -function $$i \
			$(GDOC_SRC) > texi/$$i.texi && \
		echo "ok"; \
	done; \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		echo -n "Creating documentation for $$i... " && \
		./gdoc -texinfo $$i > texi/$$BASE.texi && \
		echo "ok"; \
	done

.PHONY: update-makefile doit
