## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
#
# This file is part of GNU SASL.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SUBDIRS = cyclo
if ENABLE_GTK_DOC
SUBDIRS += reference
endif

EXTRA_DIST = gdoc \
	controlflow.dia controlflow2.dia abstraction.dia \
	gsasl.html gsasl.ps gsasl.pdf texinfo.css \
	doxygen/Doxyfile.in doxygen/gdoc2doxygen

.dia.png:
	$(DIA) --export=$@ --export-to-format=png $<

.dia.eps:
	$(DIA) --export=$@ --export-to-format=eps $<

.eps.pdf:
	$(EPSTOPDF) $<

info_TEXINFOS = gsasl.texi
gsasl_TEXINFOS = fdl.texi gpl-3.0.texi lgpl-2.1.texi $(gdoc_TEXINFOS) \
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

AM_CPPFLAGS = -I$(top_srcdir)/lib/src
noinst_PROGRAMS = print-errors
print_errors_LDADD = ../lib/src/libgsasl.la

gsasl-api-error-labels.texi: $(top_srcdir)/lib/src/error.c print-errors.c
	make print-errors$(EXEEXT)
	$(builddir)/print-errors$(EXEEXT) > $@.new
	mv $@.new $@

AM_MAKEINFOFLAGS = -I $(top_srcdir)/doc \
	-I $(top_builddir)/doc -I $(top_srcdir)/examples
TEXI2DVI = texi2dvi $(AM_MAKEINFOFLAGS)
AM_MAKEINFOHTMLFLAGS = $(AM_MAKEINFOFLAGS) \
	--no-split --number-sections --css-include=texinfo.css

dist_man_MANS = gsasl.1 $(gdoc_MANS)
MAINTAINERCLEANFILES = $(dist_man_MANS)

gsasl.1: $(top_srcdir)/src/gsasl.c $(top_srcdir)/src/gsasl.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="SASL library command line interface" \
		--output=$@ $(top_builddir)/src/gsasl$(EXEEXT)

gdoc_MANS =
gdoc_MANS += man/gsasl_base64_to.3
gdoc_MANS += man/gsasl_base64_from.3
gdoc_MANS += man/gsasl_callback_set.3
gdoc_MANS += man/gsasl_callback.3
gdoc_MANS += man/gsasl_callback_hook_set.3
gdoc_MANS += man/gsasl_callback_hook_get.3
gdoc_MANS += man/gsasl_session_hook_set.3
gdoc_MANS += man/gsasl_session_hook_get.3
gdoc_MANS += man/gsasl_nonce.3
gdoc_MANS += man/gsasl_random.3
gdoc_MANS += man/gsasl_md5.3
gdoc_MANS += man/gsasl_hmac_md5.3
gdoc_MANS += man/gsasl_done.3
gdoc_MANS += man/gsasl_strerror.3
gdoc_MANS += man/gsasl_strerror_name.3
gdoc_MANS += man/gsasl_free.3
gdoc_MANS += man/gsasl_init.3
gdoc_MANS += man/gsasl_client_mechlist.3
gdoc_MANS += man/gsasl_server_mechlist.3
gdoc_MANS += man/gsasl_simple_getpass.3
gdoc_MANS += man/gsasl_mechanism_name.3
gdoc_MANS += man/gsasl_client_listmech.3
gdoc_MANS += man/gsasl_server_listmech.3
gdoc_MANS += man/gsasl_client_step.3
gdoc_MANS += man/gsasl_server_step.3
gdoc_MANS += man/gsasl_client_step_base64.3
gdoc_MANS += man/gsasl_server_step_base64.3
gdoc_MANS += man/gsasl_client_finish.3
gdoc_MANS += man/gsasl_server_finish.3
gdoc_MANS += man/gsasl_client_ctx_get.3
gdoc_MANS += man/gsasl_client_application_data_set.3
gdoc_MANS += man/gsasl_client_application_data_get.3
gdoc_MANS += man/gsasl_server_ctx_get.3
gdoc_MANS += man/gsasl_server_application_data_set.3
gdoc_MANS += man/gsasl_server_application_data_get.3
gdoc_MANS += man/gsasl_randomize.3
gdoc_MANS += man/gsasl_ctx_get.3
gdoc_MANS += man/gsasl_encode_inline.3
gdoc_MANS += man/gsasl_decode_inline.3
gdoc_MANS += man/gsasl_application_data_set.3
gdoc_MANS += man/gsasl_application_data_get.3
gdoc_MANS += man/gsasl_appinfo_set.3
gdoc_MANS += man/gsasl_appinfo_get.3
gdoc_MANS += man/gsasl_server_suggest_mechanism.3
gdoc_MANS += man/gsasl_client_callback_authentication_id_set.3
gdoc_MANS += man/gsasl_client_callback_authentication_id_get.3
gdoc_MANS += man/gsasl_client_callback_authorization_id_set.3
gdoc_MANS += man/gsasl_client_callback_authorization_id_get.3
gdoc_MANS += man/gsasl_client_callback_password_set.3
gdoc_MANS += man/gsasl_client_callback_password_get.3
gdoc_MANS += man/gsasl_client_callback_passcode_set.3
gdoc_MANS += man/gsasl_client_callback_passcode_get.3
gdoc_MANS += man/gsasl_client_callback_pin_set.3
gdoc_MANS += man/gsasl_client_callback_pin_get.3
gdoc_MANS += man/gsasl_client_callback_service_set.3
gdoc_MANS += man/gsasl_client_callback_service_get.3
gdoc_MANS += man/gsasl_client_callback_anonymous_set.3
gdoc_MANS += man/gsasl_client_callback_anonymous_get.3
gdoc_MANS += man/gsasl_client_callback_qop_set.3
gdoc_MANS += man/gsasl_client_callback_qop_get.3
gdoc_MANS += man/gsasl_client_callback_maxbuf_set.3
gdoc_MANS += man/gsasl_client_callback_maxbuf_get.3
gdoc_MANS += man/gsasl_client_callback_realm_set.3
gdoc_MANS += man/gsasl_client_callback_realm_get.3
gdoc_MANS += man/gsasl_server_callback_validate_set.3
gdoc_MANS += man/gsasl_server_callback_validate_get.3
gdoc_MANS += man/gsasl_server_callback_retrieve_set.3
gdoc_MANS += man/gsasl_server_callback_retrieve_get.3
gdoc_MANS += man/gsasl_server_callback_cram_md5_set.3
gdoc_MANS += man/gsasl_server_callback_cram_md5_get.3
gdoc_MANS += man/gsasl_server_callback_digest_md5_set.3
gdoc_MANS += man/gsasl_server_callback_digest_md5_get.3
gdoc_MANS += man/gsasl_server_callback_external_set.3
gdoc_MANS += man/gsasl_server_callback_external_get.3
gdoc_MANS += man/gsasl_server_callback_anonymous_set.3
gdoc_MANS += man/gsasl_server_callback_anonymous_get.3
gdoc_MANS += man/gsasl_server_callback_realm_set.3
gdoc_MANS += man/gsasl_server_callback_realm_get.3
gdoc_MANS += man/gsasl_server_callback_qop_set.3
gdoc_MANS += man/gsasl_server_callback_qop_get.3
gdoc_MANS += man/gsasl_server_callback_maxbuf_set.3
gdoc_MANS += man/gsasl_server_callback_maxbuf_get.3
gdoc_MANS += man/gsasl_server_callback_cipher_set.3
gdoc_MANS += man/gsasl_server_callback_cipher_get.3
gdoc_MANS += man/gsasl_server_callback_securid_set.3
gdoc_MANS += man/gsasl_server_callback_securid_get.3
gdoc_MANS += man/gsasl_server_callback_gssapi_set.3
gdoc_MANS += man/gsasl_server_callback_gssapi_get.3
gdoc_MANS += man/gsasl_server_callback_service_set.3
gdoc_MANS += man/gsasl_server_callback_service_get.3
gdoc_MANS += man/gsasl_stringprep_nfkc.3
gdoc_MANS += man/gsasl_stringprep_saslprep.3
gdoc_MANS += man/gsasl_stringprep_trace.3
gdoc_MANS += man/gsasl_md5pwd_get_password.3
gdoc_MANS += man/gsasl_base64_encode.3
gdoc_MANS += man/gsasl_base64_decode.3
gdoc_MANS += man/gsasl_property_set.3
gdoc_MANS += man/gsasl_property_set_raw.3
gdoc_MANS += man/gsasl_property_fast.3
gdoc_MANS += man/gsasl_property_get.3
gdoc_MANS += man/gsasl_register.3
gdoc_MANS += man/gsasl_saslprep.3
gdoc_MANS += man/gsasl_client_suggest_mechanism.3
gdoc_MANS += man/gsasl_client_support_p.3
gdoc_MANS += man/gsasl_server_support_p.3
gdoc_MANS += man/gsasl_check_version.3
gdoc_MANS += man/gsasl_encode.3
gdoc_MANS += man/gsasl_decode.3
gdoc_MANS += man/gsasl_finish.3
gdoc_MANS += man/gsasl_client_start.3
gdoc_MANS += man/gsasl_server_start.3
gdoc_MANS += man/gsasl_step.3
gdoc_MANS += man/gsasl_step64.3

gdoc_TEXINFOS =
gdoc_TEXINFOS += texi/base64.c.texi
gdoc_TEXINFOS += texi/callback.c.texi
gdoc_TEXINFOS += texi/crypto.c.texi
gdoc_TEXINFOS += texi/done.c.texi
gdoc_TEXINFOS += texi/doxygen.c.texi
gdoc_TEXINFOS += texi/error.c.texi
gdoc_TEXINFOS += texi/free.c.texi
gdoc_TEXINFOS += texi/init.c.texi
gdoc_TEXINFOS += texi/listmech.c.texi
gdoc_TEXINFOS += texi/md5pwd.c.texi
gdoc_TEXINFOS += texi/mechname.c.texi
gdoc_TEXINFOS += texi/obsolete.c.texi
gdoc_TEXINFOS += texi/property.c.texi
gdoc_TEXINFOS += texi/register.c.texi
gdoc_TEXINFOS += texi/saslprep.c.texi
gdoc_TEXINFOS += texi/suggest.c.texi
gdoc_TEXINFOS += texi/supportp.c.texi
gdoc_TEXINFOS += texi/version.c.texi
gdoc_TEXINFOS += texi/xcode.c.texi
gdoc_TEXINFOS += texi/xfinish.c.texi
gdoc_TEXINFOS += texi/xstart.c.texi
gdoc_TEXINFOS += texi/xstep.c.texi
gdoc_TEXINFOS += texi/gsasl_base64_to.texi
gdoc_TEXINFOS += texi/gsasl_base64_from.texi
gdoc_TEXINFOS += texi/gsasl_callback_set.texi
gdoc_TEXINFOS += texi/gsasl_callback.texi
gdoc_TEXINFOS += texi/gsasl_callback_hook_set.texi
gdoc_TEXINFOS += texi/gsasl_callback_hook_get.texi
gdoc_TEXINFOS += texi/gsasl_session_hook_set.texi
gdoc_TEXINFOS += texi/gsasl_session_hook_get.texi
gdoc_TEXINFOS += texi/gsasl_nonce.texi
gdoc_TEXINFOS += texi/gsasl_random.texi
gdoc_TEXINFOS += texi/gsasl_md5.texi
gdoc_TEXINFOS += texi/gsasl_hmac_md5.texi
gdoc_TEXINFOS += texi/gsasl_done.texi
gdoc_TEXINFOS += texi/gsasl_strerror.texi
gdoc_TEXINFOS += texi/gsasl_strerror_name.texi
gdoc_TEXINFOS += texi/gsasl_free.texi
gdoc_TEXINFOS += texi/gsasl_init.texi
gdoc_TEXINFOS += texi/gsasl_client_mechlist.texi
gdoc_TEXINFOS += texi/gsasl_server_mechlist.texi
gdoc_TEXINFOS += texi/gsasl_simple_getpass.texi
gdoc_TEXINFOS += texi/gsasl_mechanism_name.texi
gdoc_TEXINFOS += texi/gsasl_client_listmech.texi
gdoc_TEXINFOS += texi/gsasl_server_listmech.texi
gdoc_TEXINFOS += texi/gsasl_client_step.texi
gdoc_TEXINFOS += texi/gsasl_server_step.texi
gdoc_TEXINFOS += texi/gsasl_client_step_base64.texi
gdoc_TEXINFOS += texi/gsasl_server_step_base64.texi
gdoc_TEXINFOS += texi/gsasl_client_finish.texi
gdoc_TEXINFOS += texi/gsasl_server_finish.texi
gdoc_TEXINFOS += texi/gsasl_client_ctx_get.texi
gdoc_TEXINFOS += texi/gsasl_client_application_data_set.texi
gdoc_TEXINFOS += texi/gsasl_client_application_data_get.texi
gdoc_TEXINFOS += texi/gsasl_server_ctx_get.texi
gdoc_TEXINFOS += texi/gsasl_server_application_data_set.texi
gdoc_TEXINFOS += texi/gsasl_server_application_data_get.texi
gdoc_TEXINFOS += texi/gsasl_randomize.texi
gdoc_TEXINFOS += texi/gsasl_ctx_get.texi
gdoc_TEXINFOS += texi/gsasl_encode_inline.texi
gdoc_TEXINFOS += texi/gsasl_decode_inline.texi
gdoc_TEXINFOS += texi/gsasl_application_data_set.texi
gdoc_TEXINFOS += texi/gsasl_application_data_get.texi
gdoc_TEXINFOS += texi/gsasl_appinfo_set.texi
gdoc_TEXINFOS += texi/gsasl_appinfo_get.texi
gdoc_TEXINFOS += texi/gsasl_server_suggest_mechanism.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_authentication_id_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_authentication_id_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_authorization_id_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_authorization_id_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_password_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_password_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_passcode_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_passcode_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_pin_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_pin_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_service_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_service_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_anonymous_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_anonymous_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_qop_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_qop_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_maxbuf_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_maxbuf_get.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_realm_set.texi
gdoc_TEXINFOS += texi/gsasl_client_callback_realm_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_validate_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_validate_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_retrieve_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_retrieve_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_cram_md5_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_cram_md5_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_digest_md5_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_digest_md5_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_external_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_external_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_anonymous_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_anonymous_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_realm_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_realm_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_qop_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_qop_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_maxbuf_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_maxbuf_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_cipher_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_cipher_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_securid_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_securid_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_gssapi_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_gssapi_get.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_service_set.texi
gdoc_TEXINFOS += texi/gsasl_server_callback_service_get.texi
gdoc_TEXINFOS += texi/gsasl_stringprep_nfkc.texi
gdoc_TEXINFOS += texi/gsasl_stringprep_saslprep.texi
gdoc_TEXINFOS += texi/gsasl_stringprep_trace.texi
gdoc_TEXINFOS += texi/gsasl_md5pwd_get_password.texi
gdoc_TEXINFOS += texi/gsasl_base64_encode.texi
gdoc_TEXINFOS += texi/gsasl_base64_decode.texi
gdoc_TEXINFOS += texi/gsasl_property_set.texi
gdoc_TEXINFOS += texi/gsasl_property_set_raw.texi
gdoc_TEXINFOS += texi/gsasl_property_fast.texi
gdoc_TEXINFOS += texi/gsasl_property_get.texi
gdoc_TEXINFOS += texi/gsasl_register.texi
gdoc_TEXINFOS += texi/gsasl_saslprep.texi
gdoc_TEXINFOS += texi/gsasl_client_suggest_mechanism.texi
gdoc_TEXINFOS += texi/gsasl_client_support_p.texi
gdoc_TEXINFOS += texi/gsasl_server_support_p.texi
gdoc_TEXINFOS += texi/gsasl_check_version.texi
gdoc_TEXINFOS += texi/gsasl_encode.texi
gdoc_TEXINFOS += texi/gsasl_decode.texi
gdoc_TEXINFOS += texi/gsasl_finish.texi
gdoc_TEXINFOS += texi/gsasl_client_start.texi
gdoc_TEXINFOS += texi/gsasl_server_start.texi
gdoc_TEXINFOS += texi/gsasl_step.texi
gdoc_TEXINFOS += texi/gsasl_step64.texi

$(gdoc_MANS) $(gdoc_TEXINFOS):
	make update-makefile
	make Makefile
	make doit

GDOC_SRC = $(top_srcdir)/lib/src/*.c

update-makefile:
	MANS=""; \
	TEXINFOS=""; \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		TEXINFOS="$$TEXINFOS\ngdoc_TEXINFOS += texi/$$BASE.texi"; \
	done; \
	FUNCS=`./gdoc -listfunc $(GDOC_SRC)`; \
	for i in $$FUNCS; do \
		MANS="$$MANS\ngdoc_MANS += man/$$i.3"; \
		TEXINFOS="$$TEXINFOS\ngdoc_TEXINFOS += texi/$$i.texi"; \
	done; \
	grep -v -e '^gdoc_MANS += ' -e '^gdoc_TEXINFOS += ' Makefile.am | \
		perl -p -e "s,^gdoc_MANS =,gdoc_MANS =$$MANS," | \
		perl -p -e "s,^gdoc_TEXINFOS =,gdoc_TEXINFOS =$$TEXINFOS,;" \
		> Makefile.am.new && \
	mv Makefile.am.new Makefile.am

doit:
	@$(mkdir_p) man texi; \
	echo -n "Creating function documentation" && \
	for i in `./gdoc -listfunc $(GDOC_SRC)`; do \
		./gdoc -man \
			-module $(PACKAGE) -sourceversion $(VERSION) \
			-bugsto $(PACKAGE_BUGREPORT) \
			-includefuncprefix \
			-seeinfo $(PACKAGE) -verbatimcopying \
			-copyright "2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson" \
			-function $$i \
			$(GDOC_SRC) > man/$$i.3 && \
		./gdoc -texinfo -function $$i \
			$(GDOC_SRC) > texi/$$i.texi && \
		echo -n "."; \
	done; \
	echo ""; \
	echo -n "Creating file documentation" && \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		./gdoc -texinfo $$i > texi/$$BASE.texi && \
		echo -n "."; \
	done; \
	echo ""

.PHONY: update-makefile doit
