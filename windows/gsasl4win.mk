# gsasl4win.mk --- build GNU SASL for Windows
# Copyright (C) 2006-2012 Simon Josefsson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

GSASL_DLL_VERSION=7

all:
	@echo 'Usage examples:'
	@echo '  make -f gsasl4win.mk gsasl4win VERSION=1.6.1'
	@echo '  make -f gsasl4win.mk gsasl4win32 VERSION=1.6.1'
	@echo '  make -f gsasl4win.mk gsasl4win64 VERSION=1.6.1'
	@echo '  make -f gsasl4win.mk gsasl4win32kfw322 VERSION=1.6.1'

clean:
	rm -rf src build-x86 build-x64 inst-x86 inst-x64 kfw322x86

gsasl4win: gsasl4win32 gsasl4win64 gsasl4win32kfw322
gsasl4win32: gsasl-$(VERSION)-x86.zip
gsasl4win64: gsasl-$(VERSION)-x64.zip
gsasl4win32kfw322: gsasl-$(VERSION)-x86-kfw322.zip

# GNU SASL

dist/gsasl-$(VERSION).tar.gz:
	rm -rf tmp
	mkdir tmp
	cd tmp && wget -q ftp://ftp.gnu.org/gnu/gsasl/gsasl-$(VERSION).tar.gz ftp://ftp.gnu.org/gnu/gsasl/gsasl-$(VERSION).tar.gz.sig
	gpg tmp/gsasl-$(VERSION).tar.gz.sig
	-mkdir dist
	mv tmp/gsasl-$(VERSION).tar.gz tmp/gsasl-$(VERSION).tar.gz.sig dist/
	rm -rf tmp

src/gsasl-$(VERSION)/configure: dist/gsasl-$(VERSION).tar.gz
	-mkdir src
	cd src && tar xfz ../dist/gsasl-$(VERSION).tar.gz

# x86 vanilla

build-x86/gsasl-$(VERSION)/Makefile: src/gsasl-$(VERSION)/configure
	rm -rf build-x86/gsasl-$(VERSION)
	mkdir -p build-x86/gsasl-$(VERSION) && \
	cd build-x86/gsasl-$(VERSION) && \
	../../src/gsasl-$(VERSION)/configure --host=i686-w64-mingw32 --build=i686-pc-linux-gnu --prefix=$(PWD)/inst-x86 --without-libgcrypt --disable-obsolete

inst-x86/bin/libgsasl-$(GSASL_DLL_VERSION).dll: build-x86/gsasl-$(VERSION)/Makefile
	make -C build-x86/gsasl-$(VERSION) install
	make -C build-x86/gsasl-$(VERSION)/tests check

gsasl-$(VERSION)-x86.zip: inst-x86/bin/libgsasl-$(GSASL_DLL_VERSION).dll
	rm -f gsasl-$(VERSION)-x86.zip
	cd inst-x86 && zip -r ../gsasl-$(VERSION)-x86.zip *

# x64 vanilla

build-x64/gsasl-$(VERSION)/Makefile: src/gsasl-$(VERSION)/configure
	rm -rf build-x64/gsasl-$(VERSION)
	mkdir -p build-x64/gsasl-$(VERSION) && \
	cd build-x64/gsasl-$(VERSION) && \
	../../src/gsasl-$(VERSION)/configure --host=i686-w64-mingw32 --build=i686-pc-linux-gnu --prefix=$(PWD)/inst-x64 --without-libgcrypt --disable-obsolete

inst-x64/bin/libgsasl-$(GSASL_DLL_VERSION).dll: build-x64/gsasl-$(VERSION)/Makefile
	make -C build-x64/gsasl-$(VERSION) install
	make -C build-x64/gsasl-$(VERSION)/tests check

gsasl-$(VERSION)-x64.zip: inst-x64/bin/libgsasl-$(GSASL_DLL_VERSION).dll
	rm -f gsasl-$(VERSION)-x64.zip
	cd inst-x64 && zip -r ../gsasl-$(VERSION)-x64.zip *

# x86 KfW 3.2.2 flavor

build-x86-kfw322/gsasl-$(VERSION)/Makefile: src/gsasl-$(VERSION)/configure kfw322sdkx86/kfw-3-2-2-final/inc/krb5/win-mac.h
	rm -rf build-x86-kfw322/gsasl-$(VERSION)
	mkdir -p build-x86-kfw322/gsasl-$(VERSION) && \
	cd build-x86-kfw322/gsasl-$(VERSION) && \
	lt_cv_deplibs_check_method=pass_all ../../src/gsasl-$(VERSION)/configure --host=i686-w64-mingw32 --build=i686-pc-linux-gnu --prefix=$(PWD)/inst-x86-kfw322 --without-libgcrypt --disable-obsolete --with-gssapi-impl=kfw LDFLAGS="-L$(PWD)/kfw322sdkx86/kfw-3-2-2-final/lib/i386" CPPFLAGS="-I$(PWD)/kfw322sdkx86/kfw-3-2-2-final/inc/krb5 -DSSIZE_T_DEFINED"

inst-x86-kfw322/bin/libgsasl-$(GSASL_DLL_VERSION).dll: build-x86-kfw322/gsasl-$(VERSION)/Makefile install-kfw322
	make -C build-x86-kfw322/gsasl-$(VERSION) install
	make -C build-x86-kfw322/gsasl-$(VERSION)/tests check

gsasl-$(VERSION)-x86-kfw322.zip: inst-x86-kfw322/bin/libgsasl-$(GSASL_DLL_VERSION).dll
	rm -f gsasl-$(VERSION)-x86-kfw322.zip
	cd inst-x86-kfw322 && zip -r ../gsasl-$(VERSION)-x86-kfw322.zip *

# KfW 3.2.2

dist/kfw-3-2-2-sdk.zip:
	-mkdir dist
	cd dist && wget http://web.mit.edu/kerberos/dist/kfw/3.2/kfw-3.2.2/kfw-3-2-2-sdk.zip

kfw322sdkx86/kfw-3-2-2-final/inc/krb5/win-mac.h: dist/kfw-3-2-2-sdk.zip
	-mkdir kfw322sdkx86
	cd kfw322sdkx86 && unzip -u ../dist/kfw-3-2-2-sdk.zip
	perl -pi -e 's,sys\\,sys/,' kfw322sdkx86/kfw-3-2-2-final/inc/krb5/win-mac.h

dist/kfw-3-2-2.zip:
	-mkdir dist
	cd dist && wget http://web.mit.edu/kerberos/dist/kfw/3.2/kfw-3.2.2/kfw-3-2-2.zip

install-kfw322: dist/kfw-3-2-2.zip
	-mkdir kfw322x86
	cd kfw322x86 && unzip -u ../dist/kfw-3-2-2.zip
	mkdir -p build-x86-kfw322/gsasl-$(VERSION)/lib/src/.libs
	cp -v kfw322x86/kfw-3-2-2-final/bin/i386/*.dll build-x86-kfw322/gsasl-$(VERSION)/lib/src/.libs/
