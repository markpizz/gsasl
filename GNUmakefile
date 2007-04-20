have-gnulib-files := $(shell test -f gnulib.mk && test -f maint.mk && echo yes)
ifneq ($(have-gnulib-files),yes)
gnulib.mk:
	ln -s build-aux/GNUmakefile gnulib.mk || cp build-aux/GNUmakefile gnulib.mk
	ln -s build-aux/maint.mk maint.mk || cp build-aux/maint.mk maint.mk
	mv build-aux/config.rpath{,-}
	ln -s lib/build-aux/GNUmakefile lib/gnulib.mk || cp lib/build-aux/GNUmakefile lib/gnulib.mk
	ln -s lib/build-aux/maint.mk lib/maint.mk || cp lib/build-aux/maint.mk lib/maint.mk
	mv lib/build-aux/config.rpath{,-}
endif

-include gnulib.mk
