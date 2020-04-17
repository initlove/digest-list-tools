if CMOCKA
check_PROGRAMS=lib ima gen

lib_LDFLAGS=-no-undefined -avoid-version
lib_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
lib_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
lib_SOURCES=lib.c

ima_LDFLAGS=-no-undefined -avoid-version
ima_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
ima_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
ima_SOURCES=ima.c

gen_LDFLAGS=-no-undefined -avoid-version
gen_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
gen_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
gen_SOURCES=gen.c

if RPM
check_PROGRAMS+=rpm
rpm_LDFLAGS=-no-undefined -avoid-version
rpm_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka -lrpm -lrpmio
rpm_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
rpm_SOURCES=rpm.c
endif
endif
