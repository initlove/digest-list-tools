if CMOCKA
TESTS_ENVIRONMENT = \
	LD_LIBRARY_PATH=$(top_srcdir)/lib/.libs:$(top_srcdir)/parsers/.libs:$(top_srcdir)/generators/.libs; export LD_LIBRARY_PATH;

check_PROGRAMS=lib gen compact_tlv
TESTS = $(check_PROGRAMS)

lib_LDFLAGS=-no-undefined -avoid-version
lib_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
lib_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
lib_SOURCES=lib.c

gen_LDFLAGS=-no-undefined -avoid-version
gen_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
gen_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
gen_SOURCES=gen.c

compact_tlv_LDFLAGS=-no-undefined -avoid-version
compact_tlv_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
compact_tlv_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
compact_tlv_SOURCES=compact_tlv.c

if RPM
check_PROGRAMS+=rpm
rpm_LDFLAGS=-no-undefined -avoid-version
rpm_LDADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka -lrpm -lrpmio
rpm_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
rpm_SOURCES=rpm.c
endif
endif
