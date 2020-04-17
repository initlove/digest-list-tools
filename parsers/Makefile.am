digestlistdir=$(libdir)/digestlist

digestlist_LTLIBRARIES=libparser-rpm.la libparser-compact_tlv.la

libparser_LDFLAGS=-no-undefined -avoid-version -L$(top_srcdir)/lib/.libs
libparser_LIBADD=$(top_srcdir)/lib/libdigestlist-base.la
libparser_CFLAGS=-I$(top_srcdir)/include

libparser_rpm_la_LDFLAGS=${libparser_LDFLAGS}
libparser_rpm_la_LIBADD=${libparser_LIBADD}
libparser_rpm_la_CFLAGS=${libparser_CFLAGS}
libparser_rpm_la_SOURCES=rpm.c

libparser_compact_tlv_la_LDFLAGS=${libparser_LDFLAGS}
libparser_compact_tlv_la_LIBADD=${libparser_LIBADD}
libparser_compact_tlv_la_CFLAGS=${libparser_CFLAGS}
libparser_compact_tlv_la_SOURCES=compact_tlv.c

if CMOCKA
check_LTLIBRARIES=libparser-rpm-test.la libparser-compact_tlv-test.la

libparser_test_LDFLAGS=-no-undefined -avoid-version -L$(top_srcdir)/lib/.libs \
		       -rpath /dev/null
libparser_test_LIBADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
libparser_test_CFLAGS=-I$(top_srcdir)/include -DUNIT_TESTING

libparser_rpm_test_la_LDFLAGS=${libparser_test_LDFLAGS}
libparser_rpm_test_la_LIBADD=${libparser_test_LIBADD}
libparser_rpm_test_la_CFLAGS=${libparser_test_CFLAGS}
libparser_rpm_test_la_SOURCES=rpm.c

libparser_compact_tlv_test_la_LDFLAGS=${libparser_test_LDFLAGS}
libparser_compact_tlv_test_la_LIBADD=${libparser_test_LIBADD}
libparser_compact_tlv_test_la_CFLAGS=${libparser_test_CFLAGS}
libparser_compact_tlv_test_la_SOURCES=compact_tlv.c
endif
