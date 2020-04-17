digestlistdir=$(libdir)/digestlist

digestlist_LTLIBRARIES=libgenerator-copy.la libgenerator-compact.la \
		       libgenerator-unknown.la

libgenerator_LDFLAGS=-no-undefined -avoid-version -L$(top_srcdir)/lib/.libs
libgenerator_LIBADD=$(top_srcdir)/lib/libdigestlist-base.la
libgenerator_CFLAGS=-I$(top_srcdir)/include

libgenerator_copy_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_copy_la_LIBADD=${libgenerator_LIBADD}
libgenerator_copy_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_copy_la_SOURCES=copy.c

libgenerator_compact_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_compact_la_LIBADD=${libgenerator_LIBADD}
libgenerator_compact_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_compact_la_SOURCES=compact.c

if RPM
digestlist_LTLIBRARIES+=libgenerator-rpm.la
libgenerator_rpm_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_rpm_la_LIBADD=${libgenerator_LIBADD} -lrpm -lrpmio
libgenerator_rpm_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_rpm_la_SOURCES=rpm.c
endif

libgenerator_unknown_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_unknown_la_LIBADD=${libgenerator_LIBADD}
libgenerator_unknown_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_unknown_la_SOURCES=unknown.c

if CMOCKA
check_LTLIBRARIES=libgenerator-copy-test.la libgenerator-compact-test.la \
		  libgenerator-unknown-test.la

libgenerator_test_LDFLAGS=-no-undefined -avoid-version \
			  -L$(top_srcdir)/lib/.libs -rpath /dev/null
libgenerator_test_LIBADD=$(top_srcdir)/lib/libdigestlist-base-test.la -lcmocka
libgenerator_test_CFLAGS=-I$(top_srcdir)/include -DUNIT_TESTING

libgenerator_copy_test_la_LDFLAGS=${libgenerator_test_LDFLAGS}
libgenerator_copy_test_la_LIBADD=${libgenerator_test_LIBADD}
libgenerator_copy_test_la_CFLAGS=${libgenerator_test_CFLAGS}
libgenerator_copy_test_la_SOURCES=copy.c

libgenerator_compact_test_la_LDFLAGS=${libgenerator_test_LDFLAGS}
libgenerator_compact_test_la_LIBADD=${libgenerator_test_LIBADD}
libgenerator_compact_test_la_CFLAGS=${libgenerator_test_CFLAGS}
libgenerator_compact_test_la_SOURCES=compact.c

if RPM
check_LTLIBRARIES+=libgenerator-rpm-test.la
libgenerator_rpm_test_la_LDFLAGS=${libgenerator_test_LDFLAGS}
libgenerator_rpm_test_la_LIBADD=${libgenerator_test_LIBADD} -lrpm -lrpmio
libgenerator_rpm_test_la_CFLAGS=${libgenerator_test_CFLAGS}
libgenerator_rpm_test_la_SOURCES=rpm.c
endif

libgenerator_unknown_test_la_LDFLAGS=${libgenerator_test_LDFLAGS}
libgenerator_unknown_test_la_LIBADD=${libgenerator_test_LIBADD}
libgenerator_unknown_test_la_CFLAGS=${libgenerator_test_CFLAGS}
libgenerator_unknown_test_la_SOURCES=unknown.c
endif
