digestlistdir=$(libdir)/digestlist

digestlist_LTLIBRARIES=libparser-rpm.la libparser-ima.la

libparser_LDFLAGS=-no-undefined -avoid-version
if CMOCKA
libparser_LIBADD=$(top_srcdir)/lib/libdigestlist-base-test.la
else
libparser_LIBADD=$(top_srcdir)/lib/libdigestlist-base.la
endif
libparser_CFLAGS=-I$(top_srcdir)/include

libparser_rpm_la_LDFLAGS=${libparser_LDFLAGS}
libparser_rpm_la_LIBADD=${libparser_LIBADD}
libparser_rpm_la_CFLAGS=${libparser_CFLAGS}
libparser_rpm_la_SOURCES=rpm.c

libparser_ima_la_LDFLAGS=${libparser_LDFLAGS}
libparser_ima_la_LIBADD=${libparser_LIBADD}
libparser_ima_la_CFLAGS=${libparser_CFLAGS}
libparser_ima_la_SOURCES=ima.c
