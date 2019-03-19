digestlistdir=$(libdir)/digestlist

digestlist_LTLIBRARIES=libgenerator-ima.la libgenerator-copy.la

libgenerator_LDFLAGS=-no-undefined -avoid-version
if CMOCKA
libgenerator_LIBADD=$(top_srcdir)/lib/libdigestlist-base-test.la
else
libgenerator_LIBADD=$(top_srcdir)/lib/libdigestlist-base.la
endif
libgenerator_CFLAGS=-I$(top_srcdir)/include

libgenerator_ima_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_ima_la_LIBADD=${libgenerator_LIBADD}
libgenerator_ima_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_ima_la_SOURCES=ima.c

libgenerator_copy_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_copy_la_LIBADD=${libgenerator_LIBADD}
libgenerator_copy_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_copy_la_SOURCES=copy.c

if CRYPTO
digestlist_LTLIBRARIES+=libgenerator-compact.la
libgenerator_compact_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_compact_la_LIBADD=${libgenerator_LIBADD} \
			       $(top_srcdir)/lib/libdigestlist-gen.la
libgenerator_compact_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_compact_la_SOURCES=compact.c
endif

if RPM
digestlist_LTLIBRARIES+=libgenerator-rpm.la
libgenerator_rpm_la_LDFLAGS=${libgenerator_LDFLAGS}
libgenerator_rpm_la_LIBADD=${libgenerator_LIBADD} -lrpm -lrpmio
libgenerator_rpm_la_CFLAGS=${libgenerator_CFLAGS}
libgenerator_rpm_la_SOURCES=rpm.c
endif
