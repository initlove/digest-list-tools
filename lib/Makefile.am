lib_LTLIBRARIES=libdigestlist-base.la libdigestlist-gen.la

libdigestlist_base_la_CFLAGS=-I$(top_srcdir)/include
libdigestlist_base_la_LIBADD=-ldl
libdigestlist_base_la_SOURCES=kernel_lib.c lib.c compact_list.c xattr.c

if CMOCKA
noinst_LTLIBRARIES=libdigestlist-base-test.la
libdigestlist_base_test_la_CFLAGS=${libdigestlist_base_la_CFLAGS} -DUNIT_TESTING
libdigestlist_base_test_la_LIBADD=${libdigestlist_base_la_LIBADD} -lcmocka
libdigestlist_base_test_la_SOURCES=${libdigestlist_base_la_SOURCES}
endif

if CRYPTO
libdigestlist_gen_la_CFLAGS=${libdigestlist_base_la_CFLAGS}
libdigestlist_gen_la_LIBADD=-lcrypto
libdigestlist_gen_la_SOURCES=crypto.c
endif
