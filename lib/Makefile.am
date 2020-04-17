lib_LTLIBRARIES=libdigestlist-base.la

libdigestlist_base_la_LDFLAGS=-no-undefined -avoid-version -rpath /dev/null
libdigestlist_base_la_LIBADD=-ldl -lcrypto -lselinux -lcap
libdigestlist_base_la_SOURCES=kernel_lib.c lib.c compact_list.c xattr.c evm.c \
			      selinux.c parser_lib.c crypto.c cap.c ima_list.c
libdigestlist_base_la_CFLAGS=-I$(top_srcdir)/include -Werror

if CMOCKA
check_LTLIBRARIES=libdigestlist-base-test.la
libdigestlist_base_test_la_LDFLAGS=-no-undefined -avoid-version -rpath /dev/null
libdigestlist_base_test_la_LIBADD=${libdigestlist_base_la_LIBADD} -lcmocka
libdigestlist_base_test_la_SOURCES=${libdigestlist_base_la_SOURCES}
libdigestlist_base_test_la_CFLAGS=${libdigestlist_base_la_CFLAGS} -DUNIT_TESTING
endif
