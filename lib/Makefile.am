lib_LTLIBRARIES = libdigestlists.la libparserstatic.la

libdigestlists_la_LIBADD = -lcrypto -lrpm -lrpmio -lcurl

libdigestlists_la_CFLAGS = -I$(top_srcdir)/include -DCRYPTO

libdigestlists_la_SOURCES = kernel_lib.c \
			    kernel_ima.c \
			    metadata.c \
			    lib.c \
			    securityfs.c \
			    pgp.c \
			    parsers/rpm.c \
			    parsers/deb.c \
			    generators/compact_list.c \
			    generators/rpm.c \
			    generators/deb.c

libparserstatic_la_CFLAGS = -I$(top_srcdir)/include
libparserstatic_la_LDFLAGS = -all-static -lc -lz

libparserstatic_la_SOURCES = kernel_lib.c \
			     kernel_ima.c \
			     lib.c \
			     securityfs.c \
			     pgp.c \
			     parsers/rpm.c \
			     parsers/deb.c
