lib_LTLIBRARIES = libdigestlists.la

libdigestlists_la_LIBADD = -lcrypto -lrpm -lrpmio

libdigestlists_la_CFLAGS = -I$(top_srcdir)/include

libdigestlists_la_SOURCES = kernel_lib.c \
			    kernel_ima.c \
			    compact_list.c \
			    rpm.c \
			    metadata.c \
			    lib.c
