bin_PROGRAMS=upload_digest_lists gen_digest_lists verify_digest_lists

upload_digest_lists_CFLAGS=-I$(top_srcdir)/include
upload_digest_lists_LDFLAGS=$(top_srcdir)/lib/libdigestlist-base.la
upload_digest_lists_SOURCES=upload_digest_lists.c

gen_digest_lists_CFLAGS=-I$(top_srcdir)/include
gen_digest_lists_LDFLAGS=$(top_srcdir)/lib/libdigestlist-base.la \
			 $(top_srcdir)/lib/libdigestlist-gen.la
gen_digest_lists_SOURCES=gen_digest_lists.c

verify_digest_lists_CFLAGS=-I$(top_srcdir)/include
verify_digest_lists_LDFLAGS=$(top_srcdir)/lib/libdigestlist-base.la \
			 $(top_srcdir)/lib/libdigestlist-gen.la
verify_digest_lists_SOURCES=verify_digest_lists.c
