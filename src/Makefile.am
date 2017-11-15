bin_PROGRAMS = gen_digest_lists verify_digest_lists

gen_digest_lists_CFLAGS = -I$(top_srcdir)/include
gen_digest_lists_LDADD = $(top_srcdir)/lib/libdigestlists.la -lcrypto -lrpm -lrpmio
gen_digest_lists_SOURCES = gen_digest_lists.c

verify_digest_lists_CFLAGS = -I$(top_srcdir)/include
verify_digest_lists_LDADD = $(top_srcdir)/lib/libdigestlists.la -lcrypto -lrpm -lrpmio
verify_digest_lists_SOURCES = verify_digest_lists.c
