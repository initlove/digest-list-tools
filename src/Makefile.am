bin_PROGRAMS = gen_digest_lists verify_digest_lists modify_digest_lists \
	       upload_digest_lists gen_parser_metadata

gen_digest_lists_CFLAGS = -I$(top_srcdir)/include
gen_digest_lists_LDFLAGS = $(top_srcdir)/lib/libdigestlists.la -lcrypto
gen_digest_lists_SOURCES = gen_digest_lists.c

gen_parser_metadata_CFLAGS = -I$(top_srcdir)/include
gen_parser_metadata_LDFLAGS = $(top_srcdir)/lib/libdigestlists.la -lcrypto
gen_parser_metadata_SOURCES = gen_parser_metadata.c

verify_digest_lists_CFLAGS = -I$(top_srcdir)/include
verify_digest_lists_LDFLAGS = $(top_srcdir)/lib/libdigestlists.la -lcrypto
verify_digest_lists_SOURCES = verify_digest_lists.c

modify_digest_lists_CFLAGS = -I$(top_srcdir)/include -D DIGEST_CHECK_DISABLED
modify_digest_lists_LDFLAGS = $(top_srcdir)/lib/libdigestlists.la
modify_digest_lists_SOURCES = modify_digest_lists.c

upload_digest_lists_CFLAGS = -I$(top_srcdir)/include
upload_digest_lists_LDFLAGS = -all-static $(top_srcdir)/lib/libparserstatic.la
upload_digest_lists_SOURCES = upload_digest_lists.c
