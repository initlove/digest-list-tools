#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([digest-list-tools], [0.3], [roberto.sassu@huawei.com])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

# Enable debug.
AC_ARG_ENABLE([debug], [  --enable-debug    Turn on debugging],
	      [debug=${enableval}], [debug=no])

if test -z "$CFLAGS"; then
  if test "$debug" == yes; then
    CFLAGS="-O0 -g"
  else
    CFLAGS="-O2"
  fi
fi

if test "$debug" == yes; then
  CFLAGS="$CFLAGS -DDEBUG"
fi

big_endian=false
AC_C_BIGENDIAN ([big_endian=true], [big_endian=false])
if test "$big_endian" == true; then
  CFLAGS="$CFLAGS -D__BIG_ENDIAN__"
fi

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB(rpm, headerGet,[rpm=yes], [rpm=no], [])
AC_CHECK_LIB([crypto], [SHA256_Init], [crypto=yes], [crypto=no], [])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([rpm/rpmlib.h], [], [rpm=no])
AC_CHECK_HEADERS([openssl/evp.h], [], [crypto=no])

PKG_CHECK_EXISTS(cmocka,
    [AC_CHECK_HEADERS([stdarg.h stddef.h setjmp.h],
        [], dnl We are only intrested in action-if-not-found
        [AC_MSG_WARN([Header files stdarg.h stddef.h setjmp.h are
                      required by cmocka])
         cmocka_required_headers="no"
        ]
    )
    AS_IF([test x"$cmocka_required_headers" != x"no"],
          [PKG_CHECK_MODULES([CMOCKA], [cmocka], [cmocka="yes"])]
    )],
    dnl PKG_CHECK_EXISTS ACTION-IF-NOT-FOUND
    [AC_MSG_WARN([No libcmocka library found, cmocka tests
                  will not be built])])

AM_CONDITIONAL([RPM], [test "$rpm" = yes])
AM_CONDITIONAL([CRYPTO], [test "$crypto" = yes])
AM_CONDITIONAL([CMOCKA], [test "$cmocka" = yes])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([ftruncate memset munmap strstr])

# Check availability of initrd tools
DRACUT_SUBDIR=
AC_CHECK_FILE(/usr/bin/dracut, [DRACUT_SUBDIR=dracut], [])
AC_SUBST([DRACUT_SUBDIR])
INITRAMFS_TOOLS_SUBDIR=
AC_CHECK_FILE(/usr/sbin/mkinitramfs,
	      [INITRAMFS_TOOLS_SUBDIR=initramfs-tools], [])
AC_SUBST([INITRAMFS_TOOLS_SUBDIR])

CFLAGS="$CFLAGS -Wall -Werror"

AC_SUBST(CFLAGS)

AC_CONFIG_FILES([Makefile
		 docs/Makefile
		 include/Makefile
		 initrd/Makefile
		 initrd/dracut/Makefile
		 initrd/initramfs-tools/Makefile
		 lib/Makefile
		 generators/Makefile
		 parsers/Makefile
		 scripts/Makefile
		 src/Makefile
		 systemd/Makefile
		 tests/Makefile])
AC_OUTPUT
cat <<EOF

CFLAGS:				${CFLAGS}

EOF
