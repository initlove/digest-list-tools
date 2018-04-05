#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([digest-list-tools], [0.2], [roberto.sassu@huawei.com])
AC_CONFIG_HEADERS([config.h])
CFLAGS="$CFLAGS -Wall"

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_PROG_AR
AC_PROG_CC
LT_INIT

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([crypto], [SHA256_Init],[found=yes],[],[])
AC_CHECK_LIB([rpm], [headerGet],[found=yes],[],[])
AC_CHECK_LIB([rpmio], [Fopen],[found=yes],[],[])
AC_CHECK_LIB([curl], [curl_easy_setopt],[found=yes],[],[])
AC_CHECK_LIB([z], [inflate],[found=yes],[],[])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([curl/curl.h])
AC_CHECK_HEADERS([rpm/rpmlib.h])

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

# Enable debug.
AC_ARG_ENABLE([debug],
[  --enable-debug    Turn on debugging],
[case "${enableval}" in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],[debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

if test -z "$CFLAGS"; then
  if test "$debug" == true; then
    CFLAGS="-O0 -g"
  else
    CFLAGS="-O2 -g"
  fi
elif test "$debug" == true; then
  CFLAGS="$CFLAGS -O0 -g"
fi

# Check availability of initrd tools
DRACUT_SUBDIR=
AC_CHECK_FILE(/usr/bin/dracut, [DRACUT_SUBDIR=dracut], [])
AC_SUBST([DRACUT_SUBDIR])
INITRAMFS_TOOLS_SUBDIR=
AC_CHECK_FILE(/usr/sbin/mkinitramfs,
	      [INITRAMFS_TOOLS_SUBDIR=initramfs-tools], [])
AC_SUBST([INITRAMFS_TOOLS_SUBDIR])

AC_CONFIG_FILES([Makefile
                 initrd/Makefile
                 initrd/dracut/Makefile
                 initrd/initramfs-tools/Makefile
                 docs/Makefile
                 include/Makefile
                 lib/Makefile
                 src/Makefile
                 scripts/Makefile])
AC_OUTPUT
