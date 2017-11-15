#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([digest-list-tools], [0.1], [roberto.sassu@huawei.com])
AC_CONFIG_HEADERS([config.h])
CFLAGS="$CFLAGS -Wall"

AM_INIT_AUTOMAKE([-Wall foreign])
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
AC_CHECK_LIB([crypto], [SHA256_Init])
AC_CHECK_LIB([rpm], [headerGetEntry])
AC_CHECK_LIB([rpmio], [Fopen])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])

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

AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 include/Makefile
                 lib/Makefile
                 src/Makefile
                 scripts/Makefile])
AC_OUTPUT
