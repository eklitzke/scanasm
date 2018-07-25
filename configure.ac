#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([scanasm], [0.1], [evan@eklitzke.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.cc])
AC_CONFIG_HEADERS([src/config.h])

AC_LANG([C++])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL

AM_INIT_AUTOMAKE([dist-bzip2 foreign subdir-objects -Wall -Werror])
# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

PKG_CHECK_MODULES([CAPSTONE], [capstone])

AC_SUBST([CAPSTONE_CFLAGS])
AC_SUBST([CAPSTONE_LIBS])
AC_SUBST([CAPSTONE_LDFLAGS])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
