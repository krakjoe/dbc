dnl $Id$
dnl config.m4 for extension dbc

PHP_ARG_ENABLE(dbc, whether to enable dbc support,
[  --enable-dbc           Enable dbc support])

if test "$PHP_DBC" != "no"; then
  PHP_NEW_EXTENSION(dbc, dbc.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
