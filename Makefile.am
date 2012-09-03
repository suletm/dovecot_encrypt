doveadm_moduledir = $(moduledir)/doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/dbox-common \
	-I$(top_srcdir)/src/doveadm

NOPLUGIN_LDFLAGS =
lib10_doveadm_encrypt_plugin_la_LDFLAGS = -module -avoid-version
lib20_encrypt_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_encrypt_plugin.la

if BUILD_ENCRYPT
ENCRYPT_LIB = -lgpg
endif

lib20_encrypt_plugin_la_LIBADD = \
	$(ENCRYPT_LIB) 

lib20_encrypt_plugin_la_SOURCES = \
	istream-encrypt.c \
	ostream-encrypt.c \
	encrypt-plugin.c

noinst_HEADERS = \
	istream-encrypt.h \
	ostream-encrypt.h \
	encrypt-plugin.h

doveadm_module_LTLIBRARIES = \
	lib10_doveadm_encrypt_plugin.la

lib10_doveadm_encrypt_plugin_la_SOURCES = \
	doveadm-encrypt.c
