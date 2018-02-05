bindir = /usr/bin
bin_PROGRAMS = WiFicommission

WiFicommission_FLAGS = -I=/usr/include/ -I=/usr/include/bluetooth/

AM_CPPFLAGS = \
	-I$(srcdir)/src/include/ \
	$(INCLUDE_PARAMS) \
	$(WiFicommission_FLAGS)

WiFicommission_SOURCES := \
		WiFicommission.c

WiFicommission_LDFLAGS = -lpthread -lrt -L=/usr/lib/bluez5/ -lshared-mainloop -lshared-glib -lbluetooth-internal -lgwutils $(LDFLAGS)
