#
# Makefile for Asterisk discovery consul resource
# Copyright (C) 2015, Sylvain Boily
#
# This program is free software, distributed under the terms of
# the GNU General Public License Version 3. See the COPYING file
# at the top of the source tree.
#

INSTALL = install
ASTETCDIR = $(INSTALL_PREFIX)/etc/asterisk
SAMPLENAME = res_discovery_consul.conf.sample
CONFNAME = $(basename $(SAMPLENAME))

TARGET = res_discovery_consul.so
OBJECTS = res_discovery_consul.o
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Winit-self -Wmissing-format-attribute \
          -Wformat=2 -g -fPIC -D_GNU_SOURCE -D'AST_MODULE="res_discovery_consul"' 
LIBS += -lcurl -ljson-c
LDFLAGS = -Wall -shared

ifdef VERSION
	CFLAGS += -D'VERSION="$(VERSION)"'
endif

.PHONY: install clean

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $<

install: $(TARGET)
	mkdir -p $(DESTDIR)/usr/lib/asterisk/modules
	install -m 644 $(TARGET) $(DESTDIR)/usr/lib/asterisk/modules/
	@echo " +----- res_discovery_consul installed ------+"
	@echo " +                                           +"
	@echo " + res_discovery_consul has successfully     +"
	@echo " + been installed.                           +"
	@echo " + If you would like to install the sample   +"
	@echo " + configuration file run:                   +"
	@echo " +                                           +"
	@echo " +              make samples                 +"
	@echo " +-------------------------------------------+"

clean:
	rm -f $(OBJECTS)
	rm -f $(TARGET)

samples:
	$(INSTALL) -m 644 $(SAMPLENAME) $(DESTDIR)$(ASTETCDIR)/$(CONFNAME)
	@echo " ------- res_discovery_consul config installed ---------"
