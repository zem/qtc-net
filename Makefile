# This Makefile is for the qtc::net extension to perl.
#
PREFIX=/usr/local
DATADIR=/var/spool/qtc
CGIDIR=$(PREFIX)/share/qtc/cgi-bin
ETCDIR=/etc/qtc
INITDIR=/etc/init.d

all: Makefile.PL.mk
	make -f Makefile.PL.mk

# create perl makefile 
Makefile.PL.mk: Makefile.PL
	perl $<

install: Makefile.PL.mk
	make -f Makefile.PL.mk install
	if [ ! -d $(CGIDIR) ] ;\
	then \
		mkdir -p $(CGIDIR); \
	fi
	cp cgi-bin/*.cgi $(CGIDIR)
	if [ ! -d $(ETCDIR) ] ;\
	then \
		mkdir -p $(ETCDIR); \
	fi
	for etcfile in etc/qtc/* ; \
	do \
		if [ ! -f $(ETCDIR)/`basename $$etcfile` ] ; \
		then \
			cp $$etcfile $(ETCDIR) ; \
			chown root:root $(ETCDIR)/`basename $$etcfile` ; \
		fi ; \
	done
	for service in etc/init.d/* ; \
	do \
		if [ ! -f $(INITDIR)/`basename $$service` ] ; \
		then \
			cp $$service $(INITDIR) ; \
			chown root:root $(INITDIR)/`basename $$service` ; \
		fi ; \
	done

clean:
	rm -f Makefile.PL.mk
	MYMETA.yml
	MYMETA.json
	pm_to_blib
	deps
	Makefile.old

