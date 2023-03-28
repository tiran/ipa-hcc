VERSION = 0.7

srcdir = .
DEST =

# /etc
SYSCONFDIR := $(shell rpm --eval '%{_sysconfdir}')
# /usr/share
DATADIR := $(shell rpm --eval '%{_datadir}')
# /usr/bin/pythonX
PYTHON := /usr/bin/python3
# /usr/lib/pythonX.Y/site-packages
PYTHON_SITELIB := $(shell $(PYTHON) -c 'from sys import version_info as v; print("/usr/lib/python{}.{}/site-packages".format(v.major, v.minor))')
# /usr/sbin
SBINDIR := $(shell rpm --eval '%{_sbindir}')
# /usr/libexec
LIBEXECDIR := $(shell rpm --eval '%{_libexecdir}')
# /usr/lib/systemd/system
UNITDIR:= $(shell rpm --eval '%{_unitdir}')
# /usr/share/man
MANDIR:= $(shell rpm --eval '%{_mandir}')
# /var/lib
SHAREDSTATEDIR := $(shell rpm --eval '%{_sharedstatedir}')
# /var
LOCALSTATEDIR := $(shell rpm --eval '%{_localstatedir}')

INSTALL = install
INSTALL_DATAFILE = $(INSTALL) -d -m644
INSTALL_EXE = $(INSTALL) -D -m755
MKDIR_P = mkdir -p -m755
CP_PD = cp -p -d
CP_CONFIG = $(CP_PD) -n

BLACK = black
CERT = tests/clients/3ecb23bf-c99b-40ec-bec5-d884a63ddf12.pem


.PHONY: all
all: test rehash lint version

.PHONY: clean-idm-ci
clean-idm-ci:
	rm -rf config credentials
	rm -f mrack.* runner.log
	rm -f host-info.txt

.PHONY: clean
clean:
	find -name '*.pyc' -delete
	find -name __pycache__ | xargs rm -rf
	rm -f .coverage*
	rm -rf htmlcov

.PHONY: cleanall
cleanall: clean clean-idm-ci
	rm -rf .tox

.PHONY: lint
lint:
	$(BLACK) --check .
	yamllint --strict .

.PHONY: black
black:
	$(BLACK) .

.PHONY: version
version:
	sed -i 's/^VERSION\ =\ ".*\"/VERSION = "$(VERSION)"/g' \
		$(srcdir)/ipahcc/hccplatform.py \
		$(srcdir)/ipahcc_auto_enrollment.py

.PHONY: rpkg
rpkg:
	@rm -rf .tox/rpkg
	@mkdir -p .tox/rpkg
	rpkg local --outdir $$(pwd)/.tox/rpkg
	rpmlint --ignore-unused-rpmlintrc --strict -r ipa-hcc.rpmlintrc .tox/rpkg/

.PHONY: test
test:
	openssl verify -purpose sslclient -CAfile $(srcdir)/install/server/redhat-candlepin-bundle.pem $(CERT)
	openssl verify -purpose sslclient -CApath $(srcdir)/install/server/cacerts/ $(CERT)

.PHONY: run-idm-ci
run-idm-ci:
	@# tmpfs at /root/.ansible is needed to work around an SELinux violation
	@# when copying files from fusefs to mount point.
	podman run -ti --rm \
		--pull always \
		-v $(PWD):/ipa-hcc:Z \
		-w /ipa-hcc \
		--tmpfs /root/.ansible:rw,mode=750 \
		quay.io/idmops/idm-ci:latest /bin/bash

.PHONY: rehash
rehash:
	openssl rehash install/server/cacerts

.PHONY: install_client
install_client:
	$(MKDIR_P) $(DEST)$(LIBEXECDIR)/ipa-hcc
	$(CP_PD) $(srcdir)/ipahcc_auto_enrollment.py $(DEST)$(LIBEXECDIR)/ipa-hcc/ipa-hcc-auto-enrollment
	sed -i 's/^VERSION\ =\ ".*\"/VERSION = "$(VERSION)"/g' $(DEST)$(LIBEXECDIR)/ipa-hcc/ipa-hcc-auto-enrollment
	sed -i -e "1 s|^#!.*\bpython[^ ]*|#!$(PYTHON)|" $(DEST)$(LIBEXECDIR)/ipa-hcc/ipa-hcc-auto-enrollment
	chmod 755 $(DEST)$(LIBEXECDIR)/ipa-hcc/ipa-hcc-auto-enrollment

	$(MKDIR_P) $(DEST)$(UNITDIR)
	$(CP_PD) $(srcdir)/install/client/systemd/ipa-hcc-auto-enrollment.service $(DEST)$(UNITDIR)/
	$(MKDIR_P) $(DEST)$(SYSCONFDIR)/sysconfig
	$(CP_CONFIG) $(srcdir)/install/client/sysconfig/ipa-hcc-auto-enrollment $(DEST)$(SYSCONFDIR)/sysconfig/

.PHONY: install_server_plugin
install_server_plugin:
	$(MKDIR_P) $(DEST)$(PYTHON_SITELIB)/ipahcc
	$(CP_PD) $(srcdir)/ipahcc/*.py $(DEST)$(PYTHON_SITELIB)/ipahcc/
	sed -i 's/^VERSION\ =\ ".*\"/VERSION = "$(VERSION)"/g' $(DEST)$(PYTHON_SITELIB)/ipahcc/hccplatform.py
	$(MKDIR_P) $(DEST)$(SYSCONFDIR)/ipa
	$(CP_CONFIG) $(srcdir)/install/server/ipa/hcc.conf $(DEST)$(SYSCONFDIR)/ipa/
	$(MKDIR_P) $(DEST)$(SYSCONFDIR)/ipa/hcc

	$(MKDIR_P) $(DEST)$(PYTHON_SITELIB)/ipahcc/server
	$(CP_PD) $(srcdir)/ipahcc/server/*.py $(DEST)$(PYTHON_SITELIB)/ipahcc/server/
	$(MKDIR_P) $(DEST)$(SBINDIR)
	$(CP_PD) $(srcdir)/install/server/ipa-hcc $(DEST)$(SBINDIR)/
	sed -i -e "1 s|^#!.*\bpython[^ ]*|#!$(PYTHON)|" $(DEST)$(SBINDIR)/ipa-hcc
	chmod 755 $(DEST)$(SBINDIR)/ipa-hcc
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa-hcc/cacerts
	$(CP_PD) $(srcdir)/install/server/redhat-candlepin-bundle.pem $(DEST)$(DATADIR)/ipa-hcc/
	$(CP_PD) $(srcdir)/install/server/cacerts/*.pem $(DEST)$(DATADIR)/ipa-hcc/cacerts/
	openssl rehash $(DEST)$(DATADIR)/ipa-hcc/cacerts || true
	$(MKDIR_P) $(DEST)$(UNITDIR)
	$(CP_PD) $(srcdir)/install/server/systemd/ipa-hcc-update.* $(DEST)$(UNITDIR)/
	$(CP_PD) $(srcdir)/install/server/systemd/ipa-hcc-dbus.service $(DEST)$(UNITDIR)/
	$(MKDIR_P) $(DEST)$(DATADIR)/dbus-1/system.d
	$(CP_PD) $(srcdir)/install/server/dbus-1/system.d/com.redhat.console.ipahcc.conf $(DEST)$(DATADIR)/dbus-1/system.d/
	$(MKDIR_P) $(DEST)$(DATADIR)/dbus-1/system-services
	$(CP_PD) $(srcdir)/install/server/dbus-1/system-services/com.redhat.console.ipahcc.service $(DEST)$(DATADIR)/dbus-1/system-services/
	$(MKDIR_P) $(DEST)$(LIBEXECDIR)/ipa-hcc
	$(CP_PD) $(srcdir)/install/server/ipa-hcc-dbus $(DEST)$(LIBEXECDIR)/ipa-hcc/ipa-hcc-dbus
	sed -i -e "1 s|^#!.*\bpython[^ ]*|#!$(PYTHON)|" $(DEST)$(LIBEXECDIR)/ipa-hcc/ipa-hcc-dbus
	$(MKDIR_P) $(DEST)$(MANDIR)/man1
	$(CP_PD) $(srcdir)/install/server/man/*.1 $(DEST)$(MANDIR)/man1/
	$(MKDIR_P) $(DEST)$(PYTHON_SITELIB)/ipaserver/install/plugins
	$(CP_PD) $(srcdir)/ipaserver/install/plugins/update_hcc.py $(DEST)$(PYTHON_SITELIB)/ipaserver/install/plugins/
	$(MKDIR_P) $(DEST)$(PYTHON_SITELIB)/ipaserver/plugins
	$(CP_PD) $(srcdir)/ipaserver/plugins/*.py $(DEST)$(PYTHON_SITELIB)/ipaserver/plugins/
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa/updates/
	$(CP_PD) $(srcdir)/install/server/updates/85-hcc.update $(DEST)$(DATADIR)/ipa/updates/
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa/schema.d
	$(CP_PD) $(srcdir)/install/server/schema.d/85-hcc.ldif $(DEST)$(DATADIR)/ipa/schema.d/
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa/ui/js/plugins/hccconfig
	$(CP_PD) $(srcdir)/install/server/ui/js/plugins/hccconfig/hccconfig.js $(DEST)$(DATADIR)/ipa/ui/js/plugins/hccconfig/
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa/ui/js/plugins/hcchost/
	$(CP_PD) $(srcdir)/install/server/ui/js/plugins/hcchost/hcchost.js $(DEST)$(DATADIR)/ipa/ui/js/plugins/hcchost/

.PHONY: install_registration_service
install_registration_service:
	$(MKDIR_P) $(DEST)$(PYTHON_SITELIB)/ipahcc/registration
	$(CP_PD) $(srcdir)/ipahcc/registration/*.py $(DEST)$(PYTHON_SITELIB)/ipahcc/registration/
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa-hcc
	$(CP_PD) $(srcdir)/install/registration/wsgi/hcc_registration_service.py $(DEST)$(DATADIR)/ipa-hcc/
	$(MKDIR_P) $(DEST)$(LOCALSTATEDIR)/cache/ipa-hcc
	$(MKDIR_P) $(DEST)$(SHAREDSTATEDIR)/ipa/gssproxy
	$(MKDIR_P) $(DEST)$(PYTHON_SITELIB)/ipaserver/install/plugins
	$(CP_PD) $(srcdir)/ipaserver/install/plugins/update_hcc_enrollment_service.py $(DEST)$(PYTHON_SITELIB)/ipaserver/install/plugins/
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa/updates
	$(CP_PD) $(srcdir)/install/registration/updates/86-hcc-registration-service.update $(DEST)$(DATADIR)/ipa/updates/
	$(MKDIR_P) $(DEST)$(SYSCONFDIR)/httpd/conf.d
	$(CP_CONFIG) $(srcdir)/install/registration/httpd/ipa-hcc.conf $(DEST)$(SYSCONFDIR)/httpd/conf.d/
	$(MKDIR_P) $(DEST)$(SYSCONFDIR)/gssproxy
	$(CP_CONFIG) $(srcdir)/install/registration/gssproxy/85-ipa-hcc.conf $(DEST)$(SYSCONFDIR)/gssproxy/

.PHONY: install_mockapi
install_mockapi:
	$(MKDIR_P) $(DEST)$(PYTHON_SITELIB)/ipahcc/mockapi
	$(CP_PD) $(srcdir)/ipahcc/mockapi/*.py $(DEST)$(PYTHON_SITELIB)/ipahcc/mockapi/
	$(MKDIR_P) $(DEST)$(DATADIR)/ipa-hcc
	$(CP_PD) $(srcdir)/install/mockapi/wsgi/hcc_mockapi.py $(DEST)$(DATADIR)/ipa-hcc/
	$(MKDIR_P) $(DEST)$(SYSCONFDIR)/httpd/conf.d
	$(CP_CONFIG) $(srcdir)/install/mockapi/httpd/ipa-hcc-mockapi.conf $(DEST)$(SYSCONFDIR)/httpd/conf.d/

.PHONY: install_server
install_server: install_server_plugin install_registration_service

.PHONY: install
install: install_client install_server
