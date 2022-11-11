#!/bin/sh
set -ex

# install CA certs, update all local bundles
ipa-cacert-manage install ./ca/bundle.pem
ipa-certupdate

# alternative approach
#cp ca/bundle.pem /etc/ipa/candlepin-bundle.pem
#cp pkinit_candlepin.conf /etc/krb5.conf.d/pkinit_candlepin

# XXX bug: ipa-certupdate does not restart KDC
systemctl restart krb5kdc.service

ipa-ldap-updater ./89-testdata.update

