#!/bin/sh
set -ex

# install CA certs, update all local bundles
ipa-cacert-manage install ./ca/bundle.pem
ipa-certupdate

# XXX bug: ipa-certupdate does not restart KDC
systemctl restart krb5kdc.service

ipa-ldap-updater ./89-testdata.update
