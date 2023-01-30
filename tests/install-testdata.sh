#!/bin/sh
set -ex

systemctl restart krb5kdc.service

ipa-ldap-updater ./89-testdata.update
