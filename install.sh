#!/bin/sh
set -ex

SITELIB=$(python -c 'from sys import version_info as v; print("/usr/lib/python{}.{}/site-packages".format(v.major, v.minor))')

## phase 1, install files

make install_server PYTHON=python PYTHON_SITELIB=$SITELIB

## phase 2, user, change permissions

# user and group
getent group ipaapi >/dev/null || groupadd -f -r ipaapi
getent passwd ipahcc >/dev/null || useradd -r -g ipaapi -s /sbin/nologin -d /usr/share/ipa-hcc -c "IPA Hybrid Cloud Console enrollment service" ipahcc

chown ipahcc:root -R /etc/ipa/hcc
chmod 750 /etc/ipa/hcc
chown ipahcc:ipaapi -R /var/cache/ipa-hcc
semanage fcontext -a -f a -s system_u -t httpd_cache_t -r 's0' '/var/cache/ipa-hcc(/.*)?' || :
restorecon -R /var/cache/ipa-hcc || :

python -m compileall ${SITELIB}/ipaserver/install/plugins ${SITELIB}/ipaserver/plugins ${SITELIB}/ipahcc

# run updater
ipa-ldap-updater \
    -S /usr/share/ipa/schema.d/85-hcc.ldif \
    /usr/share/ipa/updates/85-hcc.update \
    /usr/share/ipa/updates/86-hcc-registration-service.update
killall -9 httpd
systemctl restart httpd.service

echo "NOTE: $0 is a hack for internal development."
echo "Some changes require a proper ipa-server-upgrade or ipactl restart."
