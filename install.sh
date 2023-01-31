#!/bin/sh
set -ex

SITE_PACKAGES=$(python3 -c 'from sys import version_info as v; print(f"/usr/lib/python{v.major}.{v.minor}/site-packages")')

if [ -f /usr/share/ipa/schema.d/85-hcc.ldif -a -f /usr/share/ipa/updates/85-hcc.update ]; then
    NEEDS_UPGRADE=0;
else
    NEEDS_UPGRADE=1;
fi

## phase 1, handled by RPM package

# user and group
getent group ipaapi >/dev/null || groupadd -f -r ipaapi
getent passwd ipahcc >/dev/null || useradd -r -g ipaapi -s /sbin/nologin -d /usr/share/ipa-hcc -c "IPA Hybrid Cloud Console enrollment service" ipahcc

# directories, cache directory must be writeable by user
mkdir -p /usr/share/ipa-hcc
mkdir -p /usr/libexec/ipa-hcc
mkdir -p /var/cache/ipa-hcc
chown ipahcc:ipaapi -R /var/cache/ipa-hcc
semanage fcontext -a -f a -s system_u -t httpd_cache_t -r 's0' '/var/cache/ipa-hcc(/.*)?' || :
restorecon -R /var/cache/ipa-hcc || :

# WSGI app and configuration
cp wsgi/hcc_registration_service.py /usr/share/ipa-hcc/
cp apache/ipa-hcc.conf /etc/httpd/conf.d/ipa-hcc.conf
cp refresh_token /etc/ipa || true

# CA certs
cp rhsm/redhat-candlepin-bundle.pem /usr/share/ipa-hcc/redhat-candlepin-bundle.pem
mkdir -p /usr/share/ipa-hcc/cacerts
cp rhsm/cacerts/* /usr/share/ipa-hcc/cacerts/

# gssproxy
cp gssproxy/85-ipa-hcc.conf /etc/gssproxy/
systemctl restart gssproxy.service

# IPA plugins, UI, schema, and update
cp schema.d/85-hcc.ldif /usr/share/ipa/schema.d/
cp updates/85-hcc.update /usr/share/ipa/updates/

mkdir -p -m 755 /usr/share/ipa/ui/js/plugins/hccconfig
cp ui/js/plugins/hccconfig/hccconfig.js /usr/share/ipa/ui/js/plugins/hccconfig/
mkdir -p -m 755 /usr/share/ipa/ui/js/plugins/hcchost
cp ui/js/plugins/hcchost/hcchost.js /usr/share/ipa/ui/js/plugins/hcchost/

cp ipaserver/plugins/*.py ${SITE_PACKAGES}/ipaserver/plugins/
cp ipaserver/install/plugins/*.py ${SITE_PACKAGES}/ipaserver/install/plugins/
cp ipaplatform/*.py ${SITE_PACKAGES}/ipaplatform
python3 -m compileall ${SITE_PACKAGES}/ipaserver/plugins/ ${SITE_PACKAGES}/ipaserver/install/plugins ${SITE_PACKAGES}/ipaplatform

# run updater
if [ $NEEDS_UPGRADE = 1 ]; then
    ipa-server-upgrade
else
    ipa-ldap-updater \
        -S /usr/share/ipa/schema.d/85-hcc.ldif \
        /usr/share/ipa/updates/85-hcc.update
    systemctl restart httpd.service
fi

echo "NOTE: $0 is a hack for internal development."
echo "Some changes require a proper ipa-server-upgrade or ipactl restart."
