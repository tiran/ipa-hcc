#!/bin/sh
set -ex

SITE_PACKAGES=$(python3 -c 'from sys import version_info as v; print(f"/usr/lib/python{v.major}.{v.minor}/site-packages")')

if [ -f /usr/share/ipa/schema.d/85-consoledot.ldif -a -f /usr/share/ipa/updates/85-consoledot.update ]; then
    NEEDS_UPGRADE=0;
else
    NEEDS_UPGRADE=1;
fi

## phase 1, handled by RPM package

# user and group
getent group ipaapi >/dev/null || groupadd -f -r ipaapi
getent passwd ipaconsoledot >/dev/null || useradd -r -g ipaapi -s /sbin/nologin -d /usr/share/ipa-consoledot -c "IPA consoleDot enrollment service" ipaconsoledot

# directories, cache directory must be writeable by user
mkdir -p /usr/share/ipa-consoledot
mkdir -p /usr/libexec/ipa-consoledot
mkdir -p /var/cache/ipa-consoledot
chown ipaconsoledot:ipaapi -R /var/cache/ipa-consoledot
semanage fcontext -a -f a -s system_u -t httpd_cache_t -r 's0' '/var/cache/ipa-consoledot(/.*)?' || :
restorecon -R /var/cache/ipa-consoledot || :

# WSGI app and configuration
cp wsgi/consoledotwsgi.py /usr/share/ipa-consoledot/
cp apache/consoledot.conf /etc/httpd/conf.d/85-consoledot.conf
cp refresh_token /etc/ipa || true

# CA certs
cp rhsm/hmsidm-ca-bundle.pem /usr/share/ipa-consoledot/hmsidm-ca-bundle.pem
mkdir -p /usr/share/ipa-consoledot/cacerts
cp rhsm/cacerts/* /usr/share/ipa-consoledot/cacerts/

# gssproxy
cp gssproxy/85-consoledot-enrollment.conf /etc/gssproxy/
systemctl restart gssproxy.service

# IPA plugins, UI, schema, and update
cp schema.d/85-consoledot.ldif /usr/share/ipa/schema.d/
cp updates/85-consoledot.update /usr/share/ipa/updates/

mkdir -p -m 755 /usr/share/ipa/ui/js/plugins/consoledotconfig
cp ui/js/plugins/consoledotconfig/consoledotconfig.js /usr/share/ipa/ui/js/plugins/consoledotconfig/
mkdir -p -m 755 /usr/share/ipa/ui/js/plugins/consoledothost
cp ui/js/plugins/consoledothost/consoledothost.js /usr/share/ipa/ui/js/plugins/consoledothost/

cp ipaserver/plugins/*.py ${SITE_PACKAGES}/ipaserver/plugins/
cp ipaserver/install/plugins/*.py ${SITE_PACKAGES}/ipaserver/install/plugins/
cp ipaplatform/*.py ${SITE_PACKAGES}/ipaplatform
python3 -m compileall ${SITE_PACKAGES}/ipaserver/plugins/ ${SITE_PACKAGES}/ipaserver/install/plugins ${SITE_PACKAGES}/ipaplatform

# run updater
if [ $NEEDS_UPGRADE = 1 ]; then
    ipa-server-upgrade
else
    ipa-ldap-updater \
        -S /usr/share/ipa/schema.d/85-consoledot.ldif \
        /usr/share/ipa/updates/85-consoledot.update
    systemctl restart httpd.service
fi

echo "NOTE: $0 is a hack for internal development."
echo "Some changes require a proper ipa-server-upgrade or ipactl restart."
