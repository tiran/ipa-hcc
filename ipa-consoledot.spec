%if 0%{?rhel}
# RHEL 8 or 9
%global package_name ipa-consoledot
%global alt_name freeipa-consoledot
%global ipa_name ipa
%if 0%{?rhel} < 9
%global ipa_version 4.9.10
%else
%global ipa_version 4.10.0
%endif
%else
# Fedora
%global package_name freeipa-consoledot
%global alt_name ipa-consoledot
%global ipa_name freeipa
%global ipa_version 4.10.0
%endif

Name:           %{package_name}
Version:        0.0.1
Release:        2%{?dist}
Summary:        consoleDot extension for IPA

BuildArch:      noarch

License:        GPLv3+
# URL:            https://github.com/tiran/ipa-consoledot
# Source0:        https://github.com/tiran/ipa-consoledot/archive/v{version}/ipa-consoledot-{version}.tar.gz
Source0:    ipa-consoledot-%{version}.tar.gz

BuildRequires: python3-devel
BuildRequires: systemd-devel
BuildRequires: selinux-policy-devel

%description
An extension for IPA integration with Red Hat Console (consoleDot).


%package common
Summary: Common files for IPA consoleDot extension
BuildArch: noarch

Provides: %{alt_name}-common = %{version}
Conflicts: %{alt_name}-common
Obsoletes: %{alt_name}-common < %{version}
Requires: %{ipa_name}-client >= %{ipa_version}

%description common
This package contains common files for consoleDot IPA extension.


%package server-plugin
Summary: Server plugin for IPA consoleDot extension
BuildArch: noarch

Provides: %{alt_name}-server-plugin = %{version}
Conflicts: %{alt_name}-server-plugin
Obsoletes: %{alt_name}-server-plugin < %{version}
Requires: %{package_name}-common >= %{version}
Requires: %{ipa_name}-server >= %{ipa_version}
Requires(post): %{ipa_name}-server >= %{ipa_version}
%{?systemd_requires}

%description server-plugin
This package contains server plugins and WebUI extension for
consoleDot IPA extension.

%posttrans server-plugin
python3 -c "import sys; from ipaserver.install import installutils; sys.exit(0 if installutils.is_ipa_configured() else 1);" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    /usr/sbin/ipa-server-upgrade --quiet >/dev/null || :
    /usr/sbin/ipa-cacert-manage --quiet install %{_datadir}/ipa-consoledot/hmsidm-ca-bundle.pem || :
    /usr/sbin/ipa-certupdate --quiet || :
    # restart if running
    /bin/systemctl try-restart ipa.service >/dev/null 2>&1 || :
fi


%package registration-service
Summary: Registration service for IPA consoleDot extension
BuildArch: noarch

Provides:       %{alt_name}-registration-service = %{version}
Conflicts: %{alt_name}-registration-service
Obsoletes: %{alt_name}-registration-service < %{version}
# Don't allow installation on an IPA server
# Conflicts:       {ipa_name}-server
Requires: %{package_name}-common >= %{version}
Requires: httpd
Requires: python3-mod_wsgi
Requires: mod_ssl
%{?selinux_requires}
%{?systemd_requires}

%description registration-service
This package contains the registration service for
consoleDot IPA extension.

%pre registration-service
# create user account for service
getent passwd ipaconsoledot >/dev/null || useradd -r -g ipaapi -s /sbin/nologin -d / -c "IPA consoleDot enrollment service" ipaconsoledot

%post registration-service
# SELinux context for cache dir
/usr/sbin/semanage fcontext -a -f a -s system_u -t httpd_cache_t -r 's0' '/var/cache/ipa-consoledot(/.*)?' 2>/dev/null || :
/usr/sbin/restorecon -R /var/cache/ipa-consoledot || :
# pick up new gssproxy and HTTPD config (restart if running)
systemctl try-restart gssproxy.service httpd.service

%postun registration-service
/usr/sbin/semanage fcontext -d '/var/cache/ipa-consoledot(/.*)?' 2>/dev/null || :


%prep
%autosetup -n ipa-consoledot-%{version}

%build
touch debugfiles.list

%install
rm -rf $RPM_BUILD_ROOT

%__mkdir_p %{buildroot}%{python3_sitelib}/ipaplatform
cp -p ipaplatform/*.py %{buildroot}%{python3_sitelib}/ipaplatform/

%__mkdir_p %{buildroot}%{python3_sitelib}/ipaserver/plugins
cp -p ipaserver/plugins/*.py %{buildroot}%{python3_sitelib}/ipaserver/plugins/

%__mkdir_p %{buildroot}%{python3_sitelib}/ipaserver/install/plugins
cp -p ipaserver/install/plugins/*.py %{buildroot}%{python3_sitelib}/ipaserver/install/plugins/

%__mkdir_p %buildroot/%{_datadir}/ipa/schema.d
cp -p schema.d/*.ldif %buildroot/%{_datadir}/ipa/schema.d/

%__mkdir_p %buildroot/%{_datadir}/ipa/updates
cp -p updates/*.update %buildroot/%{_datadir}/ipa/updates/

%__mkdir_p %buildroot/%{_datadir}/ipa/ui/js/plugins
for j in $(find ui/ -name '*.js') ; do
    destdir=%buildroot/%{_datadir}/ipa/ui/js/plugins/$(basename ${j%.js})
    %__mkdir_p $destdir
    %__cp -p $j $destdir/
done

mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d/
cp apache/consoledot.conf %{buildroot}%{_sysconfdir}/httpd/conf.d/85-consoledot.conf

mkdir -p %{buildroot}%{_sysconfdir}/gssproxy
cp gssproxy/85-consoledot-enrollment.conf %{buildroot}%{_sysconfdir}/gssproxy/85-consoledot-enrollment.conf

mkdir -p %{buildroot}%{_datadir}/ipa-consoledot
cp -p wsgi/consoledotwsgi.py %{buildroot}%{_datadir}/ipa-consoledot/
cp -p rhsm/hmsidm-ca-bundle.pem %{buildroot}%{_datadir}/ipa-consoledot/

mkdir -p %{buildroot}%{_localstatedir}/cache/ipa-consoledot


%files common
%doc README.md CONTRIBUTORS.txt
%license COPYING
%dir %{_datadir}/ipa-consoledot/
%{_datadir}/ipa-consoledot/hmsidm-ca-bundle.pem
%{python3_sitelib}/ipaplatform/*.py
%{python3_sitelib}/ipaplatform/__pycache__/*.pyc


%files server-plugin
%doc README.md CONTRIBUTORS.txt
%license COPYING
%{python3_sitelib}/ipaserver/plugins/*.py
%{python3_sitelib}/ipaserver/plugins/__pycache__/*.pyc
%{python3_sitelib}/ipaserver/install/plugins/*.py
%{python3_sitelib}/ipaserver/install/plugins/__pycache__/*.pyc
%{_datadir}/ipa/schema.d/*.ldif
%{_datadir}/ipa/updates/*.update
%{_datadir}/ipa/ui/js/plugins/*


%files registration-service
%attr(0755,ipaconsoledot,ipaapi) %dir %{_localstatedir}/cache/ipa-consoledot
%{_datadir}/ipa-consoledot/consoledotwsgi.py
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/httpd/conf.d/85-consoledot.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/gssproxy/85-consoledot-enrollment.conf


%changelog
* Fri Dec 09 2022 Christian Heimes <cheimes@redhat.com> - 0.0.1-2
- Initial release
