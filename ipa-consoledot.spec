%global debug_package %{nil}
%global plugin_name consoledot
%global ipa_version 4.9.8

%if 0%{?rhel}
Name:           ipa-%{plugin_name}
%else
Name:           freeipa-%{plugin_name}
%endif
Version:        0.0.1
Release:        1%{?dist}
Summary:        consoleDot extension for IPA

BuildArch:      noarch

License:        GPLv3+
# URL:            https://github.com/tiran/ipa-consoledot
# Source0:        https://github.com/tiran/ipa-consoledot/archive/v%{version}/ipa-consoledot-%{version}.tar.gz

BuildRequires: python3-devel
BuildRequires: systemd

%if 0%{?rhel}
Requires:        ipa-server >= %{ipa_version}
Requires(post):  ipa-server >= %{ipa_version}
%else
Provides:        ipa-%{plugin_name} = %{version}-%{release}
Requires:        freeipa-server >= %{ipa_version}
Requires(post):  freeipa-server >= %{ipa_version}
%endif

%description
A module for IPA server with extensions for consoleDot

%prep
%autosetup -n ipa-%{plugin_name}-%{version}

%build
touch debugfiles.list

%install
rm -rf $RPM_BUILD_ROOT

%__mkdir_p %{buildroot}%{python3_sitelib}/ipaserver/plugins
for j in $(find ipaserver/plugins -name '*.py') ; do
    %__cp -p $j %{buildroot}%{python3_sitelib}/ipaserver/plugins
done

%__mkdir_p %buildroot/%{_datadir}/ipa/schema.d
for j in $(find schema.d/ -name '*.ldif') ; do
    %__cp -p $j %buildroot/%{_datadir}/ipa/schema.d/
done

%__mkdir_p %buildroot/%{_datadir}/ipa/updates
for j in $(find updates/ -name '*.update') ; do
    %__cp -p $j %buildroot/%{_datadir}/ipa/updates/
done

%__mkdir_p %buildroot/%{_datadir}/ipa/ui/js/plugins
for j in $(find ui/ -name '*.js') ; do
    destdir=%buildroot/%{_datadir}/ipa/ui/js/plugins/$(basename ${j%.js})
    %__mkdir_p $destdir
    %__cp -p $j $destdir/
done

mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d/
cp apache/*.conf %{buildroot}%{_sysconfdir}/httpd/conf.d/

mkdir -p %{buildroot}%{_datadir}/ipa
cp wsgi/consoledot.py %{buildroot}%{_datadir}/ipa/

%posttrans
python3 -c "import sys; from ipaserver.install import installutils; sys.exit(0 if installutils.is_ipa_configured() else 1);" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    # This must be run in posttrans so that updates from previous
    # execution that may no longer be shipped are not applied.
    /usr/sbin/ipa-server-upgrade --quiet >/dev/null || :

    # Restart IPA processes. This must be also run in postrans so that plugins
    # and software is in consistent state
    # NOTE: systemd specific section

    /bin/systemctl is-enabled ipa.service >/dev/null 2>&1
    if [  $? -eq 0 ]; then
        /bin/systemctl restart ipa.service >/dev/null 2>&1 || :
    fi
fi

%files
%license COPYING
%doc README.md CONTRIBUTORS.txt
%{python3_sitelib}/ipaserver/plugins/*.py
%{python3_sitelib}/ipaserver/plugins/__pycache__/*.pyc
%{_datadir}/ipa/schema.d/*.ldif
%{_datadir}/ipa/updates/*.update
%{_datadir}/ipa/ui/js/plugins/*
%{_datadir}/ipa/consoledot.py
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/httpd/conf.d/99-consoledot.conf

%changelog
* Tue Nov 01 2022 Christian Heimes <cheimes@redhat.com> - 0.0.1-1
- Initial release
