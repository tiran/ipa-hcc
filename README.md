# IPA plugin for Hybrid Cloud Console

The *ipa-hcc* plugin provides schema extension of IPA for
Hybrid Cloud Console integration. The plugin must be installed on all FreeIPA
servers, preferable before the server/replica is installed.

If the plugin is installed later, then the local schema cache may be
outdated and ``ipa`` command may not be aware of the new attributes.
In that case the local schema cache can be refreshed by enforcing
a schema check ``ipa -eforce_schema_check=True ping`` or by purging
the cache with ``rm -rf ~/.cache/ipa``.

Installation requires a server upgrade ``ipa-server-upgrade`` and
restart of services ``ipactl restart``. The post transaction hook
of the RPM package takes care of both. A server upgrade can take a
while and can disrupt normal operations on the machine. It is advised
to serialize the operation and install the plugin on one server at a
time.

## Additional host attributes

* *HCCOrgId*: int
* *HCCSubscriptionId*: string
* *HCCInventoryId*: string
* *HCCCertSubject*: string (auto-generated)

## Server config

* *HCCOrgId*: int

## Host groups

Host group ``hcc-enrollment`` is created on server upgrade. Hosts with
a ``HCCSubscriptionId`` are automatically added to the host group by
an **automember rule**.

## certmap rule

A certmap rule ``rhsm-cert`` matches subject of RHSM certificates to host's
``HCCCertSubject` attribute.

## service principal

Each IPA server has a ``hcc-enrollment/$FQDN`` service with role
``HCC Enrollment Administrators``.

## Indexes

* Index on ``HCCSubscriptionId`` for presence and equality
* Index on ``HCCInventoryId`` for presence and equality
* Index on ``HCCCertSubject`` for presence and equality
* Uniqueness of ``HCCCertSubject`` attributes

## Command line extension

```
$ ipa host-mod --help
  ...
  --hccsubscriptionid=STR
  --hccinventoryid=STR
  ...
$ ipa host-show host.test.example
  ...
  organization id: 42
  subscription id: 1f84492f-a824-41b8-8ccd-a4e9e1ab2f3d
  inventory id: e98a6828-faf2-4917-8f0f-7af27fad3683
  RHSM certificate subject: O=42,CN=1f84492f-a824-41b8-8ccd-a4e9e1ab2f3d
  ...
$ ipa config-mod --help
  ...
  --hccorgid=INT  organization id
  ...
```

## Roles / Privileges / Permissions

* Permission
  * ``System: Read HCC config attributes``
  * ``System: Read HCC host attributes``
  * ``System: Modify HCC host attributes``
* Role ``HCC Enrollment Administrators``
* Privilege ``HCC Host Administrators`` that grants permissions
  * ``System: Add Hosts``
  * ``System: Modify HCC host attributes``

## Schema / server updater

The update file `85-hcc.update` for `ipa-server-upgrade` creates:

- host group `hcc-enrollment`
- automember rule for host group
- certmap rule `rhsm-cert`
- service principal `hcc-enrollment/$FQDN@$REALM`
- additional role and privileges
- new indexes and unique constraint
- runs `update_hcc` update plugin

The `update_hcc` update plugin:

- creates or validates the keytab for `hcc-enrollment/$FQDN@$REALM`
  service account
- modifies KRB5 KDC config file to trust the RHSM certificate chain and
  restarts the service if necessary.
- checks HCCOrgId setting in IPA's global configuration. If the
  option is not set, then it sets the value based on the subject org
  name of server's RHSM certificate (`/etc/pki/consumer/cert.pem`).


## Server test setup

1) Prepare host

```
$ hostnamectl set-hostname ipaserver.ipahcc.test
$ vi /etc/hosts
# add public IPv4 address to /etc/hosts
$ dnf install ipa-server ipa-server-dns
```

2) Install an IPA server with DNS

```
$ ipa-server-install -n ipahcc.test -r IPAHCC.TEST -p DMSecret123 -a Secret123 \
     --setup-dns --auto-forwarders --no-dnssec-validation -U
```

3) Configure `trusted_network` ACL in `/etc/named/*.conf` and
`systemctl restart named.service`, e.g.

```
# /etc/named/ipa-ext.conf
acl "trusted_network" {
   localnets;
   localhost;
   10.0.0.0/8;
};
```

```
# /etc/named/ipa-options-ext.conf
allow-recursion { trusted_network; };
allow-query-cache { trusted_network; };
listen-on-v6 { any; };
dnssec-validation no;
```

4) Add client hostname to DNS

```
$ kinit admin
$ ipa dnsrecord-add ipahcc.test ipaclient1 --a-rec=...
```

5) Create a [Red Hat API](https://access.redhat.com/articles/3626371) refresh
token and save it in `/etc/ipa/refresh_token`.

**WARNING** the token has the same privileges as your user
account.

6) Install plugin and other services

```
dnf copr enable copr.devel.redhat.com/cheimes/hmsidm
dnf install --refresh ipa-hcc-registration-service ipa-hcc-server-plugin
```

## Client test setup

1) Install packages

```
dnf copr enable copr.devel.redhat.com/cheimes/hmsidm
dnf install --refresh ipa-client ipa-hcc-client-enrollment
```

2) Current RHEL releases of `ipa-client` are missing PKINIT option.

RHEL 9.1 hack:

```
curl -o /usr/lib/python3.9/site-packages/ipaclient/install/client.py https://raw.githubusercontent.com/freeipa/freeipa/release-4-10-1/ipaclient/install/client.py
curl -o /usr/lib/python3.9/site-packages/ipalib/install/kinit.py https://raw.githubusercontent.com/freeipa/freeipa/release-4-10-1/ipalib/install/kinit.py
```

RHEL 8.7 hack:
```
curl -o /usr/lib/python3.6/site-packages/ipaclient/install/client.py https://raw.githubusercontent.com/freeipa/freeipa/release-4-9-11/ipaclient/install/client.py
curl -o /usr/lib/python3.6/site-packages/ipalib/install/kinit.py https://raw.githubusercontent.com/freeipa/freeipa/release-4-9-11/ipalib/install/kinit.py
```

3) Configure DNS and hostname. The client must be able to discover its
IPA domain and IPA servers with DNS SRV discovery.

4) Enable the auto-enrollment service

```
systemctl enable ipa-hcc-auto-enrollment.service
```

5) Register system with RHSM and Insights

```
rhc connect
```

The `ipa-hcc-auto-enrollment.service` triggers after `rhc` starts the
`rhcd` service. The enrollment service runs the script
`ipa-hcc-auto-enrollment.py`, which uses DNS SRV discovery to locate
IPA servers, connects to `/hcc` WSGI app to self-register the
host and finally runs `ipa-client-install`.

## Client test setup (step by step)

1) Copy `/var/lib/ipa-client/pki/kdc-ca-bundle.pem` from server to client.

2) Register system with RHSM and Insights

```
rhc connect
```

3) Self-register host with IdM

```
curl \
  --cacert /root/kdc-ca-bundle.pem \
  --cert /etc/pki/consumer/cert.pem \
  --key /etc/pki/consumer/key.pem \
  https://ipaserver.hmsidm.test/hcc
```

4) Enroll host with IdM

```
ipa-client-install \
  --pkinit-identity=FILE:/etc/pki/consumer/cert.pem,/etc/pki/consumer/key.pem \
  --pkinit-anchor=FILE:/root/kdc-ca-bundle.pem \
  --server ipaserver.hmsidm.test --domain hmsidm.test -U -N
```

## Notes

- IPA's KDC plugin caches certmap rules for 5 minutes. For rapid testing
  restart the KDC with ``systemctl restart krb5kdc.service``. See
  ``ipa_kdc_certauth.c``: ``DEFAULT_CERTMAP_LIFETIME``.
- ``ipa certmap-match`` is only implemented for users. It cannot be used
  to test cert mappings for hosts.

## Workarounds

IdM does not implement [#9272](https://pagure.io/freeipa/issue/9272)
*"Install CA certificates only for PKINIT or TLS client auth"*, yet.

- Apache HTTPd is configured to load extra CA certs for client cert
  authentication from CA path `/usr/share/ipa-hcc/cacerts/`.
- Kerberos KDC loads extra PKINIT trust anchors from
  `FILE:/usr/share/ipa-hcc/redhat-candlepin-bundle.pem`.

## RPM build

[rpkg](https://docs.pagure.org/rpkg-util/v3/index.html)

```
rpkg spec --outdir .
```

## License

See file 'COPYING' for use and warranty information

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
