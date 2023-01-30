# IPA plugin for consoleDot

The *ipa-consoledot* plugin provides schema extension of IPA for
consoleDot integration. The plugin must be installed on all FreeIPA
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

* *consoleDotOrgId*: int
* *consoleDotSubscriptionId*: string
* *consoleDotInventoryId*: string
* *consoleDotCertSubject*: string (auto-generated)

## Server config

* *consoleDotOrgId*: int

## Host groups

Host group ``consoledot-enrollment`` is created on server upgrade. Hosts with
a ``consoleDotSubscriptionId`` are automatically added to the host group by
an **automember rule**.

## certmap rule

A certmap rule ``rhsm-cert`` matches subject of RHSM certificates to host's
``consoleDotCertSubject` attribute.

## service principal

Each IPA server has a ``consoledot-enrollment/$FQDN`` service with role
``consoleDot Enrollment Administrators``.

## Indexes

* Index on ``consoleDotSubscriptionId`` for presence and equality
* Index on ``consoleDotInventoryId`` for presence and equality
* Index on ``consoleDotCertSubject`` for presence and equality
* Uniqueness of ``consoleDotCertSubject`` attributes

## Update plugin

The server update plugin ``update_consoledot_service`` retrieves the service
keytab for ``consoledot-enrollment/$FQDN`` principal.

## Command line extension

```
$ ipa host-mod --help
  ...
  --consoledotsubscriptionid=STR
  --consoledotinventoryid=STR
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
  --consoledotorgid=INT  organization id
  ...
```

## Roles / Privileges / Permissions

* Permission
  * ``System: Read consoleDot config attributes``
  * ``System: Read consoleDot host attributes``
  * ``System: Modify consoleDot host attributes``
* Role ``consoleDot Enrollment Administrators``
* Privilege ``consoleDot Host Administrators`` that grants permissions
  * ``System: Add Hosts``
  * ``System: Modify consoleDot host attributes``

## Schema / server updater

The update file `85-consoledot.update` for `ipa-server-upgrade` creates:

- host group `consoledot-enrollment`
- automember rule for host group
- certmap rule `rhsm-cert`
- service principal `consoledot-enrollment/$FQDN@$REALM`
- additional role and privileges
- new indexes and unique constraint
- runs `update_consoledot_service` update plugin

The `update_consoledot_service` update plugin:

- creates or validates the keytab for `consoledot-enrollment/$FQDN@$REALM`
  service account
- modifies KRB5 KDC config file to trust the RHSM certificate chain and
  restarts the service if necessary.
- checks consoledotOrgId setting in IPA's global configuration. If the
  option is not set, then it sets the value based on the subject org
  name of server's RHSM certificate (`/etc/pki/consumer/cert.pem`).


## Server test setup

Create a [Red Hat API](https://access.redhat.com/articles/3626371) refresh
token and store it in file `refresh_token`. `install.sh` will copy it to
`/etc/ipa`. **WARNING** the token has the same privileges as your user
account.

Install plugin and other services
```
./install.sh
```

- creates `ipaconsoledot` system user
- copies plugins, UI extension, schema extension, and updates
- runs updater


## Client test setup

Current RHEL releases of `ipa-client` are missing PKINIT option.

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

1) Install packages

```
dnf copr enable copr.devel.redhat.com/cheimes/hmsidm
dnf install ipa-consoledot-client-enrollment
```

2) Configure DNS and hostname. The client must be able to discover its
IPA domain and IPA servers with DNS SRV discovery.

3) Enable the auto-enrollment service

```
systemctl enable ipa-consoledot-enrollment.service
```

2) Register system with RHSM and Insights

```
rhc connect
```

The `ipa-consoledot-enrollment.service` triggers after `rhc` starts the
`rhcd` service. The enrollment service runs the script
`ipa-consoledot-enrollment.py`, which uses DNS SRV discovery to locate
IPA servers, connects to `/consoledot` WSGI app to self-register the
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
  https://ipaserver.hmsidm.test/consoledot
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
  authentication from CA path `/usr/share/ipa-consoledot/cacerts/`.
- Kerberos KDC loads extra PKINIT trust anchors from
  `FILE:/usr/share/ipa-consoledot/redhat-candlepin-bundle.pem`.

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
