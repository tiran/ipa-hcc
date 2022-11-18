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

## Indexes

* Index on ``consoleDotSubscriptionId`` for presence and equality
* Index on ``consoleDotInventoryId`` for presence and equality
* Index on ``consoleDotCertSubject`` for presence and equality
* Uniqueness of ``consoleDotCertSubject`` attributes

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

## Server test setup

Add user account

```
useradd -r -m -d /var/lib/ipa/consoledot -g ipaapi ipaconsoledot
```

Install plugin
```
./install.sh
```

Configure consoleDot org id (replace 42 with your org id)

```
ipa config-mod --consoledotorgid=42
```

Add enrollment service account
```
ipa service-add consoledot-enrollment/$(hostname)
ipa role-add-member --services=consoledot-enrollment/$(hostname) "consoleDot Enrollment Administrators"
```

Configure keytab
TODO: get gssproxy working
```
ipa-getkeytab -k /var/lib/ipa/consoledot/service.keytab -p consoledot-enrollment/$(hostname)
chown -R ipaconsoledot:ipaapi /var/lib/ipa/consoledot/
```

Import cross-signed RHSM cert chain (required on RHEL 9)
```
ipa-cacert-manage install rhsm/hmsidm-ca-bundle.pem
ipa-certupdate
systemctl restart krb5kdc.service
```

**or** import RHSM cert chain
```
ipa-cacert-manage install /etc/rhsm/ca/redhat-uep.pem
ipa-cacert-manage install rhsm/candlepin-redhat-ca.pem
ipa-certupdate
systemctl restart krb5kdc.service
```


## Client test setup

Update RHSM UUID in `/usr/share/ipa/consoledot.py` on the IPA server.

Copy `/var/lib/ipa-client/pki/kdc-ca-bundle.pem` from server to client.

Self-register system

```
curl \
  --cacert /root/kdc-ca-bundle.pem \
  --cert /etc/pki/consumer/cert.pem \
  --key /etc/pki/consumer/key.pem \
  https://ipaserver.hmsidm.test/consoledot
```

Enroll system

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
