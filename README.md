# IPA plugin for consokeDot

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
a ``consoleDotSubscriptionId`` are automatically added to the host group.

## ACIs

* ``System: Read consoleDot host attributes``
* ``System: Read consoleDot config attributes``

## Indexes

* Index on ``consoleDotSubscriptionId`` for presence and equality
* Index on ``consoleDotInventoryId`` for presence and equality
* Index on ``consoleDotCertSubject`` for presence and equality
* Uniqueness of ``consoleDotCertSubject`` attributes

## Command line extension

```
$ ipa host-mod --help
...
  ...
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
