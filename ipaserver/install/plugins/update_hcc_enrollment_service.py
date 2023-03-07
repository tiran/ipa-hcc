#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Configure Hybrid Cloud Console enrollment services
"""
import os
import logging

from ipalib import errors
from ipalib import Registry
from ipalib import Updater
from ipalib.install.kinit import kinit_keytab

try:
    from ipapython.ipaldap import realm_to_ldapi_uri
    from ipapython.ipautil import remove_file
except ImportError:
    # IPA 4.6
    from ipaserver.install.installutils import realm_to_ldapi_uri, remove_file
from ipapython.certdb import NSSDatabase, parse_trust_flags
from ipapython.kerberos import Principal
from ipapython import ipautil
from ipapython.version import VERSION
from ipaplatform import hccplatform
from ipaplatform.paths import paths
from ipaplatform.services import knownservices
from ipaserver.plugins.hccserverroles import (
    hcc_enrollment_server_attribute,
    hcc_update_server_attribute,
)

logger = logging.getLogger(__name__)


CANDLEPIN_CHAIN = [
    (
        "redhat-entitlement-master",
        "/usr/share/ipa-hcc/cacerts/redhat-entitlement-master-ca.pem",
    ),
    (
        "redhat-entitlement-authority",
        "/usr/share/ipa-hcc/cacerts/redhat-entitlement-authority-2022.pem",
    ),
    (
        "redhat-candlepin",
        "/usr/share/ipa-hcc/cacerts/candlepin-redhat-ca-sha256.pem",
    ),
]

register = Registry()


@register()
class update_hcc_enrollment_service(Updater):
    """Configure Hybrid Cloud Console enrollment services

    - create service account
    - add service to 'HCC Enrollment Administrators' role
    - verify/create keytab for hcc-enrollment service
    """

    @property
    def service_principal(self):
        return Principal(
            (hccplatform.HCC_SERVICE, self.api.env.host),
            self.api.env.realm,
        )

    def add_hcc_enrollment_service(self):
        principal = self.service_principal
        princname = hccplatform.text(principal)
        try:
            self.api.Command.service_show(principal)
        except errors.NotFound:
            logger.info("Adding service '%s'.", principal)
            # Remove stale keytab
            remove_file(hccplatform.HCC_SERVICE_KEYTAB)
            # force is required to skip the 'verify_host_resolvable' check
            # in service_add pre-callback. ipa-server-install runs updates
            # before it installs DNS service.
            self.api.Command.service_add(
                principal,
                force=True,
            )
            logger.info(
                "Adding service '%s' to role '%s'.",
                principal,
                hccplatform.HCC_ENROLLMENT_ROLE,
            )
            self.api.Command.role_add_member(
                hccplatform.HCC_ENROLLMENT_ROLE,
                service=princname,
            )

            host = self.api.env.host
            server_role = self.api.Object.server_role
            hcc_enrollment_servers = server_role.get_hcc_enrollment_servers()
            if host not in hcc_enrollment_servers:
                logger.info(
                    "Adding '%s' to server role '%s'.",
                    host,
                    hcc_enrollment_server_attribute.name,
                )
                hcc_enrollment_servers.add(host)
                server_role.set_hcc_enrollment_servers(hcc_enrollment_servers)

            hcc_update_server = server_role.get_update_server()
            if hcc_update_server is None:
                logger.info(
                    "Setting '%s' as single server role '%s'.",
                    host,
                    hcc_update_server_attribute.name,
                )
                server_role.set_hcc_update_server(host)

            return True
        else:
            logger.info(
                "Service '%s' already exists. Not updating role '%s'.",
                principal,
                hccplatform.HCC_ENROLLMENT_ROLE,
            )
            return (False,)

    def add_hcc_enrollment_service_keytab(self):
        """Create keytab for hcc-enrollment WSGI app"""
        keytab = hccplatform.HCC_SERVICE_KEYTAB
        princname = hccplatform.text(self.service_principal)
        ldap_uri = realm_to_ldapi_uri(self.api.env.realm)

        if os.path.isfile(keytab):
            try:
                kinit_keytab(princname, keytab, "MEMORY:")
            except Exception as e:
                # keytab from previous installation?
                logger.debug("keytab %s is outdated: %s", keytab, e)
                remove_file(keytab)
            else:
                logger.debug(
                    "keytab %s exists and works, nothing to do",
                    keytab,
                )
                return False

        # fmt: off
        args = [
            paths.IPA_GETKEYTAB,
            "-k", keytab,
            "-p", princname,
            "-H", ldap_uri,
            "-Y", "EXTERNAL"
        ]
        # fmt: on
        ipautil.run(args)
        os.chmod(keytab, 0o640)
        os.chown(keytab, 0, 0)

        logger.debug(
            "Created keytab '%s' for principal '%s'",
            keytab,
            princname,
        )
        if knownservices.gssproxy.is_running():
            logger.debug("Restarting gssproxy")
            knownservices.gssproxy.restart()

        return True

    def add_ca_to_httpd_nssdb(self):
        db = NSSDatabase(paths.HTTPD_ALIAS_DIR)
        if not os.path.isfile(db.certdb):
            logger.debug("Cert DB %s does not exist.", db.certdb)
            return False

        nicknames = set(nick for nick, _trust in db.list_certs())
        # CA valid for client cert auth
        trustflags = parse_trust_flags("T,,")
        modified = False

        for nick, certpath in CANDLEPIN_CHAIN:
            if nick not in nicknames:
                logger.debug(
                    "Adding %s (%s) to %s", nick, certpath, db.secdir
                )
                db.import_pem_cert(nick, trustflags, certpath)
                modified = True

        if modified and knownservices.httpd.is_running():
            logger.debug("Restarting httpd")
            knownservices.httpd.restart()

    def execute(self, **options):
        self.add_hcc_enrollment_service()
        self.add_hcc_enrollment_service_keytab()
        if VERSION.startswith("4.6"):
            self.add_ca_to_httpd_nssdb()
        return False, []
