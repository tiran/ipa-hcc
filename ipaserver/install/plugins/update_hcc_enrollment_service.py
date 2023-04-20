#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Configure Hybrid Cloud Console enrollment services
"""
import logging
import os

from ipalib import Registry, Updater, errors
from ipalib.install.kinit import kinit_keytab  # pylint: disable=import-error
from ipaplatform.paths import paths
from ipaplatform.services import knownservices
from ipapython import ipautil
from ipapython.ipaldap import realm_to_ldapi_uri
from ipapython.ipautil import remove_file
from ipapython.kerberos import Principal

from ipahcc import hccplatform
from ipaserver.plugins.hccserverroles import (  # pylint:disable=import-error
    hcc_enrollment_agent_attribute,
    hcc_update_server_attribute,
)

logger = logging.getLogger(__name__)


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
            (hccplatform.HCC_ENROLLMENT_AGENT, self.api.env.host),
            self.api.env.realm,
        )

    def add_hcc_enrollment_service(self):
        principal = self.service_principal
        princname = str(principal)
        try:
            self.api.Command.service_show(principal)
        except errors.NotFound:
            logger.info("Adding service '%s'.", principal)
            # Remove stale keytab
            remove_file(hccplatform.HCC_ENROLLMENT_AGENT_KEYTAB)
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
            hcc_enrollment_agents = server_role.get_hcc_enrollment_agents()
            if host not in hcc_enrollment_agents:
                logger.info(
                    "Adding '%s' to server role '%s'.",
                    host,
                    hcc_enrollment_agent_attribute.name,
                )
                hcc_enrollment_agents.add(host)
                server_role.set_hcc_enrollment_agents(hcc_enrollment_agents)

            hcc_update_server = server_role.get_hcc_update_server()
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
        keytab = hccplatform.HCC_ENROLLMENT_AGENT_KEYTAB
        princname = str(self.service_principal)
        ldap_uri = realm_to_ldapi_uri(self.api.env.realm)

        if os.path.isfile(keytab):
            try:
                kinit_keytab(princname, keytab, "MEMORY:")
            except Exception as e:  # pylint: disable=broad-except
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

    def execute(self, **options):
        self.add_hcc_enrollment_service()
        self.add_hcc_enrollment_service_keytab()
        return False, []
