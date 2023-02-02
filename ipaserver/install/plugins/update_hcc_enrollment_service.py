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
from ipapython.kerberos import Principal
from ipapython.ipaldap import realm_to_ldapi_uri
from ipapython import ipautil
from ipaplatform import hccplatform
from ipaplatform.paths import paths

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
    def service_principal(self) -> str:
        return str(
            Principal(
                (
                    hccplatform.HCC_SERVICE,
                    self.api.env.host,
                ),
                self.api.env.realm,
            )
        )

    def add_hcc_enrollment_service(self) -> bool:
        name = self.service_principal
        try:
            self.api.Command.service_show(name)
        except errors.NotFound:
            logger.info("Adding service '%s'", name)
            # Remove stale keytab
            ipautil.remove_file(hccplatform.HCC_SERVICE_KEYTAB)
            # force is required to skip the 'verify_host_resolvable' check
            # in service_add pre-callback. ipa-server-install runs updates
            # before it installs DNS service.
            self.api.Command.service_add(
                name,
                force=True,
            )
            logger.info(
                "Adding service '%s' to role '%s'",
                name,
                hccplatform.HCC_ENROLLMENT_ROLE,
            )
            self.api.Command.role_add_member(
                hccplatform.HCC_ENROLLMENT_ROLE,
                service=str(name),
            )
            return True
        else:
            logger.info(
                "Service '%s' already exists. Not updating role '%s'.",
                name,
                hccplatform.HCC_ENROLLMENT_ROLE,
            )
            return (False,)

    def add_hcc_enrollment_service_keytab(self) -> bool:
        """Create keytab for hcc-enrollment WSGI app"""
        keytab = hccplatform.HCC_SERVICE_KEYTAB
        service = hccplatform.HCC_SERVICE
        principal = f"{service}/{self.api.env.host}@{self.api.env.realm}"
        ldap_uri = realm_to_ldapi_uri(self.api.env.realm)

        if os.path.isfile(keytab):
            try:
                kinit_keytab(principal, keytab, "MEMORY:")
            except Exception as e:
                # keytab from previous installation?
                logger.debug("keytab %s is outdated: %s", keytab, e)
                ipautil.remove_file(keytab)
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
            "-p", principal,
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
            principal,
        )
        return True

    def execute(self, **options):
        self.add_hcc_enrollment_service()
        self.add_hcc_enrollment_service_keytab()
        return False, []
