#
# IPA plugin for Red Hat consoleDot
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat consoleDot
"""
import os
import logging

from ipalib import Registry
from ipalib import Updater
from ipapython.ipaldap import realm_to_ldapi_uri
from ipapython import ipautil
from ipaplatform import consoledotplatform
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_consoledot_service(Updater):
    """Create keytab for consoledot enrollment service"""

    def execute(self, **options):
        keytab = consoledotplatform.CONSOLEDOT_SERVICE_KEYTAB
        if os.path.isfile(keytab):
            logger.debug("keytab %s exists, nothing to do", keytab)
            return False, []

        ldap_uri = realm_to_ldapi_uri(self.api.env.realm)
        service = consoledotplatform.CONSOLEDOT_SERVICE
        principal = f"{service}/{self.api.env.host}@{self.api.env.realm}"

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
            "Created keytab '%s' for principal '%s'", keytab, principal
        )

        return False, []
