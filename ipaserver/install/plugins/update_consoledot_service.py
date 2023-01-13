#
# IPA plugin for Red Hat consoleDot
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat consoleDot
"""
import os
import logging

from augeas import Augeas

from ipalib import Registry
from ipalib import Updater
from ipapython.ipaldap import realm_to_ldapi_uri
from ipapython import ipautil
from ipaplatform import consoledotplatform
from ipaplatform.paths import paths
from ipaplatform.services import knownservices

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_consoledot_service(Updater):
    """Create keytab for consoledot enrollment service"""

    def add_service_keytab(self):
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

    def modify_krb5kdc_conf(self):
        anchor = f"FILE:{consoledotplatform.HMSIDM_CA_BUNDLE_PEM}"
        logger.debug(
            "Checking for 'pkinit_anchors=%s' in '%s'", anchor, paths.KRB5KDC_KDC_CONF
        )

        aug = Augeas(
            flags=Augeas.NO_LOAD | Augeas.NO_MODL_AUTOLOAD,
            loadpath=paths.USR_SHARE_IPA_DIR,
        )
        modified = False

        realm = self.api.env.realm
        path = f"/files{paths.KRB5KDC_KDC_CONF}/realms/{realm}"
        expr = f'{path}/pkinit_anchors[.="{anchor}"]'

        try:
            aug.transform("IPAKrb5", paths.KRB5KDC_KDC_CONF)
            aug.load()
            if not aug.match(expr):
                aug.set(f"{path}/pkinit_anchors[last()+1]", anchor)
                modified = True

            if modified:
                logger.debug("Added new pkinit anchor to KDC configuration.")
                try:
                    aug.save()
                except IOError:
                    for error_path in aug.match('/augeas//error'):
                        logger.error('augeas: %s', aug.get(error_path))
                    raise
            else:
                logger.debug("KDC already configured.")
        finally:
            aug.close()
        
        if modified:
            # restart KDC if running
            logger.debug("Restarting KDC")
            knownservices.krb5kdc.try_restart()

    def execute(self, **options):
        self.add_service_keytab()
        self.modify_krb5kdc_conf()
        return False, []
