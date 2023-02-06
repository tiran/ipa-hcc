#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Configure Hybrid Cloud Console basic settings
"""
import os
import logging

from augeas import Augeas
from cryptography.x509.oid import NameOID

from ipalib import errors
from ipalib import Registry
from ipalib import Updater
from ipalib import x509
from ipaplatform import hccplatform
from ipaplatform.paths import paths
from ipaplatform.services import knownservices

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_hcc(Updater):
    """Configure Hybrid Cloud Console basic settings

    - Add RHSM cert chain to KDC
    - auto-configure HCC org id
    """

    def modify_krb5kdc_conf(self):
        """Add RHSM cert chain to KDC"""
        anchor = "FILE:{}".format(hccplatform.HMSIDM_CA_BUNDLE_PEM)
        logger.debug(
            "Checking for 'pkinit_anchors=%s' in '%s'",
            anchor,
            paths.KRB5KDC_KDC_CONF,
        )

        aug = Augeas(
            flags=Augeas.NO_LOAD | Augeas.NO_MODL_AUTOLOAD,
            loadpath=paths.USR_SHARE_IPA_DIR,
        )
        modified = False

        realm = self.api.env.realm
        path = "/files{conf}/realms/{realm}".format(
            conf=paths.KRB5KDC_KDC_CONF, realm=realm
        )
        expr = '{path}/pkinit_anchors[.="{anchor}"]'.format(
            path=path, anchor=anchor
        )

        try:
            aug.transform("IPAKrb5", paths.KRB5KDC_KDC_CONF)
            aug.load()
            if not aug.match(expr):
                aug.set(
                    "{path}/pkinit_anchors[last()+1]".format(path=path),
                    anchor,
                )
                modified = True

            if modified:
                logger.debug("Added new pkinit anchor to KDC configuration.")
                try:
                    aug.save()
                except IOError:
                    for error_path in aug.match("/augeas//error"):
                        logger.error(
                            "augeas: %s",
                            aug.get(error_path),
                        )
                    raise
            else:
                logger.debug("KDC already configured.")
        finally:
            aug.close()

        if modified:
            # restart KDC if running
            logger.debug("Restarting KDC")
            if hasattr(knownservices.krb5kdc, "try_restart"):
                knownservices.krb5kdc.try_restart()
            else:
                if knownservices.krb5kdc.is_running():
                    knownservices.krb5kdc.restart()

        return modified

    def configure_hcc_orgid(self):
        """Auto-configure global HCC org id"""
        result = self.api.Command.config_show()["result"]
        org_ids = result.get("hccorgid")
        if org_ids:
            logger.debug(
                "hccorgid already configured: %s",
                org_ids[0],
            )
            return False

        if not os.path.isfile(hccplatform.RHSM_CERT):
            logger.debug(
                "RHSM certificate file '%s' does not exist.",
                hccplatform.RHSM_CERT,
            )
            return False

        try:
            with open(hccplatform.RHSM_CERT, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
        except Exception:
            logger.exception(
                "Failed to parse '%s'.",
                hccplatform.RHSM_CERT,
            )
            return False

        nas = list(cert.subject)
        if len(nas) != 2 or nas[0].oid != NameOID.ORGANIZATION_NAME:
            logger.error("Unexpected cert subject %s", cert.subject)
            return False
        try:
            org_id = int(nas[0].value)
        except (ValueError, TypeError):
            logger.error("Unexpected cert subject %s", cert.subject)
            return False

        try:
            self.api.Command.config_mod(hccorgid=org_id)
        except errors.EmptyModlist:
            return False
        else:
            return True

    def execute(self, **options):
        self.modify_krb5kdc_conf()
        self.configure_hcc_orgid()
        return False, []
