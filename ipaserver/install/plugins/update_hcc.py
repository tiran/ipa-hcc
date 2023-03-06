#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Configure Hybrid Cloud Console basic settings
"""
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

    def parse_rhsm_cert(self):
        """Parse RHSM certificate, return org_id and rhsm_id (CN UUID)"""
        with open(hccplatform.RHSM_CERT, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        nas = list(cert.subject)
        if len(nas) != 2 or nas[0].oid != NameOID.ORGANIZATION_NAME:
            raise ValueError(
                "Invalid cert subject {subject}.".format(subject=cert.subject)
            )
        try:
            org_id = int(nas[0].value)
        except (ValueError, TypeError):
            raise ValueError(
                "Invalid cert subject {subject}.".format(subject=cert.subject)
            )
        return org_id, nas[1].value

    def configure_global_hcc_orgid(self, org_id):
        """Auto-configure global HCC org id"""
        # check if org_id is already set, so we don't configure a different
        # org id.
        result = self.api.Command.config_show(raw=True)["result"]
        current_org_ids = result.get("hccorgid")
        if current_org_ids:
            logger.debug(
                "hccOrgId already configured: %s",
                current_org_ids[0],
            )
            return False

        try:
            self.api.Command.config_mod(hccorgid=org_id)
        except errors.EmptyModlist:
            logger.debug("hccOrgId already configured.")
            return False
        else:
            logger.info("hccOrgId configured to '%s'.", org_id)
            return True

    def configure_host_rhsm_id(self, rhsm_id):
        """Update rhsm_id of server's host record"""
        host = self.api.env.host
        try:
            self.api.Command.host_mod(host, hccsubscriptionid=rhsm_id)
        except errors.EmptyModlist:
            logger.debug(
                "hccSubscriptionId of host '%s' already configured.", host
            )
            return False
        else:
            logger.debug(
                "hccSubscriptionId of host '%s' set to '%s'.", host, rhsm_id
            )
            return True

    def execute(self, **options):
        self.modify_krb5kdc_conf()
        try:
            org_id, rhsm_id = self.parse_rhsm_cert()
        except (OSError, IOError):  # Python 2
            logger.exception("Unable to read %s", hccplatform.RHSM_CERT)
        except Exception:
            logger.exception("Failed to parse %s", hccplatform.RHSM_CERT)
        else:
            self.configure_global_hcc_orgid(org_id)
            self.configure_host_rhsm_id(rhsm_id)
        return False, []
