#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Configure Hybrid Cloud Console basic settings
"""
import logging

from augeas import Augeas  # pylint: disable=import-error
from ipalib import Registry, Updater, errors
from ipaplatform.paths import paths
from ipaplatform.services import knownservices

from ipahcc import hccplatform
from ipahcc.server.util import parse_rhsm_cert

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
        anchor = f"DIR:{hccplatform.HMSIDM_CACERTS_DIR}"
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
        path = f"/files{paths.KRB5KDC_KDC_CONF}/realms/{realm}"
        expr = f'{path}/pkinit_anchors[.="{anchor}"]'

        try:
            aug.transform("IPAKrb5", paths.KRB5KDC_KDC_CONF)
            aug.load()
            if not aug.match(expr):
                aug.set(
                    f"{path}/pkinit_anchors[last()+1]",
                    anchor,
                )
                modified = True

            if modified:
                logger.debug("Added new pkinit anchor to KDC configuration.")
                try:
                    aug.save()
                except OSError:
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
            with open(hccplatform.RHSM_CERT, "rb") as f:
                org_id, rhsm_id = parse_rhsm_cert(f.read())
        except OSError:
            logger.exception("Unable to read %s", hccplatform.RHSM_CERT)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to parse %s", hccplatform.RHSM_CERT)
        else:
            self.configure_global_hcc_orgid(org_id)
            self.configure_host_rhsm_id(rhsm_id)
        return False, []
