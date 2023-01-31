#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
import os
import logging

from augeas import Augeas
from cryptography import x509
from cryptography.x509.oid import NameOID

from ipalib import errors
from ipalib import Registry
from ipalib import Updater
from ipalib.install.kinit import kinit_keytab
from ipapython.ipaldap import realm_to_ldapi_uri
from ipapython import ipautil
from ipaplatform import hccplatform
from ipaplatform.paths import paths
from ipaplatform.services import knownservices

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_hcc(Updater):
    """Configure Hybrid Cloud Console services

    - create keytab for hcc-enrollment service
    - auto-configure HCC org id
    """

    def add_service_keytab(self):
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
            else:
                logger.debug("keytab %s exists, nothing to do", keytab)
                return False, []

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
        """Add RHSM cert chain to KDC"""
        anchor = f"FILE:{hccplatform.HMSIDM_CA_BUNDLE_PEM}"
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
                aug.set(f"{path}/pkinit_anchors[last()+1]", anchor)
                modified = True

            if modified:
                logger.debug("Added new pkinit anchor to KDC configuration.")
                try:
                    aug.save()
                except IOError:
                    for error_path in aug.match("/augeas//error"):
                        logger.error("augeas: %s", aug.get(error_path))
                    raise
            else:
                logger.debug("KDC already configured.")
        finally:
            aug.close()

        if modified:
            # restart KDC if running
            logger.debug("Restarting KDC")
            knownservices.krb5kdc.try_restart()

    def configure_hcc_orgid(self):
        """Auto-configure global HCC org id"""
        result = self.api.Command.config_show()["result"]
        org_ids = result.get("hccorgid")
        if org_ids:
            logger.debug("hccorgid already configured: %s", org_ids[0])
        try:
            with open(hccplatform.RHSM_CERT, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
        except Exception:
            logger.exception("Failed to parse '%s'.", hccplatform.RHSM_CERT)
            return False

        nas = list(cert.subject)
        if len(nas) != 2 or nas[0].oid != NameOID.ORGANIZATION_NAME:
            logger.error("Unexpected cert subject %s", cert.subject)
        try:
            org_id = int(nas[0].value)
        except (ValueError, TypeError):
            logger.error("Unexpected cert subject %s", cert.subject)

        try:
            self.api.Command.config_mod(hccorgid=org_id)
        except errors.EmptyModlist:
            pass

    def execute(self, **options):
        self.add_service_keytab()
        self.modify_krb5kdc_conf()
        self.configure_hcc_orgid()
        return False, []
