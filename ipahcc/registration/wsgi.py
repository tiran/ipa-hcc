#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#

import logging
import os
import typing

import gssapi

from ipahcc import hccplatform

# must be set before ipalib or ipapython is imported
os.environ["XDG_CACHE_HOME"] = hccplatform.HCC_ENROLLMENT_AGENT_CACHE_DIR
os.environ["KRB5CCNAME"] = hccplatform.HCC_ENROLLMENT_AGENT_KRB5CCNAME
os.environ["GSS_USE_PROXY"] = "1"

# pylint: disable=wrong-import-position,wrong-import-order,ungrouped-imports
from ipalib import errors  # noqa: E402

from ipahcc.server.framework import (  # noqa: E402
    HTTPException,
    JSONWSGIApp,
    route,
)
from ipahcc.server.util import read_cert_dir  # noqa: E402

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-hcc")
logger.setLevel(logging.DEBUG)


class Application(JSONWSGIApp):
    def __init__(self, api=None) -> None:
        super().__init__(api=api)
        # cached org_id from IPA config_show
        self._org_id: typing.Optional[int] = None
        self._domain_id: typing.Optional[str] = None
        # cached PEM bundle
        self._kdc_cabundle = read_cert_dir(hccplatform.HMSIDM_CACERTS_DIR)

    def kinit_gssproxy(self) -> gssapi.Credentials:
        service = hccplatform.HCC_ENROLLMENT_AGENT
        principal = f"{service}/{self.api.env.host}@{self.api.env.realm}"
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        store = {"ccache": hccplatform.HCC_ENROLLMENT_AGENT_KRB5CCNAME}
        return gssapi.Credentials(
            name=name, store=store, usage="initiate"  # type: ignore
        )

    def before_call(self) -> None:
        logger.debug("Connecting to IPA")
        self.kinit_gssproxy()
        if not self.api.isdone("finalize"):
            self.api.finalize()
        if not self.api.Backend.rpcclient.isconnected():
            self.api.Backend.rpcclient.connect()
            logger.debug("Connected")
        else:
            logger.debug("IPA rpcclient is already connected.")

    def after_call(self) -> None:
        if (
            self.api.isdone("finalize")
            and self.api.Backend.rpcclient.isconnected()
        ):
            self.api.Backend.rpcclient.disconnect()

    def _get_ipa_config(self) -> typing.Tuple[int, str]:
        """Get org_id and domain_id from IPA config"""
        # no need to fetch additional values
        result = self.api.Command.config_show(raw=True)["result"]
        org_ids = result.get("hccorgid")
        if not org_ids or len(org_ids) != 1:
            raise ValueError(
                "Invalid IPA configuration, 'hccorgid' is not set."
            )
        domain_ids = result.get("hccdomainid")
        if not domain_ids or len(domain_ids) != 1:
            raise ValueError(
                "Invalid IPA configuration, 'hccdomainid' is not set."
            )

        return int(org_ids[0]), domain_ids[0]

    @property
    def org_id(self) -> int:
        if self._org_id is None:
            self._org_id, self._domain_id = self._get_ipa_config()
        return self._org_id

    @property
    def domain_id(self) -> str:
        if self._domain_id is None:
            self._org_id, self._domain_id = self._get_ipa_config()
        return self._domain_id

    def update_ipa(
        self,
        org_id: int,
        rhsm_id: str,
        inventory_id: str,
        fqdn: str,
    ):
        ipa_org_id = self.org_id
        if org_id != ipa_org_id:
            raise HTTPException(
                400,
                f"Invalid org_id: {org_id} != {ipa_org_id}",
            )
        rhsm_id = str(rhsm_id)
        inventory_id = str(inventory_id)
        fqdn = str(fqdn)
        try:
            self.api.Command.host_add(
                fqdn,
                # hccorgid=org_id,
                hccsubscriptionid=rhsm_id,
                hccinventoryid=inventory_id,
                force=True,
            )
            logger.info("Added IPA host %s", fqdn)
        except errors.DuplicateEntry:
            try:
                self.api.Command.host_mod(
                    fqdn,
                    # hccorgid=org_id,
                    hccsubscriptionid=rhsm_id,
                    hccinventoryid=inventory_id,
                )
                logger.info("Updated IPA host %s", fqdn)
            except errors.EmptyModlist:
                logger.info(
                    "Nothing to update for IPA host %s",
                    fqdn,
                )

    @route(
        "POST",
        "^/(?P<inventory_id>[^/]+)/(?P<fqdn>[^/]+)$",
        schema="HCCHostRegister",
    )
    def handle(  # pylint: disable=unused-argument
        self, env: dict, body: dict, inventory_id: str, fqdn: str
    ) -> dict:
        org_id, rhsm_id = self.parse_cert(env)
        logger.warning(
            "Received self-enrollment request for org O=%s, CN=%s",
            org_id,
            rhsm_id,
        )
        # TODO: verify client request with a signed assertion (token)
        logger.warning("Enrollment request is not verified.")
        self.update_ipa(org_id, rhsm_id, inventory_id, fqdn)

        logger.info(
            "Self-registration of %s (O=%s, CN=%s) was successful",
            fqdn,
            org_id,
            rhsm_id,
        )
        # TODO: return value?
        return {"status": "ok", "kdc_cabundle": self._kdc_cabundle}
