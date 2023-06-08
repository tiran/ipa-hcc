"""Mock API endpoints

The WSGI service provides a minimalistic implementation of /host-conf/ and
/check-host API endpoints. It has to be installed on an IPA server with
ipa-hcc-registration-service. The mockapi performs minimal checks.

NOTE: The WSGI app does not use any frameworks such as FastAPI or Flask
to reduce dependencies on RHEL. This makes the code is unnecessary
complicated and someward fragile, too. Works well enough for local
testing, though.
"""

import logging
import typing
from time import monotonic as monotonic_time

import requests
from ipaplatform.paths import paths

from ipahcc import hccplatform
from ipahcc.server.framework import HTTPException, JSONWSGIApp, route

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-mockapi")
logger.setLevel(logging.DEBUG)


class Application(JSONWSGIApp):
    def __init__(self, api=None) -> None:
        super().__init__(api=api)
        # inventory bearer token + validity timestamp
        self.access_token: typing.Optional[str] = None
        self.valid_until: int = 0
        # requests session for persistent HTTP connection
        self.session = requests.Session()
        self.session.headers.update(hccplatform.HTTP_HEADERS)

    def get_access_token(self) -> str:  # pragma: no cover
        """Get a bearer access token from an offline token

        TODO: Poor man's OAuth2 workflow. Replace with
        requests-oauthlib.

        https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#refreshing-tokens
        """
        # use cached access token
        if self.access_token and monotonic_time() < self.valid_until:
            return self.access_token

        refresh_token_file = hccplatform.REFRESH_TOKEN_FILE
        try:
            with open(refresh_token_file, encoding="utf-8") as f:
                refresh_token = f.read().strip()
        except OSError as e:
            logger.error(
                "Unable to read refresh token from '%s': %s",
                refresh_token_file,
                e,
            )
            raise

        data = {
            "grant_type": "refresh_token",
            "client_id": hccplatform.TOKEN_CLIENT_ID,
            "refresh_token": refresh_token,
        }
        url = hccplatform.TOKEN_URL
        start = monotonic_time()
        resp = self.session.post(url, data)
        dur = monotonic_time() - start
        if resp.status_code >= 400:
            raise HTTPException(
                resp.status_code,
                f"get_access_token() failed: {resp} {resp.content!r} ({url})",
            )
        logger.debug(
            "Got access token from refresh token in %0.3fs.",
            dur,
        )
        j = resp.json()
        self.access_token = j["access_token"]
        # 10 seconds slack
        self.valid_until = monotonic_time() + j["expires_in"] - 10
        if typing.TYPE_CHECKING:
            assert self.access_token
        return self.access_token

    def lookup_inventory(
        self, inventory_id: str, rhsm_id: str, access_token: str
    ) -> typing.Tuple[str, str, str]:
        """Lookup host by its inventory_id

        Returns fqdn, inventory_id, rhsm_id
        """
        # cannot lookup from .../hosts/{inventory_id}, RHEL 7 does not include
        # subscription_manager_id in return value.
        url = "/".join((hccplatform.INVENTORY_API_URL.rstrip("/"), "hosts"))
        logger.debug(
            "Looking up inventory id %s / rhsm %s in console inventory %s",
            inventory_id,
            rhsm_id,
            url,
        )
        headers = {"Authorization": f"Bearer {access_token}"}
        params = {"filter[system_profile][owner_id]": rhsm_id}
        start = monotonic_time()
        resp = self.session.get(url, params=params, headers=headers)
        dur = monotonic_time() - start
        if resp.status_code >= 400:
            # reset access token
            self.access_token = None
            raise HTTPException(
                resp.status_code,
                f"lookup_inventory() failed: {resp.reason}",
            )

        j = resp.json()
        if j["total"] != 1:
            raise HTTPException(
                404,
                f"Unknown host {inventory_id}.",
            )
        result = j["results"][0]
        fqdn = result["fqdn"]
        rhsm_id = result["subscription_manager_id"]
        inventory_id = result["id"]
        logger.debug(
            "Got result for %s (%s, %s) in %0.3fs",
            fqdn,
            inventory_id,
            rhsm_id,
            dur,
        )
        return fqdn, inventory_id, rhsm_id

    def check_inventory(
        self, inventory_id: str, fqdn: str, rhsm_id: str
    ) -> None:
        if not fqdn.endswith(self.api.env.domain):
            raise HTTPException(404, "hostname not recognized")

        access_token = self.get_access_token()
        exp_fqdn, exp_id, exp_rhsm_id = self.lookup_inventory(
            inventory_id, rhsm_id, access_token=access_token
        )
        if fqdn != exp_fqdn:
            raise HTTPException(
                400,
                f"unexpected fqdn: {fqdn} != {exp_fqdn}",
            )
        if inventory_id != exp_id:
            raise HTTPException(
                400,
                f"unexpected inventory_id: {inventory_id} != {exp_id}",
            )
        # RHEL 7.9 clients have subscription_manager_id == None
        if exp_rhsm_id is not None and rhsm_id != exp_rhsm_id:
            raise HTTPException(
                400,
                f"unexpected RHSM id: {rhsm_id} != {exp_rhsm_id}",
            )

    def get_ca_certs(self) -> str:
        with open(paths.IPA_CA_CRT, encoding="utf-8") as f:
            ipa_ca_pem = f.read()
        return ipa_ca_pem

    @route("GET", "^/$")
    def handle_root(  # pylint: disable=unused-argument
        self, env: dict, body: dict
    ) -> dict:
        return {}

    @route(
        "POST",
        "^/host-conf/(?P<inventory_id>[^/]+)/(?P<fqdn>[^/]+)$",
        schema="host-conf",
    )
    def handle_host_conf(  # pylint: disable=unused-argument
        self, env: dict, body: dict, inventory_id: str, fqdn: str
    ) -> dict:
        org_id, rhsm_id = self.parse_cert(env)
        logger.warning(
            "Received host configuration request for "
            "org O=%s, CN=%s, FQDN %s, inventory %s",
            org_id,
            rhsm_id,
            fqdn,
            inventory_id,
        )

        self.check_inventory(inventory_id, fqdn, rhsm_id)

        ca = self.get_ca_certs()
        logger.info(
            "host-conf for %s (%s, %s) is domain %s.",
            fqdn,
            inventory_id,
            rhsm_id,
            self.api.env.domain,
        )
        response = {
            "domain_name": self.api.env.domain,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_id": hccplatform.TEST_DOMAIN_ID,
            "auto_enrollment_enabled": True,
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": self.api.env.realm,
                "cabundle": ca,
                "enrollment_servers": [
                    {"fqdn": self.api.env.host},
                ],
            },
            "inventory_id": inventory_id,
        }
        return response

    @route(
        "POST",
        "^/check-host/(?P<inventory_id>[^/]+)/(?P<fqdn>[^/]+)$",
        schema="check-host",
    )
    def handle_check_host(  # pylint: disable=unused-argument
        self, env: dict, body: dict, inventory_id: str, fqdn: str
    ) -> dict:
        logger.info("Checking host %s (%s)", fqdn, inventory_id)

        domain_name = body["domain_name"]
        domain_type = body["domain_type"]
        domain_id = body["domain_id"]
        rhsm_id = body["subscription_manager_id"]

        if domain_name != self.api.env.domain:
            raise HTTPException(
                400,
                f"unsupported domain name: {domain_name} != {self.api.env.domain}",
            )
        if domain_type != hccplatform.HCC_DOMAIN_TYPE:
            raise HTTPException(400, "unsupported domain type")

        # TODO validate domain id
        assert domain_id

        self.check_inventory(inventory_id, fqdn, rhsm_id)

        logger.info("Approving host %s (%s, %s)", fqdn, inventory_id, rhsm_id)
        response = {"inventory_id": inventory_id}
        return response

    @route(
        "PUT",
        "^/domains/(?P<domain_id>[^/]+)/register$",
        schema="domain-register-update",
    )
    def handle_register_domain(
        self, env: dict, body: dict, domain_id: str
    ) -> dict:
        logger.info("Register domain %s", domain_id)
        token = env.get("HTTP_X_RH_IDM_REGISTRATION_TOKEN")
        if token is None:
            raise HTTPException(403, "missing X-RH-IDM-Registration-Token")
        if token != "mockapi":  # noqa: S105
            raise HTTPException(404, "invalid X-RH-IDM-Registration-Token")
        return self._handle_domain(env, body, domain_id)

    @route(
        "PUT",
        "^/domains/(?P<domain_id>[^/]+)/update$",
        schema="domain-register-update",
    )
    def handle_update_domain(
        self, env: dict, body: dict, domain_id: str
    ) -> dict:
        logger.info("Update domain %s", domain_id)
        return self._handle_domain(env, body, domain_id)

    def _handle_domain(  # pylint: disable=unused-argument
        self, env: dict, body: dict, domain_id: str
    ) -> dict:
        domain_name = body["domain_name"]
        domain_type = body["domain_type"]
        if domain_name != self.api.env.domain:
            raise HTTPException(400, "unsupported domain name")
        if domain_type != hccplatform.HCC_DOMAIN_TYPE:
            raise HTTPException(400, "unsupported domain type")
        if domain_id != hccplatform.TEST_DOMAIN_ID:
            raise HTTPException(400, "unsupported domain id")

        # return request value
        body = body.copy()
        body["domain_id"] = domain_id
        body.setdefault("auto_enrollment_enabled", True)
        return body
