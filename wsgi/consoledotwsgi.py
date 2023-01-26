import http.client
import logging
import os
import sys
import time
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
import gssapi
import requests

from ipaplatform.paths import paths
from ipaplatform import consoledotplatform

# must be set before ipalib or ipapython is imported
os.environ["XDG_CACHE_HOME"] = "/var/cache/ipa-consoledot"
os.environ["GSS_USE_PROXY"] = "1"

from ipalib import api, errors  # noqa: E402

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("consoledot")
logger.setLevel(logging.DEBUG)

os.environ["KRB5CCNAME"] = consoledotplatform.CONSOLEDOT_SERVICE_KRB5CCNAME

SCRIPT = """\
#!/bin/sh
set -e

CABUNDLE=$(mktemp)
trap "rm -f $CABUNDLE" EXIT

cat >$CABUNDLE << EOF
{cabundle_pem}
EOF

set -x
ipa-client-install \
--ca-cert-file=$CABUNDLE \
--server={server} \
--domain={domain} \
--realm={realm} \
--pkinit-identity=FILE:/etc/pki/consumer/cert.pem,/etc/pki/consumer/key.pem \
--pkinit-anchor=FILE:$CABUNDLE \
--no-ntp \
--unattended
"""

# consoleDot Inventory and acess token
# see https://access.redhat.com/articles/3626371
REFRESH_TOKEN = None
TOKEN_URL = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
CLIENT_ID = "rhsm-api"
INVENTORY_HOSTS_API = "https://console.redhat.com/api/inventory/v1/hosts"


try:
    with open("/etc/ipa/refresh_token", "r") as f:
        REFRESH_TOKEN = f.read().strip()
except FileNotFoundError:
    pass


class HTTPException(Exception):
    def __init__(self, code, msg):
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        headers = [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(msg))),
        ]
        super(HTTPException, self).__init__(code, msg, headers)
        self.code = code
        self.message = msg
        self.headers = headers

    def __str__(self):
        return "{} {}".format(self.code, http.client.responses[self.code])


class Application:
    def __init__(self):
        # inventory bearer token + validity timestamp
        self.access_token: Optional[str] = None
        self.valid_until: int = 0
        # cached org_id from IPA config_show
        self.org_id: Optional[int] = None
        # requests session for persistent HTTP connection
        self.session = requests.Session()

    def parse_cert(self, env: dict, envname: str) -> x509.Certificate:
        cert_pem = env.get(envname)
        if not cert_pem:
            raise HTTPException(412, f"{envname} is missing or empty.")
        return x509.load_pem_x509_certificate(cert_pem.encode("ascii"))

    def parse_subject(self, subject: x509.Name) -> Tuple[int, str]:
        nas = list(subject)
        if len(nas) != 2:
            raise HTTPException(400, f"Invalid cert subject {subject}.")
        if (
            nas[0].oid != NameOID.ORGANIZATION_NAME
            or nas[1].oid != NameOID.COMMON_NAME
        ):
            raise HTTPException(400, f"Invalid cert subject {subject}.")
        return int(nas[0].value), nas[1].value

    def get_access_token(
        self, refresh_token: str, url: str = TOKEN_URL
    ) -> str:
        """Get a bearer access token from an offline token

        TODO: Poor man's OAuth2 workflow. Replace with
        requests-oauthlib.

        https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#refreshing-tokens
        """
        # use cached access token
        if self.access_token and time.monotonic() < self.valid_until:
            return self.access_token

        logger.debug("Getting refresh token from %s", url)
        if refresh_token is None:
            raise ValueError("REFRESH_TOKEN not set")
        data = {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": REFRESH_TOKEN,
        }
        start = time.monotonic()
        resp = self.session.post(url, data)
        dur = time.monotonic() - start
        if resp.status_code >= 400:
            raise HTTPException(
                resp.status_code, f"get_access_token() failed: {resp.reason}"
            )
        logger.debug("Got access token from refresh token in %0.3fs.", dur)
        j = resp.json()
        self.access_token = j["access_token"]
        # 10 seconds slack
        self.valid_until = time.monotonic() + j["expires_in"] - 10
        return self.access_token

    def lookup_inventory(
        self, rhsm_id: str, access_token: str, url: str = INVENTORY_HOSTS_API
    ) -> Tuple[str, str]:
        """Lookup host by subscription manager id

        Returns FQDN, inventory_id
        """
        logger.debug("Looking up %s in console inventory", rhsm_id)
        headers = {"Authorization": f"Bearer {access_token}"}
        params = {"filter[system_profile][owner_id]": rhsm_id}
        start = time.monotonic()
        resp = self.session.get(url, params=params, headers=headers)
        dur = time.monotonic() - start
        if resp.status_code >= 400:
            # reset access token
            self.access_token = None
            raise HTTPException(
                resp.status_code, f"lookup_inventory() failed: {resp.reason}"
            )

        j = resp.json()
        if j["total"] != 1:
            raise HTTPException(404, f"Unknown host {rhsm_id}.")
        result = j["results"][0]
        fqdn = result["fqdn"]
        inventoryid = result["id"]
        logger.warning(
            "Resolved %s to fqdn %s / inventory %s in %0.3fs",
            rhsm_id,
            fqdn,
            inventoryid,
            dur,
        )
        return fqdn, inventoryid

    def kinit_gssproxy(self):
        service = consoledotplatform.CONSOLEDOT_SERVICE
        principal = f"{service}/{api.env.host}@{api.env.realm}"
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        store = {"ccache": consoledotplatform.CONSOLEDOT_SERVICE_KRB5CCNAME}
        return gssapi.Credentials(name=name, store=store, usage="initiate")

    def connect_ipa(self):
        logger.debug("Connecting to IPA")
        if not api.isdone("bootstrap"):
            api.bootstrap(in_server=False)
        self.kinit_gssproxy()
        if not api.isdone("finalize"):
            api.finalize()
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()
            logger.debug("Connected")
        else:
            logger.debug("IPA rpcclient is already connected.")

    def disconnect_ipa(self):
        if api.isdone("finalize") and api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.disconnect()

    def get_ipa_org_id(self) -> int:
        """Get and cache global org_id from IPA config"""
        if self.org_id is not None:
            return self.org_id
        result = api.Command.config_show()["result"]
        org_ids = result.get("consoledotorgid")
        if not org_ids or len(org_ids) != 1:
            raise ValueError(
                "Invalid IPA configuration, 'consoledotorgid' is not set."
            )
        self.org_id = int(org_ids[0])
        return self.org_id

    def update_ipa(
        self, org_id: int, rhsm_id: str, inventory_id: str, fqdn: str
    ):
        ipa_org_id = self.get_ipa_org_id()
        if org_id != ipa_org_id:
            raise HTTPException(
                403, f"Invalid org_id: {org_id} != {ipa_org_id}"
            )
        try:
            api.Command.host_add(
                fqdn,
                # consoledotorgid=org_id,
                consoledotsubscriptionid=rhsm_id,
                consoledotinventoryid=inventory_id,
                force=True,
            )
            logger.info("Added IPA host %s", fqdn)
        except errors.DuplicateEntry:
            try:
                api.Command.host_mod(
                    fqdn,
                    # consoledotorgid=org_id,
                    consoledotsubscriptionid=rhsm_id,
                    consoledotinventoryid=inventory_id,
                )
                logger.info("Updated IPA host %s", fqdn)
            except errors.EmptyModlist:
                logger.info("Nothing to update for IPA host %s", fqdn)

    def get_ca_bundle(self):
        with open(paths.IPA_CA_CRT, "r") as f:
            ipa_ca_pem = f.read()
        with open(consoledotplatform.HMSIDM_CA_BUNDLE_PEM, "r") as f:
            hsmidm_ca_bundle_pem = f.read()
        return ipa_ca_pem + "\n" + hsmidm_ca_bundle_pem

    def handle(self, env, start_repose):
        method = env["REQUEST_METHOD"]
        if method != "GET":
            raise HTTPException(405, f"Method {method} not allowed.")
        cert = self.parse_cert(env, "SSL_CLIENT_CERT")
        org_id, rhsm_id = self.parse_subject(cert.subject)
        logger.warn(
            "Received self-enrollment request for org O=%s, CN=%s",
            org_id,
            rhsm_id,
        )
        access_token = self.get_access_token(REFRESH_TOKEN)
        fqdn, inventory_id = self.lookup_inventory(
            rhsm_id, access_token=access_token
        )
        try:
            self.connect_ipa()
            self.update_ipa(org_id, rhsm_id, inventory_id, fqdn)
        finally:
            self.disconnect_ipa()
        cabundle_pem = self.get_ca_bundle()
        script = SCRIPT.format(
            server=api.env.host,
            domain=api.env.domain,
            realm=api.env.realm,
            cabundle_pem=cabundle_pem,
        )
        logger.info(
            "Self-registration of %s (O=%s, CN=%s) was successful",
            fqdn,
            org_id,
            rhsm_id,
        )
        raise HTTPException(
            200,
            script,
        )

    def __call__(self, env, start_response):
        try:
            return self.handle(env, start_response)
        except HTTPException as e:
            if e.code >= 400:
                logger.info("%s: %s", str(e), e.message)
            start_response(str(e), e.headers)
            return [e.message]
        except Exception as e:
            logger.exception("Request failed")
            e = HTTPException(500, f"invalid server error: {e}")
            start_response(str(e), e.headers)
            return [e.message]


application = Application()


def test(rhsm_id: str):
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s %(name)s] <%(levelname)s>: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        force=True,
    )
    if False:
        # extra debug output
        from http.client import HTTPConnection

        requests_log = logging.getLogger("urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        HTTPConnection.debuglevel = 1

    # Internal testing VM has issues with IPv6 connections:
    # import urllib3.util.connection
    # urllib3.util.connection.HAS_IPV6 = False

    access_token = application.get_access_token(REFRESH_TOKEN)
    application.lookup_inventory(rhsm_id, access_token)
    application.lookup_inventory(rhsm_id, access_token)


if __name__ == "__main__" and len(sys.argv) == 2:
    test(sys.argv[1])
