import logging
import os
import sys

from cryptography.x509.oid import NameOID
import gssapi
import requests

from ipalib import x509
from ipaplatform.paths import paths
from ipaplatform import hccplatform

PY2 = sys.version_info.major == 2

if PY2:
    from httplib import responses as http_responses
    from time import time as monotonic_time
else:
    from http.client import responses as http_responses
    from time import monotonic as monotonic_time

# must be set before ipalib or ipapython is imported
os.environ["XDG_CACHE_HOME"] = hccplatform.HCC_SERVICE_CACHE_DIR
os.environ["KRB5CCNAME"] = hccplatform.HCC_SERVICE_KRB5CCNAME
os.environ["GSS_USE_PROXY"] = "1"

from ipalib import api, errors  # noqa: E402

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-hcc")
logger.setLevel(logging.DEBUG)

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
        return "{} {}".format(self.code, http_responses[self.code])


class Application:
    def __init__(self):
        # inventory bearer token + validity timestamp
        self.access_token = None
        self.valid_until = 0
        # cached org_id from IPA config_show
        self.org_id = None
        # requests session for persistent HTTP connection
        self.session = requests.Session()

    def parse_cert(self, env, envname):
        cert_pem = env.get(envname)
        if not cert_pem:
            raise HTTPException(
                412, "{envname} is missing or empty.".format(envname=envname)
            )
        return x509.load_pem_x509_certificate(cert_pem.encode("ascii"))

    def parse_subject(self, subject):
        nas = list(subject)
        if len(nas) != 2:
            raise HTTPException(
                400, "Invalid cert subject {subject}.".format(subject=subject)
            )
        if (
            nas[0].oid != NameOID.ORGANIZATION_NAME
            or nas[1].oid != NameOID.COMMON_NAME
        ):
            raise HTTPException(
                400, "Invalid cert subject {subject}.".format(subject=subject)
            )
        return int(nas[0].value), nas[1].value

    def get_access_token(
        self,
        refresh_token_file=hccplatform.REFRESH_TOKEN_FILE,
        url=hccplatform.TOKEN_URL,
    ):
        """Get a bearer access token from an offline token

        TODO: Poor man's OAuth2 workflow. Replace with
        requests-oauthlib.

        https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#refreshing-tokens
        """
        # use cached access token
        if self.access_token and monotonic_time() < self.valid_until:
            return self.access_token

        try:
            with open(refresh_token_file, "r") as f:
                refresh_token = f.read().strip()
        except IOError as e:
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
        start = monotonic_time()
        resp = self.session.post(url, data)
        dur = monotonic_time() - start
        if resp.status_code >= 400:
            raise HTTPException(
                resp.status_code,
                "get_access_token() failed: {resp}".format(resp=resp.reason),
            )
        logger.debug(
            "Got access token from refresh token in %0.3fs.",
            dur,
        )
        j = resp.json()
        self.access_token = j["access_token"]
        # 10 seconds slack
        self.valid_until = monotonic_time() + j["expires_in"] - 10
        return self.access_token

    def lookup_inventory(
        self,
        rhsm_id,
        access_token,
        url=hccplatform.INVENTORY_HOSTS_API,
    ):
        """Lookup host by subscription manager id

        Returns FQDN, inventory_id
        """
        logger.debug("Looking up %s in console inventory", rhsm_id)
        headers = {
            "Authorization": "Bearer {access_token}".format(
                access_token=access_token
            )
        }
        params = {"filter[system_profile][owner_id]": rhsm_id}
        start = monotonic_time()
        resp = self.session.get(url, params=params, headers=headers)
        dur = monotonic_time() - start
        if resp.status_code >= 400:
            # reset access token
            self.access_token = None
            raise HTTPException(
                resp.status_code,
                "lookup_inventory() failed: {resp}".format(resp=resp.reason),
            )

        j = resp.json()
        if j["total"] != 1:
            raise HTTPException(
                404, "Unknown host {rhsm_id}.".format(rhsm_id=rhsm_id)
            )
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
        service = hccplatform.HCC_SERVICE
        principal = "{service}/{host}@{realm}".format(
            service=service, host=api.env.host, realm=api.env.realm
        )
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        store = {"ccache": hccplatform.HCC_SERVICE_KRB5CCNAME}
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

    def get_ipa_org_id(self):
        """Get and cache global org_id from IPA config"""
        if self.org_id is not None:
            return self.org_id
        result = api.Command.config_show()["result"]
        org_ids = result.get("hccorgid")
        if not org_ids or len(org_ids) != 1:
            raise ValueError(
                "Invalid IPA configuration, 'hccorgid' is not set."
            )
        self.org_id = int(org_ids[0])
        return self.org_id

    def update_ipa(
        self,
        org_id,
        rhsm_id,
        inventory_id,
        fqdn,
    ):
        ipa_org_id = self.get_ipa_org_id()
        if org_id != ipa_org_id:
            raise HTTPException(
                403,
                "Invalid org_id: {org_id} != {ipa_org_id}".format(
                    org_id=org_id,
                    ipa_org_id=ipa_org_id,
                ),
            )
        try:
            api.Command.host_add(
                fqdn,
                # hccorgid=org_id,
                hccsubscriptionid=rhsm_id,
                hccinventoryid=inventory_id,
                force=True,
            )
            logger.info("Added IPA host %s", fqdn)
        except errors.DuplicateEntry:
            try:
                api.Command.host_mod(
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

    def get_ca_bundle(self):
        with open(paths.IPA_CA_CRT, "r") as f:
            ipa_ca_pem = f.read()
        with open(hccplatform.HMSIDM_CA_BUNDLE_PEM, "r") as f:
            hsmidm_ca_bundle_pem = f.read()
        return ipa_ca_pem + "\n" + hsmidm_ca_bundle_pem

    def handle(self, env, start_repose):
        method = env["REQUEST_METHOD"]
        if method != "GET":
            raise HTTPException(
                405, "Method {method} not allowed.".format(method=method)
            )
        cert = self.parse_cert(env, "SSL_CLIENT_CERT")
        org_id, rhsm_id = self.parse_subject(cert.subject)
        logger.warn(
            "Received self-enrollment request for org O=%s, CN=%s",
            org_id,
            rhsm_id,
        )
        access_token = self.get_access_token()
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
            e = HTTPException(500, "invalid server error: {e}".format(e=e))
            start_response(str(e), e.headers)
            return [e.message]


application = Application()


def test(rhsm_id):
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

    # switch effective UID for gssproxy
    if os.geteuid() == 0:
        import pwd

        user = pwd.getpwnam(hccplatform.HCC_SERVICE_USER)
        os.setreuid(user.pw_uid, user.pw_uid)
        os.environ["HOME"] = user.pw_dir
        os.environ["USER"] = user.pw_name

    access_token = application.get_access_token()
    application.lookup_inventory(rhsm_id, access_token)
    application.lookup_inventory(rhsm_id, access_token)

    application.connect_ipa()
    print(application.get_ipa_org_id())
    application.disconnect_ipa()


if __name__ == "__main__" and len(sys.argv) == 2:
    test(sys.argv[1])
