import json
import logging
import os
import sys

from cryptography.x509.oid import NameOID
import gssapi
import requests

from ipalib import x509
from ipaplatform import hccplatform

if hccplatform.PY2:
    from httplib import responses as http_responses
else:
    from http.client import responses as http_responses

# must be set before ipalib or ipapython is imported
os.environ["XDG_CACHE_HOME"] = hccplatform.HCC_SERVICE_CACHE_DIR
os.environ["KRB5CCNAME"] = hccplatform.HCC_SERVICE_KRB5CCNAME
os.environ["GSS_USE_PROXY"] = "1"

from ipalib import api, errors  # noqa: E402

hccconfig = hccplatform.HCCConfig()

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-hcc")
logger.setLevel(logging.DEBUG)


class HTTPException(Exception):
    def __init__(self, code, msg, content_type="text/plain; charset=utf-8"):
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        headers = [
            ("Content-Type", content_type),
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

    def check_host(self, rhsm_id, fqdn):
        body = {
            "domain_type": "ipa",
            "domain_name": api.env.domain,
        }
        api_url = hccconfig.hcc_api_url.rstrip("/")
        url = "/".join((api_url, "check_host", rhsm_id, fqdn))
        resp = self.session.post(url, json=body)
        resp.raise_for_status()
        j = resp.json()
        return j["inventory_id"]

    def kinit_gssproxy(self):
        service = hccplatform.HCC_SERVICE
        principal = "{service}/{host}@{realm}".format(
            service=service, host=api.env.host, realm=api.env.realm
        )
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        store = {"ccache": hccplatform.HCC_SERVICE_KRB5CCNAME}
        return gssapi.Credentials(name=name, store=store, usage="initiate")

    def bootstrap_ipa(self):
        if not api.isdone("bootstrap"):
            api.bootstrap(in_server=False)

    def connect_ipa(self):
        logger.debug("Connecting to IPA")
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
        # no need to fetch additional values
        result = api.Command.config_show(raw=True)["result"]
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

    def get_json(self, env, maxlength=10240):
        content_type = env["CONTENT_TYPE"]
        if content_type != "application/json":
            raise HTTPException(
                406,
                "Unsupported content type {content_type}.".format(
                    content_type=content_type
                ),
            )
        try:
            length = int(env["CONTENT_LENGTH"])
        except (KeyError, ValueError):
            length = -1
        if length < 0:
            raise HTTPException(411, "Length required.")
        if length > maxlength:
            raise HTTPException(413, "Request entity too large.")
        result = json.load(env["wsgi.input"])
        if not isinstance(result, dict):
            raise HTTPException(403, "JSON object expected")
        return result

    def handle(self, env, start_repose):
        method = env["REQUEST_METHOD"]
        if method != "POST":
            raise HTTPException(
                405, "Method {method} not allowed.".format(method=method)
            )
        # verify it's valid JSON body
        self.get_json(env)
        print(env)
        fqdn = env["PATH_INFO"][1:]
        if not fqdn or "/" in fqdn:
            raise HTTPException(404, "host not found")

        self.bootstrap_ipa()

        cert = self.parse_cert(env, "SSL_CLIENT_CERT")
        org_id, rhsm_id = self.parse_subject(cert.subject)
        logger.warn(
            "Received self-enrollment request for org O=%s, CN=%s",
            org_id,
            rhsm_id,
        )
        inventory_id = self.check_host(rhsm_id, fqdn)
        try:
            self.connect_ipa()
            self.update_ipa(org_id, rhsm_id, inventory_id, fqdn)
        finally:
            self.disconnect_ipa()

        logger.info(
            "Self-registration of %s (O=%s, CN=%s) was successful",
            fqdn,
            org_id,
            rhsm_id,
        )
        # TODO: return value?
        result = {}
        raise HTTPException(
            200,
            json.dumps(result),
            content_type="application/json",
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


def test(rhsm_id, fqdn):
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

    application.connect_ipa()
    print(application.check_host(rhsm_id, fqdn))
    print(application.get_ipa_org_id())
    application.disconnect_ipa()


if __name__ == "__main__" and len(sys.argv) == 2:
    test(sys.argv[1])
