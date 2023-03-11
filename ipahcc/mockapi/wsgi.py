"""Mock API endpoints

The WSGI service provides a minimalistic implementation of /hostconf/ and
/check_host API endpoints. It has to be installed on an IPA server with
ipa-hcc-registration-service. The mockapi performs minimal checks.

NOTE: The WSGI app does not use any frameworks such as FastAPI or Flask
to reduce dependencies on RHEL. This makes the code is unnecessary
complicated and someward fragile, too. Works well enough for local
testing, though.
"""

import logging
import json
import re

from cryptography.x509.oid import NameOID
import requests

from ipalib import x509
from ipaplatform.paths import paths
from ipahcc import hccplatform


if hccplatform.PY2:
    from httplib import responses as http_responses
    from time import time as monotonic_time
else:
    from http.client import responses as http_responses
    from time import monotonic as monotonic_time

from ipalib import api  # noqa: E402

hccconfig = hccplatform.HCCConfig()

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-mockapi")
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
        # inventory bearer token + validity timestamp
        self.access_token = None
        self.valid_until = 0
        # requests session for persistent HTTP connection
        self.session = requests.Session()
        self.routes = [
            (re.compile("^/$"), self.handle_root),
            (re.compile("^/hostconf/(?P<fqdn>[^/]+)$"), self.handle_hostconf),
            (
                re.compile("^/check_host/(?P<smid>[^/]+)/(?P<fqdn>[^/]+)$"),
                self.handle_check_host,
            ),
        ]

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
        url=hccconfig.token_url,
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
                "get_access_token() failed: {resp} {content} ({url})".format(
                    resp=resp.reason,
                    content=resp.content,
                    url=url,
                ),
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
        url=hccconfig.inventory_hosts_api,
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
        logger.debug(
            "Resolved %s to fqdn %s / inventory %s in %0.3fs",
            rhsm_id,
            fqdn,
            inventoryid,
            dur,
        )
        return fqdn, inventoryid

    def bootstrap_ipa(self):
        if not api.isdone("bootstrap"):
            api.bootstrap(in_server=False)

    def get_ca_crt(self):
        with open(paths.IPA_CA_CRT, "r") as f:
            ipa_ca_pem = f.read()
        return ipa_ca_pem

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

    def check_method(self, env, expected):
        method = env["REQUEST_METHOD"]
        if method != expected:
            raise HTTPException(
                405, "Method {method} not allowed.".format(method=method)
            )

    def handle_root(self, env):
        self.check_method(env, "GET")
        return {}

    def handle_hostconf(self, env, fqdn):
        self.check_method(env, "POST")

        cert = self.parse_cert(env, "SSL_CLIENT_CERT")
        org_id, rhsm_id = self.parse_subject(cert.subject)
        logger.warn(
            "Received host configuration request for org O=%s, CN=%s, FQDN %s",
            org_id,
            rhsm_id,
            fqdn,
        )

        # just to verify it's json
        self.get_json(env)

        if not fqdn.endswith(api.env.domain):
            raise HTTPException(404, "hostname not recognized")

        access_token = self.get_access_token()
        expected_fqdn, inventory_id = self.lookup_inventory(
            rhsm_id, access_token=access_token
        )
        if fqdn != expected_fqdn:
            raise HTTPException(403, "unexpected fqdn")
        ca = self.get_ca_crt()
        logger.info(
            "hostconf for %s (%s) is domain %s.",
            fqdn,
            rhsm_id,
            api.env.domain,
        )
        return {
            "domain_name": api.env.domain,
            "domain_type": "ipa",
            "auto_enrollment_enabled": True,
            "ipa": {
                "realm_name": api.env.realm,
                "ca_cert": ca,
                "enrollment_servers": [api.env.host],
            },
            "inventory": {
                "id": inventory_id,
            },
        }

    def handle_check_host(self, env, smid, fqdn):
        self.check_method(env, "POST")
        body = self.get_json(env)
        logger.info("Checking host %s (%s)", fqdn, smid)
        try:
            domain_name = body["domain_name"]
            domain_type = body["domain_type"]
        except KeyError as e:
            raise HTTPException(400, str(e))
        if domain_name != api.env.domain:
            raise HTTPException(403, "unsupported domain name")
        if domain_type != "ipa":
            raise HTTPException(403, "unsupported domain type")

        access_token = self.get_access_token()
        expected_fqdn, inventory_id = self.lookup_inventory(
            smid, access_token=access_token
        )
        if fqdn != expected_fqdn:
            raise HTTPException(403, "unexpected fqdn")
        logger.info("Approving host %s (%s, %s)", fqdn, smid, inventory_id)
        return {"inventory_id": inventory_id}

    def handle(self, env, start_response):
        self.bootstrap_ipa()
        pathinfo = env["PATH_INFO"]
        for r, func in self.routes:
            mo = r.match(pathinfo)
            if mo is not None:
                result = func(env, **mo.groupdict())
                data = json.dumps(result)
                raise HTTPException(
                    200, data, content_type="application/json"
                )
        raise HTTPException(
            404, "{pathinfo} not found".format(pathinfo=pathinfo)
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
