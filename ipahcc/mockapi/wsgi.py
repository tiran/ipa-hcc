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
import json
import re

from cryptography.x509.oid import NameOID
import requests

from ipalib import x509
from ipaplatform.paths import paths
from ipahcc import hccplatform
from ipahcc.server import schema
from ipahcc.registration.wsgi import HTTPException

if hccplatform.PY2:
    from time import time as monotonic_time
else:
    from time import monotonic as monotonic_time

from ipalib import api  # noqa: E402

hccconfig = hccplatform.HCCConfig()

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-mockapi")
logger.setLevel(logging.DEBUG)


def validate_schema(instance, schema_id):
    try:
        schema.validate_schema(instance, schema_id)
    except schema.ValidationError:
        raise HTTPException(
            400,
            "schema violation: invalid JSON for {schema_id}".format(
                schema_id=schema_id
            ),
        )


class Application:
    def __init__(self):
        # inventory bearer token + validity timestamp
        self.access_token = None
        self.valid_until = 0
        # requests session for persistent HTTP connection
        self.session = requests.Session()
        self.routes = [
            (
                "GET",
                re.compile("^/$"),
                self.handle_root,
            ),
            (
                "POST",
                re.compile("^/host-conf/(?P<fqdn>[^/]+)$"),
                self.handle_host_conf,
            ),
            (
                "POST",
                re.compile("^/check-host/(?P<smid>[^/]+)/(?P<fqdn>[^/]+)$"),
                self.handle_check_host,
            ),
            (
                "PUT",
                re.compile("^/domains/(?P<domain_id>[^/]+)/register$"),
                self.handle_register_domain,
            ),
            (
                "PUT",
                re.compile("^/domains/(?P<domain_id>[^/]+)/update$"),
                self.handle_update_domain,
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
            raise HTTPException.from_error(
                400, "Invalid cert subject {subject}.".format(subject=subject)
            )
        if (
            nas[0].oid != NameOID.ORGANIZATION_NAME
            or nas[1].oid != NameOID.COMMON_NAME
        ):
            raise HTTPException.from_error(
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
            raise HTTPException.from_error(
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
            raise HTTPException.from_error(
                resp.status_code,
                "lookup_inventory() failed: {resp}".format(resp=resp.reason),
            )

        j = resp.json()
        if j["total"] != 1:
            raise HTTPException.from_error(
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
            raise HTTPException.from_error(
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
            raise HTTPException(400, "JSON object expected")
        return result

    def handle_root(self, env):
        return {}

    def handle_host_conf(self, env, fqdn):
        cert = self.parse_cert(env, "SSL_CLIENT_CERT")
        org_id, rhsm_id = self.parse_subject(cert.subject)
        logger.warn(
            "Received host configuration request for org O=%s, CN=%s, FQDN %s",
            org_id,
            rhsm_id,
            fqdn,
        )

        # just to verify it's json
        body = self.get_json(env)
        validate_schema(body, "/schemas/host-conf/request")

        if not fqdn.endswith(api.env.domain):
            raise HTTPException.from_error(404, "hostname not recognized")

        access_token = self.get_access_token()
        expected_fqdn, inventory_id = self.lookup_inventory(
            rhsm_id, access_token=access_token
        )
        if fqdn != expected_fqdn:
            raise HTTPException.from_error(
                400,
                "unexpected fqdn: {fqdn} != {expected_fqdn}".format(
                    fqdn=fqdn, expected_fqdn=expected_fqdn
                ),
            )
        ca = self.get_ca_crt()
        logger.info(
            "host-conf for %s (%s) is domain %s.",
            fqdn,
            rhsm_id,
            api.env.domain,
        )
        response = {
            "domain_name": api.env.domain,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_id": hccplatform.TEST_DOMAIN_ID,
            "auto_enrollment_enabled": True,
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": api.env.realm,
                "cabundle": ca,
                "enrollment_servers": [api.env.host],
            },
            "inventory_id": inventory_id,
        }
        validate_schema(response, "/schemas/host-conf/response")
        return response

    def handle_check_host(self, env, smid, fqdn):
        body = self.get_json(env)
        validate_schema(body, "/schemas/check-host/request")
        logger.info("Checking host %s (%s)", fqdn, smid)

        domain_name = body["domain_name"]
        domain_type = body["domain_type"]
        domain_id = body["domain_id"]
        rhsm_id = body["subscription_manager_id"]
        inventory_id = body["inventory_id"]

        if domain_name != api.env.domain:
            raise HTTPException.from_error(
                400,
                "unsupported domain name: {domain} != {expected_domain}".format(
                    domain=domain_name, expected_domain=api.env.domain
                ),
            )
        if domain_type != hccplatform.HCC_DOMAIN_TYPE:
            raise HTTPException.from_error(400, "unsupported domain type")
        if rhsm_id != smid:
            raise HTTPException.from_error(400, "path and rhsm_id mismatch")

        # TODO validate domain id
        assert domain_id

        access_token = self.get_access_token()
        expected_fqdn, expected_inventory_id = self.lookup_inventory(
            smid, access_token=access_token
        )
        if fqdn != expected_fqdn:
            raise HTTPException.from_error(
                400,
                "unexpected fqdn: {fqdn} != {expected_fqdn}".format(
                    fqdn=fqdn, expected_fqdn=expected_fqdn
                ),
            )
        if inventory_id != expected_inventory_id:
            raise HTTPException.from_error(
                400,
                "unexpected inventory id: {inventory_id} != {expected_inventory_id}".format(
                    inventory_id=inventory_id,
                    expected_inventory_id=expected_inventory_id,
                ),
            )

        logger.info("Approving host %s (%s, %s)", fqdn, smid, inventory_id)
        response = {"inventory_id": inventory_id}
        validate_schema(response, "/schemas/check-host/response")
        return response

    def handle_register_domain(self, env, domain_id):
        logger.info("Register domain %s", domain_id)
        token = env.get("HTTP_X_RH_IDM_REGISTRATION_TOKEN")
        if token is None:
            raise HTTPException.from_error(
                403, "missing X-RH-IDM-Registration-Token"
            )
        if token != "mockapi":
            raise HTTPException.from_error(
                404, "invalid X-RH-IDM-Registration-Token"
            )
        return self._handle_domain(env, domain_id)

    def handle_update_domain(self, env, domain_id):
        logger.info("Update domain %s", domain_id)
        return self._handle_domain(env, domain_id)

    def _handle_domain(self, env, domain_id):
        body = self.get_json(env)
        validate_schema(body, "/schemas/domain/request")

        domain_name = body["domain_name"]
        domain_type = body["domain_type"]
        if domain_name != api.env.domain:
            raise HTTPException.from_error(400, "unsupported domain name")
        if domain_type != hccplatform.HCC_DOMAIN_TYPE:
            raise HTTPException.from_error(400, "unsupported domain type")

        response = {"status": "ok"}
        validate_schema(response, "/schemas/domain/response")
        return response

    def handle(self, env, start_response):
        self.bootstrap_ipa()
        pathinfo = env["PATH_INFO"]
        for method, r, func in self.routes:
            mo = r.match(pathinfo)
            if mo is not None:
                if method != env["REQUEST_METHOD"]:
                    raise HTTPException(
                        405,
                        "Method {method} not allowed.".format(
                            method=env["REQUEST_METHOD"]
                        ),
                    )
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
            e = HTTPException.from_exception(
                e, 500, "invalid server error: {e}".format(e=e)
            )
            start_response(str(e), e.headers)
            return [e.message]


application = Application()
