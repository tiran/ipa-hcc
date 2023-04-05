#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
from __future__ import print_function

import json
import logging
import os
import traceback

import gssapi

from ipahcc import hccplatform

# pylint: disable=import-error
if hccplatform.PY2:
    from httplib import responses as http_responses
else:
    from http.client import responses as http_responses
# pylint: enable=import-error

# must be set before ipalib or ipapython is imported
os.environ["XDG_CACHE_HOME"] = hccplatform.HCC_ENROLLMENT_AGENT_CACHE_DIR
os.environ["KRB5CCNAME"] = hccplatform.HCC_ENROLLMENT_AGENT_KRB5CCNAME
os.environ["GSS_USE_PROXY"] = "1"

# pylint: disable=wrong-import-position,wrong-import-order,ungrouped-imports
from ipalib import errors  # noqa: E402
from ipahcc.server import dbus_client  # noqa: E402
from ipahcc.server import schema  # noqa: E402
from ipahcc.server.util import parse_rhsm_cert, read_cert_dir  # noqa: E402


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

    @classmethod
    def from_exception(cls, e, code, title):
        assert isinstance(e, Exception)
        body = {
            "status": code,
            "title": title,
            "details": traceback.print_exc(),
        }
        return cls(code, json.dumps(body), content_type="application/json")

    @classmethod
    def from_error(cls, code, msg):
        body = {
            "status": code,
            "title": http_responses[code],
            "details": msg,
        }
        return cls(code, json.dumps(body), content_type="application/json")

    def __str__(self):
        return "{} {}".format(self.code, http_responses[self.code])


class Application(object):
    def __init__(self, api):
        self.api = api
        # cached org_id from IPA config_show
        self._org_id = None
        self._domain_id = None
        # cached PEM bundle
        self._kdc_cabundle = read_cert_dir(hccplatform.HMSIDM_CACERTS_DIR)

    def parse_cert(self, env, envname):
        cert_pem = env.get(envname)
        if not cert_pem:
            raise HTTPException(
                412, "{envname} is missing or empty.".format(envname=envname)
            )
        try:
            return parse_rhsm_cert(cert_pem)
        except ValueError as e:
            raise HTTPException.from_error(400, str(e))

    def check_host(self, inventory_id, rhsm_id, fqdn):
        try:
            result = dbus_client.check_host(
                self.domain_id, inventory_id, rhsm_id, fqdn
            )
        except dbus_client.APIError as e:
            raise HTTPException.from_error(
                e.result.status_code, e.result.body
            )
        return result.body["inventory_id"]

    def kinit_gssproxy(self):
        service = hccplatform.HCC_ENROLLMENT_AGENT
        principal = "{service}/{host}@{realm}".format(
            service=service, host=self.api.env.host, realm=self.api.env.realm
        )
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        store = {"ccache": hccplatform.HCC_ENROLLMENT_AGENT_KRB5CCNAME}
        return gssapi.Credentials(name=name, store=store, usage="initiate")

    def bootstrap_ipa(self):
        if not self.api.isdone("bootstrap"):
            self.api.bootstrap(in_server=False)

    def connect_ipa(self):
        logger.debug("Connecting to IPA")
        self.kinit_gssproxy()
        if not self.api.isdone("finalize"):
            self.api.finalize()
        if not self.api.Backend.rpcclient.isconnected():
            self.api.Backend.rpcclient.connect()
            logger.debug("Connected")
        else:
            logger.debug("IPA rpcclient is already connected.")

    def disconnect_ipa(self):
        if (
            self.api.isdone("finalize")
            and self.api.Backend.rpcclient.isconnected()
        ):
            self.api.Backend.rpcclient.disconnect()

    def _get_ipa_config(self):
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
    def org_id(self):
        if self._org_id is None:
            self._org_id, self._domain_id = self._get_ipa_config()
        return self._org_id

    @property
    def domain_id(self):
        if self._domain_id is None:
            self._org_id, self._domain_id = self._get_ipa_config()
        return self._domain_id

    def update_ipa(
        self,
        org_id,
        rhsm_id,
        inventory_id,
        fqdn,
    ):
        ipa_org_id = self.org_id
        if org_id != ipa_org_id:
            raise HTTPException.from_error(
                400,
                "Invalid org_id: {org_id} != {ipa_org_id}".format(
                    org_id=org_id,
                    ipa_org_id=ipa_org_id,
                ),
            )
        rhsm_id = hccplatform.text(rhsm_id)
        inventory_id = hccplatform.text(inventory_id)
        fqdn = hccplatform.text(fqdn)
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
            raise HTTPException.from_error(411, "Length required.")
        if length > maxlength:
            raise HTTPException.from_error(413, "Request entity too large.")
        return json.load(env["wsgi.input"])

    def handle(self, env):
        method = env["REQUEST_METHOD"]
        if method != "POST":
            raise HTTPException.from_error(
                405, "Method {method} not allowed.".format(method=method)
            )
        fqdn = env["PATH_INFO"][1:]
        if not fqdn or "/" in fqdn:
            raise HTTPException.from_error(404, "host not found")

        body = self.get_json(env)
        try:
            schema.validate_schema(body, "/schemas/hcc-host-register/request")
        except schema.ValidationError as e:
            raise HTTPException.from_exception(e, 400, "Invalid request body")

        inventory_id = body["inventory_id"]

        self.bootstrap_ipa()

        org_id, rhsm_id = self.parse_cert(env, "SSL_CLIENT_CERT")
        logger.warning(
            "Received self-enrollment request for org O=%s, CN=%s",
            org_id,
            rhsm_id,
        )
        try:
            self.connect_ipa()
            self.check_host(inventory_id, rhsm_id, fqdn)
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
        response = {"status": "ok", "kdc_cabundle": self._kdc_cabundle}
        schema.validate_schema(
            response, "/schemas/hcc-host-register/response"
        )
        raise HTTPException(
            200,
            json.dumps(response),
            content_type="application/json",
        )

    def __call__(self, env, start_response):
        try:
            return self.handle(env)
        except HTTPException as e:
            if e.code >= 400:
                logger.info("%s: %s", str(e), e.message)
            start_response(str(e), e.headers)
            return [e.message]
        except BaseException as e:  # pylint: disable=broad-except
            logger.exception("Request failed")
            e = HTTPException.from_exception(
                e, 500, "invalid server error: {e}".format(e=e)
            )
            start_response(str(e), e.headers)
            return [e.message]
