import os
import http.client
from typing import Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID

from ipalib import api, errors
from ipalib.install.kinit import kinit_keytab
from ipaplatform.paths import paths

INVENTORY = {
    "c50f3252-520f-433d-9a1c-4b2c7a06dffa": "ipaclient1.hmsidm.test",
}

# KEYTAB = "/var/lib/ipa/gssproxy/ipaconsoledot.keytab"
KEYTAB = "/var/lib/ipa/consoledot/service.keytab"
CCNAME = "/tmp/krb5cc-ipaconsoledot"
SERVICE = "consoledot-enrollment"

os.environ["KRB5CCNAME"] = CCNAME
os.environ["KRB5_CLIENT_KTNAME"] = KEYTAB

SCRIPT = """\
#!/bin/sh
set -ex

CABUNDLE=$(mktemp)
trap "rm -f $CABUNDLE" EXIT

cat >$CABUNDLE << EOF
{cabundle_pem}
EOF

ipa-client-install \
--ca-cert-file=$CABUNDLE \
--server={server} \
--domain={domain} \
--realm={realm} \
--pkinit-identity=FILE:/etc/pki/consumer/cert.pem,/etc/pki/consumer/key.pem \
--pkinit-anchor=FILE:$CABUNDLE \
--force-join \
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
        return "{} {}".format(self.code, http.client.responses[self.code])


class Application:
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

    def lookup_inventory(self, rhsm_id: str) -> str:
        try:
            return INVENTORY[rhsm_id]
        except KeyError:
            raise HTTPException(404, f"Unknown host {rhsm_id}.")

    def connect_ipa(self):
        if not api.isdone("bootstrap"):
            api.bootstrap(in_server=False)
        principal = f"{SERVICE}/{api.env.host}@{api.env.realm}"
        kinit_keytab(principal, KEYTAB, CCNAME)
        if not api.isdone("finalize"):
            api.finalize()
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

    def disconnect_ipa(self):
        if api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.disconnect()

    def update_ipa(self, org_id: int, rhsm_id: str, fqdn: str):
        try:
            api.Command.host_add(
                fqdn,
                # consoledotorgid=org_id,
                consoledotsubscriptionid=rhsm_id,
                force=True,
            )
        except errors.DuplicateEntry:
            try:
                api.Command.host_mod(
                    fqdn,
                    # consoledotorgid=org_id,
                    consoledotsubscriptionid=rhsm_id,
                )
            except errors.EmptyModlist:
                pass

    def handle(self, env, start_repose):
        method = env["REQUEST_METHOD"]
        if method != "GET":
            raise HTTPException(405, f"Method {method} not allowed.")
        cert = self.parse_cert(env, "SSL_CLIENT_CERT")
        org_id, rhsm_id = self.parse_subject(cert.subject)
        fqdn = self.lookup_inventory(rhsm_id)
        try:
            self.connect_ipa()
            self.update_ipa(org_id, rhsm_id, fqdn)
        finally:
            self.disconnect_ipa()
        with open(paths.KDC_CA_BUNDLE_PEM, "r") as f:
            cabundle_pem = f.read()
        script = SCRIPT.format(
            server=api.env.host,
            domain=api.env.domain,
            realm=api.env.realm,
            cabundle_pem=cabundle_pem,
        )
        raise HTTPException(
            200,
            script,
        )

    def __call__(self, env, start_response):
        try:
            return self.handle(env, start_response)
        except HTTPException as e:
            start_response(str(e), e.headers)
            return [e.message]
        except Exception as e:
            e = HTTPException(500, f"invalid server error: {e}")
            start_response(str(e), e.headers)
            return [e.message]


application = Application()
