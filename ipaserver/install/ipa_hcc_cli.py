"""ipa-hcc CLI tool
"""
import json

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ipalib import api
from ipalib import errors
from ipalib.install import certstore
from ipaplatform.paths import paths
from ipapython import admintool

try:
    from ipalib.facts import is_ipa_configured
except ImportError:
    from ipaserver.install.installutils import is_ipa_configured

RFC4514_MAP = {
    NameOID.EMAIL_ADDRESS: "E",
}

missing = object()


def get_one(dct, key, default=missing):
    try:
        return dct[key][0]
    except (KeyError, ValueError):
        if default is missing:
            raise
        return default


class IPAHCCCli(admintool.AdminTool):
    command_name = "ipa-hcc"
    usage = "%prog"
    description = "Renew expired certificates."

    def validate_options(self):
        super(IPAHCCCli, self).validate_options(needs_root=True)

    def list_servers(self):
        config = api.Command.config_show()["result"]
        ca_servers = set(config.get("ca_server_server", ()))
        hcc_enrollment = set(config.get("hcc_enrollment_server_server", ()))
        pkinit_servers = set(config.get("pkinit_server_server", ()))

        result = api.Command.host_find(in_hostgroup="ipaservers")

        servers = []
        for server in result["result"]:
            fqdn = get_one(server, "fqdn")

            server_info = dict(
                fqdn=fqdn,
                rhsm_id=get_one(server, "hccsubscriptionid", default=None),
                ca_server=fqdn in ca_servers,
                hcc_enrollment_server=fqdn in hcc_enrollment,
                pkinit_server=fqdn in pkinit_servers,
            )
            servers.append(server_info)

        return servers

    def get_cacerts(self):
        try:
            result = api.Command.ca_is_enabled(version="2.107")
            ca_enabled = result["result"]
        except (errors.CommandError, errors.NetworkError):
            result = api.Command.env(server=True, version="2.0")
            ca_enabled = result["result"]["enable_ra"]

        certs = certstore.get_ca_certs(
            api.Backend.ldap2, api.env.basedn, api.env.realm, ca_enabled
        )

        cacerts = []
        for cert, nickname, trusted, _eku in certs:
            if not trusted:
                continue
            certinfo = dict(
                nickname=nickname,
                pem=cert.public_bytes(Encoding.PEM).decode("ascii"),
                issuer=cert.issuer.rfc4514_string(RFC4514_MAP),
                subject=cert.subject.rfc4514_string(RFC4514_MAP),
                # JSON number type cannot handle large serial numbers
                serial_number=str(cert.serial_number),
                not_valid_before=cert.not_valid_before.isoformat(),
                not_valid_after=cert.not_valid_before.isoformat(),
            )
            cacerts.append(certinfo)

        return cacerts

    def run(self):
        if not is_ipa_configured():
            print("IPA is not configured.")
            return 2

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect()

        info = dict(
            domain_type="ipa",
            domain_name=api.env.domain,
            realm_name=api.env.realm,
            servers=self.list_servers(),
            cacerts=self.get_cacerts(),
        )
        print(json.dumps(info, indent=2))


if __name__ == "__main__":
    IPAHCCCli.run_cli()
