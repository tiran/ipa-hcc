"""ipa-hcc CLI tool
"""
import logging
import json

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ipalib import api
from ipalib import errors
from ipalib.install import certstore
from ipaplatform.paths import paths
from ipaplatform import hccplatform
from ipapython import admintool
from ipaserver.plugins.hccserverroles import (
    hcc_enrollment_server_attribute,
    hcc_update_server_attribute,
)
from ipaserver.install import installutils

if hccplatform.PY2:
    from ConfigParser import SafeConfigParser as ConfigParser
    from ConfigParser import NoOptionError, NoSectionError
else:
    from configparser import ConfigParser, NoOptionError, NoSectionError

logger = logging.getLogger(__name__)

RFC4514_MAP = {
    NameOID.EMAIL_ADDRESS: "E",
}


def detect_environment(rhsm_conf="/etc/rhsm/rhsm.conf", default="prod"):
    """Detect environment (stage, prod) from RHSM server name"""
    c = ConfigParser()
    try:
        with open(rhsm_conf) as f:
            c.read_file(f)
    except Exception as e:
        logger.error("Failed to read '%s': %s", rhsm_conf, e)
        return default

    try:
        # Python 2 does not support get(..., fallback) argument
        server_hostname = c.get("server", "hostname")
    except (NoOptionError, NoSectionError):
        return default

    server_hostname = server_hostname.strip()
    if server_hostname == "subscription.rhsm.redhat.com":
        return "prod"
    elif server_hostname == "subscription.rhsm.stage.redhat.com":
        return "stage"
    else:
        return default


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
    usage = "\n".join(
        ["%prog [options] register TOKEN", "%prog [options] update"]
    )
    description = "Renew expired certificates."

    def validate_options(self):
        super(IPAHCCCli, self).validate_options(needs_root=True)
        # fail if server is not installed
        installutils.check_server_configuration()

        parser = self.option_parser
        if not self.args:
            parser.error("command not provided")

        self.command = self.args[0]
        if self.command == "register":
            if len(self.args) != 2:
                parser.error("register requires a token.")
            self.token = self.args[1]
        elif self.command == "update":
            if len(self.args) != 1:
                parser.error("update does not take additional arguments.")
        else:
            parser.error(
                "Unknown command {command}".format(command=self.command)
            )

    def _get_servers(self):
        """Get list of IPA server info objects"""
        # Include location information from
        config = api.Command.config_show()["result"]
        ca_servers = set(config.get("ca_server_server", ()))
        hcc_enrollment = set(
            config.get(hcc_enrollment_server_attribute.attr_name, ())
        )
        hcc_update = config.get(hcc_update_server_attribute.attr_name, None)
        pkinit_servers = set(config.get("pkinit_server_server", ()))

        result = api.Command.host_find(in_hostgroup="ipaservers")

        servers = []
        for server in result["result"]:
            fqdn = get_one(server, "fqdn")

            server_info = dict(
                fqdn=fqdn,
                rhsm_id=get_one(server, "hccsubscriptionid", default=None),
                ca_server=(fqdn in ca_servers),
                hcc_enrollment_server=(fqdn in hcc_enrollment),
                hcc_update_server=(fqdn == hcc_update),
                pkinit_server=(fqdn in pkinit_servers),
            )
            servers.append(server_info)

        return servers

    def _get_cacerts(self):
        """Get list of trusted CA cert info objects"""
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

    def _get_realmdomains(self):
        """Get list of realm domain names"""
        result = api.Command.realmdomains_show()
        return list(result["result"]["associateddomain"])

    def get_ipa_info(self):
        return dict(
            domain_type="ipa",
            domain_name=api.env.domain,
            realm_name=api.env.realm,
            servers=self._get_servers(),
            cacerts=self._get_cacerts(),
            realmdomains=self._get_realmdomains(),
        )

    def register(self):
        payload = dict(
            type="register",
            token=self.token,
            source=api.env.host,
            info=self.get_ipa_info(),
        )
        print(json.dumps(payload, indent=2))

    def update(self):
        payload = dict(
            type="update",
            source=api.env.host,
            info=self.get_ipa_info(),
        )
        print(json.dumps(payload, indent=2))

    def run(self):
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect()
        try:
            if self.command == "register":
                self.register()
            elif self.command == "update":
                self.update()
        finally:
            api.Backend.ldap2.disconnect()


if __name__ == "__main__":
    IPAHCCCli.run_cli()
