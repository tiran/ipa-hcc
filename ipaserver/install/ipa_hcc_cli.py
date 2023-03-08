"""ipa-hcc CLI tool
"""
import logging
import json

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
import requests
import requests.exceptions

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

hccconfig = hccplatform.HCCConfig()
logger = logging.getLogger(__name__)

RFC4514_MAP = {
    NameOID.EMAIL_ADDRESS: "E",
}

DO_REQUEST = False


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
        [
            "%prog [options] register DOMAIN_ID TOKEN",
            "%prog [options] update",
        ]
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
            if len(self.args) != 3:
                parser.error(
                    "register requires domain id and token argument."
                )
            self.domain_id = self.args[1]
            self.token = self.args[2]
        elif self.command == "update":
            if len(self.args) != 1:
                parser.error("update does not take additional arguments.")
        else:
            parser.error(
                "Unknown command {command}".format(command=self.command)
            )

    def _get_servers(self, config):
        """Get list of IPA server info objects"""
        # Include location information from
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

    def _get_ipa_info(self, config):
        return {
            "domain_id": self.domain_id,
            "domain_name": api.env.domain,
            "domain_type": "ipa",
            "ipa": {
                "realm_name": api.env.realm,
                "servers": self._get_servers(config),
                "cacerts": self._get_cacerts(),
                "realmdomains": self._get_realmdomains(),
            },
        }

    def _submit_domain_api(self, payload, extra_headers=None):
        url = "{idm_api}/domain/{domain_id}".format(
            idm_api=hccconfig.idm_domain_cert_api, domain_id=self.domain_id
        )
        method = "PUT"
        headers = {}
        if extra_headers:
            headers.update(extra_headers)
        logger.debug(
            "Sending %s request to %s with headers %s", method, url, headers
        )
        body = json.dumps(payload, indent=2)
        logger.debug("body: %s", body)
        if not DO_REQUEST:
            logger.warning("Skip request, body:\n%s", body)
            return
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                cert=(hccplatform.RHSM_CERT, hccplatform.RHSM_KEY),
                json=payload,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(
                "Request to %s failed: %s: %s", url, type(e).__name__, e
            )
            raise admintool.ScriptError(
                "{e.__class__.__name__}: {e}".format(e=e),
                rval=4,
            )

    def register(self, config):
        info = self._get_ipa_info(config)
        extra_headers = {
            "X-RH-IDM-Registration-Token": self.token,
        }
        self._submit_domain_api(info, extra_headers)
        # update after successful registration
        api.Command.config_mod(hccdomainid=self.domain_id)

    def update(self, config):
        self.domain_id = get_one(config, "hccdomainid", None)
        if self.domain_id is None:
            raise admintool.ScriptError(
                "Global setting 'hccDomainId' is missing.",
                rval=3,
            )
        info = self._get_ipa_info(config)
        self._submit_domain_api(info)

    def run(self):
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect()
        try:
            config = api.Command.config_show()["result"]
        except Exception as e:
            logger.exception("Unable to get global configuration from IPA")
            raise admintool.ScriptError(e, rval=5)

        try:
            if self.command == "register":
                self.register(config)
            elif self.command == "update":
                self.update(config)
        finally:
            api.Backend.ldap2.disconnect()


if __name__ == "__main__":
    IPAHCCCli.run_cli()
