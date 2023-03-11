"""ipa-hcc CLI tool
"""
import logging
import json
from optparse import OptionGroup  # pylint: disable=deprecated-module

from cryptography.hazmat.primitives.serialization import Encoding
import requests
import requests.exceptions

import ipalib
from ipalib import errors
from ipalib.install import certstore
from ipaplatform.paths import paths
from ipapython import admintool
from ipaserver.install import installutils

from ipahcc import hccplatform

hccconfig = hccplatform.HCCConfig()
logger = logging.getLogger(__name__)


missing = object()


def get_one(dct, key, default=missing):
    try:
        return dct[key][0]
    except (KeyError, IndexError):
        if default is missing:
            raise
        return default


class IPAHCC(object):
    """Register or update domain information in HCC"""

    domain_type = "rhel-idm"

    def __init__(self, api, timeout=10, dry_run=False):
        if not api.isdone("finalize") or not api.env.in_server:
            raise ValueError(
                "api must be an in_server, finalized, and connected API object"
            )

        self.api = api
        self.timeout = timeout
        self.dry_run = dry_run
        self._config = None

    def __enter__(self):
        try:
            self._config = self.api.Command.config_show()["result"]
        except Exception as e:
            logger.exception("Unable to get global configuration from IPA")
            raise admintool.ScriptError(e, rval=5)

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._config = None

    def register(self, domain_id, token):
        info = self._get_ipa_info()
        extra_headers = {
            "X-RH-IDM-Registration-Token": token,
        }
        self._submit_domain_api(domain_id, info, extra_headers)
        # update after successful registration
        self.api.Command.config_mod(hccdomainid=domain_id)
        return True

    def update(self, update_server_only=False):
        # hcc_update_server_server is a single attribute
        update_server = self._config.get("hcc_update_server_server")
        if update_server_only and update_server != self.api.env.host:
            # stop with success
            logger.info(
                "Current host is not an HCC update server (update server: %s)",
                update_server,
            )
            return False

        domain_id = get_one(self._config, "hccdomainid", None)
        if domain_id is None:
            raise admintool.ScriptError(
                "Global setting 'hccDomainId' is missing.",
                rval=3,
            )

        info = self._get_ipa_info()
        self._submit_domain_api(domain_id, info)

    def _get_servers(self):
        """Get list of IPA server info objects"""
        # Include location information from
        ca_servers = set(self._config.get("ca_server_server", ()))
        hcc_enrollment = set(
            self._config.get("hcc_enrollment_server_server", ())
        )
        hcc_update = self._config.get("hcc_update_server_server", None)
        pkinit_servers = set(self._config.get("pkinit_server_server", ()))

        result = self.api.Command.host_find(in_hostgroup="ipaservers")

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
            result = self.api.Command.ca_is_enabled(version="2.107")
            ca_enabled = result["result"]
        except (errors.CommandError, errors.NetworkError):
            result = self.api.Command.env(server=True, version="2.0")
            ca_enabled = result["result"]["enable_ra"]

        certs = certstore.get_ca_certs(
            self.api.Backend.ldap2,
            self.api.env.basedn,
            self.api.env.realm,
            ca_enabled,
        )

        cacerts = []
        for cert, nickname, trusted, _eku in certs:
            if not trusted:
                continue
            certinfo = dict(
                nickname=nickname,
                pem=cert.public_bytes(Encoding.PEM).decode("ascii"),
            )
            cacerts.append(certinfo)

        return cacerts

    def _get_realmdomains(self):
        """Get list of realm domain names"""
        result = self.api.Command.realmdomains_show()
        return list(result["result"]["associateddomain"])

    def _get_ipa_info(self):
        return {
            "domain_name": self.api.env.domain,
            "domain_type": self.domain_type,
            self.domain_type: {
                "realm_name": self.api.env.realm,
                "servers": self._get_servers(),
                "cacerts": self._get_cacerts(),
                "realmdomains": self._get_realmdomains(),
            },
        }

    def _submit_domain_api(self, domain_id, payload, extra_headers=None):
        url = "{idm_api}/domain/{domain_id}".format(
            idm_api=hccconfig.idm_cert_api, domain_id=domain_id
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
        if self.dry_run:
            logger.warning("Skip %s request %s, body:\n%s", method, url, body)
            return
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
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


class IPAHCCCli(admintool.AdminTool):
    command_name = "ipa-hcc"
    usage = "\n".join(
        [
            "%prog [options] register DOMAIN_ID TOKEN",
            "%prog [options] update",
        ]
    )
    description = "Register or update IPA domain in Hybrid Cloud Console"

    @classmethod
    def add_options(cls, parser):
        super(IPAHCCCli, cls).add_options(parser)

        parser.add_option(
            "--timeout",
            type="int",
            default=10,
            help="Timeout for HTTP and LDAP requests",
        )

        update_group = OptionGroup(parser, "Update options")
        update_group.add_option(
            "--update-server-only",
            dest="update_server_only",
            action="store_true",
            help="only run on HCC update server",
        )
        parser.add_option_group(update_group)

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
        elif self.command == "update":
            if len(self.args) != 1:
                parser.error("update does not take additional arguments.")
        else:
            parser.error(
                "Unknown command {command}".format(command=self.command)
            )

    def run(self):
        ipalib.api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        ipalib.api.finalize()
        try:
            ipalib.api.Backend.ldap2.connect(time_limit=self.options.timeout)
        except errors.NetworkError:
            logger.debug("Failed to connect to IPA", exc_info=True)
            raise admintool.ScriptError(
                "The IPA server is not running; cannot proceed.", rval=2
            )

        with IPAHCC(
            ipalib.api,
            timeout=self.options.timeout,
            dry_run=True,
        ) as ipahcc:
            if self.command == "register":
                ipahcc.register(domain_id=self.args[1], token=self.args[2])
            elif self.command == "update":
                ipahcc.update(
                    update_server_only=self.options.update_server_only
                )


if __name__ == "__main__":
    IPAHCCCli.run_cli()
