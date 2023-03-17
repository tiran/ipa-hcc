"""ipa-hcc CLI tool
"""
import logging
from optparse import OptionGroup  # pylint: disable=deprecated-module

import ipalib
from ipalib import errors
from ipaplatform.paths import paths
from ipapython import admintool
from ipaserver.install import installutils

from ipahcc import hccplatform
from .hccapi import HCCAPI, APIError, DEFAULT_TIMEOUT

hccconfig = hccplatform.HCCConfig()
logger = logging.getLogger(__name__)


class IPAHCCCli(admintool.AdminTool):
    command_name = "ipa-hcc"
    usage = "\n".join(
        [
            "%prog [options] register DOMAIN_ID TOKEN",
            "%prog [options] update",
            # undocumented option for debugging and testing
            # "%prog [options] check-host INVENTORY_ID RHSM_ID FQDN",
        ]
    )
    description = "Register or update IPA domain in Hybrid Cloud Console"

    @classmethod
    def add_options(cls, parser):
        super(IPAHCCCli, cls).add_options(parser)

        parser.add_option(
            "--timeout",
            type="int",
            default=DEFAULT_TIMEOUT,
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
            if len(self.args) - 1 != 2:
                parser.error(
                    "register requires domain id and token argument."
                )
        elif self.command == "update":
            if len(self.args) - 1 != 0:
                parser.error("update does not take additional arguments.")
        elif self.command == "check-host":
            if len(self.args) - 1 != 3:
                parser.error(
                    "check-host requires inventory_id, rhsm_id, fqdn."
                )
        else:
            parser.error(
                "Unknown command {command}".format(command=self.command)
            )

    def run(self):
        ipalib.api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        ipalib.api.finalize()

        try:
            with HCCAPI(
                ipalib.api,
                timeout=self.options.timeout,
                dry_run=False,
            ) as ipahcc:
                if self.command == "register":
                    ipahcc.register_domain(
                        domain_id=self.args[1], token=self.args[2]
                    )
                elif self.command == "update":
                    ipahcc.update_domain(
                        update_server_only=self.options.update_server_only
                    )
                elif self.command == "check-host":
                    ipahcc.check_host(
                        domain_id=None,
                        inventory_id=self.args[1],
                        rhsm_id=self.args[2],
                        fqdn=self.args[3],
                    )
                else:
                    raise ValueError(self.command)
        except APIError as e:
            logger.exception("API call failed")
            raise admintool.ScriptError(e.error_message, rval=e.exit_code)
        except errors.NetworkError:
            logger.debug("Failed to connect to IPA", exc_info=True)
            raise admintool.ScriptError(
                "The IPA server is not running; cannot proceed.", rval=2
            )


if __name__ == "__main__":
    IPAHCCCli.run_cli()
