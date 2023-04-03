from __future__ import absolute_import, print_function

import argparse
import logging
import sys
import uuid

import dbus.exceptions

from ipapython import admintool

from ipahcc import hccplatform
from . import dbus_client
from .hccapi import APIError

logger = logging.getLogger(__name__)


def uuidtype(v):
    uuid.UUID(v)
    return v


parser = argparse.ArgumentParser(
    prog="ipa-hcc",
    description="Register or update IPA domain in Hybrid Cloud Console",
    usage="\n".join(
        [
            "",
            "  %(prog)s [options] register DOMAIN_ID TOKEN",
            "  %(prog)s [options] update [--update-server-only]",
            # undocumented option for debugging and testing
            # "%prog [options] check-host INVENTORY_ID RHSM_ID FQDN",
        ]
    ),
)
parser.add_argument(
    "--version",
    "-V",
    help="Show version number and exit",
    action="version",
    version="ipa-hcc {} (IPA {})".format(
        hccplatform.VERSION, hccplatform.IPA_VERSION
    ),
)
subparsers = parser.add_subparsers(dest="action")

parser_register = subparsers.add_parser(
    "register", help="Register a domain with Hybrid Cloud Console"
)
parser_register.add_argument("domain_id", type=uuidtype)
parser_register.add_argument("token", type=str)

parser_update = subparsers.add_parser(
    "update", help="Update domain information"
)
parser_update.add_argument("--update-server-only", action="store_true")

# undocumented debug helper
parser_check_host = subparsers.add_parser("check-host")
parser_check_host.add_argument("domain_id", type=uuidtype)
parser_check_host.add_argument("inventory_id", type=uuidtype)
parser_check_host.add_argument("rhsm_id", type=uuidtype)
parser_check_host.add_argument("fqdn")


def main(args=None):
    args = parser.parse_args(args)
    # Python < 3.7 does not have required subparser
    if not getattr(args, "action", None):
        parser.error("action required\n")
    if not hccplatform.is_ipa_configured():
        print("IPA is not configured on this system.", file=sys.stderr)
        parser.exit(admintool.SERVER_NOT_CONFIGURED)
    try:
        if args.action == "check-host":
            result = dbus_client.check_host(
                args.domain_id,
                args.inventory_id,
                args.rhsm_id,
                args.fqdn,
            )
        elif args.action == "register":
            result = dbus_client.register_domain(args.domain_id, args.token)
        elif args.action == "update":
            result = dbus_client.update_domain(args.update_server_only)
        else:  # pragma: no cover
            raise ValueError(args.action)
    except dbus.exceptions.DBusException as e:
        logger.exception("D-Bus call failed")
        print("D-Bus error: {e}".format(e=e), file=sys.stderr)
        parser.exit(255)
    except APIError as e:
        logger.error("API error: %s", e)
        print(e.result.exit_message, file=sys.stderr)
        parser.exit(e.result.exit_code)
    else:
        print(result)
        parser.exit(0)


if __name__ == "__main__":
    main()
