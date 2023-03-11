from __future__ import absolute_import, print_function

import argparse
import logging
import sys
import uuid

import dbus.exceptions

from . import dbus_client
from .hccapi import APIError

logger = logging.getLogger(__name__)


def uuidtype(v):
    uuid.UUID(v)
    return v


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="action")

parser_check_host = subparsers.add_parser("check-host")
parser_check_host.add_argument("domain_id", type=uuidtype)
parser_check_host.add_argument("inventory_id", type=uuidtype)
parser_check_host.add_argument("rhsm_id", type=uuidtype)
parser_check_host.add_argument("fqdn")

parser_register = subparsers.add_parser("register")
parser_register.add_argument("domain_id", type=uuidtype)
parser_register.add_argument("token", type=str)

parser_update = subparsers.add_parser("update")
parser_update.add_argument("--update-server-only", action="store_true")


def main(*args):
    args = parser.parse_args(*args)
    # Python < 3.7 does not have required subparser
    if not getattr(args, "action", None):
        parser.error("action required\n")
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
        else:
            raise ValueError(args.action)
    except dbus.exceptions.DBusException as e:
        logger.exception("D-Bus call failed")
        print("D-Bus error: {e}".format(e=e), file=sys.stderr)
        sys.exit(255)
    except APIError as e:
        logger.error("API error: {e}".format(e=e))
        print(e.result.exit_message, file=sys.stderr)
        sys.exit(e.result.exit_code)
    else:
        print(result)


if __name__ == "__main__":
    main()
