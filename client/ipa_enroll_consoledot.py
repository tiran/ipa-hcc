#!/usr/bin/env python3
import argparse
import logging
import os
import subprocess
import tempfile

import requests

from ipaclient import discovery
from ipaplatform.paths import paths

try:
    from ipaplatform.consoledotplatform import RHSM_CERT, RHSM_KEY
except ImportError:
    RHSM_CERT = "/etc/pki/consumer/cert.pem"
    RHSM_KEY = "/etc/pki/consumer/key.pem"

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument(
    "-d",
    "--debug",
    dest="debug",
    action="store_true",
)
parser.add_argument(
    "--ca-cert-file",
    dest="cacert",
    # default="/etc/ipa/ca.crt",
)
parser.add_argument(
    "--insecure",
    action="store_true",
)

def discover_ipa(args):
    ds = discovery.IPADiscovery()
    res = ds.search(ca_cert_path=args.cacert)
    if res != discovery.SUCCESS:
        parser.error(
            f"IPA discovery failed: %s.\n", discovery.error_names[res]
        )
    logger.info(
        "Discovered IPA realm '%s', domain '%s'.", ds.realm, ds.domain
    )
    logger.info("IPA servers: %s", ", ".join(ds.servers))
    return ds


def consoledot_register(args, server):
    url = f"https://{server}/consoledot"
    logger.info("Registering host at %s", url)
    r = requests.get(
        url,
        verify=args.cacert,
        cert=(RHSM_CERT, RHSM_KEY),
    )
    r.raise_for_status()
    return r.content


def main():
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    if args.cacert:
        if not os.path.isfile(args.cacert):
            parser.error(f"CA cert {args.cacert} is missing.\n")
    elif os.path.isfile(paths.IPA_CA_CRT):
        args.cacert = paths.IPA_CA_CRT
    elif args.insecure:
        logger.warning("Insecure HTTPS connection")
        args.cacert = False
    else:
        logger.warning("No CA file")

    if os.path.isfile(paths.IPA_DEFAULT_CONF):
        parser.error(
            f"IPA is already installed, '{paths.IPA_DEFAULT_CONF}' exists.\n"
        )

    ds = discover_ipa(args)

    kdc_ca_data = consoledot_register(args, ds.server)

    with tempfile.NamedTemporaryFile() as f:
        f.write(kdc_ca_data)
        f.flush()

        cmd = [
            "ipa-client-install",
            f"--pkinit-identity=FILE:{RHSM_CERT},{RHSM_KEY}",
            f"--pkinit-anchor=FILE:{f.name}",
            "--unattended",
        ]
        if args.cacert:
            cmd.append(f"--ca-cert-file={args.cacert}")
        logger.info("Installing client: %s", " ".join(cmd))
        subprocess.check_call(cmd)

    logger.info("Done")


if __name__ == "__main__":
    main()
