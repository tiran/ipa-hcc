#!/usr/bin/env python3
import argparse
import logging
import os
import subprocess
import tempfile
import time

import requests

from ipaclient import discovery
from ipalib.constants import FQDN
from ipaplatform.paths import paths

from ipaplatform import hccplatform

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
parser.add_argument(
    "--hostname",
    default=FQDN,
)


def discover_ipa(args):
    """Discover IPA servers

    Uses DNS SRV records and LDAP query to detect IPA domain, realm and
    servers.
    """
    ds = discovery.IPADiscovery()
    res = ds.search(
        hostname=args.hostname,
        ca_cert_path=args.cacert,
    )
    if res != discovery.SUCCESS:
        err = discovery.error_names[res]
        parser.error(f"IPA discovery failed: {err}.\n")
    logger.info(
        "Discovered IPA realm '%s', domain '%s'.",
        ds.realm,
        ds.domain,
    )
    logger.info("IPA servers: %s", ", ".join(ds.servers))
    return ds


def hcc_register(args, server):
    """Register this host with /hcc API endpoint

    TODO: On 404 try next server
    """
    url = f"https://{server}/hcc"
    logger.info("Registering host at %s", url)
    r = requests.get(
        url,
        verify=args.cacert,
        cert=(hccplatform.RHSM_CERT, hccplatform.RHSM_KEY),
    )
    r.raise_for_status()
    return r.content


def wait_for_inventory_host(args):
    """Wait until this host is available in Insights inventory

    Sometimes it takes a while until a host appears in Insights.
    """
    sess = requests.Session()
    sess.cert = (
        hccplatform.RHSM_CERT,
        hccplatform.RHSM_KEY,
    )
    for i in range(5):
        try:
            resp = sess.get(hccplatform.INVENTORY_HOSTS_CERT_API)
            resp.raise_for_status()
            j = resp.json()
            # 'j["total"] != 0' also works. A host sees only its record.
            for host in j.get("results", ()):
                if host["fqdn"] == FQDN:
                    logger.info(
                        "Host '%s' found in Insights Inventory.",
                        host["subscription_manager_id"],
                    )
                    return host
        except Exception:
            logger.exception("Host inventory lookup failed, sleeping...")
        else:
            logger.info("Host not found in Insights Inventory, sleeping...")
        time.sleep(5)
    else:
        logger.warning("Host not found in Insights Inventory inventory")


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

    # wait until this host appears in ConsoleDont host inventory
    wait_for_inventory_host(args)
    # discover IPA realm, domain, and servers
    ds = discover_ipa(args)
    # self-register host with IPA
    kdc_ca_data = hcc_register(args, ds.server)

    with tempfile.NamedTemporaryFile() as f:
        f.write(kdc_ca_data)
        f.flush()

        cmd = [
            "ipa-client-install",
            f"--pkinit-identity=FILE:{hccplatform.RHSM_CERT},{hccplatform.RHSM_KEY}",
            # use HMSIDM_CA_BUNDLE_PEM here?
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
