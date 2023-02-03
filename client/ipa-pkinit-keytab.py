#!/usr/bin/env python3
"""Get host keytab with PKINIT

- discover IPA realm, domain, servers, KDCs, and base DN based
  on CLI arguments and DNS SRV records (pretty much like ipa-client).
- write a temporary krb5.conf for kinit and ipa-getkeytab commands
- with kinit using PKINIT identity and host principal 'host/$FQDN'
- ipa-getkeytab for host principal 'host/$FQDN' using the first
  IPA server from auto-discovery / CLI

The script requires the public CA cert of the KDC in order to initiate
secure PKINIT. Insecure fetch::

  curl --insecure https://SERVER/ipa/config/ca.crt -o ca.crt

"""
import argparse
import logging
import os
import shlex
import shutil
import tempfile


try:
    from ipaclient import discovery

    SUCCESS = discovery.SUCCESS
except ImportError:
    from ipaclient.install import ipadiscovery as discovery

    SUCCESS = 0

from ipaclient.install.client import configure_krb5_conf
from ipalib.constants import FQDN
from ipalib.util import validate_domain_name, validate_hostname
from ipaplatform.paths import paths
from ipapython.ipautil import run


logger = logging.getLogger(__name__)


def check_hostname(arg):
    validate_hostname(arg)
    return arg.lower()


def check_realm(arg):
    validate_domain_name(arg, entity="realm")
    return arg.upper()


def check_domain(arg):
    validate_domain_name(arg, entity="domain")
    return arg.lower()


def check_cafile(arg):
    if not os.path.isfile(arg):
        raise ValueError("{arg} does not exist".format(arg))
    return os.path.abspath(arg)


parser = argparse.ArgumentParser()

parser.add_argument(
    "--debug",
    "-d",
    help="Enable debug logging",
    dest="debug",
    action="count",
    default=False,
)
parser.add_argument(
    "--ca-cert-file",
    metavar="FILE",
    required=True,
    help="load the CA certificate from this file",
    dest="cacert",
    type=check_cafile,
)
parser.add_argument(
    "--server",
    metavar="SERVER",
    help="FQDN of IPA server",
    type=check_hostname,
)
parser.add_argument(
    "--domain",
    metavar="DOMAIN_NAME",
    help="primary DNS domain of the IPA deployment",
    type=check_domain,
)
parser.add_argument(
    "--realm",
    metavar="REALM",
    help="Kerberos realm name of the IPA deployment",
    type=check_realm,
)
parser.add_argument(
    "--hostname",
    metavar="HOST_NAME",
    help="The hostname of this machine (FQDN)",
    default=FQDN,
    type=check_hostname,
)
parser.add_argument(
    "--pkinit-identity",
    metavar="IDENTITY",
    help="PKINIT identity information",
    default="FILE:/etc/pki/consumer/cert.pem,/etc/pki/consumer/key.pem",
)
parser.add_argument(
    "--pkinit-anchor",
    metavar="FILEDIR",
    help=(
        "PKINIT trust anchors, prefixed with FILE: for CA PEM bundle file or "
        "DIR: for an OpenSSL hash dir."
    ),
    dest="pkinit_anchors",
    action="append",  # support multiple
)
parser.add_argument(
    "--keytab",
    "-k",
    metavar="FILE",
    help="The keytab file to append the new key to (will be created if it does not exist)",
    required=True,
    dest="keytab",
)
parser.add_argument(
    "--force",
    help="force setting of Kerberos conf",
    action="store_true",
)

DEFAULT_PKINIT_ANCHOR = "FILE:/usr/share/ipa-hcc/redhat-candlepin-bundle.pem"


def discover(args):
    ds = discovery.IPADiscovery()
    res = ds.search(
        domain=args.domain if args.domain else "",
        servers=[args.server] if args.server is not None else "",
        realm=args.realm,
        hostname=args.hostname,
        ca_cert_path=args.cacert,
    )
    if res != SUCCESS:
        err = discovery.error_names[res]
        parser.error("IPA discovery failed: {}.\n".format(err))
    logger.info(
        "Discovered IPA realm '%s', domain '%s'.",
        ds.realm,
        ds.domain,
    )
    logger.info("IPA servers: %s", ", ".join(ds.servers))

    dnsok = False
    if not args.server and False:
        server, domain = ds.check_domain(
            ds.domain, set(), "Validating DNS Discovery"
        )
        if server and domain:
            logger.debug("DNS validated, enabling discovery")
            dnsok = True
        else:
            logger.debug("DNS discovery failed, disabling discovery")
    else:
        logger.debug(
            "Using servers from command line, disabling DNS discovery"
        )

    logger.info("Client hostname: %s", args.hostname)
    logger.info("Realm: %s", ds.realm)
    logger.debug("Realm source: %s", ds.realm_source)
    logger.info("DNS Domain: %s", ds.domain)
    logger.info("DNS discovery works: %s", dnsok)
    logger.debug("DNS Domain source: %s", ds.domain_source)
    logger.info("IPA Server: %s", ", ".join(ds.servers))
    logger.debug("IPA Server source: %s", ds.server_source)
    logger.info("BaseDN: %s", ds.basedn)
    logger.debug("BaseDN source: %s", ds.basedn_source)

    return ds, dnsok


def create_krb5_conf(args, ds, dnsok, krb_name):
    client_domain = args.hostname.split(".", 1)[1]
    configure_krb5_conf(
        cli_realm=ds.realm,
        cli_domain=ds.domain,
        cli_server=ds.servers,
        cli_kdc=ds.kdc,
        dnsok=dnsok,
        filename=krb_name,
        client_domain=client_domain,
        client_hostname=args.hostname,
        configure_sssd=False,
        force=args.force,
    )

    # remove pkinit anchors and pool lines. The files do not exist, yet.
    with open(krb_name) as f:
        lines = list(f)
    with open(krb_name, "w") as f:
        for line in lines:
            if line.strip().startswith(("pkinit_anchors", "pkinit_pool")):
                logger.debug(
                    "Removed line '%s' from %s", line.strip(), krb_name
                )
                continue
            f.write(line)


def pkinit(args, host_principal, env):
    cmd = [paths.KINIT]
    anchors = []
    if args.cacert:
        anchors.append("FILE:{}".format(args.cacert))
    if args.pkinit_anchors:
        anchors.extend(args.pkinit_anchors)
    for pkinit_anchor in anchors:
        if not pkinit_anchor.startswith(("FILE:", "DIR:", "ENV:")):
            raise ValueError(pkinit_anchor)
        cmd.extend(["-X", "X509_anchors={}".format(pkinit_anchor)])
    cmd.extend(["-X", "X509_user_identity={}".format(args.pkinit_identity)])
    cmd.append(host_principal)
    # send \n on stdin in case we get a password prompt
    run(cmd, env=env, stdin="\n", raiseonerr=True)


def getkeytab(args, host_principal, ds, env):
    # fmt: off
    cmd = [
        paths.IPA_GETKEYTAB,
        "-s", ds.server,
        "-p", host_principal,
        "-k", args.keytab,
    ]
    # fmt: on
    if args.cacert is not None:
        cmd.extend(("--cacert", args.cacert))
    run(cmd, env=env, raiseonerr=True)


def ipa_client_cmd(args):
    # fmt: off
    cmd = [
        paths.IPA_CLIENT_INSTALL,
        "--keytab", args.keytab,
        "--ca-cert-file", args.cacert,
        "--hostname", args.hostname,
    ]
    # fmt: on
    if args.realm:
        cmd.extend(["--realm", args.realm])
    if args.domain:
        cmd.extend(["--domain", args.domain])
    if args.server:
        cmd.extend(["--server", args.server])
    if args.force:
        cmd.append("--force")
    return cmd


def main():
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    if args.realm and not args.domain:
        args.domain = args.realm.lower()
    if args.domain and not args.realm:
        args.realm = args.domain.upper()
    if args.pkinit_anchors is None:
        args.pkinit_anchors = [DEFAULT_PKINIT_ANCHOR]

    tmpdir = tempfile.mkdtemp()  # Python 2
    try:
        krb_name = os.path.join(tmpdir, "krb5.conf")
        env = {
            "LC_ALL": "C",
            "KRB5_CONFIG": krb_name,
            "KRB5CCNAME": os.path.join(tmpdir, "ccache"),
        }
        if args.debug >= 2:
            env["KRB5_TRACE"] = "/dev/stderr"

        ds, dnsok = discover(args)
        host_principal = "host/{}@{}".format(args.hostname, ds.realm)
        create_krb5_conf(args, ds, dnsok, krb_name)
        pkinit(args, host_principal, env)
        getkeytab(args, host_principal, ds, env)
    finally:
        shutil.rmtree(tmpdir)

    cmd = ipa_client_cmd(args)
    if hasattr(shlex, "join"):
        print(shlex.join(cmd))
    else:
        print(" ".join(cmd))


if __name__ == "__main__":
    main()
