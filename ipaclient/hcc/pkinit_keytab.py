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


from ipaplatform.paths import paths
from ipaclient.hcc.auto_enrollment import (
    discover_ipa,
    create_krb5_conf,
    pkinit,
    getkeytab,
    FQDN,
    check_hostname,
    check_realm,
    check_domain,
)


logger = logging.getLogger(__name__)


def check_cafile(arg):
    if not os.path.isfile(arg):
        raise ValueError("{arg} does not exist".format(arg=arg))
    return os.path.abspath(arg)


parser = argparse.ArgumentParser()

parser.add_argument(
    "--debug",
    "-d",
    help="Enable debug logging",
    dest="debug",
    default=False,
    type=int,
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
    "--insecure",
    action="store_true",
    help="Use insecure download of CA cert chain",
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


def main(*args):
    args = parser.parse_args(*args)
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
        local_cacert = args.cacert
        env = {
            "LC_ALL": "C",
            "KRB5_CONFIG": krb_name,
            "KRB5CCNAME": os.path.join(tmpdir, "ccache"),
        }
        if args.debug >= 2:
            env["KRB5_TRACE"] = "/dev/stderr"

        ds, dnsok = discover_ipa(args, local_cacert)
        host_principal = "host/{}@{}".format(args.hostname, ds.realm)
        create_krb5_conf(args, ds, dnsok, krb_name)
        pkinit(args, host_principal, local_cacert, env)
        getkeytab(args, host_principal, ds, local_cacert, env)
    finally:
        shutil.rmtree(tmpdir)

    cmd = ipa_client_cmd(args)
    if hasattr(shlex, "join"):
        print(shlex.join(cmd))
    else:
        print(" ".join(cmd))
