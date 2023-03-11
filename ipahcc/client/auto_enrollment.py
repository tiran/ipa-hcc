"""IPA client auto-enrollment for Hybrid Cloud Console

Installation with older clients that lack PKINIT:

- get configuration from remote api /hostconf
- write a temporary krb5.conf for kinit and ipa-getkeytab commands
- with kinit using PKINIT identity and host principal 'host/$FQDN'
- ipa-getkeytab for host principal 'host/$FQDN' using the first
  IPA server from remote configuration
"""

import argparse
import json
import logging
import os
import shutil
import socket
import tempfile
import time

import requests
import requests.exceptions

from ipalib.install import kinit
from ipalib.util import validate_hostname
from ipaplatform.paths import paths
from ipapython.ipautil import run

from ipahcc import hccplatform

# IPA >= 4.9.10 / 4.10.1
HAS_KINIT_PKINIT = hasattr(kinit, "kinit_pkinit")
FQDN = socket.gethostname()

hccconfig = hccplatform.HCCConfig()
logger = logging.getLogger(__name__)


def check_arg_hostname(arg):
    try:
        validate_hostname(arg)
    except ValueError as e:
        raise argparse.ArgumentError(None, str(e))
    return arg.lower()


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
    "--insecure",
    action="store_true",
    help="Use insecure connection to Console API",
)
parser.add_argument(
    "--hostname",
    metavar="HOST_NAME",
    help="The hostname of this machine (FQDN)",
    default=FQDN,
    type=check_arg_hostname,
)
parser.add_argument(
    "--force",
    help="force setting of Kerberos conf",
    action="store_true",
)
parser.add_argument(
    "--timeout",
    help="timeout for HTTP request",
    type=int,
    default=10,
)
# hidden arguments for internal testing
parser.add_argument(
    "--upto",
    metavar="PHASE",
    help=argparse.SUPPRESS,
    choices=("hostconf", "register", "pkinit", "keytab"),
)
parser.add_argument(
    "--override-server",
    metavar="SERVER",
    help=argparse.SUPPRESS,
    type=check_arg_hostname,
)


# configure_krb5_conf() adds unwanted entries and sometimes creates a
# bad krb5.conf.
KRB5_CONF = """\
# includedir /etc/krb5.conf.d/

[libdefaults]
  default_realm = {realm}
  dns_lookup_realm = false
  rdns = false
  dns_canonicalize_hostname = false
  dns_lookup_kdc = true
  ticket_lifetime = 24h
  forwardable = true
  udp_preference_limit = 0

[realms]
  {realm} = {{
    kdc = {server}:88
    master_kdc = {server}:88
    admin_server = {server}:749
    kpasswd_server = {server}:464
    {extra_kdcs}
    default_domain = {domain}
  }}

[domain_realm]
  {hostname} = {realm}
  .{domain} = {realm}
  {domain} = {realm}
"""


def hcc_hostconf(args):
    body = {}
    api_url = hccconfig.hcc_api_url.rstrip("/")
    url = "/".join((api_url, "hostconf", args.hostname))
    verify = not args.insecure
    logger.info(
        "Getting host configuration from %s (secure: %s).", url, verify
    )
    try:
        resp = requests.post(
            url,
            verify=verify,
            timeout=args.timeout,
            cert=(hccplatform.RHSM_CERT, hccplatform.RHSM_KEY),
            json=body,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error("Request to %s failed: %s: %s", url, type(e).__name__, e)
        raise SystemExit(2)
    j = resp.json()

    args.ipa_cacert = os.path.join(args.tmpdir, "ca.crt")
    with open(args.ipa_cacert, "w") as f:
        f.write(j["ipa"]["ca_cert"])
    # IPA CA signs KDC cert
    args.pkinit_anchors.append(
        "FILE:{}".format(args.ipa_cacert),
    )

    args.domain = j["domain_name"]
    args.realm = j["ipa"]["realm_name"]
    args.servers = j["ipa"]["enrollment_servers"]
    # TODO: use all servers
    if args.override_server is None:
        args.server = args.servers[0]
    else:
        args.server = args.override_server
    logger.info("Domain: %s", args.domain)
    logger.info("Realm: %s", args.realm)
    logger.info("Servers: %s", ", ".join(args.servers))


def hcc_register(args):
    """Register this host with /hcc API endpoint

    TODO: On 404 try next server
    """
    url = "https://{server}/hcc/{hostname}".format(
        server=args.server, hostname=args.hostname
    )
    body = {}
    logger.info("Registering host at %s", url)
    resp = requests.post(
        url,
        verify=args.ipa_cacert,
        timeout=args.timeout,
        cert=(hccplatform.RHSM_CERT, hccplatform.RHSM_KEY),
        json=body,
    )
    resp.raise_for_status()
    return resp.json()


def wait_for_inventory_host(args):
    """Wait until this host is available in Insights inventory

    Sometimes it takes a while until a host appears in Insights.
    """
    sess = requests.Session()
    sess.cert = (
        hccplatform.RHSM_CERT,
        hccplatform.RHSM_KEY,
    )
    sess.verify = True  # RH HCC uses public, trusted cert
    time.sleep(3)  # short initial sleep
    sleep_dur = 10  # sleep for 10, 20, 40, ...
    for i in range(5):
        try:
            resp = sess.get(hccconfig.inventory_hosts_cert_api)
            resp.raise_for_status()
            j = resp.json()
            # 'j["total"] != 0' also works. A host sees only its record.
            logger.debug(json.dumps(j, indent=2))
            for host in j.get("results", ()):
                if host["fqdn"] == args.hostname:
                    logger.info(
                        "Host '%s' found in Insights Inventory.",
                        host["subscription_manager_id"],
                    )
                    return host
        except Exception:
            logger.exception(
                "Host inventory lookup failed, try again in %is", sleep_dur
            )
        else:
            logger.info(
                "Host '%s' not found in Insights Inventory, wait for %is",
                args.hostname,
                sleep_dur,
            )
        time.sleep(sleep_dur)
        sleep_dur *= 2
    else:
        logger.warning(
            "Host '%s' not found in Insights Inventory inventory",
            args.hostname,
        )


def create_krb5_conf(args, krb_name):
    """Create a temporary krb5.conf"""
    extra_kdcs = [
        "kdc = {server}:88".format(server=server)
        for server in args.servers
        if server != args.server
    ]
    conf = KRB5_CONF.format(
        realm=args.realm,
        domain=args.domain,
        server=args.server,
        extra_kdcs="\n    ".join(extra_kdcs).strip(),
        hostname=args.hostname,
    )
    logger.debug("Creating %s with content:\n%s", krb_name, conf)
    with open(krb_name, "w") as f:
        f.write(conf)


def pkinit(args, host_principal, env):
    """Perform kinit with X509_user_identity (PKINIT)"""
    cmd = [paths.KINIT]
    for anchor in args.pkinit_anchors:
        cmd.extend(["-X", "X509_anchors={anchor}".format(anchor=anchor)])
    cmd.extend(["-X", "X509_user_identity={}".format(args.pkinit_identity)])
    cmd.append(host_principal)
    # send \n on stdin in case we get a password prompt
    run(cmd, env=env, stdin="\n", raiseonerr=True)


def getkeytab(args, host_principal, env):
    """Retrieve keytab with ipa-getkeytab"""
    keytab = os.path.join(args.tmpdir, "host.keytab")
    # fmt: off
    cmd = [
        paths.IPA_GETKEYTAB,
        "-s", args.server,
        "-p", host_principal,
        "-k", keytab,
        "--cacert", args.ipa_cacert,
    ]
    # fmt: on
    run(cmd, env=env, raiseonerr=True)
    return keytab


def _run_ipa_client(args, extra_args=()):
    # fmt: off
    cmd = [
        paths.IPA_CLIENT_INSTALL,
        "--ca-cert-file", args.ipa_cacert,
        "--hostname", args.hostname,
    ]
    # fmt: on
    if args.realm:
        cmd.extend(["--realm", args.realm])
    if args.domain:
        cmd.extend(["--domain", args.domain])
    if args.servers:
        for server in args.servers:
            cmd.extend(["--server", server])
    if args.force:
        cmd.append("--force")
    cmd.append("--unattended")
    cmd.extend(extra_args)

    return run(cmd, raiseonerr=True)


def ipa_client_keytab(args, keytab):
    """Install IPA client with existing keytab"""
    extra_args = ["--keytab", keytab]
    return _run_ipa_client(args, extra_args)


def ipa_client_pkinit(args):
    """Install IPA client with PKINIT"""
    extra_args = [
        "--pkinit-identity={}".format(args.pkinit_identity),
    ]
    for anchor in args.pkinit_anchors:
        extra_args.append(
            "--pkinit-anchor={anchor}".format(anchor=anchor),
        )
    return _run_ipa_client(args, extra_args)


def parse_args(*args):
    args = parser.parse_args(*args)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Candlepin CA signs RHSM client cert
    args.pkinit_anchors = ["FILE:{}".format(hccplatform.HMSIDM_CA_BUNDLE_PEM)]
    args.pkinit_identity = "FILE:{cert},{key}".format(
        cert=hccplatform.RHSM_CERT, key=hccplatform.RHSM_KEY
    )

    # initialized later
    args.tmpdir = None
    args.ipa_cacert = None
    args.servers = None
    args.domain = None
    args.realm = None

    return args


def check_upto(args, phase):
    if args.upto is not None and args.upto == phase:
        logger.info("Stopping at phase %s", phase)
        parser.exit(0)


def main(*args):
    args = parse_args(*args)

    if os.path.isfile(paths.IPA_DEFAULT_CONF) and not args.upto:
        parser.error(
            "IPA is already installed, '{conf}' exists.\n".format(
                conf=paths.IPA_DEFAULT_CONF
            )
        )

    tmpdir = tempfile.mkdtemp()  # Python 2
    try:
        args.tmpdir = tmpdir
        # wait until this host appears in ConsoleDot host inventory
        # wait_for_inventory_host(args)

        # set local_cacert, servers, domain, realm
        hcc_hostconf(args)
        check_upto(args, "hostconf")

        # self-register host with IPA
        # TODO: check other servers if server returns 400
        hcc_register(args)
        check_upto(args, "register")

        if HAS_KINIT_PKINIT and args.upto is None:
            ipa_client_pkinit(args)
        else:
            krb_name = os.path.join(tmpdir, "krb5.conf")
            # pass KRB5 and OpenSSL env vars
            env = {
                k: v
                for k, v in os.environ.items()
                if k.startswith(("KRB5", "GSS", "OPENSSL"))
            }
            env["LC_ALL"] = "C"
            env["KRB5_CONFIG"] = krb_name
            env["KRB5CCNAME"] = os.path.join(tmpdir, "ccache")
            if args.debug >= 2:
                env["KRB5_TRACE"] = "/dev/stderr"

            host_principal = "host/{}@{}".format(args.hostname, args.realm)
            create_krb5_conf(args, krb_name)
            pkinit(args, host_principal, env=env)
            check_upto(args, "pkinit")

            keytab = getkeytab(args, host_principal, env=env)
            check_upto(args, "keytab")

            ipa_client_keytab(args, keytab)
    finally:
        if args.debug >= 2:
            logger.info("Keeping temporary directory %s", tmpdir)
        else:
            shutil.rmtree(tmpdir)

    logger.info("Done")


if __name__ == "__main__":
    main()
