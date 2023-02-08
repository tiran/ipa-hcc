"""IPA client auto-enrollment for Hybrid Cloud Console

Installation with older clients that lack PKINIT:

- discover IPA realm, domain, servers, KDCs, and base DN based
  on CLI arguments and DNS SRV records (pretty much like ipa-client).
- write a temporary krb5.conf for kinit and ipa-getkeytab commands
- with kinit using PKINIT identity and host principal 'host/$FQDN'
- ipa-getkeytab for host principal 'host/$FQDN' using the first
  IPA server from auto-discovery / CLI
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

try:
    from ipaclient import discovery
except ImportError:
    from ipaclient.install import ipadiscovery as discovery

# from ipalib.constants import FQDN
from ipalib.install import kinit
from ipalib.util import validate_domain_name, validate_hostname
from ipaplatform.paths import paths
from ipaplatform import hccplatform
from ipapython.ipautil import run

# IPA >= 4.9.10 / 4.10.1
HAS_KINIT_PKINIT = hasattr(kinit, "kinit_pkinit")
# IPA 4.6 has no SUCCESS
SUCCESS = getattr(discovery, "SUCCESS", 0)
DEFAULT_PKINIT_ANCHOR = "FILE:{}".format(hccplatform.HMSIDM_CA_BUNDLE_PEM)
FQDN = socket.gethostname()

logger = logging.getLogger(__name__)


def check_arg_hostname(arg):
    try:
        validate_hostname(arg)
    except ValueError as e:
        raise argparse.ArgumentError("--hostname", str(e))
    return arg.lower()


def check_arg_realm(arg):
    try:
        validate_domain_name(arg, entity="realm")
    except ValueError as e:
        raise argparse.ArgumentError("--realm", str(e))
    return arg.upper()


def check_arg_domain(arg):
    try:
        validate_domain_name(arg, entity="domain")
    except ValueError as e:
        raise argparse.ArgumentError("--domain", str(e))
    return arg.lower()


def check_arg_cafile(arg):
    if arg.startswith(("http://", "https://")):
        return arg
    if not os.path.isfile(arg):
        raise argparse.ArgumentError(
            "--ca-cert-file",
            "CA file {arg} does not exist".format(arg=arg),
        )
    return os.path.abspath(arg)


def check_arg_pkinit_identity(arg):
    argname = "--pkinit-identity"
    if not arg.startswith(("FILE:", "PKCS11:", "PKCS12:", "DIR:", "ENV:")):
        raise argparse.ArgumentError(
            argname,
            "Invalid value '{arg}', must start with FILE:, PKCS11:, PKCS12: DIR:, ENV:".format(
                arg=arg
            ),
        )
    if arg.startswith("FILE:"):
        cert = arg[5:]
        if "," in cert:
            cert, key = arg.split(",", 1)
        else:
            key = None
        if not os.path.isfile(cert):
            raise argparse.ArgumentError(
                argname,
                "Invalid value '{arg}', cert file {cert} does not exist.".format(
                    arg=arg, cert=cert
                ),
            )
        if not os.path.isfile(key):
            raise argparse.ArgumentError(
                argname,
                "Invalid value '{arg}', key file {key} does not exist.".format(
                    arg=arg, key=key
                ),
            )
    return arg


def check_arg_pkinit_anchor(arg):
    argname = "--pkinit-anchor"
    if not arg.startswith(("FILE:", "DIR:", "ENV:")):
        raise argparse.ArgumentError(
            argname,
            "Invalid value '{arg}', must start with FILE:, DIR:, ENV:".format(
                arg=arg
            ),
        )
    if arg.startswith("FILE:"):
        bundle = arg[5:]
        if not os.path.isfile(bundle):
            raise argparse.ArgumentError(
                argname,
                "Invalid value '{arg}', bundle file {bundle} does not exist.".format(
                    arg=arg, bundle=bundle
                ),
            )

    return arg


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
    help="load the CA certificate from this file or URL",
    dest="cacert",
    type=check_arg_cafile,
)
parser.add_argument(
    "--insecure",
    action="store_true",
    help="Use insecure download of CA cert chain",
)
parser.add_argument(
    "--server",
    metavar="SERVER",
    dest="servers",
    action="append",  # support multiple
    help="FQDN of IPA server(s)",
    type=check_arg_hostname,
)
parser.add_argument(
    "--domain",
    metavar="DOMAIN_NAME",
    help="primary DNS domain of the IPA deployment",
    type=check_arg_domain,
)
parser.add_argument(
    "--realm",
    metavar="REALM",
    help="Kerberos realm name of the IPA deployment",
    type=check_arg_realm,
)
parser.add_argument(
    "--hostname",
    metavar="HOST_NAME",
    help="The hostname of this machine (FQDN)",
    default=FQDN,
    type=check_arg_hostname,
)
parser.add_argument(
    "--pkinit-identity",
    metavar="IDENTITY",
    help="PKINIT identity information (default: RHSM cert/key)",
    default="FILE:{cert},{key}".format(
        cert=hccplatform.RHSM_CERT, key=hccplatform.RHSM_KEY
    ),
    type=check_arg_pkinit_identity,
)
parser.add_argument(
    "--pkinit-anchor",
    metavar="FILEDIR",
    help=(
        "PKINIT trust anchors, prefixed with FILE: for CA PEM bundle file or "
        "DIR: for an OpenSSL hash dir (default: Red Hat Candlepin bundle)."
    ),
    type=check_arg_pkinit_anchor,
    dest="pkinit_anchors",
    action="append",  # support multiple
)
# parser.add_argument(
#     "--keytab",
#     "-k",
#     metavar="FILE",
#     help="The keytab file to append the new key to (will be created if it does not exist)",
#     required=True,
#     dest="keytab",
# )
parser.add_argument(
    "--force",
    help="force setting of Kerberos conf",
    action="store_true",
)
# hidden argument for internal testing
parser.add_argument(
    "--upto",
    metavar="PHASE",
    help=argparse.SUPPRESS,
    choices=("discover", "register", "pkinit", "keytab"),
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


def download_cert(args, url, local_cacert):
    """Download CA cert and write it to 'local_cacert' file"""
    verify = not args.insecure
    logger.debug("Downloading CA certs from %s (secure: %s)", url, verify)
    try:
        r = requests.get(url, verify=verify)
        r.raise_for_status()
    except requests.exceptions.SSLError as e:
        logger.error("Secure connection to %s failed: %s", url, e)
        raise SystemExit(2)
    except requests.exceptions.RequestException as e:
        logger.error("Request to %s failed: %s: %s", url, type(e).__name__, e)
        raise SystemExit(2)
    with open(local_cacert, "wb") as f:
        f.write(r.content)
    logger.debug("Stored %i bytes in %s", len(r.content), local_cacert)


def discover_ipa(args, local_cacert):
    """Discover IPA servers

    Uses DNS SRV records and LDAP query to detect IPA domain, realm and
    servers.
    """
    ds = discovery.IPADiscovery()
    kwargs = dict(
        hostname=args.hostname,
        ca_cert_path=local_cacert,
    )
    if args.domain:
        kwargs["domain"] = args.domain
    if args.realm:
        kwargs["realm"] = args.realm
    if args.servers:
        assert args.domain
        kwargs["servers"] = args.servers

    res = ds.search(**kwargs)
    if res != SUCCESS:
        err = discovery.error_names[res]
        parser.error("IPA discovery failed: {}.\n".format(err))

    # servers, domain = ds.check_domain(
    #     ds.domain, set(), "Validating DNS Discovery"
    # )

    logger.info("Client hostname: %s", args.hostname)
    logger.info("Realm: %s", ds.realm)
    logger.debug("Realm source: %s", ds.realm_source)
    logger.info("DNS Domain: %s", ds.domain)
    logger.debug("DNS Domain source: %s", ds.domain_source)
    logger.info("Preferred IPA Server: %s", ds.server)
    logger.info("IPA Servers: %s", ", ".join(ds.servers))
    logger.debug("IPA Server source: %s", ds.server_source)
    logger.info("BaseDN: %s", ds.basedn)
    logger.debug("BaseDN source: %s", ds.basedn_source)

    return ds


def hcc_register(args, server, local_cacert):
    """Register this host with /hcc API endpoint

    TODO: On 404 try next server
    """
    url = "https://{server}/hcc".format(server=server)
    logger.info("Registering host at %s", url)
    r = requests.get(
        url,
        verify=local_cacert,
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
    sess.verify = True  # RH HCC uses public, trusted cert
    time.sleep(3)  # short initial sleep
    sleep_dur = 10  # sleep for 10, 20, 40, ...
    for i in range(5):
        try:
            resp = sess.get(hccplatform.INVENTORY_HOSTS_CERT_API)
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


def create_krb5_conf(args, ds, krb_name):
    """Create a temporary krb5.conf"""
    extra_kdcs = [
        "kdc = {server}:88".format(server=server)
        for server in ds.servers
        if server != ds.server
    ]
    conf = KRB5_CONF.format(
        realm=ds.realm,
        domain=ds.domain,
        server=ds.server,
        extra_kdcs="\n    ".join(extra_kdcs).strip(),
        hostname=args.hostname,
    )
    logger.debug("Creating %s with content:\n%s", krb_name, conf)
    with open(krb_name, "w") as f:
        f.write(conf)


def pkinit(args, host_principal, local_cacert, env):
    """Perform kinit with X509_user_identity (PKINIT)"""
    cmd = [paths.KINIT]
    # CA cert signs KDC cert
    anchors = ["FILE:{}".format(local_cacert)]
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


def getkeytab(args, tmpdir, host_principal, ds, local_cacert, env):
    """Retrieve keytab with ipa-getkeytab"""
    keytab = os.path.join(tmpdir, "host.keytab")
    # fmt: off
    cmd = [
        paths.IPA_GETKEYTAB,
        "-s", ds.server,
        "-p", host_principal,
        "-k", keytab,
        "--cacert", local_cacert,
    ]
    # fmt: on
    run(cmd, env=env, raiseonerr=True)
    return keytab


def _run_ipa_client(args, local_cacert, extra_args=()):
    # fmt: off
    cmd = [
        paths.IPA_CLIENT_INSTALL,
        "--ca-cert-file", local_cacert,
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


def ipa_client_keytab(args, keytab, local_cacert):
    """Install IPA client with existing keytab"""
    extra_args = ["--keytab", keytab]
    return _run_ipa_client(args, local_cacert, extra_args)


def ipa_client_pkinit(args, local_cacert):
    """Install IPA client with PKINIT"""
    extra_args = [
        "--pkinit-identity={}".format(args.pkinit_identity),
    ]
    for anchor in args.pkinit_anchors:
        extra_args.append(
            "--pkinit-anchor=FILE:{anchor}".format(anchor=anchor),
        )
    return _run_ipa_client(args, local_cacert, extra_args)


def parse_args(*args):
    args = parser.parse_args(*args)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    if args.servers and not (args.domain or args.realm):
        parser.error("--server requires --domain or --realm option\n")
    if args.realm and not args.domain:
        args.domain = args.realm.lower()
    if args.domain and not args.realm:
        args.realm = args.domain.upper()
    if args.pkinit_anchors is None:
        args.pkinit_anchors = [DEFAULT_PKINIT_ANCHOR]

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
        # get remote CA cert file first
        if args.cacert:
            if args.cacert.startswith(("http://", "https://")):
                local_cacert = os.path.join(tmpdir, "ca.crt")
                download_cert(
                    args, url=args.cacert, local_cacert=local_cacert
                )
            else:
                # it's a file
                local_cacert = args.cacert
        else:
            local_cacert = None
        logger.debug("Using local CA cert %s", local_cacert)

        # discover IPA realm, domain, and servers
        ds = discover_ipa(args, local_cacert)

        # if CA cert is not available yet, download it from IPA server
        if local_cacert is None:
            # download cert from IPA server
            url = "https://{server}/ipa/config/ca.crt".format(
                server=ds.server
            )
            local_cacert = os.path.join(tmpdir, "ca.crt")
            download_cert(args, url=url, local_cacert=local_cacert)

        check_upto(args, "discover")

        # wait until this host appears in ConsoleDont host inventory
        wait_for_inventory_host(args)

        # self-register host with IPA
        # TODO: check other servers if server returns 400
        hcc_register(args, server=ds.server, local_cacert=local_cacert)

        check_upto(args, "register")

        if HAS_KINIT_PKINIT and args.upto is None:
            ipa_client_pkinit(args, local_cacert)
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

            host_principal = "host/{}@{}".format(args.hostname, ds.realm)
            create_krb5_conf(args, ds, krb_name)
            pkinit(args, host_principal, local_cacert=local_cacert, env=env)
            check_upto(args, "pkinit")

            keytab = getkeytab(
                args,
                tmpdir,
                host_principal,
                ds=ds,
                local_cacert=local_cacert,
                env=env,
            )
            check_upto(args, "keytab")

            ipa_client_keytab(args, keytab, local_cacert)
    finally:
        if args.debug >= 2:
            logger.info("Keeping temporary directory %s", tmpdir)
        else:
            shutil.rmtree(tmpdir)

    logger.info("Done")


if __name__ == "__main__":
    main()
