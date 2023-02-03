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

from ipaclient.install.client import configure_krb5_conf

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
    if arg.startswith(("http://", "https://")):
        return arg
    if not os.path.isfile(arg):
        raise ValueError("CA file {arg} does not exist".format(arg=arg))
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
    help="load the CA certificate from this file or URL",
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
    dest="servers",
    action="append",  # support multiple
    help="FQDN of IPA server(s)",
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
    help="PKINIT identity information (default: RHSM cert/key)",
    default="FILE:{cert},{key}".format(
        cert=hccplatform.RHSM_CERT, key=hccplatform.RHSM_KEY
    ),
)
parser.add_argument(
    "--pkinit-anchor",
    metavar="FILEDIR",
    help=(
        "PKINIT trust anchors, prefixed with FILE: for CA PEM bundle file or "
        "DIR: for an OpenSSL hash dir (default: Red Hat Candlepin bundle)."
    ),
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


def download_cert(args, url, local_cacert):
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
    res = ds.search(
        domain=args.domain if args.domain else "",
        servers=args.servers if args.servers else "",
        realm=args.realm,
        hostname=args.hostname,
        ca_cert_path=local_cacert,
    )
    if res != SUCCESS:
        err = discovery.error_names[res]
        parser.error("IPA discovery failed: {}.\n".format(err))

    dnsok = False
    if not args.servers:
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
    logger.info("Preferred IPA Server: %s", ds.server)
    logger.info("IPA Servers: %s", ", ".join(ds.servers))
    logger.debug("IPA Server source: %s", ds.server_source)
    logger.info("BaseDN: %s", ds.basedn)
    logger.debug("BaseDN source: %s", ds.basedn_source)

    return ds, dnsok


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
            logger.exception("Host inventory lookup failed, sleeping...")
        else:
            logger.info(
                "Host '%s' not found in Insights Inventory, sleeping...",
                args.hostname,
            )
        time.sleep(5)
    else:
        logger.warning(
            "Host '%s' not found in Insights Inventory inventory",
            args.hostname,
        )


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


def pkinit(args, host_principal, local_cacert, env):
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


def getkeytab(args, keytab, host_principal, ds, local_cacert, env):
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
    extra_args = ["--keytab", keytab]
    return _run_ipa_client(args, local_cacert, extra_args)


def ipa_client_pkinit(args, local_cacert):
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
    if args.realm and not args.domain:
        args.domain = args.realm.lower()
    if args.domain and not args.realm:
        args.realm = args.domain.upper()
    if args.pkinit_anchors is None:
        args.pkinit_anchors = [DEFAULT_PKINIT_ANCHOR]

    return args


def main(*args):
    args = parse_args(*args)

    if os.path.isfile(paths.IPA_DEFAULT_CONF):
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
        ds, dnsok = discover_ipa(args, local_cacert)

        # if CA cert is not available yet, download it from IPA server
        if local_cacert is None:
            # download cert from IPA server
            url = "https://{server}/ipa/config/ca.crt".format(
                server=ds.server
            )
            local_cacert = os.path.join(tmpdir, "ca.crt")
            download_cert(args, url=url, local_cacert=local_cacert)

        # wait until this host appears in ConsoleDont host inventory
        wait_for_inventory_host(args)

        # self-register host with IPA
        # TODO: check other servers if server returns 400
        hcc_register(args, server=ds.server, local_cacert=local_cacert)

        if HAS_KINIT_PKINIT:
            ipa_client_pkinit(args, local_cacert)
        else:
            krb_name = os.path.join(tmpdir, "krb5.conf")
            keytab = os.path.join(tmpdir, "host.keytab")
            env = {
                "LC_ALL": "C",
                "KRB5_CONFIG": krb_name,
                "KRB5CCNAME": os.path.join(tmpdir, "ccache"),
            }
            if args.debug >= 2:
                env["KRB5_TRACE"] = "/dev/stderr"

            host_principal = "host/{}@{}".format(args.hostname, ds.realm)
            create_krb5_conf(args, ds, dnsok, krb_name)
            pkinit(args, host_principal, local_cacert=local_cacert, env=env)
            getkeytab(
                args,
                keytab,
                host_principal,
                ds=ds,
                local_cacert=local_cacert,
                env=env,
            )
            ipa_client_keytab(args, keytab, local_cacert)
    finally:
        if args.debug >= 2:
            logger.info("Keeping temporary directory %s", tmpdir)
        else:
            shutil.rmtree(tmpdir)

    logger.info("Done")


if __name__ == "__main__":
    main()
