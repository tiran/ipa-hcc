"""IPA client auto-enrollment for Hybrid Cloud Console

Installation with older clients that lack PKINIT:

- get configuration from remote api /host-conf
- write a temporary krb5.conf for kinit and ipa-getkeytab commands
- with kinit using PKINIT identity and host principal 'host/$FQDN'
- ipa-getkeytab for host principal 'host/$FQDN' using the first
  IPA server from remote configuration
"""

import argparse
import collections
import io
import json
import logging
import os
import random
import shutil
import ssl
import socket
import sys
import tempfile
import time
import uuid

from dns.exception import DNSException
from ipalib import util
from ipaplatform.paths import paths
from ipapython.dnsutil import query_srv
from ipapython.ipautil import run
from ipapython.version import VENDOR_VERSION as IPA_VERSION

try:
    # pylint: disable=unused-import,ungrouped-imports
    from ipalib.install.kinit import kinit_pkinit  # noqa: F401
except ImportError:
    HAS_KINIT_PKINIT = False
else:
    # IPA >= 4.9.10 / 4.10.1
    HAS_KINIT_PKINIT = True

from ipahcc import hccplatform

PY2 = sys.version_info.major == 2
FQDN = socket.gethostname()

# version is updated by Makefile
VERSION = "0.7"

RHSM_CERT = hccplatform.RHSM_CERT
RHSM_KEY = hccplatform.RHSM_KEY
HCC_DOMAIN_TYPE = hccplatform.HCC_DOMAIN_TYPE
INSIGHTS_HOST_DETAILS = hccplatform.INSIGHTS_HOST_DETAILS
HTTP_HEADERS = hccplatform.HTTP_HEADERS
del hccplatform

logger = logging.getLogger(__name__)

# pylint: disable=import-error
if PY2:
    from urllib2 import HTTPError, Request, urlopen
else:
    from urllib.request import HTTPError, Request, urlopen
# pylint: enable=import-error


def check_arg_hostname(arg):
    try:
        util.validate_hostname(arg)
    except ValueError as e:
        raise argparse.ArgumentError(None, str(e))
    return arg.lower()


def check_arg_domain_name(arg):
    try:
        util.validate_domain_name(arg)
    except ValueError as e:
        raise argparse.ArgumentError(None, str(e))
    return arg.lower()


def check_arg_location(arg):
    try:
        util.validate_dns_label(arg)
    except ValueError as e:
        raise argparse.ArgumentError(None, str(e))
    return arg.lower()


def check_arg_uuid(arg):
    try:
        uuid.UUID(arg)
    except ValueError as e:
        raise argparse.ArgumentError(None, str(e))
    return arg.lower()


parser = argparse.ArgumentParser()

parser.add_argument(
    "--verbose",
    "-v",
    help="Enable verbose logging",
    dest="verbose",
    default=0,
    action="count",
)
parser.add_argument(
    "--version",
    "-V",
    help="Show version number and exit",
    action="version",
    version="ipa-hcc {} (IPA {})".format(VERSION, IPA_VERSION),
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
DEFAULT_HCC_API_HOST = "cert.console.redhat.com"
parser.add_argument(
    "--hcc-api-host",
    help=(
        "URL of Hybrid Cloud Console API with cert auth "
        "(default: {})".format(DEFAULT_HCC_API_HOST)
    ),
    default=DEFAULT_HCC_API_HOST,
    type=str,
)

group = parser.add_argument_group("domain filter")
# location, domain_name, domain_id
group.add_argument(
    "--domain-name",
    metavar="NAME",
    help="Request enrollment into domain",
    type=check_arg_domain_name,
)
group.add_argument(
    "--domain-id",
    metavar="UUID",
    help="Request enrollment into domain by HCC domain id",
    type=check_arg_uuid,
)
group.add_argument(
    "--location",
    help="Prefer servers from location",
    type=check_arg_location,
    default=None,
)
# hidden arguments for internal testing
parser.add_argument(
    "--upto",
    metavar="PHASE",
    help=argparse.SUPPRESS,
    choices=("host-conf", "register", "pkinit", "keytab"),
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


class AutoEnrollment(object):
    def __init__(self, args):
        self.args = args
        # initialized later
        self.servers = None
        self.server = None
        self.domain = None
        self.realm = None
        self.domain_id = None
        self.inventory_id = None
        # internals
        self.tmpdir = None

    def __enter__(self):
        self.tmpdir = tempfile.mkdtemp()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.args.verbose >= 2:
            logger.info("Keeping temporary directory %s", self.tmpdir)
        else:
            shutil.rmtree(self.tmpdir)
            self.tmpdir = None

    def _do_post(self, url, body, verify, cafile=None):
        headers = {
            "Content-Type": "application/json",
        }
        headers.update(HTTP_HEADERS)
        logger.debug("POST request %s: %s", url, body)
        data = json.dumps(body)
        if not PY2:
            data = data.encode("utf-8")
        # Requests with data are always POST requests.
        req = Request(url, data=data, headers=headers)
        context = ssl.create_default_context(cafile=cafile)
        context.load_cert_chain(RHSM_CERT, RHSM_KEY)
        if getattr(context, "post_handshake_auth", None) is not None:
            context.post_handshake_auth = True
        if verify:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        resp = urlopen(
            req, timeout=self.args.timeout, context=context
        )  # nosec
        j = json.load(resp)
        logger.debug("Server response: %s", j)
        return j

    def _run(self, cmd, stdin=None, setenv=False):
        if setenv:
            # pass KRB5 and OpenSSL env vars
            env = {
                k: v
                for k, v in os.environ.items()
                if k.startswith(("KRB5", "GSS", "OPENSSL"))
            }
            env["LC_ALL"] = "C.UTF-8"
            env["KRB5_CONFIG"] = self.krb_name
            env["KRB5CCNAME"] = os.path.join(self.tmpdir, "ccache")
            if self.args.verbose >= 2:
                env["KRB5_TRACE"] = "/dev/stderr"
        else:
            env = None
        return run(cmd, stdin=stdin, env=env, raiseonerr=True)

    @property
    def ipa_cacert(self):
        return os.path.join(self.tmpdir, "ipa_ca.crt")

    @property
    def kdc_cacert(self):
        return os.path.join(self.tmpdir, "kdc_ca.crt")

    @property
    def pkinit_anchors(self):
        return [
            # Candlepin CA chain signs RHSM client cert
            "FILE:{}".format(self.kdc_cacert),
            # IPA CA signs KDC cert
            "FILE:{}".format(self.ipa_cacert),
        ]

    @property
    def pkinit_identity(self):
        return "FILE:{cert},{key}".format(cert=RHSM_CERT, key=RHSM_KEY)

    @property
    def krb_name(self):
        return os.path.join(self.tmpdir, "krb5.conf")

    def enroll_host(self):
        # wait until this host appears in ConsoleDot host inventory and
        # insights-client has stored a local copy of the inventory data.
        self.wait_for_inventory_host()

        # set local_cacert, servers, domain name, domain_id, realm
        self.hcc_host_conf()
        self.check_upto("host-conf")

        # self-register host with IPA
        # TODO: check other servers if server returns 400
        self.hcc_register()
        self.check_upto("register")

        if HAS_KINIT_PKINIT and self.args.upto is None:
            self.ipa_client_pkinit()
        else:
            host_principal = "host/{}@{}".format(
                self.args.hostname, self.realm
            )
            self.create_krb5_conf()
            self.pkinit(host_principal)
            self.check_upto("pkinit")

            keytab = self.getkeytab(host_principal)
            self.check_upto("keytab")

            self.ipa_client_keytab(keytab)

    def check_upto(self, phase):
        if self.args.upto is not None and self.args.upto == phase:
            logger.info("Stopping at phase %s", phase)
            parser.exit(0)

    def wait_for_inventory_host(self):
        """Wait until this host is available in Insights inventory

        insights-client stores the result of Insights API query in a local file
        once the host is registered.
        """
        sleep_dur = 10
        for _ in range(5):
            try:
                with io.open(INSIGHTS_HOST_DETAILS, encoding="utf-8") as f:
                    j = json.load(f)
            except (OSError, IOError, ValueError):
                logger.exception(
                    "Cannot read JSON file %s, try again in %i",
                    INSIGHTS_HOST_DETAILS,
                    sleep_dur,
                )
                time.sleep(sleep_dur)
            else:
                assert len(j["results"]) == 1
                result = j["results"][0]
                self.inventory_id = result["id"]
                logger.info(
                    "Host '%s' has inventory id '%s'.",
                    self.args.hostname,
                    self.inventory_id,
                )
                return result
        raise ValueError("Failed to read {}".format(INSIGHTS_HOST_DETAILS))

    def _lookup_dns_srv(self):
        """Lookup IPA servers via LDAP SRV records

        Returns a list of hostnames sorted by priority (takes locations
        into account).
        """
        ldap_srv = "_ldap._tcp.{domain}.".format(domain=self.domain)
        try:
            anser = query_srv(ldap_srv)
        except DNSException as e:
            logger.error("DNS SRV lookup error: %s", e)
            return []
        result = []
        for rec in anser:
            result.append(str(rec.target).rstrip(".").lower())
        logger.debug("%s servers: %r", ldap_srv, result)
        return result

    @classmethod
    def _sort_servers(cls, server_list, dns_srvs, location=None):
        """Sort servers by location and DNS SRV records

        1) If `location` is set, prefer servers from that location.
        2) Keep ordering of DNS SRV records. SRV lookup already sorts by priority and
           uses weighted randomization.
        3) Ignore any server in DNS SRV records that is not in `server_list`.
        4) Append additional servers (with randomization).
        """
        # ordered dict is required to keep stable sorting under Python 2.7
        # fqdn -> location
        enrollment_servers = collections.OrderedDict(
            (s["fqdn"].rstrip(".").lower(), s.get("location"))
            for s in server_list
        )
        # decorate-sort-undecorate, larger value means higher priority
        # [0.0, 1.0) is used for additional servers
        dsu = collections.OrderedDict(
            (name, i)
            for i, name in enumerate(reversed(dns_srvs), start=1)
            if name in enrollment_servers  # only enrollment-servers
        )
        for fqdn, server_location in enrollment_servers.items():
            idx = dsu.get(fqdn)
            # sort additional servers after DNS SRV entries, randomize order
            if idx is None:
                idx = random.random()  # [0.0, 1.0)
            # bump servers with current location
            if location is not None and server_location == location:
                idx += 1000
            dsu[fqdn] = idx

        return sorted(dsu, key=dsu.get, reverse=True)

    def hcc_host_conf(self):
        body = {
            "domain_type": HCC_DOMAIN_TYPE,
            "inventory_id": self.inventory_id,
        }
        for key in ["domain_name", "domain_id", "location"]:
            value = getattr(self.args, key)
            if value is not None:
                body[key] = value

        url = "https://{api_host}/api/idm/v1/host-conf/{hostname}".format(
            api_host=self.args.hcc_api_host, hostname=self.args.hostname
        )
        verify = not self.args.insecure
        logger.info(
            "Getting host configuration from %s (secure: %s).", url, verify
        )
        try:
            j = self._do_post(url, body=body, verify=verify)
        except HTTPError as e:
            logger.error(
                "Request to %s failed: %s: %s", url, type(e).__name__, e
            )
            raise SystemExit(2)

        with io.open(self.ipa_cacert, "w", encoding="utf-8") as f:
            f.write(j[HCC_DOMAIN_TYPE]["cabundle"])

        if j["domain_type"] != HCC_DOMAIN_TYPE:
            raise ValueError(j["domain_type"])
        self.domain = j["domain_name"]
        self.domain_id = j["domain_id"]
        self.realm = j[HCC_DOMAIN_TYPE]["realm_name"]
        self.servers = self._sort_servers(
            j[HCC_DOMAIN_TYPE]["enrollment_servers"],
            self._lookup_dns_srv(),
            self.args.location,
        )
        # TODO: use all servers
        if self.args.override_server is None:
            self.server = self.servers[0]
        else:
            self.server = self.args.override_server
        logger.info("Domain: %s", self.domain)
        logger.info("Realm: %s", self.realm)
        logger.info("Servers: %s", ", ".join(self.servers))
        return j

    def hcc_register(self):
        """Register this host with /hcc API endpoint

        TODO: On 404 try next server
        """
        url = "https://{server}/hcc/{hostname}".format(
            server=self.server, hostname=self.args.hostname
        )
        body = {
            "domain_type": HCC_DOMAIN_TYPE,
            "domain_name": self.domain,
            "domain_id": self.domain_id,
            "inventory_id": self.inventory_id,
        }
        logger.info("Registering host at %s", url)
        j = self._do_post(url, body=body, verify=True, cafile=self.ipa_cacert)
        if j["status"] != "ok":
            raise SystemExit(3)
        with io.open(self.kdc_cacert, "w", encoding="utf-8") as f:
            f.write(j["kdc_cabundle"])
        return j

    def create_krb5_conf(self):
        """Create a temporary krb5.conf"""
        extra_kdcs = [
            "kdc = {server}:88".format(server=server)
            for server in self.servers
            if server != self.server
        ]
        conf = KRB5_CONF.format(
            realm=self.realm,
            domain=self.domain,
            server=self.server,
            extra_kdcs="\n    ".join(extra_kdcs).strip(),
            hostname=self.args.hostname,
        )
        if PY2:
            conf = conf.decode("utf-8")
        logger.debug("Creating %s with content:\n%s", self.krb_name, conf)
        with io.open(self.krb_name, "w", encoding="utf-8") as f:
            f.write(conf)

    def pkinit(self, host_principal):
        """Perform kinit with X509_user_identity (PKINIT)"""
        cmd = [paths.KINIT]
        for anchor in self.pkinit_anchors:
            cmd.extend(["-X", "X509_anchors={anchor}".format(anchor=anchor)])
        cmd.extend(
            ["-X", "X509_user_identity={}".format(self.pkinit_identity)]
        )
        cmd.append(host_principal)
        # send \n on stdin in case we get a password prompt
        self._run(cmd, stdin="\n", setenv=True)

    def getkeytab(self, host_principal):
        """Retrieve keytab with ipa-getkeytab"""
        keytab = os.path.join(self.tmpdir, "host.keytab")
        # fmt: off
        cmd = [
            paths.IPA_GETKEYTAB,
            "-s", self.server,
            "-p", host_principal,
            "-k", keytab,
            "--cacert", self.ipa_cacert,
        ]
        # fmt: on
        self._run(cmd, setenv=True)
        return keytab

    def _run_ipa_client(self, extra_args=()):
        # fmt: off
        cmd = [
            paths.IPA_CLIENT_INSTALL,
            "--ca-cert-file", self.ipa_cacert,
            "--hostname", self.args.hostname,
            "--domain", self.domain,
            "--realm", self.realm,
        ]
        # fmt: on
        # TODO: Make ipa-client-install prefer servers from current location.
        if self.args.override_server:
            cmd.extend(["--server", self.args.override_server])
        if self.args.force:
            cmd.append("--force")
        cmd.append("--unattended")
        cmd.extend(extra_args)

        return self._run(cmd)

    def ipa_client_keytab(self, keytab):
        """Install IPA client with existing keytab"""
        extra_args = ["--keytab", keytab]
        return self._run_ipa_client(extra_args)

    def ipa_client_pkinit(self):
        """Install IPA client with PKINIT"""
        extra_args = [
            "--pkinit-identity",
            self.pkinit_identity,
        ]
        for anchor in self.pkinit_anchors:
            extra_args.extend(["--pkinit-anchor", anchor])
        return self._run_ipa_client(extra_args)


def main(args=None):
    args = parser.parse_args(args)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if os.path.isfile(paths.IPA_DEFAULT_CONF) and not args.upto:
        parser.error(
            "IPA is already installed, '{conf}' exists.\n".format(
                conf=paths.IPA_DEFAULT_CONF
            )
        )

    with AutoEnrollment(args) as autoenrollment:
        autoenrollment.enroll_host()

    logger.info("Done")


if __name__ == "__main__":
    main()
