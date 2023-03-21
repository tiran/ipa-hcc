import contextlib
import importlib
import io
import os
import sys
import unittest

from ipalib import api

from ipahcc import hccplatform
from ipahcc.server import schema

BASEDIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
TESTDATA = os.path.join(BASEDIR, "tests", "data")

DOMAIN = "ipa-hcc.test"
REALM = DOMAIN.upper()
CLIENT_FQDN = "client.ipa-hcc.test"
SERVER_FQDN = "server.ipa-hcc.test"

# initialize first step of IPA API so server imports work
if not api.isdone("bootstrap"):
    api.bootstrap(
        host=CLIENT_FQDN,
        server=SERVER_FQDN,
        domain=DOMAIN,
        realm=REALM,
    )


try:
    import ipaclient.install  # noqa: F401
except ImportError:
    HAS_IPACLIENT_INSTALL = False
else:
    HAS_IPACLIENT_INSTALL = True

try:
    import ipaserver.masters  # noqa: F401
except ImportError:
    HAS_IPASERVER = False
else:
    HAS_IPASERVER = True

try:
    from unittest import mock
except ImportError:
    try:
        import mock
    except ImportError:
        mock = None

requires_ipaclient_install = unittest.skipUnless(
    HAS_IPACLIENT_INSTALL, "ipaclient.install"
)
requires_ipaserver = unittest.skipUnless(HAS_IPASERVER, "requires ipaserver")
requires_jsonschema = unittest.skipUnless(
    schema.jsonschema, "requires jsonschema"
)
requires_mock = unittest.skipUnless(mock is not None, "requires mock")


@contextlib.contextmanager
def capture_output():
    if hccplatform.PY2:
        out = io.BytesIO()
    else:
        out = io.StringIO()
    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    sys.stdout = out
    sys.stderr = out
    try:
        yield out
    finally:
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr


def _fixup_ipaserver_import(name):
    path = os.path.join(BASEDIR, name.replace(".", os.sep))
    mod = importlib.import_module(name)
    mod.__path__.append(path)


if HAS_IPASERVER:
    _fixup_ipaserver_import("ipaserver.install.plugins")
    _fixup_ipaserver_import("ipaserver.plugins")
