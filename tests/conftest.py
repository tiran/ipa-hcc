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
DOMAIN_ID = hccplatform.TEST_DOMAIN_ID
CLIENT_RHSM_ID = "1ee437bc-7b65-40cc-8a02-c24c8a7f9368"
CLIENT_INVENTORY_ID = "1efd5f0e-7589-44ac-a9af-85ba5569d5c3"
SERVER_RHSM_ID = "e658e3eb-148c-46a6-b48a-099f9593191a"
SERVER_INVENTORY_ID = "f0468001-7632-4d3f-afd2-770c93825adf"
ORG_ID = "16765486"

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
    import dbus.mainloop.glib  # noqa: F401
    import gi.repository  # noqa: F401
except ImportError:
    HAS_DBUS = False
else:
    HAS_DBUS = True

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
requires_dbus = unittest.skipUnless(
    HAS_DBUS, "requires dbus and gi.repository"
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
