# pylint: disable=too-many-locals,ungrouped-imports

import contextlib
import importlib
import logging
import io
import json
import os
import sys
import unittest

from ipalib import api
from ipaplatform.paths import paths
from requests import Response

from ipahcc import hccplatform
from ipahcc.server import schema

# pylint: disable=import-error
if hccplatform.PY2:
    from httplib import responses as http_responses
else:
    from http.client import responses as http_responses

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

RHSM_CERT = os.path.join(TESTDATA, "autoenrollment", "cert.pem")
RHSM_KEY = os.path.join(TESTDATA, "autoenrollment", "key.pem")
IPA_CA_CRT = os.path.join(TESTDATA, "autoenrollment", "ipa_ca.crt")
KDC_CA_CRT = os.path.join(
    BASEDIR, "install", "server", "redhat-candlepin-bundle.pem"
)
HOST_DETAILS = os.path.join(TESTDATA, "autoenrollment", "host-details.json")

# patch
paths.IPA_CA_CRT = IPA_CA_CRT
hccplatform.HMSIDM_CA_BUNDLE_PEM = KDC_CA_CRT

with io.open(RHSM_CERT, encoding="utf-8") as f:
    RHSM_CERT_DATA = f.read()
with io.open(IPA_CA_CRT, encoding="utf-8") as f:
    IPA_CA_DATA = f.read()
with io.open(KDC_CA_CRT, encoding="utf-8") as f:
    KDC_CA_DATA = f.read()

# initialize first step of IPA API so server imports work
if not api.isdone("bootstrap"):
    api.bootstrap(
        host=CLIENT_FQDN,
        server=SERVER_FQDN,
        domain=DOMAIN,
        realm=REALM,
    )
else:  # pragma: no cover
    pass


try:
    # pylint: disable=unused-import,ungrouped-imports
    import ipaclient.install  # noqa: F401
    import ipalib.install  # noqa: F401
except ImportError:
    HAS_IPA_INSTALL = False
else:
    HAS_IPA_INSTALL = True

try:
    # pylint: disable=unused-import
    import ipaserver.masters  # noqa: F401
except ImportError:
    HAS_IPASERVER = False
else:
    HAS_IPASERVER = True

try:
    # pylint: disable=unused-import
    import dbus.mainloop.glib  # noqa: F401
    import gi.repository  # noqa: F401
except ImportError:  # pragma: no cover
    HAS_DBUS = False
else:
    HAS_DBUS = True

try:
    # pylint: disable=unused-import
    from unittest import mock
except ImportError:
    try:
        import mock
    except ImportError:  # pragma: no cover
        mock = None

requires_ipa_install = unittest.skipUnless(
    HAS_IPA_INSTALL, "requires 'ipaclient.install' or 'ipalib.install'"
)
requires_ipaserver = unittest.skipUnless(
    HAS_IPASERVER, "requires 'ipaserver'"
)
requires_jsonschema = unittest.skipUnless(
    schema.jsonschema, "requires 'jsonschema'"
)
requires_dbus = unittest.skipUnless(
    HAS_DBUS, "requires 'dbus' and 'gi.repository'"
)
requires_mock = unittest.skipUnless(
    mock is not None, "requires 'unittest.mock' or 'mock'"
)


class CaptureHandler(logging.Handler):
    def __init__(self):
        super(CaptureHandler, self).__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


class IPABaseTests(unittest.TestCase):
    maxDiff = None

    def log_capture_start(self):
        self.log_capture = CaptureHandler()
        self.log_capture.setFormatter(
            logging.Formatter("%(levelname)s:%(name)s:%(message)s")
        )

        root_logger = logging.getLogger(None)
        self._old_handlers = root_logger.handlers[:]
        self._old_level = root_logger.level
        root_logger.handlers = [self.log_capture]
        root_logger.setLevel(logging.DEBUG)
        self.addCleanup(self.log_capture_stop)

    def log_capture_stop(self):
        root_logger = logging.getLogger(None)
        root_logger.handlers = self._old_handlers
        root_logger.setLevel(self._old_level)

    def setUp(self):
        super(IPABaseTests, self).setUp()
        self.log_capture_start()

    def get_mock_env(self):
        return mock.Mock(
            in_server=True,
            domain=DOMAIN,
            realm=REALM,
            host=SERVER_FQDN,
            basedn="dc=ipa-hcc,dc=test",
        )

    def mkresponse(self, status_code, body):
        j = json.dumps(body).encode("utf-8")
        resp = Response()
        resp.url = None
        resp.status_code = status_code
        resp.reason = http_responses[status_code]
        resp.encoding = "utf-8"
        resp.headers["content-type"] = "application/json"
        resp.headers["content-length"] = len(j)
        resp.raw = io.BytesIO(j)
        resp.raw.seek(0)
        return resp

    def call_wsgi(
        self,
        path,
        body,
        content_type="application/json",
        method="POST",
        extra_headers=None,
    ):
        dump = json.dumps(body).encode("utf-8")
        wsgi_input = io.BytesIO()
        wsgi_input.write(dump)
        wsgi_input.seek(0)
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": len(dump),
            "SSL_CLIENT_CERT": RHSM_CERT_DATA,
            "wsgi.input": wsgi_input,
        }
        if extra_headers:
            for key, value in extra_headers.items():
                key = "HTTP_" + key.upper().replace("-", "_")
                env[key] = value
        start_response = mock.Mock()
        response = self.app(env, start_response)
        status = start_response.call_args[0][0]
        status_code, status_msg = status.split(" ", 1)
        status_code = int(status_code)
        headers = dict(start_response.call_args[0][1])
        if headers["Content-Type"] == "application/json":
            response = json.loads(b"".join(response).decode("utf-8"))
        return status_code, status_msg, headers, response

    def assert_cli_run(self, mainfunc, *args):
        try:
            with capture_output():
                mainfunc(list(args))
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:  # pragma: no cover
            self.fail("SystemExit expected")


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
