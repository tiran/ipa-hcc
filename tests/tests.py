#
# very basic tests to ensure code is at least importable.
#

import contextlib
import importlib
import io
import os
import sys
import unittest

from ipalib import api

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


PY2 = sys.version_info.major == 2


@contextlib.contextmanager
def capture_output():
    if PY2:
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


class IPABaseTests(unittest.TestCase):
    register_paths = []

    @classmethod
    def setUpClass(cls):
        # initialize first step of IPA API so server imports work
        if not api.isdone("bootstrap"):
            api.bootstrap(
                domain="ipahcc.test",
            )

        # register additional paths for package imports
        for name in cls.register_paths:
            path = os.path.abspath(name.replace(".", os.sep))
            mod = importlib.import_module(name)
            mod.__path__.append(path)


class IPAClientTests(IPABaseTests):
    def test_platform_imports(self):
        # noqa: F401
        from ipahcc import hccplatform  # noqa: F401

    @unittest.skipUnless(HAS_IPACLIENT_INSTALL, "ipaclient.install")
    def test_auto_enrollment_help(self):
        from ipahcc.client import auto_enrollment

        try:
            with capture_output():
                auto_enrollment.main(["--help"])
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:
            self.fail("SystemExit expected")


class WSGITests(IPABaseTests):
    def test_wsgi_imports(self):
        from ipahcc.registration import wsgi as hcc_registration_service
        from ipahcc.mockapi import wsgi as hcc_mockapi

        assert callable(hcc_registration_service.application)
        assert callable(hcc_mockapi.application)


@unittest.skipUnless(HAS_IPASERVER, "requires ipaserver")
class IPAServerTests(IPABaseTests):
    register_paths = [
        "ipaserver.install.plugins",
        "ipaserver.plugins",
    ]

    def test_server_plugin_imports(self):
        from ipaserver.plugins import hccconfig  # noqa: F401
        from ipaserver.plugins import hcchost  # noqa: F401
        from ipaserver.install.plugins import update_hcc  # noqa: F401

    def test_registration_service_imports(self):
        from ipaserver.install.plugins import (  # noqa: F401
            update_hcc_enrollment_service,
        )

    def test_ipa_hcc_cli_help(self):
        from ipahcc.server.ipa_hcc_cli import IPAHCCCli

        try:
            with capture_output():
                IPAHCCCli.main(["ipa-hc", "--help"])
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:
            self.fail("SystemExit expected")


if __name__ == "__main__":
    unittest.main()
