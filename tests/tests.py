#
# very basic tests to ensure code is at least importable.
#

import unittest

import conftest
from ipahcc.server import schema


class IPABaseTests(unittest.TestCase):
    pass


class IPAClientTests(IPABaseTests):
    def test_platform_imports(self):
        # noqa: F401
        from ipahcc import hccplatform  # noqa: F401

    @conftest.requires_ipaclient_install
    def test_auto_enrollment_help(self):
        from ipahcc.client import auto_enrollment

        try:
            with conftest.capture_output():
                auto_enrollment.main(["--help"])
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:  # pragma: no cover
            self.fail("SystemExit expected")


class WSGITests(IPABaseTests):
    def test_wsgi_imports(self):
        from ipahcc.registration import wsgi as hcc_registration_service
        from ipahcc.mockapi import wsgi as hcc_mockapi

        assert callable(hcc_registration_service.application)
        assert callable(hcc_mockapi.application)


@conftest.requires_ipaserver
class IPAServerTests(IPABaseTests):
    def test_server_plugin_imports(self):
        from ipaserver.plugins import hccconfig  # noqa: F401
        from ipaserver.plugins import hcchost  # noqa: F401
        from ipaserver.install.plugins import update_hcc  # noqa: F401

    def test_registration_service_imports(self):
        from ipaserver.install.plugins import (  # noqa: F401
            update_hcc_enrollment_service,
        )

    def test_ipa_hcc_cli_help(self):
        from ipahcc.server.cli import IPAHCCCli

        try:
            with conftest.capture_output():
                IPAHCCCli.main(["ipa-hcc", "--help"])
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:  # pragma: no cover
            self.fail("SystemExit expected")

    @conftest.requires_dbus
    def test_ipa_hcc_dbus_help(self):
        from ipahcc.server import dbus_service
        from ipahcc.server import dbus_cli

        try:
            with conftest.capture_output():
                dbus_service.main(["--help"])
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:
            self.fail("SystemExit expected")

        try:
            with conftest.capture_output():
                dbus_cli.main(["--help"])
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:  # pragma: no cover
            self.fail("SystemExit expected")


@conftest.requires_jsonschema
class TestJSONSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # disable error logging
        schema.logger.setLevel(1000)

    def test_hcc_request(self):
        instance = {
            "domain_name": "domain.example",
            "domain_type": "rhel-idm",
            "domain_id": "71c0bf27-37e7-41ae-b51b-1a8599025e1a",
            "inventory_id": "91e3fa59-4de2-4a28-90b2-01965b201ade",
        }
        schema.validate_schema(instance, "/schemas/hcc/request")

        instance["extra"] = True

        with self.assertRaises(schema.ValidationError):
            schema.validate_schema(instance, "/schemas/hcc/request")

    def test_domain_request(self):
        instance = {
            "domain_name": "ipahcc.test",
            "domain_type": "rhel-idm",
            "rhel-idm": {
                "realm_name": "IPAHCC.TEST",
                "servers": [
                    {
                        "fqdn": "ipaserver.ipahcc.test",
                        "subscription_manager_id": "547ce70c-9eb5-4783-a619-086aa26f88e5",
                        "ca_server": True,
                        "hcc_enrollment_server": True,
                        "hcc_update_server": True,
                        "pkinit_server": True,
                    },
                    {
                        "fqdn": "ipareplica1.ipahcc.test",
                        "subscription_manager_id": "fdebb5ad-f8d7-4234-a1ff-2b9ef074089b",
                        "ca_server": True,
                        "hcc_enrollment_server": True,
                        "hcc_update_server": False,
                        "pkinit_server": True,
                    },
                    {
                        "fqdn": "ipareplica2.ipahcc.test",
                        "ca_server": False,
                        "hcc_enrollment_server": False,
                        "hcc_update_server": False,
                        "pkinit_server": True,
                    },
                ],
                "cacerts": [
                    {
                        "nickname": "IPAHCC.TEST IPA CA",
                        "pem": "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----\n",
                    }
                ],
                "realm_domains": ["ipahcc.test"],
            },
        }
        schema.validate_schema(instance, "/schemas/domain/request")


if __name__ == "__main__":
    unittest.main()
