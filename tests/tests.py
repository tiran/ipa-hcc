#
# very basic tests to ensure code is at least importable.
#

import conftest
from ipahcc import hccplatform
from ipahcc.server import schema
from ipahcc.server.util import parse_rhsm_cert

# pylint: disable=import-outside-toplevel


class IPAClientTests(conftest.IPABaseTests):
    def test_auto_enrollment_help(self):
        import ipahcc_auto_enrollment

        self.assert_cli_run(ipahcc_auto_enrollment.main, "--help")


@conftest.requires_ipaserver
class IPAServerTests(conftest.IPABaseTests):
    def test_server_plugin_imports(self):
        # pylint: disable=unused-import,unused-variable,import-error
        from ipaserver.install.plugins import update_hcc  # noqa: F401
        from ipaserver.plugins import (
            hccconfig,  # noqa: F401
            hcchost,  # noqa: F401
            hccserverroles,  # noqa: F401
        )

    def test_registration_service_imports(self):
        # pylint: disable=unused-import,unused-variable,import-error
        from ipaserver.install.plugins import (  # noqa: F401
            update_hcc_enrollment_service,
        )


class IPAHCCServerTests(conftest.IPABaseTests):
    def test_ipa_hcc_dbus_help(self):
        from ipahcc.server import dbus_cli, dbus_service

        self.assert_cli_run(dbus_service.main, "--help")
        self.assert_cli_run(dbus_cli.main, "--help")


class TestJSONSchema(conftest.IPABaseTests):
    def test_valid_schema(self):
        cls = schema.VALIDATOR_CLS
        for name in schema.SCHEMATA:
            with self.subTest(name=name):
                validator = schema.get_validator(name)
                self.assertIsInstance(validator, cls)
                cls.check_schema(validator.schema)
        # validate defs' sub schemas
        filename = schema.SCHEMATA["defs"]
        _, defs = schema.RESOLVER.resolve(filename)
        for subname, subschema in defs["$defs"].items():
            with self.subTest(filename=filename, subname=subname):
                cls.check_schema(subschema)

    def test_invalid_instance(self):
        inst = {
            "domain_type": "invalid",
            "domain_name": "INVALID.DOMAIN",
            "domain_id": "not an uuid",
        }
        try:
            schema.validate_schema(inst, "HostRegisterRequest")
        except schema.ValidationError as e:
            self.assertIn("'invalid' is not one of ['rhel-idm']", str(e))

    def test_hcc_request(self):
        instance = {
            "domain_name": conftest.DOMAIN,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_id": conftest.DOMAIN_ID,
        }
        schema.validate_schema(instance, "HostRegisterRequest")

        instance["extra"] = True

        with self.assertRaises(schema.ValidationError):
            schema.validate_schema(instance, "HostRegisterRequest")

    def test_domain_request(self):
        instance = {
            "domain_name": conftest.DOMAIN,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": conftest.REALM,
                "servers": [
                    {
                        "fqdn": conftest.SERVER_FQDN,
                        "subscription_manager_id": conftest.SERVER_RHSM_ID,
                        "location": "sigma",
                        "ca_server": True,
                        "hcc_enrollment_server": True,
                        "hcc_update_server": True,
                        "pkinit_server": True,
                    },
                    {
                        "fqdn": "ipareplica1.ipahcc.test",
                        "subscription_manager_id": (
                            "fdebb5ad-f8d7-4234-a1ff-2b9ef074089b"
                        ),
                        "location": "tau",
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
                "ca_certs": [conftest.IPA_CA_CERTINFO],
                "realm_domains": [conftest.DOMAIN],
                "locations": [
                    {"name": "kappa"},
                    {"name": "sigma"},
                    {"name": "tau", "description": "location tau"},
                ],
            },
        }
        schema.validate_schema(instance, "IPADomainRequest")


class TestUtil(IPAClientTests):
    def test_parse_cert(self):
        with open(conftest.RHSM_CERT, "rb") as f:
            org_id, rhsm_id = parse_rhsm_cert(f.read())
        self.assertEqual(org_id, conftest.ORG_ID)
        self.assertEqual(rhsm_id, conftest.CLIENT_RHSM_ID)

        with self.assertRaises(ValueError):
            parse_rhsm_cert("data")
        with self.assertRaises(ValueError):
            parse_rhsm_cert(b"data")
