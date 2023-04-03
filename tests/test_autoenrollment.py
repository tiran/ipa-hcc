import io
import json
import os
import ssl
import unittest

from dns.rdtypes.IN.SRV import SRV
from ipaplatform.paths import paths

import conftest
from conftest import mock

from ipahcc import hccplatform
from ipahcc.server import schema
import ipahcc_auto_enrollment as auto_enrollment


HOST_CONF_REQUEST = {
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "inventory_id": conftest.CLIENT_INVENTORY_ID,
}

HOST_CONF_RESPONSE = {
    "domain_name": conftest.DOMAIN,
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "domain_id": conftest.DOMAIN_ID,
    "auto_enrollment_enabled": True,
    hccplatform.HCC_DOMAIN_TYPE: {
        "realm_name": conftest.REALM,
        "cabundle": conftest.IPA_CA_DATA,
        "enrollment_servers": [
            {"fqdn": conftest.SERVER_FQDN, "location": None},
        ],
    },
    "inventory_id": conftest.CLIENT_INVENTORY_ID,
}

REGISTER_REQUEST = {
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "domain_name": conftest.DOMAIN,
    "domain_id": conftest.DOMAIN_ID,
    "inventory_id": conftest.CLIENT_INVENTORY_ID,
}

REGISTER_RESPONSE = {"status": "ok", "kdc_cabundle": conftest.KDC_CA_DATA}


def jsonio(body):
    j = json.dumps(body).encode("utf-8")
    out = io.BytesIO(j)
    out.seek(0)
    return out


class TestAutoEnrollmentNoMock(unittest.TestCase):
    def test_module_attributes(self):
        self.assertEqual(hccplatform.RHSM_CERT, auto_enrollment.RHSM_CERT)
        self.assertEqual(hccplatform.RHSM_KEY, auto_enrollment.RHSM_KEY)
        self.assertEqual(
            hccplatform.HCC_DOMAIN_TYPE, auto_enrollment.HCC_DOMAIN_TYPE
        )
        self.assertEqual(
            hccplatform.INSIGHTS_HOST_DETAILS,
            auto_enrollment.INSIGHTS_HOST_DETAILS,
        )
        self.assertEqual(
            hccplatform.HTTP_HEADERS, auto_enrollment.HTTP_HEADERS
        )


@conftest.requires_mock
class TestAutoEnrollment(conftest.IPABaseTests):
    def setUp(self):
        super(TestAutoEnrollment, self).setUp()
        modname = "ipahcc_auto_enrollment"
        p = mock.patch.multiple(
            modname,
            HAS_KINIT_PKINIT=False,
            RHSM_CERT=conftest.RHSM_CERT,
            RHSM_KEY=conftest.RHSM_KEY,
            RHSM_CONF=conftest.NO_FILE,
            INSIGHTS_HOST_DETAILS=conftest.HOST_DETAILS,
            INSIGHTS_MACHINE_ID=conftest.MACHINE_ID,
            IPA_DEFAULT_CONF=conftest.NO_FILE,
        )
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(auto_enrollment, "run")
        self.m_run = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(auto_enrollment, "urlopen")
        self.m_urlopen = p.start()
        # hcc_host_conf, hcc_register
        self.m_urlopen.side_effect = [
            jsonio(HOST_CONF_RESPONSE),
            jsonio(REGISTER_RESPONSE),
        ]
        self.addCleanup(p.stop)

        p = mock.patch.object(auto_enrollment, "query_srv")
        self.m_query_srv = p.start()
        self.m_query_srv.return_value = [
            SRV(1, 33, 0, 100, 389, conftest.SERVER_FQDN)
        ]
        self.addCleanup(p.stop)

        p = mock.patch("time.sleep")
        p.start()
        self.addCleanup(p.stop)

    @conftest.requires_jsonschema
    def test_schema(self):
        schema.validate_schema(
            HOST_CONF_REQUEST, "/schemas/host-conf/request"
        )
        schema.validate_schema(
            HOST_CONF_RESPONSE, "/schemas/host-conf/response"
        )
        schema.validate_schema(
            REGISTER_REQUEST, "/schemas/hcc-host-register/request"
        )
        schema.validate_schema(
            REGISTER_RESPONSE, "/schemas/hcc-host-register/response"
        )

    def parse_args(self, *args):
        return auto_enrollment.parser.parse_args(args=args)

    def assert_args_error(self, args, expected=None):
        with self.assertRaises(SystemExit):
            with conftest.capture_output() as out:
                auto_enrollment.main(args)
        if expected is not None:
            self.assertIn(expected, out.read())
        return out

    def test_args(self):
        args = self.parse_args(
            # fmt: off
            "--hostname", conftest.CLIENT_FQDN,
            "--timeout", "20",
            "--domain-name", conftest.DOMAIN,
            "--domain-id", conftest.DOMAIN_ID,
            "--location", "sigma",
            "--upto", "host-conf",
            "--override-server", conftest.SERVER_FQDN,
            "--hcc-api-host", conftest.SERVER_FQDN,
            # fmt: on
        )
        self.assertEqual(args.timeout, 20)
        self.assertEqual(args.hcc_api_host, conftest.SERVER_FQDN)
        self.assert_args_error(("--hostname", "invalid_hostname"))
        self.assert_args_error(("--domain-name", "invalid_domain"))
        self.assert_args_error(("--domain-id", "invalid_domain"))
        self.assert_args_error(("--location", "invalid.location"))

    def test_system_state_error(self):
        args = (
            "--hcc-api-host",
            conftest.SERVER_FQDN,
            "--hostname",
            conftest.CLIENT_FQDN,
        )

        # module vars are already mocked
        auto_enrollment.IPA_DEFAULT_CONF = conftest.RHSM_CERT  # any file
        self.assert_args_error(
            args, expected="Host is already an IPA client."
        )
        auto_enrollment.IPA_DEFAULT_CONF = conftest.NO_FILE
        auto_enrollment.INSIGHTS_MACHINE_ID = conftest.NO_FILE
        self.assert_args_error(
            args, expected="Host is not registered with Insights."
        )
        auto_enrollment.RHSM_CERT = conftest.NO_FILE
        self.assert_args_error(
            args,
            expected="Host is not registered with subscription-manager.",
        )

    def test_sort_servers(self):
        p = mock.patch("random.random", return_value=0.5)
        p.start()
        self.addCleanup(p.stop)
        # pylint: disable=protected-access
        sort_servers = auto_enrollment.AutoEnrollment._sort_servers
        # pylint: enable=protected-access
        s1 = "srv1.ipa.example"
        s2 = "srv2.ipa.example"
        s3 = "srv3.ipa.example"
        s4 = "srv4.ipa.example"
        a = "other.ipa.example"
        server_list = [
            {"fqdn": s1},
            {"fqdn": s2, "location": "sigma"},
            {"fqdn": s3, "location": "tau"},
            {"fqdn": s4, "location": "sigma"},
        ]
        r = sort_servers(server_list, [])
        self.assertEqual(r, [s1, s2, s3, s4])
        r = sort_servers(server_list, [s1, a, s4, s3])
        self.assertEqual(r, [s1, s4, s3, s2])
        r = sort_servers(server_list, [], "sigma")
        self.assertEqual(r, [s2, s4, s1, s3])
        r = sort_servers(server_list, [], "kappa")
        self.assertEqual(r, [s1, s2, s3, s4])
        r = sort_servers(server_list, [s1, a, s4, s3], "sigma")
        self.assertEqual(r, [s4, s2, s1, s3])
        r = sort_servers(server_list, [s1, a, s4, s3], "kappa")
        self.assertEqual(r, [s1, s4, s3, s2])

    def test_basic(self):
        args = self.parse_args("--hostname", conftest.CLIENT_FQDN)
        ae = auto_enrollment.AutoEnrollment(args)
        self.assertEqual(ae.tmpdir, None)
        with ae:
            tmpdir = ae.tmpdir
            self.assertTrue(os.path.isdir(tmpdir))

        self.assertEqual(ae.tmpdir, None)
        self.assertFalse(os.path.isdir(tmpdir))

    def test_inventory_from_host_details(self):
        args = self.parse_args("--hostname", conftest.CLIENT_FQDN)
        ae = auto_enrollment.AutoEnrollment(args)
        with ae:
            self.assertEqual(ae.inventory_id, None)
            ae.get_host_details()
            self.assertEqual(ae.inventory_id, conftest.CLIENT_INVENTORY_ID)

    def test_inventory_from_api(self):
        args = self.parse_args("--hostname", conftest.CLIENT_FQDN)
        auto_enrollment.INSIGHTS_HOST_DETAILS = conftest.NO_FILE
        # first call to urlopen gets host details from API
        with io.open(conftest.HOST_DETAILS, "r", encoding="utf-8") as f:
            host_details = json.load(f)
        self.m_urlopen.side_effect = [jsonio(host_details), Exception]
        ae = auto_enrollment.AutoEnrollment(args)
        with ae:
            self.assertEqual(ae.inventory_id, None)
            ae.get_host_details()
            self.assertEqual(ae.inventory_id, conftest.CLIENT_INVENTORY_ID)

        self.assertEqual(self.m_urlopen.call_count, 1)
        req = self.m_urlopen.call_args[0][0]
        self.assertEqual(
            req.get_full_url(),
            "https://cert-api.access.redhat.com/r/insights"
            "/inventory/v1/hosts?insights_id=96aac268-e7b8-429a-8c86-f498b96fe1f9",
        )
        self.assertEqual(req.get_method(), "GET")

    def test_hcc_host_conf(self):
        args = self.parse_args(
            "--hostname",
            conftest.CLIENT_FQDN,
            "--hcc-api-host",
            conftest.SERVER_FQDN,
        )
        ae = auto_enrollment.AutoEnrollment(args)
        with ae:
            ae.get_host_details()

            urlopen = self.m_urlopen
            ae.hcc_host_conf()
            self.assertEqual(urlopen.call_count, 1)
            req = urlopen.call_args[0][0]
            self.assertEqual(
                req.get_full_url(),
                "https://{}/api/idm/v1/host-conf/{}".format(
                    conftest.SERVER_FQDN, conftest.CLIENT_FQDN
                ),
            )
            self.assertEqual(
                req.data, json.dumps(HOST_CONF_REQUEST).encode("utf-8")
            )
            self.assertEqual(
                req.get_header("Content-type"), "application/json"
            )
            self.assertEqual(urlopen.call_args[1]["timeout"], ae.args.timeout)
            self.assertEqual(
                urlopen.call_args[1]["context"].verify_mode,
                ssl.CERT_REQUIRED,
            )
            self.assertEqual(ae.domain, conftest.DOMAIN)
            self.assertEqual(ae.domain_id, conftest.DOMAIN_ID)
            self.assertEqual(ae.realm, conftest.REALM)
            self.assertEqual(ae.servers, [conftest.SERVER_FQDN])
            self.assertEqual(ae.server, conftest.SERVER_FQDN)

    def test_hcc_register(self):
        args = self.parse_args("--hostname", conftest.CLIENT_FQDN)
        ae = auto_enrollment.AutoEnrollment(args)
        with ae:
            ae.get_host_details()
            urlopen = self.m_urlopen
            ae.hcc_host_conf()
            self.assertEqual(urlopen.call_count, 1)

            ae.hcc_register()
            self.assertEqual(urlopen.call_count, 2)
            req = urlopen.call_args[0][0]
            self.assertEqual(
                req.get_full_url(),
                "https://{}/hcc/{}".format(
                    conftest.SERVER_FQDN, conftest.CLIENT_FQDN
                ),
            )
            self.assertTrue(os.path.isfile(ae.ipa_cacert))
            self.assertTrue(os.path.isfile(ae.kdc_cacert))

            with io.open(ae.ipa_cacert, "r", encoding="utf-8") as f:
                data = f.read()
            self.assertEqual(data, conftest.IPA_CA_DATA)
            with io.open(ae.kdc_cacert, "r", encoding="utf-8") as f:
                data = f.read()
            self.assertEqual(data, conftest.KDC_CA_DATA)

    def test_enroll_host_pkinit(self):
        args = self.parse_args("--hostname", conftest.CLIENT_FQDN)

        with mock.patch.object(auto_enrollment, "HAS_KINIT_PKINIT", True):
            ae = auto_enrollment.AutoEnrollment(args)
            with ae:
                tmpdir = ae.tmpdir
                ae.enroll_host()
                self.assertTrue(os.path.isfile(ae.ipa_cacert))
                self.assertTrue(os.path.isfile(ae.kdc_cacert))

        self.assertEqual(self.m_urlopen.call_count, 2)
        self.assertEqual(self.m_run.call_count, 1)

        args, kwargs = self.m_run.call_args_list[0]
        self.assertEqual(
            args[0],
            [
                paths.IPA_CLIENT_INSTALL,
                "--ca-cert-file",
                "{}/ipa_ca.crt".format(tmpdir),
                "--hostname",
                conftest.CLIENT_FQDN,
                "--domain",
                conftest.DOMAIN,
                "--realm",
                conftest.REALM,
                "--unattended",
                "--pkinit-identity",
                "FILE:{},{}".format(
                    auto_enrollment.RHSM_CERT, auto_enrollment.RHSM_KEY
                ),
                "--pkinit-anchor",
                "FILE:{}/kdc_ca.crt".format(tmpdir),
                "--pkinit-anchor",
                "FILE:{}/ipa_ca.crt".format(tmpdir),
            ],
        )
        self.assertEqual(
            kwargs, {"stdin": None, "env": None, "raiseonerr": True}
        )

    def test_enroll_host_keytab(self):
        args = self.parse_args("--hostname", conftest.CLIENT_FQDN)
        ae = auto_enrollment.AutoEnrollment(args)
        with ae:
            tmpdir = ae.tmpdir
            ae.enroll_host()
            self.assertTrue(os.path.isfile(ae.ipa_cacert))
            self.assertTrue(os.path.isfile(ae.kdc_cacert))

        self.assertEqual(self.m_urlopen.call_count, 2)
        self.assertEqual(self.m_run.call_count, 3)

        principal = "host/{}@{}".format(conftest.CLIENT_FQDN, conftest.REALM)
        keytab = "{}/host.keytab".format(tmpdir)
        cacert = "{}/ipa_ca.crt".format(tmpdir)
        # kinit
        args, kwargs = self.m_run.call_args_list[0]
        self.assertEqual(
            args[0],
            [
                paths.KINIT,
                "-X",
                "X509_anchors=FILE:{}/kdc_ca.crt".format(tmpdir),
                "-X",
                "X509_anchors=FILE:{}/ipa_ca.crt".format(tmpdir),
                "-X",
                "X509_user_identity=FILE:{},{}".format(
                    auto_enrollment.RHSM_CERT, auto_enrollment.RHSM_KEY
                ),
                principal,
            ],
        )
        self.assertEqual(kwargs["stdin"], "\n")
        self.assertTrue(
            set(kwargs["env"]).issuperset(
                {"LC_ALL", "KRB5_CONFIG", "KRB5CCNAME"}
            ),
            kwargs["env"],
        )

        # ipa-getkeytab
        args, kwargs = self.m_run.call_args_list[1]
        self.assertEqual(
            args[0],
            [
                paths.IPA_GETKEYTAB,
                "-s",
                conftest.SERVER_FQDN,
                "-p",
                principal,
                "-k",
                keytab,
                "--cacert",
                cacert,
            ],
        )
        self.assertEqual(kwargs["stdin"], None)

        # ipa-client-install
        args, kwargs = self.m_run.call_args_list[2]
        self.assertEqual(
            args[0],
            [
                paths.IPA_CLIENT_INSTALL,
                "--ca-cert-file",
                cacert,
                "--hostname",
                conftest.CLIENT_FQDN,
                "--domain",
                conftest.DOMAIN,
                "--realm",
                conftest.REALM,
                "--unattended",
                "--keytab",
                keytab,
            ],
        )
        self.assertEqual(
            kwargs, {"stdin": None, "env": None, "raiseonerr": True}
        )
