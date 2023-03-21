import io
import json
import os
import ssl
import unittest

from ipaplatform.paths import paths

import conftest
from conftest import mock

from ipahcc import hccplatform
from ipahcc.client import auto_enrollment
from ipahcc.server import schema


AEDATA = os.path.join(conftest.TESTDATA, "autoenrollment")
CAFILE = os.path.join(AEDATA, "ca.crt")
INVENTORY_ID = "1efd5f0e-7589-44ac-a9af-85ba5569d5c3"

with open(CAFILE) as f:
    CADATA = f.read()

HOST_CONF_REQUEST = {
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "inventory_id": INVENTORY_ID,
}

HOST_CONF_RESPONSE = {
    "domain_name": conftest.DOMAIN,
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "domain_id": hccplatform.TEST_DOMAIN_ID,
    "auto_enrollment_enabled": True,
    hccplatform.HCC_DOMAIN_TYPE: {
        "realm_name": conftest.REALM,
        "cabundle": CADATA,
        "enrollment_servers": [conftest.SERVER_FQDN],
    },
    "inventory_id": INVENTORY_ID,
}

REGISTER_REQUEST = {
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "domain_name": conftest.DOMAIN,
    "domain_id": hccplatform.TEST_DOMAIN_ID,
    "inventory_id": INVENTORY_ID,
}

REGISTER_RESPONSE = {"inventory_id": INVENTORY_ID}


def jsonio(body):
    j = json.dumps(body)
    out = io.BytesIO()
    out.write(j.encode("utf-8"))
    out.seek(0)
    return out


@conftest.requires_mock
class TestAutoEnrollment(unittest.TestCase):
    def setUp(self):
        modname = "ipahcc.client.auto_enrollment"
        p = mock.patch.multiple(
            modname,
            HAS_KINIT_PKINIT=False,
            RHSM_CERT=os.path.join(AEDATA, "cert.pem"),
            RHSM_KEY=os.path.join(AEDATA, "key.pem"),
            HMSIDM_CA_BUNDLE_PEM=os.path.join(
                conftest.BASEDIR, "install/common/redhat-candlepin-bundle.pem"
            ),
            INSIGHTS_HOST_DETAILS=os.path.join(AEDATA, "host-details.json"),
            hccconfig=mock.Mock(
                environment="test",
                idm_cert_api_url="https://console.ipa-hcc.test/api/idm/v1",
            ),
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

    @conftest.requires_jsonschema
    def test_schema(self):
        schema.validate_schema(
            HOST_CONF_REQUEST, "/schemas/host-conf/request"
        )
        schema.validate_schema(
            HOST_CONF_RESPONSE, "/schemas/host-conf/response"
        )
        schema.validate_schema(
            REGISTER_REQUEST, "/schemas/check-host/request"
        )
        schema.validate_schema(
            REGISTER_RESPONSE, "/schemas/check-host/response"
        )

    def test_basic(self):
        ae = auto_enrollment.AutoEnrollment(hostname=conftest.CLIENT_FQDN)
        self.assertEqual(ae.tmpdir, None)
        with ae:
            tmpdir = ae.tmpdir
            self.assertTrue(os.path.isdir(tmpdir))

        self.assertEqual(ae.tmpdir, None)
        self.assertFalse(os.path.isdir(tmpdir))

    def test_wait_for_inventor(self):
        ae = auto_enrollment.AutoEnrollment(hostname=conftest.CLIENT_FQDN)
        with ae:
            self.assertEqual(ae.inventory_id, None)
            ae.wait_for_inventory_host()
            self.assertEqual(ae.inventory_id, INVENTORY_ID)

    def test_hcc_host_conf(self):
        ae = auto_enrollment.AutoEnrollment(hostname=conftest.CLIENT_FQDN)
        with ae:
            ae.wait_for_inventory_host()

            urlopen = self.m_urlopen
            ae.hcc_host_conf()
            self.assertEqual(urlopen.call_count, 1)
            req = urlopen.call_args[0][0]
            self.assertEqual(
                req.full_url,
                "https://console.ipa-hcc.test/api/idm/v1/host-conf/{}".format(
                    conftest.CLIENT_FQDN
                ),
            )
            self.assertEqual(
                req.data, json.dumps(HOST_CONF_REQUEST).encode("utf-8")
            )
            self.assertEqual(urlopen.call_args[1]["timeout"], ae.timeout)
            self.assertEqual(
                urlopen.call_args[1]["context"].verify_mode,
                ssl.CERT_REQUIRED,
            )
            self.assertEqual(ae.domain, conftest.DOMAIN)
            self.assertEqual(ae.domain_id, hccplatform.TEST_DOMAIN_ID)
            self.assertEqual(ae.realm, conftest.REALM)
            self.assertEqual(ae.servers, [conftest.SERVER_FQDN])
            self.assertEqual(ae.server, conftest.SERVER_FQDN)

    def test_hcc_register(self):
        ae = auto_enrollment.AutoEnrollment(hostname=conftest.CLIENT_FQDN)
        with ae:
            ae.wait_for_inventory_host()
            urlopen = self.m_urlopen
            ae.hcc_host_conf()
            self.assertEqual(urlopen.call_count, 1)

            ae.hcc_register()
            self.assertEqual(urlopen.call_count, 2)
            req = urlopen.call_args[0][0]
            self.assertEqual(
                req.full_url,
                "https://{}/hcc/{}".format(
                    conftest.SERVER_FQDN, conftest.CLIENT_FQDN
                ),
            )

    def test_enroll_host(self):
        ae = auto_enrollment.AutoEnrollment(hostname=conftest.CLIENT_FQDN)
        with ae:
            tmpdir = ae.tmpdir
            ae.enroll_host()

        self.assertEqual(self.m_urlopen.call_count, 2)
        self.assertEqual(self.m_run.call_count, 3)

        principal = "host/{}@{}".format(conftest.CLIENT_FQDN, conftest.REALM)
        keytab = "{}/host.keytab".format(tmpdir)
        cacert = "{}/ca.crt".format(tmpdir)
        # kinit
        args, kwargs = self.m_run.call_args_list[0]
        self.assertEqual(
            args[0],
            [
                paths.KINIT,
                "-X",
                "X509_anchors=FILE:{}".format(
                    auto_enrollment.HMSIDM_CA_BUNDLE_PEM
                ),
                "-X",
                "X509_anchors=FILE:{}/ca.crt".format(tmpdir),
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
                "--realm",
                conftest.REALM,
                "--domain",
                conftest.DOMAIN,
                "--server",
                conftest.SERVER_FQDN,
                "--unattended",
                "--keytab",
                keytab,
            ],
        )
        self.assertEqual(
            kwargs, {"stdin": None, "env": None, "raiseonerr": True}
        )
