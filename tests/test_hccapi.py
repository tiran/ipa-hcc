from requests import Response
from ipapython.dnsutil import DNSName
from ipalib import x509

import conftest
from conftest import mock

from ipahcc.server import hccapi

CACERT = x509.load_certificate_from_file(conftest.IPA_CA_CRT)


@conftest.requires_mock
class TestHCCAPI(conftest.IPABaseTests):
    def setUp(self):
        super(TestHCCAPI, self).setUp()
        self.m_api = mock.Mock()
        self.m_api.isdone.return_value = True
        self.m_api.env = self.get_mock_env()
        self.m_api.Command.ca_is_enabled.return_value = {"result": True}
        # note: stripped down config_show() output
        self.m_api.Command.config_show.return_value = {
            "result": {
                "ca_server_server": (conftest.SERVER_FQDN,),
                "dns_server_server": (conftest.SERVER_FQDN,),
                "hcc_enrollment_server_server": (conftest.SERVER_FQDN,),
                "hcc_update_server_server": conftest.SERVER_FQDN,
                "hccdomainid": (conftest.DOMAIN_ID,),
                "hccorgid": (conftest.ORG_ID,),
                "ipa_master_server": (conftest.SERVER_FQDN,),
                "kra_server_server": (conftest.SERVER_FQDN,),
                "pkinit_server_server": (conftest.SERVER_FQDN,),
            },
            "summary": None,
            "value": None,
        }
        self.m_api.Command.server_find.return_value = {
            "count": 1,
            "result": (
                {
                    "cn": (conftest.SERVER_FQDN,),
                    "ipalocation_location": (DNSName("sigma"),),
                },
            ),
            "summary": "1 host matched",
            "truncated": False,
        }
        self.m_api.Command.host_find.return_value = {
            "count": 1,
            "result": (
                {
                    "fqdn": (conftest.SERVER_FQDN,),
                    "hccsubscriptionid": (conftest.SERVER_RHSM_ID,),
                },
            ),
            "summary": "1 host matched",
            "truncated": False,
        }
        self.m_api.Command.realmdomains_show.return_value = {
            "result": {
                "associateddomain": (conftest.DOMAIN,),
            }
        }
        self.m_api.Command.location_find.return_value = {
            "result": (
                {"idnsname": (DNSName("kappa"),)},
                {"idnsname": (DNSName("sigma"),)},
                {
                    "idnsname": (DNSName("tau"),),
                    "description": ("location tau",),
                },
            ),
        }

        p = mock.patch.object(hccapi, "get_ca_certs")
        self.m_get_ca_certs = p.start()
        self.m_get_ca_certs.return_value = [
            (CACERT, "IPA-HCC.TEST IPA CA", True, None)
        ]
        self.addCleanup(p.stop)

        self.m_session = mock.Mock()
        self.hccapi = hccapi.HCCAPI(self.m_api)
        self.hccapi.session = self.m_session

    def test_check_host(self):
        body = {"inventory_id": conftest.CLIENT_INVENTORY_ID}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.hccapi.check_host(
            conftest.DOMAIN_ID,
            conftest.CLIENT_INVENTORY_ID,
            conftest.CLIENT_RHSM_ID,
            conftest.CLIENT_FQDN,
        )
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, Response)

    def test_register_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.hccapi.register_domain(
            conftest.DOMAIN_ID, "mockapi"
        )
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, Response)

    def test_update_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.hccapi.update_domain()
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, Response)
