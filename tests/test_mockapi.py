import conftest
from conftest import mock

from ipahcc import hccplatform
from ipahcc.mockapi import wsgi


domain_request = {
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
        ],
        "cacerts": [
            {
                "nickname": "IPAHCC.TEST IPA CA",
                "pem": conftest.IPA_CA_DATA,
            }
        ],
        "realm_domains": [conftest.DOMAIN],
        "locations": [
            {"name": "sigma", "description": None},
            {"name": "tau", "description": "location tau"},
        ],
    },
}


@conftest.requires_mock
class TestMockAPIWSGI(conftest.IPABaseTests):
    def setUp(self):
        super(TestMockAPIWSGI, self).setUp()
        self.m_api = mock.Mock()
        self.m_api.isdone.return_value = True
        self.m_api.env = self.get_mock_env()

        self.app = wsgi.Application(self.m_api)

        p = mock.patch.object(self.app, "session")
        self.m_session = p.start()
        self.addCleanup(p.stop)

        # lookup inventory result
        self.m_session.get.return_value = self.mkresponse(
            200,
            {
                "results": [
                    {
                        "fqdn": conftest.CLIENT_FQDN,
                        "id": conftest.CLIENT_INVENTORY_ID,
                        "subscription_manager_id": conftest.CLIENT_RHSM_ID,
                    }
                ],
                "total": 1,
            },
        )

        p = mock.patch.object(self.app, "get_access_token")
        self.m_access_token = p.start()
        self.addCleanup(p.stop)
        self.m_access_token.return_value = "access token"

    def test_root(self):
        status_code, status_msg, headers, response = self.call_wsgi(
            "/", {}, method="GET"
        )
        self.assertEqual(status_code, 200, response)
        self.assertEqual(status_msg, "OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(response, {})

    def test_check_host(self):
        path = "/".join(
            ("", "check-host", conftest.CLIENT_RHSM_ID, conftest.CLIENT_FQDN)
        )
        body = {
            "domain_name": conftest.DOMAIN,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_id": conftest.DOMAIN_ID,
            "inventory_id": conftest.CLIENT_INVENTORY_ID,
        }
        status_code, status_msg, headers, response = self.call_wsgi(
            path, body, method="POST"
        )
        self.assertEqual(status_code, 200, response)
        self.assertEqual(status_msg, "OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(
            response, {"inventory_id": conftest.CLIENT_INVENTORY_ID}
        )

    def test_host_conf(self):
        path = "/".join(("", "host-conf", conftest.CLIENT_FQDN))
        body = {"inventory_id": conftest.CLIENT_INVENTORY_ID}
        status_code, status_msg, headers, response = self.call_wsgi(
            path, body, method="POST"
        )
        self.assertEqual(status_code, 200, response)
        self.assertEqual(status_msg, "OK")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_register_domain(self):
        headers = {"HTTP_X_RH_IDM_REGISTRATION_TOKEN": "mockapi"}
        path = "/".join(("", "domains", conftest.DOMAIN_ID, "register"))
        status_code, status_msg, headers, response = self.call_wsgi(
            path,
            domain_request,
            method="PUT",
            extra_headers={
                "X-RH-IDM-Registration-Token": "mockapi",
            },
        )
        self.assertEqual(status_code, 200, response)
        self.assertEqual(status_msg, "OK")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_update_domain(self):
        path = "/".join(("", "domains", conftest.DOMAIN_ID, "update"))
        status_code, status_msg, headers, response = self.call_wsgi(
            path, domain_request, method="PUT"
        )
        self.assertEqual(status_code, 200, response)
        self.assertEqual(status_msg, "OK")
        self.assertEqual(headers["Content-Type"], "application/json")
