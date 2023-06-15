import copy
from unittest import mock

from test_hccapi import DOMAIN_RESULT

import conftest
from ipahcc import hccplatform
from ipahcc.mockapi import wsgi
from ipahcc.server import token

domain_request = {
    "title": "Some title",
    "description": "Some description",
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
        "ca_certs": [conftest.IPA_CA_CERTINFO],
        "locations": [
            {"name": "kappa"},
            {"name": "sigma"},
            {"name": "tau", "description": "location tau"},
        ],
        "realm_domains": [conftest.DOMAIN],
    },
}

host_conf_response = {
    "domain_name": conftest.DOMAIN,
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "domain_id": conftest.DOMAIN_ID,
    "auto_enrollment_enabled": True,
    # "token": ...,
    hccplatform.HCC_DOMAIN_TYPE: {
        "realm_name": conftest.REALM,
        "cabundle": conftest.IPA_CA_DATA,
        "enrollment_servers": [{"fqdn": conftest.SERVER_FQDN}],
    },
    "inventory_id": conftest.CLIENT_INVENTORY_ID,
}

PRIV_KEY = token.generate_private_key()
PUB_KEY = token.get_public_key(PRIV_KEY)


class TestMockAPIWSGI(conftest.IPABaseTests):
    def setUp(self):
        super().setUp()
        self.m_api = mock.Mock()
        self.m_api.isdone.return_value = True
        self.m_api.env = self.get_mock_env()

        p = mock.patch.object(wsgi.Application, "_load_jwk")
        self.m_load_jwk = p.start()
        self.m_load_jwk.return_value = (PRIV_KEY, PUB_KEY.export_public())
        self.addCleanup(p.stop)

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
        self.assert_response200(status_code, status_msg, headers, response)
        self.assertEqual(response, {})

    def test_host_conf(self):
        path = "/".join(
            (
                "",
                "host-conf",
                conftest.CLIENT_INVENTORY_ID,
                conftest.CLIENT_FQDN,
            )
        )
        body = {}
        status_code, status_msg, headers, response = self.call_wsgi(
            path, body, method="POST"
        )
        self.assert_response200(status_code, status_msg, headers, response)
        raw_token = response.pop("token")
        self.assertEqual(response, host_conf_response)
        header, claims = token.validate_host_token(
            raw_token,
            PUB_KEY,
            cert_o=conftest.ORG_ID,
            cert_cn=conftest.CLIENT_RHSM_ID,
            inventory_id=conftest.CLIENT_INVENTORY_ID,
            fqdn=conftest.CLIENT_FQDN,
            domain_id=conftest.DOMAIN_ID,
        )
        self.assertEqual(header["kid"], PUB_KEY["kid"])
        self.assertIn("jti", claims)

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
        self.assert_response200(status_code, status_msg, headers, response)
        expected = copy.deepcopy(DOMAIN_RESULT)
        expected["signing_keys"] = {
            "keys": [self.app.pub_key],
            "revoked": ["bad key id"],
        }
        self.assertEqual(response, expected)

    def test_update_domain(self):
        path = "/".join(("", "domains", conftest.DOMAIN_ID, "update"))
        status_code, status_msg, headers, response = self.call_wsgi(
            path, domain_request, method="PUT"
        )
        self.assert_response200(status_code, status_msg, headers, response)
        expected = copy.deepcopy(DOMAIN_RESULT)
        expected["signing_keys"] = {
            "keys": [self.app.pub_key],
            "revoked": ["bad key id"],
        }
        self.assertEqual(response, expected)
