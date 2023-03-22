import io
import json
import os
import unittest

from requests import Response
from ipalib import x509

import conftest
from conftest import mock

from ipahcc import hccplatform

if hccplatform.PY2:
    from httplib import responses as http_responses
else:
    from http.client import responses as http_responses

CAFILE = os.path.join(conftest.TESTDATA, "autoenrollment", "ca.crt")
CACERT = x509.load_certificate_from_file(CAFILE)


@conftest.requires_mock
@conftest.requires_ipaclient_install
class TestHCCAPI(unittest.TestCase):
    def setUp(self):
        self.m_api = mock.Mock()
        self.m_api.isdone.return_value = True
        self.m_api.env = mock.Mock(
            in_server=True,
            domain=conftest.DOMAIN,
            realm=conftest.REALM,
            host=conftest.SERVER_FQDN,
            basedn="dc=ipa-hcc,dc=test",
        )
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

        # depends on ipaclient.install
        from ipahcc.server import hccapi

        p = mock.patch.object(hccapi.certstore, "get_ca_certs")
        self.m_get_ca_certs = p.start()
        self.m_get_ca_certs.return_value = [
            (CACERT, "IPA-HCC.TEST IPA CA", True, None)
        ]
        self.addCleanup(p.stop)

        self.m_session = mock.Mock()
        self.hccapi = hccapi.HCCAPI(self.m_api)
        self.hccapi._session = self.m_session

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

    def test_check_host(self):
        body = {"inventory_id": conftest.CLIENT_INVENTORY_ID}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.hccapi.check_host(
            conftest.DOMAIN_ID,
            conftest.CLIENT_INVENTORY_ID,
            conftest.CLIENT_RHSM_ID,
            conftest.CLIENT_FQDN,
        )

    def test_register_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.hccapi.register_domain(
            conftest.DOMAIN_ID, "mockapi"
        )

    def test_update_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.hccapi.update_domain()
