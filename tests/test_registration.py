import json
from unittest import mock

import gssapi

import conftest
from ipahcc import hccplatform
from ipahcc.registration import wsgi
from ipahcc.server import dbus_client


class TestRegistrationWSGI(conftest.IPABaseTests):
    def setUp(self):
        super().setUp()
        self.m_api = mock.Mock()
        self.m_api.env = self.get_mock_env()
        self.m_api.isdone.return_value = False
        self.m_api.Command.config_show.return_value = {
            "result": {
                "hccdomainid": (conftest.DOMAIN_ID,),
                "hccorgid": (conftest.ORG_ID,),
            }
        }

        self.app = wsgi.Application(self.m_api)

        p = mock.patch.object(gssapi, "Credentials")
        self.m_gss_credentials = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(dbus_client, "_dbus_getmethod")
        self.m_dbus_method = p.start()
        self.addCleanup(p.stop)

    def test_ipaapi(self):
        app = self.app
        api = self.m_api

        api.Backend.rpcclient.isconnected.return_value = False
        app.before_call()
        self.m_gss_credentials.assert_called_once()
        api.finalize.assert_called()
        api.Backend.rpcclient.connect.assert_called_once()

        self.m_api.isdone.return_value = True
        api.Backend.rpcclient.isconnected.return_value = True
        app.after_call()
        api.Backend.rpcclient.disconnect.assert_called_once()

    def test_register(self):
        self.m_dbus_method.return_value = mock.Mock(
            return_value=(
                "rid",
                200,
                "OK",
                "url",
                {"content-type": "application/json"},
                json.dumps({"inventory_id": conftest.CLIENT_INVENTORY_ID}),
                0,
                "",
            )
        )
        body = {
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_name": conftest.DOMAIN,
            "domain_id": conftest.DOMAIN_ID,
        }
        path = "/".join(
            ("", conftest.CLIENT_INVENTORY_ID, conftest.CLIENT_FQDN)
        )
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path, body=body
        )

        self.assert_response(200, status_code, status_msg, headers, response)
        self.assertEqual(
            response,
            {
                "status": "ok",
                "kdc_cabundle": conftest.KDC_CA_DATA,
            },
        )

        app = self.app
        self.assertEqual(app.org_id, int(conftest.ORG_ID))
        self.assertEqual(app.domain_id, conftest.DOMAIN_ID)

        host_add = self.m_api.Command.host_add
        host_add.assert_called_once()
        args, kwargs = host_add.call_args
        self.assertEqual(
            args,
            (conftest.CLIENT_FQDN,),
        )
        self.assertEqual(
            kwargs,
            {
                "force": True,
                "hccinventoryid": conftest.CLIENT_INVENTORY_ID,
                "hccsubscriptionid": conftest.CLIENT_RHSM_ID,
            },
        )
