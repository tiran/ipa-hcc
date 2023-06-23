import copy
import json
import textwrap
from unittest import mock

from ipalib import x509
from ipapython import admintool
from ipapython.dnsutil import DNSName

import conftest
from ipahcc import hccplatform
from ipahcc.server import hccapi
from ipahcc.server.dbus_service import IPAHCCDbus

CACERT = x509.load_pem_x509_certificate(conftest.IPA_CA_DATA.encode("ascii"))

COMMON_RESULT = {
    "domain_name": conftest.DOMAIN,
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    hccplatform.HCC_DOMAIN_TYPE: {
        "realm_name": conftest.REALM,
        "servers": [
            {
                "fqdn": conftest.SERVER_FQDN,
                "ca_server": True,
                "hcc_enrollment_server": True,
                "hcc_update_server": True,
                "pkinit_server": True,
                "subscription_manager_id": conftest.SERVER_RHSM_ID,
                "location": "sigma",
            }
        ],
        "locations": [
            {"name": "kappa"},
            {"name": "sigma"},
            {"name": "tau", "description": "location tau"},
        ],
        "realm_domains": [conftest.DOMAIN],
    },
}

DOMAIN_RESULT = copy.deepcopy(COMMON_RESULT)
DOMAIN_RESULT.update(
    {
        "title": "Some title",
        "description": "Some description",
        "auto_enrollment_enabled": True,
        "domain_id": conftest.DOMAIN_ID,
    }
)
DOMAIN_RESULT[hccplatform.HCC_DOMAIN_TYPE].update(
    {
        "ca_certs": [conftest.IPA_CA_CERTINFO],
    }
)

STATUS_CHECK_RESULT = copy.deepcopy(COMMON_RESULT)
STATUS_CHECK_RESULT.update(
    {
        "domain_id": conftest.DOMAIN_ID,
        "org_id": conftest.ORG_ID,
    }
)


def mkresult(dct, status_code=200, exit_code=0, exit_message="ok"):
    return hccapi.APIResult(
        "",
        status_code,
        "",
        "",
        {"content-type": "application/json"},
        dct,
        exit_code,
        exit_message,
    )


class TestHCCAPICommon(conftest.IPABaseTests):
    def setUp(self):
        super().setUp()

        self.mock_hccplatform()

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
            (CACERT, conftest.IPA_CA_NICKNAME, True, None)
        ]
        self.addCleanup(p.stop)

        self.m_session = mock.Mock()
        self.m_hccapi = hccapi.HCCAPI(self.m_api)
        self.m_hccapi.session = self.m_session


class TestHCCAPI(TestHCCAPICommon):
    def test_register_domain(self):
        self.m_session.request.return_value = self.mkresponse(
            200, DOMAIN_RESULT
        )
        info, resp = self.m_hccapi.register_domain(
            conftest.DOMAIN_ID, "mockapi"
        )
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, hccapi.APIResult)

    def test_update_domain(self):
        self.m_session.request.return_value = self.mkresponse(
            200, DOMAIN_RESULT
        )
        info, resp = self.m_hccapi.update_domain()
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, hccapi.APIResult)

    def test_status_check(self):
        info, resp = self.m_hccapi.status_check()
        self.m_session.request.assert_not_called()
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, hccapi.APIResult)


class TestIPAHCCDbus(TestHCCAPICommon):
    def setUp(self):
        super().setUp()
        bus = mock.Mock()
        bus_name = mock.Mock()
        self.m_mainloop = mock.Mock()
        self.dbus = IPAHCCDbus(
            bus,
            hccplatform.HCC_DBUS_OBJ_PATH,
            bus_name=bus_name,
            loop=self.m_mainloop,
            hccapi=self.m_hccapi,
        )
        self.addCleanup(self.dbus.stop)

    def dbus_call(self, method, *args):
        # pylint: disable=protected-access
        self.assertTrue(self.dbus._lq_thread.is_alive())
        ok_cb = mock.Mock()
        err_cb = mock.Mock()
        args += (ok_cb, err_cb)
        method(*args)
        # wait for queue to process task
        self.dbus._lq._queue.join()
        return ok_cb, err_cb

    def test_dbus_livecycle(self):
        # pylint: disable=protected-access
        self.assertTrue(self.dbus._lq_thread.is_alive())
        self.dbus.stop()
        self.assertFalse(self.dbus._lq_thread.is_alive())
        self.assert_log_entry("Stopping lookup queue")
        self.m_mainloop.quit.assert_called_once()

    def test_register_domain(self):
        body = DOMAIN_RESULT
        self.m_session.request.return_value = self.mkresponse(200, body)
        ok_cb, err_cb = self.dbus_call(
            self.dbus.register_domain, conftest.DOMAIN_ID, "mockapi"
        )

        err_cb.assert_not_called()
        body_str = json.dumps(body)
        ok_cb.assert_called_once_with(
            "rid",
            200,
            "OK",
            "",
            {
                "content-type": "application/json",
                "content-length": str(len(body_str)),
            },
            body_str,
            0,
            (
                f"Successfully registered domain '{conftest.DOMAIN}' "
                f"with Hybrid Cloud Console (id: {conftest.DOMAIN_ID})."
            ),
        )

    def test_update_domain(self):
        body = DOMAIN_RESULT
        self.m_session.request.return_value = self.mkresponse(200, body)
        ok_cb, err_cb = self.dbus_call(
            self.dbus.update_domain,
            False,
        )

        err_cb.assert_not_called()
        body_str = json.dumps(body)
        ok_cb.assert_called_once_with(
            "rid",
            200,
            "OK",
            "",
            {
                "content-type": "application/json",
                "content-length": str(len(body_str)),
            },
            body_str,
            0,
            (
                f"Successfully updated domain '{conftest.DOMAIN}' "
                f"({conftest.DOMAIN_ID})."
            ),
        )

    def test_status_check(self):
        ok_cb, err_cb = self.dbus_call(
            self.dbus.status_check,
        )
        expected = json.dumps(STATUS_CHECK_RESULT, sort_keys=True)

        err_cb.assert_not_called()
        ok_cb.assert_called_once_with(
            "rid",
            200,
            "OK",
            "",
            {
                "content-type": "application/json",
                "content-length": str(len(expected)),
            },
            expected,
            0,
            (
                f"IPA domain '{conftest.DOMAIN}' is registered with Hybrid Cloud "
                f"Console (domain_id: {conftest.DOMAIN_ID}, organization: "
                f"{conftest.ORG_ID})."
            ),
        )


class TestDBUSCli(conftest.IPABaseTests):
    def setUp(self):
        super().setUp()
        p = mock.patch("ipahcc.hccplatform.is_ipa_configured")
        self.m_is_ipa_configured = p.start()
        self.addCleanup(p.stop)
        self.m_is_ipa_configured.return_value = True

        p = mock.patch.multiple(
            "ipahcc.server.dbus_client",
            register_domain=mock.Mock(),
            update_domain=mock.Mock(),
        )
        self.m_dbus_client = p.start()
        self.addCleanup(p.stop)

    def assert_dbus_cli_run(self, *args, **kwargs):
        # pylint: disable=import-outside-toplevel
        from ipahcc.server.dbus_cli import main

        return self.assert_cli_run(main, *args, **kwargs)

    def test_cli_noaction(self):
        out = self.assert_dbus_cli_run(exitcode=2)
        self.assertIn("usage:", out)

    def test_cli_not_configured(self):
        self.m_is_ipa_configured.return_value = False

        out = self.assert_dbus_cli_run(
            "register",
            conftest.DOMAIN_ID,
            "mockapi",
            exitcode=admintool.SERVER_NOT_CONFIGURED,
        )
        self.assertEqual(out.strip(), "IPA is not configured on this system.")

    def test_cli_register(self):
        with mock.patch("ipahcc.server.dbus_client.register_domain") as m:
            m.return_value = mkresult({"status": "ok"})
            out = self.assert_dbus_cli_run(
                "register", "--unattended", conftest.DOMAIN_ID, "mockapi"
            )
        self.assertIn("ok", out)

    def test_cli_update(self):
        with mock.patch("ipahcc.server.dbus_client.update_domain") as m:
            m.return_value = mkresult({"status": "ok"})
            out = self.assert_dbus_cli_run("update")
        self.assertIn("ok", out)

    def test_cli_status(self):
        with mock.patch("ipahcc.server.dbus_client.status_check") as m:
            m.return_value = mkresult(STATUS_CHECK_RESULT)
            out = self.assert_dbus_cli_run("status")

        self.assertEqual(
            out,
            textwrap.dedent(
                f"""\
            domain name: {conftest.DOMAIN}
            domain id: {conftest.DOMAIN_ID}
            org id: {conftest.ORG_ID}
            servers:
            \t{conftest.SERVER_FQDN} (HCC plugin: yes)
            """
            ),
        )
