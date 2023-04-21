import os
import shutil
import tempfile
from unittest import mock

from ipalib import errors
from ipaplatform.services import knownservices
from ipapython.kerberos import Principal

import conftest
from ipahcc import hccplatform


@conftest.requires_ipaserver
class TestIPAServerUpdates(conftest.IPABaseTests):
    def setUp(self):
        super().setUp()
        self.mock_hccplatform()

        self.m_api = mock.Mock()
        self.m_api.isdone.return_value = True
        self.m_api.env = self.get_mock_env()

        self.m_api.Command.config_show.return_value = {
            "result": {
                "hccorgid": None,
            }
        }
        self.m_api.Object.server_role.get_hcc_enrollment_agents.return_value = (
            set()
        )
        self.m_api.Object.server_role.get_hcc_update_server.return_value = (
            None
        )

        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmpdir = td.name

        self.kdc_conf = os.path.join(self.tmpdir, "kdc.conf")
        shutil.copy(conftest.KDC_CONF, self.kdc_conf)

        self.alias_dir = os.path.join(self.tmpdir, "aliase")
        os.makedirs(self.alias_dir)

        p = mock.patch.multiple(
            "ipaplatform.paths.paths",
            KRB5KDC_KDC_CONF=self.kdc_conf,
            HTTPD_ALIAS_DIR=self.alias_dir,
        )
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch.multiple(
            "ipaplatform.services.knownservices",
            gssproxy=mock.Mock(),
            httpd=mock.Mock(),
            krb5kdc=mock.Mock(),
        )
        p.start()
        self.addCleanup(p.stop)

    def test_update_hcc(self):
        with open(self.kdc_conf, encoding="utf-8") as f:
            content = f.read()
        self.assertEqual(content.count("pkinit_anchors = "), 2)

        from ipaserver.install.plugins.update_hcc import update_hcc

        updater = update_hcc(self.m_api)

        updater.execute()

        knownservices.krb5kdc.try_restart.assert_called_once()
        with open(self.kdc_conf, encoding="utf-8") as f:
            content = f.read()
        self.assertIn(
            f"pkinit_anchors = DIR:{hccplatform.HMSIDM_CACERTS_DIR}",
            content,
        )
        self.assertEqual(content.count("pkinit_anchors = "), 3)

        self.m_api.Command.host_mod.assert_called_once_with(
            conftest.SERVER_FQDN,
            # test uses client's cert
            hccsubscriptionid=conftest.CLIENT_RHSM_ID,
        )

        self.m_api.Command.config_mod.assert_called_once_with(
            hccorgid=int(conftest.ORG_ID),
        )

    def test_update_hcc_enrollment_service(self):
        from ipaserver.install.plugins.update_hcc_enrollment_service import (
            update_hcc_enrollment_service,
        )

        self.m_api.Command.service_show.side_effect = errors.NotFound(
            reason="not found"
        )

        updater = update_hcc_enrollment_service(self.m_api)
        updater.add_hcc_enrollment_service()

        principal = Principal(
            f"hcc-enrollment/{conftest.SERVER_FQDN}@{conftest.REALM}"
        )
        self.m_api.Command.service_add.assert_called_once_with(
            principal, force=True
        )
        self.m_api.Command.role_add_member.assert_called_once_with(
            hccplatform.HCC_ENROLLMENT_ROLE,
            service=str(principal),
        )
