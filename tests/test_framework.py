from unittest import mock

import conftest
from ipahcc.server.framework import JSONWSGIApp, route
from ipahcc.server.hccapi import APIResult


class Application(JSONWSGIApp):
    @route("GET", "^/$")
    def index(self, env, body):
        return {"status": "ok"}

    @route("GET", "^/fail$")
    def fail(self, env, body):
        raise ValueError

    @route("GET", "^/cert$")
    def cert(self, env, body):
        org_id, rhsm_id = self.parse_cert(env)
        return {"org_id": org_id, "subscription_manager_id": rhsm_id}

    @route(
        "POST",
        "^/host-conf/(?P<inventory_id>[^/]+)/(?P<fqdn>[^/]+)$",
        schema="HostConf",
    )
    def handle_host_conf(
        self, env, body, inventory_id, fqdn
    ):  # pylint: disable=unused-argument
        return {}


class TestWSGIFramework(conftest.IPABaseTests):
    maxDiff = None

    def setUp(self):
        super().setUp()
        self.m_api = mock.Mock()
        self.app = Application(self.m_api)
        p = mock.patch.object(APIResult, "genrid")
        self.m_genrid = p.start()
        self.m_genrid.return_value = "rid"
        self.addCleanup(p.stop)

    def test_route(self):
        with self.assertRaises(ValueError):
            route("INVALID", "^/$")
        with self.assertRaises(ValueError):
            route("GET", "/")

    def test_index_get(self):
        status_code, status_msg, headers, response = self.call_wsgi(
            path="/", body=None, method="GET"
        )

        self.assert_response(200, status_code, status_msg, headers, response)
        self.assertEqual(response, {"status": "ok"})

    def test_errors(self):
        # method not allowed
        status_code, status_msg, headers, response = self.call_wsgi(
            path="/", body={}, method="POST"
        )
        self.assert_response(405, status_code, status_msg, headers, response)

        status_code, status_msg, headers, response = self.call_wsgi(
            path="/fail", body=None, method="GET"
        )
        self.assert_response(500, status_code, status_msg, headers, response)

        # not found
        status_code, status_msg, headers, response = self.call_wsgi(
            path="/not-found",
            body={},
        )
        self.assert_response(404, status_code, status_msg, headers, response)

        # length required
        path = "/".join(
            (
                "",
                "host-conf",
                conftest.CLIENT_INVENTORY_ID,
                conftest.CLIENT_FQDN,
            )
        )
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path, body=None
        )
        self.assert_response(411, status_code, status_msg, headers, response)

        # not acceptable (content type)
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path,
            body={},
            content_type="text/plain",
        )
        self.assert_response(406, status_code, status_msg, headers, response)

        # too large
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path,
            body={"large": "a" * (JSONWSGIApp.max_content_length + 1)},
        )
        self.assert_response(413, status_code, status_msg, headers, response)

    def test_cert(self):
        status_code, status_msg, headers, response = self.call_wsgi(
            path="/cert",
            body=None,
            method="GET",
        )
        self.assert_response(200, status_code, status_msg, headers, response)
        self.assertEqual(
            response,
            {
                "org_id": conftest.ORG_ID,
                "subscription_manager_id": conftest.CLIENT_RHSM_ID,
            },
        )

        status_code, status_msg, headers, response = self.call_wsgi(
            path="/cert", body=None, method="GET", client_cert=None
        )
        self.assert_response(412, status_code, status_msg, headers, response)

        status_code, status_msg, headers, response = self.call_wsgi(
            path="/cert", body=None, method="GET", client_cert="invalid"
        )
        self.assert_response(400, status_code, status_msg, headers, response)

    def test_schema_violations(self):
        path = "/".join(
            (
                "",
                "host-conf",
                conftest.CLIENT_INVENTORY_ID,
                conftest.CLIENT_FQDN,
            )
        )
        body = {"invalid": "error"}
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path, body=body
        )
        self.assert_response(400, status_code, status_msg, headers, response)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(
            response,
            {
                "errors": [
                    {
                        "id": self.m_genrid.return_value,
                        "detail": (
                            "schema violation: "
                            "invalid JSON for HostConfRequest"
                        ),
                        "status": "400",
                        "title": "Bad Request",
                    }
                ]
            },
        )
