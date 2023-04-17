import conftest
from conftest import mock

from ipahcc.server.framework import JSONWSGIApp, route


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
        schema="host-conf",
    )
    def handle_host_conf(
        self, env, body, inventory_id, fqdn
    ):  # pylint: disable=unused-argument
        return {}


@conftest.requires_mock
class TestWSGIFramework(conftest.IPABaseTests):
    maxDiff = None

    def setUp(self):
        super(TestWSGIFramework, self).setUp()
        self.m_api = mock.Mock()
        self.app = Application(self.m_api)

    def test_route(self):
        with self.assertRaises(ValueError):
            route("INVALID", "^/$")
        with self.assertRaises(ValueError):
            route("GET", "/")

    def test_index_get(self):
        status_code, status_msg, headers, response = self.call_wsgi(
            path="/", body=None, method="GET"
        )

        self.assertEqual(status_code, 200)
        self.assertEqual(status_msg, "OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(response, {"status": "ok"})

    def test_errors(self):
        status_code, status_msg, headers, response = self.call_wsgi(
            path="/", body={}, method="POST"
        )
        self.assertEqual(status_code, 405)

        status_code, status_msg, headers, response = self.call_wsgi(
            path="/fail", body=None, method="GET"
        )
        self.assertEqual(status_code, 500)

        status_code, status_msg, headers, response = self.call_wsgi(
            path="/not-found",
            body={},
        )
        self.assertEqual(status_code, 404)

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
        self.assertEqual(status_code, 411)

        status_code, status_msg, headers, response = self.call_wsgi(
            path=path,
            body={},
            content_type="text/plain",
        )
        self.assertEqual(status_code, 406)

        status_code, status_msg, headers, response = self.call_wsgi(
            path=path,
            body={"large": "a" * (JSONWSGIApp.max_content_length + 1)},
        )
        self.assertEqual(status_code, 413)

    def test_cert(self):
        status_code, status_msg, headers, response = self.call_wsgi(
            path="/cert",
            body=None,
            method="GET",
        )
        self.assertEqual(status_code, 200)
        self.assertEqual(
            response,
            {
                "org_id": int(conftest.ORG_ID),
                "subscription_manager_id": conftest.CLIENT_RHSM_ID,
            },
        )

        status_code, status_msg, headers, response = self.call_wsgi(
            path="/cert", body=None, method="GET", client_cert=None
        )
        self.assertEqual(status_code, 412)

        status_code, status_msg, headers, response = self.call_wsgi(
            path="/cert", body=None, method="GET", client_cert="invalid"
        )
        self.assertEqual(status_code, 400)

    def test_schema_violations(self):
        path = "/".join(
            (
                "",
                "host-conf",
                conftest.CLIENT_INVENTORY_ID,
                conftest.CLIENT_FQDN,
            )
        )
        body = {"error": "error"}
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path, body=body
        )
        self.assertEqual(status_code, 400)
        self.assertEqual(status_msg, "Bad Request")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(
            response,
            {
                "details": "schema violation: invalid JSON for /schemas/host-conf/request",
                "status": 400,
                "title": "Bad Request",
            },
        )

        body = {}
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path, body=body
        )
        self.assertEqual(status_code, 400)
        self.assertEqual(status_msg, "Bad Request")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(
            response,
            {
                "details": "schema violation: invalid JSON for /schemas/host-conf/response",
                "status": 400,
                "title": "Bad Request",
            },
        )
